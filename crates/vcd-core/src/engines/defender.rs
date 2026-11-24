//! Microsoft Defender engine.
//!
//! `MpCmdRun.exe` ships with Windows: no install step and no database to load,
//! so a single-file scan costs tens of milliseconds. Two facts shape this
//! engine:
//!
//! - The exit code is the stable contract (0 = no threats, 2 = a threat or an
//!   error); the summary text is human-facing, so the `hr = 0x…` line decides
//!   which of the two a 2 means.
//! - `-DisableRemediation` is always passed: a scanner that deletes the user's
//!   files is not a scanner.
//!
//! A "no threats" answer may come from Defender's scan cache, populated when
//! real-time protection read the file on write. That is still Defender's
//! verdict for those bytes, but a path listed in Defender's exclusions would
//! also answer clean, and reading exclusions needs administrator rights. The
//! caveat is reported as a fact instead of hidden.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::report::{Coverage, Detection, EngineReport, Fact, Severity};

use super::{Engine, ScanTarget};

const SCAN_TIMEOUT: Duration = Duration::from_secs(300);
const EXIT_THREATS_FOUND: i32 = 2;
const MAX_EVIDENCE_CHARS: usize = 300;

const HINT: &str = "Microsoft Defender command line utility not found; \
     it is part of Windows, so check that Defender is enabled and not removed by policy";

const CACHE_CAVEAT: &str = "Defender may answer from its scan cache, and excluded paths are invisible without admin rights";

pub struct DefenderEngine {
    executable: Option<PathBuf>,
}

impl DefenderEngine {
    pub fn discover() -> Self {
        Self {
            executable: find_executable(),
        }
    }

    pub fn with_executable(executable: PathBuf) -> Self {
        Self {
            executable: Some(executable),
        }
    }
}

impl Engine for DefenderEngine {
    fn name(&self) -> &'static str {
        "defender"
    }

    fn scan(&self, target: &ScanTarget<'_>) -> EngineReport {
        let Some(executable) = &self.executable else {
            return EngineReport::unavailable(self.name(), HINT);
        };

        let started = Instant::now();
        let output_path = temp_output_path();
        let outcome = run_scan(executable, target.path, &output_path);
        let stdout = read_text(&output_path);
        let _ = std::fs::remove_file(&output_path);

        // Exit 0 with output we could not read is not a clean scan.
        let stdout = match stdout {
            Ok(text) => text,
            Err(error) => {
                return EngineReport::failed(
                    self.name(),
                    format!("cannot read MpCmdRun's output: {error}"),
                );
            }
        };

        let exit_code = match outcome {
            Ok(code) => code,
            Err(RunError::Timeout) => {
                return EngineReport::failed(
                    self.name(),
                    format!("MpCmdRun timed out after {}s", SCAN_TIMEOUT.as_secs()),
                );
            }
            Err(RunError::Io(error)) => {
                return EngineReport::failed(self.name(), format!("cannot run MpCmdRun: {error}"));
            }
        };

        classify(self.name(), exit_code, &stdout, started.elapsed())
    }
}

fn classify(engine: &str, exit_code: i32, stdout: &str, duration: Duration) -> EngineReport {
    // On a detection the signature is the useful line; the tail of that report
    // is the resource list, not the verdict.
    let evidence = threat_name(stdout).unwrap_or_else(|| summarize(stdout));
    let facts = vec![
        Fact::new("result", evidence.clone()),
        Fact::new("caveat", CACHE_CAVEAT),
    ];

    match exit_code {
        0 => EngineReport::completed(engine, Vec::new(), Coverage::Complete, duration)
            .with_facts(facts),
        EXIT_THREATS_FOUND if !looks_like_error(stdout) => EngineReport::completed(
            engine,
            vec![Detection {
                name: "defender-detection".to_string(),
                severity: Severity::Malicious,
                detail: evidence,
            }],
            Coverage::Complete,
            duration,
        )
        .with_facts(facts),
        EXIT_THREATS_FOUND => EngineReport::failed(
            engine,
            format!("MpCmdRun reported an error instead of a scan result: {evidence}"),
        ),
        other => EngineReport::failed(
            engine,
            format!("MpCmdRun exited with code {other}: {evidence}"),
        ),
    }
}

/// `MpCmdRun` returns 2 for a detection *and* for its own failures. The HRESULT
/// line is the error shape; a real detection carries a `Threat` line instead.
fn looks_like_error(stdout: &str) -> bool {
    stdout.contains("hr = 0x") || stdout.contains("Failed with hr")
}

/// `Threat                  : Virus:DOS/EICAR_Test_File` -> the signature.
/// The label stays English even on a localized Windows, but the exit code
/// remains the contract if it ever changes.
fn threat_name(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        if let Some((label, value)) = line.split_once(':')
            && label.trim().eq_ignore_ascii_case("threat")
            && !value.trim().is_empty()
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Last non-empty line, capped: enough to see what happened without dumping a
/// localized progress log into the report.
fn summarize(stdout: &str) -> String {
    let line = stdout
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty() && !line.chars().all(|c| c == '-'))
        .unwrap_or("no output");

    if line.chars().count() <= MAX_EVIDENCE_CHARS {
        return line.to_string();
    }

    let mut shortened: String = line.chars().take(MAX_EVIDENCE_CHARS - 3).collect();
    shortened.push_str("...");
    shortened
}

enum RunError {
    Io(io::Error),
    Timeout,
}

fn run_scan(executable: &Path, target: &Path, output: &Path) -> Result<i32, RunError> {
    // Same reasoning as the ClamAV engine: stdout goes to a file so an
    // undrained pipe can never deadlock the child.
    let sink = File::create(output).map_err(RunError::Io)?;

    // An absolute path can never be read as an option.
    let target = std::path::absolute(target).unwrap_or_else(|_| target.to_path_buf());

    let mut child = crate::download::hidden_command(executable)
        .arg("-Scan")
        .arg("-ScanType")
        .arg("3")
        .arg("-File")
        .arg(&target)
        .arg("-DisableRemediation")
        .stdin(Stdio::null())
        .stdout(Stdio::from(sink))
        .stderr(Stdio::null())
        .spawn()
        .map_err(RunError::Io)?;

    let deadline = Instant::now() + SCAN_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(-1)),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::Timeout);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(RunError::Io(error)),
        }
    }
}

fn read_text(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

fn temp_output_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("vcd-defender-{}-{unique}.log", std::process::id()))
}

/// Prefer the platform directory Defender actually runs from; the versioned
/// folders sort before the `CurrentVersion` alias, so a reverse sort starts
/// with the alias.
fn find_executable() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(r"C:\ProgramData\Microsoft\Windows Defender\Platform") {
        let mut directories: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect();
        directories.sort();
        for directory in directories.into_iter().rev() {
            candidates.push(directory.join("MpCmdRun.exe"));
        }
    }

    candidates.push(PathBuf::from(
        r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    ));

    candidates.into_iter().find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::report::{Coverage, EngineStatus};

    fn target<'a>(path: &'a Path, size: u64) -> ScanTarget<'a> {
        ScanTarget {
            path,
            size,
            header: &[],
            content_type: crate::filetype::ContentType::Zip,
        }
    }

    /// Captured from a real run: EICAR inside a zip, `-DisableRemediation`.
    const THREAT_OUTPUT: &str = "\
Threat                  : Virus:DOS/EICAR_Test_File
Resources               : 2 total
    file                : C:\\Users\\Public\\vcd-scan-test\\eicar.zip->eicar.txt
    containerfile       : C:\\Users\\Public\\vcd-scan-test\\eicar.zip
-------------------------------------------------------------------------------
";

    #[test]
    fn zero_exit_is_a_complete_clean_scan() {
        let report = classify(
            "defender",
            0,
            "Scan starting...\r\nScan finished.\r\nScanning C:\\x\\a.exe found no threats.\r\n",
            Duration::from_millis(30),
        );

        assert_eq!(report.status, EngineStatus::Completed);
        assert!(report.detections.is_empty());
        assert_eq!(report.coverage, Coverage::Complete);
        assert!(
            report
                .facts
                .iter()
                .any(|fact| fact.value.contains("found no threats"))
        );
    }

    #[test]
    fn exit_two_reports_the_signature_from_a_real_capture() {
        let report = classify("defender", 2, THREAT_OUTPUT, Duration::from_millis(160));

        assert_eq!(report.detections.len(), 1);
        assert_eq!(report.detections[0].name, "defender-detection");
        assert_eq!(report.detections[0].severity, Severity::Malicious);
        assert_eq!(report.detections[0].detail, "Virus:DOS/EICAR_Test_File");
        assert!(
            report
                .facts
                .iter()
                .any(|fact| fact.name == "result" && fact.value == "Virus:DOS/EICAR_Test_File"),
            "the result fact should carry the signature, not the resource list"
        );
    }

    #[test]
    fn a_detection_without_a_threat_line_still_reports_the_evidence() {
        let report = classify("defender", 2, "something happened\r\n", Duration::ZERO);

        assert_eq!(report.detections.len(), 1);
        assert_eq!(report.detections[0].detail, "something happened");
    }

    #[test]
    fn other_exit_codes_are_failures() {
        let report = classify("defender", 1, "", Duration::ZERO);

        assert!(matches!(report.status, EngineStatus::Failed { .. }));
    }

    #[test]
    fn an_hresult_error_with_exit_two_is_a_failure_not_a_detection() {
        // Captured from a real run on this machine: MpCmdRun exits 2 when it
        // cannot scan, and exit 2 was being read as a detection.
        let captured = "CmdTool: Failed with hr = 0x80508023. Check \
                        C:\\Users\\x\\AppData\\Local\\Temp\\MpCmdRun.log for more information\r\n";
        let report = classify("defender", 2, captured, Duration::from_millis(58));

        assert!(matches!(report.status, EngineStatus::Failed { .. }));
        assert!(report.detections.is_empty());
    }

    #[test]
    fn evidence_is_capped() {
        let long = "x".repeat(MAX_EVIDENCE_CHARS * 2);
        let report = classify("defender", 0, &long, Duration::ZERO);

        let evidence = report
            .facts
            .iter()
            .find(|fact| fact.name == "result")
            .expect("result fact");
        assert_eq!(evidence.value.chars().count(), MAX_EVIDENCE_CHARS);
        assert!(evidence.value.ends_with("..."));
    }

    #[test]
    fn missing_engine_is_unavailable() {
        let report = DefenderEngine { executable: None }.scan(&target(Path::new("x"), 10));

        assert!(matches!(report.status, EngineStatus::Unavailable { .. }));
    }

    #[test]
    fn an_unspawnable_executable_is_a_failure() {
        let engine = DefenderEngine::with_executable(PathBuf::from(
            r"C:\definitely-not-a-real-binary\MpCmdRun.exe",
        ));
        let report = engine.scan(&target(Path::new("x"), 10));

        assert!(matches!(report.status, EngineStatus::Failed { .. }));
    }
}
