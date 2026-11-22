//! ClamAV engine.
//!
//! Preferred path: a managed `clamd` (see [`super::clamd`]) scanned through
//! `clamdscan`, so the signature database loads once instead of per file. If no
//! daemon can be started, it falls back to one `clamscan` process per file and
//! says so, because that cost is real and the report should carry it.
//!
//! ClamAV is always a separate process, never linked: its license is GPLv2 and
//! its database updates on its own schedule. Its per-file cap is reported as
//! [`Coverage`]: a 3 GiB file that ClamAV refused to open must not look clean.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::report::{Coverage, Detection, EngineReport, Fact, Severity};

use super::clamd::{ClamDaemon, MAX_SCAN_BYTES, discover_paths};
use super::{Engine, ScanTarget};

const SCAN_TIMEOUT: Duration = Duration::from_secs(600);

const HINT: &str = "ClamAV not found: install it and put clamscan.exe on PATH \
     (https://docs.clamav.net/manual/Installing.html) or in C:\\Program Files\\ClamAV";

enum Mode {
    Unavailable(String),
    /// Managed daemon plus the `clamdscan` client that talks to it.
    Daemon { daemon: ClamDaemon, client: PathBuf },
    Clamscan(PathBuf),
}

pub struct ClamAvEngine {
    mode: Mode,
    daemon_note: Option<String>,
}

impl ClamAvEngine {
    /// Prefer a daemon; fall back to per-file processes, and record why.
    pub fn discover(use_daemon: bool) -> Self {
        let paths = discover_paths();
        let Some(scan) = paths.scan else {
            return Self {
                mode: Mode::Unavailable(HINT.to_string()),
                daemon_note: None,
            };
        };

        let mut note = None;

        if use_daemon
            && let (Some(daemon), Some(database)) = (paths.daemon, paths.database)
        {
            let client = scan.with_file_name("clamdscan.exe");
            if client.is_file() {
                match ClamDaemon::start(&daemon, &database) {
                    Ok(daemon) => {
                        return Self {
                            mode: Mode::Daemon { daemon, client },
                            daemon_note: Some("clamd".to_string()),
                        };
                    }
                    Err(error) => note = Some(format!("clamd unavailable: {error}")),
                }
            } else {
                note = Some("clamdscan.exe not found next to clamscan.exe".to_string());
            }
        } else if !use_daemon {
            note = Some("single-file scan: clamscan, no daemon startup".to_string());
        }

        Self {
            mode: Mode::Clamscan(scan),
            daemon_note: note,
        }
    }

    pub fn with_executable(executable: PathBuf) -> Self {
        Self {
            mode: Mode::Clamscan(executable),
            daemon_note: None,
        }
    }
}

impl Engine for ClamAvEngine {
    fn name(&self) -> &'static str {
        "clamav"
    }

    fn scan(&self, target: &ScanTarget<'_>) -> EngineReport {
        let (program, prefix) = match &self.mode {
            Mode::Unavailable(hint) => return EngineReport::unavailable(self.name(), hint.clone()),
            Mode::Daemon { daemon, client } => {
                (client.as_path(), vec![OsString::from("-c"), daemon.config().as_os_str().to_owned()])
            }
            Mode::Clamscan(path) => (path.as_path(), Vec::new()),
        };

        let started = Instant::now();

        if target.size > MAX_SCAN_BYTES {
            return EngineReport::completed(
                self.name(),
                Vec::new(),
                Coverage::Partial {
                    scanned_bytes: 0,
                    reason: "ClamAV refuses a single file above 2 GiB (--max-filesize)".to_string(),
                },
                started.elapsed(),
            )
            .with_facts(vec![Fact::new(
                "skipped",
                "file exceeds ClamAV's per-file cap; no signature check was performed",
            )]);
        }

        let output_path = temp_output_path();
        let outcome = run_scan(program, &prefix, target.path, &output_path);
        let stdout = read_text(&output_path).unwrap_or_default();
        let _ = std::fs::remove_file(&output_path);

        let exit_code = match outcome {
            Ok(code) => code,
            Err(RunError::Timeout) => {
                return EngineReport::failed(
                    self.name(),
                    format!("ClamAV timed out after {}s", SCAN_TIMEOUT.as_secs()),
                );
            }
            Err(RunError::Io(error)) => {
                return EngineReport::failed(self.name(), format!("cannot run ClamAV: {error}"));
            }
        };

        if exit_code > 1 {
            return EngineReport::failed(
                self.name(),
                format!("ClamAV exited with code {exit_code}"),
            );
        }

        let detections = parse_found(&stdout);
        let mut facts = vec![Fact::new(
            "signatures",
            format!("{} detection(s) reported by ClamAV", detections.len()),
        )];
        facts.push(Fact::new(
            "mode",
            match &self.mode {
                Mode::Daemon { .. } => "clamd (database loaded once)",
                _ => "clamscan (database loaded per file)",
            },
        ));
        if let Some(note) = &self.daemon_note {
            facts.push(Fact::new("daemon", note.clone()));
        }

        EngineReport::completed(
            self.name(),
            detections,
            Coverage::Complete,
            started.elapsed(),
        )
        .with_facts(facts)
    }
}

/// `path: Signature.Name FOUND` -> one malicious detection per signature.
fn parse_found(stdout: &str) -> Vec<Detection> {
    let mut detections: Vec<Detection> = Vec::new();

    for line in stdout.lines() {
        let Some((_, tail)) = line.trim().rsplit_once(": ") else {
            continue;
        };
        let Some(signature) = tail.strip_suffix(" FOUND") else {
            continue;
        };
        if signature.is_empty()
            || detections
                .iter()
                .any(|detection| detection.detail == signature)
        {
            continue;
        }

        detections.push(Detection {
            name: "clamav-signature".to_string(),
            severity: Severity::Malicious,
            detail: signature.to_string(),
        });
    }

    detections
}

enum RunError {
    Io(io::Error),
    Timeout,
}

fn run_scan(
    program: &Path,
    prefix: &[OsString],
    target: &Path,
    output: &Path,
) -> Result<i32, RunError> {
    // Stdout goes to a file, not a pipe: a pipe nobody drains deadlocks the
    // child, and the timeout would then be indistinguishable from a slow scan.
    let sink = File::create(output).map_err(RunError::Io)?;

    let mut command = Command::new(program);
    command.args(prefix);
    command
        .arg("--no-summary")
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::from(sink))
        .stderr(Stdio::null());

    let mut child = command.spawn().map_err(RunError::Io)?;

    let deadline = Instant::now() + SCAN_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code().unwrap_or(2)),
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
    std::env::temp_dir().join(format!("vcd-clamav-{}-{unique}.log", std::process::id()))
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
            content_type: crate::filetype::ContentType::Pe,
        }
    }

    #[test]
    fn parses_found_lines_and_ignores_noise() {
        let stdout = "\
LibClamAV Warning: something odd
C:\\samples\\eicar.com: Win.Test.EICAR_HDB-1 FOUND
C:\\samples\\eicar.com: Win.Test.EICAR_HDB-1 FOUND
C:\\samples\\clean.txt: OK
";
        let detections = parse_found(stdout);

        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].name, "clamav-signature");
        assert_eq!(detections[0].severity, Severity::Malicious);
        assert_eq!(detections[0].detail, "Win.Test.EICAR_HDB-1");
    }

    #[test]
    fn clean_output_yields_no_detections() {
        assert!(parse_found("C:\\a\\b.exe: OK\n").is_empty());
        assert!(parse_found("").is_empty());
    }

    #[test]
    fn missing_engine_is_unavailable_not_failed() {
        let engine = ClamAvEngine {
            mode: Mode::Unavailable("not installed".to_string()),
            daemon_note: None,
        };
        let report = engine.scan(&target(Path::new("x"), 10));

        assert!(matches!(report.status, EngineStatus::Unavailable { .. }));
        assert!(!report.coverage.inspected());
    }

    #[test]
    fn files_above_the_clamav_cap_are_reported_as_uninspected() {
        let engine = ClamAvEngine::with_executable(PathBuf::from(r"C:\nope\clamscan.exe"));
        let report = engine.scan(&target(Path::new("huge.bin"), MAX_SCAN_BYTES + 1));

        assert_eq!(
            report.coverage,
            Coverage::Partial {
                scanned_bytes: 0,
                reason: "ClamAV refuses a single file above 2 GiB (--max-filesize)".to_string()
            }
        );
        assert!(!report.coverage.inspected());
        assert!(report.detections.is_empty());
    }

    #[test]
    fn an_unspawnable_executable_is_a_failure() {
        let engine = ClamAvEngine::with_executable(PathBuf::from(
            r"C:\definitely-not-a-real-binary\clamscan.exe",
        ));
        let report = engine.scan(&target(Path::new("x"), 10));

        assert!(matches!(report.status, EngineStatus::Failed { .. }));
    }
}
