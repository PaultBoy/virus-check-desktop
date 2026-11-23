//! Windows Sandbox detonation.
//!
//! The sample is copied into a read-only mapped folder and run inside a
//! disposable Windows Sandbox. A script inside the sandbox records processes,
//! TCP connections, DNS lookups, file drops and Run-key changes, and writes the
//! result into a writable mapped folder that the host reads back.
//!
//! Limits that are stated, not hidden:
//!
//! - Networking is **disabled** unless the caller asks for it.
//! - The report is written by the guest. A sample that targets the harness can
//!   tamper with or delete it, so "nothing observed" is not "nothing happened".
//! - Only types Windows can execute are run; anything else is reported as
//!   unsupported instead of faking a detonation.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const RUN_SCRIPT: &str = include_str!("sandbox/run.ps1");
const SANDBOX_DESKTOP: &str = r"C:\Users\WDAGUtilityAccount\Desktop";
const SESSION_IMAGES: [&str; 2] = ["WindowsSandboxRemoteSession.exe", "WindowsSandboxServer.exe"];

#[derive(Debug, Clone)]
pub struct DetonateOptions {
    /// How long the sample is allowed to run inside the sandbox.
    pub duration: Duration,
    /// Wall clock for boot, run and collection.
    pub timeout: Duration,
    pub network: bool,
}

impl Default for DetonateOptions {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(30),
            timeout: Duration::from_secs(120),
            network: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("cannot prepare the sandbox: {0}")]
    Io(#[from] io::Error),
    #[error("Windows Sandbox did not start: {0}")]
    Launch(String),
    #[error("the sandbox reported no result within {0} s")]
    NoResult(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProcess {
    pub pid: u32,
    pub parent: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConnection {
    pub remote: String,
    pub pid: u32,
    #[serde(default)]
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SandboxReport {
    #[serde(default)]
    executed: bool,
    #[serde(default)]
    unsupported: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    finished: bool,
    #[serde(default)]
    sample: Option<String>,
    #[serde(default)]
    processes: Vec<SandboxProcess>,
    #[serde(default)]
    connections: Vec<SandboxConnection>,
    #[serde(default)]
    dns: Vec<String>,
    #[serde(default)]
    files_created: Vec<String>,
    #[serde(default)]
    files_modified: Vec<String>,
    #[serde(default)]
    registry_changed: Vec<String>,
}

impl Default for SandboxReport {
    fn default() -> Self {
        Self {
            executed: false,
            unsupported: None,
            error: None,
            finished: false,
            sample: None,
            processes: Vec::new(),
            connections: Vec::new(),
            dns: Vec::new(),
            files_created: Vec::new(),
            files_modified: Vec::new(),
            registry_changed: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detonation {
    pub sample: PathBuf,
    pub workspace: PathBuf,
    pub network_enabled: bool,
    pub executed: bool,
    pub unsupported: Option<String>,
    pub error: Option<String>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub processes: Vec<SandboxProcess>,
    pub connections: Vec<SandboxConnection>,
    pub dns: Vec<String>,
    pub files_created: Vec<String>,
    pub files_modified: Vec<String>,
    pub registry_changed: Vec<String>,
    /// Host paths of dropped files copied out of the sandbox (max 10, 5 MiB each).
    pub dropped: Vec<PathBuf>,
    pub caveats: Vec<String>,
}

pub fn detonate(sample: &Path, options: &DetonateOptions) -> Result<Detonation, SandboxError> {
    if !sample.is_file() {
        return Err(SandboxError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("not a regular file: {}", sample.display()),
        )));
    }

    let started = Instant::now();
    let workspace = workspace_dir();
    let payload = workspace.join("payload");
    let out = workspace.join("out");
    fs::create_dir_all(&payload)?;
    fs::create_dir_all(&out)?;

    let name = sample
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sample.bin");
    fs::copy(sample, payload.join(sanitize(name)))?;
    fs::write(out.join("duration.txt"), options.duration.as_secs().to_string())?;
    fs::write(out.join("run.ps1"), RUN_SCRIPT)?;

    let wsb = workspace.join("detonation.wsb");
    fs::write(&wsb, wsb_config(&payload, &out, options.network))?;

    let known_sessions = sandbox_processes();
    Command::new("explorer.exe")
        .arg(&wsb)
        .spawn()
        .map_err(|error| SandboxError::Launch(error.to_string()))?;

    wait_for_session(&known_sessions)?;

    let result_path = out.join("result.json");
    let deadline = Instant::now() + options.timeout;
    let mut report = None;

    while Instant::now() < deadline {
        if let Some(parsed) = read_report(&result_path)
            && parsed.finished
        {
            report = Some(parsed);
            break;
        }
        std::thread::sleep(Duration::from_millis(400));
    }

    let timed_out = report.is_none();
    if timed_out {
        stop_new_sessions(&known_sessions);
        // Whatever the guest managed to write before we pulled the plug.
        report = read_report(&result_path);
    }

    let report = report.unwrap_or_default();
    let dropped = dropped_files(&out.join("dropped"));

    let mut caveats = vec![format!(
        "networking {}",
        if options.network { "enabled" } else { "disabled" }
    )];
    caveats.push(
        "telemetry is written from inside the sandbox; a sample that targets the harness can tamper with it".to_string(),
    );
    caveats.push(
        "no observed behaviour is not proof of benign behaviour".to_string(),
    );
    if timed_out {
        caveats.push(format!(
            "the sandbox was stopped after {} s without a final report",
            options.timeout.as_secs()
        ));
    }

    Ok(Detonation {
        sample: sample.to_path_buf(),
        workspace,
        network_enabled: options.network,
        executed: report.executed,
        unsupported: report.unsupported.clone(),
        error: report.error.clone(),
        timed_out,
        duration_ms: started.elapsed().as_millis() as u64,
        processes: report.processes,
        connections: report.connections,
        dns: report.dns,
        files_created: report.files_created,
        files_modified: report.files_modified,
        registry_changed: report.registry_changed,
        dropped,
        caveats,
    })
}

fn workspace_dir() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("VirusCheckDesktop")
        .join("detonations")
        .join(stamp.to_string())
}

fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => character,
            _ => '_',
        })
        .collect();

    if cleaned.is_empty() {
        "sample.bin".to_string()
    } else {
        cleaned
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn wsb_config(payload: &Path, out: &Path, network: bool) -> String {
    format!(
        r#"<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{payload}</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{out}</HostFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <Networking>{networking}</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <LogonCommand>
    <Command>powershell -NoProfile -ExecutionPolicy Bypass -File {desktop}\out\run.ps1</Command>
  </LogonCommand>
</Configuration>
"#,
        payload = xml_escape(&payload.display().to_string()),
        out = xml_escape(&out.display().to_string()),
        networking = if network { "Enable" } else { "Disable" },
        desktop = SANDBOX_DESKTOP,
    )
}

fn read_report(path: &Path) -> Option<SandboxReport> {
    let text = fs::read_to_string(path).ok()?;
    // Windows PowerShell 5.1 writes UTF-8 with a BOM unless told otherwise, and
    // older builds of the guest script did exactly that.
    let text = text.trim_start_matches('\u{feff}');
    serde_json::from_str(text).ok()
}

fn dropped_files(directory: &Path) -> Vec<PathBuf> {
    fs::read_dir(directory)
        .map(|entries| {
            let mut files: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
            files.sort();
            files
        })
        .unwrap_or_default()
}

fn wait_for_session(known: &[(String, u32)]) -> Result<(), SandboxError> {
    let deadline = Instant::now() + Duration::from_secs(45);

    while Instant::now() < deadline {
        let appeared = sandbox_processes().iter().any(|(name, pid)| {
            name == SESSION_IMAGES[0] && !known.iter().any(|(_, known)| known == pid)
        });
        if appeared {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Err(SandboxError::Launch(
        "no Windows Sandbox session appeared within 45 s".to_string(),
    ))
}

/// Kill the session *and* the server that keeps the VM alive: killing only the
/// session leaves `WindowsSandboxServer` and the VM behind.
fn stop_new_sessions(known: &[(String, u32)]) {
    for (name, pid) in sandbox_processes() {
        if known.iter().any(|(known_name, known_pid)| {
            *known_name == name && *known_pid == pid
        }) {
            continue;
        }
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output();
    }
}

fn sandbox_processes() -> Vec<(String, u32)> {
    let Ok(output) = Command::new("tasklist").args(["/FO", "CSV", "/NH"]).output() else {
        return Vec::new();
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('"').collect();
            let name = fields.get(1)?.to_string();
            if !SESSION_IMAGES.iter().any(|image| *image == name) {
                return None;
            }
            let pid = fields.get(3)?.trim().parse::<u32>().ok()?;
            Some((name, pid))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_maps_both_folders_and_can_disable_networking() {
        let config = wsb_config(
            Path::new(r"C:\work\payload"),
            Path::new(r"C:\work\out"),
            false,
        );

        assert!(config.contains(r"<HostFolder>C:\work\payload</HostFolder>"));
        assert!(config.contains(r"<HostFolder>C:\work\out</HostFolder>"));
        assert!(config.contains("<Networking>Disable</Networking>"));
        assert!(config.contains("<ReadOnly>true</ReadOnly>"));
        assert!(config.contains(r"Desktop\out\run.ps1"));
        assert!(config.contains("<ClipboardRedirection>Disable</ClipboardRedirection>"));
    }

    #[test]
    fn enabling_network_is_explicit() {
        let config = wsb_config(Path::new("p"), Path::new("o"), true);
        assert!(config.contains("<Networking>Enable</Networking>"));
    }

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize("evil file (1).exe"), "evil_file__1_.exe");
        assert_eq!(sanitize(""), "sample.bin");
        assert_eq!(sanitize("a.bin"), "a.bin");
    }

    #[test]
    fn xml_special_characters_are_escaped() {
        let config = wsb_config(Path::new(r"C:\a&b"), Path::new(r"C:\c<d"), false);
        assert!(config.contains("C:\\a&amp;b"));
        assert!(config.contains("C:\\c&lt;d"));
    }

    #[test]
    fn a_missing_sample_is_an_error_not_an_empty_report() {
        let error = detonate(
            Path::new(r"C:\definitely-missing\vcd-sample.bin"),
            &DetonateOptions::default(),
        )
        .expect_err("missing sample");

        assert!(matches!(error, SandboxError::Io(_)));
    }
}
