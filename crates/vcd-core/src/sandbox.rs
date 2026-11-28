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
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

mod capabilities;
mod sandboxie;
mod sandboxie_install;

pub use capabilities::{Backend, Edition, SandboxSupport, detect_support, enable_windows_sandbox};
pub use sandboxie_install::install as install_sandboxie;

const RUN_SCRIPT: &str = include_str!("sandbox/run.ps1");
const SANDBOX_DESKTOP: &str = r"C:\Users\WDAGUtilityAccount\Desktop";
const SESSION_IMAGES: [&str; 2] = [
    "WindowsSandboxRemoteSession.exe",
    "WindowsSandboxServer.exe",
];

/// The guest writes `out/result.json` and `out` is mapped writable, so the
/// report is hostile input: a huge one must not take the host down with it.
const MAX_REPORT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REPORT_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
pub struct DetonateOptions {
    /// How long the sample is allowed to run inside the sandbox.
    pub duration: Duration,
    /// Wall clock for boot, run and collection. Sandboxie never waits less than
    /// `duration + 30 s`, because it still has to boot the box and drain
    /// telemetry after the sample is done.
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SandboxReport {
    #[serde(default)]
    pub(crate) executed: bool,
    #[serde(default)]
    pub(crate) unsupported: Option<String>,
    #[serde(default)]
    pub(crate) error: Option<String>,
    #[serde(default)]
    pub(crate) finished: bool,
    #[serde(default)]
    pub(crate) sample: Option<String>,
    #[serde(default)]
    pub(crate) processes: Vec<SandboxProcess>,
    #[serde(default)]
    pub(crate) connections: Vec<SandboxConnection>,
    #[serde(default)]
    pub(crate) dns: Vec<String>,
    #[serde(default)]
    pub(crate) files_created: Vec<String>,
    #[serde(default)]
    pub(crate) files_modified: Vec<String>,
    #[serde(default)]
    pub(crate) registry_changed: Vec<String>,
    /// How the sample process ended, measured from the guest's own clock.
    #[serde(default)]
    pub(crate) sample_exit_ms: Option<u64>,
    #[serde(default)]
    pub(crate) sample_exit_code: Option<i64>,
    /// The process the run is about: the sample, or the interpreter that runs a
    /// script. Everything else in `processes` is context.
    #[serde(default)]
    pub(crate) sample_pid: Option<u32>,
    /// True only when the guest confirmed that real-time protection is off.
    #[serde(default)]
    pub(crate) defender_disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detonation {
    pub sample: PathBuf,
    pub workspace: PathBuf,
    pub backend: Backend,
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
    detonate_with(sample, options, Backend::WindowsSandbox)
}

/// Run the sample in the requested backend. The caller chooses; this never
/// silently downgrades a VM boundary to a shared-kernel sandbox.
pub fn detonate_with(
    sample: &Path,
    options: &DetonateOptions,
    backend: Backend,
) -> Result<Detonation, SandboxError> {
    // One detonation at a time per session: two runs would share the Sandboxie
    // box, and the VM teardown cannot tell whose session it is looking at.
    let _lock = DetonationLock::acquire()
        .ok_or_else(|| SandboxError::Launch("another detonation is already running".to_string()))?;

    match backend {
        Backend::WindowsSandbox => detonate_windows(sample, options),
        Backend::Sandboxie => {
            let paths = sandboxie::discover().ok_or_else(|| {
                SandboxError::Launch(
                    "Sandboxie-Plus is not installed (Start.exe not found)".to_string(),
                )
            })?;
            sandboxie::detonate(sample, options, &paths)
        }
    }
}

fn detonate_windows(sample: &Path, options: &DetonateOptions) -> Result<Detonation, SandboxError> {
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
    fs::write(
        out.join("duration.txt"),
        options.duration.as_secs().to_string(),
    )?;
    fs::write(out.join("run.ps1"), RUN_SCRIPT)?;

    let wsb = workspace.join("detonation.wsb");
    fs::write(&wsb, wsb_config(&payload, &out, options.network))?;

    let known_sessions = sandbox_processes();
    Command::new("explorer.exe")
        .arg(&wsb)
        .spawn()
        .map_err(|error| SandboxError::Launch(error.to_string()))?;

    // Only the session this run launched may be torn down: another process (or
    // another app window) can have its own Windows Sandbox running at the same
    // time. The guard covers every exit path after the session is identified.
    let session = match wait_for_session(&known_sessions) {
        Ok(session) => session,
        Err(error) => {
            // The launch was ours, but a session that appears now may belong to
            // someone else. The guest stops itself after its duration, so it is
            // left alone instead of killing another window.
            return Err(error);
        }
    };
    let guard = SessionGuard {
        session,
        known: known_sessions,
    };

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
        stop_session(&guard.session, &guard.known);
        // Whatever the guest managed to write before we pulled the plug.
        report = read_report(&result_path);
    }

    let report = report.unwrap_or_default();
    let dropped = dropped_files(&out.join("dropped"));

    let mut caveats = vec![format!(
        "networking {}",
        if options.network {
            "enabled"
        } else {
            "disabled"
        }
    )];
    caveats.push(
        "telemetry is written from inside the sandbox; a sample that targets the harness can tamper with it".to_string(),
    );
    if report.defender_disabled == Some(true) {
        caveats.push(
            "real-time protection inside the disposable sandbox was disabled for the run, so the sample can act"
                .to_string(),
        );
    }
    caveats.push("no observed behaviour is not proof of benign behaviour".to_string());
    if timed_out {
        caveats.push(format!(
            "the sandbox was stopped after {} s without a final report",
            options.timeout.as_secs()
        ));
    }
    if let Some(exit_ms) = report.sample_exit_ms {
        caveats.push(describe_exit(exit_ms, report.sample_exit_code));
        if exited_before_acting(&report) {
            caveats.push(
                "it exited before acting: the guest's real-time protection can block a sample, and nothing observed is not proof of benign behaviour"
                    .to_string(),
            );
        }
    }

    Ok(Detonation {
        sample: sample.to_path_buf(),
        workspace,
        backend: Backend::WindowsSandbox,
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

pub(crate) fn workspace_dir() -> PathBuf {
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

pub(crate) fn read_report(path: &Path) -> Option<SandboxReport> {
    // `out` is writable from inside the guest, so the report is hostile input:
    // an oversized one must not take the host down with it.
    let file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_REPORT_BYTES {
        return None;
    }

    let mut text = String::new();
    let mut handle = file.take(MAX_REPORT_BYTES);
    handle.read_to_string(&mut text).ok()?;
    // Windows PowerShell 5.1 writes UTF-8 with a BOM unless told otherwise, and
    // older builds of the guest script did exactly that.
    let text = text.trim_start_matches('\u{feff}');

    let mut report: SandboxReport = serde_json::from_str(text).ok()?;
    report.processes.truncate(MAX_REPORT_ENTRIES);
    report.connections.truncate(MAX_REPORT_ENTRIES);
    report.dns.truncate(MAX_REPORT_ENTRIES);
    report.files_created.truncate(MAX_REPORT_ENTRIES);
    report.files_modified.truncate(MAX_REPORT_ENTRIES);
    report.registry_changed.truncate(MAX_REPORT_ENTRIES);
    Some(report)
}

/// The sample and everything that descends from it, by parent link. Guest noise
/// (RuntimeBroker, smartscreen, the shell) is not part of it.
pub(crate) fn sample_tree(report: &SandboxReport) -> std::collections::HashSet<u32> {
    let mut ids = std::collections::HashSet::new();
    if let Some(root) = report.sample_pid {
        ids.insert(root);
    }

    loop {
        let before = ids.len();
        for process in &report.processes {
            if ids.contains(&process.parent) {
                ids.insert(process.pid);
            }
        }
        if ids.len() == before {
            break;
        }
    }

    ids
}

/// A sample that died immediately and left nothing behind is more likely to have
/// been blocked than to have done nothing. A process count is not a portable
/// test: one backend records every guest process, the other only the sample tree.
pub(crate) fn exited_before_acting(report: &SandboxReport) -> bool {
    if !report.sample_exit_ms.is_some_and(|exit_ms| exit_ms < 2_000) {
        return false;
    }

    let tree = sample_tree(report);
    let descendants = tree
        .iter()
        .filter(|pid| Some(**pid) != report.sample_pid)
        .count();

    descendants == 0
        && report.files_created.is_empty()
        && !report
            .connections
            .iter()
            .any(|connection| tree.contains(&connection.pid))
}
/// Windows status values a sample most often dies with before it can act. The
/// number alone says nothing to a person; the reason is the useful part.
fn exit_code_hint(code: i64) -> Option<&'static str> {
    Some(match code as u32 {
        0xC000_0135 => "a DLL it needs is not present in the sandbox",
        0xC000_0139 => "an entry point it needs is missing",
        0xC000_007B => "the image is for another architecture or is corrupted",
        0xC000_0005 => "it crashed with an access violation",
        0xC000_0142 => "a DLL it needs could not initialize",
        0xC000_012F => "the image is not a valid Windows application",
        _ => return None,
    })
}

/// How the sample ended, in words the report can show as-is.
pub(crate) fn describe_exit(exit_ms: u64, code: Option<i64>) -> String {
    match code {
        Some(code) => {
            let hint = exit_code_hint(code)
                .map(|hint| format!(" ({hint})"))
                .unwrap_or_default();
            format!("the sample process exited after {exit_ms} ms with code {code}{hint}")
        }
        None => format!("the sample process exited after {exit_ms} ms"),
    }
}

fn dropped_files(directory: &Path) -> Vec<PathBuf> {
    // The guest can write this folder directly, so the listing is capped.
    const MAX_DROPPED_LISTED: usize = 256;

    let mut files: Vec<PathBuf> = fs::read_dir(directory)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    files.sort();
    files.truncate(MAX_DROPPED_LISTED);
    files
}

fn wait_for_session(known: &[(String, u32)]) -> Result<u32, SandboxError> {
    let deadline = Instant::now() + Duration::from_secs(45);

    while Instant::now() < deadline {
        let appeared = sandbox_processes().into_iter().find(|(name, pid)| {
            name.as_str() == SESSION_IMAGES[0] && !known.iter().any(|(_, known)| known == pid)
        });
        if let Some((_, pid)) = appeared {
            return Ok(pid);
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Err(SandboxError::Launch(
        "no Windows Sandbox session appeared within 45 s".to_string(),
    ))
}

/// Tears down the one session this run launched, on every exit path.
struct SessionGuard {
    session: u32,
    known: Vec<(String, u32)>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        stop_session(&self.session, &self.known);
    }
}

/// One detonation at a time per session. Two runs would share the Sandboxie box
/// and the VM teardown cannot tell whose session it is looking at. A named
/// mutex is released by the kernel when the process dies, so a crash cannot
/// leave a stale lock behind.
struct DetonationLock {
    handle: *mut std::ffi::c_void,
}

impl DetonationLock {
    fn acquire() -> Option<Self> {
        use std::os::windows::ffi::OsStrExt;

        unsafe extern "system" {
            fn CreateMutexW(
                attributes: *mut std::ffi::c_void,
                owner: i32,
                name: *const u16,
            ) -> *mut std::ffi::c_void;
            fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }

        let name: Vec<u16> = std::ffi::OsStr::new(r"Local\VirusCheckDesktop.Detonation")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr()) };
        if handle.is_null() {
            return None;
        }

        // WAIT_OBJECT_0 = acquired; anything else means someone holds it.
        if unsafe { WaitForSingleObject(handle, 0) } == 0 {
            Some(Self { handle })
        } else {
            unsafe { CloseHandle(handle) };
            None
        }
    }
}

impl Drop for DetonationLock {
    fn drop(&mut self) {
        unsafe extern "system" {
            fn ReleaseMutex(handle: *mut std::ffi::c_void) -> i32;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }

        unsafe {
            ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

/// Kill our session tree, and the server behind it only when no other session is
/// running: a concurrent detonation owns its own VM.
fn stop_session(session: &u32, known: &[(String, u32)]) {
    let _ = crate::download::hidden_command("taskkill")
        .args(["/PID", &session.to_string(), "/T", "/F"])
        .output();

    let another_session = sandbox_processes()
        .iter()
        .any(|(name, _)| name.as_str() == SESSION_IMAGES[0]);

    if !another_session {
        stop_new_sessions(known);
    }
}

/// Kill every session that appeared after `known`, plus the servers behind them.
fn stop_new_sessions(known: &[(String, u32)]) {
    for (name, pid) in sandbox_processes() {
        if known
            .iter()
            .any(|(known_name, known_pid)| *known_name == name && *known_pid == pid)
        {
            continue;
        }
        let _ = crate::download::hidden_command("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output();
    }
}

fn sandbox_processes() -> Vec<(String, u32)> {
    let Ok(output) = crate::download::hidden_command("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    else {
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

    #[test]
    fn a_missing_dll_exit_is_explained() {
        // 0xC0000135, what a sample dies with when the sandbox lacks a runtime.
        let text = describe_exit(59, Some(-1_073_741_515));
        assert!(text.contains("exited after 59 ms"));
        assert!(text.contains("DLL"), "{text}");
    }

    #[test]
    fn every_documented_status_is_explained() {
        for (code, needle) in [
            (-1_073_741_515i64, "DLL it needs is not present"),
            (-1_073_741_511, "entry point it needs is missing"),
            (-1_073_741_701, "another architecture"),
            (-1_073_741_819, "access violation"),
            (-1_073_741_502, "could not initialize"),
            (-1_073_741_521, "not a valid Windows application"),
        ] {
            let text = describe_exit(1, Some(code));
            assert!(text.contains(needle), "{code:#x}: {text}");
        }
    }

    #[test]
    fn an_exit_without_a_code_reports_only_the_time() {
        assert_eq!(
            describe_exit(12_000, None),
            "the sample process exited after 12000 ms"
        );
    }

    fn sample_report(exit_ms: Option<u64>) -> SandboxReport {
        SandboxReport {
            sample_pid: Some(10),
            sample_exit_ms: exit_ms,
            processes: vec![
                SandboxProcess {
                    pid: 10,
                    parent: 1,
                    name: Some("sample.exe".to_string()),
                    path: None,
                    command: None,
                },
                SandboxProcess {
                    pid: 11,
                    parent: 10,
                    name: None,
                    path: None,
                    command: None,
                },
                SandboxProcess {
                    pid: 20,
                    parent: 5,
                    name: None,
                    path: None,
                    command: None,
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn the_sample_tree_follows_parent_links_only() {
        let tree = sample_tree(&sample_report(Some(10)));
        assert!(tree.contains(&10));
        assert!(tree.contains(&11));
        assert!(!tree.contains(&20), "guest noise is not part of the sample");
    }

    #[test]
    fn an_immediate_exit_without_descendants_is_flagged() {
        let mut report = sample_report(Some(59));
        report.processes.truncate(1);
        assert!(exited_before_acting(&report));

        report.files_created.push("a file".to_string());
        assert!(!exited_before_acting(&report), "a file proves it acted");
    }

    #[test]
    fn a_late_exit_is_not_flagged() {
        assert!(!exited_before_acting(&sample_report(Some(20_000))));
        assert!(!exited_before_acting(&sample_report(None)));
    }

    #[test]
    fn the_guest_writes_state_before_the_defender_call() {
        let save = RUN_SCRIPT.find("Save-State").expect("state write");
        let defender = RUN_SCRIPT.find("Set-MpPreference").expect("defender call");
        assert!(save < defender);
    }

    fn report_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vcd-report-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn a_complete_report_round_trips() {
        let path = report_path("ok");
        fs::write(&path, r#"{"executed":true,"finished":true,"processes":[]}"#)
            .expect("write report");

        let report = read_report(&path).expect("parse report");
        assert!(report.executed);
        assert!(report.finished);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn an_oversized_report_is_rejected_instead_of_parsed() {
        let path = report_path("huge");
        let padding = "a".repeat(MAX_REPORT_BYTES as usize + 1);
        fs::write(&path, format!(r#"{{"error":"{padding}"}}"#)).expect("write report");

        assert!(read_report(&path).is_none());

        let _ = fs::remove_file(&path);
    }
}
