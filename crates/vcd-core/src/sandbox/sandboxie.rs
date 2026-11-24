//! Sandboxie backend.
//!
//! Sandboxie runs the sample under a kernel-level sandbox on the same machine,
//! so it works where Windows Sandbox does not (Home). That is also its limit: a
//! driver flaw is an escape, and it is not a VM. The report says so.
//!
//! The host runs a watcher script while the sample executes inside the box:
//! process lineage, TCP connections, files redirected into the box root, and a
//! copy of dropped files. Registry writes land in the box's `RegHive` and are
//! not decoded, which is reported as a caveat rather than guessed.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use super::{Backend, DetonateOptions, Detonation, SandboxError, read_report, workspace_dir};

const WATCH_SCRIPT: &str = include_str!("sandboxie_watch.ps1");
pub(crate) const BOX: &str = "VCDDetonate";

pub(crate) struct Sandboxie {
    pub start: PathBuf,
    pub sbieini: PathBuf,
    pub box_root: PathBuf,
}

pub(crate) fn discover() -> Option<Sandboxie> {
    let start = [
        r"C:\Program Files\Sandboxie-Plus\Start.exe",
        r"C:\Program Files\Sandboxie\Start.exe",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|candidate| candidate.is_file())?;

    let sbieini = start.with_file_name("SbieIni.exe");
    if !sbieini.is_file() {
        return None;
    }

    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".to_string());
    let box_root = PathBuf::from(r"C:\Sandbox").join(user).join(BOX);

    Some(Sandboxie {
        start,
        sbieini,
        box_root,
    })
}

pub(crate) fn detonate(
    sample: &Path,
    options: &DetonateOptions,
    paths: &Sandboxie,
) -> Result<Detonation, SandboxError> {
    let started = Instant::now();
    let workspace = workspace_dir();
    fs::create_dir_all(&workspace)?;

    let result = workspace.join("result.json");
    let dropped_dir = workspace.join("dropped");
    configure_box(paths, options.network)?;

    let script = workspace.join("watch.ps1");
    fs::write(&script, WATCH_SCRIPT)?;

    let status = crate::download::hidden_command("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .arg("-StartExe")
        .arg(&paths.start)
        .arg("-Box")
        .arg(BOX)
        .arg("-Sample")
        .arg(sample)
        .arg("-Seconds")
        .arg(options.duration.as_secs().to_string())
        .arg("-Out")
        .arg(&result)
        .arg("-BoxRoot")
        .arg(&paths.box_root)
        .arg("-CopyTo")
        .arg(&dropped_dir)
        .spawn()?;

    let mut child = status;
    let deadline = Instant::now()
        + options
            .timeout
            .max(options.duration + std::time::Duration::from_secs(30));
    let mut timed_out = false;
    let mut exit = None;

    loop {
        match child.try_wait()? {
            Some(status) => {
                exit = Some(status);
                break;
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = Command::new(&paths.start)
                    .args([format!("/box:{BOX}"), "/terminate".to_string()])
                    .status();
                timed_out = true;
                break;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(200)),
        }
    }

    if !timed_out && !exit.map(|status| status.success()).unwrap_or(false) {
        return Err(SandboxError::Launch(
            "the Sandboxie watcher exited with a failure".to_string(),
        ));
    }

    // A watcher that never wrote a report tells us nothing: returning an empty
    // detonation as success would look like a clean run with no evidence.
    let Some(report) = read_report(&result) else {
        return Err(SandboxError::Launch(if timed_out {
            "the Sandboxie watcher was stopped before it wrote a report".to_string()
        } else {
            "the Sandboxie watcher finished without writing a report".to_string()
        }));
    };
    let dropped = dropped_files(&dropped_dir);

    let mut caveats = vec![
        "Sandboxie shares the Windows kernel: it is a sandbox, not a virtual machine".to_string(),
        format!(
            "network {} for the sandbox (AllowNetworkAccess)",
            if options.network {
                "allowed"
            } else {
                "blocked"
            }
        ),
        "registry writes are virtualized into the box's RegHive and are not decoded".to_string(),
        "processes are sampled by polling: very short-lived ones can be missed".to_string(),
        format!(
            "the box is kept at {} until it is deleted",
            paths.box_root.display()
        ),
    ];
    if report.processes.is_empty() {
        caveats.push(
            "no process could be tied to the sample; absence of behaviour is not proof of safety"
                .to_string(),
        );
    }

    Ok(Detonation {
        sample: sample.to_path_buf(),
        workspace,
        backend: Backend::Sandboxie,
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

/// Create or update the box, set network policy, and empty it before the run.
fn configure_box(paths: &Sandboxie, network: bool) -> Result<(), SandboxError> {
    for (key, value) in [
        ("Enabled", "y"),
        ("AllowNetworkAccess", if network { "y" } else { "n" }),
    ] {
        let output = crate::download::hidden_command(&paths.sbieini)
            .args(["set", BOX, key, value])
            .output()?;
        if !output.status.success() {
            return Err(SandboxError::Io(io::Error::other(format!(
                "SbieIni could not set {key}"
            ))));
        }
    }

    let _ = Command::new(&paths.start).arg("/reload").status();
    let _ = Command::new(&paths.start)
        .args([format!("/box:{BOX}"), "delete_sandbox_silent".to_string()])
        .status();

    Ok(())
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
