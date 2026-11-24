//! Managed `clamd` instance.
//!
//! `clamscan` loads the whole signature database on every process start (~6 s
//! per file on this machine), so scanning more than one file that way is
//! hopeless. This module owns a `clamd` for the lifetime of the process:
//!
//! - config and logs under `%LOCALAPPDATA%\VirusCheckDesktop\clamav`;
//! - a fixed loopback port, so a daemon left behind by a previous run is
//!   reused instead of piling up;
//! - a later run adopts a listener only when `clamd.pid` names a live `clamd.exe`
//!   that also answers `clamdscan --ping`; anything else holding the port is
//!   refused and the engine falls back to `clamscan` with the reason recorded;
//! - dropping the handle stops the daemon this run started or verified.

use std::fs;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const DAEMON_PORT: u16 = 3311;
const START_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);
/// Written by clamd itself, which is what makes it evidence of ownership.
const PID_FILE: &str = "clamd.pid";

/// A single file above this is refused by ClamAV itself.
pub(crate) const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(crate) struct ClamPaths {
    pub scan: Option<PathBuf>,
    pub daemon: Option<PathBuf>,
    pub database: Option<PathBuf>,
}

pub(crate) fn discover_paths() -> ClamPaths {
    let mut roots: Vec<PathBuf> = vec![
        PathBuf::from(r"C:\Program Files\ClamAV"),
        PathBuf::from(r"C:\ClamAV"),
    ];
    if let Some(portable) = crate::clamav_install::portable_root() {
        roots.push(portable);
    }

    // A coherent installation is one root that has both the binaries and a
    // database; mixing a system clamscan with a portable database would report
    // signatures that do not belong to that engine. When both exist, the one
    // with the newest database wins, so a stale copy never hides a fresh one.
    let install = freshest(&roots).or_else(|| {
        roots
            .iter()
            .find(|root| root.join("clamscan.exe").is_file())
            .cloned()
    });

    let scan = install
        .as_ref()
        .map(|root| root.join("clamscan.exe"))
        .filter(|candidate| candidate.is_file())
        .or_else(|| find_binary("clamscan", Path::new(r"C:\Program Files\ClamAV")));

    let daemon = install
        .as_ref()
        .map(|root| root.join("clamd.exe"))
        .filter(|candidate| candidate.is_file())
        .or_else(|| find_binary("clamd", Path::new(r"C:\Program Files\ClamAV")));

    let database = install
        .as_ref()
        .map(|root| root.join("database"))
        .filter(|directory| {
            directory.join("daily.cvd").is_file() || directory.join("daily.cld").is_file()
        });

    ClamPaths {
        scan,
        daemon,
        database,
    }
}

fn freshest(roots: &[PathBuf]) -> Option<PathBuf> {
    roots
        .iter()
        .filter(|root| root.join("clamscan.exe").is_file())
        .filter_map(|root| database_time(root).map(|time| (time, root)))
        .max_by_key(|(time, _)| *time)
        .map(|(_, root)| root.clone())
}

fn database_time(root: &Path) -> Option<std::time::SystemTime> {
    let database = root.join("database");
    [database.join("daily.cld"), database.join("daily.cvd")]
        .into_iter()
        .filter_map(|path| std::fs::metadata(path).ok()?.modified().ok())
        .max()
}

fn find_binary(name: &str, install: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            candidates.push(directory.join(format!("{name}.exe")));
            candidates.push(directory.join(name));
        }
    }
    candidates.push(install.join(format!("{name}.exe")));
    candidates.push(Path::new(r"C:\ClamAV").join(format!("{name}.exe")));

    candidates.into_iter().find(|candidate| candidate.is_file())
}

pub(crate) struct ClamDaemon {
    config: PathBuf,
    child: Option<Child>,
}

impl ClamDaemon {
    /// Start a daemon, or adopt one already listening on the configured port.
    pub fn start(daemon: &Path, database: &Path) -> Result<Self, String> {
        let work_dir = work_dir();
        fs::create_dir_all(&work_dir)
            .map_err(|error| format!("cannot create {work_dir:?}: {error}"))?;

        let config = work_dir.join("clamd.conf");
        write_config(&config, database, &work_dir)?;

        if port_is_open() {
            // A listener on our port is only ours if the PID it published is a
            // clamd that also speaks the protocol. Otherwise anything resident
            // could answer "OK" for every file and the report would call it
            // clean.
            if !listener_is_our_daemon(&work_dir, &config) {
                return Err(format!(
                    "port {DAEMON_PORT} is in use by a process that is not this ClamAV daemon; refusing to trust it"
                ));
            }

            return Ok(Self {
                config,
                child: None,
            });
        }

        // A pid file left by a crash would let a recycled PID pass the check.
        let _ = fs::remove_file(work_dir.join(PID_FILE));

        let log = work_dir.join("clamd.log");
        let sink = fs::File::create(&log).map_err(|error| format!("cannot create log: {error}"))?;
        let stderr = sink
            .try_clone()
            .map_err(|error| format!("cannot clone log: {error}"))?;

        let mut child = Command::new(daemon)
            .arg("-c")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(sink))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|error| format!("cannot start clamd: {error}"))?;

        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if port_is_open() {
                return Ok(Self {
                    config,
                    child: Some(child),
                });
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(format!("clamd exited with {status}: {}", log_tail(&log)));
                }
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    return Err(format!(
                        "clamd did not listen within {}s: {}",
                        START_TIMEOUT.as_secs(),
                        log_tail(&log)
                    ));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(200)),
                Err(error) => return Err(format!("cannot watch clamd: {error}")),
            }
        }
    }

    pub fn config(&self) -> &Path {
        &self.config
    }
}

impl Drop for ClamDaemon {
    fn drop(&mut self) {
        // Ask politely first, then make sure the child is gone.
        let stopped = Command::new(clamdscan_path())
            .arg("-c")
            .arg(&self.config)
            .arg("--stop")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);

        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        // A stale pid file would let a recycled PID pass the ownership check.
        if stopped || !port_is_open() {
            let _ = fs::remove_file(work_dir().join(PID_FILE));
        }
    }
}

fn clamdscan_path() -> PathBuf {
    discover_paths()
        .scan
        .map(|path| path.with_file_name("clamdscan.exe"))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files\ClamAV\clamdscan.exe"))
}

pub(crate) fn work_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("VirusCheckDesktop")
        .join("clamav")
}

fn port_is_open() -> bool {
    let Ok(mut addresses) = ("127.0.0.1", DAEMON_PORT).to_socket_addrs() else {
        return false;
    };
    addresses.any(|address| TcpStream::connect_timeout(&address, PROBE_TIMEOUT).is_ok())
}

/// The daemon writes its own PID to `clamd.pid`, and any process can hold the
/// port: both signals have to agree before a listener is trusted.
fn listener_is_our_daemon(work_dir: &Path, config: &Path) -> bool {
    let Ok(text) = fs::read_to_string(work_dir.join(PID_FILE)) else {
        return false;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        return false;
    };

    let is_clamd =
        process_image_name(pid).is_some_and(|name| name.eq_ignore_ascii_case("clamd.exe"));

    is_clamd && ping_daemon(config)
}

/// `clamdscan --ping` is a protocol check, not a port check: a squatter that
/// does not speak clamd fails it.
fn ping_daemon(config: &Path) -> bool {
    Command::new(clamdscan_path())
        .arg("-c")
        .arg(config)
        .arg("--ping")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn process_image_name(pid: u32) -> Option<String> {
    let output = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next()?.trim();
    let name = first.split(',').next()?.trim_matches('"');

    (!name.is_empty() && !name.starts_with("INFO")).then(|| name.to_string())
}

fn write_config(config: &Path, database: &Path, work_dir: &Path) -> Result<(), String> {
    let log = work_dir.join("clamd.log");
    let pid = work_dir.join(PID_FILE);
    let temp = std::env::temp_dir();

    let mut file =
        fs::File::create(config).map_err(|error| format!("cannot write config: {error}"))?;
    let contents = format!(
        "\
DatabaseDirectory \"{}\"
TemporaryDirectory \"{}\"
LogFile \"{}\"
LogTime yes
PidFile \"{}\"
TCPSocket {}
TCPAddr 127.0.0.1
MaxFileSize {}M
MaxScanSize {}M
MaxScanTime 600000
MaxFiles 10000
MaxRecursion 17
MaxThreads 2
",
        database.display(),
        temp.display(),
        log.display(),
        pid.display(),
        DAEMON_PORT,
        MAX_SCAN_BYTES / (1024 * 1024),
        MAX_SCAN_BYTES / (1024 * 1024),
    );
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("cannot write config: {error}"))
}

fn log_tail(log: &Path) -> String {
    fs::read_to_string(log)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .rfind(|line| !line.is_empty())
                .unwrap_or("no log output")
                .to_string()
        })
        .unwrap_or_else(|_| "no log file".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_carries_the_caps_and_the_loopback_port() {
        let directory = std::env::temp_dir().join(format!("vcd-clamd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create dir");
        let config = directory.join("clamd.conf");

        write_config(&config, Path::new(r"C:\db"), &directory).expect("write config");
        let text = fs::read_to_string(&config).expect("read config");

        assert!(text.contains(&format!("TCPSocket {DAEMON_PORT}")));
        assert!(text.contains("TCPAddr 127.0.0.1"));
        assert!(text.contains("DatabaseDirectory \"C:\\db\""));
        assert!(text.contains("MaxFileSize 2048M"));
        assert!(text.contains("MaxScanSize 2048M"));

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn missing_database_is_not_reported_as_available() {
        let paths = discover_paths();
        assert_eq!(
            paths.database.is_some(),
            paths
                .database
                .as_ref()
                .is_some_and(|directory| directory.is_dir())
        );
    }
}
