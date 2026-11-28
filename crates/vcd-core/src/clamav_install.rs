//! Portable ClamAV bootstrap.
//!
//! Installing ClamAV normally needs an administrator. This module does it
//! without one: it downloads the official MSI, extracts it with an
//! administrative install (`msiexec /a`, which copies files and installs
//! nothing), then runs the extracted `freshclam` with a config inside the
//! user's profile. The result is a complete ClamAV tree under
//! `%LOCALAPPDATA%\VirusCheckDesktop\clamav` that the engines find like any
//! other installation.
//!
//! Integrity does not rest on HTTPS alone. The MSI is **not** Authenticode-
//! signed, so the exact file this module accepts is pinned by SHA-256 in
//! [`CLAMAV_MSI_SHA256`]; a download that does not match is deleted before
//! `msiexec` can see it. Bumping ClamAV means updating both constants, which is
//! the point: the pair is a code change someone reviews.

use std::fs;
use std::path::{Path, PathBuf};

use crate::download;

/// Bumping ClamAV is a code change on purpose: the URL is built from this.
pub const CLAMAV_VERSION: &str = "1.5.5";

/// SHA-256 of the exact MSI the URL above serves. Published by the release
/// itself and verified against a fresh download before this constant was set.
pub const CLAMAV_MSI_SHA256: &str =
    "58876d43d212bef67c104c8d1a1caf59834e03bc3571a7bb418a27d196726d79";

pub fn portable_base() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("VirusCheckDesktop").join("clamav")
}

/// The extracted tree: `msiexec /a` puts everything under a `ClamAV` folder.
pub fn portable_root() -> Option<PathBuf> {
    let base = portable_base();
    [base.clone(), base.join("ClamAV")]
        .into_iter()
        .find(|candidate| candidate.join("libclamav.dll").is_file())
}

/// A tree is usable only when it also has signatures: `msiexec /a` leaves the
/// libraries behind even when the update step never ran.
pub fn is_installed() -> bool {
    portable_root().is_some_and(|root| database_ready(&root))
}

/// The signature set ClamAV needs before it can scan anything.
fn database_files_present(root: &Path) -> bool {
    let database = root.join("database");
    let main = database.join("main.cvd").is_file() || database.join("main.cld").is_file();
    let daily = database.join("daily.cvd").is_file() || database.join("daily.cld").is_file();
    main && daily
}

/// Present **and** verified: a file that never passed the load check is not a
/// database, it is a download that may be truncated or unsigned.
fn database_ready(root: &Path) -> bool {
    database_files_present(root) && root.join(VERIFIED_MARKER).is_file()
}

/// Where ClamAV lives, if it lives anywhere.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClamavStatus {
    pub portable: Option<PathBuf>,
    pub system: Option<PathBuf>,
}

impl ClamavStatus {
    pub fn available(&self) -> bool {
        self.portable.is_some() || self.system.is_some()
    }
}

/// One definition of "installed", shared with the engine: whatever ClamAV the
/// scanner would actually use, with the portable tree reported separately.
pub fn status() -> ClamavStatus {
    // A tree without signatures is not an install: reporting it would close the
    // setup dialog and let scans fail one file at a time.
    let portable = portable_root().filter(|root| database_ready(root));
    let paths = crate::engines::clamd::discover_paths();

    // `discover_paths` collapses to the newest database, which is often the
    // portable tree; a system install must still be reported next to it.
    let system = paths
        .scan
        .and_then(|scan| scan.parent().map(Path::to_path_buf))
        .filter(|root| !is_portable(root, portable.as_deref()))
        .or_else(system_install_root);

    ClamavStatus { portable, system }
}

fn is_portable(root: &Path, portable: Option<&Path>) -> bool {
    portable.is_some_and(|portable| root == portable) || root.starts_with(portable_base())
}

/// The two roots a normal ClamAV installer uses.
fn system_install_root() -> Option<PathBuf> {
    [
        PathBuf::from(r"C:\Program Files\ClamAV"),
        PathBuf::from(r"C:\ClamAV"),
    ]
    .into_iter()
    .find(|root| root.join("clamscan.exe").is_file())
}

/// Marks a database that passed the load check. `database_ready` would otherwise
/// be existence-only, and a failed fallback can leave complete-looking files.
const VERIFIED_MARKER: &str = "database.verified";

/// Steps a GUI can show while ClamAV installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InstallStep {
    Downloading,
    Extracting,
    Updating,
    Verifying,
    Ready,
}

impl InstallStep {
    pub fn english(self) -> &'static str {
        match self {
            InstallStep::Downloading => "Downloading ClamAV (about 214 MB)…",
            InstallStep::Extracting => "Extracting without installing…",
            InstallStep::Updating => "Downloading the signature database (about 300 MB)…",
            InstallStep::Verifying => "Checking the signature database…",
            InstallStep::Ready => "ClamAV is ready",
        }
    }
}

/// Download, extract and update. Prints progress because it can move ~500 MB.
pub fn install() -> Result<PathBuf, String> {
    install_with(&mut |step| println!("{}", step.english()))
}

/// Same, reporting each step so a GUI can show it.
pub fn install_with(progress: &mut dyn FnMut(InstallStep)) -> Result<PathBuf, String> {
    let base = portable_base();
    fs::create_dir_all(&base).map_err(|error| format!("cannot create {base:?}: {error}"))?;

    // Two installers (GUI and CLI) would fight over the same tree and the same
    // config temp file.
    let _lock = InstallLock::acquire()
        .ok_or_else(|| "another ClamAV install is already running".to_string())?;

    // A tree with the libraries but no verified database is an interrupted
    // install: it resumes at the update step instead of reporting "ready".
    let root = match portable_root() {
        Some(root) if database_ready(&root) => {
            progress(InstallStep::Ready);
            return Ok(root);
        }
        Some(root) => root,
        None => {
            let msi = download_msi()?;

            progress(InstallStep::Extracting);
            let extracted = extract(&msi, &base);
            let _ = fs::remove_file(&msi);
            if let Some(directory) = msi.parent() {
                let _ = fs::remove_dir(directory);
            }
            extracted?;

            portable_root().ok_or_else(|| {
                format!(
                    "extraction finished but libclamav.dll is not under {}",
                    base.display()
                )
            })?
        }
    };

    // A database that never passed the load check is not trusted, but a valid
    // one left by an earlier version is verified once instead of downloaded
    // again.
    if database_files_present(&root) {
        progress(InstallStep::Verifying);
        if verify_database(&root).is_ok() {
            mark_verified(&root)?;
            progress(InstallStep::Ready);
            return Ok(root);
        }
    }
    clear_database(&root)?;

    let database = root.join("database");
    fs::create_dir_all(&database)
        .map_err(|error| format!("cannot create database dir: {error}"))?;
    clear_staging(&database);

    let config = root.join("freshclam.conf");
    write_freshclam_config(&config, &database, &root)?;

    progress(InstallStep::Updating);
    let freshclam = root.join("freshclam.exe");
    let status = download::hidden_command(&freshclam)
        .arg(format!("--config-file={}", config.display()))
        .status()
        .map_err(|error| format!("cannot run freshclam: {error}"))?;
    if !status.success() {
        // freshclam's OpenSSL has no trusted roots on a fresh image and ignores
        // the CA environment on Windows; the fallback is the observed condition
        // (the database is still missing), not one guessed exit code.
        let failure = freshclam_failure(&status);
        download_databases(&database).map_err(|fallback| {
            format!("{failure}; the fallback download also failed: {fallback}")
        })?;
    }

    // freshclam stages as `tmp.<name>`; a killed run can leave one behind, and
    // libclamav loads every `*.cvd` it finds in the directory.
    clear_staging(&database);

    progress(InstallStep::Verifying);
    verify_database(&root)?;
    mark_verified(&root)?;

    progress(InstallStep::Ready);
    Ok(root)
}

/// `freshclam` exits with a member of the shipped `fc_error_t` enum, which ends
/// at `FC_ERROR = 19`. The hints below are the codes that leave the database
/// incomplete and that a person can act on.
fn freshclam_hint(code: Option<i32>) -> Option<&'static str> {
    Some(match code? {
        5 => {
            "it could not reach the update server: no network, or no trusted certificate store; if this runs inside Windows Sandbox, enable networking"
        }
        7 => "the downloaded database failed ClamAV's own check",
        9 => "freshclam rejected its configuration",
        10 => "it could not access the database directory",
        11 => "the update server refused or failed the request",
        12 => "the update mirrors are not synchronized yet; try again in a few minutes",
        17 => "the update server refused the request (forbidden)",
        _ => return None,
    })
}

fn freshclam_failure(status: &std::process::ExitStatus) -> String {
    match freshclam_hint(status.code()) {
        Some(hint) => format!("freshclam exited with {status}: {hint}"),
        None => format!("freshclam exited with {status}"),
    }
}

/// Remove freshclam's staging entries and partial downloads.
fn clear_staging(database: &Path) {
    let Ok(entries) = fs::read_dir(database) else {
        return;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("tmp.") || name.ends_with(".part")) {
            continue;
        }

        let path = entry.path();
        if path.is_dir() {
            let _ = fs::remove_dir_all(&path);
        } else {
            let _ = fs::remove_file(&path);
        }
    }
}

fn clear_database_files(database: &Path) {
    clear_staging(database);
    for name in [
        "main.cvd",
        "main.cld",
        "daily.cvd",
        "daily.cld",
        "bytecode.cvd",
        "bytecode.cld",
    ] {
        let _ = fs::remove_file(database.join(name));
    }
}

/// Drop a database (and its verified mark) so the next run cannot mistake the
/// leftovers for a finished install.
fn clear_database(root: &Path) -> Result<(), String> {
    let database = root.join("database");
    let _ = fs::remove_file(root.join(VERIFIED_MARKER));
    fs::create_dir_all(&database)
        .map_err(|error| format!("cannot create database dir: {error}"))?;
    clear_database_files(&database);
    Ok(())
}

/// Load the database with ClamAV itself: `cl_load` checks the CVD signatures,
/// which is the only integrity check that matters for these files.
fn verify_database(root: &Path) -> Result<(), String> {
    crate::engines::clamav_direct::ClamAvDirect::load(root)
        .map(|_| ())
        .map_err(|error| {
            format!(
                "the ClamAV database does not load ({error}); database: {}; freshclam log: {}",
                root.join("database").display(),
                root.join("freshclam.log").display()
            )
        })
}

fn mark_verified(root: &Path) -> Result<(), String> {
    fs::write(root.join(VERIFIED_MARKER), b"ok")
        .map_err(|error| format!("cannot record the verified database: {error}"))
}

/// `freshclam`'s libcurl ignores `SSL_CERT_FILE`/`CURL_CA_BUNDLE` on Windows
/// (`set_tls_ca_bundle` is compiled out), and a Windows Sandbox image ships 16
/// root certificates with no dynamic update, so OpenSSL cannot validate the CDN
/// while Schannel can. The three databases are fetched with `curl` instead and
/// verified by the caller, which loads them.
fn download_databases(database: &Path) -> Result<(), String> {
    let user_agent = format!("clamav/{CLAMAV_VERSION} (OS: win; ARCH: x86_64; CPU: x86_64)");
    download_databases_with(database, &mut |url, target| {
        download::fetch_as(url, target, Some(&user_agent))
    })
}

/// Same, with the download injected so the failure path is testable.
fn download_databases_with(
    database: &Path,
    fetch: &mut dyn FnMut(&str, &Path) -> Result<(), String>,
) -> Result<(), String> {
    let result = (|| {
        for name in ["main.cvd", "daily.cvd", "bytecode.cvd"] {
            let target = database.join(name);
            let partial = database.join(format!("{name}.part"));
            let _ = fs::remove_file(&partial);

            fetch(&format!("https://database.clamav.net/{name}"), &partial)?;
            fs::rename(&partial, &target).map_err(|error| {
                format!("cannot move {} into place: {error}", partial.display())
            })?;
        }
        Ok(())
    })();

    if result.is_err() {
        clear_database_files(database);
    }

    result
}

fn msi_url() -> String {
    format!(
        "https://github.com/Cisco-Talos/clamav/releases/download/clamav-{CLAMAV_VERSION}/clamav-{CLAMAV_VERSION}.win.x64.msi"
    )
}

/// Download into a per-run directory and refuse anything that is not the pinned
/// file.
fn download_msi() -> Result<PathBuf, String> {
    let directory = download::per_run_directory("vcd-clamav")?;
    let msi = directory.join(format!("clamav-{CLAMAV_VERSION}.msi"));

    let fetched = download::fetch(&msi_url(), &msi)
        .and_then(|()| download::verify_sha256(&msi, CLAMAV_MSI_SHA256, "ClamAV MSI"));

    if let Err(error) = fetched {
        let _ = fs::remove_dir_all(&directory);
        return Err(error);
    }

    Ok(msi)
}

fn extract(msi: &Path, base: &Path) -> Result<(), String> {
    let status = download::hidden_command(download::system32("msiexec.exe"))
        .arg("/a")
        .arg(msi)
        .args(["/qn", &format!("TARGETDIR={}", base.display())])
        .status()
        .map_err(|error| format!("cannot run msiexec: {error}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("msiexec /a exited with {status}"))
    }
}

/// Write then rename, so an interrupted run never leaves half a config.
fn write_freshclam_config(config: &Path, database: &Path, root: &Path) -> Result<(), String> {
    let body = format!(
        "DatabaseDirectory \"{}\"\nCVDCertsDirectory \"{}\"\nUpdateLogFile \"{}\"\nDatabaseMirror database.clamav.net\n",
        database.display(),
        root.join("certs").display(),
        root.join("freshclam.log").display()
    );

    let temporary = config.with_extension("conf.tmp");
    fs::write(&temporary, body).map_err(|error| format!("cannot write freshclam.conf: {error}"))?;
    fs::rename(&temporary, config)
        .map_err(|error| format!("cannot install freshclam.conf: {error}"))
}

/// Fail-fast install lock: two installers would write the same tree and the same
/// `freshclam.conf.tmp`. The kernel releases it if the process dies. `Local\`
/// covers this session; a second session of the same user is not serialised.
struct InstallLock {
    handle: *mut std::ffi::c_void,
}

impl InstallLock {
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

        let name: Vec<u16> = std::ffi::OsStr::new(r"Local\VirusCheckDesktop.Install")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr()) };
        if handle.is_null() {
            return None;
        }

        if unsafe { WaitForSingleObject(handle, 0) } == 0 {
            Some(Self { handle })
        } else {
            unsafe { CloseHandle(handle) };
            None
        }
    }
}

impl Drop for InstallLock {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_portable_root_is_under_the_user_profile() {
        let base = portable_base();
        assert!(base.ends_with("VirusCheckDesktop\\clamav"));
    }

    #[test]
    fn the_pinned_url_names_the_pinned_file() {
        let url = msi_url();
        assert!(url.starts_with("https://github.com/Cisco-Talos/clamav/releases/download/"));
        assert!(url.ends_with(&format!("clamav-{CLAMAV_VERSION}.win.x64.msi")));
    }

    #[test]
    fn the_pinned_digest_is_a_sha256() {
        assert_eq!(CLAMAV_MSI_SHA256.len(), 64);
        assert!(
            CLAMAV_MSI_SHA256
                .chars()
                .all(|digit| digit.is_ascii_hexdigit() && !digit.is_ascii_uppercase())
        );
    }

    #[test]
    fn a_freshclam_connection_failure_points_at_the_sandbox() {
        let hint = freshclam_hint(Some(5)).expect("code 5 has a hint");
        assert!(hint.contains("Windows Sandbox"));

        // The shipped enum is `fc_error_t`, 0..=19. The hints name the codes that
        // leave the database incomplete; the numbers from the manual (52, 54, …)
        // are not in it.
        for code in [5, 7, 9, 10, 11, 12, 17] {
            assert!(freshclam_hint(Some(code)).is_some(), "{code} needs a hint");
        }
        for code in [20, 40, 52, 54, 56, 57, 59, 999] {
            assert!(
                freshclam_hint(Some(code)).is_none(),
                "{code} is not an fc_error_t"
            );
        }
    }

    fn scratch_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "vcd-clamav-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(root.join("database")).expect("create scratch database");
        root
    }

    #[test]
    fn a_tree_without_the_verified_marker_is_not_ready() {
        let root = scratch_root("marker");
        fs::write(root.join("database").join("main.cvd"), b"x").expect("main");
        fs::write(root.join("database").join("daily.cvd"), b"x").expect("daily");

        assert!(!database_ready(&root), "files alone are not a database");

        mark_verified(&root).expect("mark");
        assert!(database_ready(&root));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_fallback_leaves_no_database_behind() {
        let root = scratch_root("fallback");
        let database = root.join("database");
        let mut calls = 0;

        let result = download_databases_with(&database, &mut |_url, target| {
            calls += 1;
            if calls == 3 {
                return Err("network went away".to_string());
            }
            fs::write(target, b"x").map_err(|error| error.to_string())
        });

        assert!(result.is_err());
        assert!(
            !database_files_present(&root),
            "a partial fallback must not look like a database"
        );
        assert_eq!(
            fs::read_dir(&database)
                .map(|entries| entries.count())
                .unwrap_or(0),
            0
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn stale_staging_entries_are_cleaned_whether_file_or_directory() {
        let root = scratch_root("staging");
        let database = root.join("database");
        fs::write(database.join("tmp.7"), b"partial").expect("tmp file");
        fs::create_dir_all(database.join("tmp.8")).expect("tmp dir");
        fs::write(database.join("main.cvd.part"), b"partial").expect("part file");
        fs::write(database.join("main.cvd"), b"keep").expect("kept");

        clear_staging(&database);

        assert!(!database.join("tmp.7").exists(), "tmp file removed");
        assert!(!database.join("tmp.8").exists(), "tmp dir removed");
        assert!(!database.join("main.cvd.part").exists(), "part removed");
        assert!(database.join("main.cvd").is_file(), "database kept");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_freshclam_config_names_the_shipped_certificates() {
        let root = std::env::temp_dir().join(format!(
            "vcd-freshclam-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        let database = root.join("database");
        fs::create_dir_all(&database).expect("create database dir");

        let config = root.join("freshclam.conf");
        write_freshclam_config(&config, &database, &root).expect("write config");

        let body = fs::read_to_string(&config).expect("read config");
        assert!(body.contains("CVDCertsDirectory"));
        assert!(body.contains("certs"));
        assert!(body.contains("DatabaseMirror database.clamav.net"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_tree_without_both_databases_is_not_ready() {
        let root = std::env::temp_dir().join(format!(
            "vcd-database-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        let database = root.join("database");
        fs::create_dir_all(&database).expect("create scratch database");

        assert!(!database_files_present(&root));
        fs::write(database.join("main.cvd"), b"x").expect("write main");
        assert!(!database_files_present(&root));
        fs::write(database.join("daily.cld"), b"x").expect("write daily");
        assert!(database_files_present(&root));

        let _ = fs::remove_dir_all(&root);
    }
}
