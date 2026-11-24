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
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

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
fn database_ready(root: &Path) -> bool {
    let database = root.join("database");
    let main = database.join("main.cvd").is_file() || database.join("main.cld").is_file();
    let daily = database.join("daily.cvd").is_file() || database.join("daily.cld").is_file();
    main && daily
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

/// Steps a GUI can show while ClamAV installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InstallStep {
    Downloading,
    Extracting,
    Updating,
    Ready,
}

impl InstallStep {
    pub fn english(self) -> &'static str {
        match self {
            InstallStep::Downloading => "Downloading ClamAV (about 214 MB)…",
            InstallStep::Extracting => "Extracting without installing…",
            InstallStep::Updating => "Downloading the signature database (about 300 MB)…",
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

    // A tree with the libraries but no database is an interrupted install: it
    // resumes at the update step instead of reporting "ready".
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
            extracted?;

            portable_root().ok_or_else(|| {
                format!(
                    "extraction finished but libclamav.dll is not under {}",
                    base.display()
                )
            })?
        }
    };

    let database = root.join("database");
    fs::create_dir_all(&database)
        .map_err(|error| format!("cannot create database dir: {error}"))?;

    let config = root.join("freshclam.conf");
    write_freshclam_config(&config, &database, &root)?;

    progress(InstallStep::Updating);
    let freshclam = root.join("freshclam.exe");
    let status = Command::new(&freshclam)
        .arg(format!("--config-file={}", config.display()))
        .status()
        .map_err(|error| format!("cannot run freshclam: {error}"))?;
    if !status.success() {
        return Err(format!(
            "freshclam exited with {status}; run it again from {}",
            root.display()
        ));
    }

    if !database_ready(&root) {
        return Err(format!(
            "the database download did not produce a complete set under {}",
            database.display()
        ));
    }

    progress(InstallStep::Ready);
    Ok(root)
}

fn msi_url() -> String {
    format!(
        "https://github.com/Cisco-Talos/clamav/releases/download/clamav-{CLAMAV_VERSION}/clamav-{CLAMAV_VERSION}.win.x64.msi"
    )
}

/// Download into a per-run directory and refuse anything that is not the pinned
/// file. Two installs running at once therefore never share a path.
fn download_msi() -> Result<PathBuf, String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let directory = std::env::temp_dir().join(format!("vcd-clamav-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;

    let msi = directory.join(format!("clamav-{CLAMAV_VERSION}.msi"));
    download(&msi_url(), &msi)?;
    verify_msi(&msi)?;
    Ok(msi)
}

/// The MSI is not Authenticode-signed, so the pinned digest is the integrity
/// control. A mismatch deletes the file and nothing is executed.
fn verify_msi(msi: &Path) -> Result<(), String> {
    let actual = sha256_file(msi)?;
    if actual != CLAMAV_MSI_SHA256 {
        let _ = fs::remove_file(msi);
        return Err(format!(
            "the downloaded MSI does not match the pinned SHA-256 (expected {CLAMAV_MSI_SHA256}, got {actual}); nothing was executed"
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn extract(msi: &Path, base: &Path) -> Result<(), String> {
    let status = Command::new(system32("msiexec.exe"))
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
        "DatabaseDirectory \"{}\"\nUpdateLogFile \"{}\"\nDatabaseMirror database.clamav.net\n",
        database.display(),
        root.join("freshclam.log").display()
    );

    let temporary = config.with_extension("conf.tmp");
    fs::write(&temporary, body).map_err(|error| format!("cannot write freshclam.conf: {error}"))?;
    fs::rename(&temporary, config)
        .map_err(|error| format!("cannot install freshclam.conf: {error}"))
}

/// A fixed script that reads its inputs from the environment, so neither the URL
/// nor the destination ever becomes part of the PowerShell source.
const POWERSHELL_DOWNLOAD: &str = "Invoke-WebRequest -Uri $env:VCD_DOWNLOAD_URL \
     -OutFile $env:VCD_DOWNLOAD_TARGET -UseBasicParsing";

fn download(url: &str, destination: &Path) -> Result<(), String> {
    // curl.exe ships with Windows 10 1803+; PowerShell is the fallback.
    let curl = system32("curl.exe");
    if curl.is_file() {
        let status = Command::new(&curl)
            .args([
                "-L",
                "--fail",
                "--connect-timeout",
                "30",
                "--max-time",
                "1800",
                "-o",
            ])
            .arg(destination)
            .arg(url)
            .status()
            .map_err(|error| format!("cannot run curl: {error}"))?;

        if status.success() {
            return Ok(());
        }
        return Err(format!("curl exited with {status}"));
    }

    let status = Command::new(powershell())
        .args(["-NoProfile", "-Command", POWERSHELL_DOWNLOAD])
        .env("VCD_DOWNLOAD_URL", url)
        .env("VCD_DOWNLOAD_TARGET", destination)
        .status()
        .map_err(|error| format!("cannot run powershell: {error}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("download failed with {status}"))
    }
}

/// System programs by absolute path: the executable's own directory and the
/// working directory come before System32 in the Windows search order.
fn system32(name: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(name)
}

fn powershell() -> PathBuf {
    system32(r"WindowsPowerShell\v1.0\powershell.exe")
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
    fn a_download_that_does_not_match_the_digest_is_deleted() {
        let path = std::env::temp_dir().join(format!(
            "vcd-msi-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        fs::write(&path, b"not the installer").expect("write fake msi");

        let error = verify_msi(&path).expect_err("a foreign file must be refused");
        assert!(error.contains("does not match"));
        assert!(
            !path.exists(),
            "the rejected file is removed before msiexec"
        );
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

        assert!(!database_ready(&root));
        fs::write(database.join("main.cvd"), b"x").expect("write main");
        assert!(!database_ready(&root));
        fs::write(database.join("daily.cld"), b"x").expect("write daily");
        assert!(database_ready(&root));

        let _ = fs::remove_dir_all(&root);
    }
}
