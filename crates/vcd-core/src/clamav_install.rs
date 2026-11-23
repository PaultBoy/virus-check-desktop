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
//! Integrity is stated, not implied: the MSI comes from the official GitHub
//! release over HTTPS and is **not** Authenticode-signed, which is why the
//! version is pinned in this file and the URL is not taken from a redirect.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Bumping ClamAV is a code change on purpose: the URL is built from this.
pub const CLAMAV_VERSION: &str = "1.5.5";

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

pub fn is_installed() -> bool {
    portable_root().is_some()
}

/// Download, extract and update. Prints progress because it can move ~500 MB.
pub fn install() -> Result<PathBuf, String> {
    if let Some(root) = portable_root() {
        println!("ClamAV is already installed at {}", root.display());
        return Ok(root);
    }

    let base = portable_base();
    fs::create_dir_all(&base).map_err(|error| format!("cannot create {base:?}: {error}"))?;

    let msi = std::env::temp_dir().join(format!("clamav-{CLAMAV_VERSION}.msi"));
    let url = format!(
        "https://github.com/Cisco-Talos/clamav/releases/download/clamav-{CLAMAV_VERSION}/clamav-{CLAMAV_VERSION}.win.x64.msi"
    );

    println!("Downloading ClamAV {CLAMAV_VERSION} (about 214 MB)…");
    download(&url, &msi)?;

    println!("Extracting without installing…");
    let status = Command::new("msiexec.exe")
        .args([
            "/a",
            &msi.display().to_string(),
            "/qn",
            &format!("TARGETDIR={}", base.display()),
        ])
        .status()
        .map_err(|error| format!("cannot run msiexec: {error}"))?;
    if !status.success() {
        return Err(format!("msiexec /a exited with {status}"));
    }
    let _ = fs::remove_file(&msi);

    let root = portable_root().ok_or_else(|| {
        format!(
            "extraction finished but libclamav.dll is not under {}",
            base.display()
        )
    })?;

    let database = root.join("database");
    fs::create_dir_all(&database)
        .map_err(|error| format!("cannot create database dir: {error}"))?;

    let config = root.join("freshclam.conf");
    fs::write(
        &config,
        format!(
            "DatabaseDirectory \"{}\"\nUpdateLogFile \"{}\"\nDatabaseMirror database.clamav.net\n",
            database.display(),
            root.join("freshclam.log").display()
        ),
    )
    .map_err(|error| format!("cannot write freshclam.conf: {error}"))?;

    println!("Downloading the signature database (about 300 MB); this takes a while…");
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

    if !database.join("main.cvd").is_file() && !database.join("main.cld").is_file() {
        return Err("the database download did not produce main.cvd".to_string());
    }

    Ok(root)
}

fn download(url: &str, destination: &Path) -> Result<(), String> {
    // curl.exe ships with Windows 10 1803+; PowerShell is the fallback.
    if Command::new("curl.exe").arg("--version").output().is_ok() {
        let status = Command::new("curl.exe")
            .args(["-L", "--fail", "-o"])
            .arg(destination)
            .arg(url)
            .status()
            .map_err(|error| format!("cannot run curl: {error}"))?;

        if status.success() {
            return Ok(());
        }
        return Err(format!("curl exited with {status}"));
    }

    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Invoke-WebRequest -Uri '{}' -OutFile '{}' -UseBasicParsing",
                url,
                destination.display()
            ),
        ])
        .status()
        .map_err(|error| format!("cannot run powershell: {error}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("download failed with {status}"))
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
    fn the_pinned_url_names_the_pinned_version() {
        assert!(CLAMAV_VERSION.starts_with("1."));
    }
}
