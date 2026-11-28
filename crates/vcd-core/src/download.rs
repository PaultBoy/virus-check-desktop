//! Downloading programs at runtime, and spawning console children invisibly.
//!
//! Two rules live here because both installers need them:
//!
//! - The desktop app is a GUI process with no console of its own, so a console
//!   child spawned without a flag opens a black window of its own; `tasklist`
//!   polls would flash one every 500 ms. Console programs go through
//!   [`hidden_command`].
//! - A downloaded file is pinned by SHA-256 and checked with [`verify_sha256`]
//!   before anything executes it. [`fetch`] does not verify on its own: the
//!   caller knows the digest it expects, so the check is never a hidden default
//!   nobody reads.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A fixed script that reads its inputs from the environment, so neither the URL
/// nor the destination ever becomes part of the PowerShell source. The progress
/// bar is off (it makes `Invoke-WebRequest` an order of magnitude slower on a
/// large file) and the whole request is bounded like the curl it replaces.
const POWERSHELL_DOWNLOAD: &str = "$ProgressPreference = 'SilentlyContinue'; \
     $request = @{ Uri = $env:VCD_DOWNLOAD_URL; OutFile = $env:VCD_DOWNLOAD_TARGET; \
     UseBasicParsing = $true; TimeoutSec = 1800 }; \
     if ($env:VCD_DOWNLOAD_UA) { $request.UserAgent = $env:VCD_DOWNLOAD_UA }; \
     Invoke-WebRequest @request";

/// A console program with no window of its own.
pub(crate) fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    use std::os::windows::process::CommandExt;

    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

/// System programs by absolute path: the executable's own directory and the
/// working directory come before System32 in the Windows search order.
pub(crate) fn system32(name: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(name)
}

pub(crate) fn powershell() -> PathBuf {
    system32(r"WindowsPowerShell\v1.0\powershell.exe")
}

/// A fresh directory per run, so two downloads never share a file.
pub(crate) fn per_run_directory(prefix: &str) -> Result<PathBuf, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let directory = std::env::temp_dir().join(format!("{prefix}-{}-{stamp}", std::process::id()));

    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;
    Ok(directory)
}

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
    crate::hashing::hash_file(path)
        .map(|digests| digests.sha256)
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))
}

/// Download to `destination` with `curl`, falling back to PowerShell.
///
/// Windows `curl` uses Schannel, which refuses the connection (error 35) when it
/// cannot confirm certificate revocation, which is common on a machine that never
/// fetched this host before or sits behind a TLS-inspecting proxy. The check adds
/// nothing here: the file is pinned by SHA-256, so a tampered download is refused
/// afterwards either way. PowerShell is a real second chance, not just a
/// missing-curl fallback: it uses .NET's TLS stack and the machine proxy settings.
pub(crate) fn fetch(url: &str, destination: &Path) -> Result<(), String> {
    fetch_as(url, destination, None)
}

/// Same, with a caller-chosen `User-Agent`. ClamAV's CDN answers 403 to curl's
/// default agent and 200 to `clamav/<version>`.
pub(crate) fn fetch_as(
    url: &str,
    destination: &Path,
    user_agent: Option<&str>,
) -> Result<(), String> {
    let mut failure = None;

    // curl.exe ships with Windows 10 1803+.
    let curl = system32("curl.exe");
    if curl.is_file() {
        let mut command = hidden_command(&curl);
        command.args([
            "-L",
            "--fail",
            "--ssl-no-revoke",
            "--connect-timeout",
            "30",
            "--max-time",
            "1800",
            "-o",
        ]);
        command.arg(destination).arg(url);
        if let Some(user_agent) = user_agent {
            command.arg("-A").arg(user_agent);
        }

        match command.status() {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => failure = Some(format!("curl exited with {status}")),
            Err(error) => failure = Some(format!("cannot run curl: {error}")),
        }

        let _ = fs::remove_file(destination);
    }

    let mut command = hidden_command(powershell());
    command
        .args(["-NoProfile", "-Command", POWERSHELL_DOWNLOAD])
        .env("VCD_DOWNLOAD_URL", url)
        .env("VCD_DOWNLOAD_TARGET", destination);
    if let Some(user_agent) = user_agent {
        command.env("VCD_DOWNLOAD_UA", user_agent);
    }

    let status = command.status();

    let status = match status {
        Ok(status) => status,
        Err(error) => {
            let _ = fs::remove_file(destination);
            return Err(match failure {
                Some(first) => format!("cannot run powershell: {error} (curl first: {first})"),
                None => format!("cannot run powershell: {error}"),
            });
        }
    };

    if status.success() {
        return Ok(());
    }

    let _ = fs::remove_file(destination);

    Err(match failure {
        Some(first) => format!("download failed with {status} (curl first: {first})"),
        None => format!("download failed with {status}"),
    })
}

/// Refuse anything that is not the exact file this build expects. A mismatch
/// deletes the download so nothing can execute it.
pub(crate) fn verify_sha256(path: &Path, expected: &str, what: &str) -> Result<(), String> {
    let actual = sha256_file(path)?;
    if actual != expected {
        let _ = fs::remove_file(path);
        return Err(format!(
            "the downloaded {what} does not match the pinned SHA-256 (expected {expected}, got {actual}); nothing was executed"
        ));
    }
    Ok(())
}

/// `powershell -EncodedCommand` takes base64 of the UTF-16LE script.
pub(crate) fn utf16le_base64(text: &str) -> String {
    base64(
        &text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>(),
    )
}

pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (first << 16) | (second << 8) | third;

        encoded.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        encoded.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vcd-download-test-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn a_download_that_does_not_match_the_digest_is_deleted() {
        let path = scratch("mismatch");
        fs::write(&path, b"not the file").expect("write fake download");

        let error = verify_sha256(
            &path,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "file",
        )
        .expect_err("a foreign file must be refused");

        assert!(error.contains("does not match"));
        assert!(
            !path.exists(),
            "the rejected file is removed before it can run"
        );
    }

    #[test]
    fn a_download_that_matches_the_digest_is_kept() {
        let path = scratch("match");
        fs::write(&path, b"payload").expect("write download");

        let digest = sha256_file(&path).expect("hash");
        verify_sha256(&path, &digest, "file").expect("the pinned file is accepted");
        assert!(path.exists());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_hash_is_lowercase_hex_sha256() {
        let path = scratch("format");
        fs::write(&path, b"payload").expect("write download");

        let digest = sha256_file(&path).expect("hash");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|digit| digit.is_ascii_hexdigit()));
        assert!(!digest.chars().any(|digit| digit.is_ascii_uppercase()));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_powershell_fallback_is_bounded() {
        assert!(POWERSHELL_DOWNLOAD.contains("TimeoutSec = 1800"));
        assert!(POWERSHELL_DOWNLOAD.contains("$ProgressPreference"));
    }

    #[test]
    fn base64_matches_rfc4648_with_padding() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
        assert_eq!(base64(b""), "");
    }

    #[test]
    fn the_encoded_command_is_utf16le_base64() {
        // "A" is 0x41 0x00 in UTF-16LE, which is "QQA=" in base64.
        assert_eq!(utf16le_base64("A"), "QQA=");
    }
}
