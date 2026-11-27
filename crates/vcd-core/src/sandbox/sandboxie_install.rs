//! Sandboxie-Plus bootstrap.
//!
//! Sandboxie is the detonation backend that exists on every Windows edition,
//! Home included, so offering it is what makes the feature usable on machines
//! where Windows Sandbox cannot be enabled at all.
//!
//! Installing it needs administrator rights: it loads a kernel driver. The whole
//! fetch happens **inside** the elevated process, which is the point: a file
//! downloaded to `%TEMP%` can be rewritten by anything running as the same user
//! between the digest check and the `Start-Process -Verb RunAs`, and the UAC
//! prompt would then elevate someone else's binary. The elevated script creates
//! a directory only administrators can write (`%ProgramFiles%`), downloads a
//! uniquely named file there, checks the pinned SHA-256 on that copy and only
//! then starts it.
//!
//! The install is silent and unattended: `/VERYSILENT` with no console window, so
//! the only thing the user answers is the UAC prompt. It is **not** portable, and
//! cannot be: the installer's own `/PORTABLE=1` mode skips every step that
//! registers `SbieDrv.sys` and `SbieSvc` (`Installer/Sandboxie-Plus.iss` gates
//! them on `Check: not IsPortable`), which is exactly what makes Sandboxie a
//! sandbox. A kernel driver has to live where a non-admin user cannot rewrite it,
//! so `%ProgramFiles%` is a requirement, not a preference. The installer file
//! itself is deleted once it finishes.

use crate::download;

/// Bumping Sandboxie is a code change on purpose: the URL is built from this.
const SANDBOXIE_VERSION: &str = "1.19.1";

/// SHA-256 published for the exact asset this URL serves, confirmed against a
/// fresh 25,500,688-byte download before the constant was set.
const SANDBOXIE_INSTALLER_SHA256: &str =
    "443b528766f4e6448632fd94afa7df5d9e1c52e13940db79139d4070da3aa384";

fn installer_url() -> String {
    format!(
        "https://github.com/sandboxie-plus/Sandboxie/releases/download/v{SANDBOXIE_VERSION}/Sandboxie-Plus-x64-v{SANDBOXIE_VERSION}.exe"
    )
}

/// Runs inside the elevated PowerShell. The URL and the digest are compile-time
/// constants carried in the encoded script: environment variables are not
/// inherited across a UAC elevation, so passing them through `$env:` would leave
/// the script with empty values.
const ELEVATED_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:ProgramFiles 'VirusCheckDesktop\installers'
try { New-Item -ItemType Directory -Force -Path $dir | Out-Null } catch { exit 4 }
Get-ChildItem -LiteralPath $dir -Filter '*.exe' -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue
$path = Join-Path $dir ((New-Guid).Guid + '.exe')
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
if (-not (Test-Path -LiteralPath $curl)) { exit 3 }
& $curl -L --fail --ssl-no-revoke --connect-timeout 30 --max-time 1800 -o $path '__URL__'
if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; exit 3 }
$hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne '__DIGEST__') { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; exit 2 }
$exe = Join-Path $env:ProgramFiles 'Sandboxie-Plus\Start.exe'
$installed = $false
# The driver registration can fail on the first run on a machine that never had
# it, and succeeds on a second pass; do that pass here instead of asking the user.
for ($attempt = 1; $attempt -le 2 -and -not $installed; $attempt++) {
    & $path /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
    $code = $LASTEXITCODE
    if ($code -ne 0 -and $code -ne 3010 -and $code -ne 1641) { continue }
    for ($wait = 0; $wait -lt 20 -and -not $installed; $wait++) {
        $svc = Get-Service -Name SbieSvc -ErrorAction SilentlyContinue
        if ((Test-Path -LiteralPath $exe) -and ($null -ne $svc)) {
            if ($svc.Status -ne 'Running') { Start-Service -Name SbieSvc -ErrorAction SilentlyContinue }
            $installed = $true
        } else {
            Start-Sleep -Seconds 2
        }
    }
}
Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
if (-not $installed) { exit 5 }
exit 0
"#;

/// Starts the elevated script and maps its exit code back to a reason. Both the
/// outer `Start-Process` and the PowerShell inside it are hidden: a console
/// window would be the first thing the user sees.
const LAUNCH_SCRIPT: &str = "$ErrorActionPreference = 'Stop'\n\
     try {\n\
     $p = Start-Process -FilePath $env:VCD_ELEVATED_POWERSHELL -ArgumentList @('-NoProfile','-WindowStyle','Hidden','-EncodedCommand',$env:VCD_ELEVATED_ENCODED) -Verb RunAs -WindowStyle Hidden -Wait -PassThru\n\
     exit $p.ExitCode\n\
     } catch { exit 1 }";

/// Download, verify and start the official installer, elevated. Returns once
/// the installer process exists; the user finishes its wizard.
pub fn install() -> Result<(), String> {
    let script = ELEVATED_SCRIPT
        .replace("__URL__", &installer_url())
        .replace("__DIGEST__", SANDBOXIE_INSTALLER_SHA256);
    let encoded = download::utf16le_base64(&script);

    let status = download::hidden_command(download::powershell())
        .args(["-NoProfile", "-Command", LAUNCH_SCRIPT])
        .env("VCD_ELEVATED_POWERSHELL", download::powershell())
        .env("VCD_ELEVATED_ENCODED", encoded)
        .status()
        .map_err(|error| format!("cannot run powershell: {error}"))?;

    match status.code() {
        Some(0) => Ok(()),
        Some(1) => Err("the administrator prompt was declined; nothing was installed".to_string()),
        Some(2) => Err(
            "the downloaded installer did not match the pinned SHA-256; nothing was run"
                .to_string(),
        ),
        Some(3) => Err("the installer could not be downloaded; nothing was run".to_string()),
        Some(4) => Err(
            "cannot create the installer directory under Program Files; nothing was run"
                .to_string(),
        ),
        Some(5) => Err(
            "the installer finished but Sandboxie-Plus is not under Program Files; check its log"
                .to_string(),
        ),
        _ => Err(format!("the installer did not start (exit code {status})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_url_names_the_pinned_file() {
        let url = installer_url();
        assert!(url.starts_with("https://github.com/sandboxie-plus/Sandboxie/releases/download/"));
        assert!(url.ends_with(&format!("Sandboxie-Plus-x64-v{SANDBOXIE_VERSION}.exe")));
    }

    #[test]
    fn the_pinned_digest_is_a_sha256() {
        assert_eq!(SANDBOXIE_INSTALLER_SHA256.len(), 64);
        assert!(
            SANDBOXIE_INSTALLER_SHA256
                .chars()
                .all(|digit| digit.is_ascii_hexdigit() && !digit.is_ascii_uppercase())
        );
    }

    #[test]
    fn the_elevated_script_downloads_checks_and_installs_silently() {
        let script = ELEVATED_SCRIPT
            .replace("__URL__", &installer_url())
            .replace("__DIGEST__", SANDBOXIE_INSTALLER_SHA256);

        let download_at = script.find("curl.exe").expect("downloads with curl");
        let hash_at = script.find("Get-FileHash").expect("hashes the copy");
        let install_at = script
            .find("/VERYSILENT")
            .expect("installs without a wizard");

        assert!(
            download_at < hash_at,
            "the digest is checked after the download"
        );
        assert!(
            hash_at < install_at,
            "the installer runs only after the check"
        );
        assert!(script.contains("/SUPPRESSMSGBOXES"));
        assert!(script.contains("/NORESTART"));
        assert!(
            script.contains("$attempt -le 2"),
            "a first-run failure is retried once instead of being handed to the user"
        );
        assert!(
            script.contains("SbieSvc"),
            "the service is what makes the install usable"
        );
        assert!(
            !script.contains("Start-Process -FilePath $path"),
            "no interactive wizard is started"
        );
        assert!(
            script.contains("Sandboxie-Plus\\Start.exe"),
            "it verifies the install landed"
        );
        assert!(
            script.contains("Remove-Item -LiteralPath $path"),
            "the installer file does not stay behind"
        );
        assert!(script.contains(SANDBOXIE_INSTALLER_SHA256));
        assert!(
            !script.contains("$env:VCD_SANDBOXIE"),
            "constants travel in the script: the elevated process does not inherit the environment"
        );
    }

    #[test]
    fn both_the_outer_and_the_inner_window_are_hidden() {
        assert!(LAUNCH_SCRIPT.contains("-WindowStyle Hidden"));
        assert!(LAUNCH_SCRIPT.contains("'-WindowStyle','Hidden'"));
    }

    #[test]
    #[ignore = "downloads ~25 MB; run manually"]
    fn the_pinned_installer_downloads_and_matches_the_digest() {
        let directory = download::per_run_directory("vcd-sandboxie-test").expect("temp dir");
        let installer = directory.join("Sandboxie-Plus-x64.exe");

        download::fetch(&installer_url(), &installer).expect("download the installer");
        download::verify_sha256(&installer, SANDBOXIE_INSTALLER_SHA256, "installer")
            .expect("the pinned digest matches");

        let _ = std::fs::remove_dir_all(&directory);
    }
}
