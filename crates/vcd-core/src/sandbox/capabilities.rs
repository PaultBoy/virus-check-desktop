//! Which detonation backends this machine can use, and how to get one.
//!
//! Windows Sandbox is a VM boundary and only exists on Pro/Enterprise/Education.
//! Sandboxie shares the kernel and works on Home, so it is the fallback; the
//! trade-off is reported with every detonation instead of being hidden.

use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Edition {
    Home,
    Pro,
    Enterprise,
    Education,
    Unknown,
}

impl Edition {
    pub fn as_str(self) -> &'static str {
        match self {
            Edition::Home => "Home",
            Edition::Pro => "Pro",
            Edition::Enterprise => "Enterprise",
            Edition::Education => "Education",
            Edition::Unknown => "unknown",
        }
    }

    /// Windows Sandbox is only available on these editions.
    pub fn supports_windows_sandbox(self) -> bool {
        matches!(
            self,
            Edition::Pro | Edition::Enterprise | Edition::Education
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    WindowsSandbox,
    Sandboxie,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::WindowsSandbox => "Windows Sandbox",
            Backend::Sandboxie => "Sandboxie",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSupport {
    pub edition: Edition,
    pub windows_sandbox: bool,
    pub sandboxie: bool,
}

impl SandboxSupport {
    pub fn available(&self) -> Vec<Backend> {
        let mut backends = Vec::new();
        if self.windows_sandbox {
            backends.push(Backend::WindowsSandbox);
        }
        if self.sandboxie {
            backends.push(Backend::Sandboxie);
        }
        backends
    }

    /// Prefer the VM boundary when both exist.
    pub fn recommended(&self) -> Option<Backend> {
        if self.windows_sandbox {
            Some(Backend::WindowsSandbox)
        } else if self.sandboxie {
            Some(Backend::Sandboxie)
        } else {
            None
        }
    }

    /// One line the CLI and the UI can show as-is.
    pub fn guidance(&self) -> String {
        match (self.windows_sandbox, self.sandboxie) {
            (true, true) => "Windows Sandbox (VM) and Sandboxie (shared kernel) are both available"
                .to_string(),
            (true, false) => "Windows Sandbox is available; Sandboxie is not installed".to_string(),
            (false, true) if self.edition.supports_windows_sandbox() => {
                "Sandboxie is available; Windows Sandbox is not enabled on this machine".to_string()
            }
            (false, true) => format!(
                "Sandboxie is available; Windows Sandbox requires Pro/Enterprise (this is {})",
                self.edition.as_str()
            ),
            (false, false) if self.edition.supports_windows_sandbox() => {
                "no backend: enable Windows Sandbox (administrator + reboot), or install Sandboxie-Plus"
                    .to_string()
            }
            (false, false) => format!(
                "no backend: Windows Sandbox requires Pro/Enterprise (this is {}), so install Sandboxie-Plus",
                self.edition.as_str()
            ),
        }
    }
}

pub fn detect_support() -> SandboxSupport {
    SandboxSupport {
        edition: edition(),
        windows_sandbox: windows_sandbox_present(),
        sandboxie: super::sandboxie::discover().is_some(),
    }
}

fn edition() -> Edition {
    let Ok(output) = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "/v",
            "EditionID",
        ])
        .output()
    else {
        return Edition::Unknown;
    };

    let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();

    if text.contains("education") {
        Edition::Education
    } else if text.contains("enterprise") {
        Edition::Enterprise
    } else if text.contains("professional") {
        Edition::Pro
    } else if text.contains("home") {
        Edition::Home
    } else {
        Edition::Unknown
    }
}

fn windows_sandbox_present() -> bool {
    std::env::var_os("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join("WindowsSandbox.exe")
        .is_file()
}

const ENABLE_SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$log = Join-Path $env:TEMP 'vcd-enable-sandbox.log'
try {
    Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart -ErrorAction Stop |
        Out-File $log -Encoding utf8
    'enabled: a reboot is required before Windows Sandbox works' | Add-Content $log
} catch {
    "error: $($_.Exception.Message)" | Out-File $log -Encoding utf8
    exit 1
}
"#;

/// Ask for a UAC prompt that enables the Windows Sandbox feature. Returns the
/// log path; the caller must tell the user a reboot is required.
pub fn enable_windows_sandbox() -> Result<PathBuf, String> {
    let script = std::env::temp_dir().join("vcd-enable-sandbox.ps1");
    std::fs::write(&script, ENABLE_SCRIPT).map_err(|error| error.to_string())?;

    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{}'",
                script.display()
            ),
        ])
        .spawn()
        .map_err(|error| error.to_string())?;

    Ok(std::env::temp_dir().join("vcd-enable-sandbox.log"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_never_offers_windows_sandbox() {
        assert!(!Edition::Home.supports_windows_sandbox());
        assert!(Edition::Pro.supports_windows_sandbox());
        assert!(Edition::Enterprise.supports_windows_sandbox());
        assert!(Edition::Education.supports_windows_sandbox());
    }

    #[test]
    fn the_vm_backend_is_recommended_when_available() {
        let both = SandboxSupport {
            edition: Edition::Pro,
            windows_sandbox: true,
            sandboxie: true,
        };
        assert_eq!(both.recommended(), Some(Backend::WindowsSandbox));
        assert_eq!(both.available().len(), 2);

        let home = SandboxSupport {
            edition: Edition::Home,
            windows_sandbox: false,
            sandboxie: true,
        };
        assert_eq!(home.recommended(), Some(Backend::Sandboxie));
        assert!(home.guidance().contains("Pro/Enterprise"));
    }

    #[test]
    fn no_backend_says_what_to_do() {
        let pro = SandboxSupport {
            edition: Edition::Pro,
            windows_sandbox: false,
            sandboxie: false,
        };
        assert!(pro.guidance().contains("enable Windows Sandbox"));

        let home = SandboxSupport {
            edition: Edition::Home,
            windows_sandbox: false,
            sandboxie: false,
        };
        assert!(home.guidance().contains("Sandboxie-Plus"));
    }
}
