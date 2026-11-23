//! Static analysis core for Virus Check Desktop.
//!
//! Design rule: no report may claim more than was actually inspected. The
//! building blocks are [`hashing`] (one streaming pass over any file size),
//! [`filetype`] (content typing by magic bytes, never by extension),
//! [`analysis`] (structure of the formats we can read) and [`engines`]
//! (per-engine results that carry their own [`report::Coverage`]).

pub mod analysis;
pub mod clamav_install;
pub mod engines;
pub mod filetype;
pub mod hashing;
pub mod report;
pub mod sandbox;
pub mod scanner;
pub mod verdict;

#[cfg(test)]
pub(crate) mod test_support;

pub use sandbox::{
    Backend, DetonateOptions, Detonation, Edition, SandboxError, SandboxSupport, detect_support,
    detonate, detonate_with, enable_windows_sandbox,
};

pub use clamav_install::{
    ClamavStatus, InstallStep, install as install_portable_clamav,
    install_with as install_portable_clamav_with, is_installed as clamav_portable_installed,
    portable_root as clamav_portable_root, status as clamav_status,
};

pub use filetype::{ContentType, Family};
pub use report::{
    Coverage, Detection, DirectoryReport, EngineReport, EngineStatus, Fact, FileError, ScanReport,
    Severity, Summary,
};
pub use scanner::{ScanControl, ScanError, ScanProgress, ScanScope, Scanner};
pub use verdict::Verdict;
