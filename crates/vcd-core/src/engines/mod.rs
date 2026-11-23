//! Engine contract.
//!
//! An engine inspects a target and returns an [`EngineReport`] carrying its own
//! status, findings and coverage. External engines (ClamAV, Defender, YARA-X)
//! are spawned as processes by their own modules; nothing here links their code.

pub mod clamav;
pub mod clamav_direct;
pub mod clamd;
pub mod content;
pub mod defender;
pub mod pe_structure;
pub mod yara;

use std::path::Path;

use crate::filetype::ContentType;
use crate::report::EngineReport;

pub use clamav::ClamAvEngine;
pub use content::ContentTypeEngine;
pub use defender::DefenderEngine;
pub use pe_structure::PeStructureEngine;
pub use yara::YaraEngine;

/// Everything an engine may look at. `header` is read once by the scanner, so
/// an engine that only needs magic bytes or headers never touches the disk.
pub struct ScanTarget<'a> {
    pub path: &'a Path,
    pub size: u64,
    pub header: &'a [u8],
    pub content_type: ContentType,
}

pub trait Engine: Send + Sync {
    fn name(&self) -> &'static str;
    fn scan(&self, target: &ScanTarget<'_>) -> EngineReport;
}
