//! Static analysis core for Virus Check Desktop.
//!
//! Design rule: no report may claim more than was actually inspected. The
//! building blocks are [`hashing`] (one streaming pass over any file size),
//! [`filetype`] (content typing by magic bytes, never by extension),
//! [`analysis`] (structure of the formats we can read) and [`engines`]
//! (per-engine results that carry their own [`report::Coverage`]).

pub mod analysis;
pub mod engines;
pub mod filetype;
pub mod hashing;
pub mod report;
pub mod scanner;
pub mod verdict;

#[cfg(test)]
pub(crate) mod test_support;

pub use filetype::{ContentType, Family};
pub use report::{Coverage, Detection, EngineReport, EngineStatus, Fact, ScanReport, Severity};
pub use scanner::{ScanError, Scanner};
pub use verdict::Verdict;
