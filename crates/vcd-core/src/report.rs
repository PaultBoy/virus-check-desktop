//! Report model shared by the CLI and the UI.
//!
//! Every engine reports its own [`Coverage`]. The model never merges "scanned"
//! and "skipped" into one boolean, because that is how a scanner ends up
//! saying "clean" about a 5 GiB file that its engine refused to open.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::filetype::ContentType;
use crate::hashing::FileDigests;
use crate::verdict::Verdict;

/// How much of the target an engine actually inspected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Coverage {
    /// Every byte the engine is responsible for was inspected.
    Complete,
    /// Part of the target was inspected; `reason` names the limit that stopped
    /// the engine (its own cap, not ours).
    Partial { scanned_bytes: u64, reason: String },
    /// Nothing was inspected; `reason` says why.
    None { reason: String },
}

impl Coverage {
    /// `Partial` with zero bytes read is not inspection: it is an engine that
    /// could not open what it is responsible for.
    pub fn inspected(&self) -> bool {
        match self {
            Coverage::Complete => true,
            Coverage::Partial { scanned_bytes, .. } => *scanned_bytes > 0,
            Coverage::None { .. } => false,
        }
    }

    pub fn is_complete(&self) -> bool {
        matches!(self, Coverage::Complete)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Malicious,
    Suspicious,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Malicious => "malicious",
            Severity::Suspicious => "suspicious",
            Severity::Info => "info",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Stable identifier, safe to match on: `extension-mismatch`,
    /// `double-extension`, `clamav-signature`, ...
    pub name: String,
    pub severity: Severity,
    /// Human-readable evidence.
    pub detail: String,
}

/// A measured property the UI can render as a table row. Facts carry no
/// judgement: they are what the engine saw, not what it concluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub name: String,
    pub value: String,
}

impl Fact {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineStatus {
    Completed,
    /// The engine is installed-but-broken or not reachable; `hint` tells the
    /// user how to make it available.
    Unavailable { hint: String },
    Failed { error: String },
    /// The engine does not apply to this target type; `reason` says why.
    Skipped { reason: String },
}

impl EngineStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EngineStatus::Completed => "completed",
            EngineStatus::Unavailable { .. } => "unavailable",
            EngineStatus::Failed { .. } => "failed",
            EngineStatus::Skipped { .. } => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineReport {
    pub engine: String,
    pub status: EngineStatus,
    pub detections: Vec<Detection>,
    /// Measured properties, not findings.
    pub facts: Vec<Fact>,
    pub coverage: Coverage,
    pub duration_ms: u64,
}

impl EngineReport {
    pub fn completed(
        engine: impl Into<String>,
        detections: Vec<Detection>,
        coverage: Coverage,
        duration: Duration,
    ) -> Self {
        Self {
            engine: engine.into(),
            status: EngineStatus::Completed,
            detections,
            facts: Vec::new(),
            coverage,
            duration_ms: duration.as_millis() as u64,
        }
    }

    pub fn with_facts(mut self, facts: Vec<Fact>) -> Self {
        self.facts = facts;
        self
    }

    pub fn unavailable(engine: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            engine: engine.into(),
            status: EngineStatus::Unavailable {
                hint: hint.into(),
            },
            detections: Vec::new(),
            facts: Vec::new(),
            coverage: Coverage::None {
                reason: "engine unavailable".to_string(),
            },
            duration_ms: 0,
        }
    }

    pub fn failed(engine: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            engine: engine.into(),
            status: EngineStatus::Failed {
                error: error.into(),
            },
            detections: Vec::new(),
            facts: Vec::new(),
            coverage: Coverage::None {
                reason: "engine failed".to_string(),
            },
            duration_ms: 0,
        }
    }

    pub fn skipped(engine: impl Into<String>, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            engine: engine.into(),
            status: EngineStatus::Skipped {
                reason: reason.clone(),
            },
            detections: Vec::new(),
            facts: Vec::new(),
            coverage: Coverage::None { reason },
            duration_ms: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: PathBuf,
    pub size: u64,
    pub content_type: ContentType,
    pub extension: Option<String>,
    pub hashes: FileDigests,
    pub engines: Vec<EngineReport>,
    pub verdict: Verdict,
    pub duration_ms: u64,
    pub scanned_at_unix_ms: u64,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn coverage_partial_is_inspected_but_not_complete() {
        let partial = Coverage::Partial {
            scanned_bytes: 4,
            reason: "cap".into(),
        };
        assert!(partial.inspected());
        assert!(!partial.is_complete());
        assert!(!Coverage::None { reason: "x".into() }.inspected());
    }

    #[test]
    fn report_round_trips_through_json() {
        let report = ScanReport {
            target: PathBuf::from(r"C:\samples\x.bin"),
            size: 12,
            content_type: ContentType::Pe,
            extension: Some("pdf".into()),
            hashes: FileDigests {
                size: 12,
                md5: "a".into(),
                sha1: "b".into(),
                sha256: "c".into(),
            },
            engines: vec![EngineReport::completed(
                "content-type",
                vec![Detection {
                    name: "extension-mismatch".into(),
                    severity: Severity::Suspicious,
                    detail: "pe behind pdf".into(),
                }],
                Coverage::Complete,
                Duration::from_millis(2),
            )],
            verdict: Verdict::Suspicious,
            duration_ms: 3,
            scanned_at_unix_ms: 1,
        };

        let json = serde_json::to_string(&report).expect("serialize");
        let restored: ScanReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, report);
        assert!(json.contains("\"verdict\":\"suspicious\""));
        assert!(json.contains("\"kind\":\"complete\""));
    }
}
