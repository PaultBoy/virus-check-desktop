//! Verdict aggregation.
//!
//! "Undetected" is deliberately not called "clean": it only means no engine in
//! this run reported a detection.
//!
//! - `Skipped` is neutral: the engine does not apply to this type.
//! - `Unavailable` and `Failed` make the run incomplete: a check that should
//!   have run did not, so a quiet result cannot be trusted.
//! - A completed engine that skipped bytes also makes it incomplete.

use serde::{Deserialize, Serialize};

use crate::report::{Coverage, EngineReport, EngineStatus, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Malicious,
    Suspicious,
    Undetected,
    Inconclusive,
    Unknown,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Malicious => "MALICIOUS",
            Verdict::Suspicious => "SUSPICIOUS",
            Verdict::Undetected => "UNDETECTED",
            Verdict::Inconclusive => "INCONCLUSIVE",
            Verdict::Unknown => "UNKNOWN",
        }
    }
}

pub fn aggregate(engines: &[EngineReport]) -> Verdict {
    let mut malicious = false;
    let mut suspicious = false;
    let mut inspected = false;
    let mut incomplete = false;
    let mut completed = false;

    for engine in engines {
        match &engine.status {
            EngineStatus::Completed => {
                completed = true;
                match &engine.coverage {
                    Coverage::Complete => inspected = true,
                    Coverage::Partial { scanned_bytes, .. } => {
                        // Something was read, but a range was skipped: quiet is
                        // not the same as covered. Zero bytes read means the
                        // engine could not open what it is responsible for.
                        if *scanned_bytes > 0 {
                            inspected = true;
                        }
                        incomplete = true;
                    }
                    Coverage::None { .. } => incomplete = true,
                }
            }
            EngineStatus::Unavailable { .. } | EngineStatus::Failed { .. } => incomplete = true,
            EngineStatus::Skipped { .. } => {}
        }

        for detection in &engine.detections {
            match detection.severity {
                Severity::Malicious => malicious = true,
                Severity::Suspicious => suspicious = true,
                Severity::Info => {}
            }
        }
    }

    if malicious {
        Verdict::Malicious
    } else if suspicious {
        Verdict::Suspicious
    } else if !completed || !inspected {
        Verdict::Unknown
    } else if incomplete {
        Verdict::Inconclusive
    } else {
        Verdict::Undetected
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::report::{Coverage, Detection};

    fn detection(severity: Severity) -> Detection {
        Detection {
            name: "test".into(),
            severity,
            detail: String::new(),
        }
    }

    fn report(coverage: Coverage, detections: Vec<Detection>) -> EngineReport {
        EngineReport::completed("stub", detections, coverage, Duration::ZERO)
    }

    #[test]
    fn detections_win_over_gaps() {
        let engines = [
            report(Coverage::Complete, vec![detection(Severity::Malicious)]),
            report(
                Coverage::None {
                    reason: "skipped".into(),
                },
                vec![],
            ),
        ];
        assert_eq!(aggregate(&engines), Verdict::Malicious);
    }

    #[test]
    fn gap_without_detections_is_inconclusive() {
        let engines = [report(
            Coverage::Partial {
                scanned_bytes: 10,
                reason: "2 GiB cap".into(),
            },
            vec![],
        )];
        assert_eq!(aggregate(&engines), Verdict::Inconclusive);
    }

    #[test]
    fn partial_coverage_with_zero_bytes_is_not_inspection() {
        let zero = Coverage::Partial {
            scanned_bytes: 0,
            reason: "engine cap".into(),
        };
        assert!(!zero.inspected());
        assert_eq!(aggregate(&[report(zero, vec![])]), Verdict::Unknown,);
        assert_eq!(
            aggregate(&[
                report(Coverage::Complete, vec![]),
                report(
                    Coverage::Partial {
                        scanned_bytes: 0,
                        reason: "engine cap".into()
                    },
                    vec![]
                )
            ]),
            Verdict::Inconclusive,
        );
    }

    #[test]
    fn full_coverage_without_detections_is_undetected() {
        let engines = [report(Coverage::Complete, vec![])];
        assert_eq!(aggregate(&engines), Verdict::Undetected);
    }

    #[test]
    fn completed_engine_that_inspected_nothing_is_unknown() {
        let engines = [report(
            Coverage::None {
                reason: "nope".into(),
            },
            vec![],
        )];
        assert_eq!(aggregate(&engines), Verdict::Unknown);
        assert_eq!(aggregate(&[]), Verdict::Unknown);
    }

    #[test]
    fn skipped_engine_is_neutral() {
        let engines = [
            report(Coverage::Complete, vec![]),
            EngineReport::skipped("pe-structure", "not a PE image"),
        ];
        assert_eq!(aggregate(&engines), Verdict::Undetected);
    }

    #[test]
    fn unavailable_engine_makes_the_run_incomplete() {
        let engines = [
            report(Coverage::Complete, vec![]),
            EngineReport::unavailable("clamav", "install ClamAV"),
        ];
        assert_eq!(aggregate(&engines), Verdict::Inconclusive);
    }

    #[test]
    fn failed_engine_makes_the_run_incomplete_but_alone_is_unknown() {
        let failed = EngineReport {
            engine: "yara".into(),
            status: EngineStatus::Failed {
                error: "exit code 2".into(),
            },
            detections: vec![],
            facts: vec![],
            coverage: Coverage::Complete,
            duration_ms: 4,
        };
        assert_eq!(
            aggregate(&[report(Coverage::Complete, vec![]), failed.clone()]),
            Verdict::Inconclusive
        );
        assert_eq!(aggregate(&[failed]), Verdict::Unknown);
    }

    #[test]
    fn info_findings_do_not_change_the_verdict() {
        let engines = [report(Coverage::Complete, vec![detection(Severity::Info)])];
        assert_eq!(aggregate(&engines), Verdict::Undetected);
    }
}
