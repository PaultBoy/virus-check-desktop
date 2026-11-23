//! Header-level PE structure checks, plus the two bounded peeks that are worth
//! a file read: the import table and section entropy.
//!
//! The engine declares its scope as a fact, because `Coverage::Complete` means
//! "complete for the scope this engine claims", not "every byte was hashed".

use std::fs::File;
use std::time::Instant;

use crate::analysis::entropy::shannon;
use crate::analysis::imports::read_imports;
use crate::analysis::{PeImage, read_at};
use crate::filetype::ContentType;
use crate::report::{Coverage, Detection, EngineReport, Fact, Severity};

use super::{Engine, ScanTarget};

/// Per-section sample cap. Entropy over a sample is a hint, and a bounded read
/// keeps a 2 GiB packed binary as cheap as a small one.
const SAMPLE_PER_SECTION: u64 = 256 * 1024;

/// Total sample budget for one scan, across all sections.
const SAMPLE_BUDGET: u64 = 4 * 1024 * 1024;

/// Below this, entropy says nothing useful.
const MIN_SECTION_BYTES: u64 = 4096;

/// Near 8 bits per byte: compressed or encrypted content.
const HIGH_ENTROPY: f64 = 7.2;

/// Small native images legitimately have no imports; larger ones that lack a
/// readable table are worth a look.
const MIN_IMPORT_CHECK_SIZE: u64 = 64 * 1024;

const PACKER_MARKERS: &[&str] = &[
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".packed", "pec2", ".themida", ".vmp0", ".vmp1",
    ".petite",
];

pub struct PeStructureEngine;

impl Engine for PeStructureEngine {
    fn name(&self) -> &'static str {
        "pe-structure"
    }

    fn scan(&self, target: &ScanTarget<'_>) -> EngineReport {
        if target.content_type != ContentType::Pe {
            return EngineReport::skipped(self.name(), "not a PE image");
        }

        let started = Instant::now();
        let Some(image) = PeImage::parse(target.header) else {
            return EngineReport::completed(
                self.name(),
                vec![Detection {
                    name: "pe-malformed".to_string(),
                    severity: Severity::Suspicious,
                    detail: "content starts like a PE image but the header cannot be parsed"
                        .to_string(),
                }],
                Coverage::Complete,
                started.elapsed(),
            );
        };

        let mut detections = Vec::new();
        let mut facts = vec![
            Fact::new(
                "scope",
                "PE headers, import table, section entropy from bounded samples",
            ),
            Fact::new("machine", image.machine_name()),
            Fact::new("sections", image.sections.len().to_string()),
            Fact::new("entry point", format!("0x{:X}", image.entry_point)),
        ];

        if image.has_entry_point_outside_sections() {
            detections.push(Detection {
                name: "pe-entrypoint-outside-sections".to_string(),
                severity: Severity::Suspicious,
                detail: format!(
                    "entry point RVA 0x{:X} falls outside every section ({}, {} sections)",
                    image.entry_point,
                    image.machine_name(),
                    image.sections.len()
                ),
            });
        }

        if image.number_of_sections == 0 || image.number_of_sections > 96 {
            detections.push(Detection {
                name: "pe-section-count".to_string(),
                severity: Severity::Suspicious,
                detail: format!(
                    "{} sections is outside what normal linkers emit",
                    image.number_of_sections
                ),
            });
        }

        for section in &image.sections {
            let lowered = section.name.to_ascii_lowercase();
            if PACKER_MARKERS
                .iter()
                .any(|marker| lowered == *marker || lowered.starts_with(marker))
            {
                detections.push(Detection {
                    name: "pe-packer-section".to_string(),
                    severity: Severity::Info,
                    detail: format!(
                        "section '{}' matches a known packer naming scheme",
                        section.name
                    ),
                });
            }

            if section.is_writable() && section.is_executable() {
                detections.push(Detection {
                    name: "pe-wx-section".to_string(),
                    severity: Severity::Info,
                    detail: format!("section '{}' is both writable and executable", section.name),
                });
            }

            if !section.printable_name {
                detections.push(Detection {
                    name: "pe-section-name".to_string(),
                    severity: Severity::Info,
                    detail: "a section name contains non-printable bytes".to_string(),
                });
            }
        }

        if image.is_dotnet {
            detections.push(Detection {
                name: "pe-dotnet".to_string(),
                severity: Severity::Info,
                detail: format!(
                    "managed .NET assembly ({}, {} sections)",
                    image.machine_name(),
                    image.sections.len()
                ),
            });
        }

        let mut file = match File::open(target.path) {
            Ok(file) => file,
            Err(error) => {
                return EngineReport::failed(
                    self.name(),
                    format!("cannot read {}: {error}", target.path.display()),
                );
            }
        };

        match read_imports(&mut file, &image) {
            Ok(summary) if summary.is_empty() => {
                facts.push(Fact::new("imports", "none"));
                if !image.is_dotnet && target.size > MIN_IMPORT_CHECK_SIZE {
                    detections.push(Detection {
                        name: "pe-no-imports".to_string(),
                        severity: Severity::Suspicious,
                        detail: "native image larger than 64 KiB with no readable import table"
                            .to_string(),
                    });
                }
            }
            Ok(summary) => {
                facts.push(Fact::new("imports", format!("{} DLLs", summary.dlls.len())));
                facts.push(Fact::new("import dlls", summary.dlls.join(", ")));
                if summary.truncated {
                    facts.push(Fact::new("imports truncated", "yes"));
                }
            }
            Err(_) => facts.push(Fact::new("imports", "unreadable")),
        }

        let mut budget = SAMPLE_BUDGET;
        let mut peak: Option<(String, f64, u64)> = None;

        for section in &image.sections {
            if section.raw_size == 0 || budget == 0 {
                continue;
            }

            let take = (section.raw_size as u64)
                .min(SAMPLE_PER_SECTION)
                .min(budget);
            if take < MIN_SECTION_BYTES {
                continue;
            }

            let Ok(bytes) = read_at(&mut file, section.raw_pointer as u64, take as usize) else {
                continue;
            };
            if bytes.is_empty() {
                continue;
            }
            budget -= take;

            let entropy = shannon(&bytes);
            if peak.as_ref().is_none_or(|(_, best, _)| entropy > *best) {
                peak = Some((section.name.clone(), entropy, bytes.len() as u64));
            }

            if entropy >= HIGH_ENTROPY {
                detections.push(Detection {
                    name: "pe-high-entropy-section".to_string(),
                    severity: Severity::Info,
                    detail: format!(
                        "section '{}' entropy {entropy:.2} over {} bytes sampled",
                        section.name,
                        bytes.len()
                    ),
                });
            }
        }

        if let Some((name, entropy, sampled)) = peak {
            facts.push(Fact::new(
                "entropy max",
                format!("{entropy:.2} in '{name}' over {sampled} bytes"),
            ));
        }

        EngineReport::completed(
            self.name(),
            detections,
            Coverage::Complete,
            started.elapsed(),
        )
        .with_facts(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::pe::tests::{minimal_pe, minimal_pe_with_section_body};
    use crate::report::EngineStatus;
    use crate::test_support::TempFile;

    fn scan(bytes: &[u8], content_type: ContentType) -> EngineReport {
        let file = TempFile::new("sample.bin", bytes);
        let target = ScanTarget {
            path: file.path(),
            size: bytes.len() as u64,
            header: bytes,
            content_type,
        };
        PeStructureEngine.scan(&target)
    }

    fn names(report: &EngineReport) -> Vec<&str> {
        report
            .detections
            .iter()
            .map(|detection| detection.name.as_str())
            .collect()
    }

    #[test]
    fn skips_non_pe_content() {
        let report = scan(b"%PDF-1.7", ContentType::Pdf);
        assert!(matches!(report.status, EngineStatus::Skipped { .. }));
        assert!(report.detections.is_empty());
    }

    #[test]
    fn reports_malformed_pe() {
        let report = scan(b"MZ garbage", ContentType::Pe);
        assert_eq!(names(&report), vec!["pe-malformed"]);
        assert_eq!(report.detections[0].severity, Severity::Suspicious);
    }

    #[test]
    fn flags_writable_executable_section_as_info_only() {
        let report = scan(&minimal_pe(0x1000, false, true, false), ContentType::Pe);
        assert_eq!(names(&report), vec!["pe-wx-section"]);
        assert_eq!(report.detections[0].severity, Severity::Info);
    }

    #[test]
    fn reports_entry_point_outside_sections_as_suspicious() {
        let report = scan(&minimal_pe(0x9000, false, false, false), ContentType::Pe);
        assert_eq!(names(&report), vec!["pe-entrypoint-outside-sections"]);
        assert_eq!(report.detections[0].severity, Severity::Suspicious);
    }

    #[test]
    fn a_plain_image_produces_no_detections_and_reports_facts() {
        let report = scan(&minimal_pe(0x1000, false, false, false), ContentType::Pe);

        assert!(report.detections.is_empty());
        assert_eq!(report.coverage, Coverage::Complete);
        assert!(
            report
                .facts
                .iter()
                .any(|fact| fact.name == "machine" && fact.value == "x86")
        );
        assert!(
            report
                .facts
                .iter()
                .any(|fact| fact.name == "imports" && fact.value == "none")
        );
    }

    #[test]
    fn high_entropy_section_is_reported_as_info() {
        let bytes = minimal_pe_with_section_body(8192, |index| {
            (index.wrapping_mul(2_654_435_761) >> 7) as u8
        });
        let report = scan(&bytes, ContentType::Pe);

        assert!(names(&report).contains(&"pe-high-entropy-section"));
        assert!(
            report
                .facts
                .iter()
                .any(|fact| fact.name == "entropy max" && fact.value.contains("in '.text'"))
        );
    }

    #[test]
    fn a_large_native_image_without_imports_is_suspicious() {
        let mut bytes = minimal_pe(0x1000, false, false, false);
        bytes.resize(0x20000, 0);

        let report = scan(&bytes, ContentType::Pe);

        assert!(names(&report).contains(&"pe-no-imports"));
        let detection = report
            .detections
            .iter()
            .find(|detection| detection.name == "pe-no-imports")
            .expect("detection");
        assert_eq!(detection.severity, Severity::Suspicious);
    }
}
