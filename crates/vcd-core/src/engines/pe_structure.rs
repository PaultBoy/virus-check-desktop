//! Header-level PE structure checks.
//!
//! No byte is skipped, and nothing here needs the file body, so it stays cheap
//! on huge files.

use std::time::Instant;

use crate::analysis::PeImage;
use crate::filetype::ContentType;
use crate::report::{Coverage, Detection, EngineReport, Severity};

use super::{Engine, ScanTarget};

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
            if section.is_writable() && section.is_executable() {
                detections.push(Detection {
                    name: "pe-wx-section".to_string(),
                    severity: Severity::Info,
                    detail: format!(
                        "section '{}' is both writable and executable",
                        section.name
                    ),
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

        EngineReport::completed(
            self.name(),
            detections,
            Coverage::Complete,
            started.elapsed(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::analysis::pe::tests::minimal_pe;

    fn target(header: &[u8], content_type: ContentType) -> ScanTarget<'_> {
        ScanTarget {
            path: Path::new("sample.bin"),
            size: header.len() as u64,
            header,
            content_type,
        }
    }

    #[test]
    fn skips_non_pe_content() {
        let report = PeStructureEngine.scan(&target(b"%PDF-1.7", ContentType::Pdf));
        assert!(matches!(report.status, crate::report::EngineStatus::Skipped { .. }));
        assert!(report.detections.is_empty());
    }

    #[test]
    fn reports_malformed_pe() {
        let report = PeStructureEngine.scan(&target(b"MZ garbage", ContentType::Pe));
        assert_eq!(report.detections.len(), 1);
        assert_eq!(report.detections[0].name, "pe-malformed");
        assert_eq!(report.detections[0].severity, Severity::Suspicious);
    }

    #[test]
    fn flags_writable_executable_section_as_info_only() {
        let report =
            PeStructureEngine.scan(&target(&minimal_pe(0x1000, false, true, false), ContentType::Pe));
        assert_eq!(report.detections.len(), 1);
        assert_eq!(report.detections[0].name, "pe-wx-section");
        assert_eq!(report.detections[0].severity, Severity::Info);
    }

    #[test]
    fn reports_entry_point_outside_sections_as_suspicious() {
        let report =
            PeStructureEngine.scan(&target(&minimal_pe(0x9000, false, false, false), ContentType::Pe));
        assert_eq!(report.detections.len(), 1);
        assert_eq!(report.detections[0].name, "pe-entrypoint-outside-sections");
        assert_eq!(report.detections[0].severity, Severity::Suspicious);
    }

    #[test]
    fn a_plain_image_produces_no_detections_and_full_coverage() {
        let report =
            PeStructureEngine.scan(&target(&minimal_pe(0x1000, false, false, false), ContentType::Pe));
        assert!(report.detections.is_empty());
        assert_eq!(report.coverage, Coverage::Complete);
    }
}
