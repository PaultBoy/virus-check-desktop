//! Built-in content/extension engine.
//!
//! The cheapest useful signal in the pipeline: what the file *is* versus what
//! its name claims. No external dependency, and it never skips a byte, so its
//! coverage is always complete.

use std::time::Instant;

use crate::filetype::{Family, compatible, expected_family, extension_of};
use crate::report::{Coverage, Detection, EngineReport, Severity};

use super::{Engine, ScanTarget};

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "jse", "hta", "lnk", "msi",
];

const DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "csv",
    "rtf", "mp3", "mp4", "zip", "rar", "7z",
];

pub struct ContentTypeEngine;

impl Engine for ContentTypeEngine {
    fn name(&self) -> &'static str {
        "content-type"
    }

    fn scan(&self, target: &ScanTarget<'_>) -> EngineReport {
        let started = Instant::now();
        let file_name = target.path.file_name().and_then(|name| name.to_str());
        let mut detections = Vec::new();

        if let Some(name) = file_name
            && let Some(detection) = double_extension(name)
        {
            detections.push(detection);
        }

        if let Some(extension) = extension_of(file_name)
            && let Some(expected) = expected_family(extension)
        {
            let detected = target.content_type.family();
            if !compatible(expected, detected) {
                // Executable content behind a data extension is the
                // dangerous direction; the reverse is usually a container
                // that lost its refinement, so it stays informational.
                let severity = if detected == Family::Executable {
                    Severity::Suspicious
                } else {
                    Severity::Info
                };
                detections.push(Detection {
                    name: "extension-mismatch".to_string(),
                    severity,
                    detail: format!(
                        "extension .{} expects {} content, but the file is {}",
                        extension.to_ascii_lowercase(),
                        expected.as_str(),
                        target.content_type.as_str()
                    ),
                });
            }
        }

        EngineReport::completed(
            self.name(),
            detections,
            Coverage::Complete,
            started.elapsed(),
        )
    }
}

fn double_extension(file_name: &str) -> Option<Detection> {
    let parts: Vec<&str> = file_name.split('.').collect();
    if parts.len() < 3 {
        return None;
    }
    let last = parts.last()?.to_ascii_lowercase();
    if !EXECUTABLE_EXTENSIONS.contains(&last.as_str()) {
        return None;
    }
    let decoy = parts[parts.len() - 2].to_ascii_lowercase();
    if !DECOY_EXTENSIONS.contains(&decoy.as_str()) {
        return None;
    }
    Some(Detection {
        name: "double-extension".to_string(),
        severity: Severity::Suspicious,
        detail: format!("executable .{last} hidden behind a .{decoy} name"),
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::filetype::ContentType;

    fn target<'a>(name: &'a str, content_type: ContentType) -> ScanTarget<'a> {
        ScanTarget {
            path: Path::new(name),
            size: 10,
            header: &[],
            content_type,
        }
    }

    #[test]
    fn flags_executable_behind_document_extension() {
        let report = ContentTypeEngine.scan(&target("invoice.pdf", ContentType::Pe));
        assert_eq!(report.detections.len(), 1);
        assert_eq!(report.detections[0].name, "extension-mismatch");
        assert_eq!(report.detections[0].severity, Severity::Suspicious);
        assert_eq!(report.coverage, Coverage::Complete);
    }

    #[test]
    fn quiet_when_extension_matches() {
        let report = ContentTypeEngine.scan(&target("setup.exe", ContentType::Pe));
        assert!(report.detections.is_empty());
    }

    #[test]
    fn script_without_magic_is_not_a_mismatch() {
        let report = ContentTypeEngine.scan(&target("deploy.ps1", ContentType::Text));
        assert!(report.detections.is_empty());
    }

    #[test]
    fn container_mismatch_stays_informational() {
        let report = ContentTypeEngine.scan(&target("report.docx", ContentType::Zip));
        assert_eq!(report.detections.len(), 1);
        assert_eq!(report.detections[0].severity, Severity::Info);
    }

    #[test]
    fn flags_double_extension() {
        let report = ContentTypeEngine.scan(&target("photo.jpg.exe", ContentType::Pe));
        let names: Vec<&str> = report
            .detections
            .iter()
            .map(|detection| detection.name.as_str())
            .collect();
        assert!(names.contains(&"double-extension"));
    }

    #[test]
    fn ignores_names_without_extension() {
        let report = ContentTypeEngine.scan(&target("README", ContentType::Text));
        assert!(report.detections.is_empty());
    }
}
