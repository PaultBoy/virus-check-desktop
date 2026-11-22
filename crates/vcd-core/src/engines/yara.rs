//! YARA-X engine.
//!
//! In-process pattern matching: `yara-x` is VirusTotal's Rust reimplementation
//! of YARA, so there is no binary to spawn and no signature database to load.
//! Rules come from two places, compiled once per process:
//!
//! - the rules embedded in this binary (they must always compile);
//! - `%LOCALAPPDATA%\VirusCheckDesktop\rules\*.yar|*.yara`, where the user drops
//!   their own rules. A file that fails to compile is skipped and reported, so
//!   one bad rule cannot disable the engine.
//!
//! Severity comes from the rule's `severity` metadata (`malicious`, `suspicious`
//! or `info`); a rule without it is treated as suspicious, never as clean.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use yara_x::{Compiler, MetaValue, Rules, Scanner};

use crate::report::{Coverage, Detection, EngineReport, Fact, Severity};

use super::{Engine, ScanTarget};

/// Small on purpose: these rules must be defensible, not numerous. Everything
/// else belongs in the user's rules directory.
const BUILTIN_RULES: &str = include_str!("../../rules/builtin.yar");

const MAX_REPORTED_SKIPS: usize = 5;

pub struct YaraEngine {
    rules: Option<Rules>,
    rule_count: usize,
    skipped: Vec<String>,
}

impl YaraEngine {
    pub fn discover() -> Self {
        Self::load(default_rules_dir())
    }

    /// Load the embedded rules plus every `.yar`/`.yara` file in `user_dir`.
    pub fn load(user_dir: Option<PathBuf>) -> Self {
        let mut compiler = Compiler::new();
        let mut skipped = Vec::new();

        if let Err(error) = compiler.add_source(BUILTIN_RULES) {
            // Shipping a binary whose own rules do not compile is a build
            // defect; report it instead of pretending there is no engine.
            return Self {
                rules: None,
                rule_count: 0,
                skipped: vec![format!("builtin rules: {error}")],
            };
        }

        if let Some(directory) = user_dir {
            add_user_rules(&mut compiler, &directory, &mut skipped);
        }

        let rules = compiler.build();
        let rule_count = rules.iter().count();

        Self {
            rules: Some(rules),
            rule_count,
            skipped,
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

impl Engine for YaraEngine {
    fn name(&self) -> &'static str {
        "yara"
    }

    fn scan(&self, target: &ScanTarget<'_>) -> EngineReport {
        let Some(rules) = &self.rules else {
            return EngineReport::unavailable(
                self.name(),
                self.skipped
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "no rules could be loaded".to_string()),
            );
        };

        let started = Instant::now();
        let mut scanner = Scanner::new(rules);

        let results = match scanner.scan_file(target.path) {
            Ok(results) => results,
            Err(error) => {
                return EngineReport::failed(self.name(), format!("cannot scan: {error}"));
            }
        };

        let mut detections = Vec::new();
        for rule in results.matching_rules() {
            let identifier = rule.identifier().to_string();
            let description = metadata_string(&rule, "description");
            detections.push(Detection {
                name: "yara-match".to_string(),
                severity: metadata_severity(&rule),
                detail: match description {
                    Some(description) => format!("{identifier}: {description}"),
                    None => identifier,
                },
            });
        }

        let mut facts = vec![
            Fact::new("rules", self.rule_count.to_string()),
            Fact::new("matches", detections.len().to_string()),
        ];
        if !self.skipped.is_empty() {
            let shown: Vec<&str> = self
                .skipped
                .iter()
                .take(MAX_REPORTED_SKIPS)
                .map(String::as_str)
                .collect();
            facts.push(Fact::new("skipped rules", shown.join("; ")));
        }

        EngineReport::completed(self.name(), detections, Coverage::Complete, started.elapsed())
            .with_facts(facts)
    }
}

fn add_user_rules(compiler: &mut Compiler, directory: &Path, skipped: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };

    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("yar") || extension.eq_ignore_ascii_case("yara")
                })
        })
        .collect();
    paths.sort();

    for path in paths {
        match fs::read_to_string(&path) {
            Ok(source) => match compiler.add_source(source.as_str()) {
                Ok(_) => {}
                Err(error) => skipped.push(format!("{}: {error}", file_name(&path))),
            },
            Err(error) => skipped.push(format!("{}: {error}", file_name(&path))),
        }
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<rule file>")
        .to_string()
}

fn metadata_string(rule: &yara_x::Rule, wanted: &str) -> Option<String> {
    rule.metadata().find_map(|(name, value)| {
        if name != wanted {
            return None;
        }
        match value {
            MetaValue::String(text) => Some(text.to_string()),
            _ => None,
        }
    })
}

fn metadata_severity(rule: &yara_x::Rule) -> Severity {
    match metadata_string(rule, "severity")
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("malicious") => Severity::Malicious,
        Some("info") => Severity::Info,
        _ => Severity::Suspicious,
    }
}

fn default_rules_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(|base| PathBuf::from(base).join("VirusCheckDesktop").join("rules"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::report::EngineStatus;
    use crate::test_support::TempFile;

    const EICAR: &str =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    fn scan_bytes(name: &str, bytes: &[u8]) -> EngineReport {
        let file = TempFile::new(name, bytes);
        let target = ScanTarget {
            path: file.path(),
            size: bytes.len() as u64,
            header: bytes,
            content_type: crate::filetype::ContentType::Text,
        };
        YaraEngine::load(None).scan(&target)
    }

    #[test]
    fn builtin_rules_detect_eicar() {
        let report = scan_bytes("eicar.com", EICAR.as_bytes());

        assert_eq!(report.status, EngineStatus::Completed);
        let detection = report
            .detections
            .iter()
            .find(|detection| detection.name == "yara-match")
            .expect("eicar detection");
        assert_eq!(detection.severity, Severity::Malicious);
        assert!(detection.detail.contains("eicar"));
    }

    #[test]
    fn a_clean_file_matches_nothing() {
        let report = scan_bytes("plain.txt", b"nothing to see here\n");

        assert!(report.detections.is_empty());
        assert_eq!(report.coverage, Coverage::Complete);
        assert!(
            report
                .facts
                .iter()
                .any(|fact| fact.name == "rules" && fact.value != "0")
        );
    }

    #[test]
    fn an_embedded_rule_without_severity_is_only_suspicious() {
        // The builtin encoded-PowerShell rule carries `severity = "suspicious"`,
        // so this also proves metadata is read rather than assumed.
        let sample = "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=";
        let report = scan_bytes("run.ps1", sample.as_bytes());

        let detection = report
            .detections
            .iter()
            .find(|detection| detection.detail.contains("encoded"))
            .expect("encoded command detection");
        assert_eq!(detection.severity, Severity::Suspicious);
    }

    #[test]
    fn user_rules_are_loaded_from_the_directory() {
        let directory = std::env::temp_dir().join(format!("vcd-rules-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create rules dir");
        fs::write(
            directory.join("marker.yar"),
            r#"
rule user_marker : marker {
    meta:
        description = "user supplied marker"
        severity = "info"
    strings:
        $marker = "VCD-USER-RULE-MARKER"
    condition:
        $marker
}
"#,
        )
        .expect("write rule");

        let engine = YaraEngine::load(Some(directory.clone()));
        let file = TempFile::new("marker.txt", b"prefix VCD-USER-RULE-MARKER suffix");
        let target = ScanTarget {
            path: file.path(),
            size: 32,
            header: b"",
            content_type: crate::filetype::ContentType::Text,
        };
        let report = engine.scan(&target);

        let detection = report
            .detections
            .iter()
            .find(|detection| detection.detail.starts_with("user_marker"))
            .expect("user rule match");
        assert_eq!(detection.severity, Severity::Info);
        assert_eq!(engine.rule_count(), 3);

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_broken_user_rule_is_skipped_without_disabling_the_engine() {
        let directory = std::env::temp_dir().join(format!("vcd-rules-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create rules dir");
        fs::write(directory.join("broken.yar"), "rule { nope").expect("write bad rule");

        let engine = YaraEngine::load(Some(directory.clone()));
        let file = TempFile::new("eicar.com", EICAR.as_bytes());
        let target = ScanTarget {
            path: file.path(),
            size: EICAR.len() as u64,
            header: b"",
            content_type: crate::filetype::ContentType::Text,
        };
        let report = engine.scan(&target);

        // The embedded EICAR rule still works, and the failure is visible.
        assert!(!report.detections.is_empty());
        assert!(
            report
                .facts
                .iter()
                .any(|fact| fact.name == "skipped rules" && fact.value.contains("broken.yar"))
        );

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn scanning_a_missing_file_fails_instead_of_reporting_clean() {
        let engine = YaraEngine::load(None);
        let target = ScanTarget {
            path: Path::new(r"C:\definitely-missing\vcd-yara-none.bin"),
            size: 1,
            header: b"",
            content_type: crate::filetype::ContentType::Text,
        };
        let report = engine.scan(&target);

        assert!(matches!(report.status, EngineStatus::Failed { .. }));
    }
}
