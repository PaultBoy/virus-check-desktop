//! Scan orchestration: read once, type, hash, fan out to engines.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::engines::{
    ClamAvEngine, ContentTypeEngine, Engine, PeStructureEngine, ScanTarget,
};
use crate::filetype::{HEADER_BYTES, detect, extension_of};
use crate::hashing::hash_file;
use crate::report::ScanReport;
use crate::verdict::aggregate;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("not a regular file: {0}")]
    NotAFile(PathBuf),
}

pub struct Scanner {
    engines: Vec<Box<dyn Engine>>,
}

impl Scanner {
    pub fn new(engines: Vec<Box<dyn Engine>>) -> Self {
        Self { engines }
    }

    /// Built-in engines only: no external binary, no network.
    pub fn with_builtin() -> Self {
        Self::new(vec![
            Box::new(ContentTypeEngine),
            Box::new(PeStructureEngine),
        ])
    }

    /// Everything this machine can run. An external engine that is missing is
    /// reported as unavailable, which makes the verdict Inconclusive instead of
    /// pretending the check happened.
    pub fn with_local_engines() -> Self {
        Self::new(vec![
            Box::new(ContentTypeEngine),
            Box::new(PeStructureEngine),
            Box::new(ClamAvEngine::discover()),
        ])
    }

    pub fn engines(&self) -> Vec<&'static str> {
        self.engines.iter().map(|engine| engine.name()).collect()
    }

    pub fn scan(&self, path: &Path) -> Result<ScanReport, ScanError> {
        let started = Instant::now();

        let metadata = std::fs::metadata(path).map_err(|source| ScanError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.is_file() {
            return Err(ScanError::NotAFile(path.to_path_buf()));
        }

        let header = read_header(path)?;
        let file_name = path.file_name().and_then(|name| name.to_str());
        let content_type = detect(&header, file_name);

        let hashes = hash_file(path).map_err(|source| ScanError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let target = ScanTarget {
            path,
            size: hashes.size,
            header: &header,
            content_type,
        };
        let engines: Vec<_> = self
            .engines
            .iter()
            .map(|engine| engine.scan(&target))
            .collect();

        let verdict = aggregate(&engines);

        Ok(ScanReport {
            target: path.to_path_buf(),
            size: hashes.size,
            content_type,
            extension: extension_of(file_name).map(str::to_ascii_lowercase),
            hashes,
            engines,
            verdict,
            duration_ms: started.elapsed().as_millis() as u64,
            scanned_at_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis() as u64)
                .unwrap_or(0),
        })
    }
}

fn read_header(path: &Path) -> Result<Vec<u8>, ScanError> {
    let file = File::open(path).map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut buffer = vec![0u8; HEADER_BYTES];
    let mut filled = 0;
    let mut reader = file;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(ScanError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    use super::*;
    use crate::analysis::pe::tests::minimal_pe;
    use crate::report::Coverage;
    use crate::verdict::Verdict;

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(name: &str, bytes: &[u8]) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("vcd-{unique}-{name}"));
            let mut file = fs::File::create(&path).expect("create temp file");
            file.write_all(bytes).expect("write temp file");
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn scans_disguised_executable_end_to_end() {
        let file = TempFile::new("invoice.pdf", &minimal_pe(0x1000, false, false, false));
        let report = Scanner::with_builtin().scan(&file.path).expect("scan");

        assert_eq!(report.content_type, crate::filetype::ContentType::Pe);
        assert_eq!(report.extension.as_deref(), Some("pdf"));
        assert_eq!(report.size, 0x400);
        assert_eq!(report.hashes.sha256.len(), 64);
        assert_eq!(report.verdict, Verdict::Suspicious);

        assert_eq!(report.engines.len(), 2);
        let content = report
            .engines
            .iter()
            .find(|engine| engine.engine == "content-type")
            .expect("content engine");
        assert!(
            content
                .detections
                .iter()
                .any(|detection| detection.name == "extension-mismatch")
        );

        let structure = report
            .engines
            .iter()
            .find(|engine| engine.engine == "pe-structure")
            .expect("pe engine");
        assert_eq!(structure.coverage, Coverage::Complete);
    }

    #[test]
    fn scans_empty_file_without_failing() {
        let file = TempFile::new("empty.bin", &[]);
        let report = Scanner::with_builtin().scan(&file.path).expect("scan");
        assert_eq!(report.size, 0);
        assert_eq!(report.content_type, crate::filetype::ContentType::Unknown);
        assert_eq!(report.verdict, Verdict::Undetected);
    }

    #[test]
    fn rejects_directories() {
        let error = Scanner::with_builtin()
            .scan(&std::env::temp_dir())
            .expect_err("directory must be rejected");
        assert!(matches!(error, ScanError::NotAFile(_)));
    }

    #[test]
    fn missing_file_reports_the_path() {
        let missing = std::env::temp_dir().join("vcd-does-not-exist-9271");
        let error = Scanner::with_builtin().scan(&missing).expect_err("missing");
        let message = error.to_string();
        assert!(message.contains("vcd-does-not-exist-9271"), "{message}");
    }
}
