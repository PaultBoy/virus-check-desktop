//! Scan orchestration: read once, type, hash, fan out to engines.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::engines::{
    ClamAvEngine, ContentTypeEngine, DefenderEngine, Engine, PeStructureEngine, ScanTarget,
    YaraEngine,
};
use crate::filetype::{HEADER_BYTES, detect, extension_of};
use crate::hashing::hash_file;
use crate::report::{DirectoryReport, FileError, ScanReport, Summary};
use crate::verdict::{Verdict, aggregate};

/// Hint for engine selection: a managed ClamAV daemon pays for itself only when
/// more than one file will be scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanScope {
    SingleFile,
    Tree,
}

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
    #[error("not a directory: {0}")]
    NotADirectory(PathBuf),
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
    pub fn with_local_engines(scope: ScanScope) -> Self {
        Self::new(vec![
            Box::new(ContentTypeEngine),
            Box::new(PeStructureEngine),
            Box::new(DefenderEngine::discover()),
            Box::new(YaraEngine::discover()),
            Box::new(ClamAvEngine::discover(scope == ScanScope::Tree)),
        ])
    }

    pub fn engines(&self) -> Vec<&'static str> {
        self.engines.iter().map(|engine| engine.name()).collect()
    }

    /// Scan every regular file under `root`, recursively. Unreadable files are
    /// listed as errors; they never turn into a clean result.
    pub fn scan_directory(&self, root: &Path) -> Result<DirectoryReport, ScanError> {
        let started = Instant::now();

        if !root.is_dir() {
            return Err(ScanError::NotADirectory(root.to_path_buf()));
        }

        let mut paths = Vec::new();
        collect_files(root, &mut paths).map_err(|source| ScanError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        paths.sort();

        let mut files = Vec::with_capacity(paths.len());
        let mut errors = Vec::new();
        let mut summary = Summary {
            files: 0,
            malicious: 0,
            suspicious: 0,
            undetected: 0,
            inconclusive: 0,
            unknown: 0,
            errors: 0,
            duration_ms: 0,
        };

        for path in paths {
            match self.scan(&path) {
                Ok(report) => {
                    match report.verdict {
                        Verdict::Malicious => summary.malicious += 1,
                        Verdict::Suspicious => summary.suspicious += 1,
                        Verdict::Undetected => summary.undetected += 1,
                        Verdict::Inconclusive => summary.inconclusive += 1,
                        Verdict::Unknown => summary.unknown += 1,
                    }
                    files.push(report);
                }
                Err(error) => errors.push(FileError {
                    path,
                    error: error.to_string(),
                }),
            }
        }

        summary.files = files.len();
        summary.errors = errors.len();
        summary.duration_ms = started.elapsed().as_millis() as u64;

        Ok(DirectoryReport {
            root: root.to_path_buf(),
            files,
            errors,
            summary,
        })
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

/// Walk the tree without following links (a link cycle must not hang a scan)
/// and without any depth assumption beyond the filesystem's own.
fn collect_files(root: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut stack = vec![root.to_path_buf()];

    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }

    Ok(())
}

fn read_header(path: &Path) -> Result<Vec<u8>, ScanError> {    let file = File::open(path).map_err(|source| ScanError::Io {
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

    #[test]
    fn scans_a_tree_and_summarizes_it() {
        let directory = crate::test_support::TempDir::new("tree");
        fs::write(
            directory.path().join("invoice.pdf"),
            minimal_pe(0x1000, false, false, false),
        )
        .expect("write pe");
        fs::write(directory.path().join("note.txt"), b"plain text\n").expect("write text");
        fs::create_dir_all(directory.path().join("nested")).expect("nested");
        fs::write(directory.path().join("nested").join("deep.txt"), b"deep\n").expect("deep");

        let report = Scanner::with_builtin()
            .scan_directory(directory.path())
            .expect("scan tree");

        assert_eq!(report.summary.files, 3);
        assert_eq!(report.summary.suspicious, 1);
        assert_eq!(report.summary.undetected, 2);
        assert_eq!(report.summary.errors, 0);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn scanning_a_file_as_a_directory_is_rejected() {
        let file = TempFile::new("single.bin", b"x");

        let error = Scanner::with_builtin()
            .scan_directory(&file.path)
            .expect_err("must reject a file");

        assert!(matches!(error, ScanError::NotADirectory(_)));
    }
}
