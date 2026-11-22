//! Streaming digests.
//!
//! One sequential read feeds every hasher, and for files above
//! [`PARALLEL_THRESHOLD`] each hasher runs on its own thread over shared,
//! read-only chunks. The read stays sequential (that is what the disk likes);
//! the three hash functions, which are the CPU cost, overlap.
//!
//! Memory stays constant either way: a fixed chunk buffer plus a bounded queue
//! per worker, no matter how large the file is.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::thread;

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Bytes per read. Fixed, so memory use is independent of the file size.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Below this size the cost of spawning threads is larger than the gain.
pub const PARALLEL_THRESHOLD: u64 = 4 * 1024 * 1024;

/// Chunks a worker may lag behind before the reader blocks.
const QUEUE_DEPTH: usize = 2;

/// MD5 and SHA-1 are carried for reputation lookups against existing feeds
/// (both are broken as collision-resistant hashes and never decide trust here);
/// SHA-256 is the identity of the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDigests {
    pub size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

pub fn hash_file(path: &Path) -> io::Result<FileDigests> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();

    if size >= PARALLEL_THRESHOLD {
        hash_stream_parallel(file)
    } else {
        hash_reader(BufReader::with_capacity(CHUNK_SIZE, file))
    }
}

/// Hash any reader on one thread. Short reads are handled by the fill loop, so
/// a reader that trickles bytes yields the same digests.
pub fn hash_reader<R: Read>(mut reader: R) -> io::Result<FileDigests> {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut size: u64 = 0;

    loop {
        let read = fill(&mut reader, &mut buf)?;
        if read == 0 {
            break;
        }
        let chunk = &buf[..read];
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        size = size.saturating_add(read as u64);
    }

    Ok(FileDigests {
        size,
        md5: hex(md5.finalize()),
        sha1: hex(sha1.finalize()),
        sha256: hex(sha256.finalize()),
    })
}

fn hash_stream_parallel<R: Read + Send>(mut reader: R) -> io::Result<FileDigests> {
    thread::scope(|scope| {
        let (md5_tx, md5_rx) = sync_channel::<Arc<Vec<u8>>>(QUEUE_DEPTH);
        let (sha1_tx, sha1_rx) = sync_channel::<Arc<Vec<u8>>>(QUEUE_DEPTH);
        let (sha256_tx, sha256_rx) = sync_channel::<Arc<Vec<u8>>>(QUEUE_DEPTH);

        let md5_worker = scope.spawn(move || {
            let mut hasher = Md5::new();
            for chunk in md5_rx {
                hasher.update(&chunk[..]);
            }
            hasher.finalize()
        });
        let sha1_worker = scope.spawn(move || {
            let mut hasher = Sha1::new();
            for chunk in sha1_rx {
                hasher.update(&chunk[..]);
            }
            hasher.finalize()
        });
        let sha256_worker = scope.spawn(move || {
            let mut hasher = Sha256::new();
            for chunk in sha256_rx {
                hasher.update(&chunk[..]);
            }
            hasher.finalize()
        });

        let mut size: u64 = 0;
        loop {
            let mut buffer = vec![0u8; CHUNK_SIZE];
            let read = fill(&mut reader, &mut buffer)?;
            if read == 0 {
                break;
            }
            buffer.truncate(read);
            size = size.saturating_add(read as u64);

            // One allocation, three readers: no per-hasher copy.
            let chunk = Arc::new(buffer);
            let delivered = md5_tx.send(Arc::clone(&chunk)).is_ok()
                && sha1_tx.send(Arc::clone(&chunk)).is_ok()
                && sha256_tx.send(chunk).is_ok();
            if !delivered {
                // A worker died; joining below reports it as an error.
                break;
            }
        }

        drop(md5_tx);
        drop(sha1_tx);
        drop(sha256_tx);

        Ok(FileDigests {
            size,
            md5: hex(join(md5_worker)?),
            sha1: hex(join(sha1_worker)?),
            sha256: hex(join(sha256_worker)?),
        })
    })
}

fn join<T>(handle: thread::ScopedJoinHandle<'_, T>) -> io::Result<T> {
    handle
        .join()
        .map_err(|_| io::Error::other("hash worker panicked"))
}

/// Read until the buffer is full or the reader ends. Returns the bytes read.
fn fill<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;

    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    /// Reader that returns at most `step` bytes per call, forcing the hashing
    /// loop to reassemble digests across short reads.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let take = self.data.len().min(self.step).min(out.len());
            out[..take].copy_from_slice(&self.data[..take]);
            self.data = &self.data[take..];
            Ok(take)
        }
    }

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(name: &str, bytes: &[u8]) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("vcd-hash-{unique}-{name}"));
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
    fn empty_input_vectors() {
        let digests = hash_reader(std::io::empty()).expect("hash empty");
        assert_eq!(digests.size, 0);
        assert_eq!(digests.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(digests.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            digests.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_vectors() {
        let digests = hash_reader(&b"abc"[..]).expect("hash abc");
        assert_eq!(digests.size, 3);
        assert_eq!(digests.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(digests.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            digests.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn short_reads_produce_the_same_digests() {
        let data: Vec<u8> = (0..5_000u32).map(|i| (i % 251) as u8).collect();
        let whole = hash_reader(data.as_slice()).expect("single read");
        let trickled = hash_reader(Trickle {
            data: &data,
            step: 7,
        })
        .expect("trickled");
        assert_eq!(whole, trickled);
        assert_eq!(trickled.size, data.len() as u64);
    }

    #[test]
    fn chunk_boundaries_do_not_change_the_digest() {
        let mut data = vec![0u8; CHUNK_SIZE + 1];
        data[0] = 0xAB;
        data[CHUNK_SIZE] = 0xCD;
        let whole = hash_reader(data.as_slice()).expect("whole");

        let exact = hash_reader(&data[..CHUNK_SIZE]).expect("exact chunk");
        let plus_one = hash_reader(&data[..CHUNK_SIZE + 1]).expect("one byte over");

        assert_eq!(whole.size, (CHUNK_SIZE + 1) as u64);
        assert_ne!(exact.sha256, plus_one.sha256);
        assert_eq!(plus_one, whole);
    }

    #[test]
    fn parallel_and_sequential_paths_agree() {
        // Above PARALLEL_THRESHOLD, so hash_file takes the threaded path.
        let data: Vec<u8> = (0..5_000_000u32)
            .map(|index| (index.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let file = TempFile::new("big.bin", &data);

        let sequential = hash_reader(data.as_slice()).expect("sequential");
        let from_file = hash_file(&file.path).expect("parallel");

        assert_eq!(from_file, sequential);
        assert_eq!(from_file.size, data.len() as u64);
    }
}
