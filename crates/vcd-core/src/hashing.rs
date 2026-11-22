//! Streaming digests.
//!
//! One sequential read feeds every hasher, so a 100 GiB file costs a single
//! pass instead of one pass per algorithm, and the buffer size does not depend
//! on the file size.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Bytes per read. Fixed, so memory use is independent of the file size.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// MD5 and SHA-1 are carried for reputation lookups against existing feeds
/// (both are broken as collision-resistant hashes and never decide trust here);
/// SHA-256 is the identity of the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDigests {
    pub size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

pub fn hash_file(path: &Path) -> io::Result<FileDigests> {
    let file = File::open(path)?;
    hash_reader(BufReader::with_capacity(CHUNK_SIZE, file))
}

/// Hash any reader without buffering it whole. Short reads are handled by the
/// loop, so a reader that trickles bytes yields the same digests.
pub fn hash_reader<R: Read>(mut reader: R) -> io::Result<FileDigests> {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut size: u64 = 0;

    loop {
        let read = reader.read(&mut buf)?;
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
}
