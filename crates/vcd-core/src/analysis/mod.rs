//! Structure of the formats we can read without their body.

pub mod entropy;
pub mod imports;
pub mod pe;

use std::io::{self, Read, Seek, SeekFrom};

pub use imports::{ImportSummary, read_imports};
pub use pe::{PeImage, PeSection};

/// Read up to `len` bytes at an absolute offset, stopping at end of file.
/// Bounded by construction: callers pass the cap, the file never decides it.
pub(crate) fn read_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    len: usize,
) -> io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; len];
    let mut filled = 0;

    while filled < len {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    buffer.truncate(filled);
    Ok(buffer)
}
