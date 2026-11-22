//! Import table summary.
//!
//! Reads only the descriptor block and the DLL names, both capped, and never
//! follows the thunk arrays: a scanner must stay cheap on a hostile binary.

use std::io::{self, Read, Seek};

use super::{PeImage, read_at};

/// Directory index of the import table in the optional header.
const IMPORT_DIRECTORY: usize = 1;
const MAX_DESCRIPTORS: usize = 32;
const MAX_DLL_NAME: usize = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub dlls: Vec<String>,
    /// The table had more entries than the cap.
    pub truncated: bool,
}

impl ImportSummary {
    pub fn is_empty(&self) -> bool {
        self.dlls.is_empty()
    }
}

pub fn read_imports<R: Read + Seek>(
    reader: &mut R,
    image: &PeImage,
) -> io::Result<ImportSummary> {
    let Some(&(rva, _size)) = image.data_directories.get(IMPORT_DIRECTORY) else {
        return Ok(ImportSummary::default());
    };
    if rva == 0 {
        return Ok(ImportSummary::default());
    }
    let Some(offset) = image.rva_to_offset(rva) else {
        return Ok(ImportSummary::default());
    };

    let table = read_at(reader, offset, MAX_DESCRIPTORS * 20)?;
    let mut summary = ImportSummary::default();
    let mut saw_terminator = false;

    for entry in table.chunks_exact(20) {
        if entry.iter().all(|byte| *byte == 0) {
            saw_terminator = true;
            break;
        }

        let name_rva = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
        if name_rva == 0 {
            continue;
        }
        let Some(name_offset) = image.rva_to_offset(name_rva) else {
            continue;
        };

        let raw = read_at(reader, name_offset, MAX_DLL_NAME)?;
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        if end == 0 {
            continue;
        }
        if let Ok(name) = std::str::from_utf8(&raw[..end]) {
            summary.dlls.push(name.to_string());
        }
    }

    summary.truncated = !saw_terminator;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::analysis::{PeImage, PeSection};

    fn image_with_directory(rva: u32) -> PeImage {
        PeImage {
            machine: 0x014C,
            number_of_sections: 1,
            subsystem: 3,
            entry_point: 0,
            image_base: 0,
            is_64bit: false,
            is_dotnet: false,
            is_dll: true,
            sections: vec![PeSection {
                name: ".idata".into(),
                virtual_address: 0x2000,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                raw_pointer: 0x200,
                characteristics: 0x4000_0040,
                printable_name: true,
            }],
            data_directories: vec![(0, 0), (rva, 0x28)],
        }
    }

    /// Descriptors live at RVA 0x2000 (file 0x200); the names sit at RVA
    /// 0x2400 and 0x2410, past the 640-byte descriptor window.
    fn sample_with_two_dlls() -> Cursor<Vec<u8>> {
        let mut data = vec![0u8; 0x1200];

        data[0x200 + 12..0x200 + 16].copy_from_slice(&0x2400u32.to_le_bytes());
        data[0x214 + 12..0x214 + 16].copy_from_slice(&0x2410u32.to_le_bytes());

        data[0x600..0x60C].copy_from_slice(b"KERNEL32.dll");
        data[0x610..0x616].copy_from_slice(b"USER32");
        Cursor::new(data)
    }

    #[test]
    fn reads_the_dll_names() {
        let mut cursor = sample_with_two_dlls();
        let summary = read_imports(&mut cursor, &image_with_directory(0x2000)).expect("read");

        assert_eq!(summary.dlls, vec!["KERNEL32.dll", "USER32"]);
        assert!(!summary.truncated);
    }

    #[test]
    fn no_directory_means_no_imports() {
        let mut cursor = Cursor::new(vec![0u8; 16]);
        let summary = read_imports(&mut cursor, &image_with_directory(0)).expect("read");
        assert!(summary.is_empty());
        assert!(!summary.truncated);
    }

    #[test]
    fn a_table_without_terminator_is_marked_truncated() {
        let mut data = vec![0u8; 0x1200];
        for index in 0..MAX_DESCRIPTORS {
            let at = 0x200 + (index * 20);
            data[at + 12..at + 16].copy_from_slice(&0x2400u32.to_le_bytes());
        }
        data[0x600..0x60C].copy_from_slice(b"KERNEL32.dll");

        let mut cursor = Cursor::new(data);
        let summary = read_imports(&mut cursor, &image_with_directory(0x2000)).expect("read");

        assert_eq!(summary.dlls.len(), MAX_DESCRIPTORS);
        assert!(summary.truncated);
    }
}
