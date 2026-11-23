//! Header-level PE facts.
//!
//! Deliberately parses only what the first
//! [`FileTypeDetector`](crate::filetype) header buffer contains, so it costs no
//! extra IO on a multi-gigabyte file, and every read is bounds-checked because
//! the input is hostile by definition.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
    pub printable_name: bool,
}

impl PeSection {
    const MEM_EXECUTE: u32 = 0x2000_0000;
    const MEM_WRITE: u32 = 0x8000_0000;

    pub fn is_executable(&self) -> bool {
        self.characteristics & Self::MEM_EXECUTE != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & Self::MEM_WRITE != 0
    }

    pub fn end(&self) -> u64 {
        self.virtual_address as u64 + self.virtual_size.max(self.raw_size) as u64
    }

    pub fn contains(&self, rva: u32) -> bool {
        rva >= self.virtual_address && (rva as u64) < self.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    pub machine: u16,
    pub number_of_sections: u16,
    pub subsystem: u16,
    pub entry_point: u32,
    pub image_base: u64,
    pub is_64bit: bool,
    pub is_dotnet: bool,
    pub is_dll: bool,
    pub sections: Vec<PeSection>,
    /// (rva, size) pairs, index order as defined by the PE format.
    pub data_directories: Vec<(u32, u32)>,
}

impl PeImage {
    const DLL_CHARACTERISTIC: u16 = 0x2000;
    const CLR_DIRECTORY_INDEX: u32 = 14;

    pub fn machine_name(&self) -> String {
        match self.machine {
            0x014C => "x86".to_string(),
            0x8664 => "x64".to_string(),
            0xAA64 => "arm64".to_string(),
            0x01C4 => "arm".to_string(),
            0 => "unknown".to_string(),
            other => format!("0x{other:04X}"),
        }
    }

    /// A DLL may legitimately have entry point 0, so the "outside every
    /// section" question only makes sense for images that declare one.
    pub fn has_entry_point_outside_sections(&self) -> bool {
        self.entry_point != 0
            && !self.is_dll
            && !self
                .sections
                .iter()
                .any(|section| section.contains(self.entry_point))
    }

    /// Translate a relative virtual address into a file offset using the
    /// section table, or `None` when it falls outside every section.
    pub fn rva_to_offset(&self, rva: u32) -> Option<u64> {
        self.sections
            .iter()
            .find(|section| section.contains(rva))
            .map(|section| section.raw_pointer as u64 + (rva - section.virtual_address) as u64)
    }

    pub fn parse(data: &[u8]) -> Option<PeImage> {
        if data.len() < 0x40 || !data.starts_with(b"MZ") {
            return None;
        }

        let pe_offset = u32_at(data, 0x3C)? as usize;
        if pe_offset > data.len().saturating_sub(24) {
            return None;
        }

        let pe = &data[pe_offset..];
        if !pe.starts_with(b"PE\0\0") {
            return None;
        }

        let coff = &pe[4..];
        let machine = u16_at(coff, 0)?;
        let number_of_sections = u16_at(coff, 2)?;
        let optional_size = u16_at(coff, 16)? as usize;
        let characteristics = u16_at(coff, 18)?;

        let optional = &coff[20..];
        let magic = u16_at(optional, 0)?;
        let is_64bit = magic == 0x20B;
        if !is_64bit && magic != 0x10B {
            return None;
        }

        let minimum_optional = if is_64bit { 112 } else { 96 };
        if optional_size < minimum_optional || optional.len() < minimum_optional {
            return None;
        }

        let entry_point = u32_at(optional, 16)?;
        let image_base = if is_64bit {
            u64_at(optional, 24)?
        } else {
            u32_at(optional, 28)? as u64
        };
        let subsystem = u16_at(optional, 68)?;

        let directory_start = if is_64bit { 112 } else { 96 };
        let directory_count = u32_at(optional, if is_64bit { 108 } else { 92 })?;
        let clr_directory = directory_start + (Self::CLR_DIRECTORY_INDEX as usize * 8);
        let is_dotnet = directory_count > Self::CLR_DIRECTORY_INDEX
            && optional_size >= clr_directory + 8
            && optional.len() >= clr_directory + 8
            && u32_at(optional, clr_directory).unwrap_or(0) != 0;

        let section_table = pe_offset + 24 + optional_size;
        let table_len = number_of_sections as usize * 40;
        if section_table.checked_add(table_len)? > data.len() {
            return None;
        }

        let mut sections = Vec::with_capacity(number_of_sections as usize);
        for index in 0..number_of_sections as usize {
            let raw = &data[section_table + (index * 40)..section_table + (index * 40) + 40];
            sections.push(PeSection {
                name: decode_name(&raw[..8]),
                virtual_address: u32_at(raw, 12)?,
                virtual_size: u32_at(raw, 8)?,
                raw_size: u32_at(raw, 16)?,
                raw_pointer: u32_at(raw, 20)?,
                characteristics: u32_at(raw, 36)?,
                printable_name: is_printable_name(&raw[..8]),
            });
        }

        let mut data_directories = Vec::new();
        for index in 0..(directory_count as usize).min(16) {
            let at = directory_start + (index * 8);
            if at + 8 > optional.len() || at + 8 > optional_size {
                break;
            }
            data_directories.push((u32_at(optional, at)?, u32_at(optional, at + 4)?));
        }

        Some(PeImage {
            machine,
            number_of_sections,
            subsystem,
            entry_point,
            image_base,
            is_64bit,
            is_dotnet,
            is_dll: characteristics & Self::DLL_CHARACTERISTIC != 0,
            sections,
            data_directories,
        })
    }
}

fn decode_name(raw: &[u8]) -> String {
    let length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    raw[..length]
        .iter()
        .map(|byte| {
            if (0x20..=0x7E).contains(byte) {
                *byte as char
            } else {
                '?'
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn is_printable_name(raw: &[u8]) -> bool {
    let length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    length > 0
        && raw[..length]
            .iter()
            .all(|byte| (0x20..=0x7E).contains(byte))
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const OPTIONAL_SIZE: usize = 0xE0;
    pub(crate) const SECTION_TABLE: usize = 0x40 + 24 + OPTIONAL_SIZE;

    /// Minimal but structurally valid PE32 image: DOS header, PE signature, one
    /// section, and the optional-header fields the parser reads.
    pub(crate) fn minimal_pe(
        entry_point: u32,
        dll: bool,
        writable_executable: bool,
        dotnet: bool,
    ) -> Vec<u8> {
        let mut data = vec![0u8; 0x400];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        data[0x40..0x44].copy_from_slice(b"PE\0\0");

        data[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes()); // machine: x86
        data[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // sections
        data[0x54..0x56].copy_from_slice(&(OPTIONAL_SIZE as u16).to_le_bytes());
        data[0x56..0x58].copy_from_slice(&(if dll { 0x2000u16 } else { 0x0002 }).to_le_bytes());

        data[0x58..0x5A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
        data[0x68..0x6C].copy_from_slice(&entry_point.to_le_bytes());
        data[0x74..0x78].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        data[0x9C..0x9E].copy_from_slice(&3u16.to_le_bytes());
        data[0xB4..0xB8].copy_from_slice(&16u32.to_le_bytes());

        if dotnet {
            let clr = 0x58 + 96 + (14 * 8);
            data[clr..clr + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        }

        let section = SECTION_TABLE;
        data[section..section + 5].copy_from_slice(b".text");
        data[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        data[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        let flags: u32 = if writable_executable {
            0xE000_0020
        } else {
            0x6000_0020
        };
        data[section + 36..section + 40].copy_from_slice(&flags.to_le_bytes());

        data
    }

    /// A valid PE whose single section carries `len` bytes produced by `fill`,
    /// used to exercise the sampled-body analysis.
    pub(crate) fn minimal_pe_with_section_body(len: usize, fill: impl Fn(usize) -> u8) -> Vec<u8> {
        let mut data = minimal_pe(0x1000, false, false, false);
        data.resize(0x400 + len, 0);
        data[SECTION_TABLE + 8..SECTION_TABLE + 12].copy_from_slice(&(len as u32).to_le_bytes());
        data[SECTION_TABLE + 16..SECTION_TABLE + 20].copy_from_slice(&(len as u32).to_le_bytes());
        for index in 0..len {
            data[0x400 + index] = fill(index);
        }
        data
    }

    #[test]
    fn parses_a_valid_image() {
        let image = PeImage::parse(&minimal_pe(0x1000, false, false, false)).expect("parse");
        assert_eq!(image.machine, 0x014C);
        assert_eq!(image.machine_name(), "x86");
        assert!(!image.is_64bit);
        assert!(!image.is_dll);
        assert!(!image.is_dotnet);
        assert_eq!(image.sections.len(), 1);
        assert_eq!(image.sections[0].name, ".text");
        assert!(image.sections[0].is_executable());
        assert!(!image.sections[0].is_writable());
        assert!(!image.has_entry_point_outside_sections());
    }

    #[test]
    fn entry_point_outside_every_section_is_flagged() {
        let image = PeImage::parse(&minimal_pe(0x9000, false, false, false)).expect("parse");
        assert!(image.has_entry_point_outside_sections());
    }

    #[test]
    fn dll_without_entry_point_is_not_flagged() {
        let image = PeImage::parse(&minimal_pe(0, true, false, false)).expect("parse");
        assert!(image.is_dll);
        assert!(!image.has_entry_point_outside_sections());
    }

    #[test]
    fn detects_the_clr_directory() {
        assert!(
            PeImage::parse(&minimal_pe(0x1000, false, false, true))
                .expect("parse")
                .is_dotnet
        );
        assert!(
            !PeImage::parse(&minimal_pe(0x1000, false, false, false))
                .expect("parse")
                .is_dotnet
        );
    }

    #[test]
    fn rejects_truncated_headers() {
        assert!(PeImage::parse(&[0x4D, 0x5A, 0, 0]).is_none());
        assert!(PeImage::parse(&[]).is_none());
    }

    #[test]
    fn rejects_an_mz_without_pe_signature() {
        let mut data = vec![0u8; 0x100];
        data[0..2].copy_from_slice(b"MZ");
        assert!(PeImage::parse(&data).is_none());
    }

    #[test]
    fn section_bounds_use_the_larger_of_virtual_and_raw_size() {
        let section = PeSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x200,
            raw_size: 0x800,
            raw_pointer: 0x400,
            characteristics: 0x6000_0020,
            printable_name: true,
        };
        assert!(section.contains(0x17FF));
        assert!(!section.contains(0x1800));
    }
}
