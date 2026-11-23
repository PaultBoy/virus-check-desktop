//! Content typing from magic bytes.
//!
//! The extension is evidence, never the answer: a file named `invoice.pdf`
//! that begins with a PE header is a PE executable, and [`compatible`] turns
//! that gap into a finding.

use serde::{Deserialize, Serialize};

/// Bytes read once per scan to type the file. Constant, so typing cost does
/// not grow with the file size.
pub const HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Executable,
    Archive,
    Document,
    Image,
    Media,
    Script,
    Text,
    Data,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    Pe,
    Elf,
    MachO,
    Msi,
    Ole2Document,
    Pdf,
    Rtf,
    Zip,
    OoxmlDocument,
    OoxmlSheet,
    OoxmlSlides,
    JavaArchive,
    AndroidPackage,
    SevenZip,
    Rar,
    Gzip,
    Bzip2,
    Xz,
    Tar,
    Iso,
    Sqlite,
    JavaClass,
    Wasm,
    Lnk,
    Registry,
    Png,
    Jpeg,
    Gif,
    Webp,
    Bmp,
    Icon,
    Mp3,
    Mp4,
    Wav,
    Html,
    Xml,
    Json,
    Text,
    Unknown,
}

impl ContentType {
    pub fn as_str(self) -> &'static str {
        match self {
            ContentType::Pe => "PE executable",
            ContentType::Elf => "ELF executable",
            ContentType::MachO => "Mach-O executable",
            ContentType::Msi => "Windows Installer package",
            ContentType::Ole2Document => "OLE2 compound document",
            ContentType::Pdf => "PDF document",
            ContentType::Rtf => "RTF document",
            ContentType::Zip => "ZIP archive",
            ContentType::OoxmlDocument => "OOXML word-processing document",
            ContentType::OoxmlSheet => "OOXML spreadsheet",
            ContentType::OoxmlSlides => "OOXML presentation",
            ContentType::JavaArchive => "Java archive",
            ContentType::AndroidPackage => "Android package",
            ContentType::SevenZip => "7-Zip archive",
            ContentType::Rar => "RAR archive",
            ContentType::Gzip => "gzip stream",
            ContentType::Bzip2 => "bzip2 stream",
            ContentType::Xz => "xz stream",
            ContentType::Tar => "tar archive",
            ContentType::Iso => "ISO 9660 image",
            ContentType::Sqlite => "SQLite database",
            ContentType::JavaClass => "Java class file",
            ContentType::Wasm => "WebAssembly module",
            ContentType::Lnk => "Windows shortcut",
            ContentType::Registry => "Windows registry export",
            ContentType::Png => "PNG image",
            ContentType::Jpeg => "JPEG image",
            ContentType::Gif => "GIF image",
            ContentType::Webp => "WebP image",
            ContentType::Bmp => "BMP image",
            ContentType::Icon => "Windows icon",
            ContentType::Mp3 => "MP3 audio",
            ContentType::Mp4 => "MP4 container",
            ContentType::Wav => "WAV audio",
            ContentType::Html => "HTML document",
            ContentType::Xml => "XML document",
            ContentType::Json => "JSON document",
            ContentType::Text => "text",
            ContentType::Unknown => "unknown",
        }
    }

    pub fn family(self) -> Family {
        match self {
            ContentType::Pe
            | ContentType::Elf
            | ContentType::MachO
            | ContentType::Msi
            | ContentType::JavaClass
            | ContentType::Wasm => Family::Executable,
            ContentType::Zip
            | ContentType::JavaArchive
            | ContentType::AndroidPackage
            | ContentType::SevenZip
            | ContentType::Rar
            | ContentType::Gzip
            | ContentType::Bzip2
            | ContentType::Xz
            | ContentType::Tar
            | ContentType::Iso => Family::Archive,
            ContentType::Ole2Document
            | ContentType::Pdf
            | ContentType::Rtf
            | ContentType::OoxmlDocument
            | ContentType::OoxmlSheet
            | ContentType::OoxmlSlides => Family::Document,
            ContentType::Png
            | ContentType::Jpeg
            | ContentType::Gif
            | ContentType::Webp
            | ContentType::Bmp
            | ContentType::Icon => Family::Image,
            ContentType::Mp3 | ContentType::Mp4 | ContentType::Wav => Family::Media,
            ContentType::Html | ContentType::Xml | ContentType::Json | ContentType::Text => {
                Family::Text
            }
            ContentType::Sqlite | ContentType::Lnk | ContentType::Registry => Family::Data,
            ContentType::Unknown => Family::Unknown,
        }
    }
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Executable => "executable",
            Family::Archive => "archive",
            Family::Document => "document",
            Family::Image => "image",
            Family::Media => "media",
            Family::Script => "script",
            Family::Text => "text",
            Family::Data => "data",
            Family::Unknown => "unknown",
        }
    }
}

/// Type a file from its first bytes. `file_name` is only a tiebreak for
/// containers whose magic cannot distinguish the payload (OLE2 vs MSI).
pub fn detect(header: &[u8], file_name: Option<&str>) -> ContentType {
    if header.is_empty() {
        return ContentType::Unknown;
    }

    if is_pe(header) {
        return ContentType::Pe;
    }
    if header.starts_with(b"\x7fELF") {
        return ContentType::Elf;
    }
    if header.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
        || header.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
        || header.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || header.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
    {
        return ContentType::MachO;
    }
    if header.starts_with(b"\xca\xfe\xba\xbe") {
        return ContentType::JavaClass;
    }
    if header.starts_with(b"\0asm") {
        return ContentType::Wasm;
    }
    if header.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return if matches!(
            extension_of(file_name)
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("msi" | "msp" | "mst" | "msix")
        ) {
            ContentType::Msi
        } else {
            ContentType::Ole2Document
        };
    }
    if header.starts_with(b"%PDF-") {
        return ContentType::Pdf;
    }
    if header.starts_with(b"{\\rtf") {
        return ContentType::Rtf;
    }
    if header.starts_with(b"PK\x03\x04") || header.starts_with(b"PK\x05\x06") {
        return zip_kind(header);
    }
    if header.starts_with(b"Rar!\x1a\x07") {
        return ContentType::Rar;
    }
    if header.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return ContentType::SevenZip;
    }
    if header.starts_with(&[0x1F, 0x8B]) {
        return ContentType::Gzip;
    }
    if header.starts_with(b"BZh") {
        return ContentType::Bzip2;
    }
    if header.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return ContentType::Xz;
    }
    if header.get(257..262) == Some(b"ustar") {
        return ContentType::Tar;
    }
    if header.get(0x8001..0x8006) == Some(b"CD001") {
        return ContentType::Iso;
    }
    if header.starts_with(b"SQLite format 3\0") {
        return ContentType::Sqlite;
    }
    if header.starts_with(b"\x89PNG\r\n\x1a\n") {
        return ContentType::Png;
    }
    if header.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return ContentType::Jpeg;
    }
    if header.starts_with(b"GIF87a") || header.starts_with(b"GIF89a") {
        return ContentType::Gif;
    }
    if header.starts_with(b"RIFF") {
        return match header.get(8..12) {
            Some(b"WEBP") => ContentType::Webp,
            Some(b"WAVE") => ContentType::Wav,
            _ => ContentType::Unknown,
        };
    }
    if header.starts_with(b"BM") && header.len() > 26 {
        return ContentType::Bmp;
    }
    if header.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return ContentType::Icon;
    }
    if header.starts_with(b"ID3") {
        return ContentType::Mp3;
    }
    if header.get(4..8) == Some(b"ftyp") {
        return ContentType::Mp4;
    }
    if header.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return ContentType::Lnk;
    }
    if header.starts_with(b"Windows Registry Editor") {
        return ContentType::Registry;
    }

    if looks_like_text(header) {
        return text_kind(header);
    }

    ContentType::Unknown
}

fn is_pe(header: &[u8]) -> bool {
    if header.len() < 0x40 || !header.starts_with(b"MZ") {
        return false;
    }
    let offset =
        u32::from_le_bytes([header[0x3C], header[0x3D], header[0x3E], header[0x3F]]) as usize;
    offset > 0 && header.get(offset..offset.saturating_add(4)) == Some(b"PE\0\0")
}

fn zip_kind(header: &[u8]) -> ContentType {
    // An APK also carries META-INF, so the Android marker is checked first.
    if contains(header, b"AndroidManifest.xml") {
        return ContentType::AndroidPackage;
    }
    if contains(header, b"META-INF/MANIFEST.MF") {
        return ContentType::JavaArchive;
    }
    if contains(header, b"[Content_Types].xml") {
        if contains(header, b"word/") {
            return ContentType::OoxmlDocument;
        }
        if contains(header, b"xl/") {
            return ContentType::OoxmlSheet;
        }
        if contains(header, b"ppt/") {
            return ContentType::OoxmlSlides;
        }
    }
    ContentType::Zip
}

fn contains(header: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && header.len() >= needle.len()
        && header.windows(needle.len()).any(|window| window == needle)
}

fn looks_like_text(header: &[u8]) -> bool {
    let sample = &header[..header.len().min(8192)];
    if sample.contains(&0) {
        return false;
    }
    let acceptable = sample
        .iter()
        .filter(|byte| matches!(**byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7E) || **byte >= 0x80)
        .count();
    acceptable * 100 >= sample.len() * 95
}

fn text_kind(header: &[u8]) -> ContentType {
    let trimmed = trim_ascii_start(header);
    if starts_with_ignore_ascii_case(trimmed, b"<!doctype html")
        || starts_with_ignore_ascii_case(trimmed, b"<html")
    {
        return ContentType::Html;
    }
    if starts_with_ignore_ascii_case(trimmed, b"<?xml") {
        return ContentType::Xml;
    }
    if trimmed.starts_with(b"{") || trimmed.starts_with(b"[") {
        return ContentType::Json;
    }
    ContentType::Text
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        start = 3;
    }
    while let Some(byte) = bytes.get(start) {
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
            start += 1;
        } else {
            break;
        }
    }
    &bytes[start..]
}

fn starts_with_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

pub fn extension_of(file_name: Option<&str>) -> Option<&str> {
    let name = file_name?;
    let (stem, extension) = name.rsplit_once('.')?;
    if stem.is_empty() || extension.is_empty() {
        return None;
    }
    Some(extension)
}

/// Family an extension leads a reader to expect. `None` means the extension
/// carries no expectation (or there is none).
pub fn expected_family(extension: &str) -> Option<Family> {
    let family = match extension.to_ascii_lowercase().as_str() {
        "exe" | "dll" | "sys" | "scr" | "com" | "ocx" | "cpl" | "pif" | "msi" | "msp" | "msix"
        | "appx" | "class" => Family::Executable,
        "zip" | "7z" | "rar" | "gz" | "tgz" | "bz2" | "xz" | "tar" | "iso" | "jar" | "apk" => {
            Family::Archive
        }
        "pdf" | "rtf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods"
        | "odp" => Family::Document,
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "ico" | "tif" | "tiff" => Family::Image,
        "mp3" | "wav" | "flac" | "mp4" | "mkv" | "avi" | "mov" => Family::Media,
        "bat" | "cmd" | "ps1" | "psm1" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "wsh" | "hta"
        | "sh" | "py" | "pl" | "rb" => Family::Script,
        "txt" | "md" | "log" | "csv" | "json" | "xml" | "html" | "htm" | "yaml" | "yml" | "ini"
        | "cfg" | "conf" | "svg" => Family::Text,
        "db" | "sqlite" | "sqlite3" | "reg" | "lnk" => Family::Data,
        _ => return None,
    };
    Some(family)
}

/// Whether the detected content is consistent with what the extension
/// promised. Text and script are interchangeable: a `.ps1` has no magic bytes
/// and legitimately types as text.
pub fn compatible(expected: Family, detected: Family) -> bool {
    expected == detected
        || detected == Family::Unknown
        || matches!(
            (expected, detected),
            (Family::Script, Family::Text)
                | (Family::Text, Family::Script)
                | (Family::Data, Family::Text)
                | (Family::Text, Family::Data)
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_header() -> Vec<u8> {
        let mut header = vec![0u8; 0x100];
        header[0..2].copy_from_slice(b"MZ");
        header[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        header[0x40..0x44].copy_from_slice(b"PE\0\0");
        header
    }

    #[test]
    fn detects_pe_by_header_not_extension() {
        assert_eq!(detect(&pe_header(), Some("invoice.pdf")), ContentType::Pe);
        assert_eq!(detect(&pe_header(), None).family(), Family::Executable);
    }

    #[test]
    fn mz_without_pe_signature_is_not_pe() {
        let mut header = vec![0u8; 0x100];
        header[0..2].copy_from_slice(b"MZ");
        assert_ne!(detect(&header, None), ContentType::Pe);
    }

    #[test]
    fn detects_common_magics() {
        assert_eq!(detect(b"%PDF-1.7\n", None), ContentType::Pdf);
        assert_eq!(detect(b"\x7fELF\x02\x01\x01", None), ContentType::Elf);
        assert_eq!(detect(b"SQLite format 3\0rest", None), ContentType::Sqlite);
        assert_eq!(detect(b"\x89PNG\r\n\x1a\n", None), ContentType::Png);
        assert_eq!(detect(b"PK\x03\x04plain zip", None), ContentType::Zip);
    }

    #[test]
    fn refines_zip_containers() {
        assert_eq!(
            detect(
                b"PK\x03\x04[Content_Types].xml .... word/document.xml",
                Some("a.docx")
            ),
            ContentType::OoxmlDocument
        );
        assert_eq!(
            detect(b"PK\x03\x04[Content_Types].xml .... xl/workbook.xml", None),
            ContentType::OoxmlSheet
        );
        assert_eq!(
            detect(b"PK\x03\x04META-INF/MANIFEST.MF AndroidManifest.xml", None),
            ContentType::AndroidPackage
        );
        assert_eq!(
            detect(b"PK\x03\x04META-INF/MANIFEST.MF com/example", None),
            ContentType::JavaArchive
        );
    }

    #[test]
    fn ole2_is_msi_only_for_installer_extensions() {
        let ole2 = [0xD0u8, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0, 0, 0];
        assert_eq!(detect(&ole2, Some("setup.msi")), ContentType::Msi);
        assert_eq!(detect(&ole2, Some("report.doc")), ContentType::Ole2Document);
    }

    #[test]
    fn types_text_and_its_formats() {
        assert_eq!(detect(b"{\"a\":1}", None), ContentType::Json);
        assert_eq!(detect(b"  <!DOCTYPE html><html>", None), ContentType::Html);
        assert_eq!(detect(b"<?xml version=\"1.0\"?>", None), ContentType::Xml);
        assert_eq!(detect(b"just some words\n", None), ContentType::Text);
        assert_eq!(detect(b"", None), ContentType::Unknown);
    }

    #[test]
    fn binary_without_magic_is_unknown() {
        assert_eq!(
            detect(&[0u8, 1, 2, 3, 0, 255, 4], None),
            ContentType::Unknown
        );
    }

    #[test]
    fn extension_expectations() {
        assert_eq!(expected_family("PDF"), Some(Family::Document));
        assert_eq!(expected_family("ps1"), Some(Family::Script));
        assert_eq!(expected_family("weird"), None);
        assert!(compatible(Family::Script, Family::Text));
        assert!(compatible(Family::Text, Family::Data));
        assert!(!compatible(Family::Document, Family::Executable));
        assert!(compatible(Family::Document, Family::Unknown));
    }

    #[test]
    fn extension_parsing() {
        assert_eq!(extension_of(Some("a.PDF")), Some("PDF"));
        assert_eq!(extension_of(Some("noext")), None);
        assert_eq!(extension_of(Some(".gitignore")), None);
        assert_eq!(extension_of(None), None);
    }
}
