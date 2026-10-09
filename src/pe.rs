use std::io::{self, Read};

use pelite::PeFile;

/// Bytes to fetch past the last section, which holds the start of the NSIS data.
pub const OVERLAY_BYTES: usize = 4096;
/// Upper limit for a PE stub. NSIS stubs are well below it, and other installers can keep their payload in a section.
pub const MAX_HEAD_BYTES: usize = 1024 * 1024;

const NSIS_SIGNATURE: &[u8] = b"\xef\xbe\xad\xdeNullsoftInst";
const NSIS_DESCRIPTION: &str = "Nullsoft Install System";

/// What the PE headers say about how much of the file is needed.
#[derive(Debug, PartialEq, Eq)]
pub enum Layout {
    NotPe,
    NeedMore(usize),
    SectionsEnd(usize),
}

#[derive(Debug, Default)]
pub struct Inspection {
    pub detected_type: &'static str,
    pub description: Option<String>,
    pub nsis_version: Option<String>,
    pub nsis_signature: bool,
}

fn read_u16(buf: &[u8], offset: usize) -> Option<usize> {
    buf.get(offset..offset + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
}

fn read_u32(buf: &[u8], offset: usize) -> Option<usize> {
    buf.get(offset..offset + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
}

/// Reads the section table from the start of a file that can be incomplete.
pub fn layout(head: &[u8]) -> Layout {
    if head.len() < 0x40 {
        return if head.len() >= 2 && !head.starts_with(b"MZ") { Layout::NotPe } else { Layout::NeedMore(0x40) };
    }
    if !head.starts_with(b"MZ") {
        return Layout::NotPe;
    }
    let pe = read_u32(head, 0x3c).unwrap_or(0);
    let (Some(sections), Some(optional_size)) = (read_u16(head, pe + 6), read_u16(head, pe + 20)) else {
        return Layout::NeedMore(pe + 24);
    };
    if head.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Layout::NotPe;
    }
    let table = pe + 24 + optional_size;
    let table_end = table + 40 * sections;
    if head.len() < table_end {
        return Layout::NeedMore(table_end);
    }
    let end = (0..sections)
        .filter_map(|i| {
            let raw_size = read_u32(head, table + 40 * i + 16)?;
            let raw_offset = read_u32(head, table + 40 * i + 20)?;
            (raw_size > 0).then_some(raw_offset + raw_size)
        })
        .max()
        .unwrap_or(table_end);
    Layout::SectionsEnd(end)
}

/// Reads the manifest description and looks for the NSIS header at each 512-byte boundary, as the NSIS loader does.
pub fn inspect(head: &[u8]) -> Inspection {
    let description = PeFile::from_bytes(head)
        .ok()
        .and_then(|pe| pe.resources().ok())
        .and_then(|r| r.manifest().ok())
        .and_then(manifest_description);
    let nsis_signature = (0..head.len())
        .step_by(512)
        .any(|offset| head.get(offset + 4..offset + 4 + NSIS_SIGNATURE.len()) == Some(NSIS_SIGNATURE));
    let nsis_version = description
        .as_deref()
        .and_then(|d| d.strip_prefix(NSIS_DESCRIPTION))
        .map(|v| v.trim().trim_start_matches('v').to_string())
        .filter(|v| !v.is_empty());

    let detected_type = match description.as_deref() {
        Some(d) if d.starts_with(NSIS_DESCRIPTION) => "nsis",
        _ if nsis_signature => "nsis",
        Some(d) if d.contains("7-Zip") => "7z_sfx",
        _ => "pe",
    };
    Inspection { detected_type, description, nsis_version, nsis_signature }
}

/// Reads the PE stub from the start of a stream, up to `max` bytes. Returns the bytes, the layout and whether the
/// stub fit within `max`.
pub fn read_stub(reader: &mut dyn Read, max: usize) -> io::Result<(Vec<u8>, Layout, bool)> {
    let mut bytes = Vec::new();
    let mut fill = |bytes: &mut Vec<u8>, wanted: usize| -> io::Result<()> {
        if bytes.len() < wanted {
            reader.take((wanted - bytes.len()) as u64).read_to_end(bytes)?;
        }
        Ok(())
    };
    let layout = loop {
        match layout(&bytes) {
            Layout::NeedMore(n) if n <= max && bytes.len() < n => {
                fill(&mut bytes, n)?;
                if bytes.len() < n {
                    break Layout::NotPe;
                }
            }
            Layout::NeedMore(_) => break Layout::NotPe,
            other => break other,
        }
    };
    let mut complete = true;
    if let Layout::SectionsEnd(end) = layout {
        let wanted = (end + OVERLAY_BYTES).min(max);
        complete = wanted == end + OVERLAY_BYTES;
        fill(&mut bytes, wanted)?;
    }
    Ok((bytes, layout, complete))
}

fn manifest_description(manifest: &str) -> Option<String> {
    let start = manifest.find("<description>")? + "<description>".len();
    let end = manifest[start..].find("</description>")? + start;
    Some(manifest[start..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(sections: &[(u32, u32)]) -> Vec<u8> {
        let pe = 0x80;
        let optional_size = 0xe0;
        let mut buf = vec![0u8; pe + 24 + optional_size + 40 * sections.len()];
        buf[..2].copy_from_slice(b"MZ");
        buf[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
        buf[pe + 6..pe + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[pe + 20..pe + 22].copy_from_slice(&(optional_size as u16).to_le_bytes());
        for (i, (offset, size)) in sections.iter().enumerate() {
            let s = pe + 24 + optional_size + 40 * i;
            buf[s + 16..s + 20].copy_from_slice(&size.to_le_bytes());
            buf[s + 20..s + 24].copy_from_slice(&offset.to_le_bytes());
        }
        buf
    }

    #[test]
    fn sections_end_is_furthest_section() {
        let buf = header(&[(0x400, 0x5000), (0x5400, 0x200), (0x5600, 0x8000), (0, 0)]);
        assert_eq!(layout(&buf), Layout::SectionsEnd(0xd600));
    }

    #[test]
    fn partial_header_asks_for_more() {
        let buf = header(&[(0x400, 0x5000), (0x5400, 0x200)]);
        assert_eq!(layout(&buf[..10]), Layout::NeedMore(0x40));
        assert_eq!(layout(&buf[..0x100]), Layout::NeedMore(buf.len()));
    }

    #[test]
    fn html_is_not_pe() {
        assert_eq!(layout(b"<!DOCTYPE html><html>"), Layout::NotPe);
    }

    #[test]
    fn finds_nsis_signature() {
        let mut buf = header(&[(0x400, 0x200)]);
        buf.resize(0x800, 0);
        buf[0x604..0x604 + NSIS_SIGNATURE.len()].copy_from_slice(NSIS_SIGNATURE);
        let inspection = inspect(&buf);
        assert!(inspection.nsis_signature);
        assert_eq!(inspection.detected_type, "nsis");
    }

    #[test]
    fn reads_stub_from_stream() {
        let mut file = header(&[(0x400, 0x200)]);
        file.resize(0x10000, 0xcc);
        let (bytes, layout, complete) = read_stub(&mut file.as_slice(), 1 << 20).unwrap();
        assert_eq!(layout, Layout::SectionsEnd(0x600));
        assert_eq!(bytes.len(), 0x600 + OVERLAY_BYTES);
        assert!(complete);
    }

    #[test]
    fn parses_description() {
        let manifest = r#"<assembly><description>Nullsoft Install System v3.08</description></assembly>"#;
        assert_eq!(manifest_description(manifest).as_deref(), Some("Nullsoft Install System v3.08"));
    }
}
