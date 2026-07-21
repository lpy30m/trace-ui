use std::fs;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ElfBinaryIdentity {
    pub binary_path: String,
    pub binary_sha256: String,
    pub file_size: u64,
    pub format: String,
    pub architecture: String,
    pub elf_machine: u16,
    pub build_id: Option<String>,
}

#[derive(Clone, Copy)]
enum ElfEndian {
    Little,
    Big,
}

pub fn inspect_elf_binary(binary_path: &str) -> Result<ElfBinaryIdentity, String> {
    let bytes = fs::read(binary_path)
        .map_err(|error| format!("failed to read static ELF '{binary_path}': {error}"))?;
    inspect_elf_bytes(binary_path, &bytes)
}

pub fn inspect_elf_bytes(binary_path: &str, bytes: &[u8]) -> Result<ElfBinaryIdentity, String> {
    if bytes.get(..4) != Some(b"\x7fELF") {
        return Err("static binary is not an ELF image".to_string());
    }
    let class = *bytes.get(4).ok_or("truncated ELF class")?;
    if !matches!(class, 1 | 2) {
        return Err(format!("unsupported ELF class {class}"));
    }
    let endian = match bytes.get(5) {
        Some(1) => ElfEndian::Little,
        Some(2) => ElfEndian::Big,
        other => return Err(format!("unsupported ELF byte order {other:?}")),
    };
    let machine = read_u16(bytes, 18, endian)?;
    let (program_offset, entry_size, entry_count) = if class == 2 {
        (
            read_u64(bytes, 32, endian)?,
            read_u16(bytes, 54, endian)? as u64,
            read_u16(bytes, 56, endian)? as u64,
        )
    } else {
        (
            read_u32(bytes, 28, endian)? as u64,
            read_u16(bytes, 42, endian)? as u64,
            read_u16(bytes, 44, endian)? as u64,
        )
    };
    let minimum_entry_size = if class == 2 { 56 } else { 32 };
    if entry_count > 0 && entry_size < minimum_entry_size {
        return Err(format!("invalid ELF program-header size {entry_size}"));
    }

    let mut build_id = None;
    for index in 0..entry_count {
        let header = program_offset
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .ok_or("ELF program-header index overflow")?,
            )
            .ok_or("ELF program-header offset overflow")?;
        let header =
            usize::try_from(header).map_err(|_| "ELF program-header offset is too large")?;
        let entry_size_usize =
            usize::try_from(entry_size).map_err(|_| "ELF program-header size is too large")?;
        if header
            .checked_add(entry_size_usize)
            .map_or(true, |end| end > bytes.len())
        {
            return Err("ELF program header extends beyond the file".to_string());
        }
        if read_u32(bytes, header, endian)? != 4 || build_id.is_some() {
            continue;
        }
        let (file_offset, file_size) = if class == 2 {
            (
                read_u64(bytes, header + 8, endian)?,
                read_u64(bytes, header + 32, endian)?,
            )
        } else {
            (
                read_u32(bytes, header + 4, endian)? as u64,
                read_u32(bytes, header + 16, endian)? as u64,
            )
        };
        build_id = parse_gnu_build_id(bytes, file_offset, file_size, endian);
    }

    Ok(ElfBinaryIdentity {
        binary_path: binary_path.to_string(),
        binary_sha256: hex_bytes(&Sha256::digest(bytes)),
        file_size: bytes.len().min(u64::MAX as usize) as u64,
        format: format!(
            "ELF{} {}-endian",
            if class == 2 { 64 } else { 32 },
            match endian {
                ElfEndian::Little => "little",
                ElfEndian::Big => "big",
            }
        ),
        architecture: machine_name(machine).to_string(),
        elf_machine: machine,
        build_id,
    })
}

fn parse_gnu_build_id(
    bytes: &[u8],
    file_offset: u64,
    file_size: u64,
    endian: ElfEndian,
) -> Option<String> {
    let start = usize::try_from(file_offset).ok()?;
    let size = usize::try_from(file_size).ok()?;
    let end = start.checked_add(size)?;
    if end > bytes.len() {
        return None;
    }
    let mut cursor = start;
    while cursor.checked_add(12)? <= end {
        let name_size = read_u32(bytes, cursor, endian).ok()? as usize;
        let description_size = read_u32(bytes, cursor + 4, endian).ok()? as usize;
        let note_type = read_u32(bytes, cursor + 8, endian).ok()?;
        let name_start = cursor.checked_add(12)?;
        let name_end = name_start.checked_add(name_size)?;
        let description_start = name_start.checked_add(align4(name_size)?)?;
        let description_end = description_start.checked_add(description_size)?;
        if name_end > end || description_end > end {
            return None;
        }
        if note_type == 3 && bytes.get(name_start..name_end)?.starts_with(b"GNU") {
            return Some(hex_bytes(bytes.get(description_start..description_end)?));
        }
        cursor = description_start.checked_add(align4(description_size)?)?;
    }
    None
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn read_u16(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<u16, String> {
    let raw: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| "truncated ELF u16 field".to_string())?
        .try_into()
        .expect("slice length checked");
    Ok(match endian {
        ElfEndian::Little => u16::from_le_bytes(raw),
        ElfEndian::Big => u16::from_be_bytes(raw),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<u32, String> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| "truncated ELF u32 field".to_string())?
        .try_into()
        .expect("slice length checked");
    Ok(match endian {
        ElfEndian::Little => u32::from_le_bytes(raw),
        ElfEndian::Big => u32::from_be_bytes(raw),
    })
}

fn read_u64(bytes: &[u8], offset: usize, endian: ElfEndian) -> Result<u64, String> {
    let raw: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or_else(|| "truncated ELF u64 field".to_string())?
        .try_into()
        .expect("slice length checked");
    Ok(match endian {
        ElfEndian::Little => u64::from_le_bytes(raw),
        ElfEndian::Big => u64::from_be_bytes(raw),
    })
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        3 => "x86",
        40 => "ARM",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "Unknown",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn reads_aarch64_sha256_and_gnu_build_id() {
        const NOTE_OFFSET: usize = 120;
        let mut elf = vec![0u8; NOTE_OFFSET + 20];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        write_u16(&mut elf, 18, 183);
        write_u64(&mut elf, 32, 64);
        write_u16(&mut elf, 54, 56);
        write_u16(&mut elf, 56, 1);
        write_u32(&mut elf, 64, 4);
        write_u64(&mut elf, 72, NOTE_OFFSET as u64);
        write_u64(&mut elf, 96, 20);
        write_u32(&mut elf, NOTE_OFFSET, 4);
        write_u32(&mut elf, NOTE_OFFSET + 4, 4);
        write_u32(&mut elf, NOTE_OFFSET + 8, 3);
        elf[NOTE_OFFSET + 12..NOTE_OFFSET + 16].copy_from_slice(b"GNU\0");
        elf[NOTE_OFFSET + 16..NOTE_OFFSET + 20].copy_from_slice(&[1, 2, 3, 4]);

        let identity = inspect_elf_bytes("libtarget.so", &elf).unwrap();
        assert_eq!(identity.architecture, "AArch64");
        assert_eq!(identity.elf_machine, 183);
        assert_eq!(identity.build_id.as_deref(), Some("01020304"));
        assert_eq!(identity.binary_sha256.len(), 64);
        assert_eq!(identity.file_size, elf.len() as u64);
    }

    #[test]
    fn rejects_non_elf_input() {
        assert!(inspect_elf_bytes("bad.so", b"not an elf").is_err());
    }
}
