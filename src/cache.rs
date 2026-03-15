use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use sha2::{Sha256, Digest};
use crate::state::Phase2State;
use crate::taint::scanner::ScanState;

const MAGIC: &[u8; 8] = b"TCACHE04";
const HEAD_SIZE: usize = 1024 * 1024; // 1MB

fn cache_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("trace-ui").join("cache"))
}

fn cache_path(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}.bin", hash, suffix)))
}

fn head_hash(data: &[u8]) -> [u8; 32] {
    let end = data.len().min(HEAD_SIZE);
    let mut hasher = Sha256::new();
    hasher.update(&data[..end]);
    hasher.finalize().into()
}

fn validate_header(buf: &[u8], data: &[u8]) -> bool {
    if buf.len() < 48 || &buf[0..8] != MAGIC {
        return false;
    }
    let stored_size = u64::from_le_bytes(buf[8..16].try_into().unwrap_or_default());
    if stored_size != data.len() as u64 {
        return false;
    }
    let cached_hash: [u8; 32] = match buf[16..48].try_into() {
        Ok(h) => h,
        Err(_) => return false,
    };
    cached_hash == head_hash(data)
}

fn validate_header_from_reader(reader: &mut impl Read, data: &[u8]) -> bool {
    let mut header = [0u8; 48];
    if reader.read_exact(&mut header).is_err() {
        return false;
    }
    validate_header(&header, data)
}

fn write_header(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(&head_hash(data));
}

// ── 通用加载/保存 ──

fn load_cached<T: serde::de::DeserializeOwned>(file_path: &str, data: &[u8], suffix: &str) -> Option<T> {
    let path = cache_path(file_path, suffix)?;
    let file = std::fs::File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    if !validate_header_from_reader(&mut reader, data) { return None; }
    bincode::deserialize_from(reader).ok()
}

fn save_cached<T: serde::Serialize>(file_path: &str, data: &[u8], suffix: &str, value: &T) {
    let Some(path) = cache_path(file_path, suffix) else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut writer = BufWriter::new(file);
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    if writer.write_all(&header).is_err() { return; }
    if bincode::serialize_into(&mut writer, value).is_err() { return; }
    let _ = writer.flush();
}

// ── Phase2 缓存 ──

pub fn load_cache(file_path: &str, data: &[u8]) -> Option<Phase2State> {
    load_cached(file_path, data, "")
}

pub fn save_cache(file_path: &str, data: &[u8], state: &Phase2State) {
    save_cached(file_path, data, "", state);
}

// ── ScanState 缓存 ──

pub fn load_scan_cache(file_path: &str, data: &[u8]) -> Option<ScanState> {
    load_cached(file_path, data, "-scan")
}

pub fn save_scan_cache(file_path: &str, data: &[u8], state: &ScanState) {
    save_cached(file_path, data, "-scan", state);
}

// ── LineIndex 缓存 ──

pub fn load_line_index_cache(file_path: &str, data: &[u8]) -> Option<crate::line_index::LineIndex> {
    load_cached(file_path, data, "-lidx")
}

pub fn save_line_index_cache(file_path: &str, data: &[u8], line_index: &crate::line_index::LineIndex) {
    save_cached(file_path, data, "-lidx", line_index);
}

/// 删除指定文件的所有缓存（Phase2 + ScanState + LineIndex）
pub fn delete_cache(file_path: &str) {
    for suffix in ["", "-scan", "-lidx"] {
        if let Some(p) = cache_path(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
}
