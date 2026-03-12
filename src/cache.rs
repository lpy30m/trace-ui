use std::io::Read;
use std::path::PathBuf;
use sha2::{Sha256, Digest};
use crate::state::Phase2State;
use crate::taint::scanner::ScanState;

const MAGIC: &[u8; 8] = b"TCACHE03";
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
    let cached_size = match u64::from_le_bytes(buf[8..16].try_into().unwrap_or_default()) {
        s if s == data.len() as u64 => s,
        _ => return false,
    };
    let _ = cached_size;
    let cached_hash: [u8; 32] = match buf[16..48].try_into() {
        Ok(h) => h,
        Err(_) => return false,
    };
    cached_hash == head_hash(data)
}

fn write_header(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(&head_hash(data));
}

// ── Phase2 缓存 ──

pub fn load_cache(file_path: &str, data: &[u8]) -> Option<Phase2State> {
    let path = cache_path(file_path, "")?;
    let mut file = std::fs::File::open(&path).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    if !validate_header(&buf, data) { return None; }
    bincode::deserialize(&buf[48..]).ok()
}

pub fn save_cache(file_path: &str, data: &[u8], state: &Phase2State) {
    let Some(path) = cache_path(file_path, "") else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let serialized = match bincode::serialize(state) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut buf = Vec::with_capacity(48 + serialized.len());
    write_header(&mut buf, data);
    buf.extend_from_slice(&serialized);
    let _ = std::fs::write(&path, &buf);
}

// ── ScanState 缓存 ──

pub fn load_scan_cache(file_path: &str, data: &[u8]) -> Option<ScanState> {
    let path = cache_path(file_path, "-scan")?;
    let mut file = std::fs::File::open(&path).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    if !validate_header(&buf, data) { return None; }
    bincode::deserialize(&buf[48..]).ok()
}

/// 删除指定文件的所有缓存（Phase2 + ScanState）
pub fn delete_cache(file_path: &str) {
    if let Some(p) = cache_path(file_path, "") {
        let _ = std::fs::remove_file(p);
    }
    if let Some(p) = cache_path(file_path, "-scan") {
        let _ = std::fs::remove_file(p);
    }
}

pub fn save_scan_cache(file_path: &str, data: &[u8], state: &ScanState) {
    let Some(path) = cache_path(file_path, "-scan") else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let serialized = match bincode::serialize(state) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut buf = Vec::with_capacity(48 + serialized.len());
    write_header(&mut buf, data);
    buf.extend_from_slice(&serialized);
    let _ = std::fs::write(&path, &buf);
}
