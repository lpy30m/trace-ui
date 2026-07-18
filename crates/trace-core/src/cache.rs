use crate::analysis::AnalysisRecord;
use crate::query::strings::StringIndex;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

const MAGIC: &[u8; 8] = b"TCACHE03";
const MAGIC_V4: &[u8; 8] = b"TCACHE04";
const HEAD_SIZE: usize = 1024 * 1024; // 1MB
const HEADER_LEN_V4: usize = 64;

static CACHE_DIR_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

fn atomic_replace(path: &Path, parts: &[&[u8]]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache path has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cache");
    let temp_path = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));

    let result = (|| {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        let mut writer = BufWriter::new(file);
        for part in parts {
            writer.write_all(part)?;
        }
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);
        replace_file(&temp_path, path)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)?;
    if let Some(parent) = destination.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let ok = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_cache_dir_override(path: Option<PathBuf>) {
    *CACHE_DIR_OVERRIDE.write().unwrap() = path;
}

pub fn cache_dir() -> Option<PathBuf> {
    if let Ok(guard) = CACHE_DIR_OVERRIDE.read() {
        if let Some(ref p) = *guard {
            return Some(p.clone());
        }
    }
    dirs::data_dir().map(|d| d.join("trace-ui").join("cache"))
}

fn cache_path(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}.bin", hash, suffix)))
}

/// Cache path with explicit extension (no automatic `.bin` suffix).
fn cache_path_ext(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}", hash, suffix)))
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

// ── 通用加载/保存 (bincode, legacy) ──

fn load_cached<T: serde::de::DeserializeOwned>(
    file_path: &str,
    data: &[u8],
    suffix: &str,
) -> Option<T> {
    let path = cache_path(file_path, suffix)?;
    let file = std::fs::File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    if !validate_header_from_reader(&mut reader, data) {
        return None;
    }
    bincode::deserialize_from(reader).ok()
}

fn save_cached<T: serde::Serialize>(file_path: &str, data: &[u8], suffix: &str, value: &T) {
    let Some(path) = cache_path(file_path, suffix) else {
        return;
    };
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    let Ok(payload) = bincode::serialize(value) else {
        return;
    };
    if let Err(error) = atomic_replace(&path, &[&header, &payload]) {
        eprintln!("[cache] failed to save {:?}: {}", path, error);
    }
}

fn load_json_cached<T: serde::de::DeserializeOwned>(
    file_path: &str,
    data: &[u8],
    suffix: &str,
) -> Option<T> {
    let path = cache_path(file_path, suffix)?;
    let file = std::fs::File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    if !validate_header_from_reader(&mut reader, data) {
        return None;
    }
    serde_json::from_reader(reader).ok()
}

fn save_json_cached<T: serde::Serialize>(file_path: &str, data: &[u8], suffix: &str, value: &T) {
    let Some(path) = cache_path(file_path, suffix) else {
        return;
    };
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    let Ok(payload) = serde_json::to_vec(value) else {
        return;
    };
    if let Err(error) = atomic_replace(&path, &[&header, &payload]) {
        eprintln!("[cache] failed to save {:?}: {}", path, error);
    }
}

/// 将预序列化的 bincode 字节写入缓存文件（TCACHE03 header + raw bytes），不依赖 session。
pub fn save_bincode_raw(file_path: &str, data: &[u8], suffix: &str, payload: &[u8]) {
    let Some(path) = cache_path(file_path, suffix) else {
        return;
    };
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    if let Err(error) = atomic_replace(&path, &[&header, payload]) {
        eprintln!("[cache] failed to save {:?}: {}", path, error);
    }
}

// ── Section-based cache save/load ──

/// 将预序列化的 section 字节写入缓存文件（header + raw bytes），不依赖 session。
pub fn save_sections_raw(file_path: &str, data: &[u8], suffix: &str, section_bytes: &[u8]) {
    let Some(path) = cache_path_ext(file_path, suffix) else {
        return;
    };

    // Write 64-byte V4 header
    let mut header = Vec::with_capacity(HEADER_LEN_V4);
    header.extend_from_slice(MAGIC_V4);
    header.extend_from_slice(&(data.len() as u64).to_le_bytes());
    header.extend_from_slice(&head_hash(data));
    header.resize(HEADER_LEN_V4, 0); // pad to 64 bytes

    if let Err(error) = atomic_replace(&path, &[&header, section_bytes]) {
        eprintln!("[cache] failed to save {:?}: {}", path, error);
        return;
    }
    eprintln!(
        "[cache] saved {} ({} + {} bytes)",
        suffix,
        HEADER_LEN_V4,
        section_bytes.len()
    );
}

fn load_cache_mmap(file_path: &str, data: &[u8], suffix: &str) -> Option<Arc<Mmap>> {
    let path = cache_path_ext(file_path, suffix)?;
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("[cache] {} not found: {:?}", suffix, path);
            return None;
        }
    };
    let mmap = unsafe { Mmap::map(&file) }.ok()?;

    // Validate V4 header
    if mmap.len() < HEADER_LEN_V4 {
        eprintln!("[cache] {} too small: {} bytes", suffix, mmap.len());
        return None;
    }
    if &mmap[0..8] != MAGIC_V4 {
        eprintln!("[cache] {} magic mismatch: {:?}", suffix, &mmap[0..8]);
        return None;
    }
    let stored_size = u64::from_le_bytes(mmap[8..16].try_into().ok()?);
    if stored_size != data.len() as u64 {
        eprintln!(
            "[cache] {} size mismatch: stored={} actual={}",
            suffix,
            stored_size,
            data.len()
        );
        return None;
    }
    let cached_hash: [u8; 32] = mmap[16..48].try_into().ok()?;
    if cached_hash != head_hash(data) {
        eprintln!("[cache] {} hash mismatch", suffix);
        return None;
    }

    eprintln!("[cache] {} loaded: {} bytes", suffix, mmap.len());
    Some(Arc::new(mmap))
}

// ── Section-based cache load ──

pub fn load_phase2_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    let mmap = load_cache_mmap(file_path, data, ".p2.cache")?;
    if crate::flat::archives::Phase2Archive::views_from_sections(
        mmap.get(crate::flat::archives::HEADER_LEN..)?,
    )
    .is_none()
    {
        drop(mmap);
        if let Some(path) = cache_path_ext(file_path, ".p2.cache") {
            let _ = std::fs::remove_file(path);
        }
        return None;
    }
    Some(mmap)
}

pub fn load_scan_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    let mmap = load_cache_mmap(file_path, data, ".scan.cache")?;
    if crate::flat::archives::ScanArchive::views_from_sections(
        mmap.get(crate::flat::archives::HEADER_LEN..)?,
    )
    .is_none()
    {
        drop(mmap);
        if let Some(path) = cache_path_ext(file_path, ".scan.cache") {
            let _ = std::fs::remove_file(path);
        }
        return None;
    }
    Some(mmap)
}

pub fn load_lidx_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    let mmap = load_cache_mmap(file_path, data, ".lidx.cache")?;
    if crate::flat::line_index::LineIndexArchive::views_from_sections(
        mmap.get(crate::flat::archives::HEADER_LEN..)?,
    )
    .is_none()
    {
        drop(mmap);
        if let Some(path) = cache_path_ext(file_path, ".lidx.cache") {
            let _ = std::fs::remove_file(path);
        }
        return None;
    }
    Some(mmap)
}

// ── StringIndex bincode 缓存 ──

pub fn save_string_cache(file_path: &str, data: &[u8], index: &StringIndex) {
    save_cached(file_path, data, ".strings", index);
}

pub fn load_string_cache(file_path: &str, data: &[u8]) -> Option<StringIndex> {
    load_cached(file_path, data, ".strings")
}

// ── Crypto scan bincode 缓存 ──

use crate::query::crypto::CryptoScanResult;

pub fn save_crypto_cache(file_path: &str, data: &[u8], result: &CryptoScanResult) {
    save_cached(file_path, data, ".crypto", result);
}

pub fn load_crypto_cache(file_path: &str, data: &[u8]) -> Option<CryptoScanResult> {
    load_cached(file_path, data, ".crypto")
}

// ── AI analysis record bincode cache ──

pub fn save_analysis_cache(file_path: &str, data: &[u8], records: &[AnalysisRecord]) {
    save_json_cached(file_path, data, ".analyses", &records);
}

pub fn load_analysis_cache(file_path: &str, data: &[u8]) -> Option<Vec<AnalysisRecord>> {
    load_json_cached(file_path, data, ".analyses")
}

// ── Gumtrace extra (call_annotations + consumed_seqs) bincode 缓存 ──

use trace_parser::gumtrace::CallAnnotation;

pub fn save_gumtrace_extra(
    file_path: &str,
    data: &[u8],
    call_annotations: &std::collections::HashMap<u32, CallAnnotation>,
    consumed_seqs: &[u32],
) {
    save_cached(
        file_path,
        data,
        ".gum-extra",
        &(call_annotations, consumed_seqs),
    );
}

pub fn load_gumtrace_extra(
    file_path: &str,
    data: &[u8],
) -> Option<(std::collections::HashMap<u32, CallAnnotation>, Vec<u32>)> {
    load_cached(file_path, data, ".gum-extra")
}

/// 删除指定文件的所有缓存
pub fn delete_cache(file_path: &str) {
    // New section-based cache suffixes
    for suffix in [
        ".p2.cache",
        ".scan.cache",
        ".lidx.cache",
        ".strings.bin",
        ".gum-extra.bin",
        ".crypto.bin",
        ".analyses.bin",
    ] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // Old rkyv suffixes (cleanup)
    for suffix in [".p2.rkyv", ".scan.rkyv", ".lidx.rkyv"] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // Old bincode suffixes (cleanup)
    for suffix in ["", "-scan", "-lidx"] {
        if let Some(p) = cache_path(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub fn get_cache_info() -> (String, u64) {
    let dir = cache_dir().unwrap_or_default();
    let path_str = dir.to_string_lossy().to_string();
    let size = dir_size(&dir);
    (path_str, size)
}

pub fn clear_all_cache() -> (u32, u64) {
    let Some(dir) = cache_dir() else {
        return (0, 0);
    };
    let mut count = 0u32;
    let mut total_size = 0u64;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if ext == Some("bin") || ext == Some("rkyv") || ext == Some("cache") {
                if let Ok(meta) = path.metadata() {
                    total_size += meta.len();
                }
                if std::fs::remove_file(&path).is_ok() {
                    count += 1;
                }
            }
        }
    }
    (count, total_size)
}

fn dir_size(path: &PathBuf) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_replace_overwrites_complete_file_without_temp_leftovers() {
        let dir = std::env::temp_dir().join(format!("trace-ui-cache-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.cache");
        std::fs::write(&path, b"old").unwrap();

        atomic_replace(&path, &[b"new", b"-complete"]).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new-complete");
        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
