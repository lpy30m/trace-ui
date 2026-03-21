use serde::Serialize;
use tauri::State;
use crate::state::AppState;
use crate::taint::types::TraceFormat;
use crate::commands::browse::{parse_trace_line, parse_trace_line_gumtrace};
use crate::commands::utils::ascii_contains;
use crate::taint::types::RegId;

/// 28 crypto algorithms with their magic number constants.
/// Each entry: (algorithm_name, &[magic_u32_values])
const CRYPTO_MAGIC_NUMBERS: &[(&str, &[u32])] = &[
    ("MD5",          &[0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE]),
    ("SHA1",         &[0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]),
    ("SHA256",       &[0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5]),
    ("SM3",          &[0x79CC4519, 0x7A879D8A]),
    ("CRC32",        &[0x77073096, 0xEE0E612C, 0xEDB88320, 0x04C11DB7]),
    ("CRC32C",       &[0x82F63B78]),
    ("ChaCha20/Salsa20", &[0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]),
    ("HMAC (generic)", &[0x36363636, 0x5C5C5C5C]),
    ("TEA",          &[0x9E3779B9]),
    ("Twofish",      &[0xBCBC3275, 0xECEC21F3, 0x202043C6, 0xB3B3C9F4]),
    ("Blowfish",     &[0x243F6A88, 0x85A308D3]),
    ("RC6",          &[0xB7E15163, 0x9E3779B9]),
    ("AES",          &[0xC66363A5, 0xF87C7C84]),
    ("APLib",        &[0x32335041]),
    ("RC4",          &[0x4F3B2B74, 0x4E27D213]),
    ("Threefish",    &[0x1B22B279, 0xAE23C8A4, 0xBC6F0C0D, 0x5E27A878]),
    ("Camellia",     &[0x4D49E62D, 0x934F19C8, 0x34E72602, 0xF75E005E]),
    ("Serpent",      &[0xC43FFF8B, 0x1D03D043, 0x1B2A04D0, 0x9AC28989]),
    ("AES_SBOX",     &[0x637C777B, 0xF26B6FC5, 0x3001672B, 0xFEFED7AB]),
    ("SHA256_K2",    &[0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5]),
    ("SHA512_IV",    &[0x6A09E667, 0xF3BCC908, 0xBB67AE85, 0x84CAA73B]),
    ("Camellia_IV",  &[0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2]),
    ("Whirlpool_T0", &[0x18186018, 0xC07830D8, 0x60281818, 0xD8181860]),
    ("Poly1305",     &[0xEB44ACC0, 0xD8DFB523]),
    ("DES",          &[0xFEE1A2B3, 0xD7BEF080]),
    ("DES1",         &[0x3A322A22, 0x2A223A32]),
    ("DES_SBOX",     &[0x2C1E241B, 0x5A7F361D, 0x3D4793C6, 0x0B0EEDF8]),
];

#[derive(Serialize, Clone)]
pub struct CryptoMatch {
    pub algorithm: String,
    pub magic_hex: String,
    pub seq: u32,
    pub address: String,
    pub disasm: String,
    pub changes: String,
}

#[derive(Serialize)]
pub struct CryptoScanResult {
    pub matches: Vec<CryptoMatch>,
    pub algorithms_found: Vec<String>,
    pub total_lines_scanned: u32,
    pub scan_duration_ms: u64,
}

/// Pre-compute all needle bytes (lowercase hex of each magic number).
/// Returns Vec<(algorithm, magic_hex_display, needle_bytes)>
fn build_needles() -> Vec<(&'static str, String, Vec<u8>)> {
    let mut needles = Vec::new();
    for &(algo, magics) in CRYPTO_MAGIC_NUMBERS {
        for &val in magics {
            let hex_display = format!("0x{:08X}", val);
            let needle = format!("{:x}", val).into_bytes();
            needles.push((algo, hex_display, needle));
        }
    }
    needles
}

/// Scan a chunk of the trace file for crypto magic numbers.
fn scan_chunk(
    data: &[u8],
    start_seq: u32,
    end_seq: u32,
    start_offset: usize,
    needles: &[(&str, String, Vec<u8>)],
    trace_format: TraceFormat,
) -> Vec<CryptoMatch> {
    // 粗估 0.5% 匹配率预分配，减少运行时 Vec 扩容
    let estimated = end_seq.saturating_sub(start_seq) as usize / 200;
    let mut matches = Vec::with_capacity(estimated);
    let mut pos = start_offset;
    let mut seq = start_seq;

    while pos < data.len() && seq < end_seq {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());

        let line = &data[pos..end];

        for (algo, hex_display, needle) in needles {
            if ascii_contains(line, needle) {
                let parsed = match trace_format {
                    TraceFormat::Unidbg => parse_trace_line(seq, line),
                    TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, line),
                };
                if let Some(p) = parsed {
                    matches.push(CryptoMatch {
                        algorithm: algo.to_string(),
                        magic_hex: hex_display.clone(),
                        seq,
                        address: p.address,
                        disasm: p.disasm,
                        changes: p.changes,
                    });
                }
                break; // one match per line is enough
            }
        }

        pos = end + 1;
        seq += 1;
    }

    matches
}

#[tauri::command]
pub async fn scan_crypto(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<CryptoScanResult, String> {
    let start_time = std::time::Instant::now();

    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let (mmap_arc, total_lines, trace_format, chunks) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id)
            .ok_or_else(|| format!("Session {} not found", session_id))?;
        let total_lines = session.lidx_store.as_ref().map(|s| s.total_lines()).unwrap_or(0);

        let chunks: Option<Vec<(u32, u32, usize)>> = if num_cpus > 1 && total_lines > 10000 {
            session.line_index_view().map(|li| {
                let data: &[u8] = &session.mmap;
                let num_chunks = num_cpus.min(16);
                let lines_per_chunk = (total_lines as usize + num_chunks - 1) / num_chunks;
                let mut chunks = Vec::with_capacity(num_chunks);
                for i in 0..num_chunks {
                    let start_seq = (i * lines_per_chunk) as u32;
                    if start_seq >= total_lines { break; }
                    let end_seq = ((i + 1) * lines_per_chunk).min(total_lines as usize) as u32;
                    let start_offset = li.line_byte_offset(data, start_seq).unwrap_or(0) as usize;
                    chunks.push((start_seq, end_seq, start_offset));
                }
                chunks
            })
        } else {
            None
        };

        (session.mmap.clone(), total_lines, session.trace_format, chunks)
    };

    let result = tauri::async_runtime::spawn_blocking(move || {
        let data: &[u8] = &mmap_arc;
        let needles = build_needles();

        let all_matches = if let Some(chunks) = chunks {
            use rayon::prelude::*;
            let chunk_results: Vec<Vec<CryptoMatch>> = chunks.par_iter()
                .map(|&(start_seq, end_seq, start_offset)| {
                    scan_chunk(data, start_seq, end_seq, start_offset, &needles, trace_format)
                })
                .collect();

            chunk_results.into_iter().flatten().collect()
        } else {
            scan_chunk(data, 0, total_lines, 0, &needles, trace_format)
        };

        // Collect unique algorithms found
        let mut algos: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for m in &all_matches {
            if seen.insert(&m.algorithm) {
                algos.push(m.algorithm.clone());
            }
        }

        CryptoScanResult {
            matches: all_matches,
            algorithms_found: algos,
            total_lines_scanned: total_lines,
            scan_duration_ms: start_time.elapsed().as_millis() as u64,
        }
    })
    .await
    .map_err(|e| format!("Scan thread panic: {}", e))?;

    Ok(result)
}

#[derive(Serialize)]
pub struct CryptoFunctionContext {
    func_name: Option<String>,
    func_addr: String,
    entry_seq: u32,
    exit_seq: u32,
    caller_name: Option<String>,
    caller_addr: Option<String>,
    caller_entry_seq: Option<u32>,
    caller_exit_seq: Option<u32>,
    args: [String; 4],
    input_hex: Option<String>,
    output_hex: Option<String>,
    param_hint: String,
}

/// Read register values at a given seq by replaying from nearest checkpoint.
fn replay_registers_at(
    session: &crate::state::SessionState,
    seq: u32,
) -> Option<[u64; RegId::COUNT]> {
    let reg_view = session.reg_checkpoints_view()?;
    let line_index = session.line_index_view()?;
    let (ckpt_seq, snapshot) = reg_view.nearest_before(seq)?;
    let mut values = *snapshot;
    for replay_seq in ckpt_seq..=seq {
        if let Some(raw) = line_index.get_line(&session.mmap, replay_seq) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                crate::phase2::update_reg_values(&mut values, line_str);
            }
        }
    }
    Some(values)
}

/// Read up to `len` bytes from memory at the given address/seq.
fn read_memory_bytes(
    session: &crate::state::SessionState,
    addr: u64,
    seq: u32,
    len: usize,
) -> Option<Vec<u8>> {
    let mem_view = session.mem_accesses_view()?;
    let mut bytes = vec![0u8; len];
    let mut any_known = false;
    for offset in 0..len {
        let byte_addr = addr + offset as u64;
        let mut best_seq: Option<u32> = None;
        let mut best_byte: u8 = 0;
        for check_offset in 0u64..=7 {
            if byte_addr < check_offset {
                continue;
            }
            let check_addr = byte_addr - check_offset;
            if let Some(records) = mem_view.query(check_addr) {
                let pos = records.partition_point(|r: &crate::flat::mem_access::FlatMemAccessRecord| r.seq <= seq);
                if pos > 0 {
                    let rec = &records[pos - 1];
                    if check_offset < rec.size as u64 {
                        if best_seq.is_none() || rec.seq > best_seq.unwrap() {
                            best_seq = Some(rec.seq);
                            best_byte = ((rec.data >> (check_offset * 8)) & 0xFF) as u8;
                        }
                    }
                }
            }
        }
        if best_seq.is_some() {
            bytes[offset] = best_byte;
            any_known = true;
        }
    }
    if any_known { Some(bytes) } else { None }
}

fn make_param_hint(algorithm: &str) -> String {
    let algo_upper = algorithm.to_uppercase();
    if algo_upper.contains("MD5") || algo_upper.contains("SHA1") || algo_upper.contains("SHA256")
        || algo_upper.contains("SHA512") || algo_upper.contains("SM3")
    {
        "x0=ctx, x1=data_ptr, x2=data_len".to_string()
    } else if algo_upper.contains("AES") {
        "x0=input, x1=output, x2=key, x3=rounds/len".to_string()
    } else {
        "x0=arg0, x1=arg1, x2=arg2, x3=arg3".to_string()
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

#[tauri::command]
pub fn get_crypto_context(
    session_id: String,
    seq: u32,
    algorithm: String,
    state: State<'_, AppState>,
) -> Result<CryptoFunctionContext, String> {
    let sessions = state.sessions.read().map_err(|e| e.to_string())?;
    let session = sessions.get(&session_id)
        .ok_or_else(|| format!("Session {} not found", session_id))?;

    // 1. Find the innermost function containing this seq
    let call_tree = session.call_tree.as_ref().ok_or("Call tree not built yet")?;
    let mut best_node: Option<&crate::taint::call_tree::CallTreeNode> = None;
    for node in &call_tree.nodes {
        if node.entry_seq <= seq && seq <= node.exit_seq {
            match best_node {
                None => best_node = Some(node),
                Some(prev) => {
                    let prev_span = prev.exit_seq - prev.entry_seq;
                    let this_span = node.exit_seq - node.entry_seq;
                    if this_span < prev_span {
                        best_node = Some(node);
                    }
                }
            }
        }
    }
    let func_node = best_node.ok_or("No function found for this seq")?;

    // Resolve inner func_addr
    let line_index = session.line_index_view();
    let data: &[u8] = &session.mmap;
    let func_addr_str = crate::commands::call_tree::resolve_offset_addr(
        func_node, line_index.as_ref(), data,
    );

    let entry_seq = func_node.entry_seq;
    let exit_seq = func_node.exit_seq;
    let func_name = func_node.func_name.clone();

    // 2. Find parent (caller) node via parent_id
    let parent_node = func_node.parent_id
        .and_then(|pid| call_tree.nodes.get(pid as usize));

    let (caller_name, caller_addr, caller_entry_seq, caller_exit_seq) = match parent_node {
        Some(pn) => {
            let addr = crate::commands::call_tree::resolve_offset_addr(
                pn, line_index.as_ref(), data,
            );
            (pn.func_name.clone(), Some(addr), Some(pn.entry_seq), Some(pn.exit_seq))
        }
        None => (None, None, None, None),
    };

    // 3. Replay registers at the parent's entry (or inner entry as fallback) to get x0~x3
    let args_seq = caller_entry_seq.unwrap_or(entry_seq);
    let entry_regs = replay_registers_at(session, args_seq);
    let reg_vals: [u64; 4] = match &entry_regs {
        Some(vals) => [vals[0], vals[1], vals[2], vals[3]],
        None => [u64::MAX; 4],
    };

    let format_reg = |v: u64| -> String {
        if v == u64::MAX { "?".to_string() } else { format!("0x{:x}", v) }
    };

    let args = [
        format_reg(reg_vals[0]),
        format_reg(reg_vals[1]),
        format_reg(reg_vals[2]),
        format_reg(reg_vals[3]),
    ];

    // 4. Read input memory based on algorithm heuristics
    //    Use inner function's entry_seq for memory reads — that's when the data
    //    is actually in memory, ready to be processed. The pointers come from
    //    caller's registers but memory content must be sampled at inner entry.
    let algo_upper = algorithm.to_uppercase();
    let is_hash = algo_upper.contains("MD5") || algo_upper.contains("SHA1")
        || algo_upper.contains("SHA256") || algo_upper.contains("SHA512")
        || algo_upper.contains("SM3");
    let is_aes = algo_upper.contains("AES");

    let mem_read_seq = entry_seq; // inner function entry: data is ready here

    let input_hex = if is_hash {
        // Hash: x1 = data pointer, x2 = length
        let ptr = reg_vals[1];
        let len = reg_vals[2];
        if ptr != u64::MAX && ptr != 0 && len != u64::MAX {
            let read_len = (len as usize).min(256);
            if read_len > 0 {
                read_memory_bytes(session, ptr, mem_read_seq, read_len)
                    .map(|b| bytes_to_hex(&b))
            } else {
                None
            }
        } else {
            None
        }
    } else if is_aes {
        // AES: x0 = input buffer, 64 bytes
        let ptr = reg_vals[0];
        if ptr != u64::MAX && ptr != 0 {
            read_memory_bytes(session, ptr, mem_read_seq, 64)
                .map(|b| bytes_to_hex(&b))
        } else {
            None
        }
    } else {
        // Generic: x0, 64 bytes
        let ptr = reg_vals[0];
        if ptr != u64::MAX && ptr != 0 {
            read_memory_bytes(session, ptr, mem_read_seq, 64)
                .map(|b| bytes_to_hex(&b))
        } else {
            None
        }
    };

    // 5. Read output memory at inner function's exit
    let exit_regs = replay_registers_at(session, exit_seq);
    let output_hex = if let Some(exit_vals) = &exit_regs {
        if is_hash {
            // Hash: x0 = ctx/digest buffer, 64 bytes
            let ptr = exit_vals[0];
            if ptr != u64::MAX && ptr != 0 {
                read_memory_bytes(session, ptr, exit_seq, 64)
                    .map(|b| bytes_to_hex(&b))
            } else {
                None
            }
        } else if is_aes {
            // AES: x1 = output buffer, 64 bytes
            let ptr = exit_vals[1];
            if ptr != u64::MAX && ptr != 0 {
                read_memory_bytes(session, ptr, exit_seq, 64)
                    .map(|b| bytes_to_hex(&b))
            } else {
                None
            }
        } else {
            // Generic: x0, 64 bytes
            let ptr = exit_vals[0];
            if ptr != u64::MAX && ptr != 0 {
                read_memory_bytes(session, ptr, exit_seq, 64)
                    .map(|b| bytes_to_hex(&b))
            } else {
                None
            }
        }
    } else {
        None
    };

    // 6. Generate param hint
    let param_hint = make_param_hint(&algorithm);

    Ok(CryptoFunctionContext {
        func_name,
        func_addr: func_addr_str,
        entry_seq,
        exit_seq,
        caller_name,
        caller_addr,
        caller_entry_seq,
        caller_exit_seq,
        args,
        input_hex,
        output_hex,
        param_hint,
    })
}
