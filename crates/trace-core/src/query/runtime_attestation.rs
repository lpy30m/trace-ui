use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::query::elf_identity::{inspect_elf_layout, ElfBinaryLayout};

pub const FRIDA_RUNTIME_ATTESTATION_SCHEMA: &str = "trace-ui/frida-runtime-attestation-v1";
pub const RUNTIME_ATTESTATION_VERIFICATION_SCHEMA: &str =
    "trace-ui/runtime-attestation-verification-v1";
const MIN_WINDOW_BYTES: u32 = 256;
const MAX_WINDOW_BYTES: u32 = 65_536;
const MAX_WINDOWS: u32 = 4_096;
const MAX_PLANNED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;

fn default_window_bytes() -> u32 {
    4_096
}

fn default_max_windows() -> u32 {
    1_024
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FridaRuntimeAttestationRequest {
    pub module_name: String,
    pub static_binary_path: String,
    #[serde(default = "default_window_bytes")]
    pub window_bytes: u32,
    #[serde(default = "default_max_windows")]
    pub max_windows: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeAttestationWindowKind {
    ElfHeader,
    GnuBuildId,
    Executable,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAttestationExpectedIdentity {
    pub binary_sha256: String,
    pub file_size: u64,
    pub architecture: String,
    pub elf_machine: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAttestationWindowPlan {
    pub index: u32,
    pub kind: RuntimeAttestationWindowKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_index: Option<u32>,
    pub file_offset: String,
    pub module_offset: String,
    pub length: u32,
    pub expected_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAttestationPlan {
    pub schema: String,
    pub attestation_id: String,
    pub module_name: String,
    pub expected_identity: RuntimeAttestationExpectedIdentity,
    pub load_base_vaddr: String,
    pub expected_mapped_size: u64,
    pub window_bytes: u32,
    pub max_windows: u32,
    pub coverage_strategy: String,
    pub complete_executable_coverage: bool,
    pub total_executable_bytes: u64,
    pub selected_executable_bytes: u64,
    pub plan_sha256: String,
    pub windows: Vec<RuntimeAttestationWindowPlan>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaRuntimeAttestationScript {
    pub file_name: String,
    pub module_name: String,
    pub static_binary_path: String,
    pub protocol_version: String,
    pub frida_api_version: String,
    pub script: String,
    pub plan: RuntimeAttestationPlan,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAttestationWindowCapture {
    pub index: u32,
    pub kind: RuntimeAttestationWindowKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_index: Option<u32>,
    pub file_offset: String,
    pub module_offset: String,
    pub length: u32,
    pub expected_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_sha256: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeAttestationRecord {
    pub protocol: String,
    pub event: String,
    pub attestation_id: String,
    pub timestamp_ms: u64,
    pub module_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_base: Option<String>,
    pub module_size: u64,
    pub expected_binary_sha256: String,
    pub expected_file_size: u64,
    pub expected_architecture: String,
    pub expected_elf_machine: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_build_id: Option<String>,
    pub load_base_vaddr: String,
    pub expected_mapped_size: u64,
    pub window_bytes: u32,
    pub max_windows: u32,
    pub coverage_strategy: String,
    pub complete_executable_coverage: bool,
    pub total_executable_bytes: u64,
    pub selected_executable_bytes: u64,
    pub plan_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fatal_error: Option<String>,
    #[serde(default)]
    pub windows: Vec<RuntimeAttestationWindowCapture>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationCaptureBundle {
    pub schema: String,
    pub records: Vec<RuntimeAttestationRecord>,
    pub duplicate_record_count: u64,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationWindowVerification {
    pub index: u32,
    pub kind: RuntimeAttestationWindowKind,
    pub file_offset: String,
    pub module_offset: String,
    pub length: u32,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationVerificationReport {
    pub schema: String,
    pub attestation_id: String,
    pub module_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_module_path: Option<String>,
    pub status: String,
    pub verification_gate_met: bool,
    pub attested_scope: String,
    pub exact_binary_sha256: String,
    pub expected_binary_sha256: String,
    pub exact_build_id: Option<String>,
    pub expected_build_id: Option<String>,
    pub plan_sha256: String,
    pub regenerated_plan_sha256: String,
    pub plan_matched: bool,
    pub module_size: u64,
    pub expected_mapped_size: u64,
    pub module_size_sufficient: bool,
    pub complete_executable_coverage: bool,
    pub total_executable_bytes: u64,
    pub selected_executable_bytes: u64,
    pub matched_executable_bytes: u64,
    pub matched_window_count: u64,
    pub mismatched_window_count: u64,
    pub unreadable_window_count: u64,
    pub missing_window_count: u64,
    pub unexpected_window_count: u64,
    pub windows: Vec<RuntimeAttestationWindowVerification>,
    pub evidence: Vec<String>,
    pub counter_evidence: Vec<String>,
    pub blockers: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAttestationInspectionReport {
    pub schema: String,
    pub capture_path: String,
    pub exact_binary_path: String,
    pub status: String,
    pub verification_gate_met: bool,
    pub record_count: u64,
    pub records: Vec<RuntimeAttestationVerificationReport>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

fn parse_hex_u64(value: &str, field: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty() {
        return Err(format!("{field} must be a hexadecimal integer"));
    }
    u64::from_str_radix(digits, 16).map_err(|_| format!("invalid {field}: {value}"))
}

fn sanitize_identifier(value: &str, fallback: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
            output.push(character);
        } else if !output.ends_with('_') {
            output.push('_');
        }
    }
    let output = output.trim_matches('_');
    if output.is_empty() {
        fallback.to_string()
    } else {
        output.to_string()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_request(request: &FridaRuntimeAttestationRequest) -> Result<(), String> {
    let module_name = request.module_name.trim();
    if module_name.is_empty()
        || module_name.len() > 512
        || module_name.chars().any(|character| character.is_control())
    {
        return Err("module_name must be a non-empty printable basename".to_string());
    }
    if request.static_binary_path.trim().is_empty() {
        return Err("static_binary_path must not be empty".to_string());
    }
    if !(MIN_WINDOW_BYTES..=MAX_WINDOW_BYTES).contains(&request.window_bytes)
        || !request.window_bytes.is_power_of_two()
    {
        return Err(format!(
            "window_bytes must be a power of two from {MIN_WINDOW_BYTES} through {MAX_WINDOW_BYTES}"
        ));
    }
    if request.max_windows == 0 || request.max_windows > MAX_WINDOWS {
        return Err(format!("max_windows must be from 1 through {MAX_WINDOWS}"));
    }
    let planned_bytes = u64::from(request.window_bytes) * u64::from(request.max_windows);
    if planned_bytes > MAX_PLANNED_BYTES {
        return Err(format!(
            "window_bytes * max_windows must not exceed {MAX_PLANNED_BYTES} bytes"
        ));
    }
    Ok(())
}

fn module_offset_for_file_range(
    layout: &ElfBinaryLayout,
    file_offset: u64,
    length: u64,
) -> Option<(u32, u64)> {
    let end = file_offset.checked_add(length)?;
    layout.load_segments.iter().find_map(|segment| {
        let segment_end = segment.file_offset.checked_add(segment.file_size)?;
        if file_offset < segment.file_offset || end > segment_end {
            return None;
        }
        let virtual_address = segment
            .virtual_address
            .checked_add(file_offset - segment.file_offset)?;
        let module_offset = virtual_address.checked_sub(layout.load_base_vaddr)?;
        Some((segment.index, module_offset))
    })
}

fn executable_window_plans(
    bytes: &[u8],
    layout: &ElfBinaryLayout,
    window_bytes: u32,
) -> Result<(Vec<RuntimeAttestationWindowPlan>, Vec<(usize, usize)>), String> {
    let mut windows = Vec::new();
    let mut segment_ranges = Vec::new();
    for segment in layout
        .load_segments
        .iter()
        .filter(|segment| segment.executable && segment.file_size > 0)
    {
        let start_index = windows.len();
        let mut consumed = 0u64;
        while consumed < segment.file_size {
            let length = (segment.file_size - consumed).min(u64::from(window_bytes));
            let file_offset = segment
                .file_offset
                .checked_add(consumed)
                .ok_or("executable file-offset overflow")?;
            let virtual_address = segment
                .virtual_address
                .checked_add(consumed)
                .ok_or("executable virtual-address overflow")?;
            let module_offset = virtual_address
                .checked_sub(layout.load_base_vaddr)
                .ok_or("executable module-offset underflow")?;
            let start = usize::try_from(file_offset)
                .map_err(|_| "executable file offset is too large".to_string())?;
            let length_usize = usize::try_from(length)
                .map_err(|_| "executable window length is too large".to_string())?;
            let end = start
                .checked_add(length_usize)
                .ok_or("executable window range overflow")?;
            let slice = bytes
                .get(start..end)
                .ok_or("executable window extends beyond the exact ELF")?;
            windows.push(RuntimeAttestationWindowPlan {
                index: 0,
                kind: RuntimeAttestationWindowKind::Executable,
                segment_index: Some(segment.index),
                file_offset: hex_u64(file_offset),
                module_offset: hex_u64(module_offset),
                length: length.min(u32::MAX as u64) as u32,
                expected_sha256: sha256_hex(slice),
            });
            consumed = consumed
                .checked_add(length)
                .ok_or("executable coverage counter overflow")?;
        }
        segment_ranges.push((start_index, windows.len()));
    }
    Ok((windows, segment_ranges))
}

fn evenly_spaced_indices(indices: &[usize], count: usize) -> Vec<usize> {
    if count == 0 || indices.is_empty() {
        return Vec::new();
    }
    if count >= indices.len() {
        return indices.to_vec();
    }
    if count == 1 {
        return vec![indices[0]];
    }
    let last = indices.len() - 1;
    (0..count)
        .map(|slot| indices[slot * last / (count - 1)])
        .collect()
}

fn select_executable_windows(
    all: &[RuntimeAttestationWindowPlan],
    segment_ranges: &[(usize, usize)],
    max_windows: usize,
) -> Vec<RuntimeAttestationWindowPlan> {
    if all.len() <= max_windows {
        return all.to_vec();
    }
    let mut selected = BTreeSet::new();
    for &(start, end) in segment_ranges {
        if start < end {
            selected.insert(start);
            selected.insert(end - 1);
        }
    }
    if selected.len() > max_windows {
        let mandatory = selected.into_iter().collect::<Vec<_>>();
        selected = evenly_spaced_indices(&mandatory, max_windows)
            .into_iter()
            .collect();
    } else if selected.len() < max_windows {
        let remaining = (0..all.len())
            .filter(|index| !selected.contains(index))
            .collect::<Vec<_>>();
        let wanted = max_windows - selected.len();
        selected.extend(evenly_spaced_indices(&remaining, wanted));
    }
    selected
        .into_iter()
        .filter_map(|index| all.get(index).cloned())
        .collect()
}

fn metadata_window(
    bytes: &[u8],
    layout: &ElfBinaryLayout,
    kind: RuntimeAttestationWindowKind,
    file_offset: u64,
    length: u32,
) -> Option<RuntimeAttestationWindowPlan> {
    let (segment_index, module_offset) =
        module_offset_for_file_range(layout, file_offset, u64::from(length))?;
    let start = usize::try_from(file_offset).ok()?;
    let end = start.checked_add(length as usize)?;
    let slice = bytes.get(start..end)?;
    Some(RuntimeAttestationWindowPlan {
        index: 0,
        kind,
        segment_index: Some(segment_index),
        file_offset: hex_u64(file_offset),
        module_offset: hex_u64(module_offset),
        length,
        expected_sha256: sha256_hex(slice),
    })
}

fn plan_digest(plan: &RuntimeAttestationPlan) -> Result<String, String> {
    let mut unsigned = plan.clone();
    unsigned.plan_sha256.clear();
    let encoded = serde_json::to_vec(&unsigned)
        .map_err(|error| format!("serialize runtime attestation plan failed: {error}"))?;
    Ok(sha256_hex(&encoded))
}

pub fn build_runtime_attestation_plan(
    request: &FridaRuntimeAttestationRequest,
) -> Result<RuntimeAttestationPlan, String> {
    validate_request(request)?;
    let bytes = fs::read(request.static_binary_path.trim()).map_err(|error| {
        format!(
            "failed to read exact ELF '{}': {error}",
            request.static_binary_path.trim()
        )
    })?;
    let layout = inspect_elf_layout(request.static_binary_path.trim())?;
    if layout.identity.elf_machine != 183 {
        return Err(format!(
            "runtime attestation requires an AArch64 ELF (e_machine 183); selected file is {} (e_machine {})",
            layout.identity.architecture, layout.identity.elf_machine
        ));
    }
    let (all_executable, segment_ranges) =
        executable_window_plans(&bytes, &layout, request.window_bytes)?;
    if all_executable.is_empty() {
        return Err("exact ELF has no file-backed executable PT_LOAD bytes".to_string());
    }
    let total_executable_bytes = all_executable
        .iter()
        .map(|window| u64::from(window.length))
        .sum::<u64>();
    let selected_executable = select_executable_windows(
        &all_executable,
        &segment_ranges,
        request.max_windows as usize,
    );
    let selected_executable_bytes = selected_executable
        .iter()
        .map(|window| u64::from(window.length))
        .sum::<u64>();
    let complete_executable_coverage = selected_executable.len() == all_executable.len()
        && selected_executable_bytes == total_executable_bytes;

    let mut windows = Vec::new();
    let header_length = bytes.len().min(64) as u32;
    if header_length > 0 {
        if let Some(window) = metadata_window(
            &bytes,
            &layout,
            RuntimeAttestationWindowKind::ElfHeader,
            0,
            header_length,
        ) {
            windows.push(window);
        }
    }
    if let Some(location) = &layout.build_id_location {
        if let Some(window) = metadata_window(
            &bytes,
            &layout,
            RuntimeAttestationWindowKind::GnuBuildId,
            location.file_offset,
            location.size,
        ) {
            windows.push(window);
        }
    }
    windows.extend(selected_executable);
    for (index, window) in windows.iter_mut().enumerate() {
        window.index = index.min(u32::MAX as usize) as u32;
    }

    let module_name = request.module_name.trim().to_string();
    let attestation_id = format!(
        "runtime-attestation-{}-{}",
        sanitize_identifier(&module_name, "module"),
        &layout.identity.binary_sha256[..12]
    );
    let mut plan = RuntimeAttestationPlan {
        schema: FRIDA_RUNTIME_ATTESTATION_SCHEMA.to_string(),
        attestation_id,
        module_name,
        expected_identity: RuntimeAttestationExpectedIdentity {
            binary_sha256: layout.identity.binary_sha256.clone(),
            file_size: layout.identity.file_size,
            architecture: layout.identity.architecture.clone(),
            elf_machine: layout.identity.elf_machine,
            build_id: layout.identity.build_id.clone(),
        },
        load_base_vaddr: hex_u64(layout.load_base_vaddr),
        expected_mapped_size: layout.mapped_size,
        window_bytes: request.window_bytes,
        max_windows: request.max_windows,
        coverage_strategy: if complete_executable_coverage {
            "full-file-backed-executable".to_string()
        } else {
            "deterministic-sampled-executable".to_string()
        },
        complete_executable_coverage,
        total_executable_bytes,
        selected_executable_bytes,
        plan_sha256: String::new(),
        windows,
    };
    plan.plan_sha256 = plan_digest(&plan)?;
    Ok(plan)
}

pub fn generate_frida_runtime_attestation_script(
    request: &FridaRuntimeAttestationRequest,
) -> Result<FridaRuntimeAttestationScript, String> {
    let plan = build_runtime_attestation_plan(request)?;
    let plan_json = serde_json::to_string_pretty(&plan)
        .map_err(|error| format!("serialize runtime attestation plan failed: {error}"))?;
    let file_name = format!(
        "{}-runtime-attestation.js",
        sanitize_identifier(&plan.module_name, "module")
    );
    let template = r##"/* Trace UI runtime image attestation
 * Frida JavaScript API target: 16.x
 * Protocol: trace-ui/frida-runtime-attestation-v1
 * The user manually loads this script. Trace UI does not attach, spawn, load, or execute Frida.
 * Scope: bounded hashes of exact-ELF-backed executable windows plus mapped ELF identity metadata.
 */
'use strict';

const PLAN = __PLAN_JSON__;

function emit(record) {
  send(record);
  console.log('TRACE_UI_JSON ' + JSON.stringify(record));
}

function rotr(value, amount) {
  return (value >>> amount) | (value << (32 - amount));
}

function sha256Hex(arrayBuffer) {
  const source = new Uint8Array(arrayBuffer);
  const bitLength = source.length * 8;
  const paddedLength = Math.ceil((source.length + 9) / 64) * 64;
  const data = new Uint8Array(paddedLength);
  data.set(source);
  data[source.length] = 0x80;
  const high = Math.floor(bitLength / 0x100000000);
  const low = bitLength >>> 0;
  data[paddedLength - 8] = (high >>> 24) & 0xff;
  data[paddedLength - 7] = (high >>> 16) & 0xff;
  data[paddedLength - 6] = (high >>> 8) & 0xff;
  data[paddedLength - 5] = high & 0xff;
  data[paddedLength - 4] = (low >>> 24) & 0xff;
  data[paddedLength - 3] = (low >>> 16) & 0xff;
  data[paddedLength - 2] = (low >>> 8) & 0xff;
  data[paddedLength - 1] = low & 0xff;

  const constants = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
  let h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const words = new Uint32Array(64);
  for (let offset = 0; offset < data.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const p = offset + i * 4;
      words[i] = ((data[p] << 24) | (data[p+1] << 16) | (data[p+2] << 8) | data[p+3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = (rotr(words[i-15],7) ^ rotr(words[i-15],18) ^ (words[i-15] >>> 3)) >>> 0;
      const s1 = (rotr(words[i-2],17) ^ rotr(words[i-2],19) ^ (words[i-2] >>> 10)) >>> 0;
      words[i] = (words[i-16] + s0 + words[i-7] + s1) >>> 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 64; i++) {
      const s1 = (rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)) >>> 0;
      const choose = ((e & f) ^ ((~e) & g)) >>> 0;
      const temp1 = (h + s1 + choose + constants[i] + words[i]) >>> 0;
      const s0 = (rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)) >>> 0;
      const majority = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (s0 + majority) >>> 0;
      h=g; g=f; f=e; e=(d+temp1)>>>0; d=c; c=b; b=a; a=(temp1+temp2)>>>0;
    }
    h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
    h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
  }
  return [h0,h1,h2,h3,h4,h5,h6,h7].map(value => ('00000000' + value.toString(16)).slice(-8)).join('');
}

function runAttestation() {
  const baseRecord = {
    protocol: PLAN.schema,
    event: 'runtime-attestation',
    attestationId: PLAN.attestationId,
    timestampMs: Date.now(),
    moduleName: PLAN.moduleName,
    modulePath: null,
    moduleBase: null,
    moduleSize: 0,
    expectedBinarySha256: PLAN.expectedIdentity.binarySha256,
    expectedFileSize: PLAN.expectedIdentity.fileSize,
    expectedArchitecture: PLAN.expectedIdentity.architecture,
    expectedElfMachine: PLAN.expectedIdentity.elfMachine,
    expectedBuildId: PLAN.expectedIdentity.buildId,
    loadBaseVaddr: PLAN.loadBaseVaddr,
    expectedMappedSize: PLAN.expectedMappedSize,
    windowBytes: PLAN.windowBytes,
    maxWindows: PLAN.maxWindows,
    coverageStrategy: PLAN.coverageStrategy,
    completeExecutableCoverage: PLAN.completeExecutableCoverage,
    totalExecutableBytes: PLAN.totalExecutableBytes,
    selectedExecutableBytes: PLAN.selectedExecutableBytes,
    planSha256: PLAN.planSha256,
    fatalError: null,
    windows: [],
    warnings: [
      'This is user-captured runtime evidence, not trusted remote attestation.',
      'Only planned file-backed executable bytes and mapped identity metadata are compared.'
    ]
  };
  let module;
  let moduleBase;
  try {
    moduleBase = Module.getBaseAddress(PLAN.moduleName);
    if (moduleBase === null) throw new Error('module not loaded: ' + PLAN.moduleName);
    module = Process.getModuleByName(PLAN.moduleName);
    baseRecord.moduleBase = moduleBase.toString();
    baseRecord.moduleSize = module.size;
    baseRecord.modulePath = module.path || null;
  } catch (error) {
    baseRecord.fatalError = 'module resolution failed: ' + String(error);
    emit(baseRecord);
    return;
  }
  for (const window of PLAN.windows) {
    const result = Object.assign({}, window, {
      actualSha256: null,
      status: 'unreadable',
      address: null,
      protection: null,
      readError: null
    });
    try {
      const address = moduleBase.add(ptr(window.moduleOffset));
      result.address = address.toString();
      try {
        const range = Process.findRangeByAddress(address);
        result.protection = range ? range.protection : null;
      } catch (_) {}
      const bytes = address.readByteArray(window.length);
      if (bytes === null) throw new Error('readByteArray returned null');
      result.actualSha256 = sha256Hex(bytes);
      result.status = result.actualSha256.toLowerCase() === window.expectedSha256.toLowerCase()
        ? 'matched'
        : 'mismatch';
    } catch (error) {
      result.readError = String(error);
    }
    baseRecord.windows.push(result);
  }
  emit(baseRecord);
}

setImmediate(runAttestation);
"##;
    let script = template.replace("__PLAN_JSON__", &plan_json);
    Ok(FridaRuntimeAttestationScript {
        file_name,
        module_name: plan.module_name.clone(),
        static_binary_path: request.static_binary_path.trim().to_string(),
        protocol_version: FRIDA_RUNTIME_ATTESTATION_SCHEMA.to_string(),
        frida_api_version: "16.x".to_string(),
        script,
        plan,
        warnings: vec![
            "Trace UI only generates this Frida 16.x script. The user controls attach, spawn, load, and execution.".to_string(),
            "Full verification is scoped to all file-backed executable PT_LOAD bytes selected by a complete plan; writable/BSS/runtime-generated state is outside that scope.".to_string(),
            "When the configured window cap forces deterministic sampling, a clean result remains Related rather than Verified.".to_string(),
            "A capture file can be fabricated or altered by its producer; this is reproducible user-captured byte evidence, not hardware-backed or remote attestation.".to_string(),
        ],
    })
}

fn collect_attestation_values(value: Value, output: &mut Vec<Value>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_attestation_values(value, output);
            }
        }
        Value::Object(mut object) => {
            if object
                .get("protocol")
                .and_then(Value::as_str)
                .is_some_and(|protocol| protocol == FRIDA_RUNTIME_ATTESTATION_SCHEMA)
            {
                output.push(Value::Object(object));
            } else if let Some(payload) = object.remove("payload") {
                collect_attestation_values(payload, output);
            }
        }
        _ => {}
    }
}

fn parse_capture_values(bytes: &[u8]) -> Result<Vec<Value>, String> {
    if bytes.len() as u64 > MAX_CAPTURE_BYTES {
        return Err(format!(
            "runtime attestation capture exceeds {MAX_CAPTURE_BYTES} bytes"
        ));
    }
    let mut output = Vec::new();
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        collect_attestation_values(value, &mut output);
        if !output.is_empty() {
            return Ok(output);
        }
    }
    let text = std::str::from_utf8(bytes).map_err(|error| {
        format!("runtime attestation capture is not UTF-8 JSON/NDJSON: {error}")
    })?;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let candidate = trimmed
            .split_once("TRACE_UI_JSON ")
            .map(|(_, value)| value.trim())
            .or_else(|| trimmed.starts_with('{').then_some(trimmed));
        let Some(candidate) = candidate else {
            continue;
        };
        if let Ok(value) = serde_json::from_str::<Value>(candidate) {
            collect_attestation_values(value, &mut output);
        }
    }
    Ok(output)
}

fn validate_capture_record(record: &RuntimeAttestationRecord) -> Result<(), String> {
    if record.protocol != FRIDA_RUNTIME_ATTESTATION_SCHEMA || record.event != "runtime-attestation"
    {
        return Err("unsupported runtime attestation protocol/event".to_string());
    }
    if record.attestation_id.trim().is_empty() || record.module_name.trim().is_empty() {
        return Err("runtime attestation IDs and module name must not be empty".to_string());
    }
    if !valid_sha256(&record.expected_binary_sha256) || !valid_sha256(&record.plan_sha256) {
        return Err("runtime attestation expected binary/plan SHA-256 is invalid".to_string());
    }
    if record.expected_elf_machine != 183 || record.expected_architecture != "AArch64" {
        return Err("runtime attestation capture is not for an AArch64 ELF".to_string());
    }
    if !(MIN_WINDOW_BYTES..=MAX_WINDOW_BYTES).contains(&record.window_bytes)
        || !record.window_bytes.is_power_of_two()
        || record.max_windows == 0
        || record.max_windows > MAX_WINDOWS
    {
        return Err("runtime attestation window configuration is out of bounds".to_string());
    }
    if record.windows.len() > MAX_WINDOWS as usize + 2 {
        return Err("runtime attestation contains too many windows".to_string());
    }
    let mut indexes = BTreeSet::new();
    for window in &record.windows {
        if !indexes.insert(window.index) {
            return Err(format!(
                "runtime attestation repeats window index {}",
                window.index
            ));
        }
        parse_hex_u64(&window.file_offset, "window fileOffset")?;
        parse_hex_u64(&window.module_offset, "window moduleOffset")?;
        if window.length == 0 || window.length > MAX_WINDOW_BYTES {
            return Err(format!(
                "runtime attestation window {} has invalid length {}",
                window.index, window.length
            ));
        }
        if !valid_sha256(&window.expected_sha256) {
            return Err(format!(
                "runtime attestation window {} expected SHA-256 is invalid",
                window.index
            ));
        }
        if let Some(actual) = &window.actual_sha256 {
            if !valid_sha256(actual) {
                return Err(format!(
                    "runtime attestation window {} actual SHA-256 is invalid",
                    window.index
                ));
            }
        }
        if !matches!(
            window.status.as_str(),
            "matched" | "mismatch" | "unreadable"
        ) {
            return Err(format!(
                "runtime attestation window {} has unsupported status {}",
                window.index, window.status
            ));
        }
    }
    Ok(())
}

pub fn parse_runtime_attestation_capture_bundle(
    bytes: &[u8],
) -> Result<RuntimeAttestationCaptureBundle, String> {
    let values = parse_capture_values(bytes)?;
    if values.is_empty() {
        return Err(
            "No trace-ui/frida-runtime-attestation-v1 records found in capture".to_string(),
        );
    }
    let mut records = Vec::new();
    let mut seen = BTreeSet::new();
    let mut duplicate_record_count = 0u64;
    for value in values {
        let record: RuntimeAttestationRecord = serde_json::from_value(value)
            .map_err(|error| format!("invalid runtime attestation record: {error}"))?;
        validate_capture_record(&record)?;
        let key = format!(
            "{}\0{}\0{}",
            record.attestation_id, record.timestamp_ms, record.plan_sha256
        );
        if seen.insert(key) {
            records.push(record);
        } else {
            duplicate_record_count += 1;
        }
    }
    if records.len() > 32 {
        return Err("runtime attestation capture contains more than 32 unique records".to_string());
    }
    Ok(RuntimeAttestationCaptureBundle {
        schema: FRIDA_RUNTIME_ATTESTATION_SCHEMA.to_string(),
        records,
        duplicate_record_count,
        warnings: (duplicate_record_count > 0)
            .then(|| {
                vec![format!(
                    "Deduplicated {duplicate_record_count} repeated send()/TRACE_UI_JSON record(s)."
                )]
            })
            .unwrap_or_default(),
    })
}

fn plan_request_from_record(
    record: &RuntimeAttestationRecord,
    binary_path: &str,
) -> FridaRuntimeAttestationRequest {
    FridaRuntimeAttestationRequest {
        module_name: record.module_name.clone(),
        static_binary_path: binary_path.to_string(),
        window_bytes: record.window_bytes,
        max_windows: record.max_windows,
    }
}

pub fn verify_runtime_attestation_record(
    record: &RuntimeAttestationRecord,
    exact_binary_path: &str,
) -> Result<RuntimeAttestationVerificationReport, String> {
    validate_capture_record(record)?;
    let regenerated =
        build_runtime_attestation_plan(&plan_request_from_record(record, exact_binary_path))?;
    let exact_identity = &regenerated.expected_identity;
    let identity_matches = exact_identity
        .binary_sha256
        .eq_ignore_ascii_case(&record.expected_binary_sha256)
        && exact_identity.file_size == record.expected_file_size
        && exact_identity.architecture == record.expected_architecture
        && exact_identity.elf_machine == record.expected_elf_machine
        && exact_identity.build_id == record.expected_build_id;
    let plan_matched = identity_matches
        && regenerated
            .plan_sha256
            .eq_ignore_ascii_case(&record.plan_sha256)
        && regenerated.load_base_vaddr == record.load_base_vaddr
        && regenerated.expected_mapped_size == record.expected_mapped_size
        && regenerated.complete_executable_coverage == record.complete_executable_coverage
        && regenerated.total_executable_bytes == record.total_executable_bytes
        && regenerated.selected_executable_bytes == record.selected_executable_bytes;
    let module_size_sufficient = record.module_size >= regenerated.expected_mapped_size;
    let captured_by_index = record
        .windows
        .iter()
        .map(|window| (window.index, window))
        .collect::<BTreeMap<_, _>>();
    let expected_indexes = regenerated
        .windows
        .iter()
        .map(|window| window.index)
        .collect::<BTreeSet<_>>();
    let unexpected_window_count = captured_by_index
        .keys()
        .filter(|index| !expected_indexes.contains(index))
        .count() as u64;
    let mut windows = Vec::new();
    let mut matched_window_count = 0u64;
    let mut mismatched_window_count = 0u64;
    let mut unreadable_window_count = 0u64;
    let mut missing_window_count = 0u64;
    let mut matched_executable_bytes = 0u64;
    let mut counter_evidence = Vec::new();
    let mut blockers = Vec::new();

    for expected in &regenerated.windows {
        let Some(captured) = captured_by_index.get(&expected.index).copied() else {
            missing_window_count += 1;
            windows.push(RuntimeAttestationWindowVerification {
                index: expected.index,
                kind: expected.kind,
                file_offset: expected.file_offset.clone(),
                module_offset: expected.module_offset.clone(),
                length: expected.length,
                status: "missing".to_string(),
                expected_sha256: Some(expected.expected_sha256.clone()),
                actual_sha256: None,
                reason: Some("The capture omitted a planned window.".to_string()),
            });
            continue;
        };
        let plan_fields_match = captured.kind == expected.kind
            && captured.segment_index == expected.segment_index
            && captured
                .file_offset
                .eq_ignore_ascii_case(&expected.file_offset)
            && captured
                .module_offset
                .eq_ignore_ascii_case(&expected.module_offset)
            && captured.length == expected.length
            && captured
                .expected_sha256
                .eq_ignore_ascii_case(&expected.expected_sha256);
        let (status, reason) = if !plan_fields_match {
            mismatched_window_count += 1;
            counter_evidence.push(format!(
                "Window {} plan fields do not match the exact ELF-derived plan.",
                expected.index
            ));
            (
                "plan-mismatch".to_string(),
                Some(
                    "Captured plan metadata differs from the regenerated exact-ELF plan."
                        .to_string(),
                ),
            )
        } else if let Some(actual) = &captured.actual_sha256 {
            if actual.eq_ignore_ascii_case(&expected.expected_sha256)
                && captured.status == "matched"
            {
                matched_window_count += 1;
                if expected.kind == RuntimeAttestationWindowKind::Executable {
                    matched_executable_bytes += u64::from(expected.length);
                }
                ("matched".to_string(), None)
            } else {
                mismatched_window_count += 1;
                counter_evidence.push(format!(
                    "Window {} at module offset {} differs from exact ELF bytes.",
                    expected.index, expected.module_offset
                ));
                (
                    "mismatch".to_string(),
                    Some("Runtime SHA-256 differs from the exact ELF window.".to_string()),
                )
            }
        } else {
            unreadable_window_count += 1;
            (
                "unreadable".to_string(),
                Some(
                    captured
                        .read_error
                        .clone()
                        .unwrap_or_else(|| "No runtime SHA-256 was captured.".to_string()),
                ),
            )
        };
        windows.push(RuntimeAttestationWindowVerification {
            index: expected.index,
            kind: expected.kind,
            file_offset: expected.file_offset.clone(),
            module_offset: expected.module_offset.clone(),
            length: expected.length,
            status,
            expected_sha256: Some(expected.expected_sha256.clone()),
            actual_sha256: captured.actual_sha256.clone(),
            reason,
        });
    }

    if !identity_matches {
        counter_evidence.push(
            "The capture expected identity does not match the selected exact ELF identity."
                .to_string(),
        );
    }
    if !plan_matched {
        blockers.push(
            "The captured plan SHA-256 or exact-ELF-derived plan metadata does not match."
                .to_string(),
        );
    }
    if record.module_base.is_none() {
        blockers.push("The capture has no resolved runtime module base.".to_string());
    }
    if !module_size_sufficient {
        blockers.push(format!(
            "Runtime module size {} is smaller than the exact ELF mapped span {}.",
            record.module_size, regenerated.expected_mapped_size
        ));
    }
    if let Some(error) = &record.fatal_error {
        blockers.push(format!("Frida runtime capture failed: {error}"));
    }
    if missing_window_count > 0 {
        blockers.push(format!(
            "{missing_window_count} planned runtime window(s) are missing."
        ));
    }
    if unreadable_window_count > 0 {
        blockers.push(format!(
            "{unreadable_window_count} planned runtime window(s) were unreadable."
        ));
    }
    if unexpected_window_count > 0 {
        blockers.push(format!(
            "{unexpected_window_count} unexpected runtime window(s) are present."
        ));
    }
    if !regenerated.complete_executable_coverage {
        blockers.push(format!(
            "The plan sampled {} of {} file-backed executable byte(s); full coverage is required for Verified.",
            regenerated.selected_executable_bytes, regenerated.total_executable_bytes
        ));
    }
    let verification_gate_met = identity_matches
        && plan_matched
        && regenerated.complete_executable_coverage
        && mismatched_window_count == 0
        && unreadable_window_count == 0
        && missing_window_count == 0
        && unexpected_window_count == 0
        && record.module_base.is_some()
        && module_size_sufficient
        && record.fatal_error.is_none()
        && matched_executable_bytes == regenerated.total_executable_bytes;
    let status = if !identity_matches || mismatched_window_count > 0 {
        "refuted"
    } else if verification_gate_met {
        "verified-full"
    } else if matched_executable_bytes > 0
        && unreadable_window_count == 0
        && missing_window_count == 0
        && record.fatal_error.is_none()
    {
        "related-sampled"
    } else {
        "incomplete"
    };
    let mut evidence = vec![format!(
        "Matched {matched_window_count}/{} planned runtime window(s).",
        regenerated.windows.len()
    )];
    if matched_executable_bytes > 0 {
        evidence.push(format!(
            "Matched {matched_executable_bytes}/{} file-backed executable byte(s).",
            regenerated.total_executable_bytes
        ));
    }
    if verification_gate_met {
        evidence.push(
            "runtime-attestation/full-file-backed-executable-byte-match verification gate passed"
                .to_string(),
        );
    }
    Ok(RuntimeAttestationVerificationReport {
        schema: RUNTIME_ATTESTATION_VERIFICATION_SCHEMA.to_string(),
        attestation_id: record.attestation_id.clone(),
        module_name: record.module_name.clone(),
        runtime_module_path: record.module_path.clone(),
        status: status.to_string(),
        verification_gate_met,
        attested_scope: "user-captured mapped ELF metadata and file-backed executable PT_LOAD bytes"
            .to_string(),
        exact_binary_sha256: exact_identity.binary_sha256.clone(),
        expected_binary_sha256: record.expected_binary_sha256.clone(),
        exact_build_id: exact_identity.build_id.clone(),
        expected_build_id: record.expected_build_id.clone(),
        plan_sha256: record.plan_sha256.clone(),
        regenerated_plan_sha256: regenerated.plan_sha256,
        plan_matched,
        module_size: record.module_size,
        expected_mapped_size: regenerated.expected_mapped_size,
        module_size_sufficient,
        complete_executable_coverage: regenerated.complete_executable_coverage,
        total_executable_bytes: regenerated.total_executable_bytes,
        selected_executable_bytes: regenerated.selected_executable_bytes,
        matched_executable_bytes,
        matched_window_count,
        mismatched_window_count,
        unreadable_window_count,
        missing_window_count,
        unexpected_window_count,
        windows,
        evidence,
        counter_evidence,
        blockers,
        limitations: vec![
            "The capture was produced in a user-controlled Frida environment and is not hardware-backed or remote attestation.".to_string(),
            "Verified-full is scoped only to mapped metadata windows and all file-backed executable PT_LOAD bytes; writable data, BSS, heap, JIT code, and process state remain outside the claim.".to_string(),
            "A matching runtime image does not verify crypto semantics, OLLVM classification, branch reachability, or simulator completeness.".to_string(),
        ],
    })
}

pub fn verify_runtime_attestation_bundle(
    bundle: &RuntimeAttestationCaptureBundle,
    capture_path: &str,
    exact_binary_path: &str,
) -> Result<RuntimeAttestationInspectionReport, String> {
    let mut records = Vec::new();
    for record in &bundle.records {
        records.push(verify_runtime_attestation_record(
            record,
            exact_binary_path,
        )?);
    }
    let verification_gate_met =
        !records.is_empty() && records.iter().all(|record| record.verification_gate_met);
    let distinct_statuses = records
        .iter()
        .map(|record| record.status.as_str())
        .collect::<BTreeSet<_>>();
    let status = if records.iter().any(|record| record.status == "refuted") {
        "refuted"
    } else if verification_gate_met {
        "verified-full"
    } else if distinct_statuses.len() > 1 {
        "mixed"
    } else {
        records
            .first()
            .map(|record| record.status.as_str())
            .unwrap_or("incomplete")
    };
    Ok(RuntimeAttestationInspectionReport {
        schema: RUNTIME_ATTESTATION_VERIFICATION_SCHEMA.to_string(),
        capture_path: capture_path.to_string(),
        exact_binary_path: exact_binary_path.to_string(),
        status: status.to_string(),
        verification_gate_met,
        record_count: records.len() as u64,
        records,
        warnings: bundle.warnings.clone(),
        limitations: vec![
            "Trace UI parsed and recomputed this artifact but did not execute Frida or observe the target process directly.".to_string(),
            "Do not reuse an attestation across module builds, process runs, or module basenames without a new manual capture.".to_string(),
        ],
    })
}

pub fn inspect_runtime_attestation_capture(
    capture_path: &str,
    exact_binary_path: &str,
) -> Result<RuntimeAttestationInspectionReport, String> {
    if capture_path.trim().is_empty() || exact_binary_path.trim().is_empty() {
        return Err("capture_path and exact_binary_path must not be empty".to_string());
    }
    let metadata = fs::metadata(capture_path)
        .map_err(|error| format!("failed to read runtime attestation capture metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_CAPTURE_BYTES {
        return Err(format!(
            "runtime attestation capture must be a regular file no larger than {MAX_CAPTURE_BYTES} bytes"
        ));
    }
    let bytes = fs::read(capture_path)
        .map_err(|error| format!("failed to read runtime attestation capture: {error}"))?;
    let bundle = parse_runtime_attestation_capture_bundle(&bytes)?;
    verify_runtime_attestation_bundle(&bundle, capture_path, exact_binary_path)
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

    fn test_elf(executable_bytes: usize) -> Vec<u8> {
        const PROGRAM_OFFSET: usize = 64;
        const NOTE_OFFSET: usize = 0x180;
        const EXEC_OFFSET: usize = 0x1000;
        let mut elf = vec![0u8; EXEC_OFFSET + executable_bytes];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        write_u16(&mut elf, 16, 3);
        write_u16(&mut elf, 18, 183);
        write_u32(&mut elf, 20, 1);
        write_u64(&mut elf, 32, PROGRAM_OFFSET as u64);
        write_u16(&mut elf, 52, 64);
        write_u16(&mut elf, 54, 56);
        write_u16(&mut elf, 56, 3);

        write_u32(&mut elf, PROGRAM_OFFSET, 1);
        write_u32(&mut elf, PROGRAM_OFFSET + 4, 4);
        write_u64(&mut elf, PROGRAM_OFFSET + 8, 0);
        write_u64(&mut elf, PROGRAM_OFFSET + 16, 0);
        write_u64(&mut elf, PROGRAM_OFFSET + 32, EXEC_OFFSET as u64);
        write_u64(&mut elf, PROGRAM_OFFSET + 40, EXEC_OFFSET as u64);
        write_u64(&mut elf, PROGRAM_OFFSET + 48, 0x1000);

        let note_header = PROGRAM_OFFSET + 56;
        write_u32(&mut elf, note_header, 4);
        write_u32(&mut elf, note_header + 4, 4);
        write_u64(&mut elf, note_header + 8, NOTE_OFFSET as u64);
        write_u64(&mut elf, note_header + 16, NOTE_OFFSET as u64);
        write_u64(&mut elf, note_header + 32, 20);
        write_u64(&mut elf, note_header + 40, 20);
        write_u64(&mut elf, note_header + 48, 4);

        let exec_header = PROGRAM_OFFSET + 112;
        write_u32(&mut elf, exec_header, 1);
        write_u32(&mut elf, exec_header + 4, 5);
        write_u64(&mut elf, exec_header + 8, EXEC_OFFSET as u64);
        write_u64(&mut elf, exec_header + 16, EXEC_OFFSET as u64);
        write_u64(&mut elf, exec_header + 32, executable_bytes as u64);
        write_u64(&mut elf, exec_header + 40, executable_bytes as u64);
        write_u64(&mut elf, exec_header + 48, 0x1000);

        write_u32(&mut elf, NOTE_OFFSET, 4);
        write_u32(&mut elf, NOTE_OFFSET + 4, 4);
        write_u32(&mut elf, NOTE_OFFSET + 8, 3);
        elf[NOTE_OFFSET + 12..NOTE_OFFSET + 16].copy_from_slice(b"GNU\0");
        elf[NOTE_OFFSET + 16..NOTE_OFFSET + 20].copy_from_slice(&[1, 2, 3, 4]);
        for (index, byte) in elf[EXEC_OFFSET..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        elf
    }

    fn temp_elf(executable_bytes: usize) -> String {
        let path = std::env::temp_dir().join(format!(
            "trace-ui-runtime-attestation-{}.so",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, test_elf(executable_bytes)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn request(path: &str, max_windows: u32) -> FridaRuntimeAttestationRequest {
        FridaRuntimeAttestationRequest {
            module_name: "libtarget.so".to_string(),
            static_binary_path: path.to_string(),
            window_bytes: 4096,
            max_windows,
        }
    }

    fn matching_record(plan: &RuntimeAttestationPlan) -> RuntimeAttestationRecord {
        RuntimeAttestationRecord {
            protocol: FRIDA_RUNTIME_ATTESTATION_SCHEMA.to_string(),
            event: "runtime-attestation".to_string(),
            attestation_id: plan.attestation_id.clone(),
            timestamp_ms: 1,
            module_name: plan.module_name.clone(),
            module_path: Some("/data/app/libtarget.so".to_string()),
            module_base: Some("0x71000000".to_string()),
            module_size: plan.expected_mapped_size,
            expected_binary_sha256: plan.expected_identity.binary_sha256.clone(),
            expected_file_size: plan.expected_identity.file_size,
            expected_architecture: plan.expected_identity.architecture.clone(),
            expected_elf_machine: plan.expected_identity.elf_machine,
            expected_build_id: plan.expected_identity.build_id.clone(),
            load_base_vaddr: plan.load_base_vaddr.clone(),
            expected_mapped_size: plan.expected_mapped_size,
            window_bytes: plan.window_bytes,
            max_windows: plan.max_windows,
            coverage_strategy: plan.coverage_strategy.clone(),
            complete_executable_coverage: plan.complete_executable_coverage,
            total_executable_bytes: plan.total_executable_bytes,
            selected_executable_bytes: plan.selected_executable_bytes,
            plan_sha256: plan.plan_sha256.clone(),
            fatal_error: None,
            windows: plan
                .windows
                .iter()
                .map(|window| RuntimeAttestationWindowCapture {
                    index: window.index,
                    kind: window.kind,
                    segment_index: window.segment_index,
                    file_offset: window.file_offset.clone(),
                    module_offset: window.module_offset.clone(),
                    length: window.length,
                    expected_sha256: window.expected_sha256.clone(),
                    actual_sha256: Some(window.expected_sha256.clone()),
                    status: "matched".to_string(),
                    address: Some("0x71001000".to_string()),
                    protection: Some("r-x".to_string()),
                    read_error: None,
                })
                .collect(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn generates_manual_frida_16_script_with_full_plan() {
        let path = temp_elf(8192);
        let generated = generate_frida_runtime_attestation_script(&request(&path, 8)).unwrap();
        assert!(generated.plan.complete_executable_coverage);
        assert_eq!(generated.plan.total_executable_bytes, 8192);
        assert!(generated.script.contains("Module.getBaseAddress"));
        assert!(generated.script.contains("Process.getModuleByName"));
        assert!(generated.script.contains("TRACE_UI_JSON"));
        assert!(!generated.script.contains("frida.attach"));
        assert!(!generated.script.contains("frida.spawn"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn full_executable_byte_match_passes_scoped_gate() {
        let path = temp_elf(8192);
        let plan = build_runtime_attestation_plan(&request(&path, 8)).unwrap();
        let report = verify_runtime_attestation_record(&matching_record(&plan), &path).unwrap();
        assert_eq!(report.status, "verified-full");
        assert!(report.verification_gate_met);
        assert_eq!(report.matched_executable_bytes, 8192);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn deterministic_sample_remains_related() {
        let path = temp_elf(20_000);
        let plan = build_runtime_attestation_plan(&request(&path, 2)).unwrap();
        assert!(!plan.complete_executable_coverage);
        let report = verify_runtime_attestation_record(&matching_record(&plan), &path).unwrap();
        assert_eq!(report.status, "related-sampled");
        assert!(!report.verification_gate_met);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_hash_difference_is_counter_evidence() {
        let path = temp_elf(4096);
        let plan = build_runtime_attestation_plan(&request(&path, 8)).unwrap();
        let mut record = matching_record(&plan);
        let executable = record
            .windows
            .iter_mut()
            .find(|window| window.kind == RuntimeAttestationWindowKind::Executable)
            .unwrap();
        executable.actual_sha256 = Some("ff".repeat(32));
        executable.status = "mismatch".to_string();
        let report = verify_runtime_attestation_record(&record, &path).unwrap();
        assert_eq!(report.status, "refuted");
        assert!(!report.counter_evidence.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn parser_deduplicates_send_and_cli_copies() {
        let path = temp_elf(4096);
        let plan = build_runtime_attestation_plan(&request(&path, 8)).unwrap();
        let record = matching_record(&plan);
        let encoded = serde_json::to_string(&record).unwrap();
        let input =
            format!("{{\"type\":\"send\",\"payload\":{encoded}}}\nTRACE_UI_JSON {encoded}\n");
        let parsed = parse_runtime_attestation_capture_bundle(input.as_bytes()).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.duplicate_record_count, 1);
        let _ = fs::remove_file(path);
    }
}
