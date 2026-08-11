use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::query::elf_identity::{inspect_elf_layout, ElfBinaryIdentity, ElfBinaryLayout};
use crate::query::frida_capture::{
    parse_frida_capture_bundle, FridaCaptureBundle, FridaCaptureEvent, FridaCapturedValue,
};
use crate::utils::parse_hex_addr;

pub const EXACT_CALL_SUMMARY_SCHEMA: &str = "trace-ui/exact-call-summary-v1";
pub const EXACT_CALL_REPLAY_AUTHORIZATION_SCHEMA: &str =
    "trace-ui/exact-call-replay-authorization-v1";
pub const MAX_EXACT_CALL_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

const DEFAULT_MAX_CALLS: u32 = 1_024;
const MAX_CALLS: u32 = 4_096;
const DEFAULT_MAX_MEMORY_BYTES_PER_CALL: u64 = 1_048_576;
const MAX_MEMORY_BYTES_PER_CALL: u64 = 8 * 1_048_576;
const MAX_AUTHORIZED_CALLS: usize = 64;

fn default_max_calls() -> u32 {
    DEFAULT_MAX_CALLS
}

fn default_max_memory_bytes_per_call() -> u64 {
    DEFAULT_MAX_MEMORY_BYTES_PER_CALL
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallSummaryRequest {
    pub caller_module_name: String,
    pub static_binary_path: String,
    #[serde(default = "default_max_calls")]
    pub max_calls: u32,
    #[serde(default = "default_max_memory_bytes_per_call")]
    pub max_memory_bytes_per_call: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallChangedRange {
    pub start_offset: u64,
    pub end_offset_exclusive: u64,
    pub before_hex: String,
    pub after_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallMemoryEffect {
    pub index: u8,
    pub label: String,
    pub direction: String,
    pub pointer: String,
    pub byte_length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_register: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displacement: Option<String>,
    pub before_hex: String,
    pub after_hex: String,
    pub changed_ranges: Vec<ExactCallChangedRange>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallRegisterEffect {
    pub register: String,
    pub before: String,
    pub after: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallCaptureCompleteness {
    pub pair_complete: bool,
    pub same_thread: bool,
    pub event_order_valid: bool,
    pub exact_record_mode: bool,
    pub exact_target_known: bool,
    pub exact_call_site_known: bool,
    pub exact_return_site_known: bool,
    pub full_gpr_enter: bool,
    pub full_gpr_leave: bool,
    pub nzcv_enter: bool,
    pub nzcv_leave: bool,
    pub return_value_captured: bool,
    pub return_matches_x0: bool,
    pub byte_array_pairs_complete: bool,
    pub no_capture_errors: bool,
    pub no_capture_truncation: bool,
    pub callee_saved_preserved: bool,
    pub capture_ready: bool,
    pub hidden_memory_effects_known: bool,
    pub simd_fp_effects_known: bool,
    pub tls_effects_known: bool,
    pub system_thread_effects_known: bool,
    pub replay_authorized: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallRecord {
    pub call_id: String,
    pub hook_id: String,
    pub function_name: String,
    pub enter_event_index: u64,
    pub leave_event_index: u64,
    pub thread_id: u64,
    pub enter_timestamp_ms: u64,
    pub leave_timestamp_ms: u64,
    pub duration_ms: u64,
    pub target_module_name: String,
    pub target_module_base: String,
    pub target_module_size: u64,
    pub target_address: String,
    pub target_offset: String,
    pub caller_module_name: String,
    pub caller_module_base: String,
    pub caller_module_size: u64,
    pub call_site: String,
    pub call_site_offset: String,
    pub return_address: String,
    pub return_offset: String,
    pub entry_registers: BTreeMap<String, String>,
    pub exit_registers: BTreeMap<String, String>,
    pub register_effects: Vec<ExactCallRegisterEffect>,
    pub memory_effects: Vec<ExactCallMemoryEffect>,
    pub captured_memory_bytes: u64,
    pub memory_effects_truncated: bool,
    pub return_value: String,
    pub completeness: ExactCallCaptureCompleteness,
    pub status: String,
    pub evidence_level: String,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallSummaryBundle {
    pub schema: String,
    pub request: ExactCallSummaryRequest,
    pub source_capture_path: String,
    pub source_capture_sha256: String,
    pub exact_binary_identity: ElfBinaryIdentity,
    pub calls: Vec<ExactCallRecord>,
    pub paired_call_count: u64,
    pub capture_ready_call_count: u64,
    pub incomplete_call_count: u64,
    pub unpaired_enter_event_indices: Vec<u64>,
    pub unpaired_leave_event_indices: Vec<u64>,
    pub calls_truncated: bool,
    pub verification_gate_met: bool,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallReplayAssumptions {
    #[serde(default)]
    pub captured_memory_effects_complete: bool,
    #[serde(default)]
    pub no_simd_fp_side_effects: bool,
    #[serde(default)]
    pub no_tls_side_effects: bool,
    #[serde(default)]
    pub no_system_register_or_syscall_effects: bool,
    #[serde(default)]
    pub no_thread_signal_or_callback_effects: bool,
    #[serde(default)]
    pub deterministic_for_exact_preconditions: bool,
}

impl ExactCallReplayAssumptions {
    fn missing(&self) -> Vec<String> {
        let mut missing = Vec::new();
        if !self.captured_memory_effects_complete {
            missing.push("captured-memory-effects-complete".to_string());
        }
        if !self.no_simd_fp_side_effects {
            missing.push("no-simd-fp-side-effects".to_string());
        }
        if !self.no_tls_side_effects {
            missing.push("no-tls-side-effects".to_string());
        }
        if !self.no_system_register_or_syscall_effects {
            missing.push("no-system-register-or-syscall-effects".to_string());
        }
        if !self.no_thread_signal_or_callback_effects {
            missing.push("no-thread-signal-or-callback-effects".to_string());
        }
        if !self.deterministic_for_exact_preconditions {
            missing.push("deterministic-for-exact-preconditions".to_string());
        }
        missing
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallReplayAuthorizationRequest {
    pub call_ids: Vec<String>,
    #[serde(default)]
    pub assumptions: ExactCallReplayAssumptions,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallRegisterValue {
    pub register: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallReplayAuthorization {
    pub authorization_id: String,
    pub call_id: String,
    pub status: String,
    pub authorized: bool,
    pub evidence_level: String,
    pub caller_module_name: String,
    pub caller_module_base: String,
    pub caller_module_size: u64,
    pub call_site_offset: String,
    pub return_offset: String,
    pub target_module_name: String,
    pub target_module_base: String,
    pub target_module_size: u64,
    pub target_address: String,
    pub target_offset: String,
    pub precondition_registers: Vec<ExactCallRegisterValue>,
    pub register_writes: Vec<ExactCallRegisterValue>,
    pub memory_effects: Vec<ExactCallMemoryEffect>,
    pub return_value: String,
    pub assumptions: ExactCallReplayAssumptions,
    pub blockers: Vec<String>,
    pub limitations: Vec<String>,
    pub verification_gate_met: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactCallReplayAuthorizationBundle {
    pub schema: String,
    pub summary_path: String,
    pub summary_sha256: String,
    pub source_capture_sha256: String,
    pub exact_binary_identity: ElfBinaryIdentity,
    pub request: ExactCallReplayAuthorizationRequest,
    pub authorizations: Vec<ExactCallReplayAuthorization>,
    pub authorized_count: u64,
    pub blocked_count: u64,
    pub verification_gate_met: bool,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Default)]
struct CallPair<'a> {
    enters: Vec<&'a FridaCaptureEvent>,
    leaves: Vec<&'a FridaCaptureEvent>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_summary_request(request: &ExactCallSummaryRequest) -> Result<(), String> {
    if request.caller_module_name.trim().is_empty()
        || request
            .caller_module_name
            .chars()
            .any(|character| character.is_control())
    {
        return Err("caller_module_name must be a printable module basename".to_string());
    }
    if request.static_binary_path.trim().is_empty()
        || !Path::new(request.static_binary_path.trim()).is_absolute()
    {
        return Err("static_binary_path must be an absolute exact ELF path".to_string());
    }
    if !(1..=MAX_CALLS).contains(&request.max_calls) {
        return Err(format!("max_calls must be between 1 and {MAX_CALLS}"));
    }
    if !(1..=MAX_MEMORY_BYTES_PER_CALL).contains(&request.max_memory_bytes_per_call) {
        return Err(format!(
            "max_memory_bytes_per_call must be between 1 and {MAX_MEMORY_BYTES_PER_CALL}"
        ));
    }
    Ok(())
}

fn normalized_registers(event: &FridaCaptureEvent) -> BTreeMap<String, String> {
    let mut registers = event
        .registers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    if !registers.contains_key("x29") {
        if let Some(value) = registers.get("fp").cloned() {
            registers.insert("x29".to_string(), value);
        }
    }
    if !registers.contains_key("x30") {
        if let Some(value) = registers.get("lr").cloned() {
            registers.insert("x30".to_string(), value);
        }
    }
    registers
}

fn full_gpr(registers: &BTreeMap<String, String>) -> bool {
    (0..=30).all(|index| registers.contains_key(&format!("x{index}")))
        && registers.contains_key("sp")
        && registers.contains_key("pc")
}

fn parsed_field(value: Option<&str>) -> Option<u64> {
    value.and_then(|value| parse_hex_addr(value).ok())
}

fn derived_offset(address: Option<u64>, base: Option<u64>) -> Option<String> {
    address
        .zip(base)
        .and_then(|(address, base)| address.checked_sub(base))
        .map(|offset| format!("0x{offset:x}"))
}

fn same_module_name(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

#[derive(Default)]
struct ResolvedCallLocation {
    target_module_name: Option<String>,
    target_module_base: Option<String>,
    target_module_size: Option<u64>,
    target_address: Option<String>,
    target_offset: Option<String>,
    caller_module_name: Option<String>,
    caller_module_base: Option<String>,
    caller_module_size: Option<u64>,
    call_site: Option<String>,
    call_site_offset: Option<String>,
    return_address: Option<String>,
    return_offset: Option<String>,
}

fn resolve_call_location(
    event: &FridaCaptureEvent,
    caller_module_name: &str,
    registers: &BTreeMap<String, String>,
) -> ResolvedCallLocation {
    let target_module_name = event.module_name.clone();
    let target_module_base = event.module_base.clone();
    let target_module_size = event.module_size;
    let target_address = event.target.clone();
    let target_offset = event.target_offset.clone().or_else(|| {
        derived_offset(
            parsed_field(target_address.as_deref()),
            parsed_field(target_module_base.as_deref()),
        )
    });

    let return_address = event
        .return_address
        .clone()
        .or_else(|| registers.get("x30").cloned())
        .or_else(|| registers.get("lr").cloned());
    let return_value = parsed_field(return_address.as_deref());
    let call_site = event.call_site.clone().or_else(|| {
        return_value
            .and_then(|value| value.checked_sub(4))
            .map(|value| format!("0x{value:x}"))
    });

    let mut caller_name = event.caller_module_name.clone();
    let mut caller_base = event.caller_module_base.clone();
    let mut caller_size = event.caller_module_size;
    if caller_name
        .as_deref()
        .is_some_and(|value| !same_module_name(value, caller_module_name))
    {
        caller_name = None;
        caller_base = None;
        caller_size = None;
    }
    if caller_name.is_none() {
        let event_name_matches = event
            .module_name
            .as_deref()
            .is_some_and(|value| same_module_name(value, caller_module_name));
        let event_base = parsed_field(event.module_base.as_deref());
        let event_size = event.module_size.unwrap_or_default();
        let return_in_event = return_value.zip(event_base).is_some_and(|(address, base)| {
            event_size > 0 && address >= base && address < base.saturating_add(event_size)
        });
        if event_name_matches && return_in_event {
            caller_name = event.module_name.clone();
            caller_base = event.module_base.clone();
            caller_size = event.module_size;
        }
    }
    let call_site_offset = event.call_site_offset.clone().or_else(|| {
        derived_offset(
            parsed_field(call_site.as_deref()),
            parsed_field(caller_base.as_deref()),
        )
    });
    let return_offset = event.return_offset.clone().or_else(|| {
        derived_offset(
            parsed_field(return_address.as_deref()),
            parsed_field(caller_base.as_deref()),
        )
    });

    ResolvedCallLocation {
        target_module_name,
        target_module_base,
        target_module_size,
        target_address,
        target_offset,
        caller_module_name: caller_name,
        caller_module_base: caller_base,
        caller_module_size: caller_size,
        call_site,
        call_site_offset,
        return_address,
        return_offset,
    }
}

fn strict_hex_bytes(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .ok()
                .and_then(|value| u8::from_str_radix(value, 16).ok())
        })
        .collect()
}

fn changed_ranges(before: &[u8], after: &[u8]) -> Vec<ExactCallChangedRange> {
    let mut ranges = Vec::new();
    let mut index = 0usize;
    while index < before.len().min(after.len()) {
        if before[index] == after[index] {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < before.len().min(after.len()) && before[index] != after[index] {
            index += 1;
        }
        ranges.push(ExactCallChangedRange {
            start_offset: start as u64,
            end_offset_exclusive: index as u64,
            before_hex: before[start..index]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            after_hex: after[start..index]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        });
    }
    ranges
}

#[derive(Default)]
struct CapturePair<'a> {
    enter: Vec<&'a FridaCapturedValue>,
    leave: Vec<&'a FridaCapturedValue>,
}

fn build_memory_effects(
    enter: &FridaCaptureEvent,
    leave: &FridaCaptureEvent,
    max_bytes: u64,
) -> (
    Vec<ExactCallMemoryEffect>,
    u64,
    bool,
    bool,
    bool,
    bool,
    Vec<String>,
) {
    let mut pairs = BTreeMap::<(u8, String, String), CapturePair<'_>>::new();
    for capture in &enter.captures {
        pairs
            .entry((
                capture.index,
                capture.label.to_ascii_lowercase(),
                capture.kind.to_ascii_lowercase(),
            ))
            .or_default()
            .enter
            .push(capture);
    }
    for capture in &leave.captures {
        pairs
            .entry((
                capture.index,
                capture.label.to_ascii_lowercase(),
                capture.kind.to_ascii_lowercase(),
            ))
            .or_default()
            .leave
            .push(capture);
    }

    let mut effects = Vec::new();
    let mut captured_bytes = 0u64;
    let mut pairs_complete = true;
    let mut no_errors = true;
    let mut no_truncation = true;
    let mut effects_truncated = false;
    let mut blockers = Vec::new();

    for ((index, _label_key, kind), pair) in pairs {
        for capture in pair.enter.iter().chain(&pair.leave) {
            if capture.read_error.is_some() {
                no_errors = false;
            }
            if capture
                .requested_length
                .zip(capture.byte_length)
                .is_some_and(|(requested, captured)| requested > captured)
            {
                no_truncation = false;
            }
        }
        if kind != "bytearray" {
            continue;
        }
        if pair.enter.len() != 1 || pair.leave.len() != 1 {
            pairs_complete = false;
            blockers.push(format!(
                "X{index} byteArray capture requires exactly one enter and one leave value"
            ));
            continue;
        }
        let before_capture = pair.enter[0];
        let after_capture = pair.leave[0];
        let Some(pointer) = before_capture.pointer.as_deref() else {
            pairs_complete = false;
            blockers.push(format!("X{index} enter byteArray has no pointer"));
            continue;
        };
        if after_capture.pointer.as_deref() != Some(pointer) {
            pairs_complete = false;
            blockers.push(format!("X{index} pointer changed between enter and leave"));
            continue;
        }
        let Some(before_hex) = before_capture.value.as_deref() else {
            pairs_complete = false;
            blockers.push(format!("X{index} enter byteArray has no exact bytes"));
            continue;
        };
        let Some(after_hex) = after_capture.value.as_deref() else {
            pairs_complete = false;
            blockers.push(format!("X{index} leave byteArray has no exact bytes"));
            continue;
        };
        let Some(before) = strict_hex_bytes(before_hex) else {
            pairs_complete = false;
            blockers.push(format!(
                "X{index} enter byteArray is not strict hexadecimal"
            ));
            continue;
        };
        let Some(after) = strict_hex_bytes(after_hex) else {
            pairs_complete = false;
            blockers.push(format!(
                "X{index} leave byteArray is not strict hexadecimal"
            ));
            continue;
        };
        if before.len() != after.len()
            || before_capture.byte_length != Some(before.len() as u64)
            || after_capture.byte_length != Some(after.len() as u64)
        {
            pairs_complete = false;
            blockers.push(format!(
                "X{index} byteArray length metadata does not match paired exact bytes"
            ));
            continue;
        }
        let pair_bytes = (before.len() as u64).saturating_add(after.len() as u64);
        if captured_bytes.saturating_add(pair_bytes) > max_bytes {
            effects_truncated = true;
            no_truncation = false;
            blockers.push(format!(
                "X{index} byteArray exceeded the per-call exact-memory bound"
            ));
            continue;
        }
        captured_bytes = captured_bytes.saturating_add(pair_bytes);
        if before == after {
            continue;
        }
        effects.push(ExactCallMemoryEffect {
            index,
            label: before_capture.label.clone(),
            direction: before_capture.direction.clone(),
            pointer: pointer.to_string(),
            byte_length: before.len() as u64,
            base_register: before_capture
                .base_register
                .clone()
                .or_else(|| after_capture.base_register.clone()),
            displacement: before_capture
                .displacement
                .clone()
                .or_else(|| after_capture.displacement.clone()),
            before_hex: before_hex.to_ascii_lowercase(),
            after_hex: after_hex.to_ascii_lowercase(),
            changed_ranges: changed_ranges(&before, &after),
        });
    }

    (
        effects,
        captured_bytes,
        pairs_complete,
        no_errors,
        no_truncation,
        effects_truncated,
        blockers,
    )
}

fn push_unique(values: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if !values.contains(&value) {
        values.push(value);
    }
}

fn build_record(
    call_id: &str,
    enter: &FridaCaptureEvent,
    leave: &FridaCaptureEvent,
    request: &ExactCallSummaryRequest,
) -> ExactCallRecord {
    let entry_registers = normalized_registers(enter);
    let exit_registers = normalized_registers(leave);
    let location = resolve_call_location(enter, &request.caller_module_name, &entry_registers);
    let leave_location = resolve_call_location(leave, &request.caller_module_name, &exit_registers);
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    let pair_complete = true;
    let same_thread = enter.thread_id == leave.thread_id;
    if !same_thread {
        blockers.push("enter and leave thread IDs differ".to_string());
    }
    let event_order_valid = enter.index < leave.index && enter.timestamp_ms <= leave.timestamp_ms;
    if !event_order_valid {
        blockers.push("enter/leave event order or timestamps are invalid".to_string());
    }
    let exact_record_mode = enter.exact_call_record && leave.exact_call_record;
    if !exact_record_mode {
        blockers.push(
            "capture was not generated in exact-call mode, so configured buffers were not guaranteed on both phases"
                .to_string(),
        );
    }

    let target_fields = [
        location.target_module_name.as_ref(),
        location.target_module_base.as_ref(),
        location.target_address.as_ref(),
        location.target_offset.as_ref(),
    ];
    let exact_target_known = target_fields.iter().all(|value| value.is_some())
        && location.target_module_size.unwrap_or_default() > 0;
    if !exact_target_known {
        blockers.push("exact target module/base/size/address/offset is incomplete".to_string());
    }
    let exact_call_site_known = location
        .caller_module_name
        .as_deref()
        .is_some_and(|value| same_module_name(value, &request.caller_module_name))
        && location.caller_module_base.is_some()
        && location.caller_module_size.unwrap_or_default() > 0
        && location.call_site.is_some()
        && location.call_site_offset.is_some();
    if !exact_call_site_known {
        blockers.push(
            "exact caller module/base/size and BL/BLR call-site offset are incomplete; recapture with the new exact-call hook metadata"
                .to_string(),
        );
    }
    let exact_return_site_known = location.return_address.is_some()
        && location.return_offset.is_some()
        && parsed_field(location.call_site_offset.as_deref())
            .and_then(|offset| offset.checked_add(4))
            == parsed_field(location.return_offset.as_deref());
    if !exact_return_site_known {
        blockers.push("return offset is missing or is not exactly call-site + 4".to_string());
    }
    for (label, left, right) in [
        (
            "caller module",
            location.caller_module_name.as_deref(),
            leave_location.caller_module_name.as_deref(),
        ),
        (
            "call-site offset",
            location.call_site_offset.as_deref(),
            leave_location.call_site_offset.as_deref(),
        ),
        (
            "return offset",
            location.return_offset.as_deref(),
            leave_location.return_offset.as_deref(),
        ),
        (
            "target offset",
            location.target_offset.as_deref(),
            leave_location.target_offset.as_deref(),
        ),
    ] {
        if right.is_some() && left != right {
            blockers.push(format!("enter/leave {label} metadata differs"));
        }
    }

    let full_gpr_enter = full_gpr(&entry_registers);
    let full_gpr_leave = full_gpr(&exit_registers);
    if !full_gpr_enter || !full_gpr_leave {
        blockers.push(
            "full X0-X30/SP/PC register state is required on both enter and leave".to_string(),
        );
    }
    let nzcv_enter = entry_registers.contains_key("nzcv");
    let nzcv_leave = exit_registers.contains_key("nzcv");
    if !nzcv_enter || !nzcv_leave {
        blockers.push("NZCV is required on both enter and leave".to_string());
    }
    let return_value_captured = leave.return_value.is_some();
    if !return_value_captured {
        blockers.push("hook-leave returnValue is missing".to_string());
    }
    let return_matches_x0 = leave
        .return_value
        .as_deref()
        .zip(exit_registers.get("x0").map(String::as_str))
        .and_then(|(retval, x0)| parse_hex_addr(retval).ok().zip(parse_hex_addr(x0).ok()))
        .is_some_and(|(retval, x0)| retval == x0);
    if return_value_captured && !return_matches_x0 {
        blockers.push("hook-leave returnValue does not match captured X0".to_string());
    }

    let (
        memory_effects,
        captured_memory_bytes,
        byte_array_pairs_complete,
        no_capture_errors,
        no_capture_truncation,
        memory_effects_truncated,
        memory_blockers,
    ) = build_memory_effects(enter, leave, request.max_memory_bytes_per_call);
    for blocker in memory_blockers {
        push_unique(&mut blockers, blocker);
    }
    if !no_capture_errors {
        push_unique(
            &mut blockers,
            "one or more configured captures reported readError".to_string(),
        );
    }
    if !no_capture_truncation {
        push_unique(
            &mut blockers,
            "one or more configured captures were truncated or exceeded the exact-memory bound"
                .to_string(),
        );
    }

    let mut register_effects = Vec::new();
    for register in entry_registers.keys().chain(exit_registers.keys()) {
        let before = entry_registers.get(register);
        let after = exit_registers.get(register);
        if before == after || register == "pc" || register == "fp" || register == "lr" {
            continue;
        }
        if let (Some(before), Some(after)) = (before, after) {
            register_effects.push(ExactCallRegisterEffect {
                register: register.to_ascii_uppercase(),
                before: before.clone(),
                after: after.clone(),
            });
        }
    }
    register_effects.sort_by(|left, right| left.register.cmp(&right.register));

    let callee_saved_preserved = (18..=29)
        .map(|index| format!("x{index}"))
        .chain(std::iter::once("sp".to_string()))
        .all(|register| entry_registers.get(&register) == exit_registers.get(&register));
    if !callee_saved_preserved {
        blockers.push(
            "X18-X29 or SP changed across the call; platform/callee-saved state cannot be replayed safely"
                .to_string(),
        );
    }

    if enter.error.is_some() || leave.error.is_some() {
        blockers.push("enter or leave event contains an error".to_string());
    }
    if memory_effects.is_empty() {
        warnings.push(
            "No changed configured byteArray region was observed; this does not prove the call had no hidden memory side effects."
                .to_string(),
        );
    }
    warnings.push(
        "SIMD/FP, TLS/errno, system registers, syscalls, signals, callbacks, threads, and unconfigured memory remain outside the capture itself."
            .to_string(),
    );

    let capture_ready = pair_complete
        && same_thread
        && event_order_valid
        && exact_record_mode
        && exact_target_known
        && exact_call_site_known
        && exact_return_site_known
        && full_gpr_enter
        && full_gpr_leave
        && nzcv_enter
        && nzcv_leave
        && return_value_captured
        && return_matches_x0
        && byte_array_pairs_complete
        && no_capture_errors
        && no_capture_truncation
        && callee_saved_preserved
        && enter.error.is_none()
        && leave.error.is_none();
    let status = if capture_ready {
        "capture-ready"
    } else {
        "incomplete"
    };
    ExactCallRecord {
        call_id: call_id.to_string(),
        hook_id: enter.hook_id.clone(),
        function_name: enter.function_name.clone(),
        enter_event_index: enter.index,
        leave_event_index: leave.index,
        thread_id: enter.thread_id,
        enter_timestamp_ms: enter.timestamp_ms,
        leave_timestamp_ms: leave.timestamp_ms,
        duration_ms: leave.timestamp_ms.saturating_sub(enter.timestamp_ms),
        target_module_name: location.target_module_name.unwrap_or_default(),
        target_module_base: location.target_module_base.unwrap_or_default(),
        target_module_size: location.target_module_size.unwrap_or_default(),
        target_address: location.target_address.unwrap_or_default(),
        target_offset: location.target_offset.unwrap_or_default(),
        caller_module_name: location.caller_module_name.unwrap_or_default(),
        caller_module_base: location.caller_module_base.unwrap_or_default(),
        caller_module_size: location.caller_module_size.unwrap_or_default(),
        call_site: location.call_site.unwrap_or_default(),
        call_site_offset: location.call_site_offset.unwrap_or_default(),
        return_address: location.return_address.unwrap_or_default(),
        return_offset: location.return_offset.unwrap_or_default(),
        entry_registers,
        exit_registers,
        register_effects,
        memory_effects,
        captured_memory_bytes,
        memory_effects_truncated,
        return_value: leave.return_value.clone().unwrap_or_default(),
        completeness: ExactCallCaptureCompleteness {
            pair_complete,
            same_thread,
            event_order_valid,
            exact_record_mode,
            exact_target_known,
            exact_call_site_known,
            exact_return_site_known,
            full_gpr_enter,
            full_gpr_leave,
            nzcv_enter,
            nzcv_leave,
            return_value_captured,
            return_matches_x0,
            byte_array_pairs_complete,
            no_capture_errors,
            no_capture_truncation,
            callee_saved_preserved,
            capture_ready,
            hidden_memory_effects_known: false,
            simd_fp_effects_known: false,
            tls_effects_known: false,
            system_thread_effects_known: false,
            replay_authorized: false,
        },
        status: status.to_string(),
        evidence_level: "related".to_string(),
        blockers,
        warnings,
    }
}

fn summarize_bundle(
    bundle: &FridaCaptureBundle,
    source_capture_path: &str,
    source_capture_sha256: &str,
    exact_binary_identity: &ElfBinaryIdentity,
    request: &ExactCallSummaryRequest,
) -> ExactCallSummaryBundle {
    let mut grouped = BTreeMap::<(String, String), CallPair<'_>>::new();
    let mut unpaired_enter_event_indices = Vec::new();
    let mut unpaired_leave_event_indices = Vec::new();
    let mut warnings = bundle.warnings.clone();
    for event in &bundle.events {
        if !matches!(event.event.as_str(), "hook-enter" | "hook-leave") {
            continue;
        }
        let Some(call_id) = event.call_id.as_deref() else {
            if event.event == "hook-enter" {
                unpaired_enter_event_indices.push(event.index);
            } else {
                unpaired_leave_event_indices.push(event.index);
            }
            continue;
        };
        let pair = grouped
            .entry((event.hook_id.clone(), call_id.to_string()))
            .or_default();
        if event.event == "hook-enter" {
            pair.enters.push(event);
        } else {
            pair.leaves.push(event);
        }
    }

    let mut calls = Vec::new();
    let mut calls_truncated = false;
    for ((_hook_id, call_id), pair) in grouped {
        if pair.enters.len() != 1 || pair.leaves.len() != 1 {
            unpaired_enter_event_indices.extend(pair.enters.iter().map(|event| event.index));
            unpaired_leave_event_indices.extend(pair.leaves.iter().map(|event| event.index));
            warnings.push(format!(
                "callId {call_id} was not summarized because it had {} enter and {} leave events.",
                pair.enters.len(),
                pair.leaves.len()
            ));
            continue;
        }
        if calls.len() >= request.max_calls as usize {
            calls_truncated = true;
            break;
        }
        calls.push(build_record(
            call_id.as_str(),
            pair.enters[0],
            pair.leaves[0],
            request,
        ));
    }
    calls.sort_by_key(|call| call.enter_event_index);
    unpaired_enter_event_indices.sort_unstable();
    unpaired_enter_event_indices.dedup();
    unpaired_leave_event_indices.sort_unstable();
    unpaired_leave_event_indices.dedup();
    if calls_truncated {
        warnings.push(format!(
            "Exact-call summaries were truncated at {} paired calls.",
            request.max_calls
        ));
    }
    let capture_ready_call_count = calls
        .iter()
        .filter(|call| call.completeness.capture_ready)
        .count() as u64;
    let paired_call_count = calls.len() as u64;
    ExactCallSummaryBundle {
        schema: EXACT_CALL_SUMMARY_SCHEMA.to_string(),
        request: request.clone(),
        source_capture_path: source_capture_path.to_string(),
        source_capture_sha256: source_capture_sha256.to_string(),
        exact_binary_identity: exact_binary_identity.clone(),
        calls,
        paired_call_count,
        capture_ready_call_count,
        incomplete_call_count: paired_call_count.saturating_sub(capture_ready_call_count),
        unpaired_enter_event_indices,
        unpaired_leave_event_indices,
        calls_truncated,
        verification_gate_met: false,
        warnings,
        limitations: vec![
            "A capture-ready call is still not replay-authorized. Hidden memory, SIMD/FP, TLS/errno, system-register/syscall, callback, signal, and thread effects remain unknown until explicitly bounded by a separate authorization artifact."
                .to_string(),
            "Exact binary SHA-256 binds the selected caller ELF file; it does not attest the runtime-loaded image or the callee binary."
                .to_string(),
            "Every result remains Candidate/Related and can replay only when exact call-site, target, return, register, and memory preconditions match."
                .to_string(),
        ],
    }
}

pub fn summarize_exact_calls(
    capture_path: &str,
    request: &ExactCallSummaryRequest,
) -> Result<ExactCallSummaryBundle, String> {
    validate_summary_request(request)?;
    if capture_path.trim().is_empty() || !Path::new(capture_path.trim()).is_absolute() {
        return Err("capture_path must be an absolute Frida capture path".to_string());
    }
    let bytes = std::fs::read(capture_path)
        .map_err(|error| format!("failed to read Frida capture: {error}"))?;
    if bytes.len() as u64 > MAX_EXACT_CALL_ARTIFACT_BYTES {
        return Err("Frida capture exceeds the 64 MiB exact-call import limit".to_string());
    }
    let bundle = parse_frida_capture_bundle(&bytes)?;
    let identity = inspect_elf_layout(&request.static_binary_path)?.identity;
    if identity.elf_machine != 183 {
        return Err(format!(
            "exact-call replay requires an AArch64 ELF, got {}",
            identity.architecture
        ));
    }
    Ok(summarize_bundle(
        &bundle,
        capture_path,
        &sha256_hex(&bytes),
        &identity,
        request,
    ))
}

pub fn save_exact_call_summary(
    output_path: &str,
    capture_path: &str,
    request: &ExactCallSummaryRequest,
) -> Result<ExactCallSummaryBundle, String> {
    let bundle = summarize_exact_calls(capture_path, request)?;
    let bytes = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| format!("serialize exact-call summary failed: {error}"))?;
    std::fs::write(output_path, bytes)
        .map_err(|error| format!("failed to save exact-call summary: {error}"))?;
    Ok(bundle)
}

pub fn parse_exact_call_summary_bundle(bytes: &[u8]) -> Result<ExactCallSummaryBundle, String> {
    if bytes.len() as u64 > MAX_EXACT_CALL_ARTIFACT_BYTES {
        return Err("exact-call summary exceeds 64 MiB".to_string());
    }
    let bundle: ExactCallSummaryBundle = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid exact-call summary JSON: {error}"))?;
    if bundle.schema != EXACT_CALL_SUMMARY_SCHEMA {
        return Err(format!(
            "unsupported exact-call summary schema: {}",
            bundle.schema
        ));
    }
    validate_summary_request(&bundle.request)?;
    if bundle.calls.len() > MAX_CALLS as usize
        || bundle.paired_call_count != bundle.calls.len() as u64
        || bundle.verification_gate_met
        || bundle.source_capture_sha256.len() != 64
        || bundle
            .source_capture_sha256
            .chars()
            .any(|character| !character.is_ascii_hexdigit())
    {
        return Err("exact-call summary contains invalid counts, gate, or source hash".to_string());
    }
    let mut call_ids = BTreeSet::new();
    for call in &bundle.calls {
        if call.call_id.trim().is_empty()
            || !call_ids.insert(call.call_id.as_str())
            || call.completeness.replay_authorized
            || call.evidence_level != "related"
        {
            return Err(
                "exact-call summary contains invalid or duplicate call records".to_string(),
            );
        }
        for offset in [
            &call.target_offset,
            &call.call_site_offset,
            &call.return_offset,
        ] {
            if !offset.is_empty() {
                parse_hex_addr(offset)
                    .map_err(|error| format!("invalid exact-call offset {offset}: {error}"))?;
            }
        }
    }
    Ok(bundle)
}

fn recompute_exact_call_summary_with_sources(
    serialized: &ExactCallSummaryBundle,
    capture_path: &str,
    static_binary_path: &str,
) -> Result<ExactCallSummaryBundle, String> {
    let mut request = serialized.request.clone();
    request.static_binary_path = static_binary_path.to_string();
    let mut recomputed = summarize_exact_calls(capture_path, &request)?;

    // Paths are provenance locators rather than content identity. Preserve the serialized
    // locators while recomputing every hash, call pair, register, and memory effect from the
    // explicitly bound case parents so a relocated case can still be checked strictly.
    recomputed.source_capture_path = serialized.source_capture_path.clone();
    recomputed.request.static_binary_path = serialized.request.static_binary_path.clone();
    recomputed.exact_binary_identity.binary_path =
        serialized.exact_binary_identity.binary_path.clone();
    if serialized != &recomputed {
        return Err(
            "exact-call summary does not match a fresh recomputation of its bound Frida capture and exact ELF"
                .to_string(),
        );
    }
    Ok(recomputed)
}

pub(crate) fn inspect_exact_call_summary_with_sources(
    summary_path: &str,
    capture_path: &str,
    static_binary_path: &str,
) -> Result<ExactCallSummaryBundle, String> {
    let bytes = std::fs::read(summary_path)
        .map_err(|error| format!("failed to read exact-call summary: {error}"))?;
    let serialized = parse_exact_call_summary_bundle(&bytes)?;
    recompute_exact_call_summary_with_sources(&serialized, capture_path, static_binary_path)
}

pub fn inspect_exact_call_summary(path: &str) -> Result<ExactCallSummaryBundle, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("failed to read exact-call summary: {error}"))?;
    let serialized = parse_exact_call_summary_bundle(&bytes)?;
    recompute_exact_call_summary_with_sources(
        &serialized,
        &serialized.source_capture_path,
        &serialized.request.static_binary_path,
    )
}

fn executable_offset(layout: &ElfBinaryLayout, offset: u64) -> bool {
    layout.load_segments.iter().any(|segment| {
        if !segment.executable {
            return false;
        }
        let start = segment
            .virtual_address
            .saturating_sub(layout.load_base_vaddr);
        let end = start.saturating_add(segment.memory_size);
        offset >= start && offset < end
    })
}

fn authorization_id(binary_sha256: &str, call: &ExactCallRecord) -> String {
    let source = format!(
        "{binary_sha256}|{}|{}|{}|{}|{}",
        call.call_id,
        call.caller_module_name.to_ascii_lowercase(),
        call.call_site_offset.to_ascii_lowercase(),
        call.target_module_name.to_ascii_lowercase(),
        call.target_offset.to_ascii_lowercase()
    );
    format!("exact-call:{}", &sha256_hex(source.as_bytes())[..24])
}

fn register_values(
    registers: &BTreeMap<String, String>,
    names: impl IntoIterator<Item = String>,
) -> Vec<ExactCallRegisterValue> {
    names
        .into_iter()
        .filter_map(|name| {
            registers.get(&name).map(|value| ExactCallRegisterValue {
                register: name.to_ascii_uppercase(),
                value: value.clone(),
            })
        })
        .collect()
}

fn build_authorization_bundle(
    summary_path: &str,
    summary_sha256: &str,
    summary: &ExactCallSummaryBundle,
    layout: &ElfBinaryLayout,
    request: &ExactCallReplayAuthorizationRequest,
) -> Result<ExactCallReplayAuthorizationBundle, String> {
    if request.call_ids.is_empty() || request.call_ids.len() > MAX_AUTHORIZED_CALLS {
        return Err(format!(
            "call_ids must explicitly select between 1 and {MAX_AUTHORIZED_CALLS} calls"
        ));
    }
    let mut selected = BTreeSet::new();
    for call_id in &request.call_ids {
        if call_id.trim().is_empty() || !selected.insert(call_id.to_string()) {
            return Err("call_ids must be non-empty and unique".to_string());
        }
    }
    if !summary
        .exact_binary_identity
        .binary_sha256
        .eq_ignore_ascii_case(&layout.identity.binary_sha256)
    {
        return Err("exact-call summary ELF SHA-256 does not match authorization ELF".to_string());
    }

    let missing_assumptions = request.assumptions.missing();
    let mut authorizations = Vec::new();
    for call_id in &request.call_ids {
        let Some(call) = summary.calls.iter().find(|call| &call.call_id == call_id) else {
            return Err(format!("exact-call summary has no callId {call_id}"));
        };
        let mut blockers = call.blockers.clone();
        if !call.completeness.capture_ready {
            push_unique(
                &mut blockers,
                "paired capture did not pass the intrinsic capture-ready checks".to_string(),
            );
        }
        if !same_module_name(
            &call.caller_module_name,
            &summary.request.caller_module_name,
        ) {
            push_unique(
                &mut blockers,
                "call-site module does not match the summary caller module".to_string(),
            );
        }
        let call_site = parse_hex_addr(&call.call_site_offset).ok();
        let return_offset = parse_hex_addr(&call.return_offset).ok();
        if call_site.is_none_or(|offset| !executable_offset(layout, offset)) {
            push_unique(
                &mut blockers,
                "call-site offset is outside an executable PT_LOAD range of the exact ELF"
                    .to_string(),
            );
        }
        if return_offset.is_none_or(|offset| !executable_offset(layout, offset)) {
            push_unique(
                &mut blockers,
                "return offset is outside an executable PT_LOAD range of the exact ELF".to_string(),
            );
        }
        if call_site.and_then(|offset| offset.checked_add(4)) != return_offset {
            push_unique(
                &mut blockers,
                "authorization return offset is not exactly call-site + 4".to_string(),
            );
        }
        for assumption in &missing_assumptions {
            push_unique(
                &mut blockers,
                format!("manual side-effect assumption not accepted: {assumption}"),
            );
        }
        let authorized = blockers.is_empty();
        let precondition_names = (0..=7)
            .map(|index| format!("x{index}"))
            .chain(std::iter::once("sp".to_string()));
        let write_names = (0..=17)
            .map(|index| format!("x{index}"))
            .chain(["x30".to_string(), "nzcv".to_string()]);
        authorizations.push(ExactCallReplayAuthorization {
            authorization_id: authorization_id(&layout.identity.binary_sha256, call),
            call_id: call.call_id.clone(),
            status: if authorized {
                "authorized-candidate"
            } else {
                "blocked"
            }
            .to_string(),
            authorized,
            evidence_level: "related".to_string(),
            caller_module_name: call.caller_module_name.clone(),
            caller_module_base: call.caller_module_base.clone(),
            caller_module_size: call.caller_module_size,
            call_site_offset: call.call_site_offset.clone(),
            return_offset: call.return_offset.clone(),
            target_module_name: call.target_module_name.clone(),
            target_module_base: call.target_module_base.clone(),
            target_module_size: call.target_module_size,
            target_address: call.target_address.clone(),
            target_offset: call.target_offset.clone(),
            precondition_registers: register_values(&call.entry_registers, precondition_names),
            register_writes: register_values(&call.exit_registers, write_names),
            memory_effects: call.memory_effects.clone(),
            return_value: call.return_value.clone(),
            assumptions: request.assumptions.clone(),
            blockers,
            limitations: vec![
                "Authorization is a bounded manual side-effect contract for one exact observed call. It is never semantic Verified evidence."
                    .to_string(),
                "Replay must still stop when call-site/target/return/register/memory preconditions differ or any effect cannot be applied exactly."
                    .to_string(),
            ],
            verification_gate_met: false,
        });
    }
    let authorized_count = authorizations
        .iter()
        .filter(|authorization| authorization.authorized)
        .count() as u64;
    let blocked_count = authorizations.len() as u64 - authorized_count;
    let mut warnings = Vec::new();
    if authorized_count == 0 {
        warnings.push(
            "No selected call passed authorization; Unicorn must continue stopping at those call boundaries."
                .to_string(),
        );
    }
    if authorized_count > 0 {
        warnings.push(
            "Authorized calls rely on explicit manual assumptions about hidden side effects. Exact precondition matching limits reuse but does not turn replay into proof."
                .to_string(),
        );
    }
    Ok(ExactCallReplayAuthorizationBundle {
        schema: EXACT_CALL_REPLAY_AUTHORIZATION_SCHEMA.to_string(),
        summary_path: summary_path.to_string(),
        summary_sha256: summary_sha256.to_string(),
        source_capture_sha256: summary.source_capture_sha256.clone(),
        exact_binary_identity: layout.identity.clone(),
        request: request.clone(),
        authorizations,
        authorized_count,
        blocked_count,
        verification_gate_met: false,
        warnings,
        limitations: vec![
            "The authorization binds a caller ELF file SHA-256, not a runtime image attestation or the callee build."
                .to_string(),
            "Unknown calls and any precondition mismatch remain explicit stop conditions; Trace UI never fills missing state with zero."
                .to_string(),
            "All exact-call replay evidence remains Candidate/Related."
                .to_string(),
        ],
    })
}

pub fn authorize_exact_call_replay(
    summary_path: &str,
    static_binary_path: &str,
    request: &ExactCallReplayAuthorizationRequest,
) -> Result<ExactCallReplayAuthorizationBundle, String> {
    if summary_path.trim().is_empty() || !Path::new(summary_path.trim()).is_absolute() {
        return Err("summary_path must be an absolute exact-call summary path".to_string());
    }
    if static_binary_path.trim().is_empty() || !Path::new(static_binary_path.trim()).is_absolute() {
        return Err("static_binary_path must be an absolute exact ELF path".to_string());
    }
    let summary_bytes = std::fs::read(summary_path)
        .map_err(|error| format!("failed to read exact-call summary: {error}"))?;
    let summary_sha256 = sha256_hex(&summary_bytes);
    let summary = inspect_exact_call_summary(summary_path)?;
    let layout = inspect_elf_layout(static_binary_path)?;
    if layout.identity.elf_machine != 183 {
        return Err(format!(
            "exact-call replay requires an AArch64 ELF, got {}",
            layout.identity.architecture
        ));
    }
    build_authorization_bundle(summary_path, &summary_sha256, &summary, &layout, request)
}

pub fn save_exact_call_replay_authorization(
    output_path: &str,
    summary_path: &str,
    static_binary_path: &str,
    request: &ExactCallReplayAuthorizationRequest,
) -> Result<ExactCallReplayAuthorizationBundle, String> {
    let bundle = authorize_exact_call_replay(summary_path, static_binary_path, request)?;
    let bytes = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| format!("serialize exact-call authorization failed: {error}"))?;
    std::fs::write(output_path, bytes)
        .map_err(|error| format!("failed to save exact-call authorization: {error}"))?;
    Ok(bundle)
}

pub fn parse_exact_call_replay_authorization_bundle(
    bytes: &[u8],
) -> Result<ExactCallReplayAuthorizationBundle, String> {
    if bytes.len() as u64 > MAX_EXACT_CALL_ARTIFACT_BYTES {
        return Err("exact-call authorization exceeds 64 MiB".to_string());
    }
    let bundle: ExactCallReplayAuthorizationBundle = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid exact-call authorization JSON: {error}"))?;
    if bundle.schema != EXACT_CALL_REPLAY_AUTHORIZATION_SCHEMA {
        return Err(format!(
            "unsupported exact-call authorization schema: {}",
            bundle.schema
        ));
    }
    if bundle.authorizations.is_empty()
        || bundle.authorizations.len() > MAX_AUTHORIZED_CALLS
        || bundle.verification_gate_met
        || bundle.authorized_count
            != bundle
                .authorizations
                .iter()
                .filter(|authorization| authorization.authorized)
                .count() as u64
        || bundle.blocked_count + bundle.authorized_count != bundle.authorizations.len() as u64
    {
        return Err("exact-call authorization contains invalid counts or gate state".to_string());
    }
    let mut ids = BTreeSet::new();
    for authorization in &bundle.authorizations {
        if authorization.authorization_id.trim().is_empty()
            || !ids.insert(authorization.authorization_id.as_str())
            || authorization.evidence_level != "related"
            || authorization.verification_gate_met
            || authorization.authorized != (authorization.status == "authorized-candidate")
        {
            return Err(
                "exact-call authorization contains invalid or duplicate records".to_string(),
            );
        }
        parse_hex_addr(&authorization.call_site_offset)
            .map_err(|error| format!("invalid call-site offset: {error}"))?;
        parse_hex_addr(&authorization.return_offset)
            .map_err(|error| format!("invalid return offset: {error}"))?;
        parse_hex_addr(&authorization.target_offset)
            .map_err(|error| format!("invalid target offset: {error}"))?;
    }
    Ok(bundle)
}

fn recompute_exact_call_replay_authorization_with_sources(
    serialized: &ExactCallReplayAuthorizationBundle,
    summary_path: &str,
    capture_path: &str,
    static_binary_path: &str,
) -> Result<ExactCallReplayAuthorizationBundle, String> {
    let summary_bytes = std::fs::read(summary_path)
        .map_err(|error| format!("failed to read bound exact-call summary: {error}"))?;
    if !sha256_hex(&summary_bytes).eq_ignore_ascii_case(&serialized.summary_sha256) {
        return Err("bound exact-call summary SHA-256 changed".to_string());
    }
    let summary =
        inspect_exact_call_summary_with_sources(summary_path, capture_path, static_binary_path)?;
    let mut layout = inspect_elf_layout(static_binary_path)?;
    if !layout
        .identity
        .binary_sha256
        .eq_ignore_ascii_case(&serialized.exact_binary_identity.binary_sha256)
    {
        return Err("exact-call authorization ELF SHA-256 does not match".to_string());
    }
    layout.identity.binary_path = serialized.exact_binary_identity.binary_path.clone();
    let recomputed = build_authorization_bundle(
        &serialized.summary_path,
        &serialized.summary_sha256,
        &summary,
        &layout,
        &serialized.request,
    )?;
    if serialized != &recomputed {
        return Err(
            "exact-call authorization does not match a fresh recomputation of its summary, assumptions, and exact ELF"
                .to_string(),
        );
    }
    Ok(recomputed)
}

pub(crate) fn inspect_exact_call_replay_authorization_with_sources(
    authorization_path: &str,
    summary_path: &str,
    capture_path: &str,
    static_binary_path: &str,
) -> Result<ExactCallReplayAuthorizationBundle, String> {
    let bytes = std::fs::read(authorization_path)
        .map_err(|error| format!("failed to read exact-call authorization: {error}"))?;
    let serialized = parse_exact_call_replay_authorization_bundle(&bytes)?;
    recompute_exact_call_replay_authorization_with_sources(
        &serialized,
        summary_path,
        capture_path,
        static_binary_path,
    )
}

pub fn inspect_exact_call_replay_authorization(
    authorization_path: &str,
    static_binary_path: &str,
) -> Result<ExactCallReplayAuthorizationBundle, String> {
    let bytes = std::fs::read(authorization_path)
        .map_err(|error| format!("failed to read exact-call authorization: {error}"))?;
    let serialized = parse_exact_call_replay_authorization_bundle(&bytes)?;
    let summary_bytes = std::fs::read(&serialized.summary_path)
        .map_err(|error| format!("failed to read bound exact-call summary: {error}"))?;
    let summary = parse_exact_call_summary_bundle(&summary_bytes)?;
    recompute_exact_call_replay_authorization_with_sources(
        &serialized,
        &serialized.summary_path,
        &summary.source_capture_path,
        static_binary_path,
    )
}

pub fn load_authorized_exact_calls(
    authorization_paths: &[String],
    static_binary_path: &str,
    caller_module_name: &str,
) -> Result<Vec<ExactCallReplayAuthorization>, String> {
    if authorization_paths.len() > 16 {
        return Err("at most 16 exact-call authorization artifacts may be embedded".to_string());
    }
    let mut results = Vec::new();
    let mut ids = BTreeSet::new();
    for path in authorization_paths {
        let bundle = inspect_exact_call_replay_authorization(path, static_binary_path)?;
        for authorization in bundle.authorizations {
            if !authorization.authorized {
                continue;
            }
            if !same_module_name(&authorization.caller_module_name, caller_module_name) {
                return Err(format!(
                    "exact-call authorization {} caller module {} does not match replay module {}",
                    authorization.authorization_id,
                    authorization.caller_module_name,
                    caller_module_name
                ));
            }
            if !ids.insert(authorization.authorization_id.clone()) {
                continue;
            }
            results.push(authorization);
            if results.len() > MAX_AUTHORIZED_CALLS {
                return Err(format!(
                    "at most {MAX_AUTHORIZED_CALLS} authorized exact calls may be embedded"
                ));
            }
        }
    }
    results.sort_by(|left, right| {
        parse_hex_addr(&left.call_site_offset)
            .unwrap_or_default()
            .cmp(&parse_hex_addr(&right.call_site_offset).unwrap_or_default())
            .then_with(|| left.authorization_id.cmp(&right.authorization_id))
    });
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registers(pc: u64, lr: u64, x0: u64) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for index in 0..=28 {
            map.insert(
                format!("x{index}"),
                serde_json::Value::String(format!("0x{:x}", if index == 0 { x0 } else { index })),
            );
        }
        map.insert("fp".to_string(), serde_json::json!("0x1d"));
        map.insert("lr".to_string(), serde_json::json!(format!("0x{lr:x}")));
        map.insert("sp".to_string(), serde_json::json!("0x90000000"));
        map.insert("pc".to_string(), serde_json::json!(format!("0x{pc:x}")));
        map.insert("nzcv".to_string(), serde_json::json!("0x60000000"));
        serde_json::Value::Object(map)
    }

    fn capture_bytes() -> Vec<u8> {
        let enter = serde_json::json!({
            "protocol": "trace-ui/frida-hook-v1",
            "eventId": "call:event:1",
            "hookId": "callee",
            "event": "hook-enter",
            "functionName": "callee",
            "timestampMs": 10,
            "threadId": 7,
            "callId": "callee:7:1",
            "moduleName": "libtarget.so",
            "moduleBase": "0x70000000",
            "moduleSize": 0x1000,
            "target": "0x70000180",
            "targetOffset": "0x180",
            "callerModuleName": "libtarget.so",
            "callerModuleBase": "0x70000000",
            "callerModuleSize": 0x1000,
            "callSite": "0x70000100",
            "callSiteOffset": "0x100",
            "returnAddress": "0x70000104",
            "returnOffset": "0x104",
            "exactCallRecord": true,
            "registers": registers(0x70000180, 0x70000104, 0x90000100),
            "captures": [{
                "index": 0,
                "label": "buffer",
                "kind": "byteArray",
                "direction": "inOut",
                "phase": "enter",
                "pointer": "0x90000100",
                "value": "00112233",
                "byteLength": 4,
                "requestedLength": 4
            }]
        });
        let leave = serde_json::json!({
            "protocol": "trace-ui/frida-hook-v1",
            "eventId": "call:event:2",
            "hookId": "callee",
            "event": "hook-leave",
            "functionName": "callee",
            "timestampMs": 12,
            "threadId": 7,
            "callId": "callee:7:1",
            "moduleName": "libtarget.so",
            "moduleBase": "0x70000000",
            "moduleSize": 0x1000,
            "target": "0x70000180",
            "targetOffset": "0x180",
            "callerModuleName": "libtarget.so",
            "callerModuleBase": "0x70000000",
            "callerModuleSize": 0x1000,
            "callSite": "0x70000100",
            "callSiteOffset": "0x100",
            "returnAddress": "0x70000104",
            "returnOffset": "0x104",
            "exactCallRecord": true,
            "registers": registers(0x70000104, 0x70000104, 1),
            "returnValue": "0x1",
            "captures": [{
                "index": 0,
                "label": "buffer",
                "kind": "byteArray",
                "direction": "inOut",
                "phase": "leave",
                "pointer": "0x90000100",
                "value": "0011aabb",
                "byteLength": 4,
                "requestedLength": 4
            }]
        });
        serde_json::to_vec(&vec![enter, leave]).unwrap()
    }

    fn minimal_aarch64_elf() -> Vec<u8> {
        let mut elf = vec![0u8; 0x300];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64usize;
        elf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
        elf[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&0u64.to_le_bytes());
        let elf_len = elf.len() as u64;
        elf[ph + 32..ph + 40].copy_from_slice(&elf_len.to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&elf_len.to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        elf
    }

    fn temp_paths(label: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-exact-call-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        (dir.join("capture.json"), dir.join("libtarget.so"), dir)
    }

    #[test]
    fn summarizes_paired_exact_call_without_promoting_hidden_effects() {
        let (capture_path, elf_path, dir) = temp_paths("summary");
        std::fs::write(&capture_path, capture_bytes()).unwrap();
        std::fs::write(&elf_path, minimal_aarch64_elf()).unwrap();
        let request = ExactCallSummaryRequest {
            caller_module_name: "libtarget.so".to_string(),
            static_binary_path: elf_path.to_string_lossy().into_owned(),
            max_calls: 16,
            max_memory_bytes_per_call: 1024,
        };
        let summary = summarize_exact_calls(capture_path.to_str().unwrap(), &request).unwrap();
        assert_eq!(summary.capture_ready_call_count, 1);
        assert!(!summary.verification_gate_met);
        let call = &summary.calls[0];
        assert_eq!(call.call_site_offset, "0x100");
        assert_eq!(call.return_offset, "0x104");
        assert_eq!(call.memory_effects[0].changed_ranges[0].start_offset, 2);
        assert!(call.completeness.capture_ready);
        assert!(!call.completeness.hidden_memory_effects_known);
        assert!(!call.completeness.replay_authorized);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn authorization_is_blocked_until_every_hidden_effect_assumption_is_explicit() {
        let (capture_path, elf_path, dir) = temp_paths("authorization");
        let summary_path = dir.join("summary.json");
        std::fs::write(&capture_path, capture_bytes()).unwrap();
        std::fs::write(&elf_path, minimal_aarch64_elf()).unwrap();
        let summary_request = ExactCallSummaryRequest {
            caller_module_name: "libtarget.so".to_string(),
            static_binary_path: elf_path.to_string_lossy().into_owned(),
            max_calls: 16,
            max_memory_bytes_per_call: 1024,
        };
        save_exact_call_summary(
            summary_path.to_str().unwrap(),
            capture_path.to_str().unwrap(),
            &summary_request,
        )
        .unwrap();
        let blocked = authorize_exact_call_replay(
            summary_path.to_str().unwrap(),
            elf_path.to_str().unwrap(),
            &ExactCallReplayAuthorizationRequest {
                call_ids: vec!["callee:7:1".to_string()],
                assumptions: ExactCallReplayAssumptions::default(),
            },
        )
        .unwrap();
        assert_eq!(blocked.authorized_count, 0);
        assert!(blocked.authorizations[0]
            .blockers
            .iter()
            .any(|value| value.contains("no-simd-fp-side-effects")));

        let authorized = authorize_exact_call_replay(
            summary_path.to_str().unwrap(),
            elf_path.to_str().unwrap(),
            &ExactCallReplayAuthorizationRequest {
                call_ids: vec!["callee:7:1".to_string()],
                assumptions: ExactCallReplayAssumptions {
                    captured_memory_effects_complete: true,
                    no_simd_fp_side_effects: true,
                    no_tls_side_effects: true,
                    no_system_register_or_syscall_effects: true,
                    no_thread_signal_or_callback_effects: true,
                    deterministic_for_exact_preconditions: true,
                },
            },
        )
        .unwrap();
        assert_eq!(authorized.authorized_count, 1);
        assert!(authorized.authorizations[0].authorized);
        assert!(!authorized.authorizations[0].verification_gate_met);
        let _ = std::fs::remove_dir_all(dir);
    }
}
