use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::query::elf_identity::ElfBinaryIdentity;
use crate::query::unicorn::{UnicornOllvmResultBundle, UnicornReplayRun};
use crate::utils::{format_signed_offset_hex, parse_hex_addr, parse_signed_offset};

const FRIDA_UNICORN_CHECKPOINT_HOOK_SCHEMA: &str = "trace-ui/frida-unicorn-checkpoint-hook-v1";
const FRIDA_HOOK_PROTOCOL: &str = "trace-ui/frida-hook-v1";

fn default_max_events() -> u32 {
    5_000
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaUnicornCheckpointHookOptions {
    #[serde(default = "default_max_events")]
    pub max_events: u32,
}

impl Default for FridaUnicornCheckpointHookOptions {
    fn default() -> Self {
        Self {
            max_events: default_max_events(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaUnicornCheckpointMemorySpec {
    pub index: u8,
    pub label: String,
    pub base_register: String,
    pub displacement: i64,
    pub displacement_hex: String,
    pub byte_length: u32,
    pub source_event_indices: Vec<u64>,
    pub source_seed_offsets: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaUnicornCheckpointHookTarget {
    pub hook_id: String,
    pub offset: String,
    pub source_event_indices: Vec<u64>,
    pub source_seed_offsets: Vec<String>,
    pub stop_reasons: Vec<String>,
    pub captures: Vec<FridaUnicornCheckpointMemorySpec>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaUnicornCheckpointHookScript {
    pub schema_version: String,
    pub module_name: String,
    pub file_name: String,
    pub expected_binary_sha256: String,
    pub selected_seed_offsets: Vec<String>,
    pub targets: Vec<FridaUnicornCheckpointHookTarget>,
    pub capture_window_count: u32,
    pub max_events: u32,
    pub script: String,
    pub warnings: Vec<String>,
    pub protocol_version: String,
    pub frida_api_version: String,
}

#[derive(Default)]
struct CaptureAccumulator {
    source_event_indices: BTreeSet<u64>,
    source_seed_offsets: BTreeSet<String>,
}

#[derive(Default)]
struct TargetAccumulator {
    source_event_indices: BTreeSet<u64>,
    source_seed_offsets: BTreeSet<String>,
    stop_reasons: BTreeSet<String>,
    captures: BTreeMap<(String, i64, u32), CaptureAccumulator>,
}

fn normalized_offset(value: &str) -> Result<String, String> {
    parse_hex_addr(value).map(|offset| format!("0x{offset:x}"))
}

fn checkpoint_stop_supported(stop_reason: &str) -> bool {
    matches!(
        stop_reason,
        "missing-memory"
            | "missing-register"
            | "call-boundary"
            | "loop-detected"
            | "instruction-limit"
            | "timeout"
    )
}

fn checkpoint_offsets_for_run(run: &UnicornReplayRun) -> Result<BTreeSet<String>, String> {
    let mut offsets = BTreeSet::new();
    if !checkpoint_stop_supported(&run.stop_reason) {
        return Ok(offsets);
    }
    if run.stop_reason == "call-boundary" {
        let Some(boundary) = run.call_boundaries.last() else {
            return Ok(offsets);
        };
        let call_offset = normalized_offset(&boundary.pc_offset)?;
        let terminal_offset = run
            .terminal_offset
            .as_deref()
            .ok_or_else(|| "Unicorn call-boundary requires a terminal offset".to_string())?;
        if normalized_offset(terminal_offset)? != call_offset {
            return Err(
                "Unicorn call-boundary terminal offset does not match the recorded call PC"
                    .to_string(),
            );
        }
        let (return_offset, return_address) = match (
            boundary.return_offset.as_deref(),
            boundary.return_address.as_deref(),
        ) {
            (None, None) => return Ok(offsets),
            (Some(offset), Some(address)) => (offset, address),
            _ => {
                return Err(
                    "Unicorn call-boundary return offset and address must be present together"
                        .to_string(),
                )
            }
        };
        let return_offset = normalized_offset(return_offset)?;
        let call_value = parse_hex_addr(&call_offset)
            .map_err(|error| format!("invalid call-boundary PC: {error}"))?;
        let expected_return = call_value
            .checked_add(4)
            .ok_or_else(|| "Unicorn call-boundary return offset overflow".to_string())?;
        if parse_hex_addr(&return_offset)
            .map_err(|error| format!("invalid call-boundary return offset: {error}"))?
            != expected_return
        {
            return Err("Unicorn call-boundary return offset must equal call PC + 4".to_string());
        }
        let mapped_base = parse_hex_addr(&run.mapped_base)
            .map_err(|error| format!("invalid Unicorn mapped base: {error}"))?;
        let expected_address = mapped_base
            .checked_add(expected_return)
            .ok_or_else(|| "Unicorn call-boundary return address overflow".to_string())?;
        if parse_hex_addr(return_address)
            .map_err(|error| format!("invalid call-boundary return address: {error}"))?
            != expected_address
        {
            return Err(
                "Unicorn call-boundary return address does not match mapped base + return offset"
                    .to_string(),
            );
        }
        offsets.insert(return_offset);
    } else if run.stop_reason == "missing-memory" {
        for missing in &run.missing_memory {
            if let Some(offset) = &missing.pc_offset {
                offsets.insert(normalized_offset(offset)?);
            }
        }
    }
    if offsets.is_empty() {
        if let Some(offset) = &run.terminal_offset {
            offsets.insert(normalized_offset(offset)?);
        }
    }
    offsets.remove(&normalized_offset(&run.start_offset)?);
    Ok(offsets)
}

pub fn unicorn_checkpoint_offsets(
    bundle: &UnicornOllvmResultBundle,
) -> Result<BTreeSet<String>, String> {
    let mut offsets = BTreeSet::new();
    for run in &bundle.runs {
        offsets.extend(checkpoint_offsets_for_run(run)?);
    }
    Ok(offsets)
}

fn parse_displacement(value: Option<&str>) -> Result<i64, String> {
    let parsed = parse_signed_offset(value.unwrap_or("0"))
        .map_err(|error| format!("invalid checkpoint displacement: {error}"))?;
    if !(-1_048_576..=1_048_576).contains(&parsed) {
        return Err("Frida Unicorn checkpoint displacement must be within +/- 1 MiB".to_string());
    }
    Ok(parsed)
}

fn validate_window_bounds(displacement: i64, byte_length: u32) -> Result<(), String> {
    let Some(last_displacement) =
        displacement.checked_add(i64::from(byte_length.saturating_sub(1)))
    else {
        return Err("Frida Unicorn checkpoint window displacement overflow".to_string());
    };
    if !(-1_048_576..=1_048_576).contains(&last_displacement) {
        return Err(
            "Frida Unicorn checkpoint window must remain within +/- 1 MiB of its base register"
                .to_string(),
        );
    }
    Ok(())
}

fn capture_register(value: &str) -> Result<(String, u8), String> {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized == "SP" {
        return Ok((normalized, 29));
    }
    let Some(index) = normalized
        .strip_prefix('X')
        .and_then(|index| index.parse::<u8>().ok())
    else {
        return Err(format!(
            "Frida Unicorn checkpoint requires X0-X28 or SP, got {value}"
        ));
    };
    if index > 28 {
        return Err(format!(
            "Frida Unicorn checkpoint requires X0-X28 or SP, got {value}"
        ));
    }
    Ok((normalized, index))
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

fn checkpoint_label(base_register: &str, displacement: i64, byte_length: u32) -> String {
    let displacement = if displacement < 0 {
        format!("minus-{:x}", displacement.unsigned_abs())
    } else if displacement > 0 {
        format!("plus-{displacement:x}")
    } else {
        "base".to_string()
    };
    format!(
        "unicorn-checkpoint-{}-{displacement}-{byte_length}b",
        base_register.to_ascii_lowercase()
    )
}

fn validate_bundle_identity(bundle: &UnicornOllvmResultBundle) -> Result<&str, String> {
    let module_name = bundle.module_name.trim();
    if module_name.is_empty() || module_name.chars().any(|character| character.is_control()) {
        return Err("Unicorn result module name must be a non-empty printable name".to_string());
    }
    if !bundle.binary_identity_matched
        || !bundle
            .binary_sha256
            .eq_ignore_ascii_case(&bundle.expected_binary_sha256)
    {
        return Err(
            "Unicorn result exact ELF identity must match before generating a checkpoint hook"
                .to_string(),
        );
    }
    Ok(module_name)
}

pub fn authorize_unicorn_checkpoint_offsets(
    bundle: &UnicornOllvmResultBundle,
    module_name: &str,
    expected_binary_identity: &ElfBinaryIdentity,
) -> Result<BTreeSet<String>, String> {
    let result_module = validate_bundle_identity(bundle)?;
    let expected_module = module_name.trim();
    if expected_module.is_empty() || result_module != expected_module {
        return Err(format!(
            "Unicorn checkpoint result module {result_module} does not match OLLVM report module {expected_module}"
        ));
    }
    if !bundle
        .binary_sha256
        .eq_ignore_ascii_case(&expected_binary_identity.binary_sha256)
    {
        return Err(
            "Unicorn checkpoint result does not match the selected exact ELF SHA-256".to_string(),
        );
    }
    unicorn_checkpoint_offsets(bundle)
}

pub fn generate_frida_unicorn_checkpoint_hook(
    bundle: &UnicornOllvmResultBundle,
    seed_capture_offsets: &[String],
    options: &FridaUnicornCheckpointHookOptions,
) -> Result<FridaUnicornCheckpointHookScript, String> {
    if !(1..=50_000).contains(&options.max_events) {
        return Err("Frida Unicorn checkpoint event limit must be between 1 and 50000".to_string());
    }
    let module_name = validate_bundle_identity(bundle)?;
    if seed_capture_offsets.is_empty() || seed_capture_offsets.len() > 32 {
        return Err(
            "Frida Unicorn checkpoint requires between 1 and 32 seed capture offsets".to_string(),
        );
    }

    let mut selected_seed_offsets = seed_capture_offsets
        .iter()
        .map(|offset| normalized_offset(offset))
        .collect::<Result<Vec<_>, _>>()?;
    selected_seed_offsets.sort_by_key(|offset| parse_hex_addr(offset).unwrap_or(u64::MAX));
    selected_seed_offsets.dedup();
    let selected_seed_set = selected_seed_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let known_seed_offsets = bundle
        .seeds
        .iter()
        .map(|seed| normalized_offset(&seed.capture_offset))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for selected in &selected_seed_set {
        if !known_seed_offsets.contains(selected) {
            return Err(format!(
                "selected Unicorn checkpoint seed offset {selected} is absent from the result"
            ));
        }
    }

    let selected_events = bundle
        .seeds
        .iter()
        .filter_map(|seed| {
            normalized_offset(&seed.capture_offset)
                .ok()
                .filter(|offset| selected_seed_set.contains(offset))
                .map(|offset| (seed.source_event_index, offset))
        })
        .collect::<BTreeMap<_, _>>();
    let mut warnings = vec![
        "This generated Frida 16.x script only captures closer exact-offset checkpoint state; Trace UI never attaches, spawns, loads, or executes it.".to_string(),
        "The embedded ELF SHA-256 comes from the prior Unicorn replay and is provenance only; confirm the runtime module is the same build before using the capture.".to_string(),
        "Checkpoint captures remain Candidate/Related execution evidence and do not prove that the path is reachable from a real entry point.".to_string(),
    ];
    let mut targets = BTreeMap::<String, TargetAccumulator>::new();
    for run in &bundle.runs {
        let Some(seed_offset) = selected_events.get(&run.source_event_index) else {
            continue;
        };
        let offsets = checkpoint_offsets_for_run(run)?;
        if offsets.is_empty() {
            warnings.push(format!(
                "Seed event {} at {} stopped with {}; no closer checkpoint target was generated for that stop reason.",
                run.source_event_index, seed_offset, run.stop_reason
            ));
            continue;
        }
        for offset in offsets {
            let target = targets.entry(offset).or_default();
            target.source_event_indices.insert(run.source_event_index);
            target.source_seed_offsets.insert(seed_offset.clone());
            target.stop_reasons.insert(run.stop_reason.clone());
        }
    }
    if targets.is_empty() || targets.len() > 32 {
        return Err(
            "selected Unicorn seeds produced no supported closer checkpoint targets, or more than 32 targets"
                .to_string(),
        );
    }
    if targets
        .values()
        .any(|target| target.stop_reasons.contains("call-boundary"))
    {
        warnings.push(
            "A post-call checkpoint hooks the AArch64 PC+4 return site and fires only when the real call returns through that continuation; exceptions, non-returning calls, and alternate control flow produce no capture."
                .to_string(),
        );
    }

    let mut plan_by_event = BTreeMap::new();
    for plan in &bundle.seed_recapture_plans {
        if plan_by_event
            .insert(plan.source_event_index, plan)
            .is_some()
        {
            return Err(format!(
                "Unicorn result contains duplicate seed recapture plans for event {}",
                plan.source_event_index
            ));
        }
    }
    let mut carried_window_count = 0u32;
    if bundle.seed_recapture_plans.is_empty() {
        warnings.push(
            "This Unicorn result has no seedRecapturePlans, so prior seed memory cannot be re-read at the closer checkpoint; the Hook still captures registers and supported current missing-memory windows."
                .to_string(),
        );
    } else {
        for target in targets.values_mut() {
            let source_events = target
                .source_event_indices
                .iter()
                .copied()
                .collect::<Vec<_>>();
            for source_event_index in source_events {
                let seed_offset = selected_events
                    .get(&source_event_index)
                    .expect("checkpoint target source event was selected");
                let Some(plan) = plan_by_event.get(&source_event_index) else {
                    warnings.push(format!(
                        "Unicorn result has no seed recapture plan for selected event {source_event_index}; its prior seed memory cannot be re-read at the closer checkpoint."
                    ));
                    continue;
                };
                if normalized_offset(&plan.capture_offset)? != *seed_offset {
                    return Err(format!(
                        "Unicorn seed recapture plan captureOffset does not match event {source_event_index} provenance"
                    ));
                }
                if plan.unsupported_memory_region_count > 0 {
                    warnings.push(format!(
                        "Seed event {source_event_index} has {} memory region(s) without a verified X0-X28/SP-relative relation; those regions cannot be re-read at the closer checkpoint.",
                        plan.unsupported_memory_region_count
                    ));
                }
                if plan.windows_truncated {
                    warnings.push(format!(
                        "Seed event {source_event_index} reached the bounded 256-window recapture-plan limit; omitted prior-memory windows remain explicit."
                    ));
                }
                for window in &plan.windows {
                    if window.source_kind != "byteArray" {
                        return Err(format!(
                            "Unicorn seed recapture plan event {source_event_index} contains a non-byteArray window"
                        ));
                    }
                    let (base_register, _) = capture_register(&window.base_register)?;
                    let displacement = parse_displacement(Some(&window.displacement))?;
                    let byte_length = u32::try_from(window.byte_length).map_err(|_| {
                        "Unicorn seed recapture window byte length does not fit u32".to_string()
                    })?;
                    if !(1..=4_096).contains(&byte_length) {
                        return Err(
                            "Frida Unicorn checkpoint carried-forward byte length must be between 1 and 4096"
                                .to_string(),
                        );
                    }
                    validate_window_bounds(displacement, byte_length)?;
                    let capture = target
                        .captures
                        .entry((base_register, displacement, byte_length))
                        .or_default();
                    capture.source_event_indices.insert(source_event_index);
                    capture.source_seed_offsets.insert(seed_offset.clone());
                    carried_window_count = carried_window_count.saturating_add(1);
                }
            }
        }
    }
    if carried_window_count > 0 {
        warnings.push(format!(
            "{carried_window_count} verified seed byteArray window reference(s) will be re-read from the current checkpoint register values; the Hook never copies prior absolute addresses or stale bytes."
        ));
    }

    for suggestion in &bundle.recapture_suggestions {
        let checkpoint_offset = normalized_offset(&suggestion.pc_offset)?;
        let Some(target) = targets.get_mut(&checkpoint_offset) else {
            continue;
        };
        let selected_sources = suggestion
            .source_event_indices
            .iter()
            .filter_map(|event| {
                selected_events
                    .get(event)
                    .map(|seed| (*event, seed.clone()))
            })
            .collect::<Vec<_>>();
        if selected_sources.is_empty() {
            continue;
        }
        let Some(base_register) = suggestion.base_register.as_deref() else {
            warnings.push(format!(
                "Checkpoint {checkpoint_offset} includes an absolute-address missing-memory request; it was not carried into the new runtime process."
            ));
            continue;
        };
        let (base_register, _) = match capture_register(base_register) {
            Ok(value) => value,
            Err(error) => {
                warnings.push(format!("Checkpoint {checkpoint_offset}: {error}"));
                continue;
            }
        };
        let displacement = parse_displacement(suggestion.displacement.as_deref())?;
        let byte_length = u32::try_from(suggestion.byte_length)
            .map_err(|_| "Frida Unicorn checkpoint byte length exceeds u32".to_string())?;
        if !(1..=4_096).contains(&byte_length) {
            return Err(
                "Frida Unicorn checkpoint byte length must be between 1 and 4096".to_string(),
            );
        }
        validate_window_bounds(displacement, byte_length)?;
        let capture = target
            .captures
            .entry((base_register, displacement, byte_length))
            .or_default();
        for (event, seed_offset) in selected_sources {
            capture.source_event_indices.insert(event);
            capture.source_seed_offsets.insert(seed_offset);
        }
    }

    let mut public_targets = Vec::with_capacity(targets.len());
    let mut capture_window_count = 0u32;
    for (offset, target) in targets {
        if target.captures.len() > 256 {
            return Err(format!(
                "Frida Unicorn checkpoint target {offset} contains more than 256 memory windows"
            ));
        }
        let mut total_bytes = 0u64;
        let mut captures = Vec::with_capacity(target.captures.len());
        for ((base_register, displacement, byte_length), capture) in target.captures {
            total_bytes = total_bytes.saturating_add(byte_length as u64);
            let (_, index) = capture_register(&base_register)?;
            captures.push(FridaUnicornCheckpointMemorySpec {
                index,
                label: checkpoint_label(&base_register, displacement, byte_length),
                base_register,
                displacement,
                displacement_hex: format_signed_offset_hex(displacement),
                byte_length,
                source_event_indices: capture.source_event_indices.into_iter().collect(),
                source_seed_offsets: capture.source_seed_offsets.into_iter().collect(),
            });
        }
        if total_bytes > 1_048_576 {
            return Err(format!(
                "Frida Unicorn checkpoint target {offset} exceeds the 1 MiB seed-memory limit"
            ));
        }
        if target.stop_reasons.contains("missing-memory") && captures.is_empty() {
            warnings.push(format!(
                "Checkpoint {offset} has no safe X0-X28/SP-relative missing-memory window; the Hook captures registers only and further memory may need manual configuration."
            ));
        }
        if target.stop_reasons.contains("call-boundary") && captures.is_empty() {
            warnings.push(format!(
                "Post-call checkpoint {offset} has no safe carried-forward memory window; the Hook captures registers only and the resumed replay may request another bounded recapture."
            ));
        }
        capture_window_count = capture_window_count.saturating_add(captures.len() as u32);
        let offset_stem = offset.trim_start_matches("0x");
        public_targets.push(FridaUnicornCheckpointHookTarget {
            hook_id: format!("unicorn-checkpoint-{offset_stem}"),
            offset,
            source_event_indices: target.source_event_indices.into_iter().collect(),
            source_seed_offsets: target.source_seed_offsets.into_iter().collect(),
            stop_reasons: target.stop_reasons.into_iter().collect(),
            captures,
        });
    }
    if capture_window_count > 256 {
        return Err("Frida Unicorn checkpoint contains more than 256 memory windows".to_string());
    }
    public_targets.sort_by_key(|target| parse_hex_addr(&target.offset).unwrap_or(u64::MAX));
    warnings.sort();
    warnings.dedup();

    let module_json = serde_json::to_string(module_name)
        .map_err(|error| format!("serialize module name failed: {error}"))?;
    let sha_json = serde_json::to_string(&bundle.expected_binary_sha256.to_ascii_lowercase())
        .map_err(|error| format!("serialize expected SHA-256 failed: {error}"))?;
    let targets_json = serde_json::to_string(&public_targets)
        .map_err(|error| format!("serialize checkpoint targets failed: {error}"))?;
    let template = r##"/* Trace UI Unicorn closer-checkpoint capture hook
 * Frida JavaScript API target: 16.x
 * Generated schema: trace-ui/frida-unicorn-checkpoint-hook-v1
 * Event protocol: trace-ui/frida-hook-v1
 * Execute manually with your preferred Frida 16 host or CLI.
 * Trace UI never attaches, spawns, loads, or executes this script.
 */
'use strict';

const TRACE_UI_PROTOCOL = 'trace-ui/frida-hook-v1';
const MODULE_NAME = __MODULE_NAME__;
const EXPECTED_BINARY_SHA256 = __EXPECTED_BINARY_SHA256__;
const TARGETS = __TARGETS__;
const MAX_EVENTS = __MAX_EVENTS__;
const CAPTURE_SESSION_ID = 'unicorn-checkpoint:' + Date.now().toString(16) + ':' + Process.id;
let resolvedModuleBase = null;
let resolvedModuleSize = 0;
let nextEventId = 1;
let emittedHits = 0;
let limitReported = false;

function sendRecord(spec, event, payload) {
  const record = Object.assign({
    protocol: TRACE_UI_PROTOCOL,
    eventId: CAPTURE_SESSION_ID + ':event:' + (nextEventId++),
    hookId: spec ? spec.hookId : 'unicorn-checkpoint',
    event: event,
    functionName: spec ? ('unicorn-checkpoint-' + spec.offset.slice(2)) : 'unicorn-checkpoint',
    moduleName: MODULE_NAME,
    moduleBase: resolvedModuleBase !== null ? resolvedModuleBase.toString() : null,
    moduleSize: resolvedModuleSize,
    captureSessionId: CAPTURE_SESSION_ID,
    expectedBinarySha256: EXPECTED_BINARY_SHA256,
    timestampMs: Date.now(),
    threadId: Process.getCurrentThreadId()
  }, payload || {});
  send(record);
  console.log('TRACE_UI_JSON ' + JSON.stringify(record));
}

function captureRegisters(context) {
  const registers = {};
  for (let i = 0; i < 29; i++) {
    try {
      const value = context['x' + i];
      if (value !== null && value !== undefined) registers['x' + i] = value.toString();
    } catch (_) {}
  }
  for (const name of ['fp', 'lr', 'sp', 'pc', 'nzcv']) {
    try {
      const value = context[name];
      if (value !== null && value !== undefined) registers[name] = value.toString();
    } catch (_) {}
  }
  return registers;
}

function bytesToHex(bytes) {
  const array = new Uint8Array(bytes);
  let value = '';
  for (let i = 0; i < array.length; i++) value += ('0' + array[i].toString(16)).slice(-2);
  return value;
}

function captureRelativeWindow(context, spec) {
  let base = null;
  let pointer = null;
  try {
    base = context[spec.baseRegister.toLowerCase()];
    const baseText = base !== null && base !== undefined ? base.toString() : null;
    if (!baseText || baseText === '0x0') {
      return { index: spec.index, label: spec.label, kind: 'byteArray', direction: 'input', phase: 'enter', pointer: baseText, value: null, byteLength: 0, requestedLength: spec.byteLength, baseRegister: spec.baseRegister, displacement: spec.displacementHex, readError: 'null base register' };
    }
    pointer = spec.displacement >= 0 ? base.add(spec.displacement) : base.sub(-spec.displacement);
    const bytes = pointer.readByteArray(spec.byteLength);
    if (bytes === null) {
      return { index: spec.index, label: spec.label, kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointer.toString(), value: null, byteLength: 0, requestedLength: spec.byteLength, baseRegister: spec.baseRegister, displacement: spec.displacementHex, readError: 'readByteArray returned null' };
    }
    return { index: spec.index, label: spec.label, kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointer.toString(), value: bytesToHex(bytes), byteLength: spec.byteLength, requestedLength: spec.byteLength, baseRegister: spec.baseRegister, displacement: spec.displacementHex };
  } catch (error) {
    return { index: spec.index, label: spec.label, kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointer ? pointer.toString() : null, value: null, byteLength: 0, requestedLength: spec.byteLength, baseRegister: spec.baseRegister, displacement: spec.displacementHex, readError: String(error) };
  }
}

function install() {
  try {
    resolvedModuleBase = Module.getBaseAddress(MODULE_NAME);
    if (resolvedModuleBase === null) throw new Error('module not loaded: ' + MODULE_NAME);
    try { resolvedModuleSize = Process.getModuleByName(MODULE_NAME).size; } catch (_) { resolvedModuleSize = 0; }
  } catch (error) {
    sendRecord(null, 'hook-error', { error: 'module resolution failed: ' + String(error) });
    return;
  }

  TARGETS.forEach(function (spec) {
    let target = null;
    try {
      target = resolvedModuleBase.add(ptr(spec.offset));
      sendRecord(spec, 'hook-ready', {
        target: target.toString(),
        captureOffset: spec.offset,
        checkpointSourceEventIndices: spec.sourceEventIndices,
        checkpointSourceSeedOffsets: spec.sourceSeedOffsets,
        checkpointStopReasons: spec.stopReasons,
        captureSpecs: spec.captures
      });
      Interceptor.attach(target, {
        onEnter: function () {
          if (emittedHits >= MAX_EVENTS) {
            if (!limitReported) {
              limitReported = true;
              sendRecord(null, 'capture-limit', { error: 'Unicorn checkpoint hit limit reached: ' + MAX_EVENTS });
            }
            return;
          }
          emittedHits += 1;
          sendRecord(spec, 'hook-enter', {
            target: target.toString(),
            captureOffset: spec.offset,
            checkpointSourceEventIndices: spec.sourceEventIndices,
            checkpointSourceSeedOffsets: spec.sourceSeedOffsets,
            checkpointStopReasons: spec.stopReasons,
            registers: captureRegisters(this.context),
            captures: spec.captures.map(function (capture) { return captureRelativeWindow(this.context, capture); }, this)
          });
        }
      });
      sendRecord(spec, 'hook-installed', {
        target: target.toString(),
        captureOffset: spec.offset,
        checkpointSourceEventIndices: spec.sourceEventIndices,
        checkpointSourceSeedOffsets: spec.sourceSeedOffsets,
        checkpointStopReasons: spec.stopReasons
      });
    } catch (error) {
      sendRecord(spec, 'hook-error', {
        target: target ? target.toString() : null,
        captureOffset: spec.offset,
        error: String(error)
      });
    }
  });
}

setImmediate(install);
"##;
    let script = template
        .replace("__MODULE_NAME__", &module_json)
        .replace("__EXPECTED_BINARY_SHA256__", &sha_json)
        .replace("__TARGETS__", &targets_json)
        .replace("__MAX_EVENTS__", &options.max_events.to_string());
    let file_name = format!(
        "{}-unicorn-checkpoint-frida-hook.js",
        sanitize_identifier(module_name, "module")
    );
    Ok(FridaUnicornCheckpointHookScript {
        schema_version: FRIDA_UNICORN_CHECKPOINT_HOOK_SCHEMA.to_string(),
        module_name: module_name.to_string(),
        file_name,
        expected_binary_sha256: bundle.expected_binary_sha256.to_ascii_lowercase(),
        selected_seed_offsets,
        targets: public_targets,
        capture_window_count,
        max_events: options.max_events,
        script,
        warnings,
        protocol_version: FRIDA_HOOK_PROTOCOL.to_string(),
        frida_api_version: "16.x".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::angr::AngrOllvmFridaSeedProvenance;
    use crate::query::frida_capture::{generate_angr_state_seed, parse_frida_capture_bundle};
    use crate::query::unicorn::{
        UnicornCallBoundary, UnicornMissingMemory, UnicornOllvmConfig, UnicornRecaptureSuggestion,
        UnicornReplayRun, UnicornSeedRecapturePlan, UnicornSeedRecaptureWindow,
    };

    fn sample_bundle() -> UnicornOllvmResultBundle {
        UnicornOllvmResultBundle {
            schema: "trace-ui/unicorn-ollvm-v1".to_string(),
            module_name: "libtarget.so".to_string(),
            binary_sha256: "a".repeat(64),
            expected_binary_sha256: "a".repeat(64),
            binary_identity_matched: true,
            architecture: "AArch64".to_string(),
            unicorn_version: "2.1.4".to_string(),
            capstone_version: "5.0.6".to_string(),
            config: UnicornOllvmConfig::default(),
            seeds: vec![AngrOllvmFridaSeedProvenance {
                source_event_index: 7,
                hook_id: "seed".to_string(),
                call_id: None,
                module_name: "libtarget.so".to_string(),
                function_name: "dispatcher".to_string(),
                capture_offset: "0x100".to_string(),
                registers_seeded: vec!["x19".to_string(), "sp".to_string()],
                memory_region_count: 0,
                matched_probe_offsets: vec!["0x100".to_string()],
                matched_branch_offsets: Vec::new(),
                matched_dispatcher_offsets: vec!["0x100".to_string()],
            }],
            seed_qualities: Vec::new(),
            seed_recapture_plans: Vec::new(),
            runs: vec![UnicornReplayRun {
                source_event_index: 7,
                seed_kind: "frida-capture-exact-dispatcher".to_string(),
                start_offset: "0x100".to_string(),
                mapped_base: "0x40000000".to_string(),
                stop_reason: "missing-memory".to_string(),
                instruction_count: 8,
                elapsed_ms: 1,
                terminal_address: "0x40000180".to_string(),
                terminal_offset: Some("0x180".to_string()),
                matched_dispatcher_offset: None,
                source_state_values: Vec::new(),
                target_state_values: Vec::new(),
                executed_offsets: vec!["0x100".to_string(), "0x180".to_string()],
                executed_offsets_truncated: false,
                block_offsets: vec!["0x100".to_string(), "0x180".to_string()],
                block_offsets_truncated: false,
                register_changes: Vec::new(),
                memory_writes: Vec::new(),
                memory_writes_truncated: false,
                call_boundaries: Vec::new(),
                missing_memory: vec![UnicornMissingMemory {
                    access: "read".to_string(),
                    address: "0x90000020".to_string(),
                    size: 8,
                    pc_offset: Some("0x180".to_string()),
                    instruction: Some("ldr x0, [x19, #0x20]".to_string()),
                    base_register: Some("X19".to_string()),
                    displacement: Some("0x20".to_string()),
                }],
                warnings: Vec::new(),
                error: None,
            }],
            transition_matrix: Vec::new(),
            recapture_suggestions: vec![UnicornRecaptureSuggestion {
                pc_offset: "0x180".to_string(),
                base_register: Some("X19".to_string()),
                displacement: Some("0x20".to_string()),
                byte_length: 8,
                reason: "capture X19+0x20".to_string(),
                source_event_indices: vec![7],
            }],
            warnings: Vec::new(),
        }
    }

    #[test]
    fn generates_closer_missing_memory_checkpoint_instead_of_original_seed() {
        let generated = generate_frida_unicorn_checkpoint_hook(
            &sample_bundle(),
            &["0x100".to_string()],
            &FridaUnicornCheckpointHookOptions { max_events: 100 },
        )
        .unwrap();
        assert_eq!(
            generated.schema_version,
            FRIDA_UNICORN_CHECKPOINT_HOOK_SCHEMA
        );
        assert_eq!(generated.targets.len(), 1);
        assert_eq!(generated.targets[0].offset, "0x180");
        assert_eq!(generated.targets[0].captures.len(), 1);
        assert_eq!(generated.targets[0].captures[0].base_register, "X19");
        assert_eq!(generated.targets[0].captures[0].displacement, 0x20);
        assert!(generated.script.contains("Interceptor.attach(target"));
        assert!(generated.script.contains("checkpointSourceSeedOffsets"));
        assert!(!generated.script.contains("frida.attach"));
    }

    #[test]
    fn checkpoint_capture_round_trips_to_exact_offset_state_seed() {
        let generated = generate_frida_unicorn_checkpoint_hook(
            &sample_bundle(),
            &["0x100".to_string()],
            &FridaUnicornCheckpointHookOptions::default(),
        )
        .unwrap();
        let target = &generated.targets[0];
        let spec = &target.captures[0];
        let capture = serde_json::json!([{
            "protocol": FRIDA_HOOK_PROTOCOL,
            "hookId": target.hook_id,
            "event": "hook-enter",
            "functionName": "unicorn-checkpoint-180",
            "moduleName": generated.module_name,
            "moduleBase": "0x71000000",
            "moduleSize": 0x4000,
            "target": "0x71000180",
            "captureOffset": target.offset,
            "timestampMs": 1,
            "threadId": 7,
            "registers": {
                "x19": "0x90000000",
                "sp": "0xa0001000",
                "pc": "0x71000180",
                "nzcv": "0x60000000"
            },
            "captures": [{
                "index": spec.index,
                "label": spec.label,
                "kind": "byteArray",
                "direction": "input",
                "phase": "enter",
                "pointer": "0x90000020",
                "value": "0011223344556677",
                "byteLength": 8,
                "requestedLength": 8,
                "baseRegister": "X19",
                "displacement": "0x20"
            }]
        }]);
        let bundle = parse_frida_capture_bundle(&serde_json::to_vec(&capture).unwrap()).unwrap();
        let seed = generate_angr_state_seed(&bundle, 0, true, true).unwrap();
        assert_eq!(seed.capture_offset.as_deref(), Some("0x180"));
        assert_eq!(seed.memory_regions.len(), 1);
        assert_eq!(seed.memory_regions[0].address, "0x90000020");
    }

    #[test]
    fn uses_terminal_offset_for_loop_checkpoint_and_rejects_unknown_seed() {
        let mut bundle = sample_bundle();
        bundle.runs[0].stop_reason = "loop-detected".to_string();
        bundle.runs[0].terminal_offset = Some("0x188".to_string());
        bundle.runs[0].missing_memory.clear();
        bundle.recapture_suggestions.clear();
        let offsets = unicorn_checkpoint_offsets(&bundle).unwrap();
        assert_eq!(offsets.into_iter().collect::<Vec<_>>(), vec!["0x188"]);
        let generated = generate_frida_unicorn_checkpoint_hook(
            &bundle,
            &["0x100".to_string()],
            &FridaUnicornCheckpointHookOptions::default(),
        )
        .unwrap();
        assert_eq!(generated.targets[0].offset, "0x188");
        assert!(generated.targets[0].captures.is_empty());
        assert!(generate_frida_unicorn_checkpoint_hook(
            &bundle,
            &["0x999".to_string()],
            &FridaUnicornCheckpointHookOptions::default(),
        )
        .is_err());

        bundle.runs[0].terminal_offset = Some("0x100".to_string());
        assert!(generate_frida_unicorn_checkpoint_hook(
            &bundle,
            &["0x100".to_string()],
            &FridaUnicornCheckpointHookOptions::default(),
        )
        .is_err());
    }

    #[test]
    fn call_boundary_checkpoint_hooks_post_call_return_and_rereads_seed_memory() {
        let mut bundle = sample_bundle();
        bundle.runs[0].stop_reason = "call-boundary".to_string();
        bundle.runs[0].terminal_address = "0x40000180".to_string();
        bundle.runs[0].terminal_offset = Some("0x180".to_string());
        bundle.runs[0].missing_memory.clear();
        bundle.runs[0].call_boundaries = vec![UnicornCallBoundary {
            pc_offset: "0x180".to_string(),
            mnemonic: "blr x9".to_string(),
            target_address: Some("0x70001000".to_string()),
            target_offset: None,
            return_address: Some("0x40000184".to_string()),
            return_offset: Some("0x184".to_string()),
        }];
        bundle.recapture_suggestions.clear();
        bundle.seed_recapture_plans = vec![UnicornSeedRecapturePlan {
            source_event_index: 7,
            capture_offset: "0x100".to_string(),
            windows: vec![UnicornSeedRecaptureWindow {
                label: "seed-x19-input".to_string(),
                base_register: "X19".to_string(),
                displacement: "0x20".to_string(),
                byte_length: 16,
                source_kind: "byteArray".to_string(),
                phase: "enter".to_string(),
            }],
            carry_forward_bytes: 16,
            unsupported_memory_region_count: 0,
            windows_truncated: false,
        }];

        assert_eq!(
            unicorn_checkpoint_offsets(&bundle)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["0x184"]
        );
        let generated = generate_frida_unicorn_checkpoint_hook(
            &bundle,
            &["0x100".to_string()],
            &FridaUnicornCheckpointHookOptions::default(),
        )
        .unwrap();
        assert_eq!(generated.targets.len(), 1);
        assert_eq!(generated.targets[0].offset, "0x184");
        assert_eq!(generated.targets[0].stop_reasons, vec!["call-boundary"]);
        assert_eq!(generated.targets[0].captures.len(), 1);
        assert_eq!(generated.targets[0].captures[0].base_register, "X19");
        assert_eq!(generated.targets[0].captures[0].byte_length, 16);
        assert!(generated
            .warnings
            .iter()
            .any(|warning| warning.contains("post-call checkpoint")));
        assert!(generated.warnings.iter().any(
            |warning| warning.contains("never copies prior absolute addresses or stale bytes")
        ));

        bundle.runs[0].call_boundaries[0].return_offset = Some("0x188".to_string());
        assert!(unicorn_checkpoint_offsets(&bundle).is_err());
    }
}
