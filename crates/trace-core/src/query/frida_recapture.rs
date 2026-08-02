use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::query::unicorn::UnicornOllvmResultBundle;
use crate::utils::{format_signed_offset_hex, parse_hex_addr, parse_signed_offset};

const FRIDA_UNICORN_RECAPTURE_HOOK_SCHEMA: &str = "trace-ui/frida-unicorn-recapture-hook-v1";
const FRIDA_HOOK_PROTOCOL: &str = "trace-ui/frida-hook-v1";

fn default_max_events() -> u32 {
    5_000
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaUnicornRecaptureHookOptions {
    #[serde(default = "default_max_events")]
    pub max_events: u32,
}

impl Default for FridaUnicornRecaptureHookOptions {
    fn default() -> Self {
        Self {
            max_events: default_max_events(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaUnicornRecaptureMemorySpec {
    pub index: u8,
    pub label: String,
    pub base_register: String,
    pub displacement: i64,
    pub displacement_hex: String,
    pub byte_length: u32,
    pub missing_pc_offsets: Vec<String>,
    pub source_event_indices: Vec<u64>,
    pub source_labels: Vec<String>,
    pub carried_forward: bool,
    pub suggested: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaUnicornRecaptureHookTarget {
    pub hook_id: String,
    pub offset: String,
    pub source_event_indices: Vec<u64>,
    pub missing_pc_offsets: Vec<String>,
    pub captures: Vec<FridaUnicornRecaptureMemorySpec>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaUnicornRecaptureHookScript {
    pub schema_version: String,
    pub module_name: String,
    pub file_name: String,
    pub expected_binary_sha256: String,
    pub selected_suggestion_indices: Vec<u32>,
    pub targets: Vec<FridaUnicornRecaptureHookTarget>,
    pub carried_forward_window_count: u32,
    pub suggested_window_count: u32,
    pub unsupported_seed_region_count: u64,
    pub max_events: u32,
    pub script: String,
    pub warnings: Vec<String>,
    pub protocol_version: String,
    pub frida_api_version: String,
}

#[derive(Default)]
struct CaptureAccumulator {
    missing_pc_offsets: BTreeSet<String>,
    source_event_indices: BTreeSet<u64>,
    source_labels: BTreeSet<String>,
    preferred_label: Option<String>,
    carried_forward: bool,
    suggested: bool,
}

#[derive(Default)]
struct TargetAccumulator {
    source_event_indices: BTreeSet<u64>,
    missing_pc_offsets: BTreeSet<String>,
    captures: BTreeMap<(String, i64, u32), CaptureAccumulator>,
}

fn normalized_offset(value: &str) -> Result<String, String> {
    parse_hex_addr(value).map(|offset| format!("0x{offset:x}"))
}

fn parse_displacement(value: Option<&str>) -> Result<i64, String> {
    let parsed = parse_signed_offset(value.unwrap_or("0"))
        .map_err(|error| format!("invalid recapture displacement: {error}"))?;
    if !(-1_048_576..=1_048_576).contains(&parsed) {
        return Err("Frida Unicorn recapture displacement must be within +/- 1 MiB".to_string());
    }
    Ok(parsed)
}

fn validate_window_bounds(displacement: i64, byte_length: u32) -> Result<(), String> {
    let last_displacement = i64::from(byte_length.saturating_sub(1));
    let Some(last_displacement) = displacement.checked_add(last_displacement) else {
        return Err("Frida Unicorn recapture window displacement overflow".to_string());
    };
    if !(-1_048_576..=1_048_576).contains(&last_displacement) {
        return Err(
            "Frida Unicorn recapture window must remain within +/- 1 MiB of its base register"
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
            "Frida Unicorn recapture requires X0-X28 or SP, got {value}"
        ));
    };
    if index > 28 {
        return Err(format!(
            "Frida Unicorn recapture requires X0-X28 or SP, got {value}"
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

fn capture_label(base_register: &str, displacement: i64, byte_length: u32) -> String {
    let displacement = if displacement < 0 {
        format!("minus-{:x}", displacement.unsigned_abs())
    } else if displacement > 0 {
        format!("plus-{displacement:x}")
    } else {
        "base".to_string()
    };
    format!(
        "unicorn-recapture-{}-{displacement}-{byte_length}b",
        base_register.to_ascii_lowercase()
    )
}

pub fn generate_frida_unicorn_recapture_hook(
    bundle: &UnicornOllvmResultBundle,
    suggestion_indices: &[u32],
    options: &FridaUnicornRecaptureHookOptions,
) -> Result<FridaUnicornRecaptureHookScript, String> {
    if !(1..=50_000).contains(&options.max_events) {
        return Err("Frida Unicorn recapture event limit must be between 1 and 50000".to_string());
    }
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
            "Unicorn result exact ELF identity must match before generating a recapture hook"
                .to_string(),
        );
    }
    if bundle.expected_binary_sha256.len() != 64
        || !bundle
            .expected_binary_sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("Unicorn result expectedBinarySha256 is invalid".to_string());
    }
    let mut selected_suggestion_indices = suggestion_indices.to_vec();
    selected_suggestion_indices.sort_unstable();
    selected_suggestion_indices.dedup();
    if selected_suggestion_indices.is_empty() || selected_suggestion_indices.len() > 64 {
        return Err(
            "Frida Unicorn recapture requires between 1 and 64 suggestion indices".to_string(),
        );
    }

    let seed_by_event = bundle
        .seeds
        .iter()
        .map(|seed| (seed.source_event_index, seed))
        .collect::<BTreeMap<_, _>>();
    let mut target_accumulators = BTreeMap::<String, TargetAccumulator>::new();
    let mut selected_source_event_indices = BTreeSet::new();
    let mut warnings = vec![
        "This Frida 16.x recapture script is generated only. The user manually attaches/spawns/loads/runs it; Trace UI performs no runtime Frida control.".to_string(),
        "The hook targets the original exact seed offsets so its hook-enter events remain eligible for another OLLVM Unicorn/angr seed. Register-relative windows are evaluated at those seed points, not at the later missing-memory instruction.".to_string(),
        "The embedded SHA-256 records the ELF used by the prior Unicorn replay but cannot attest the module currently loaded in the target process; confirm the exact build manually.".to_string(),
        "Every memory read is explicitly register-relative and bounded to 1-4096 bytes. Null, unreadable, or guard-page-crossing windows emit readError and are never replaced with zero bytes.".to_string(),
        "Recaptured execution remains Candidate/Related evidence. A changed register value, thread, input, or earlier path can make the requested window differ from the original missing-memory state.".to_string(),
    ];

    for suggestion_index in &selected_suggestion_indices {
        let suggestion = bundle
            .recapture_suggestions
            .get(*suggestion_index as usize)
            .ok_or_else(|| {
                format!(
                    "Unicorn recapture suggestion index {} is out of range",
                    suggestion_index
                )
            })?;
        let base_register = suggestion.base_register.as_deref().ok_or_else(|| {
            format!(
                "Unicorn recapture suggestion {} has no register-relative expression and cannot be generated automatically",
                suggestion_index
            )
        })?;
        let (base_register, _capture_index) = capture_register(base_register)?;
        let displacement = parse_displacement(suggestion.displacement.as_deref())?;
        let byte_length = u32::try_from(suggestion.byte_length)
            .map_err(|_| "Unicorn recapture byte length does not fit u32".to_string())?;
        if !(1..=4096).contains(&byte_length) {
            return Err(
                "Frida Unicorn recapture byte length must be between 1 and 4096".to_string(),
            );
        }
        validate_window_bounds(displacement, byte_length)?;
        if suggestion.source_event_indices.is_empty() {
            return Err(format!(
                "Unicorn recapture suggestion {} has no source events",
                suggestion_index
            ));
        }
        let missing_pc_offset = normalized_offset(&suggestion.pc_offset)?;
        for source_event_index in &suggestion.source_event_indices {
            selected_source_event_indices.insert(*source_event_index);
            let seed = seed_by_event.get(source_event_index).ok_or_else(|| {
                format!(
                    "Unicorn recapture suggestion {} references unknown seed event {}",
                    suggestion_index, source_event_index
                )
            })?;
            if seed.module_name.trim() != module_name {
                return Err(format!(
                    "Unicorn seed event {} module {} does not match {}",
                    source_event_index, seed.module_name, module_name
                ));
            }
            let target_offset = normalized_offset(&seed.capture_offset)?;
            let target = target_accumulators.entry(target_offset).or_default();
            target.source_event_indices.insert(*source_event_index);
            target.missing_pc_offsets.insert(missing_pc_offset.clone());
            let capture = target
                .captures
                .entry((base_register.clone(), displacement, byte_length))
                .or_default();
            capture.source_event_indices.insert(*source_event_index);
            capture.missing_pc_offsets.insert(missing_pc_offset.clone());
            let label = capture_label(&base_register, displacement, byte_length);
            capture.source_labels.insert(label.clone());
            if capture.preferred_label.is_none() {
                capture.preferred_label = Some(label);
            }
            capture.suggested = true;
        }
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
    let mut unsupported_seed_region_count = 0u64;
    if bundle.seed_recapture_plans.is_empty() {
        warnings.push(
            "This Unicorn result predates seedRecapturePlans, so prior seed memory cannot be carried forward automatically. The generated hook still captures the selected new missing-memory windows; regenerate and rerun Unicorn from a current seed to enable cumulative recapture."
                .to_string(),
        );
    } else {
        for source_event_index in selected_source_event_indices {
            let seed = seed_by_event
                .get(&source_event_index)
                .expect("selected suggestion seed was validated above");
            let Some(plan) = plan_by_event.get(&source_event_index) else {
                warnings.push(format!(
                    "Unicorn result has no seed recapture plan for selected event {source_event_index}; its prior seed memory cannot be carried forward automatically."
                ));
                continue;
            };
            let target_offset = normalized_offset(&seed.capture_offset)?;
            if normalized_offset(&plan.capture_offset)? != target_offset {
                return Err(format!(
                    "Unicorn seed recapture plan captureOffset does not match event {source_event_index} provenance"
                ));
            }
            unsupported_seed_region_count =
                unsupported_seed_region_count.saturating_add(plan.unsupported_memory_region_count);
            if plan.unsupported_memory_region_count > 0 {
                warnings.push(format!(
                    "Seed event {source_event_index} has {} memory region(s) without a verified X0-X28/SP-relative relation; those regions cannot be carried into this recapture hook automatically.",
                    plan.unsupported_memory_region_count
                ));
            }
            if plan.windows_truncated {
                warnings.push(format!(
                    "Seed event {source_event_index} reached the bounded 256-window recapture-plan limit; later prior-memory windows were not carried forward."
                ));
            }
            let target = target_accumulators
                .get_mut(&target_offset)
                .expect("selected suggestion target was created above");
            for window in &plan.windows {
                if window.source_kind != "byteArray" {
                    return Err(format!(
                        "Unicorn seed recapture plan event {source_event_index} contains a non-byteArray window"
                    ));
                }
                let (base_register, _capture_index) = capture_register(&window.base_register)?;
                let displacement = parse_displacement(Some(&window.displacement))?;
                let byte_length = u32::try_from(window.byte_length).map_err(|_| {
                    "Unicorn seed recapture window byte length does not fit u32".to_string()
                })?;
                if !(1..=4096).contains(&byte_length) {
                    return Err(
                        "Frida Unicorn carried-forward byte length must be between 1 and 4096"
                            .to_string(),
                    );
                }
                validate_window_bounds(displacement, byte_length)?;
                let capture = target
                    .captures
                    .entry((base_register, displacement, byte_length))
                    .or_default();
                capture.source_event_indices.insert(source_event_index);
                capture.source_labels.insert(window.label.clone());
                if !capture.carried_forward {
                    capture.preferred_label = Some(window.label.clone());
                }
                capture.carried_forward = true;
            }
        }
    }

    if target_accumulators.is_empty() || target_accumulators.len() > 32 {
        return Err("Frida Unicorn recapture requires between 1 and 32 seed targets".to_string());
    }

    let mut targets = Vec::new();
    let mut total_capture_specs = 0usize;
    let mut carried_forward_window_count = 0u32;
    let mut suggested_window_count = 0u32;
    for (offset, target) in target_accumulators {
        if target.captures.len() > 256 {
            return Err(format!(
                "Frida Unicorn recapture target {offset} contains more than 256 memory windows"
            ));
        }
        let mut target_bytes = 0u64;
        let mut captures = Vec::new();
        for ((base_register, displacement, byte_length), capture) in target.captures {
            target_bytes = target_bytes.saturating_add(byte_length as u64);
            let (_, index) = capture_register(&base_register)?;
            if capture.carried_forward {
                carried_forward_window_count = carried_forward_window_count.saturating_add(1);
            }
            if capture.suggested {
                suggested_window_count = suggested_window_count.saturating_add(1);
            }
            let source_labels = capture.source_labels.into_iter().collect::<Vec<_>>();
            captures.push(FridaUnicornRecaptureMemorySpec {
                index,
                label: capture
                    .preferred_label
                    .unwrap_or_else(|| capture_label(&base_register, displacement, byte_length)),
                base_register,
                displacement,
                displacement_hex: format_signed_offset_hex(displacement),
                byte_length,
                missing_pc_offsets: capture.missing_pc_offsets.into_iter().collect(),
                source_event_indices: capture.source_event_indices.into_iter().collect(),
                source_labels,
                carried_forward: capture.carried_forward,
                suggested: capture.suggested,
            });
        }
        if target_bytes > 1_048_576 {
            return Err(format!(
                "Frida Unicorn recapture target {offset} exceeds the 1 MiB seed-memory limit"
            ));
        }
        total_capture_specs = total_capture_specs.saturating_add(captures.len());
        let offset_stem = offset.trim_start_matches("0x");
        targets.push(FridaUnicornRecaptureHookTarget {
            hook_id: format!("unicorn-recapture-{offset_stem}"),
            offset,
            source_event_indices: target.source_event_indices.into_iter().collect(),
            missing_pc_offsets: target.missing_pc_offsets.into_iter().collect(),
            captures,
        });
    }
    if total_capture_specs > 256 {
        return Err("Frida Unicorn recapture contains more than 256 memory windows".to_string());
    }
    targets.sort_by_key(|target| parse_hex_addr(&target.offset).unwrap_or(u64::MAX));

    let module_json = serde_json::to_string(module_name)
        .map_err(|error| format!("serialize module name failed: {error}"))?;
    let sha_json = serde_json::to_string(&bundle.expected_binary_sha256.to_ascii_lowercase())
        .map_err(|error| format!("serialize expected SHA-256 failed: {error}"))?;
    let targets_json = serde_json::to_string(&targets)
        .map_err(|error| format!("serialize recapture targets failed: {error}"))?;
    let template = r##"/* Trace UI Unicorn missing-memory recapture hook
 * Frida JavaScript API target: 16.x
 * Generated schema: trace-ui/frida-unicorn-recapture-hook-v1
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
const CAPTURE_SESSION_ID = 'unicorn-recapture:' + Date.now().toString(16) + ':' + Process.id;
let resolvedModuleBase = null;
let resolvedModuleSize = 0;
let nextEventId = 1;
let emittedHits = 0;
let limitReported = false;

function sendRecord(spec, event, payload) {
  const record = Object.assign({
    protocol: TRACE_UI_PROTOCOL,
    eventId: CAPTURE_SESSION_ID + ':event:' + (nextEventId++),
    hookId: spec ? spec.hookId : 'unicorn-recapture',
    event: event,
    functionName: spec ? ('unicorn-recapture-' + spec.offset.slice(2)) : 'unicorn-recapture',
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
    const contextName = spec.baseRegister.toLowerCase();
    base = context[contextName];
    const baseText = base !== null && base !== undefined ? base.toString() : null;
    if (!baseText || baseText === '0x0') {
      return { index: spec.index, label: spec.label, kind: 'byteArray', direction: 'input', phase: 'enter', pointer: baseText, value: null, byteLength: 0, requestedLength: spec.byteLength, baseRegister: spec.baseRegister, displacement: spec.displacementHex, missingPcOffsets: spec.missingPcOffsets, readError: 'null base register' };
    }
    pointer = spec.displacement >= 0 ? base.add(spec.displacement) : base.sub(-spec.displacement);
    const bytes = pointer.readByteArray(spec.byteLength);
    if (bytes === null) {
      return { index: spec.index, label: spec.label, kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointer.toString(), value: null, byteLength: 0, requestedLength: spec.byteLength, baseRegister: spec.baseRegister, displacement: spec.displacementHex, missingPcOffsets: spec.missingPcOffsets, readError: 'readByteArray returned null' };
    }
    return { index: spec.index, label: spec.label, kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointer.toString(), value: bytesToHex(bytes), byteLength: spec.byteLength, requestedLength: spec.byteLength, baseRegister: spec.baseRegister, displacement: spec.displacementHex, missingPcOffsets: spec.missingPcOffsets };
  } catch (error) {
    return { index: spec.index, label: spec.label, kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointer ? pointer.toString() : null, value: null, byteLength: 0, requestedLength: spec.byteLength, baseRegister: spec.baseRegister, displacement: spec.displacementHex, missingPcOffsets: spec.missingPcOffsets, readError: String(error) };
  }
}

function captureTargetWindows(context, specs) {
  return specs.map(function (spec) { return captureRelativeWindow(context, spec); });
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
        recaptureSourceEventIndices: spec.sourceEventIndices,
        recaptureMissingPcOffsets: spec.missingPcOffsets,
        captureSpecs: spec.captures
      });
      Interceptor.attach(target, {
        onEnter: function () {
          if (emittedHits >= MAX_EVENTS) {
            if (!limitReported) {
              limitReported = true;
              sendRecord(null, 'capture-limit', { error: 'Unicorn recapture hit limit reached: ' + MAX_EVENTS });
            }
            return;
          }
          emittedHits += 1;
          sendRecord(spec, 'hook-enter', {
            target: target.toString(),
            captureOffset: spec.offset,
            recaptureSourceEventIndices: spec.sourceEventIndices,
            recaptureMissingPcOffsets: spec.missingPcOffsets,
            registers: captureRegisters(this.context),
            captures: captureTargetWindows(this.context, spec.captures)
          });
        }
      });
      sendRecord(spec, 'hook-installed', {
        target: target.toString(),
        captureOffset: spec.offset,
        recaptureSourceEventIndices: spec.sourceEventIndices,
        recaptureMissingPcOffsets: spec.missingPcOffsets
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
        "{}-unicorn-recapture-frida-hook.js",
        sanitize_identifier(module_name, "module")
    );
    Ok(FridaUnicornRecaptureHookScript {
        schema_version: FRIDA_UNICORN_RECAPTURE_HOOK_SCHEMA.to_string(),
        module_name: module_name.to_string(),
        file_name,
        expected_binary_sha256: bundle.expected_binary_sha256.to_ascii_lowercase(),
        selected_suggestion_indices,
        targets,
        carried_forward_window_count,
        suggested_window_count,
        unsupported_seed_region_count,
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
        UnicornOllvmConfig, UnicornRecaptureSuggestion, UnicornReplayRun, UnicornSeedRecapturePlan,
        UnicornSeedRecaptureWindow,
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
            runs: Vec::<UnicornReplayRun>::new(),
            transition_matrix: Vec::new(),
            recapture_suggestions: vec![
                UnicornRecaptureSuggestion {
                    pc_offset: "0x180".to_string(),
                    base_register: Some("X19".to_string()),
                    displacement: Some("0x20".to_string()),
                    byte_length: 8,
                    reason: "capture X19+0x20".to_string(),
                    source_event_indices: vec![7],
                },
                UnicornRecaptureSuggestion {
                    pc_offset: "0x184".to_string(),
                    base_register: Some("SP".to_string()),
                    displacement: Some("-0x10".to_string()),
                    byte_length: 16,
                    reason: "capture SP-0x10".to_string(),
                    source_event_indices: vec![7],
                },
            ],
            warnings: Vec::new(),
        }
    }

    fn sample_bundle_with_recapture_plan() -> UnicornOllvmResultBundle {
        let mut bundle = sample_bundle();
        bundle.seed_recapture_plans = vec![UnicornSeedRecapturePlan {
            source_event_index: 7,
            capture_offset: "0x100".to_string(),
            windows: vec![
                UnicornSeedRecaptureWindow {
                    label: "prior-key".to_string(),
                    base_register: "X1".to_string(),
                    displacement: "0x0".to_string(),
                    byte_length: 16,
                    source_kind: "byteArray".to_string(),
                    phase: "enter".to_string(),
                },
                UnicornSeedRecaptureWindow {
                    label: "prior-x19-state".to_string(),
                    base_register: "X19".to_string(),
                    displacement: "0x20".to_string(),
                    byte_length: 8,
                    source_kind: "byteArray".to_string(),
                    phase: "enter".to_string(),
                },
            ],
            carry_forward_bytes: 24,
            unsupported_memory_region_count: 1,
            windows_truncated: true,
        }];
        bundle
    }

    #[test]
    fn generates_exact_seed_recapture_hook_with_positive_and_negative_windows() {
        let generated = generate_frida_unicorn_recapture_hook(
            &sample_bundle(),
            &[0, 1],
            &FridaUnicornRecaptureHookOptions { max_events: 100 },
        )
        .unwrap();
        assert_eq!(
            generated.schema_version,
            FRIDA_UNICORN_RECAPTURE_HOOK_SCHEMA
        );
        assert_eq!(generated.targets.len(), 1);
        assert_eq!(generated.targets[0].offset, "0x100");
        assert_eq!(generated.targets[0].captures.len(), 2);
        assert!(generated.targets[0]
            .captures
            .iter()
            .any(|capture| capture.base_register == "X19" && capture.displacement == 0x20));
        assert!(generated.targets[0]
            .captures
            .iter()
            .any(|capture| capture.base_register == "SP" && capture.displacement == -0x10));
        assert!(generated
            .script
            .contains("Module.getBaseAddress(MODULE_NAME)"));
        assert!(generated.script.contains("Interceptor.attach(target"));
        assert!(generated.script.contains("base.sub(-spec.displacement)"));
        assert!(generated.script.contains("event: event"));
        assert!(generated.script.contains("'hook-enter'"));
        assert!(!generated.script.contains("frida.attach"));
        assert_eq!(generated.carried_forward_window_count, 0);
        assert_eq!(generated.suggested_window_count, 2);
        assert!(generated
            .warnings
            .iter()
            .any(|warning| warning.contains("predates seedRecapturePlans")));
    }

    #[test]
    fn merges_prior_seed_windows_with_new_suggestions_and_deduplicates_overlap() {
        let generated = generate_frida_unicorn_recapture_hook(
            &sample_bundle_with_recapture_plan(),
            &[0, 1],
            &FridaUnicornRecaptureHookOptions::default(),
        )
        .unwrap();
        assert_eq!(generated.targets.len(), 1);
        assert_eq!(generated.targets[0].captures.len(), 3);
        assert_eq!(generated.carried_forward_window_count, 2);
        assert_eq!(generated.suggested_window_count, 2);
        assert_eq!(generated.unsupported_seed_region_count, 1);
        let overlap = generated.targets[0]
            .captures
            .iter()
            .find(|capture| {
                capture.base_register == "X19"
                    && capture.displacement == 0x20
                    && capture.byte_length == 8
            })
            .unwrap();
        assert_eq!(overlap.label, "prior-x19-state");
        assert!(overlap.carried_forward);
        assert!(overlap.suggested);
        assert!(overlap
            .source_labels
            .contains(&"prior-x19-state".to_string()));
        assert!(overlap
            .source_labels
            .iter()
            .any(|label| label.starts_with("unicorn-recapture-x19-plus-20")));
        assert!(generated
            .warnings
            .iter()
            .any(|warning| warning.contains("without a verified X0-X28/SP-relative")));
        assert!(generated
            .warnings
            .iter()
            .any(|warning| warning.contains("256-window recapture-plan limit")));
    }

    #[test]
    fn rejects_absolute_and_unsupported_register_suggestions() {
        let mut bundle = sample_bundle();
        bundle.recapture_suggestions[0].base_register = None;
        let error = generate_frida_unicorn_recapture_hook(
            &bundle,
            &[0],
            &FridaUnicornRecaptureHookOptions::default(),
        )
        .unwrap_err();
        assert!(error.contains("no register-relative expression"));

        bundle.recapture_suggestions[0].base_register = Some("X29".to_string());
        let error = generate_frida_unicorn_recapture_hook(
            &bundle,
            &[0],
            &FridaUnicornRecaptureHookOptions::default(),
        )
        .unwrap_err();
        assert!(error.contains("X0-X28 or SP"));

        let mut bundle = sample_bundle();
        bundle.recapture_suggestions[0].displacement = Some("0x100000".to_string());
        let error = generate_frida_unicorn_recapture_hook(
            &bundle,
            &[0],
            &FridaUnicornRecaptureHookOptions::default(),
        )
        .unwrap_err();
        assert!(error.contains("remain within +/- 1 MiB"));
    }

    #[test]
    fn rejects_unknown_suggestion_index_and_unbounded_event_limit() {
        let error = generate_frida_unicorn_recapture_hook(
            &sample_bundle(),
            &[9],
            &FridaUnicornRecaptureHookOptions::default(),
        )
        .unwrap_err();
        assert!(error.contains("out of range"));

        let error = generate_frida_unicorn_recapture_hook(
            &sample_bundle(),
            &[0],
            &FridaUnicornRecaptureHookOptions { max_events: 0 },
        )
        .unwrap_err();
        assert!(error.contains("event limit"));
    }

    #[test]
    fn recapture_hook_event_round_trips_into_an_angr_state_seed() {
        let generated = generate_frida_unicorn_recapture_hook(
            &sample_bundle(),
            &[0, 1],
            &FridaUnicornRecaptureHookOptions::default(),
        )
        .unwrap();
        let target = &generated.targets[0];
        let x19_capture = target
            .captures
            .iter()
            .find(|capture| capture.base_register == "X19")
            .unwrap();
        let sp_capture = target
            .captures
            .iter()
            .find(|capture| capture.base_register == "SP")
            .unwrap();
        let capture = serde_json::json!([{
            "protocol": FRIDA_HOOK_PROTOCOL,
            "eventId": "recapture:test:event:1",
            "hookId": target.hook_id,
            "event": "hook-enter",
            "functionName": "unicorn-recapture-100",
            "moduleName": generated.module_name,
            "moduleBase": "0x71000000",
            "moduleSize": 0x4000,
            "target": "0x71000100",
            "captureOffset": target.offset,
            "timestampMs": 1,
            "threadId": 7,
            "registers": {
                "x19": "0x90000000",
                "sp": "0xa0001000",
                "pc": "0x71000100",
                "nzcv": "0x60000000"
            },
            "captures": [
                {
                    "index": x19_capture.index,
                    "label": x19_capture.label,
                    "kind": "byteArray",
                    "direction": "input",
                    "phase": "enter",
                    "pointer": "0x90000020",
                    "value": "0011223344556677",
                    "byteLength": 8,
                    "requestedLength": 8,
                    "baseRegister": x19_capture.base_register,
                    "displacement": x19_capture.displacement_hex,
                    "missingPcOffsets": x19_capture.missing_pc_offsets
                },
                {
                    "index": sp_capture.index,
                    "label": sp_capture.label,
                    "kind": "byteArray",
                    "direction": "input",
                    "phase": "enter",
                    "pointer": "0xa0000ff0",
                    "value": "000102030405060708090a0b0c0d0e0f",
                    "byteLength": 16,
                    "requestedLength": 16,
                    "baseRegister": sp_capture.base_register,
                    "displacement": sp_capture.displacement_hex,
                    "missingPcOffsets": sp_capture.missing_pc_offsets
                }
            ]
        }]);

        let bundle = parse_frida_capture_bundle(&serde_json::to_vec(&capture).unwrap()).unwrap();
        assert_eq!(bundle.events.len(), 1);
        assert_eq!(
            bundle.events[0].module_name.as_deref(),
            Some("libtarget.so")
        );
        let seed = generate_angr_state_seed(&bundle, 0, true, true).unwrap();
        assert_eq!(seed.capture_offset.as_deref(), Some("0x100"));
        assert!(seed.memory_regions.iter().any(|region| {
            region.label == x19_capture.label
                && region.address == "0x90000020"
                && region.bytes_hex == "0011223344556677"
        }));
        assert!(seed.memory_regions.iter().any(|region| {
            region.label == sp_capture.label
                && region.address == "0xa0000ff0"
                && region.bytes_hex == "000102030405060708090a0b0c0d0e0f"
        }));
        assert!(seed.script.contains("state.regs.x19"));
        assert!(seed.script.contains("state.regs.sp"));
        assert!(seed.script.contains("bytes.fromhex(\"0011223344556677\")"));
    }

    #[test]
    fn second_round_seed_contains_prior_and_newly_recaptured_memory() {
        let generated = generate_frida_unicorn_recapture_hook(
            &sample_bundle_with_recapture_plan(),
            &[0, 1],
            &FridaUnicornRecaptureHookOptions::default(),
        )
        .unwrap();
        let target = &generated.targets[0];
        let prior_key = target
            .captures
            .iter()
            .find(|capture| capture.base_register == "X1")
            .unwrap();
        let overlap = target
            .captures
            .iter()
            .find(|capture| capture.base_register == "X19")
            .unwrap();
        let new_stack = target
            .captures
            .iter()
            .find(|capture| capture.base_register == "SP")
            .unwrap();
        let capture = serde_json::json!([{
            "protocol": FRIDA_HOOK_PROTOCOL,
            "eventId": "recapture:test:event:2",
            "hookId": target.hook_id,
            "event": "hook-enter",
            "functionName": "unicorn-recapture-100",
            "moduleName": generated.module_name,
            "moduleBase": "0x71000000",
            "moduleSize": 0x4000,
            "target": "0x71000100",
            "captureOffset": target.offset,
            "timestampMs": 2,
            "threadId": 7,
            "registers": {
                "x1": "0x80000000",
                "x19": "0x90000000",
                "sp": "0xa0001000",
                "pc": "0x71000100"
            },
            "captures": [
                {
                    "index": prior_key.index,
                    "label": prior_key.label,
                    "kind": "byteArray",
                    "direction": "input",
                    "phase": "enter",
                    "pointer": "0x80000000",
                    "value": "000102030405060708090a0b0c0d0e0f",
                    "byteLength": 16,
                    "requestedLength": 16,
                    "baseRegister": prior_key.base_register,
                    "displacement": prior_key.displacement_hex
                },
                {
                    "index": overlap.index,
                    "label": overlap.label,
                    "kind": "byteArray",
                    "direction": "input",
                    "phase": "enter",
                    "pointer": "0x90000020",
                    "value": "0011223344556677",
                    "byteLength": 8,
                    "requestedLength": 8,
                    "baseRegister": overlap.base_register,
                    "displacement": overlap.displacement_hex
                },
                {
                    "index": new_stack.index,
                    "label": new_stack.label,
                    "kind": "byteArray",
                    "direction": "input",
                    "phase": "enter",
                    "pointer": "0xa0000ff0",
                    "value": "101112131415161718191a1b1c1d1e1f",
                    "byteLength": 16,
                    "requestedLength": 16,
                    "baseRegister": new_stack.base_register,
                    "displacement": new_stack.displacement_hex
                }
            ]
        }]);
        let parsed = parse_frida_capture_bundle(&serde_json::to_vec(&capture).unwrap()).unwrap();
        let seed = generate_angr_state_seed(&parsed, 0, true, true).unwrap();
        assert_eq!(seed.memory_regions.len(), 3);
        assert!(seed.memory_regions.iter().any(|region| {
            region.label == "prior-key"
                && region.base_register.as_deref() == Some("X1")
                && region.displacement.as_deref() == Some("0x0")
        }));
        assert!(seed.memory_regions.iter().any(|region| {
            region.label == "prior-x19-state"
                && region.base_register.as_deref() == Some("X19")
                && region.displacement.as_deref() == Some("0x20")
        }));
        assert!(seed.memory_regions.iter().any(|region| {
            region.base_register.as_deref() == Some("SP")
                && region.displacement.as_deref() == Some("-0x10")
        }));
    }

    #[test]
    fn generated_recapture_hook_has_valid_javascript_syntax_when_node_is_available() {
        use std::process::Command;

        if !Command::new("node")
            .arg("--version")
            .status()
            .is_ok_and(|status| status.success())
        {
            eprintln!("skipping generated recapture JavaScript syntax check: Node.js unavailable");
            return;
        }
        let generated = generate_frida_unicorn_recapture_hook(
            &sample_bundle(),
            &[0, 1],
            &FridaUnicornRecaptureHookOptions::default(),
        )
        .unwrap();
        let path = std::env::temp_dir().join(format!(
            "trace-ui-unicorn-recapture-{}.js",
            std::process::id()
        ));
        std::fs::write(&path, &generated.script).unwrap();
        let output = Command::new("node")
            .arg("--check")
            .arg(&path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            output.status.success(),
            "generated recapture JavaScript failed syntax check: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
