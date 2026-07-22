use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::query::frida_capture::{FridaCaptureBundle, FridaCaptureEvent};
use crate::query::ollvm::{DispatcherCandidate, OllvmReport};
use crate::utils::parse_hex_addr;

const FRIDA_OLLVM_HOOK_SCHEMA: &str = "trace-ui/frida-ollvm-dispatcher-hook-v1";
const FRIDA_OLLVM_ATLAS_SCHEMA: &str = "trace-ui/frida-ollvm-dispatcher-atlas-v1";
const FRIDA_HOOK_PROTOCOL: &str = "trace-ui/frida-hook-v1";

fn default_max_dispatchers() -> u32 {
    12
}

fn default_idle_gap_ms() -> u32 {
    1_000
}

fn default_max_events() -> u32 {
    50_000
}

fn default_pointer_capture_bytes() -> u32 {
    64
}

fn default_max_values_per_register() -> u32 {
    64
}

fn default_max_state_changes_per_transition() -> u32 {
    128
}

fn default_max_flow_length() -> u32 {
    256
}

fn default_max_flows() -> u32 {
    2_048
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmDispatcherHookOptions {
    #[serde(default = "default_max_dispatchers")]
    pub max_dispatchers: u32,
    #[serde(default = "default_idle_gap_ms")]
    pub idle_gap_ms: u32,
    #[serde(default = "default_max_events")]
    pub max_events: u32,
    #[serde(default)]
    pub capture_pointer_registers: Vec<u8>,
    #[serde(default = "default_pointer_capture_bytes")]
    pub pointer_capture_bytes: u32,
}

impl Default for FridaOllvmDispatcherHookOptions {
    fn default() -> Self {
        Self {
            max_dispatchers: default_max_dispatchers(),
            idle_gap_ms: default_idle_gap_ms(),
            max_events: default_max_events(),
            capture_pointer_registers: Vec::new(),
            pointer_capture_bytes: default_pointer_capture_bytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmDispatcherAtlasOptions {
    #[serde(default = "default_idle_gap_ms")]
    pub idle_gap_ms: u32,
    #[serde(default = "default_max_events")]
    pub max_events: u32,
    #[serde(default = "default_max_values_per_register")]
    pub max_values_per_register: u32,
    #[serde(default = "default_max_state_changes_per_transition")]
    pub max_state_changes_per_transition: u32,
    #[serde(default = "default_max_flow_length")]
    pub max_flow_length: u32,
    #[serde(default = "default_max_flows")]
    pub max_flows: u32,
}

impl Default for FridaOllvmDispatcherAtlasOptions {
    fn default() -> Self {
        Self {
            idle_gap_ms: default_idle_gap_ms(),
            max_events: default_max_events(),
            max_values_per_register: default_max_values_per_register(),
            max_state_changes_per_transition: default_max_state_changes_per_transition(),
            max_flow_length: default_max_flow_length(),
            max_flows: default_max_flows(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmDispatcherHookTarget {
    pub hook_id: String,
    pub block_id: String,
    pub offset: String,
    pub state_registers: Vec<String>,
    pub score: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmDispatcherHookScript {
    pub schema_version: String,
    pub module_name: String,
    pub file_name: String,
    pub targets: Vec<FridaOllvmDispatcherHookTarget>,
    pub idle_gap_ms: u32,
    pub max_events: u32,
    pub capture_pointer_registers: Vec<u8>,
    pub pointer_capture_bytes: u32,
    pub script: String,
    pub warnings: Vec<String>,
    pub protocol_version: String,
    pub frida_api_version: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmStateValueCount {
    pub value: String,
    pub execution_count: u64,
    pub first_event_index: u64,
    pub last_event_index: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmRegisterValueSummary {
    pub register: String,
    pub observed_count: u64,
    pub missing_count: u64,
    pub values: Vec<FridaOllvmStateValueCount>,
    pub values_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmDispatcherNode {
    pub block_id: String,
    pub offset: String,
    pub event_count: u64,
    pub thread_count: u64,
    pub flow_count: u64,
    pub state_registers: Vec<String>,
    pub register_values: Vec<FridaOllvmRegisterValueSummary>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmStateChange {
    pub register: String,
    pub from_value: String,
    pub to_value: String,
    pub execution_count: u64,
    pub sample_from_event_index: u64,
    pub sample_to_event_index: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmDispatcherTransition {
    pub from_offset: String,
    pub to_offset: String,
    pub execution_count: u64,
    pub thread_count: u64,
    pub flow_count: u64,
    pub sample_from_event_index: u64,
    pub sample_to_event_index: u64,
    pub state_changes: Vec<FridaOllvmStateChange>,
    pub state_changes_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmDispatcherFlow {
    pub flow_id: String,
    pub capture_session_id: Option<String>,
    pub thread_id: u64,
    pub event_count: u64,
    pub first_event_index: u64,
    pub last_event_index: u64,
    pub offsets: Vec<String>,
    pub offsets_truncated: bool,
    pub explicit_flow_id: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaOllvmDispatcherAtlas {
    pub schema_version: String,
    pub module_name: String,
    pub source_format: String,
    pub matched_event_count: u64,
    pub skipped_event_count: u64,
    pub thread_count: u64,
    pub flow_count: u64,
    pub explicit_flow_count: u64,
    pub derived_flow_count: u64,
    pub nodes: Vec<FridaOllvmDispatcherNode>,
    pub transitions: Vec<FridaOllvmDispatcherTransition>,
    pub flows: Vec<FridaOllvmDispatcherFlow>,
    pub flows_truncated: bool,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

fn validate_hook_options(options: &FridaOllvmDispatcherHookOptions) -> Result<(), String> {
    if !(1..=64).contains(&options.max_dispatchers) {
        return Err("Frida OLLVM dispatcher target count must be between 1 and 64".to_string());
    }
    if !(1..=600_000).contains(&options.idle_gap_ms) {
        return Err("Frida OLLVM flow idle gap must be between 1 and 600000 ms".to_string());
    }
    if !(1..=200_000).contains(&options.max_events) {
        return Err("Frida OLLVM capture event limit must be between 1 and 200000".to_string());
    }
    let pointer_registers = options
        .capture_pointer_registers
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    if options.capture_pointer_registers.len() > 8
        || pointer_registers.len() != options.capture_pointer_registers.len()
        || options
            .capture_pointer_registers
            .iter()
            .any(|index| *index > 7)
    {
        return Err(
            "Frida OLLVM pointer capture registers must be unique X0-X7 entries (maximum 8)"
                .to_string(),
        );
    }
    if !(1..=4096).contains(&options.pointer_capture_bytes) {
        return Err("Frida OLLVM pointer capture bytes must be between 1 and 4096".to_string());
    }
    Ok(())
}

fn validate_atlas_options(options: &FridaOllvmDispatcherAtlasOptions) -> Result<(), String> {
    if !(1..=600_000).contains(&options.idle_gap_ms) {
        return Err("Frida OLLVM flow idle gap must be between 1 and 600000 ms".to_string());
    }
    if !(1..=200_000).contains(&options.max_events) {
        return Err("Frida OLLVM atlas event limit must be between 1 and 200000".to_string());
    }
    if !(1..=256).contains(&options.max_values_per_register) {
        return Err("Frida OLLVM state values per register must be between 1 and 256".to_string());
    }
    if !(1..=1_024).contains(&options.max_state_changes_per_transition) {
        return Err(
            "Frida OLLVM state changes per transition must be between 1 and 1024".to_string(),
        );
    }
    if !(1..=4_096).contains(&options.max_flow_length) {
        return Err("Frida OLLVM flow length must be between 1 and 4096".to_string());
    }
    if !(1..=10_000).contains(&options.max_flows) {
        return Err("Frida OLLVM returned flow count must be between 1 and 10000".to_string());
    }
    Ok(())
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

fn normalized_offset(value: &str) -> Result<String, String> {
    parse_hex_addr(value).map(|offset| format!("0x{offset:x}"))
}

pub fn generate_frida_ollvm_dispatcher_hook(
    report: &OllvmReport,
    options: &FridaOllvmDispatcherHookOptions,
) -> Result<FridaOllvmDispatcherHookScript, String> {
    validate_hook_options(options)?;
    let module_name = report.scope.module_name.trim();
    if module_name.is_empty() || module_name.chars().any(|character| character.is_control()) {
        return Err("OLLVM report module name must be a non-empty printable name".to_string());
    }
    let mut candidates = report.dispatcher_candidates.iter().collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| {
        (
            Reverse(candidate.assessment.score),
            parse_hex_addr(&candidate.start_offset).unwrap_or(u64::MAX),
        )
    });
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for candidate in candidates
        .into_iter()
        .take(options.max_dispatchers as usize)
    {
        let offset = normalized_offset(&candidate.start_offset)?;
        if !seen.insert(offset.clone()) {
            continue;
        }
        let offset_stem = offset.trim_start_matches("0x");
        targets.push(FridaOllvmDispatcherHookTarget {
            hook_id: format!("ollvm-dispatcher-{offset_stem}"),
            block_id: candidate.block_id.clone(),
            offset,
            state_registers: candidate.state_registers.clone(),
            score: candidate.assessment.score,
        });
    }
    if targets.is_empty() {
        return Err("OLLVM report has no dispatcher candidates to hook".to_string());
    }
    let file_name = format!(
        "{}-ollvm-dispatchers-frida-hook.js",
        sanitize_identifier(module_name, "module")
    );
    let module_json = serde_json::to_string(module_name)
        .map_err(|error| format!("serialize module name failed: {error}"))?;
    let targets_json = serde_json::to_string(&targets)
        .map_err(|error| format!("serialize dispatcher targets failed: {error}"))?;
    let mut capture_pointer_registers = options.capture_pointer_registers.clone();
    capture_pointer_registers.sort_unstable();
    let pointer_registers_json = serde_json::to_string(&capture_pointer_registers)
        .map_err(|error| format!("serialize pointer capture registers failed: {error}"))?;
    let template = r##"/* Trace UI OLLVM dispatcher capture hook
 * Frida JavaScript API target: 16.x
 * Generated schema: trace-ui/frida-ollvm-dispatcher-hook-v1
 * Event protocol: trace-ui/frida-hook-v1
 * Execute manually with your preferred Frida 16 host or CLI.
 * Trace UI never attaches, spawns, loads, or executes this script.
 */
'use strict';

const TRACE_UI_PROTOCOL = 'trace-ui/frida-hook-v1';
const MODULE_NAME = __MODULE_NAME__;
const TARGETS = __TARGETS__;
const IDLE_GAP_MS = __IDLE_GAP_MS__;
const MAX_EVENTS = __MAX_EVENTS__;
const POINTER_CAPTURE_REGISTERS = __POINTER_CAPTURE_REGISTERS__;
const POINTER_CAPTURE_BYTES = __POINTER_CAPTURE_BYTES__;
const CAPTURE_SESSION_ID = 'ollvm:' + Date.now().toString(16) + ':' + Process.id;
let resolvedModuleBase = null;
let resolvedModuleSize = 0;
let nextEventId = 1;
let emittedHits = 0;
let limitReported = false;
const threadFlows = {};
const threadFlowCounters = {};

function sendRecord(spec, event, payload) {
  const record = Object.assign({
    protocol: TRACE_UI_PROTOCOL,
    eventId: CAPTURE_SESSION_ID + ':event:' + (nextEventId++),
    hookId: spec ? spec.hookId : 'ollvm-dispatcher-capture',
    event: event,
    functionName: spec ? ('ollvm-dispatcher-' + spec.offset.slice(2)) : 'ollvm-dispatcher-capture',
    moduleName: MODULE_NAME,
    moduleBase: resolvedModuleBase !== null ? resolvedModuleBase.toString() : null,
    moduleSize: resolvedModuleSize,
    captureSessionId: CAPTURE_SESSION_ID,
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

function capturePointerRegisters(context) {
  const captures = [];
  POINTER_CAPTURE_REGISTERS.forEach(function (index) {
    const name = 'x' + index;
    let pointer = null;
    try {
      pointer = context[name];
      const pointerText = pointer !== null && pointer !== undefined ? pointer.toString() : null;
      if (!pointerText || pointerText === '0x0') {
        captures.push({ index: index, label: name + '-memory', kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointerText, value: null, byteLength: 0, requestedLength: POINTER_CAPTURE_BYTES, readError: 'null pointer' });
        return;
      }
      const bytes = pointer.readByteArray(POINTER_CAPTURE_BYTES);
      if (bytes === null) {
        captures.push({ index: index, label: name + '-memory', kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointerText, value: null, byteLength: 0, requestedLength: POINTER_CAPTURE_BYTES, readError: 'readByteArray returned null' });
        return;
      }
      const array = new Uint8Array(bytes);
      let value = '';
      for (let i = 0; i < array.length; i++) value += ('0' + array[i].toString(16)).slice(-2);
      captures.push({ index: index, label: name + '-memory', kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointerText, value: value, byteLength: array.length, requestedLength: POINTER_CAPTURE_BYTES });
    } catch (error) {
      captures.push({ index: index, label: name + '-memory', kind: 'byteArray', direction: 'input', phase: 'enter', pointer: pointer ? pointer.toString() : null, value: null, byteLength: 0, requestedLength: POINTER_CAPTURE_BYTES, readError: String(error) });
    }
  });
  return captures;
}

function nextFlow(threadId, now) {
  const key = String(threadId);
  let state = threadFlows[key];
  if (!state || now < state.lastTimestampMs || now - state.lastTimestampMs > IDLE_GAP_MS) {
    const counter = (threadFlowCounters[key] || 0) + 1;
    threadFlowCounters[key] = counter;
    state = {
      flowId: CAPTURE_SESSION_ID + ':thread:' + key + ':flow:' + counter,
      hitSequence: 0,
      lastTimestampMs: now
    };
    threadFlows[key] = state;
  }
  state.hitSequence += 1;
  state.lastTimestampMs = now;
  return state;
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
    let target;
    try {
      target = resolvedModuleBase.add(ptr(spec.offset));
      sendRecord(spec, 'hook-ready', {
        target: target.toString(),
        dispatcherOffset: spec.offset,
        candidateStateRegisters: spec.stateRegisters
      });
      Interceptor.attach(target, {
        onEnter: function () {
          if (emittedHits >= MAX_EVENTS) {
            if (!limitReported) {
              limitReported = true;
              sendRecord(null, 'capture-limit', { error: 'dispatcher hit limit reached: ' + MAX_EVENTS });
            }
            return;
          }
          emittedHits += 1;
          const now = Date.now();
          const threadId = Process.getCurrentThreadId();
          const flow = nextFlow(threadId, now);
          sendRecord(spec, 'ollvm-dispatcher-hit', {
            timestampMs: now,
            threadId: threadId,
            target: target.toString(),
            dispatcherOffset: spec.offset,
            flowId: flow.flowId,
            hitSequence: flow.hitSequence,
            candidateStateRegisters: spec.stateRegisters,
            registers: captureRegisters(this.context),
            captures: capturePointerRegisters(this.context)
          });
        }
      });
      sendRecord(spec, 'hook-installed', {
        target: target.toString(),
        dispatcherOffset: spec.offset,
        candidateStateRegisters: spec.stateRegisters
      });
    } catch (error) {
      sendRecord(spec, 'hook-error', {
        target: target ? target.toString() : null,
        dispatcherOffset: spec.offset,
        error: String(error)
      });
    }
  });
}

setImmediate(install);
"##;
    let script = template
        .replace("__MODULE_NAME__", &module_json)
        .replace("__TARGETS__", &targets_json)
        .replace("__IDLE_GAP_MS__", &options.idle_gap_ms.to_string())
        .replace("__MAX_EVENTS__", &options.max_events.to_string())
        .replace("__POINTER_CAPTURE_REGISTERS__", &pointer_registers_json)
        .replace(
            "__POINTER_CAPTURE_BYTES__",
            &options.pointer_capture_bytes.to_string(),
        );
    Ok(FridaOllvmDispatcherHookScript {
        schema_version: FRIDA_OLLVM_HOOK_SCHEMA.to_string(),
        module_name: module_name.to_string(),
        file_name,
        targets,
        idle_gap_ms: options.idle_gap_ms,
        max_events: options.max_events,
        script,
        warnings: vec![
            "This Frida 16.x script is generated only. The user manually attaches/spawns/loads/runs it; Trace UI performs no runtime Frida control.".to_string(),
            "Each target is an exact module-relative dispatcher candidate startOffset from the current dynamic OLLVM report; confirm the loaded module is the same binary build.".to_string(),
            "Flow IDs split a thread after the configured idle gap. They are capture-session grouping aids, not proof of function-invocation boundaries.".to_string(),
            "The script captures full ARM64 GPR context at dispatcher hits and emits bounded trace-ui/frida-hook-v1 events for manual import.".to_string(),
            "Pointer-register memory capture is opt-in, limited to X0-X7 and the configured byte count; unreadable pointers are reported as readError without retrying unbounded reads.".to_string(),
        ],
        protocol_version: FRIDA_HOOK_PROTOCOL.to_string(),
        frida_api_version: "16.x".to_string(),
        capture_pointer_registers,
        pointer_capture_bytes: options.pointer_capture_bytes,
    })
}

#[derive(Clone)]
struct HitPoint {
    event_index: u64,
    thread_id: u64,
    capture_session_id: String,
    flow_id: String,
    explicit_flow_id: bool,
    hit_sequence: Option<u64>,
    offset: String,
    registers: BTreeMap<String, String>,
}

#[derive(Default)]
struct ValueAgg {
    execution_count: u64,
    first_event_index: u64,
    last_event_index: u64,
}

#[derive(Default)]
struct RegisterAgg {
    observed_count: u64,
    missing_count: u64,
    values: BTreeMap<String, ValueAgg>,
    truncated: bool,
}

struct NodeAgg {
    block_id: String,
    offset: String,
    event_count: u64,
    threads: BTreeSet<String>,
    flows: BTreeSet<String>,
    state_registers: Vec<String>,
    registers: BTreeMap<String, RegisterAgg>,
}

#[derive(Default)]
struct ChangeAgg {
    execution_count: u64,
    sample_from_event_index: u64,
    sample_to_event_index: u64,
}

struct TransitionAgg {
    execution_count: u64,
    threads: BTreeSet<String>,
    flows: BTreeSet<String>,
    sample_from_event_index: u64,
    sample_to_event_index: u64,
    changes: BTreeMap<(String, String, String), ChangeAgg>,
    changes_truncated: bool,
}

struct FlowAgg {
    flow_id: String,
    capture_session_id: Option<String>,
    thread_id: u64,
    event_count: u64,
    first_event_index: u64,
    last_event_index: u64,
    offsets: Vec<String>,
    offsets_truncated: bool,
    explicit_flow_id: bool,
}

#[derive(Default)]
struct DerivedFlowState {
    counter: u64,
    last_timestamp_ms: Option<u64>,
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 500 && !warnings.contains(&warning) {
        warnings.push(warning);
    } else if warnings.len() == 500 {
        warnings.push("Additional dispatcher capture warnings were omitted.".to_string());
    }
}

fn runtime_event_offset(event: &FridaCaptureEvent) -> Result<Option<String>, String> {
    let explicit = event
        .dispatcher_offset
        .as_deref()
        .map(normalized_offset)
        .transpose()?;
    let runtime = match (event.module_base.as_deref(), event.target.as_deref()) {
        (Some(base), Some(target)) => {
            let base = parse_hex_addr(base)?;
            let target = parse_hex_addr(target)?;
            if target < base {
                return Err(format!(
                    "event {} target is below its module base",
                    event.index
                ));
            }
            let offset = target - base;
            if event
                .module_size
                .is_some_and(|size| size > 0 && offset >= size)
            {
                return Err(format!(
                    "event {} target is outside its reported module size",
                    event.index
                ));
            }
            Some(format!("0x{offset:x}"))
        }
        _ => None,
    };
    if let (Some(explicit), Some(runtime)) = (&explicit, &runtime) {
        if !explicit.eq_ignore_ascii_case(runtime) {
            return Err(format!(
                "event {} dispatcherOffset {} disagrees with target-moduleBase {}",
                event.index, explicit, runtime
            ));
        }
    }
    Ok(explicit.or(runtime))
}

fn thread_key(session: &str, thread_id: u64) -> String {
    format!("{session}:thread:{thread_id}")
}

fn flow_key(session: &str, thread_id: u64, flow_id: &str) -> String {
    format!("{session}:thread:{thread_id}:flow:{flow_id}")
}

pub fn analyze_frida_ollvm_dispatcher_capture(
    report: &OllvmReport,
    bundle: &FridaCaptureBundle,
    options: &FridaOllvmDispatcherAtlasOptions,
) -> Result<FridaOllvmDispatcherAtlas, String> {
    validate_atlas_options(options)?;
    let module_name = report.scope.module_name.trim();
    if module_name.is_empty() {
        return Err("OLLVM report module name must not be empty".to_string());
    }
    if report.dispatcher_candidates.is_empty() {
        return Err("OLLVM report has no dispatcher candidates to reconcile".to_string());
    }
    let mut candidates = HashMap::<String, DispatcherCandidate>::new();
    for candidate in &report.dispatcher_candidates {
        candidates.insert(
            normalized_offset(&candidate.start_offset)?,
            candidate.clone(),
        );
    }
    let mut warnings = bundle.warnings.clone();
    warnings.truncate(500);
    let mut hits = Vec::new();
    let mut skipped_event_count = 0u64;
    let mut derived_states = HashMap::<(String, u64), DerivedFlowState>::new();
    let mut warned_zero_timestamp = false;

    for event in &bundle.events {
        if event.event != "ollvm-dispatcher-hit" && event.event != "hook-enter" {
            continue;
        }
        if hits.len() >= options.max_events as usize {
            push_warning(
                &mut warnings,
                format!(
                    "Dispatcher atlas stopped after the configured {} matched events.",
                    options.max_events
                ),
            );
            break;
        }
        if event.module_name.as_deref() != Some(module_name) {
            skipped_event_count += 1;
            continue;
        }
        let offset = match runtime_event_offset(event) {
            Ok(Some(offset)) => offset,
            Ok(None) => {
                skipped_event_count += 1;
                push_warning(
                    &mut warnings,
                    format!(
                        "Ignored dispatcher event {} without dispatcherOffset or target/moduleBase metadata.",
                        event.index
                    ),
                );
                continue;
            }
            Err(error) => {
                skipped_event_count += 1;
                push_warning(&mut warnings, error);
                continue;
            }
        };
        if !candidates.contains_key(&offset) {
            skipped_event_count += 1;
            continue;
        }
        if event.registers.is_empty() {
            skipped_event_count += 1;
            push_warning(
                &mut warnings,
                format!(
                    "Ignored dispatcher event {} without registers.",
                    event.index
                ),
            );
            continue;
        }
        let capture_session_id = event
            .capture_session_id
            .as_deref()
            .filter(|value| !value.trim().is_empty() && value.len() <= 256)
            .unwrap_or("unknown-session")
            .to_string();
        let explicit_flow_id = event
            .flow_id
            .as_deref()
            .filter(|value| !value.trim().is_empty() && value.len() <= 256)
            .map(ToOwned::to_owned);
        let (flow_id, explicit) = if let Some(flow_id) = explicit_flow_id {
            (flow_id, true)
        } else {
            let state = derived_states
                .entry((capture_session_id.clone(), event.thread_id))
                .or_default();
            let new_flow = match state.last_timestamp_ms {
                None => true,
                Some(previous) if event.timestamp_ms == 0 || previous == 0 => false,
                Some(previous) => {
                    event.timestamp_ms < previous
                        || event.timestamp_ms.saturating_sub(previous) > options.idle_gap_ms as u64
                }
            };
            if new_flow {
                state.counter += 1;
            }
            if event.timestamp_ms == 0 && !warned_zero_timestamp {
                warned_zero_timestamp = true;
                push_warning(
                    &mut warnings,
                    "Capture events without timestamps are grouped into one derived flow per thread; regenerate with the dedicated dispatcher script for explicit flow IDs.".to_string(),
                );
            }
            state.last_timestamp_ms = Some(event.timestamp_ms);
            (format!("derived:{}", state.counter.max(1)), false)
        };
        hits.push(HitPoint {
            event_index: event.index,
            thread_id: event.thread_id,
            capture_session_id,
            flow_id,
            explicit_flow_id: explicit,
            hit_sequence: event.hit_sequence,
            offset,
            registers: event.registers.clone(),
        });
    }
    if hits.is_empty() {
        return Err(format!(
            "No user-captured dispatcher events exactly matched module {module_name} and the current OLLVM dispatcher startOffsets"
        ));
    }

    let mut nodes = BTreeMap::<String, NodeAgg>::new();
    let mut transitions = BTreeMap::<(String, String), TransitionAgg>::new();
    let mut flows = BTreeMap::<String, FlowAgg>::new();
    let mut flows_truncated = false;
    let mut all_threads = BTreeSet::new();
    let mut all_flows = BTreeSet::new();
    let mut explicit_flows = BTreeSet::new();
    let mut derived_flows = BTreeSet::new();
    let mut previous_by_thread = HashMap::<String, HitPoint>::new();

    for hit in hits {
        let candidate = candidates
            .get(&hit.offset)
            .expect("matched candidate offset");
        let thread = thread_key(&hit.capture_session_id, hit.thread_id);
        let flow = flow_key(&hit.capture_session_id, hit.thread_id, &hit.flow_id);
        all_threads.insert(thread.clone());
        all_flows.insert(flow.clone());
        if hit.explicit_flow_id {
            explicit_flows.insert(flow.clone());
        } else {
            derived_flows.insert(flow.clone());
        }

        let node = nodes.entry(hit.offset.clone()).or_insert_with(|| NodeAgg {
            block_id: candidate.block_id.clone(),
            offset: hit.offset.clone(),
            event_count: 0,
            threads: BTreeSet::new(),
            flows: BTreeSet::new(),
            state_registers: candidate.state_registers.clone(),
            registers: candidate
                .state_registers
                .iter()
                .map(|register| (register.clone(), RegisterAgg::default()))
                .collect(),
        });
        node.event_count += 1;
        node.threads.insert(thread.clone());
        node.flows.insert(flow.clone());
        for register in &node.state_registers {
            let summary = node
                .registers
                .get_mut(register)
                .expect("initialized state register");
            if let Some(value) = hit
                .registers
                .get(&register.to_ascii_lowercase())
                .and_then(|value| parse_hex_addr(value).ok())
                .map(|value| format!("0x{value:x}"))
            {
                summary.observed_count += 1;
                if let Some(existing) = summary.values.get_mut(&value) {
                    existing.execution_count += 1;
                    existing.last_event_index = hit.event_index;
                } else if summary.values.len() < options.max_values_per_register as usize {
                    summary.values.insert(
                        value,
                        ValueAgg {
                            execution_count: 1,
                            first_event_index: hit.event_index,
                            last_event_index: hit.event_index,
                        },
                    );
                } else {
                    summary.truncated = true;
                }
            } else {
                summary.missing_count += 1;
            }
        }

        if let Some(previous) = previous_by_thread.get(&thread) {
            let same_flow = previous.flow_id == hit.flow_id
                && previous.capture_session_id == hit.capture_session_id;
            let sequence_contiguous = match (previous.hit_sequence, hit.hit_sequence) {
                (Some(left), Some(right)) => right == left.saturating_add(1),
                _ => true,
            };
            if same_flow && sequence_contiguous {
                let transition = transitions
                    .entry((previous.offset.clone(), hit.offset.clone()))
                    .or_insert_with(|| TransitionAgg {
                        execution_count: 0,
                        threads: BTreeSet::new(),
                        flows: BTreeSet::new(),
                        sample_from_event_index: previous.event_index,
                        sample_to_event_index: hit.event_index,
                        changes: BTreeMap::new(),
                        changes_truncated: false,
                    });
                transition.execution_count += 1;
                transition.threads.insert(thread.clone());
                transition.flows.insert(flow.clone());
                let from_candidate = candidates
                    .get(&previous.offset)
                    .expect("previous candidate offset");
                let from_registers = from_candidate
                    .state_registers
                    .iter()
                    .map(|register| register.to_ascii_lowercase())
                    .collect::<BTreeSet<_>>();
                let to_registers = candidate
                    .state_registers
                    .iter()
                    .map(|register| register.to_ascii_lowercase())
                    .collect::<BTreeSet<_>>();
                for register in from_registers.intersection(&to_registers) {
                    let from_value = previous
                        .registers
                        .get(register)
                        .and_then(|value| parse_hex_addr(value).ok())
                        .map(|value| format!("0x{value:x}"));
                    let to_value = hit
                        .registers
                        .get(register)
                        .and_then(|value| parse_hex_addr(value).ok())
                        .map(|value| format!("0x{value:x}"));
                    let (Some(from_value), Some(to_value)) = (from_value, to_value) else {
                        continue;
                    };
                    let key = (register.to_ascii_uppercase(), from_value, to_value);
                    if let Some(change) = transition.changes.get_mut(&key) {
                        change.execution_count += 1;
                    } else if transition.changes.len()
                        < options.max_state_changes_per_transition as usize
                    {
                        transition.changes.insert(
                            key,
                            ChangeAgg {
                                execution_count: 1,
                                sample_from_event_index: previous.event_index,
                                sample_to_event_index: hit.event_index,
                            },
                        );
                    } else {
                        transition.changes_truncated = true;
                    }
                }
            } else if same_flow && !sequence_contiguous {
                push_warning(
                    &mut warnings,
                    format!(
                        "Skipped a transition on thread {} because dispatcher hitSequence was not contiguous between events {} and {}.",
                        hit.thread_id, previous.event_index, hit.event_index
                    ),
                );
            }
        }
        previous_by_thread.insert(thread, hit.clone());

        if let Some(summary) = flows.get_mut(&flow) {
            summary.event_count += 1;
            summary.last_event_index = hit.event_index;
            if summary.offsets.len() < options.max_flow_length as usize {
                summary.offsets.push(hit.offset.clone());
            } else {
                summary.offsets_truncated = true;
            }
        } else if flows.len() < options.max_flows as usize {
            flows.insert(
                flow,
                FlowAgg {
                    flow_id: hit.flow_id,
                    capture_session_id: (hit.capture_session_id != "unknown-session")
                        .then_some(hit.capture_session_id),
                    thread_id: hit.thread_id,
                    event_count: 1,
                    first_event_index: hit.event_index,
                    last_event_index: hit.event_index,
                    offsets: vec![hit.offset],
                    offsets_truncated: false,
                    explicit_flow_id: hit.explicit_flow_id,
                },
            );
        } else {
            flows_truncated = true;
        }
    }

    let mut node_results = nodes
        .into_values()
        .map(|node| {
            let mut register_values = node
                .registers
                .into_iter()
                .map(|(register, summary)| {
                    let mut values = summary
                        .values
                        .into_iter()
                        .map(|(value, aggregate)| FridaOllvmStateValueCount {
                            value,
                            execution_count: aggregate.execution_count,
                            first_event_index: aggregate.first_event_index,
                            last_event_index: aggregate.last_event_index,
                        })
                        .collect::<Vec<_>>();
                    values.sort_by_key(|value| {
                        (
                            Reverse(value.execution_count),
                            parse_hex_addr(&value.value).unwrap_or(u64::MAX),
                        )
                    });
                    FridaOllvmRegisterValueSummary {
                        register,
                        observed_count: summary.observed_count,
                        missing_count: summary.missing_count,
                        values,
                        values_truncated: summary.truncated,
                    }
                })
                .collect::<Vec<_>>();
            register_values.sort_by(|left, right| left.register.cmp(&right.register));
            FridaOllvmDispatcherNode {
                block_id: node.block_id,
                offset: node.offset,
                event_count: node.event_count,
                thread_count: node.threads.len() as u64,
                flow_count: node.flows.len() as u64,
                state_registers: node.state_registers,
                register_values,
            }
        })
        .collect::<Vec<_>>();
    node_results.sort_by_key(|node| parse_hex_addr(&node.offset).unwrap_or(u64::MAX));

    let mut transition_results = transitions
        .into_iter()
        .map(|((from_offset, to_offset), transition)| {
            let mut state_changes = transition
                .changes
                .into_iter()
                .map(
                    |((register, from_value, to_value), aggregate)| FridaOllvmStateChange {
                        register,
                        from_value,
                        to_value,
                        execution_count: aggregate.execution_count,
                        sample_from_event_index: aggregate.sample_from_event_index,
                        sample_to_event_index: aggregate.sample_to_event_index,
                    },
                )
                .collect::<Vec<_>>();
            state_changes.sort_by_key(|change| {
                (
                    Reverse(change.execution_count),
                    change.register.clone(),
                    parse_hex_addr(&change.from_value).unwrap_or(u64::MAX),
                    parse_hex_addr(&change.to_value).unwrap_or(u64::MAX),
                )
            });
            FridaOllvmDispatcherTransition {
                from_offset,
                to_offset,
                execution_count: transition.execution_count,
                thread_count: transition.threads.len() as u64,
                flow_count: transition.flows.len() as u64,
                sample_from_event_index: transition.sample_from_event_index,
                sample_to_event_index: transition.sample_to_event_index,
                state_changes,
                state_changes_truncated: transition.changes_truncated,
            }
        })
        .collect::<Vec<_>>();
    transition_results.sort_by_key(|transition| {
        (
            Reverse(transition.execution_count),
            parse_hex_addr(&transition.from_offset).unwrap_or(u64::MAX),
            parse_hex_addr(&transition.to_offset).unwrap_or(u64::MAX),
        )
    });
    let flow_results = flows
        .into_values()
        .map(|flow| FridaOllvmDispatcherFlow {
            flow_id: flow.flow_id,
            capture_session_id: flow.capture_session_id,
            thread_id: flow.thread_id,
            event_count: flow.event_count,
            first_event_index: flow.first_event_index,
            last_event_index: flow.last_event_index,
            offsets: flow.offsets,
            offsets_truncated: flow.offsets_truncated,
            explicit_flow_id: flow.explicit_flow_id,
        })
        .collect::<Vec<_>>();

    let matched_event_count = node_results.iter().map(|node| node.event_count).sum();
    Ok(FridaOllvmDispatcherAtlas {
        schema_version: FRIDA_OLLVM_ATLAS_SCHEMA.to_string(),
        module_name: module_name.to_string(),
        source_format: bundle.source_format.clone(),
        matched_event_count,
        skipped_event_count,
        thread_count: all_threads.len() as u64,
        flow_count: all_flows.len() as u64,
        explicit_flow_count: explicit_flows.len() as u64,
        derived_flow_count: derived_flows.len() as u64,
        nodes: node_results,
        transitions: transition_results,
        flows: flow_results,
        flows_truncated,
        warnings,
        limitations: vec![
            "Dispatcher edges are reconstructed from adjacent user-captured events within a thread/flow. They are execution-specific Candidate/Related evidence, not a complete static CFG or proof of OLLVM flattening.".to_string(),
            "Dedicated-script flow IDs use an idle-gap heuristic and do not prove function-invocation boundaries. Legacy captures without flow IDs are grouped heuristically during import.".to_string(),
            "A matching module basename and runtime-relative offset do not cryptographically attest the loaded binary build; confirm the exact SO/dylib separately.".to_string(),
            "Missing registers, capture loss, other threads, unhooked dispatchers, and unexecuted paths can make nodes, transitions, and state values incomplete.".to_string(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::evidence_score::{score_evidence, EvidenceScoreSignal};
    use crate::query::ollvm::{DispatcherStateSnapshot, DispatcherStateTransition, OllvmScope};

    fn sample_candidate(offset: &str, register: &str, score: u8) -> DispatcherCandidate {
        DispatcherCandidate {
            block_id: format!("block-{offset}"),
            start_offset: offset.to_string(),
            end_offset: offset.to_string(),
            visit_count: 4,
            predecessor_count: 2,
            successor_count: 2,
            indirect_branch_count: 1,
            backward_edge_count: 1,
            state_registers: vec![register.to_string()],
            state_snapshots: Vec::<DispatcherStateSnapshot>::new(),
            state_transitions: Vec::<DispatcherStateTransition>::new(),
            state_snapshots_truncated: false,
            rationale: "candidate".to_string(),
            assessment: score_evidence(
                "dispatcher",
                false,
                vec![EvidenceScoreSignal::new(
                    "dispatcher",
                    "Dispatcher candidate",
                    score as i16,
                    true,
                    None,
                )],
                Vec::new(),
            ),
        }
    }

    fn sample_report() -> OllvmReport {
        OllvmReport {
            schema_version: "trace-ui/ollvm-v1".to_string(),
            scope: OllvmScope {
                session_id: "session".to_string(),
                node_id: Some(1),
                function_name: Some("target".to_string()),
                module_name: "libtarget.so".to_string(),
                module_base: "0x71000000".to_string(),
                start_seq: 1,
                end_seq: 10,
                child_calls_excluded: 0,
            },
            executed_instruction_count: 10,
            unique_instruction_count: 4,
            block_count: 2,
            edge_count: 1,
            blocks: vec![],
            edges: vec![],
            branch_profiles: vec![],
            dispatcher_candidates: vec![
                sample_candidate("0x80", "X8", 80),
                sample_candidate("0x120", "X8", 70),
            ],
            opaque_branch_candidates: vec![],
            instructions_truncated: false,
            blocks_truncated: false,
            edges_truncated: false,
            limitations: vec![],
            next_steps: vec![],
        }
    }

    #[test]
    fn generates_bounded_multi_dispatcher_frida_16_script() {
        let generated = generate_frida_ollvm_dispatcher_hook(
            &sample_report(),
            &FridaOllvmDispatcherHookOptions::default(),
        )
        .unwrap();
        assert_eq!(generated.targets.len(), 2);
        assert!(generated.script.contains("Module.getBaseAddress"));
        assert!(generated.script.contains("Interceptor.attach"));
        assert!(generated.script.contains("ollvm-dispatcher-hit"));
        assert!(generated.script.contains("dispatcherOffset"));
        assert!(generated.script.contains("flowId"));
        assert!(!generated.script.contains("frida.attach"));
    }

    #[test]
    fn generates_opt_in_bounded_pointer_memory_capture() {
        let generated = generate_frida_ollvm_dispatcher_hook(
            &sample_report(),
            &FridaOllvmDispatcherHookOptions {
                capture_pointer_registers: vec![3, 0],
                pointer_capture_bytes: 96,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(generated.capture_pointer_registers, vec![0, 3]);
        assert_eq!(generated.pointer_capture_bytes, 96);
        assert!(generated
            .script
            .contains("const POINTER_CAPTURE_REGISTERS = [0,3]"));
        assert!(generated
            .script
            .contains("const POINTER_CAPTURE_BYTES = 96"));
        assert!(generated.script.contains("pointer.readByteArray"));
        assert!(generated.script.contains("readError"));
    }

    #[test]
    fn generated_dispatcher_hook_has_valid_javascript_syntax_when_node_is_available() {
        let node = ["node", "nodejs"].into_iter().find(|candidate| {
            std::process::Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        });
        let Some(node) = node else {
            eprintln!(
                "skipping generated dispatcher JavaScript syntax check: Node.js is unavailable"
            );
            return;
        };
        let generated = generate_frida_ollvm_dispatcher_hook(
            &sample_report(),
            &FridaOllvmDispatcherHookOptions::default(),
        )
        .unwrap();
        let directory = std::env::temp_dir().join(format!(
            "trace-ui-frida-ollvm-syntax-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let script_path = directory.join("generated.js");
        std::fs::write(&script_path, generated.script).unwrap();
        let output = std::process::Command::new(node)
            .arg("--check")
            .arg(&script_path)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            output.status.success(),
            "generated dispatcher JavaScript failed syntax check: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn builds_thread_flow_dispatcher_atlas_with_state_changes() {
        let input = br#"[
          {"protocol":"trace-ui/frida-hook-v1","eventId":"one","hookId":"ollvm-dispatcher-80","event":"ollvm-dispatcher-hit","functionName":"d80","timestampMs":1,"threadId":7,"moduleName":"libtarget.so","moduleBase":"0x71000000","moduleSize":4096,"target":"0x71000080","dispatcherOffset":"0x80","captureSessionId":"capture","flowId":"capture:thread:7:flow:1","hitSequence":1,"registers":{"x8":"0x1","pc":"0x71000080"}},
          {"protocol":"trace-ui/frida-hook-v1","eventId":"two","hookId":"ollvm-dispatcher-120","event":"ollvm-dispatcher-hit","functionName":"d120","timestampMs":2,"threadId":7,"moduleName":"libtarget.so","moduleBase":"0x71000000","moduleSize":4096,"target":"0x71000120","dispatcherOffset":"0x120","captureSessionId":"capture","flowId":"capture:thread:7:flow:1","hitSequence":2,"registers":{"x8":"0x2","pc":"0x71000120"}},
          {"protocol":"trace-ui/frida-hook-v1","eventId":"three","hookId":"ollvm-dispatcher-80","event":"ollvm-dispatcher-hit","functionName":"d80","timestampMs":3,"threadId":7,"moduleName":"libtarget.so","moduleBase":"0x71000000","moduleSize":4096,"target":"0x71000080","dispatcherOffset":"0x80","captureSessionId":"capture","flowId":"capture:thread:7:flow:1","hitSequence":3,"registers":{"x8":"0x3","pc":"0x71000080"}}
        ]"#;
        let bundle = crate::query::frida_capture::parse_frida_capture_bundle(input).unwrap();
        let atlas = analyze_frida_ollvm_dispatcher_capture(
            &sample_report(),
            &bundle,
            &FridaOllvmDispatcherAtlasOptions::default(),
        )
        .unwrap();
        assert_eq!(atlas.matched_event_count, 3);
        assert_eq!(atlas.thread_count, 1);
        assert_eq!(atlas.flow_count, 1);
        assert_eq!(atlas.explicit_flow_count, 1);
        assert_eq!(atlas.nodes.len(), 2);
        assert_eq!(atlas.transitions.len(), 2);
        assert_eq!(atlas.transitions[0].state_changes[0].register, "X8");
        assert_eq!(atlas.flows[0].offsets, vec!["0x80", "0x120", "0x80"]);
    }

    #[test]
    fn skips_non_contiguous_dispatcher_hit_sequences() {
        let input = br#"[
          {"protocol":"trace-ui/frida-hook-v1","eventId":"one","hookId":"ollvm-dispatcher-80","event":"ollvm-dispatcher-hit","functionName":"d80","timestampMs":1,"threadId":7,"moduleName":"libtarget.so","moduleBase":"0x71000000","moduleSize":4096,"target":"0x71000080","dispatcherOffset":"0x80","captureSessionId":"capture","flowId":"capture:thread:7:flow:1","hitSequence":1,"registers":{"x8":"0x1"}},
          {"protocol":"trace-ui/frida-hook-v1","eventId":"three","hookId":"ollvm-dispatcher-120","event":"ollvm-dispatcher-hit","functionName":"d120","timestampMs":3,"threadId":7,"moduleName":"libtarget.so","moduleBase":"0x71000000","moduleSize":4096,"target":"0x71000120","dispatcherOffset":"0x120","captureSessionId":"capture","flowId":"capture:thread:7:flow:1","hitSequence":3,"registers":{"x8":"0x2"}}
        ]"#;
        let bundle = crate::query::frida_capture::parse_frida_capture_bundle(input).unwrap();
        let atlas = analyze_frida_ollvm_dispatcher_capture(
            &sample_report(),
            &bundle,
            &FridaOllvmDispatcherAtlasOptions::default(),
        )
        .unwrap();
        assert!(atlas.transitions.is_empty());
        assert!(atlas
            .warnings
            .iter()
            .any(|warning| warning.contains("hitSequence was not contiguous")));
    }

    #[test]
    fn rejects_runtime_offset_disagreement() {
        let input = br#"[{"protocol":"trace-ui/frida-hook-v1","hookId":"bad","event":"ollvm-dispatcher-hit","functionName":"bad","timestampMs":1,"threadId":1,"moduleName":"libtarget.so","moduleBase":"0x71000000","moduleSize":4096,"target":"0x71000080","dispatcherOffset":"0x120","registers":{"x8":"0x1"}}]"#;
        let bundle = crate::query::frida_capture::parse_frida_capture_bundle(input).unwrap();
        let error = analyze_frida_ollvm_dispatcher_capture(
            &sample_report(),
            &bundle,
            &FridaOllvmDispatcherAtlasOptions::default(),
        )
        .unwrap_err();
        assert!(error.contains("No user-captured dispatcher events"));
    }
}
