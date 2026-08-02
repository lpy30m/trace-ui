use std::collections::{BTreeMap, HashMap, HashSet};

use hmac::{Hmac, Mac};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::query::crypto_material::{
    CryptoFormula, CryptoMaterial, CryptoMaterialKind, CryptoMaterialReport,
};
use crate::query::evidence_score::{score_evidence, EvidenceScoreSignal};
use crate::utils::parse_hex_addr;

const FRIDA_CAPTURE_SCHEMA: &str = "trace-ui/frida-capture-v1";
const FRIDA_HOOK_PROTOCOL: &str = "trace-ui/frida-hook-v1";
const ANGR_STATE_SEED_SCHEMA: &str = "trace-ui/angr-state-seed-v1";
const DEFAULT_MAX_FRIDA_MATERIALS: u32 = 1_000;
const MAX_FRIDA_MATERIALS: u32 = 5_000;
const MAX_FRIDA_PBKDF2_ITERATIONS: u32 = 1_000_000;
const DEFAULT_FRIDA_EVENT_PAGE_SIZE: u32 = 50;
const MAX_FRIDA_EVENT_PAGE_SIZE: u32 = 200;
const MAX_FRIDA_EVENT_DETAIL_BYTES: u32 = 1_048_576;
// Generic hook arguments use X0-X7. OLLVM dispatcher hooks additionally use
// X8-X28 pointer snapshots and the synthetic index 29 for an SP stack window.
const MAX_FRIDA_CAPTURE_INDEX: u64 = 29;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaCapturedValue {
    pub index: u8,
    pub label: String,
    pub kind: String,
    pub direction: String,
    pub phase: String,
    #[serde(default)]
    pub pointer: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub byte_length: Option<u64>,
    #[serde(default)]
    pub requested_length: Option<u64>,
    #[serde(default)]
    pub read_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaCaptureEvent {
    pub index: u64,
    pub protocol: String,
    #[serde(default)]
    pub event_id: Option<String>,
    pub hook_id: String,
    pub event: String,
    pub function_name: String,
    pub timestamp_ms: u64,
    pub thread_id: u64,
    #[serde(default)]
    pub call_id: Option<String>,
    #[serde(default)]
    pub module_name: Option<String>,
    #[serde(default)]
    pub module_base: Option<String>,
    #[serde(default)]
    pub module_size: Option<u64>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub dispatcher_offset: Option<String>,
    #[serde(default)]
    pub capture_session_id: Option<String>,
    #[serde(default)]
    pub flow_id: Option<String>,
    #[serde(default)]
    pub hit_sequence: Option<u64>,
    #[serde(default)]
    pub candidate_state_registers: Vec<String>,
    #[serde(default)]
    pub registers: BTreeMap<String, String>,
    #[serde(default)]
    pub captures: Vec<FridaCapturedValue>,
    #[serde(default)]
    pub return_value: Option<String>,
    #[serde(default)]
    pub backtrace: Vec<String>,
    #[serde(default)]
    pub stalker_mode: Option<String>,
    #[serde(default)]
    pub stalker_event_count: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaCaptureBundle {
    pub schema: String,
    pub source_format: String,
    pub events: Vec<FridaCaptureEvent>,
    pub hook_ids: Vec<String>,
    pub enter_event_count: u64,
    pub leave_event_count: u64,
    pub stalker_event_count: u64,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct FridaCaptureSearchOptions {
    pub query: Option<String>,
    pub event_type: Option<String>,
    pub module_name: Option<String>,
    pub function_name: Option<String>,
    pub call_id: Option<String>,
    pub only_payload: bool,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaCaptureEventSummary {
    pub index: u64,
    pub event_id: Option<String>,
    pub hook_id: String,
    pub event: String,
    pub function_name: String,
    pub timestamp_ms: u64,
    pub thread_id: u64,
    pub call_id: Option<String>,
    pub module_name: Option<String>,
    pub module_base: Option<String>,
    pub module_size: Option<u64>,
    pub target: Option<String>,
    pub dispatcher_offset: Option<String>,
    pub capture_session_id: Option<String>,
    pub flow_id: Option<String>,
    pub hit_sequence: Option<u64>,
    pub candidate_state_registers: Vec<String>,
    pub register_count: u32,
    pub capture_count: u32,
    pub capture_labels: Vec<String>,
    pub has_return_value: bool,
    pub backtrace_count: u32,
    pub stalker_mode: Option<String>,
    pub stalker_event_count: Option<u64>,
    pub has_error: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaCaptureEventSearchResult {
    pub schema: String,
    pub total_event_count: u64,
    pub matched_event_count: u64,
    pub offset: u32,
    pub limit: u32,
    pub has_more: bool,
    pub events: Vec<FridaCaptureEventSummary>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaCaptureValueDetail {
    pub index: u8,
    pub label: String,
    pub kind: String,
    pub direction: String,
    pub phase: String,
    pub pointer: Option<String>,
    pub value: Option<String>,
    pub byte_length: Option<u64>,
    pub requested_length: Option<u64>,
    pub read_error: Option<String>,
    pub value_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FridaCaptureEventDetail {
    pub schema: String,
    pub event: FridaCaptureEventSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registers: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captures: Option<Vec<FridaCaptureValueDetail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backtrace: Option<Vec<String>>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrSeedMemoryRegion {
    pub address: String,
    pub byte_length: u64,
    pub bytes_hex: String,
    pub label: String,
    pub source_kind: String,
    pub phase: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrSeedRegister {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrStateSeed {
    pub schema_version: String,
    pub source_event_index: u64,
    pub source_event: String,
    pub hook_id: String,
    pub call_id: Option<String>,
    pub module_name: Option<String>,
    pub module_base: Option<String>,
    pub module_size: u64,
    pub function_name: String,
    pub capture_target: Option<String>,
    pub capture_offset: Option<String>,
    pub script: String,
    pub registers_seeded: Vec<String>,
    pub registers: Vec<AngrSeedRegister>,
    pub memory_regions: Vec<AngrSeedMemoryRegion>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct HookMetadata {
    module_name: Option<String>,
    module_base: Option<String>,
    module_size: Option<u64>,
    target: Option<String>,
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 500 {
        warnings.push(warning);
    } else if warnings.len() == 500 {
        warnings.push("Additional capture warnings were omitted.".to_string());
    }
}

fn string_field(object: &Map<String, Value>, name: &str) -> Option<String> {
    match object.get(name) {
        Some(Value::String(value)) if !value.trim().is_empty() => Some(value.clone()),
        Some(Value::Number(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn u64_field(object: &Map<String, Value>, name: &str) -> Option<u64> {
    match object.get(name) {
        Some(Value::Number(value)) => value.as_u64(),
        Some(Value::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn object_field<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Map<String, Value>> {
    object.get(name)?.as_object()
}

fn parse_capture(value: &Value) -> Option<FridaCapturedValue> {
    let object = value.as_object()?;
    let index = u64_field(object, "index")?;
    if index > MAX_FRIDA_CAPTURE_INDEX {
        return None;
    }
    Some(FridaCapturedValue {
        index: index as u8,
        label: string_field(object, "label").unwrap_or_else(|| format!("x{index}")),
        kind: string_field(object, "kind").unwrap_or_else(|| "pointer".to_string()),
        direction: string_field(object, "direction").unwrap_or_else(|| "input".to_string()),
        phase: string_field(object, "phase").unwrap_or_else(|| "unknown".to_string()),
        pointer: string_field(object, "pointer"),
        value: string_field(object, "value"),
        byte_length: u64_field(object, "byteLength"),
        requested_length: u64_field(object, "requestedLength"),
        read_error: string_field(object, "readError"),
    })
}

fn unwrap_payload(value: Value) -> Option<Value> {
    let object = value.as_object()?;
    if let Some(message) = object.get("message") {
        if let Some(payload) = unwrap_payload(message.clone()) {
            return Some(payload);
        }
    }
    if object.get("type").and_then(Value::as_str) == Some("send") {
        return object.get("payload").cloned();
    }
    if object.contains_key("protocol") {
        return Some(value);
    }
    None
}

fn parse_event(value: Value, index: u64, warnings: &mut Vec<String>) -> Option<FridaCaptureEvent> {
    let payload = unwrap_payload(value)?;
    let object = payload.as_object()?;
    let protocol = string_field(object, "protocol")?;
    if protocol != FRIDA_HOOK_PROTOCOL {
        push_warning(
            warnings,
            format!("Ignored event {index} with unsupported protocol {protocol}."),
        );
        return None;
    }
    let hook_id = string_field(object, "hookId").unwrap_or_else(|| "unknown-hook".to_string());
    let event = string_field(object, "event").unwrap_or_else(|| "unknown".to_string());
    let function_name = string_field(object, "functionName").unwrap_or_else(|| hook_id.clone());
    let registers = object_field(object, "registers")
        .map(|registers| {
            registers
                .iter()
                .filter_map(|(name, value)| match value {
                    Value::String(value) if !value.trim().is_empty() => {
                        Some((name.to_ascii_lowercase(), value.clone()))
                    }
                    Value::Number(value) => Some((name.to_ascii_lowercase(), value.to_string())),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let captures = object
        .get("captures")
        .and_then(Value::as_array)
        .map(|captures| captures.iter().filter_map(parse_capture).collect())
        .unwrap_or_default();
    let backtrace = object
        .get("backtrace")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let stalker_event_count = object
        .get("events")
        .and_then(Value::as_array)
        .map(|events| events.len() as u64);
    Some(FridaCaptureEvent {
        index,
        protocol,
        event_id: string_field(object, "eventId"),
        hook_id,
        event,
        function_name,
        timestamp_ms: u64_field(object, "timestampMs").unwrap_or_default(),
        thread_id: u64_field(object, "threadId").unwrap_or_default(),
        call_id: string_field(object, "callId"),
        module_name: string_field(object, "moduleName").or_else(|| string_field(object, "module")),
        module_base: string_field(object, "moduleBase"),
        module_size: u64_field(object, "moduleSize"),
        target: string_field(object, "target"),
        dispatcher_offset: string_field(object, "dispatcherOffset"),
        capture_session_id: string_field(object, "captureSessionId"),
        flow_id: string_field(object, "flowId"),
        hit_sequence: u64_field(object, "hitSequence"),
        candidate_state_registers: object
            .get("candidateStateRegisters")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned)
                    .take(32)
                    .collect()
            })
            .unwrap_or_default(),
        registers,
        captures,
        return_value: string_field(object, "returnValue"),
        backtrace,
        stalker_mode: string_field(object, "mode"),
        stalker_event_count,
        error: string_field(object, "error"),
    })
}

fn parse_input_values(text: &str) -> Result<(String, Vec<Value>, Vec<String>), String> {
    let mut warnings = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return match value {
            Value::Array(values) => Ok(("json-array".to_string(), values, warnings)),
            Value::Object(mut object) => {
                if let Some(events) = object
                    .remove("events")
                    .and_then(|value| value.as_array().cloned())
                {
                    if let Some(schema) = object.get("schema").and_then(Value::as_str) {
                        if schema != FRIDA_CAPTURE_SCHEMA {
                            push_warning(&mut warnings, format!(
                                "Capture container schema {schema} is not {FRIDA_CAPTURE_SCHEMA}; event payloads were still inspected."
                            ));
                        }
                    }
                    Ok(("capture-bundle".to_string(), events, warnings))
                } else {
                    Ok((
                        "json-object".to_string(),
                        vec![Value::Object(object)],
                        warnings,
                    ))
                }
            }
            _ => Err("Frida capture JSON must be an object, array, or NDJSON stream".to_string()),
        };
    }

    let mut values = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let json_text = trimmed
            .split_once("TRACE_UI_JSON ")
            .map(|(_, json)| json.trim())
            .unwrap_or(trimmed);
        match serde_json::from_str::<Value>(json_text) {
            Ok(value) => values.push(value),
            Err(error) => push_warning(
                &mut warnings,
                format!(
                    "Ignored non-JSON line {} while parsing NDJSON: {error}",
                    line_index + 1
                ),
            ),
        }
    }
    if values.is_empty() {
        return Err(
            "No JSON Frida messages found. Save send() messages as JSON objects, a JSON array, or NDJSON."
                .to_string(),
        );
    }
    Ok(("ndjson".to_string(), values, warnings))
}

fn normalize_metadata_and_calls(events: &mut [FridaCaptureEvent]) {
    let mut metadata: HashMap<String, HookMetadata> = HashMap::new();
    let mut call_stacks: HashMap<(String, u64), Vec<String>> = HashMap::new();
    let mut call_counters: HashMap<(String, u64), u64> = HashMap::new();

    for event in events {
        let hook_metadata = metadata.entry(event.hook_id.clone()).or_default();
        if event.module_name.is_some() {
            hook_metadata.module_name.clone_from(&event.module_name);
        }
        if event.module_base.is_some() {
            hook_metadata.module_base.clone_from(&event.module_base);
        }
        if event.module_size.is_some() {
            hook_metadata.module_size = event.module_size;
        }
        if event.target.is_some() {
            hook_metadata.target.clone_from(&event.target);
        }
        if event.module_name.is_none() {
            event.module_name.clone_from(&hook_metadata.module_name);
        }
        if event.module_base.is_none() {
            event.module_base.clone_from(&hook_metadata.module_base);
        }
        if event.module_size.is_none() {
            event.module_size = hook_metadata.module_size;
        }
        if event.target.is_none() {
            event.target.clone_from(&hook_metadata.target);
        }

        let key = (event.hook_id.clone(), event.thread_id);
        if event.event == "hook-enter" {
            let call_id = event.call_id.clone().unwrap_or_else(|| {
                let counter = call_counters.entry(key.clone()).or_default();
                *counter += 1;
                format!("inferred:{}:{}:{}", event.hook_id, event.thread_id, counter)
            });
            event.call_id = Some(call_id.clone());
            call_stacks.entry(key).or_default().push(call_id);
        } else {
            if event.call_id.is_none() {
                event.call_id = call_stacks
                    .get(&key)
                    .and_then(|stack| stack.last())
                    .cloned();
            }
            if event.event == "hook-leave" {
                if let Some(stack) = call_stacks.get_mut(&key) {
                    stack.pop();
                }
            }
        }
    }
}

pub fn parse_frida_capture_bundle(bytes: &[u8]) -> Result<FridaCaptureBundle, String> {
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("Frida capture file exceeds 64 MiB".to_string());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| format!("Frida capture must be UTF-8 JSON or NDJSON: {error}"))?;
    let (source_format, values, mut warnings) = parse_input_values(text)?;
    let mut events = Vec::new();
    let mut seen_event_ids = HashSet::new();
    for (index, value) in values.into_iter().enumerate() {
        if events.len() >= 200_000 {
            push_warning(
                &mut warnings,
                "Capture was truncated at 200000 protocol events.".to_string(),
            );
            break;
        }
        match parse_event(value, index as u64, &mut warnings) {
            Some(event) => {
                if let Some(event_id) = &event.event_id {
                    if !seen_event_ids.insert(event_id.clone()) {
                        push_warning(
                            &mut warnings,
                            format!("Ignored duplicate Frida eventId {event_id}."),
                        );
                        continue;
                    }
                }
                events.push(event);
            }
            None => push_warning(&mut warnings, format!(
                "Ignored JSON item {index} because it was not a trace-ui/frida-hook-v1 send() payload."
            )),
        }
    }
    if events.is_empty() {
        return Err("No trace-ui/frida-hook-v1 events found in capture".to_string());
    }
    normalize_metadata_and_calls(&mut events);
    let mut hook_ids: Vec<String> = events
        .iter()
        .map(|event| event.hook_id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    hook_ids.sort();
    let enter_event_count = events
        .iter()
        .filter(|event| event.event == "hook-enter")
        .count() as u64;
    let leave_event_count = events
        .iter()
        .filter(|event| event.event == "hook-leave")
        .count() as u64;
    let stalker_event_count = events
        .iter()
        .filter(|event| event.event == "stalker-events")
        .count() as u64;
    Ok(FridaCaptureBundle {
        schema: FRIDA_CAPTURE_SCHEMA.to_string(),
        source_format,
        events,
        hook_ids,
        enter_event_count,
        leave_event_count,
        stalker_event_count,
        warnings,
    })
}

fn event_has_payload(event: &FridaCaptureEvent) -> bool {
    !event.registers.is_empty()
        || !event.captures.is_empty()
        || event.return_value.is_some()
        || !event.backtrace.is_empty()
        || event.stalker_event_count.unwrap_or_default() > 0
}

fn contains_case_insensitive(value: Option<&str>, query: &str) -> bool {
    value
        .map(|value| value.to_ascii_lowercase().contains(query))
        .unwrap_or(false)
}

fn event_matches_query(event: &FridaCaptureEvent, query: &str) -> bool {
    contains_case_insensitive(Some(&event.event), query)
        || contains_case_insensitive(Some(&event.hook_id), query)
        || contains_case_insensitive(Some(&event.function_name), query)
        || contains_case_insensitive(event.event_id.as_deref(), query)
        || contains_case_insensitive(event.call_id.as_deref(), query)
        || contains_case_insensitive(event.module_name.as_deref(), query)
        || contains_case_insensitive(event.target.as_deref(), query)
        || contains_case_insensitive(event.dispatcher_offset.as_deref(), query)
        || contains_case_insensitive(event.capture_session_id.as_deref(), query)
        || contains_case_insensitive(event.flow_id.as_deref(), query)
        || event.registers.iter().any(|(name, value)| {
            contains_case_insensitive(Some(name), query)
                || contains_case_insensitive(Some(value), query)
        })
        || event.captures.iter().any(|capture| {
            contains_case_insensitive(Some(&capture.label), query)
                || contains_case_insensitive(Some(&capture.kind), query)
                || contains_case_insensitive(Some(&capture.direction), query)
                || contains_case_insensitive(capture.pointer.as_deref(), query)
                || contains_case_insensitive(capture.value.as_deref(), query)
                || contains_case_insensitive(capture.read_error.as_deref(), query)
        })
        || contains_case_insensitive(event.return_value.as_deref(), query)
        || event
            .backtrace
            .iter()
            .any(|frame| contains_case_insensitive(Some(frame), query))
        || contains_case_insensitive(event.error.as_deref(), query)
}

fn event_summary(event: &FridaCaptureEvent) -> FridaCaptureEventSummary {
    FridaCaptureEventSummary {
        index: event.index,
        event_id: event.event_id.clone(),
        hook_id: event.hook_id.clone(),
        event: event.event.clone(),
        function_name: event.function_name.clone(),
        timestamp_ms: event.timestamp_ms,
        thread_id: event.thread_id,
        call_id: event.call_id.clone(),
        module_name: event.module_name.clone(),
        module_base: event.module_base.clone(),
        module_size: event.module_size,
        target: event.target.clone(),
        dispatcher_offset: event.dispatcher_offset.clone(),
        capture_session_id: event.capture_session_id.clone(),
        flow_id: event.flow_id.clone(),
        hit_sequence: event.hit_sequence,
        candidate_state_registers: event.candidate_state_registers.clone(),
        register_count: event.registers.len() as u32,
        capture_count: event.captures.len() as u32,
        capture_labels: event
            .captures
            .iter()
            .map(|capture| capture.label.clone())
            .collect(),
        has_return_value: event.return_value.is_some(),
        backtrace_count: event.backtrace.len() as u32,
        stalker_mode: event.stalker_mode.clone(),
        stalker_event_count: event.stalker_event_count,
        has_error: event.error.is_some(),
    }
}

pub fn search_frida_capture_events(
    bundle: &FridaCaptureBundle,
    options: &FridaCaptureSearchOptions,
) -> FridaCaptureEventSearchResult {
    let query = options
        .query
        .as_deref()
        .map(str::trim)
        .filter(|query| !query.is_empty())
        .map(str::to_ascii_lowercase);
    let event_type = options
        .event_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let module_name = options
        .module_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let function_name = options
        .function_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let call_id = options
        .call_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let limit = if options.limit == 0 {
        DEFAULT_FRIDA_EVENT_PAGE_SIZE
    } else {
        options.limit.min(MAX_FRIDA_EVENT_PAGE_SIZE)
    };

    let matches: Vec<&FridaCaptureEvent> = bundle
        .events
        .iter()
        .filter(|event| {
            query
                .as_deref()
                .map(|query| event_matches_query(event, query))
                .unwrap_or(true)
                && event_type
                    .as_deref()
                    .map(|event_type| event.event.eq_ignore_ascii_case(event_type))
                    .unwrap_or(true)
                && module_name
                    .as_deref()
                    .map(|module_name| {
                        contains_case_insensitive(event.module_name.as_deref(), module_name)
                    })
                    .unwrap_or(true)
                && function_name
                    .as_deref()
                    .map(|function_name| {
                        contains_case_insensitive(Some(&event.function_name), function_name)
                    })
                    .unwrap_or(true)
                && call_id
                    .as_deref()
                    .map(|call_id| contains_case_insensitive(event.call_id.as_deref(), call_id))
                    .unwrap_or(true)
                && (!options.only_payload || event_has_payload(event))
        })
        .collect();
    let matched_event_count = matches.len() as u64;
    let events = matches
        .iter()
        .skip(options.offset as usize)
        .take(limit as usize)
        .map(|event| event_summary(event))
        .collect::<Vec<_>>();
    let consumed = (options.offset as u64).saturating_add(events.len() as u64);

    FridaCaptureEventSearchResult {
        schema: "trace-ui/frida-capture-search-v1".to_string(),
        total_event_count: bundle.events.len() as u64,
        matched_event_count,
        offset: options.offset,
        limit,
        has_more: consumed < matched_event_count,
        events,
        warnings: bundle.warnings.clone(),
    }
}

fn capture_value_detail(capture: &FridaCapturedValue, max_bytes: u32) -> FridaCaptureValueDetail {
    let max_bytes = max_bytes.clamp(1, MAX_FRIDA_EVENT_DETAIL_BYTES) as usize;
    let (value, value_truncated) = match capture.value.as_deref() {
        Some(value) if capture.kind.eq_ignore_ascii_case("byteArray") => {
            let max_chars = max_bytes.saturating_mul(2);
            if value.len() > max_chars {
                (Some(value.chars().take(max_chars).collect()), true)
            } else {
                (Some(value.to_string()), false)
            }
        }
        Some(value) => {
            let char_count = value.chars().count();
            if char_count > max_bytes {
                (Some(value.chars().take(max_bytes).collect()), true)
            } else {
                (Some(value.to_string()), false)
            }
        }
        None => (None, false),
    };

    FridaCaptureValueDetail {
        index: capture.index,
        label: capture.label.clone(),
        kind: capture.kind.clone(),
        direction: capture.direction.clone(),
        phase: capture.phase.clone(),
        pointer: capture.pointer.clone(),
        value,
        byte_length: capture.byte_length,
        requested_length: capture.requested_length,
        read_error: capture.read_error.clone(),
        value_truncated,
    }
}

pub fn get_frida_capture_event(
    bundle: &FridaCaptureBundle,
    event_index: u64,
    include_registers: bool,
    include_captures: bool,
    include_return_value: bool,
    include_backtrace: bool,
    max_bytes: u32,
) -> Result<FridaCaptureEventDetail, String> {
    let event = bundle
        .events
        .iter()
        .find(|event| event.index == event_index)
        .ok_or_else(|| format!("Frida capture event index {event_index} was not found"))?;
    let max_bytes = max_bytes.clamp(1, MAX_FRIDA_EVENT_DETAIL_BYTES);
    let captures = include_captures.then(|| {
        event
            .captures
            .iter()
            .map(|capture| capture_value_detail(capture, max_bytes))
            .collect::<Vec<_>>()
    });
    let mut warnings = Vec::new();
    if captures
        .as_ref()
        .map(|captures| captures.iter().any(|capture| capture.value_truncated))
        .unwrap_or(false)
    {
        warnings.push(format!(
            "One or more capture values were truncated to {max_bytes} bytes."
        ));
    }

    Ok(FridaCaptureEventDetail {
        schema: "trace-ui/frida-capture-event-v1".to_string(),
        event: event_summary(event),
        registers: include_registers.then(|| event.registers.clone()),
        captures,
        return_value: include_return_value
            .then(|| event.return_value.clone())
            .flatten(),
        backtrace: include_backtrace.then(|| event.backtrace.clone()),
        warnings,
    })
}

#[derive(Clone)]
struct FridaMaterialEntry {
    material_id: String,
    call_id: String,
    function_name: String,
    label: String,
    phase: String,
    kind: CryptoMaterialKind,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
enum FridaHashAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl FridaHashAlgorithm {
    fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    fn output_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Md5 => Md5::digest(input).to_vec(),
            Self::Sha1 => Sha1::digest(input).to_vec(),
            Self::Sha256 => Sha256::digest(input).to_vec(),
            Self::Sha384 => Sha384::digest(input).to_vec(),
            Self::Sha512 => Sha512::digest(input).to_vec(),
        }
    }

    fn hmac(self, key: &[u8], input: &[u8]) -> Option<Vec<u8>> {
        macro_rules! calculate {
            ($digest:ty) => {{
                let mut mac = Hmac::<$digest>::new_from_slice(key).ok()?;
                mac.update(input);
                Some(mac.finalize().into_bytes().to_vec())
            }};
        }
        match self {
            Self::Md5 => calculate!(Md5),
            Self::Sha1 => calculate!(Sha1),
            Self::Sha256 => calculate!(Sha256),
            Self::Sha384 => calculate!(Sha384),
            Self::Sha512 => calculate!(Sha512),
        }
    }

    fn pbkdf2(self, password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        match self {
            Self::Md5 => pbkdf2_hmac::<Md5>(password, salt, iterations, &mut output),
            Self::Sha1 => pbkdf2_hmac::<Sha1>(password, salt, iterations, &mut output),
            Self::Sha256 => pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output),
            Self::Sha384 => pbkdf2_hmac::<Sha384>(password, salt, iterations, &mut output),
            Self::Sha512 => pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut output),
        }
        output
    }
}

fn detect_frida_hash_algorithm(function_name: &str) -> Option<FridaHashAlgorithm> {
    let normalized = function_name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    if normalized.contains("sha512") {
        Some(FridaHashAlgorithm::Sha512)
    } else if normalized.contains("sha384") {
        Some(FridaHashAlgorithm::Sha384)
    } else if normalized.contains("sha256") {
        Some(FridaHashAlgorithm::Sha256)
    } else if normalized.contains("sha1") {
        Some(FridaHashAlgorithm::Sha1)
    } else if normalized.contains("md5") {
        Some(FridaHashAlgorithm::Md5)
    } else {
        None
    }
}

fn frida_label_tokens(label: &str) -> HashSet<String> {
    label
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn classify_frida_material(
    capture: &FridaCapturedValue,
    function_name: &str,
) -> (CryptoMaterialKind, String, bool) {
    let tokens = frida_label_tokens(&capture.label);
    let function = function_name.to_ascii_lowercase();
    let explicit = |values: &[&str]| values.iter().any(|value| tokens.contains(*value));
    if explicit(&["key", "secret", "secretkey", "mackey", "hmackey"]) {
        (CryptoMaterialKind::Key, "key".to_string(), true)
    } else if explicit(&["password", "passwd", "passphrase", "pass"]) {
        (CryptoMaterialKind::Password, "password".to_string(), true)
    } else if explicit(&["salt"]) {
        (CryptoMaterialKind::Salt, "salt".to_string(), true)
    } else if explicit(&["nonce"]) {
        (CryptoMaterialKind::Nonce, "nonce".to_string(), true)
    } else if explicit(&["iv", "initializationvector"]) {
        (CryptoMaterialKind::Iv, "iv".to_string(), true)
    } else if explicit(&["counter", "ctr"]) {
        (CryptoMaterialKind::Counter, "counter".to_string(), true)
    } else if explicit(&["aad", "associateddata"]) {
        (CryptoMaterialKind::Aad, "aad".to_string(), true)
    } else if explicit(&["tag", "authtag", "authenticationtag"]) {
        (
            CryptoMaterialKind::AuthTag,
            "authenticationTag".to_string(),
            true,
        )
    } else if explicit(&[
        "digest", "hash", "md5", "sha1", "sha256", "sha384", "sha512",
    ]) {
        (CryptoMaterialKind::Digest, "digest".to_string(), true)
    } else if explicit(&["mac", "hmac"]) {
        (CryptoMaterialKind::Mac, "mac".to_string(), true)
    } else if explicit(&["plaintext", "plain"]) {
        (CryptoMaterialKind::Plaintext, "plaintext".to_string(), true)
    } else if explicit(&["ciphertext", "cipher"]) {
        (
            CryptoMaterialKind::Ciphertext,
            "ciphertext".to_string(),
            true,
        )
    } else if explicit(&["input", "message", "data", "source", "src"]) {
        (CryptoMaterialKind::Input, "input".to_string(), true)
    } else if explicit(&["output", "result", "destination", "dst"]) {
        (CryptoMaterialKind::Output, "output".to_string(), true)
    } else if capture.phase == "leave" || capture.direction == "output" {
        let kind = if function.contains("encrypt") {
            CryptoMaterialKind::Ciphertext
        } else if function.contains("decrypt") {
            CryptoMaterialKind::Plaintext
        } else {
            CryptoMaterialKind::Output
        };
        (kind, "output".to_string(), false)
    } else {
        let kind = if function.contains("encrypt") {
            CryptoMaterialKind::Plaintext
        } else if function.contains("decrypt") {
            CryptoMaterialKind::Ciphertext
        } else {
            CryptoMaterialKind::Input
        };
        (kind, "input".to_string(), false)
    }
}

fn captured_material_bytes(capture: &FridaCapturedValue) -> Option<Vec<u8>> {
    if capture.read_error.is_some() {
        return None;
    }
    let value = capture.value.as_deref()?;
    match capture.kind.as_str() {
        "byteArray" => decode_hex(value),
        "utf8String" => Some(value.as_bytes().to_vec()),
        "utf16String" => Some(value.encode_utf16().flat_map(u16::to_le_bytes).collect()),
        _ => None,
    }
}

fn crypto_kind_name(kind: CryptoMaterialKind) -> &'static str {
    match kind {
        CryptoMaterialKind::Key => "key",
        CryptoMaterialKind::ExpandedKey => "expandedKey",
        CryptoMaterialKind::Password => "password",
        CryptoMaterialKind::Salt => "salt",
        CryptoMaterialKind::Iv => "iv",
        CryptoMaterialKind::Nonce => "nonce",
        CryptoMaterialKind::Counter => "counter",
        CryptoMaterialKind::Aad => "aad",
        CryptoMaterialKind::AuthTag => "authTag",
        CryptoMaterialKind::Input => "input",
        CryptoMaterialKind::Output => "output",
        CryptoMaterialKind::Plaintext => "plaintext",
        CryptoMaterialKind::Ciphertext => "ciphertext",
        CryptoMaterialKind::Digest => "digest",
        CryptoMaterialKind::Mac => "mac",
        CryptoMaterialKind::DerivedKey => "derivedKey",
        CryptoMaterialKind::Unknown => "unknown",
    }
}

fn mark_frida_material_verified(
    materials: &mut [CryptoMaterial],
    material_id: &str,
    evidence: String,
) {
    let Some(material) = materials
        .iter_mut()
        .find(|material| material.material_id == material_id)
    else {
        return;
    };
    material.evidence.push(evidence.clone());
    material.assessment = score_evidence(
        format!("frida_crypto_material:{material_id}"),
        true,
        vec![
            EvidenceScoreSignal::new(
                "captured_bytes",
                "Exact bytes imported from user-captured Frida output",
                30,
                true,
                material.bytes_hex.clone(),
            ),
            EvidenceScoreSignal::new(
                "semantic_recomputation",
                "Observed output was deterministically recomputed",
                70,
                true,
                Some(evidence),
            ),
        ],
        vec![
            "Verification applies to the imported call bytes, not to every invocation or the entire native function."
                .to_string(),
        ],
    );
}

pub fn analyze_frida_crypto_materials(
    bundle: &FridaCaptureBundle,
    max_materials: Option<u32>,
    include_unknown: bool,
) -> Result<CryptoMaterialReport, String> {
    if bundle.schema != FRIDA_CAPTURE_SCHEMA {
        return Err(format!(
            "unsupported Frida capture schema: {}",
            bundle.schema
        ));
    }
    let max_materials = max_materials
        .unwrap_or(DEFAULT_MAX_FRIDA_MATERIALS)
        .clamp(1, MAX_FRIDA_MATERIALS) as usize;
    let mut materials = Vec::new();
    let mut entries = Vec::new();
    let mut integer_values: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    let mut materials_truncated = false;
    for event in &bundle.events {
        let Some(call_id) = event.call_id.as_deref() else {
            continue;
        };
        for capture in &event.captures {
            if capture.kind == "integer" {
                if let Some(value) = capture
                    .value
                    .as_deref()
                    .and_then(|value| parse_hex_addr(value).ok())
                {
                    integer_values
                        .entry(call_id.to_string())
                        .or_default()
                        .push((capture.label.clone(), value));
                }
                continue;
            }
            let Some(bytes) = captured_material_bytes(capture) else {
                continue;
            };
            if bytes.is_empty() {
                continue;
            }
            let (kind, role, explicit_role) =
                classify_frida_material(capture, &event.function_name);
            if !include_unknown && !explicit_role && kind == CryptoMaterialKind::Input {
                continue;
            }
            if materials.len() >= max_materials {
                materials_truncated = true;
                break;
            }
            let material_id = format!("frida-material-{}", materials.len() + 1);
            let address = capture
                .pointer
                .as_deref()
                .and_then(|pointer| parse_hex_addr(pointer).ok());
            let algorithm = detect_frida_hash_algorithm(&event.function_name)
                .map(|algorithm| algorithm.name().to_string());
            let mut evidence = vec![format!(
                "Imported from {} event {} callId {} X{} {} phase.",
                event.event, event.index, call_id, capture.index, capture.phase
            )];
            if explicit_role {
                evidence.push(format!(
                    "Capture label '{}' explicitly suggests role {}.",
                    capture.label, role
                ));
            } else {
                evidence.push(format!(
                    "Role {} was inferred from capture direction/phase and function name; treat it as Related evidence.",
                    role
                ));
            }
            let assessment = score_evidence(
                format!("frida_crypto_material:{material_id}"),
                false,
                vec![
                    EvidenceScoreSignal::new(
                        "captured_bytes",
                        "Exact imported capture bytes",
                        30,
                        true,
                        Some(format!("{} bytes", bytes.len())),
                    ),
                    EvidenceScoreSignal::new(
                        "explicit_role_label",
                        "Explicit crypto role label",
                        35,
                        explicit_role,
                        Some(capture.label.clone()),
                    ),
                    EvidenceScoreSignal::new(
                        "call_correlation",
                        "Capture correlated by callId and phase",
                        20,
                        true,
                        Some(call_id.to_string()),
                    ),
                    EvidenceScoreSignal::new(
                        "algorithm_name",
                        "Hash/HMAC/KDF algorithm indicated by function name",
                        15,
                        algorithm.is_some(),
                        algorithm.clone(),
                    ),
                ],
                vec![
                    "Labels and ABI positions are role hints until deterministic recomputation or independent API semantics confirm them."
                        .to_string(),
                ],
            );
            materials.push(CryptoMaterial {
                material_id: material_id.clone(),
                kind,
                role,
                algorithm,
                bytes_hex: Some(bytes_hex(&bytes)),
                ascii_preview: Some(
                    bytes
                        .iter()
                        .take(96)
                        .map(|byte| {
                            if byte.is_ascii_graphic() || *byte == b' ' {
                                *byte as char
                            } else {
                                '.'
                            }
                        })
                        .collect(),
                ),
                byte_len: Some(bytes.len() as u32),
                address: address.map(|address| format!("0x{address:x}")),
                observation_seq: u32::try_from(event.index).ok(),
                completion_seq: u32::try_from(event.index).ok(),
                function_name: Some(event.function_name.clone()),
                register: Some(format!("X{}", capture.index)),
                source: "frida-capture".to_string(),
                evidence,
                assessment,
            });
            entries.push(FridaMaterialEntry {
                material_id,
                call_id: call_id.to_string(),
                function_name: event.function_name.clone(),
                label: capture.label.clone(),
                phase: capture.phase.clone(),
                kind,
                bytes,
            });
        }
        if materials_truncated {
            break;
        }
    }

    let mut formulas = Vec::new();
    let mut grouped: BTreeMap<String, Vec<FridaMaterialEntry>> = BTreeMap::new();
    for entry in entries {
        grouped
            .entry(entry.call_id.clone())
            .or_default()
            .push(entry);
    }
    for (call_id, call_entries) in grouped {
        let Some(first) = call_entries.first() else {
            continue;
        };
        let Some(algorithm) = detect_frida_hash_algorithm(&first.function_name) else {
            continue;
        };
        let function_lower = first.function_name.to_ascii_lowercase();
        let is_hmac = function_lower.contains("hmac");
        let input_entries: Vec<_> = call_entries
            .iter()
            .filter(|entry| {
                entry.phase == "enter"
                    && matches!(
                        entry.kind,
                        CryptoMaterialKind::Input
                            | CryptoMaterialKind::Plaintext
                            | CryptoMaterialKind::Password
                    )
            })
            .collect();
        let key_entries: Vec<_> = call_entries
            .iter()
            .filter(|entry| entry.kind == CryptoMaterialKind::Key)
            .collect();
        let output_entries: Vec<_> = call_entries
            .iter()
            .filter(|entry| {
                entry.phase == "leave"
                    && entry.bytes.len() == algorithm.output_len()
                    && matches!(
                        entry.kind,
                        CryptoMaterialKind::Output
                            | CryptoMaterialKind::Digest
                            | CryptoMaterialKind::Mac
                            | CryptoMaterialKind::AuthTag
                    )
            })
            .collect();
        if function_lower.contains("pbkdf2") {
            let password = call_entries.iter().find(|entry| {
                entry.phase == "enter"
                    && matches!(
                        entry.kind,
                        CryptoMaterialKind::Password | CryptoMaterialKind::Input
                    )
            });
            let salt = call_entries
                .iter()
                .find(|entry| entry.phase == "enter" && entry.kind == CryptoMaterialKind::Salt);
            let derived = call_entries.iter().find(|entry| {
                entry.phase == "leave"
                    && matches!(
                        entry.kind,
                        CryptoMaterialKind::Output | CryptoMaterialKind::DerivedKey
                    )
            });
            let iterations = integer_values.get(&call_id).and_then(|values| {
                values
                    .iter()
                    .find(|(label, _)| {
                        let normalized = label.to_ascii_lowercase();
                        normalized.contains("iter")
                            || normalized.contains("round")
                            || normalized.contains("count")
                    })
                    .or_else(|| values.first())
                    .map(|(_, value)| *value)
            });
            if let (Some(password), Some(salt), Some(derived), Some(iterations)) =
                (password, salt, derived, iterations)
            {
                if let Ok(iterations) = u32::try_from(iterations) {
                    if (1..=MAX_FRIDA_PBKDF2_ITERATIONS).contains(&iterations)
                        && algorithm.pbkdf2(
                            &password.bytes,
                            &salt.bytes,
                            iterations,
                            derived.bytes.len(),
                        ) == derived.bytes
                    {
                        let evidence = format!(
                            "Imported callId {call_id}: PBKDF2-{}({}, {}, {}, {}) recomputes to the captured output.",
                            algorithm.name(),
                            password.label,
                            salt.label,
                            iterations,
                            derived.bytes.len()
                        );
                        for material_id in [
                            &password.material_id,
                            &salt.material_id,
                            &derived.material_id,
                        ] {
                            mark_frida_material_verified(
                                &mut materials,
                                material_id,
                                evidence.clone(),
                            );
                        }
                        if let Some(material) = materials
                            .iter_mut()
                            .find(|material| material.material_id == derived.material_id)
                        {
                            material.kind = CryptoMaterialKind::DerivedKey;
                            material.role = "derivedKey".to_string();
                        }
                        formulas.push(CryptoFormula {
                            formula_id: format!("frida-formula-{}", formulas.len() + 1),
                            operation: "PBKDF2".to_string(),
                            algorithm: algorithm.name().to_string(),
                            expression: format!(
                                "PBKDF2-{}({}, {}, iterations={}, length={}) = {}",
                                algorithm.name(),
                                password.label,
                                salt.label,
                                iterations,
                                derived.bytes.len(),
                                derived.label
                            ),
                            input_material_ids: vec![
                                password.material_id.clone(),
                                salt.material_id.clone(),
                            ],
                            output_material_id: Some(derived.material_id.clone()),
                            call_seq: None,
                            function_name: Some(first.function_name.clone()),
                            evidence: vec![evidence.clone()],
                            assessment: score_evidence(
                                format!("frida_crypto_formula:{call_id}"),
                                true,
                                vec![EvidenceScoreSignal::new(
                                    "semantic_recomputation",
                                    "Captured PBKDF2 output matches deterministic recomputation",
                                    100,
                                    true,
                                    Some(evidence),
                                )],
                                vec![
                                    "Verification is scoped to the imported call bytes, iteration count, PRF, and output length."
                                        .to_string(),
                                ],
                            ),
                        });
                    }
                }
            }
            continue;
        }
        'verify: for input in &input_entries {
            for output in &output_entries {
                let recomputed = if is_hmac {
                    let Some(key) = key_entries.first() else {
                        continue;
                    };
                    algorithm.hmac(&key.bytes, &input.bytes)
                } else {
                    Some(algorithm.digest(&input.bytes))
                };
                if recomputed.as_deref() != Some(output.bytes.as_slice()) {
                    continue;
                }
                let operation = if is_hmac { "HMAC" } else { "Digest" };
                let mut input_ids = Vec::new();
                if is_hmac {
                    input_ids.push(key_entries[0].material_id.clone());
                }
                input_ids.push(input.material_id.clone());
                let expression = if is_hmac {
                    format!(
                        "HMAC-{}({}, {}) = {}",
                        algorithm.name(),
                        key_entries[0].label,
                        input.label,
                        output.label
                    )
                } else {
                    format!("{}({}) = {}", algorithm.name(), input.label, output.label)
                };
                let evidence = format!(
                    "Imported callId {call_id}: exact captured bytes recompute to the observed {} output.",
                    algorithm.name()
                );
                mark_frida_material_verified(&mut materials, &input.material_id, evidence.clone());
                mark_frida_material_verified(&mut materials, &output.material_id, evidence.clone());
                if is_hmac {
                    mark_frida_material_verified(
                        &mut materials,
                        &key_entries[0].material_id,
                        evidence.clone(),
                    );
                }
                formulas.push(CryptoFormula {
                    formula_id: format!("frida-formula-{}", formulas.len() + 1),
                    operation: operation.to_string(),
                    algorithm: algorithm.name().to_string(),
                    expression,
                    input_material_ids: input_ids,
                    output_material_id: Some(output.material_id.clone()),
                    call_seq: None,
                    function_name: Some(first.function_name.clone()),
                    evidence: vec![evidence.clone()],
                    assessment: score_evidence(
                        format!("frida_crypto_formula:{call_id}"),
                        true,
                        vec![EvidenceScoreSignal::new(
                            "semantic_recomputation",
                            "Captured output matches deterministic recomputation",
                            100,
                            true,
                            Some(evidence),
                        )],
                        vec![
                            "Verification is scoped to the imported call bytes and selected capture lengths."
                                .to_string(),
                        ],
                    ),
                });
                break 'verify;
            }
        }
    }

    let mut material_counts = BTreeMap::new();
    for material in &materials {
        *material_counts
            .entry(crypto_kind_name(material.kind).to_string())
            .or_default() += 1;
    }
    let verified_materials = materials
        .iter()
        .filter(|material| material.assessment.verification_gate_met)
        .count() as u32;
    let verified_formulas = formulas
        .iter()
        .filter(|formula| formula.assessment.verification_gate_met)
        .count() as u32;
    Ok(CryptoMaterialReport {
        materials,
        formulas,
        material_counts,
        verified_materials,
        verified_formulas,
        annotations_scanned: bundle.events.len().min(u32::MAX as usize) as u32,
        materials_truncated,
        coverage: vec![
            "Imported Frida byteArray/UTF-8/UTF-16 captures are grouped by callId and classified by explicit labels, phase, direction, and function name."
                .to_string(),
            "MD5/SHA, HMAC, and PBKDF2 outputs are deterministically recomputed when the required captured bytes and integer parameters are present in one call."
                .to_string(),
        ],
        limitations: vec![
            "Trace UI analyzes only the user-imported capture file and never attaches, spawns, loads, or executes Frida."
                .to_string(),
            "UTF-8/UTF-16 captures are re-encoded text and may not preserve invalid bytes or terminators; prefer byteArray for verification."
                .to_string(),
            "Role labels remain Related evidence unless deterministic recomputation or independently verified API semantics confirm them."
                .to_string(),
            "Capture max_bytes and pointer read failures can truncate key, input, output, salt, or digest material."
                .to_string(),
            format!(
                "PBKDF2 recomputation is bounded to {MAX_FRIDA_PBKDF2_ITERATIONS} iterations per imported call."
            ),
        ],
    })
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let cleaned: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if cleaned.is_empty()
        || cleaned.len() % 2 != 0
        || !cleaned.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).ok())
        .collect()
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn safe_comment(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

pub fn generate_angr_state_seed(
    bundle: &FridaCaptureBundle,
    event_index: u64,
    include_sp: bool,
    include_lr: bool,
) -> Result<AngrStateSeed, String> {
    if bundle.schema != FRIDA_CAPTURE_SCHEMA {
        return Err(format!(
            "unsupported Frida capture schema: {}",
            bundle.schema
        ));
    }
    let event = bundle
        .events
        .iter()
        .find(|event| event.index == event_index)
        .ok_or_else(|| format!("Frida capture event index {event_index} was not found"))?;
    if event.registers.is_empty() && event.captures.is_empty() {
        return Err("selected Frida event has no registers or captured values to seed".to_string());
    }

    let mut warnings = vec![
        "This seed is reconstructed from a user-supplied Frida capture and is candidate evidence until matched to the exact binary, hook target, and invocation.".to_string(),
        "Use a branch-level seed only when the capture point has the same state semantics as the angr blank-state address; a function-entry snapshot is not automatically a branch snapshot.".to_string(),
        "Heap and stack pointers remain process-specific absolute addresses. Module pointers are rebased when moduleBase/moduleSize are available.".to_string(),
    ];
    let mut registers_seeded = Vec::new();
    let mut registers = Vec::new();
    let mut register_lines = Vec::new();
    for index in 0..29 {
        let name = format!("x{index}");
        if let Some(value) = event.registers.get(&name) {
            if let Ok(parsed) = parse_hex_addr(value) {
                register_lines.push(format!(
                    "    state.regs.{name} = _trace_ui_rebase(0x{parsed:x}, state)"
                ));
                registers_seeded.push(name.clone());
                registers.push(AngrSeedRegister {
                    name,
                    value: format!("0x{parsed:x}"),
                });
            } else {
                warnings.push(format!("Ignored non-address register {name}={value}."));
            }
        }
    }
    if let Some((_, value)) = event
        .registers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("nzcv"))
    {
        if let Ok(parsed) = parse_hex_addr(value) {
            register_lines.push(format!("    _trace_ui_set_nzcv(state, 0x{parsed:x})"));
            registers_seeded.push("nzcv".to_string());
            registers.push(AngrSeedRegister {
                name: "nzcv".to_string(),
                value: format!("0x{parsed:x}"),
            });
            warnings.push(
                "NZCV was seeded from the Frida ARM64 context; verify that the capture point and angr instruction semantics use the same flags state.".to_string(),
            );
        } else {
            warnings.push(format!("Ignored non-address register nzcv={value}."));
        }
    }
    if let Some(value) = event.registers.get("fp") {
        if let Ok(parsed) = parse_hex_addr(value) {
            register_lines.push(format!(
                "    state.regs.x29 = _trace_ui_rebase(0x{parsed:x}, state)"
            ));
            registers_seeded.push("x29/fp".to_string());
            registers.push(AngrSeedRegister {
                name: "x29".to_string(),
                value: format!("0x{parsed:x}"),
            });
        }
    }
    if include_sp {
        if let Some(value) = event.registers.get("sp") {
            if let Ok(parsed) = parse_hex_addr(value) {
                register_lines.push(format!(
                    "    state.regs.sp = _trace_ui_rebase(0x{parsed:x}, state)"
                ));
                registers_seeded.push("sp".to_string());
                registers.push(AngrSeedRegister {
                    name: "sp".to_string(),
                    value: format!("0x{parsed:x}"),
                });
                warnings.push(
                    "SP was seeded, but uncaptured stack bytes remain unconstrained unless added as memory regions."
                        .to_string(),
                );
            }
        }
    }
    if include_lr {
        if let Some(value) = event.registers.get("lr") {
            if let Ok(parsed) = parse_hex_addr(value) {
                register_lines.push(format!(
                    "    state.regs.x30 = _trace_ui_rebase(0x{parsed:x}, state)"
                ));
                registers_seeded.push("x30/lr".to_string());
                registers.push(AngrSeedRegister {
                    name: "x30".to_string(),
                    value: format!("0x{parsed:x}"),
                });
            }
        }
    }

    let mut memory_regions = Vec::new();
    let mut memory_lines = Vec::new();
    let mut seen_memory = HashSet::new();
    for capture in &event.captures {
        if capture.read_error.is_some() {
            continue;
        }
        let Some(pointer) = capture.pointer.as_deref() else {
            continue;
        };
        let Ok(address) = parse_hex_addr(pointer) else {
            warnings.push(format!(
                "Ignored capture {} with invalid pointer {}.",
                capture.label, pointer
            ));
            continue;
        };
        if address == 0 {
            continue;
        }
        let Some(value) = capture.value.as_deref() else {
            continue;
        };
        let (bytes, source_kind) = match capture.kind.as_str() {
            "byteArray" => match decode_hex(value) {
                Some(bytes) => (bytes, "byteArray".to_string()),
                None => {
                    warnings.push(format!(
                        "Ignored byteArray capture {} because value was not complete hexadecimal bytes.",
                        capture.label
                    ));
                    continue;
                }
            },
            "utf8String" => {
                warnings.push(format!(
                    "UTF-8 capture {} was re-encoded from text; original terminator and invalid byte sequences are not preserved.",
                    capture.label
                ));
                (
                    value.as_bytes().to_vec(),
                    "utf8String-reencoded".to_string(),
                )
            }
            "utf16String" => {
                warnings.push(format!(
                    "UTF-16 capture {} was re-encoded as UTF-16LE text; original terminator and invalid code units are not preserved.",
                    capture.label
                ));
                let bytes = value
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>();
                (bytes, "utf16String-reencoded".to_string())
            }
            _ => continue,
        };
        if bytes.is_empty() || !seen_memory.insert((address, bytes.clone())) {
            continue;
        }
        let hex = bytes_hex(&bytes);
        memory_lines.push(format!(
            "    state.memory.store(_trace_ui_rebase(0x{address:x}, state), bytes.fromhex(\"{hex}\"))  # {} ({})",
            safe_comment(&capture.label),
            safe_comment(&capture.phase)
        ));
        memory_regions.push(AngrSeedMemoryRegion {
            address: format!("0x{address:x}"),
            byte_length: bytes.len() as u64,
            bytes_hex: hex,
            label: capture.label.clone(),
            source_kind,
            phase: capture.phase.clone(),
        });
    }

    if register_lines.is_empty() && memory_lines.is_empty() {
        return Err(
            "selected Frida event did not contain any valid register or memory seed".to_string(),
        );
    }
    let module_base = event
        .module_base
        .as_deref()
        .and_then(|value| parse_hex_addr(value).ok());
    let module_size = event.module_size.unwrap_or_default();
    let capture_offset = match (
        module_base,
        module_size,
        event
            .target
            .as_deref()
            .and_then(|value| parse_hex_addr(value).ok()),
    ) {
        (Some(base), size, Some(target))
            if size > 0 && target >= base && target < base.saturating_add(size) =>
        {
            Some(format!("0x{:x}", target - base))
        }
        (_, _, Some(_)) => {
            warnings.push(
                "The captured hook target could not be converted to a module-relative offset; exact OLLVM branch-seed matching is unavailable."
                    .to_string(),
            );
            None
        }
        _ => None,
    };
    if module_base.is_none() || module_size == 0 {
        warnings.push(
            "moduleBase/moduleSize were unavailable, so module-relative pointer rebasing is disabled for this seed. Regenerate the hook with the current Trace UI version for richer metadata."
                .to_string(),
        );
    }
    let module_name_literal =
        serde_json::to_string(event.module_name.as_deref().unwrap_or("unknown"))
            .map_err(|error| format!("quote module name failed: {error}"))?;
    let mut script = format!(
        "# Trace UI angr state seed from Frida 16 capture\n# Schema: {ANGR_STATE_SEED_SCHEMA}\n# Source event: {} / {} / {}\nTRACE_UI_FRIDA_MODULE_NAME = {module_name_literal}\nTRACE_UI_FRIDA_MODULE_BASE = {}\nTRACE_UI_FRIDA_MODULE_SIZE = 0x{module_size:x}\n\ndef _trace_ui_rebase(value, state):\n    if TRACE_UI_FRIDA_MODULE_BASE is not None and TRACE_UI_FRIDA_MODULE_SIZE > 0:\n        if TRACE_UI_FRIDA_MODULE_BASE <= value < TRACE_UI_FRIDA_MODULE_BASE + TRACE_UI_FRIDA_MODULE_SIZE:\n            return state.project.loader.main_object.mapped_base + (value - TRACE_UI_FRIDA_MODULE_BASE)\n    return value\n\ndef configure_state(state):\n",
        safe_comment(&event.hook_id),
        safe_comment(event.call_id.as_deref().unwrap_or("no-call-id")),
        event.index,
        module_base
            .map(|value| format!("0x{value:x}"))
            .unwrap_or_else(|| "None".to_string()),
    );
    let nzcv_helper = "\ndef _trace_ui_set_nzcv(state, value):\n    \"\"\"Seed packed AArch64 NZCV, with a conservative per-flag fallback.\"\"\"\n    try:\n        state.regs.nzcv = value\n        return\n    except Exception:\n        pass\n    wrote = False\n    for name, bit in ((\"n\", 31), (\"z\", 30), (\"c\", 29), (\"v\", 28)):\n        try:\n            setattr(state.regs, name, (value >> bit) & 1)\n            wrote = True\n        except Exception:\n            pass\n    if not wrote:\n        raise RuntimeError(\"angr architecture exposes neither packed nzcv nor individual N/Z/C/V flags\")\n";
    script = script.replace(
        "\ndef configure_state(state):\n",
        &format!("{nzcv_helper}\ndef configure_state(state):\n"),
    );
    if !register_lines.is_empty() {
        script.push_str("    # Registers captured at the selected hook event\n");
        script.push_str(&register_lines.join("\n"));
        script.push('\n');
    }
    if !memory_lines.is_empty() {
        script
            .push_str("    # Best-effort memory snapshots captured by the generated Frida hook\n");
        script.push_str(&memory_lines.join("\n"));
        script.push('\n');
    }
    script.push_str("    return state\n");

    Ok(AngrStateSeed {
        schema_version: ANGR_STATE_SEED_SCHEMA.to_string(),
        source_event_index: event.index,
        source_event: event.event.clone(),
        hook_id: event.hook_id.clone(),
        call_id: event.call_id.clone(),
        module_name: event.module_name.clone(),
        module_base: module_base.map(|value| format!("0x{value:x}")),
        module_size,
        function_name: event.function_name.clone(),
        capture_target: event.target.clone(),
        capture_offset,
        script,
        registers_seeded,
        registers,
        memory_regions,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_capture() -> Vec<u8> {
        br#"[
          {"type":"send","payload":{"protocol":"trace-ui/frida-hook-v1","hookId":"target","event":"hook-ready","functionName":"target","timestampMs":1,"threadId":7,"module":"libtarget.so","moduleBase":"0x71000000","moduleSize":4096,"target":"0x71000100"}},
          {"type":"send","payload":{"protocol":"trace-ui/frida-hook-v1","hookId":"target","event":"hook-enter","functionName":"target","timestampMs":2,"threadId":7,"registers":{"x0":"0x71000200","x1":"0x90000000","x8":"0x88","fp":"0x71000340","sp":"0xa0000000","lr":"0x71000300","pc":"0x71000100","nzcv":"0x60000000"},"captures":[{"index":1,"label":"key","kind":"byteArray","direction":"input","phase":"enter","pointer":"0x90000000","value":"00112233","byteLength":4,"requestedLength":4}]}},
          {"type":"send","payload":{"protocol":"trace-ui/frida-hook-v1","hookId":"target","event":"stalker-events","functionName":"target","timestampMs":3,"threadId":7,"mode":"blocks","events":[["block","0x1","0x2"]]}},
          {"type":"send","payload":{"protocol":"trace-ui/frida-hook-v1","hookId":"target","event":"hook-leave","functionName":"target","timestampMs":4,"threadId":7,"returnValue":"0x1","captures":[]}}
        ]"#
            .to_vec()
    }

    #[test]
    fn parses_envelopes_propagates_module_metadata_and_infers_call_ids() {
        let bundle = parse_frida_capture_bundle(&sample_capture()).unwrap();
        assert_eq!(bundle.schema, FRIDA_CAPTURE_SCHEMA);
        assert_eq!(bundle.events.len(), 4);
        assert_eq!(bundle.enter_event_count, 1);
        assert_eq!(bundle.leave_event_count, 1);
        assert_eq!(bundle.stalker_event_count, 1);
        let enter = &bundle.events[1];
        assert_eq!(enter.module_name.as_deref(), Some("libtarget.so"));
        assert_eq!(enter.module_base.as_deref(), Some("0x71000000"));
        assert_eq!(enter.call_id.as_deref(), Some("inferred:target:7:1"));
        assert_eq!(bundle.events[2].call_id, enter.call_id);
        assert_eq!(bundle.events[3].call_id, enter.call_id);
    }

    #[test]
    fn parses_ndjson_direct_payloads() {
        let input = br#"[Remote::target ]-> TRACE_UI_JSON {"protocol":"trace-ui/frida-hook-v1","eventId":"one:event:1","hookId":"one","event":"hook-enter","functionName":"one","timestampMs":1,"threadId":1,"registers":{"x0":"0x1"}}
not json
TRACE_UI_JSON {"protocol":"trace-ui/frida-hook-v1","eventId":"one:event:2","hookId":"one","event":"hook-leave","functionName":"one","timestampMs":2,"threadId":1}
TRACE_UI_JSON {"protocol":"trace-ui/frida-hook-v1","eventId":"one:event:2","hookId":"one","event":"hook-leave","functionName":"one","timestampMs":2,"threadId":1}
"#;
        let bundle = parse_frida_capture_bundle(input).unwrap();
        assert_eq!(bundle.source_format, "ndjson");
        assert_eq!(bundle.events.len(), 2);
        assert!(bundle
            .warnings
            .iter()
            .any(|warning| warning.contains("non-JSON line")));
        assert!(bundle
            .warnings
            .iter()
            .any(|warning| warning.contains("duplicate Frida eventId")));
    }

    #[test]
    fn searches_capture_events_with_bounded_metadata_summaries() {
        let bundle = parse_frida_capture_bundle(&sample_capture()).unwrap();
        let result = search_frida_capture_events(
            &bundle,
            &FridaCaptureSearchOptions {
                event_type: Some("hook-enter".to_string()),
                only_payload: true,
                offset: 0,
                limit: 1,
                ..Default::default()
            },
        );
        assert_eq!(result.matched_event_count, 1);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].index, 1);
        assert_eq!(result.events[0].capture_labels, vec!["key"]);
        assert_eq!(result.events[0].register_count, 8);
        assert!(!result.has_more);
        let serialized = serde_json::to_value(&result).unwrap();
        assert!(serialized["events"][0].get("registers").is_none());
        assert!(serialized["events"][0].get("captures").is_none());
    }

    #[test]
    fn gets_one_event_with_opt_in_and_bounded_payload_details() {
        let bundle = parse_frida_capture_bundle(&sample_capture()).unwrap();
        let detail = get_frida_capture_event(&bundle, 1, true, true, false, false, 2).unwrap();
        assert_eq!(detail.event.index, 1);
        assert!(detail.registers.as_ref().unwrap().contains_key("x0"));
        let capture = &detail.captures.as_ref().unwrap()[0];
        assert_eq!(capture.value.as_deref(), Some("0011"));
        assert!(capture.value_truncated);
        assert!(detail
            .warnings
            .iter()
            .any(|warning| warning.contains("truncated")));
        assert!(get_frida_capture_event(&bundle, 999, false, false, false, false, 256).is_err());
    }

    #[test]
    fn generates_rebased_angr_seed_from_registers_and_memory() {
        let bundle = parse_frida_capture_bundle(&sample_capture()).unwrap();
        let seed = generate_angr_state_seed(&bundle, 1, false, true).unwrap();
        assert_eq!(seed.schema_version, ANGR_STATE_SEED_SCHEMA);
        assert!(seed.script.contains("state.regs.x0"));
        assert!(seed.script.contains("state.regs.x8"));
        assert!(seed.script.contains("state.regs.x29"));
        assert!(seed.script.contains("state.regs.x30"));
        assert!(seed
            .script
            .contains("_trace_ui_set_nzcv(state, 0x60000000)"));
        assert!(!seed.script.contains("state.regs.pc"));
        assert!(!seed.script.contains("state.regs.sp"));
        assert!(seed.script.contains("bytes.fromhex(\"00112233\")"));
        assert!(seed.script.contains("main_object.mapped_base"));
        assert_eq!(seed.source_event, "hook-enter");
        assert_eq!(seed.capture_offset.as_deref(), Some("0x100"));
        assert!(seed.registers.iter().any(|register| register.name == "x8"));
        assert!(seed
            .registers
            .iter()
            .any(|register| register.name == "nzcv"));
        assert_eq!(seed.memory_regions.len(), 1);
    }

    #[test]
    fn preserves_extended_ollvm_pointer_and_stack_captures_in_state_seed() {
        let capture = serde_json::json!([{
            "protocol": FRIDA_HOOK_PROTOCOL,
            "hookId": "ollvm-dispatchers",
            "event": "ollvm-dispatcher-hit",
            "functionName": "dispatcher-100",
            "timestampMs": 1,
            "threadId": 1,
            "module": "libtarget.so",
            "moduleBase": "0x71000000",
            "moduleSize": 0x4000,
            "target": "0x71000100",
            "dispatcherOffset": "0x100",
            "registers": {
                "x19": "0x90000000",
                "sp": "0xa0000000",
                "pc": "0x71000100",
                "nzcv": "0x0"
            },
            "captures": [
                {
                    "index": 19,
                    "label": "x19-memory",
                    "kind": "byteArray",
                    "direction": "input",
                    "phase": "enter",
                    "pointer": "0x90000000",
                    "value": "00112233",
                    "byteLength": 4,
                    "requestedLength": 4
                },
                {
                    "index": 29,
                    "label": "sp-stack-memory",
                    "kind": "byteArray",
                    "direction": "input",
                    "phase": "enter",
                    "pointer": "0xa0000000",
                    "value": "aabbccdd",
                    "byteLength": 4,
                    "requestedLength": 4
                }
            ]
        }]);
        let bundle = parse_frida_capture_bundle(&serde_json::to_vec(&capture).unwrap()).unwrap();
        assert_eq!(bundle.events[0].captures.len(), 2);
        assert_eq!(bundle.events[0].captures[0].index, 19);
        assert_eq!(bundle.events[0].captures[1].index, 29);

        let seed = generate_angr_state_seed(&bundle, 0, true, true).unwrap();
        assert_eq!(seed.memory_regions.len(), 2);
        assert!(seed
            .memory_regions
            .iter()
            .any(|region| region.label == "x19-memory" && region.address == "0x90000000"));
        assert!(seed
            .memory_regions
            .iter()
            .any(|region| { region.label == "sp-stack-memory" && region.address == "0xa0000000" }));
    }

    #[test]
    fn rejects_non_ascii_byte_array_text_without_panicking() {
        assert_eq!(decode_hex("𐀀"), None);
    }

    #[test]
    fn indexes_and_verifies_sha256_material_from_one_captured_call() {
        let capture = serde_json::json!([
            {
                "protocol": FRIDA_HOOK_PROTOCOL,
                "hookId": "sha",
                "event": "hook-enter",
                "functionName": "SHA256",
                "timestampMs": 1,
                "threadId": 1,
                "callId": "sha:1",
                "captures": [{
                    "index": 0,
                    "label": "data",
                    "kind": "byteArray",
                    "direction": "input",
                    "phase": "enter",
                    "pointer": "0x1000",
                    "value": "616263",
                    "byteLength": 3
                }]
            },
            {
                "protocol": FRIDA_HOOK_PROTOCOL,
                "hookId": "sha",
                "event": "hook-leave",
                "functionName": "SHA256",
                "timestampMs": 2,
                "threadId": 1,
                "callId": "sha:1",
                "captures": [{
                    "index": 2,
                    "label": "digest",
                    "kind": "byteArray",
                    "direction": "output",
                    "phase": "leave",
                    "pointer": "0x2000",
                    "value": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "byteLength": 32
                }]
            }
        ]);
        let bundle = parse_frida_capture_bundle(&serde_json::to_vec(&capture).unwrap()).unwrap();
        let report = analyze_frida_crypto_materials(&bundle, None, false).unwrap();
        assert_eq!(report.formulas.len(), 1);
        assert_eq!(report.verified_formulas, 1);
        assert_eq!(report.verified_materials, 2);
        assert!(report
            .materials
            .iter()
            .any(|material| material.kind == CryptoMaterialKind::Digest));
    }

    #[test]
    fn verifies_hmac_key_input_and_mac_from_one_captured_call() {
        let key = b"secret";
        let input = b"message";
        let expected = FridaHashAlgorithm::Sha256.hmac(key, input).unwrap();
        let capture = serde_json::json!([
            {
                "protocol": FRIDA_HOOK_PROTOCOL,
                "hookId": "hmac",
                "event": "hook-enter",
                "functionName": "HMAC_SHA256",
                "timestampMs": 1,
                "threadId": 1,
                "callId": "hmac:1",
                "captures": [
                    {"index":0,"label":"key","kind":"byteArray","direction":"input","phase":"enter","pointer":"0x1000","value":bytes_hex(key)},
                    {"index":1,"label":"data","kind":"byteArray","direction":"input","phase":"enter","pointer":"0x2000","value":bytes_hex(input)}
                ]
            },
            {
                "protocol": FRIDA_HOOK_PROTOCOL,
                "hookId": "hmac",
                "event": "hook-leave",
                "functionName": "HMAC_SHA256",
                "timestampMs": 2,
                "threadId": 1,
                "callId": "hmac:1",
                "captures": [{"index":2,"label":"mac","kind":"byteArray","direction":"output","phase":"leave","pointer":"0x3000","value":bytes_hex(&expected)}]
            }
        ]);
        let bundle = parse_frida_capture_bundle(&serde_json::to_vec(&capture).unwrap()).unwrap();
        let report = analyze_frida_crypto_materials(&bundle, None, false).unwrap();
        assert_eq!(report.verified_formulas, 1);
        assert_eq!(report.verified_materials, 3);
        assert_eq!(report.formulas[0].operation, "HMAC");
        assert_eq!(report.formulas[0].input_material_ids.len(), 2);
    }

    #[test]
    fn verifies_pbkdf2_password_salt_iterations_and_derived_key() {
        let password = b"password";
        let salt = b"salt";
        let mut derived = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(password, salt, 2, &mut derived);
        let capture = serde_json::json!([
            {
                "protocol": FRIDA_HOOK_PROTOCOL,
                "hookId": "kdf",
                "event": "hook-enter",
                "functionName": "PBKDF2_HMAC_SHA256",
                "timestampMs": 1,
                "threadId": 1,
                "callId": "kdf:1",
                "captures": [
                    {"index":0,"label":"password","kind":"byteArray","direction":"input","phase":"enter","pointer":"0x1000","value":bytes_hex(password)},
                    {"index":1,"label":"salt","kind":"byteArray","direction":"input","phase":"enter","pointer":"0x2000","value":bytes_hex(salt)},
                    {"index":2,"label":"iterations","kind":"integer","direction":"input","phase":"enter","pointer":"0x2","value":"0x2"}
                ]
            },
            {
                "protocol": FRIDA_HOOK_PROTOCOL,
                "hookId": "kdf",
                "event": "hook-leave",
                "functionName": "PBKDF2_HMAC_SHA256",
                "timestampMs": 2,
                "threadId": 1,
                "callId": "kdf:1",
                "captures": [{"index":3,"label":"output","kind":"byteArray","direction":"output","phase":"leave","pointer":"0x3000","value":bytes_hex(&derived)}]
            }
        ]);
        let bundle = parse_frida_capture_bundle(&serde_json::to_vec(&capture).unwrap()).unwrap();
        let report = analyze_frida_crypto_materials(&bundle, None, false).unwrap();
        assert_eq!(report.verified_formulas, 1);
        assert!(report
            .materials
            .iter()
            .any(|material| material.kind == CryptoMaterialKind::Salt));
        assert!(report
            .materials
            .iter()
            .any(|material| material.kind == CryptoMaterialKind::DerivedKey));
    }

    #[test]
    fn skips_pbkdf2_recomputation_above_the_iteration_limit() {
        let capture = serde_json::json!([
            {
                "protocol": FRIDA_HOOK_PROTOCOL,
                "hookId": "kdf-limit",
                "event": "hook-enter",
                "functionName": "PBKDF2_HMAC_SHA256",
                "timestampMs": 1,
                "threadId": 1,
                "callId": "kdf-limit:1",
                "captures": [
                    {"index":0,"label":"password","kind":"byteArray","direction":"input","phase":"enter","pointer":"0x1000","value":"70617373776f7264"},
                    {"index":1,"label":"salt","kind":"byteArray","direction":"input","phase":"enter","pointer":"0x2000","value":"73616c74"},
                    {"index":2,"label":"iterations","kind":"integer","direction":"input","phase":"enter","pointer":"0xf4241","value":"0xf4241"}
                ]
            },
            {
                "protocol": FRIDA_HOOK_PROTOCOL,
                "hookId": "kdf-limit",
                "event": "hook-leave",
                "functionName": "PBKDF2_HMAC_SHA256",
                "timestampMs": 2,
                "threadId": 1,
                "callId": "kdf-limit:1",
                "captures": [{"index":3,"label":"output","kind":"byteArray","direction":"output","phase":"leave","pointer":"0x3000","value":"0000000000000000000000000000000000000000000000000000000000000000"}]
            }
        ]);
        let bundle = parse_frida_capture_bundle(&serde_json::to_vec(&capture).unwrap()).unwrap();
        let report = analyze_frida_crypto_materials(&bundle, None, false).unwrap();
        assert_eq!(report.verified_formulas, 0);
        assert_eq!(report.verified_materials, 0);
        assert!(report.formulas.is_empty());
    }

    #[test]
    fn generated_angr_seed_has_valid_python_syntax_when_python_is_available() {
        let python = ["python3", "python"].into_iter().find(|candidate| {
            std::process::Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        });
        let Some(python) = python else {
            eprintln!("skipping angr state seed syntax check: Python is unavailable");
            return;
        };
        let bundle = parse_frida_capture_bundle(&sample_capture()).unwrap();
        let seed = generate_angr_state_seed(&bundle, 1, false, true).unwrap();
        let directory =
            std::env::temp_dir().join(format!("trace-ui-angr-seed-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let script_path = directory.join("seed.py");
        std::fs::write(&script_path, seed.script).unwrap();
        let output = std::process::Command::new(python)
            .arg("-m")
            .arg("py_compile")
            .arg(&script_path)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            output.status.success(),
            "generated state seed failed py_compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn rejects_capture_without_trace_ui_events() {
        assert!(parse_frida_capture_bundle(br#"[{"type":"log","payload":"hello"}]"#).is_err());
    }
}
