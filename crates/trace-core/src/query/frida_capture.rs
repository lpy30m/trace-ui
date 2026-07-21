use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::utils::parse_hex_addr;

const FRIDA_CAPTURE_SCHEMA: &str = "trace-ui/frida-capture-v1";
const FRIDA_HOOK_PROTOCOL: &str = "trace-ui/frida-hook-v1";
const ANGR_STATE_SEED_SCHEMA: &str = "trace-ui/angr-state-seed-v1";

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
pub struct AngrStateSeed {
    pub schema_version: String,
    pub source_event_index: u64,
    pub hook_id: String,
    pub call_id: Option<String>,
    pub module_name: Option<String>,
    pub function_name: String,
    pub capture_target: Option<String>,
    pub script: String,
    pub registers_seeded: Vec<String>,
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
    if index > 7 {
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
    let mut register_lines = Vec::new();
    for index in 0..8 {
        let name = format!("x{index}");
        if let Some(value) = event.registers.get(&name) {
            if let Ok(parsed) = parse_hex_addr(value) {
                register_lines.push(format!(
                    "    state.regs.{name} = _trace_ui_rebase(0x{parsed:x}, state)"
                ));
                registers_seeded.push(name);
            } else {
                warnings.push(format!("Ignored non-address register {name}={value}."));
            }
        }
    }
    if include_sp {
        if let Some(value) = event.registers.get("sp") {
            if let Ok(parsed) = parse_hex_addr(value) {
                register_lines.push(format!(
                    "    state.regs.sp = _trace_ui_rebase(0x{parsed:x}, state)"
                ));
                registers_seeded.push("sp".to_string());
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
        hook_id: event.hook_id.clone(),
        call_id: event.call_id.clone(),
        module_name: event.module_name.clone(),
        function_name: event.function_name.clone(),
        capture_target: event.target.clone(),
        script,
        registers_seeded,
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
          {"type":"send","payload":{"protocol":"trace-ui/frida-hook-v1","hookId":"target","event":"hook-enter","functionName":"target","timestampMs":2,"threadId":7,"registers":{"x0":"0x71000200","x1":"0x90000000","sp":"0xa0000000","lr":"0x71000300","pc":"0x71000100"},"captures":[{"index":1,"label":"key","kind":"byteArray","direction":"input","phase":"enter","pointer":"0x90000000","value":"00112233","byteLength":4,"requestedLength":4}]}},
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
    fn generates_rebased_angr_seed_from_registers_and_memory() {
        let bundle = parse_frida_capture_bundle(&sample_capture()).unwrap();
        let seed = generate_angr_state_seed(&bundle, 1, false, true).unwrap();
        assert_eq!(seed.schema_version, ANGR_STATE_SEED_SCHEMA);
        assert!(seed.script.contains("state.regs.x0"));
        assert!(seed.script.contains("state.regs.x30"));
        assert!(!seed.script.contains("state.regs.pc"));
        assert!(!seed.script.contains("state.regs.sp"));
        assert!(seed.script.contains("bytes.fromhex(\"00112233\")"));
        assert!(seed.script.contains("main_object.mapped_base"));
        assert_eq!(seed.memory_regions.len(), 1);
    }

    #[test]
    fn rejects_non_ascii_byte_array_text_without_panicking() {
        assert_eq!(decode_hex("𐀀"), None);
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
