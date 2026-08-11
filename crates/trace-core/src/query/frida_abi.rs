//! Conservative ABI and structure-role inference over user-captured Frida events.
//!
//! Every classification remains Candidate/Related. The analysis uses repeated observations,
//! enter/leave byte changes, explicit capture metadata, and pointer/length equality; it never turns
//! labels alone into proof and never executes Frida or the target.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::query::frida_capture::{
    parse_frida_capture_bundle, FridaCaptureBundle, FridaCaptureEvent, FridaCapturedValue,
};
use crate::utils::{format_signed_offset_hex, parse_hex_addr, parse_signed_offset};

pub const FRIDA_ABI_INFERENCE_SCHEMA: &str = "trace-ui/frida-abi-inference-v1";
const MAX_CAPTURE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVIDENCE_EVENTS: usize = 32;

#[derive(Clone, Debug)]
pub struct FridaAbiInferenceOptions {
    pub min_observations: u32,
    pub max_functions: u32,
    pub max_candidates_per_function: u32,
}

impl Default for FridaAbiInferenceOptions {
    fn default() -> Self {
        Self {
            min_observations: 2,
            max_functions: 64,
            max_candidates_per_function: 128,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FridaAbiArgumentCandidate {
    pub index: u8,
    pub register: String,
    pub observation_count: u64,
    pub call_count: u64,
    pub observed_kinds: Vec<String>,
    pub declared_directions: Vec<String>,
    pub labels: Vec<String>,
    pub pointer_observation_count: u64,
    pub distinct_pointer_count: u64,
    pub stable_pointer_across_calls: bool,
    pub observed_byte_lengths: Vec<u64>,
    pub enter_leave_pair_count: u64,
    pub changed_enter_leave_pair_count: u64,
    pub unchanged_enter_leave_pair_count: u64,
    pub role_candidates: Vec<String>,
    pub confidence: String,
    pub evidence_event_indices: Vec<u64>,
    pub evidence_level: String,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FridaPointerLengthPairCandidate {
    pub pointer_index: u8,
    pub pointer_register: String,
    pub length_index: u8,
    pub length_register: String,
    pub matched_observation_count: u64,
    pub compared_observation_count: u64,
    pub match_ratio: f64,
    pub confidence: String,
    pub evidence_event_indices: Vec<u64>,
    pub rationale: String,
    pub evidence_level: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FridaContextPointerCandidate {
    pub index: u8,
    pub register: String,
    pub sample_pointer: String,
    pub call_count: u64,
    pub distinct_pointer_count: u64,
    pub varying_other_argument_count: u64,
    pub explicit_context_label: bool,
    pub confidence: String,
    pub evidence_event_indices: Vec<u64>,
    pub rationale: String,
    pub evidence_level: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FridaStructFieldCandidate {
    pub base_register: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_argument_index: Option<u8>,
    pub displacement: String,
    pub observation_count: u64,
    pub readable_observation_count: u64,
    pub unreadable_observation_count: u64,
    pub observed_byte_lengths: Vec<u64>,
    pub labels: Vec<String>,
    pub value_change_count: u64,
    pub role_candidates: Vec<String>,
    pub confidence: String,
    pub evidence_event_indices: Vec<u64>,
    pub rationale: String,
    pub evidence_level: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FridaReturnCandidate {
    pub observation_count: u64,
    pub distinct_value_count: u64,
    pub zero_count: u64,
    pub nonzero_count: u64,
    pub role_candidate: String,
    pub sample_values: Vec<String>,
    pub evidence_event_indices: Vec<u64>,
    pub evidence_level: String,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FridaFunctionAbiInference {
    pub hook_id: String,
    pub function_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub event_count: u64,
    pub call_count: u64,
    pub argument_candidates: Vec<FridaAbiArgumentCandidate>,
    pub pointer_length_pairs: Vec<FridaPointerLengthPairCandidate>,
    pub context_pointer_candidates: Vec<FridaContextPointerCandidate>,
    pub struct_field_candidates: Vec<FridaStructFieldCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_candidate: Option<FridaReturnCandidate>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FridaAbiInferenceReport {
    pub schema: String,
    pub source_schema: String,
    pub source_event_count: u64,
    pub analyzed_function_count: u64,
    pub omitted_function_count: u64,
    pub min_observations: u32,
    pub functions: Vec<FridaFunctionAbiInference>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone)]
struct ArgumentObservation {
    event_index: u64,
    call_key: String,
    phase: String,
    kind: String,
    direction: String,
    label: String,
    pointer: Option<u64>,
    integer: Option<u64>,
    bytes: Option<Vec<u8>>,
    byte_length: Option<u64>,
    requested_length: Option<u64>,
}

#[derive(Clone)]
struct FieldObservation {
    event_index: u64,
    base_register: String,
    displacement: i64,
    label: String,
    bytes: Option<Vec<u8>>,
    byte_length: Option<u64>,
    read_error: bool,
}

fn bounded_options(options: &FridaAbiInferenceOptions) -> FridaAbiInferenceOptions {
    FridaAbiInferenceOptions {
        min_observations: options.min_observations.clamp(2, 64),
        max_functions: options.max_functions.clamp(1, 128),
        max_candidates_per_function: options.max_candidates_per_function.clamp(8, 512),
    }
}

fn parse_integer(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.starts_with("0x") || value.starts_with("0X") {
        parse_hex_addr(value).ok()
    } else {
        value
            .parse::<u64>()
            .ok()
            .or_else(|| parse_hex_addr(value).ok())
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

fn capture_bytes(capture: &FridaCapturedValue) -> Option<Vec<u8>> {
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

fn call_key(event: &FridaCaptureEvent) -> String {
    event
        .call_id
        .clone()
        .unwrap_or_else(|| format!("event:{}", event.index))
}

fn label_tokens(label: &str) -> HashSet<String> {
    label
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn explicit_roles(labels: impl Iterator<Item = String>) -> Vec<String> {
    let mut roles = BTreeSet::new();
    for label in labels {
        let tokens = label_tokens(&label);
        let has = |values: &[&str]| values.iter().any(|value| tokens.contains(*value));
        if has(&["ctx", "context", "state", "session", "handle"]) {
            roles.insert("context-pointer-candidate".to_string());
        }
        if has(&["len", "length", "size", "count", "bytes"]) {
            roles.insert("length-candidate".to_string());
        }
        if has(&["key", "secret", "password", "passphrase"]) {
            roles.insert("key-or-secret-candidate".to_string());
        }
        if has(&["iv", "nonce", "salt", "aad", "tag"]) {
            roles.insert("crypto-parameter-candidate".to_string());
        }
        if has(&[
            "input", "src", "source", "plain", "cipher", "data", "message",
        ]) {
            roles.insert("input-buffer-candidate".to_string());
        }
        if has(&["output", "out", "dst", "dest", "result", "digest", "mac"]) {
            roles.insert("output-buffer-candidate".to_string());
        }
    }
    roles.into_iter().collect()
}

fn event_indices(observations: impl Iterator<Item = u64>) -> Vec<u64> {
    let mut indices = observations
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    indices.truncate(MAX_EVIDENCE_EVENTS);
    indices
}

fn observation_length(observation: &ArgumentObservation) -> Option<u64> {
    observation
        .byte_length
        .or(observation.requested_length)
        .or_else(|| observation.bytes.as_ref().map(|bytes| bytes.len() as u64))
}

fn function_key(event: &FridaCaptureEvent) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        event.hook_id,
        event.function_name,
        event.module_name.as_deref().unwrap_or_default(),
        event.target.as_deref().unwrap_or_default()
    )
}

fn argument_candidate(
    index: u8,
    observations: &[ArgumentObservation],
    min_observations: u32,
) -> FridaAbiArgumentCandidate {
    let calls = observations
        .iter()
        .map(|observation| observation.call_key.clone())
        .collect::<BTreeSet<_>>();
    let pointers = observations
        .iter()
        .filter_map(|observation| observation.pointer)
        .collect::<BTreeSet<_>>();
    let kinds = observations
        .iter()
        .map(|observation| observation.kind.clone())
        .collect::<BTreeSet<_>>();
    let directions = observations
        .iter()
        .map(|observation| observation.direction.clone())
        .collect::<BTreeSet<_>>();
    let labels = observations
        .iter()
        .map(|observation| observation.label.clone())
        .collect::<BTreeSet<_>>();
    let lengths = observations
        .iter()
        .filter_map(observation_length)
        .collect::<BTreeSet<_>>();

    let mut pairs = 0u64;
    let mut changed = 0u64;
    let mut unchanged = 0u64;
    let mut by_call = BTreeMap::<String, (Option<&[u8]>, Option<&[u8]>)>::new();
    for observation in observations {
        let Some(bytes) = observation.bytes.as_deref() else {
            continue;
        };
        let pair = by_call.entry(observation.call_key.clone()).or_default();
        if observation.phase.eq_ignore_ascii_case("enter") {
            pair.0 = Some(bytes);
        } else if observation.phase.eq_ignore_ascii_case("leave") {
            pair.1 = Some(bytes);
        }
    }
    for (enter, leave) in by_call.values() {
        if let (Some(enter), Some(leave)) = (enter, leave) {
            pairs += 1;
            if enter == leave {
                unchanged += 1;
            } else {
                changed += 1;
            }
        }
    }

    let mut roles = explicit_roles(labels.iter().cloned());
    if directions
        .iter()
        .any(|direction| direction.eq_ignore_ascii_case("output"))
    {
        roles.push("declared-output-candidate".to_string());
    }
    if directions
        .iter()
        .any(|direction| direction.eq_ignore_ascii_case("input"))
    {
        roles.push("declared-input-candidate".to_string());
    }
    if changed > 0 {
        roles.push("mutated-output-or-inout-candidate".to_string());
    } else if unchanged >= min_observations as u64 {
        roles.push("unchanged-across-captured-boundary".to_string());
    }
    roles.sort();
    roles.dedup();

    let stable_pointer = calls.len() >= min_observations as usize && pointers.len() == 1;
    let confidence = if changed >= min_observations as u64
        || (stable_pointer && roles.iter().any(|role| role.contains("context")))
    {
        "high"
    } else if observations.len() >= min_observations as usize && !roles.is_empty() {
        "medium"
    } else {
        "low"
    };
    FridaAbiArgumentCandidate {
        index,
        register: format!("x{index}"),
        observation_count: observations.len() as u64,
        call_count: calls.len() as u64,
        observed_kinds: kinds.into_iter().collect(),
        declared_directions: directions.into_iter().collect(),
        labels: labels.into_iter().collect(),
        pointer_observation_count: observations
            .iter()
            .filter(|observation| observation.pointer.is_some())
            .count() as u64,
        distinct_pointer_count: pointers.len() as u64,
        stable_pointer_across_calls: stable_pointer,
        observed_byte_lengths: lengths.into_iter().collect(),
        enter_leave_pair_count: pairs,
        changed_enter_leave_pair_count: changed,
        unchanged_enter_leave_pair_count: unchanged,
        role_candidates: roles,
        confidence: confidence.to_string(),
        evidence_event_indices: event_indices(
            observations.iter().map(|observation| observation.event_index),
        ),
        evidence_level: "candidate/related".to_string(),
        limitations: vec![
            "Capture labels/directions describe Hook configuration and are Related evidence unless byte changes or independent semantics corroborate them."
                .to_string(),
            "An unchanged captured window may still be read, aliased, partially updated outside the window, or used only on unexecuted paths."
                .to_string(),
        ],
    }
}

fn pointer_length_pairs(
    arguments: &BTreeMap<u8, Vec<ArgumentObservation>>,
    min_observations: u32,
    max_candidates: usize,
) -> Vec<FridaPointerLengthPairCandidate> {
    let pointer_indices = arguments
        .iter()
        .filter(|(_, observations)| {
            observations
                .iter()
                .any(|observation| observation.pointer.is_some() || observation.bytes.is_some())
        })
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    let integer_indices = arguments
        .iter()
        .filter(|(_, observations)| {
            observations
                .iter()
                .any(|observation| observation.integer.is_some())
        })
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    for pointer_index in pointer_indices {
        for length_index in &integer_indices {
            if pointer_index == *length_index {
                continue;
            }
            let mut pointer_by_call = BTreeMap::<&str, &ArgumentObservation>::new();
            for observation in &arguments[&pointer_index] {
                if observation_length(observation).is_some() {
                    pointer_by_call
                        .entry(observation.call_key.as_str())
                        .or_insert(observation);
                }
            }
            let mut length_by_call = BTreeMap::<&str, &ArgumentObservation>::new();
            for observation in &arguments[length_index] {
                if observation.integer.is_some() {
                    length_by_call
                        .entry(observation.call_key.as_str())
                        .or_insert(observation);
                }
            }
            let mut compared = 0u64;
            let mut matched = 0u64;
            let mut evidence = BTreeSet::new();
            for (call, pointer) in &pointer_by_call {
                let Some(length) = length_by_call.get(call) else {
                    continue;
                };
                compared += 1;
                evidence.insert(pointer.event_index);
                evidence.insert(length.event_index);
                if observation_length(pointer) == length.integer {
                    matched += 1;
                }
            }
            if matched < min_observations as u64 || compared == 0 {
                continue;
            }
            let ratio = matched as f64 / compared as f64;
            if ratio < 0.75 {
                continue;
            }
            let confidence = if matched >= 3 && ratio == 1.0 {
                "high"
            } else if matched >= 2 && ratio >= 0.8 {
                "medium"
            } else {
                "low"
            };
            candidates.push(FridaPointerLengthPairCandidate {
                pointer_index,
                pointer_register: format!("x{pointer_index}"),
                length_index: *length_index,
                length_register: format!("x{length_index}"),
                matched_observation_count: matched,
                compared_observation_count: compared,
                match_ratio: ratio,
                confidence: confidence.to_string(),
                evidence_event_indices: evidence.into_iter().take(MAX_EVIDENCE_EVENTS).collect(),
                rationale: "The scalar argument repeatedly equals the captured/requested byte length for the pointer argument in the same call."
                    .to_string(),
                evidence_level: "candidate/related".to_string(),
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .matched_observation_count
            .cmp(&left.matched_observation_count)
            .then_with(|| left.pointer_index.cmp(&right.pointer_index))
            .then_with(|| left.length_index.cmp(&right.length_index))
    });
    candidates.truncate(max_candidates);
    candidates
}

fn context_candidates(
    arguments: &BTreeMap<u8, Vec<ArgumentObservation>>,
    min_observations: u32,
    max_candidates: usize,
) -> Vec<FridaContextPointerCandidate> {
    let varying_arguments = arguments
        .iter()
        .filter(|(_, observations)| {
            let pointers = observations
                .iter()
                .filter_map(|observation| observation.pointer)
                .collect::<BTreeSet<_>>();
            let values = observations
                .iter()
                .filter_map(|observation| observation.bytes.as_ref())
                .map(|bytes| bytes.as_slice())
                .collect::<HashSet<_>>();
            pointers.len() > 1 || values.len() > 1
        })
        .map(|(index, _)| *index)
        .collect::<BTreeSet<_>>();
    let mut candidates = Vec::new();
    for (index, observations) in arguments {
        let calls = observations
            .iter()
            .map(|observation| observation.call_key.as_str())
            .collect::<BTreeSet<_>>();
        let pointers = observations
            .iter()
            .filter_map(|observation| observation.pointer)
            .collect::<BTreeSet<_>>();
        if calls.len() < min_observations as usize || pointers.len() != 1 {
            continue;
        }
        let explicit = observations.iter().any(|observation| {
            explicit_roles(std::iter::once(observation.label.clone()))
                .iter()
                .any(|role| role == "context-pointer-candidate")
        });
        let varying_other_count = varying_arguments
            .iter()
            .filter(|other| **other != *index)
            .count();
        let large_window = observations
            .iter()
            .filter_map(observation_length)
            .max()
            .unwrap_or_default()
            >= 32;
        if !explicit && !(varying_other_count >= 2 && large_window) {
            continue;
        }
        let confidence = if explicit && calls.len() >= 3 && varying_other_count > 0 {
            "high"
        } else {
            "medium"
        };
        candidates.push(FridaContextPointerCandidate {
            index: *index,
            register: format!("x{index}"),
            sample_pointer: format!("0x{:x}", pointers.iter().next().copied().unwrap_or_default()),
            call_count: calls.len() as u64,
            distinct_pointer_count: pointers.len() as u64,
            varying_other_argument_count: varying_other_count as u64,
            explicit_context_label: explicit,
            confidence: confidence.to_string(),
            evidence_event_indices: event_indices(
                observations.iter().map(|observation| observation.event_index),
            ),
            rationale: "This pointer remains stable across repeated calls while explicit context metadata and/or other arguments vary. Runtime addresses are process-specific."
                .to_string(),
            evidence_level: "candidate/related".to_string(),
        });
    }
    candidates.sort_by(|left, right| {
        right
            .call_count
            .cmp(&left.call_count)
            .then_with(|| left.index.cmp(&right.index))
    });
    candidates.truncate(max_candidates);
    candidates
}

fn struct_field_candidates(
    observations: &[FieldObservation],
    min_observations: u32,
    max_candidates: usize,
) -> Vec<FridaStructFieldCandidate> {
    let mut groups = BTreeMap::<(String, i64), Vec<&FieldObservation>>::new();
    for observation in observations {
        groups
            .entry((observation.base_register.clone(), observation.displacement))
            .or_default()
            .push(observation);
    }
    let mut candidates = Vec::new();
    for ((base_register, displacement), items) in groups {
        if items.len() < min_observations as usize {
            continue;
        }
        let labels = items
            .iter()
            .map(|item| item.label.clone())
            .collect::<BTreeSet<_>>();
        let lengths = items
            .iter()
            .filter_map(|item| {
                item.byte_length
                    .or_else(|| item.bytes.as_ref().map(|bytes| bytes.len() as u64))
            })
            .collect::<BTreeSet<_>>();
        let readable = items.iter().filter(|item| item.bytes.is_some()).count() as u64;
        let unreadable = items.iter().filter(|item| item.read_error).count() as u64;
        let mut changes = 0u64;
        let values = items
            .iter()
            .filter_map(|item| item.bytes.as_deref())
            .collect::<Vec<_>>();
        for pair in values.windows(2) {
            if pair[0] != pair[1] {
                changes += 1;
            }
        }
        let roles = explicit_roles(labels.iter().cloned());
        let confidence = if items.len() >= 3 && (!roles.is_empty() || changes > 0) {
            "medium"
        } else {
            "low"
        };
        let base_argument_index = base_register
            .strip_prefix('x')
            .or_else(|| base_register.strip_prefix('X'))
            .and_then(|value| value.parse::<u8>().ok())
            .filter(|index| *index <= 7);
        candidates.push(FridaStructFieldCandidate {
            base_register: base_register.clone(),
            base_argument_index,
            displacement: format_signed_offset_hex(displacement),
            observation_count: items.len() as u64,
            readable_observation_count: readable,
            unreadable_observation_count: unreadable,
            observed_byte_lengths: lengths.into_iter().collect(),
            labels: labels.into_iter().collect(),
            value_change_count: changes,
            role_candidates: roles,
            confidence: confidence.to_string(),
            evidence_event_indices: event_indices(items.iter().map(|item| item.event_index)),
            rationale: "Repeated captures use the same base register and displacement. This is a field/window candidate, not proof of a C struct layout or type."
                .to_string(),
            evidence_level: "candidate/related".to_string(),
        });
    }
    candidates.sort_by(|left, right| {
        right
            .observation_count
            .cmp(&left.observation_count)
            .then_with(|| left.base_register.cmp(&right.base_register))
            .then_with(|| left.displacement.cmp(&right.displacement))
    });
    candidates.truncate(max_candidates);
    candidates
}

fn return_candidate(events: &[&FridaCaptureEvent]) -> Option<FridaReturnCandidate> {
    let observations = events
        .iter()
        .filter_map(|event| event.return_value.as_ref().map(|value| (*event, value)))
        .collect::<Vec<_>>();
    if observations.is_empty() {
        return None;
    }
    let parsed = observations
        .iter()
        .filter_map(|(_, value)| parse_integer(value))
        .collect::<Vec<_>>();
    let zero_count = parsed.iter().filter(|value| **value == 0).count() as u64;
    let nonzero_count = parsed.len() as u64 - zero_count;
    let pointer_like = !parsed.is_empty()
        && parsed.iter().filter(|value| **value >= 0x1_0000).count() * 2 >= parsed.len();
    let small_scalar = !parsed.is_empty() && parsed.iter().all(|value| *value <= 0xffff);
    let role = if pointer_like {
        "pointer-or-handle-candidate"
    } else if small_scalar && zero_count > 0 && nonzero_count > 0 {
        "status-code-candidate"
    } else {
        "scalar-return-candidate"
    };
    Some(FridaReturnCandidate {
        observation_count: observations.len() as u64,
        distinct_value_count: observations
            .iter()
            .map(|(_, value)| value.as_str())
            .collect::<BTreeSet<_>>()
            .len() as u64,
        zero_count,
        nonzero_count,
        role_candidate: role.to_string(),
        sample_values: observations
            .iter()
            .map(|(_, value)| (*value).clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(8)
            .collect(),
        evidence_event_indices: event_indices(observations.iter().map(|(event, _)| event.index)),
        evidence_level: "candidate/related".to_string(),
        limitations: vec![
            "Return-value shape alone cannot distinguish a pointer, handle, byte count, status enum, or packed scalar."
                .to_string(),
        ],
    })
}

fn analyze_function(
    events: &[&FridaCaptureEvent],
    options: &FridaAbiInferenceOptions,
) -> FridaFunctionAbiInference {
    let first = events[0];
    let mut arguments = BTreeMap::<u8, Vec<ArgumentObservation>>::new();
    let mut fields = Vec::new();
    let mut calls = BTreeSet::new();
    for event in events {
        calls.insert(call_key(event));
        for capture in &event.captures {
            if capture.index <= 7 {
                arguments
                    .entry(capture.index)
                    .or_default()
                    .push(ArgumentObservation {
                        event_index: event.index,
                        call_key: call_key(event),
                        phase: capture.phase.clone(),
                        kind: capture.kind.clone(),
                        direction: capture.direction.clone(),
                        label: capture.label.clone(),
                        pointer: capture.pointer.as_deref().and_then(parse_integer),
                        integer: (capture.kind.eq_ignore_ascii_case("integer"))
                            .then(|| capture.value.as_deref().and_then(parse_integer))
                            .flatten(),
                        bytes: capture_bytes(capture),
                        byte_length: capture.byte_length,
                        requested_length: capture.requested_length,
                    });
            }
            if let (Some(base_register), Some(displacement)) = (
                capture.base_register.as_ref(),
                capture
                    .displacement
                    .as_deref()
                    .and_then(|value| parse_signed_offset(value).ok()),
            ) {
                fields.push(FieldObservation {
                    event_index: event.index,
                    base_register: base_register.to_ascii_lowercase(),
                    displacement,
                    label: capture.label.clone(),
                    bytes: capture_bytes(capture),
                    byte_length: capture.byte_length,
                    read_error: capture.read_error.is_some(),
                });
            }
        }
    }
    let max_candidates = options.max_candidates_per_function as usize;
    let mut argument_candidates = arguments
        .iter()
        .map(|(index, observations)| {
            argument_candidate(*index, observations, options.min_observations)
        })
        .collect::<Vec<_>>();
    argument_candidates.sort_by_key(|candidate| candidate.index);
    argument_candidates.truncate(max_candidates);

    FridaFunctionAbiInference {
        hook_id: first.hook_id.clone(),
        function_name: first.function_name.clone(),
        module_name: first.module_name.clone(),
        target: first.target.clone(),
        event_count: events.len() as u64,
        call_count: calls.len() as u64,
        argument_candidates,
        pointer_length_pairs: pointer_length_pairs(
            &arguments,
            options.min_observations,
            max_candidates,
        ),
        context_pointer_candidates: context_candidates(
            &arguments,
            options.min_observations,
            max_candidates,
        ),
        struct_field_candidates: struct_field_candidates(
            &fields,
            options.min_observations,
            max_candidates,
        ),
        return_candidate: return_candidate(events),
        warnings: Vec::new(),
        limitations: vec![
            "All argument, pointer-length, context, field, and return classifications are Candidate/Related until confirmed by instructions, data flow, symbols, API contracts, or controlled counterexamples."
                .to_string(),
            "Runtime pointers are process-specific and must not be reused as module-relative addresses or across runs."
                .to_string(),
            "Only captured calls and bounded windows are analyzed; missing fields, alternate layouts, aliases, and unexecuted paths remain unknown."
                .to_string(),
        ],
    }
}

pub fn infer_frida_abi(
    bundle: &FridaCaptureBundle,
    options: &FridaAbiInferenceOptions,
) -> FridaAbiInferenceReport {
    let options = bounded_options(options);
    let mut grouped = BTreeMap::<String, Vec<&FridaCaptureEvent>>::new();
    for event in &bundle.events {
        if !event.captures.is_empty() || event.return_value.is_some() {
            grouped.entry(function_key(event)).or_default().push(event);
        }
    }
    let total_functions = grouped.len();
    let mut functions = grouped
        .into_values()
        .map(|events| analyze_function(&events, &options))
        .collect::<Vec<_>>();
    functions.sort_by(|left, right| {
        right
            .event_count
            .cmp(&left.event_count)
            .then_with(|| left.function_name.cmp(&right.function_name))
            .then_with(|| left.hook_id.cmp(&right.hook_id))
    });
    functions.truncate(options.max_functions as usize);
    let omitted_function_count = total_functions.saturating_sub(functions.len()) as u64;
    let mut warnings = bundle.warnings.clone();
    if omitted_function_count > 0 {
        warnings.push(format!(
            "{omitted_function_count} function group(s) were omitted by maxFunctions={}.",
            options.max_functions
        ));
    }
    FridaAbiInferenceReport {
        schema: FRIDA_ABI_INFERENCE_SCHEMA.to_string(),
        source_schema: bundle.schema.clone(),
        source_event_count: bundle.events.len() as u64,
        analyzed_function_count: functions.len() as u64,
        omitted_function_count,
        min_observations: options.min_observations,
        functions,
        warnings,
        limitations: vec![
            "This report is an explainable candidate model for AI navigation, not recovered source types or a verified ABI declaration."
                .to_string(),
            "Explicit capture labels and directions originate from Hook configuration; repeated byte equality/mutation and controlled runs carry more weight."
                .to_string(),
            "Trace UI parses user-captured files only and never attaches, spawns, loads, or executes Frida or the target."
                .to_string(),
        ],
    }
}

pub fn inspect_frida_abi_capture(
    file_path: &str,
    options: &FridaAbiInferenceOptions,
) -> Result<FridaAbiInferenceReport, String> {
    let metadata = std::fs::metadata(file_path)
        .map_err(|error| format!("failed to inspect Frida capture: {error}"))?;
    if !metadata.is_file() {
        return Err("Frida capture is not a regular file".to_string());
    }
    if metadata.len() > MAX_CAPTURE_FILE_BYTES {
        return Err(format!(
            "Frida capture exceeds the bounded maximum of {MAX_CAPTURE_FILE_BYTES} bytes"
        ));
    }
    let mut file =
        File::open(file_path).map_err(|error| format!("failed to open Frida capture: {error}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("failed to read Frida capture: {error}"))?;
    let bundle = parse_frida_capture_bundle(&bytes)?;
    Ok(infer_frida_abi(&bundle, options))
}

pub fn save_frida_abi_inference(
    path: &str,
    report: &FridaAbiInferenceReport,
) -> Result<(), String> {
    let mut file = File::create(path)
        .map_err(|error| format!("failed to create ABI inference report: {error}"))?;
    serde_json::to_writer_pretty(&mut file, report)
        .map_err(|error| format!("failed to serialize ABI inference report: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("failed to finish ABI inference report: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        index: u64,
        call_id: &str,
        event_name: &str,
        captures: Vec<FridaCapturedValue>,
        return_value: Option<&str>,
    ) -> FridaCaptureEvent {
        FridaCaptureEvent {
            index,
            protocol: "trace-ui/frida-hook-v1".to_string(),
            event_id: None,
            hook_id: "encrypt-hook".to_string(),
            event: event_name.to_string(),
            function_name: "encrypt_buffer".to_string(),
            timestamp_ms: index,
            thread_id: 1,
            call_id: Some(call_id.to_string()),
            module_name: Some("libtarget.so".to_string()),
            module_base: Some("0x70000000".to_string()),
            module_size: Some(0x10000),
            target: Some("0x70001000".to_string()),
            dispatcher_offset: None,
            capture_session_id: None,
            flow_id: None,
            hit_sequence: None,
            candidate_state_registers: Vec::new(),
            registers: BTreeMap::new(),
            captures,
            return_value: return_value.map(str::to_string),
            backtrace: Vec::new(),
            stalker_mode: None,
            stalker_event_count: None,
            error: None,
        }
    }

    fn capture(
        index: u8,
        label: &str,
        kind: &str,
        direction: &str,
        phase: &str,
        pointer: Option<&str>,
        value: Option<String>,
        byte_length: Option<u64>,
    ) -> FridaCapturedValue {
        FridaCapturedValue {
            index,
            label: label.to_string(),
            kind: kind.to_string(),
            direction: direction.to_string(),
            phase: phase.to_string(),
            pointer: pointer.map(str::to_string),
            value,
            byte_length,
            requested_length: byte_length,
            read_error: None,
            base_register: None,
            displacement: None,
        }
    }

    #[test]
    fn infers_pointer_length_context_mutation_and_field_candidates() {
        let mut events = Vec::new();
        for call in 0..3u64 {
            let length = 5 + call;
            let mut context = capture(
                0,
                "ctx",
                "byteArray",
                "input",
                "enter",
                Some("0x1000"),
                Some("11".repeat(32)),
                Some(32),
            );
            context.base_register = Some("x0".to_string());
            context.displacement = Some("0x10".to_string());
            context.label = "ctx-key-field".to_string();
            events.push(event(
                call * 2,
                &format!("call-{call}"),
                "hook-enter",
                vec![
                    context,
                    capture(
                        1,
                        "input",
                        "byteArray",
                        "input",
                        "enter",
                        Some(&format!("0x{:x}", 0x2000 + call * 0x100)),
                        Some("41".repeat(length as usize)),
                        Some(length),
                    ),
                    capture(
                        2,
                        "input-length",
                        "integer",
                        "input",
                        "enter",
                        None,
                        Some(length.to_string()),
                        None,
                    ),
                    capture(
                        3,
                        "output",
                        "byteArray",
                        "output",
                        "enter",
                        Some(&format!("0x{:x}", 0x3000 + call * 0x100)),
                        Some("00".repeat(length as usize)),
                        Some(length),
                    ),
                ],
                None,
            ));
            events.push(event(
                call * 2 + 1,
                &format!("call-{call}"),
                "hook-leave",
                vec![capture(
                    3,
                    "output",
                    "byteArray",
                    "output",
                    "leave",
                    Some(&format!("0x{:x}", 0x3000 + call * 0x100)),
                    Some("aa".repeat(length as usize)),
                    Some(length),
                )],
                Some(if call == 0 { "0" } else { "1" }),
            ));
        }
        let bundle = FridaCaptureBundle {
            schema: "trace-ui/frida-capture-v1".to_string(),
            source_format: "test".to_string(),
            events,
            hook_ids: vec!["encrypt-hook".to_string()],
            enter_event_count: 3,
            leave_event_count: 3,
            stalker_event_count: 0,
            warnings: Vec::new(),
        };
        let report = infer_frida_abi(&bundle, &FridaAbiInferenceOptions::default());
        let function = &report.functions[0];
        assert!(function.pointer_length_pairs.iter().any(|pair| {
            pair.pointer_index == 1 && pair.length_index == 2 && pair.match_ratio == 1.0
        }));
        assert!(function
            .context_pointer_candidates
            .iter()
            .any(|candidate| candidate.index == 0));
        assert_eq!(
            function
                .argument_candidates
                .iter()
                .find(|candidate| candidate.index == 3)
                .unwrap()
                .changed_enter_leave_pair_count,
            3
        );
        assert!(function
            .struct_field_candidates
            .iter()
            .any(|field| { field.base_register == "x0" && field.displacement == "0x10" }));
        assert_eq!(
            function.return_candidate.as_ref().unwrap().role_candidate,
            "status-code-candidate"
        );
    }

    #[test]
    fn one_labeled_observation_does_not_create_cross_call_pairs_or_context() {
        let bundle = FridaCaptureBundle {
            schema: "trace-ui/frida-capture-v1".to_string(),
            source_format: "test".to_string(),
            events: vec![event(
                0,
                "call-0",
                "hook-enter",
                vec![
                    capture(
                        0,
                        "ctx",
                        "byteArray",
                        "input",
                        "enter",
                        Some("0x1000"),
                        Some("00".repeat(32)),
                        Some(32),
                    ),
                    capture(
                        1,
                        "length",
                        "integer",
                        "input",
                        "enter",
                        None,
                        Some("32".to_string()),
                        None,
                    ),
                ],
                None,
            )],
            hook_ids: vec!["encrypt-hook".to_string()],
            enter_event_count: 1,
            leave_event_count: 0,
            stalker_event_count: 0,
            warnings: Vec::new(),
        };
        let report = infer_frida_abi(&bundle, &FridaAbiInferenceOptions::default());
        assert!(report.functions[0].pointer_length_pairs.is_empty());
        assert!(report.functions[0].context_pointer_candidates.is_empty());
        assert!(report.functions[0]
            .argument_candidates
            .iter()
            .all(|candidate| candidate.evidence_level == "candidate/related"));
    }
}
