use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use trace_parser::gumtrace::CallAnnotation;

pub const MEMORY_OBJECT_GRAPH_SCHEMA: &str = "trace-ui/memory-object-graph-v1";
pub const MEMORY_POINTER_EXPLANATION_SCHEMA: &str = "trace-ui/memory-pointer-explanation-v1";

fn default_true() -> bool {
    true
}

fn default_max_objects() -> u32 {
    500
}

fn default_max_aliases() -> u32 {
    64
}

fn default_max_field_windows() -> u32 {
    64
}

fn default_max_access_samples() -> u32 {
    16
}

fn default_max_anomalies() -> u32 {
    256
}

fn default_max_runtime_clusters() -> u32 {
    128
}

fn default_max_accesses() -> u64 {
    5_000_000
}

fn default_max_stack_distance() -> u64 {
    1024 * 1024
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryObjectOptions {
    #[serde(default)]
    pub start_seq: Option<u32>,
    #[serde(default)]
    pub end_seq: Option<u32>,
    #[serde(default = "default_true")]
    pub include_stack_frames: bool,
    #[serde(default = "default_true")]
    pub include_runtime_clusters: bool,
    #[serde(default = "default_max_objects")]
    pub max_objects: u32,
    #[serde(default = "default_max_aliases")]
    pub max_aliases_per_object: u32,
    #[serde(default = "default_max_field_windows")]
    pub max_field_windows_per_object: u32,
    #[serde(default = "default_max_access_samples")]
    pub max_access_samples_per_object: u32,
    #[serde(default = "default_max_anomalies")]
    pub max_anomalies: u32,
    #[serde(default = "default_max_runtime_clusters")]
    pub max_runtime_clusters: u32,
    #[serde(default = "default_max_accesses")]
    pub max_accesses: u64,
    #[serde(default = "default_max_stack_distance")]
    pub max_stack_distance: u64,
}

impl Default for MemoryObjectOptions {
    fn default() -> Self {
        Self {
            start_seq: None,
            end_seq: None,
            include_stack_frames: true,
            include_runtime_clusters: true,
            max_objects: default_max_objects(),
            max_aliases_per_object: default_max_aliases(),
            max_field_windows_per_object: default_max_field_windows(),
            max_access_samples_per_object: default_max_access_samples(),
            max_anomalies: default_max_anomalies(),
            max_runtime_clusters: default_max_runtime_clusters(),
            max_accesses: default_max_accesses(),
            max_stack_distance: default_max_stack_distance(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryAccessKind {
    Read,
    Write,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryAccessObservation {
    pub seq: u32,
    pub address: u64,
    pub size: u8,
    pub kind: MemoryAccessKind,
    pub instruction_address: u64,
    #[serde(default)]
    pub call_node_id: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryStackFrameObservation {
    pub call_node_id: u32,
    pub parent_call_node_id: Option<u32>,
    pub function_name: Option<String>,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub entry_sp: u64,
    pub exit_sp: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryObjectScope {
    pub start_seq: u32,
    pub end_seq: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryAliasObservation {
    pub seq: u32,
    pub source_kind: String,
    pub source: String,
    pub pointer: String,
    pub offset: String,
    pub relation: String,
    pub lifetime_state: String,
    pub evidence_level: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryAccessSample {
    pub seq: u32,
    pub address: String,
    pub size: u8,
    pub kind: String,
    pub instruction_address: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryObjectAccessSummary {
    pub read_count: u64,
    pub write_count: u64,
    pub first_access_seq: Option<u32>,
    pub last_access_seq: Option<u32>,
    pub first_read_seq: Option<u32>,
    pub last_read_seq: Option<u32>,
    pub first_write_seq: Option<u32>,
    pub last_write_seq: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryFieldWindow {
    pub offset: String,
    pub end_offset: String,
    pub read_count: u64,
    pub write_count: u64,
    pub first_seq: u32,
    pub last_seq: u32,
    pub sample_addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryObjectRecord {
    pub object_id: String,
    pub kind: String,
    pub generation: u32,
    pub base_address: String,
    pub end_address: Option<String>,
    pub size: Option<u64>,
    pub start_seq: u32,
    pub end_seq: Option<u32>,
    pub allocation_call_seq: Option<u32>,
    pub release_call_seq: Option<u32>,
    pub allocator: Option<String>,
    pub release_function: Option<String>,
    pub release_reason: Option<String>,
    pub call_node_id: Option<u32>,
    pub parent_call_node_id: Option<u32>,
    pub function_name: Option<String>,
    pub entry_sp: Option<String>,
    pub exit_sp: Option<String>,
    pub lifecycle_state: String,
    pub evidence_level: String,
    pub access_summary: MemoryObjectAccessSummary,
    pub access_samples: Vec<MemoryAccessSample>,
    pub access_samples_truncated: bool,
    pub aliases: Vec<MemoryAliasObservation>,
    pub aliases_truncated: bool,
    pub field_windows: Vec<MemoryFieldWindow>,
    pub field_windows_truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryObjectAnomaly {
    pub kind: String,
    pub status: String,
    pub seq: u32,
    pub address: Option<String>,
    pub object_id: Option<String>,
    pub function_name: Option<String>,
    pub access_kind: Option<String>,
    pub access_size: Option<u8>,
    pub instruction_address: Option<String>,
    pub occurrence_count: u64,
    pub reason: String,
    pub counter_evidence: Vec<String>,
    pub required_evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRuntimeCluster {
    pub cluster_id: String,
    pub base_address: String,
    pub end_address: String,
    pub page_count: u32,
    pub first_seq: u32,
    pub last_seq: u32,
    pub read_count: u64,
    pub write_count: u64,
    pub sample_addresses: Vec<String>,
    pub evidence_level: String,
    pub rationale: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryObjectStatistics {
    pub total_objects: u32,
    pub heap_objects: u32,
    pub mmap_objects: u32,
    pub stack_frame_objects: u32,
    pub active_at_scope_end: u32,
    pub released_or_ended: u32,
    pub reused_address_count: u32,
    pub failed_allocation_count: u32,
    pub lifecycle_unknown_count: u32,
    pub processed_access_count: u64,
    pub attributed_access_count: u64,
    pub unattributed_access_count: u64,
    pub alias_count: u64,
    pub anomaly_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryObjectGraphReport {
    pub schema_version: String,
    pub scope: MemoryObjectScope,
    pub objects: Vec<MemoryObjectRecord>,
    pub runtime_clusters: Vec<MemoryRuntimeCluster>,
    pub anomalies: Vec<MemoryObjectAnomaly>,
    pub statistics: MemoryObjectStatistics,
    pub objects_truncated: bool,
    pub runtime_clusters_truncated: bool,
    pub anomalies_truncated: bool,
    pub accesses_truncated: bool,
    pub verification_gate_met: bool,
    pub limitations: Vec<String>,
    pub next_steps: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryPointerObjectMatch {
    pub object_id: String,
    pub kind: String,
    pub generation: u32,
    pub base_address: String,
    pub size: Option<u64>,
    pub offset: String,
    pub lifetime_state_at_seq: String,
    pub evidence_level: String,
    pub rationale: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRegisterAlias {
    pub register: String,
    pub value: String,
    pub relation: String,
    pub displacement: String,
    pub object_id: Option<String>,
    pub evidence_level: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryPointerExplanation {
    pub schema_version: String,
    pub address: String,
    pub seq: u32,
    pub object_matches: Vec<MemoryPointerObjectMatch>,
    pub register_aliases: Vec<MemoryRegisterAlias>,
    pub call_aliases: Vec<MemoryAliasObservation>,
    pub nearby_accesses: Vec<MemoryAccessSample>,
    pub assessment: String,
    pub risks: Vec<String>,
    pub unknowns: Vec<String>,
    pub next_steps: Vec<String>,
    pub verification_gate_met: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ObjectKind {
    Heap,
    Mmap,
    StackFrame,
}

impl ObjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Heap => "heap",
            Self::Mmap => "mmap",
            Self::StackFrame => "stack-frame",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct FieldWork {
    read_count: u64,
    write_count: u64,
    first_seq: u32,
    last_seq: u32,
    sample_addresses: Vec<u64>,
}

#[derive(Clone, Debug)]
struct ObjectWork {
    object_id: String,
    kind: ObjectKind,
    generation: u32,
    identity_base: u64,
    base: u64,
    size: Option<u64>,
    start_seq: u32,
    end_seq: Option<u32>,
    allocation_call_seq: Option<u32>,
    release_call_seq: Option<u32>,
    allocator: Option<String>,
    release_function: Option<String>,
    release_reason: Option<String>,
    call_node_id: Option<u32>,
    parent_call_node_id: Option<u32>,
    function_name: Option<String>,
    entry_sp: Option<u64>,
    exit_sp: Option<u64>,
    access_summary: MemoryObjectAccessSummary,
    access_samples: Vec<MemoryAccessSample>,
    access_samples_omitted: u64,
    aliases: Vec<MemoryAliasObservation>,
    alias_keys: HashSet<(u32, String, u64)>,
    aliases_omitted: u64,
    fields: BTreeMap<u64, FieldWork>,
    fields_omitted: u64,
}

impl ObjectWork {
    fn exclusive_end(&self) -> Option<u64> {
        self.size.map(|size| self.base.saturating_add(size.max(1)))
    }

    fn live_at(&self, seq: u32) -> bool {
        if seq < self.start_seq {
            return false;
        }
        match (self.kind, self.end_seq) {
            (_, None) => true,
            (ObjectKind::StackFrame, Some(end)) => seq <= end,
            (_, Some(end)) => seq < end,
        }
    }

    fn released_before_or_at(&self, seq: u32) -> bool {
        match (self.kind, self.end_seq) {
            (_, None) => false,
            (ObjectKind::StackFrame, Some(end)) => seq > end,
            (_, Some(end)) => seq >= end,
        }
    }

    fn intersects_scope(&self, start_seq: u32, end_seq: u32) -> bool {
        self.start_seq <= end_seq
            && self
                .end_seq
                .is_none_or(|object_end| object_end >= start_seq)
    }
}

#[derive(Clone, Debug)]
struct RuntimeClusterWork {
    base: u64,
    first_seq: u32,
    last_seq: u32,
    read_count: u64,
    write_count: u64,
    sample_addresses: Vec<u64>,
}

#[derive(Clone, Debug)]
struct IntervalEntry {
    base: u64,
    end: u64,
    object_index: usize,
}

#[derive(Clone, Debug, Default)]
struct IntervalIndex {
    entries: Vec<IntervalEntry>,
    prefix_max_end: Vec<u64>,
}

impl IntervalIndex {
    fn build(objects: &[ObjectWork], include_stack: bool) -> Self {
        let mut entries = objects
            .iter()
            .enumerate()
            .filter(|(_, object)| include_stack || object.kind != ObjectKind::StackFrame)
            .map(|(object_index, object)| {
                let end = object
                    .exclusive_end()
                    .unwrap_or_else(|| object.base.saturating_add(1));
                IntervalEntry {
                    base: object.base,
                    end,
                    object_index,
                }
            })
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| (entry.base, entry.end, entry.object_index));
        let mut prefix_max_end = Vec::with_capacity(entries.len());
        let mut max_end = 0u64;
        for entry in &entries {
            max_end = max_end.max(entry.end);
            prefix_max_end.push(max_end);
        }
        Self {
            entries,
            prefix_max_end,
        }
    }

    fn overlapping(&self, start: u64, end: u64) -> Vec<usize> {
        let mut position = self.entries.partition_point(|entry| entry.base < end);
        let mut result = Vec::new();
        while position > 0 {
            let index = position - 1;
            if self.prefix_max_end[index] <= start {
                break;
            }
            let entry = &self.entries[index];
            if entry.end > start {
                result.push(entry.object_index);
            }
            position -= 1;
        }
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallKind {
    Malloc,
    Calloc,
    Realloc,
    Free,
    Mmap,
    Munmap,
    New,
    Delete,
    Other,
}

fn canonical_function_name(function_name: &str) -> String {
    let lower = function_name.to_ascii_lowercase();
    let without_version = lower.split('@').next().unwrap_or(lower.as_str());
    let token = without_version
        .split(|character: char| matches!(character, '!' | ':' | '/' | '\\' | ' ' | '(' | ')'))
        .filter(|value| !value.is_empty())
        .next_back()
        .unwrap_or(without_version)
        .trim_start_matches('_');
    token.strip_suffix("_chk").unwrap_or(token).to_string()
}

fn classify_call(function_name: &str) -> CallKind {
    let name = canonical_function_name(function_name);
    match name.as_str() {
        "malloc" | "libc_malloc" | "je_malloc" | "scudo_malloc" => CallKind::Malloc,
        "calloc" | "libc_calloc" | "je_calloc" | "scudo_calloc" => CallKind::Calloc,
        "realloc" | "libc_realloc" | "je_realloc" | "scudo_realloc" => CallKind::Realloc,
        "free" | "libc_free" | "je_free" | "scudo_free" => CallKind::Free,
        "mmap" | "mmap64" | "libc_mmap" => CallKind::Mmap,
        "munmap" | "libc_munmap" => CallKind::Munmap,
        "znwm" | "znam" | "operatornew" | "operatornew[]" | "new" | "new[]" => CallKind::New,
        "zdlpv" | "zdapv" | "operatordelete" | "operatordelete[]" | "delete" | "delete[]" => {
            CallKind::Delete
        }
        _ => CallKind::Other,
    }
}

fn raw_call_args(annotation: &CallAnnotation) -> Vec<String> {
    let Some(call_line) = annotation.raw_lines.first() else {
        return Vec::new();
    };
    let rest = call_line
        .trim()
        .strip_prefix("call jni func: ")
        .or_else(|| call_line.trim().strip_prefix("call func: "))
        .unwrap_or(call_line.trim());
    if let (Some(start), Some(end)) = (rest.find('('), rest.rfind(')')) {
        if end > start {
            return rest[start + 1..end]
                .split(',')
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect();
        }
    }
    rest.split_once(':')
        .map(|(_, args)| {
            args.split(',')
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_numeric_value(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let bytes = trimmed.as_bytes();
    let mut index = 0usize;
    while index + 2 <= bytes.len() {
        if bytes[index] == b'0'
            && index + 2 <= bytes.len()
            && matches!(bytes.get(index + 1), Some(b'x') | Some(b'X'))
        {
            let start = index + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end > start {
                return u64::from_str_radix(&trimmed[start..end], 16).ok();
            }
        }
        index += 1;
    }

    let token = trimmed
        .trim_matches(|character: char| {
            matches!(character, ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}')
        })
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .next_back()?;
    token.parse::<u64>().ok()
}

fn call_arg(annotation: &CallAnnotation, index: usize) -> Option<u64> {
    raw_call_args(annotation)
        .get(index)
        .and_then(|value| parse_numeric_value(value))
        .or_else(|| {
            annotation.args.iter().find_map(|(label, value)| {
                let normalized = label
                    .trim()
                    .trim_start_matches("args")
                    .trim_start_matches('x')
                    .parse::<usize>()
                    .ok()?;
                (normalized == index)
                    .then(|| parse_numeric_value(value))
                    .flatten()
            })
        })
}

fn call_return(annotation: &CallAnnotation) -> Option<u64> {
    annotation
        .ret_value
        .as_deref()
        .and_then(parse_numeric_value)
}

fn effect_seq(call_seq: u32, annotation: &CallAnnotation) -> u32 {
    annotation
        .completion_seq
        .or(annotation.observation_seq)
        .unwrap_or(call_seq)
}

fn format_addr(address: u64) -> String {
    format!("0x{address:x}")
}

fn format_offset(offset: u64) -> String {
    format!("0x{offset:x}")
}

fn format_displacement(value: i128) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{:x}", value as u128)
    }
}

fn access_end(address: u64, size: u8) -> u64 {
    address.saturating_add(u64::from(size.max(1)))
}

fn update_first_last(first: &mut Option<u32>, last: &mut Option<u32>, seq: u32) {
    *first = Some(first.map_or(seq, |current| current.min(seq)));
    *last = Some(last.map_or(seq, |current| current.max(seq)));
}

fn add_alias(
    object: &mut ObjectWork,
    seq: u32,
    source_kind: &str,
    source: String,
    pointer: u64,
    lifetime_state: &str,
    max_aliases: usize,
) {
    let key = (seq, source_kind.to_string(), pointer);
    if !object.alias_keys.insert(key) {
        return;
    }
    if object.aliases.len() >= max_aliases {
        object.aliases_omitted += 1;
        return;
    }
    let offset = pointer.saturating_sub(object.base);
    object.aliases.push(MemoryAliasObservation {
        seq,
        source_kind: source_kind.to_string(),
        source,
        pointer: format_addr(pointer),
        offset: format_offset(offset),
        relation: if pointer == object.base {
            "base-pointer".to_string()
        } else {
            "interior-pointer".to_string()
        },
        lifetime_state: lifetime_state.to_string(),
        evidence_level: "related".to_string(),
    });
}

fn new_object(
    objects: &mut Vec<ObjectWork>,
    generation_by_base: &mut HashMap<(ObjectKind, u64), u32>,
    kind: ObjectKind,
    base: u64,
    size: Option<u64>,
    start_seq: u32,
    allocation_call_seq: Option<u32>,
    allocator: Option<String>,
) -> usize {
    let generation = generation_by_base.entry((kind, base)).or_default();
    *generation += 1;
    let generation_value = *generation;
    let object_id = format!(
        "{}:{}:g{}",
        kind.as_str(),
        format_addr(base),
        generation_value
    );
    objects.push(ObjectWork {
        object_id,
        kind,
        generation: generation_value,
        identity_base: base,
        base,
        size,
        start_seq,
        end_seq: None,
        allocation_call_seq,
        release_call_seq: None,
        allocator,
        release_function: None,
        release_reason: None,
        call_node_id: None,
        parent_call_node_id: None,
        function_name: None,
        entry_sp: None,
        exit_sp: None,
        access_summary: MemoryObjectAccessSummary::default(),
        access_samples: Vec::new(),
        access_samples_omitted: 0,
        aliases: Vec::new(),
        alias_keys: HashSet::new(),
        aliases_omitted: 0,
        fields: BTreeMap::new(),
        fields_omitted: 0,
    });
    objects.len() - 1
}

fn mark_released(object: &mut ObjectWork, seq: u32, call_seq: u32, function: &str, reason: &str) {
    object.end_seq = Some(seq.max(object.start_seq));
    object.release_call_seq = Some(call_seq);
    object.release_function = Some(function.to_string());
    object.release_reason = Some(reason.to_string());
}

fn object_contains_address(object: &ObjectWork, address: u64) -> bool {
    match object.exclusive_end() {
        Some(end) => address >= object.base && address < end,
        None => address == object.base,
    }
}

fn object_overlaps_access(object: &ObjectWork, address: u64, end: u64) -> bool {
    let object_end = object
        .exclusive_end()
        .unwrap_or_else(|| object.base.saturating_add(1));
    object.base < end && object_end > address
}

fn anomaly_key(anomaly: &MemoryObjectAnomaly) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        anomaly.kind,
        anomaly.object_id.as_deref().unwrap_or(""),
        anomaly.address.as_deref().unwrap_or(""),
        anomaly.instruction_address.as_deref().unwrap_or(""),
        anomaly.function_name.as_deref().unwrap_or("")
    )
}

fn push_anomaly(
    anomalies: &mut Vec<MemoryObjectAnomaly>,
    anomaly_indices: &mut HashMap<String, usize>,
    mut anomaly: MemoryObjectAnomaly,
    max_anomalies: usize,
    omitted: &mut u64,
) {
    let key = anomaly_key(&anomaly);
    if let Some(index) = anomaly_indices.get(&key).copied() {
        anomalies[index].occurrence_count = anomalies[index]
            .occurrence_count
            .saturating_add(anomaly.occurrence_count.max(1));
        anomalies[index].seq = anomalies[index].seq.min(anomaly.seq);
        return;
    }
    if anomalies.len() >= max_anomalies {
        *omitted += 1;
        return;
    }
    anomaly.occurrence_count = anomaly.occurrence_count.max(1);
    anomaly_indices.insert(key, anomalies.len());
    anomalies.push(anomaly);
}

fn lifecycle_anomaly(
    kind: &str,
    seq: u32,
    address: Option<u64>,
    object_id: Option<String>,
    function_name: Option<String>,
    reason: String,
) -> MemoryObjectAnomaly {
    MemoryObjectAnomaly {
        kind: kind.to_string(),
        status: "candidate".to_string(),
        seq,
        address: address.map(format_addr),
        object_id,
        function_name,
        access_kind: None,
        access_size: None,
        instruction_address: None,
        occurrence_count: 1,
        reason,
        counter_evidence: vec![
            "The trace may omit a custom allocator, a prior allocation, or a lifecycle call outside the selected capture window.".to_string(),
        ],
        required_evidence: vec![
            "Capture the allocator/deallocator arguments and return value at the exact call, then repeat with a wider trace window.".to_string(),
        ],
    }
}

fn access_anomaly(
    kind: &str,
    access: &MemoryAccessObservation,
    object: &ObjectWork,
    reason: String,
) -> MemoryObjectAnomaly {
    MemoryObjectAnomaly {
        kind: kind.to_string(),
        status: "candidate".to_string(),
        seq: access.seq,
        address: Some(format_addr(access.address)),
        object_id: Some(object.object_id.clone()),
        function_name: object.function_name.clone(),
        access_kind: Some(match access.kind {
            MemoryAccessKind::Read => "read".to_string(),
            MemoryAccessKind::Write => "write".to_string(),
        }),
        access_size: Some(access.size),
        instruction_address: Some(format_addr(access.instruction_address)),
        occurrence_count: 1,
        reason,
        counter_evidence: vec![
            "An unobserved allocation, address reuse, partial unmap, or truncated lifecycle event could make this address belong to another object.".to_string(),
        ],
        required_evidence: vec![
            "Record the exact allocation generation and replay the call with complete pointer/length/memory state before treating this as a proven memory-safety defect.".to_string(),
        ],
    }
}

fn update_object_access(
    object: &mut ObjectWork,
    access: &MemoryAccessObservation,
    max_samples: usize,
    max_fields: usize,
) {
    update_first_last(
        &mut object.access_summary.first_access_seq,
        &mut object.access_summary.last_access_seq,
        access.seq,
    );
    match access.kind {
        MemoryAccessKind::Read => {
            object.access_summary.read_count += 1;
            update_first_last(
                &mut object.access_summary.first_read_seq,
                &mut object.access_summary.last_read_seq,
                access.seq,
            );
        }
        MemoryAccessKind::Write => {
            object.access_summary.write_count += 1;
            update_first_last(
                &mut object.access_summary.first_write_seq,
                &mut object.access_summary.last_write_seq,
                access.seq,
            );
        }
    }

    if object.access_samples.len() < max_samples {
        object.access_samples.push(MemoryAccessSample {
            seq: access.seq,
            address: format_addr(access.address),
            size: access.size,
            kind: match access.kind {
                MemoryAccessKind::Read => "read".to_string(),
                MemoryAccessKind::Write => "write".to_string(),
            },
            instruction_address: format_addr(access.instruction_address),
        });
    } else {
        object.access_samples_omitted += 1;
    }

    let bucket = access.address & !0xf;
    if !object.fields.contains_key(&bucket) && object.fields.len() >= max_fields {
        object.fields_omitted += 1;
        return;
    }
    let field = object.fields.entry(bucket).or_insert_with(|| FieldWork {
        first_seq: access.seq,
        last_seq: access.seq,
        ..FieldWork::default()
    });
    field.first_seq = field.first_seq.min(access.seq);
    field.last_seq = field.last_seq.max(access.seq);
    match access.kind {
        MemoryAccessKind::Read => field.read_count += 1,
        MemoryAccessKind::Write => field.write_count += 1,
    }
    if field.sample_addresses.len() < 4 && !field.sample_addresses.contains(&access.address) {
        field.sample_addresses.push(access.address);
    }
}

fn active_exact_base(objects: &[ObjectWork], base: u64, kind: Option<ObjectKind>) -> Option<usize> {
    objects
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, object)| {
            (object.identity_base == base
                && object.end_seq.is_none()
                && kind.is_none_or(|expected| object.kind == expected))
            .then_some(index)
        })
}

fn latest_released_exact_base(
    objects: &[ObjectWork],
    base: u64,
    kind: Option<ObjectKind>,
) -> Option<usize> {
    objects
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, object)| {
            (object.identity_base == base
                && object.end_seq.is_some()
                && kind.is_none_or(|expected| object.kind == expected))
            .then_some(index)
        })
}

fn create_runtime_cluster(
    clusters: &mut BTreeMap<u64, RuntimeClusterWork>,
    access: &MemoryAccessObservation,
) {
    let page = access.address & !0xfff;
    let cluster = clusters.entry(page).or_insert_with(|| RuntimeClusterWork {
        base: page,
        first_seq: access.seq,
        last_seq: access.seq,
        read_count: 0,
        write_count: 0,
        sample_addresses: Vec::new(),
    });
    cluster.first_seq = cluster.first_seq.min(access.seq);
    cluster.last_seq = cluster.last_seq.max(access.seq);
    match access.kind {
        MemoryAccessKind::Read => cluster.read_count += 1,
        MemoryAccessKind::Write => cluster.write_count += 1,
    }
    if cluster.sample_addresses.len() < 8 && !cluster.sample_addresses.contains(&access.address) {
        cluster.sample_addresses.push(access.address);
    }
}

fn call_pointer_values(annotation: &CallAnnotation) -> Vec<(String, u64)> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    for (index, value) in raw_call_args(annotation).iter().enumerate() {
        if let Some(pointer) = parse_numeric_value(value) {
            let label = format!("x{index}");
            if seen.insert((label.clone(), pointer)) {
                values.push((label, pointer));
            }
        }
    }
    for (label, value) in &annotation.args {
        if let Some(pointer) = parse_numeric_value(value) {
            if seen.insert((label.clone(), pointer)) {
                values.push((label.clone(), pointer));
            }
        }
    }
    values
}

pub fn reconstruct_memory_objects<I>(
    annotations: &HashMap<u32, CallAnnotation>,
    accesses: I,
    stack_frames: &[MemoryStackFrameObservation],
    total_lines: u32,
    options: &MemoryObjectOptions,
) -> MemoryObjectGraphReport
where
    I: IntoIterator<Item = MemoryAccessObservation>,
{
    let start_seq = options
        .start_seq
        .unwrap_or(0)
        .min(total_lines.saturating_sub(1));
    let end_seq = options
        .end_seq
        .unwrap_or_else(|| total_lines.saturating_sub(1))
        .min(total_lines.saturating_sub(1));
    let (start_seq, end_seq) = if start_seq <= end_seq {
        (start_seq, end_seq)
    } else {
        (end_seq, start_seq)
    };
    let max_aliases = options.max_aliases_per_object.max(1) as usize;
    let max_fields = options.max_field_windows_per_object.max(1) as usize;
    let max_samples = options.max_access_samples_per_object.max(1) as usize;
    let max_anomalies = options.max_anomalies.max(1) as usize;

    let mut objects = Vec::<ObjectWork>::new();
    let mut generation_by_base = HashMap::<(ObjectKind, u64), u32>::new();
    let mut anomalies = Vec::<MemoryObjectAnomaly>::new();
    let mut anomaly_indices = HashMap::<String, usize>::new();
    let mut anomalies_omitted = 0u64;
    let mut failed_allocations = 0u32;
    let mut lifecycle_unknown = 0u32;

    let mut ordered_calls = annotations.iter().collect::<Vec<_>>();
    ordered_calls.sort_by_key(|(seq, _)| **seq);
    for (&call_seq, annotation) in &ordered_calls {
        if call_seq > end_seq {
            continue;
        }
        let function = canonical_function_name(&annotation.func_name);
        let call_kind = classify_call(&annotation.func_name);
        let lifecycle_seq = effect_seq(call_seq, annotation);
        match call_kind {
            CallKind::Malloc | CallKind::New => {
                let Some(base) = call_return(annotation) else {
                    lifecycle_unknown += 1;
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "allocation-result-unknown",
                            lifecycle_seq,
                            None,
                            None,
                            Some(function.clone()),
                            format!(
                                "{function} was observed, but its returned pointer was not captured."
                            ),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                    continue;
                };
                if base == 0 {
                    failed_allocations += 1;
                    continue;
                }
                let size = call_arg(annotation, 0);
                if let Some(previous_index) = active_exact_base(&objects, base, None) {
                    let previous_id = objects[previous_index].object_id.clone();
                    mark_released(
                        &mut objects[previous_index],
                        lifecycle_seq,
                        call_seq,
                        &function,
                        "address-reused-without-observed-release",
                    );
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "address-reuse-without-release",
                            lifecycle_seq,
                            Some(base),
                            Some(previous_id),
                            Some(function.clone()),
                            "A new allocation reused an address while the prior generation had no observed release.".to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                }
                let index = new_object(
                    &mut objects,
                    &mut generation_by_base,
                    ObjectKind::Heap,
                    base,
                    size,
                    lifecycle_seq,
                    Some(call_seq),
                    Some(function.clone()),
                );
                add_alias(
                    &mut objects[index],
                    lifecycle_seq,
                    "allocator-return",
                    function,
                    base,
                    "live",
                    max_aliases,
                );
            }
            CallKind::Calloc => {
                let Some(base) = call_return(annotation) else {
                    lifecycle_unknown += 1;
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "allocation-result-unknown",
                            lifecycle_seq,
                            None,
                            None,
                            Some(function.clone()),
                            "calloc was observed, but its returned pointer was not captured."
                                .to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                    continue;
                };
                if base == 0 {
                    failed_allocations += 1;
                    continue;
                }
                let size = call_arg(annotation, 0)
                    .zip(call_arg(annotation, 1))
                    .and_then(|(count, width)| count.checked_mul(width));
                if let Some(previous_index) = active_exact_base(&objects, base, None) {
                    let previous_id = objects[previous_index].object_id.clone();
                    mark_released(
                        &mut objects[previous_index],
                        lifecycle_seq,
                        call_seq,
                        &function,
                        "address-reused-without-observed-release",
                    );
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "address-reuse-without-release",
                            lifecycle_seq,
                            Some(base),
                            Some(previous_id),
                            Some(function.clone()),
                            "A new allocation reused an address while the prior generation had no observed release.".to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                }
                let index = new_object(
                    &mut objects,
                    &mut generation_by_base,
                    ObjectKind::Heap,
                    base,
                    size,
                    lifecycle_seq,
                    Some(call_seq),
                    Some(function.clone()),
                );
                add_alias(
                    &mut objects[index],
                    lifecycle_seq,
                    "allocator-return",
                    function,
                    base,
                    "live",
                    max_aliases,
                );
            }
            CallKind::Mmap => {
                let Some(base) = call_return(annotation) else {
                    lifecycle_unknown += 1;
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "mapping-result-unknown",
                            lifecycle_seq,
                            None,
                            None,
                            Some(function.clone()),
                            "mmap was observed, but its returned mapping address was not captured."
                                .to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                    continue;
                };
                if base == u64::MAX {
                    failed_allocations += 1;
                    continue;
                }
                let size = call_arg(annotation, 1);
                if let Some(previous_index) = active_exact_base(&objects, base, None) {
                    let previous_id = objects[previous_index].object_id.clone();
                    mark_released(
                        &mut objects[previous_index],
                        lifecycle_seq,
                        call_seq,
                        &function,
                        "address-reused-without-observed-release",
                    );
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "address-reuse-without-release",
                            lifecycle_seq,
                            Some(base),
                            Some(previous_id),
                            Some(function.clone()),
                            "A new mapping reused an address while the prior generation had no observed release.".to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                }
                let index = new_object(
                    &mut objects,
                    &mut generation_by_base,
                    ObjectKind::Mmap,
                    base,
                    size,
                    lifecycle_seq,
                    Some(call_seq),
                    Some(function.clone()),
                );
                add_alias(
                    &mut objects[index],
                    lifecycle_seq,
                    "allocator-return",
                    function,
                    base,
                    "live",
                    max_aliases,
                );
            }
            CallKind::Free | CallKind::Delete => {
                let Some(pointer) = call_arg(annotation, 0) else {
                    lifecycle_unknown += 1;
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "release-pointer-unknown",
                            lifecycle_seq,
                            None,
                            None,
                            Some(function.clone()),
                            format!("{function} was observed without a captured pointer argument."),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                    continue;
                };
                if pointer == 0 {
                    continue;
                }
                if let Some(index) = active_exact_base(&objects, pointer, Some(ObjectKind::Heap)) {
                    mark_released(
                        &mut objects[index],
                        lifecycle_seq,
                        call_seq,
                        &function,
                        "released-by-free",
                    );
                    continue;
                }
                if let Some(index) = objects
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(index, object)| {
                        (object.kind == ObjectKind::Heap
                            && object.end_seq.is_none()
                            && object_contains_address(object, pointer))
                        .then_some(index)
                    })
                {
                    let object_id = objects[index].object_id.clone();
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "interior-pointer-release",
                            lifecycle_seq,
                            Some(pointer),
                            Some(object_id),
                            Some(function.clone()),
                            "The release pointer falls inside an active object but is not its recorded base address.".to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                } else if let Some(index) =
                    latest_released_exact_base(&objects, pointer, Some(ObjectKind::Heap))
                {
                    let object_id = objects[index].object_id.clone();
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "double-release-or-stale-pointer",
                            lifecycle_seq,
                            Some(pointer),
                            Some(object_id),
                            Some(function.clone()),
                            "The pointer matches an already released generation and no newer active generation was observed.".to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                } else {
                    lifecycle_unknown += 1;
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "release-without-observed-allocation",
                            lifecycle_seq,
                            Some(pointer),
                            None,
                            Some(function.clone()),
                            "The released pointer has no matching observed allocation generation."
                                .to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                }
            }
            CallKind::Realloc => {
                let old_pointer = call_arg(annotation, 0);
                let new_size = call_arg(annotation, 1);
                let new_pointer = call_return(annotation);
                let Some(new_pointer) = new_pointer else {
                    lifecycle_unknown += 1;
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "realloc-result-unknown",
                            lifecycle_seq,
                            old_pointer,
                            None,
                            Some(function.clone()),
                            "realloc was observed, but its returned pointer was not captured."
                                .to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                    continue;
                };
                if new_pointer == 0 {
                    failed_allocations += 1;
                    if new_size == Some(0) && old_pointer.is_some_and(|value| value != 0) {
                        lifecycle_unknown += 1;
                        push_anomaly(
                            &mut anomalies,
                            &mut anomaly_indices,
                            lifecycle_anomaly(
                                "realloc-zero-size-semantics-unknown",
                                lifecycle_seq,
                                old_pointer,
                                None,
                                Some(function.clone()),
                                "A zero-size realloc returned null; whether the old object was released is implementation-specific in this trace model.".to_string(),
                            ),
                            max_anomalies,
                            &mut anomalies_omitted,
                        );
                    }
                    continue;
                }

                if let Some(old_pointer) = old_pointer.filter(|value| *value != 0) {
                    if let Some(index) =
                        active_exact_base(&objects, old_pointer, Some(ObjectKind::Heap))
                    {
                        mark_released(
                            &mut objects[index],
                            lifecycle_seq,
                            call_seq,
                            &function,
                            "superseded-by-realloc",
                        );
                    } else {
                        lifecycle_unknown += 1;
                        push_anomaly(
                            &mut anomalies,
                            &mut anomaly_indices,
                            lifecycle_anomaly(
                                "realloc-source-generation-unknown",
                                lifecycle_seq,
                                Some(old_pointer),
                                None,
                                Some(function.clone()),
                                "The source pointer of realloc has no active observed allocation generation.".to_string(),
                            ),
                            max_anomalies,
                            &mut anomalies_omitted,
                        );
                    }
                }
                if let Some(previous_index) = active_exact_base(&objects, new_pointer, None) {
                    let previous_id = objects[previous_index].object_id.clone();
                    mark_released(
                        &mut objects[previous_index],
                        lifecycle_seq,
                        call_seq,
                        &function,
                        "address-reused-without-observed-release",
                    );
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "address-reuse-without-release",
                            lifecycle_seq,
                            Some(new_pointer),
                            Some(previous_id),
                            Some(function.clone()),
                            "realloc returned an address owned by another still-active observed generation.".to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                }
                let index = new_object(
                    &mut objects,
                    &mut generation_by_base,
                    ObjectKind::Heap,
                    new_pointer,
                    new_size,
                    lifecycle_seq,
                    Some(call_seq),
                    Some(function.clone()),
                );
                add_alias(
                    &mut objects[index],
                    lifecycle_seq,
                    "allocator-return",
                    function,
                    new_pointer,
                    "live",
                    max_aliases,
                );
            }
            CallKind::Munmap => {
                let pointer = call_arg(annotation, 0);
                let length = call_arg(annotation, 1);
                let Some(pointer) = pointer else {
                    lifecycle_unknown += 1;
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "unmap-pointer-unknown",
                            lifecycle_seq,
                            None,
                            None,
                            Some(function.clone()),
                            "munmap was observed without a captured mapping address.".to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                    continue;
                };
                if let Some(index) = active_exact_base(&objects, pointer, Some(ObjectKind::Mmap)) {
                    let full_release = match (objects[index].size, length) {
                        (Some(size), Some(length)) => length >= size,
                        (None, Some(_)) | (_, None) => false,
                    };
                    if full_release {
                        mark_released(
                            &mut objects[index],
                            lifecycle_seq,
                            call_seq,
                            &function,
                            "released-by-munmap",
                        );
                    } else {
                        let object_id = objects[index].object_id.clone();
                        push_anomaly(
                            &mut anomalies,
                            &mut anomaly_indices,
                            lifecycle_anomaly(
                                "partial-unmap-not-split",
                                lifecycle_seq,
                                Some(pointer),
                                Some(object_id),
                                Some(function.clone()),
                                "The observed munmap does not prove that the complete recorded mapping ended; partial mappings are not split by this model.".to_string(),
                            ),
                            max_anomalies,
                            &mut anomalies_omitted,
                        );
                    }
                } else {
                    lifecycle_unknown += 1;
                    push_anomaly(
                        &mut anomalies,
                        &mut anomaly_indices,
                        lifecycle_anomaly(
                            "unmap-without-observed-mapping",
                            lifecycle_seq,
                            Some(pointer),
                            None,
                            Some(function.clone()),
                            "munmap has no matching active observed mmap generation.".to_string(),
                        ),
                        max_anomalies,
                        &mut anomalies_omitted,
                    );
                }
            }
            CallKind::Other => {}
        }
    }

    let mut stack_object_by_node = HashMap::<u32, usize>::new();
    if options.include_stack_frames {
        let mut ordered_frames = stack_frames.to_vec();
        ordered_frames.sort_by_key(|frame| (frame.entry_seq, frame.call_node_id));
        for frame in ordered_frames {
            if frame.entry_seq > end_seq || frame.exit_seq < start_seq {
                continue;
            }
            let index = new_object(
                &mut objects,
                &mut generation_by_base,
                ObjectKind::StackFrame,
                frame.entry_sp,
                None,
                frame.entry_seq,
                None,
                None,
            );
            let object = &mut objects[index];
            object.end_seq = Some(frame.exit_seq);
            object.release_reason = Some("call-frame-ended".to_string());
            object.call_node_id = Some(frame.call_node_id);
            object.parent_call_node_id = frame.parent_call_node_id;
            object.function_name = frame.function_name;
            object.entry_sp = Some(frame.entry_sp);
            object.exit_sp = frame.exit_sp;
            add_alias(
                object,
                frame.entry_seq,
                "register",
                "SP at call entry".to_string(),
                frame.entry_sp,
                "live",
                max_aliases,
            );
            stack_object_by_node.insert(frame.call_node_id, index);
        }
    }

    let interval_index = IntervalIndex::build(&objects, false);
    let mut runtime_clusters = BTreeMap::<u64, RuntimeClusterWork>::new();
    let mut processed_accesses = 0u64;
    let mut attributed_accesses = 0u64;
    let mut unattributed_accesses = 0u64;
    let mut accesses_truncated = false;

    for access in accesses {
        if access.seq < start_seq || access.seq > end_seq {
            continue;
        }
        if processed_accesses >= options.max_accesses.max(1) {
            accesses_truncated = true;
            break;
        }
        processed_accesses += 1;
        let end = access_end(access.address, access.size);
        let overlapping = interval_index.overlapping(access.address, end);

        let live_index = overlapping
            .iter()
            .copied()
            .filter(|index| objects[*index].live_at(access.seq))
            .filter(|index| object_contains_address(&objects[*index], access.address))
            .max_by_key(|index| {
                (
                    objects[*index].start_seq,
                    objects[*index].generation,
                    objects[*index].base,
                )
            });
        if let Some(index) = live_index {
            if objects[index]
                .exclusive_end()
                .is_some_and(|object_end| end > object_end)
            {
                let anomaly = access_anomaly(
                    "out-of-bounds-access",
                    &access,
                    &objects[index],
                    "The access starts inside the live object but extends beyond its recorded exclusive end.".to_string(),
                );
                push_anomaly(
                    &mut anomalies,
                    &mut anomaly_indices,
                    anomaly,
                    max_anomalies,
                    &mut anomalies_omitted,
                );
            }
            update_object_access(&mut objects[index], &access, max_samples, max_fields);
            attributed_accesses += 1;
            continue;
        }

        let live_overlap_index = overlapping
            .iter()
            .copied()
            .filter(|index| objects[*index].live_at(access.seq))
            .filter(|index| object_overlaps_access(&objects[*index], access.address, end))
            .max_by_key(|index| (objects[*index].start_seq, objects[*index].generation));
        if let Some(index) = live_overlap_index {
            let anomaly = access_anomaly(
                "out-of-bounds-access",
                &access,
                &objects[index],
                "The access overlaps a live object boundary but does not begin inside the recorded object range.".to_string(),
            );
            push_anomaly(
                &mut anomalies,
                &mut anomaly_indices,
                anomaly,
                max_anomalies,
                &mut anomalies_omitted,
            );
            update_object_access(&mut objects[index], &access, max_samples, max_fields);
            attributed_accesses += 1;
            continue;
        }

        if let Some(node_id) = access.call_node_id {
            if let Some(index) = stack_object_by_node.get(&node_id).copied() {
                if objects[index].live_at(access.seq) {
                    let entry_sp = objects[index].entry_sp.unwrap_or(objects[index].base);
                    let observed_base = objects[index].base.min(access.address);
                    let observed_end = objects[index]
                        .exclusive_end()
                        .unwrap_or(entry_sp)
                        .max(entry_sp)
                        .max(end);
                    objects[index].base = observed_base;
                    objects[index].size = Some(observed_end.saturating_sub(observed_base).max(1));
                    update_object_access(&mut objects[index], &access, max_samples, max_fields);
                    attributed_accesses += 1;
                    continue;
                }
            }
        }

        let released_index = overlapping
            .iter()
            .copied()
            .filter(|index| objects[*index].released_before_or_at(access.seq))
            .filter(|index| object_overlaps_access(&objects[*index], access.address, end))
            .max_by_key(|index| {
                (
                    objects[*index].end_seq.unwrap_or(0),
                    objects[*index].generation,
                )
            });
        if let Some(index) = released_index {
            let anomaly = access_anomaly(
                "access-after-lifetime",
                &access,
                &objects[index],
                "The access falls in a previously released object generation and no newer live observed generation covers it.".to_string(),
            );
            push_anomaly(
                &mut anomalies,
                &mut anomaly_indices,
                anomaly,
                max_anomalies,
                &mut anomalies_omitted,
            );
            update_object_access(&mut objects[index], &access, max_samples, max_fields);
            attributed_accesses += 1;
            continue;
        }

        unattributed_accesses += 1;
        if options.include_runtime_clusters {
            create_runtime_cluster(&mut runtime_clusters, &access);
        }
    }

    let full_interval_index = IntervalIndex::build(&objects, true);
    for (&call_seq, annotation) in &ordered_calls {
        if call_seq < start_seq || call_seq > end_seq {
            continue;
        }
        let function = canonical_function_name(&annotation.func_name);
        for (label, pointer) in call_pointer_values(annotation) {
            if pointer == 0 {
                continue;
            }
            let pointer_end = pointer.saturating_add(1);
            let matches = full_interval_index.overlapping(pointer, pointer_end);
            if let Some(index) = matches
                .iter()
                .copied()
                .filter(|index| objects[*index].live_at(call_seq))
                .filter(|index| object_contains_address(&objects[*index], pointer))
                .max_by_key(|index| (objects[*index].start_seq, objects[*index].generation))
            {
                add_alias(
                    &mut objects[index],
                    call_seq,
                    "call-argument",
                    format!("{function} {label}"),
                    pointer,
                    "live",
                    max_aliases,
                );
            } else if let Some(index) = matches
                .iter()
                .copied()
                .filter(|index| objects[*index].released_before_or_at(call_seq))
                .filter(|index| object_contains_address(&objects[*index], pointer))
                .max_by_key(|index| {
                    (
                        objects[*index].end_seq.unwrap_or(0),
                        objects[*index].generation,
                    )
                })
            {
                add_alias(
                    &mut objects[index],
                    call_seq,
                    "call-argument",
                    format!("{function} {label}"),
                    pointer,
                    "released",
                    max_aliases,
                );
            }
        }
    }

    let mut relevant_indices = objects
        .iter()
        .enumerate()
        .filter(|(_, object)| {
            let access_count = object.access_summary.read_count + object.access_summary.write_count;
            match object.kind {
                ObjectKind::StackFrame => access_count > 0,
                _ => object.intersects_scope(start_seq, end_seq) || access_count > 0,
            }
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    relevant_indices.sort_by_key(|index| {
        (
            objects[*index].start_seq,
            objects[*index].base,
            objects[*index].generation,
        )
    });

    let total_objects = relevant_indices.len();
    let max_objects = options.max_objects.max(1) as usize;
    let objects_truncated = total_objects > max_objects;
    relevant_indices.truncate(max_objects);

    let mut statistics = MemoryObjectStatistics {
        total_objects: total_objects.min(u32::MAX as usize) as u32,
        failed_allocation_count: failed_allocations,
        lifecycle_unknown_count: lifecycle_unknown,
        processed_access_count: processed_accesses,
        attributed_access_count: attributed_accesses,
        unattributed_access_count: unattributed_accesses,
        anomaly_count: anomalies
            .iter()
            .map(|anomaly| anomaly.occurrence_count)
            .sum::<u64>()
            .saturating_add(anomalies_omitted),
        ..MemoryObjectStatistics::default()
    };

    let relevant_object_ids = objects
        .iter()
        .enumerate()
        .filter(|(_, object)| {
            let access_count = object.access_summary.read_count + object.access_summary.write_count;
            match object.kind {
                ObjectKind::StackFrame => access_count > 0,
                _ => object.intersects_scope(start_seq, end_seq) || access_count > 0,
            }
        })
        .map(|(_, object)| object.object_id.clone())
        .collect::<HashSet<_>>();

    let mut reused_bases = HashSet::<(ObjectKind, u64)>::new();
    let mut generations_seen = HashMap::<(ObjectKind, u64), u32>::new();
    for object in objects
        .iter()
        .filter(|object| relevant_object_ids.contains(&object.object_id))
    {
        match object.kind {
            ObjectKind::Heap => statistics.heap_objects += 1,
            ObjectKind::Mmap => statistics.mmap_objects += 1,
            ObjectKind::StackFrame => statistics.stack_frame_objects += 1,
        }
        if object.live_at(end_seq) {
            statistics.active_at_scope_end += 1;
        } else {
            statistics.released_or_ended += 1;
        }
        statistics.alias_count += object.aliases.len() as u64 + object.aliases_omitted;
        let key = (object.kind, object.identity_base);
        let count = generations_seen.entry(key).or_default();
        *count += 1;
        if *count > 1 {
            reused_bases.insert(key);
        }
    }
    statistics.reused_address_count = reused_bases.len().min(u32::MAX as usize) as u32;

    let records = relevant_indices
        .into_iter()
        .map(|index| object_to_record(&objects[index], start_seq, end_seq))
        .collect::<Vec<_>>();

    let mut runtime_cluster_records = runtime_clusters
        .into_values()
        .map(|cluster| MemoryRuntimeCluster {
            cluster_id: format!("runtime-page:{}", format_addr(cluster.base)),
            base_address: format_addr(cluster.base),
            end_address: format_addr(cluster.base.saturating_add(0x1000)),
            page_count: 1,
            first_seq: cluster.first_seq,
            last_seq: cluster.last_seq,
            read_count: cluster.read_count,
            write_count: cluster.write_count,
            sample_addresses: cluster
                .sample_addresses
                .into_iter()
                .map(format_addr)
                .collect(),
            evidence_level: "candidate".to_string(),
            rationale: "Accesses on this runtime page were not attributable to an observed heap, mmap, or inferred stack-frame object. The page may contain globals, TLS, loader state, a custom allocator object, or memory created outside the capture window.".to_string(),
        })
        .collect::<Vec<_>>();
    runtime_cluster_records.sort_by(|left, right| {
        (right.read_count + right.write_count)
            .cmp(&(left.read_count + left.write_count))
            .then_with(|| left.base_address.cmp(&right.base_address))
    });
    let runtime_clusters_truncated =
        runtime_cluster_records.len() > options.max_runtime_clusters.max(1) as usize;
    runtime_cluster_records.truncate(options.max_runtime_clusters.max(1) as usize);

    let anomalies_truncated = anomalies_omitted > 0;
    let mut limitations = vec![
        "This graph reconstructs dynamic object candidates from observed allocator annotations, memory accesses, and inferred stack frames; it is not a proof of source-level object identity.".to_string(),
        "Missing custom allocators, calls outside the trace window, incomplete returns, partial munmap, signals, TLS, and address reuse can change the correct lifetime assignment.".to_string(),
        "Call-argument and register pointer relations are Related evidence because an integer can coincide with an address and API roles are not inferred solely from position.".to_string(),
        "Use-after-lifetime and out-of-bounds findings remain Candidate until the exact allocation generation, bounds, and access are reproduced with complete state.".to_string(),
        "Stack ranges are inferred from call-tree lifetime, entry SP, and observed stack-near accesses; nested calls and omitted SP changes can leave ranges incomplete.".to_string(),
    ];
    if accesses_truncated {
        limitations.push(format!(
            "Access processing stopped at the configured maxAccesses={} bound; absence and completeness claims are invalid for omitted accesses.",
            options.max_accesses.max(1)
        ));
    }
    if objects_truncated || runtime_clusters_truncated || anomalies_truncated {
        limitations.push(
            "One or more serialized output lists were truncated; inspect the reported truncation flags before relying on absence.".to_string(),
        );
    }

    MemoryObjectGraphReport {
        schema_version: MEMORY_OBJECT_GRAPH_SCHEMA.to_string(),
        scope: MemoryObjectScope { start_seq, end_seq },
        objects: records,
        runtime_clusters: runtime_cluster_records,
        anomalies,
        statistics,
        objects_truncated,
        runtime_clusters_truncated,
        anomalies_truncated,
        accesses_truncated,
        verification_gate_met: false,
        limitations,
        next_steps: vec![
            "Use explain_memory_pointer at the exact sequence to resolve the active generation, interior offset, register aliases, and stale-generation alternatives.".to_string(),
            "For a load-bearing finding, capture malloc/calloc/realloc/free or mmap/munmap arguments and returns at exact offsets, including the accessed byte window.".to_string(),
            "Feed the exact call record into bounded Unicorn replay first; escalate to angr only when a concrete replay stops on missing state or alternate paths matter.".to_string(),
            "Compare a controlled rerun with one changed input or allocation pattern to refute accidental pointer coincidences and unstable lifetime hypotheses.".to_string(),
        ],
    }
}

fn object_to_record(object: &ObjectWork, _scope_start: u32, scope_end: u32) -> MemoryObjectRecord {
    let lifecycle_state = if object.live_at(scope_end) {
        "live-at-scope-end"
    } else if object.kind == ObjectKind::StackFrame {
        "scope-ended"
    } else {
        "released"
    };
    let mut warnings = Vec::new();
    if object.size.is_none() {
        warnings.push(
            "Object size is unknown; only exact base-pointer relations can be assigned safely."
                .to_string(),
        );
    }
    if object.kind == ObjectKind::StackFrame {
        warnings.push(
            "Stack bounds are inferred from observed accesses near entry SP and may omit untouched fields or caller-owned argument areas.".to_string(),
        );
    } else if object.end_seq.is_none() {
        warnings.push(
            "No release was observed by the end of the selected scope; this does not by itself prove a leak."
                .to_string(),
        );
    }
    if object.aliases_omitted > 0 {
        warnings.push(format!(
            "{} additional alias observations were omitted by the per-object bound.",
            object.aliases_omitted
        ));
    }
    if object.fields_omitted > 0 {
        warnings.push(format!(
            "{} additional field-window observations were omitted by the per-object bound.",
            object.fields_omitted
        ));
    }

    let mut fields = object
        .fields
        .iter()
        .map(|(&absolute_bucket, field)| {
            let offset = absolute_bucket.saturating_sub(object.base);
            MemoryFieldWindow {
                offset: format_offset(offset),
                end_offset: format_offset(offset.saturating_add(0x10)),
                read_count: field.read_count,
                write_count: field.write_count,
                first_seq: field.first_seq,
                last_seq: field.last_seq,
                sample_addresses: field
                    .sample_addresses
                    .iter()
                    .copied()
                    .map(format_addr)
                    .collect(),
            }
        })
        .collect::<Vec<_>>();
    fields.sort_by(|left, right| {
        (right.read_count + right.write_count)
            .cmp(&(left.read_count + left.write_count))
            .then_with(|| left.offset.cmp(&right.offset))
    });

    MemoryObjectRecord {
        object_id: object.object_id.clone(),
        kind: object.kind.as_str().to_string(),
        generation: object.generation,
        base_address: format_addr(object.base),
        end_address: object.exclusive_end().map(format_addr),
        size: object.size,
        start_seq: object.start_seq,
        end_seq: object.end_seq,
        allocation_call_seq: object.allocation_call_seq,
        release_call_seq: object.release_call_seq,
        allocator: object.allocator.clone(),
        release_function: object.release_function.clone(),
        release_reason: object.release_reason.clone(),
        call_node_id: object.call_node_id,
        parent_call_node_id: object.parent_call_node_id,
        function_name: object.function_name.clone(),
        entry_sp: object.entry_sp.map(format_addr),
        exit_sp: object.exit_sp.map(format_addr),
        lifecycle_state: lifecycle_state.to_string(),
        evidence_level: if object.kind == ObjectKind::StackFrame {
            "candidate".to_string()
        } else {
            "related".to_string()
        },
        access_summary: object.access_summary.clone(),
        access_samples: object.access_samples.clone(),
        access_samples_truncated: object.access_samples_omitted > 0,
        aliases: object.aliases.clone(),
        aliases_truncated: object.aliases_omitted > 0,
        field_windows: fields,
        field_windows_truncated: object.fields_omitted > 0,
        warnings,
    }
}

fn parse_report_address(value: &str) -> Option<u64> {
    let value = value.trim();
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    u64::from_str_radix(value, 16).ok()
}

fn record_live_at(object: &MemoryObjectRecord, seq: u32) -> bool {
    if seq < object.start_seq {
        return false;
    }
    match (object.kind.as_str(), object.end_seq) {
        (_, None) => true,
        ("stack-frame", Some(end)) => seq <= end,
        (_, Some(end)) => seq < end,
    }
}

pub fn explain_memory_pointer_from_report(
    report: &MemoryObjectGraphReport,
    address: u64,
    seq: u32,
    registers: &[(String, u64)],
    nearby_accesses: Vec<MemoryAccessSample>,
) -> MemoryPointerExplanation {
    let mut object_matches = Vec::new();
    for object in &report.objects {
        let Some(base) = parse_report_address(&object.base_address) else {
            continue;
        };
        let contains = match object.size {
            Some(size) => address >= base && address < base.saturating_add(size.max(1)),
            None => address == base,
        };
        if !contains {
            continue;
        }
        let lifetime_state_at_seq = if seq < object.start_seq {
            "not-yet-live"
        } else if record_live_at(object, seq) {
            "live"
        } else {
            "released"
        };
        object_matches.push(MemoryPointerObjectMatch {
            object_id: object.object_id.clone(),
            kind: object.kind.clone(),
            generation: object.generation,
            base_address: object.base_address.clone(),
            size: object.size,
            offset: format_offset(address.saturating_sub(base)),
            lifetime_state_at_seq: lifetime_state_at_seq.to_string(),
            evidence_level: object.evidence_level.clone(),
            rationale: if lifetime_state_at_seq == "live" {
                "The address falls inside this observed generation during its reconstructed lifetime."
                    .to_string()
            } else if lifetime_state_at_seq == "released" {
                "The address falls inside this generation, but the query sequence is after its reconstructed lifetime ended.".to_string()
            } else {
                "The address falls inside this generation, but the query sequence precedes its reconstructed start.".to_string()
            },
        });
    }
    object_matches.sort_by_key(|item| {
        (
            item.lifetime_state_at_seq != "live",
            std::cmp::Reverse(item.generation),
        )
    });

    let mut register_aliases = Vec::new();
    let mut register_keys = HashSet::new();
    for (register, value) in registers {
        if *value == address && register_keys.insert((register.clone(), "exact".to_string())) {
            register_aliases.push(MemoryRegisterAlias {
                register: register.clone(),
                value: format_addr(*value),
                relation: "exact-pointer".to_string(),
                displacement: "0x0".to_string(),
                object_id: object_matches.first().map(|item| item.object_id.clone()),
                evidence_level: "observed".to_string(),
            });
        }
        for object_match in &object_matches {
            let Some(object) = report
                .objects
                .iter()
                .find(|object| object.object_id == object_match.object_id)
            else {
                continue;
            };
            let Some(base) = parse_report_address(&object.base_address) else {
                continue;
            };
            let end = object
                .size
                .map(|size| base.saturating_add(size.max(1)))
                .unwrap_or(base.saturating_add(1));
            let same_object = *value >= base && *value < end;
            let stack_relation = object.kind == "stack-frame"
                && matches!(register.to_ascii_uppercase().as_str(), "SP" | "X29" | "FP")
                && value.abs_diff(address) <= 1024 * 1024;
            let object_base_relation = *value == base && address != base;
            if (same_object || stack_relation || object_base_relation)
                && register_keys.insert((register.clone(), object.object_id.clone()))
            {
                register_aliases.push(MemoryRegisterAlias {
                    register: register.clone(),
                    value: format_addr(*value),
                    relation: if stack_relation {
                        "stack-relative-pointer".to_string()
                    } else if object_base_relation {
                        "object-base-for-interior-pointer".to_string()
                    } else {
                        "same-object-pointer".to_string()
                    },
                    displacement: format_displacement(address as i128 - *value as i128),
                    object_id: Some(object.object_id.clone()),
                    evidence_level: "related".to_string(),
                });
            }
        }
    }

    let matched_ids = object_matches
        .iter()
        .map(|item| item.object_id.as_str())
        .collect::<HashSet<_>>();
    let mut call_aliases = report
        .objects
        .iter()
        .filter(|object| matched_ids.contains(object.object_id.as_str()))
        .flat_map(|object| object.aliases.iter())
        .filter(|alias| alias.seq <= seq)
        .cloned()
        .collect::<Vec<_>>();
    call_aliases.sort_by_key(|alias| std::cmp::Reverse(alias.seq));
    call_aliases.truncate(32);

    let live_count = object_matches
        .iter()
        .filter(|item| item.lifetime_state_at_seq == "live")
        .count();
    let released_count = object_matches
        .iter()
        .filter(|item| item.lifetime_state_at_seq == "released")
        .count();
    let assessment = if live_count == 1 {
        "single-live-generation"
    } else if live_count > 1 {
        "overlapping-live-candidates"
    } else if released_count > 0 {
        "released-generation-candidate"
    } else {
        "unowned-or-unobserved"
    };

    let mut risks = Vec::new();
    if released_count > 0 && live_count == 0 {
        risks.push(
            "The pointer resolves only to released generations at this sequence, so stale-pointer/use-after-lifetime is a Candidate finding.".to_string(),
        );
    }
    if live_count > 1 {
        risks.push(
            "More than one reconstructed live object overlaps this address; partial mappings, incomplete bounds, or model ambiguity must be resolved before attribution.".to_string(),
        );
    }
    if object_matches.iter().any(|item| item.size.is_none()) {
        risks.push(
            "At least one matching generation has unknown size, so interior-pointer and boundary claims are incomplete.".to_string(),
        );
    }

    let mut unknowns = Vec::new();
    if object_matches.is_empty() {
        unknowns.push(
            "No serialized heap, mmap, or inferred stack-frame object contains the address. It may be global/TLS/custom-allocator memory or originate outside the capture window.".to_string(),
        );
    }
    if report.objects_truncated || report.accesses_truncated {
        unknowns.push(
            "The source memory-object report is truncated, so a missing or alternate generation may have been omitted.".to_string(),
        );
    }
    unknowns.push(
        "Register equality and call-argument position do not prove source-level pointer type or ownership."
            .to_string(),
    );

    MemoryPointerExplanation {
        schema_version: MEMORY_POINTER_EXPLANATION_SCHEMA.to_string(),
        address: format_addr(address),
        seq,
        object_matches,
        register_aliases,
        call_aliases,
        nearby_accesses,
        assessment: assessment.to_string(),
        risks,
        unknowns,
        next_steps: vec![
            "Inspect the exact access instruction and the allocator/release call sequences shown for the selected generation.".to_string(),
            "Capture the pointer register plus the bounded object bytes at the exact access and allocator return offsets.".to_string(),
            "Use a concrete Unicorn replay for the exact captured state; use bounded angr only if alternate paths or missing state remain material.".to_string(),
        ],
        verification_gate_met: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn annotation(
        function: &str,
        args: &[&str],
        ret: Option<&str>,
        completion_seq: u32,
    ) -> CallAnnotation {
        CallAnnotation {
            func_name: function.to_string(),
            is_jni: false,
            args: args
                .iter()
                .enumerate()
                .map(|(index, value)| (format!("x{index}"), (*value).to_string()))
                .collect(),
            ret_value: ret.map(str::to_string),
            raw_lines: vec![format!("call func: {function}({})", args.join(", "))],
            observation_seq: None,
            completion_seq: Some(completion_seq),
        }
    }

    fn access(seq: u32, address: u64, size: u8, kind: MemoryAccessKind) -> MemoryAccessObservation {
        MemoryAccessObservation {
            seq,
            address,
            size,
            kind,
            instruction_address: 0x4000 + u64::from(seq) * 4,
            call_node_id: None,
        }
    }

    #[test]
    fn reconstructs_malloc_free_and_keeps_uaf_as_candidate() {
        let annotations = HashMap::from([
            (10, annotation("malloc", &["0x20"], Some("0x1000"), 11)),
            (20, annotation("free", &["0x1000"], None, 21)),
        ]);
        let report = reconstruct_memory_objects(
            &annotations,
            vec![
                access(12, 0x1008, 4, MemoryAccessKind::Write),
                access(30, 0x1008, 4, MemoryAccessKind::Read),
            ],
            &[],
            40,
            &MemoryObjectOptions::default(),
        );
        assert_eq!(report.objects.len(), 1);
        assert_eq!(report.objects[0].base_address, "0x1000");
        assert_eq!(report.objects[0].end_seq, Some(21));
        assert!(report
            .anomalies
            .iter()
            .any(|item| item.kind == "access-after-lifetime" && item.status == "candidate"));
        assert!(!report.verification_gate_met);
    }

    #[test]
    fn same_address_second_allocation_is_a_new_generation() {
        let annotations = HashMap::from([
            (1, annotation("malloc", &["16"], Some("0x2000"), 2)),
            (4, annotation("free", &["0x2000"], None, 5)),
            (8, annotation("malloc", &["32"], Some("0x2000"), 9)),
        ]);
        let report = reconstruct_memory_objects(
            &annotations,
            Vec::<MemoryAccessObservation>::new(),
            &[],
            20,
            &MemoryObjectOptions::default(),
        );
        assert_eq!(report.objects.len(), 2);
        assert_eq!(report.objects[0].generation, 1);
        assert_eq!(report.objects[1].generation, 2);
        assert_ne!(report.objects[0].object_id, report.objects[1].object_id);
        assert_eq!(report.statistics.reused_address_count, 1);
    }

    #[test]
    fn realloc_ends_old_object_and_starts_new_generation() {
        let annotations = HashMap::from([
            (1, annotation("malloc", &["16"], Some("0x3000"), 2)),
            (
                10,
                annotation("realloc", &["0x3000", "64"], Some("0x4000"), 11),
            ),
        ]);
        let report = reconstruct_memory_objects(
            &annotations,
            Vec::<MemoryAccessObservation>::new(),
            &[],
            20,
            &MemoryObjectOptions::default(),
        );
        assert_eq!(report.objects.len(), 2);
        assert_eq!(report.objects[0].end_seq, Some(11));
        assert_eq!(
            report.objects[0].release_reason.as_deref(),
            Some("superseded-by-realloc")
        );
        assert_eq!(report.objects[1].base_address, "0x4000");
        assert_eq!(report.objects[1].start_seq, 11);
    }

    #[test]
    fn records_interior_pointer_call_alias() {
        let annotations = HashMap::from([
            (1, annotation("malloc", &["64"], Some("0x5000"), 2)),
            (10, annotation("consume", &["0x5018", "8"], None, 11)),
        ]);
        let report = reconstruct_memory_objects(
            &annotations,
            Vec::<MemoryAccessObservation>::new(),
            &[],
            20,
            &MemoryObjectOptions::default(),
        );
        let alias = report.objects[0]
            .aliases
            .iter()
            .find(|alias| alias.source_kind == "call-argument" && alias.pointer == "0x5018")
            .unwrap();
        assert_eq!(alias.relation, "interior-pointer");
        assert_eq!(alias.offset, "0x18");
    }

    #[test]
    fn stack_frame_has_call_lifetime_and_observed_range() {
        let frames = vec![MemoryStackFrameObservation {
            call_node_id: 7,
            parent_call_node_id: Some(1),
            function_name: Some("target".to_string()),
            entry_seq: 10,
            exit_seq: 30,
            entry_sp: 0x8000,
            exit_sp: Some(0x8000),
        }];
        let mut stack_access = access(15, 0x7fc0, 8, MemoryAccessKind::Write);
        stack_access.call_node_id = Some(7);
        let report = reconstruct_memory_objects(
            &HashMap::new(),
            vec![stack_access],
            &frames,
            40,
            &MemoryObjectOptions::default(),
        );
        assert_eq!(report.objects.len(), 1);
        assert_eq!(report.objects[0].kind, "stack-frame");
        assert_eq!(report.objects[0].base_address, "0x7fc0");
        assert_eq!(report.objects[0].end_address.as_deref(), Some("0x8000"));
        assert_eq!(report.objects[0].end_seq, Some(30));
        assert_eq!(report.objects[0].evidence_level, "candidate");
    }

    #[test]
    fn missing_return_is_explicit_unknown_not_fake_object() {
        let annotations = HashMap::from([(1, annotation("malloc", &["32"], None, 2))]);
        let report = reconstruct_memory_objects(
            &annotations,
            Vec::<MemoryAccessObservation>::new(),
            &[],
            10,
            &MemoryObjectOptions::default(),
        );
        assert!(report.objects.is_empty());
        assert_eq!(report.statistics.lifecycle_unknown_count, 1);
        assert!(report
            .anomalies
            .iter()
            .any(|item| item.kind == "allocation-result-unknown"));
    }

    #[test]
    fn unknown_size_object_accepts_only_exact_base_access() {
        let annotations = HashMap::from([(1, annotation("malloc", &[], Some("0xa000"), 2))]);
        let report = reconstruct_memory_objects(
            &annotations,
            vec![
                access(3, 0xa000, 8, MemoryAccessKind::Write),
                access(4, 0xa008, 8, MemoryAccessKind::Read),
            ],
            &[],
            10,
            &MemoryObjectOptions::default(),
        );
        assert_eq!(report.objects[0].access_summary.write_count, 1);
        assert_eq!(report.objects[0].access_summary.read_count, 0);
        assert_eq!(report.statistics.unattributed_access_count, 1);
        assert_eq!(report.objects[0].size, None);
    }

    #[test]
    fn pointer_explanation_prefers_live_generation_and_register_alias() {
        let annotations = HashMap::from([
            (1, annotation("malloc", &["32"], Some("0x9000"), 2)),
            (5, annotation("free", &["0x9000"], None, 6)),
            (8, annotation("malloc", &["64"], Some("0x9000"), 9)),
        ]);
        let options = MemoryObjectOptions {
            max_objects: 100,
            ..MemoryObjectOptions::default()
        };
        let report = reconstruct_memory_objects(
            &annotations,
            Vec::<MemoryAccessObservation>::new(),
            &[],
            20,
            &options,
        );
        let explanation = explain_memory_pointer_from_report(
            &report,
            0x9010,
            10,
            &[("X0".to_string(), 0x9010), ("X1".to_string(), 0x9000)],
            Vec::new(),
        );
        assert_eq!(explanation.assessment, "single-live-generation");
        assert_eq!(explanation.object_matches[0].generation, 2);
        assert!(explanation
            .register_aliases
            .iter()
            .any(|alias| alias.register == "X0" && alias.relation == "exact-pointer"));
        assert!(!explanation.verification_gate_met);
    }
}
