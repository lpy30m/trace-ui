use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

use crate::query::angr::{prepare_frida_seed_with_allowed_offsets, AngrOllvmFridaSeedProvenance};
use crate::query::elf_identity::ElfBinaryIdentity;
use crate::query::frida_capture::AngrStateSeed;
use crate::query::frida_checkpoint::unicorn_checkpoint_offsets;
use crate::query::ollvm::OllvmReport;
use crate::utils::{format_signed_offset_hex, parse_hex_addr, parse_signed_offset};

const UNICORN_OLLVM_SCHEMA: &str = "trace-ui/unicorn-ollvm-v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UnicornOllvmConfig {
    pub max_instructions: u64,
    pub timeout_ms: u64,
    pub max_memory_writes: u64,
    pub max_recorded_offsets: u64,
    pub stop_on_call: bool,
    pub loop_visit_limit: u32,
}

impl Default for UnicornOllvmConfig {
    fn default() -> Self {
        Self {
            max_instructions: 50_000,
            timeout_ms: 5_000,
            max_memory_writes: 4_096,
            max_recorded_offsets: 50_000,
            stop_on_call: true,
            loop_visit_limit: 2,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornSeedQuality {
    pub source_event_index: u64,
    pub capture_offset: String,
    pub status: String,
    pub register_count: u64,
    pub missing_registers: Vec<String>,
    pub memory_region_count: u64,
    pub captured_memory_bytes: u64,
    pub stack_memory_captured: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornSeedRecaptureWindow {
    pub label: String,
    pub base_register: String,
    pub displacement: String,
    pub byte_length: u64,
    pub source_kind: String,
    pub phase: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornSeedRecapturePlan {
    pub source_event_index: u64,
    pub capture_offset: String,
    pub windows: Vec<UnicornSeedRecaptureWindow>,
    pub carry_forward_bytes: u64,
    pub unsupported_memory_region_count: u64,
    pub windows_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornOllvmScript {
    pub file_name: String,
    pub script: String,
    pub schema_version: String,
    pub seeds: Vec<AngrOllvmFridaSeedProvenance>,
    pub seed_qualities: Vec<UnicornSeedQuality>,
    pub seed_recapture_plans: Vec<UnicornSeedRecapturePlan>,
    pub expected_binary_identity: ElfBinaryIdentity,
    pub config: UnicornOllvmConfig,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornStateValue {
    pub register: String,
    pub status: String,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornRegisterChange {
    pub register: String,
    pub before: String,
    pub after: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornMemoryWrite {
    pub address: String,
    #[serde(default)]
    pub offset: Option<String>,
    pub size: u64,
    #[serde(default)]
    pub value_hex: Option<String>,
    #[serde(default)]
    pub pc_offset: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornMissingMemory {
    pub access: String,
    pub address: String,
    pub size: u64,
    #[serde(default)]
    pub pc_offset: Option<String>,
    #[serde(default)]
    pub instruction: Option<String>,
    #[serde(default)]
    pub base_register: Option<String>,
    #[serde(default)]
    pub displacement: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornCallBoundary {
    pub pc_offset: String,
    pub mnemonic: String,
    #[serde(default)]
    pub target_address: Option<String>,
    #[serde(default)]
    pub target_offset: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornReplayRun {
    pub source_event_index: u64,
    pub seed_kind: String,
    pub start_offset: String,
    pub mapped_base: String,
    pub stop_reason: String,
    pub instruction_count: u64,
    pub elapsed_ms: u64,
    pub terminal_address: String,
    #[serde(default)]
    pub terminal_offset: Option<String>,
    #[serde(default)]
    pub matched_dispatcher_offset: Option<String>,
    #[serde(default)]
    pub source_state_values: Vec<UnicornStateValue>,
    #[serde(default)]
    pub target_state_values: Vec<UnicornStateValue>,
    #[serde(default)]
    pub executed_offsets: Vec<String>,
    #[serde(default)]
    pub executed_offsets_truncated: bool,
    #[serde(default)]
    pub block_offsets: Vec<String>,
    #[serde(default)]
    pub block_offsets_truncated: bool,
    #[serde(default)]
    pub register_changes: Vec<UnicornRegisterChange>,
    #[serde(default)]
    pub memory_writes: Vec<UnicornMemoryWrite>,
    #[serde(default)]
    pub memory_writes_truncated: bool,
    #[serde(default)]
    pub call_boundaries: Vec<UnicornCallBoundary>,
    #[serde(default)]
    pub missing_memory: Vec<UnicornMissingMemory>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornTransitionEvidence {
    pub source_offset: String,
    pub source_state: String,
    pub target_offset: String,
    pub target_state: String,
    pub stop_reason: String,
    pub execution_count: u64,
    pub source_event_indices: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornRecaptureSuggestion {
    pub pc_offset: String,
    #[serde(default)]
    pub base_register: Option<String>,
    #[serde(default)]
    pub displacement: Option<String>,
    pub byte_length: u64,
    pub reason: String,
    pub source_event_indices: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnicornOllvmResultBundle {
    pub schema: String,
    pub module_name: String,
    pub binary_sha256: String,
    pub expected_binary_sha256: String,
    pub binary_identity_matched: bool,
    pub architecture: String,
    pub unicorn_version: String,
    pub capstone_version: String,
    pub config: UnicornOllvmConfig,
    #[serde(default)]
    pub seeds: Vec<AngrOllvmFridaSeedProvenance>,
    #[serde(default)]
    pub seed_qualities: Vec<UnicornSeedQuality>,
    #[serde(default)]
    pub seed_recapture_plans: Vec<UnicornSeedRecapturePlan>,
    #[serde(default)]
    pub runs: Vec<UnicornReplayRun>,
    #[serde(default)]
    pub transition_matrix: Vec<UnicornTransitionEvidence>,
    #[serde(default)]
    pub recapture_suggestions: Vec<UnicornRecaptureSuggestion>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

fn sanitize_name(value: &str) -> String {
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
        "ollvm-replay".to_string()
    } else {
        output.to_string()
    }
}

fn validate_config(config: &UnicornOllvmConfig) -> Result<(), String> {
    if !(1..=2_000_000).contains(&config.max_instructions) {
        return Err("Unicorn max instructions must be between 1 and 2000000".to_string());
    }
    if !(1..=60_000).contains(&config.timeout_ms) {
        return Err("Unicorn timeout must be between 1 and 60000 ms".to_string());
    }
    if !(1..=100_000).contains(&config.max_memory_writes) {
        return Err("Unicorn max memory writes must be between 1 and 100000".to_string());
    }
    if !(1..=500_000).contains(&config.max_recorded_offsets) {
        return Err("Unicorn max recorded offsets must be between 1 and 500000".to_string());
    }
    if !(1..=100).contains(&config.loop_visit_limit) {
        return Err("Unicorn loop visit limit must be between 1 and 100".to_string());
    }
    Ok(())
}

fn stack_memory_captured(seed: &AngrStateSeed) -> bool {
    let Some(sp) = seed
        .registers
        .iter()
        .find(|register| register.name.eq_ignore_ascii_case("sp"))
        .and_then(|register| parse_hex_addr(&register.value).ok())
    else {
        return false;
    };
    seed.memory_regions.iter().any(|region| {
        parse_hex_addr(&region.address)
            .ok()
            .is_some_and(|start| sp >= start && sp < start.saturating_add(region.byte_length))
    })
}

fn assess_seed_quality(seed: &AngrStateSeed, capture_offset: &str) -> UnicornSeedQuality {
    let present = seed
        .registers
        .iter()
        .map(|register| register.name.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut required = (0..=30)
        .map(|index| format!("x{index}"))
        .collect::<Vec<_>>();
    required.push("sp".to_string());
    required.push("nzcv".to_string());
    let missing_registers = required
        .into_iter()
        .filter(|register| !present.contains(register))
        .map(|register| register.to_ascii_uppercase())
        .collect::<Vec<_>>();
    let stack_memory_captured = stack_memory_captured(seed);
    let captured_memory_bytes = seed.memory_regions.iter().fold(0u64, |total, region| {
        total.saturating_add(region.byte_length)
    });
    let mut warnings = Vec::new();
    if !missing_registers.is_empty() {
        warnings.push(format!(
            "{} architectural registers were not captured; replay stops if an instruction reads one before defining it.",
            missing_registers.len()
        ));
    }
    if !stack_memory_captured {
        warnings.push(
            "SP is not covered by a captured byteArray region; stack reads will stop as missing-memory."
                .to_string(),
        );
    }
    if seed.memory_regions.is_empty() {
        warnings.push(
            "No runtime memory regions were captured; only ELF-backed reads and write-before-read memory can continue."
                .to_string(),
        );
    }
    let status = if missing_registers.is_empty() && stack_memory_captured {
        "ready"
    } else if present.contains("sp") && present.contains("nzcv") {
        "partial"
    } else {
        "insufficient"
    };
    UnicornSeedQuality {
        source_event_index: seed.source_event_index,
        capture_offset: capture_offset.to_string(),
        status: status.to_string(),
        register_count: seed.registers.len() as u64,
        missing_registers,
        memory_region_count: seed.memory_regions.len() as u64,
        captured_memory_bytes,
        stack_memory_captured,
        warnings,
    }
}

fn recapture_base_register(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_uppercase();
    if value == "SP" {
        return Some(value);
    }
    value
        .strip_prefix('X')
        .and_then(|index| index.parse::<u8>().ok())
        .filter(|index| *index <= 28)
        .map(|index| format!("X{index}"))
}

fn bounded_recapture_label(value: &str) -> String {
    const MAX_BASE_LABEL_BYTES: usize = 220;
    let mut label = String::new();
    for character in value.chars().filter(|character| !character.is_control()) {
        if label.len().saturating_add(character.len_utf8()) > MAX_BASE_LABEL_BYTES {
            break;
        }
        label.push(character);
    }
    if label.trim().is_empty() {
        "seed-memory".to_string()
    } else {
        label
    }
}

fn build_seed_recapture_plan(
    seed: &AngrStateSeed,
    capture_offset: &str,
) -> UnicornSeedRecapturePlan {
    const MAX_WINDOW_BYTES: u64 = 4_096;
    const MAX_WINDOWS: usize = 256;
    const MAX_DISPLACEMENT: i64 = 1_048_576;

    let mut windows = BTreeMap::<(String, i64, u64), UnicornSeedRecaptureWindow>::new();
    let mut unsupported_memory_region_count = 0u64;
    let mut windows_truncated = false;

    for region in &seed.memory_regions {
        let Some(base_register) = region
            .base_register
            .as_deref()
            .and_then(recapture_base_register)
        else {
            unsupported_memory_region_count += 1;
            continue;
        };
        let Some(displacement) = region
            .displacement
            .as_deref()
            .and_then(|value| parse_signed_offset(value).ok())
        else {
            unsupported_memory_region_count += 1;
            continue;
        };
        if region.source_kind != "byteArray" || region.byte_length == 0 {
            unsupported_memory_region_count += 1;
            continue;
        }
        let Some(last_displacement) = region
            .byte_length
            .checked_sub(1)
            .and_then(|length| i64::try_from(length).ok())
            .and_then(|length| displacement.checked_add(length))
        else {
            unsupported_memory_region_count += 1;
            continue;
        };
        if !(-MAX_DISPLACEMENT..=MAX_DISPLACEMENT).contains(&displacement)
            || !(-MAX_DISPLACEMENT..=MAX_DISPLACEMENT).contains(&last_displacement)
        {
            unsupported_memory_region_count += 1;
            continue;
        }

        let mut chunk_offset = 0u64;
        let chunk_count = region.byte_length.div_ceil(MAX_WINDOW_BYTES);
        let base_label = bounded_recapture_label(&region.label);
        while chunk_offset < region.byte_length {
            let byte_length = (region.byte_length - chunk_offset).min(MAX_WINDOW_BYTES);
            let Some(chunk_displacement) = i64::try_from(chunk_offset)
                .ok()
                .and_then(|offset| displacement.checked_add(offset))
            else {
                unsupported_memory_region_count += 1;
                break;
            };
            let key = (base_register.clone(), chunk_displacement, byte_length);
            if !windows.contains_key(&key) && windows.len() >= MAX_WINDOWS {
                windows_truncated = true;
                break;
            }
            let part_index = chunk_offset / MAX_WINDOW_BYTES + 1;
            windows
                .entry(key)
                .or_insert_with(|| UnicornSeedRecaptureWindow {
                    label: if chunk_count > 1 {
                        format!("{base_label}-part-{part_index}")
                    } else {
                        base_label.clone()
                    },
                    base_register: base_register.clone(),
                    displacement: format_signed_offset_hex(chunk_displacement),
                    byte_length,
                    source_kind: region.source_kind.clone(),
                    phase: region.phase.clone(),
                });
            chunk_offset += byte_length;
        }
    }

    let carry_forward_bytes = windows.values().fold(0u64, |total, window| {
        total.saturating_add(window.byte_length)
    });
    UnicornSeedRecapturePlan {
        source_event_index: seed.source_event_index,
        capture_offset: capture_offset.to_string(),
        windows: windows.into_values().collect(),
        carry_forward_bytes,
        unsupported_memory_region_count,
        windows_truncated,
    }
}

fn quoted_json<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let json = serde_json::to_string(value)
        .map_err(|error| format!("serialize {label} failed: {error}"))?;
    serde_json::to_string(&json).map_err(|error| format!("quote {label} failed: {error}"))
}

pub fn generate_unicorn_ollvm_script(
    report: &OllvmReport,
    frida_seeds: Vec<&AngrStateSeed>,
    config: UnicornOllvmConfig,
    expected_binary_identity: &ElfBinaryIdentity,
) -> Result<UnicornOllvmScript, String> {
    generate_unicorn_ollvm_script_with_checkpoint_result(
        report,
        frida_seeds,
        config,
        expected_binary_identity,
        None,
    )
}

pub fn generate_unicorn_ollvm_script_with_checkpoint_result(
    report: &OllvmReport,
    frida_seeds: Vec<&AngrStateSeed>,
    config: UnicornOllvmConfig,
    expected_binary_identity: &ElfBinaryIdentity,
    checkpoint_result: Option<&UnicornOllvmResultBundle>,
) -> Result<UnicornOllvmScript, String> {
    if report.scope.module_name.trim().is_empty() {
        return Err("OLLVM report module name must not be empty".to_string());
    }
    if expected_binary_identity.elf_machine != 183 {
        return Err(format!(
            "Unicorn OLLVM replay requires an AArch64 ELF, got {}",
            expected_binary_identity.architecture
        ));
    }
    validate_config(&config)?;
    if frida_seeds.is_empty() {
        return Err("Unicorn concrete replay requires at least one exact Frida seed".to_string());
    }
    if frida_seeds.len() > 32 {
        return Err("at most 32 Frida seeds may be embedded in one Unicorn replay".to_string());
    }
    let allowed_checkpoint_offsets = if let Some(bundle) = checkpoint_result {
        if bundle.module_name.trim() != report.scope.module_name.trim() {
            return Err(format!(
                "Unicorn checkpoint result module {} does not match OLLVM report module {}",
                bundle.module_name, report.scope.module_name
            ));
        }
        if !bundle.binary_identity_matched
            || !bundle
                .binary_sha256
                .eq_ignore_ascii_case(&bundle.expected_binary_sha256)
            || !bundle
                .binary_sha256
                .eq_ignore_ascii_case(&expected_binary_identity.binary_sha256)
        {
            return Err(
                "Unicorn checkpoint result does not match the selected exact ELF SHA-256"
                    .to_string(),
            );
        }
        unicorn_checkpoint_offsets(bundle)?
    } else {
        BTreeSet::new()
    };

    let mut payloads = Vec::with_capacity(frida_seeds.len());
    let mut provenances = Vec::with_capacity(frida_seeds.len());
    let mut qualities = Vec::with_capacity(frida_seeds.len());
    let mut recapture_plans = Vec::with_capacity(frida_seeds.len());
    let mut source_event_indices = HashSet::new();
    for seed in frida_seeds {
        if !source_event_indices.insert(seed.source_event_index) {
            return Err(format!(
                "duplicate Frida seed source event index {}",
                seed.source_event_index
            ));
        }
        let (mut payload, provenance) =
            prepare_frida_seed_with_allowed_offsets(report, seed, &allowed_checkpoint_offsets)?;
        let quality = assess_seed_quality(seed, &provenance.capture_offset);
        let recapture_plan = build_seed_recapture_plan(seed, &provenance.capture_offset);
        payload["quality"] = serde_json::to_value(&quality)
            .map_err(|error| format!("serialize seed quality failed: {error}"))?;
        payload["recapturePlan"] = serde_json::to_value(&recapture_plan)
            .map_err(|error| format!("serialize seed recapture plan failed: {error}"))?;
        payloads.push(payload);
        provenances.push(provenance);
        qualities.push(quality);
        recapture_plans.push(recapture_plan);
    }

    let report_literal = quoted_json(report, "OLLVM report")?;
    let seeds_literal = quoted_json(&payloads, "Frida seeds")?;
    let identity_literal = quoted_json(expected_binary_identity, "expected ELF identity")?;
    let config_literal = quoted_json(&config, "Unicorn config")?;
    let template = include_str!("unicorn_bridge.py");
    let script = template
        .replace("__REPORT_JSON__", &report_literal)
        .replace("__SEEDS_JSON__", &seeds_literal)
        .replace("__EXPECTED_BINARY_IDENTITY__", &identity_literal)
        .replace("__CONFIG_JSON__", &config_literal);

    let function_name = report
        .scope
        .function_name
        .as_deref()
        .unwrap_or(&report.scope.module_name);
    let file_name = format!("{}-trace-ui-unicorn.py", sanitize_name(function_name));
    let mut warnings = vec![
        "This generated Python script performs bounded concrete emulation only; Trace UI does not execute Unicorn or the target binary.".to_string(),
        "Every replay starts from an exact-offset user-captured Frida state and remains Candidate/Related evidence rather than recovered control flow.".to_string(),
        "ELF-backed bytes, captured memory, and bytes defined by replay writes are valid. Missing runtime memory stops explicitly instead of being treated as zero.".to_string(),
        "Calls stop by default. TLS, uncaptured system state, and SIMD reads without an in-replay definition stop explicitly.".to_string(),
    ];
    if qualities.iter().any(|quality| quality.status != "ready") {
        warnings.push(
            "One or more seeds are partial; review seedQualities and enable bounded stack/pointer capture before relying on replay continuity."
                .to_string(),
        );
    }
    let unsupported_regions = recapture_plans
        .iter()
        .map(|plan| plan.unsupported_memory_region_count)
        .sum::<u64>();
    if unsupported_regions > 0 {
        warnings.push(format!(
            "{unsupported_regions} seed memory region(s) lacked a verified bounded X0-X28/SP-relative relation and cannot be automatically carried into the next Frida recapture round."
        ));
    }
    if recapture_plans.iter().any(|plan| plan.windows_truncated) {
        warnings.push(
            "One or more seed recapture plans reached the 256-window bound; review the omitted coverage before another replay."
                .to_string(),
        );
    }
    if checkpoint_result.is_some() {
        warnings.push(format!(
            "{} closer checkpoint offset(s) were authorized from a strictly validated prior Unicorn result for the same module and exact ELF.",
            allowed_checkpoint_offsets.len()
        ));
    }

    Ok(UnicornOllvmScript {
        file_name,
        script,
        schema_version: UNICORN_OLLVM_SCHEMA.to_string(),
        seeds: provenances,
        seed_qualities: qualities,
        seed_recapture_plans: recapture_plans,
        expected_binary_identity: expected_binary_identity.clone(),
        config,
        warnings,
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn validate_offset(value: &str, label: &str) -> Result<(), String> {
    parse_hex_addr(value)
        .map(|_| ())
        .map_err(|error| format!("invalid {label} {value}: {error}"))
}

pub fn parse_unicorn_ollvm_result_bundle(bytes: &[u8]) -> Result<UnicornOllvmResultBundle, String> {
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("Unicorn result exceeds the 64 MiB import limit".to_string());
    }
    let bundle: UnicornOllvmResultBundle = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid Unicorn result JSON: {error}"))?;
    if bundle.schema != UNICORN_OLLVM_SCHEMA {
        return Err(format!(
            "unsupported Unicorn result schema: {}",
            bundle.schema
        ));
    }
    if bundle.module_name.trim().is_empty() {
        return Err("Unicorn result moduleName must not be empty".to_string());
    }
    if !valid_sha256(&bundle.binary_sha256) || !valid_sha256(&bundle.expected_binary_sha256) {
        return Err(
            "Unicorn result SHA-256 fields must contain 64 hexadecimal characters".to_string(),
        );
    }
    if !bundle.binary_identity_matched
        || !bundle
            .binary_sha256
            .eq_ignore_ascii_case(&bundle.expected_binary_sha256)
    {
        return Err("Unicorn result exact ELF identity did not match".to_string());
    }
    if !bundle.architecture.to_ascii_lowercase().contains("aarch64") {
        return Err(format!(
            "Unicorn result architecture is not AArch64: {}",
            bundle.architecture
        ));
    }
    validate_config(&bundle.config)?;
    if bundle.seeds.is_empty() || bundle.seeds.len() > 32 {
        return Err("Unicorn result must contain between 1 and 32 seed provenances".to_string());
    }
    if bundle.runs.is_empty() || bundle.runs.len() > 32 {
        return Err("Unicorn result must contain between 1 and 32 replay runs".to_string());
    }
    if bundle.seed_qualities.len() != bundle.seeds.len() {
        return Err("Unicorn result seedQualities count does not match seeds".to_string());
    }
    let seed_events = bundle
        .seeds
        .iter()
        .map(|seed| seed.source_event_index)
        .collect::<BTreeSet<_>>();
    if seed_events.len() != bundle.seeds.len() {
        return Err("Unicorn result contains duplicate seed event indices".to_string());
    }
    for seed in &bundle.seeds {
        if seed.module_name != bundle.module_name {
            return Err(format!(
                "Unicorn seed event {} module {} does not match result module {}",
                seed.source_event_index, seed.module_name, bundle.module_name
            ));
        }
        validate_offset(&seed.capture_offset, "seed captureOffset")?;
        if seed.matched_probe_offsets.is_empty() {
            return Err(format!(
                "Unicorn seed event {} has no exact matched probe offset",
                seed.source_event_index
            ));
        }
        for offset in seed
            .matched_probe_offsets
            .iter()
            .chain(&seed.matched_branch_offsets)
            .chain(&seed.matched_dispatcher_offsets)
        {
            validate_offset(offset, "seed matched offset")?;
        }
    }
    let mut quality_events = BTreeSet::new();
    for quality in &bundle.seed_qualities {
        if !seed_events.contains(&quality.source_event_index)
            || !quality_events.insert(quality.source_event_index)
        {
            return Err(format!(
                "Unicorn seed quality references an unknown or duplicate event {}",
                quality.source_event_index
            ));
        }
        if !["ready", "partial", "insufficient"].contains(&quality.status.as_str()) {
            return Err(format!(
                "unsupported Unicorn seed quality status: {}",
                quality.status
            ));
        }
        validate_offset(&quality.capture_offset, "seed quality captureOffset")?;
        let Some(seed) = bundle
            .seeds
            .iter()
            .find(|seed| seed.source_event_index == quality.source_event_index)
        else {
            return Err(format!(
                "Unicorn seed quality references unknown event {}",
                quality.source_event_index
            ));
        };
        if !quality
            .capture_offset
            .eq_ignore_ascii_case(&seed.capture_offset)
        {
            return Err(format!(
                "Unicorn seed quality captureOffset does not match event {} provenance",
                quality.source_event_index
            ));
        }
    }
    if !bundle.seed_recapture_plans.is_empty() {
        if bundle.seed_recapture_plans.len() != bundle.seeds.len() {
            return Err("Unicorn result seedRecapturePlans count does not match seeds".to_string());
        }
        let mut plan_events = BTreeSet::new();
        let mut total_plan_bytes = 0u64;
        for plan in &bundle.seed_recapture_plans {
            if !seed_events.contains(&plan.source_event_index)
                || !plan_events.insert(plan.source_event_index)
            {
                return Err(format!(
                    "Unicorn seed recapture plan references an unknown or duplicate event {}",
                    plan.source_event_index
                ));
            }
            let seed = bundle
                .seeds
                .iter()
                .find(|seed| seed.source_event_index == plan.source_event_index)
                .expect("validated seed event must exist");
            validate_offset(&plan.capture_offset, "seed recapture captureOffset")?;
            if !plan
                .capture_offset
                .eq_ignore_ascii_case(&seed.capture_offset)
            {
                return Err(format!(
                    "Unicorn seed recapture captureOffset does not match event {} provenance",
                    plan.source_event_index
                ));
            }
            if plan.windows.len() > 256 {
                return Err(format!(
                    "Unicorn seed recapture plan {} exceeds the bounded window count",
                    plan.source_event_index
                ));
            }
            let mut plan_bytes = 0u64;
            let mut unique_windows = BTreeSet::new();
            for window in &plan.windows {
                if window.label.trim().is_empty()
                    || window.label.len() > 256
                    || window.label.chars().any(|character| character.is_control())
                {
                    return Err("Unicorn seed recapture window label is invalid".to_string());
                }
                let Some(base_register) = recapture_base_register(&window.base_register) else {
                    return Err(format!(
                        "Unicorn seed recapture window uses unsupported register {}",
                        window.base_register
                    ));
                };
                let displacement = parse_signed_offset(&window.displacement)?;
                let Some(last_displacement) = window
                    .byte_length
                    .checked_sub(1)
                    .and_then(|length| i64::try_from(length).ok())
                    .and_then(|length| displacement.checked_add(length))
                else {
                    return Err("Unicorn seed recapture window displacement overflow".to_string());
                };
                if window.byte_length == 0
                    || window.byte_length > 4096
                    || !(-1_048_576..=1_048_576).contains(&displacement)
                    || !(-1_048_576..=1_048_576).contains(&last_displacement)
                {
                    return Err(
                        "Unicorn seed recapture window must be 1-4096 bytes within +/- 1 MiB"
                            .to_string(),
                    );
                }
                if window.source_kind != "byteArray" {
                    return Err(
                        "Unicorn seed recapture windows must originate from byteArray captures"
                            .to_string(),
                    );
                }
                if !unique_windows.insert((base_register, displacement, window.byte_length)) {
                    return Err(
                        "Unicorn seed recapture plan contains duplicate windows".to_string()
                    );
                }
                plan_bytes = plan_bytes.saturating_add(window.byte_length);
            }
            if plan_bytes != plan.carry_forward_bytes || plan_bytes > 1_048_576 {
                return Err(format!(
                    "Unicorn seed recapture byte count is invalid for event {}",
                    plan.source_event_index
                ));
            }
            total_plan_bytes = total_plan_bytes.saturating_add(plan_bytes);
        }
        if plan_events != seed_events || total_plan_bytes > 33_554_432 {
            return Err(
                "Unicorn result seed recapture plans are incomplete or too large".to_string(),
            );
        }
    }
    let mut run_events = BTreeSet::new();
    let mut total_offsets = 0usize;
    let mut total_writes = 0usize;
    let allowed_stops = [
        "next-dispatcher",
        "return",
        "call-boundary",
        "loop-detected",
        "missing-memory",
        "missing-register",
        "unsupported-simd-state",
        "unsupported-system-state",
        "outside-executable",
        "instruction-limit",
        "timeout",
        "invalid-instruction",
        "emulation-error",
        "completed",
    ];
    for run in &bundle.runs {
        if !seed_events.contains(&run.source_event_index) {
            return Err(format!(
                "Unicorn replay run references unknown event {}",
                run.source_event_index
            ));
        }
        if !run_events.insert(run.source_event_index) {
            return Err(format!(
                "Unicorn result contains duplicate replay run for event {}",
                run.source_event_index
            ));
        }
        if !allowed_stops.contains(&run.stop_reason.as_str()) {
            return Err(format!(
                "unsupported Unicorn stop reason: {}",
                run.stop_reason
            ));
        }
        validate_offset(&run.start_offset, "startOffset")?;
        validate_offset(&run.mapped_base, "mappedBase")?;
        validate_offset(&run.terminal_address, "terminalAddress")?;
        if let Some(offset) = &run.terminal_offset {
            validate_offset(offset, "terminalOffset")?;
        }
        if let Some(offset) = &run.matched_dispatcher_offset {
            validate_offset(offset, "matchedDispatcherOffset")?;
        }
        total_offsets = total_offsets.saturating_add(run.executed_offsets.len());
        total_writes = total_writes.saturating_add(run.memory_writes.len());
        if run.missing_memory.len() > 64 {
            return Err(format!(
                "Unicorn replay run {} contains more than 64 missing-memory records",
                run.source_event_index
            ));
        }
    }
    if run_events != seed_events {
        return Err(
            "Unicorn result must contain exactly one replay run per seed event".to_string(),
        );
    }
    if total_offsets > 1_000_000 {
        return Err("Unicorn result contains more than 1000000 executed offsets".to_string());
    }
    if total_writes > 100_000 {
        return Err("Unicorn result contains more than 100000 memory writes".to_string());
    }
    for transition in &bundle.transition_matrix {
        validate_offset(&transition.source_offset, "transition sourceOffset")?;
        validate_offset(&transition.target_offset, "transition targetOffset")?;
        if transition.execution_count == 0
            || transition.execution_count != transition.source_event_indices.len() as u64
        {
            return Err(
                "Unicorn transition executionCount does not match event indices".to_string(),
            );
        }
        if transition
            .source_event_indices
            .iter()
            .any(|event| !run_events.contains(event))
        {
            return Err("Unicorn transition references an unknown replay event".to_string());
        }
    }
    for suggestion in &bundle.recapture_suggestions {
        validate_offset(&suggestion.pc_offset, "recapture pcOffset")?;
        if suggestion.byte_length == 0 || suggestion.byte_length > 4096 {
            return Err("Unicorn recapture suggestion byteLength must be 1-4096".to_string());
        }
        if suggestion
            .source_event_indices
            .iter()
            .any(|event| !run_events.contains(event))
        {
            return Err(
                "Unicorn recapture suggestion references an unknown replay event".to_string(),
            );
        }
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::elf_identity::inspect_elf_bytes;
    use crate::query::evidence_score::{score_evidence, EvidenceScoreSignal};
    use crate::query::frida_capture::{AngrSeedMemoryRegion, AngrSeedRegister};
    use crate::query::ollvm::{
        DispatcherCandidate, DynamicBasicBlock, OllvmScope, OpaqueBranchCandidate,
    };

    fn sample_report() -> OllvmReport {
        let dispatcher = |offset: &str| DispatcherCandidate {
            block_id: format!("libtarget.so+{offset}"),
            start_offset: offset.to_string(),
            end_offset: offset.to_string(),
            visit_count: 4,
            predecessor_count: 2,
            successor_count: 2,
            indirect_branch_count: 2,
            backward_edge_count: 1,
            state_registers: vec!["X8".to_string()],
            state_snapshots: Vec::new(),
            state_transitions: Vec::new(),
            state_snapshots_truncated: false,
            rationale: "candidate dispatcher".to_string(),
            assessment: score_evidence(
                "dispatcher",
                false,
                vec![EvidenceScoreSignal::new(
                    "test",
                    "test evidence",
                    40,
                    true,
                    None,
                )],
                vec!["candidate only".to_string()],
            ),
        };
        OllvmReport {
            schema_version: "trace-ui/ollvm-v1".to_string(),
            scope: OllvmScope {
                session_id: "session".to_string(),
                node_id: Some(1),
                function_name: Some("target".to_string()),
                module_name: "libtarget.so".to_string(),
                module_base: "0x40000000".to_string(),
                start_seq: 1,
                end_seq: 3,
                child_calls_excluded: 0,
            },
            executed_instruction_count: 3,
            unique_instruction_count: 3,
            block_count: 2,
            edge_count: 1,
            blocks: vec![DynamicBasicBlock {
                block_id: "libtarget.so+0x100".to_string(),
                module_name: "libtarget.so".to_string(),
                start_offset: "0x100".to_string(),
                end_offset: "0x104".to_string(),
                start_address: "0x40000100".to_string(),
                end_address: "0x40000104".to_string(),
                visit_count: 1,
                predecessor_count: 0,
                successor_count: 1,
                terminal_operation: "b".to_string(),
                sample_seqs: vec![1],
                instructions: Vec::new(),
            }],
            edges: Vec::new(),
            branch_profiles: Vec::new(),
            dispatcher_candidates: vec![dispatcher("0x100"), dispatcher("0x108")],
            opaque_branch_candidates: vec![OpaqueBranchCandidate {
                branch_offset: "0x104".to_string(),
                disasm: "b 0x108".to_string(),
                execution_count: 1,
                observed_taken_count: 1,
                observed_fallthrough_count: 0,
                observed_other_count: 0,
                observed_successors: vec!["0x108".to_string()],
                condition_source_offsets: vec!["0x100".to_string()],
                observations: Vec::new(),
                observations_truncated: false,
                condition_state_profile: Default::default(),
                rationale: "candidate branch".to_string(),
                assessment: score_evidence(
                    "opaque-branch",
                    false,
                    vec![EvidenceScoreSignal::new(
                        "test",
                        "test evidence",
                        40,
                        true,
                        None,
                    )],
                    vec!["candidate only".to_string()],
                ),
            }],
            instructions_truncated: false,
            blocks_truncated: false,
            edges_truncated: false,
            limitations: Vec::new(),
            next_steps: Vec::new(),
        }
    }

    fn sample_seed() -> AngrStateSeed {
        let mut registers = (0..=30)
            .map(|index| AngrSeedRegister {
                name: format!("x{index}"),
                value: if index == 8 {
                    "0x1".to_string()
                } else {
                    "0x0".to_string()
                },
            })
            .collect::<Vec<_>>();
        registers.push(AngrSeedRegister {
            name: "sp".to_string(),
            value: "0x50000000".to_string(),
        });
        registers.push(AngrSeedRegister {
            name: "nzcv".to_string(),
            value: "0x0".to_string(),
        });
        AngrStateSeed {
            schema_version: "trace-ui/angr-state-seed-v1".to_string(),
            source_event_index: 7,
            source_event: "ollvm-dispatcher-hit".to_string(),
            hook_id: "dispatcher-100".to_string(),
            call_id: None,
            module_name: Some("libtarget.so".to_string()),
            module_base: Some("0x40000000".to_string()),
            module_size: 0x2000,
            function_name: "dispatcher-100".to_string(),
            capture_target: Some("0x40000100".to_string()),
            capture_offset: Some("0x100".to_string()),
            script: String::new(),
            registers_seeded: registers.iter().map(|value| value.name.clone()).collect(),
            registers,
            memory_regions: vec![AngrSeedMemoryRegion {
                address: "0x50000000".to_string(),
                byte_length: 256,
                bytes_hex: "00".repeat(256),
                label: "sp-stack-memory".to_string(),
                source_kind: "byteArray".to_string(),
                phase: "enter".to_string(),
                base_register: Some("SP".to_string()),
                displacement: Some("0x0".to_string()),
            }],
            warnings: Vec::new(),
        }
    }

    fn minimal_aarch64_elf() -> Vec<u8> {
        let mut elf = vec![0u8; 0x200];
        let file_size = elf.len() as u64;
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x100u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5u32.to_le_bytes());
        elf[72..80].copy_from_slice(&0u64.to_le_bytes());
        elf[80..88].copy_from_slice(&0u64.to_le_bytes());
        elf[96..104].copy_from_slice(&file_size.to_le_bytes());
        elf[104..112].copy_from_slice(&file_size.to_le_bytes());
        elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[0x100..0x104].copy_from_slice(&0x91000508u32.to_le_bytes());
        elf[0x104..0x108].copy_from_slice(&0x14000001u32.to_le_bytes());
        elf[0x108..0x10c].copy_from_slice(&0xd65f03c0u32.to_le_bytes());
        elf
    }

    fn checkpoint_result(identity: &ElfBinaryIdentity) -> UnicornOllvmResultBundle {
        let generated = generate_unicorn_ollvm_script(
            &sample_report(),
            vec![&sample_seed()],
            UnicornOllvmConfig::default(),
            identity,
        )
        .unwrap();
        UnicornOllvmResultBundle {
            schema: UNICORN_OLLVM_SCHEMA.to_string(),
            module_name: "libtarget.so".to_string(),
            binary_sha256: identity.binary_sha256.clone(),
            expected_binary_sha256: identity.binary_sha256.clone(),
            binary_identity_matched: true,
            architecture: "AArch64".to_string(),
            unicorn_version: "2.1.4".to_string(),
            capstone_version: "5.0.6".to_string(),
            config: generated.config,
            seeds: generated.seeds,
            seed_qualities: generated.seed_qualities,
            seed_recapture_plans: generated.seed_recapture_plans,
            runs: vec![UnicornReplayRun {
                source_event_index: 7,
                seed_kind: "frida-capture-exact-dispatcher".to_string(),
                start_offset: "0x100".to_string(),
                mapped_base: "0x40000000".to_string(),
                stop_reason: "missing-memory".to_string(),
                instruction_count: 4,
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
                    address: "0x60000020".to_string(),
                    size: 16,
                    pc_offset: Some("0x180".to_string()),
                    instruction: Some("ldr q0, [x19, #0x20]".to_string()),
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
                byte_length: 16,
                reason: "test checkpoint memory".to_string(),
                source_event_indices: vec![7],
            }],
            warnings: Vec::new(),
        }
    }

    fn checkpoint_seed(offset: &str) -> AngrStateSeed {
        let mut seed = sample_seed();
        let absolute = 0x4000_0000u64 + parse_hex_addr(offset).unwrap();
        seed.source_event_index = 8;
        seed.source_event = "hook-enter".to_string();
        seed.hook_id = format!("unicorn-checkpoint-{}", offset.trim_start_matches("0x"));
        seed.function_name = seed.hook_id.clone();
        seed.capture_target = Some(format!("0x{absolute:x}"));
        seed.capture_offset = Some(offset.to_string());
        seed
    }

    #[test]
    fn generates_bounded_script_and_ready_quality() {
        let elf = minimal_aarch64_elf();
        let identity = inspect_elf_bytes("libtarget.so", &elf).unwrap();
        let seed = sample_seed();
        let generated = generate_unicorn_ollvm_script(
            &sample_report(),
            vec![&seed],
            UnicornOllvmConfig::default(),
            &identity,
        )
        .unwrap();
        assert_eq!(generated.schema_version, UNICORN_OLLVM_SCHEMA);
        assert_eq!(generated.seed_qualities[0].status, "ready");
        assert_eq!(generated.seed_recapture_plans.len(), 1);
        assert_eq!(generated.seed_recapture_plans[0].windows.len(), 1);
        assert_eq!(generated.seed_recapture_plans[0].carry_forward_bytes, 256);
        assert!(generated.script.contains("Uc(UC_ARCH_ARM64"));
        assert!(generated.script.contains("missing-memory"));
        assert!(generated.script.contains("seedRecapturePlans"));
        assert!(generated.script.contains(&identity.binary_sha256));
    }

    #[test]
    fn splits_large_seed_memory_into_bounded_recapture_windows() {
        let mut seed = sample_seed();
        seed.memory_regions[0].byte_length = 16 * 1024;
        seed.memory_regions[0].bytes_hex = "00".repeat(16 * 1024);
        let plan = build_seed_recapture_plan(&seed, "0x100");
        assert_eq!(plan.windows.len(), 4);
        assert_eq!(plan.carry_forward_bytes, 16 * 1024);
        assert_eq!(plan.unsupported_memory_region_count, 0);
        assert!(!plan.windows_truncated);
        assert_eq!(plan.windows[0].displacement, "0x0");
        assert_eq!(plan.windows[1].displacement, "0x1000");
        assert_eq!(plan.windows[2].displacement, "0x2000");
        assert_eq!(plan.windows[3].displacement, "0x3000");
        assert!(plan.windows.iter().all(|window| window.byte_length == 4096));
    }

    #[test]
    fn rejects_missing_seed_and_non_aarch64_identity() {
        let identity = inspect_elf_bytes("libtarget.so", &minimal_aarch64_elf()).unwrap();
        assert!(generate_unicorn_ollvm_script(
            &sample_report(),
            Vec::new(),
            UnicornOllvmConfig::default(),
            &identity,
        )
        .is_err());
        let mut wrong = identity;
        wrong.elf_machine = 62;
        wrong.architecture = "x86-64".to_string();
        assert!(generate_unicorn_ollvm_script(
            &sample_report(),
            vec![&sample_seed()],
            UnicornOllvmConfig::default(),
            &wrong,
        )
        .is_err());
    }

    #[test]
    fn authorizes_only_checkpoint_offsets_from_matching_prior_result() {
        let identity = inspect_elf_bytes("libtarget.so", &minimal_aarch64_elf()).unwrap();
        let seed = checkpoint_seed("0x180");
        let without_prior = generate_unicorn_ollvm_script(
            &sample_report(),
            vec![&seed],
            UnicornOllvmConfig::default(),
            &identity,
        )
        .unwrap_err();
        assert!(without_prior.contains("authorized Unicorn checkpoint"));

        let prior = checkpoint_result(&identity);
        let generated = generate_unicorn_ollvm_script_with_checkpoint_result(
            &sample_report(),
            vec![&seed],
            UnicornOllvmConfig::default(),
            &identity,
            Some(&prior),
        )
        .unwrap();
        assert_eq!(generated.seeds[0].capture_offset, "0x180");
        assert_eq!(generated.seeds[0].matched_probe_offsets, vec!["0x180"]);
        assert!(generated.seeds[0].matched_branch_offsets.is_empty());
        assert!(generated.seeds[0].matched_dispatcher_offsets.is_empty());
        assert!(generated.script.contains("frida-capture-exact-offset"));
        assert!(generated
            .warnings
            .iter()
            .any(|warning| warning.contains("1 closer checkpoint offset")));

        let unknown = checkpoint_seed("0x184");
        let error = generate_unicorn_ollvm_script_with_checkpoint_result(
            &sample_report(),
            vec![&unknown],
            UnicornOllvmConfig::default(),
            &identity,
            Some(&prior),
        )
        .unwrap_err();
        assert!(error.contains("authorized Unicorn checkpoint"));
    }

    #[test]
    fn rejects_checkpoint_result_module_or_elf_mismatch() {
        let identity = inspect_elf_bytes("libtarget.so", &minimal_aarch64_elf()).unwrap();
        let seed = checkpoint_seed("0x180");

        let mut wrong_module = checkpoint_result(&identity);
        wrong_module.module_name = "libother.so".to_string();
        let error = generate_unicorn_ollvm_script_with_checkpoint_result(
            &sample_report(),
            vec![&seed],
            UnicornOllvmConfig::default(),
            &identity,
            Some(&wrong_module),
        )
        .unwrap_err();
        assert!(error.contains("does not match OLLVM report module"));

        let mut wrong_hash = checkpoint_result(&identity);
        wrong_hash.binary_sha256 = "f".repeat(64);
        wrong_hash.expected_binary_sha256 = wrong_hash.binary_sha256.clone();
        let error = generate_unicorn_ollvm_script_with_checkpoint_result(
            &sample_report(),
            vec![&seed],
            UnicornOllvmConfig::default(),
            &identity,
            Some(&wrong_hash),
        )
        .unwrap_err();
        assert!(error.contains("exact ELF SHA-256"));
    }

    #[test]
    fn result_parser_requires_one_run_for_every_seed_event() {
        let identity = inspect_elf_bytes("libtarget.so", &minimal_aarch64_elf()).unwrap();
        let generated = generate_unicorn_ollvm_script(
            &sample_report(),
            vec![&sample_seed()],
            UnicornOllvmConfig::default(),
            &identity,
        )
        .unwrap();
        let mut bundle = UnicornOllvmResultBundle {
            schema: UNICORN_OLLVM_SCHEMA.to_string(),
            module_name: "libtarget.so".to_string(),
            binary_sha256: identity.binary_sha256.clone(),
            expected_binary_sha256: identity.binary_sha256,
            binary_identity_matched: true,
            architecture: "AArch64".to_string(),
            unicorn_version: "2.1.4".to_string(),
            capstone_version: "5.0.6".to_string(),
            config: generated.config,
            seeds: generated.seeds,
            seed_qualities: generated.seed_qualities,
            seed_recapture_plans: generated.seed_recapture_plans,
            runs: vec![UnicornReplayRun {
                source_event_index: 7,
                seed_kind: "frida-capture-exact-dispatcher".to_string(),
                start_offset: "0x100".to_string(),
                mapped_base: "0x40000000".to_string(),
                stop_reason: "return".to_string(),
                instruction_count: 1,
                elapsed_ms: 1,
                terminal_address: "0x40000108".to_string(),
                terminal_offset: Some("0x108".to_string()),
                matched_dispatcher_offset: None,
                source_state_values: Vec::new(),
                target_state_values: Vec::new(),
                executed_offsets: vec!["0x100".to_string()],
                executed_offsets_truncated: false,
                block_offsets: vec!["0x100".to_string()],
                block_offsets_truncated: false,
                register_changes: Vec::new(),
                memory_writes: Vec::new(),
                memory_writes_truncated: false,
                call_boundaries: Vec::new(),
                missing_memory: Vec::new(),
                warnings: Vec::new(),
                error: None,
            }],
            transition_matrix: Vec::new(),
            recapture_suggestions: Vec::new(),
            warnings: Vec::new(),
        };
        parse_unicorn_ollvm_result_bundle(&serde_json::to_vec(&bundle).unwrap()).unwrap();

        let mut invalid = bundle.clone();
        invalid.seed_recapture_plans.clear();
        invalid
            .seed_recapture_plans
            .push(bundle.seed_recapture_plans[0].clone());
        invalid
            .seed_recapture_plans
            .push(bundle.seed_recapture_plans[0].clone());
        let error =
            parse_unicorn_ollvm_result_bundle(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
        assert!(error.contains("count does not match seeds"));

        let mut invalid = bundle.clone();
        invalid.seed_recapture_plans[0].source_event_index = 99;
        let error =
            parse_unicorn_ollvm_result_bundle(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
        assert!(error.contains("unknown or duplicate event"));

        let mut invalid = bundle.clone();
        invalid.seed_recapture_plans[0].capture_offset = "0x104".to_string();
        let error =
            parse_unicorn_ollvm_result_bundle(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
        assert!(error.contains("captureOffset does not match"));

        let mut invalid = bundle.clone();
        invalid.seed_recapture_plans[0].windows[0].base_register = "X29".to_string();
        let error =
            parse_unicorn_ollvm_result_bundle(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
        assert!(error.contains("unsupported register"));

        let mut invalid = bundle.clone();
        invalid.seed_recapture_plans[0].windows[0].displacement = "0x200000".to_string();
        let error =
            parse_unicorn_ollvm_result_bundle(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
        assert!(error.contains("within +/- 1 MiB"));

        let mut invalid = bundle.clone();
        invalid.seed_recapture_plans[0].carry_forward_bytes += 1;
        let error =
            parse_unicorn_ollvm_result_bundle(&serde_json::to_vec(&invalid).unwrap()).unwrap_err();
        assert!(error.contains("byte count is invalid"));

        let mut extra_seed = bundle.seeds[0].clone();
        extra_seed.source_event_index = 8;
        let mut extra_quality = bundle.seed_qualities[0].clone();
        extra_quality.source_event_index = 8;
        let mut extra_recapture_plan = bundle.seed_recapture_plans[0].clone();
        extra_recapture_plan.source_event_index = 8;
        bundle.seeds.push(extra_seed);
        bundle.seed_qualities.push(extra_quality);
        bundle.seed_recapture_plans.push(extra_recapture_plan);
        let error =
            parse_unicorn_ollvm_result_bundle(&serde_json::to_vec(&bundle).unwrap()).unwrap_err();
        assert!(error.contains("exactly one replay run per seed event"));
    }

    #[test]
    fn generated_script_replays_to_next_dispatcher_when_python_modules_exist() {
        use std::process::Command;

        let python = if cfg!(windows) { "python" } else { "python3" };
        let modules = Command::new(python)
            .args(["-c", "import unicorn, capstone, elftools"])
            .status();
        if !modules.is_ok_and(|status| status.success()) {
            eprintln!("skipping Unicorn runtime smoke test because Python modules are unavailable");
            return;
        }
        let elf = minimal_aarch64_elf();
        let identity = inspect_elf_bytes("libtarget.so", &elf).unwrap();
        let generated = generate_unicorn_ollvm_script(
            &sample_report(),
            vec![&sample_seed()],
            UnicornOllvmConfig::default(),
            &identity,
        )
        .unwrap();
        let temp =
            std::env::temp_dir().join(format!("trace-ui-unicorn-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let binary_path = temp.join("libtarget.so");
        let script_path = temp.join("replay.py");
        let result_path = temp.join("result.json");
        std::fs::write(&binary_path, elf).unwrap();
        std::fs::write(&script_path, generated.script).unwrap();
        let output = Command::new(python)
            .arg(&script_path)
            .arg(&binary_path)
            .arg("-o")
            .arg(&result_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "generated Unicorn script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let parsed =
            parse_unicorn_ollvm_result_bundle(&std::fs::read(&result_path).unwrap()).unwrap();
        assert_eq!(parsed.seed_recapture_plans.len(), 1);
        assert_eq!(parsed.seed_recapture_plans[0].carry_forward_bytes, 256);
        assert_eq!(parsed.seed_recapture_plans[0].windows.len(), 1);
        assert_eq!(parsed.runs[0].stop_reason, "next-dispatcher");
        assert_eq!(
            parsed.runs[0].matched_dispatcher_offset.as_deref(),
            Some("0x108")
        );
        assert!(parsed.runs[0]
            .target_state_values
            .iter()
            .any(|value| value.register == "X8" && value.value.as_deref() == Some("0x2")));
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn generated_script_reports_register_relative_missing_memory() {
        use std::process::Command;

        let python = if cfg!(windows) { "python" } else { "python3" };
        if !Command::new(python)
            .args(["-c", "import unicorn, capstone, elftools"])
            .status()
            .is_ok_and(|status| status.success())
        {
            eprintln!(
                "skipping Unicorn missing-memory smoke test because Python modules are unavailable"
            );
            return;
        }
        let mut elf = minimal_aarch64_elf();
        elf[0x100..0x104].copy_from_slice(&0xf9401260u32.to_le_bytes());
        let identity = inspect_elf_bytes("libtarget.so", &elf).unwrap();
        let mut seed = sample_seed();
        seed.registers
            .iter_mut()
            .find(|register| register.name == "x19")
            .unwrap()
            .value = "0x60000000".to_string();
        let generated = generate_unicorn_ollvm_script(
            &sample_report(),
            vec![&seed],
            UnicornOllvmConfig::default(),
            &identity,
        )
        .unwrap();
        let temp = std::env::temp_dir().join(format!(
            "trace-ui-unicorn-missing-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let binary_path = temp.join("libtarget.so");
        let script_path = temp.join("replay.py");
        let result_path = temp.join("result.json");
        std::fs::write(&binary_path, elf).unwrap();
        std::fs::write(&script_path, generated.script).unwrap();
        let output = Command::new(python)
            .arg(&script_path)
            .arg(&binary_path)
            .arg("-o")
            .arg(&result_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "generated Unicorn script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let parsed =
            parse_unicorn_ollvm_result_bundle(&std::fs::read(&result_path).unwrap()).unwrap();
        assert_eq!(parsed.runs[0].stop_reason, "missing-memory");
        assert_eq!(
            parsed.runs[0].missing_memory[0].base_register.as_deref(),
            Some("X19")
        );
        assert_eq!(
            parsed.runs[0].missing_memory[0].displacement.as_deref(),
            Some("0x20")
        );
        assert!(parsed
            .recapture_suggestions
            .iter()
            .any(|suggestion| suggestion.base_register.as_deref() == Some("X19")));
        assert!(parsed.recapture_suggestions.iter().any(|suggestion| {
            suggestion.reason.contains("X19 pointer capture")
                && suggestion.reason.contains("at least 40 bytes")
        }));
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn generated_script_classifies_external_instruction_fetch_as_control_boundary() {
        use std::process::Command;

        let python = if cfg!(windows) { "python" } else { "python3" };
        if !Command::new(python)
            .args(["-c", "import unicorn, capstone, elftools"])
            .status()
            .is_ok_and(|status| status.success())
        {
            eprintln!(
                "skipping Unicorn external-fetch smoke test because Python modules are unavailable"
            );
            return;
        }
        let mut elf = minimal_aarch64_elf();
        // b 0x1100 from offset 0x100, outside the mapped 0x1000-byte image.
        elf[0x100..0x104].copy_from_slice(&0x14000400u32.to_le_bytes());
        let identity = inspect_elf_bytes("libtarget.so", &elf).unwrap();
        let generated = generate_unicorn_ollvm_script(
            &sample_report(),
            vec![&sample_seed()],
            UnicornOllvmConfig::default(),
            &identity,
        )
        .unwrap();
        let temp = std::env::temp_dir().join(format!(
            "trace-ui-unicorn-external-fetch-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let binary_path = temp.join("libtarget.so");
        let script_path = temp.join("replay.py");
        let result_path = temp.join("result.json");
        std::fs::write(&binary_path, elf).unwrap();
        std::fs::write(&script_path, generated.script).unwrap();
        let output = Command::new(python)
            .arg(&script_path)
            .arg(&binary_path)
            .arg("-o")
            .arg(&result_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "generated Unicorn script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let parsed =
            parse_unicorn_ollvm_result_bundle(&std::fs::read(&result_path).unwrap()).unwrap();
        assert_eq!(parsed.runs[0].stop_reason, "outside-executable");
        assert!(parsed.runs[0].missing_memory.is_empty());
        assert!(parsed.recapture_suggestions.is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }
}
