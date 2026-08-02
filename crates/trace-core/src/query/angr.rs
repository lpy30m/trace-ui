use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::query::elf_identity::ElfBinaryIdentity;
use crate::query::frida_capture::AngrStateSeed;
use crate::query::ollvm::OllvmReport;
use crate::utils::parse_hex_addr;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrOllvmScript {
    pub file_name: String,
    pub script: String,
    pub schema_version: String,
    #[serde(default)]
    pub frida_seed: Option<AngrOllvmFridaSeedProvenance>,
    #[serde(default)]
    pub frida_seeds: Vec<AngrOllvmFridaSeedProvenance>,
    #[serde(default)]
    pub expected_binary_identity: Option<ElfBinaryIdentity>,
    pub flow_config: AngrOllvmFlowConfig,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrOllvmFlowConfig {
    pub enabled: bool,
    pub max_depth: u32,
    pub max_states_per_probe: u32,
}

impl Default for AngrOllvmFlowConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: 8,
            max_states_per_probe: 32,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrOllvmFridaSeedProvenance {
    pub source_event_index: u64,
    pub hook_id: String,
    #[serde(default)]
    pub call_id: Option<String>,
    pub module_name: String,
    pub function_name: String,
    pub capture_offset: String,
    pub registers_seeded: Vec<String>,
    pub memory_region_count: u64,
    pub matched_probe_offsets: Vec<String>,
    #[serde(default)]
    pub matched_branch_offsets: Vec<String>,
    #[serde(default)]
    pub matched_dispatcher_offsets: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrSuccessor {
    pub address: String,
    #[serde(default)]
    pub offset: Option<String>,
    #[serde(default)]
    pub jumpkind: Option<String>,
    #[serde(default)]
    pub satisfiable: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrBlockResult {
    pub offset: String,
    pub cfg_node_found: bool,
    #[serde(default)]
    pub function_name: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub static_successors: Vec<AngrSuccessor>,
    #[serde(default)]
    pub observed_successors: Vec<String>,
    #[serde(default)]
    pub unobserved_static_successors: Vec<String>,
    #[serde(default)]
    pub dynamic_only_successors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrBranchProbe {
    pub offset: String,
    pub status: String,
    #[serde(default)]
    pub seed_kind: Option<String>,
    #[serde(default)]
    pub source_seq: Option<u32>,
    #[serde(default)]
    pub source_event_index: Option<u64>,
    #[serde(default)]
    pub source_offset: Option<String>,
    #[serde(default)]
    pub seeded_registers: Vec<String>,
    #[serde(default)]
    pub seeded_memory_regions: Vec<String>,
    #[serde(default)]
    pub observed_successors: Vec<String>,
    #[serde(default)]
    pub successors: Vec<AngrSuccessor>,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub flow_exploration: Option<AngrFlowExploration>,
    pub limitation: String,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrFlowPath {
    pub status: String,
    #[serde(default)]
    pub offsets: Vec<String>,
    #[serde(default)]
    pub jump_kinds: Vec<String>,
    pub terminal_address: String,
    #[serde(default)]
    pub terminal_offset: Option<String>,
    #[serde(default)]
    pub matched_dispatcher_offset: Option<String>,
    #[serde(default)]
    pub dispatcher_state_values: Vec<AngrRegisterValue>,
    pub constraint_count: u64,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrRegisterValue {
    pub register: String,
    pub status: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub alternatives: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrFlowExploration {
    pub max_depth: u32,
    pub max_states: u32,
    pub explored_states: u32,
    pub truncated: bool,
    #[serde(default)]
    pub paths: Vec<AngrFlowPath>,
    pub limitation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrDispatcherProbe {
    pub offset: String,
    pub status: String,
    pub seed_kind: String,
    pub source_event_index: u64,
    pub source_offset: String,
    #[serde(default)]
    pub seeded_registers: Vec<String>,
    #[serde(default)]
    pub seeded_memory_regions: Vec<String>,
    #[serde(default)]
    pub state_registers: Vec<String>,
    #[serde(default)]
    pub source_state_values: Vec<AngrRegisterValue>,
    #[serde(default)]
    pub flow_exploration: Option<AngrFlowExploration>,
    pub limitation: String,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrOllvmResultBundle {
    pub schema: String,
    pub module_name: String,
    pub binary_sha256: String,
    #[serde(default)]
    pub expected_binary_sha256: Option<String>,
    #[serde(default)]
    pub binary_identity_matched: Option<bool>,
    pub mapped_base: String,
    pub architecture: String,
    pub angr_version: String,
    pub cfg_kind: String,
    #[serde(default)]
    pub frida_seed: Option<AngrOllvmFridaSeedProvenance>,
    #[serde(default)]
    pub frida_seeds: Vec<AngrOllvmFridaSeedProvenance>,
    #[serde(default)]
    pub flow_config: Option<AngrOllvmFlowConfig>,
    #[serde(default)]
    pub blocks: Vec<AngrBlockResult>,
    #[serde(default)]
    pub branch_probes: Vec<AngrBranchProbe>,
    #[serde(default)]
    pub dispatcher_probes: Vec<AngrDispatcherProbe>,
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
        "dynamic-cfg".to_string()
    } else {
        output.to_string()
    }
}

pub fn generate_angr_ollvm_script(
    report: &OllvmReport,
    probe_opaque_branches: bool,
    use_cfg_emulated: bool,
) -> Result<AngrOllvmScript, String> {
    generate_angr_ollvm_script_with_seed(report, probe_opaque_branches, use_cfg_emulated, None)
}

fn validate_flow_config(config: &AngrOllvmFlowConfig) -> Result<(), String> {
    if !(1..=64).contains(&config.max_depth) {
        return Err("angr seeded-flow max depth must be between 1 and 64".to_string());
    }
    if !(1..=256).contains(&config.max_states_per_probe) {
        return Err("angr seeded-flow max states per probe must be between 1 and 256".to_string());
    }
    Ok(())
}

fn allowed_seed_register(name: &str) -> bool {
    if name == "sp" || name == "nzcv" {
        return true;
    }
    name.strip_prefix('x')
        .and_then(|value| value.parse::<u8>().ok())
        .is_some_and(|index| index <= 30)
}

pub(crate) fn prepare_frida_seed(
    report: &OllvmReport,
    seed: &AngrStateSeed,
) -> Result<(serde_json::Value, AngrOllvmFridaSeedProvenance), String> {
    prepare_frida_seed_with_allowed_offsets(report, seed, &BTreeSet::new())
}

pub(crate) fn prepare_frida_seed_with_allowed_offsets(
    report: &OllvmReport,
    seed: &AngrStateSeed,
    allowed_exact_offsets: &BTreeSet<String>,
) -> Result<(serde_json::Value, AngrOllvmFridaSeedProvenance), String> {
    if seed.schema_version != "trace-ui/angr-state-seed-v1" {
        return Err(format!(
            "unsupported Frida angr seed schema: {}",
            seed.schema_version
        ));
    }
    let module_name = seed
        .module_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Frida seed moduleName is required for OLLVM matching".to_string())?;
    if module_name != report.scope.module_name.trim() {
        return Err(format!(
            "Frida seed module {} does not match OLLVM report module {}",
            module_name, report.scope.module_name
        ));
    }
    let capture_offset = seed
        .capture_offset
        .as_deref()
        .ok_or_else(|| {
            "Frida seed lacks a module-relative captureOffset; regenerate the hook with module metadata"
                .to_string()
        })?
        .to_lowercase();
    parse_hex_addr(&capture_offset)?;
    let mut matched_branch_offsets = report
        .opaque_branch_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .branch_offset
                .eq_ignore_ascii_case(&capture_offset)
                || candidate
                    .condition_source_offsets
                    .iter()
                    .any(|offset| offset.eq_ignore_ascii_case(&capture_offset))
        })
        .map(|candidate| candidate.branch_offset.to_lowercase())
        .collect::<Vec<_>>();
    matched_branch_offsets.sort_by_key(|value| parse_hex_addr(value).unwrap_or(u64::MAX));
    matched_branch_offsets.dedup();
    let mut matched_dispatcher_offsets = report
        .dispatcher_candidates
        .iter()
        .filter(|candidate| candidate.start_offset.eq_ignore_ascii_case(&capture_offset))
        .map(|candidate| candidate.start_offset.to_lowercase())
        .collect::<Vec<_>>();
    matched_dispatcher_offsets.sort_by_key(|value| parse_hex_addr(value).unwrap_or(u64::MAX));
    matched_dispatcher_offsets.dedup();
    let matched_allowed_offset = allowed_exact_offsets
        .iter()
        .find(|offset| offset.eq_ignore_ascii_case(&capture_offset))
        .cloned();
    if seed.source_event != "hook-enter"
        && !(seed.source_event == "ollvm-dispatcher-hit" && !matched_dispatcher_offsets.is_empty())
    {
        return Err(
            "OLLVM Frida seeds must come from hook-enter or an exact ollvm-dispatcher-hit event"
                .to_string(),
        );
    }
    let mut matched_probe_offsets = matched_branch_offsets
        .iter()
        .chain(&matched_dispatcher_offsets)
        .cloned()
        .collect::<Vec<_>>();
    if let Some(offset) = matched_allowed_offset {
        matched_probe_offsets.push(offset);
    }
    matched_probe_offsets.sort_by_key(|value| parse_hex_addr(value).unwrap_or(u64::MAX));
    matched_probe_offsets.dedup();
    if matched_probe_offsets.is_empty() {
        return Err(format!(
            "Frida capture offset {} does not exactly match an opaque branch, its condition-source offset, a dispatcher entry, or an authorized Unicorn checkpoint",
            capture_offset
        ));
    }
    // X0-X30 plus SP and NZCV are all valid in one complete ARM64 capture.
    if seed.registers.len() > 33 {
        return Err("Frida seed contains more than 33 registers".to_string());
    }
    for register in &seed.registers {
        if !allowed_seed_register(&register.name) {
            return Err(format!(
                "unsupported Frida seed register: {}",
                register.name
            ));
        }
        parse_hex_addr(&register.value)?;
    }
    if seed.memory_regions.len() > 256 {
        return Err("Frida seed contains more than 256 memory regions".to_string());
    }
    let mut total_memory = 0u64;
    for region in &seed.memory_regions {
        parse_hex_addr(&region.address)?;
        if region.bytes_hex.len() % 2 != 0
            || !region
                .bytes_hex
                .chars()
                .all(|character| character.is_ascii_hexdigit())
            || region.bytes_hex.len() as u64 != region.byte_length.saturating_mul(2)
        {
            return Err(format!(
                "invalid Frida seed memory region: {}",
                region.label
            ));
        }
        total_memory = total_memory.saturating_add(region.byte_length);
    }
    if total_memory > 1_048_576 {
        return Err("Frida seed memory exceeds the 1 MiB merge limit".to_string());
    }
    if let Some(base) = &seed.module_base {
        parse_hex_addr(base)?;
    }
    let provenance = AngrOllvmFridaSeedProvenance {
        source_event_index: seed.source_event_index,
        hook_id: seed.hook_id.clone(),
        call_id: seed.call_id.clone(),
        module_name: module_name.to_string(),
        function_name: seed.function_name.clone(),
        capture_offset: capture_offset.clone(),
        registers_seeded: seed.registers_seeded.clone(),
        memory_region_count: seed.memory_regions.len() as u64,
        matched_probe_offsets,
        matched_branch_offsets,
        matched_dispatcher_offsets,
    };
    let payload = serde_json::json!({
        "sourceEventIndex": seed.source_event_index,
        "hookId": seed.hook_id,
        "callId": seed.call_id,
        "moduleName": module_name,
        "moduleBase": seed.module_base,
        "moduleSize": seed.module_size,
        "functionName": seed.function_name,
        "captureOffset": capture_offset,
        "registers": seed.registers,
        "memoryRegions": seed.memory_regions,
        "provenance": provenance,
    });
    Ok((payload, provenance))
}

pub fn generate_angr_ollvm_script_with_seed(
    report: &OllvmReport,
    probe_opaque_branches: bool,
    use_cfg_emulated: bool,
    frida_seed: Option<&AngrStateSeed>,
) -> Result<AngrOllvmScript, String> {
    generate_angr_ollvm_script_with_seed_and_flow(
        report,
        probe_opaque_branches,
        use_cfg_emulated,
        frida_seed,
        AngrOllvmFlowConfig::default(),
    )
}

pub fn generate_angr_ollvm_script_with_seed_and_flow(
    report: &OllvmReport,
    probe_opaque_branches: bool,
    use_cfg_emulated: bool,
    frida_seed: Option<&AngrStateSeed>,
    flow_config: AngrOllvmFlowConfig,
) -> Result<AngrOllvmScript, String> {
    generate_angr_ollvm_script_with_seeds_flow_and_identity(
        report,
        probe_opaque_branches,
        use_cfg_emulated,
        frida_seed.into_iter().collect::<Vec<_>>(),
        flow_config,
        None,
    )
}

/// Generate the manual angr bridge with optional exact ELF identity metadata.
///
/// The identity is embedded in the generated Python script and checked before
/// any CFG/probe work. This protects against accidentally running a trace seed
/// against a different build that happens to share the same module basename and
/// offsets. The check is still about the user-selected file; it cannot attest
/// which image was mapped in the original runtime trace.
pub fn generate_angr_ollvm_script_with_seeds_flow_and_identity(
    report: &OllvmReport,
    probe_opaque_branches: bool,
    use_cfg_emulated: bool,
    frida_seeds: Vec<&AngrStateSeed>,
    mut flow_config: AngrOllvmFlowConfig,
    expected_binary_identity: Option<&ElfBinaryIdentity>,
) -> Result<AngrOllvmScript, String> {
    if report.scope.module_name.trim().is_empty() {
        return Err("OLLVM report module name must not be empty".to_string());
    }
    validate_flow_config(&flow_config)?;
    if frida_seeds.len() > 32 {
        return Err("at most 32 Frida seeds may be embedded in one angr bridge".to_string());
    }
    let mut frida_seed_payloads = Vec::with_capacity(frida_seeds.len());
    let mut frida_seed_provenances = Vec::with_capacity(frida_seeds.len());
    let mut source_event_indices = std::collections::HashSet::new();
    for seed in frida_seeds {
        if !source_event_indices.insert(seed.source_event_index) {
            return Err(format!(
                "duplicate Frida seed source event index {}",
                seed.source_event_index
            ));
        }
        let (payload, provenance) = prepare_frida_seed(report, seed)?;
        frida_seed_payloads.push(payload);
        frida_seed_provenances.push(provenance);
    }
    let frida_seed_json = serde_json::Value::Array(frida_seed_payloads);
    let frida_seed_provenance = frida_seed_provenances.first().cloned();
    let has_dispatcher_seed = frida_seed_provenances
        .iter()
        .any(|provenance| !provenance.matched_dispatcher_offsets.is_empty());
    let has_branch_seed = frida_seed_provenances
        .iter()
        .any(|provenance| !provenance.matched_branch_offsets.is_empty());
    if has_branch_seed && !probe_opaque_branches && !has_dispatcher_seed {
        return Err(
            "Frida branch/condition-source seed merging requires opaque branch probes".to_string(),
        );
    }
    if !probe_opaque_branches && !has_dispatcher_seed {
        flow_config.enabled = false;
    }
    let frida_seed_json = serde_json::to_string(&frida_seed_json)
        .map_err(|error| format!("serialize Frida seed failed: {error}"))?;
    let frida_seed_literal = serde_json::to_string(&frida_seed_json)
        .map_err(|error| format!("quote Frida seed failed: {error}"))?;
    let report_json = serde_json::to_string(report)
        .map_err(|error| format!("serialize OLLVM report failed: {error}"))?;
    let report_literal = serde_json::to_string(&report_json)
        .map_err(|error| format!("quote OLLVM report failed: {error}"))?;
    let expected_binary_json = expected_binary_identity
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| format!("serialize expected ELF identity failed: {error}"))?
        .unwrap_or_else(|| "null".to_string());
    let expected_binary_literal = serde_json::to_string(&expected_binary_json)
        .map_err(|error| format!("quote expected ELF identity failed: {error}"))?;
    let function_name = report
        .scope
        .function_name
        .as_deref()
        .unwrap_or(&report.scope.module_name);
    let file_name = format!("{}-trace-ui-angr.py", sanitize_name(function_name));
    let template = r##"#!/usr/bin/env python3
# Trace UI trace-guided angr / OLLVM bridge
# Schema: trace-ui/angr-ollvm-v1
# Run manually in a Python environment with angr installed.
import argparse
import hashlib
import json
import os
import sys

try:
    import angr
except ImportError:
    sys.stderr.write("angr is not installed. Install it in an isolated Python environment and rerun this script.\n")
    raise


SCHEMA = "trace-ui/angr-ollvm-v1"
REPORT = json.loads(__REPORT_JSON__)
DEFAULT_PROBE_OPAQUE_BRANCHES = __PROBE_OPAQUE__
DEFAULT_CFG_EMULATED = __CFG_EMULATED__
DEFAULT_EXPLORE_SEEDED_FLOWS = __EXPLORE_FLOWS__
DEFAULT_FLOW_MAX_DEPTH = __FLOW_MAX_DEPTH__
DEFAULT_FLOW_MAX_STATES = __FLOW_MAX_STATES__
FRIDA_SEEDS = json.loads(__FRIDA_SEEDS_JSON__)
EXPECTED_BINARY_IDENTITY = json.loads(__EXPECTED_BINARY_IDENTITY__)


def configure_state(state):
    """Customize registers, memory, argv, or symbolic inputs before branch probes.

    The default state is intentionally unconstrained. Results from it are candidates,
    not proof that a successor is reachable from the real function entry.
    """
    return state


def _offset(value):
    return int(value, 16)


def _mapped_offset(project, address):
    main = project.loader.main_object
    if main.min_addr <= address <= main.max_addr:
        return hex(address - main.mapped_base)
    return None


def _set_nzcv(state, value):
    """Seed packed AArch64 NZCV, with a conservative per-flag fallback."""
    try:
        state.regs.nzcv = value
        return True
    except Exception:
        pass
    wrote = False
    for name, bit in (("n", 31), ("z", 30), ("c", 29), ("v", 28)):
        try:
            setattr(state.regs, name, (value >> bit) & 1)
            wrote = True
        except Exception:
            pass
    return wrote


def _successor(project, address, jumpkind=None, satisfiable=None):
    return {
        "address": hex(address),
        "offset": _mapped_offset(project, address),
        "jumpkind": jumpkind,
        "satisfiable": satisfiable,
    }


def _observed_successors():
    result = {}
    for edge in REPORT.get("edges", []):
        result.setdefault(edge["sourceOffset"].lower(), set()).add(edge["targetOffset"].lower())
    return result


def _build_cfg(project, prefer_emulated):
    warnings = []
    if prefer_emulated:
        blocks = REPORT.get("blocks", [])
        starts = [project.loader.main_object.mapped_base + _offset(blocks[0]["startOffset"])] if blocks else None
        try:
            cfg = project.analyses.CFGEmulated(
                starts=starts,
                normalize=True,
                keep_state=False,
                context_sensitivity_level=2,
            )
            return cfg, "CFGEmulated", warnings
        except Exception as error:
            warnings.append("CFGEmulated failed; fell back to CFGFast: {}".format(error))
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    return cfg, "CFGFast", warnings


def _reconcile_blocks(project, cfg):
    base = project.loader.main_object.mapped_base
    observed = _observed_successors()
    results = []
    for block in REPORT.get("blocks", []):
        offset = block["startOffset"].lower()
        address = base + _offset(offset)
        node = cfg.model.get_any_node(address, anyaddr=True)
        static_successors = []
        function_name = None
        size = None
        if node is not None:
            function_name = getattr(node, "name", None)
            size = getattr(node, "size", None)
            for successor in cfg.graph.successors(node):
                edge = cfg.graph.get_edge_data(node, successor) or {}
                static_successors.append(_successor(
                    project,
                    successor.addr,
                    edge.get("jumpkind"),
                    None,
                ))
        static_offsets = {
            item["offset"].lower() for item in static_successors if item.get("offset") is not None
        }
        observed_offsets = observed.get(offset, set())
        results.append({
            "offset": offset,
            "cfgNodeFound": node is not None,
            "functionName": function_name,
            "size": size,
            "staticSuccessors": static_successors,
            "observedSuccessors": sorted(observed_offsets, key=lambda value: int(value, 16)),
            "unobservedStaticSuccessors": sorted(static_offsets - observed_offsets, key=lambda value: int(value, 16)),
            "dynamicOnlySuccessors": sorted(observed_offsets - static_offsets, key=lambda value: int(value, 16)),
        })
    return results


def _apply_trace_snapshot(state, snapshot):
    seeded = []
    errors = []
    if snapshot is None:
        return seeded, errors
    for name, text in snapshot.get("registers", {}).items():
        register_name = name.lower()
        try:
            parsed = int(text, 16)
            if register_name == "nzcv":
                if not _set_nzcv(state, parsed):
                    raise RuntimeError("angr architecture exposes no NZCV flags")
            else:
                setattr(state.regs, register_name, parsed)
            seeded.append(name.upper())
        except Exception as error:
            errors.append("{}={}: {}".format(name, text, error))
    return seeded, errors


def _frida_rebase(project, value, seed):
    if seed is None:
        return value
    base_text = seed.get("moduleBase")
    size = int(seed.get("moduleSize") or 0)
    if base_text and size > 0:
        base = int(base_text, 16)
        if base <= value < base + size:
            return project.loader.main_object.mapped_base + (value - base)
    return value


def _apply_frida_seed(state, seed):
    seeded_registers = []
    seeded_memory = []
    errors = []
    if seed is None:
        return seeded_registers, seeded_memory, errors
    for register in seed.get("registers", []):
        name = register["name"].lower()
        try:
            parsed = int(register["value"], 16)
            if name == "nzcv":
                if not _set_nzcv(state, parsed):
                    raise RuntimeError("angr architecture exposes no NZCV flags")
            else:
                setattr(state.regs, name, _frida_rebase(state.project, parsed, seed))
            seeded_registers.append(name.upper())
        except Exception as error:
            errors.append("{}={}: {}".format(name, register.get("value"), error))
    for region in seed.get("memoryRegions", []):
        try:
            address = _frida_rebase(state.project, int(region["address"], 16), seed)
            state.memory.store(address, bytes.fromhex(region["bytesHex"]))
            seeded_memory.append(region.get("label") or region["address"])
        except Exception as error:
            errors.append("memory {}: {}".format(region.get("label") or region.get("address"), error))
    return seeded_registers, seeded_memory, errors


def _register_values(state, names):
    values = []
    for original_name in names[:16]:
        name = original_name.lower()
        try:
            expression = getattr(state.regs, name)
            alternatives = state.solver.eval_upto(expression, 2)
            if len(alternatives) == 1:
                values.append({
                    "register": original_name.upper(),
                    "status": "concrete",
                    "value": hex(int(alternatives[0])),
                    "alternatives": [],
                })
            else:
                values.append({
                    "register": original_name.upper(),
                    "status": "symbolic",
                    "value": None,
                    "alternatives": [hex(int(value)) for value in alternatives[:2]],
                })
        except Exception:
            values.append({
                "register": original_name.upper(),
                "status": "unavailable",
                "value": None,
                "alternatives": [],
            })
    return values


def _flow_path(project, status, state, offsets, jump_kinds, error=None, matched_dispatcher_offset=None, dispatcher_state_values=None):
    return {
        "status": status,
        "offsets": offsets,
        "jumpKinds": jump_kinds,
        "terminalAddress": hex(state.addr),
        "terminalOffset": _mapped_offset(project, state.addr),
        "matchedDispatcherOffset": matched_dispatcher_offset,
        "dispatcherStateValues": dispatcher_state_values or [],
        "constraintCount": len(state.solver.constraints),
        "constraints": [str(item)[:500] for item in state.solver.constraints[-4:]],
        "error": error,
    }


def _dispatcher_candidates():
    return {
        candidate["startOffset"].lower(): candidate
        for candidate in REPORT.get("dispatcherCandidates", [])
    }


def _explore_dispatcher_flow(project, source_offset, initial_state, max_depth, max_states):
    limitation = (
        "Bounded symbolic continuation starts at an exact dispatcher-entry Frida capture and stops at the next observed dispatcher entry, loop, external target, dead end, or configured bound. "
        "It does not prove function-entry reachability, complete state-machine recovery, or OLLVM removal."
    )
    dispatchers = _dispatcher_candidates()
    queue = [(initial_state, 0, [source_offset], [])]
    paths = []
    truncated = False
    explored = 0
    while queue and explored < max_states:
        state, depth, offsets, jump_kinds = queue.pop(0)
        explored += 1
        current_offset = _mapped_offset(project, state.addr)
        if current_offset is None:
            paths.append(_flow_path(project, "external-target", state, offsets, jump_kinds))
            continue
        current_offset = current_offset.lower()
        if depth > 0 and current_offset in dispatchers:
            candidate = dispatchers[current_offset]
            paths.append(_flow_path(
                project,
                "dispatcher-hit",
                state,
                offsets,
                jump_kinds,
                matched_dispatcher_offset=current_offset,
                dispatcher_state_values=_register_values(state, candidate.get("stateRegisters", [])),
            ))
            continue
        if current_offset in offsets[:-1]:
            paths.append(_flow_path(project, "loop-detected", state, offsets, jump_kinds))
            continue
        if depth >= max_depth:
            truncated = True
            paths.append(_flow_path(project, "depth-limit", state, offsets, jump_kinds))
            continue
        try:
            successors = project.factory.successors(state, opt_level=0)
        except Exception as error:
            paths.append(_flow_path(project, "step-error", state, offsets, jump_kinds, str(error)))
            continue
        flat = []
        for successor in successors.flat_successors:
            try:
                if successor.solver.satisfiable():
                    flat.append(successor)
            except Exception:
                continue
        if not flat:
            status = "unconstrained" if successors.unconstrained_successors else "dead-end"
            paths.append(_flow_path(project, status, state, offsets, jump_kinds))
            continue
        for successor in flat:
            if explored + len(queue) >= max_states:
                truncated = True
                next_offsets = list(offsets)
                next_offset = _mapped_offset(project, successor.addr)
                if next_offset is not None:
                    next_offsets.append(next_offset.lower())
                paths.append(_flow_path(
                    project,
                    "state-limit",
                    successor,
                    next_offsets,
                    jump_kinds + [successor.history.jumpkind or "unknown"],
                ))
                break
            next_offsets = list(offsets)
            next_offset = _mapped_offset(project, successor.addr)
            if next_offset is not None:
                next_offsets.append(next_offset.lower())
            queue.append((
                successor,
                depth + 1,
                next_offsets,
                jump_kinds + [successor.history.jumpkind or "unknown"],
            ))
    if queue:
        truncated = True
        state, _, offsets, jump_kinds = queue[0]
        paths.append(_flow_path(project, "state-limit", state, offsets, jump_kinds))
    return {
        "maxDepth": max_depth,
        "maxStates": max_states,
        "exploredStates": explored,
        "truncated": truncated,
        "paths": paths,
        "limitation": limitation,
    }


def _explore_seeded_flow(project, branch_offset, initial_states, max_depth, max_states):
    limitation = (
        "Bounded symbolic continuation starts after the candidate branch from a partial trace/Frida seed. "
        "It does not prove function-entry reachability, path completeness, or OLLVM removal."
    )
    queue = []
    paths = []
    truncated = False
    for state in initial_states:
        try:
            if not state.solver.satisfiable():
                continue
        except Exception:
            continue
        offset = _mapped_offset(project, state.addr)
        offsets = [branch_offset]
        if offset is not None:
            offsets.append(offset.lower())
        queue.append((state, 1, offsets, [state.history.jumpkind or "unknown"]))
        if len(queue) >= max_states:
            truncated = len(initial_states) > len(queue)
            break
    explored = 0
    while queue and explored < max_states:
        state, depth, offsets, jump_kinds = queue.pop(0)
        explored += 1
        current_offset = _mapped_offset(project, state.addr)
        if current_offset is None:
            paths.append(_flow_path(project, "external-target", state, offsets, jump_kinds))
            continue
        current_offset = current_offset.lower()
        if current_offset in offsets[:-1]:
            paths.append(_flow_path(project, "loop-detected", state, offsets, jump_kinds))
            continue
        if depth >= max_depth:
            truncated = True
            paths.append(_flow_path(project, "depth-limit", state, offsets, jump_kinds))
            continue
        try:
            successors = project.factory.successors(state, opt_level=0)
        except Exception as error:
            paths.append(_flow_path(project, "step-error", state, offsets, jump_kinds, str(error)))
            continue
        flat = []
        for successor in successors.flat_successors:
            try:
                if successor.solver.satisfiable():
                    flat.append(successor)
            except Exception:
                continue
        if not flat:
            status = "unconstrained" if successors.unconstrained_successors else "dead-end"
            paths.append(_flow_path(project, status, state, offsets, jump_kinds))
            continue
        for successor in flat:
            if explored + len(queue) >= max_states:
                truncated = True
                break
            next_offset = _mapped_offset(project, successor.addr)
            next_offsets = list(offsets)
            if next_offset is not None:
                next_offsets.append(next_offset.lower())
            queue.append((
                successor,
                depth + 1,
                next_offsets,
                jump_kinds + [successor.history.jumpkind or "unknown"],
            ))
    if queue:
        truncated = True
        state, _, offsets, jump_kinds = queue[0]
        paths.append(_flow_path(project, "state-limit", state, offsets, jump_kinds))
    return {
        "maxDepth": max_depth,
        "maxStates": max_states,
        "exploredStates": explored,
        "truncated": truncated,
        "paths": paths,
        "limitation": limitation,
    }


def _probe_branch(project, candidate, snapshot=None, explore_flow=False, flow_max_depth=8, flow_max_states=32):
    offset = candidate["branchOffset"].lower()
    observed = [value.lower() for value in candidate.get("observedSuccessors", [])]
    seed_kind = "trace-register-snapshot" if snapshot is not None else "blank-unconstrained"
    limitation = (
        "A trace-register snapshot reproduces selected observed registers but not uncaptured memory, SIMD state, "
        "or the full entry path; it remains candidate evidence."
        if snapshot is not None else
        "The probe begins at the branch with unconstrained state and does not prove reachability from the real function entry."
    )
    try:
        address = project.loader.main_object.mapped_base + _offset(offset)
        state = configure_state(project.factory.blank_state(addr=address))
        seeded_registers, seed_errors = _apply_trace_snapshot(state, snapshot)
        state.options.add(angr.options.LAZY_SOLVES)
        successors = project.factory.successors(state, num_inst=1, opt_level=0)
        records = []
        satisfiable_count = 0
        for successor in successors.flat_successors:
            satisfiable = bool(successor.solver.satisfiable())
            if satisfiable:
                satisfiable_count += 1
            records.append(_successor(project, successor.addr, successor.history.jumpkind, satisfiable))
        for successor in successors.unsat_successors:
            records.append(_successor(project, successor.addr, successor.history.jumpkind, False))
        status_context = "with_trace_register_snapshot" if snapshot is not None else "without_trace_context"
        if satisfiable_count >= 2:
            status = "multiple_satisfiable_successors_{}".format(status_context)
        elif satisfiable_count == 1:
            status = "single_satisfiable_successor_{}".format(status_context)
        else:
            status = "no_satisfiable_successor_{}".format(status_context)
        constraints = [str(item)[:500] for item in state.solver.constraints[-4:]]
        flow = None
        if explore_flow and snapshot is not None:
            flow = _explore_seeded_flow(
                project,
                offset,
                list(successors.flat_successors),
                flow_max_depth,
                flow_max_states,
            )
        return {
            "offset": offset,
            "status": status,
            "seedKind": seed_kind,
            "sourceSeq": snapshot.get("seq") if snapshot is not None else None,
            "sourceEventIndex": None,
            "sourceOffset": offset,
            "seededRegisters": seeded_registers,
            "seededMemoryRegions": [],
            "observedSuccessors": observed,
            "successors": records,
            "constraints": constraints + ["seed-warning: " + item for item in seed_errors],
            "flowExploration": flow,
            "limitation": limitation,
            "error": None,
        }
    except Exception as error:
        return {
            "offset": offset,
            "status": "probe_error",
            "seedKind": seed_kind,
            "sourceSeq": snapshot.get("seq") if snapshot is not None else None,
            "sourceEventIndex": None,
            "sourceOffset": offset,
            "seededRegisters": [],
            "seededMemoryRegions": [],
            "observedSuccessors": observed,
            "successors": [],
            "constraints": [],
            "flowExploration": None,
            "limitation": limitation,
            "error": str(error),
        }


def _probe_branch_with_frida(project, candidate, seed, explore_flow=False, flow_max_depth=8, flow_max_states=32):
    branch_offset = candidate["branchOffset"].lower()
    source_offset = seed["captureOffset"].lower()
    condition_sources = [value.lower() for value in candidate.get("conditionSourceOffsets", [])]
    if source_offset == branch_offset:
        instruction_count = 1
        seed_kind = "frida-capture-exact-branch"
    elif source_offset in condition_sources:
        distance = _offset(branch_offset) - _offset(source_offset)
        if distance < 0 or distance % 4 != 0 or distance // 4 + 1 > 64:
            return {
                "offset": branch_offset,
                "status": "probe_error",
                "seedKind": "frida-capture-condition-source",
                "sourceSeq": None,
                "sourceEventIndex": seed.get("sourceEventIndex"),
                "sourceOffset": source_offset,
                "seededRegisters": [],
                "seededMemoryRegions": [],
                "observedSuccessors": [value.lower() for value in candidate.get("observedSuccessors", [])],
                "successors": [],
                "constraints": [],
                "flowExploration": None,
                "limitation": "The exact condition-source offset could not be bounded to the candidate branch.",
                "error": "condition-source to branch distance is invalid or exceeds 64 ARM64 instructions",
            }
        instruction_count = distance // 4 + 1
        seed_kind = "frida-capture-exact-condition-source"
    else:
        return None
    limitation = (
        "The Frida capture offset exactly matches this branch or its recorded condition source, but the snapshot may still omit flags, SIMD state, unread memory, and real-entry path constraints; it remains candidate evidence."
    )
    try:
        source_address = project.loader.main_object.mapped_base + _offset(source_offset)
        state = configure_state(project.factory.blank_state(addr=source_address))
        seeded_registers, seeded_memory, seed_errors = _apply_frida_seed(state, seed)
        state.options.add(angr.options.LAZY_SOLVES)
        successors = project.factory.successors(
            state,
            num_inst=instruction_count,
            opt_level=0,
        )
        records = []
        satisfiable_count = 0
        for successor in successors.flat_successors:
            satisfiable = bool(successor.solver.satisfiable())
            if satisfiable:
                satisfiable_count += 1
            records.append(_successor(project, successor.addr, successor.history.jumpkind, satisfiable))
        for successor in successors.unsat_successors:
            records.append(_successor(project, successor.addr, successor.history.jumpkind, False))
        if satisfiable_count >= 2:
            status = "multiple_satisfiable_successors_with_frida_capture"
        elif satisfiable_count == 1:
            status = "single_satisfiable_successor_with_frida_capture"
        else:
            status = "no_satisfiable_successor_with_frida_capture"
        flow = None
        if explore_flow:
            flow = _explore_seeded_flow(
                project,
                branch_offset,
                list(successors.flat_successors),
                flow_max_depth,
                flow_max_states,
            )
        return {
            "offset": branch_offset,
            "status": status,
            "seedKind": seed_kind,
            "sourceSeq": None,
            "sourceEventIndex": seed.get("sourceEventIndex"),
            "sourceOffset": source_offset,
            "seededRegisters": seeded_registers,
            "seededMemoryRegions": seeded_memory,
            "observedSuccessors": [value.lower() for value in candidate.get("observedSuccessors", [])],
            "successors": records,
            "constraints": ["seed-warning: " + item for item in seed_errors],
            "flowExploration": flow,
            "limitation": limitation,
            "error": None,
        }
    except Exception as error:
        return {
            "offset": branch_offset,
            "status": "probe_error",
            "seedKind": seed_kind,
            "sourceSeq": None,
            "sourceEventIndex": seed.get("sourceEventIndex"),
            "sourceOffset": source_offset,
            "seededRegisters": [],
            "seededMemoryRegions": [],
            "observedSuccessors": [value.lower() for value in candidate.get("observedSuccessors", [])],
            "successors": [],
            "constraints": [],
            "flowExploration": None,
            "limitation": limitation,
            "error": str(error),
        }


def _probe_dispatcher_with_frida(project, candidate, seed, explore_flow=False, flow_max_depth=8, flow_max_states=32):
    dispatcher_offset = candidate["startOffset"].lower()
    source_offset = seed["captureOffset"].lower()
    if source_offset != dispatcher_offset:
        return None
    limitation = (
        "The Frida capture exactly matches this dispatcher entry and seeds captured GPR/memory state. "
        "The bounded continuation can identify candidate next-dispatcher states, but missing SIMD, flags, unread memory, and entry-path constraints still prevent Verified control-flow recovery."
    )
    try:
        address = project.loader.main_object.mapped_base + _offset(dispatcher_offset)
        state = configure_state(project.factory.blank_state(addr=address))
        seeded_registers, seeded_memory, seed_errors = _apply_frida_seed(state, seed)
        state.options.add(angr.options.LAZY_SOLVES)
        source_state_values = _register_values(state, candidate.get("stateRegisters", []))
        flow = None
        if explore_flow:
            flow = _explore_dispatcher_flow(
                project,
                dispatcher_offset,
                state,
                flow_max_depth,
                flow_max_states,
            )
        status = "dispatcher_flow_explored" if flow is not None else "dispatcher_seed_applied"
        if seed_errors:
            status += "_with_seed_warnings"
        return {
            "offset": dispatcher_offset,
            "status": status,
            "seedKind": "frida-capture-exact-dispatcher",
            "sourceEventIndex": seed.get("sourceEventIndex"),
            "sourceOffset": source_offset,
            "seededRegisters": seeded_registers,
            "seededMemoryRegions": seeded_memory,
            "stateRegisters": [value.upper() for value in candidate.get("stateRegisters", [])],
            "sourceStateValues": source_state_values,
            "flowExploration": flow,
            "limitation": limitation,
            "error": "; ".join(seed_errors) if seed_errors else None,
        }
    except Exception as error:
        return {
            "offset": dispatcher_offset,
            "status": "probe_error",
            "seedKind": "frida-capture-exact-dispatcher",
            "sourceEventIndex": seed.get("sourceEventIndex"),
            "sourceOffset": source_offset,
            "seededRegisters": [],
            "seededMemoryRegions": [],
            "stateRegisters": [value.upper() for value in candidate.get("stateRegisters", [])],
            "sourceStateValues": [],
            "flowExploration": None,
            "limitation": limitation,
            "error": str(error),
        }


def analyze(binary_path, prefer_emulated, probe_opaque, explore_flows, flow_max_depth, flow_max_states):
    with open(binary_path, "rb") as source:
        binary_sha256 = hashlib.sha256(source.read()).hexdigest()
    expected_binary_sha256 = None
    binary_identity_matched = None
    if EXPECTED_BINARY_IDENTITY is not None:
        expected_binary_sha256 = EXPECTED_BINARY_IDENTITY["binarySha256"].lower()
        binary_identity_matched = binary_sha256.lower() == expected_binary_sha256
        if not binary_identity_matched:
            raise RuntimeError(
                "exact ELF identity mismatch: expected SHA-256 {}, got {} for {}".format(
                    expected_binary_sha256, binary_sha256, binary_path
                )
            )
    project = angr.Project(binary_path, auto_load_libs=False)
    cfg, cfg_kind, warnings = _build_cfg(project, prefer_emulated)
    architecture = project.arch.name
    if "AARCH64" not in architecture.upper() and "ARM64" not in architecture.upper():
        warnings.append("Trace report is ARM64-oriented but angr loaded architecture {}".format(architecture))
    blocks = _reconcile_blocks(project, cfg)
    probes = []
    if probe_opaque:
        for item in REPORT.get("opaqueBranchCandidates", []):
            probes.append(_probe_branch(project, item))
            for snapshot_index, snapshot in enumerate(item.get("observations", [])):
                if snapshot.get("registers"):
                    probes.append(_probe_branch(
                        project,
                        item,
                        snapshot,
                        explore_flow=explore_flows and snapshot_index == 0,
                        flow_max_depth=flow_max_depth,
                        flow_max_states=flow_max_states,
                    ))
            for frida_seed in FRIDA_SEEDS:
                frida_probe = _probe_branch_with_frida(
                    project,
                    item,
                    frida_seed,
                    explore_flow=explore_flows,
                    flow_max_depth=flow_max_depth,
                    flow_max_states=flow_max_states,
                )
                if frida_probe is not None:
                    probes.append(frida_probe)
    dispatcher_probes = []
    if FRIDA_SEEDS:
        for item in REPORT.get("dispatcherCandidates", []):
            for frida_seed in FRIDA_SEEDS:
                dispatcher_probe = _probe_dispatcher_with_frida(
                    project,
                    item,
                    frida_seed,
                    explore_flow=explore_flows,
                    flow_max_depth=flow_max_depth,
                    flow_max_states=flow_max_states,
                )
                if dispatcher_probe is not None:
                    dispatcher_probes.append(dispatcher_probe)
    warnings.extend([
        "Static CFG successors absent from the dynamic trace may be unexecuted, infeasible, or CFG recovery artifacts.",
        "Dynamic-only edges may indicate indirect control flow or static CFG recovery gaps.",
        "Unconstrained branch probes are hypothesis generators, not proof of real-input reachability.",
        "Trace-seeded probes contain selected register values only; missing memory and architectural state can change feasibility.",
    ])
    if explore_flows and (probe_opaque or dispatcher_probes):
        warnings.append("Bounded seeded-flow paths stop at configured depth/state limits and remain candidate execution-flow evidence.")
    if FRIDA_SEEDS:
        warnings.append("Frida-seeded probes are emitted only for exact module-relative branch, condition-source, or dispatcher-entry offset matches; they remain candidate evidence.")
    if binary_identity_matched:
        warnings.append("The manually supplied ELF matched the SHA-256 embedded when this script was generated. This validates the selected file, not the image mapped during the original trace.")
    return {
        "schema": SCHEMA,
        "moduleName": REPORT["scope"]["moduleName"],
        "binarySha256": binary_sha256,
        "expectedBinarySha256": expected_binary_sha256,
        "binaryIdentityMatched": binary_identity_matched,
        "mappedBase": hex(project.loader.main_object.mapped_base),
        "architecture": architecture,
        "angrVersion": getattr(angr, "__version__", "unknown"),
        "cfgKind": cfg_kind,
        "fridaSeed": FRIDA_SEEDS[0].get("provenance") if FRIDA_SEEDS else None,
        "fridaSeeds": [seed.get("provenance") for seed in FRIDA_SEEDS],
        "flowConfig": {
            "enabled": bool(explore_flows and (probe_opaque or dispatcher_probes)),
            "maxDepth": flow_max_depth,
            "maxStatesPerProbe": flow_max_states,
        },
        "blocks": blocks,
        "branchProbes": probes,
        "dispatcherProbes": dispatcher_probes,
        "warnings": warnings,
    }


def main():
    parser = argparse.ArgumentParser(description="Trace-guided angr reconciliation for Trace UI OLLVM evidence")
    parser.add_argument("binary", help="Exact ELF/shared object used by the trace")
    parser.add_argument("-o", "--output", default="trace-ui-angr-ollvm.json", help="Output JSON path")
    parser.add_argument("--cfg-emulated", action="store_true", default=DEFAULT_CFG_EMULATED, help="Prefer CFGEmulated and fall back to CFGFast")
    parser.add_argument("--cfg-fast", action="store_false", dest="cfg_emulated", help="Force CFGFast")
    parser.add_argument("--probe-opaque", action="store_true", default=DEFAULT_PROBE_OPAQUE_BRANCHES, help="Probe opaque-branch candidates from unconstrained state")
    parser.add_argument("--skip-probes", action="store_false", dest="probe_opaque", help="Skip symbolic branch probes")
    parser.add_argument("--explore-seeded-flows", action="store_true", default=DEFAULT_EXPLORE_SEEDED_FLOWS, help="Continue the first trace seed and exact Frida seed through a bounded symbolic flow")
    parser.add_argument("--skip-seeded-flows", action="store_false", dest="explore_seeded_flows", help="Disable bounded symbolic flow continuation")
    parser.add_argument("--flow-depth", type=int, default=DEFAULT_FLOW_MAX_DEPTH, choices=range(1, 65), metavar="1..64", help="Maximum symbolic flow depth per seeded probe")
    parser.add_argument("--flow-max-states", type=int, default=DEFAULT_FLOW_MAX_STATES, choices=range(1, 257), metavar="1..256", help="Maximum symbolic states per seeded probe")
    args = parser.parse_args()
    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        parser.error("binary does not exist: {}".format(binary_path))
    result = analyze(
        binary_path,
        args.cfg_emulated,
        args.probe_opaque,
        args.explore_seeded_flows,
        args.flow_depth,
        args.flow_max_states,
    )
    output_path = os.path.abspath(args.output)
    with open(output_path, "w", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
    flow_count = sum(1 for probe in result["branchProbes"] if probe.get("flowExploration") is not None)
    flow_count += sum(1 for probe in result["dispatcherProbes"] if probe.get("flowExploration") is not None)
    print("[Trace UI] wrote {} block reconciliations, {} branch probes, {} dispatcher probes, and {} bounded flows to {}".format(
        len(result["blocks"]), len(result["branchProbes"]), len(result["dispatcherProbes"]), flow_count, output_path
    ))


if __name__ == "__main__":
    main()
"##;
    let script = template
        .replace("__REPORT_JSON__", &report_literal)
        .replace(
            "__PROBE_OPAQUE__",
            if probe_opaque_branches {
                "True"
            } else {
                "False"
            },
        )
        .replace(
            "__CFG_EMULATED__",
            if use_cfg_emulated { "True" } else { "False" },
        )
        .replace(
            "__EXPLORE_FLOWS__",
            if flow_config.enabled { "True" } else { "False" },
        )
        .replace("__FLOW_MAX_DEPTH__", &flow_config.max_depth.to_string())
        .replace(
            "__FLOW_MAX_STATES__",
            &flow_config.max_states_per_probe.to_string(),
        )
        .replace("__FRIDA_SEEDS_JSON__", &frida_seed_literal)
        .replace("__EXPECTED_BINARY_IDENTITY__", &expected_binary_literal);
    let mut warnings = vec![
        "Trace UI generates the script but does not install or execute angr; run it manually in an isolated Python environment.".to_string(),
        "Use the exact ELF/shared object that produced the trace. Module offsets are aligned to angr's main-object mapped base.".to_string(),
        "Static CFG differences and unconstrained symbolic branch probes remain candidate evidence until validated with real entry state and inputs.".to_string(),
    ];
    if flow_config.enabled {
        warnings.push(format!(
            "Bounded symbolic flow continuation is enabled for the first trace-register branch seed and each exact Frida branch/dispatcher seed (depth {}, at most {} states per probe). Paths remain Candidate/Related evidence.",
            flow_config.max_depth, flow_config.max_states_per_probe
        ));
    }
    if frida_seed_provenance.is_some() {
        warnings.push(
            "Each embedded Frida seed is applied only to exact branch/condition-source or dispatcher-entry offset matches. Missing flags, SIMD state, memory, and entry-path constraints can still change feasibility."
                .to_string(),
        );
    } else {
        warnings.push(
            "Edit configure_state(state) in the generated script to seed registers and memory from Trace UI or Frida evidence."
                .to_string(),
        );
    }
    Ok(AngrOllvmScript {
        file_name,
        script,
        schema_version: "trace-ui/angr-ollvm-v1".to_string(),
        frida_seed: frida_seed_provenance,
        frida_seeds: frida_seed_provenances,
        expected_binary_identity: expected_binary_identity.cloned(),
        flow_config,
        warnings,
    })
}

fn validate_angr_register_values(
    values: &[AngrRegisterValue],
    context: &str,
) -> Result<(), String> {
    if values.len() > 16 {
        return Err(format!(
            "{context} contains more than 16 state-register values"
        ));
    }
    for value in values {
        if value.register.trim().is_empty() {
            return Err(format!("{context} contains an empty register name"));
        }
        if value.alternatives.len() > 2 {
            return Err(format!(
                "{context} register {} contains more than two alternatives",
                value.register
            ));
        }
        if let Some(concrete) = &value.value {
            parse_hex_addr(concrete)?;
        }
        for alternative in &value.alternatives {
            parse_hex_addr(alternative)?;
        }
        match value.status.as_str() {
            "concrete" if value.value.is_some() && value.alternatives.is_empty() => {}
            "symbolic" if value.value.is_none() => {}
            "unavailable" if value.value.is_none() && value.alternatives.is_empty() => {}
            _ => {
                return Err(format!(
                    "{context} register {} has inconsistent status/value fields",
                    value.register
                ));
            }
        }
    }
    Ok(())
}

fn validate_angr_flow(
    probe_offset: &str,
    flow: &AngrFlowExploration,
    config: &AngrOllvmFlowConfig,
    dispatcher_flow: bool,
) -> Result<(), String> {
    if !config.enabled {
        return Err("angr seeded-flow result is disabled by flowConfig".to_string());
    }
    if flow.max_depth != config.max_depth || flow.max_states != config.max_states_per_probe {
        return Err(format!(
            "angr seeded-flow bounds do not match flowConfig at {probe_offset}"
        ));
    }
    if flow.explored_states > flow.max_states {
        return Err(format!(
            "angr seeded-flow exploredStates exceeds maxStates at {probe_offset}"
        ));
    }
    if flow.paths.len() > flow.max_states as usize + 1 {
        return Err(format!(
            "angr seeded-flow path count exceeds the bounded limit at {probe_offset}"
        ));
    }
    for path in &flow.paths {
        parse_hex_addr(&path.terminal_address)?;
        if let Some(offset) = &path.terminal_offset {
            parse_hex_addr(offset)?;
        }
        if path.offsets.is_empty() {
            return Err(format!("angr seeded-flow path is empty at {probe_offset}"));
        }
        if path.offsets.len() > flow.max_depth as usize + 1 {
            return Err(format!(
                "angr seeded-flow path depth exceeds the configured limit at {probe_offset}"
            ));
        }
        for offset in &path.offsets {
            parse_hex_addr(offset)?;
        }
        if path.constraints.len() > 4
            || path
                .constraints
                .iter()
                .any(|constraint| constraint.len() > 500)
        {
            return Err(format!(
                "angr seeded-flow constraints exceed the bounded limit at {probe_offset}"
            ));
        }
        if path
            .offsets
            .first()
            .is_some_and(|offset| !offset.eq_ignore_ascii_case(probe_offset))
        {
            return Err(format!(
                "angr seeded-flow path does not begin at probe offset {probe_offset}"
            ));
        }
        if let Some(dispatcher_offset) = &path.matched_dispatcher_offset {
            if !dispatcher_flow || path.status != "dispatcher-hit" {
                return Err(format!(
                    "angr seeded-flow has unexpected dispatcher match at {probe_offset}"
                ));
            }
            parse_hex_addr(dispatcher_offset)?;
            if path
                .terminal_offset
                .as_deref()
                .is_some_and(|terminal| !terminal.eq_ignore_ascii_case(dispatcher_offset))
            {
                return Err(format!(
                    "angr dispatcher-hit terminal offset does not match {dispatcher_offset}"
                ));
            }
        } else if path.status == "dispatcher-hit" {
            return Err(format!(
                "angr dispatcher-hit path lacks matchedDispatcherOffset at {probe_offset}"
            ));
        }
        if !dispatcher_flow && !path.dispatcher_state_values.is_empty() {
            return Err(format!(
                "angr branch flow contains dispatcher state values at {probe_offset}"
            ));
        }
        validate_angr_register_values(
            &path.dispatcher_state_values,
            &format!("angr flow path at {probe_offset}"),
        )?;
    }
    Ok(())
}

pub fn parse_angr_ollvm_result_bundle(bytes: &[u8]) -> Result<AngrOllvmResultBundle, String> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("angr result file exceeds 32 MiB".to_string());
    }
    let bundle: AngrOllvmResultBundle = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid angr result JSON: {error}"))?;
    if bundle.schema != "trace-ui/angr-ollvm-v1" {
        return Err(format!("unsupported angr result schema: {}", bundle.schema));
    }
    if bundle.module_name.trim().is_empty() {
        return Err("angr result moduleName must not be empty".to_string());
    }
    if bundle.binary_sha256.len() != 64
        || !bundle
            .binary_sha256
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("angr result binarySha256 must contain 64 hexadecimal characters".to_string());
    }
    if let Some(expected) = &bundle.expected_binary_sha256 {
        if expected.len() != 64
            || !expected
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(
                "angr result expectedBinarySha256 must contain 64 hexadecimal characters"
                    .to_string(),
            );
        }
        if bundle.binary_identity_matched == Some(true)
            && !expected.eq_ignore_ascii_case(&bundle.binary_sha256)
        {
            return Err("angr result marks binary identity matched but hashes differ".to_string());
        }
    } else if bundle.binary_identity_matched.is_some() {
        return Err("angr result binaryIdentityMatched requires expectedBinarySha256".to_string());
    }
    parse_hex_addr(&bundle.mapped_base)?;
    let frida_provenances = if !bundle.frida_seeds.is_empty() {
        bundle.frida_seeds.iter().collect::<Vec<_>>()
    } else {
        bundle.frida_seed.iter().collect::<Vec<_>>()
    };
    if !frida_provenances.is_empty() {
        let mut event_indices = std::collections::HashSet::new();
        for seed in &frida_provenances {
            if seed.module_name != bundle.module_name {
                return Err(
                    "angr result Frida seed moduleName does not match bundle moduleName"
                        .to_string(),
                );
            }
            if !event_indices.insert(seed.source_event_index) {
                return Err(format!(
                    "angr result contains duplicate Frida provenance event {}",
                    seed.source_event_index
                ));
            }
            parse_hex_addr(&seed.capture_offset)?;
            for offset in &seed.matched_probe_offsets {
                parse_hex_addr(offset)?;
                let branch_match = bundle.branch_probes.iter().any(|probe| {
                    probe.offset.eq_ignore_ascii_case(offset)
                        && probe.source_event_index == Some(seed.source_event_index)
                        && probe
                            .seed_kind
                            .as_deref()
                            .is_some_and(|kind| kind.starts_with("frida-capture-"))
                });
                let dispatcher_match = bundle.dispatcher_probes.iter().any(|probe| {
                    probe.offset.eq_ignore_ascii_case(offset)
                        && probe.source_event_index == seed.source_event_index
                        && probe.seed_kind == "frida-capture-exact-dispatcher"
                });
                if !branch_match && !dispatcher_match {
                    return Err(format!(
                    "angr result Frida provenance has no matching branch or dispatcher probe at {offset}"
                ));
                }
            }
            for offset in &seed.matched_branch_offsets {
                parse_hex_addr(offset)?;
                if !seed
                    .matched_probe_offsets
                    .iter()
                    .any(|matched| matched.eq_ignore_ascii_case(offset))
                {
                    return Err(format!(
                    "angr result Frida branch offset {offset} is absent from matchedProbeOffsets"
                ));
                }
            }
            for offset in &seed.matched_dispatcher_offsets {
                parse_hex_addr(offset)?;
                if !seed
                    .matched_probe_offsets
                    .iter()
                    .any(|matched| matched.eq_ignore_ascii_case(offset))
                {
                    return Err(format!(
                    "angr result Frida dispatcher offset {offset} is absent from matchedProbeOffsets"
                ));
                }
            }
        }
    } else if bundle.branch_probes.iter().any(|probe| {
        probe.source_event_index.is_some()
            || probe
                .seed_kind
                .as_deref()
                .is_some_and(|kind| kind.starts_with("frida-capture-"))
    }) || !bundle.dispatcher_probes.is_empty()
    {
        return Err(
            "angr result contains a Frida branch/dispatcher probe without top-level provenance"
                .to_string(),
        );
    }
    if let Some(config) = &bundle.flow_config {
        validate_flow_config(config)?;
        if !config.enabled
            && (bundle
                .branch_probes
                .iter()
                .any(|probe| probe.flow_exploration.is_some())
                || bundle
                    .dispatcher_probes
                    .iter()
                    .any(|probe| probe.flow_exploration.is_some()))
        {
            return Err(
                "angr result contains seeded-flow paths while flowConfig is disabled".to_string(),
            );
        }
    } else if bundle
        .branch_probes
        .iter()
        .any(|probe| probe.flow_exploration.is_some())
        || bundle
            .dispatcher_probes
            .iter()
            .any(|probe| probe.flow_exploration.is_some())
    {
        return Err("angr result contains seeded-flow paths without flowConfig".to_string());
    }
    for block in &bundle.blocks {
        parse_hex_addr(&block.offset)?;
        for offset in block
            .observed_successors
            .iter()
            .chain(&block.unobserved_static_successors)
            .chain(&block.dynamic_only_successors)
        {
            parse_hex_addr(offset)?;
        }
        for successor in &block.static_successors {
            parse_hex_addr(&successor.address)?;
            if let Some(offset) = &successor.offset {
                parse_hex_addr(offset)?;
            }
        }
    }
    for probe in &bundle.branch_probes {
        parse_hex_addr(&probe.offset)?;
        if let Some(offset) = &probe.source_offset {
            parse_hex_addr(offset)?;
        }
        for offset in &probe.observed_successors {
            parse_hex_addr(offset)?;
        }
        for successor in &probe.successors {
            parse_hex_addr(&successor.address)?;
            if let Some(offset) = &successor.offset {
                parse_hex_addr(offset)?;
            }
        }
        if let Some(flow) = &probe.flow_exploration {
            let config = bundle
                .flow_config
                .as_ref()
                .ok_or_else(|| "angr seeded-flow result lacks flowConfig".to_string())?;
            if !probe.seed_kind.as_deref().is_some_and(|kind| {
                kind == "trace-register-snapshot" || kind.starts_with("frida-capture-")
            }) {
                return Err(format!(
                    "angr seeded-flow is attached to a non-seeded probe at {}",
                    probe.offset
                ));
            }
            validate_angr_flow(&probe.offset, flow, config, false)?;
        }
    }
    for probe in &bundle.dispatcher_probes {
        parse_hex_addr(&probe.offset)?;
        parse_hex_addr(&probe.source_offset)?;
        if probe.seed_kind != "frida-capture-exact-dispatcher" {
            return Err(format!(
                "angr dispatcher probe at {} has unsupported seedKind {}",
                probe.offset, probe.seed_kind
            ));
        }
        if !probe.offset.eq_ignore_ascii_case(&probe.source_offset) {
            return Err(format!(
                "angr dispatcher probe sourceOffset does not match probe offset {}",
                probe.offset
            ));
        }
        let seed = frida_provenances
            .iter()
            .find(|seed| seed.source_event_index == probe.source_event_index)
            .ok_or_else(|| "angr dispatcher probe lacks matching Frida provenance".to_string())?;
        if !seed
            .matched_probe_offsets
            .iter()
            .any(|offset| offset.eq_ignore_ascii_case(&probe.offset))
        {
            return Err(format!(
                "angr dispatcher probe provenance mismatch at {}",
                probe.offset
            ));
        }
        if probe.state_registers.len() > 16 {
            return Err(format!(
                "angr dispatcher probe has more than 16 state registers at {}",
                probe.offset
            ));
        }
        validate_angr_register_values(
            &probe.source_state_values,
            &format!("angr dispatcher probe at {}", probe.offset),
        )?;
        if let Some(flow) = &probe.flow_exploration {
            let config = bundle
                .flow_config
                .as_ref()
                .ok_or_else(|| "angr dispatcher flow result lacks flowConfig".to_string())?;
            validate_angr_flow(&probe.offset, flow, config, true)?;
        }
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::evidence_score::{score_evidence, EvidenceScoreSignal};
    use crate::query::frida_capture::{AngrSeedMemoryRegion, AngrSeedRegister};
    use crate::query::ollvm::{
        BranchStateObservation, DispatcherCandidate, DynamicBasicBlock, DynamicBranchProfile,
        OllvmScope, OpaqueBranchCandidate,
    };

    fn sample_report() -> OllvmReport {
        OllvmReport {
            schema_version: "trace-ui/ollvm-v1".to_string(),
            scope: OllvmScope {
                session_id: "session".to_string(),
                node_id: Some(1),
                function_name: Some("target".to_string()),
                module_name: "libtarget.so".to_string(),
                module_base: "0x100000".to_string(),
                start_seq: 1,
                end_seq: 10,
                child_calls_excluded: 0,
            },
            executed_instruction_count: 2,
            unique_instruction_count: 2,
            block_count: 1,
            edge_count: 0,
            blocks: vec![DynamicBasicBlock {
                block_id: "libtarget.so+0x100".to_string(),
                module_name: "libtarget.so".to_string(),
                start_offset: "0x100".to_string(),
                end_offset: "0x104".to_string(),
                start_address: "0x100100".to_string(),
                end_address: "0x100104".to_string(),
                visit_count: 1,
                predecessor_count: 0,
                successor_count: 0,
                terminal_operation: "b.eq".to_string(),
                sample_seqs: vec![1],
                instructions: Vec::new(),
            }],
            edges: Vec::new(),
            branch_profiles: vec![DynamicBranchProfile {
                branch_offset: "0x104".to_string(),
                disasm: "b.eq 0x120".to_string(),
                execution_count: 2,
                observed_taken_count: 2,
                observed_fallthrough_count: 0,
                observed_other_count: 0,
                observed_successors: vec!["0x120".to_string()],
                condition_source_offsets: vec!["0x100".to_string()],
                observations: Vec::new(),
                observations_truncated: false,
                condition_state_profile: Default::default(),
            }],
            dispatcher_candidates: vec![DispatcherCandidate {
                block_id: "libtarget.so+0x80".to_string(),
                start_offset: "0x80".to_string(),
                end_offset: "0x8c".to_string(),
                visit_count: 8,
                predecessor_count: 3,
                successor_count: 2,
                indirect_branch_count: 8,
                backward_edge_count: 1,
                state_registers: vec!["X8".to_string()],
                state_snapshots: Vec::new(),
                state_transitions: Vec::new(),
                state_snapshots_truncated: false,
                rationale: "dispatcher candidate".to_string(),
                assessment: score_evidence(
                    "dispatcher",
                    false,
                    vec![EvidenceScoreSignal::new(
                        "test",
                        "Test evidence",
                        40,
                        true,
                        None,
                    )],
                    vec!["candidate only".to_string()],
                ),
            }],
            opaque_branch_candidates: vec![OpaqueBranchCandidate {
                branch_offset: "0x104".to_string(),
                disasm: "b.eq 0x120".to_string(),
                execution_count: 2,
                observed_taken_count: 2,
                observed_fallthrough_count: 0,
                observed_other_count: 0,
                observed_successors: vec!["0x120".to_string()],
                condition_source_offsets: vec!["0x100".to_string()],
                observations: vec![BranchStateObservation {
                    seq: 4,
                    outcome: "taken".to_string(),
                    successor: "0x120".to_string(),
                    registers: [("NZCV".to_string(), "0x40000000".to_string())]
                        .into_iter()
                        .collect(),
                }],
                observations_truncated: false,
                condition_state_profile: Default::default(),
                rationale: "single observed outcome".to_string(),
                assessment: score_evidence(
                    "opaque-branch",
                    false,
                    vec![EvidenceScoreSignal::new(
                        "test",
                        "Test evidence",
                        40,
                        true,
                        Some("test".to_string()),
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

    fn sample_frida_seed(capture_offset: &str) -> AngrStateSeed {
        AngrStateSeed {
            schema_version: "trace-ui/angr-state-seed-v1".to_string(),
            source_event_index: 7,
            source_event: "hook-enter".to_string(),
            hook_id: "branch-probe".to_string(),
            call_id: Some("branch-probe:1".to_string()),
            module_name: Some("libtarget.so".to_string()),
            module_base: Some("0x71000000".to_string()),
            module_size: 0x1000,
            function_name: "branch-probe".to_string(),
            capture_target: Some("0x71000100".to_string()),
            capture_offset: Some(capture_offset.to_string()),
            script: "def configure_state(state): return state".to_string(),
            registers_seeded: vec!["x0".to_string()],
            registers: vec![
                AngrSeedRegister {
                    name: "x0".to_string(),
                    value: "0x90000000".to_string(),
                },
                AngrSeedRegister {
                    name: "nzcv".to_string(),
                    value: "0x60000000".to_string(),
                },
            ],
            memory_regions: vec![AngrSeedMemoryRegion {
                address: "0x90000000".to_string(),
                byte_length: 4,
                bytes_hex: "00112233".to_string(),
                label: "input".to_string(),
                source_kind: "byteArray".to_string(),
                phase: "enter".to_string(),
                base_register: None,
                displacement: None,
            }],
            warnings: Vec::new(),
        }
    }

    #[test]
    fn generates_manual_angr_bridge_with_cfg_and_symbolic_probe() {
        let generated = generate_angr_ollvm_script(&sample_report(), true, false).unwrap();
        assert!(generated.script.contains("import angr"));
        assert!(generated.script.contains("CFGFast"));
        assert!(generated.script.contains("def configure_state(state)"));
        assert!(generated.script.contains("project.factory.successors"));
        assert!(generated.script.contains("trace-register-snapshot"));
        assert!(generated.script.contains("_apply_trace_snapshot"));
        assert!(generated.script.contains("_probe_branch_with_frida"));
        assert!(generated.script.contains("_explore_seeded_flow"));
        assert!(generated.script.contains("_probe_dispatcher_with_frida"));
        assert!(generated.script.contains("_explore_dispatcher_flow"));
        assert!(generated.script.contains("def _set_nzcv(state, value):"));
        assert!(generated
            .script
            .contains("DEFAULT_EXPLORE_SEEDED_FLOWS = True"));
        assert!(generated.script.contains("DEFAULT_FLOW_MAX_DEPTH = 8"));
        assert!(generated.script.contains("DEFAULT_FLOW_MAX_STATES = 32"));
        assert!(!generated.script.contains("__FLOW_"));
        assert!(!generated.script.contains("__EXPLORE_FLOWS__"));
        assert!(generated.flow_config.enabled);
        assert_eq!(generated.flow_config.max_depth, 8);
        assert_eq!(generated.flow_config.max_states_per_probe, 32);
        assert!(generated.script.contains("trace-ui/angr-ollvm-v1"));
        assert!(generated
            .script
            .contains("DEFAULT_PROBE_OPAQUE_BRANCHES = True"));
    }

    #[test]
    fn embeds_only_exact_offset_matched_frida_seed() {
        let seed = sample_frida_seed("0x100");
        let generated =
            generate_angr_ollvm_script_with_seed(&sample_report(), true, false, Some(&seed))
                .unwrap();
        let provenance = generated.frida_seed.unwrap();
        assert_eq!(provenance.capture_offset, "0x100");
        assert_eq!(provenance.matched_probe_offsets, vec!["0x104"]);
        assert!(generated
            .script
            .contains("frida-capture-exact-condition-source"));
        assert!(generated.script.contains("00112233"));
        assert!(generated.script.contains("nzcv"));
        assert!(generated.script.contains("sourceEventIndex"));

        let mismatched = sample_frida_seed("0x200");
        assert!(generate_angr_ollvm_script_with_seed(
            &sample_report(),
            true,
            false,
            Some(&mismatched)
        )
        .is_err());
    }

    #[test]
    fn embeds_multiple_exact_frida_seeds_and_optional_elf_guard() {
        let first = sample_frida_seed("0x100");
        let mut second = sample_frida_seed("0x80");
        second.source_event_index = 8;
        let identity = ElfBinaryIdentity {
            binary_path: "/tmp/libtarget.so".to_string(),
            binary_sha256: "ab".repeat(32),
            file_size: 123,
            format: "ELF64".to_string(),
            architecture: "AArch64".to_string(),
            elf_machine: 183,
            build_id: Some("build".to_string()),
        };
        let generated = generate_angr_ollvm_script_with_seeds_flow_and_identity(
            &sample_report(),
            true,
            false,
            vec![&first, &second],
            AngrOllvmFlowConfig::default(),
            Some(&identity),
        )
        .unwrap();
        assert_eq!(generated.frida_seeds.len(), 2);
        assert_eq!(generated.frida_seeds[0].source_event_index, 7);
        assert_eq!(generated.frida_seeds[1].source_event_index, 8);
        assert_eq!(
            generated
                .expected_binary_identity
                .as_ref()
                .unwrap()
                .binary_sha256,
            identity.binary_sha256
        );
        assert!(generated.script.contains("FRIDA_SEEDS = json.loads"));
        assert!(generated.script.contains("EXPECTED_BINARY_IDENTITY"));
        assert!(generated.script.contains(&identity.binary_sha256));
    }

    #[test]
    fn embeds_exact_dispatcher_seed_without_requiring_branch_probes() {
        let seed = sample_frida_seed("0x80");
        let generated = generate_angr_ollvm_script_with_seed_and_flow(
            &sample_report(),
            false,
            false,
            Some(&seed),
            AngrOllvmFlowConfig::default(),
        )
        .unwrap();
        let provenance = generated.frida_seed.unwrap();
        assert_eq!(provenance.matched_probe_offsets, vec!["0x80"]);
        assert!(provenance.matched_branch_offsets.is_empty());
        assert_eq!(provenance.matched_dispatcher_offsets, vec!["0x80"]);
        assert!(generated.flow_config.enabled);
        assert!(generated.script.contains("frida-capture-exact-dispatcher"));
        assert!(generated.script.contains("dispatcherProbes"));
    }

    #[test]
    fn embeds_exact_dispatcher_hit_event_from_multi_hook_capture() {
        let mut seed = sample_frida_seed("0x80");
        seed.source_event = "ollvm-dispatcher-hit".to_string();
        seed.hook_id = "ollvm-dispatcher-80".to_string();
        let generated = generate_angr_ollvm_script_with_seed_and_flow(
            &sample_report(),
            false,
            false,
            Some(&seed),
            AngrOllvmFlowConfig::default(),
        )
        .unwrap();
        assert_eq!(
            generated
                .frida_seed
                .as_ref()
                .unwrap()
                .matched_dispatcher_offsets,
            vec!["0x80"]
        );

        let mut branch_seed = sample_frida_seed("0x100");
        branch_seed.source_event = "ollvm-dispatcher-hit".to_string();
        assert!(generate_angr_ollvm_script_with_seed(
            &sample_report(),
            true,
            false,
            Some(&branch_seed)
        )
        .is_err());
    }

    #[test]
    fn generated_angr_bridge_has_valid_python_syntax_when_python_is_available() {
        let python = ["python3", "python"].into_iter().find(|candidate| {
            std::process::Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        });
        let Some(python) = python else {
            eprintln!("skipping generated Python syntax check: Python is unavailable");
            return;
        };
        let seed = sample_frida_seed("0x100");
        let generated =
            generate_angr_ollvm_script_with_seed(&sample_report(), true, false, Some(&seed))
                .unwrap();
        let directory =
            std::env::temp_dir().join(format!("trace-ui-angr-syntax-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let script_path = directory.join("generated.py");
        std::fs::write(&script_path, generated.script).unwrap();
        let output = std::process::Command::new(python)
            .arg("-m")
            .arg("py_compile")
            .arg(&script_path)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            output.status.success(),
            "generated Python failed py_compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn parses_valid_result_and_rejects_wrong_schema() {
        let valid = br#"{
          "schema":"trace-ui/angr-ollvm-v1",
          "moduleName":"libtarget.so",
          "binarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "mappedBase":"0x400000",
          "architecture":"AARCH64",
          "angrVersion":"9.2",
          "cfgKind":"CFGFast",
          "blocks":[],
          "branchProbes":[],
          "warnings":[]
        }"#;
        assert!(parse_angr_ollvm_result_bundle(valid).is_ok());
        let wrong = br#"{
          "schema":"trace-ui/angr-ollvm-v0",
          "moduleName":"libtarget.so",
          "binarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "mappedBase":"0x400000",
          "architecture":"AARCH64",
          "angrVersion":"9.2",
          "cfgKind":"CFGFast"
        }"#;
        assert!(parse_angr_ollvm_result_bundle(wrong).is_err());
    }

    #[test]
    fn validates_embedded_exact_elf_identity_result() {
        let valid = br#"{
          "schema":"trace-ui/angr-ollvm-v1",
          "moduleName":"libtarget.so",
          "binarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "expectedBinarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "binaryIdentityMatched":true,
          "mappedBase":"0x400000",
          "architecture":"AARCH64",
          "angrVersion":"9.2",
          "cfgKind":"CFGFast",
          "blocks":[],
          "branchProbes":[],
          "warnings":[]
        }"#;
        assert!(parse_angr_ollvm_result_bundle(valid).is_ok());
        let mismatch = br#"{
          "schema":"trace-ui/angr-ollvm-v1",
          "moduleName":"libtarget.so",
          "binarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "expectedBinarySha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "binaryIdentityMatched":true,
          "mappedBase":"0x400000",
          "architecture":"AARCH64",
          "angrVersion":"9.2",
          "cfgKind":"CFGFast"
        }"#;
        assert!(parse_angr_ollvm_result_bundle(mismatch).is_err());
    }

    #[test]
    fn rejects_frida_provenance_without_matching_branch_probe() {
        let result = br#"{
          "schema":"trace-ui/angr-ollvm-v1",
          "moduleName":"libtarget.so",
          "binarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "mappedBase":"0x400000",
          "architecture":"AARCH64",
          "angrVersion":"9.2",
          "cfgKind":"CFGFast",
          "fridaSeed":{
            "sourceEventIndex":7,
            "hookId":"branch-probe",
            "moduleName":"libtarget.so",
            "functionName":"branch-probe",
            "captureOffset":"0x100",
            "registersSeeded":["x0"],
            "memoryRegionCount":1,
            "matchedProbeOffsets":["0x104"]
          },
          "blocks":[],
          "branchProbes":[],
          "warnings":[]
        }"#;

        let error = parse_angr_ollvm_result_bundle(result).unwrap_err();
        assert!(error.contains("no matching branch or dispatcher probe at 0x104"));
    }

    #[test]
    fn accepts_frida_provenance_with_matching_branch_probe() {
        let result = br#"{
          "schema":"trace-ui/angr-ollvm-v1",
          "moduleName":"libtarget.so",
          "binarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "mappedBase":"0x400000",
          "architecture":"AARCH64",
          "angrVersion":"9.2",
          "cfgKind":"CFGFast",
          "fridaSeed":{
            "sourceEventIndex":7,
            "hookId":"branch-probe",
            "moduleName":"libtarget.so",
            "functionName":"branch-probe",
            "captureOffset":"0x100",
            "registersSeeded":["x0"],
            "memoryRegionCount":1,
            "matchedProbeOffsets":["0x104"]
          },
          "blocks":[],
          "branchProbes":[{
            "offset":"0x104",
            "status":"candidate",
            "seedKind":"frida-capture-exact-condition-source",
            "sourceEventIndex":7,
            "sourceOffset":"0x100",
            "seededRegisters":["x0"],
            "seededMemoryRegions":["0x90000000+4"],
            "observedSuccessors":[],
            "successors":[],
            "constraints":[],
            "limitation":"Candidate only"
          }],
          "warnings":[]
        }"#;

        let parsed = parse_angr_ollvm_result_bundle(result).unwrap();
        assert_eq!(parsed.frida_seed.unwrap().source_event_index, 7);
        assert_eq!(
            parsed.branch_probes[0].source_offset.as_deref(),
            Some("0x100")
        );
    }

    #[test]
    fn accepts_bounded_dispatcher_seed_flow_and_state_values() {
        let result = br#"{
          "schema":"trace-ui/angr-ollvm-v1",
          "moduleName":"libtarget.so",
          "binarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "mappedBase":"0x400000",
          "architecture":"AARCH64",
          "angrVersion":"9.2",
          "cfgKind":"CFGFast",
          "fridaSeed":{
            "sourceEventIndex":7,
            "hookId":"dispatcher-probe",
            "moduleName":"libtarget.so",
            "functionName":"dispatcher-probe",
            "captureOffset":"0x80",
            "registersSeeded":["x8"],
            "memoryRegionCount":0,
            "matchedProbeOffsets":["0x80"],
            "matchedDispatcherOffsets":["0x80"]
          },
          "flowConfig":{"enabled":true,"maxDepth":8,"maxStatesPerProbe":32},
          "blocks":[],
          "branchProbes":[],
          "dispatcherProbes":[{
            "offset":"0x80",
            "status":"dispatcher_flow_explored",
            "seedKind":"frida-capture-exact-dispatcher",
            "sourceEventIndex":7,
            "sourceOffset":"0x80",
            "seededRegisters":["X8"],
            "seededMemoryRegions":[],
            "stateRegisters":["X8"],
            "sourceStateValues":[{"register":"X8","status":"concrete","value":"0x1","alternatives":[]}],
            "flowExploration":{
              "maxDepth":8,
              "maxStates":32,
              "exploredStates":2,
              "truncated":false,
              "paths":[{
                "status":"dispatcher-hit",
                "offsets":["0x80","0x120"],
                "jumpKinds":["Ijk_Boring"],
                "terminalAddress":"0x400120",
                "terminalOffset":"0x120",
                "matchedDispatcherOffset":"0x120",
                "dispatcherStateValues":[{"register":"X9","status":"symbolic","alternatives":["0x2","0x3"]}],
                "constraintCount":1,
                "constraints":["x8 == 1"]
              }],
              "limitation":"Candidate only"
            },
            "limitation":"Candidate only"
          }],
          "warnings":[]
        }"#;
        let parsed = parse_angr_ollvm_result_bundle(result).unwrap();
        let probe = &parsed.dispatcher_probes[0];
        assert_eq!(probe.source_state_values[0].value.as_deref(), Some("0x1"));
        let path = &probe.flow_exploration.as_ref().unwrap().paths[0];
        assert_eq!(path.matched_dispatcher_offset.as_deref(), Some("0x120"));
        assert_eq!(path.dispatcher_state_values[0].alternatives.len(), 2);
    }

    #[test]
    fn validates_bounded_seeded_flow_results() {
        let valid = br#"{
          "schema":"trace-ui/angr-ollvm-v1",
          "moduleName":"libtarget.so",
          "binarySha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "mappedBase":"0x400000",
          "architecture":"AARCH64",
          "angrVersion":"9.2",
          "cfgKind":"CFGFast",
          "flowConfig":{"enabled":true,"maxDepth":8,"maxStatesPerProbe":32},
          "blocks":[],
          "branchProbes":[{
            "offset":"0x104",
            "status":"single_satisfiable_successor_with_trace_register_snapshot",
            "seedKind":"trace-register-snapshot",
            "sourceSeq":4,
            "sourceOffset":"0x104",
            "seededRegisters":["NZCV"],
            "observedSuccessors":["0x120"],
            "successors":[],
            "constraints":[],
            "flowExploration":{
              "maxDepth":8,
              "maxStates":32,
              "exploredStates":1,
              "truncated":false,
              "paths":[{
                "status":"dead-end",
                "offsets":["0x104","0x120"],
                "jumpKinds":["Ijk_Boring"],
                "terminalAddress":"0x400120",
                "terminalOffset":"0x120",
                "constraintCount":1,
                "constraints":["x0 == 1"]
              }],
              "limitation":"Candidate only"
            },
            "limitation":"Candidate only"
          }],
          "warnings":[]
        }"#;

        let parsed = parse_angr_ollvm_result_bundle(valid).unwrap();
        let flow = parsed.branch_probes[0].flow_exploration.as_ref().unwrap();
        assert_eq!(flow.paths[0].offsets, vec!["0x104", "0x120"]);

        let mut invalid: serde_json::Value = serde_json::from_slice(valid).unwrap();
        invalid["branchProbes"][0]["flowExploration"]["exploredStates"] = serde_json::json!(33);
        let bytes = serde_json::to_vec(&invalid).unwrap();
        assert!(parse_angr_ollvm_result_bundle(&bytes)
            .unwrap_err()
            .contains("exploredStates exceeds maxStates"));

        let mut missing_config: serde_json::Value = serde_json::from_slice(valid).unwrap();
        missing_config.as_object_mut().unwrap().remove("flowConfig");
        let bytes = serde_json::to_vec(&missing_config).unwrap();
        assert!(parse_angr_ollvm_result_bundle(&bytes)
            .unwrap_err()
            .contains("without flowConfig"));

        let mut blank_flow: serde_json::Value = serde_json::from_slice(valid).unwrap();
        blank_flow["branchProbes"][0]["seedKind"] = serde_json::json!("blank-unconstrained");
        let bytes = serde_json::to_vec(&blank_flow).unwrap();
        assert!(parse_angr_ollvm_result_bundle(&bytes)
            .unwrap_err()
            .contains("non-seeded probe"));

        let mut excessive_constraints: serde_json::Value = serde_json::from_slice(valid).unwrap();
        excessive_constraints["branchProbes"][0]["flowExploration"]["paths"][0]["constraints"] =
            serde_json::json!(["a", "b", "c", "d", "e"]);
        let bytes = serde_json::to_vec(&excessive_constraints).unwrap();
        assert!(parse_angr_ollvm_result_bundle(&bytes)
            .unwrap_err()
            .contains("constraints exceed the bounded limit"));
    }

    #[test]
    fn rejects_unbounded_seeded_flow_generation_options() {
        let invalid = AngrOllvmFlowConfig {
            enabled: true,
            max_depth: 65,
            max_states_per_probe: 32,
        };
        assert!(generate_angr_ollvm_script_with_seed_and_flow(
            &sample_report(),
            true,
            false,
            None,
            invalid,
        )
        .unwrap_err()
        .contains("max depth"));
    }
}
