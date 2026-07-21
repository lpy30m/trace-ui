use serde::{Deserialize, Serialize};

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
    pub warnings: Vec<String>,
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
    pub mapped_base: String,
    pub architecture: String,
    pub angr_version: String,
    pub cfg_kind: String,
    #[serde(default)]
    pub frida_seed: Option<AngrOllvmFridaSeedProvenance>,
    #[serde(default)]
    pub blocks: Vec<AngrBlockResult>,
    #[serde(default)]
    pub branch_probes: Vec<AngrBranchProbe>,
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

fn allowed_seed_register(name: &str) -> bool {
    if name == "sp" {
        return true;
    }
    name.strip_prefix('x')
        .and_then(|value| value.parse::<u8>().ok())
        .is_some_and(|index| index <= 30)
}

fn prepare_frida_seed(
    report: &OllvmReport,
    seed: &AngrStateSeed,
) -> Result<(serde_json::Value, AngrOllvmFridaSeedProvenance), String> {
    if seed.schema_version != "trace-ui/angr-state-seed-v1" {
        return Err(format!(
            "unsupported Frida angr seed schema: {}",
            seed.schema_version
        ));
    }
    if seed.source_event != "hook-enter" {
        return Err("OLLVM Frida seeds must come from a hook-enter event".to_string());
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
    let mut matched_probe_offsets = report
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
    matched_probe_offsets.sort_by_key(|value| parse_hex_addr(value).unwrap_or(u64::MAX));
    matched_probe_offsets.dedup();
    if matched_probe_offsets.is_empty() {
        return Err(format!(
            "Frida capture offset {} does not exactly match an opaque branch or its condition-source offset",
            capture_offset
        ));
    }
    if seed.registers.len() > 32 {
        return Err("Frida seed contains more than 32 registers".to_string());
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
    if report.scope.module_name.trim().is_empty() {
        return Err("OLLVM report module name must not be empty".to_string());
    }
    if frida_seed.is_some() && !probe_opaque_branches {
        return Err("Frida OLLVM seed merging requires opaque branch probes".to_string());
    }
    let (frida_seed_json, frida_seed_provenance) = match frida_seed {
        Some(seed) => {
            let (payload, provenance) = prepare_frida_seed(report, seed)?;
            (payload, Some(provenance))
        }
        None => (serde_json::Value::Null, None),
    };
    let frida_seed_json = serde_json::to_string(&frida_seed_json)
        .map_err(|error| format!("serialize Frida seed failed: {error}"))?;
    let frida_seed_literal = serde_json::to_string(&frida_seed_json)
        .map_err(|error| format!("quote Frida seed failed: {error}"))?;
    let report_json = serde_json::to_string(report)
        .map_err(|error| format!("serialize OLLVM report failed: {error}"))?;
    let report_literal = serde_json::to_string(&report_json)
        .map_err(|error| format!("quote OLLVM report failed: {error}"))?;
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
FRIDA_SEED = json.loads(__FRIDA_SEED_JSON__)


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
            setattr(state.regs, register_name, int(text, 16))
            seeded.append(name.upper())
        except Exception as error:
            errors.append("{}={}: {}".format(name, text, error))
    return seeded, errors


def _frida_rebase(project, value):
    if FRIDA_SEED is None:
        return value
    base_text = FRIDA_SEED.get("moduleBase")
    size = int(FRIDA_SEED.get("moduleSize") or 0)
    if base_text and size > 0:
        base = int(base_text, 16)
        if base <= value < base + size:
            return project.loader.main_object.mapped_base + (value - base)
    return value


def _apply_frida_seed(state):
    seeded_registers = []
    seeded_memory = []
    errors = []
    if FRIDA_SEED is None:
        return seeded_registers, seeded_memory, errors
    for register in FRIDA_SEED.get("registers", []):
        name = register["name"].lower()
        try:
            setattr(state.regs, name, _frida_rebase(state.project, int(register["value"], 16)))
            seeded_registers.append(name.upper())
        except Exception as error:
            errors.append("{}={}: {}".format(name, register.get("value"), error))
    for region in FRIDA_SEED.get("memoryRegions", []):
        try:
            address = _frida_rebase(state.project, int(region["address"], 16))
            state.memory.store(address, bytes.fromhex(region["bytesHex"]))
            seeded_memory.append(region.get("label") or region["address"])
        except Exception as error:
            errors.append("memory {}: {}".format(region.get("label") or region.get("address"), error))
    return seeded_registers, seeded_memory, errors


def _probe_branch(project, candidate, snapshot=None):
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
            "limitation": limitation,
            "error": str(error),
        }


def _probe_branch_with_frida(project, candidate):
    branch_offset = candidate["branchOffset"].lower()
    source_offset = FRIDA_SEED["captureOffset"].lower()
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
                "sourceEventIndex": FRIDA_SEED.get("sourceEventIndex"),
                "sourceOffset": source_offset,
                "seededRegisters": [],
                "seededMemoryRegions": [],
                "observedSuccessors": [value.lower() for value in candidate.get("observedSuccessors", [])],
                "successors": [],
                "constraints": [],
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
        seeded_registers, seeded_memory, seed_errors = _apply_frida_seed(state)
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
        return {
            "offset": branch_offset,
            "status": status,
            "seedKind": seed_kind,
            "sourceSeq": None,
            "sourceEventIndex": FRIDA_SEED.get("sourceEventIndex"),
            "sourceOffset": source_offset,
            "seededRegisters": seeded_registers,
            "seededMemoryRegions": seeded_memory,
            "observedSuccessors": [value.lower() for value in candidate.get("observedSuccessors", [])],
            "successors": records,
            "constraints": ["seed-warning: " + item for item in seed_errors],
            "limitation": limitation,
            "error": None,
        }
    except Exception as error:
        return {
            "offset": branch_offset,
            "status": "probe_error",
            "seedKind": seed_kind,
            "sourceSeq": None,
            "sourceEventIndex": FRIDA_SEED.get("sourceEventIndex"),
            "sourceOffset": source_offset,
            "seededRegisters": [],
            "seededMemoryRegions": [],
            "observedSuccessors": [value.lower() for value in candidate.get("observedSuccessors", [])],
            "successors": [],
            "constraints": [],
            "limitation": limitation,
            "error": str(error),
        }


def analyze(binary_path, prefer_emulated, probe_opaque):
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
            for snapshot in item.get("observations", []):
                if snapshot.get("registers"):
                    probes.append(_probe_branch(project, item, snapshot))
            if FRIDA_SEED is not None:
                frida_probe = _probe_branch_with_frida(project, item)
                if frida_probe is not None:
                    probes.append(frida_probe)
    warnings.extend([
        "Static CFG successors absent from the dynamic trace may be unexecuted, infeasible, or CFG recovery artifacts.",
        "Dynamic-only edges may indicate indirect control flow or static CFG recovery gaps.",
        "Unconstrained branch probes are hypothesis generators, not proof of real-input reachability.",
        "Trace-seeded probes contain selected register values only; missing memory and architectural state can change feasibility.",
    ])
    if FRIDA_SEED is not None:
        warnings.append("Frida-seeded probes are emitted only for an exact module-relative branch or condition-source offset match; they remain candidate evidence.")
    with open(binary_path, "rb") as source:
        binary_sha256 = hashlib.sha256(source.read()).hexdigest()
    return {
        "schema": SCHEMA,
        "moduleName": REPORT["scope"]["moduleName"],
        "binarySha256": binary_sha256,
        "mappedBase": hex(project.loader.main_object.mapped_base),
        "architecture": architecture,
        "angrVersion": getattr(angr, "__version__", "unknown"),
        "cfgKind": cfg_kind,
        "fridaSeed": FRIDA_SEED.get("provenance") if FRIDA_SEED is not None else None,
        "blocks": blocks,
        "branchProbes": probes,
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
    args = parser.parse_args()
    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        parser.error("binary does not exist: {}".format(binary_path))
    result = analyze(binary_path, args.cfg_emulated, args.probe_opaque)
    output_path = os.path.abspath(args.output)
    with open(output_path, "w", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
    print("[Trace UI] wrote {} block reconciliations and {} branch probes to {}".format(
        len(result["blocks"]), len(result["branchProbes"]), output_path
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
        .replace("__FRIDA_SEED_JSON__", &frida_seed_literal);
    let mut warnings = vec![
        "Trace UI generates the script but does not install or execute angr; run it manually in an isolated Python environment.".to_string(),
        "Use the exact ELF/shared object that produced the trace. Module offsets are aligned to angr's main-object mapped base.".to_string(),
        "Static CFG differences and unconstrained symbolic branch probes remain candidate evidence until validated with real entry state and inputs.".to_string(),
    ];
    if frida_seed_provenance.is_some() {
        warnings.push(
            "The embedded Frida seed is applied only to exact branch/condition-source offset matches. Missing flags, SIMD state, memory, and entry-path constraints can still change feasibility."
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
        warnings,
    })
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
    parse_hex_addr(&bundle.mapped_base)?;
    if let Some(seed) = &bundle.frida_seed {
        if seed.module_name != bundle.module_name {
            return Err(
                "angr result Frida seed moduleName does not match bundle moduleName".to_string(),
            );
        }
        parse_hex_addr(&seed.capture_offset)?;
        for offset in &seed.matched_probe_offsets {
            parse_hex_addr(offset)?;
            if !bundle.branch_probes.iter().any(|probe| {
                probe.offset.eq_ignore_ascii_case(offset)
                    && probe.source_event_index == Some(seed.source_event_index)
                    && probe
                        .seed_kind
                        .as_deref()
                        .is_some_and(|kind| kind.starts_with("frida-capture-"))
            }) {
                return Err(format!(
                    "angr result Frida provenance has no matching branch probe at {offset}"
                ));
            }
        }
    } else if bundle.branch_probes.iter().any(|probe| {
        probe.source_event_index.is_some()
            || probe
                .seed_kind
                .as_deref()
                .is_some_and(|kind| kind.starts_with("frida-capture-"))
    }) {
        return Err(
            "angr result contains a Frida branch probe without top-level provenance".to_string(),
        );
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
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::evidence_score::{score_evidence, EvidenceScoreSignal};
    use crate::query::frida_capture::{AngrSeedMemoryRegion, AngrSeedRegister};
    use crate::query::ollvm::{
        BranchStateObservation, DynamicBasicBlock, DynamicBranchProfile, OllvmScope,
        OpaqueBranchCandidate,
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
            }],
            dispatcher_candidates: Vec::new(),
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
            registers: vec![AngrSeedRegister {
                name: "x0".to_string(),
                value: "0x90000000".to_string(),
            }],
            memory_regions: vec![AngrSeedMemoryRegion {
                address: "0x90000000".to_string(),
                byte_length: 4,
                bytes_hex: "00112233".to_string(),
                label: "input".to_string(),
                source_kind: "byteArray".to_string(),
                phase: "enter".to_string(),
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
        assert!(error.contains("no matching branch probe at 0x104"));
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
}
