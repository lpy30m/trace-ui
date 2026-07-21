use serde::{Deserialize, Serialize};

use crate::query::ollvm::OllvmReport;
use crate::utils::parse_hex_addr;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AngrOllvmScript {
    pub file_name: String,
    pub script: String,
    pub schema_version: String,
    pub warnings: Vec<String>,
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
    pub seeded_registers: Vec<String>,
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
    if report.scope.module_name.trim().is_empty() {
        return Err("OLLVM report module name must not be empty".to_string());
    }
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
        if satisfiable_count >= 2:
            status = "multiple_satisfiable_successors_without_trace_context"
        elif satisfiable_count == 1:
            status = "single_satisfiable_successor_without_trace_context"
        else:
            status = "no_satisfiable_successor_without_trace_context"
        constraints = [str(item)[:500] for item in state.solver.constraints[-4:]]
        return {
            "offset": offset,
            "status": status,
            "seedKind": seed_kind,
            "sourceSeq": snapshot.get("seq") if snapshot is not None else None,
            "seededRegisters": seeded_registers,
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
            "seededRegisters": [],
            "observedSuccessors": observed,
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
    warnings.extend([
        "Static CFG successors absent from the dynamic trace may be unexecuted, infeasible, or CFG recovery artifacts.",
        "Dynamic-only edges may indicate indirect control flow or static CFG recovery gaps.",
        "Unconstrained branch probes are hypothesis generators, not proof of real-input reachability.",
        "Trace-seeded probes contain selected register values only; missing memory and architectural state can change feasibility.",
    ])
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
        );
    Ok(AngrOllvmScript {
        file_name,
        script,
        schema_version: "trace-ui/angr-ollvm-v1".to_string(),
        warnings: vec![
            "Trace UI generates the script but does not install or execute angr; run it manually in an isolated Python environment.".to_string(),
            "Use the exact ELF/shared object that produced the trace. Module offsets are aligned to angr's main-object mapped base.".to_string(),
            "Static CFG differences and unconstrained symbolic branch probes remain candidate evidence until validated with real entry state and inputs.".to_string(),
            "Edit configure_state(state) in the generated script to seed registers and memory from Trace UI or Frida evidence.".to_string(),
        ],
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

    #[test]
    fn generates_manual_angr_bridge_with_cfg_and_symbolic_probe() {
        let generated = generate_angr_ollvm_script(&sample_report(), true, false).unwrap();
        assert!(generated.script.contains("import angr"));
        assert!(generated.script.contains("CFGFast"));
        assert!(generated.script.contains("def configure_state(state)"));
        assert!(generated.script.contains("project.factory.successors"));
        assert!(generated.script.contains("trace-register-snapshot"));
        assert!(generated.script.contains("_apply_trace_snapshot"));
        assert!(generated.script.contains("trace-ui/angr-ollvm-v1"));
        assert!(generated
            .script
            .contains("DEFAULT_PROBE_OPAQUE_BRANCHES = True"));
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
        let generated = generate_angr_ollvm_script(&sample_report(), true, false).unwrap();
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
}
