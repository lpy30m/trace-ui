use serde::{Deserialize, Serialize};

use crate::query::evidence_score::EvidenceAssessment;
use crate::utils::parse_hex_addr;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OllvmAnalysisOptions {
    #[serde(default)]
    pub node_id: Option<u32>,
    #[serde(default)]
    pub module_name: Option<String>,
    #[serde(default)]
    pub start_seq: Option<u32>,
    #[serde(default)]
    pub end_seq: Option<u32>,
    #[serde(default)]
    pub include_child_calls: bool,
    #[serde(default = "default_max_blocks")]
    pub max_blocks: u32,
    #[serde(default = "default_max_edges")]
    pub max_edges: u32,
}

fn default_max_blocks() -> u32 {
    1_000
}

fn default_max_edges() -> u32 {
    3_000
}

impl Default for OllvmAnalysisOptions {
    fn default() -> Self {
        Self {
            node_id: None,
            module_name: None,
            start_seq: None,
            end_seq: None,
            include_child_calls: false,
            max_blocks: default_max_blocks(),
            max_edges: default_max_edges(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OllvmScope {
    pub session_id: String,
    pub node_id: Option<u32>,
    pub function_name: Option<String>,
    pub module_name: String,
    pub module_base: String,
    pub start_seq: u32,
    pub end_seq: u32,
    pub child_calls_excluded: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicBlockInstruction {
    pub offset: String,
    pub address: String,
    pub disasm: String,
    pub execution_count: u64,
    pub sample_seq: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicBasicBlock {
    pub block_id: String,
    pub module_name: String,
    pub start_offset: String,
    pub end_offset: String,
    pub start_address: String,
    pub end_address: String,
    pub visit_count: u64,
    pub predecessor_count: u32,
    pub successor_count: u32,
    pub terminal_operation: String,
    pub sample_seqs: Vec<u32>,
    pub instructions: Vec<DynamicBlockInstruction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynamicCfgEdge {
    pub source_block_id: String,
    pub target_block_id: String,
    pub source_offset: String,
    pub target_offset: String,
    pub kind: String,
    pub execution_count: u64,
    pub sample_seq: u32,
    pub backward: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatcherCandidate {
    pub block_id: String,
    pub start_offset: String,
    pub end_offset: String,
    pub visit_count: u64,
    pub predecessor_count: u32,
    pub successor_count: u32,
    pub indirect_branch_count: u64,
    pub backward_edge_count: u32,
    pub state_registers: Vec<String>,
    pub rationale: String,
    pub assessment: EvidenceAssessment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueBranchCandidate {
    pub branch_offset: String,
    pub disasm: String,
    pub execution_count: u64,
    pub observed_taken_count: u64,
    pub observed_fallthrough_count: u64,
    pub observed_other_count: u64,
    pub observed_successors: Vec<String>,
    pub condition_source_offsets: Vec<String>,
    pub rationale: String,
    pub assessment: EvidenceAssessment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OllvmReport {
    pub schema_version: String,
    pub scope: OllvmScope,
    pub executed_instruction_count: u64,
    pub unique_instruction_count: u32,
    pub block_count: u32,
    pub edge_count: u32,
    pub blocks: Vec<DynamicBasicBlock>,
    pub edges: Vec<DynamicCfgEdge>,
    pub dispatcher_candidates: Vec<DispatcherCandidate>,
    pub opaque_branch_candidates: Vec<OpaqueBranchCandidate>,
    pub instructions_truncated: bool,
    pub blocks_truncated: bool,
    pub edges_truncated: bool,
    pub limitations: Vec<String>,
    pub next_steps: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdaOllvmScript {
    pub file_name: String,
    pub script: String,
    pub schema_version: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdaAnnotation {
    pub offset: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub repeatable_comment: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdaAnnotationBundle {
    pub schema: String,
    pub module_name: String,
    pub image_base: String,
    #[serde(default)]
    pub annotations: Vec<IdaAnnotation>,
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

pub fn generate_ida_ollvm_script(
    report: &OllvmReport,
    ida_image_base: Option<&str>,
    add_user_xrefs: bool,
) -> Result<IdaOllvmScript, String> {
    let base_literal = match ida_image_base
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => format!("0x{:x}", parse_hex_addr(value)?),
        None => "None".to_string(),
    };
    let report_json = serde_json::to_string(report)
        .map_err(|error| format!("serialize OLLVM report failed: {error}"))?;
    let report_literal = serde_json::to_string(&report_json)
        .map_err(|error| format!("quote OLLVM report failed: {error}"))?;
    let function_name = report
        .scope
        .function_name
        .as_deref()
        .unwrap_or(&report.scope.module_name);
    let file_name = format!("{}-trace-ui-ollvm.py", sanitize_name(function_name));
    let template = r##"# Trace UI dynamic CFG / OLLVM bridge
# Schema: trace-ui/ida-ollvm-v1
# Run manually inside IDA. Dynamic xrefs are disabled by default.
import json
import os

import idaapi
import ida_kernwin
import ida_name
import ida_xref
import idc

SCHEMA = "trace-ui/ida-ollvm-v1"
REPORT = json.loads(__REPORT_JSON__)
IDA_IMAGE_BASE_OVERRIDE = __IMAGE_BASE__
ADD_USER_XREFS = __ADD_XREFS__


def _base():
    return IDA_IMAGE_BASE_OVERRIDE if IDA_IMAGE_BASE_OVERRIDE is not None else idaapi.get_imagebase()


def _ea(offset):
    return _base() + int(offset, 16)


def _append_comment(ea, text, repeatable=False):
    previous = idc.get_cmt(ea, 1 if repeatable else 0) or ""
    if text in previous:
        return
    combined = text if not previous else previous + "\n" + text
    idc.set_cmt(ea, combined, 1 if repeatable else 0)


def apply_trace_ui_report():
    for block in REPORT.get("blocks", []):
        ea = _ea(block["startOffset"])
        text = "[Trace UI] dynamic block visits={} preds={} succs={} end={}".format(
            block.get("visitCount", 0),
            block.get("predecessorCount", 0),
            block.get("successorCount", 0),
            block.get("endOffset", "?"),
        )
        _append_comment(ea, text)

    for candidate in REPORT.get("dispatcherCandidates", []):
        ea = _ea(candidate["startOffset"])
        _append_comment(ea, "[Trace UI] OLLVM dispatcher candidate: " + candidate.get("rationale", ""), True)
        idc.set_color(ea, idc.CIC_ITEM, 0x00A5FF)

    for candidate in REPORT.get("opaqueBranchCandidates", []):
        ea = _ea(candidate["branchOffset"])
        _append_comment(ea, "[Trace UI] opaque-branch candidate: " + candidate.get("rationale", ""), True)
        idc.set_color(ea, idc.CIC_ITEM, 0x80D0FF)

    if ADD_USER_XREFS:
        for edge in REPORT.get("edges", []):
            source = _ea(edge["sourceOffset"])
            target = _ea(edge["targetOffset"])
            ida_xref.add_cref(source, target, ida_xref.fl_JN | ida_xref.XREF_USER)

    ida_kernwin.msg("[Trace UI] Applied {} dynamic blocks, {} edges, {} dispatcher candidates, {} opaque-branch candidates.\n".format(
        len(REPORT.get("blocks", [])),
        len(REPORT.get("edges", [])),
        len(REPORT.get("dispatcherCandidates", [])),
        len(REPORT.get("opaqueBranchCandidates", [])),
    ))


def export_ida_annotations(path=None):
    if path is None:
        path = ida_kernwin.ask_file(True, "*.json", "Export Trace UI IDA annotations")
    if not path:
        return None
    offsets = set()
    for block in REPORT.get("blocks", []):
        offsets.add(block["startOffset"])
    for candidate in REPORT.get("opaqueBranchCandidates", []):
        offsets.add(candidate["branchOffset"])
    annotations = []
    for offset in sorted(offsets, key=lambda value: int(value, 16)):
        ea = _ea(offset)
        name = ida_name.get_name(ea) or None
        comment = idc.get_cmt(ea, 0) or None
        repeatable = idc.get_cmt(ea, 1) or None
        if name or comment or repeatable:
            annotations.append({
                "offset": offset,
                "name": name,
                "comment": comment,
                "repeatableComment": repeatable,
            })
    payload = {
        "schema": SCHEMA,
        "moduleName": REPORT["scope"]["moduleName"],
        "imageBase": hex(_base()),
        "annotations": annotations,
    }
    with open(path, "w", encoding="utf-8") as output:
        json.dump(payload, output, ensure_ascii=False, indent=2)
    ida_kernwin.msg("[Trace UI] Exported {} annotations to {}\n".format(len(annotations), os.path.abspath(path)))
    return path


apply_trace_ui_report()
"##;
    let script = template
        .replace("__REPORT_JSON__", &report_literal)
        .replace("__IMAGE_BASE__", &base_literal)
        .replace(
            "__ADD_XREFS__",
            if add_user_xrefs { "True" } else { "False" },
        );
    Ok(IdaOllvmScript {
        file_name,
        script,
        schema_version: "trace-ui/ida-ollvm-v1".to_string(),
        warnings: vec![
            "The report contains executed paths only; unexecuted IDA basic blocks and alternate branches remain unknown.".to_string(),
            "Dispatcher and opaque-branch labels are evidence-ranked candidates, not automatic deobfuscation proof.".to_string(),
            "The script adds comments and colors. Dynamic user xrefs are opt-in and disabled by default.".to_string(),
            "Run export_ida_annotations() inside IDA to create a JSON file that Trace UI can import manually.".to_string(),
        ],
    })
}

pub fn parse_ida_annotation_bundle(bytes: &[u8]) -> Result<IdaAnnotationBundle, String> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("IDA annotation file exceeds 16 MiB".to_string());
    }
    let bundle: IdaAnnotationBundle = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid IDA annotation JSON: {error}"))?;
    if bundle.schema != "trace-ui/ida-ollvm-v1" {
        return Err(format!(
            "unsupported IDA annotation schema: {}",
            bundle.schema
        ));
    }
    if bundle.module_name.trim().is_empty() {
        return Err("IDA annotation moduleName must not be empty".to_string());
    }
    parse_hex_addr(&bundle.image_base)?;
    for annotation in &bundle.annotations {
        parse_hex_addr(&annotation.offset)?;
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> OllvmReport {
        OllvmReport {
            schema_version: "trace-ui/ollvm-v1".to_string(),
            scope: OllvmScope {
                session_id: "session".to_string(),
                node_id: Some(7),
                function_name: Some("target".to_string()),
                module_name: "libtarget.so".to_string(),
                module_base: "0x100000".to_string(),
                start_seq: 10,
                end_seq: 20,
                child_calls_excluded: 0,
            },
            executed_instruction_count: 4,
            unique_instruction_count: 4,
            block_count: 1,
            edge_count: 0,
            blocks: vec![DynamicBasicBlock {
                block_id: "libtarget.so+0x100".to_string(),
                module_name: "libtarget.so".to_string(),
                start_offset: "0x100".to_string(),
                end_offset: "0x10c".to_string(),
                start_address: "0x100100".to_string(),
                end_address: "0x10010c".to_string(),
                visit_count: 1,
                predecessor_count: 0,
                successor_count: 0,
                terminal_operation: "ret".to_string(),
                sample_seqs: vec![10],
                instructions: Vec::new(),
            }],
            edges: Vec::new(),
            dispatcher_candidates: Vec::new(),
            opaque_branch_candidates: Vec::new(),
            instructions_truncated: false,
            blocks_truncated: false,
            edges_truncated: false,
            limitations: Vec::new(),
            next_steps: Vec::new(),
        }
    }

    #[test]
    fn ida_script_uses_module_offsets_and_manual_export() {
        let generated =
            generate_ida_ollvm_script(&sample_report(), Some("0x400000"), false).unwrap();
        assert!(generated
            .script
            .contains("IDA_IMAGE_BASE_OVERRIDE = 0x400000"));
        assert!(generated.script.contains("def export_ida_annotations"));
        assert!(generated.script.contains("ADD_USER_XREFS = False"));
        assert!(generated.script.contains("0x100"));
    }

    #[test]
    fn annotation_bundle_rejects_wrong_schema() {
        let value =
            br#"{"schema":"wrong","moduleName":"lib.so","imageBase":"0x0","annotations":[]}"#;
        assert!(parse_ida_annotation_bundle(value).is_err());
    }
}
