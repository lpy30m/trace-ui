use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::query::elf_identity::{inspect_elf_layout, ElfBinaryIdentity, ElfBinaryLayout};
use crate::query::ollvm::OllvmReport;
use crate::utils::parse_hex_addr;

pub const COVERAGE_RECONCILIATION_SCHEMA: &str = "trace-ui/coverage-reconciliation-v1";
pub const COVERAGE_RECONCILIATION_INSPECTION_SCHEMA: &str =
    "trace-ui/coverage-reconciliation-inspection-v1";
pub const MAX_COVERAGE_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_COVERAGE_ITEMS: usize = 2_000_000;
const MAX_COVERAGE_RUNS: usize = 256;
const MAX_SAMPLE_OFFSETS: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageEdge {
    pub source_offset: String,
    pub target_offset: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageFunctionRange {
    pub start_offset: String,
    pub end_offset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageScope {
    pub kind: String,
    pub start_offset: String,
    pub end_offset: String,
    #[serde(default)]
    pub function_offsets: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageStaticInventory {
    pub source_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
    pub complete_for_scope: bool,
    pub instructions_truncated: bool,
    pub blocks_truncated: bool,
    pub branches_truncated: bool,
    pub functions_truncated: bool,
    pub edges_truncated: bool,
    #[serde(default)]
    pub instruction_offsets: Vec<String>,
    #[serde(default)]
    pub block_offsets: Vec<String>,
    #[serde(default)]
    pub branch_offsets: Vec<String>,
    #[serde(default)]
    pub functions: Vec<CoverageFunctionRange>,
    #[serde(default)]
    pub edges: Vec<CoverageEdge>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageDynamicRun {
    pub run_id: String,
    pub source_artifact_sha256: String,
    pub capture_complete_for_scope: bool,
    #[serde(default)]
    pub instruction_offsets: Vec<String>,
    #[serde(default)]
    pub block_offsets: Vec<String>,
    #[serde(default)]
    pub branch_offsets: Vec<String>,
    #[serde(default)]
    pub function_offsets: Vec<String>,
    #[serde(default)]
    pub edges: Vec<CoverageEdge>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageCounts {
    pub instructions: u64,
    pub blocks: u64,
    pub branches: u64,
    pub functions: u64,
    pub edges: u64,
}

impl CoverageCounts {
    fn is_zero(&self) -> bool {
        self.instructions == 0
            && self.blocks == 0
            && self.branches == 0
            && self.functions == 0
            && self.edges == 0
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageBasisPoints {
    pub instructions: u16,
    pub blocks: u16,
    pub branches: u16,
    pub functions: u16,
    pub edges: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageReconciliationSummary {
    pub static_counts: CoverageCounts,
    pub observed_static_counts: CoverageCounts,
    pub uncovered_counts: CoverageCounts,
    pub dynamic_only_counts: CoverageCounts,
    pub coverage_basis_points: CoverageBasisPoints,
    pub static_inventory_complete: bool,
    pub dynamic_capture_complete: bool,
    pub coverage_complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageReconciliationBundle {
    pub schema: String,
    pub module_name: String,
    pub architecture: String,
    pub binary_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    pub claim_scope: String,
    pub scope: CoverageScope,
    pub static_inventory: CoverageStaticInventory,
    pub dynamic_runs: Vec<CoverageDynamicRun>,
    pub summary: CoverageReconciliationSummary,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageOffsetSamples {
    pub instructions: Vec<String>,
    pub blocks: Vec<String>,
    pub branches: Vec<String>,
    pub functions: Vec<String>,
    pub edges: Vec<CoverageEdge>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageReconciliationInspectionReport {
    pub schema: String,
    pub status: String,
    pub module_name: String,
    pub claim_scope: String,
    pub exact_binary_identity: ElfBinaryIdentity,
    pub identity_matched: bool,
    pub source_provenance_matched: bool,
    pub missing_source_sha256s: Vec<String>,
    pub coverage_gate_met: bool,
    pub scope: CoverageScope,
    pub summary: CoverageReconciliationSummary,
    pub uncovered_samples: CoverageOffsetSamples,
    pub dynamic_only_samples: CoverageOffsetSamples,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageScriptScopeKind {
    Module,
    #[default]
    FunctionClosure,
    Range,
}

impl CoverageScriptScopeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Module => "module",
            Self::FunctionClosure => "function-closure",
            Self::Range => "range",
        }
    }
}

fn default_max_script_instructions() -> u32 {
    500_000
}

fn default_max_script_blocks() -> u32 {
    100_000
}

fn default_max_script_edges() -> u32 {
    250_000
}

fn default_max_script_functions() -> u32 {
    25_000
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoverageReconciliationScriptRequest {
    pub static_binary_path: String,
    pub ollvm_report_path: String,
    pub claim_scope: String,
    #[serde(default)]
    pub scope_kind: CoverageScriptScopeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_start_offset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_end_offset: Option<String>,
    #[serde(default = "default_max_script_instructions")]
    pub max_instructions: u32,
    #[serde(default = "default_max_script_blocks")]
    pub max_blocks: u32,
    #[serde(default = "default_max_script_edges")]
    pub max_edges: u32,
    #[serde(default = "default_max_script_functions")]
    pub max_functions: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageReconciliationScript {
    pub file_name: String,
    pub script: String,
    pub schema: String,
    pub module_name: String,
    pub claim_scope: String,
    pub expected_binary_identity: ElfBinaryIdentity,
    pub source_ollvm_sha256: String,
    pub warnings: Vec<String>,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical_offset(value: &str, label: &str) -> Result<(String, u64), String> {
    let parsed =
        parse_hex_addr(value).map_err(|error| format!("invalid {label} {value}: {error}"))?;
    let canonical = format!("0x{parsed:x}");
    if value != canonical {
        return Err(format!(
            "{label} must use canonical lowercase hexadecimal form {canonical}, got {value}"
        ));
    }
    if parsed & 3 != 0 {
        return Err(format!(
            "{label} must be 4-byte aligned for AArch64: {value}"
        ));
    }
    Ok((canonical, parsed))
}

fn validate_offsets(values: &[String], label: &str) -> Result<(), String> {
    if values.len() > MAX_COVERAGE_ITEMS {
        return Err(format!("{label} exceeds {MAX_COVERAGE_ITEMS} items"));
    }
    let mut previous = None;
    for value in values {
        let (_, parsed) = canonical_offset(value, label)?;
        if previous.is_some_and(|previous| parsed <= previous) {
            return Err(format!(
                "{label} must be strictly sorted and deduplicated by numeric offset"
            ));
        }
        previous = Some(parsed);
    }
    Ok(())
}

fn validate_edges(edges: &[CoverageEdge], label: &str) -> Result<(), String> {
    if edges.len() > MAX_COVERAGE_ITEMS {
        return Err(format!("{label} exceeds {MAX_COVERAGE_ITEMS} items"));
    }
    let mut previous = None;
    for edge in edges {
        let (_, source) = canonical_offset(&edge.source_offset, &format!("{label} sourceOffset"))?;
        let (_, target) = canonical_offset(&edge.target_offset, &format!("{label} targetOffset"))?;
        let key = (source, target);
        if previous.is_some_and(|previous| key <= previous) {
            return Err(format!(
                "{label} must be strictly sorted and deduplicated by source/target offsets"
            ));
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_functions(functions: &[CoverageFunctionRange]) -> Result<(), String> {
    if functions.len() > MAX_COVERAGE_ITEMS {
        return Err(format!(
            "coverage function inventory exceeds {MAX_COVERAGE_ITEMS} items"
        ));
    }
    let mut previous = None;
    for function in functions {
        let (_, start) = canonical_offset(&function.start_offset, "coverage function startOffset")?;
        let (_, end) = canonical_offset(&function.end_offset, "coverage function endOffset")?;
        if end < start {
            return Err(format!(
                "coverage function range ends before it starts: {}..{}",
                function.start_offset, function.end_offset
            ));
        }
        if previous.is_some_and(|previous| start <= previous) {
            return Err(
                "coverage functions must be strictly sorted and deduplicated by startOffset"
                    .to_string(),
            );
        }
        if function
            .name
            .as_deref()
            .is_some_and(|name| name.trim().is_empty() || name.chars().count() > 512)
        {
            return Err("coverage function name is empty or exceeds 512 characters".to_string());
        }
        previous = Some(start);
    }
    Ok(())
}

fn counts_from_sets(
    instructions: usize,
    blocks: usize,
    branches: usize,
    functions: usize,
    edges: usize,
) -> CoverageCounts {
    CoverageCounts {
        instructions: instructions.min(u64::MAX as usize) as u64,
        blocks: blocks.min(u64::MAX as usize) as u64,
        branches: branches.min(u64::MAX as usize) as u64,
        functions: functions.min(u64::MAX as usize) as u64,
        edges: edges.min(u64::MAX as usize) as u64,
    }
}

fn coverage_bp(observed: u64, total: u64) -> u16 {
    if total == 0 {
        10_000
    } else {
        observed
            .saturating_mul(10_000)
            .checked_div(total)
            .unwrap_or(0)
            .min(10_000) as u16
    }
}

fn difference_count<T: Ord>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> usize {
    left.difference(right).count()
}

fn intersection_count<T: Ord>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> usize {
    left.intersection(right).count()
}

fn static_function_offsets(bundle: &CoverageReconciliationBundle) -> BTreeSet<String> {
    bundle
        .static_inventory
        .functions
        .iter()
        .map(|function| function.start_offset.clone())
        .collect()
}

pub fn recompute_coverage_reconciliation_summary(
    bundle: &CoverageReconciliationBundle,
) -> CoverageReconciliationSummary {
    let static_instructions = bundle
        .static_inventory
        .instruction_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let static_blocks = bundle
        .static_inventory
        .block_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let static_branches = bundle
        .static_inventory
        .branch_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let static_functions = static_function_offsets(bundle);
    let static_edges = bundle
        .static_inventory
        .edges
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    let dynamic_instructions = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.instruction_offsets.iter().cloned())
        .collect::<BTreeSet<_>>();
    let dynamic_blocks = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.block_offsets.iter().cloned())
        .collect::<BTreeSet<_>>();
    let dynamic_branches = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.branch_offsets.iter().cloned())
        .collect::<BTreeSet<_>>();
    let dynamic_functions = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.function_offsets.iter().cloned())
        .collect::<BTreeSet<_>>();
    let dynamic_edges = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.edges.iter().cloned())
        .collect::<BTreeSet<_>>();

    let static_counts = counts_from_sets(
        static_instructions.len(),
        static_blocks.len(),
        static_branches.len(),
        static_functions.len(),
        static_edges.len(),
    );
    let observed_static_counts = counts_from_sets(
        intersection_count(&static_instructions, &dynamic_instructions),
        intersection_count(&static_blocks, &dynamic_blocks),
        intersection_count(&static_branches, &dynamic_branches),
        intersection_count(&static_functions, &dynamic_functions),
        intersection_count(&static_edges, &dynamic_edges),
    );
    let uncovered_counts = counts_from_sets(
        difference_count(&static_instructions, &dynamic_instructions),
        difference_count(&static_blocks, &dynamic_blocks),
        difference_count(&static_branches, &dynamic_branches),
        difference_count(&static_functions, &dynamic_functions),
        difference_count(&static_edges, &dynamic_edges),
    );
    let dynamic_only_counts = counts_from_sets(
        difference_count(&dynamic_instructions, &static_instructions),
        difference_count(&dynamic_blocks, &static_blocks),
        difference_count(&dynamic_branches, &static_branches),
        difference_count(&dynamic_functions, &static_functions),
        difference_count(&dynamic_edges, &static_edges),
    );
    let coverage_basis_points = CoverageBasisPoints {
        instructions: coverage_bp(
            observed_static_counts.instructions,
            static_counts.instructions,
        ),
        blocks: coverage_bp(observed_static_counts.blocks, static_counts.blocks),
        branches: coverage_bp(observed_static_counts.branches, static_counts.branches),
        functions: coverage_bp(observed_static_counts.functions, static_counts.functions),
        edges: coverage_bp(observed_static_counts.edges, static_counts.edges),
    };
    let static_inventory_complete = bundle.static_inventory.complete_for_scope
        && !bundle.static_inventory.instructions_truncated
        && !bundle.static_inventory.blocks_truncated
        && !bundle.static_inventory.branches_truncated
        && !bundle.static_inventory.functions_truncated
        && !bundle.static_inventory.edges_truncated;
    let dynamic_capture_complete = !bundle.dynamic_runs.is_empty()
        && bundle
            .dynamic_runs
            .iter()
            .all(|run| run.capture_complete_for_scope);
    let core_static_inventory_nonempty =
        static_counts.instructions > 0 && static_counts.blocks > 0 && static_counts.functions > 0;
    let coverage_complete = static_inventory_complete
        && dynamic_capture_complete
        && core_static_inventory_nonempty
        && uncovered_counts.is_zero()
        && dynamic_only_counts.is_zero();
    CoverageReconciliationSummary {
        static_counts,
        observed_static_counts,
        uncovered_counts,
        dynamic_only_counts,
        coverage_basis_points,
        static_inventory_complete,
        dynamic_capture_complete,
        coverage_complete,
    }
}

fn validate_bundle_structure(bundle: &CoverageReconciliationBundle) -> Result<(), String> {
    if bundle.schema != COVERAGE_RECONCILIATION_SCHEMA {
        return Err(format!(
            "unsupported coverage reconciliation schema: {}",
            bundle.schema
        ));
    }
    if bundle.module_name.trim().is_empty() || bundle.module_name.chars().count() > 512 {
        return Err("coverage moduleName is empty or exceeds 512 characters".to_string());
    }
    if bundle.architecture != "AArch64" {
        return Err(format!(
            "coverage architecture must be AArch64, got {}",
            bundle.architecture
        ));
    }
    if !valid_sha256(&bundle.binary_sha256) {
        return Err(
            "coverage binarySha256 must contain exactly 64 hexadecimal characters".to_string(),
        );
    }
    if bundle.claim_scope.trim().is_empty() || bundle.claim_scope.chars().count() > 500 {
        return Err("coverage claimScope is empty or exceeds 500 characters".to_string());
    }
    if !matches!(
        bundle.scope.kind.as_str(),
        "module" | "function-closure" | "range"
    ) {
        return Err(format!(
            "unsupported coverage scope kind: {}",
            bundle.scope.kind
        ));
    }
    let (_, scope_start) =
        canonical_offset(&bundle.scope.start_offset, "coverage scope startOffset")?;
    let (_, scope_end) = canonical_offset(&bundle.scope.end_offset, "coverage scope endOffset")?;
    if scope_end < scope_start {
        return Err("coverage scope endOffset is before startOffset".to_string());
    }
    validate_offsets(
        &bundle.scope.function_offsets,
        "coverage scope functionOffsets",
    )?;
    if bundle.static_inventory.source_kind.trim().is_empty()
        || bundle.static_inventory.source_kind.chars().count() > 128
    {
        return Err("coverage static sourceKind is empty or exceeds 128 characters".to_string());
    }
    if bundle
        .static_inventory
        .source_version
        .as_deref()
        .is_some_and(|value| value.trim().is_empty() || value.chars().count() > 256)
    {
        return Err("coverage static sourceVersion is empty or exceeds 256 characters".to_string());
    }
    validate_offsets(
        &bundle.static_inventory.instruction_offsets,
        "coverage static instructionOffsets",
    )?;
    validate_offsets(
        &bundle.static_inventory.block_offsets,
        "coverage static blockOffsets",
    )?;
    validate_offsets(
        &bundle.static_inventory.branch_offsets,
        "coverage static branchOffsets",
    )?;
    validate_functions(&bundle.static_inventory.functions)?;
    validate_edges(&bundle.static_inventory.edges, "coverage static edges")?;
    if bundle.dynamic_runs.is_empty() || bundle.dynamic_runs.len() > MAX_COVERAGE_RUNS {
        return Err(format!(
            "coverage dynamicRuns must contain between 1 and {MAX_COVERAGE_RUNS} runs"
        ));
    }
    let mut run_ids = HashSet::new();
    for run in &bundle.dynamic_runs {
        if run.run_id.trim().is_empty()
            || run.run_id.chars().count() > 256
            || !run_ids.insert(run.run_id.as_str())
        {
            return Err(format!(
                "coverage runId is empty, duplicated, or too long: {}",
                run.run_id
            ));
        }
        if !valid_sha256(&run.source_artifact_sha256) {
            return Err(format!(
                "coverage run {} sourceArtifactSha256 must contain 64 hexadecimal characters",
                run.run_id
            ));
        }
        validate_offsets(
            &run.instruction_offsets,
            &format!("coverage run {} instructionOffsets", run.run_id),
        )?;
        validate_offsets(
            &run.block_offsets,
            &format!("coverage run {} blockOffsets", run.run_id),
        )?;
        validate_offsets(
            &run.branch_offsets,
            &format!("coverage run {} branchOffsets", run.run_id),
        )?;
        validate_offsets(
            &run.function_offsets,
            &format!("coverage run {} functionOffsets", run.run_id),
        )?;
        validate_edges(&run.edges, &format!("coverage run {} edges", run.run_id))?;
    }
    if bundle.limitations.len() > 512
        || bundle
            .limitations
            .iter()
            .any(|value| value.trim().is_empty() || value.chars().count() > 2_000)
    {
        return Err("coverage limitations are empty, too long, or exceed 512 items".to_string());
    }

    let static_instructions = bundle
        .static_inventory
        .instruction_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let static_blocks = bundle
        .static_inventory
        .block_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for block in &static_blocks {
        if !static_instructions.contains(block) {
            return Err(format!(
                "coverage static block offset {block} is absent from static instructionOffsets"
            ));
        }
    }
    for branch in &bundle.static_inventory.branch_offsets {
        if !static_instructions.contains(branch) {
            return Err(format!(
                "coverage static branch offset {branch} is absent from static instructionOffsets"
            ));
        }
    }
    for function in &bundle.static_inventory.functions {
        if !static_blocks.contains(&function.start_offset)
            || !static_instructions.contains(&function.start_offset)
        {
            return Err(format!(
                "coverage function start {} must be present in static block/instruction inventories",
                function.start_offset
            ));
        }
    }
    let static_function_starts = static_function_offsets(bundle);
    let declared_scope_functions = bundle
        .scope
        .function_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if declared_scope_functions != static_function_starts {
        return Err(
            "coverage scope functionOffsets must exactly equal static function start offsets"
                .to_string(),
        );
    }
    for edge in &bundle.static_inventory.edges {
        if !static_blocks.contains(&edge.source_offset)
            || !static_blocks.contains(&edge.target_offset)
        {
            return Err(format!(
                "coverage static edge {} -> {} must reference static block starts",
                edge.source_offset, edge.target_offset
            ));
        }
    }

    let recomputed = recompute_coverage_reconciliation_summary(bundle);
    if bundle.summary != recomputed {
        return Err(format!(
            "coverage summary does not match recomputed inventories; declared={:?}, recomputed={:?}",
            bundle.summary, recomputed
        ));
    }
    Ok(())
}

pub fn parse_coverage_reconciliation_bundle(
    bytes: &[u8],
) -> Result<CoverageReconciliationBundle, String> {
    if bytes.len() > MAX_COVERAGE_ARTIFACT_BYTES {
        return Err(format!(
            "coverage reconciliation artifact exceeds {} MiB",
            MAX_COVERAGE_ARTIFACT_BYTES / (1024 * 1024)
        ));
    }
    let bundle: CoverageReconciliationBundle = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid coverage reconciliation JSON: {error}"))?;
    validate_bundle_structure(&bundle)?;
    Ok(bundle)
}

fn executable_ranges(layout: &ElfBinaryLayout) -> Result<Vec<(u64, u64)>, String> {
    let mut ranges = Vec::new();
    for segment in layout
        .load_segments
        .iter()
        .filter(|segment| segment.executable && segment.file_size > 0)
    {
        let start = segment
            .virtual_address
            .checked_sub(layout.load_base_vaddr)
            .ok_or("ELF executable segment is below the load base")?;
        let end = start
            .checked_add(segment.file_size)
            .ok_or("ELF executable segment range overflow")?;
        ranges.push((start, end));
    }
    if ranges.is_empty() {
        return Err("exact ELF has no file-backed executable PT_LOAD bytes".to_string());
    }
    Ok(ranges)
}

fn offset_in_executable_ranges(offset: u64, ranges: &[(u64, u64)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| offset >= *start && offset < *end)
}

fn validate_offset_against_elf(
    value: &str,
    label: &str,
    scope_start: u64,
    scope_end: u64,
    ranges: &[(u64, u64)],
) -> Result<(), String> {
    let (_, offset) = canonical_offset(value, label)?;
    if offset < scope_start || offset > scope_end {
        return Err(format!(
            "{label} {value} falls outside the declared coverage scope"
        ));
    }
    if !offset_in_executable_ranges(offset, ranges) {
        return Err(format!(
            "{label} {value} falls outside file-backed executable PT_LOAD bytes of the exact ELF"
        ));
    }
    Ok(())
}

fn validate_bundle_against_elf(
    bundle: &CoverageReconciliationBundle,
    layout: &ElfBinaryLayout,
) -> Result<(), String> {
    if layout.identity.elf_machine != 183 {
        return Err(format!(
            "coverage reconciliation accepts only AArch64 exact ELF files; selected {} has e_machine {}",
            layout.identity.architecture, layout.identity.elf_machine
        ));
    }
    let ranges = executable_ranges(layout)?;
    let (_, scope_start) =
        canonical_offset(&bundle.scope.start_offset, "coverage scope startOffset")?;
    let (_, scope_end) = canonical_offset(&bundle.scope.end_offset, "coverage scope endOffset")?;
    if !offset_in_executable_ranges(scope_start, &ranges)
        || !offset_in_executable_ranges(scope_end, &ranges)
    {
        return Err(
            "coverage scope start/end must both fall within file-backed executable PT_LOAD bytes"
                .to_string(),
        );
    }

    for value in bundle
        .static_inventory
        .instruction_offsets
        .iter()
        .chain(&bundle.static_inventory.block_offsets)
        .chain(&bundle.static_inventory.branch_offsets)
        .chain(&bundle.scope.function_offsets)
    {
        validate_offset_against_elf(
            value,
            "coverage static offset",
            scope_start,
            scope_end,
            &ranges,
        )?;
    }
    for function in &bundle.static_inventory.functions {
        validate_offset_against_elf(
            &function.start_offset,
            "coverage function startOffset",
            scope_start,
            scope_end,
            &ranges,
        )?;
        validate_offset_against_elf(
            &function.end_offset,
            "coverage function endOffset",
            scope_start,
            scope_end,
            &ranges,
        )?;
    }
    for edge in &bundle.static_inventory.edges {
        validate_offset_against_elf(
            &edge.source_offset,
            "coverage static edge sourceOffset",
            scope_start,
            scope_end,
            &ranges,
        )?;
        validate_offset_against_elf(
            &edge.target_offset,
            "coverage static edge targetOffset",
            scope_start,
            scope_end,
            &ranges,
        )?;
    }
    for run in &bundle.dynamic_runs {
        for value in run
            .instruction_offsets
            .iter()
            .chain(&run.block_offsets)
            .chain(&run.branch_offsets)
            .chain(&run.function_offsets)
        {
            validate_offset_against_elf(
                value,
                &format!("coverage run {} offset", run.run_id),
                scope_start,
                scope_end,
                &ranges,
            )?;
        }
        for edge in &run.edges {
            validate_offset_against_elf(
                &edge.source_offset,
                &format!("coverage run {} edge sourceOffset", run.run_id),
                scope_start,
                scope_end,
                &ranges,
            )?;
            validate_offset_against_elf(
                &edge.target_offset,
                &format!("coverage run {} edge targetOffset", run.run_id),
                scope_start,
                scope_end,
                &ranges,
            )?;
        }
    }
    Ok(())
}

fn sample_difference<T: Ord + Clone>(left: &BTreeSet<T>, right: &BTreeSet<T>) -> Vec<T> {
    left.difference(right)
        .take(MAX_SAMPLE_OFFSETS)
        .cloned()
        .collect()
}

fn offset_samples(bundle: &CoverageReconciliationBundle, uncovered: bool) -> CoverageOffsetSamples {
    let static_instructions = bundle
        .static_inventory
        .instruction_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let static_blocks = bundle
        .static_inventory
        .block_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let static_branches = bundle
        .static_inventory
        .branch_offsets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let static_functions = static_function_offsets(bundle);
    let static_edges = bundle
        .static_inventory
        .edges
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let dynamic_instructions = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.instruction_offsets.iter().cloned())
        .collect::<BTreeSet<_>>();
    let dynamic_blocks = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.block_offsets.iter().cloned())
        .collect::<BTreeSet<_>>();
    let dynamic_branches = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.branch_offsets.iter().cloned())
        .collect::<BTreeSet<_>>();
    let dynamic_functions = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.function_offsets.iter().cloned())
        .collect::<BTreeSet<_>>();
    let dynamic_edges = bundle
        .dynamic_runs
        .iter()
        .flat_map(|run| run.edges.iter().cloned())
        .collect::<BTreeSet<_>>();
    if uncovered {
        CoverageOffsetSamples {
            instructions: sample_difference(&static_instructions, &dynamic_instructions),
            blocks: sample_difference(&static_blocks, &dynamic_blocks),
            branches: sample_difference(&static_branches, &dynamic_branches),
            functions: sample_difference(&static_functions, &dynamic_functions),
            edges: sample_difference(&static_edges, &dynamic_edges),
        }
    } else {
        CoverageOffsetSamples {
            instructions: sample_difference(&dynamic_instructions, &static_instructions),
            blocks: sample_difference(&dynamic_blocks, &static_blocks),
            branches: sample_difference(&dynamic_branches, &static_branches),
            functions: sample_difference(&dynamic_functions, &static_functions),
            edges: sample_difference(&dynamic_edges, &static_edges),
        }
    }
}

pub fn inspect_coverage_reconciliation_bundle(
    bundle: &CoverageReconciliationBundle,
    exact_binary_path: &str,
    allowed_source_sha256s: &[String],
) -> Result<CoverageReconciliationInspectionReport, String> {
    validate_bundle_structure(bundle)?;
    let layout = inspect_elf_layout(exact_binary_path)?;
    let build_id_matched = bundle.build_id.as_ref().map_or(true, |expected| {
        layout
            .identity
            .build_id
            .as_ref()
            .is_some_and(|actual| expected.eq_ignore_ascii_case(actual))
    });
    let identity_matched = bundle
        .binary_sha256
        .eq_ignore_ascii_case(&layout.identity.binary_sha256)
        && build_id_matched;
    if identity_matched {
        validate_bundle_against_elf(bundle, &layout)?;
    }
    let allowed = allowed_source_sha256s
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let missing_source_sha256s = bundle
        .dynamic_runs
        .iter()
        .map(|run| run.source_artifact_sha256.to_ascii_lowercase())
        .filter(|sha256| !allowed.contains(sha256))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let source_provenance_matched = missing_source_sha256s.is_empty();
    let summary = recompute_coverage_reconciliation_summary(bundle);
    let coverage_gate_met =
        identity_matched && source_provenance_matched && summary.coverage_complete;
    let status = if !identity_matched {
        "identity-mismatch"
    } else if !source_provenance_matched {
        "source-provenance-mismatch"
    } else if summary.coverage_complete {
        "complete-site-coverage"
    } else {
        "partial-site-coverage"
    };
    let mut warnings = Vec::new();
    if !identity_matched {
        warnings.push(format!(
            "Coverage artifact binary identity {} does not match exact ELF {}.",
            bundle.binary_sha256, layout.identity.binary_sha256
        ));
    }
    if !source_provenance_matched {
        warnings.push(format!(
            "{} dynamic source artifact SHA-256 value(s) are not bound as allowed provenance.",
            missing_source_sha256s.len()
        ));
    }
    if !summary.static_inventory_complete {
        warnings.push(
            "The static inventory is declared incomplete or truncated; unlisted static sites remain unknown."
                .to_string(),
        );
    }
    if !summary.dynamic_capture_complete {
        warnings.push(
            "At least one dynamic run is incomplete for the declared scope; unrecorded execution remains unknown."
                .to_string(),
        );
    }
    if !summary.uncovered_counts.is_zero() {
        warnings.push(format!(
            "Uncovered static sites remain: instructions={}, blocks={}, branches={}, functions={}, edges={}.",
            summary.uncovered_counts.instructions,
            summary.uncovered_counts.blocks,
            summary.uncovered_counts.branches,
            summary.uncovered_counts.functions,
            summary.uncovered_counts.edges
        ));
    }
    if !summary.dynamic_only_counts.is_zero() {
        warnings.push(format!(
            "Dynamic-only sites conflict with the supplied static inventory: instructions={}, blocks={}, branches={}, functions={}, edges={}.",
            summary.dynamic_only_counts.instructions,
            summary.dynamic_only_counts.blocks,
            summary.dynamic_only_counts.branches,
            summary.dynamic_only_counts.functions,
            summary.dynamic_only_counts.edges
        ));
    }
    let mut limitations = bundle.limitations.clone();
    limitations.extend([
        "Coverage reconciliation limits the maximum defensible claim level; it never proves algorithm semantics, infeasibility, reachability for all inputs, or deobfuscation by itself."
            .to_string(),
        "A static CFG/function inventory is tool-discoverable structure for one exact ELF, not an oracle for all indirect targets or embedded code/data distinctions."
            .to_string(),
        "A dynamic union shows sites observed in the supplied controlled runs only. Unexecuted paths and untested machine/input states remain unknown."
            .to_string(),
        "OLLVM, angr, IDA, and Unicorn structural conclusions remain Candidate/Related even when every listed static site was observed."
            .to_string(),
    ]);
    limitations.sort();
    limitations.dedup();
    Ok(CoverageReconciliationInspectionReport {
        schema: COVERAGE_RECONCILIATION_INSPECTION_SCHEMA.to_string(),
        status: status.to_string(),
        module_name: bundle.module_name.clone(),
        claim_scope: bundle.claim_scope.clone(),
        exact_binary_identity: layout.identity,
        identity_matched,
        source_provenance_matched,
        missing_source_sha256s,
        coverage_gate_met,
        scope: bundle.scope.clone(),
        summary,
        uncovered_samples: offset_samples(bundle, true),
        dynamic_only_samples: offset_samples(bundle, false),
        warnings,
        limitations,
    })
}

pub fn inspect_coverage_reconciliation(
    artifact_path: &str,
    exact_binary_path: &str,
    source_artifact_paths: &[String],
) -> Result<CoverageReconciliationInspectionReport, String> {
    let bytes = fs::read(artifact_path)
        .map_err(|error| format!("failed to read coverage artifact '{artifact_path}': {error}"))?;
    let bundle = parse_coverage_reconciliation_bundle(&bytes)?;
    let mut source_sha256s = Vec::with_capacity(source_artifact_paths.len());
    for path in source_artifact_paths {
        let bytes = fs::read(path).map_err(|error| {
            format!("failed to read coverage source artifact '{path}': {error}")
        })?;
        source_sha256s.push(sha256_hex(&bytes));
    }
    inspect_coverage_reconciliation_bundle(&bundle, exact_binary_path, &source_sha256s)
}

fn sanitize_file_component(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
            output.push(character);
        } else if !output.ends_with('_') {
            output.push('_');
        }
    }
    let output = output.trim_matches('_');
    if output.is_empty() {
        "coverage".to_string()
    } else {
        output.to_string()
    }
}

fn validate_script_limit(value: u32, label: &str, maximum: u32) -> Result<(), String> {
    if value == 0 || value > maximum {
        return Err(format!("{label} must be between 1 and {maximum}"));
    }
    Ok(())
}

pub fn generate_coverage_reconciliation_script(
    request: &CoverageReconciliationScriptRequest,
) -> Result<CoverageReconciliationScript, String> {
    if request.claim_scope.trim().is_empty() || request.claim_scope.chars().count() > 500 {
        return Err("coverage claimScope is empty or exceeds 500 characters".to_string());
    }
    validate_script_limit(request.max_instructions, "maxInstructions", 2_000_000)?;
    validate_script_limit(request.max_blocks, "maxBlocks", 500_000)?;
    validate_script_limit(request.max_edges, "maxEdges", 1_000_000)?;
    validate_script_limit(request.max_functions, "maxFunctions", 100_000)?;

    let layout = inspect_elf_layout(request.static_binary_path.trim())?;
    if layout.identity.elf_machine != 183 {
        return Err(format!(
            "coverage script requires an AArch64 exact ELF; selected {} has e_machine {}",
            layout.identity.architecture, layout.identity.elf_machine
        ));
    }
    let report_bytes = fs::read(request.ollvm_report_path.trim()).map_err(|error| {
        format!(
            "failed to read OLLVM report '{}': {error}",
            request.ollvm_report_path
        )
    })?;
    if report_bytes.len() > MAX_COVERAGE_ARTIFACT_BYTES {
        return Err("OLLVM report exceeds 64 MiB".to_string());
    }
    let report: OllvmReport = serde_json::from_slice(&report_bytes)
        .map_err(|error| format!("invalid OLLVM report JSON: {error}"))?;
    if report.schema_version != "trace-ui/ollvm-v1" {
        return Err(format!(
            "unsupported OLLVM report schema: {}",
            report.schema_version
        ));
    }
    if report.scope.module_name.trim().is_empty() {
        return Err("OLLVM report moduleName must not be empty".to_string());
    }

    let (range_start, range_end) = match request.scope_kind {
        CoverageScriptScopeKind::Range => {
            let start = request
                .range_start_offset
                .as_deref()
                .ok_or("range scope requires rangeStartOffset")?;
            let end = request
                .range_end_offset
                .as_deref()
                .ok_or("range scope requires rangeEndOffset")?;
            let (start_canonical, start_value) = canonical_offset(start, "rangeStartOffset")?;
            let (end_canonical, end_value) = canonical_offset(end, "rangeEndOffset")?;
            if end_value < start_value {
                return Err("rangeEndOffset is before rangeStartOffset".to_string());
            }
            let ranges = executable_ranges(&layout)?;
            if !offset_in_executable_ranges(start_value, &ranges)
                || !offset_in_executable_ranges(end_value, &ranges)
            {
                return Err(
                    "coverage range start/end must fall in file-backed executable PT_LOAD bytes"
                        .to_string(),
                );
            }
            (Some(start_canonical), Some(end_canonical))
        }
        _ => {
            if request.range_start_offset.is_some() || request.range_end_offset.is_some() {
                return Err(
                    "rangeStartOffset/rangeEndOffset are accepted only with scopeKind=range"
                        .to_string(),
                );
            }
            (None, None)
        }
    };

    let report_json = serde_json::to_string(&report)
        .map_err(|error| format!("failed to serialize embedded OLLVM report: {error}"))?;
    let report_literal = serde_json::to_string(&report_json)
        .map_err(|error| format!("failed to quote embedded OLLVM report: {error}"))?;
    let identity_json = serde_json::to_string(&layout.identity)
        .map_err(|error| format!("failed to serialize exact ELF identity: {error}"))?;
    let identity_literal = serde_json::to_string(&identity_json)
        .map_err(|error| format!("failed to quote exact ELF identity: {error}"))?;
    let claim_scope_literal = serde_json::to_string(request.claim_scope.trim())
        .map_err(|error| format!("failed to quote coverage claim scope: {error}"))?;
    let source_ollvm_sha256 = sha256_hex(&report_bytes);
    let source_sha_literal = serde_json::to_string(&source_ollvm_sha256)
        .map_err(|error| format!("failed to quote OLLVM SHA-256: {error}"))?;
    let range_start_literal = range_start
        .as_ref()
        .map(|value| serde_json::to_string(value))
        .transpose()
        .map_err(|error| format!("failed to quote rangeStartOffset: {error}"))?
        .unwrap_or_else(|| "None".to_string());
    let range_end_literal = range_end
        .as_ref()
        .map(|value| serde_json::to_string(value))
        .transpose()
        .map_err(|error| format!("failed to quote rangeEndOffset: {error}"))?
        .unwrap_or_else(|| "None".to_string());

    let template = r###"#!/usr/bin/env python3
# Trace UI coverage reconciliation exporter
# Schema: trace-ui/coverage-reconciliation-v1
# Trace UI generated this file but does not install or execute angr or the target.
import argparse
import hashlib
import json
import os

import angr

SCHEMA = "trace-ui/coverage-reconciliation-v1"
REPORT = json.loads(__REPORT_JSON__)
EXPECTED_BINARY = json.loads(__EXPECTED_BINARY_JSON__)
CLAIM_SCOPE = __CLAIM_SCOPE__
SOURCE_OLLVM_SHA256 = __SOURCE_OLLVM_SHA256__
SCOPE_KIND = "__SCOPE_KIND__"
RANGE_START = __RANGE_START__
RANGE_END = __RANGE_END__
MAX_INSTRUCTIONS = __MAX_INSTRUCTIONS__
MAX_BLOCKS = __MAX_BLOCKS__
MAX_EDGES = __MAX_EDGES__
MAX_FUNCTIONS = __MAX_FUNCTIONS__


def _offset(value):
    return int(value, 16) if isinstance(value, str) else int(value)


def _hex(value):
    return hex(int(value))


def _main_offset(project, address):
    main = project.loader.main_object
    if main.min_addr <= address <= main.max_addr:
        return address - main.mapped_base
    return None


def _main_node(project, node):
    return node is not None and _main_offset(project, int(node.addr)) is not None


def _sorted_hex(values):
    return [_hex(value) for value in sorted(set(int(value) for value in values))]


def _sorted_edges(values):
    return [
        {"sourceOffset": _hex(source), "targetOffset": _hex(target)}
        for source, target in sorted(set((int(source), int(target)) for source, target in values))
    ]


def _bounded(values, maximum):
    ordered = sorted(set(values))
    return ordered[:maximum], len(ordered) > maximum


def _basis_points(observed, total):
    return 10000 if total == 0 else min(10000, (observed * 10000) // total)


def _edge_set(items):
    return set((item["sourceOffset"].lower(), item["targetOffset"].lower()) for item in items)


def _summary(static_inventory, dynamic_runs):
    static = {
        "instructions": set(static_inventory["instructionOffsets"]),
        "blocks": set(static_inventory["blockOffsets"]),
        "branches": set(static_inventory["branchOffsets"]),
        "functions": set(item["startOffset"] for item in static_inventory["functions"]),
        "edges": _edge_set(static_inventory["edges"]),
    }
    dynamic = {
        "instructions": set(),
        "blocks": set(),
        "branches": set(),
        "functions": set(),
        "edges": set(),
    }
    for run in dynamic_runs:
        dynamic["instructions"].update(run["instructionOffsets"])
        dynamic["blocks"].update(run["blockOffsets"])
        dynamic["branches"].update(run["branchOffsets"])
        dynamic["functions"].update(run["functionOffsets"])
        dynamic["edges"].update(_edge_set(run["edges"]))
    static_counts = {name: len(values) for name, values in static.items()}
    observed = {name: len(static[name] & dynamic[name]) for name in static}
    uncovered = {name: len(static[name] - dynamic[name]) for name in static}
    dynamic_only = {name: len(dynamic[name] - static[name]) for name in static}
    basis = {name: _basis_points(observed[name], static_counts[name]) for name in static}
    static_complete = bool(static_inventory["completeForScope"]) and not any(
        static_inventory[name]
        for name in (
            "instructionsTruncated",
            "blocksTruncated",
            "branchesTruncated",
            "functionsTruncated",
            "edgesTruncated",
        )
    )
    dynamic_complete = bool(dynamic_runs) and all(run["captureCompleteForScope"] for run in dynamic_runs)
    core_nonempty = static_counts["instructions"] > 0 and static_counts["blocks"] > 0 and static_counts["functions"] > 0
    coverage_complete = static_complete and dynamic_complete and core_nonempty and not any(uncovered.values()) and not any(dynamic_only.values())
    def _counts(values):
        return {
            "instructions": values["instructions"],
            "blocks": values["blocks"],
            "branches": values["branches"],
            "functions": values["functions"],
            "edges": values["edges"],
        }
    return {
        "staticCounts": _counts(static_counts),
        "observedStaticCounts": _counts(observed),
        "uncoveredCounts": _counts(uncovered),
        "dynamicOnlyCounts": _counts(dynamic_only),
        "coverageBasisPoints": _counts(basis),
        "staticInventoryComplete": static_complete,
        "dynamicCaptureComplete": dynamic_complete,
        "coverageComplete": coverage_complete,
    }


def _function_for_node(cfg, node):
    function_address = getattr(node, "function_address", None)
    if function_address is not None:
        return cfg.kb.functions.get(function_address)
    try:
        return cfg.kb.functions.floor_func(node.addr)
    except Exception:
        return None


def _select_scope(project, cfg, warnings):
    main = project.loader.main_object
    dynamic_offsets = sorted(set(_offset(block["startOffset"]) for block in REPORT.get("blocks", [])))
    all_nodes = [node for node in cfg.graph.nodes() if _main_node(project, node)]
    selected_nodes = {}
    functions = {}
    mapping_complete = True
    if SCOPE_KIND == "module":
        for node in all_nodes:
            selected_nodes[int(node.addr)] = node
        for function in cfg.kb.functions.values():
            if _main_offset(project, int(function.addr)) is not None:
                functions[int(function.addr)] = function
    elif SCOPE_KIND == "range":
        start = _offset(RANGE_START)
        end = _offset(RANGE_END)
        for node in all_nodes:
            offset = int(node.addr) - main.mapped_base
            if start <= offset <= end:
                selected_nodes[int(node.addr)] = node
                function = _function_for_node(cfg, node)
                if function is not None:
                    functions[int(function.addr)] = function
    else:
        for offset in dynamic_offsets:
            address = main.mapped_base + offset
            node = cfg.model.get_any_node(address, anyaddr=True)
            if not _main_node(project, node):
                mapping_complete = False
                warnings.append("No main-object CFG node maps dynamic block {}.".format(_hex(offset)))
                continue
            function = _function_for_node(cfg, node)
            if function is None:
                mapping_complete = False
                warnings.append("No CFG function maps dynamic block {}.".format(_hex(offset)))
                selected_nodes[int(node.addr)] = node
                continue
            functions[int(function.addr)] = function
        for function in functions.values():
            for address in getattr(function, "block_addrs_set", set()):
                node = cfg.model.get_any_node(address, anyaddr=True)
                if _main_node(project, node):
                    selected_nodes[int(node.addr)] = node
                else:
                    mapping_complete = False
                    warnings.append("Function {} contains an unmapped/non-main CFG block at {}.".format(getattr(function, "name", "?"), hex(address)))
    if not selected_nodes:
        raise RuntimeError("no static CFG nodes were selected for the requested coverage scope")
    return selected_nodes, functions, mapping_complete


def _static_inventory(project, cfg):
    warnings = []
    main = project.loader.main_object
    selected_nodes, selected_functions, mapping_complete = _select_scope(project, cfg, warnings)
    selected_addresses = set(selected_nodes)
    block_addresses, blocks_truncated = _bounded(selected_addresses, MAX_BLOCKS)
    selected_addresses = set(block_addresses)
    if blocks_truncated:
        warnings.append("Static block inventory reached MAX_BLOCKS={}.".format(MAX_BLOCKS))

    instruction_addresses = set()
    branch_addresses = set()
    instruction_failed = False
    for address in sorted(selected_addresses):
        node = selected_nodes[address]
        size = int(getattr(node, "size", 0) or 0)
        if size <= 0:
            instruction_failed = True
            warnings.append("CFG node {} has no positive size.".format(hex(address)))
            continue
        try:
            instructions = list(project.factory.block(address, size=size).capstone.insns)
        except Exception as error:
            instruction_failed = True
            warnings.append("Capstone failed at {}: {}".format(hex(address), error))
            continue
        if not instructions:
            instruction_failed = True
            warnings.append("Capstone returned no instructions at {}.".format(hex(address)))
            continue
        for instruction in instructions:
            if _main_offset(project, int(instruction.address)) is not None:
                instruction_addresses.add(int(instruction.address))
        outgoing = [target for target in cfg.graph.successors(node) if int(getattr(target, "addr", -1)) in selected_addresses]
        mnemonic = str(getattr(instructions[-1].insn, "mnemonic", "")).lower()
        is_branch = len(outgoing) > 1 or mnemonic.startswith(("b.", "cb", "tb")) or mnemonic in ("b", "br")
        if is_branch:
            branch_addresses.add(int(instructions[-1].address))

    instruction_addresses, instructions_truncated = _bounded(instruction_addresses, MAX_INSTRUCTIONS)
    branch_addresses = sorted(branch_addresses)
    if instructions_truncated:
        warnings.append("Static instruction inventory reached MAX_INSTRUCTIONS={}.".format(MAX_INSTRUCTIONS))

    edge_addresses = set()
    for source_address in selected_addresses:
        source = selected_nodes[source_address]
        for target in cfg.graph.successors(source):
            target_address = int(getattr(target, "addr", -1))
            if target_address in selected_addresses:
                edge_addresses.add((source_address, target_address))
    edge_addresses, edges_truncated = _bounded(edge_addresses, MAX_EDGES)
    if edges_truncated:
        warnings.append("Static edge inventory reached MAX_EDGES={}.".format(MAX_EDGES))

    function_items = []
    for function in selected_functions.values():
        addresses = sorted(address for address in getattr(function, "block_addrs_set", set()) if address in selected_addresses)
        if not addresses:
            continue
        start = addresses[0]
        end = start
        for address in addresses:
            node = selected_nodes[address]
            size = int(getattr(node, "size", 0) or 0)
            end = max(end, address + max(4, size) - 4)
        function_items.append((start, end, getattr(function, "name", None)))
    if not function_items:
        start = min(selected_addresses)
        end = max(address + max(4, int(getattr(selected_nodes[address], "size", 0) or 0)) - 4 for address in selected_addresses)
        function_items.append((start, end, REPORT.get("scope", {}).get("functionName")))
        mapping_complete = False
        warnings.append("No CFG function inventory was available; emitted one fallback selected-range function.")
    function_items, functions_truncated = _bounded(function_items, MAX_FUNCTIONS)
    if functions_truncated:
        warnings.append("Static function inventory reached MAX_FUNCTIONS={}.".format(MAX_FUNCTIONS))

    block_offsets = _sorted_hex(address - main.mapped_base for address in selected_addresses)
    instruction_offsets = _sorted_hex(address - main.mapped_base for address in instruction_addresses)
    branch_offsets = _sorted_hex(address - main.mapped_base for address in branch_addresses)
    functions = [
        {
            "startOffset": _hex(start - main.mapped_base),
            "endOffset": _hex(end - main.mapped_base),
            "name": name,
        }
        for start, end, name in sorted(function_items)
    ]
    edges = _sorted_edges((source - main.mapped_base, target - main.mapped_base) for source, target in edge_addresses)
    complete = mapping_complete and not instruction_failed and not any((instructions_truncated, blocks_truncated, functions_truncated, edges_truncated))
    return {
        "sourceKind": "angr-{}".format(getattr(cfg, "_model", None).__class__.__name__ if getattr(cfg, "_model", None) is not None else "cfgfast"),
        "sourceVersion": getattr(angr, "__version__", "unknown"),
        "completeForScope": complete,
        "instructionsTruncated": instructions_truncated,
        "blocksTruncated": blocks_truncated,
        "branchesTruncated": False,
        "functionsTruncated": functions_truncated,
        "edgesTruncated": edges_truncated,
        "instructionOffsets": instruction_offsets,
        "blockOffsets": block_offsets,
        "branchOffsets": branch_offsets,
        "functions": functions,
        "edges": edges,
    }, warnings, selected_nodes, functions


def _dynamic_run(project, cfg, selected_nodes, functions):
    main = project.loader.main_object
    instruction_offsets = set()
    block_offsets = set()
    branch_offsets = set()
    function_offsets = set()
    edges = set()
    instructions_missing = False
    function_by_block = {}
    for function in functions:
        start = _offset(function["startOffset"])
        begin = start
        end = _offset(function["endOffset"])
        for block in selected_nodes:
            offset = block - main.mapped_base
            if begin <= offset <= end:
                function_by_block[offset] = start
    for block in REPORT.get("blocks", []):
        block_offset = _offset(block["startOffset"])
        block_offsets.add(block_offset)
        instructions = block.get("instructions", [])
        if not instructions:
            instructions_missing = True
        for instruction in instructions:
            instruction_offsets.add(_offset(instruction["offset"]))
        mapped_function = function_by_block.get(block_offset)
        if mapped_function is None:
            address = main.mapped_base + block_offset
            node = cfg.model.get_any_node(address, anyaddr=True)
            function = _function_for_node(cfg, node) if node is not None else None
            if function is not None:
                candidates = [item for item in functions if _offset(item["startOffset"]) <= block_offset <= _offset(item["endOffset"])]
                if candidates:
                    mapped_function = _offset(candidates[0]["startOffset"])
        if mapped_function is not None:
            function_offsets.add(mapped_function)
    for profile in REPORT.get("branchProfiles", []):
        branch_offsets.add(_offset(profile["branchOffset"]))
    for candidate in REPORT.get("opaqueBranchCandidates", []):
        branch_offsets.add(_offset(candidate["branchOffset"]))
    for edge in REPORT.get("edges", []):
        edges.add((_offset(edge["sourceOffset"]), _offset(edge["targetOffset"])))
    capture_complete = not any((
        REPORT.get("instructionsTruncated", False),
        REPORT.get("blocksTruncated", False),
        REPORT.get("edgesTruncated", False),
        instructions_missing,
    ))
    return {
        "runId": REPORT.get("scope", {}).get("sessionId", "ollvm-run"),
        "sourceArtifactSha256": SOURCE_OLLVM_SHA256,
        "captureCompleteForScope": capture_complete,
        "instructionOffsets": _sorted_hex(instruction_offsets),
        "blockOffsets": _sorted_hex(block_offsets),
        "branchOffsets": _sorted_hex(branch_offsets),
        "functionOffsets": _sorted_hex(function_offsets),
        "edges": _sorted_edges(edges),
    }


def analyze(binary_path):
    with open(binary_path, "rb") as source:
        binary_sha256 = hashlib.sha256(source.read()).hexdigest()
    if binary_sha256.lower() != EXPECTED_BINARY["binarySha256"].lower():
        raise RuntimeError("exact ELF identity mismatch: expected {}, got {}".format(EXPECTED_BINARY["binarySha256"], binary_sha256))
    project = angr.Project(binary_path, auto_load_libs=False)
    architecture = str(project.arch.name)
    if "AARCH64" not in architecture.upper() and "ARM64" not in architecture.upper():
        raise RuntimeError("selected exact ELF is not AArch64 according to angr: {}".format(architecture))
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
    static_inventory, warnings, selected_nodes, functions = _static_inventory(project, cfg)
    dynamic_run = _dynamic_run(project, cfg, selected_nodes, functions)
    starts = [_offset(value) for value in static_inventory["instructionOffsets"]]
    if not starts:
        raise RuntimeError("static coverage inventory contains no instructions")
    scope = {
        "kind": SCOPE_KIND,
        "startOffset": _hex(min(starts)),
        "endOffset": _hex(max(starts)),
        "functionOffsets": [item["startOffset"] for item in static_inventory["functions"]],
    }
    if SCOPE_KIND == "range":
        scope["startOffset"] = RANGE_START.lower()
        scope["endOffset"] = RANGE_END.lower()
    dynamic_runs = [dynamic_run]
    summary = _summary(static_inventory, dynamic_runs)
    limitations = [
        "The static inventory is angr CFG-discoverable structure for one exact ELF and can miss indirect targets or misclassify embedded code/data.",
        "The dynamic inventory contains only executed sites present in the embedded OLLVM report; unexecuted paths and untested states remain unknown.",
        "Coverage can only cap a claim's maximum evidence level. It cannot prove crypto semantics, global opacity, complete deobfuscation, or all-input reachability.",
        "Trace UI generated this script but did not execute angr or the target; the user controls manual execution.",
    ]
    limitations.extend(warnings)
    return {
        "schema": SCHEMA,
        "moduleName": REPORT["scope"]["moduleName"],
        "architecture": "AArch64",
        "binarySha256": binary_sha256,
        "buildId": EXPECTED_BINARY.get("buildId"),
        "claimScope": CLAIM_SCOPE,
        "scope": scope,
        "staticInventory": static_inventory,
        "dynamicRuns": dynamic_runs,
        "summary": summary,
        "limitations": sorted(set(limitations)),
    }


def main():
    parser = argparse.ArgumentParser(description="Export strict Trace UI coverage reconciliation from an exact ELF and embedded OLLVM dynamic report")
    parser.add_argument("binary", help="Exact AArch64 ELF/shared object used to generate this script")
    parser.add_argument("-o", "--output", default="trace-ui-coverage-reconciliation.json", help="Output JSON path")
    args = parser.parse_args()
    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        parser.error("binary does not exist: {}".format(binary_path))
    result = analyze(binary_path)
    output_path = os.path.abspath(args.output)
    with open(output_path, "w", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
    summary = result["summary"]
    print("[Trace UI] wrote coverage reconciliation to {}: instructions={}/{} blocks={}/{} branches={}/{} functions={}/{} edges={}/{} complete={}".format(
        output_path,
        summary["observedStaticCounts"]["instructions"], summary["staticCounts"]["instructions"],
        summary["observedStaticCounts"]["blocks"], summary["staticCounts"]["blocks"],
        summary["observedStaticCounts"]["branches"], summary["staticCounts"]["branches"],
        summary["observedStaticCounts"]["functions"], summary["staticCounts"]["functions"],
        summary["observedStaticCounts"]["edges"], summary["staticCounts"]["edges"],
        summary["coverageComplete"],
    ))


if __name__ == "__main__":
    main()
"###;
    let script = template
        .replace("__REPORT_JSON__", &report_literal)
        .replace("__EXPECTED_BINARY_JSON__", &identity_literal)
        .replace("__CLAIM_SCOPE__", &claim_scope_literal)
        .replace("__SOURCE_OLLVM_SHA256__", &source_sha_literal)
        .replace("__SCOPE_KIND__", request.scope_kind.as_str())
        .replace("__RANGE_START__", &range_start_literal)
        .replace("__RANGE_END__", &range_end_literal)
        .replace(
            "__MAX_INSTRUCTIONS__",
            &request.max_instructions.to_string(),
        )
        .replace("__MAX_BLOCKS__", &request.max_blocks.to_string())
        .replace("__MAX_EDGES__", &request.max_edges.to_string())
        .replace("__MAX_FUNCTIONS__", &request.max_functions.to_string());
    let file_name = format!(
        "{}-trace-ui-coverage.py",
        sanitize_file_component(
            report
                .scope
                .function_name
                .as_deref()
                .unwrap_or(&report.scope.module_name)
        )
    );
    Ok(CoverageReconciliationScript {
        file_name,
        script,
        schema: COVERAGE_RECONCILIATION_SCHEMA.to_string(),
        module_name: report.scope.module_name,
        claim_scope: request.claim_scope.trim().to_string(),
        expected_binary_identity: layout.identity,
        source_ollvm_sha256,
        warnings: vec![
            "Run this Python manually in an isolated environment with angr installed; Trace UI never executes it or the target."
                .to_string(),
            "Import the resulting coverage JSON with the exact static-binary artifact and the source OLLVM report as parents."
                .to_string(),
            "Even complete listed-site coverage only removes one completeness blocker; semantic/OLLVM claims remain bounded by their dedicated evidence gates."
                .to_string(),
        ],
    })
}

pub fn save_coverage_reconciliation_bundle(
    bundle: &CoverageReconciliationBundle,
    output_path: &str,
) -> Result<String, String> {
    validate_bundle_structure(bundle)?;
    let path = Path::new(output_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create coverage output directory: {error}"))?;
    }
    let bytes = serde_json::to_vec_pretty(bundle)
        .map_err(|error| format!("failed to serialize coverage reconciliation: {error}"))?;
    fs::write(path, bytes).map_err(|error| {
        format!("failed to write coverage reconciliation '{output_path}': {error}")
    })?;
    Ok(path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn executable_elf() -> Vec<u8> {
        let mut elf = vec![0u8; 8192];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        elf[18..20].copy_from_slice(&183u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        write_u64(&mut elf, 32, 64);
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        write_u32(&mut elf, 64, 1);
        write_u32(&mut elf, 68, 5);
        write_u64(&mut elf, 72, 0);
        write_u64(&mut elf, 80, 0);
        let size = elf.len() as u64;
        write_u64(&mut elf, 96, size);
        write_u64(&mut elf, 104, size);
        write_u64(&mut elf, 112, 0x1000);
        for (index, byte) in elf[0x1000..].iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        elf
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("trace-ui-coverage-{}-{name}", uuid::Uuid::new_v4()))
    }

    fn summary_for(mut bundle: CoverageReconciliationBundle) -> CoverageReconciliationBundle {
        bundle.summary = recompute_coverage_reconciliation_summary(&bundle);
        bundle
    }

    fn sample_bundle() -> CoverageReconciliationBundle {
        summary_for(CoverageReconciliationBundle {
            schema: COVERAGE_RECONCILIATION_SCHEMA.to_string(),
            module_name: "libtarget.so".to_string(),
            architecture: "AArch64".to_string(),
            binary_sha256: "11".repeat(32),
            build_id: None,
            claim_scope: "crypto:libtarget.so@11".to_string(),
            scope: CoverageScope {
                kind: "function-closure".to_string(),
                start_offset: "0x100".to_string(),
                end_offset: "0x10c".to_string(),
                function_offsets: vec!["0x100".to_string()],
            },
            static_inventory: CoverageStaticInventory {
                source_kind: "angr-cfgfast".to_string(),
                source_version: Some("9.2".to_string()),
                complete_for_scope: true,
                instructions_truncated: false,
                blocks_truncated: false,
                branches_truncated: false,
                functions_truncated: false,
                edges_truncated: false,
                instruction_offsets: vec![
                    "0x100".to_string(),
                    "0x104".to_string(),
                    "0x108".to_string(),
                    "0x10c".to_string(),
                ],
                block_offsets: vec!["0x100".to_string(), "0x108".to_string()],
                branch_offsets: vec!["0x104".to_string()],
                functions: vec![CoverageFunctionRange {
                    start_offset: "0x100".to_string(),
                    end_offset: "0x10c".to_string(),
                    name: Some("target".to_string()),
                }],
                edges: vec![CoverageEdge {
                    source_offset: "0x100".to_string(),
                    target_offset: "0x108".to_string(),
                }],
            },
            dynamic_runs: vec![CoverageDynamicRun {
                run_id: "run-a".to_string(),
                source_artifact_sha256: "22".repeat(32),
                capture_complete_for_scope: true,
                instruction_offsets: vec![
                    "0x100".to_string(),
                    "0x104".to_string(),
                    "0x108".to_string(),
                    "0x10c".to_string(),
                ],
                block_offsets: vec!["0x100".to_string(), "0x108".to_string()],
                branch_offsets: vec!["0x104".to_string()],
                function_offsets: vec!["0x100".to_string()],
                edges: vec![CoverageEdge {
                    source_offset: "0x100".to_string(),
                    target_offset: "0x108".to_string(),
                }],
            }],
            summary: CoverageReconciliationSummary {
                static_counts: CoverageCounts::default(),
                observed_static_counts: CoverageCounts::default(),
                uncovered_counts: CoverageCounts::default(),
                dynamic_only_counts: CoverageCounts::default(),
                coverage_basis_points: CoverageBasisPoints::default(),
                static_inventory_complete: false,
                dynamic_capture_complete: false,
                coverage_complete: false,
            },
            limitations: Vec::new(),
        })
    }

    #[test]
    fn rejects_forged_percentage_or_count_summary() {
        let mut bundle = sample_bundle();
        bundle.summary.coverage_basis_points.instructions = 9_999;
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let error = parse_coverage_reconciliation_bundle(&bytes).unwrap_err();
        assert!(error.contains("does not match recomputed inventories"));
    }

    #[test]
    fn partial_dynamic_union_keeps_missing_sites_explicit() {
        let mut bundle = sample_bundle();
        bundle.dynamic_runs[0].instruction_offsets.pop();
        bundle = summary_for(bundle);
        assert_eq!(bundle.summary.uncovered_counts.instructions, 1);
        assert_eq!(bundle.summary.coverage_basis_points.instructions, 7_500);
        assert!(!bundle.summary.coverage_complete);
        parse_coverage_reconciliation_bundle(&serde_json::to_vec(&bundle).unwrap()).unwrap();
    }

    #[test]
    fn requires_canonical_sorted_offsets() {
        let mut bundle = sample_bundle();
        bundle.static_inventory.block_offsets = vec!["0x108".to_string(), "0x100".to_string()];
        bundle = summary_for(bundle);
        let error = parse_coverage_reconciliation_bundle(&serde_json::to_vec(&bundle).unwrap())
            .unwrap_err();
        assert!(error.contains("strictly sorted"));
    }

    #[test]
    fn exact_elf_and_source_hash_are_required_for_complete_gate() {
        let dir = temp_dir("identity");
        std::fs::create_dir_all(&dir).unwrap();
        let elf_path = dir.join("libtarget.so");
        std::fs::write(&elf_path, executable_elf()).unwrap();
        let identity =
            crate::query::elf_identity::inspect_elf_binary(elf_path.to_str().unwrap()).unwrap();
        let mut bundle = sample_bundle();
        bundle.binary_sha256 = identity.binary_sha256.clone();
        bundle.build_id = identity.build_id.clone();
        let source = bundle.dynamic_runs[0].source_artifact_sha256.clone();
        let report = inspect_coverage_reconciliation_bundle(
            &bundle,
            elf_path.to_str().unwrap(),
            std::slice::from_ref(&source),
        )
        .unwrap();
        assert_eq!(report.status, "complete-site-coverage");
        assert!(report.coverage_gate_met);

        let missing_source =
            inspect_coverage_reconciliation_bundle(&bundle, elf_path.to_str().unwrap(), &[])
                .unwrap();
        assert_eq!(missing_source.status, "source-provenance-mismatch");
        assert!(!missing_source.coverage_gate_met);

        let wrong_path = dir.join("wrong.so");
        let mut wrong = executable_elf();
        wrong[0x1800] ^= 0x5a;
        std::fs::write(&wrong_path, wrong).unwrap();
        let mismatch = inspect_coverage_reconciliation_bundle(
            &bundle,
            wrong_path.to_str().unwrap(),
            &[source],
        )
        .unwrap();
        assert_eq!(mismatch.status, "identity-mismatch");
        assert!(!mismatch.coverage_gate_met);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_offsets_outside_exact_elf_executable_ranges() {
        let dir = temp_dir("out-of-range");
        std::fs::create_dir_all(&dir).unwrap();
        let elf_path = dir.join("libtarget.so");
        std::fs::write(&elf_path, executable_elf()).unwrap();
        let identity =
            crate::query::elf_identity::inspect_elf_binary(elf_path.to_str().unwrap()).unwrap();
        let mut bundle = sample_bundle();
        bundle.binary_sha256 = identity.binary_sha256;
        bundle.scope.end_offset = "0x3000".to_string();
        bundle
            .static_inventory
            .instruction_offsets
            .push("0x3000".to_string());
        bundle.dynamic_runs[0]
            .instruction_offsets
            .push("0x3000".to_string());
        bundle.summary = recompute_coverage_reconciliation_summary(&bundle);
        let source = bundle.dynamic_runs[0].source_artifact_sha256.clone();
        let error =
            inspect_coverage_reconciliation_bundle(&bundle, elf_path.to_str().unwrap(), &[source])
                .unwrap_err();
        assert!(error.contains("file-backed executable PT_LOAD"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn generated_angr_coverage_script_has_no_placeholders_and_parses_as_python() {
        use crate::query::ollvm::{
            DynamicBasicBlock, DynamicBlockInstruction, OllvmReport, OllvmScope,
        };

        let dir = temp_dir("script");
        std::fs::create_dir_all(&dir).unwrap();
        let elf_path = dir.join("libtarget.so");
        let report_path = dir.join("ollvm.json");
        let script_path = dir.join("coverage.py");
        std::fs::write(&elf_path, executable_elf()).unwrap();
        let report = OllvmReport {
            schema_version: "trace-ui/ollvm-v1".to_string(),
            scope: OllvmScope {
                session_id: "session".to_string(),
                node_id: Some(1),
                function_name: Some("target".to_string()),
                module_name: "libtarget.so".to_string(),
                module_base: "0x71000000".to_string(),
                start_seq: 0,
                end_seq: 1,
                child_calls_excluded: 0,
            },
            executed_instruction_count: 1,
            unique_instruction_count: 1,
            block_count: 1,
            edge_count: 0,
            blocks: vec![DynamicBasicBlock {
                block_id: "libtarget.so+0x1000".to_string(),
                module_name: "libtarget.so".to_string(),
                start_offset: "0x1000".to_string(),
                end_offset: "0x1000".to_string(),
                start_address: "0x71001000".to_string(),
                end_address: "0x71001000".to_string(),
                visit_count: 1,
                predecessor_count: 0,
                successor_count: 0,
                terminal_operation: "ret".to_string(),
                sample_seqs: vec![0],
                instructions: vec![DynamicBlockInstruction {
                    offset: "0x1000".to_string(),
                    address: "0x71001000".to_string(),
                    disasm: "ret".to_string(),
                    execution_count: 1,
                    sample_seq: 0,
                }],
            }],
            edges: Vec::new(),
            branch_profiles: Vec::new(),
            dispatcher_candidates: Vec::new(),
            opaque_branch_candidates: Vec::new(),
            instructions_truncated: false,
            blocks_truncated: false,
            edges_truncated: false,
            limitations: Vec::new(),
            next_steps: Vec::new(),
        };
        std::fs::write(&report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        let generated =
            generate_coverage_reconciliation_script(&CoverageReconciliationScriptRequest {
                static_binary_path: elf_path.to_string_lossy().into_owned(),
                ollvm_report_path: report_path.to_string_lossy().into_owned(),
                claim_scope: "ollvm:libtarget.so@target".to_string(),
                scope_kind: CoverageScriptScopeKind::FunctionClosure,
                range_start_offset: None,
                range_end_offset: None,
                max_instructions: 1024,
                max_blocks: 256,
                max_edges: 512,
                max_functions: 64,
            })
            .unwrap();
        assert!(generated.script.contains("coverage-reconciliation-v1"));
        assert!(!generated.script.contains("__REPORT_JSON__"));
        assert!(!generated.script.contains("__EXPECTED_BINARY_JSON__"));
        std::fs::write(&script_path, &generated.script).unwrap();
        let python = ["python3", "python"].into_iter().find(|command| {
            std::process::Command::new(command)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        });
        if let Some(python) = python {
            let output = std::process::Command::new(python)
                .args(["-m", "py_compile"])
                .arg(&script_path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
