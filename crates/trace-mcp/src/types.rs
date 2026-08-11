use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct HealthRequest {}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub build_revision: String,
    pub schema_version: String,
    pub capabilities: Vec<String>,
}

// ── 会话管理 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenTraceRequest {
    #[schemars(description = "Absolute path to the trace file to open")]
    pub file_path: String,
    #[schemars(description = "Force rebuild the index even if cache exists")]
    #[serde(default)]
    pub force_rebuild: bool,
    #[schemars(description = "Skip building string index to speed up opening (default: false)")]
    #[serde(default)]
    pub skip_strings: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloseTraceRequest {
    #[schemars(description = "Session ID to close (optional if only one session is open)")]
    pub session_id: Option<String>,
}

// ── 数据查看 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTraceLinesRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Starting line number (0-based sequence number)")]
    pub start_seq: u32,
    #[schemars(description = "Number of lines to retrieve (default: 20, max: 100)")]
    #[serde(default = "default_line_count")]
    pub count: u32,
    #[schemars(
        description = "Return full TraceLine fields including raw, reg_before, so_offset, mem_size (default: false)"
    )]
    #[serde(default)]
    pub full: bool,
}

fn default_line_count() -> u32 {
    20
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetMemoryRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Memory address in hex (e.g. '0xbffff000')")]
    pub address: String,
    #[schemars(description = "Line number to read memory at (default: last line of trace)")]
    pub seq: Option<u32>,
    #[schemars(description = "Number of bytes to read (default: 64, max: 256)")]
    #[serde(default = "default_mem_length")]
    pub length: u32,
}

fn default_mem_length() -> u32 {
    64
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReconstructMemoryObjectsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Optional first 0-based trace sequence included in access analysis")]
    pub start_seq: Option<u32>,
    #[schemars(description = "Optional last 0-based trace sequence included in access analysis")]
    pub end_seq: Option<u32>,
    #[schemars(
        description = "Infer candidate stack-frame objects from call-tree lifetime and SP checkpoints (default: true)"
    )]
    #[serde(default = "default_true")]
    pub include_stack_frames: bool,
    #[schemars(
        description = "Group unattributed accesses into runtime/global/TLS/custom-allocator page candidates (default: true)"
    )]
    #[serde(default = "default_true")]
    pub include_runtime_clusters: bool,
    #[schemars(description = "Maximum serialized objects (default: 500, max: 5000)")]
    #[serde(default = "default_memory_object_max_objects")]
    pub max_objects: u32,
    #[schemars(description = "Maximum aliases retained per object (default: 64, max: 256)")]
    #[serde(default = "default_memory_object_max_aliases")]
    pub max_aliases_per_object: u32,
    #[schemars(
        description = "Maximum 16-byte field windows retained per object (default: 64, max: 256)"
    )]
    #[serde(default = "default_memory_object_max_fields")]
    pub max_field_windows_per_object: u32,
    #[schemars(
        description = "Maximum exact access samples retained per object (default: 16, max: 64)"
    )]
    #[serde(default = "default_memory_object_max_samples")]
    pub max_access_samples_per_object: u32,
    #[schemars(description = "Maximum serialized anomaly groups (default: 256, max: 1000)")]
    #[serde(default = "default_memory_object_max_anomalies")]
    pub max_anomalies: u32,
    #[schemars(
        description = "Maximum unattributed runtime page clusters (default: 128, max: 1000)"
    )]
    #[serde(default = "default_memory_object_max_clusters")]
    pub max_runtime_clusters: u32,
    #[schemars(
        description = "Maximum memory accesses processed before an explicit truncation flag (default: 5000000, max: 20000000)"
    )]
    #[serde(default = "default_memory_object_max_accesses")]
    pub max_accesses: u64,
    #[schemars(
        description = "Maximum bytes below entry SP considered for a candidate stack frame (default: 1048576, max: 16777216)"
    )]
    #[serde(default = "default_memory_object_stack_distance")]
    pub max_stack_distance: u64,
}

fn default_memory_object_max_objects() -> u32 {
    500
}

fn default_memory_object_max_aliases() -> u32 {
    64
}

fn default_memory_object_max_fields() -> u32 {
    64
}

fn default_memory_object_max_samples() -> u32 {
    16
}

fn default_memory_object_max_anomalies() -> u32 {
    256
}

fn default_memory_object_max_clusters() -> u32 {
    128
}

fn default_memory_object_max_accesses() -> u64 {
    5_000_000
}

fn default_memory_object_stack_distance() -> u64 {
    1024 * 1024
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ExplainMemoryPointerRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Runtime memory address in hex, for example 0x7fd84c7ad0")]
    pub address: String,
    #[schemars(description = "0-based trace sequence; defaults to the last trace sequence")]
    pub seq: Option<u32>,
    #[schemars(
        description = "Include inferred stack-frame candidates and SP/X29 relations (default: true)"
    )]
    #[serde(default = "default_true")]
    pub include_stack_frames: bool,
}

// ── 搜索与分析 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchInstructionsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Search query. Plain text or regex (wrap in /pattern/ for auto-regex). Use regex for complex patterns like 'bl.*0x[0-9a-f]+'"
    )]
    pub query: String,
    #[schemars(description = "Use regex matching")]
    #[serde(default)]
    pub use_regex: bool,
    #[schemars(description = "Case-sensitive matching")]
    #[serde(default)]
    pub case_sensitive: bool,
    #[schemars(description = "Max results to return (default: 30, max: 200)")]
    pub max_results: Option<u32>,
    #[schemars(
        description = "Return full TraceLine fields including raw, reg_before, so_offset, mem_size (default: false)"
    )]
    #[serde(default)]
    pub full: bool,
    #[schemars(description = "Limit search to seq range, e.g. '3000-6000'")]
    pub seq_range: Option<String>,
    #[schemars(
        description = "Filter results by SO offset address range, e.g. '0x246F00-0x249800'"
    )]
    pub addr_range: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ValueSearchKindRequest {
    #[default]
    Auto,
    Text,
    Hex,
    Integer,
    Address,
    Digest,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ValueEndianRequest {
    Little,
    Big,
    #[default]
    Both,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchValueRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Exact input value. Text is never silently trimmed or case-folded.")]
    pub query: String,
    #[schemars(description = "Interpretation: auto, text, hex, integer, address, or digest")]
    #[serde(default)]
    pub kind: ValueSearchKindRequest,
    #[schemars(description = "Integer/address byte order: little, big, or both")]
    #[serde(default)]
    pub endian: ValueEndianRequest,
    #[schemars(description = "Optional integer/address width in bytes: 1, 2, 4, or 8")]
    pub integer_width: Option<u8>,
    #[schemars(description = "Include exact UTF-8 bytes (default: true)")]
    #[serde(default = "default_true")]
    pub include_utf8: bool,
    #[schemars(description = "Include exact UTF-16LE bytes (default: true)")]
    #[serde(default = "default_true")]
    pub include_utf16le: bool,
    #[schemars(description = "Also include NUL-terminated text interpretations")]
    #[serde(default)]
    pub include_nul: bool,
    #[schemars(description = "Search the extracted runtime string index (default: true)")]
    #[serde(default = "default_true")]
    pub search_strings: bool,
    #[schemars(
        description = "Replay memory writes and search historical byte states (default: true)"
    )]
    #[serde(default = "default_true")]
    pub search_memory: bool,
    #[schemars(
        description = "Search exact query text in trace lines and call annotations (default: true)"
    )]
    #[serde(default = "default_true")]
    pub search_trace: bool,
    #[schemars(
        description = "Maximum returned matches across all sources (default: 100, max: 500)"
    )]
    #[serde(default = "default_value_search_results")]
    pub max_results: u32,
}

fn default_value_search_results() -> u32 {
    100
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTaintedLinesRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Analysis ID returned by taint_analysis (required; pagination is isolated per analysis)"
    )]
    pub analysis_id: String,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max lines to return (default: 50, max: 200)")]
    #[serde(default = "default_taint_limit")]
    pub limit: u32,
    #[schemars(
        description = "Return full TraceLine fields including raw, reg_before, so_offset, mem_size (default: false)"
    )]
    #[serde(default)]
    pub full: bool,
    #[schemars(
        description = "Filter out lines that only modify stack/frame pointer registers (sp, x29). Default: true"
    )]
    #[serde(default = "default_true")]
    pub ignore_stack_ops: bool,
    #[schemars(description = "Filter by SO offset address range, e.g. '0x246F00-0x249800'")]
    pub addr_range: Option<String>,
    #[schemars(
        description = "Include N non-tainted context lines before/after each tainted line (default: 0, max: 5)"
    )]
    #[serde(default)]
    pub context_lines: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GetTaintedLinesResponse {
    pub analysis_id: String,
    pub context: Option<String>,
    pub lines: Vec<serde_json::Value>,
    pub total_tainted: u32,
    pub total_after_filter: u32,
    pub stack_ops_filtered: u32,
    pub offset: u32,
    pub count: usize,
    pub context_lines: u32,
    pub has_more: bool,
}

fn default_taint_limit() -> u32 {
    50
}
fn default_true() -> bool {
    true
}

// ── 结构信息 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCallTreeRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Node ID to get children for (0 = root). Use this for lazy loading of large call trees"
    )]
    pub node_id: u32,
    #[schemars(
        description = "Number of levels to expand (default: 1, max: 3). depth=1 returns node + direct children"
    )]
    #[serde(default = "default_depth")]
    pub depth: u32,
}

fn default_depth() -> u32 {
    1
}

fn default_func_list_limit() -> u32 {
    30
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetStringsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Minimum string length to include (default: 4)")]
    #[serde(default = "default_min_str_len")]
    pub min_len: u32,
    #[schemars(description = "Filter strings containing this substring")]
    pub search: Option<String>,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max strings to return (default: 50, max: 200)")]
    #[serde(default = "default_strings_limit")]
    pub limit: u32,
}

fn default_min_str_len() -> u32 {
    4
}
fn default_strings_limit() -> u32 {
    50
}

// ── Batch 2 新增工具请求类型 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaintAnalysisRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Taint sources. Prefer explicit @line:N (1-based display line) or @seq:N (0-based sequence): \
        'reg:X0@line:1234' traces a register at display line 1234; \
        'mem:0xbffff000:32@seq:5929' traces a 32-byte memory range at sequence 5929; legacy @1234 remains supported; \
        '@last' uses the last definition. Memory size defaults to 1 byte for compatibility, \
        but AI callers should always provide :SIZE (1-4096)."
    )]
    pub from_specs: Vec<String>,
    #[schemars(
        description = "Only track data dependencies, ignore control flow (recommended for reducing noise)"
    )]
    #[serde(default)]
    pub data_only: bool,
    #[schemars(description = "Restrict analysis to lines >= this seq")]
    pub start_seq: Option<u32>,
    #[schemars(description = "Restrict analysis to lines <= this seq")]
    pub end_seq: Option<u32>,
    #[schemars(
        description = "Number of tainted lines to include in result (default: 30, 0=stats only, max: 200)"
    )]
    #[serde(default = "default_inline_lines")]
    pub include_lines: u32,
    #[schemars(
        description = "Filter results by SO offset address range, e.g. '0x246F00-0x249800'"
    )]
    pub addr_range: Option<String>,
    #[schemars(
        description = "Filter out lines that only modify stack/frame pointer registers (default: true)"
    )]
    #[serde(default = "default_true")]
    pub ignore_stack_ops: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ForwardTaintAnalysisRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Forward taint sources. Prefer explicit @line:N (1-based display line) or @seq:N (0-based sequence): \
        'reg:X0@line:1234' follows consumers of the register value at display line 1234; \
        'mem:0xbffff000:32@seq:5929' follows consumers of definitions at sequence 5929. \
        Memory size must be 1-4096 bytes."
    )]
    pub from_specs: Vec<String>,
    #[schemars(
        description = "Only follow data dependencies and ignore control dependencies (default: true)"
    )]
    #[serde(default = "default_true")]
    pub data_only: bool,
    #[schemars(description = "Restrict affected instructions to 0-based sequences >= this value")]
    pub start_seq: Option<u32>,
    #[schemars(description = "Restrict affected instructions to 0-based sequences <= this value")]
    pub end_seq: Option<u32>,
    #[schemars(description = "Maximum affected dependency nodes (default: 10000, max: 100000)")]
    #[serde(default = "default_forward_nodes")]
    pub max_nodes: u32,
    #[schemars(
        description = "Maximum affected instructions included inline (default: 100, max: 500)"
    )]
    #[serde(default = "default_forward_lines")]
    pub include_lines: u32,
    #[schemars(
        description = "Maximum source and sink candidates returned per direction (default: 100, max: 500)"
    )]
    #[serde(default = "default_forward_sinks")]
    pub max_sinks: u32,
}

fn default_forward_nodes() -> u32 {
    10_000
}

fn default_forward_lines() -> u32 {
    100
}

fn default_forward_sinks() -> u32 {
    100
}

fn default_inline_lines() -> u32 {
    30
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum KnownDigestAlgorithm {
    #[default]
    Auto,
    Crc32,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeKnownDigestRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Known CRC32, MD5, SHA-1, SHA-256, SHA-384, or SHA-512 digests. One array item per digest."
    )]
    pub digests: Vec<String>,
    #[schemars(description = "Digest algorithm. Use auto to infer it from digest length.")]
    #[serde(default)]
    pub algorithm: KnownDigestAlgorithm,
    #[schemars(description = "Hash extracted runtime strings as UTF-8 candidates (default: true)")]
    #[serde(default = "default_true")]
    pub search_strings: bool,
    #[schemars(
        description = "Reconstruct binary memory writes and search for digest output buffers (default: true)"
    )]
    #[serde(default = "default_true")]
    pub search_memory: bool,
    #[schemars(
        description = "Build the string index automatically when string matching needs it (default: true)"
    )]
    #[serde(default = "default_true")]
    pub auto_scan_strings: bool,
    #[schemars(description = "Also test UTF-8 bytes followed by one NUL byte")]
    #[serde(default)]
    pub utf8_nul: bool,
    #[schemars(description = "Also test UTF-16LE encoded candidate strings")]
    #[serde(default)]
    pub utf16le: bool,
    #[schemars(description = "Also test UTF-16LE encoded strings followed by a UTF-16 NUL")]
    #[serde(default)]
    pub utf16le_nul: bool,
    #[schemars(description = "Maximum matches returned per search mode (default: 100, max: 500)")]
    #[serde(default = "default_digest_results")]
    pub max_results: u32,
    #[schemars(
        description = "Automatically run backward data-flow analysis for top matches (default: true)"
    )]
    #[serde(default = "default_true")]
    pub trace_matches: bool,
    #[schemars(
        description = "Maximum digest/string matches to trace automatically (default: 3, max: 10)"
    )]
    #[serde(default = "default_digest_traces")]
    pub max_trace_matches: u32,
    #[schemars(
        description = "Only follow data dependencies during automatic tracing (default: true)"
    )]
    #[serde(default = "default_true")]
    pub data_only: bool,
    #[schemars(
        description = "Optional 0-based earliest sequence included in automatic taint results"
    )]
    pub start_seq: Option<u32>,
    #[schemars(
        description = "Maximum dependency nodes returned per traced match (default: 1000, max: 5000)"
    )]
    #[serde(default = "default_dependency_nodes")]
    pub max_dependency_nodes: u32,
}

fn default_digest_results() -> u32 {
    100
}
fn default_digest_traces() -> u32 {
    3
}
fn default_dependency_nodes() -> u32 {
    1000
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAnalysesRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Optional analysis kind filter, such as known_digest, crypto_flow, backward_taint, or forward_taint"
    )]
    pub kind: Option<String>,
    #[schemars(description = "Maximum records to return (default: 20, max: 100)")]
    #[serde(default = "default_analysis_limit")]
    pub limit: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetAnalysisRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Analysis ID returned by an analysis tool")]
    pub analysis_id: String,
    #[schemars(description = "Section to return: summary (default), lines, or full")]
    pub include: Option<String>,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_analysis_page_limit")]
    pub limit: u32,
}

fn default_analysis_page_limit() -> u32 {
    100
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AnalysisPageResponse {
    pub field: String,
    pub offset: u32,
    pub count: usize,
    pub total: usize,
    pub has_more: bool,
    pub items: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GetAnalysisResponse {
    pub analysis_id: String,
    pub kind: String,
    pub title: String,
    pub created_at_ms: u64,
    pub request: serde_json::Value,
    pub result: serde_json::Value,
    pub evidence: serde_json::Value,
    pub page: Option<AnalysisPageResponse>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareAnalysesRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Two to ten analysis IDs from the same trace session")]
    pub analysis_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenAnalysisCaseRequest {
    #[schemars(description = "Absolute path to a .traceui-case manifest")]
    pub case_path: String,
    #[schemars(description = "Create the case when it does not exist (default: false)")]
    #[serde(default)]
    pub create: bool,
    #[schemars(description = "Case title used only when create=true")]
    pub title: Option<String>,
    #[schemars(
        description = "Optional open trace session whose exact trace file is added as the primary artifact when creating"
    )]
    pub session_id: Option<String>,
    #[schemars(
        description = "Optional absolute primary trace path when creating without an open session"
    )]
    pub primary_trace_path: Option<String>,
    #[schemars(description = "Optional exact AArch64 ELF/shared-object path added when creating")]
    pub exact_binary_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IngestAnalysisCaseArtifactRequest {
    #[schemars(description = "Absolute path to an existing .traceui-case manifest")]
    pub case_path: String,
    #[schemars(description = "Absolute path to the artifact to hash, strictly parse, and add")]
    pub artifact_path: String,
    #[schemars(
        description = "Optional kind hint: trace, static-binary, runtime-attestation, frida-capture, unicorn-result, angr-result, ida-annotations, ollvm-report, coverage-report, analysis-report, crypto-kat, crypto-report, or other"
    )]
    pub kind_hint: Option<String>,
    #[schemars(description = "Optional human-readable artifact label")]
    pub label: Option<String>,
    #[schemars(description = "Optional parent artifact IDs recording provenance")]
    #[serde(default)]
    pub parent_artifact_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiagnoseAnalysisCaseRequest {
    #[schemars(description = "Absolute path to an existing .traceui-case manifest")]
    pub case_path: String,
    #[schemars(
        description = "Persist Replay Doctor generated claims into the case claim ledger (default: false)"
    )]
    #[serde(default)]
    pub persist_generated_claims: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanAnalysisCaseCaptureRequest {
    #[schemars(description = "Absolute path to an existing .traceui-case manifest")]
    pub case_path: String,
    #[schemars(description = "Maximum ranked targets to return (default: 12, range: 1-32)")]
    #[serde(default = "default_capture_plan_targets")]
    pub max_targets: u32,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageScriptScopeKindRequest {
    Module,
    #[default]
    FunctionClosure,
    Range,
}

fn default_coverage_max_instructions() -> u32 {
    500_000
}

fn default_coverage_max_blocks() -> u32 {
    100_000
}

fn default_coverage_max_edges() -> u32 {
    250_000
}

fn default_coverage_max_functions() -> u32 {
    25_000
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateCoverageReconciliationScriptRequest {
    #[schemars(description = "Absolute path to the exact AArch64 ELF/shared object")]
    pub static_binary_path: String,
    #[schemars(description = "Absolute path to a strict trace-ui/ollvm-v1 report")]
    pub ollvm_report_path: String,
    #[schemars(
        description = "Exact claim scope this coverage artifact will constrain; it must later match the claim scope byte-for-byte"
    )]
    pub claim_scope: String,
    #[schemars(
        description = "Static inventory scope: function-closure (default), module, or an explicit range"
    )]
    #[serde(default)]
    pub scope_kind: CoverageScriptScopeKindRequest,
    #[schemars(
        description = "Canonical module-relative range start required only for scopeKind=range"
    )]
    pub range_start_offset: Option<String>,
    #[schemars(
        description = "Canonical module-relative range end required only for scopeKind=range"
    )]
    pub range_end_offset: Option<String>,
    #[schemars(description = "Maximum exported static instruction offsets (default 500000)")]
    #[serde(default = "default_coverage_max_instructions")]
    pub max_instructions: u32,
    #[schemars(description = "Maximum exported static block offsets (default 100000)")]
    #[serde(default = "default_coverage_max_blocks")]
    pub max_blocks: u32,
    #[schemars(description = "Maximum exported static CFG edges (default 250000)")]
    #[serde(default = "default_coverage_max_edges")]
    pub max_edges: u32,
    #[schemars(description = "Maximum exported static functions (default 25000)")]
    #[serde(default = "default_coverage_max_functions")]
    pub max_functions: u32,
    #[schemars(
        description = "Optional absolute .py output path. When omitted, the generated script is returned inline."
    )]
    pub output_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectCoverageReconciliationRequest {
    #[schemars(
        description = "Absolute path to a strict trace-ui/coverage-reconciliation-v1 JSON file"
    )]
    pub artifact_path: String,
    #[schemars(description = "Absolute path to the exact AArch64 ELF/shared object")]
    pub static_binary_path: String,
    #[schemars(
        description = "Exact source OLLVM/trace artifact paths whose SHA-256 values must cover every dynamicRuns.sourceArtifactSha256"
    )]
    #[serde(default)]
    pub source_artifact_paths: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunAccuracyBenchmarkRequest {
    #[schemars(
        description = "Absolute path to a strict trace-ui/accuracy-benchmark-suite-v1 JSON file; relative case paths resolve from the suite directory"
    )]
    pub suite_path: String,
}

fn default_capture_plan_targets() -> u32 {
    12
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisCaseEvidencePackFormatRequest {
    #[default]
    Json,
    Markdown,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateAnalysisCaseEvidencePackRequest {
    #[schemars(description = "Absolute path to an existing .traceui-case manifest")]
    pub case_path: String,
    #[schemars(description = "Output format: json or markdown (default: json)")]
    #[serde(default)]
    pub format: AnalysisCaseEvidencePackFormatRequest,
    #[schemars(
        description = "Approximate output-token budget (default: 8000; range: 1024-65536). The deterministic estimate is reported in the result."
    )]
    #[serde(default = "default_evidence_pack_tokens")]
    pub max_tokens: u32,
    #[schemars(
        description = "Maximum combined claims/evidence/unknown/invalid-artifact entries (default: 256; range: 16-2048)"
    )]
    #[serde(default = "default_evidence_pack_items")]
    pub max_items: u32,
    #[schemars(description = "Include current Replay Doctor generated claims (default: true)")]
    #[serde(default = "default_true")]
    pub include_generated_claims: bool,
}

fn default_evidence_pack_tokens() -> u32 {
    8_000
}

fn default_evidence_pack_items() -> u32 {
    256
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EvidenceSliceTraceSessionBindingRequest {
    #[schemars(description = "Trace artifact ID in the selected .traceui-case")]
    pub artifact_id: String,
    #[schemars(description = "Currently open Trace UI MCP session ID for that exact trace file")]
    pub session_id: String,
}

fn default_evidence_slice_context_lines() -> u32 {
    2
}

fn default_evidence_slice_module_bytes_before() -> u32 {
    16
}

fn default_evidence_slice_module_bytes_after() -> u32 {
    32
}

fn default_evidence_slice_memory_bytes() -> u32 {
    4_096
}

fn default_evidence_slice_records() -> u32 {
    256
}

fn default_evidence_slice_payload_bytes() -> u64 {
    8 * 1024 * 1024
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateMinimalEvidenceSliceRequest {
    #[schemars(description = "Absolute path to an existing .traceui-case manifest")]
    pub case_path: String,
    #[schemars(
        description = "Optional exact case-artifact to open-session bindings. Required for trace references unless the source trace can be reopened during later inspection."
    )]
    #[serde(default)]
    pub trace_session_bindings: Vec<EvidenceSliceTraceSessionBindingRequest>,
    #[schemars(
        description = "Claim IDs to materialize. Empty selects every current persisted/generated claim allowed by includeGeneratedClaims."
    )]
    #[serde(default)]
    pub claim_ids: Vec<String>,
    #[schemars(description = "Include current Replay Doctor generated claims (default: true)")]
    #[serde(default = "default_true")]
    pub include_generated_claims: bool,
    #[schemars(
        description = "Include raw trace register/change text, memory bytes, Frida registers/captures/returns, and JSON fragments. Default false; enabling may expose secrets."
    )]
    #[serde(default)]
    pub include_sensitive_values: bool,
    #[schemars(description = "Trace context lines before each exact locator (default 2, max 16)")]
    #[serde(default = "default_evidence_slice_context_lines")]
    pub context_before: u32,
    #[schemars(description = "Trace context lines after each exact locator (default 2, max 16)")]
    #[serde(default = "default_evidence_slice_context_lines")]
    pub context_after: u32,
    #[schemars(
        description = "Static ELF bytes before an exact module offset (default 16, max 128)"
    )]
    #[serde(default = "default_evidence_slice_module_bytes_before")]
    pub module_bytes_before: u32,
    #[schemars(
        description = "Static ELF bytes after an exact module offset (default 32, max 128)"
    )]
    #[serde(default = "default_evidence_slice_module_bytes_after")]
    pub module_bytes_after: u32,
    #[schemars(
        description = "Maximum bytes in one materialized memory record (default 4096, max 65536)"
    )]
    #[serde(default = "default_evidence_slice_memory_bytes")]
    pub max_memory_bytes_per_record: u32,
    #[schemars(description = "Maximum evidence records (default 256, max 512)")]
    #[serde(default = "default_evidence_slice_records")]
    pub max_records: u32,
    #[schemars(
        description = "Canonical content byte budget (default 8388608, range 65536-16777216)"
    )]
    #[serde(default = "default_evidence_slice_payload_bytes")]
    pub max_total_payload_bytes: u64,
    #[schemars(
        description = "Optional absolute JSON output path. When omitted, the complete bounded bundle is returned inline."
    )]
    pub output_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectMinimalEvidenceSliceRequest {
    #[schemars(description = "Absolute path to the .traceui-case bound by the slice")]
    pub case_path: String,
    #[schemars(description = "Absolute path to a trace-ui/minimal-evidence-slice-v1 JSON file")]
    pub artifact_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AuditAnalysisCaseClaimsRequest {
    #[schemars(description = "Absolute path to an existing .traceui-case manifest")]
    pub case_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpsertAnalysisCaseExperimentRequest {
    #[schemars(description = "Absolute path to an existing .traceui-case manifest")]
    pub case_path: String,
    #[schemars(description = "Existing experiment ID to update; omit to generate a stable ID")]
    pub experiment_id: Option<String>,
    #[schemars(description = "Human-readable controlled-run label")]
    pub label: String,
    #[schemars(
        description = "Exact AArch64 ELF SHA-256. May be omitted when the referenced artifacts imply one unambiguous identity."
    )]
    pub binary_sha256: Option<String>,
    #[schemars(description = "Caller-declared key identity group, for example key-baseline")]
    pub key_group: Option<String>,
    #[schemars(description = "Caller-declared input identity group, for example input-baseline")]
    pub input_group: Option<String>,
    #[schemars(
        description = "Caller-declared environment identity group, including device/process/configuration controls"
    )]
    pub environment_group: Option<String>,
    #[schemars(description = "Case artifact IDs produced by or used in this controlled run")]
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    #[schemars(description = "Variables intentionally held fixed")]
    #[serde(default)]
    pub controlled_variables: Vec<String>,
    #[schemars(description = "Variables intentionally changed")]
    #[serde(default)]
    pub changed_variables: Vec<String>,
    #[schemars(description = "Bounded operator notes; do not place raw secrets here")]
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiagnoseCryptoDetectionRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Target algorithm family, normally AES (default: AES)")]
    pub target_algorithm: Option<String>,
    #[schemars(
        description = "Optional exact AArch64 ELF/shared object used for static/dynamic reconciliation"
    )]
    pub static_binary_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareTracesRequest {
    #[schemars(description = "Left/base session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Right/comparison trace session ID")]
    pub other_session_id: String,
    #[schemars(description = "Optional 0-based first sequence profiled in both traces")]
    pub start_seq: Option<u32>,
    #[schemars(description = "Optional 0-based last sequence profiled in both traces")]
    pub end_seq: Option<u32>,
    #[schemars(
        description = "Maximum added, removed, and changed items returned per section (default: 100, max: 1000)"
    )]
    #[serde(default = "default_trace_diff_items")]
    pub max_items: u32,
}

fn default_trace_diff_items() -> u32 {
    100
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteAnalysisRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Analysis ID to delete")]
    pub analysis_id: String,
}

fn default_analysis_limit() -> u32 {
    20
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InvestigateCryptoFlowRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Optional known digests to correlate with crypto detections")]
    #[serde(default)]
    pub digests: Vec<String>,
    #[schemars(description = "Digest algorithm. Use auto to infer it from digest length.")]
    #[serde(default)]
    pub algorithm: KnownDigestAlgorithm,
    #[schemars(
        description = "Instruction context lines around crypto detections (default: 3, max: 10)"
    )]
    #[serde(default = "default_crypto_context")]
    pub context_lines: u32,
    #[schemars(description = "Maximum crypto detections to return (default: 50, max: 200)")]
    #[serde(default = "default_crypto_matches")]
    pub max_crypto_matches: u32,
    #[schemars(description = "Automatically trace top digest matches (default: true)")]
    #[serde(default = "default_true")]
    pub trace_matches: bool,
    #[schemars(description = "Maximum digest matches to trace (default: 3, max: 10)")]
    #[serde(default = "default_digest_traces")]
    pub max_trace_matches: u32,
    #[schemars(
        description = "Only follow data dependencies during automatic tracing (default: true)"
    )]
    #[serde(default = "default_true")]
    pub data_only: bool,
    #[schemars(description = "Also test UTF-8 strings followed by NUL")]
    #[serde(default)]
    pub utf8_nul: bool,
    #[schemars(description = "Also test UTF-16LE strings")]
    #[serde(default)]
    pub utf16le: bool,
    #[schemars(description = "Also test UTF-16LE strings followed by NUL")]
    #[serde(default)]
    pub utf16le_nul: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AutoInvestigateRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Human or AI investigation objective recorded in the report")]
    #[serde(default)]
    pub objective: String,
    #[schemars(
        description = "Known digest values to correlate with runtime strings and output buffers"
    )]
    #[serde(default)]
    pub digests: Vec<String>,
    #[schemars(description = "Digest algorithm. Use auto to infer it from digest length.")]
    #[serde(default)]
    pub algorithm: KnownDigestAlgorithm,
    #[schemars(description = "Explicit register or memory values to trace forward")]
    #[serde(default)]
    pub from_specs: Vec<String>,
    #[schemars(
        description = "Literal instruction, function, address, or annotation terms to search"
    )]
    #[serde(default)]
    pub search_terms: Vec<String>,
    #[schemars(description = "Existing analysis IDs to compare as part of synthesis (2-10)")]
    #[serde(default)]
    pub compare_analysis_ids: Vec<String>,
    #[schemars(
        description = "Optional second open trace session for execution-profile Trace Diff"
    )]
    pub compare_session_id: Option<String>,
    #[schemars(description = "Run crypto signature detection (default: true)")]
    #[serde(default = "default_true")]
    pub include_crypto: bool,
    #[schemars(
        description = "Follow only data dependencies during automatic taint stages (default: true)"
    )]
    #[serde(default = "default_true")]
    pub data_only: bool,
    #[schemars(
        description = "Maximum matches returned for each search term (default: 20, max: 100)"
    )]
    #[serde(default = "default_auto_search_results")]
    pub max_search_results: u32,
    #[schemars(
        description = "Maximum digest candidates traced automatically (default: 3, max: 10)"
    )]
    #[serde(default = "default_digest_traces")]
    pub max_trace_matches: u32,
    #[schemars(
        description = "Maximum Trace Diff entries returned per section (default: 50, max: 500)"
    )]
    #[serde(default = "default_auto_diff_items")]
    pub max_diff_items: u32,
}

fn default_auto_search_results() -> u32 {
    20
}

fn default_auto_diff_items() -> u32 {
    50
}

fn default_crypto_matches() -> u32 {
    50
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetAnalysisTaskRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Task ID returned by a background analysis starter")]
    pub task_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAnalysisTasksRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Maximum tasks to return (default: 20, max: 100)")]
    #[serde(default = "default_analysis_limit")]
    pub limit: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CancelAnalysisTaskRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Task ID to cancel")]
    pub task_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SaveAnalysisRecipeRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Human-readable recipe name")]
    pub name: String,
    #[schemars(description = "What this recipe investigates")]
    #[serde(default)]
    pub description: String,
    #[schemars(
        description = "Recipe workflow: forward_to_sinks, known_digest_flow, crypto_investigation, or auto_investigation"
    )]
    pub workflow: String,
    #[schemars(description = "Default input object merged with run_analysis_recipe inputs")]
    #[serde(default)]
    pub defaults: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAnalysisRecipesRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunAnalysisRecipeRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Built-in recipe ID or analysis_id returned by save_analysis_recipe")]
    pub recipe_id: String,
    #[schemars(description = "Input object merged over the recipe defaults")]
    #[serde(default)]
    pub inputs: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteAnalysisRecipeRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Recipe analysis_id returned by save_analysis_recipe")]
    pub recipe_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExportAnalysisReportRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Analysis ID to export")]
    pub analysis_id: String,
    #[schemars(description = "Report format: markdown or json (default: markdown)")]
    #[serde(default = "default_report_format")]
    pub format: String,
    #[schemars(
        description = "Optional output file path. If omitted, report content is returned inline."
    )]
    pub output_path: Option<String>,
    #[schemars(
        description = "Include report content even when output_path is supplied (default: false)"
    )]
    #[serde(default)]
    pub include_content: bool,
}

fn default_report_format() -> String {
    "markdown".to_string()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFunctionRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Call tree node ID for detailed analysis of a specific function call (from get_call_tree)"
    )]
    pub node_id: Option<u32>,
    #[schemars(
        description = "Search for all calls to functions matching this name (partial, case-insensitive). \
        Omit both node_id and func_name to list all functions."
    )]
    pub func_name: Option<String>,
    #[schemars(description = "Pagination offset when listing functions (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max functions to return when listing (default: 30, max: 100)")]
    #[serde(default = "default_func_list_limit")]
    pub limit: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeCryptoRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Number of context lines around each crypto match (default: 3, max: 10)"
    )]
    #[serde(default = "default_crypto_context")]
    pub context_lines: u32,
}

fn default_crypto_context() -> u32 {
    3
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeCryptoFunctionsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Max candidate functions to return, ranked by confidence (default: 50, max: 500)"
    )]
    #[serde(default = "default_crypto_fn_candidates")]
    pub max_candidates: u32,
}

fn default_crypto_fn_candidates() -> u32 {
    50
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeCryptoMaterialsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Maximum material records to return (default: 500, max: 5000)")]
    #[serde(default = "default_crypto_materials")]
    pub max_materials: u32,
    #[schemars(
        description = "Include hexdump buffers from calls whose cryptographic role is unknown (default: false)"
    )]
    #[serde(default)]
    pub include_unknown: bool,
}

fn default_crypto_materials() -> u32 {
    500
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareCryptoMaterialTraceCaseRequest {
    #[schemars(description = "Open trace session ID")]
    pub session_id: String,
    #[schemars(description = "Human-readable case label")]
    pub label: String,
    #[schemars(
        description = "Caller-controlled primary input identity. Use the same value only when the password/message/input is intentionally unchanged."
    )]
    pub input_group: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareCryptoMaterialTracesRequest {
    #[schemars(
        description = "Two to sixteen controlled trace cases. Pairs with the same input_group are compared to isolate changing digest-input fields."
    )]
    pub cases: Vec<CompareCryptoMaterialTraceCaseRequest>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum FridaArgumentKindRequest {
    Integer,
    #[default]
    Pointer,
    Utf8String,
    Utf16String,
    ByteArray,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum FridaCaptureDirectionRequest {
    #[default]
    Input,
    Output,
    InOut,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FridaStalkerModeRequest {
    #[default]
    Off,
    Calls,
    Blocks,
    Instructions,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FridaArgumentSpecRequest {
    #[schemars(description = "ARM64 argument register index, from 0 (X0) through 7 (X7)")]
    pub index: u8,
    #[schemars(
        description = "Human-readable capture role, such as key, input, output, salt, or length"
    )]
    pub label: Option<String>,
    #[schemars(
        description = "Capture decoder: integer, pointer, utf8String, utf16String, or byteArray"
    )]
    #[serde(default)]
    pub kind: FridaArgumentKindRequest,
    #[schemars(description = "Capture phase: input, output, or inOut")]
    #[serde(default)]
    pub direction: FridaCaptureDirectionRequest,
    #[schemars(description = "Fixed byte/character length, bounded by max_bytes")]
    pub length: Option<u32>,
    #[schemars(description = "Optional X0-X7 register containing the dynamic length")]
    pub length_arg: Option<u8>,
    #[schemars(
        description = "Optional X0-X7 register pointing to a u32 output length, dereferenced on function leave"
    )]
    pub length_pointer_arg: Option<u8>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateFridaHookRequest {
    #[schemars(description = "Loaded module basename, for example libcrypto.so")]
    pub module_name: String,
    #[schemars(description = "Exported symbol name. Provide exactly one of symbol or offset.")]
    pub symbol: Option<String>,
    #[schemars(
        description = "Module-relative hexadecimal offset. Provide exactly one of symbol or offset."
    )]
    pub offset: Option<String>,
    #[schemars(
        description = "Optional stable hook label used in emitted events and the output filename"
    )]
    pub function_name: Option<String>,
    #[schemars(description = "X0-X7 values to capture on entry and/or return")]
    #[serde(default)]
    pub arguments: Vec<FridaArgumentSpecRequest>,
    #[schemars(description = "Capture X0-X7, SP, LR, and PC (default: true)")]
    #[serde(default = "default_true")]
    pub capture_registers: bool,
    #[schemars(description = "Capture the return value in X0 (default: true)")]
    #[serde(default = "default_true")]
    pub capture_return: bool,
    #[schemars(description = "Capture an accurate native backtrace on entry")]
    #[serde(default)]
    pub capture_backtrace: bool,
    #[schemars(
        description = "Capture every configured argument on both enter and leave and emit exact caller call-site/return metadata for bounded exact-call summaries. Requires register and return capture; hidden memory/SIMD/TLS/system/thread effects remain unknown."
    )]
    #[serde(default)]
    pub capture_exact_call: bool,
    #[schemars(
        description = "Optional Frida Stalker event level: off, calls, blocks, or instructions"
    )]
    #[serde(default)]
    pub stalker: FridaStalkerModeRequest,
    #[schemars(description = "Maximum Stalker capture duration in milliseconds (default: 10000)")]
    #[serde(default = "default_frida_stalker_duration")]
    pub stalker_duration_ms: u32,
    #[schemars(
        description = "Maximum bytes read from any pointer capture (default: 256, max: 1048576)"
    )]
    #[serde(default = "default_frida_max_bytes")]
    pub max_bytes: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateFridaRuntimeAttestationRequest {
    #[schemars(description = "Loaded module basename, for example libtarget.so")]
    pub module_name: String,
    #[schemars(
        description = "Absolute path to the exact AArch64 ELF whose mapped bytes will be checked"
    )]
    pub static_binary_path: String,
    #[schemars(
        description = "Power-of-two executable hash window size in bytes (default: 4096; range: 256-65536)"
    )]
    #[serde(default = "default_runtime_attestation_window_bytes")]
    pub window_bytes: u32,
    #[schemars(
        description = "Maximum executable windows (default: 1024; max: 4096). Sampling remains Related, never Verified."
    )]
    #[serde(default = "default_runtime_attestation_max_windows")]
    pub max_windows: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectRuntimeAttestationRequest {
    #[schemars(
        description = "Absolute path to user-captured trace-ui/frida-runtime-attestation-v1 JSON, NDJSON, send envelope, or CLI output"
    )]
    pub capture_path: String,
    #[schemars(
        description = "Absolute path to the exact AArch64 ELF used to regenerate and verify the complete plan"
    )]
    pub exact_binary_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyCryptoSemanticKatRequest {
    #[schemars(
        description = "Exact algorithm: aes-ecb/cbc/ctr/gcm, md5, sha1/256/384/512, hmac-*, or pbkdf2-hmac-*"
    )]
    pub algorithm: String,
    #[schemars(
        description = "Required for AES: encrypt or decrypt; omit for hashes, HMAC, and PBKDF2"
    )]
    pub direction: Option<String>,
    #[schemars(
        description = "Strict hexadecimal AES/HMAC key; no 0x prefix, whitespace, or separators"
    )]
    pub key_hex: Option<String>,
    #[schemars(
        description = "Strict hexadecimal AES/hash/HMAC input; empty string is valid for hashes and GCM"
    )]
    pub input_hex: Option<String>,
    #[schemars(description = "Strict hexadecimal observed output to compare byte-for-byte")]
    pub observed_output_hex: String,
    #[schemars(
        description = "Strict hexadecimal CBC IV, CTR initial counter, or 12-byte GCM nonce"
    )]
    pub iv_hex: Option<String>,
    #[schemars(description = "Optional strict hexadecimal GCM additional authenticated data")]
    pub aad_hex: Option<String>,
    #[schemars(description = "Required strict hexadecimal 16-byte GCM authentication tag")]
    pub observed_tag_hex: Option<String>,
    #[schemars(description = "Strict hexadecimal PBKDF2 password bytes")]
    pub password_hex: Option<String>,
    #[schemars(description = "Strict hexadecimal PBKDF2 salt bytes")]
    pub salt_hex: Option<String>,
    #[schemars(description = "PBKDF2 iteration count, bounded to 1-1000000")]
    pub iterations: Option<u32>,
    #[schemars(description = "PBKDF2 derived key length in bytes, bounded to 1-4096")]
    pub derived_key_length: Option<u32>,
    #[schemars(
        description = "Optional absolute output path for a strict trace-ui/crypto-semantic-kat-verification-v1 artifact. The file contains sensitive key/password/input/output material."
    )]
    pub output_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectCryptoSemanticKatRequest {
    #[schemars(
        description = "Absolute path to a trace-ui/crypto-semantic-kat-verification-v1 report; every field is recomputed before acceptance"
    )]
    pub file_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectFridaCaptureRequest {
    #[schemars(
        description = "Absolute path to JSON, JSON-array, or NDJSON containing trace-ui/frida-hook-v1 send() messages captured by the user"
    )]
    pub file_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SummarizeExactCallsRequest {
    #[schemars(
        description = "Absolute path to a user-captured trace-ui/frida-hook-v1 JSON/NDJSON file containing paired hook-enter/hook-leave events"
    )]
    pub capture_path: String,
    #[schemars(
        description = "Caller module basename whose exact BL/BLR call-site and PC+4 return offsets must be reconstructed"
    )]
    pub caller_module_name: String,
    #[schemars(
        description = "Absolute path to the exact AArch64 caller ELF/shared object used to bind module-relative call sites"
    )]
    pub static_binary_path: String,
    #[schemars(description = "Maximum paired calls summarized (default: 1024, max: 4096)")]
    #[serde(default = "default_exact_call_max_calls")]
    pub max_calls: u32,
    #[schemars(
        description = "Maximum paired enter+leave byteArray bytes retained per call (default: 1048576, max: 8388608)"
    )]
    #[serde(default = "default_exact_call_memory_bytes")]
    pub max_memory_bytes_per_call: u64,
    #[schemars(
        description = "Optional absolute JSON output path for trace-ui/exact-call-summary-v1. The artifact contains sensitive registers, pointers, and memory bytes."
    )]
    pub output_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AuthorizeExactCallReplayRequest {
    #[schemars(
        description = "Absolute path to a recomputable trace-ui/exact-call-summary-v1 artifact"
    )]
    pub summary_path: String,
    #[schemars(
        description = "Absolute path to the same exact AArch64 caller ELF used by the summary"
    )]
    pub static_binary_path: String,
    #[schemars(description = "One to 64 explicit callId values selected from the summary")]
    pub call_ids: Vec<String>,
    #[schemars(
        description = "Explicitly accept that configured paired byteArray captures cover every memory side effect needed by replay"
    )]
    #[serde(default)]
    pub captured_memory_effects_complete: bool,
    #[schemars(
        description = "Explicitly accept that the call has no relevant SIMD/FP side effects"
    )]
    #[serde(default)]
    pub no_simd_fp_side_effects: bool,
    #[schemars(
        description = "Explicitly accept that the call has no relevant TLS/errno side effects"
    )]
    #[serde(default)]
    pub no_tls_side_effects: bool,
    #[schemars(
        description = "Explicitly accept that the call has no relevant system-register, syscall, or process-state side effects"
    )]
    #[serde(default)]
    pub no_system_register_or_syscall_effects: bool,
    #[schemars(
        description = "Explicitly accept that the call has no relevant thread, signal, callback, or asynchronous side effects"
    )]
    #[serde(default)]
    pub no_thread_signal_or_callback_effects: bool,
    #[schemars(
        description = "Explicitly accept deterministic replay only when every serialized call-site, target, return, register, and memory precondition matches exactly"
    )]
    #[serde(default)]
    pub deterministic_for_exact_preconditions: bool,
    #[schemars(
        description = "Optional absolute JSON output path for trace-ui/exact-call-replay-authorization-v1. The artifact contains sensitive exact-call state."
    )]
    pub output_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InferFridaAbiRequest {
    #[schemars(
        description = "Absolute path to user-captured trace-ui/frida-hook-v1 JSON/NDJSON/CLI output"
    )]
    pub file_path: String,
    #[schemars(
        description = "Minimum repeated call/field observations before cross-call inference (default: 2, range: 2-64)"
    )]
    #[serde(default = "default_abi_min_observations")]
    pub min_observations: u32,
    #[schemars(description = "Maximum function groups (default: 64, range: 1-128)")]
    #[serde(default = "default_abi_max_functions")]
    pub max_functions: u32,
    #[schemars(
        description = "Maximum argument/pair/context/field candidates per function (default: 128, range: 8-512)"
    )]
    #[serde(default = "default_abi_max_candidates")]
    pub max_candidates_per_function: u32,
    #[schemars(
        description = "Optional absolute JSON output path. The saved report contains process-specific pointers and captured labels/values summarized from the source."
    )]
    pub output_path: Option<String>,
}

fn default_abi_min_observations() -> u32 {
    2
}

fn default_abi_max_functions() -> u32 {
    64
}

fn default_abi_max_candidates() -> u32 {
    128
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchFridaCaptureEventsRequest {
    #[schemars(
        description = "Absolute path to user-captured trace-ui/frida-hook-v1 JSON/NDJSON/CLI log"
    )]
    pub file_path: String,
    #[schemars(
        description = "Optional case-insensitive search across event metadata, register names/values, capture labels/values, return values, errors, and backtrace frames"
    )]
    pub query: Option<String>,
    #[schemars(
        description = "Optional exact event type such as hook-enter or ollvm-dispatcher-hit"
    )]
    pub event_type: Option<String>,
    #[schemars(description = "Optional case-insensitive module-name filter")]
    pub module_name: Option<String>,
    #[schemars(description = "Optional case-insensitive function-name filter")]
    pub function_name: Option<String>,
    #[schemars(description = "Optional case-insensitive callId filter")]
    pub call_id: Option<String>,
    #[schemars(
        description = "Only return events containing registers, captures, return values, backtraces, or Stalker payloads"
    )]
    #[serde(default)]
    pub only_payload: bool,
    #[schemars(description = "0-based offset in the filtered event list")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Maximum event summaries to return (default: 50, max: 200)")]
    #[serde(default = "default_frida_event_limit")]
    pub limit: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetFridaCaptureEventRequest {
    #[schemars(
        description = "Absolute path to user-captured trace-ui/frida-hook-v1 JSON/NDJSON/CLI log"
    )]
    pub file_path: String,
    #[schemars(
        description = "Exact normalized event index returned by search_frida_capture_events"
    )]
    pub event_index: u64,
    #[schemars(description = "Include the full captured register map (default: false)")]
    #[serde(default)]
    pub include_registers: bool,
    #[schemars(description = "Include captured argument/buffer values (default: false)")]
    #[serde(default)]
    pub include_captures: bool,
    #[schemars(description = "Include the captured return value (default: false)")]
    #[serde(default)]
    pub include_return_value: bool,
    #[schemars(description = "Include captured backtrace frames (default: false)")]
    #[serde(default)]
    pub include_backtrace: bool,
    #[schemars(
        description = "Maximum bytes returned for each capture value (default: 256, max: 1048576)"
    )]
    #[serde(default = "default_frida_max_bytes")]
    pub max_bytes: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFridaCryptoMaterialsRequest {
    #[schemars(
        description = "Absolute path to user-captured trace-ui/frida-hook-v1 JSON/NDJSON/CLI log"
    )]
    pub file_path: String,
    #[schemars(description = "Maximum returned materials (default: 1000, max: 5000)")]
    #[serde(default = "default_frida_materials")]
    pub max_materials: u32,
    #[schemars(description = "Include weak direction-only input/output classifications")]
    #[serde(default)]
    pub include_unknown: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateAngrStateSeedRequest {
    #[schemars(
        description = "Absolute path to a user-captured trace-ui/frida-hook-v1 JSON/NDJSON file"
    )]
    pub file_path: String,
    #[schemars(
        description = "Normalized capture event index, normally a hook-enter or ollvm-dispatcher-hit event"
    )]
    pub event_index: u64,
    #[schemars(
        description = "Seed SP from the capture (default: false; uncaptured stack bytes remain unconstrained)"
    )]
    #[serde(default)]
    pub include_sp: bool,
    #[schemars(description = "Seed LR/X30 from the capture (default: true)")]
    #[serde(default = "default_true")]
    pub include_lr: bool,
}

fn default_frida_stalker_duration() -> u32 {
    10_000
}

fn default_frida_event_limit() -> u32 {
    50
}

fn default_frida_materials() -> u32 {
    1_000
}

fn default_frida_max_bytes() -> u32 {
    256
}

fn default_exact_call_max_calls() -> u32 {
    1_024
}

fn default_exact_call_memory_bytes() -> u64 {
    1_048_576
}

fn default_runtime_attestation_window_bytes() -> u32 {
    4_096
}

fn default_runtime_attestation_max_windows() -> u32 {
    1_024
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeOllvmRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Optional call-tree node ID. When present, analysis is scoped to that invocation."
    )]
    pub node_id: Option<u32>,
    #[schemars(
        description = "Optional module basename. When omitted, it is inferred from the selected function/range."
    )]
    pub module_name: Option<String>,
    #[schemars(description = "Optional 0-based first trace sequence")]
    pub start_seq: Option<u32>,
    #[schemars(description = "Optional 0-based last trace sequence")]
    pub end_seq: Option<u32>,
    #[schemars(
        description = "Retain nested child-call ranges in the dynamic CFG (default: false)"
    )]
    #[serde(default)]
    pub include_child_calls: bool,
    #[schemars(description = "Maximum returned blocks (default: 1000, max: 10000)")]
    #[serde(default = "default_ollvm_blocks")]
    pub max_blocks: u32,
    #[schemars(description = "Maximum returned edges (default: 3000, max: 50000)")]
    #[serde(default = "default_ollvm_edges")]
    pub max_edges: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateFridaOllvmDispatcherHookRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    pub node_id: Option<u32>,
    pub module_name: Option<String>,
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
    #[serde(default)]
    pub include_child_calls: bool,
    #[serde(default = "default_ollvm_blocks")]
    pub max_blocks: u32,
    #[serde(default = "default_ollvm_edges")]
    pub max_edges: u32,
    #[schemars(
        description = "Maximum ranked dispatcher startOffsets included in the generated Frida 16 script (1-64, default: 12)"
    )]
    #[serde(default = "default_frida_ollvm_dispatchers")]
    pub max_dispatchers: u32,
    #[schemars(
        description = "Per-thread idle gap used to start a new candidate flow ID (1-600000 ms, default: 1000)"
    )]
    #[serde(default = "default_frida_ollvm_idle_gap")]
    pub idle_gap_ms: u32,
    #[schemars(
        description = "Maximum dispatcher-hit events emitted before the generated script stops recording (1-200000, default: 50000)"
    )]
    #[serde(default = "default_frida_ollvm_events")]
    pub max_events: u32,
    #[schemars(
        description = "Optional unique ARM64 pointer registers X0-X28 to read at every dispatcher hit; empty by default"
    )]
    #[serde(default)]
    pub capture_pointer_registers: Vec<u8>,
    #[schemars(
        description = "Bounded bytes read from each selected pointer register (1-4096, default: 64)"
    )]
    #[serde(default = "default_frida_ollvm_pointer_bytes")]
    pub pointer_capture_bytes: u32,
    #[schemars(
        description = "Optional bytes captured starting at SP for concrete replay state (0-16384, default: 0)"
    )]
    #[serde(default)]
    pub stack_capture_bytes: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFridaOllvmDispatcherCaptureRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    pub node_id: Option<u32>,
    pub module_name: Option<String>,
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
    #[serde(default)]
    pub include_child_calls: bool,
    #[serde(default = "default_ollvm_blocks")]
    pub max_blocks: u32,
    #[serde(default = "default_ollvm_edges")]
    pub max_edges: u32,
    #[schemars(
        description = "Absolute path to user-captured trace-ui/frida-hook-v1 JSON/NDJSON produced by manually running the generated dispatcher script or compatible exact-offset hooks"
    )]
    pub frida_capture_path: String,
    #[serde(default = "default_frida_ollvm_idle_gap")]
    pub idle_gap_ms: u32,
    #[serde(default = "default_frida_ollvm_events")]
    pub max_events: u32,
    #[serde(default = "default_frida_ollvm_state_values")]
    pub max_values_per_register: u32,
    #[serde(default = "default_frida_ollvm_state_changes")]
    pub max_state_changes_per_transition: u32,
    #[serde(default = "default_frida_ollvm_flow_length")]
    pub max_flow_length: u32,
    #[serde(default = "default_frida_ollvm_flows")]
    pub max_flows: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CompareOllvmTraceCaseRequest {
    #[schemars(description = "Open trace session ID")]
    pub session_id: String,
    #[schemars(description = "Unique human-readable run label")]
    pub label: String,
    #[schemars(description = "Optional call-tree node ID for this run")]
    pub node_id: Option<u32>,
    #[schemars(
        description = "Optional module basename; all cases must resolve to the same module"
    )]
    pub module_name: Option<String>,
    #[schemars(description = "Optional 0-based first trace sequence for this run")]
    pub start_seq: Option<u32>,
    #[schemars(description = "Optional 0-based last trace sequence for this run")]
    pub end_seq: Option<u32>,
    #[serde(default)]
    pub include_child_calls: bool,
    #[schemars(description = "Optional path to the exact ELF/shared object used by this run")]
    pub static_binary_path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CompareOllvmTracesRequest {
    #[schemars(description = "Two to sixteen controlled trace cases")]
    pub cases: Vec<CompareOllvmTraceCaseRequest>,
    #[schemars(
        description = "Require every case to provide a static ELF and reject comparison unless all SHA-256 values match"
    )]
    #[serde(default)]
    pub require_matching_binary: bool,
    #[serde(default = "default_ollvm_blocks")]
    pub max_blocks: u32,
    #[serde(default = "default_ollvm_edges")]
    pub max_edges: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MapOllvmVersionCaseRequest {
    #[schemars(
        description = "Unique version/build identifier, for example 1.4.2 or build-2026-07"
    )]
    pub version_id: String,
    #[schemars(description = "Open trace session ID for this version")]
    pub session_id: String,
    #[schemars(description = "Optional call-tree node ID for this version")]
    pub node_id: Option<u32>,
    #[schemars(description = "Optional module basename; version basenames may differ")]
    pub module_name: Option<String>,
    #[schemars(description = "Optional 0-based first trace sequence")]
    pub start_seq: Option<u32>,
    #[schemars(description = "Optional 0-based last trace sequence")]
    pub end_seq: Option<u32>,
    #[serde(default)]
    pub include_child_calls: bool,
    #[schemars(
        description = "Required path to the exact AArch64 ELF/shared object for this version"
    )]
    pub static_binary_path: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MapOllvmVersionsRequest {
    #[schemars(
        description = "Two to eight distinct binary versions with independent trace scopes and exact ELFs"
    )]
    pub versions: Vec<MapOllvmVersionCaseRequest>,
    #[schemars(
        description = "Optional version ID used as the dispatcher-source baseline; defaults to the first version"
    )]
    pub baseline_version_id: Option<String>,
    #[serde(default = "default_ollvm_blocks")]
    pub max_blocks: u32,
    #[serde(default = "default_ollvm_edges")]
    pub max_edges: u32,
    #[schemars(
        description = "Maximum candidates retained per baseline dispatcher and target version (1-10, default: 3)"
    )]
    #[serde(default = "default_ollvm_version_matches")]
    pub max_matches_per_block: u32,
    #[schemars(description = "Minimum structural score retained (1-100, default: 55)")]
    #[serde(default = "default_ollvm_version_score")]
    pub min_score: u8,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateIdaOllvmScriptRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    pub node_id: Option<u32>,
    pub module_name: Option<String>,
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
    #[serde(default)]
    pub include_child_calls: bool,
    #[serde(default = "default_ollvm_blocks")]
    pub max_blocks: u32,
    #[serde(default = "default_ollvm_edges")]
    pub max_edges: u32,
    #[schemars(description = "Optional IDA image base override, for example 0x7100000000")]
    pub ida_image_base: Option<String>,
    #[schemars(description = "Emit observed CFG edges as IDA user xrefs (default: false)")]
    #[serde(default)]
    pub add_user_xrefs: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectIdaAnnotationsRequest {
    #[schemars(
        description = "Absolute path to trace-ui/ida-ollvm-v1 JSON exported manually from IDA"
    )]
    pub file_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateAngrOllvmScriptRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    pub node_id: Option<u32>,
    pub module_name: Option<String>,
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
    #[serde(default)]
    pub include_child_calls: bool,
    #[serde(default = "default_ollvm_blocks")]
    pub max_blocks: u32,
    #[serde(default = "default_ollvm_edges")]
    pub max_edges: u32,
    #[schemars(
        description = "Include unconstrained single-instruction probes for opaque-branch candidates (default: true). These are hypothesis evidence, not entry-reachability proof."
    )]
    #[serde(default = "default_true")]
    pub probe_opaque_branches: bool,
    #[schemars(
        description = "Prefer CFGEmulated and fall back to CFGFast on failure (default: false)"
    )]
    #[serde(default)]
    pub use_cfg_emulated: bool,
    #[schemars(
        description = "Continue the first trace-register seed and exact Frida seed through a bounded symbolic flow (default: true). Blank-state probes remain single-step."
    )]
    #[serde(default = "default_true")]
    pub explore_seeded_flows: bool,
    #[schemars(
        description = "Maximum bounded symbolic-flow depth per seeded probe (1-64, default: 8)"
    )]
    #[serde(default = "default_angr_flow_depth")]
    pub flow_max_depth: u32,
    #[schemars(
        description = "Maximum symbolic states explored per seeded probe (1-256, default: 32)"
    )]
    #[serde(default = "default_angr_flow_states")]
    pub flow_max_states_per_probe: u32,
    #[schemars(
        description = "Optional absolute path to a user-captured trace-ui/frida-hook-v1 file. Must be paired with frida_event_index or frida_event_indices; Trace UI reads the file but never executes Frida. Every exact offset must match an opaque branch, condition source, dispatcher entry, or an offset authorized by checkpoint_result_path."
    )]
    pub frida_capture_path: Option<String>,
    #[schemars(
        description = "Normalized hook-enter or ollvm-dispatcher-hit event index whose exact module-relative offset must match an opaque branch, recorded condition source, dispatcher entry, or an authorized closer checkpoint"
    )]
    pub frida_event_index: Option<u64>,
    #[schemars(
        description = "Up to 32 normalized hook-enter or ollvm-dispatcher-hit event indices to embed as independent exact-offset seeds. This is additive with legacy frida_event_index and duplicates are removed."
    )]
    #[serde(default)]
    pub frida_event_indices: Vec<u64>,
    #[schemars(description = "Include captured SP in the embedded Frida seed (default: false)")]
    #[serde(default)]
    pub frida_include_sp: bool,
    #[schemars(description = "Include captured LR/X30 in the embedded Frida seed (default: true)")]
    #[serde(default = "default_true")]
    pub frida_include_lr: bool,
    #[schemars(
        description = "Optional exact AArch64 ELF/shared-object path. Its SHA-256 is embedded in the generated script, which refuses to analyze a different file when the user runs it manually."
    )]
    pub static_binary_path: Option<String>,
    #[schemars(
        description = "Optional absolute path to a strictly validated prior trace-ui/unicorn-ollvm-v1 result. With the exact ELF, it authorizes bounded angr continuation only from supported closer checkpoint offsets in that same module/build."
    )]
    pub checkpoint_result_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectAngrOllvmResultsRequest {
    #[schemars(
        description = "Absolute path to trace-ui/angr-ollvm-v1 JSON produced by a manually executed generated angr script"
    )]
    pub file_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateUnicornOllvmScriptRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    pub node_id: Option<u32>,
    pub module_name: Option<String>,
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
    #[serde(default)]
    pub include_child_calls: bool,
    #[serde(default = "default_ollvm_blocks")]
    pub max_blocks: u32,
    #[serde(default = "default_ollvm_edges")]
    pub max_edges: u32,
    #[schemars(
        description = "Absolute path to a user-captured trace-ui/frida-hook-v1 JSON/NDJSON file"
    )]
    pub frida_capture_path: String,
    #[schemars(description = "Legacy single exact Frida event index")]
    pub frida_event_index: Option<u64>,
    #[schemars(
        description = "One to 32 hook-enter or ollvm-dispatcher-hit event indices. Every capture offset must exactly match a branch, condition source, dispatcher entry, or an offset authorized by checkpoint_result_path."
    )]
    #[serde(default)]
    pub frida_event_indices: Vec<u64>,
    #[schemars(description = "Required exact AArch64 ELF/shared-object path")]
    pub static_binary_path: String,
    #[schemars(
        description = "Optional absolute path to a strictly validated prior trace-ui/unicorn-ollvm-v1 result. It authorizes only supported closer checkpoint offsets from the same module and exact ELF SHA-256."
    )]
    pub checkpoint_result_path: Option<String>,
    #[schemars(
        description = "Zero to 16 absolute trace-ui/exact-call-replay-authorization-v1 paths. Every artifact is strictly recomputed from its bound summary/capture and same exact ELF before authorized calls are embedded. Unknown calls and precondition mismatches still stop."
    )]
    #[serde(default)]
    pub exact_call_authorization_paths: Vec<String>,
    #[schemars(description = "Maximum concrete instructions per seed (1-2000000, default: 50000)")]
    #[serde(default = "default_unicorn_max_instructions")]
    pub max_instructions: u64,
    #[schemars(
        description = "Wall-clock timeout per seed in milliseconds (1-60000, default: 5000)"
    )]
    #[serde(default = "default_unicorn_timeout_ms")]
    pub timeout_ms: u64,
    #[schemars(description = "Maximum recorded memory writes per seed (1-100000, default: 4096)")]
    #[serde(default = "default_unicorn_memory_writes")]
    pub max_memory_writes: u64,
    #[schemars(
        description = "Maximum recorded instruction offsets per seed (1-500000, default: 50000)"
    )]
    #[serde(default = "default_unicorn_recorded_offsets")]
    pub max_recorded_offsets: u64,
    #[schemars(description = "Stop before BL/BLR call boundaries (default: true)")]
    #[serde(default = "default_true")]
    pub stop_on_call: bool,
    #[schemars(description = "Visits allowed per offset before loop-detected (1-100, default: 2)")]
    #[serde(default = "default_unicorn_loop_visits")]
    pub loop_visit_limit: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectUnicornOllvmResultsRequest {
    #[schemars(
        description = "Absolute path to trace-ui/unicorn-ollvm-v1 JSON produced by a manually executed generated Unicorn script"
    )]
    pub file_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UnicornOllvmRoundFileRequest {
    #[schemars(description = "Unique printable round label, such as round-1 or recapture-2")]
    pub round_id: String,
    #[schemars(
        description = "Absolute path to one validated trace-ui/unicorn-ollvm-v1 result JSON"
    )]
    pub file_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareUnicornOllvmRoundsRequest {
    #[schemars(
        description = "Two to 16 ordered Unicorn result rounds for the same module and exact ELF. Order must reflect the actual recapture/replay sequence."
    )]
    pub rounds: Vec<UnicornOllvmRoundFileRequest>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateFridaUnicornRecaptureHookRequest {
    #[schemars(
        description = "Absolute path to a validated trace-ui/unicorn-ollvm-v1 JSON result from a manually executed generated Unicorn script"
    )]
    pub unicorn_result_path: String,
    #[schemars(
        description = "One to 64 zero-based recaptureSuggestions indices. Every selected suggestion must use X0-X28 or SP with a bounded register-relative displacement."
    )]
    pub suggestion_indices: Vec<u32>,
    #[schemars(
        description = "Maximum hook-enter events emitted across all targets (1-50000, default: 5000)"
    )]
    #[serde(default = "default_frida_unicorn_recapture_events")]
    pub max_events: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateFridaUnicornCheckpointHookRequest {
    #[schemars(
        description = "Absolute path to a validated trace-ui/unicorn-ollvm-v1 JSON result from a manually executed generated Unicorn script"
    )]
    pub unicorn_result_path: String,
    #[schemars(
        description = "One to 32 original seed capture offsets from the result. Supported stalled runs are converted into closer missing-memory PC or terminal-offset checkpoint hooks."
    )]
    pub seed_capture_offsets: Vec<String>,
    #[schemars(
        description = "Maximum hook-enter events emitted across all closer checkpoint targets (1-50000, default: 5000)"
    )]
    #[serde(default = "default_frida_unicorn_recapture_events")]
    pub max_events: u32,
}

fn default_ollvm_blocks() -> u32 {
    1_000
}

fn default_ollvm_edges() -> u32 {
    3_000
}

fn default_unicorn_max_instructions() -> u64 {
    50_000
}

fn default_unicorn_timeout_ms() -> u64 {
    5_000
}

fn default_unicorn_memory_writes() -> u64 {
    4_096
}

fn default_unicorn_recorded_offsets() -> u64 {
    50_000
}

fn default_frida_unicorn_recapture_events() -> u32 {
    5_000
}

fn default_unicorn_loop_visits() -> u32 {
    2
}

fn default_frida_ollvm_dispatchers() -> u32 {
    12
}

fn default_frida_ollvm_idle_gap() -> u32 {
    1_000
}

fn default_frida_ollvm_events() -> u32 {
    50_000
}

fn default_frida_ollvm_pointer_bytes() -> u32 {
    64
}

fn default_frida_ollvm_state_values() -> u32 {
    64
}

fn default_frida_ollvm_state_changes() -> u32 {
    128
}

fn default_frida_ollvm_flow_length() -> u32 {
    256
}

fn default_frida_ollvm_flows() -> u32 {
    2_048
}

fn default_ollvm_version_matches() -> u32 {
    3
}

fn default_ollvm_version_score() -> u8 {
    55
}

fn default_angr_flow_depth() -> u32 {
    8
}

fn default_angr_flow_states() -> u32 {
    32
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeWhiteboxRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Target algorithm hint: aes (default), sm4, or des. Structural analysis is shared; only the final block/round match table differs."
    )]
    #[serde(default = "default_whitebox_algorithm")]
    pub algorithm: String,
    #[schemars(
        description = "Optional local ELF .so path. When supplied, file-backed PT_LOAD bytes are reconciled with dynamically observed table reads."
    )]
    #[serde(default)]
    pub static_binary_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareWhiteboxTraceCaseRequest {
    #[schemars(description = "Open trace session ID")]
    pub session_id: String,
    #[schemars(description = "Human-readable case label")]
    pub label: String,
    #[schemars(description = "Caller-provided key identity, e.g. key-a")]
    pub key_group: String,
    #[schemars(description = "Caller-provided input identity, e.g. plaintext-1")]
    pub input_group: String,
    #[schemars(description = "Optional exact ELF .so path for this case")]
    pub static_binary_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareWhiteboxTracesRequest {
    #[schemars(
        description = "Two to sixteen cases. Strong isolation uses at least two inputs for each of at least two keys."
    )]
    pub cases: Vec<CompareWhiteboxTraceCaseRequest>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CryptoImplementationResponse {
    pub analysis_id: String,
    pub saved: bool,
    pub structural: serde_json::Value,
    pub deprecation_notice: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyCryptoHypothesisRequest {
    pub key_hex: String,
    pub input_hex: String,
    pub output_hex: String,
    #[serde(default = "default_crypto_direction")]
    pub direction: String,
    #[serde(default = "default_crypto_mode")]
    pub mode: String,
    #[serde(default)]
    pub iv_hex: Option<String>,
    #[serde(default)]
    pub aad_hex: Option<String>,
    #[serde(default)]
    pub tag_hex: Option<String>,
}

fn default_crypto_direction() -> String {
    "encrypt".to_string()
}

fn default_crypto_mode() -> String {
    "ecb".to_string()
}

fn default_whitebox_algorithm() -> String {
    "aes".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digest_request_uses_ai_friendly_defaults() {
        let request: AnalyzeKnownDigestRequest = serde_json::from_value(serde_json::json!({
            "digests": ["5d41402abc4b2a76b9719d911017c592"]
        }))
        .unwrap();

        assert!(matches!(request.algorithm, KnownDigestAlgorithm::Auto));
        assert!(request.search_strings);
        assert!(request.search_memory);
        assert!(request.auto_scan_strings);
        assert!(request.trace_matches);
        assert!(request.data_only);
        assert_eq!(request.max_results, 100);
        assert_eq!(request.max_trace_matches, 3);
        assert_eq!(request.max_dependency_nodes, 1000);
    }

    #[test]
    fn crypto_flow_request_defaults_to_saved_focused_analysis() {
        let request: InvestigateCryptoFlowRequest =
            serde_json::from_value(serde_json::json!({})).unwrap();

        assert!(request.digests.is_empty());
        assert!(request.trace_matches);
        assert!(request.data_only);
        assert_eq!(request.context_lines, 3);
        assert_eq!(request.max_crypto_matches, 50);
        assert_eq!(request.max_trace_matches, 3);
    }

    #[test]
    fn crypto_hypothesis_defaults_to_ecb_without_optional_auth_fields() {
        let request: VerifyCryptoHypothesisRequest = serde_json::from_value(serde_json::json!({
            "key_hex": "00",
            "input_hex": "00",
            "output_hex": "00"
        }))
        .unwrap();
        assert_eq!(request.direction, "encrypt");
        assert_eq!(request.mode, "ecb");
        assert!(request.iv_hex.is_none());
        assert!(request.aad_hex.is_none());
        assert!(request.tag_hex.is_none());
    }

    #[test]
    fn forward_taint_request_defaults_are_bounded_and_data_only() {
        let request: ForwardTaintAnalysisRequest = serde_json::from_value(serde_json::json!({
            "from_specs": ["reg:X0@1234"]
        }))
        .unwrap();

        assert!(request.data_only);
        assert_eq!(request.max_nodes, 10_000);
        assert_eq!(request.include_lines, 100);
        assert_eq!(request.max_sinks, 100);
    }

    #[test]
    fn auto_investigation_defaults_to_bounded_multi_stage_analysis() {
        let request: AutoInvestigateRequest =
            serde_json::from_value(serde_json::json!({})).unwrap();

        assert!(request.include_crypto);
        assert!(request.data_only);
        assert_eq!(request.max_search_results, 20);
        assert_eq!(request.max_trace_matches, 3);
        assert_eq!(request.max_diff_items, 50);
        assert!(request.search_terms.is_empty());
    }

    #[test]
    fn frida_capture_queries_default_to_bounded_ai_pages() {
        let request: SearchFridaCaptureEventsRequest =
            serde_json::from_value(serde_json::json!({ "file_path": "/tmp/capture.json" }))
                .unwrap();
        assert_eq!(request.limit, 50);
        assert_eq!(request.offset, 0);
        assert!(!request.only_payload);

        let detail: GetFridaCaptureEventRequest = serde_json::from_value(serde_json::json!({
            "file_path": "/tmp/capture.json",
            "event_index": 7
        }))
        .unwrap();
        assert!(!detail.include_registers);
        assert!(!detail.include_captures);
        assert!(!detail.include_return_value);
        assert!(!detail.include_backtrace);
        assert_eq!(detail.max_bytes, 256);
    }

    #[test]
    fn trace_diff_defaults_to_explainable_result_limit() {
        let request: CompareTracesRequest = serde_json::from_value(serde_json::json!({
            "other_session_id": "other"
        }))
        .unwrap();

        assert_eq!(request.max_items, 100);
        assert!(request.start_seq.is_none());
        assert!(request.end_seq.is_none());
    }

    #[test]
    fn value_search_defaults_cover_all_primary_sources() {
        let request: SearchValueRequest = serde_json::from_value(serde_json::json!({
            "query": "0x1234"
        }))
        .unwrap();
        assert!(matches!(request.kind, ValueSearchKindRequest::Auto));
        assert!(matches!(request.endian, ValueEndianRequest::Both));
        assert!(request.include_utf8);
        assert!(request.include_utf16le);
        assert!(request.search_strings);
        assert!(request.search_memory);
        assert!(request.search_trace);
        assert_eq!(request.max_results, 100);
    }

    #[test]
    fn multi_trace_table_request_requires_explicit_labels() {
        let request: CompareWhiteboxTracesRequest = serde_json::from_value(serde_json::json!({
            "cases": [{
                "session_id": "session-a",
                "label": "key-a/input-1",
                "key_group": "key-a",
                "input_group": "input-1"
            }]
        }))
        .unwrap();
        assert_eq!(request.cases[0].key_group, "key-a");
        assert_eq!(request.cases[0].input_group, "input-1");
    }

    #[test]
    fn frida_hook_request_uses_bounded_capture_defaults() {
        let request: GenerateFridaHookRequest = serde_json::from_value(serde_json::json!({
            "module_name": "libtarget.so",
            "offset": "0x1234"
        }))
        .unwrap();
        assert!(request.capture_registers);
        assert!(request.capture_return);
        assert!(!request.capture_backtrace);
        assert!(!request.capture_exact_call);
        assert!(matches!(request.stalker, FridaStalkerModeRequest::Off));
        assert_eq!(request.stalker_duration_ms, 10_000);
        assert_eq!(request.max_bytes, 256);
    }

    #[test]
    fn analysis_case_evidence_pack_defaults_are_bounded() {
        let request: GenerateAnalysisCaseEvidencePackRequest =
            serde_json::from_value(serde_json::json!({
                "case_path": "sample.traceui-case"
            }))
            .unwrap();
        assert!(matches!(
            request.format,
            AnalysisCaseEvidencePackFormatRequest::Json
        ));
        assert_eq!(request.max_tokens, 8_000);
        assert_eq!(request.max_items, 256);
        assert!(request.include_generated_claims);
    }

    #[test]
    fn angr_state_seed_defaults_keep_stack_opt_in() {
        let request: GenerateAngrStateSeedRequest = serde_json::from_value(serde_json::json!({
            "file_path": "capture.ndjson",
            "event_index": 3
        }))
        .unwrap();
        assert!(!request.include_sp);
        assert!(request.include_lr);
    }

    #[test]
    fn frida_ollvm_dispatcher_requests_use_bounded_defaults() {
        let hook: GenerateFridaOllvmDispatcherHookRequest =
            serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(hook.max_dispatchers, 12);
        assert_eq!(hook.idle_gap_ms, 1_000);
        assert_eq!(hook.max_events, 50_000);
        assert!(hook.capture_pointer_registers.is_empty());
        assert_eq!(hook.pointer_capture_bytes, 64);
        assert_eq!(hook.stack_capture_bytes, 0);

        let atlas: AnalyzeFridaOllvmDispatcherCaptureRequest =
            serde_json::from_value(serde_json::json!({
                "frida_capture_path": "capture.ndjson"
            }))
            .unwrap();
        assert_eq!(atlas.idle_gap_ms, 1_000);
        assert_eq!(atlas.max_events, 50_000);
        assert_eq!(atlas.max_values_per_register, 64);
        assert_eq!(atlas.max_state_changes_per_transition, 128);
        assert_eq!(atlas.max_flow_length, 256);
        assert_eq!(atlas.max_flows, 2_048);
    }

    #[test]
    fn angr_ollvm_frida_seed_defaults_keep_stack_opt_in() {
        let request: GenerateAngrOllvmScriptRequest =
            serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(request.frida_capture_path.is_none());
        assert!(request.frida_event_index.is_none());
        assert!(request.frida_event_indices.is_empty());
        assert!(!request.frida_include_sp);
        assert!(request.frida_include_lr);
        assert!(request.static_binary_path.is_none());
        assert!(request.explore_seeded_flows);
        assert_eq!(request.flow_max_depth, 8);
        assert_eq!(request.flow_max_states_per_probe, 32);
    }

    #[test]
    fn unicorn_ollvm_request_uses_bounded_concrete_defaults() {
        let request: GenerateUnicornOllvmScriptRequest =
            serde_json::from_value(serde_json::json!({
                "frida_capture_path": "capture.ndjson",
                "static_binary_path": "libtarget.so"
            }))
            .unwrap();
        assert!(request.frida_event_index.is_none());
        assert!(request.frida_event_indices.is_empty());
        assert_eq!(request.max_instructions, 50_000);
        assert_eq!(request.timeout_ms, 5_000);
        assert_eq!(request.max_memory_writes, 4_096);
        assert_eq!(request.max_recorded_offsets, 50_000);
        assert!(request.stop_on_call);
        assert_eq!(request.loop_visit_limit, 2);
    }

    #[test]
    fn frida_crypto_material_request_uses_bounded_defaults() {
        let request: AnalyzeFridaCryptoMaterialsRequest =
            serde_json::from_value(serde_json::json!({
                "file_path": "capture.ndjson"
            }))
            .unwrap();
        assert_eq!(request.max_materials, 1_000);
        assert!(!request.include_unknown);
    }

    #[test]
    fn ollvm_request_defaults_to_bounded_dynamic_cfg() {
        let request: AnalyzeOllvmRequest = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(!request.include_child_calls);
        assert_eq!(request.max_blocks, 1_000);
        assert_eq!(request.max_edges, 3_000);
    }

    #[test]
    fn ollvm_multitrace_request_uses_bounded_defaults() {
        let request: CompareOllvmTracesRequest = serde_json::from_value(serde_json::json!({
            "cases": [
                {"session_id":"a","label":"run-a"},
                {"session_id":"b","label":"run-b"}
            ]
        }))
        .unwrap();
        assert_eq!(request.max_blocks, 1_000);
        assert_eq!(request.max_edges, 3_000);
        assert_eq!(request.cases.len(), 2);
        assert!(!request.cases[0].include_child_calls);
        assert!(request.cases[0].static_binary_path.is_none());
        assert!(!request.require_matching_binary);
    }

    #[test]
    fn ollvm_version_map_request_uses_bounded_defaults() {
        let request: MapOllvmVersionsRequest = serde_json::from_value(serde_json::json!({
            "versions": [
                {"version_id":"v1","session_id":"a","static_binary_path":"v1.so"},
                {"version_id":"v2","session_id":"b","static_binary_path":"v2.so"}
            ]
        }))
        .unwrap();
        assert_eq!(request.max_blocks, 1_000);
        assert_eq!(request.max_edges, 3_000);
        assert_eq!(request.max_matches_per_block, 3);
        assert_eq!(request.min_score, 55);
        assert!(request.baseline_version_id.is_none());
        assert!(!request.versions[0].include_child_calls);
    }
}
