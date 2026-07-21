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

fn default_frida_stalker_duration() -> u32 {
    10_000
}

fn default_frida_max_bytes() -> u32 {
    256
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
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectAngrOllvmResultsRequest {
    #[schemars(
        description = "Absolute path to trace-ui/angr-ollvm-v1 JSON produced by a manually executed generated angr script"
    )]
    pub file_path: String,
}

fn default_ollvm_blocks() -> u32 {
    1_000
}

fn default_ollvm_edges() -> u32 {
    3_000
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
        assert!(matches!(request.stalker, FridaStalkerModeRequest::Off));
        assert_eq!(request.stalker_duration_ms, 10_000);
        assert_eq!(request.max_bytes, 256);
    }

    #[test]
    fn ollvm_request_defaults_to_bounded_dynamic_cfg() {
        let request: AnalyzeOllvmRequest = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(!request.include_child_calls);
        assert_eq!(request.max_blocks, 1_000);
        assert_eq!(request.max_edges, 3_000);
    }
}
