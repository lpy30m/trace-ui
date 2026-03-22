export interface CallInfoDto {
  func_name: string;
  is_jni: boolean;
  summary: string;
  tooltip: string;
}

export interface TraceLine {
  seq: number;
  address: string;
  so_offset: string;
  disasm: string;
  changes: string;
  reg_before: string;
  mem_rw: string | null;
  mem_addr: string | null;
  mem_size: number | null;
  raw: string;
  call_info: CallInfoDto | null;
}

export interface MemorySnapshot {
  base_addr: string;
  bytes: number[];
  known: boolean[];
  length: number;
}

export interface CreateSessionResult {
  sessionId: string;
  totalLines: number;
  fileSize: number;
}

export interface SessionData {
  sessionId: string;
  filePath: string;
  fileName: string;
  totalLines: number;
  fileSize: number;
  isLoaded: boolean;
  isPhase2Ready: boolean;
  indexProgress: number;
}

export interface SearchMatch {
  seq: number;
  address: string;
  disasm: string;
  changes: string;
  mem_rw: string | null;
  call_info: CallInfoDto | null;
  hidden_content: string | null;
}

export interface SearchResult {
  matches: SearchMatch[];
  total_scanned: number;
  total_matches: number;
  truncated: boolean;
}

export interface DefUseChain {
  defSeq: number | null;
  useSeqs: number[];
  redefinedSeq: number | null;
}

export interface CallTreeNodeDto {
  id: number;
  func_addr: string;
  func_name: string | null;
  entry_seq: number;
  exit_seq: number;
  parent_id: number | null;
  children_ids: number[];
  line_count: number;
}

export interface SliceResult {
  markedCount: number;
  totalLines: number;
  percentage: number;
}

export interface StringRecordDto {
  idx: number;
  addr: string;
  content: string;
  encoding: string;
  byte_len: number;
  seq: number;
  xref_count: number;
}

export interface StringsResult {
  strings: StringRecordDto[];
  total: number;
}

export interface StringXRef {
  seq: number;
  rw: string;
  insn_addr: string;
  disasm: string;
}

export interface FunctionCallOccurrence {
  seq: number;
  summary: string;
}

export interface FunctionCallEntry {
  func_name: string;
  is_jni: boolean;
  occurrences: FunctionCallOccurrence[];
}

export interface FunctionCallsResult {
  functions: FunctionCallEntry[];
  total_calls: number;
}

export interface CryptoMatch {
  algorithm: string;
  magic_hex: string;
  seq: number;
  address: string;
  disasm: string;
  changes: string;
}

export interface CryptoScanResult {
  matches: CryptoMatch[];
  algorithms_found: string[];
  total_lines_scanned: number;
  scan_duration_ms: number;
}

export interface CryptoFunctionContext {
  func_name: string | null;
  func_addr: string;
  entry_seq: number;
  exit_seq: number;
  caller_name: string | null;
  caller_addr: string | null;
  caller_entry_seq: number | null;
  caller_exit_seq: number | null;
  args: [string, string, string, string];
  input_hex: string | null;
  output_hex: string | null;
  param_hint: string;
}

export interface CryptoCorrelateMatch {
  input_string: string;
  input_addr: string;
  algorithm: string;
  hash_hex: string;
  seq: number;
  address: string;
  disasm: string;
}

export interface CryptoCorrelateResult {
  matches: CryptoCorrelateMatch[];
  strings_tested: number;
  needles_count: number;
  scan_duration_ms: number;
}
