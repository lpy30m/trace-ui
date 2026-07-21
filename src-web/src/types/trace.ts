export interface CallInfoDto {
  func_name: string;
  is_jni: boolean;
  args?: Array<{
    index: string;
    value: string;
    register?: string;
    role?: string;
    type_name?: string;
    raw_value?: string;
    observation: string;
  }>;
  ret_value?: string | null;
  summary: string;
  tooltip: string;
  observation_seq?: number | null;
  completion_seq?: number | null;
}

export interface TraceLine {
  seq: number;
  address: string;
  so_offset: string;
  so_name: string | null;
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
  provenance: MemoryByteProvenance[];
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
  so_offset: string;
  so_name: string | null;
  disasm: string;
  changes: string;
  reg_before: string;
  mem_rw: string | null;
  call_info: CallInfoDto | null;
  hidden_content: string | null;
}

export interface SearchResult {
  /** 首页匹配序列号（非全量，通过 fetch_search_page 分页拉取剩余） */
  match_seqs: number[];
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
  warnings: SliceWarning[];
}

export interface SliceWarning {
  code: string;
  message: string;
  sourceSpec: string;
  missingRanges: SliceMissingRange[];
}

export interface SliceMissingRange {
  startAddr: string;
  endAddr: string;
  size: number;
}

export interface StringRecordDto {
  idx: number;
  addr: string;
  content: string;
  encoding: string;
  byte_len: number;
  seq: number;
  xref_count: number;
  rw: string;
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

export interface NodeInfo {
  seq: number;
  expression: string;
  asm: string;              // 新增
  operation: string;
  isLeaf: boolean;
  value: string | null;
  depth: number;
  address: string;
  module: string | null;
  memAddr: string | null;
  memRw: string | null;
  functionName: string | null;
}

export interface DependencyGraph {
  nodes: NodeInfo[];
  edges: [number, number][]; // [parent_seq, child_seq]
  rootSeq: number;
  totalReachable: number;
  truncated: boolean;
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

export type HashAlgorithm = "crc32" | "md5" | "sha1" | "sha256" | "sha384" | "sha512";

export type HashTransform = "utf8" | "utf8Nul" | "utf16le" | "utf16leNul";

export interface HashTransformOptions {
  utf8Nul: boolean;
  utf16le: boolean;
  utf16leNul: boolean;
}

export interface HashMatchRequest {
  digests: string[];
  algorithm: HashAlgorithm | null;
  transforms: HashTransformOptions;
  maxResults: number | null;
}

export interface HashDigestQueryResult {
  input: string;
  normalizedDigest: string | null;
  algorithm: HashAlgorithm | null;
  error: string | null;
  matchCount: number;
}

export interface HashMatchResult {
  queryIndex: number;
  inputDigest: string;
  normalizedDigest: string;
  algorithm: HashAlgorithm;
  stringIndex: number;
  content: string;
  addr: string;
  seq: number;
  encoding: string;
  byteLen: number;
  hashedByteLen: number;
  xrefCount: number;
  rw: string;
  transform: HashTransform;
}

export interface HashMatchResponse {
  queries: HashDigestQueryResult[];
  matches: HashMatchResult[];
  candidateCount: number;
  totalMatches: number;
  truncated: boolean;
}

export interface HashMemoryMatchResult {
  queryIndex: number;
  inputDigest: string;
  normalizedDigest: string;
  algorithm: HashAlgorithm;
  addr: string;
  byteLen: number;
  firstWriteSeq: number;
  lastWriteSeq: number;
  writeSeqs: number[];
}

export interface HashMemoryMatchResponse {
  queries: HashDigestQueryResult[];
  matches: HashMemoryMatchResult[];
  writesScanned: number;
  totalMatches: number;
  truncated: boolean;
}

export interface EvidenceScoreFactor {
  code: string;
  label: string;
  points: number;
  observed: boolean;
  awardedPoints: number;
  evidence: string | null;
}

export interface EvidenceAssessment {
  scope: string;
  score: number;
  grade: string;       // "verified" | "related" | "uncertain"
  confidence: string;  // "high" | "medium" | "low"
  verificationGateMet: boolean;
  factors: EvidenceScoreFactor[];
  limitations: string[];
}

export interface CryptoRegValue {
  reg: string;
  value: string;
}

export interface CryptoCallAnnotation {
  funcName: string;
  isJni: boolean;
  args: CryptoRegValue[];
  retValue: string | null;
}

export interface CryptoFunctionIo {
  entryArgs: CryptoRegValue[];
  returnValue: string | null;
  callAnnotation: CryptoCallAnnotation | null;
}

export interface CryptoFunctionCandidate {
  funcId: number;
  funcAddr: string;
  funcName: string | null;
  entrySeq: number;
  exitSeq: number;
  lineCount: number;
  algorithms: string[];
  magicHits: number;
  distinctMagics: number;
  cryptoInsnCounts: Record<string, number>;
  cryptoInsnTotal: number;
  softwareShapeCounts: Record<string, number>;
  softwareShapeTotal: number;
  implementationHints: string[];
  io: CryptoFunctionIo;
  assessment: EvidenceAssessment;
}

export interface CryptoFunctionReport {
  candidates: CryptoFunctionCandidate[];
  totalFunctionsScanned: number;
  functionsWithSignals: number;
  magicHitCount: number;
  cryptoInsnCount: number;
  candidatesTruncated: boolean;
  limitations: string[];
  coverage: string[];
  zeroResultExplanation: string | null;
}

export interface WhiteBoxIoBlock {
  baseAddr: string;
  byteLen: number;
  bytesHex: string;
  ascii: string;
  printable: boolean;
  firstSeq: number;
  lastSeq: number;
}

export interface WhiteBoxTableRegion {
  baseAddr: string;
  endAddr: string;
  moduleOffset: string;
  spanBytes: number;
  distinctAddrs: number;
  readCount: number;
  dominantSize: number;
  firstSeq: number;
  lastSeq: number;
  roleHint: "lookupData" | "controlFlowDispatcherCandidate";
  cryptoEligible: boolean;
  pointerLikeEntries: number;
}

export type ValueSearchKind = "auto" | "text" | "hex" | "integer" | "address" | "digest";
export type ValueEndian = "little" | "big" | "both";
export type ValueSearchSource = "string" | "memory" | "trace";

export interface ValueSearchRequest {
  query: string;
  kind: ValueSearchKind;
  endian: ValueEndian;
  integerWidth: number | null;
  includeUtf8: boolean;
  includeUtf16le: boolean;
  includeNul: boolean;
  searchStrings: boolean;
  searchMemory: boolean;
  searchTrace: boolean;
  maxResults: number | null;
}

export interface ValueInterpretation {
  kind: ValueSearchKind;
  label: string;
  bytesHex: string;
  byteLen: number;
  encoding: string | null;
  endian: ValueEndian | null;
  numericValue: string | null;
}

export interface ValueSearchMatch {
  interpretationIndex: number;
  source: ValueSearchSource;
  addr: string | null;
  seq: number;
  firstSeq: number;
  lastSeq: number;
  writeSeqs: number[];
  stringIndex: number | null;
  content: string | null;
  preview: string;
  encoding: string | null;
  rw: string | null;
}

export interface ValueSearchResponse {
  query: string;
  interpretations: ValueInterpretation[];
  matches: ValueSearchMatch[];
  stringsScanned: number;
  writesScanned: number;
  traceLinesScanned: number;
  totalMatches: number;
  truncated: boolean;
  warnings: string[];
}

export interface ForwardSliceResult {
  sourceSpecs: string[];
  sourceSeqs: number[];
  affectedSeqs: number[];
  terminalSeqs: number[];
  affectedCount: number;
  totalLines: number;
  traversedEdges: number;
  forwardIndexEdges: number;
  forwardIndexReused: boolean;
  truncated: boolean;
  warnings: SliceWarning[];
}

export interface WhiteBoxTableFingerprint {
  scope: string;
  normalizedSha256: string;
  wordBytes: number;
  distinctWords: number;
  normalization: string;
  algorithmHint: string | null;
}

export interface WhiteBoxEncodingBoundary {
  direction: "InputEncodingCandidate" | "OutputEncodingCandidate";
  tableBase: string;
  boundarySite: string;
  externalBaseAddr: string;
  externalEndAddr: string;
  matchedEvents: number;
  distinctExternalAddrs: number;
  firstSeq: number;
  lastSeq: number;
  rationale: string;
}

export interface WhiteBoxStaticTableMatch {
  tableBase: string;
  moduleOffset: string;
  fileOffset: string;
  comparedEntries: number;
  matchingEntries: number;
  mismatchedEntries: number;
  matchRatio: number;
  matchKind: "ExactStaticDynamicMatch" | "PartialStaticDynamicMatch" | "StaticDynamicMismatch";
  dynamicNormalizedSha256: string | null;
  staticNormalizedSha256: string | null;
  algorithmHint: string | null;
  rationale: string;
}

export interface WhiteBoxStaticBinaryAnalysis {
  binaryPath: string;
  binarySha256: string;
  format: string;
  architecture: string;
  elfMachine: number;
  buildId: string | null;
  loadSegments: number;
  tableMatches: WhiteBoxStaticTableMatch[];
}

export interface WhiteBoxRoundProfile {
  roundCount: number;
  lookups: number;
  distinctEntries: number;
  landmarkTable: string;
}

export interface WhiteBoxAlgoVerdict {
  algorithm: string;
  blockBits: number;
  roundCount: number | null;
  rationale: string;
}

export interface WhiteBoxReport {
  plaintext: WhiteBoxIoBlock | null;
  ciphertext: WhiteBoxIoBlock | null;
  inputCandidates: WhiteBoxIoBlock[];
  outputCandidates: WhiteBoxIoBlock[];
  implementationKind: "ObfuscatedStandardSoftware" | "TableDrivenSoftware" | "BitslicedSoftware" | "KeyFusedTables" | "Unknown";
  keyExposure: "RawKeyObserved" | "ExpandedScheduleObserved" | "DerivedKeyObserved" | "KeyDependentTablesOnly" | "NotObserved" | "Unknown";
  whiteboxStatus: "NotWhiteBox" | "Candidate" | "Related" | "Verified" | "Unknown";
  tables: WhiteBoxTableRegion[];
  tableFingerprints: WhiteBoxTableFingerprint[];
  encodingBoundaries: WhiteBoxEncodingBoundary[];
  staticBinary: WhiteBoxStaticBinaryAnalysis | null;
  tableReadTotal: number;
  rounds: WhiteBoxRoundProfile | null;
  verdict: WhiteBoxAlgoVerdict;
  totalReads: number;
  totalWrites: number;
  assessment: EvidenceAssessment;
  nextSteps: string[];
  softwareCrypto: SoftwareCryptoReport | null;
}

export interface TraceSessionInfo {
  sessionId: string;
  filePath: string;
  fileSize: number;
  totalLines: number;
  indexReady: boolean;
  building: boolean;
  hasSliceResult: boolean;
  traceFormat: string | null;
}

export interface WhiteBoxTraceCaseRequest {
  sessionId: string;
  label: string;
  keyGroup: string;
  inputGroup: string;
  staticBinaryPath: string | null;
}

export interface WhiteBoxMultiTraceRequest {
  cases: WhiteBoxTraceCaseRequest[];
}

export interface WhiteBoxTraceCaseSummary {
  sessionId: string;
  label: string;
  keyGroup: string;
  inputGroup: string;
  fingerprintCount: number;
  fingerprintSetSha256: string;
  rawKeyObserved: boolean;
  semanticVerification: boolean;
  binarySha256: string | null;
  buildId: string | null;
}

export interface WhiteBoxKeyGroupSummary {
  keyGroup: string;
  caseCount: number;
  distinctInputGroups: number;
  inputStable: boolean;
  fingerprintSetSha256: string | null;
  rationale: string;
}

export interface WhiteBoxCrossKeyComparison {
  leftKeyGroup: string;
  rightKeyGroup: string;
  sameTableShape: boolean;
  sameFingerprintValues: boolean;
  rationale: string;
}

export interface WhiteBoxMultiTraceReport {
  classification: string;
  whiteboxStatus: string;
  verificationGateMet: boolean;
  rationale: string;
  cases: WhiteBoxTraceCaseSummary[];
  keyGroups: WhiteBoxKeyGroupSummary[];
  crossKeyComparisons: WhiteBoxCrossKeyComparison[];
  assessment: EvidenceAssessment;
  limitations: string[];
  nextSteps: string[];
}

export interface MemoryByteProvenance {
  offset: number;
  address: string;
  source: "instruction_write" | "call_model" | "call_hexdump" | "unknown";
  seq: number | null;
  confidence: string;
}

export interface SoftwareCryptoReport {
  algorithm: string;
  direction: "Encrypt" | "Decrypt";
  mode: string;
  padding: string;
  keyHex: string;
  keyAscii: string;
  keyObservationSeq: number;
  inputObservationSeq: number;
  ivHex: string | null;
  ivObservationSeq: number | null;
  authTagHex: string | null;
  authTagObservationSeq: number | null;
  aadHex: string | null;
  aadObservationSeq: number | null;
  inputLength: number;
  paddedLength: number;
  blockCount: number;
  outputBaseAddr: string;
  outputStoreInsn: string;
  outputFirstSeq: number;
  outputLastSeq: number;
  outputStride: number;
  firstCipherBlock: string;
  lastCipherBlock: string;
  scheduleVerified: boolean;
  stateLayout: string;
  stateLayoutEvidence: string;
  implementationKind: string;
  keyExposure: string;
  whiteboxStatus: string;
  verification: "Verified" | "VerifiedFull";
  ciphertextSha256: string;
  reproducer: string;
}

export interface AnalysisEvidence {
  algorithms: string[];
  digests: string[];
  functions: string[];
  modules: string[];
  keyStrings: string[];
  memoryReads: string[];
  memoryWrites: string[];
  addresses: string[];
  operations: string[];
  warnings: string[];
}

export interface AnalysisRecordSummary {
  analysisId: string;
  sessionId: string;
  kind: string;
  title: string;
  createdAtMs: number;
  algorithms: string[];
  functions: string[];
  keyStrings: string[];
  warningCount: number;
}

export interface AnalysisRecord {
  analysisId: string;
  sessionId: string;
  kind: string;
  title: string;
  createdAtMs: number;
  request: unknown;
  result: unknown;
  evidence: AnalysisEvidence;
}

export interface AnalysisUniqueEvidence {
  analysisId: string;
  evidence: AnalysisEvidence;
}

export interface AnalysisComparison {
  analysisIds: string[];
  kinds: string[];
  commonEvidence: AnalysisEvidence;
  uniqueEvidence: AnalysisUniqueEvidence[];
}

export interface RegValue {
  reg: string;
  value: string;
}

export interface FunctionRef {
  funcId: number;
  funcAddr: string;
  funcName: string | null;
  entrySeq: number;
  exitSeq: number;
  lineCount: number;
}

export interface FunctionCallAnnotation {
  funcName: string;
  isJni: boolean;
  args: RegValue[];
  retValue: string | null;
}

export interface MemTouch {
  addr: string;
  count: number;
  size: number;
}

export interface FunctionInspection {
  funcId: number;
  funcAddr: string;
  funcName: string | null;
  entrySeq: number;
  exitSeq: number;
  lineCount: number;
  parent: FunctionRef | null;
  entryArgs: RegValue[];
  returnValue: string | null;
  callAnnotation: FunctionCallAnnotation | null;
  children: FunctionRef[];
  childCount: number;
  memoryReads: MemTouch[];
  memoryWrites: MemTouch[];
  scannedLines: number;
  ioTruncated: boolean;
}
