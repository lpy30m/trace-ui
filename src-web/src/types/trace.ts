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
  softwareSignalCounts?: Record<string, number>;
  softwareSignalTotal?: number;
  aesSboxDistinctIndices?: number;
  aesSboxBases?: string[];
  verificationStatus?: "VerifiedBlock" | "VerifiedPartial" | "VerifiedFull" | null;
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
  softwareSignalCount?: number;
  candidatesTruncated: boolean;
  limitations: string[];
  coverage: string[];
  zeroResultExplanation: string | null;
}

export type CryptoMaterialKind =
  | "key"
  | "expandedKey"
  | "password"
  | "salt"
  | "iv"
  | "nonce"
  | "counter"
  | "aad"
  | "authTag"
  | "input"
  | "output"
  | "plaintext"
  | "ciphertext"
  | "digest"
  | "mac"
  | "derivedKey"
  | "unknown";

export interface CryptoMaterial {
  materialId: string;
  kind: CryptoMaterialKind;
  role: string;
  algorithm: string | null;
  bytesHex: string | null;
  asciiPreview: string | null;
  byteLen: number | null;
  address: string | null;
  observationSeq: number | null;
  completionSeq: number | null;
  functionName: string | null;
  register: string | null;
  source: string;
  evidence: string[];
  assessment: EvidenceAssessment;
}

export interface CryptoFormula {
  formulaId: string;
  operation: string;
  algorithm: string;
  expression: string;
  inputMaterialIds: string[];
  outputMaterialId: string | null;
  callSeq: number | null;
  functionName: string | null;
  evidence: string[];
  assessment: EvidenceAssessment;
}

export interface CryptoMaterialReport {
  materials: CryptoMaterial[];
  formulas: CryptoFormula[];
  materialCounts: Record<string, number>;
  verifiedMaterials: number;
  verifiedFormulas: number;
  annotationsScanned: number;
  materialsTruncated: boolean;
  coverage: string[];
  limitations: string[];
}

export interface CryptoMaterialTraceCase {
  sessionId: string;
  label: string;
  inputGroup: string;
}

export interface DynamicParameterCandidate {
  algorithm: string;
  functionName: string | null;
  leftLabel: string;
  rightLabel: string;
  inputGroup: string;
  byteOffset: number;
  commonPrefixHex: string;
  commonSuffixHex: string;
  leftVariableHex: string;
  rightVariableHex: string;
  roleHint: string;
  rationale: string;
  assessment: EvidenceAssessment;
}

export interface CryptoMaterialMultiTraceReport {
  cases: Array<{
    sessionId: string;
    label: string;
    inputGroup: string;
    materialCount: number;
    formulaCount: number;
    verifiedFormulaCount: number;
    explicitSaltCount: number;
  }>;
  dynamicParameterCandidates: DynamicParameterCandidate[];
  verificationGateMet: boolean;
  limitations: string[];
  nextSteps: string[];
}

export type FridaArgumentKind = "integer" | "pointer" | "utf8String" | "utf16String" | "byteArray";
export type FridaCaptureDirection = "input" | "output" | "inOut";
export type FridaStalkerMode = "off" | "calls" | "blocks" | "instructions";

export interface FridaArgumentSpec {
  index: number;
  label: string | null;
  kind: FridaArgumentKind;
  direction: FridaCaptureDirection;
  length: number | null;
  lengthArg: number | null;
  lengthPointerArg: number | null;
}

export interface FridaHookRequest {
  moduleName: string;
  symbol: string | null;
  offset: string | null;
  functionName: string | null;
  arguments: FridaArgumentSpec[];
  captureRegisters: boolean;
  captureReturn: boolean;
  captureBacktrace: boolean;
  stalker: FridaStalkerMode;
  stalkerDurationMs: number;
  maxBytes: number;
}

export interface FridaHookRecipe {
  recipeId: string;
  provider: string;
  displayName: string;
  description: string;
  request: FridaHookRequest;
  evidenceRoles: string[];
  warnings: string[];
}

export interface FridaHookScript {
  hookId: string;
  fileName: string;
  targetExpression: string;
  script: string;
  warnings: string[];
  protocolVersion: string;
  fridaApiVersion: string;
}

export interface FridaOllvmDispatcherHookTarget {
  hookId: string;
  blockId: string;
  offset: string;
  stateRegisters: string[];
  score: number;
}

export interface FridaOllvmDispatcherHookScript {
  schemaVersion: string;
  moduleName: string;
  fileName: string;
  targets: FridaOllvmDispatcherHookTarget[];
  idleGapMs: number;
  maxEvents: number;
  capturePointerRegisters: number[];
  pointerCaptureBytes: number;
  script: string;
  warnings: string[];
  protocolVersion: string;
  fridaApiVersion: string;
}

export interface FridaHookSeed {
  sourceLabel: string;
  moduleName: string;
  targetMode: "symbol" | "offset";
  symbol: string;
  offset: string;
  functionName: string;
  arguments: FridaArgumentSpec[];
}

export interface FridaCapturedValue {
  index: number;
  label: string;
  kind: string;
  direction: string;
  phase: string;
  pointer: string | null;
  value: string | null;
  byteLength: number | null;
  requestedLength: number | null;
  readError: string | null;
}

export interface FridaCaptureEvent {
  index: number;
  protocol: string;
  eventId: string | null;
  hookId: string;
  event: string;
  functionName: string;
  timestampMs: number;
  threadId: number;
  callId: string | null;
  moduleName: string | null;
  moduleBase: string | null;
  moduleSize: number | null;
  target: string | null;
  dispatcherOffset: string | null;
  captureSessionId: string | null;
  flowId: string | null;
  hitSequence: number | null;
  candidateStateRegisters: string[];
  registers: Record<string, string>;
  captures: FridaCapturedValue[];
  returnValue: string | null;
  backtrace: string[];
  stalkerMode: string | null;
  stalkerEventCount: number | null;
  error: string | null;
}

export interface FridaCaptureBundle {
  schema: string;
  sourceFormat: string;
  events: FridaCaptureEvent[];
  hookIds: string[];
  enterEventCount: number;
  leaveEventCount: number;
  stalkerEventCount: number;
  warnings: string[];
}

export interface FridaOllvmStateValueCount {
  value: string;
  executionCount: number;
  firstEventIndex: number;
  lastEventIndex: number;
}

export interface FridaOllvmRegisterValueSummary {
  register: string;
  observedCount: number;
  missingCount: number;
  values: FridaOllvmStateValueCount[];
  valuesTruncated: boolean;
}

export interface FridaOllvmDispatcherNode {
  blockId: string;
  offset: string;
  eventCount: number;
  threadCount: number;
  flowCount: number;
  stateRegisters: string[];
  registerValues: FridaOllvmRegisterValueSummary[];
}

export interface FridaOllvmStateChange {
  register: string;
  fromValue: string;
  toValue: string;
  executionCount: number;
  sampleFromEventIndex: number;
  sampleToEventIndex: number;
}

export interface FridaOllvmDispatcherTransition {
  fromOffset: string;
  toOffset: string;
  executionCount: number;
  threadCount: number;
  flowCount: number;
  sampleFromEventIndex: number;
  sampleToEventIndex: number;
  stateChanges: FridaOllvmStateChange[];
  stateChangesTruncated: boolean;
}

export interface FridaOllvmDispatcherFlow {
  flowId: string;
  captureSessionId: string | null;
  threadId: number;
  eventCount: number;
  firstEventIndex: number;
  lastEventIndex: number;
  offsets: string[];
  offsetsTruncated: boolean;
  explicitFlowId: boolean;
}

export interface FridaOllvmDispatcherAtlas {
  schemaVersion: string;
  moduleName: string;
  sourceFormat: string;
  matchedEventCount: number;
  skippedEventCount: number;
  threadCount: number;
  flowCount: number;
  explicitFlowCount: number;
  derivedFlowCount: number;
  nodes: FridaOllvmDispatcherNode[];
  transitions: FridaOllvmDispatcherTransition[];
  flows: FridaOllvmDispatcherFlow[];
  flowsTruncated: boolean;
  warnings: string[];
  limitations: string[];
}

export interface AngrSeedMemoryRegion {
  address: string;
  byteLength: number;
  bytesHex: string;
  label: string;
  sourceKind: string;
  phase: string;
}

export interface AngrSeedRegister {
  name: string;
  value: string;
}

export interface AngrStateSeed {
  schemaVersion: string;
  sourceEventIndex: number;
  sourceEvent: string;
  hookId: string;
  callId: string | null;
  moduleName: string | null;
  moduleBase: string | null;
  moduleSize: number;
  functionName: string;
  captureTarget: string | null;
  captureOffset: string | null;
  script: string;
  registersSeeded: string[];
  registers: AngrSeedRegister[];
  memoryRegions: AngrSeedMemoryRegion[];
  warnings: string[];
}

export interface OllvmAnalysisOptions {
  nodeId: number | null;
  moduleName: string | null;
  startSeq: number | null;
  endSeq: number | null;
  includeChildCalls: boolean;
  maxBlocks: number;
  maxEdges: number;
}

export interface OllvmScope {
  sessionId: string;
  nodeId: number | null;
  functionName: string | null;
  moduleName: string;
  moduleBase: string;
  startSeq: number;
  endSeq: number;
  childCallsExcluded: number;
}

export interface DynamicBlockInstruction {
  offset: string;
  address: string;
  disasm: string;
  executionCount: number;
  sampleSeq: number;
}

export interface DynamicBasicBlock {
  blockId: string;
  moduleName: string;
  startOffset: string;
  endOffset: string;
  startAddress: string;
  endAddress: string;
  visitCount: number;
  predecessorCount: number;
  successorCount: number;
  terminalOperation: string;
  sampleSeqs: number[];
  instructions: DynamicBlockInstruction[];
}

export interface DynamicCfgEdge {
  sourceBlockId: string;
  targetBlockId: string;
  sourceOffset: string;
  targetOffset: string;
  kind: string;
  executionCount: number;
  sampleSeq: number;
  backward: boolean;
}

export interface DispatcherStateSnapshot {
  seq: number;
  values: Record<string, string>;
}

export interface DispatcherStateTransition {
  register: string;
  fromValue: string;
  toValue: string;
  executionCount: number;
  sampleSeq: number;
}

export interface BranchStateObservation {
  seq: number;
  outcome: string;
  successor: string;
  registers: Record<string, string>;
}

export interface BranchConditionValueCount {
  value: string;
  count: number;
}

export interface BranchFlagBitProfile {
  flag: string;
  setCount: number;
  clearCount: number;
}

export interface BranchConditionOutcomeProfile {
  outcome: string;
  observationCount: number;
  values: BranchConditionValueCount[];
  flagBits: BranchFlagBitProfile[];
}

export interface BranchConditionStateProfile {
  sourceRegister: string | null;
  capturedObservationCount: number;
  missingObservationCount: number;
  distinctValueCount: number;
  values: BranchConditionValueCount[];
  flagBits: BranchFlagBitProfile[];
  outcomes: BranchConditionOutcomeProfile[];
  incomplete: boolean;
}

export interface DynamicBranchProfile {
  branchOffset: string;
  disasm: string;
  executionCount: number;
  observedTakenCount: number;
  observedFallthroughCount: number;
  observedOtherCount: number;
  observedSuccessors: string[];
  conditionSourceOffsets: string[];
  observations: BranchStateObservation[];
  observationsTruncated: boolean;
  conditionStateProfile: BranchConditionStateProfile;
}

export interface DispatcherCandidate {
  blockId: string;
  startOffset: string;
  endOffset: string;
  visitCount: number;
  predecessorCount: number;
  successorCount: number;
  indirectBranchCount: number;
  backwardEdgeCount: number;
  stateRegisters: string[];
  stateSnapshots: DispatcherStateSnapshot[];
  stateTransitions: DispatcherStateTransition[];
  stateSnapshotsTruncated: boolean;
  rationale: string;
  assessment: EvidenceAssessment;
}

export interface OpaqueBranchCandidate {
  branchOffset: string;
  disasm: string;
  executionCount: number;
  observedTakenCount: number;
  observedFallthroughCount: number;
  observedOtherCount: number;
  observedSuccessors: string[];
  conditionSourceOffsets: string[];
  observations: BranchStateObservation[];
  observationsTruncated: boolean;
  conditionStateProfile: BranchConditionStateProfile;
  rationale: string;
  assessment: EvidenceAssessment;
}

export interface OllvmReport {
  schemaVersion: string;
  scope: OllvmScope;
  executedInstructionCount: number;
  uniqueInstructionCount: number;
  blockCount: number;
  edgeCount: number;
  blocks: DynamicBasicBlock[];
  edges: DynamicCfgEdge[];
  branchProfiles: DynamicBranchProfile[];
  dispatcherCandidates: DispatcherCandidate[];
  opaqueBranchCandidates: OpaqueBranchCandidate[];
  instructionsTruncated: boolean;
  blocksTruncated: boolean;
  edgesTruncated: boolean;
  limitations: string[];
  nextSteps: string[];
}

export interface OllvmTraceCase {
  sessionId: string;
  label: string;
  nodeId: number | null;
  moduleName: string | null;
  startSeq: number | null;
  endSeq: number | null;
  includeChildCalls: boolean;
  staticBinaryPath: string | null;
}

export interface ElfBinaryIdentity {
  binaryPath: string;
  binarySha256: string;
  fileSize: number;
  format: string;
  architecture: string;
  elfMachine: number;
  buildId: string | null;
}

export interface OllvmDispatcherCaseEvidence {
  label: string;
  present: boolean;
  candidate: boolean;
  visitCount: number;
  score: number;
  successors: string[];
  stateRegisters: string[];
  stateTransitionCount: number;
}

export interface OllvmDispatcherStability {
  startOffset: string;
  presentInRuns: number;
  candidateInRuns: number;
  commonStateRegisters: string[];
  observedStateRegisters: string[];
  cases: OllvmDispatcherCaseEvidence[];
  rationale: string;
  assessment: EvidenceAssessment;
}

export interface OllvmBranchCaseEvidence {
  label: string;
  present: boolean;
  executionCount: number;
  observedTakenCount: number;
  observedFallthroughCount: number;
  observedOtherCount: number;
  observedSuccessors: string[];
}

export interface OllvmBranchStability {
  branchOffset: string;
  presentInRuns: number;
  stableSingleOutcome: boolean;
  alternateOutcomesObserved: boolean;
  classification: string;
  cases: OllvmBranchCaseEvidence[];
  rationale: string;
  assessment: EvidenceAssessment;
}

export interface OllvmMultiTraceReport {
  schemaVersion: string;
  cases: Array<{
    sessionId: string;
    label: string;
    moduleName: string;
    blockCount: number;
    edgeCount: number;
    dispatcherCandidateCount: number;
    branchProfileCount: number;
    opaqueBranchCandidateCount: number;
    binaryIdentity: ElfBinaryIdentity | null;
  }>;
  binaryIdentityStatus: string;
  sameBinaryConfirmed: boolean;
  binarySha256: string | null;
  buildId: string | null;
  dispatcherStability: OllvmDispatcherStability[];
  branchStability: OllvmBranchStability[];
  verificationGateMet: boolean;
  limitations: string[];
  nextSteps: string[];
}

export interface OllvmVersionTraceCase {
  versionId: string;
  sessionId: string;
  nodeId: number | null;
  moduleName: string | null;
  startSeq: number | null;
  endSeq: number | null;
  includeChildCalls: boolean;
  staticBinaryPath: string;
}

export interface OllvmStateRegisterFingerprint {
  register: string;
  snapshotCount: number;
  distinctValueCount: number;
  transitionCount: number;
  distinctTransitionCount: number;
  selfTransitionCount: number;
  valueWidthBits: number | null;
}

export interface OllvmBlockFingerprint {
  versionId: string;
  blockId: string;
  moduleName: string;
  startOffset: string;
  endOffset: string;
  sampleSeq: number | null;
  operationSignature: string;
  normalizedOperations: string[];
  instructionCount: number;
  terminalShape: string;
  predecessorCount: number;
  successorCount: number;
  outgoingEdgeKinds: string[];
  dispatcherCandidate: boolean;
  indirectBranchCount: number;
  backwardEdgeCount: number;
  stateRegisters: OllvmStateRegisterFingerprint[];
}

export interface OllvmStateRegisterMatch {
  sourceRegister: string;
  targetRegister: string;
  score: number;
  rationale: string;
}

export interface OllvmVersionBlockCandidate {
  targetBlock: OllvmBlockFingerprint;
  score: number;
  classification: string;
  operationSimilarity: number;
  stateRegisterMatches: OllvmStateRegisterMatch[];
  rationale: string;
  assessment: EvidenceAssessment;
}

export interface OllvmVersionTargetMapping {
  targetVersionId: string;
  ambiguous: boolean;
  candidates: OllvmVersionBlockCandidate[];
}

export interface OllvmVersionMapReport {
  schemaVersion: string;
  baselineVersionId: string;
  versions: Array<{
    versionId: string;
    sessionId: string;
    moduleName: string;
    blockCount: number;
    edgeCount: number;
    dispatcherCandidateCount: number;
    binaryIdentity: ElfBinaryIdentity;
  }>;
  dispatcherMappings: Array<{
    sourceBlock: OllvmBlockFingerprint;
    targets: OllvmVersionTargetMapping[];
  }>;
  verificationGateMet: boolean;
  limitations: string[];
  nextSteps: string[];
}

export interface IdaOllvmScript {
  fileName: string;
  script: string;
  schemaVersion: string;
  warnings: string[];
}

export interface IdaAnnotation {
  offset: string;
  name: string | null;
  comment: string | null;
  repeatableComment: string | null;
}

export interface IdaAnnotationBundle {
  schema: string;
  moduleName: string;
  imageBase: string;
  annotations: IdaAnnotation[];
}

export interface AngrOllvmScript {
  fileName: string;
  script: string;
  schemaVersion: string;
  fridaSeed: AngrOllvmFridaSeedProvenance | null;
  fridaSeeds: AngrOllvmFridaSeedProvenance[];
  expectedBinaryIdentity: ElfBinaryIdentity | null;
  flowConfig: AngrOllvmFlowConfig;
  warnings: string[];
}

export interface AngrOllvmFlowConfig {
  enabled: boolean;
  maxDepth: number;
  maxStatesPerProbe: number;
}

export interface AngrOllvmFridaSeedProvenance {
  sourceEventIndex: number;
  hookId: string;
  callId: string | null;
  moduleName: string;
  functionName: string;
  captureOffset: string;
  registersSeeded: string[];
  memoryRegionCount: number;
  matchedProbeOffsets: string[];
  matchedBranchOffsets: string[];
  matchedDispatcherOffsets: string[];
}

export interface AngrSuccessor {
  address: string;
  offset: string | null;
  jumpkind: string | null;
  satisfiable: boolean | null;
}

export interface AngrBlockResult {
  offset: string;
  cfgNodeFound: boolean;
  functionName: string | null;
  size: number | null;
  staticSuccessors: AngrSuccessor[];
  observedSuccessors: string[];
  unobservedStaticSuccessors: string[];
  dynamicOnlySuccessors: string[];
}

export interface AngrBranchProbe {
  offset: string;
  status: string;
  seedKind: string | null;
  sourceSeq: number | null;
  sourceEventIndex: number | null;
  sourceOffset: string | null;
  seededRegisters: string[];
  seededMemoryRegions: string[];
  observedSuccessors: string[];
  successors: AngrSuccessor[];
  constraints: string[];
  flowExploration: AngrFlowExploration | null;
  limitation: string;
  error: string | null;
}

export interface AngrFlowPath {
  status: string;
  offsets: string[];
  jumpKinds: string[];
  terminalAddress: string;
  terminalOffset: string | null;
  matchedDispatcherOffset: string | null;
  dispatcherStateValues: AngrRegisterValue[];
  constraintCount: number;
  constraints: string[];
  error: string | null;
}

export interface AngrRegisterValue {
  register: string;
  status: string;
  value: string | null;
  alternatives: string[];
}

export interface AngrFlowExploration {
  maxDepth: number;
  maxStates: number;
  exploredStates: number;
  truncated: boolean;
  paths: AngrFlowPath[];
  limitation: string;
}

export interface AngrDispatcherProbe {
  offset: string;
  status: string;
  seedKind: string;
  sourceEventIndex: number;
  sourceOffset: string;
  seededRegisters: string[];
  seededMemoryRegions: string[];
  stateRegisters: string[];
  sourceStateValues: AngrRegisterValue[];
  flowExploration: AngrFlowExploration | null;
  limitation: string;
  error: string | null;
}

export interface AngrOllvmResultBundle {
  schema: string;
  moduleName: string;
  binarySha256: string;
  expectedBinarySha256: string | null;
  binaryIdentityMatched: boolean | null;
  mappedBase: string;
  architecture: string;
  angrVersion: string;
  cfgKind: string;
  fridaSeed: AngrOllvmFridaSeedProvenance | null;
  fridaSeeds: AngrOllvmFridaSeedProvenance[];
  flowConfig: AngrOllvmFlowConfig | null;
  blocks: AngrBlockResult[];
  branchProbes: AngrBranchProbe[];
  dispatcherProbes: AngrDispatcherProbe[];
  warnings: string[];
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

export interface DynamicAesSboxFingerprint {
  baseAddr: string;
  directionCandidate: "Encrypt" | "Decrypt";
  matchingReads: number;
  totalReadsInRegion: number;
  distinctIndices: number;
  matchRatio: number;
  firstSeq: number;
  lastSeq: number;
  instructionSites: string[];
}

export interface DynamicAesKeySchedule {
  scheduleAddress: string;
  rawKeyHex: string;
  startSeq: number;
  endSeq: number;
  instructionSites: string[];
  verification: {
    wordsChecked: number;
    wordsMatched: number;
    firstMismatchWord: number | null;
    keyBits: number;
    scheduleBytes: number;
    standardKeySchedule: boolean;
    partialSchedule: boolean;
  };
}

export interface DynamicAesSemanticVerification {
  status: "VerifiedBlock" | "VerifiedPartial" | "VerifiedFull";
  algorithm: string;
  keyBits: number;
  mode: string;
  direction: "Encrypt" | "Decrypt";
  padding: string | null;
  blocksChecked: number;
  matchedBlocks: number;
  allMatched: boolean;
  fullCallCoverage: boolean;
  keyScheduleAddress: string;
  inputAddress: string;
  outputAddress: string;
  byteLen: number;
  firstInputSeq: number;
  lastInputSeq: number;
  firstOutputSeq: number;
  lastOutputSeq: number;
}

export interface WhiteBoxReport {
  plaintext: WhiteBoxIoBlock | null;
  ciphertext: WhiteBoxIoBlock | null;
  inputCandidates: WhiteBoxIoBlock[];
  outputCandidates: WhiteBoxIoBlock[];
  implementationKind: "StandardSoftware" | "ObfuscatedStandardSoftware" | "TableDrivenSoftware" | "BitslicedSoftware" | "KeyFusedTables" | "Unknown";
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
  aesSboxFingerprints?: DynamicAesSboxFingerprint[];
  aesKeySchedules?: DynamicAesKeySchedule[];
  aesSemanticVerification?: DynamicAesSemanticVerification | null;
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
  inputHex: string;
  outputHex: string;
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
  verification: "Verified" | "VerifiedBlock" | "VerifiedPartial" | "VerifiedFull";
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
