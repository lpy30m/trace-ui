# trace-ui MCP tools — argument & return reference

All tools are prefixed `mcp__trace-ui__`. `session_id` is optional whenever exactly one trace is open.
Line numbers in taint `@LINE` specs are **1-based**; `start_seq`/`end_seq`/`seq` filters are **0-based**.

## Session

- **open_trace** `{file_path, force_rebuild?, skip_strings?}` → `{session_id, file_path, file_size,
  total_lines, has_string_index, from_cache, module_name, entry_address, trace_format, function_count}`.
  First step. Index build may take seconds; cached afterward.
- **close_trace** `{session_id?}` → releases indexes, cancels background tasks. Saved analyses persist on disk.

## Browse / verify (use these to prove a claim)

- **get_trace_lines** `{start_seq, count?=20 (max 100), full?}` → instruction lines (address, disasm,
  register changes, mem access). `full:true` adds raw / reg_before / so_offset / mem_size.
- **get_memory** `{address, seq?, length?=64 (max 256)}` → bytes at an address *as of* that line, with a
  `known` bitmap for never-written bytes.
- **get_strings** `{search?, min_len?=4, limit?=50, offset?}` → runtime strings (addr, content, encoding,
  xref count). Search for "http", "token", "key", "sign", etc.
- **get_call_tree** `{node_id, depth?=1 (max 3)}` → call-tree nodes (node_id=0 is root). Each node: func
  address/name, entry/exit line, child node ids.
- **search_instructions** `{query, use_regex?, case_sensitive?, seq_range?, addr_range?, max_results?=30
  (max 200)}` → matching lines. `query` may be `/regex/`. Filter with `seq_range:"3000-6000"` or
  `addr_range:"0x246F00-0x249800"` (SO offset).

- **search_value** \`{query, kind?=auto, endian?=both, integer_width?, include_utf8?=true,
  include_utf16le?=true, include_nul?, search_strings?=true, search_memory?=true,
  search_trace?=true, max_results?=100}\` returns explicit byte interpretations plus unified string,
  historical-memory, and exact trace-text hits. Memory hits expose \`addr\`, \`firstSeq\`, \`lastSeq\`,
  and \`writeSeqs\`. It searches digest bytes; use \`analyze_known_digest\` to recompute candidate inputs.

## Memory objects / aliases / lifetime

- **reconstruct_memory_objects** `{session_id?,start_seq?,end_seq?,include_stack_frames?=true,
  include_runtime_clusters?=true,max_objects?=1000,max_aliases_per_object?=64,
  max_field_windows_per_object?=64,max_access_samples_per_object?=16,max_anomalies?=256,
  max_runtime_clusters?=256,max_accesses?=2000000,max_stack_distance?=1048576}` returns
  `trace-ui/memory-object-graph-v1`. It reconstructs allocation/mmap/stack/runtime-cluster candidates,
  object generations, bounds, release/reuse state, base+offset aliases, field windows, nearby accesses,
  and Candidate access-after-lifetime/out-of-bounds leads. Missing allocator/free calls, trace truncation,
  and unattributed pages remain explicit unknowns. The result saves an `analysis_id` and never proves
  ownership, type, a memory-safety defect, or exploitability.
- **explain_memory_pointer** `{session_id?,address,seq?,include_stack_frames?=true}` explains one pointer
  at an exact 0-based sequence using the reconstructed allocation generation, live/released state,
  interior offset, register/call-argument aliases, field windows, and nearby access samples. Use it before
  treating equal absolute addresses across time as one buffer. A released-only or out-of-bounds match is
  Candidate/Related evidence and requires exact trace/allocator counter-evidence review.

## Crypto

- **analyze_crypto_implementations** `{algorithm?="aes", static_binary_path?}` → preferred implementation
  report. Returns semantic AES verification when observable, implementation kind, key exposure,
  white-box status, state layout, neutral I/O candidates, lookup tables, normalized fingerprints,
  dynamic encoding-boundary candidates, and optional static ELF reconciliation. `static_binary_path`
  must identify the exact local ELF used by the trace. Static/dynamic equality proves file-backed table
  provenance only; `assessment.verificationGateMet` still requires semantic evidence. Saves `analysis_id`.
- **analyze_whitebox_crypto** — compatibility alias; prefer `analyze_crypto_implementations`.
- **analyze_crypto_functions** `{max_candidates?=50}` → **preferred for "which function is the crypto".**
  Per-function candidates ranked by confidence: `{funcId, funcAddr, funcName, entrySeq, exitSeq,
  algorithms, magicHits, distinctMagics, cryptoInsnCounts, io:{entryArgs(X0-7), returnValue(X0),
  callAnnotation}, assessment:{confidence: high|medium|low, score, factors[]}}`. High = dedicated crypto
  instructions or many coherent constants; single stray constant → low. Saves `analysis_id`.
- **analyze_crypto** `{context_lines?=3 (max 10)}` → raw per-line magic-constant hits with surrounding
  context. Noisy (a lone constant ≠ crypto). Use to enumerate constant occurrences, not to conclude.
- **analyze_known_digest** `{digests:[...], algorithm?=auto, search_strings?=true, search_memory?=true,
  utf8_nul?, utf16le?, utf16le_nul?, trace_matches?=true, max_trace_matches?=3, data_only?=true}` →
  `{string_matches, memory_matches, traced_matches, candidate_assessments, assessment_summary:{verified,
  related, uncertain}}`. Matches a known digest to trace strings / reconstructed memory buffers and traces
  the origin. `verified` = bytes recompute to the digest. Enable utf16le/utf8_nul if plain fails. Saves id.
- **investigate_crypto_flow** `{digests?, algorithm?, context_lines?, max_crypto_matches?, trace_matches?,
  data_only?}` → orchestrates crypto detection + digest correlation into one evidence pack. Saves id.

- **compare_crypto_table_traces** \`{cases:[{session_id,label,key_group,input_group,
  static_binary_path?}, ...]}\` compares a controlled multi-trace matrix. Use at least two inputs for
  each of at least two keys with constant ELF Build ID/coverage. It returns input stability and cross-key
  shape/value comparisons, but always \`verificationGateMet:false\`: structural evidence is not proof.

- **analyze_crypto_materials** `{session_id?, max_materials?=500, include_unknown?=false}` builds a
  unified evidence-ranked index of keys, passwords, salt, IV, nonce, counter, plaintext/ciphertext,
  digest/MAC, AAD, and authentication tags. It recomputes observable AES, MD5/SHA, HMAC, and PBKDF2
  formulas. Deterministic recomputation may open the Verified gate; API role inference alone is Related.
- **compare_crypto_material_traces** `{cases:[{session_id,label,input_group}, ...]}` compares two to
  sixteen controlled traces. Pairs sharing `input_group` isolate changing byte ranges inside verified
  digest inputs. Returned `saltOrNonceCandidate` ranges remain candidates until role provenance exists.
- **verify_crypto_semantic_kat** `{algorithm,direction?,key_hex?,input_hex?,observed_output_hex,
  iv_hex?,aad_hex?,observed_tag_hex?,password_hex?,salt_hex?,iterations?,derived_key_length?,
  output_path?}` creates a strict `trace-ui/crypto-semantic-kat-verification-v1` report for AES
  ECB/CBC/CTR/GCM, MD5, SHA-1/256/384/512, HMAC, or PBKDF2-HMAC. Hex is strict and bounded; PBKDF2 is
  limited to 1,000,000 iterations and 4096 output bytes. It records exact parameters, recomputed output,
  the first mismatch range, and an exact `claimScope`. Only `verified-full` can support the matching
  `crypto:*` scope. A saved report contains sensitive material.
- **inspect_crypto_semantic_kat** `{file_path}` strictly parses an existing KAT report and recomputes
  every serialized field from the embedded vector. Modified status, claimScope, output, or parameters are
  rejected. Passing verifies only that exact vector, not function provenance, runtime reachability, or
  OLLVM/simulator structure.

## Frida 16 hook generation

- **list_frida_hook_recipes** `{}` returns audited Frida 16.x request templates for common
  OpenSSL/BoringSSL and Apple CommonCrypto MD5/SHA, EVP, HMAC, PBKDF2, and CCCrypt call shapes. Each
  recipe includes evidence roles and ABI/algorithm warnings; applying one only prefills generation.
- **generate_frida_hook** `{module_name, symbol?|offset?, function_name?, arguments?,
  capture_registers?=true, capture_return?=true, capture_backtrace?=false,
  capture_exact_call?=false, stalker?=off,
  stalker_duration_ms?=10000, max_bytes?=256}` returns a bounded JavaScript hook using the Frida 16.x
  APIs. Each argument selects X0-X7 with `kind` (`integer`, `pointer`, `utf8String`, `utf16String`,
  `byteArray`), `direction` (`input`, `output`, `inOut`), and one optional length source: fixed `length`,
  X-register `length_arg`, or output-only leave-time u32 pointer `length_pointer_arg`. Failed output
  length dereferences emit `readError` without reading the target buffer. The script
  emits `trace-ui/frida-hook-v1` messages and `TRACE_UI_JSON` strict-JSON log lines. It is generated
  only; the user manually attaches and loads it. `capture_registers:true` records X0-X28, FP/LR/SP/PC,
  plus NZCV when the Frida 16 ARM64 context exposes it; buffer argument selection remains X0-X7.
  `capture_exact_call:true` requires register and return capture, captures every configured argument on
  enter and leave, and emits exact caller/call-site/target/`PC+4` return metadata under one
  `hookId+callId`. It contains sensitive state and does not itself authorize replay.
- **summarize_exact_calls** `{capture_path,caller_module_name,static_binary_path,max_calls?=1024,
  max_memory_bytes_per_call?=1048576,output_path?}` strictly recomputes paired exact-call records from a
  user capture and exact AArch64 caller ELF. It reports full GPR/NZCV/return/register differences,
  paired byteArray mutations, truncation/read errors, callee-saved violations, unpaired events, exact
  call-site/target/return, and `captureReady`. Hidden memory, SIMD/FP, TLS/errno, system/syscall, and
  asynchronous effects remain unknown. `verificationGateMet` is always false.
- **authorize_exact_call_replay** `{summary_path,static_binary_path,call_ids,
  captured_memory_effects_complete?=false,no_simd_fp_side_effects?=false,
  no_tls_side_effects?=false,no_system_register_or_syscall_effects?=false,
  no_thread_signal_or_callback_effects?=false,deterministic_for_exact_preconditions?=false,
  output_path?}` reopens and recomputes the summary and exact ELF. One to 64 selected calls remain
  blocked unless all six assumptions are explicitly true and every intrinsic capture check passes.
  Authorized records are Candidate/Related replay effects, contain sensitive state, and never prove API
  semantics or set `verificationGateMet:true`. When imported into an Analysis Case, ingest the exact ELF
  and source Frida capture before the summary, then ingest the authorization. The case auto-binds and
  strictly recomputes summary parents (capture + ELF) and authorization parents (summary + same ELF);
  parent integrity or parser drift invalidates the downstream artifact.
- **generate_frida_runtime_attestation** `{module_name,static_binary_path,window_bytes?=4096,
  max_windows?=1024}` reads the exact AArch64 ELF, maps ELF-header/Build-ID and file-backed executable
  `PT_LOAD` windows to module-relative offsets, embeds expected SHA-256 values and a pure JavaScript
  SHA-256 implementation in a bounded Frida 16.x script, and returns the full plan. `window_bytes` must
  be a power of two from 256 through 65536; `max_windows` is 1-4096 and total planned bytes are bounded.
  The user runs the script manually. Deterministic sampling is explicitly Related, never Verified.
- **inspect_runtime_attestation** `{capture_path,exact_binary_path}` strictly parses user-captured
  `trace-ui/frida-runtime-attestation-v1` JSON/array/NDJSON/send/CLI output, deduplicates duplicate send/
  console records, regenerates the exact-ELF plan, and returns `verified-full`, `related-sampled`,
  `refuted`, `mixed`, or `incomplete` with executable byte coverage, mismatched/unreadable/missing/
  unexpected windows, supporting evidence, counter-evidence, blockers, and limitations. `verified-full`
  is scoped to captured mapped metadata and all file-backed executable `PT_LOAD` bytes; it is not trusted
  remote attestation and does not verify crypto semantics, OLLVM, reachability, or simulator completeness.
- **generate_frida_ollvm_dispatcher_hook** accepts an OLLVM scope plus
  `max_dispatchers?=12`, `idle_gap_ms?=1000`, `max_events?=50000`,
  `capture_pointer_registers?=[]` (unique X0-X28), `pointer_capture_bytes?=64` (1-4096), and
  `stack_capture_bytes?=0` (0-16384 bytes starting at SP). It
  generates one bounded Frida 16.x script for ranked dispatcher `startOffset` values, up to 64 targets
  and 200000 hits. Dedicated `ollvm-dispatcher-hit` events include full ARM64 GPRs,
  `dispatcherOffset`, `captureSessionId`, `flowId`, `hitSequence`, candidate state registers, and
  optional bounded byteArray pointer snapshots/readError records. Trace UI never runs the script.
- **generate_frida_unicorn_recapture_hook** `{unicorn_result_path,suggestion_indices,max_events?=5000}`
  strictly validates a manually produced `trace-ui/unicorn-ollvm-v1` result and converts one to 64
  selected register-relative suggestions into one bounded Frida 16.x script. Supported bases are X0-X28
  and SP, signed displacement is limited to +/-1 MiB, each memory window is 1-4096 bytes, and the script
  contains at most 32 exact seed targets and 256 windows. It hooks the original seed `captureOffset`,
  re-reads prior byteArray seed windows only when their runtime X0-X28/SP-relative relation was verified,
  merges/deduplicates those windows with the selected new suggestions, and emits full GPR/NZCV plus
  `byteArray`/`readError` captures using `trace-ui/frida-hook-v1`. It never reuses stale bytes or old
  absolute addresses and never attaches, spawns, loads, or executes Frida. Unsupported/truncated prior
  regions are reported explicitly. The embedded ELF SHA-256 is prior-replay provenance only.
- **generate_frida_unicorn_checkpoint_hook** `{unicorn_result_path,seed_capture_offsets,max_events?=5000}`
  strictly validates one manually produced `trace-ui/unicorn-ollvm-v1` result, selects one to 32
  original seed offsets, and derives at most 32 closer targets from supported stalled runs.
  `missing-memory` prefers each actual missing `pcOffset`; `call-boundary` uses the recorded AArch64
  `PC+4` return offset; `missing-register`, `loop-detected`, `instruction-limit`, and `timeout` use
  `terminalOffset`. The generated Frida 16.x Hook captures X0-X28, FP/LR/SP/PC/NZCV and re-reads only
  verified current-register X0-X28/SP-relative seed/suggestion windows. A post-call target emits only
  when the real call returns through the continuation. Absolute
  addresses, X29/X30, unsupported stops, and unverifiable memory stay warning/manual. Trace UI never
  executes Frida; the prior ELF hash is provenance and later exact-offset authorization, not runtime
  image attestation.
- **inspect_frida_capture** `{file_path}` reads user-captured JSON objects/arrays, Frida send envelopes,
  NDJSON, or `TRACE_UI_JSON`-prefixed CLI logs. It normalizes call IDs, module metadata, registers,
  buffers, returns, backtraces, and Stalker batch counts without running Frida.
- **search_frida_capture_events** `{file_path,query?,event_type?,module_name?,function_name?,call_id?,
  only_payload?=false,offset?=0,limit?=50}` searches up to 200 compact summaries per page. It returns
  exact normalized `eventIndex` values, counts, capture labels, and payload-presence metadata without
  returning register maps, capture values, return values, or backtraces.
- **get_frida_capture_event** `{file_path,event_index,include_registers?=false,
  include_captures?=false,include_return_value?=false,include_backtrace?=false,max_bytes?=256}` reads
  one exact event. Sensitive payload sections are opt-in; each capture value is bounded to at most
  1048576 bytes and reports `valueTruncated` when shortened.
- **infer_frida_abi** `{file_path,min_observations?=2,max_functions?=64,
  max_candidates_per_function?=128,output_path?}` analyzes repeated user-captured calls and returns
  `trace-ui/frida-abi-inference-v1`: X0-X7 argument-role candidates, pointer+length pairs, stable context
  pointers, enter/leave mutation, `baseRegister + displacement` field windows, and return-value shape.
  Bounds are 2-64 observations, 1-128 functions, and 8-512 candidates per function. Exact event indices
  are retained; labels/directions remain metadata and every classification is Candidate/Related. Runtime
  pointers are process-specific. Trace UI parses/saves only and never runs Frida or the target.
- **analyze_frida_crypto_materials** `{file_path,max_materials?=1000,include_unknown?=false}` groups
  imported captures by callId and indexes key/password/salt/IV/nonce/AAD/tag/input/output/digest/MAC/KDF
  candidates. Exact MD5/SHA, HMAC, and PBKDF2 recomputation may open the Verified gate for that captured
  call. PBKDF2 work is bounded; label-only roles remain Related.
- **analyze_frida_ollvm_dispatcher_capture** accepts the same OLLVM scope plus
  `frida_capture_path`, `idle_gap_ms?=1000`, `max_events?=50000`,
  `max_values_per_register?=64`, `max_state_changes_per_transition?=128`,
  `max_flow_length?=256`, and `max_flows?=2048`. It cross-checks `dispatcherOffset` against
  `target-moduleBase`, requires an exact current dispatcher `startOffset`, and connects adjacent hits
  only within one capture session/thread/flow with contiguous sequence numbers when present. It returns
  bounded nodes, transitions, state-value distributions, state changes, and paths, then saves a
  `frida_ollvm_dispatcher_atlas` analysis. Legacy captures use warned idle-gap-derived flows. Every
  result remains Candidate/Related.
- **generate_angr_state_seed** `{file_path,event_index,include_sp?=false,include_lr?=true}` returns a
  manual Python `configure_state(state)` function. It rebases pointers inside the captured module and
  seeds captured byte buffers and available ARM64 NZCV (packed `state.regs.nzcv`, with N/Z/C/V fallback).
  Heap/stack addresses remain process-specific, and capture-point/flag-semantic mismatch remains a
  limitation.

## IDA / OLLVM

- **analyze_ollvm** `{session_id?, node_id?, module_name?, start_seq?, end_seq?,
  include_child_calls?=false, max_blocks?=1000, max_edges?=3000}` builds an ASLR-stable dynamic CFG and
  ranks dispatcher and opaque-branch candidates. It also returns dispatcher state snapshots/transitions
  and bounded branch register observations reconstructed from trace checkpoints. Results cover executed
  instructions only and are not proof of obfuscation.
- **compare_ollvm_traces** `{cases:[{session_id,label,node_id?,module_name?,start_seq?,end_seq?,
  include_child_calls?,static_binary_path?}],require_matching_binary?=false,max_blocks?=1000,max_edges?=3000}`
  compares two to sixteen controlled runs by module-relative offset. Supplied ELF hashes must agree;
  `require_matching_binary:true` also requires every case to supply an ELF. The report records identity
  status, SHA-256, and GNU Build ID when available, then reports dispatcher/state-register stability and branch outcomes.
  `alternate-outcomes-observed` is evidence against a global opaque claim; stable single outcomes remain
  Candidate/Related. The result is saved to the first case session.
- **map_ollvm_versions** `{versions:[{version_id,session_id,node_id?,module_name?,start_seq?,end_seq?,
  include_child_calls?,static_binary_path}],baseline_version_id?,max_blocks?=1000,max_edges?=3000,
  max_matches_per_block?=3,min_score?=55}` maps baseline dispatcher candidates across two to eight
  distinct AArch64 ELF builds. Every version requires an exact ELF and all SHA-256 values must differ;
  equal hashes are rejected in favor of `compare_ollvm_traces`. Module basenames and offsets may change.
  It scores bounded normalized operation LCS, terminal family, dynamic predecessor/successor and edge-kind
  shape, independently ranked dispatcher role, and state-register behavioral roles. Top candidates within
  five points are marked `ambiguous`. All mappings keep `verificationGateMet:false`; do not reuse source
  offsets, concrete state values, Frida captures, or angr seeds in another build. The result is saved to
  the selected baseline session.
- **generate_ida_ollvm_script** accepts the same scope plus `ida_image_base?` and
  `add_user_xrefs?=false`. It returns IDAPython that applies dynamic comments/colors and can export
  `trace-ui/ida-ollvm-v1` annotations. The user runs it manually in IDA.
- **inspect_ida_annotations** `{file_path}` validates and returns module-relative names/comments from a
  JSON file exported manually by the generated IDAPython bridge.
- **generate_angr_ollvm_script** accepts the same trace scope plus
  `probe_opaque_branches?=true`, `use_cfg_emulated?=false`,
  `explore_seeded_flows?=true`, `flow_max_depth?=8`, `flow_max_states_per_probe?=32`, and optional
  `frida_capture_path`, legacy `frida_event_index`, bounded `frida_event_indices` (up to 32),
  `frida_include_sp?=false`, `frida_include_lr?=true`, `static_binary_path`, and
  `checkpoint_result_path`.
  The Frida fields must select user-captured `hook-enter` or `ollvm-dispatcher-hit` events whose
  module-relative targets exactly match an opaque branch, one of its recorded condition-source
  offsets, a dispatcher `startOffset`, or—only when `checkpoint_result_path` is supplied—a supported
  closer checkpoint offset. Checkpoint authorization requires the report module, prior result
  expected/actual SHA-256, current exact AArch64 ELF SHA-256, and capture offset to match; mismatches
  are rejected. When `static_binary_path` is supplied, its SHA-256 is embedded and the generated
  manual script refuses a different file before running angr.
  It returns standalone Python that the
  user manually runs against the exact ELF/shared object. The script reconciles angr static CFG
  successors with observed dynamic edges, performs blank-state probes, and performs trace-register-seeded
  probes when bounded branch snapshots are available. Each exact branch/condition-source Frida seed adds
  captured registers and byteArray memory regions as a separate branch candidate probe. Each exact
  dispatcher-entry seed adds a dispatcher probe whose bounded flow stops at the next dispatcher, loop,
  external target, dead end, unconstrained state, or configured bound and reports source/target state
  registers as `concrete`, `symbolic` with at most two alternatives, or `unavailable`. Missing flags,
  SIMD, memory, or entry-path constraints can still change feasibility. Branch continuation applies to
  the first trace seed per candidate and every exact branch Frida seed; dispatcher continuation is independent
  of `probe_opaque_branches`. Both record bounded endings and reject
  result JSON that exceeds the configured 1-64 depth or 1-256 state bounds.
  A `frida-capture-authorized-checkpoint` seed creates a separate `checkpointProbes` entry. It starts
  from a blank state at the authorized closer offset, applies captured GPR/NZCV/byteArray memory, and
  uses the same bounded next-dispatcher/loop/external/dead-end/unconstrained/bound exploration.
  It writes `trace-ui/angr-ollvm-v1` JSON with all seed provenance and optional expected-hash/match
  fields. Trace UI does not install or execute angr.
- **inspect_angr_ollvm_results** `{file_path}` validates and returns an imported
  `trace-ui/angr-ollvm-v1` bundle, including binary SHA-256, mapped base, CFG kind, unobserved static
  successors, dynamic-only successors, optional branch probes, exact dispatcher-entry probes, and
  authorized `checkpointProbes` with bounded paths and state-register values. Blank-state,
  dispatcher-flow, and checkpoint-flow results are candidate evidence and do not prove real-entry
  reachability or a recovered/deobfuscated CFG.
- **generate_unicorn_ollvm_script** accepts the same trace scope plus mandatory
  `frida_capture_path`, one to 32 exact `frida_event_indices` (legacy `frida_event_index` is accepted),
  mandatory `static_binary_path`, and bounded concrete limits: `max_instructions?=50000`,
  `timeout_ms?=5000`, `max_memory_writes?=4096`, `max_recorded_offsets?=50000`,
  `stop_on_call?=true`, `loop_visit_limit?=2`, optional `checkpoint_result_path`, and optional
  `exact_call_authorization_paths` (up to 16 strict authorization artifacts / 64 calls). Every event must
  exactly match an opaque branch, condition-source offset, dispatcher entry, or—when the prior result is
  supplied—a supported checkpoint offset authorized from the same module and exact ELF SHA-256. The
  generated Python requires Unicorn, Capstone, and
  pyelftools, verifies the AArch64 ELF SHA-256, maps PT_LOAD segments, applies captured registers and
  byteArray memory, and stops explicitly at next-dispatcher, return, call, loop, missing register/memory,
  unsupported SIMD/system state, timeout, or bounds. It never silently treats uncaptured runtime memory
  as valid zero state. An authorized external call is crossed only when call-site, target, `PC+4`
  return, X0-X7/SP, and captured input memory all match exactly; mismatch/apply/limit conditions are
  explicit stop reasons and unknown calls remain `call-boundary`.
- **inspect_unicorn_ollvm_results** `{file_path}` strictly validates
  `trace-ui/unicorn-ollvm-v1`, including exact ELF identity, per-event concrete replay runs,
  dispatcher transition groups, register changes, memory writes, missing-state evidence, and bounded
  register-relative Frida recapture suggestions. It also returns per-seed `seedRecapturePlans` for exact
  byteArray regions with verified register-relative provenance; regions above 4096 bytes are split into
  bounded windows. Supported suggestions can be passed to
  `generate_frida_unicorn_recapture_hook`, then the resulting user-captured exact-seed `hook-enter` can
  be selected in another Unicorn/angr generation request. For repeated stalls, select original seed
  offsets with `generate_frida_unicorn_checkpoint_hook`, run the closer Hook manually, then select its
  new `hook-enter` in another Unicorn request while passing the same prior result as
  `checkpoint_result_path`. Results remain Candidate/Related.
- **compare_unicorn_ollvm_rounds** `{rounds:[{round_id,file_path,source_label?}, ...]}` strictly
  validates two to 16 ordered `trace-ui/unicorn-ollvm-v1` files for the same module and exact ELF
  SHA-256. It aggregates runs by exact seed `captureOffset`, reports cumulative and adjacent-round
  new/lost instruction/block offsets, new dispatchers, moved or repeated missing-memory signatures,
  seed additions/removals, configuration drift, truncation, and bounded next-step recommendations.
  The first round is baseline coverage rather than iterative progress. Trace UI only compares imported
  files; every progress/stall/regression classification remains Candidate/Related.

## Analysis case / accuracy gates

- **open_analysis_case** `{case_path,create?=false,title?,session_id?,primary_trace_path?,exact_binary_path?}` opens or creates a strict `trace-ui/case-v1` `.traceui-case`. Creating from a session records its trace artifact; `exact_binary_path` must be an AArch64 ELF. It stores SHA-256/provenance only and executes nothing.
- **ingest_analysis_case_artifact** `{case_path,artifact_path,kind_hint?,label?,parent_artifact_ids?}` hashes and strictly parses one Trace/ELF/runtime-attestation/Frida/Unicorn/angr/IDA/OLLVM/coverage/evidence-slice/analysis/crypto artifact. Runtime attestation must bind exactly one static-binary parent. A coverage report must bind exactly one static-binary parent and at least one non-binary dynamic/source parent whose SHA-256 covers every `dynamicRuns.sourceArtifactSha256`. An Evidence Slice must bind exactly the complete declared source-artifact ID set as parents. Refuted/partial artifacts are still accepted as counter-evidence or unknowns. Duplicate content is deduplicated per parent; invalid parent IDs, schemas, identities, and non-AArch64 static binaries are rejected.
- **diagnose_analysis_case** `{case_path,persist_generated_claims?=false}` runs `trace-ui/replay-doctor-v1`. It re-hashes artifacts, strictly verifies bound runtime attestations, Crypto KATs, coverage reconciliations, and Minimal Evidence Slices, compares compatible Unicorn rounds by exact module/build/seed offset, detects authorized closer captures, and returns `claimLedgerAudit`, `stateReadiness`, `experimentMatrix`, `runtimeAttestations`, `cryptoKats`, `coverageReconciliations`, `evidenceSlices`, `capturePlan`, deterministic next actions, and scoped generated claims. Nested slice inspection validates persisted bindings without recursively regenerating claims; use the standalone inspector for full current generated-claim revalidation. Uncovered block/branch samples become explicit capture targets/unknowns. It never runs Frida, Unicorn, angr, IDA, or the target.
- **plan_analysis_case_capture** `{case_path,max_targets?=12}` returns the case's bounded
  `trace-ui/information-gain-capture-plan-v1`, truncated to 1-32 ranked targets. It combines claim
  blockers/counter-evidence, exact-ELF/runtime-attestation gaps, GPR/NZCV/stack/pointer/SIMD/system
  readiness, repeated Unicorn stalls, closer checkpoints, and missing controlled-run cells. Each target
  carries artifact/module/offset anchors when available, registers/memory to capture, competing
  hypotheses, success criteria, and a redundancy key. Scores are deterministic priorities, not
  probabilities; all execution remains manual and OLLVM/simulation results remain Candidate/Related.
- **generate_coverage_reconciliation_script** `{static_binary_path,ollvm_report_path,claim_scope,
  scope_kind?="function-closure",range_start_offset?,range_end_offset?,max_instructions?=500000,
  max_blocks?=100000,max_edges?=250000,max_functions?=25000,output_path?}` strictly reads one exact
  AArch64 ELF and one `trace-ui/ollvm-v1` report, embeds their identities/source SHA, and returns a
  standalone Python/angr exporter for `trace-ui/coverage-reconciliation-v1`. Scope is the dynamic
  function closure, whole module, or a canonical inclusive module-relative range. The script enumerates
  explicit static instruction/block/branch/function/edge sets separately from the dynamic observed sets,
  with completeness/truncation flags and recomputed basis points. When `output_path` is provided the MCP
  tool saves the `.py` and returns bounded metadata; otherwise it returns the script inline. The user
  runs it manually. Trace UI never installs or executes angr or the target.
- **inspect_coverage_reconciliation** `{artifact_path,static_binary_path,source_artifact_paths?=[]}`
  strictly parses a `trace-ui/coverage-reconciliation-v1` JSON, rejects unknown/forged fields, canonical
  ordering/alignment errors, and recomputes every count and basis-point value from explicit sets. It
  verifies the exact ELF SHA-256/Build ID, requires every offset/edge/function range to fall in file-backed
  executable `PT_LOAD` bytes, and hashes the supplied source files to cover every dynamic source SHA.
  Wrong ELF, missing source, static/dynamic truncation, uncovered, or dynamic-only sites keep
  `coverageGateMet:false`. `complete-site-coverage` only caps claim level; it never proves AES absence,
  global opacity, all-input reachability, exhaustive dispatcher discovery, or complete CFG recovery.
- **generate_analysis_case_evidence_pack** `{case_path,format?="json",max_tokens?=8000,
  max_items?=256,include_generated_claims?=true}` builds `trace-ui/ai-evidence-pack-v1`. Token bounds are
  1024-65536 and combined entry bounds are 16-2048. It orders load-bearing/refuted/blocked claims,
  reports each Claim Ledger recommended and coverage-maximum status, and keeps valid supporting evidence, valid
  counter-evidence, unknowns/next actions, and invalid artifacts in separate arrays/sections. Evidence
  retains artifact ID/kind/label and raw locator; explicit `seq`, `line`, `mem:ADDR:SIZE`, module offset,
  and event index syntax is parsed into fields. The result includes deterministic token estimates and
  total/omitted counts. JSON is intended for tool reasoning and Markdown for review. This is context
  packaging only: descriptions, summaries, and the pack itself cannot open a verification gate. Coverage
  gaps are retained as `coverage-gap` unknowns rather than summarized away.
- **generate_minimal_evidence_slice** `{case_path,trace_session_bindings?=[],claim_ids?=[],
  include_generated_claims?=true,include_sensitive_values?=false,context_before?=2,context_after?=2,
  module_bytes_before?=16,module_bytes_after?=32,max_memory_bytes_per_record?=4096,
  max_records?=256,max_total_payload_bytes?=8388608,output_path?}` creates
  `trace-ui/minimal-evidence-slice-v1` for selected persisted/current generated claims. Each Trace source
  reference requires an exact case-artifact to open-session binding during generation. The bundle binds
  source artifact SHA-256, size, stored path, full parent lineage, claim/reference fingerprints, and
  materializes locator-focused Trace lines, known-mask memory bytes with per-byte provenance, one exact
  Frida event, file-backed ELF `PT_LOAD` bytes, or a bounded JSON fragment. It also emits a typed graph
  connecting case/claim/reference/artifact/build/process/event/record. Raw trace changes, memory bytes,
  Frida registers/captures/returns, and JSON values are excluded unless `include_sensitive_values=true`;
  redaction may intentionally make materialization partial. When `output_path` is supplied the file is
  saved and bounded metadata is returned. The slice is auditable provenance, never semantic proof.
- **inspect_minimal_evidence_slice** `{case_path,artifact_path}` strictly parses one saved slice, re-hashes
  every declared source, checks exact artifact metadata and parent lineage, revalidates persisted/current
  generated claim fingerprints, reopens Trace/Frida/ELF/JSON sources, recomputes every record/content hash,
  reconstructs the typed provenance graph, and recomputes summary/status. It reports stale claims,
  unrevalidated generated claims, mismatched records, blockers, unresolved/truncated/redacted state, and
  source artifact IDs. A valid result proves only bounded source/record provenance; it never proves AES
  semantics, OLLVM structure, branch reachability, deobfuscation, or simulator completeness.
- **audit_analysis_case_claims** `{case_path}` returns only the contradiction/counter-evidence gate. It
  auto-classifies negative-existence, scope-complete, global-invariance, exhaustive-enumeration, and
  complete-control-flow wording, requires an exact matching coverage artifact when applicable, and
  returns `coverageRequirement`, `coverageGateStatus`, `coverageMaxStatus`, bound artifact IDs, and
  uncovered counts. Negative-existence remains at most Observed; global-invariance/exhaustive/complete-CFG
  structural claims remain at most Related. Non-runtime `Verified` claims still need deterministic
  semantic/known-answer/exact-output evidence. A `runtime-image:*` Verified claim instead requires a
  supporting runtime-attestation artifact whose strict exact-ELF report is `verified-full`; a locator/
  description string, SHA identity, coverage, or OLLVM/Unicorn/angr structure cannot forge that gate.
- **upsert_analysis_case_experiment** `{case_path,experiment_id?,label,binary_sha256?,key_group?,input_group?,environment_group?,artifact_ids?,controlled_variables?,changed_variables?,notes?}` records a controlled run. Replay Doctor finds pairs that differ on exactly one build/key/input/environment axis, missing Cartesian cells, and confounded comparisons. Runtime execution remains manual.
- **run_accuracy_benchmark** `{suite_path}` runs a strict `trace-ui/accuracy-benchmark-suite-v1` over
  1-128 `.traceui-case` fixtures; relative case paths resolve from the suite directory. It reports
  replay/capture-plan ranking drift, claim gate/recommended-status drift, coverage requirement/gate/
  maximum-status drift, Verified false positives/false negatives, unexpected Verified claims, and fixture errors in
  `trace-ui/accuracy-benchmark-report-v1`. Optional Evidence Slice expectations also check strict status,
  record count, unresolved/truncated bounds, claim/generated binding state, record content, and provenance
  graph drift. Any mismatch makes `gateMet:false`. This is a regression gate
  over reviewed fixtures, not new proof that fixture labels describe ground truth.
- **diagnose_crypto_detection** `{session_id?,target_algorithm?="AES",static_binary_path?}` explains each detection stage: trace/index, magic constants, ARM64 crypto instructions, function attribution, software/S-box/schedule structure, semantic verification, and optional exact ELF reconciliation. `not-observed` is not absence. The static stage distinguishes `matched` from `completed-no-match`; only deterministic semantic recomputation can produce `verified`.

State readiness values are intentionally non-equivalent: `not-executed` means no bounded run exists, `not-captured` means required state was absent, `unreadable` means a requested capture failed, `not-observed` means the imported bounded path did not demonstrate the dependency, and `hash-mismatch` blocks exact-build continuation.

## Taint (data-flow slicing)

Prefer explicit source syntax: \`reg:NAME@line:N\` for a 1-based display line, or
\`mem:ADDR:SIZE@seq:N\` for a 0-based sequence (SIZE = 1..4096 bytes). Legacy bare \`@N\` remains
1-based for compatibility but should not be emitted by AI callers.

Source spec syntax: `reg:NAME@LINE` (e.g. `reg:X0@1234`) or `mem:ADDR:SIZE@LINE`
(e.g. `mem:0xbffff000:32@5930`, SIZE = 1..4096 bytes). LINE is **1-based**.

- **taint_analysis** (backward) `{from_specs:[...], data_only?=false, ignore_stack_ops?=true,
  include_lines?=30 (max 200), start_seq?, end_seq?, addr_range?}` → where a value came from. Returns
  stats + first page of tainted lines + `analysis_id`. Recommend `data_only:true`.
- **forward_taint_analysis** `{from_specs:[...], data_only?=true, start_seq?, end_seq?, max_nodes?=10000,
  include_lines?=100, max_sinks?=100}` → where a value flows to. Key fields: `potential_sinks`,
  `flow_endpoints` (classified memory/stack/JNI/file/socket/log/syscall/call/return with direction,
  category, confidence, external flag, and cross-call resource validation), `endpoint_summary`,
  `truncated`. Saves id.
- **start_forward_taint_analysis** — same, as a cancellable background task → poll `get_analysis_task`.
- **get_tainted_lines** `{analysis_id, offset?, limit?=50 (max 200), full?, ignore_stack_ops?=true, addr_range?,
  context_lines?}` → paginate the last taint result's marked instructions.

## Functions

- **analyze_function** — three modes:
  - `{node_id}` → one call's detail: entry args X0-X7, return value X0, sub-calls (with node ids).
  - `{func_name}` → all calls whose name contains it (partial, case-insensitive), with occurrences.
  - `{}` (+ `offset?`/`limit?`) → paginated list of all functions.

## Diff (compare two executions)

- **compare_traces** `{other_session_id, start_seq?, end_seq?, max_items?=100 (max 1000)}` → dynamic diff
  of functions / branches / instructions / memory-access-sites by module-relative offset (ASLR-robust),
  plus relocated function clusters matched by normalized executed instruction shape.
- **start_trace_diff** — same, background.

## Orchestration (broad, deterministic sweeps)

- **auto_investigate** `{objective, digests?, algorithm?, from_specs?, search_terms?, include_crypto?=true,
  compare_session_id?, compare_analysis_ids?, data_only?=true, max_*}` → runs session overview + search +
  crypto + known-digest + forward flow + analysis compare + trace diff, scored into one pack. `objective`
  is recorded for context; the *deterministic stages are chosen from the structured fields you pass*.
- **start_auto_investigation** / **start_crypto_investigation** — background variants → poll `get_analysis_task`.

## Evidence store (persist / review / compare)

- **list_analyses** `{kind?, limit?=20 (max 100)}` → saved-analysis summaries (id, kind, title, created,
  evidence highlights, warning count).
- **get_analysis** `{analysis_id}` → full record (request, result, evidence, limitations, next actions).
- **compare_analyses** `{analysis_ids:[2..10]}` → common vs unique evidence across analyses (cross-check
  a backward taint against a forward flow, or two crypto hypotheses).
- **export_analysis_report** `{analysis_id, format?=markdown|json, output_path?}` → write a file, or return
  inline if no path.
- **delete_analysis** `{analysis_id}`.

## Recipes (repeatable investigations)

- **list_analysis_recipes** → built-in (`forward_to_sinks`, `known_digest_flow`, `crypto_investigation`,
  `auto_investigation`) + saved custom recipes.
- **run_analysis_recipe** `{recipe_id, inputs?}` → runtime inputs override recipe defaults; saved as a run.
- **save_analysis_recipe** `{name, workflow, defaults?, description?}` / **delete_analysis_recipe** `{recipe_id}`.

## Background tasks

- **get_analysis_task** `{task_id}` → status (queued/running/completed/failed/cancelled), stage, 0-100%,
  and final `analysis_id`.
- **list_analysis_tasks** `{limit?}` / **cancel_analysis_task** `{task_id}` (cooperative; stops before
  later phases and does not save a partial record).

## Typical end-to-end (find the sign key)

```
open_trace{file_path:"/abs/trace.log"}
get_strings{search:"sign"}                         # orient
analyze_crypto_functions{}                          # which function hashes/encrypts, ranked
analyze_function{node_id:<top High candidate>}      # its args X0-X7 + return + sub-calls
taint_analysis{from_specs:["reg:X1@<entry line>"], data_only:true}   # where the key arg came from
get_trace_lines{start_seq:<key def line-1>}         # verify exact instructions
get_memory{address:"0x...", seq:<line>}             # verify the buffer bytes
# save happens automatically (analysis_id); compare_analyses to cross-check; report with quoted evidence
```
