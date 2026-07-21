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

## Frida 16 hook generation

- **generate_frida_hook** `{module_name, symbol?|offset?, function_name?, arguments?,
  capture_registers?=true, capture_return?=true, capture_backtrace?=false, stalker?=off,
  stalker_duration_ms?=10000, max_bytes?=256}` returns a bounded JavaScript hook using the Frida 16.x
  APIs. Each argument selects X0-X7 with `kind` (`integer`, `pointer`, `utf8String`, `utf16String`,
  `byteArray`), `direction` (`input`, `output`, `inOut`), and optional fixed/dynamic length. The script
  emits `trace-ui/frida-hook-v1` messages. It is generated only; the user manually attaches and loads it.

## IDA / OLLVM

- **analyze_ollvm** `{session_id?, node_id?, module_name?, start_seq?, end_seq?,
  include_child_calls?=false, max_blocks?=1000, max_edges?=3000}` builds an ASLR-stable dynamic CFG and
  ranks dispatcher and opaque-branch candidates. Results cover executed instructions only and are not
  proof of obfuscation.
- **generate_ida_ollvm_script** accepts the same scope plus `ida_image_base?` and
  `add_user_xrefs?=false`. It returns IDAPython that applies dynamic comments/colors and can export
  `trace-ui/ida-ollvm-v1` annotations. The user runs it manually in IDA.
- **inspect_ida_annotations** `{file_path}` validates and returns module-relative names/comments from a
  JSON file exported manually by the generated IDAPython bridge.
- **generate_angr_ollvm_script** accepts the same trace scope plus
  `probe_opaque_branches?=true` and `use_cfg_emulated?=false`. It returns standalone Python that the
  user manually runs against the exact ELF/shared object. The script reconciles angr static CFG
  successors with observed dynamic edges and writes `trace-ui/angr-ollvm-v1` JSON. Trace UI does not
  install or execute angr.
- **inspect_angr_ollvm_results** `{file_path}` validates and returns an imported
  `trace-ui/angr-ollvm-v1` bundle, including binary SHA-256, mapped base, CFG kind, unobserved static
  successors, dynamic-only successors, and optional branch probes. Blank-state probes are candidate
  evidence and do not prove real-entry reachability.

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
