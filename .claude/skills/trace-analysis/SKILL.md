---
name: trace-analysis
description: >
  Analyze ARM64 unidbg, GumTrace, or Frida Stalker execution traces through the trace-ui MCP server.
  Use for native/.so reverse engineering, crypto key/IV/nonce/salt/material identification,
  MD5/SHA/HMAC/PBKDF2 input matching, backward or forward taint, function I/O inspection, cross-run
  diffing, static ELF-to-trace table reconciliation, software/table-driven/obfuscated/white-box crypto
  classification, Frida 16 hook generation/capture import, angr state seeding, and dynamic IDA/angr/OLLVM analysis. Trigger on requests
  such as analyze this trace, reverse this native function, inspect this .so with its trace, find the key
  or algorithm, isolate a salt, generate a Frida hook, inspect OLLVM, where did this value come from, or
  分析 trace / 逆向 so / 污点 / 加密分析 / Frida hook / OLLVM.
---

# Trace analysis with trace-ui (MCP)

You are driving a deterministic ARM64 trace-analysis engine over MCP. The engine does the exact
computation (indexing, taint slicing, crypto detection, digest matching); **your job is to pick the
right tools in the right order, verify with exact evidence, and separate candidates from proof.**

All tools are prefixed `mcp__trace-ui__`. If the server isn't connected, tell the user to start the
Trace UI app (embedded MCP on `127.0.0.1:19821`) or register `trace-cli`, then retry.

## Core loop

1. **Open** — `open_trace{file_path}` (absolute path). Returns `session_id`, total_lines, format,
   function_count. Index build can take seconds on large traces; it's cached after the first open.
   `session_id` is optional on every later call when only one trace is open.
2. **Orient** — get the lay of the land before diving:
   - `analyze_function` (no args) → list functions; or `get_call_tree` for structure.
   - `analyze_crypto_implementations` → semantic software/table/obfuscated crypto report; pass
     `static_binary_path` when the matching ELF is available.
   - `analyze_crypto_functions` → ranked function-level structural candidates when the implementation
     report is empty or you need to locate other algorithms/functions.
   - `get_strings{search}` → runtime strings (URLs, tokens, keys, "sign", "http").
3. **Investigate** — pick a playbook below based on the actual question.
4. **Verify** — never report a lead as fact. Pull exact evidence: `get_trace_lines{start_seq}`,
   `get_memory{address,seq}`, `get_tainted_lines{analysis_id}`. Cross-check register/memory values.
5. **Save & hand off** — analyses return an `analysis_id` (persisted with the trace). Use it with
   `get_analysis`, `compare_analyses`, `export_analysis_report`. The human can review these in the
   app's **Analyses** tab, so save anything load-bearing.
6. **Close** — `close_trace` when done to free memory (optional; cancels background tasks).

## Playbooks (question → tool sequence)

**"What crypto implementation is this, and can it be verified?"**
→ `analyze_crypto_implementations` first. It can semantically verify observed AES key/input/output,
classify mode/direction/state layout, distinguish raw-key software from white-box candidates, and expose
lookup tables plus encoding-boundary evidence. If the matching ELF exists, pass `static_binary_path` and
inspect `staticBinary.tableMatches`; an exact file/dynamic match proves table provenance, not the cipher
or key by itself. Only a report with `verificationGateMet:true` is verified.

**"Which function does the encryption / hashing, and what are its inputs/outputs?"**
→ `analyze_crypto_functions`. It aggregates magic-constant hits **and** dedicated ARM64 crypto
instructions (AES/SHA/SM3/SM4/CRC32/PMULL) **by enclosing function** and scores each **High/Med/Low**.
Focus on High/Medium; each candidate reports entry X0-X7, return X0, and call annotation. Then
`analyze_function{node_id}` or `get_trace_lines` around its entry to confirm, and `get_memory` on the
pointer args to see the input/output buffers.
Do **not** lead with raw `analyze_crypto` — that's per-line magic-constant matching and a single
coincidental constant reads as a false "AES found". Use it only to enumerate raw constant hits.

**"I have a digest (MD5/SHA-1/SHA-256/SHA-384/SHA-512/CRC32); find the input / where it's produced."**
→ `analyze_known_digest{digests:[...]}`. It matches the digest against runtime strings and reconstructed
memory buffers, then auto-traces the origin. Read `candidate_assessments` / `assessment_summary`:
**verified** = these bytes recompute to the digest; **related/uncertain** = weaker. Verify with
`get_memory` / `get_trace_lines` at the reported addr/seq. Enable `utf16le`/`utf8_nul` transforms if a
plain match fails.

**"Index keys, passwords, salt, nonce, IV, plaintext/ciphertext, digest/MAC, AAD, or tags."**
→ `analyze_crypto_materials{max_materials?,include_unknown?}`. Prefer records backed by deterministic
AES, MD5/SHA, HMAC, or PBKDF2 recomputation. API argument roles are Related evidence unless their
semantics are independently verified. Use the returned `analysis_id` for audit and comparison.

**"Which changing bytes are probably salt or nonce across controlled runs?"**
→ open two to sixteen traces, then `compare_crypto_material_traces{cases:[{session_id,label,input_group}]}`.
Use the same `input_group` only when the caller-controlled primary message/password is intentionally
unchanged. A returned `saltOrNonceCandidate` is a precise changing range, not proof of its API role.

**"Where did this value (register/memory) at line N come from?"** (backward)
→ `taint_analysis{from_specs:["reg:X0@line:N"], data_only:true}`. For memory use
`["mem:0xADDR:SIZE@seq:N"]` (SIZE bytes, e.g. 16 for an MD5 buffer). Page results with
`get_tainted_lines{analysis_id}`; pagination is isolated by the saved analysis ID.

**"Where does this input flow to (sinks: file/socket/log/return)?"** (forward)
→ `forward_taint_analysis{from_specs:["reg:X0@line:N"|"mem:0xADDR:SIZE@seq:N"], data_only:true}`. Inspect
`potential_sinks` and `flow_endpoints` (classified file/socket/JNI/log/syscall, with confidence and
cross-call resource validation). On huge traces use `start_forward_taint_analysis` (background).

**"What does function F do? Its args / return / sub-calls?"**
→ `analyze_function{func_name:"F"}` to find it (or `get_call_tree`), then `analyze_function{node_id}`
for entry X0-X7, return X0, and sub-calls. `get_memory` on pointer args for buffers.

**"Two runs differ (good vs bad input, before vs after patch)."**
→ `open_trace` both (two sessions), then `compare_traces{other_session_id}` (or `start_trace_diff`) —
diffs functions/branches/instructions/memory-access-sites by module-relative offset (ASLR-robust) and
clusters relocated functions by normalized executed shape. Compare left/right offsets and sample seqs.

**"Generate a Frida hook for this function or crypto lead."**
→ For a common OpenSSL/BoringSSL or Apple CommonCrypto call, inspect `list_frida_hook_recipes` first;
otherwise use `generate_frida_hook` with a module export or module-relative offset and explicit X0-X7 capture specs.
The output targets Frida 16.x and emits `trace-ui/frida-hook-v1`. Trace UI only generates/saves the
script. The user manually attaches/spawns/loads/runs it. Never claim runtime evidence from generation.
For detailed capture selection rules, use `$frida-hook-generation`.

**"Inspect the Frida output I captured manually or turn it into angr state."**
→ `inspect_frida_capture{file_path}` for JSON arrays, send envelopes, NDJSON, or
`TRACE_UI_JSON`-prefixed CLI logs. Use `analyze_frida_crypto_materials{file_path}` to index explicit
key/password/salt/IV/nonce/input/output labels and deterministically recompute observable
MD5/SHA/HMAC/PBKDF2 calls. Select an exact event index, then call
`generate_angr_state_seed{file_path,event_index,include_sp?,include_lr?}`. Treat module rebasing as
build-specific and heap/stack addresses as process-specific. Never claim the seed proves real-entry or
branch reachability.

**"Show OLLVM execution structure in IDA."**
→ `analyze_ollvm` on a call-tree node or narrow module/seq range, normally with child calls excluded.
Then `generate_ida_ollvm_script` for manual execution in IDA. Inspect exported
`trace-ui/ida-ollvm-v1` JSON with `inspect_ida_annotations`. Dispatcher and opaque-branch findings remain
dynamic candidates; unexecuted paths are unknown. For the full workflow, use `$ida-ollvm-analysis`.

**"Reconcile this OLLVM trace with angr or probe an opaque branch."**
→ `analyze_ollvm` on a narrow call-tree node/range, then `generate_angr_ollvm_script`. Give the
generated Python to the user for manual execution against the exact ELF/shared object. Inspect the
resulting `trace-ui/angr-ollvm-v1` JSON with `inspect_angr_ollvm_results`. CFGFast/CFGEmulated
differences, blank-state probes, and automatically emitted trace-register-seeded probes are candidate
evidence only. Trace snapshots omit memory and may omit architectural state; add memory/input evidence
to `configure_state(state)` or merge a Frida seed before increasing confidence. For the full workflow, use
`$ida-ollvm-analysis`.

**"Does this dispatcher or opaque branch stay stable across runs?"**
→ open two to sixteen controlled traces, then `compare_ollvm_traces{cases:[...]}` with a scope and
`static_binary_path` for each run; enable `require_matching_binary:true`. Differing supplied ELF SHA-256
values are rejected. Treat `alternate-outcomes-observed` as evidence against patching the branch as globally opaque.
`stable-single-outcome-across-runs` raises confidence only to Candidate/Related because untested states
and unexecuted paths remain unknown.

**"Is this a real white-box/key-fused implementation?"**
→ Do not decide from one trace or one table. Run `analyze_crypto_implementations` with the exact ELF,
then compare at least: same SO + different input, same SO + different key, and ideally a second SO version.
Treat table/encoding signals as Candidate/Related. Use \`compare_crypto_table_traces\` with explicit
\`key_group\` and \`input_group\` labels; strong isolation uses at least two inputs per key and two keys
with constant SO Build ID and coverage. Its gate remains false: only semantic recomputation can be Verified,
and raw key/standard schedule evidence contradicts a key-dependent-tables-only claim.

**"Just dig in — I don't know where to start."**
→ `auto_investigate{objective, digests?, from_specs?, search_terms?}` orchestrates search + crypto +
digest + forward flow + diff into one scored evidence pack. Or `run_analysis_recipe{recipe_id}` with a
built-in recipe (`crypto_investigation`, `known_digest_flow`, `forward_to_sinks`, `auto_investigation`).
On large traces prefer `start_auto_investigation` / `start_crypto_investigation` + poll.

**Locate specific code** → `search_instructions{query, seq_range?, addr_range?}` (text or `/regex/`).

**"Find this value anywhere, then let me trace it."**
Use \`search_value{query,kind:"auto"}\`. Inspect \`interpretations\`: every UTF-8, UTF-16LE, hex,
integer/address endian, or digest-byte form is explicit, and hex remains in input order. Prefer memory
hits because they carry exact \`addr\`, \`lastSeq\`, and byte length anchors. Verify with \`get_memory\`,
then taint from \`mem:ADDR:SIZE@seq:N\`. Use \`analyze_known_digest\` instead when asking which input
recomputes to a known digest.

## Critical rules (read before you act)

- Use explicit taint anchors: **`@line:N` is 1-based** and **`@seq:N` is 0-based**. Legacy bare `@N`
  means a display line and should be avoided. `start_seq`/`end_seq` filters are also 0-based.
- **A single magic constant is a lead, not proof.** Trust `analyze_crypto_functions` confidence grades
  over raw constant hits. Report **candidate vs verified** honestly; never upgrade "digest bytes match"
  to "this function produced it" without dependency evidence.
- **`data_only:true`** unless you specifically need control-dependency flow (it explodes result size).
- **Only executed instructions exist** in a trace — dynamic, not static. Unexecuted branches aren't there.
  If a value's origin is "missing", the computation may predate the trace's start; widen the range or
  pick a later line.
- **Large traces (10M+ lines): use the `start_*` background tools**, then poll `get_analysis_task` and
  fetch the result via `get_analysis{analysis_id}`. Don't block on a long synchronous call.
- **Verify before concluding.** End an investigation by quoting exact `get_trace_lines` / `get_memory`
  evidence for the claim, and save the `analysis_id` so the human can audit it in the GUI.

## Tool map

| Purpose | Tools |
|---|---|
| Session | `open_trace`, `close_trace` |
| Browse / verify | `get_trace_lines`, `get_memory`, `get_strings`, `get_call_tree`, `search_instructions` |
| Crypto | `analyze_crypto_implementations`, `analyze_crypto_functions`, `analyze_crypto_materials`, `compare_crypto_material_traces`, `analyze_crypto`, `analyze_known_digest`, `investigate_crypto_flow` |
| Taint | `taint_analysis` (backward), `forward_taint_analysis`, `get_tainted_lines`, `start_forward_taint_analysis` |
| Functions | `analyze_function` (node_id / name / list) |
| Diff | `compare_traces`, `start_trace_diff` |
| Frida | `list_frida_hook_recipes`, `generate_frida_hook`, `inspect_frida_capture`, `analyze_frida_crypto_materials`, `generate_angr_state_seed` (user executes hooks manually) |
| IDA / angr / OLLVM | `analyze_ollvm`, `compare_ollvm_traces`, `generate_ida_ollvm_script`, `inspect_ida_annotations`, `generate_angr_ollvm_script`, `inspect_angr_ollvm_results` |
| Orchestration | `auto_investigate`, `start_auto_investigation`, `start_crypto_investigation` |
| Evidence store | `list_analyses`, `get_analysis`, `compare_analyses`, `export_analysis_report`, `delete_analysis` |
| Recipes | `list_analysis_recipes`, `run_analysis_recipe`, `save_analysis_recipe`, `delete_analysis_recipe` |
| Background tasks | `get_analysis_task`, `list_analysis_tasks`, `cancel_analysis_task` |

Full per-tool arguments and return fields: see `references/mcp-tools.md`.
Worked end-to-end investigations (find a key, match a digest, trace to a sink, diff two runs): see
`references/playbook-examples.md` — read it when you need a concrete template for a real investigation.
