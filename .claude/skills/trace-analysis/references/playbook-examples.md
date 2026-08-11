# trace-ui — worked investigation examples

Realistic end-to-end walkthroughs. Each shows the tool sequence, **how to read the output**, the
**verification step**, and **how to report**. Adapt line numbers / addresses to the actual trace.
Reminder: taint `@LINE` is 1-based; `seq`/`start_seq` are 0-based.

---

## Example 1 — "Find the algorithm and key used to sign the request"

Goal: a native `.so` signs an HTTP request; find which function does it and what key it uses.

1. **Orient.**
   ```
   get_strings{search:"sign"}        → runtime strings mentioning sign/token/url
   analyze_crypto_functions{}
   ```
   Read `analyze_crypto_functions` candidates. Prefer `assessment.confidence: "high"`. Say the top
   candidate is `funcName:"sub_2A0F0"`, `algorithms:["SHA256","AES"]`, `cryptoInsnCounts:{"SHA256":64}`,
   `io.entryArgs:[{reg:"X0",value:"0x7b..."},{reg:"X1",value:"0x..."},{reg:"X2",value:"0x14"}]`.
   Interpretation: 64 SHA256 hardware instructions in one function → almost certainly the digest routine;
   X0/X1 look like pointers, X2=0x14=20 = a length.

2. **Inspect its I/O.**
   ```
   analyze_function{node_id:<candidate node id>}   → entry X0-X7, return X0, sub-calls
   get_memory{address:"0x<X1>", seq:<entrySeq>, length:32}   → the input buffer bytes
   ```
   If the buffer is printable, you've found the message being hashed. If X0 is a key/context pointer,
   dump it too.

3. **Trace the key back.** If X0 is the key pointer at entry line L (1-based):
   ```
   taint_analysis{from_specs:["mem:0x<X0>:16@L"], data_only:true}
   get_tainted_lines{analysis_id:"<taint analysis_id>",limit:80}
   ```
   Walk upward to where those 16 bytes were written — often a `memcpy` from a constant table or a
   key-derivation function. That STORE/derivation is the key source.

4. **Verify + report.** Quote the exact evidence:
   ```
   get_trace_lines{start_seq:<key def line minus 1>, count:5}
   get_memory{address:"0x<key addr>", seq:<def line>, length:16}
   ```
   Report: "Function `sub_2A0F0` (High confidence, 64 SHA256 instrs) hashes the 20-byte buffer at
   0x… (X1), keyed by the 16 bytes at 0x… which are written at line N by `memcpy` from 0x… — see lines
   N-1..N+1 and the memory dump." Save analysis_id; `compare_analyses` if you ran both taint directions.

---

## Example 2 — "I have this MD5, what plaintext produced it?"

Known digest `9e107d9d372bb6826bd81d3542a419d6`.

```
analyze_known_digest{digests:["9e107d9d372bb6826bd81d3542a419d6"]}
```
Read `assessment_summary`:
- `verified > 0` → a runtime string or memory buffer's bytes **recompute** to that MD5. Look in
  `candidate_assessments` for the `content` and `addr`. That's the plaintext. Done.
- only `related/uncertain` → the exact input wasn't observed whole. Retry with transforms:
  ```
  analyze_known_digest{digests:["9e10..."], utf16le:true, utf8_nul:true}
  ```
  (many Android inputs are UTF-16 or NUL-terminated). Or the input is chunked/salted → fall back to
  tracing the digest **output** buffer origin (the tool auto-runs this; read `traced_matches`).

Verify a "verified" hit before claiming it:
```
get_memory{address:"0x<addr>", seq:<seq>, length:<byteLen>}   → confirm the exact bytes
```
Report: "MD5 input = `\"the quick brown fox…\"` at 0x… (seq N), **verified** (bytes recompute to the
digest)." Never say "verified" for a `related` candidate.

---

## Example 3 — "Where does this JNI string argument end up? (does it leave the device?)"

A `NewStringUTF` / `GetStringUTFChars` returns a pointer in X0 at line L; follow it forward.

```
forward_taint_analysis{from_specs:["reg:X0@L"], data_only:true, max_sinks:100}
```
Read `flow_endpoints` / `potential_sinks`. Look for endpoints with `category` in {file, socket, log,
syscall} and `external:true` — those are where the data leaves. Check `confidence` and, for
file/socket, the cross-call `resourceValidation` (it ties the fd back to the `open`/`socket` call).

If nothing external appears, the value stayed internal (transformed/stored). If the trace is huge:
```
start_forward_taint_analysis{from_specs:["reg:X0@L"], data_only:true}
# then poll:
get_analysis_task{task_id:<returned>}   → when completed, get_analysis{analysis_id}
```
Verify a socket sink:
```
get_trace_lines{start_seq:<sink seq>, count:3}   → confirm it's send/write with X0 = your data
```
Report the concrete sink line + resource provenance, not just "it flows somewhere".

---

## Example 4 — "Good input works, bad input fails — where's the check?"

Capture two traces (valid vs invalid input), open both, diff them:
```
open_trace{file_path:"/abs/good.log"}   → session A
open_trace{file_path:"/abs/bad.log"}    → session B
compare_traces{session_id:"A", other_session_id:"B"}
```
Read the `branches` and `functions` sections: a branch taken in A but not B (or a function called only
in A) at a module-relative offset is the divergence point — likely the validation check. Jump there:
```
search_instructions{addr_range:"0x<off-8>-0x<off+8>"}   # or get_trace_lines around that seq
```
Report the diverging branch/function by module offset (ASLR-robust) and the surrounding instructions.

---

## Example 5 — "Just investigate this trace, I don't know what's in it"

```
auto_investigate{objective:"Understand what this .so computes and whether it does crypto",
                 include_crypto:true, search_terms:["http","key","sign","token"]}
```
It runs overview + search + crypto + (if you pass `digests`/`from_specs`) digest & forward flow, scored
into one pack with a grade. Read `assessment.factors` — each says what evidence was/wasn't found and
its points. Then drill into the strongest factor with the specific playbook above. On a large trace use
`start_auto_investigation` + poll.

---

## Reporting checklist (every investigation)

- Lead with the answer, then the evidence chain.
- State **confidence/grade** as the tool reported it — candidate vs verified.
- Quote at least one exact `get_trace_lines` / `get_memory` for the load-bearing claim.
- Note what's **unproven** (e.g. "the constant matches AES but the key source wasn't in the trace window").
- Mention the saved `analysis_id`(s) so the human can open the **Analyses** tab and audit / compare.

---

## Example 6 — "Reconcile this AES trace with the exact libcryptoDD.so"

```
analyze_crypto_implementations{
  algorithm:"aes",
  static_binary_path:"C:\\private-assets\\libcryptoDD.so"
}
```

Check three independent layers:

1. `softwareCrypto.verification == "VerifiedFull"` proves the observed AES key/input/output semantics.
2. `staticBinary.buildId` and `binarySha256` identify the exact ELF asset.
3. An `ExactStaticDynamicMatch` with zero mismatches proves the executed table bytes match the ELF at
   the reported module/file offset.

Do not call it white-box merely because a large table matches. If a raw key and standard key schedule
are observed, report `NotWhiteBox`. For a white-box hypothesis, repeat with different inputs and keys and
compare which table contents remain stable or change.

---

## Example 7 — "Keep a severe OLLVM/AES investigation accurate across multiple rounds"

Create a durable case from the open trace and exact ELF:

```
open_analysis_case{
  case_path:"C:\\cases\\target.traceui-case",
  create:true,
  session_id:"<session>",
  exact_binary_path:"C:\\samples\\libtarget.so"
}
```

If the investigation depends on proving which build was mapped, create a bounded runtime-image plan:

```
generate_frida_runtime_attestation{
  module_name:"libtarget.so",
  static_binary_path:"C:\\samples\\libtarget.so",
  window_bytes:4096,
  max_windows:1024
}
```

The user saves and runs the generated Frida 16.x script manually. After they provide the output:

```
inspect_runtime_attestation{
  capture_path:"C:\\captures\\runtime-attestation.json",
  exact_binary_path:"C:\\samples\\libtarget.so"
}
ingest_analysis_case_artifact{
  case_path:"C:\\cases\\target.traceui-case",
  artifact_path:"C:\\captures\\runtime-attestation.json",
  kind_hint:"runtime-attestation",
  parent_artifact_ids:["<elf-artifact-id>"]
}
```

Import a `refuted` result too: it is valuable counter-evidence. `related-sampled` is never enough for
Verified; `verified-full` proves only the scoped runtime-image bytes, not AES or OLLVM semantics.

After each user-run Frida/Unicorn/angr/IDA step, import the produced file with explicit parents:

```
ingest_analysis_case_artifact{
  case_path:"C:\\cases\\target.traceui-case",
  artifact_path:"C:\\captures\\round-1-unicorn.json",
  kind_hint:"unicorn-result",
  parent_artifact_ids:["<frida-artifact-id>","<elf-artifact-id>"]
}
diagnose_analysis_case{case_path:"C:\\cases\\target.traceui-case"}
```

Read the result in this order:

1. `artifactHealth`: stop if any artifact is missing, changed, malformed, wrong-module, or wrong-hash.
2. `runtimeAttestations`: require exact parent provenance. Full executable-byte coverage can open only
   the `runtime-image:*` gate; sampled, incomplete, and refuted records must not be promoted.
3. `stateReadiness`: treat `not-executed`, `not-captured`, `unreadable`, `not-observed`, and
   `hash-mismatch` as different causes. Do not convert any of them to "the state does not matter".
4. `unicornRoundComparison`: continue concrete recapture only when coverage/dispatcher evidence moves;
   repeated stalls should use the authorized closer checkpoint, then bounded angr if still necessary.
5. `claimLedgerAudit`: run `audit_analysis_case_claims` before saying Verified. OLLVM/Unicorn/angr
   structure is Candidate/Related unless deterministic semantic evidence independently passes.
6. `experimentMatrix`: record build/key/input/environment for every controlled run. Prefer pairs that
   differ on exactly one axis.

Record two AES runs that vary only the key:

```
upsert_analysis_case_experiment{
  case_path:"C:\\cases\\target.traceui-case",
  label:"same build/input, key B",
  binary_sha256:"<exact-elf-sha256>",
  key_group:"key-b",
  input_group:"input-a",
  environment_group:"device-config-a",
  artifact_ids:["<trace-or-capture-artifact-id>"],
  controlled_variables:["binarySha256","inputGroup","environmentGroup"],
  changed_variables:["keyGroup"]
}
```

The user still runs the target, Frida, Unicorn, angr, and IDA manually. The case tools validate and
organize evidence; they do not attach, spawn, execute, or claim automatic deobfuscation.

For a bounded AI/model handoff, do not paste the entire case or write a support-only prose summary:

```
generate_analysis_case_evidence_pack{
  case_path:"C:\\cases\\target.traceui-case",
  format:"markdown",
  max_tokens:8000,
  max_items:256,
  include_generated_claims:true
}
```

The recipient must read `recommendedMaxStatus`, counter-evidence, unknowns, invalid artifacts, and all
omitted counts before concluding. Artifact summaries and the Evidence Pack itself are navigation aids,
not proof; follow the exact artifact ID and locator for any load-bearing assertion.

---

## Example 8 — "Turn an AI crypto/ABI hypothesis into reproducible evidence"

First replace a prose crypto marker with an exact KAT. This example verifies SHA-256(`hello`):

```
verify_crypto_semantic_kat{
  algorithm:"sha256",
  input_hex:"68656c6c6f",
  observed_output_hex:"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  output_path:"C:\\cases\\sha256-kat.json"
}
inspect_crypto_semantic_kat{file_path:"C:\\cases\\sha256-kat.json"}
ingest_analysis_case_artifact{
  case_path:"C:\\cases\\target.traceui-case",
  artifact_path:"C:\\cases\\sha256-kat.json",
  kind_hint:"crypto-kat"
}
```

Only `verified-full` plus the exact returned `claimScope` may support that `crypto:*` claim. The KAT
does not prove which native function produced the bytes, so retain trace/taint evidence for provenance.

If repeated user-run Frida calls have unclear X0-X7 roles:

```
infer_frida_abi{
  file_path:"C:\\captures\\encrypt-calls.ndjson",
  min_observations:2,
  max_functions:32,
  max_candidates_per_function:128,
  output_path:"C:\\cases\\encrypt-abi-candidates.json"
}
```

Use pointer+length, mutation, context, field-window, and return candidates to configure the next narrow
Hook, but keep every result Candidate/Related. Confirm with exact event indices, trace instructions,
taint, symbols/API contracts, or a controlled counterexample. Never copy a runtime pointer into another
run or treat it as a module offset.

After importing the new KAT/capture/result, ask Replay Doctor what evidence has the highest value:

```
diagnose_analysis_case{case_path:"C:\\cases\\target.traceui-case"}
plan_analysis_case_capture{
  case_path:"C:\\cases\\target.traceui-case",
  max_targets:8
}
```

Follow the highest target relevant to the active question and record its `redundancyKey`. The score is
an ordering heuristic, not a probability. Re-run the plan after importing new evidence.

Finally, before changing claim gates or confidence rankings, run a reviewed regression suite:

```
run_accuracy_benchmark{suite_path:"C:\\cases\\accuracy-suite.json"}
```

Require `gateMet:true` and inspect FP/FN, unexpected Verified, fixture errors, and ranking drift. Passing
means the declared fixtures did not regress; it does not turn fixture labels into proof.
