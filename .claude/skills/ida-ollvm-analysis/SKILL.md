---
name: ida-ollvm-analysis
description: Analyze ARM64 dynamic traces for OLLVM control-flow-flattening and opaque-branch candidates, compare dispatcher/state/branch stability across controlled runs, map dispatcher/state structural candidates across distinct ELF versions, bridge module-relative evidence and exact-offset Frida captures to IDA, angr, and Unicorn, continue seeds through bounded symbolic or concrete flows, and inspect exported results through the trace-ui MCP server. Use for ASLR-stable dynamic CFG evidence, dispatcher state trajectories, cross-version relocation candidates, opaque predicate leads, seeded execution-flow candidates, trace-to-IDA annotations, concrete replay, or static/dynamic CFG reconciliation. Treat all OLLVM, angr, and Unicorn structural classifications as candidates unless independently proven.
---

# Analyze OLLVM traces and bridge them to IDA, angr, or Unicorn

Use `mcp__trace-ui__analyze_ollvm`, `mcp__trace-ui__compare_ollvm_traces`, `mcp__trace-ui__map_ollvm_versions`, `mcp__trace-ui__generate_ida_ollvm_script`,
`mcp__trace-ui__inspect_ida_annotations`, `mcp__trace-ui__generate_angr_ollvm_script`,
`mcp__trace-ui__inspect_angr_ollvm_results`, `mcp__trace-ui__inspect_frida_capture`, and
`mcp__trace-ui__generate_angr_state_seed`, `mcp__trace-ui__generate_unicorn_ollvm_script`, and
`mcp__trace-ui__inspect_unicorn_ollvm_results`. For multi-dispatcher manual capture, also use
`mcp__trace-ui__generate_frida_ollvm_dispatcher_hook` and
`mcp__trace-ui__analyze_frida_ollvm_dispatcher_capture`.

## Workflow

1. Open the trace and orient with `get_call_tree` or `analyze_function`.
2. Scope the analysis to a call-tree `node_id` whenever possible. Otherwise provide `module_name` plus a narrow `start_seq`/`end_seq` range.
3. Run `analyze_ollvm` with `include_child_calls:false` unless nested calls are intentionally part of the target.
4. Review dynamic blocks, edges, dispatcher candidates, dispatcher state snapshots/transitions,
   conditional branch profiles, opaque-branch candidates, scores, and limitations. Verify important
   candidates with `get_trace_lines`.
5. Choose one or both bridges:
   - Run `generate_ida_ollvm_script` for manual execution in the matching IDA database. Keep
     `add_user_xrefs:false` by default. Inspect exported `trace-ui/ida-ollvm-v1` JSON with
     `inspect_ida_annotations`.
   - Run `generate_angr_ollvm_script` for manual execution in a separate Python/angr environment
     against the exact ELF/shared object. Import `trace-ui/angr-ollvm-v1` JSON with
     `inspect_angr_ollvm_results`.
   - Run `generate_unicorn_ollvm_script` when one to 32 exact-offset Frida events provide concrete
     state. The exact AArch64 ELF is mandatory. Run the Python manually, then import
     `trace-ui/unicorn-ollvm-v1` JSON with `inspect_unicorn_ollvm_results`.
6. For controlled runs, call `compare_ollvm_traces` with two to sixteen case-specific scopes and the
   exact `static_binary_path` for every case. Enable `require_matching_binary:true`; differing SHA-256
   values must stop the comparison. Prioritize
   `alternate-outcomes-observed` as evidence against a globally opaque classification; stable single
   outcomes remain candidates.
7. Reconcile dynamic observed successors with angr static successors. Investigate unobserved-static
   and dynamic-only edges, but do not assume either side is complete.
8. For a selected opaque branch, generate a Frida 16 Hook at the branch offset or a reported
   condition-source offset and let the user run it manually. Inspect the capture, select one or more
   exact `hook-enter` events, then call `generate_angr_ollvm_script` with `frida_capture_path` and
   `frida_event_indices` (legacy `frida_event_index` remains supported). The tool must reject module or
   offset mismatches. Optionally provide the exact AArch64 ELF path to embed a SHA-256 guard. Use
   `generate_angr_state_seed` separately when a reusable standalone `configure_state(state)` function is desired.
9. For a selected dispatcher candidate, generate a Frida 16 Hook at its exact `startOffset` and let the
   user run it manually. Import the `hook-enter` event and pass it to `generate_angr_ollvm_script`.
   Keep bounded flow enabled to stop at the next dispatcher, loop, external target, dead end, or bound;
   inspect source/target state-register values as Candidate/Related leads only.
   For a fast concrete confirmation, pass the same exact event and exact ELF to
   `generate_unicorn_ollvm_script`. Prefer a bounded SP stack capture and only the X0-X28 pointer
   snapshots justified by missing-memory evidence. Review next-dispatcher transition groups,
   register changes, missing-memory stops, and recapture suggestions before escalating to angr.
10. To observe several ranked dispatchers in one user-controlled run, call
    `generate_frida_ollvm_dispatcher_hook`, return/save the Frida 16.x script, and stop until the user
    supplies its capture. Then call `analyze_frida_ollvm_dispatcher_capture` on the same OLLVM scope.
    Review exact-offset nodes, state-value distributions, adjacent transitions, state changes, and
    flow paths; do not treat idle-gap flow grouping as a call boundary or the atlas as a recovered CFG.
11. Keep bounded seeded-flow enabled when the question is where a captured state can travel after the
   candidate branch. Start with `flow_max_depth:8` and `flow_max_states_per_probe:32`; lower them when
   several candidates branch heavily. Inspect loop/depth-limit/state-limit/dead-end/external-target
   endings and the final bounded path constraints as leads, not recovered control flow.
12. For different binary builds, call `map_ollvm_versions` with two to eight independent version IDs,
    trace scopes, and exact AArch64 ELF paths. Every SHA-256 must differ; repeated runs of one ELF belong
    in `compare_ollvm_traces`. Review normalized operation/CFG/state-role candidates and ambiguous top
    scores. Never carry source offsets, concrete state values, Frida captures, or angr seeds into the
    target build; regenerate an exact-offset Frida 16 Hook and angr seed per version.

## Interpretation rules

- All addresses in reports are module-relative and ASLR-stable. Align them to IDA with the image base used by the generated script.
- A dispatcher score is a ranking signal based on repeated visits, fan-in/fan-out, indirect branches, backward edges, and state-like registers. It is not proof of control-flow flattening.
- An opaque-branch candidate reflects a repeatedly observed single outcome near flag-producing instructions. The unexecuted path is unknown.
- An alternate outcome observed in another controlled run contradicts a global opaque-branch claim for
  the tested build/scope. It does not explain why the outcome changed.
- Dispatcher state transitions are reconstructed from trace register checkpoints at candidate block
  entry. Missing/unknown registers and truncated snapshots are normal coverage limits.
- Frida dispatcher-atlas transitions are adjacent exact-offset hits only within one capture session,
  thread, and flow. Dedicated scripts provide hit sequences; legacy captures use idle-gap-derived flows.
  Both are execution-specific Candidate/Related evidence and can miss unhooked or unexecuted paths.
- Dynamic traces contain only executed instructions. Do not infer missing blocks, alternate paths, or complete static CFG coverage.
- CFGFast successors absent from the trace may be unexecuted, infeasible, or CFG recovery artifacts.
- Dynamic-only successors may reflect indirect control flow, trace scope boundaries, or static CFG recovery gaps.
- The generated angr bridge emits both blank-state probes and trace-register-seeded probes when branch
  snapshots exist. Neither proves real-entry reachability; trace-seeded probes may still lack memory,
  SIMD, flags, or other architectural state.
- An embedded Frida probe is emitted only when the hook-enter target exactly matches the candidate
  branch, condition source, or dispatcher entry. It may add X0-X28/FP/LR/SP and byteArray memory, but
  missing flags, SIMD, unread buffers, or entry-path constraints keep the result Candidate/Related. When
  Frida provides packed NZCV, the generated angr bridge carries it forward with a packed-register or
  N/Z/C/V fallback; the capture point still must have branch-equivalent flag semantics.
- Bounded branch continuation applies only to the first trace-register seed per candidate and each exact
  branch/condition-source Frida seed. An exact dispatcher-entry seed instead explores to the next
  dispatcher, loop, exit, or bound and may report each target state register as `concrete`, `symbolic`
  with at most two alternatives, or `unavailable`. Blank state remains single-step. A `loop-detected`
  result is useful evidence for a dispatcher cycle, while `depth-limit` or `state-limit` means the
  exploration is incomplete; none of these statuses proves a deobfuscated CFG or real-entry reachability.
- Require the exact ELF/shared object for every case and enable `require_matching_binary`. A matching
  supplied SHA-256 confirms the selected files are identical, not that the trace format cryptographically
  attests which image was mapped at runtime.
- When `generate_angr_ollvm_script` receives `static_binary_path`, the generated Python bridge checks that
  selected file's SHA-256 before CFG/symbolic work. This is a file-identity guard, not runtime-image attestation.
- Excluding child call ranges usually produces a cleaner function-local CFG. Include them only when the investigation explicitly needs interprocedural flow.
- Do not mark OLLVM findings `Verified` solely from structural evidence.
- Cross-version operation/CFG/state-role similarity is a relocation lead only. Module renames and offset
  changes are allowed, while equal hashes are rejected to keep cross-version and same-build semantics separate.
- Unicorn is concrete replay, not path exploration. A successful next-dispatcher transition applies only
  to the exact captured seed. Missing memory, uncaptured registers, SIMD state, TLS/system registers,
  calls, loops, timeouts, and instruction bounds must remain explicit stop reasons.
- Writable ELF segment bytes are not assumed to equal runtime state. Prefer exact Frida byteArray regions;
  use register-relative recapture suggestions to improve a partial seed instead of silently filling zeros.

## IDA bridge boundary

The generated script may add comments, colors, and optionally observed user xrefs. It does not deobfuscate the binary automatically. The user runs it manually in IDA, reviews changes, and exports annotations manually.

Prefer comments/colors first. Enable `add_user_xrefs:true` only when the user wants observed dynamic edges represented as IDA user xrefs and understands that they are execution-specific.

## angr bridge boundary

Trace UI generates a standalone Python script but does not install or execute angr. The user runs it
manually. Prefer CFGFast first; enable CFGEmulated only for a narrow scope and accept fallback. Treat
static CFG reconciliation, unconstrained probes, and bounded seeded-flow paths as Candidate/Related
evidence, never Verified by themselves. Keep depth within 1-64 and states per probe within 1-256.

## Unicorn bridge boundary

Trace UI generates a standalone Python script but does not install or execute Unicorn. Require the exact
AArch64 ELF and at least one exact-offset Frida event. Keep instructions within 1-2,000,000 and timeout
within 1-60,000 ms; begin with 50,000 instructions and 5,000 ms. Stop on calls by default. Treat the
transition matrix as grouped exact-seed replay evidence, never a complete state machine or recovered CFG.

## Reporting

Report the selected scope, module, sequence range, block/edge counts, top candidates with exact module offsets, and the saved `analysis_id`. Clearly separate observed dynamic facts from OLLVM hypotheses and note coverage limitations.
