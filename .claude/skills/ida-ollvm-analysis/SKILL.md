---
name: ida-ollvm-analysis
description: Analyze ARM64 dynamic traces for OLLVM control-flow-flattening and opaque-branch candidates, compare dispatcher/state/branch stability across controlled runs, bridge module-relative evidence to IDA and angr, and inspect results exported back through the trace-ui MCP server. Use for ASLR-stable dynamic CFG evidence, dispatcher state trajectories, opaque predicate leads, trace-seeded symbolic probes, trace-to-IDA annotations, or static/dynamic CFG reconciliation. Treat all OLLVM and angr structural classifications as candidates unless independently proven.
---

# Analyze OLLVM traces and bridge them to IDA or angr

Use `mcp__trace-ui__analyze_ollvm`, `mcp__trace-ui__compare_ollvm_traces`, `mcp__trace-ui__generate_ida_ollvm_script`,
`mcp__trace-ui__inspect_ida_annotations`, `mcp__trace-ui__generate_angr_ollvm_script`,
`mcp__trace-ui__inspect_angr_ollvm_results`, `mcp__trace-ui__inspect_frida_capture`, and
`mcp__trace-ui__generate_angr_state_seed`.

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
6. For controlled runs, call `compare_ollvm_traces` with two to sixteen case-specific scopes and the
   exact `static_binary_path` for every case. Enable `require_matching_binary:true`; differing SHA-256
   values must stop the comparison. Prioritize
   `alternate-outcomes-observed` as evidence against a globally opaque classification; stable single
   outcomes remain candidates.
7. Reconcile dynamic observed successors with angr static successors. Investigate unobserved-static
   and dynamic-only edges, but do not assume either side is complete.
8. Inspect manually captured Frida JSON with `inspect_frida_capture`, select an exact event, and use
   `generate_angr_state_seed` to produce a candidate `configure_state(state)` function. Match the
   capture point to the symbolic state address before increasing confidence.

## Interpretation rules

- All addresses in reports are module-relative and ASLR-stable. Align them to IDA with the image base used by the generated script.
- A dispatcher score is a ranking signal based on repeated visits, fan-in/fan-out, indirect branches, backward edges, and state-like registers. It is not proof of control-flow flattening.
- An opaque-branch candidate reflects a repeatedly observed single outcome near flag-producing instructions. The unexecuted path is unknown.
- An alternate outcome observed in another controlled run contradicts a global opaque-branch claim for
  the tested build/scope. It does not explain why the outcome changed.
- Dispatcher state transitions are reconstructed from trace register checkpoints at candidate block
  entry. Missing/unknown registers and truncated snapshots are normal coverage limits.
- Dynamic traces contain only executed instructions. Do not infer missing blocks, alternate paths, or complete static CFG coverage.
- CFGFast successors absent from the trace may be unexecuted, infeasible, or CFG recovery artifacts.
- Dynamic-only successors may reflect indirect control flow, trace scope boundaries, or static CFG recovery gaps.
- The generated angr bridge emits both blank-state probes and trace-register-seeded probes when branch
  snapshots exist. Neither proves real-entry reachability; trace-seeded probes may still lack memory,
  SIMD, flags, or other architectural state.
- Require the exact ELF/shared object for every case and enable `require_matching_binary`. A matching
  supplied SHA-256 confirms the selected files are identical, not that the trace format cryptographically
  attests which image was mapped at runtime.
- Excluding child call ranges usually produces a cleaner function-local CFG. Include them only when the investigation explicitly needs interprocedural flow.
- Do not mark OLLVM findings `Verified` solely from structural evidence.

## IDA bridge boundary

The generated script may add comments, colors, and optionally observed user xrefs. It does not deobfuscate the binary automatically. The user runs it manually in IDA, reviews changes, and exports annotations manually.

Prefer comments/colors first. Enable `add_user_xrefs:true` only when the user wants observed dynamic edges represented as IDA user xrefs and understands that they are execution-specific.

## angr bridge boundary

Trace UI generates a standalone Python script but does not install or execute angr. The user runs it
manually. Prefer CFGFast first; enable CFGEmulated only for a narrow scope and accept fallback. Treat
static CFG reconciliation and unconstrained probes as Candidate/Related evidence, never Verified by
themselves.

## Reporting

Report the selected scope, module, sequence range, block/edge counts, top candidates with exact module offsets, and the saved `analysis_id`. Clearly separate observed dynamic facts from OLLVM hypotheses and note coverage limitations.
