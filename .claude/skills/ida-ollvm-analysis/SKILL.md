---
name: ida-ollvm-analysis
description: Analyze ARM64 dynamic traces for OLLVM control-flow-flattening and opaque-branch candidates, generate a manual IDAPython bridge, and inspect annotations exported back from IDA through the trace-ui MCP server. Use when the user wants ASLR-stable dynamic CFG evidence, dispatcher or opaque predicate leads, trace-to-IDA comments/colors/xrefs, or IDA-to-trace names and comments. Treat all OLLVM classifications as dynamic candidates unless independently proven.
---

# Analyze OLLVM traces and bridge them to IDA

Use `mcp__trace-ui__analyze_ollvm`, `generate_ida_ollvm_script`, and `inspect_ida_annotations`.

## Workflow

1. Open the trace and orient with `get_call_tree` or `analyze_function`.
2. Scope the analysis to a call-tree `node_id` whenever possible. Otherwise provide `module_name` plus a narrow `start_seq`/`end_seq` range.
3. Run `analyze_ollvm` with `include_child_calls:false` unless nested calls are intentionally part of the target.
4. Review dynamic blocks, edges, dispatcher candidates, opaque-branch candidates, scores, and limitations. Verify important candidates with `get_trace_lines`.
5. Run `generate_ida_ollvm_script` for the same scope. Keep `add_user_xrefs:false` by default.
6. Give the generated IDAPython script to the user for manual execution in the matching IDA database.
7. If the user exports annotations with `export_ida_annotations()`, inspect the resulting `trace-ui/ida-ollvm-v1` JSON using `inspect_ida_annotations`.

## Interpretation rules

- All addresses in reports are module-relative and ASLR-stable. Align them to IDA with the image base used by the generated script.
- A dispatcher score is a ranking signal based on repeated visits, fan-in/fan-out, indirect branches, backward edges, and state-like registers. It is not proof of control-flow flattening.
- An opaque-branch candidate reflects a repeatedly observed single outcome near flag-producing instructions. The unexecuted path is unknown.
- Dynamic traces contain only executed instructions. Do not infer missing blocks, alternate paths, or complete static CFG coverage.
- Excluding child call ranges usually produces a cleaner function-local CFG. Include them only when the investigation explicitly needs interprocedural flow.
- Do not mark OLLVM findings `Verified` solely from structural evidence.

## IDA bridge boundary

The generated script may add comments, colors, and optionally observed user xrefs. It does not deobfuscate the binary automatically. The user runs it manually in IDA, reviews changes, and exports annotations manually.

Prefer comments/colors first. Enable `add_user_xrefs:true` only when the user wants observed dynamic edges represented as IDA user xrefs and understands that they are execution-specific.

## Reporting

Report the selected scope, module, sequence range, block/edge counts, top candidates with exact module offsets, and the saved `analysis_id`. Clearly separate observed dynamic facts from OLLVM hypotheses and note coverage limitations.
