---
name: frida-hook-generation
description: Generate bounded ARM64 Frida 16.x JavaScript hook scripts, inspect user-captured trace-ui/frida-hook-v1 JSON or NDJSON, index captured crypto materials, and turn exact-offset register/buffer captures into manual angr, Unicorn, or OLLVM state seeds through the trace-ui MCP server. Use for native exports or module-relative offsets, X0-X7 arguments, full ARM64 GPR snapshots, key/salt/digest buffers, strings, returns, backtraces, Stalker events, capture review, missing-memory recapture, or Frida-to-simulator handoff. Trace UI never attaches, spawns, loads, or executes Frida; the user controls runtime execution.
---

# Generate Frida 16 hooks with trace-ui

Use `mcp__trace-ui__list_frida_hook_recipes`, `mcp__trace-ui__generate_frida_hook`,
`mcp__trace-ui__generate_frida_ollvm_dispatcher_hook`, `mcp__trace-ui__inspect_frida_capture`,
`mcp__trace-ui__search_frida_capture_events`, `mcp__trace-ui__get_frida_capture_event`,
`mcp__trace-ui__analyze_frida_crypto_materials`, `mcp__trace-ui__analyze_frida_ollvm_dispatcher_capture`, and
`mcp__trace-ui__generate_angr_state_seed`, `mcp__trace-ui__generate_unicorn_ollvm_script`,
`mcp__trace-ui__inspect_unicorn_ollvm_results`, and
`mcp__trace-ui__generate_frida_unicorn_recapture_hook`, and
`mcp__trace-ui__generate_frida_unicorn_checkpoint_hook`. Generated hooks target Frida 16.x JavaScript APIs and emit
`trace-ui/frida-hook-v1` messages with `send()` plus `TRACE_UI_JSON` strict-JSON log lines.

## Workflow

1. Identify the exact module basename and either an exported symbol or an ASLR-stable module-relative offset. Provide exactly one of `symbol` or `offset`.
2. Infer argument roles from `analyze_function`, crypto-material evidence, ABI knowledge, or user input. Do not guess pointer lengths silently.
3. If the target matches a common OpenSSL/BoringSSL or Apple CommonCrypto API, call
   `list_frida_hook_recipes` and apply the closest audited recipe. Review every warning and adjust the
   module basename for the actual process. Otherwise configure the request manually.
4. Call `generate_frida_hook` with only the captures needed for the question.
5. Return or save the generated `.js` script. Explain the expected event fields and any unsafe memory-read assumptions.
6. Stop. Do not attach, spawn, load, execute, or claim the hook ran. The user performs those steps manually.
7. If the user supplies captured JSON/NDJSON, run `inspect_frida_capture`. For large captures, use
   `search_frida_capture_events` to page compact summaries, then `get_frida_capture_event` for one exact
   event index, normally a `hook-enter` with registers or buffers. Keep registers, capture values,
   return values, and backtraces opt-in.
8. When crypto roles are requested, run `analyze_frida_crypto_materials`. Treat explicit labels as
   Related unless exact MD5/SHA/HMAC/PBKDF2 recomputation verifies the captured call. Prefer byteArray;
   text re-encoding is weaker evidence.
9. When angr initialization is requested, run `generate_angr_state_seed` for that event. Keep SP
   opt-in and explain that heap/stack addresses are process-specific.
10. For an OLLVM probe, generate the Hook at the reported branch, condition-source, or dispatcher
    `startOffset`, select one or more exact `hook-enter`/`ollvm-dispatcher-hit` events, and pass
    `frida_capture_path` plus `frida_event_indices` (legacy `frida_event_index` remains supported) to
    `generate_angr_ollvm_script`. Do not bypass an exact-offset mismatch. Optionally provide the exact
    AArch64 ELF path so the generated manual script embeds a SHA-256 guard. Retain bounded seeded-flow
    for post-branch continuation or next-dispatcher exploration, keep depth/state caps small, and leave
    both Frida and angr execution to the user.
11. When several ranked dispatchers must be observed together, call
    `generate_frida_ollvm_dispatcher_hook` for the same narrow OLLVM scope. Give the standalone script
    to the user for manual execution, then call `analyze_frida_ollvm_dispatcher_capture` on the saved
    capture. Prefer dedicated `ollvm-dispatcher-hit` events with `captureSessionId`, `flowId`, and
    contiguous `hitSequence`; treat legacy idle-gap-derived flows and every atlas edge as
    Candidate/Related only.
    If angr or Unicorn needs memory context, set a small explicit X0-X28 pointer register list and byte
    cap. For concrete replay, optionally capture a bounded window starting at SP. Keep both opt-in because
    pointer validity and buffer semantics are unknown; inspect `readError` values.
12. For concrete OLLVM replay, select one to 32 exact branch/condition-source/dispatcher events and call
    `generate_unicorn_ollvm_script` with the mandatory exact AArch64 ELF. The user runs the Python
    manually and imports the JSON with `inspect_unicorn_ollvm_results`. Use missing-memory
    `baseRegister`/`displacement` suggestions to refine the next bounded Frida capture. When the
    suggestion uses X0-X28 or SP, call `generate_frida_unicorn_recapture_hook` with one to 64 selected
    indices. The generated Hook remains at the original exact seed offset and reads only 1-4096 bytes per
    signed-displacement window. It also re-reads prior seed byteArray windows whose X0-X28/SP-relative
    relation was verified against the capture register and pointer, merges duplicate old/new windows,
    and reports unsupported or truncated prior regions. The user runs it manually and reimports its
    `hook-enter` as a new seed; never copy the prior absolute address or stale captured bytes. If the
    same seed still stops on missing-memory/register, loop, timeout, or instruction limit, call
    `generate_frida_unicorn_checkpoint_hook` with the validated prior result and selected original seed
    offsets. It hooks the actual missing-memory PC, supported terminal PC, or the recorded `PC+4`
    return site for a `call-boundary`, captures full GPR/NZCV and only verified current-register
    X0-X28/SP-relative seed windows, and must be run manually. A post-call Hook emits only when the
    real call returns through that continuation. Reuse its new `hook-enter`
    with `generate_unicorn_ollvm_script.checkpoint_result_path` set to that same prior result. If concrete
    replay still lacks state, pass the same capture, exact ELF, and same prior result to
    `generate_angr_ollvm_script.checkpoint_result_path`; inspect the resulting `checkpointProbes` as
    bounded Candidate/Related paths.

## Request fields

- `module_name`: loaded module basename, such as `libtarget.so`.
- `symbol` or `offset`: exported name or module-relative hexadecimal offset.
- `function_name`: optional stable label and output filename stem.
- `arguments`: X0-X7 entries with `index`, optional `label`, `kind`, `direction`, `length`, `length_arg`, and `length_pointer_arg`.
- `kind`: `integer`, `pointer`, `utf8String`, `utf16String`, or `byteArray`.
- `direction`: `input`, `output`, or `inOut`.
- `capture_registers`, `capture_return`, `capture_backtrace`.
- `stalker`: `off`, `calls`, `blocks`, or `instructions`.
- `stalker_duration_ms` and `max_bytes`: keep bounded.
- Dispatcher capture additionally accepts unique `capture_pointer_registers` X0-X28,
  `pointer_capture_bytes` 1-4096, and `stack_capture_bytes` 0-16384 starting at SP.

## Selection rules

- Prefer a symbol when it is exported and stable; otherwise use a module-relative offset, never a runtime absolute address.
- Label crypto roles explicitly: `key`, `input`, `output`, `iv`, `nonce`, `salt`, `aad`, `tag`, or `length`.
- Use `output` or `inOut` for buffers populated or modified before function return.
- Use `length_arg` when another X register carries the dynamic buffer size. Use a fixed `length` only when verified.
- Use `length_pointer_arg` only for an output buffer whose u32 length is written through another X0-X7 pointer before return. It is dereferenced only on leave; a failed dereference emits `readError` and must not fall back to `max_bytes`.
- Treat `length`, `length_arg`, and `length_pointer_arg` as mutually exclusive.
- Do not treat JNI references such as `jbyteArray` as native byte pointers. Require a native buffer boundary or a separate Java-layer hook instead.
- With `capture_registers:true`, expect X0-X28, FP/LR/SP/PC, and best-effort NZCV from the Frida 16
  ARM64 context. Argument buffer decoding remains limited to X0-X7. The generated angr state seed
  preserves NZCV and attempts packed `state.regs.nzcv` first, with an explicit N/Z/C/V fallback.
- Default Stalker to `off`. Enable `calls` first; use `blocks` or `instructions` only for a narrow function and bounded duration.
- Treat invalid pointers, unreadable memory, and truncated captures as expected runtime conditions.
- Prefer `byteArray` captures for angr memory seeds. Re-encoded UTF-8/UTF-16 strings do not preserve
  invalid bytes or original terminators.
- Match `moduleBase/moduleSize` and the exact binary build before trusting pointer rebasing.
- A function-entry capture is not automatically valid state for a later opaque branch. Match capture
  point semantics before using a seed in a blank-state branch probe.
- For OLLVM handoff, require the captured module-relative target to equal the candidate branch offset,
  one of its recorded condition-source offsets, or a dispatcher `startOffset`. Exact matching prevents
  obvious state-point misuse; it does not prove real-entry reachability, complete dispatcher recovery,
  or completeness of flags, SIMD, and memory.
- For a dispatcher atlas, require `dispatcherOffset` to agree with `target - moduleBase` and to equal a
  current report dispatcher `startOffset`. Connect events only inside one capture session, thread, and
  flow; when both events have `hitSequence`, require consecutive values. These checks do not attest the
  loaded binary build or turn adjacent hits into a complete CFG.
- For Unicorn recapture, reject absolute-address, X29, and X30 suggestions. Preserve `readError` for null
  or unreadable windows and never substitute zero bytes. The embedded expected SHA-256 is provenance from
  the prior replay, not runtime module attestation. Carry prior seed memory only from validated
  `seedRecapturePlans`; split large regions into bounded windows, re-read them at the original exact seed
  offset, and keep unverifiable byteArray/string regions explicit rather than inventing a relation.
- For a closer Unicorn checkpoint, accept only supported stop reasons from a strictly validated prior
  result. Require the same module and exact ELF SHA-256 again when the checkpoint capture becomes a new
  Unicorn or angr seed. The prior hash is a file guard, not runtime-image attestation; absolute memory and
  X29/X30 stay manual, and the generated Hook never attaches, spawns, loads, or executes Frida. For angr,
  keep `checkpoint_result_path` bound to the same prior result and do not reinterpret the capture as a
  branch or dispatcher seed.

## Frida 16 boundary

Generated scripts must retain the classic Frida 16 APIs such as:

```javascript
Module.getExportByName(MODULE_NAME, TARGET_SYMBOL)
Module.getBaseAddress(MODULE_NAME)
Interceptor.attach(target, callbacks)
```

Do not rewrite the output to Frida 17-only APIs. Do not add `frida.attach`, device discovery, spawn control, CLI commands, `--no-pause`, or an automatic live bridge. Importing files the user captured manually does not change this boundary.

## Reporting

State that the output is a generated candidate hook, not execution evidence. When the capture is based on a trace lead, cite the module offset, function/node, and observed argument evidence used to configure it.
