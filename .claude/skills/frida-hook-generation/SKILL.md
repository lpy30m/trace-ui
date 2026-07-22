---
name: frida-hook-generation
description: Generate bounded ARM64 Frida 16.x JavaScript hook scripts, inspect user-captured trace-ui/frida-hook-v1 JSON or NDJSON, index captured crypto materials, and turn exact-offset register/buffer captures into manual angr or OLLVM state seeds through the trace-ui MCP server. Use for native exports or module-relative offsets, X0-X7 arguments, full ARM64 GPR snapshots, key/salt/digest buffers, strings, returns, backtraces, Stalker events, capture review, or Frida-to-angr handoff. Trace UI never attaches, spawns, loads, or executes Frida; the user controls runtime execution.
---

# Generate Frida 16 hooks with trace-ui

Use `mcp__trace-ui__list_frida_hook_recipes`, `mcp__trace-ui__generate_frida_hook`, `mcp__trace-ui__inspect_frida_capture`,
`mcp__trace-ui__analyze_frida_crypto_materials`, and
`mcp__trace-ui__generate_angr_state_seed`. Generated hooks target Frida 16.x JavaScript APIs and emit
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
7. If the user supplies captured JSON/NDJSON, run `inspect_frida_capture`. Select an exact event index,
   normally a `hook-enter` with registers or buffers.
8. When crypto roles are requested, run `analyze_frida_crypto_materials`. Treat explicit labels as
   Related unless exact MD5/SHA/HMAC/PBKDF2 recomputation verifies the captured call. Prefer byteArray;
   text re-encoding is weaker evidence.
9. When angr initialization is requested, run `generate_angr_state_seed` for that event. Keep SP
   opt-in and explain that heap/stack addresses are process-specific.
10. For an OLLVM probe, generate the Hook at the reported branch, condition-source, or dispatcher
    `startOffset`, select its `hook-enter` event, and pass `frida_capture_path` plus
    `frida_event_index` to `generate_angr_ollvm_script`. Do not bypass an exact-offset mismatch. Retain
    bounded seeded-flow for post-branch continuation or next-dispatcher exploration, keep depth/state
    caps small, and leave both Frida and angr execution to the user.

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

## Selection rules

- Prefer a symbol when it is exported and stable; otherwise use a module-relative offset, never a runtime absolute address.
- Label crypto roles explicitly: `key`, `input`, `output`, `iv`, `nonce`, `salt`, `aad`, `tag`, or `length`.
- Use `output` or `inOut` for buffers populated or modified before function return.
- Use `length_arg` when another X register carries the dynamic buffer size. Use a fixed `length` only when verified.
- Use `length_pointer_arg` only for an output buffer whose u32 length is written through another X0-X7 pointer before return. It is dereferenced only on leave; a failed dereference emits `readError` and must not fall back to `max_bytes`.
- Treat `length`, `length_arg`, and `length_pointer_arg` as mutually exclusive.
- Do not treat JNI references such as `jbyteArray` as native byte pointers. Require a native buffer boundary or a separate Java-layer hook instead.
- With `capture_registers:true`, expect X0-X28, FP/LR/SP/PC, and best-effort NZCV from the Frida 16
  ARM64 context. Argument buffer decoding remains limited to X0-X7.
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
