---
name: frida-hook-generation
description: Generate bounded ARM64 Frida 16.x JavaScript hook scripts through the trace-ui MCP server. Use when the user wants a hook for a native export or module-relative offset, wants to capture X0-X7 arguments, buffers, strings, return values, backtraces, or Stalker execution events, or wants to turn a trace crypto/OLLVM lead into a reusable Frida script. This skill only generates scripts; the user remains responsible for attach, spawn, script loading, target selection, and execution.
---

# Generate Frida 16 hooks with trace-ui

Use `mcp__trace-ui__generate_frida_hook`. The result targets Frida 16.x JavaScript APIs and emits `trace-ui/frida-hook-v1` messages with `send()`.

## Workflow

1. Identify the exact module basename and either an exported symbol or an ASLR-stable module-relative offset. Provide exactly one of `symbol` or `offset`.
2. Infer argument roles from `analyze_function`, crypto-material evidence, ABI knowledge, or user input. Do not guess pointer lengths silently.
3. Call `generate_frida_hook` with only the captures needed for the question.
4. Return or save the generated `.js` script. Explain the expected event fields and any unsafe memory-read assumptions.
5. Stop. Do not attach, spawn, load, execute, or claim the hook ran. The user performs those steps manually.

## Request fields

- `module_name`: loaded module basename, such as `libtarget.so`.
- `symbol` or `offset`: exported name or module-relative hexadecimal offset.
- `function_name`: optional stable label and output filename stem.
- `arguments`: X0-X7 entries with `index`, optional `label`, `kind`, `direction`, `length`, and `length_arg`.
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
- Default Stalker to `off`. Enable `calls` first; use `blocks` or `instructions` only for a narrow function and bounded duration.
- Treat invalid pointers, unreadable memory, and truncated captures as expected runtime conditions.

## Frida 16 boundary

Generated scripts must retain the classic Frida 16 APIs such as:

```javascript
Module.getExportByName(MODULE_NAME, TARGET_SYMBOL)
Module.getBaseAddress(MODULE_NAME)
Interceptor.attach(target, callbacks)
```

Do not rewrite the output to Frida 17-only APIs. Do not add `frida.attach`, device discovery, spawn control, CLI commands, `--no-pause`, or an automatic live bridge unless the user explicitly starts a separate implementation task that changes this boundary.

## Reporting

State that the output is a generated candidate hook, not execution evidence. When the capture is based on a trace lead, cite the module offset, function/node, and observed argument evidence used to configure it.
