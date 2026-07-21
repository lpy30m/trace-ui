# Windows implementation status — 2026-07-21

- Crypto Stage A-D is implemented, including AES schedule/ECB semantic verification, the real 29-block encrypt `VerifiedFull` result, and the separate wrapper AES-128-ECB decrypt result.
- Verified software AES reports expose key/input/output observation sequences for direct GUI trace jumps; decrypt reports hash and display the ciphertext input rather than the plaintext output.
- Software AES candidate pairing is time-ordered (`input/key <= output`) so buffers observed after an output window cannot retroactively verify an earlier call.
- `analyze_crypto_implementations` returns typed MCP structured content with a root object schema and a persisted `analysis_id`.
- AES semantic hypothesis verification covers ECB, CBC, CTR, and authenticated GCM for AES-128/192/256; CBC/CTR use explicit IV/counter inputs and GCM requires both payload and tag agreement.
- The software analyzer automatically recognizes VerifiedFull CBC and CTR when a time-ordered IV/initial-counter buffer is observed, exposes its sequence, and generates mode-correct Python reproducers; ECB remains the first exact-match choice.
- The software analyzer also recognizes empty-AAD AES-GCM encrypt/decrypt when a 12-byte nonce and 16-byte authentication tag are observed; payload-only matches and incorrect tags are rejected, and nonce/tag evidence is jumpable in the GUI.
- GCM auto-detection now includes explicitly observed non-empty AAD of arbitrary length, records its sequence, exposes a GUI jump, and emits it in the Python reproducer without affecting real-trace analysis time.
- CTR verification and automatic detection accept arbitrary byte lengths, including a partial final block, without applying block-cipher padding.
- Standard AES schedule evidence accepts complete round-key suffixes stored with per-word little-endian layout; the verified real traces now propagate `ObfuscatedStandardSoftware`, `RawKeyObserved`, and `NotWhiteBox` to the top-level report, while raw-key-plus-padding is rejected.
- Verified raw-key reports dynamically recommend skipping DCA/BGE/DFA key recovery and prioritize reproducer and call-boundary auditing.
- Call annotations retain raw ABI arguments, typed roles, hexdump observation sequence, and completion sequence.
- Memory provenance distinguishes `instruction_write`, `call_model`, `call_hexdump`, and `unknown`.
- Backward and forward taint cross modeled libc call boundaries.
- Sources accept explicit `@line:N` and `@seq:N` anchors while retaining legacy numeric syntax.
- `get_tainted_lines` requires `analysis_id`, reads persisted per-analysis sequences, and returns structured MCP content.
- Both supplied MD5 traces normalize to `sprintf x4 -> strcat x3 -> memmove` in ignored integration tests.
- `.github/workflows/ci.yml` validates formatting, parser/core tests, MCP, and the frontend build.
- Function-scoped structural analysis now detects dense boolean plus permutation/shift networks as `Bitsliced candidate` / `BitslicedSoftware`. This signal is deliberately `related` only, never opens the verification gate, and is shown with per-shape counts in the Functions UI.
- Function-level crypto instructions and magic-constant sets, including SM4 and DES shapes, are now explicitly structural `related` evidence only. `verified` remains reserved for semantic recomputation of observed inputs and outputs.
- Annotation buffers now use the actual hexdump observation sequence rather than the earlier BL instruction, and duplicate byte observations deterministically retain their earliest real occurrence. This prevents later call data from being paired retroactively with an earlier output.
- AES schedule classification is scoped to the selected key-to-output execution window; a valid schedule written only after that output no longer changes the current call to `ObfuscatedStandardSoftware` / `NotWhiteBox`.
- Output reconstruction now deduplicates identical indexed/raw write records, splits a repeated store site when its destination addresses are reused by a later call, and requires one consistent overwrite generation when combining multiple store sites. Partial later-call overwrites can no longer be joined with stale bytes from an earlier call into one semantic candidate.
- Table-driven analysis now emits normalized SHA-256 fingerprints for 32-bit lookup contents. The normalization is invariant to word endianness, byte rotation, entry order, and two-region table splits; exact standard AES T-table matches remain structural `AES T-table candidate` evidence and never open the verification gate. Unrelated in-module word reads no longer pollute split-table matching.
- Pointer-dense absolute/relative code-target tables are now classified as control-flow dispatcher candidates. They remain visible and jumpable in the report, but are excluded from crypto lookup volume, round estimation, implementation classification, and table fingerprints so flattened control flow cannot dominate software-crypto scoring.
- Verified ECB analysis now infers canonical, transposed 4x4, per-word byte-reversed, and combined state serializations. A non-canonical layout is accepted only when transforming every complete input/output block produces a full AES semantic match; the selected layout and transformation evidence are exposed in the report and GUI.
- Trace comparison now builds function-instance shapes from the innermost dynamic call-tree frame, normalizes register-independent mnemonic categories, and pairs matching shapes across versions. Results expose the left/right module-relative offsets, call counts, signatures, relocation status, and jumpable sample sequences through `compare_traces` and saved analysis evidence.
- Dynamic encoding-boundary analysis now reports conservative input/output candidates only around crypto-eligible tables: external byte loads must drive a stable stride lookup within 16 seq, or a table value must be stored unchanged outside the module within 16 seq. Candidates require at least 16 matches and 16 distinct external byte addresses, remain jumpable in the GUI, and never open the verification gate.
- Optional static ELF reconciliation accepts a local `.so` path through the GUI file picker, Tauri command, and MCP request. It parses ELF32/ELF64 architecture, GNU Build ID, and `PT_LOAD` mappings; converts dynamic module-relative table addresses to file offsets; compares distinct runtime values with file-backed bytes; and compares normalized static/dynamic fingerprints. The matching AArch64 `libcryptoDD.so` (Build ID `9f5dd9b43d965da8f77693f3be5a8522bfac32e7`) now passes both real AES traces with exact 1639/1639 and 1351/1351 entry matches at module/file offset `0x455e8`/`0x455e9`.
- Unified Value Search interprets exact UTF-8/UTF-16LE text, separator hex, integers, addresses, and digest bytes; searches runtime strings, historical reconstructed memory, and exact trace text; and returns jump/memory/backward/forward-taint anchors. Every byte-order or encoding transform is labeled and no text case/whitespace or hex byte order is silently changed.
- Multi-trace table classification accepts an explicitly labeled key/input matrix in core, MCP, Tauri, and the GUI. It requires per-key input stability, matching table shapes with cross-key value changes, and the same reconciled ELF SHA-256 for `KeyDependentTableCandidate`; it downgrades missing/different build identity, rejects input-dependent tables and raw-key/schedule contradictions, and deliberately keeps `verificationGateMet=false` because structural comparison is not semantic crypto proof.

## Verification commands

```powershell
cargo fmt --all -- --check
cargo test -p trace-parser
cargo test -p trace-core
cargo check -p trace-mcp
npm ci --prefix src-web
npm run build --prefix src-web
```

Private sample integration tests:

```powershell
$env:TRACE_AES_SAMPLE=(Resolve-Path '..\samples\aes\qbdi_20260719_230906_libcryptoDD.so+0x41ed8_1.gumtrace.txt').Path
cargo test -p trace-core real_trace_reaches_verified_full_without_sample_specific_offsets -- --ignored --nocapture

$env:TRACE_AES_SECOND_SAMPLE=(Resolve-Path '..\samples\aes\qbdi_20260719_230907_libcryptoDD.so+0x41ed8_3.gumtrace.txt').Path
cargo test -p trace-core real_wrapper_trace_reaches_verified_full_decrypt -- --ignored --nocapture

$env:TRACE_AES_SO=(Resolve-Path '..\trace-ui\libcryptoDD.so').Path
cargo test -p trace-core real_trace_joins_dynamic_tables_to_matching_static_elf -- --ignored --nocapture

$env:TRACE_MD5_CORE_SAMPLE=(Resolve-Path '..\samples\md5\cryptoDD_md5_core_trace_0_0x4095c.log').Path
cargo test -p trace-core real_core_trace_has_the_same_format_join_copy_call_shape -- --ignored --nocapture

$env:TRACE_MD5_WRAPPER_SAMPLE=(Resolve-Path '..\samples\md5\cryptoDD_md5_crypt_trace_1_0x43bbc.log').Path
cargo test -p trace-core real_wrapper_trace_exposes_final_buffer_with_call_provenance -- --ignored --nocapture
```
