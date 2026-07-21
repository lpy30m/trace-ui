# Unified Value Search and Multi-Trace Table Classification

Implemented on 2026-07-21.

## Unified Value Search

`search_value` is shared by trace-core, MCP, Tauri, and the GUI. It exposes every byte interpretation instead of silently transforming the input:

- exact UTF-8 and UTF-16LE, with optional NUL forms;
- separator-tolerant hex in input byte order;
- unsigned integer and address forms with explicit width and endian labels;
- CRC32/MD5/SHA digest bytes by recognized length.

Sources are runtime strings, sequence-replayed historical memory writes, and exact case-sensitive trace text. Memory replay detects values assembled by multiple stores, reports repeated occurrences at different times, and retains earlier matches before later overwrites. Results carry exact address/sequence/byte-length anchors for Jump, Memory, backward taint, and forward taint.

Digest-byte search is intentionally distinct from `analyze_known_digest`: the former locates the digest bytes, while the latter recomputes candidate inputs and applies the digest verification gate.

## Multi-trace table classification

`compare_crypto_table_traces` and the GUI trace matrix accept explicit `keyGroup` and `inputGroup` labels. A `KeyDependentTableCandidate` requires:

1. at least two labeled keys;
2. at least two differently labeled inputs in every key group;
3. stable normalized fingerprint sets across inputs within each key;
4. matching table shapes but differing normalized values across keys;
5. the same reconciled ELF SHA-256 across every case;
6. no observed raw key or standard expanded schedule contradiction.

Input-varying fingerprints are classified as `InputDependentTables`; values stable across keys are `InputAndKeyIndependentTables`; a matching table pattern without proven ELF identity is `BuildIdentityUnconfirmed`; insufficient matrices remain `InsufficientEvidence`. Caller labels and controlled-variable assumptions are always reported as limitations.

The multi-trace report always returns `verificationGateMet: false`. Table provenance, input stability, and cross-key differences are Candidate/Related structural evidence; only deterministic semantic recomputation of known key/input/output material can be Verified.

## Primary files

- `crates/trace-core/src/query/value_search.rs`
- `crates/trace-core/src/engine/value_search.rs`
- `crates/trace-core/src/query/whitebox_compare.rs`
- `crates/trace-core/src/engine/whitebox_aes.rs`
- `crates/trace-mcp/src/types.rs`
- `crates/trace-mcp/src/tools.rs`
- `src-tauri/src/commands/mod.rs`
- `src-web/src/components/ValueSearchPanel.tsx`
- `src-web/src/components/WhiteBoxPanel.tsx`

## Verification

```powershell
cargo test -p trace-core
cargo test -p trace-mcp
cargo check --workspace
npm run build --prefix src-web
cargo fmt --all -- --check
git diff --check
```
