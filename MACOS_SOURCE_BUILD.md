# Building Trace UI on macOS

Do not copy `target/`, `src-web/node_modules/`, or `src-web/dist/` from Windows.
They are generated artifacts and must be rebuilt on macOS.

## Prerequisites

Install the Xcode command-line tools:

```bash
xcode-select --install
```

Install Rust with rustup and use the stable toolchain:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable
```

Install Node.js 20 or newer. With Homebrew:

```bash
brew install node@20
```

Install the Tauri CLI:

```bash
cargo install tauri-cli --version "^2" --locked
```

## Build for Apple Silicon

Use this target on M1, M2, M3, M4, and newer Apple Silicon Macs:

```bash
cd trace-ui-source-macos-20260718
npm ci --prefix src-web
rustup target add aarch64-apple-darwin
cargo tauri build --target aarch64-apple-darwin
```

The application and DMG are generated under:

```text
target/aarch64-apple-darwin/release/bundle/
```

## Build for Intel Mac

```bash
cd trace-ui-source-macos-20260718
npm ci --prefix src-web
rustup target add x86_64-apple-darwin
cargo tauri build --target x86_64-apple-darwin
```

The output is generated under:

```text
target/x86_64-apple-darwin/release/bundle/
```

## Ad-hoc signing

For a local build without an Apple Developer certificate, sign the application after building:

```bash
codesign --force --deep --sign - \
  "target/aarch64-apple-darwin/release/bundle/macos/Trace UI.app"
codesign --verify --verbose \
  "target/aarch64-apple-darwin/release/bundle/macos/Trace UI.app"
```

Replace `aarch64-apple-darwin` with `x86_64-apple-darwin` for an Intel build.

If Gatekeeper blocks the locally built application:

```bash
xattr -dr com.apple.quarantine "/Applications/Trace UI.app"
```

## Development mode

```bash
npm ci --prefix src-web
cargo tauri dev
```

The frontend uses `http://localhost:5173`. The embedded MCP server listens on
`http://127.0.0.1:19821/mcp` while the desktop application is running.
