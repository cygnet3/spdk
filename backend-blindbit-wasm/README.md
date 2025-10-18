# Backend Blindbit WASM

**⚠️ This crate is designed exclusively for WebAssembly targets.**

## Building

This crate must be compiled with the `wasm32-unknown-unknown` target:

```bash
# Check compilation
cargo check -p backend-blindbit-wasm --target wasm32-unknown-unknown

# Build for production
cargo build -p backend-blindbit-wasm --target wasm32-unknown-unknown --release
```

## IDE Integration

### Rust Analyzer Errors

If you see errors in rust-analyzer like "unresolved import" or "could not resolve", this is normal. 
Rust-analyzer runs with the default target (usually your native platform), but this crate is WASM-only.

**Solutions:**

1. **Ignore the errors** - they won't appear when building with the correct target
2. **Configure your IDE** to use WASM target for this specific crate
3. **Use the test script** to verify everything compiles correctly:
   ```bash
   ./test-compilation.sh
   ```

### VSCode Setup

The workspace includes `.vscode/settings.json` with rust-analyzer configuration that should help reduce false errors.

## How It Works

This crate uses `reqwest` for HTTP requests. When compiled to WASM:

- `reqwest` automatically detects the WASM target
- Instead of native networking, it generates bindings to the browser's `fetch()` API
- Your Rust code stays the same, but the implementation completely changes under the hood

```rust
// This Rust code:
let response = reqwest::get("https://api.example.com").await?;

// Becomes this JavaScript when compiled to WASM:
// fetch("https://api.example.com").then(...)
```

## Limitations

When running in WASM:
- No custom timeouts (browser manages this)
- Limited TLS configuration (browser handles TLS)
- Cookies managed by browser
- CORS restrictions apply

## Usage

```rust
use backend_blindbit_wasm::BlindbitClient;

// Same API as native version
let client = BlindbitClient::new("https://blindbit-api.com".to_string())?;
let height = client.block_height().await?;
```

