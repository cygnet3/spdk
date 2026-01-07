# backend-blindbit-native

Native Rust backend implementation for SPDK (Silent Payment Development Kit) that connects to Blindbit indexing servers.

## Quick Start

### For Sync/Blocking Applications
```toml
backend-blindbit-native = { version = "0.1.0", default-features = false, features = ["ureq-client"] }
```

```rust
use backend_blindbit_native::{BlindbitBackend, UreqClient};

let client = UreqClient::new();
let backend = BlindbitBackend::new("https://blindbit.io".to_string(), client)?;
let height = backend.block_height()?; // Simple blocking call
```

**Why:** Minimal binary size (~800KB), truly blocking HTTP with no async overhead.

### For Async Applications  
```toml
backend-blindbit-native = { version = "0.1.0", default-features = false, features = ["async", "reqwest-client"] }
```

```rust
use backend_blindbit_native::{AsyncBlindbitBackend, ReqwestClient};

#[tokio::main]
async fn main() -> Result<()> {
    let client = ReqwestClient::new();
    let backend = AsyncBlindbitBackend::new("https://blindbit.io".to_string(), client)?;
    let height = backend.block_height().await?; // Async with concurrency
    Ok(())
}
```

**Why:** High performance with 200+ concurrent requests, full async/tokio benefits.

### Bring Your Own HTTP Client
```toml
backend-blindbit-native = { version = "0.1.0", default-features = false, features = ["sync"] }
```

Then implement the `HttpClient` trait with your preferred HTTP library (see [Custom HTTP Client](#custom-http-client)).

## Feature Flags

### Core Dependencies
- **`async-trait`**: Always included - the `HttpClient` trait is async by design

### Backend Features

#### `sync` - Synchronous Backend
- **What it does:** Enables `BlindbitBackend` - wraps async HTTP calls with `block_on`
- **When to use:** Simple blocking API, command-line tools, scripting
- **Performance:** Sequential processing, no concurrency
- **Dependencies:** `futures` (for `block_on`)

#### `async` - Asynchronous Backend  
- **What it does:** Enables `AsyncBlindbitBackend` - truly async with concurrent requests
- **When to use:** Web servers, high-throughput applications, need for concurrency
- **Performance:** 200+ concurrent block requests, optimal throughput
- **Dependencies:** `futures`, `futures-util`, `spdk-core/async`
- **Note:** Also enables `sync` as a dependency

### HTTP Client Features

#### `ureq-client` - Blocking HTTP Client
- **What it does:** Bundles `UreqClient` (ureq-based HTTP implementation)
- **Binary size:** ~800KB (minimal footprint)
- **Best with:** `sync` backend (or alone - automatically enables sync)
- **Architecture:** Truly blocking I/O wrapped in async trait
- **Use case:** CLI tools, simple applications, minimal dependencies

#### `reqwest-client` - Async HTTP Client
- **What it does:** Bundles `ReqwestClient` (reqwest/hyper-based HTTP implementation)
- **Binary size:** ~2MB+ (full-featured)
- **Best with:** `async` backend
- **Architecture:** True async HTTP with connection pooling, built on tokio
- **Use case:** High-performance async applications, web services

## Performance Considerations

### ✅ Efficient Combinations

| Features | Backend | HTTP Client | Binary Size | Use Case |
|----------|---------|-------------|-------------|----------|
| `ureq-client` | Sync | ureq (blocking) | ~800KB | CLI, scripts, simple apps |
| `async,ureq-client` | Both | ureq (blocking) | ~1MB | Need both APIs, minimal size |
| `async,reqwest-client` | Both | reqwest (async) | ~2.5MB | High-performance async |

### ⚠️ Valid But Inefficient

| Features | Why Inefficient | Better Alternative |
|----------|-----------------|-------------------|
| `sync,reqwest-client` or `reqwest-client` alone | Pulls in tokio runtime but blocks on every request. No concurrency. | Use `ureq-client` for sync, or add `async` feature |

**The Problem:**
```rust
// With sync backend + reqwest
let backend = BlindbitBackend::new(url, ReqwestClient::new())?;

// Internally does this for EVERY call:
block_on(async {
    tokio_spawn(async { reqwest.get().await }).await  // Start runtime, immediately block
})
// Result: ~2MB binary, zero async benefit, wasted overhead
```

## Advanced Usage

### Custom HTTP Client

Implement the `HttpClient` trait with any HTTP library (hyper, isahc, surf, platform-specific APIs, etc.):

```rust
use async_trait::async_trait;
use backend_blindbit_native::HttpClient;
use anyhow::Result;

#[derive(Clone)]
struct MyCustomClient {
    // Your HTTP client here
}

#[async_trait]
impl HttpClient for MyCustomClient {
    async fn get(&self, url: &str, query_params: &[(&str, String)]) -> Result<String> {
        // Implement with your preferred library
        todo!()
    }
    
    async fn post_json(&self, url: &str, json_body: &str) -> Result<String> {
        // Implement POST
        todo!()
    }
}
```

Then use with either backend:

```rust
// Sync
let backend = BlindbitBackend::new(url, MyCustomClient::new())?;

// Async  
let backend = AsyncBlindbitBackend::new(url, MyCustomClient::new())?;
```

### Platform-Specific HTTP

Use native HTTP on each platform:

```rust
#[cfg(target_arch = "wasm32")]
type MyClient = FetchClient;  // Browser fetch API

#[cfg(target_os = "ios")]
type MyClient = NSURLSessionClient;  // NSURLSession

#[cfg(not(any(target_arch = "wasm32", target_os = "ios")))]
type MyClient = ReqwestClient;  // Standard async
```

## Default Configuration

```toml
backend-blindbit-native = "0.1.0"
```

Enables: `sync` + `async` (both backends available)

**Use when:** You want both API styles available and will provide your own HTTP client. Good for libraries that want to expose both sync and async APIs to their users.

## Testing Feature Flags

This crate includes a comprehensive test script that validates all 13 feature flag combinations compile successfully.

### Running Tests Locally

```bash
cd backend-blindbit-native
./test-features.sh          # With colored output
./test-features.sh --ci     # CI-friendly (no colors)
```

### Tested Combinations

The script tests **13 feature flag combinations**:

**Minimal Builds (3 tests):**
1. No features - just the `HttpClient` trait
2. `sync` - Sync backend only (bring your own HTTP client)
3. `async` - Async backend only (bring your own HTTP client)

**Single HTTP Client (2 tests):**
4. `ureq-client` - Sync backend + ureq
5. `reqwest-client` - Sync backend + reqwest

**Backend + Client Combinations (4 tests):**
6. `sync,ureq-client` - Explicit sync + ureq
7. `sync,reqwest-client` - Explicit sync + reqwest
8. `async,ureq-client` - Async + ureq
9. `async,reqwest-client` - Async + reqwest

**Multiple Clients (3 tests):**
10. `sync,ureq-client,reqwest-client` - Both clients, sync backend
11. `async,ureq-client,reqwest-client` - Both clients, async backend
12. `sync,async,ureq-client,reqwest-client` - Everything enabled
13. Default features (`sync,async`)

### CI Integration

**GitHub Actions:**
```yaml
- name: Test all feature combinations
  run: |
    cd backend-blindbit-native
    ./test-features.sh --ci
```

**GitLab CI:**
```yaml
test-features:
  script:
    - cd backend-blindbit-native
    - ./test-features.sh --ci
```

**Exit Codes:**
- `0` - All tests passed ✓
- `1` - One or more tests failed ✗

**Note:** The test script validates compilation, not performance characteristics. See [Performance Considerations](#performance-considerations) for efficiency guidance.

## License

See the workspace root for license information.

