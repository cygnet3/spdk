# Usage Examples

## For Published Crates (crates.io)

### Core Client Only (Most Common)
```toml
[dependencies]
sp-client = { version = "0.1", features = ["parallel"] }
```

```rust
use sp_client::*;

fn main() {
    let client = SpClient::new(scan_sk, spend_key, network)?;
    let address = client.get_receiving_address();
    
    // With parallel feature enabled
    let script_map = client.get_script_to_secret_map(tweaks)?;
}
```

### Core Client + Native Backend
```toml
[dependencies]
sp-client = "0.1"
backend-blindbit-native = "0.1"
```

```rust
use sp_client::*;
use backend_blindbit_native::*;

fn main() {
    // Core client functionality
    let client = SpClient::new(scan_sk, spend_key, network)?;
    
    // Backend functionality
    let backend = BlindbitBackend::new(host_url)?;
    let scanner = SomeScanner::new(client, backend);
}
```

### WASM Projects
```toml
[dependencies]
sp-client = { version = "0.1", default-features = false }
# Note: No backend - only core client works in WASM
```

```rust
use sp_client::*;

// Only core client functionality available
let client = SpClient::new(scan_sk, spend_key, network)?;
let address = client.get_receiving_address();
// get_script_to_secret_map() not available without "parallel" feature
```

## For Local Development (Git Dependencies)

### Using Git Repository
```toml
[dependencies]
sp-client = { git = "https://github.com/your-org/sp-client", features = ["parallel"] }
backend-blindbit-native = { git = "https://github.com/your-org/sp-client" }
```

### Using Local Path
```toml
[dependencies]
sp-client = { path = "../sp-client/sp-client", features = ["parallel"] }
backend-blindbit-native = { path = "../sp-client/backend-blindbit-native" }
```
