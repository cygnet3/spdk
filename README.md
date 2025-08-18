# SP client

Sp-client is a library that can be used to build silent payment wallets.
It builds on top of [rust-silentpayments](https://github.com/cygnet3/rust-silentpayments).

Whereas rust-silentpayments concerns itself with cryptography (it is essentially a wrapper around secp256k1 for some silent payments logic),
sp-client is concerned with high-level wallet stuff, such as parsing incoming transactions, managing owned outputs, and signing transactions.

This library is used as a backend for the silent payment wallet [Dana wallet](https://github.com/cygnet3/danawallet).

## WASM Support

This library supports WebAssembly (WASM) targets for use in web applications. To build for WASM:

### Prerequisites

1. Install the WASM target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```

2. Install wasm-pack (optional, for easier WASM builds):
   ```bash
   cargo install wasm-pack
   ```

### Building for WASM

#### Using Cargo directly:
```bash
cargo build --target wasm32-unknown-unknown
```

#### Using wasm-pack:
```bash
wasm-pack build --target web
```

### Features

When building for WASM:
- The `rayon` dependency is automatically disabled and parallel processing falls back to sequential processing
- The `blindbit-backend` feature is available with **TypeScript HTTP client injection** for WASM
- All core functionality remains available

### HTTP Client in WASM

The library uses a **TypeScript HTTP client injection** approach for WASM builds:

- **Native builds**: Use `reqwest` for HTTP requests
- **WASM builds**: Accept a TypeScript HTTP client that implements the required interface

This approach provides several benefits:
- **No bundle bloat**: TypeScript code doesn't increase WASM bundle size
- **Familiar APIs**: Use standard `fetch()` API
- **Better error handling**: TypeScript gives proper error types
- **Flexibility**: Easy to add features like retry logic, caching, etc.

### Usage in Web Applications

The library can be used in web applications through standard WASM interop. For HTTP functionality in WASM:

```typescript
import { WasmHttpClient } from './http-client';
import init, { BlindbitClient } from './pkg/sp_client';

async function main() {
  await init();
  
  const httpClient = new WasmHttpClient();
  const blindbitClient = BlindbitClient.new_wasm(
    "https://api.example.com/", 
    httpClient
  );
  
  const height = await blindbitClient.block_height_wasm();
  console.log('Block height:', height);
}

main();
```

See the `examples/` directory for complete working examples and the `http-client.ts` file for the TypeScript HTTP client implementation.
