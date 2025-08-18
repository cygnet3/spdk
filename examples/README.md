# Using SP Client with TypeScript HTTP Client in WASM

This example demonstrates how to use the SP Client library in a WASM environment with a TypeScript HTTP client instead of the native `reqwest` client.

## Overview

The library now supports both native and WASM environments:
- **Native**: Uses `reqwest` for HTTP requests
- **WASM**: Uses a TypeScript HTTP client passed from JavaScript

## Setup

### 1. Build for WASM

```bash
# Install WASM target
rustup target add wasm32-unknown-unknown

# Build the library
cargo build --target wasm32-unknown-unknown

# Or use wasm-pack for easier builds
wasm-pack build --target web
```

### 2. TypeScript HTTP Client

The `http-client.ts` file provides a TypeScript implementation of the HTTP client interface expected by the WASM code.

## Usage

### Basic Example

```typescript
import { WasmHttpClient } from './http-client';
import init, { BlindbitClient } from './pkg/sp_client';

async function main() {
  // Initialize WASM
  await init();
  
  // Create HTTP client
  const httpClient = new WasmHttpClient();
  
  // Create Blindbit client with HTTP client
  const blindbitClient = BlindbitClient.new_wasm(
    "https://api.example.com/", 
    httpClient
  );
  
  // Use the client
  try {
    const height = await blindbitClient.block_height_wasm();
    console.log('Block height:', height);
    
    const info = await blindbitClient.info_wasm();
    console.log('Info:', info);
  } catch (error) {
    console.error('Error:', error);
  }
}

main();
```

### Advanced Example with Error Handling

```typescript
import { WasmHttpClient } from './http-client';
import init, { BlindbitClient } from './pkg/sp_client';

class BlindbitService {
  private client: BlindbitClient;
  
  constructor(apiUrl: string) {
    this.client = BlindbitClient.new_wasm(apiUrl, new WasmHttpClient());
  }
  
  async getBlockHeight(): Promise<number> {
    try {
      return await this.client.block_height_wasm();
    } catch (error) {
      console.error('Failed to get block height:', error);
      throw new Error(`Block height request failed: ${error}`);
    }
  }
  
  async getInfo(): Promise<any> {
    try {
      const infoJson = await this.client.info_wasm();
      return JSON.parse(infoJson);
    } catch (error) {
      console.error('Failed to get info:', error);
      throw new Error(`Info request failed: ${error}`);
    }
  }
}

// Usage
async function main() {
  await init();
  
  const service = new BlindbitService("https://api.example.com/");
  
  try {
    const [height, info] = await Promise.all([
      service.getBlockHeight(),
      service.getInfo()
    ]);
    
    console.log(`Current block height: ${height}`);
    console.log('API info:', info);
  } catch (error) {
    console.error('Service error:', error);
  }
}

main();
```

## Architecture

### How It Works

1. **TypeScript HTTP Client**: Implements the interface expected by Rust WASM code
2. **WASM Bindings**: Rust code exposes methods that can be called from JavaScript
3. **HTTP Client Injection**: The TypeScript client is passed to the Rust code during construction
4. **Request Delegation**: Rust code delegates HTTP requests to the injected TypeScript client

### Benefits

- **No Bundle Bloat**: TypeScript code doesn't increase WASM bundle size
- **Familiar APIs**: Use standard `fetch()` API
- **Better Error Handling**: TypeScript gives proper error types
- **Flexibility**: Easy to add features like retry logic, caching, etc.
- **Performance**: No overhead from Rust-to-JS conversions for HTTP operations

### Trade-offs

- **Complexity**: Need to handle JS interop and type conversions
- **Memory Management**: Careful about JS object lifetimes
- **Error Propagation**: Errors cross Rust/JS boundary
- **Type Safety**: Less compile-time safety for HTTP operations

## Troubleshooting

### Common Issues

1. **WASM not initialized**: Make sure to call `await init()` before using the library
2. **HTTP client not passed**: Use `new_wasm()` constructor for WASM builds
3. **CORS issues**: Ensure your API server allows requests from your domain
4. **Type errors**: Make sure TypeScript types match the expected interface

### Debug Tips

- Check browser console for JavaScript errors
- Use browser dev tools to inspect network requests
- Verify WASM module is loaded correctly
- Test HTTP client independently before integrating with WASM

## Next Steps

- Add retry logic to the HTTP client
- Implement request caching
- Add request/response interceptors
- Support for different authentication methods
- Add request timeout handling


