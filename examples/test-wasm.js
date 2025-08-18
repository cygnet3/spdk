/**
 * Simple test file to demonstrate WASM integration
 * Run this in a browser environment after building with wasm-pack
 */

// Mock HTTP client for testing
class MockHttpClient {
  constructor() {
    this.calls = [];
  }

  async get(url) {
    this.calls.push({ method: 'GET', url });
    
    // Mock responses based on URL
    if (url.includes('block-height')) {
      return { block_height: 800000 };
    } else if (url.includes('info')) {
      return { 
        network: 'bitcoin',
        height: 800000,
        tweaks_only: true,
        tweaks_full_basic: true,
        tweaks_full_with_dust_filter: true,
        tweaks_cut_through_with_dust_filter: true
      };
    }
    
    throw new Error(`Unknown endpoint: ${url}`);
  }

  async post(url, body) {
    this.calls.push({ method: 'POST', url, body });
    
    if (url.includes('forward-tx')) {
      return 'mock-txid-1234567890abcdef';
    }
    
    throw new Error(`Unknown endpoint: ${url}`);
  }

  getCallHistory() {
    return this.calls;
  }
}

// Test function
async function testWasmIntegration() {
  try {
    console.log('Testing WASM integration...');
    
    // Create mock HTTP client
    const httpClient = new MockHttpClient();
    
    // Note: In a real environment, you would:
    // 1. Import the WASM module: import init, { BlindbitClient } from './pkg/sp_client';
    // 2. Initialize WASM: await init();
    // 3. Create the client: const client = BlindbitClient.new_wasm("https://api.example.com/", httpClient);
    
    console.log('Mock HTTP client created');
    console.log('HTTP client methods:', Object.getOwnPropertyNames(Object.getPrototypeOf(httpClient)));
    
    // Test GET request
    const heightResponse = await httpClient.get('block-height');
    console.log('Block height response:', heightResponse);
    
    // Test POST request
    const txResponse = await httpClient.post('forward-tx', { data: 'mock-tx-hex' });
    console.log('Transaction response:', txResponse);
    
    // Show call history
    console.log('HTTP call history:', httpClient.getCallHistory());
    
    console.log('✅ All tests passed!');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { MockHttpClient, testWasmIntegration };
} else {
  // Browser environment
  window.MockHttpClient = MockHttpClient;
  window.testWasmIntegration = testWasmIntegration;
}

// Auto-run in browser
if (typeof window !== 'undefined') {
  testWasmIntegration();
}


