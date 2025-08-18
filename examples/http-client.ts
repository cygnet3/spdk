/**
 * TypeScript HTTP client for use with WASM code
 * This client implements the interface expected by the Rust WASM code
 */

export class WasmHttpClient {
  private baseUrl?: string;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl;
  }

  /**
   * Make a GET request
   */
  async get<T>(url: string): Promise<T> {
    const fullUrl = this.baseUrl ? `${this.baseUrl}${url}` : url;
    
    try {
      const response = await fetch(fullUrl, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('GET request failed:', error);
      throw error;
    }
  }

  /**
   * Make a POST request
   */
  async post<T>(url: string, body: any): Promise<T> {
    const fullUrl = this.baseUrl ? `${this.baseUrl}${url}` : url;
    
    try {
      const response = await fetch(fullUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('POST request failed:', error);
      throw error;
    }
  }

  /**
   * Set a base URL for all requests
   */
  setBaseUrl(baseUrl: string) {
    this.baseUrl = baseUrl;
  }
}

/**
 * Example usage with the WASM code:
 * 
 * ```typescript
 * import { WasmHttpClient } from './http-client';
 * import init, { BlindbitClient } from './pkg/sp_client';
 * 
 * async function main() {
 *   // Initialize WASM
 *   await init();
 *   
 *   // Create HTTP client
 *   const httpClient = new WasmHttpClient();
 *   
 *   // Create Blindbit client with HTTP client
 *   const blindbitClient = BlindbitClient.new_wasm(
 *     "https://api.example.com/", 
 *     httpClient
 *   );
 *   
 *   // Use the client
 *   try {
 *     const height = await blindbitClient.block_height_wasm();
 *     console.log('Block height:', height);
 *   } catch (error) {
 *     console.error('Error:', error);
 *   }
 * }
 * 
 * main();
 * ```
 */


