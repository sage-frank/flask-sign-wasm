export interface WasmExports {
  memory: WebAssembly.Memory;
  alloc: (len: number) => number;
  dealloc: (ptr: number, len: number) => void;
  result_len: () => number;
  sign_request: (ptr: number, len: number) => number;
}

let wasmInstance: WebAssembly.Instance | null = null;

export async function initWasm(wasmPath: string = '/wasm/sign_wasm.wasm'): Promise<void> {
  if (wasmInstance) return;

  try {
    const response = await fetch(wasmPath);
    if (!response.ok) {
      throw new Error(`Failed to fetch WASM: ${response.statusText}`);
    }
    const bytes = await response.arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes, {});
    wasmInstance = instance;
    console.log('WASM initialized successfully');
  } catch (error) {
    console.error('WASM initialization failed:', error);
    throw error;
  }
}

export function getWasmInstance(): WebAssembly.Instance {
  if (!wasmInstance) {
    throw new Error('WASM not initialized. Call initWasm() first.');
  }
  return wasmInstance;
}

export function signJson(payload: any): any {
  const instance = getWasmInstance();
  const exports = instance.exports as unknown as WasmExports;
  
  const jsonStr = JSON.stringify(payload);
  const encoder = new TextEncoder();
  const bytes = encoder.encode(jsonStr);
  const len = bytes.length;
  
  // Allocate memory in WASM
  const ptr = exports.alloc(len);
  
  // Write data to WASM memory
  // Always access memory.buffer freshly in case of growth
  const mem = new Uint8Array(exports.memory.buffer);
  mem.set(bytes, ptr);
  
  // Call signing function
  const outPtr = exports.sign_request(ptr, len);
  
  // Get result length
  const outLen = exports.result_len();
  
  // Read result from WASM memory
  // Re-access memory.buffer
  const outMem = new Uint8Array(exports.memory.buffer);
  const outBytes = outMem.slice(outPtr, outPtr + outLen);
  
  // Decode result
  const decoder = new TextDecoder();
  const resultJson = decoder.decode(outBytes);
  
  // Deallocate memory
  exports.dealloc(ptr, len);
  exports.dealloc(outPtr, outLen);
  
  try {
    return JSON.parse(resultJson);
  } catch (e) {
    console.error('Failed to parse WASM output:', resultJson);
    throw e;
  }
}
