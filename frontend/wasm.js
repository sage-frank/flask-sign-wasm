let wasmInstance = null;
let exports = null;

async function loadWasm() {
  if (wasmInstance) return;
  // 在 file:// 或 3000 端口开发模式下，从后端 HTTP 加载
  const isFile = window.location.protocol === 'file:';
  const isDevPort = window.location.protocol === 'http:' && window.location.port === '3000';
  const wasmUrl = (isFile || isDevPort)
    ? 'http://127.0.0.1:5000/wasm/sign_wasm.wasm'
    : '/wasm/sign_wasm.wasm';
  const resp = await fetch(wasmUrl, { credentials: 'include' });
  const bytes = await resp.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes, {});
  wasmInstance = instance;
  exports = instance.exports;
}

function toUTF8Bytes(str) {
  return new TextEncoder().encode(str);
}
function fromUTF8Bytes(bytes) {
  return new TextDecoder().decode(bytes);
}

async function callJson(funcName, payload) {
  await loadWasm();
  const jsonStr = JSON.stringify(payload);
  const data = toUTF8Bytes(jsonStr);
  const ptr = exports.alloc(data.length);
  let mem = new Uint8Array(exports.memory.buffer);
  mem.set(data, ptr);
  const outPtr = exports[funcName](ptr, data.length);
  const outLen = exports.result_len();
  mem = new Uint8Array(exports.memory.buffer);
  const outBytes = mem.slice(outPtr, outPtr + outLen);
  exports.dealloc(ptr, data.length);
  exports.dealloc(outPtr, outLen);
  const outStr = fromUTF8Bytes(outBytes);
  return JSON.parse(outStr);
}

// 挂载到 window 对象，确保全局可用
window.wasmSignWithPassword = async function(payload) {
  return callJson("sign_with_password", payload);
};

window.wasmSignWithKey = async function(payload) {
  return callJson("sign_with_key", payload);
};
