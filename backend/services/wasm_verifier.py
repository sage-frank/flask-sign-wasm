import json
import os
from wasmtime import Engine, Store, Module, Instance


class WasmVerifier:
    def __init__(self, wasm_path: str):
        self.wasm_path = wasm_path
        self.engine = Engine()
        self.store = Store(self.engine)
        self.instance = None
        self._load()

    def _load(self):
        if not os.path.exists(self.wasm_path):
            self.instance = None
            return
        module = Module.from_file(self.engine, self.wasm_path)
        self.instance = Instance(self.store, module, [])

    def _memory(self):
        return self.instance.exports(self.store)["memory"] if self.instance else None

    def _func(self, name: str):
        return self.instance.exports(self.store)[name] if self.instance else None

    def _call_json(self, func_name: str, payload: dict) -> dict:
        if not self.instance:
            return {"error": "wasm_missing"}
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        alloc = self._func("alloc")
        dealloc = self._func("dealloc")
        result_len = self._func("result_len")
        func = self._func(func_name)
        mem = self._memory()
        in_ptr = int(alloc(self.store, len(data)))
        try:
            mem.write(self.store, slice(in_ptr, in_ptr + len(data)), data)
        except Exception:
            try:
                mem.write(self.store, in_ptr, data)
            except Exception:
                buf = mem.uint8_view(self.store)
                buf[in_ptr : in_ptr + len(data)] = data
        out_ptr = int(func(self.store, in_ptr, len(data)))
        out_len = int(result_len(self.store))
        try:
            out_bytes = mem.read(self.store, slice(out_ptr, out_ptr + out_len))
        except Exception:
            try:
                out_bytes = mem.read(self.store, out_ptr, out_len)
            except Exception:
                buf = mem.uint8_view(self.store)
                out_bytes = bytes(buf[out_ptr : out_ptr + out_len])
        dealloc(self.store, in_ptr, len(data))
        dealloc(self.store, out_ptr, out_len)
        try:
            return json.loads(out_bytes.decode("utf-8"))
        except Exception:
            return {"error": "json_decode"}

    def sign_with_password(self, payload: dict) -> dict:
        return self._call_json("sign_with_password", payload)

    def sign_with_key(self, payload: dict) -> dict:
        return self._call_json("sign_with_key", payload)

    def version(self) -> dict:
        return self._call_json("wasm_version", {})

    def derive_key(self, payload: dict) -> dict:
        return self._call_json("derive_key_json", payload)
