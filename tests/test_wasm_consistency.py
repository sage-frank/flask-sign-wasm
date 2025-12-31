import base64
import time
from backend.services.wasm_verifier import WasmVerifier

def test_sign_consistency():
    wasm = WasmVerifier("backend/wasm/sign_wasm.wasm")
    payload_key = {"password": "password", "app_salt": "app-default-salt"}
    dk = wasm.derive_key(payload_key)
    key_b64 = dk.get("key_base64")
    assert key_b64 and not dk.get("error")
    ts = int(time.time())
    salt_b64 = base64.b64encode(b"unit_salt").decode()
    nonce = "n123"
    body = ""
    p_pwd = {
        "method": "POST",
        "path": "/api/login",
        "salt": salt_b64,
        "timestamp": ts,
        "nonce": nonce,
        "body": body,
        "password": "password",
        "app_salt": "app-default-salt",
    }
    p_key = {
        "method": "POST",
        "path": "/api/login",
        "salt": salt_b64,
        "timestamp": ts,
        "nonce": nonce,
        "body": body,
        "key_base64": key_b64,
    }
    s1 = wasm.sign_with_password(p_pwd)
    s2 = wasm.sign_with_key(p_key)
    assert s1.get("sig") == s2.get("sig")
