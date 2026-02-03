import os, json, time, base64, secrets, wasmtime
from flask import Flask, request, jsonify, g, make_response
from flask_cors import CORS
from functools import wraps
from uuid import uuid4
from services.redis_client import get_redis

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000", "http://localhost:3001", "http://localhost:3002"])

# Ensure we find the WASM file relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WASM_FILE = os.path.join(BASE_DIR, "wasm", "sign_wasm.wasm")
app.config.update({"WASM_PATH": WASM_FILE, "TIME_SKEW": 60})

# --- WASM 运行时驱动 ---
class WasmSigner:
    def __init__(self, path):
        self.path = path
        self._init()

    def _init(self):
        engine = wasmtime.Engine()
        self.store = wasmtime.Store(engine)
        module = wasmtime.Module.from_file(engine, self.path)
        instance = wasmtime.Instance(self.store, module, [])
        self.exports = instance.exports(self.store)

    def call(self, func_name, data):
        if func_name not in self.exports:
            self._init()
        if func_name not in self.exports:
            raise KeyError(func_name)
        bs = json.dumps(data).encode()
        ptr = self.exports["alloc"](self.store, len(bs))
        self.exports["memory"].write(self.store, bs, ptr)
        
        out_ptr = self.exports[func_name](self.store, ptr, len(bs))
        out_len = self.exports["result_len"](self.store)
        out = self.exports["memory"].read(self.store, out_ptr, out_ptr + out_len)
        
        self.exports["dealloc"](self.store, ptr, len(bs))
        self.exports["dealloc"](self.store, out_ptr, out_len)
        return json.loads(out.decode())

signer = WasmSigner(app.config["WASM_PATH"])

# --- 辅助工具 ---
def get_user_key(username):
    # 模拟数据库：生产环境应从 DB 读取用户的 PBKDF2 派生密钥
    return base64.b64encode(b"dummy-key-for-" + username.encode()).decode()

# --- 核心拦截器 ---
def verify_api_sign(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        r, data = get_redis(), request.get_json(force=True)
        print("func verify_api_sign, data:", data, flush=True)
        # 1. 消费 Salt (一次性)
        salt_val = r.get(f"salt:{data.get('salt_id')}")
        if not salt_val: return jsonify({"ok": False, "error": "salt_invalid"}), 400
        r.delete(f"salt:{data.get('salt_id')}")
        print("func verify_api_sign, salt_val:", salt_val.decode(), flush=True)

        
        print("func verify_api_sign, path:", request.path, flush=True)
        print("func verify_api_sign, method:", request.method, flush=True)
        
        # 2. 准备校验负载
        username = getattr(g, 'user', data.get('username'))
        payload = {
            "method": request.method, "path": request.path,
            "params": data.get("params", {}), "nonce": data.get("nonce"),
            "salt": salt_val.decode(), "timestamp": int(data.get("timestamp", 0)),
            "sig": data.get("sig"), "server_ts": int(time.time()),
            "max_skew_seconds": app.config["TIME_SKEW"]
        }
        print("func verify_api_sign, payload:", payload, flush=True)
        
        # 针对登录或常规请求注入密钥
        if request.path == "/api/login" and "password" in data:
            payload.update({"password": data["password"], "app_salt": "static-salt"})
        else:
            payload["key_base64"] = get_user_key(username)
            print("func verify_api_sign, key_base64:", payload["key_base64"], flush=True)

        # 3. 调用 WASM 验证
        try:
            res = signer.call("verify_request", payload)
            print("func verify_api_sign, res:", res, flush=True)
        except KeyError:
            ts = int(time.time())
            diff = abs(ts - int(payload.get("timestamp", 0)))
            if diff > app.config["TIME_SKEW"]:
                return jsonify({"ok": False, "error": "timestamp_expired"}), 401
            sign_payload = dict(payload)
            sign_payload.pop("sig", None)
            try:
                out = signer.call("sign_request", sign_payload)
            except KeyError:
                return jsonify({"ok": False, "error": "wasm_missing_func"}), 500
            exp = out.get("sig")
            if not exp or exp != data.get("sig"):
                return jsonify({"ok": False, "error": "sig_mismatch"}), 401
            res = {"ok": True}
        if not res.get("ok"):
            return jsonify({"ok": False, "error": res.get("error")}), 401
        return f(*args, **kwargs)
    return wrapper

# --- 路由接口 ---
@app.route("/api/salt", methods=["GET"])
def api_salt():
    salt_id, salt_b64 = uuid4().hex, base64.b64encode(secrets.token_bytes(24)).decode()
    get_redis().setex(f"salt:{salt_id}", 60, salt_b64)
    return jsonify({"salt_id": salt_id, "salt": salt_b64})

@app.route("/api/login", methods=["POST"])
@verify_api_sign
def api_login():
    username = request.json.get("username")
    print("func api_login, username:", username, flush=True)
    sid = uuid4().hex
    get_redis().setex(f"sess:{sid}", 3600, json.dumps({"u": username}))
    resp = make_response(jsonify({
        "status": "ok",
        "user": username,
        "key_b64": get_user_key(username)
    }))
    resp.set_cookie("session_id", sid, httponly=True)
    return resp

@app.route("/api/query", methods=["POST"])
@verify_api_sign
def api_query():
    # 此时签名已在装饰器中完成 Wasm 校验
    return jsonify({"ok": True, "data": "Top Secret Content"})

@app.route("/api/session", methods=["GET"])
def api_session():
    sid = request.cookies.get("session_id")
    if not sid:
        return jsonify({"status": "fail", "user": None, "key_b64": None})
    raw = get_redis().get(f"sess:{sid}")
    if not raw:
        return jsonify({"status": "fail", "user": None, "key_b64": None})
    try:
        obj = json.loads(raw)
    except Exception:
        obj = {"u": None}
    username = obj.get("u")
    if not username:
        return jsonify({"status": "fail", "user": None, "key_b64": None})
    return jsonify({
        "status": "ok",
        "user": username,
        "key_b64": get_user_key(username)
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
