from flask import Flask, request, jsonify, make_response, send_from_directory
from flask_cors import CORS
import os
import json
import secrets
import base64
import time
from uuid import uuid4

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

try:
    from services.redis_client import get_redis
    from services.py_crypto import derive_key_b64, hmac_b64_with_b64key, sha256_b64
except ImportError:
    from .services.redis_client import get_redis
    from .services.py_crypto import derive_key_b64, hmac_b64_with_b64key, sha256_b64

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="/static")
# 允许前端 3000 端口与 file://（Origin 为 null）跨域，支持凭证（Cookie）
CORS(
    app,
    supports_credentials=True,
    origins=["http://127.0.0.1:5000", "http://localhost:5000", "null"],
)

app.config["APP_SALT"] = os.getenv("APP_SALT", "app-default-salt")
def _resolve_wasm_path():
    env_path = os.getenv("WASM_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    candidates = [
        os.path.join(base, "wasm", "sign_wasm.wasm"),
        os.path.join(os.path.dirname(__file__), "wasm", "sign_wasm.wasm"),
        os.path.join(base, "frontend", "wasm", "sign_wasm.wasm"),
        os.path.join(base, "sign-wasm", "target", "wasm32-unknown-unknown", "release", "sign_wasm.wasm"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return candidates[0]
app.config["WASM_PATH"] = _resolve_wasm_path()
print("WASM_PATH", app.config["WASM_PATH"], flush=True)
app.config["SESSION_TTL_SECONDS"] = int(os.getenv("SESSION_TTL", "3600"))
app.config["SALT_TTL_SECONDS"] = int(os.getenv("SALT_TTL", "60"))

USERS = {}
DEFAULT_USER = os.getenv("DEMO_USER", "admin")
DEFAULT_PASS = os.getenv("DEMO_PASS", "password")


def _ensure_demo_user():
    if DEFAULT_USER not in USERS:
        app_salt = app.config["APP_SALT"]
        key_b64 = derive_key_b64(DEFAULT_PASS, app_salt, 100000)
        USERS[DEFAULT_USER] = key_b64


_ensure_demo_user()


def _make_salt():
    salt_bytes = secrets.token_bytes(24)
    return base64.b64encode(salt_bytes).decode()


def _store_salt(r, salt_id, salt_b64, ttl):
    r.setex(f"salt:{salt_id}", ttl, salt_b64)


def _consume_salt(r, salt_id):
    key = f"salt:{salt_id}"
    val = r.get(key)
    if val is not None:
        r.delete(key)
    return val.decode() if val else None


def _set_session(r, username):
    sid = uuid4().hex
    r.setex(
        f"sess:{sid}", app.config["SESSION_TTL_SECONDS"], json.dumps({"u": username})
    )
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(
        "session_id",
        sid,
        max_age=app.config["SESSION_TTL_SECONDS"],
        httponly=True,
        secure=False,
        samesite="Lax",
    )
    return resp


def _require_session(r):
    sid = request.cookies.get("session_id")
    if not sid:
        return None
    data = r.get(f"sess:{sid}")
    return (sid, json.loads(data.decode())) if data else (None, None)


@app.route("/api/salt", methods=["GET"])
def api_salt():
    r = get_redis()
    salt_id = uuid4().hex
    salt_b64 = _make_salt()
    _store_salt(r, salt_id, salt_b64, app.config["SALT_TTL_SECONDS"])
    return jsonify(
        {
            "salt_id": salt_id,
            "salt": salt_b64,
            "expires_in": app.config["SALT_TTL_SECONDS"],
        }
    )


@app.route("/api/login", methods=["POST"])
def api_login():
    r = get_redis()
    data = request.get_json(force=True)
    username = data.get("username", "")
    sig = data.get("sig", "")
    salt_id = data.get("salt_id", "")
    ts = int(data.get("timestamp", 0))
    nonce = data.get("nonce", "")
    body = data.get("body", "")
    salt_b64 = _consume_salt(r, salt_id)
    if not salt_b64:
        return jsonify({"ok": False, "error": "salt_invalid"}), 400
    key_b64 = USERS.get(username)
    if not key_b64:
        return jsonify({"ok": False, "error": "user_not_found"}), 404
    body_hash = sha256_b64(body)
    message = f"POST|/api/login|{salt_b64}|{ts}|{nonce}|{body_hash}"
    expect_sig = hmac_b64_with_b64key(key_b64, message)
    if expect_sig != sig:
        return jsonify({"ok": False, "error": "sig_mismatch"}), 401
    return _set_session(r, username)


@app.route("/api/query", methods=["POST"])
def api_query():
    r = get_redis()
    sid, sess = _require_session(r)
    if not sid:
        return jsonify({"ok": False, "error": "not_logged_in"}), 401
    data = request.get_json(force=True)
    username = data.get("username", "")
    sig = data.get("sig", "")
    salt_id = data.get("salt_id", "")
    ts = int(data.get("timestamp", 0))
    nonce = data.get("nonce", "")
    body = data.get("body", "")
    salt_b64 = _consume_salt(r, salt_id)
    
    
    if not salt_b64:
        return jsonify({"ok": False, "error": "salt_invalid"}), 400
    key_b64 = USERS.get(username)
    if not key_b64:
        return jsonify({"ok": False, "error": "user_not_found"}), 404
    body_hash = sha256_b64(body)
    message = f"POST|/api/query|{salt_b64}|{ts}|{nonce}|{body_hash}"
    expect_sig = hmac_b64_with_b64key(key_b64, message)
    if expect_sig != sig:
        return jsonify({"ok": False, "error": "sig_mismatch"}), 401
    rows = [
        {"id": 1, "name": "Alice", "status": "active"},
        {"id": 2, "name": "Bob", "status": "inactive"},
        {"id": 3, "name": "Carol", "status": "active"},
    ]
    return jsonify({"ok": True, "rows": rows})


@app.route("/api/wasm-version", methods=["GET"])
def api_wasm_version():
    return jsonify({"version": "py"})


@app.route("/wasm/sign_wasm.wasm", methods=["GET"])
def wasm_file():
    path = app.config["WASM_PATH"]
    if not os.path.exists(path):
        return jsonify({"error": "wasm_missing"}), 404
    with open(path, "rb") as f:
        data = f.read()
    resp = make_response(data)
    resp.headers["Content-Type"] = "application/wasm"
    return resp



print("FRONTEND_DIR", FRONTEND_DIR, flush=True)
@app.route("/", methods=["GET"])
def index_html():
    return app.send_static_file("index.html")


@app.route("/static/<path:fname>", methods=["GET"])
def static_files(fname):
    return send_from_directory(FRONTEND_DIR, fname)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
