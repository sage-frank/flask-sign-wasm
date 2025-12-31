// import { wasmSignWithPassword } from "./wasm.js";

function nowTs() { return Math.floor(Date.now() / 1000); }
function randNonce() { return Math.random().toString(36).slice(2); }

const isFile = window.location.protocol === 'file:';
const isDevPort = window.location.protocol === 'http:' && window.location.port === '3000';
const API_BASE = (isFile || isDevPort) ? 'http://127.0.0.1:5000' : '';

async function getSalt() {
  const resp = await fetch(`${API_BASE}/api/salt`);
  return resp.json();
}

function ensureWasm() {
  if (typeof window.wasmSignWithPassword !== "function") {
    throw new Error("WASM not available");
  }
}

async function login() {
  try {
    console.log("Starting login process...");
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    ensureWasm();

    console.log("Fetching salt...");
    const saltResp = await getSalt();
    console.log("Salt received:", saltResp);

    const ts = nowTs();
    const nonce = randNonce();
    const body = "";
    const payload = {
      method: "POST",
      path: "/api/login",
      salt: saltResp.salt,
      timestamp: ts,
      nonce,
      body,
      password,
      app_salt: "app-default-salt"
    };

    const res = await window.wasmSignWithPassword(payload);

    const sig = res.sig;

    console.log("Sending login request...");
    const resp = await fetch(`${API_BASE}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        username,
        sig,
        salt_id: saltResp.salt_id,
        timestamp: ts,
        nonce,
        body
      })
    });

    const j = await resp.json();
    console.log("Login response:", j);
    alert(j.ok ? "登录成功" : `登录失败: ${j.error}`);
  } catch (e) {
    console.error("Login failed:", e);
    alert(`系统错误: ${e.message}`);
  }
}

async function query() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  ensureWasm();
  const saltResp = await getSalt();
  const ts = nowTs();
  const nonce = randNonce();
  const body = "";
  const payload = {
    method: "POST",
    path: "/api/query",
    salt: saltResp.salt,
    timestamp: ts,
    nonce,
    body,
    password,
    app_salt: "app-default-salt"
  };
  const res = await window.wasmSignWithPassword(payload);
  const sig = res.sig;
  const resp = await fetch(`${API_BASE}/api/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({
      username,
      sig,
      salt_id: saltResp.salt_id,
      timestamp: ts,
      nonce,
      body
    })
  });
  const j = await resp.json();
  if (j.ok) {
    const tbody = document.querySelector("#resultTable tbody");
    tbody.innerHTML = "";
    j.rows.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${r.id}</td><td>${r.name}</td><td>${r.status}</td>`;
      tbody.appendChild(tr);
    });
  } else {
    alert(`查询失败: ${j.error}`);
  }
}

document.getElementById("btnLogin").addEventListener("click", login);
document.getElementById("btnQuery").addEventListener("click", query);
