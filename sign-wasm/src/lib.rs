use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

static mut LAST_LEN: u32 = 0;

// --- 内存管理 ---
#[no_mangle]
pub extern "C" fn alloc(len: u32) -> *mut u8 {
    let mut buf = Vec::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: u32) {
    unsafe { let _ = Vec::from_raw_parts(ptr, len as usize, len as usize); }
}

#[no_mangle]
pub extern "C" fn result_len() -> u32 { unsafe { LAST_LEN } }

// --- 数据结构 ---
#[derive(Deserialize)]
struct RequestInput {
    method: String,
    path: String,
    params: BTreeMap<String, String>,
    nonce: String,
    salt: String,
    timestamp: u64,
    // 认证方式二选一
    key_base64: Option<String>,
    password: Option<String>,
    app_salt: Option<String>,
    // 仅验证时需要
    sig: Option<String>,
    server_ts: Option<u64>,
}

#[derive(Serialize)]
struct ResponseOutput {
    sig: Option<String>,
    ok: bool,
    error: Option<String>,
    version: String,
}

// --- 核心逻辑 ---
fn derive_key(password: &str, app_salt: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    // 使用 10 万次迭代的 PBKDF2 增加破解难度
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), app_salt.as_bytes(), 100_000, &mut key).expect("PBKDF2");
    key
}

fn message_v3(method: &str, path: &str, params: &BTreeMap<String, String>, nonce: &str, salt: &str, timestamp: u64) -> String {
    // 1. 参数倒序排序并拼接
    let mut p_list: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
    p_list.sort_by(|a, b| b.cmp(a)); 
    let p_str = p_list.join("&");

    // 2. 这里的逻辑可以稍微“恶心”一点：比如取 salt 的中间段，或者对 timestamp 做位运算
    let salt_part = if salt.len() > 15 { &salt[5..15] } else { salt };
    
    // 3. 最终签名原串（加入私有前缀防止被轻易猜出拼接顺序）
    format!("v3#{method}#{path}#{p_str}#{nonce}#{salt_part}#{timestamp}")
}

fn compute_hmac(key: &[u8], msg: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC");
    mac.update(msg.as_bytes());
    b64.encode(mac.finalize().into_bytes())
}

// --- 通用 JSON 写回 ---
fn write_output(obj: ResponseOutput) -> *mut u8 {
    let json = serde_json::to_string(&obj).unwrap_or_else(|_| r#"{"error":"json_err"}"#.into());
    let len = json.len() as u32;
    let ptr = alloc(len);
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), ptr, len as usize);
        LAST_LEN = len;
    }
    ptr
}

// --- 导出接口 ---

#[no_mangle]
pub extern "C" fn sign_request(ptr: *mut u8, len: u32) -> *mut u8 {
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    let input: RequestInput = match serde_json::from_slice(slice) {
        Ok(v) => v,
        Err(_) => return write_output(ResponseOutput { sig: None, ok: false, error: Some("invalid_json".into()), version: "1.0".into() }),
    };

    let key = if let Some(k_b64) = input.key_base64 {
        b64.decode(k_b64).unwrap_or_default()
    } else if let (Some(p), Some(s)) = (input.password, input.app_salt) {
        derive_key(&p, &s).to_vec()
    } else {
        return write_output(ResponseOutput { sig: None, ok: false, error: Some("no_credentials".into()), version: "1.0".into() });
    };

    let msg = message_v3(&input.method, &input.path, &input.params, &input.nonce, &input.salt, input.timestamp);
    let sig = compute_hmac(&key, &msg);

    write_output(ResponseOutput { sig: Some(sig), ok: true, error: None, version: env!("CARGO_PKG_VERSION").into() })
}

#[no_mangle]
pub extern "C" fn verify_request(ptr: *mut u8, len: u32) -> *mut u8 {
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    let input: RequestInput = match serde_json::from_slice(slice) {
        Ok(v) => v,
        Err(_) => return write_output(ResponseOutput { sig: None, ok: false, error: Some("invalid_json".into()), version: "1.0".into() }),
    };

    let (client_sig, server_ts) = match (input.sig, input.server_ts) {
        (Some(s), Some(t)) => (s, t),
        _ => return write_output(ResponseOutput { sig: None, ok: false, error: Some("missing_verify_fields".into()), version: "1.0".into() }),
    };

    // 1. 校验时间戳防重放 (允许 60 秒误差)
    let diff = if server_ts > input.timestamp { server_ts - input.timestamp } else { input.timestamp - server_ts };
    if diff > 60 {
        return write_output(ResponseOutput { sig: None, ok: false, error: Some("timestamp_expired".into()), version: "1.0".into() });
    }

    // 2. 重新计算签名
    let key = if let Some(k_b64) = input.key_base64 {
        b64.decode(k_b64).unwrap_or_default()
    } else if let (Some(p), Some(s)) = (input.password, input.app_salt) {
        derive_key(&p, &s).to_vec()
    } else {
        return write_output(ResponseOutput { sig: None, ok: false, error: Some("no_key".into()), version: "1.0".into() });
    };

    let msg = message_v3(&input.method, &input.path, &input.params, &input.nonce, &input.salt, input.timestamp);
    let expected_sig = compute_hmac(&key, &msg);

    if expected_sig == client_sig {
        write_output(ResponseOutput { sig: None, ok: true, error: None, version: "1.0".into() })
    } else {
        write_output(ResponseOutput { sig: None, ok: false, error: Some("sig_mismatch".into()), version: "1.0".into() })
    }
}