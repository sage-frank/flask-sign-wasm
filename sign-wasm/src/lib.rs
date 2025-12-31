use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use serde::Deserialize;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

static mut LAST_LEN: u32 = 0;

#[no_mangle]
pub extern "C" fn alloc(len: u32) -> *mut u8 {
    let mut buf = Vec::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, len: u32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len as usize, len as usize);
    }
}

#[no_mangle]
pub extern "C" fn result_len() -> u32 {
    unsafe { LAST_LEN }
}

#[derive(Deserialize)]
struct SignInputPwd {
    method: String,
    path: String,
    salt: String,
    timestamp: u64,
    nonce: String,
    body: String,
    password: String,
    app_salt: String,
}

#[derive(Deserialize)]
struct SignInputKey {
    method: String,
    path: String,
    salt: String,
    timestamp: u64,
    nonce: String,
    body: String,
    key_base64: String,
}

#[inline]
fn derive_key(password: &str, app_salt: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), app_salt.as_bytes(), 100_000, &mut key);
    key
}

#[inline]
fn compute_hmac(key: &[u8], message: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(message.as_bytes());
    let out = mac.finalize().into_bytes();
    b64.encode(out)
}

#[inline]
fn body_hash(body: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let out = hasher.finalize();
    b64.encode(out)
}

#[inline]
fn message(method: &str, path: &str, salt_b64: &str, timestamp: u64, nonce: &str, body: &str) -> String {
    let bh = body_hash(body);
    format!("{method}|{path}|{salt_b64}|{timestamp}|{nonce}|{bh}")
}

fn write_json(json: String) -> *mut u8 {
    let len = json.len() as u32;
    let ptr = alloc(len);
    unsafe {
        std::ptr::copy_nonoverlapping(json.as_ptr(), ptr, len as usize);
        LAST_LEN = len;
    }
    ptr
}

#[derive(Deserialize)]
struct DeriveInput {
    password: String,
    app_salt: String,
}

#[no_mangle]
pub extern "C" fn derive_key_json(ptr: *mut u8, len: u32) -> *mut u8 {
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    let input_str = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return write_json(r#"{"key_base64":null,"error":"utf8"}"#.to_string()),
    };
    let parsed: DeriveInput = match serde_json::from_str(input_str) {
        Ok(v) => v,
        Err(_) => return write_json(r#"{"key_base64":null,"error":"json"}"#.to_string()),
    };
    let key = derive_key(&parsed.password, &parsed.app_salt);
    let key_b64 = b64.encode(key);
    write_json(format!(r#"{{"key_base64":"{key_b64}","error":null}}"#))
}

#[no_mangle]
pub extern "C" fn sign_with_password(ptr: *mut u8, len: u32) -> *mut u8 {
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    let input_str = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return write_json(r#"{"sig":null,"error":"utf8"}"#.to_string()),
    };
    let parsed: SignInputPwd = match serde_json::from_str(input_str) {
        Ok(v) => v,
        Err(_) => return write_json(r#"{"sig":null,"error":"json"}"#.to_string()),
    };
    let key = derive_key(&parsed.password, &parsed.app_salt);
    let msg = message(&parsed.method, &parsed.path, &parsed.salt, parsed.timestamp, &parsed.nonce, &parsed.body);
    let sig = compute_hmac(&key, &msg);
    write_json(format!(r#"{{"sig":"{sig}","error":null}}"#))
}
pub extern "C" fn sign_with_key(ptr: *mut u8, len: u32) -> *mut u8 {
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    let input_str = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return write_json(r#"{"sig":null,"error":"utf8"}"#.to_string()),
    };
    let parsed: SignInputKey = match serde_json::from_str(input_str) {
        Ok(v) => v,
        Err(_) => return write_json(r#"{"sig":null,"error":"json"}"#.to_string()),
    };
    let key = match b64.decode(parsed.key_base64.as_bytes()) {
        Ok(k) => k,
        Err(_) => return write_json(r#"{"sig":null,"error":"bad_key"}"#.to_string()),
    };
    let msg = message(&parsed.method, &parsed.path, &parsed.salt, parsed.timestamp, &parsed.nonce, &parsed.body);
    let sig = compute_hmac(&key, &msg);
    write_json(format!(r#"{{"sig":"{sig}","error":null}}"#))
}

#[no_mangle]
pub extern "C" fn wasm_version() -> *mut u8 {
    write_json(format!(r#"{{"version":"{}"}}"#, env!("CARGO_PKG_VERSION")))
}
