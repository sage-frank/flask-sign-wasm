import base64
import hashlib
import hmac

def derive_key_b64(password: str, app_salt: str, iterations: int = 100000) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), app_salt.encode("utf-8"), iterations, dklen=32)
    return base64.b64encode(dk).decode("utf-8")

def hmac_hex_with_b64key(key_b64: str, message: str) -> str:
    key = base64.b64decode(key_b64)
    sig = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
    return sig

def hmac_b64_with_b64key(key_b64: str, message: str) -> str:
    key = base64.b64decode(key_b64)
    sig = hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(sig).decode("utf-8")

def sha256_b64(data: str) -> str:
    digest = hashlib.sha256(data.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("utf-8")
