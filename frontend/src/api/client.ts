import type { LoginResponse, QueryResponse, SaltResponse, SessionResponse, SignPayload } from '../types';
import { signJson, initWasm } from '../wasm/wasmClient';

let sessionKeyB64: string | null = null;

export const setSessionKey = (key: string | null) => {
  sessionKeyB64 = key;
};

export const getSessionKey = () => sessionKeyB64;

const API_BASE = '/api';

export const checkSession = async (): Promise<SessionResponse> => {
  try {
    const res = await fetch(`${API_BASE}/session`, { credentials: 'include' });
    if (!res.ok) {
       return { status: 'fail', user: null, key_b64: null };
    }
    const data: SessionResponse = await res.json();
    if (data.status === 'ok' && data.key_b64) {
      setSessionKey(data.key_b64);
    }
    return data;
  } catch (e) {
    console.error("Session check failed", e);
    return { status: 'fail', user: null, key_b64: null };
  }
};

export const login = async (username: string, password: string): Promise<LoginResponse> => {
  await initWasm();
  try {
    const { salt, salt_id } = await getSalt();
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = Math.random().toString(36).substring(2, 15);

    const payload: SignPayload = {
      method: 'POST',
      path: '/api/login',
      params: {},
      nonce,
      salt,
      timestamp,
      password,
      app_salt: 'static-salt'
    };
    
    const signRes = signJson(payload);
    if (!signRes.sig) {
        return { status: 'error', user: '', key_b64: '', msg: '签名生成失败: ' + signRes.error };
    }

    const res = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ 
          username, 
          password,
          salt_id,
          nonce,
          timestamp,
          sig: signRes.sig
      }),
    });
    const data: LoginResponse = await res.json();
    if (data.status === 'ok' && data.key_b64) {
      setSessionKey(data.key_b64);
    }
    return data;
  } catch (e: any) {
    return { status: 'error', user: '', key_b64: '', msg: e.message || '登录失败' };
  }
};

export const getSalt = async (): Promise<SaltResponse> => {
  const res = await fetch(`${API_BASE}/salt`, { credentials: 'include' });
  const data: SaltResponse = await res.json();
  return data;
};

export const queryData = async (): Promise<QueryResponse> => {
  await initWasm();
  
  if (!sessionKeyB64) {
    return { status: 'error', msg: '未登录或会话已过期' };
  }

  try {
    const { salt, salt_id } = await getSalt();
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = Math.random().toString(36).substring(2, 15);

    const payload: SignPayload = {
      method: 'POST',
      path: '/api/query',
      params: {},
      salt,
      timestamp,
      nonce,
      key_base64: sessionKeyB64
    };

    const signRes = signJson(payload);
    if (!signRes.sig) {
      return { status: 'error', msg: '签名失败: ' + signRes.error };
    }

    const finalPayload = {
      ...payload,
      salt_id,
      sig: signRes.sig
    };

    const res = await fetch(`${API_BASE}/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(finalPayload),
    });
    
    return await res.json();
  } catch (e: any) {
    return { status: 'error', msg: e.message || '查询出错' };
  }
};
