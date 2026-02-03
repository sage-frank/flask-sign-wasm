export interface LoginResponse {
  status: string;
  user: string;
  key_b64: string;
  msg?: string;
}

export interface SaltResponse {
  salt: string;
  salt_id: string;
}

export interface QueryResponse {
  status: string;
  data?: any[];
  msg?: string;
}

export interface SessionResponse {
  status: string;
  user: string | null;
  key_b64: string | null;
}

export interface SignPayload {
  method: string;
  path: string;
  params: Record<string, string>;
  nonce: string;
  salt: string;
  timestamp: number;
  key_base64?: string;
  password?: string;
  app_salt?: string;
  sig?: string;
  server_ts?: number;
}
