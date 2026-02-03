import { useEffect, useState } from 'react';
import './App.css';
import { checkSession, login, queryData } from './api/client';
import { initWasm } from './wasm/wasmClient';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [user, setUser] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [queryResult, setQueryResult] = useState<any[] | null>(null);
  const [msg, setMsg] = useState<string>('');

  useEffect(() => {
    // Initialize Wasm and check session
    initWasm().catch(err => console.error("Wasm init failed", err));
    checkSession().then(res => {
      if (res.status === 'ok' && res.user) {
        setUser(res.user);
      }
    });
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMsg('');
    try {
      const res = await login(username, password);
      if (res.status === 'ok') {
        setUser(res.user);
        setMsg('登录成功');
      } else {
        setMsg(res.msg || '登录失败');
      }
    } catch (e) {
      setMsg('登录出错');
    } finally {
      setLoading(false);
    }
  };

  const handleQuery = async () => {
    setLoading(true);
    setMsg('');
    setQueryResult(null);
    try {
      const res = await queryData();
      if (res.status === 'ok' && res.data) {
        setQueryResult(res.data);
        setMsg('查询成功');
      } else {
        setMsg(res.msg || '查询失败');
      }
    } catch (e) {
      setMsg('查询出错');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>Flask + Rust Wasm Signature Demo</h1>
      
      {user ? (
        <div className="dashboard">
          <div className="user-info">
            <p>当前登录: <strong>{user}</strong></p>
            {/* Logout button could be added here, but not requested */}
          </div>
          
          <div className="actions">
            <button onClick={handleQuery} disabled={loading}>
              {loading ? '查询中...' : '查询数据 (带 Wasm 签名)'}
            </button>
          </div>

          {msg && <p className="message">{msg}</p>}

          {queryResult && (
            <div className="result-table">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {queryResult.map((item, idx) => (
                    <tr key={idx}>
                      <td>{item.id}</td>
                      <td>{item.name}</td>
                      <td>{item.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ) : (
        <div className="login-form">
          <h2>请登录</h2>
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label>用户名:</label>
              <input 
                type="text" 
                value={username} 
                onChange={e => setUsername(e.target.value)} 
                disabled={loading}
              />
            </div>
            <div className="form-group">
              <label>密码:</label>
              <input 
                type="password" 
                value={password} 
                onChange={e => setPassword(e.target.value)}
                disabled={loading}
              />
            </div>
            <button type="submit" disabled={loading}>
              {loading ? '登录中...' : '登录'}
            </button>
          </form>
          {msg && <p className="message error">{msg}</p>}
        </div>
      )}
    </div>
  );
}

export default App;
