# Flask + React + Rust Wasm 安全签名系统

这是一个全栈安全演示项目，展示了如何使用 **Rust** 编写核心签名算法并编译为 **WebAssembly (Wasm)**，在 **React 前端** 和 **Flask 后端** 之间复用同一套逻辑，实现防篡改和防重放的安全通信。

## 🚀 项目特性

1.  **统一核心逻辑 (Write Once, Run Everywhere)**
    *   核心签名算法由 Rust 实现，编译为 `.wasm`。
    *   前端 (Browser) 和后端 (Python/Wasmtime) 加载同一个 `.wasm` 文件，确保逻辑严格一致。

2.  **企业级安全机制**
    *   **Wasm 混淆**: 签名逻辑隐藏在 Wasm 二进制中，增加了逆向工程的难度。
    *   **防重放 (Anti-Replay)**: 采用后端动态分发的一次性 **Salt (盐值)**。Salt 使用后立即销毁 (Redis TTL)。
    *   **强加密标准**: 使用 **PBKDF2** 派生密钥，**HMAC-SHA256** 进行消息认证。
    *   **无状态/有状态混合**: 登录态使用 Cookie/Session 管理，但签名验证依赖无状态的算法逻辑。

3.  **现代技术栈**
    *   **Frontend**: React 19, TypeScript, Vite, WebAssembly.
    *   **Backend**: Python Flask, Redis, Wasmtime.
    *   **Core**: Rust (no_std 兼容).

## 📂 目录结构

```text
flask-sign-wasm/
├── backend/                # Python Flask 后端
│   ├── app.py              # API 入口 (Login, Query, Session)
│   ├── services/           # 业务逻辑 (Redis, Wasm Wrapper)
│   └── wasm/               # 后端加载的 .wasm 文件
├── frontend/               # React + TypeScript 前端
│   ├── public/wasm/        # 前端加载的 .wasm 文件
│   ├── src/
│   │   ├── api/            # API 请求封装
│   │   ├── wasm/           # Wasm 加载与调用 (WebAssembly.Instance)
│   │   └── App.tsx         # 主页面逻辑
│   └── vite.config.ts      # Vite 配置
├── sign-wasm/              # Rust 签名算法源码
│   ├── src/lib.rs          # 核心算法 (PBKDF2 + HMAC)
│   └── Cargo.toml          # Rust 配置
└── README.md
```

## 🛠️ 环境要求

*   **Rust**: `stable` (需要 `wasm32-unknown-unknown` target)
*   **Node.js**: v18+ (推荐 v20)
*   **Python**: 3.8+
*   **Redis**: 运行中的 Redis 服务 (默认端口 6379)

## ⚡ 快速开始

### 1. 编译核心签名算法 (Rust)

首先编译 Rust 代码为 Wasm，并分发到前后端目录。

```bash
cd sign-wasm

# 添加 wasm 构建目标
rustup target add wasm32-unknown-unknown

# 编译 Release 版本
cargo build --target wasm32-unknown-unknown --release

# 分发 .wasm 文件 (Windows PowerShell)
copy target\wasm32-unknown-unknown\release\sign_wasm.wasm ..\frontend\public\wasm\sign_wasm.wasm
copy target\wasm32-unknown-unknown\release\sign_wasm.wasm ..\backend\wasm\sign_wasm.wasm
```

### 2. 启动后端 (Flask)

确保 Redis 正在运行。

```bash
cd backend

# 安装依赖
pip install -r requirements.txt

# 启动服务 (默认运行在 http://127.0.0.1:5000)
python -m app
```

### 3. 启动前端 (React)

```bash
cd frontend

# 安装依赖
npm install

# 启动开发服务器
npm run dev
```

访问终端输出的地址 (通常是 `http://localhost:5173` 或 `http://localhost:3000`)。

## 🔐 交互流程详解

### 登录流程 (Login)
1.  **Get Salt**: 用户输入密码后，前端请求 `/api/salt` 获取一次性随机盐值。
2.  **Sign (Wasm)**: 
    *   前端加载 `sign_wasm.wasm`。
    *   输入: `password`, `salt`, `timestamp`, `nonce` 等。
    *   计算: `DerivedKey = PBKDF2(password, salt)` -> `Sig = HMAC(DerivedKey, Payload)`。
3.  **Verify (Backend)**:
    *   后端接收请求，提取 Salt ID 校验 Redis 中是否存在。
    *   后端加载相同的 Wasm，使用数据库中的用户密码 Hash (模拟) 进行同样的计算。
    *   比对签名，一致则签发 Session Cookie。

### 查询流程 (Query - Protected)
1.  **Get Session Key**: 登录成功后，后端会在内存/Session中维护一个会话密钥。
2.  **Sign (Wasm)**: 
    *   前端再次请求 `/api/salt`。
    *   前端使用 **Session Key** (而非密码) 对查询参数进行签名。
3.  **Verify**: 后端验证签名，通过则返回敏感数据。

## ⚠️ 注意事项

*   **Wasm 路径**: 前端默认从 `/wasm/sign_wasm.wasm` 加载，请确保 `public` 目录结构正确。
*   **CORS**: 后端已配置 `flask-cors` 允许前端跨域携带凭证 (`Access-Control-Allow-Credentials: true`)。
*   **Redis**: 如果 Redis 设置了密码，请修改 `backend/services/redis_client.py` 或通过环境变量配置。
