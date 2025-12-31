# Flask + Rust Wasm 签名验证系统

这是一个演示如何使用 Rust 编写签名算法并编译为 WebAssembly (Wasm)，在前端 (Browser) 和后端 (Python/Flask) 复用同一套签名逻辑的项目。

## 项目特性

1.  **统一签名逻辑**: 核心签名算法由 Rust 实现，编译为 `.wasm` 文件，确保前后端逻辑完全一致。
2.  **安全性**:
    *   **Wasm 签名**: 前端使用 Wasm 进行签名，避免 JS 源码直接暴露核心逻辑（虽然前端代码对客户端总是可见的，但 Wasm 增加了逆向难度）。
    *   **防重放 (Anti-Replay)**: 使用一次性 Salt (盐值)，由后端动态分发并存储在 Redis 中，验证通过后立即删除。
    *   **PBKDF2 + HMAC**: 使用 PBKDF2 进行密钥派生，HMAC-SHA256 进行消息认证。
3.  **技术栈**:
    *   **Frontend**: HTML5, Vanilla JS, WebAssembly (Rust)
    *   **Backend**: Python Flask, Redis, Wasmtime (运行 Wasm)
    *   **Build**: Rust (Cargo)

## 目录结构

```
flask-sign-wasm/
├── backend/                # Python Flask 后端
│   ├── app.py              # 主应用入口
│   ├── services/           # 服务层 (Redis, Crypto, Wasm)
│   └── requirements.txt    # Python 依赖
├── frontend/               # 前端静态资源
│   ├── index.html          # 登录与查询页面
│   ├── main.js             # 业务逻辑
│   ├── wasm.js             # Wasm 加载与调用封装
│   └── wasm/               # 存放编译好的 .wasm 文件
└── sign-wasm/              # Rust 签名库源码
    ├── src/lib.rs          # 签名逻辑实现
    └── Cargo.toml          # Rust 项目配置
```

## 环境要求

*   **Rust**: 需要安装 Rust 工具链及 `wasm32-unknown-unknown` 目标。
*   **Python**: 3.8+
*   **Redis**: 需要运行中的 Redis 服务（默认 localhost:6379）。

## 构建与运行步骤

### 1. 编译 Rust Wasm

进入 `sign-wasm` 目录并构建 Release 版本：

```bash
cd sign-wasm
# 添加 wasm 目标 (如果未安装)
rustup target add wasm32-unknown-unknown
# 编译
cargo build --target wasm32-unknown-unknown --release
```

编译完成后，将生成的 `.wasm` 文件复制到前端目录：

```bash
# Windows PowerShell 示例
copy target\wasm32-unknown-unknown\release\sign_wasm.wasm ..\frontend\wasm\sign_wasm.wasm
```

### 2. 后端设置 (Backend)

进入项目根目录，安装依赖并启动 Flask：

```bash
# 安装依赖
pip install -r backend/requirements.txt

# 启动 Redis (如果尚未启动)
# redis-server

# 启动 Flask 应用
python -m backend.app
```
后端默认运行在 `http://127.0.0.1:5000`。

### 3. 前端运行 (Frontend)

你可以使用任何静态文件服务器运行前端，例如 Python 自带的 `http.server`，或者直接在 VS Code 中使用 "Live Server"。

为了模拟跨域环境 (User 提到的 3000 端口)，建议在根目录下运行：

```bash
python -m http.server 3000
```

然后访问: `http://localhost:3000/frontend/index.html`

*注意: 后端已配置 CORS 允许 `http://localhost:3000` 访问。*

## 签名验证流程

1.  **获取 Salt**: 用户点击登录前，前端调用 `/api/salt` 获取一次性 Salt。
2.  **计算签名 (Wasm)**:
    *   前端 JS 调用 Wasm 函数 `sign_with_password`。
    *   输入: `method`, `path`, `salt`, `timestamp`, `nonce`, `body`, `password`。
    *   Wasm 内部:
        *   `Key = PBKDF2(password, salt)`
        *   `Message = method|path|salt|timestamp|nonce|Hash(body)`
        *   `Signature = HMAC-SHA256(Key, Message)`
3.  **发送请求**: 前端将 `Signature`, `Timestamp`, `Nonce`, `Salt` 通过 Request Header 发送给后端。
4.  **后端验证**:
    *   后端检查 Redis 中 Salt 是否存在且有效。
    *   后端使用相同的算法（或加载同样的 Wasm）计算签名并比对。
    *   验证通过后，从 Redis 删除该 Salt，完成登录/查询。

## 常见问题

*   **Detached ArrayBuffer**: 前端 `wasm.js` 已处理内存视图重建，防止在 Wasm 内存扩容后 JS 侧持有失效的 Buffer 引用。
*   **CORS**: 后端 `app.py` 配置了 `Access-Control-Allow-Origin` 和 `Access-Control-Allow-Credentials` 以支持跨域携带 Cookie。
