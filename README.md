# Motoko VetKD Demo

一个基于 ICP 的 VetKD 演示工程：后端使用 Motoko，前端使用 React + Vite。

## 当前功能

当前页面只保留一个核心功能入口（主页点击后全屏打开）：

1. A 发密文给 B（VetKD + IBE）
- A 使用 Internet Identity 登录后，填写 B 的 Principal 和明文。
- 点击加密后生成一段十六进制密文（`hex`），用于复制给 B。
- B 登录后粘贴密文，点击解密。
- 解密成功后，原文会显示在「B 解密密文」按钮下方的只读文本框里。
- 功能页内有实时提示条，显示执行中 / 成功 / 失败原因。

补充说明：
- 前端显示的密文虽然是单段 `hex`，内部已封装接收者 Principal 和派生公钥信息，用于更准确地提示错误原因。
- 如果 B 不是目标接收者、前端显示身份和后端实际 caller 不一致、或本地链环境已重置，页面会给出明确提示。

## 登录规则（Internet Identity）

前端会根据环境自动选择 II provider：

- `DFX_NETWORK=ic`：使用生产 II
  - `https://identity.ic0.app/#authorize`
- 其他网络（如 local）：使用本地 II
  - 优先使用 `http://<CANISTER_ID_INTERNET_IDENTITY>.localhost:4943/#authorize`
  - 并支持 `http://localhost:4943/?canisterId=<CANISTER_ID_INTERNET_IDENTITY>#authorize` 回退（兼容部分浏览器环境）

如果是本地网络但未配置 `CANISTER_ID_INTERNET_IDENTITY`，页面会提示登录配置缺失。

前端提供：
- `Identity 登录`
- `切换账号登录`（会清理 localStorage / sessionStorage / IndexedDB 中的 AuthClient 缓存）
- `退出登录`

## 后端接口（Motoko）

`backend/app.mo` 当前暴露以下接口：

- `vetkdPublicKeyExample(keyName, contextLabel)`
  - 读取 VetKD 派生公钥（hex）
- `vetkdDeriveKeyExample(transportPublicKey, keyName, contextLabel)`
  - 派生加密密钥（hex）
  - 派生输入绑定为 `caller`（`Principal.toBlob(caller)`）
  - 调用管理 canister `vetkd_derive_key` 时会附加所需 cycles（本地报错提示的 required cycles）
- `vetkdCallerInputHex()`
  - 返回当前调用方 principal bytes 的 hex

## 项目结构

- `backend/app.mo`：Motoko 后端（VetKD 逻辑）
- `frontend/src/App.jsx`：前端主页面与交互
- `frontend/src/styles.css`：前端样式
- `frontend/vite.config.js`：Vite 配置
- `dfx.json`：canister 配置

## 本地开发

1. 安装依赖

```bash
npm install
```

2. 构建前端

```bash
npm run build --workspace frontend
```

3. 启动/部署 canister（按你的开发流程执行）

```bash
dfx start --background
dfx deploy
```

如果本地 II 需要重装（例如切换 II wasm flavor 或清理本地身份问题）：

```bash
dfx deploy internet_identity --mode reinstall
dfx deploy
```

## 依赖说明

前端关键依赖：

- `@dfinity/auth-client`
- `@dfinity/agent`
- `@dfinity/vetkeys`

VetKD 与 AuthClient 均采用本地依赖打包，不再依赖 CDN 动态加载。

## 当前本地 II 配置（dfx.json）

- `internet_identity` 作为 custom canister 配置在 `dfx.json`
- 使用固定 release 的 `internet_identity_test.wasm.gz`（避免 `latest` 指针带来的不确定性）
