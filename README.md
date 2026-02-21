# Motoko VetKD Demo

一个基于 ICP 的 VetKD 演示工程：后端使用 Motoko，前端使用 React + Vite。

## 当前功能

当前页面只保留两个核心功能入口（主页点击后全屏打开）：

1. A 发密文给 B（VetKD + IBE）
- A 登录后填写 B 的 Principal 和明文，点击加密生成 JSON 密文。
- B 登录后粘贴密文，点击解密查看原文。
- 解密时会校验当前登录身份必须等于密文目标 `recipientPrincipal`。

2. A 发文字，B 按 A Principal 验签（WebCrypto Ed25519）
- A 侧生成 Ed25519 签名。
- B 侧根据公钥验签，并校验公钥推导的 Principal 与 A 的 Principal 一致。

## 登录规则（Internet Identity）

前端会根据环境自动选择 II provider：

- `DFX_NETWORK=ic`：使用生产 II
  - `https://identity.ic0.app/#authorize`
- 其他网络（如 local）：使用本地 II
  - `http://<CANISTER_ID_INTERNET_IDENTITY>.localhost:4943/#authorize`

如果是本地网络但未配置 `CANISTER_ID_INTERNET_IDENTITY`，页面会提示登录配置缺失。

## 后端接口（Motoko）

`backend/app.mo` 当前暴露以下接口：

- `vetkdPublicKeyExample(keyName, contextLabel)`
  - 读取 VetKD 派生公钥（hex）
- `vetkdDeriveKeyExample(transportPublicKey, keyName, contextLabel)`
  - 派生加密密钥（hex）
  - 派生输入绑定为 `caller`（`Principal.toBlob(caller)`）
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

## 依赖说明

前端关键依赖：

- `@dfinity/auth-client`
- `@dfinity/agent`
- `@dfinity/vetkeys`

VetKD 与 AuthClient 均采用本地依赖打包，不再依赖 CDN 动态加载。
