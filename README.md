# Motoko ICP Showcase

一个基于 ICP 的能力演示工程：后端使用 Motoko，前端使用 React + Vite，重点展示 `VetKD`、`Threshold ECDSA`、`Internet Identity` 和 `II 控制的多链钱包`。

## 当前功能（主页 3 个入口）

1. `A 发密文给 B（VetKD + IBE）`
- A 使用 `Internet Identity` 登录后，填写 B 的 `Principal` 和明文。
- 点击加密后生成一段十六进制密文（`hex`）。
- B 登录后粘贴密文，点击解密。
- 解密成功后，原文显示在「B 解密密文」按钮下方的只读文本框中。
- 功能页内有提示条显示执行中 / 成功 / 失败原因。

2. `A 生成 ETH 签名，B 用 ETH 地址验证（Threshold ECDSA）`
- A 使用当前登录身份对应的链钥（Threshold ECDSA, `secp256k1`）对消息哈希签名。
- 前端按 ETH 风格消息规则计算哈希并生成可恢复签名（`65 bytes`, 含 `v`）。
- B 手动输入原文、签名和 A 的 ETH 地址后点击验证。
- 验证方式为：恢复公钥 -> 推导 ETH 地址 -> 比对输入地址。

3. `II 控制的多链钱包（主页演示）`
- 钱包页内支持 `II 登录 / 切换账号 / 退出登录`。
- 链切换使用右上角下拉框。
- 当前链列表：
  - `ETH`
  - `Sepolia`
  - `Base`
  - `SOL (Solana Mainnet)`
  - `SOL (Solana Testnet)`
  - `APT`
  - `SUI`
  - `BTC`
  - `CKB`
  - `ICP`
- 不使用模拟数据（已移除假地址/假余额）。
- `ETH / Sepolia / Base`：后端读取链钥公钥（Threshold ECDSA），前端推导 EVM 地址。
- `SOL / Solana Testnet`：后端读取 `ed25519` 公钥并在后端生成 Solana 地址（Base58）。
- `SOL / Solana Testnet`：后端通过 HTTPS outcall 调 Solana JSON-RPC `getBalance` 返回 `lamports`，前端显示 `SOL` 余额（若环境支持 outcall）。
- 其它链当前保留页面结构与链切换入口，地址/余额查询尚未接入。

## 登录（Internet Identity）

前端会根据环境自动选择 II provider：

- `DFX_NETWORK=ic`：生产 II（`https://identity.ic0.app/#authorize`）
- 本地网络：本地 II（会尝试 `<canister>.localhost` 和 `localhost?canisterId=...` 两种 URL）

前端已支持：
- `Identity 登录`
- `切换账号登录`（会清理 AuthClient 缓存，避免 delegation 复用导致 PID 不切换）
- `退出登录`（会同步清理缓存）

## 后端接口（当前对外）

`/Users/wangbinmac/gith/motokoshow/backend/app.mo` 当前暴露：

- `vetkdPublicKeyExample(keyName, contextLabel)`
- `vetkdDeriveKeyExample(transportPublicKey, keyName, contextLabel)`
- `vetkdCallerInputHex()`
- `ecdsaPublicKeyExample(keyName)`
- `ecdsaSignMessageHashExample(messageHash, keyName)`
- `wallet_networks()`
- `wallet_overview(network, rpcUrl, erc20TokenAddress)`

## 后端目录结构（按功能拆分）

- `/Users/wangbinmac/gith/motokoshow/backend/vetkd`
  - VetKD A->B（加密/解密配套后端接口）
- `/Users/wangbinmac/gith/motokoshow/backend/eth`
  - Threshold ECDSA（ETH 地址验签相关）
- `/Users/wangbinmac/gith/motokoshow/backend/iiwallet`
  - 多链钱包后端能力与配置
  - 已按链拆子目录：
    - `/Users/wangbinmac/gith/motokoshow/backend/iiwallet/evm`
    - `/Users/wangbinmac/gith/motokoshow/backend/iiwallet/sol`
    - `/Users/wangbinmac/gith/motokoshow/backend/iiwallet/btc`
    - `/Users/wangbinmac/gith/motokoshow/backend/iiwallet/icp`

## 多链钱包（当前实现说明）

- `wallet_overview` 采用前后端一致的网络枚举（短 id）：
  - `eth`, `sepolia`, `base`, `sol`, `sol_testnet`, `apt`, `sui`, `btc`, `ckb`, `icp`
- Solana Testnet 默认 RPC：
  - `https://solana-testnet-rpc.publicnode.com`
- Solana 余额解析已使用 JSON 库（`serde`），不再使用字符串扫描提取 `value`。

## 依赖说明

Motoko（`mops`）依赖：

- `base`
- `core`
- `serde`（用于 Solana JSON-RPC 响应解析）

前端关键依赖：

- `@dfinity/agent`
- `@dfinity/auth-client`
- `@dfinity/identity`
- `@dfinity/vetkeys`
- `@noble/curves`

## 本地开发（常用）

1. 安装前端依赖

```bash
npm install
```

2. 安装 Motoko 依赖（首次或 `mops.toml` 更新后）

```bash
mops install
```

3. 生成前端声明（后端接口变更后）

```bash
dfx generate backend
```

4. 构建前端

```bash
npm --workspace frontend run build
```

5. 本地部署（按你的流程执行）

```bash
dfx start --background
dfx deploy
```

## 说明

- 钱包页 `SOL` 余额依赖 `HTTPS outcall` 能力；本地环境如果未正确支持 outcall，页面会显示未接入/不可用状态。
- 本仓库近期做过后端结构重构与稳定变量兼容清理，如从旧版本升级部署失败，可能需要 `reinstall`。请按你的环境策略执行。 
