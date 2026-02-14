# Motoko Show

一个用于展示 Motoko 能力的 ICP 示例工程。  
后端使用 Motoko canister，前端使用 React + Vite。

## 功能说明

当前前端主界面已实现以下能力：

1. 科技感视觉风格：动态背景、发光边框、HUD 风格卡片与按钮动效。
2. 横向滑动能力列表：通过滑动或左右按钮浏览 Motoko 能力卡片。
3. 中英文切换：右上角 `中 / EN` 一键切换页面文案。
4. 右上角登录按钮：支持演示态登录（访客登录/退出），后续可接 Internet Identity。

## 技术栈

- Backend: [Motoko](https://internetcomputer.org/docs/motoko/main/getting-started/motoko-introduction)
- Frontend: React 18 + Vite 5
- Canister orchestration: dfx

## 项目结构

- `backend/app.mo`: Motoko canister 逻辑
- `frontend/src/App.jsx`: React 主界面与交互
- `frontend/src/styles.css`: 前端样式（科技感主题）
- `frontend/vite.config.js`: 前端构建配置
- `dfx.json`: canister 配置

## 本地开发

1. 安装依赖：

```bash
npm install
```

2. 启动本地 replica：

```bash
dfx start --background
```

3. 本地部署 canister：

```bash
dfx deploy
```

4. 启动前端开发服务：

```bash
npm run dev --workspace frontend
```

## 生产构建与部署

```bash
npm run build
dfx deploy --network ic
```

更多环境准备步骤可参考 `BUILD.md`。
