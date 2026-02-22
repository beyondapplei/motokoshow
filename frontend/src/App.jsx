import { useEffect, useMemo, useState } from 'react';
import { backend as defaultBackend, canisterId, createActor } from 'declarations/backend';
import { Principal } from '@dfinity/principal';
import { AuthClient, IdbStorage, KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY, LocalStorage } from '@dfinity/auth-client';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import * as VetKeys from '@dfinity/vetkeys';

const DEFAULT_KEY_NAME = 'test_key_1';
const DEFAULT_CONTEXT = 'motoko-show';
const DEFAULT_ECDSA_KEY_NAME = (process.env.DFX_NETWORK ?? '').toLowerCase() === 'ic' ? 'test_key_1' : 'dfx_test_key';
const AUTH_STORAGE_IV_KEY = 'iv';
const CIPHER_PACKAGE_MAGIC = Uint8Array.from([0x56, 0x4b, 0x44, 0x01]);

const isLocalhostEnvironment = () => {
  const hostname = typeof window === 'undefined' ? '' : window.location.hostname;
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.localhost');
};

const isSafariBrowser = () => {
  if (typeof navigator === 'undefined') {
    return false;
  }
  const userAgent = navigator.userAgent;
  return /Safari/i.test(userAgent) && !/Chrome|Chromium|Edg|OPR/i.test(userAgent);
};

const getIdentityProviderConfig = () => {
  const dfxNetwork = (process.env.DFX_NETWORK ?? '').toLowerCase();
  const iiCanisterId = process.env.CANISTER_ID_INTERNET_IDENTITY;
  if (dfxNetwork === 'ic') {
    return { ok: true, identityProviders: ['https://identity.ic0.app/#authorize'] };
  }
  if (iiCanisterId) {
    const subdomainUrl = `http://${iiCanisterId}.localhost:4943/#authorize`;
    const localhostUrl = `http://localhost:4943/?canisterId=${iiCanisterId}#authorize`;
    const identityProviders = isSafariBrowser() ? [localhostUrl, subdomainUrl] : [subdomainUrl, localhostUrl];
    return { ok: true, identityProviders };
  }
  if (dfxNetwork && dfxNetwork !== 'ic') {
    return { ok: false, reason: 'missing_local_ii' };
  }
  if (isLocalhostEnvironment()) {
    return { ok: false, reason: 'missing_local_ii' };
  }
  return { ok: true, identityProviders: ['https://identity.ic0.app/#authorize'] };
};

const clearAuthClientStorage = async () => {
  const localStorageBackend = new LocalStorage();
  const indexedDbStorageBackend = new IdbStorage();

  await Promise.all([
    localStorageBackend.remove(KEY_STORAGE_KEY).catch(() => undefined),
    localStorageBackend.remove(KEY_STORAGE_DELEGATION).catch(() => undefined),
    localStorageBackend.remove(AUTH_STORAGE_IV_KEY).catch(() => undefined),
    indexedDbStorageBackend.remove(KEY_STORAGE_KEY).catch(() => undefined),
    indexedDbStorageBackend.remove(KEY_STORAGE_DELEGATION).catch(() => undefined),
    indexedDbStorageBackend.remove(AUTH_STORAGE_IV_KEY).catch(() => undefined)
  ]);

  if (typeof window !== 'undefined') {
    window.sessionStorage.removeItem(`ic-${KEY_STORAGE_KEY}`);
    window.sessionStorage.removeItem(`ic-${KEY_STORAGE_DELEGATION}`);
    window.sessionStorage.removeItem(`ic-${AUTH_STORAGE_IV_KEY}`);
  }
};

const loginWithIdentityProviderFallback = async (client, identityProviders) => {
  let lastError;
  for (const identityProvider of identityProviders) {
    try {
      await new Promise((resolve, reject) => {
        client.login({
          identityProvider,
          onSuccess: resolve,
          onError: (error) => reject(error)
        });
      });
      return;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error('identity login failed');
};

const parseHexToBytes = (hexRaw) => {
  const clean = hexRaw.trim().replace(/^0x/i, '');
  if (clean.length === 0) {
    return { ok: false, error: 'empty' };
  }
  if (clean.length % 2 !== 0) {
    return { ok: false, error: 'odd_length' };
  }
  if (!/^[0-9a-fA-F]+$/.test(clean)) {
    return { ok: false, error: 'non_hex' };
  }

  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(Number.parseInt(clean.slice(i, i + 2), 16));
  }
  return { ok: true, bytes };
};

const bytesEqual = (left, right) =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const concatBytes = (...chunks) => {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const merged = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return merged;
};

const encodeCipherPackage = ({ recipientBytes, derivedPublicKeyBytes, ciphertextBytes }) => {
  if (recipientBytes.length > 255) {
    throw new Error('recipient_too_long');
  }
  if (derivedPublicKeyBytes.length > 65535) {
    throw new Error('dpk_too_long');
  }
  const dpkLength = derivedPublicKeyBytes.length;
  const header = Uint8Array.from([
    ...CIPHER_PACKAGE_MAGIC,
    recipientBytes.length,
    (dpkLength >> 8) & 0xff,
    dpkLength & 0xff
  ]);
  return concatBytes(header, recipientBytes, derivedPublicKeyBytes, ciphertextBytes);
};

const decodeCipherPackage = (bytes) => {
  if (bytes.length < 7 || !bytesEqual(bytes.subarray(0, 4), CIPHER_PACKAGE_MAGIC)) {
    return { ok: true, packaged: false, ciphertextBytes: Uint8Array.from(bytes) };
  }
  const recipientLength = bytes[4];
  const dpkLength = (bytes[5] << 8) | bytes[6];
  const payloadOffset = 7;
  const minimumLength = payloadOffset + recipientLength + dpkLength + 1;
  if (bytes.length < minimumLength) {
    return { ok: false, error: 'invalid_package' };
  }
  const recipientStart = payloadOffset;
  const recipientEnd = recipientStart + recipientLength;
  const dpkStart = recipientEnd;
  const dpkEnd = dpkStart + dpkLength;
  return {
    ok: true,
    packaged: true,
    recipientBytes: Uint8Array.from(bytes.subarray(recipientStart, recipientEnd)),
    derivedPublicKeyBytes: Uint8Array.from(bytes.subarray(dpkStart, dpkEnd)),
    ciphertextBytes: Uint8Array.from(bytes.subarray(dpkEnd))
  };
};

const parseTextResult = (result) => {
  if (result && typeof result === 'object' && 'ok' in result) {
    return { ok: true, value: result.ok };
  }
  if (result && typeof result === 'object' && 'err' in result) {
    return { ok: false, error: result.err };
  }
  return { ok: false, error: 'unknown result' };
};

const parseVariantResult = (result) => {
  if (result && typeof result === 'object' && 'ok' in result) {
    return { ok: true, value: result.ok };
  }
  if (result && typeof result === 'object' && 'err' in result) {
    return { ok: false, error: result.err };
  }
  return { ok: false, error: 'unknown result' };
};

const fromCandidOptText = (value) => {
  if (Array.isArray(value) && value.length > 0) {
    return String(value[0] ?? '');
  }
  return '';
};

const fromCandidNatText = (value) => {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(Math.trunc(value));
  }
  if (typeof value === 'string') {
    return value;
  }
  return '';
};

const bytesToHex = (bytes) => Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('');

const toUncompressedSecp256k1PublicKeyBytes = (publicKeyBytes) => {
  if (publicKeyBytes.length === 65 && publicKeyBytes[0] === 0x04) {
    return Uint8Array.from(publicKeyBytes);
  }
  if (publicKeyBytes.length === 33 && (publicKeyBytes[0] === 0x02 || publicKeyBytes[0] === 0x03)) {
    return secp256k1.ProjectivePoint.fromHex(publicKeyBytes).toRawBytes(false);
  }
  throw new Error('invalid_secp256k1_public_key');
};

const deriveEthAddressFromPublicKeyBytes = (publicKeyBytes) => {
  const uncompressed = toUncompressedSecp256k1PublicKeyBytes(publicKeyBytes);
  const hashed = keccak_256(uncompressed.slice(1));
  return `0x${bytesToHex(hashed.slice(-20))}`;
};

const deriveEthAddressFromPublicKeyHex = (publicKeyHex) => {
  const parsed = parseHexToBytes(publicKeyHex);
  if (!parsed.ok) {
    return '';
  }
  try {
    return deriveEthAddressFromPublicKeyBytes(Uint8Array.from(parsed.bytes));
  } catch (_) {
    return '';
  }
};

const normalizeEthAddress = (addressRaw) => {
  const clean = addressRaw.trim().toLowerCase();
  const normalized = clean.startsWith('0x') ? clean : `0x${clean}`;
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    return { ok: false, error: 'invalid_eth_address' };
  }
  return { ok: true, value: normalized };
};

const ethereumPersonalMessageHash = (messageText) => {
  const encoder = new TextEncoder();
  const messageBytes = encoder.encode(messageText);
  const prefixBytes = encoder.encode(`\u0019Ethereum Signed Message:\n${messageBytes.length}`);
  return keccak_256(concatBytes(prefixBytes, messageBytes));
};

const parseRecoveryId = (vByte) => {
  if (vByte === 27 || vByte === 28) {
    return { ok: true, value: vByte - 27 };
  }
  if (vByte === 0 || vByte === 1) {
    return { ok: true, value: vByte };
  }
  if (vByte >= 35) {
    return { ok: true, value: (vByte - 35) % 2 };
  }
  return { ok: false, error: 'invalid_recovery_id' };
};

const recoverCompressedPublicKeyFromCompactSig = (compactSignatureBytes, messageHashBytes, recoveryId) =>
  secp256k1.Signature.fromCompact(compactSignatureBytes)
    .addRecoveryBit(recoveryId)
    .recoverPublicKey(messageHashBytes)
    .toRawBytes(true);

const findRecoveryIdByPublicKey = (compactSignatureBytes, messageHashBytes, compressedPublicKeyBytes) => {
  for (let recoveryId = 0; recoveryId < 4; recoveryId += 1) {
    try {
      const recovered = recoverCompressedPublicKeyFromCompactSig(compactSignatureBytes, messageHashBytes, recoveryId);
      if (bytesEqual(recovered, compressedPublicKeyBytes)) {
        return { ok: true, value: recoveryId };
      }
    } catch (_) {
      // ignore invalid recovery branches
    }
  }
  return { ok: false, error: 'recovery_id_not_found' };
};

const encodeRecoverableEthSignatureHex = (compactSignatureBytes, recoveryId) => {
  const signature65 = concatBytes(compactSignatureBytes, Uint8Array.from([27 + recoveryId]));
  return bytesToHex(signature65);
};

const WALLET_NETWORK_ID = Object.freeze({
  ETH: 'eth',
  SEPOLIA: 'sepolia',
  BASE: 'base',
  SOL: 'sol',
  SOL_TESTNET: 'sol_testnet',
  APT: 'apt',
  SUI: 'sui',
  BTC: 'btc',
  CKB: 'ckb',
  ICP: 'icp'
});

const EVM_WALLET_NETWORK_IDS = new Set([WALLET_NETWORK_ID.ETH, WALLET_NETWORK_ID.SEPOLIA, WALLET_NETWORK_ID.BASE]);

const MULTICHAIN_WALLET_CHAIN_SPECS = [
  {
    id: WALLET_NETWORK_ID.ETH,
    symbol: 'ETH',
    name: 'Ethereum',
    family: 'EVM',
    accent: '#7f8cff',
    network: 'Ethereum Mainnet'
  },
  {
    id: WALLET_NETWORK_ID.SEPOLIA,
    symbol: 'SEP',
    name: 'Sepolia',
    family: 'EVM',
    accent: '#88b7ff',
    network: 'Ethereum Sepolia'
  },
  {
    id: WALLET_NETWORK_ID.SOL,
    symbol: 'SOL',
    name: 'Solana',
    family: 'Ed25519',
    accent: '#66f9d3',
    network: 'Solana Mainnet'
  },
  {
    id: WALLET_NETWORK_ID.SOL_TESTNET,
    symbol: 'SOL',
    name: 'Solana Testnet',
    family: 'Ed25519',
    accent: '#5bf4c7',
    network: 'Solana Testnet'
  },
  {
    id: WALLET_NETWORK_ID.BASE,
    symbol: 'BASE',
    name: 'Base',
    family: 'EVM',
    accent: '#4d93ff',
    network: 'Base Mainnet'
  },
  {
    id: WALLET_NETWORK_ID.APT,
    symbol: 'APT',
    name: 'Aptos',
    family: 'Ed25519',
    accent: '#cfe6ff',
    network: 'Aptos Mainnet'
  },
  {
    id: WALLET_NETWORK_ID.SUI,
    symbol: 'SUI',
    name: 'Sui',
    family: 'Ed25519',
    accent: '#7be8ff',
    network: 'Sui Mainnet'
  },
  {
    id: WALLET_NETWORK_ID.BTC,
    symbol: 'BTC',
    name: 'Bitcoin',
    family: 'UTXO',
    accent: '#ffb25c',
    network: 'Bitcoin Mainnet'
  },
  {
    id: WALLET_NETWORK_ID.CKB,
    symbol: 'CKB',
    name: 'Nervos CKB',
    family: 'Cell',
    accent: '#8eff7a',
    network: 'CKB Mainnet'
  },
  {
    id: WALLET_NETWORK_ID.ICP,
    symbol: 'ICP',
    name: 'Internet Computer',
    family: 'ICP',
    accent: '#ff7ad9',
    network: 'ICP Mainnet'
  }
];

const buildWalletChainRuntime = (chainId, currentEthAddress, isLoggedIn) => {
  const isEvmChain = EVM_WALLET_NETWORK_IDS.has(chainId);

  if (isEvmChain) {
    if (!isLoggedIn) {
      return { address: '', addressSource: 'ii_required', primaryBalance: '', assets: [] };
    }
    if (!currentEthAddress) {
      return { address: '', addressSource: 'ii_pending', primaryBalance: '', assets: [] };
    }
    return { address: currentEthAddress, addressSource: 'ii', primaryBalance: '', assets: [] };
  }

  return { address: '', addressSource: 'not_connected', primaryBalance: '', assets: [] };
};

const shortWalletText = (value) => {
  const text = String(value ?? '').trim();
  if (!text) {
    return '-';
  }
  if (text.length <= 18) {
    return text;
  }
  return `${text.slice(0, 8)}...${text.slice(-8)}`;
};

const walletChainOptionLabel = (chain) => {
  if (!chain) {
    return '';
  }
  if (chain.id === WALLET_NETWORK_ID.SEPOLIA) {
    return `${chain.symbol} | ${chain.name} | Testnet`;
  }
  if (chain.id === WALLET_NETWORK_ID.SOL_TESTNET) {
    return `${chain.symbol} | Solana | Testnet`;
  }
  return `${chain.symbol} | ${chain.name}`;
};

const formatUnitsText = (amountText, decimals, maxFractionDigits = 6) => {
  const raw = String(amountText ?? '').trim();
  if (!/^\d+$/.test(raw)) {
    return '';
  }
  if (decimals <= 0) {
    return raw.replace(/^0+(?=\d)/, '');
  }
  const normalized = raw.replace(/^0+(?=\d)/, '');
  const padded = normalized.padStart(decimals + 1, '0');
  const integerPart = padded.slice(0, -decimals) || '0';
  let fractionPart = padded.slice(-decimals);
  if (maxFractionDigits >= 0 && fractionPart.length > maxFractionDigits) {
    fractionPart = fractionPart.slice(0, maxFractionDigits);
  }
  fractionPart = fractionPart.replace(/0+$/, '');
  return fractionPart ? `${integerPart}.${fractionPart}` : integerPart;
};

const formatWalletPrimaryAmountDisplay = (chainId, amountText) => {
  if (!amountText) {
    return '';
  }
  if (chainId === WALLET_NETWORK_ID.SOL || chainId === WALLET_NETWORK_ID.SOL_TESTNET) {
    return formatUnitsText(amountText, 9, 6);
  }
  return amountText;
};

const messages = {
  zh: {
    pageTitle: 'VetKD 功能演示',
    title: 'VetKD Mission Console',
    desc: '首页只显示功能标题，点击后进入全屏功能页，每个页面一个按钮执行一个能力。',
    backendReady: 'Backend: 已连接',
    backendMissing: 'Backend: 未连接（先部署后端）',
    idle: '状态：空闲',
    running: '执行中...',
    actionFailed: '操作失败',
    moduleMissing: 'VetKeys 模块不可用（请检查前端依赖是否已安装）',
    moduleHint: '使用本地打包的 @dfinity/vetkeys 模块，不再依赖 CDN。',
    loginTitle: 'Identity 登录',
    loginHint: '根据环境自动选择 II：ic 使用生产 II，其他网络使用本地 II。',
    loginBtn: 'Identity 登录',
    switchLoginBtn: '切换账号登录',
    logoutBtn: '退出登录',
    principalLabel: '当前 Principal',
    ethAddressLabel: '当前 ETH 地址',
    ethAddressPending: '读取中...',
    loginDone: '登录成功',
    logoutDone: '已切回匿名身份',
    loginUnsupported: '无法加载 Identity 登录模块',
    loginProviderMissing: '当前网络缺少本地 Internet Identity 配置（CANISTER_ID_INTERNET_IDENTITY）',
    homeTitle: '功能入口',
    homeHint: '点击任意功能，进入独立全屏操作界面',
    backHome: '返回主页',
    featureTipTitle: '功能提示',
    featurePublicKeyTitle: '读取 VetKD 公钥',
    featurePublicKeyDesc: '调用 vetkd_public_key，读取 key + context 的派生公钥。',
    featurePublicKeyAction: '执行：读取公钥',
    featureDeriveTitle: '派生加密密钥',
    featureDeriveDesc: '自动生成 Transport 公钥，调用 vetkd_derive_key 返回 encrypted_key。',
    featureDeriveAction: '执行：派生密钥',
    featureCallerTitle: '读取 Caller Input',
    featureCallerDesc: '读取后端实际使用的 caller 字节（hex）。',
    featureCallerAction: '执行：读取 Caller Input',
    featureRoundTripTitle: '端到端加解密',
    featureRoundTripDesc: 'derive -> decryptAndVerify -> IBE encrypt/decrypt 全流程校验。',
    featureRoundTripAction: '执行：端到端示例',
    homeAtoBTitle: 'A 发密文给 B（登录版）',
    homeAtoBDesc: 'A 登录后填写 B principal 和消息进行加密；B 登录后粘贴密文进行解密。',
    homeEthSigTitle: 'Threshold ECDSA（ETH）：A 签名，B 用地址验证',
    homeEthSigDesc: 'A 登录后用链上 Threshold ECDSA(secp256k1) 对文字做 ETH 风格签名；B 只用 A 的 ETH 地址在前端本地验证。',
    homeEthSigEthExplain:
      '签名使用 Ethereum personal_sign 消息哈希规则。A 侧会从链上公钥推导 ETH 地址，并生成带恢复位(v)的 65 字节签名；B 侧用“原文 + 签名 + ETH 地址”验证。',
    homeEthSigSignCard: 'A 侧：签名',
    homeEthSigVerifyCard: 'B 侧：验签',
    homeEthSigSignAction: 'A 生成 ETH 签名',
    homeEthSigVerifyAction: 'B 使用 ETH 地址验证',
    homeEthSigMessageToSign: 'A 要签名的文字',
    homeEthSigMessageToVerify: 'B 验签用文字',
    homeEthSigPublicKeyOut: 'A 的 secp256k1 公钥(hex，可选展示)',
    homeEthSigSignatureOut: 'A 的 ETH 签名(hex，65字节含v)',
    homeEthSigEthAddressOut: 'A 的 ETH 地址',
    homeEthSigPublicKeyIn: 'A 的 ETH 地址（B 输入）',
    homeEthSigSignatureIn: 'A 的 ETH 签名（B 输入）',
    homeEthSigVerifyOut: '验签结果',
    homeEthSigNeedLogin: '请先登录 A 的身份再签名',
    homeEthSigEmptyMessage: '签名文字不能为空',
    homeEthSigInvalidPublicKey: 'ETH 地址格式错误（需要 0x 开头的 40 位十六进制）',
    homeEthSigInvalidSignature: '签名格式错误（需要 64 或 65 字节 hex）',
    homeEthSigVerifyPassed: '验签通过：签名可恢复出与 A 的 ETH 地址一致的公钥',
    homeEthSigVerifyRejected: '验签失败：消息、签名或 ETH 地址不匹配',
    homeEthSigBackendUnsupported: '当前后端未暴露 ECDSA 示例接口，请重新生成声明并部署后端',
    homeEthSigRecoverFailed: '无法从签名恢复出匹配的 secp256k1 公钥',
    homeWalletTitle: 'II 控制的多链钱包（主页演示）',
    homeWalletDesc: '使用同一登录身份展示多链钱包主页，可切换 ETH / SEPOLIA / SOL / SOL-DEVNET / BASE / APT / SUI / BTC / CKB / ICP。',
    homeWalletExplain:
      '这是多链钱包首页 UI。当前只接入 ETH / Base 的地址读取（由后端链钥公钥推导）；其他链先保留链切换与页面结构，不展示模拟地址/模拟余额。',
    homeWalletAuthTitle: 'II 登录（钱包）',
    homeWalletAuthHint: '在钱包页直接使用 II 登录/切换账号。登录后 ETH / Base 会显示当前身份对应地址。',
    homeWalletLoginAction: 'II 登录',
    homeWalletChainSwitch: '链切换',
    homeWalletOverview: '钱包总览',
    homeWalletCurrentChain: '当前链',
    homeWalletNetwork: '网络',
    homeWalletAddress: '钱包地址',
    homeWalletAddressSource: '地址来源',
    homeWalletSourceIi: 'II 登录身份（链钥地址）',
    homeWalletSourceIiRequired: '需要先用 II 登录',
    homeWalletSourceUnavailable: '该链地址暂未接入',
    homeWalletBoundIdentity: '绑定身份',
    homeWalletMode: '运行模式',
    homeWalletModeLoggedIn: '已登录（II 控制）',
    homeWalletModeAnonymous: '匿名模式（仅展示）',
    homeWalletPrimaryBalance: '主资产余额',
    homeWalletNoBalance: '未接入',
    homeWalletAssets: '资产列表',
    homeWalletNoAssets: '当前链资产查询未接入（不展示模拟数据）',
    homeWalletTokenTab: '代币',
    homeWalletNftTab: 'NFT',
    homeWalletRefresh: '刷新',
    homeWalletTotalBalance: '总资产',
    homeWalletAssetDetailTitle: '资产详情',
    homeWalletOnChainBalance: '链上余额',
    homeWalletUsdPlaceholder: 'US$ --',
    homeWalletBackTokenList: '返回币种列表',
    homeWalletTransactionHistory: '交易记录',
    homeWalletNoHistory: '暂无交易记录',
    homeWalletReceiveSheetTitle: '接收',
    homeWalletReceiveAddressTitle: '接收地址',
    homeWalletReceiveAddressHint: '请将下面地址提供给转账方',
    homeWalletCopy: '复制',
    homeWalletQrCode: '二维码',
    homeWalletQrNotReady: '二维码功能暂未接入',
    homeWalletNoAddress: '当前链暂无可用地址',
    homeWalletActionNotReady: '当前功能未接入后端能力',
    homeWalletSendPageTitle: '发送',
    homeWalletSendToLabel: '收款地址',
    homeWalletSendAmountLabel: '数量',
    homeWalletSendAmountHint: '当前项目尚未接入真实发送能力（仅展示 UI）',
    homeWalletSendConfirm: '确认发送',
    homeWalletClose: '关闭',
    homeWalletSwapAction: '兑换',
    homeWalletBuyAction: '购买',
    homeWalletActions: '快捷操作',
    homeWalletReceiveAction: '收款',
    homeWalletSendAction: '发送',
    homeWalletSignAction: '签名',
    homeWalletComingSoon: '后续可接入各链签名/转账能力',
    homeAtoBEncryptAction: 'A 加密生成密文',
    homeAtoBDecryptAction: 'B 解密密文',
    homeAtoBPayload: 'A 发给 B 的密闻：节点汇合时间改为 20:00',
    homeAtoBRecipient: 'B Principal ID',
    homeAtoBPlaintext: 'A 要发送的明文',
    homeAtoBEncryptCard: 'A 侧：加密',
    homeAtoBDecryptCard: 'B 侧：解密',
    homeAtoBCiphertextOut: 'A 生成的密文',
    homeAtoBCiphertextIn: 'B 输入密文',
    homeAtoBCiphertextBelow: '当前用于解密的密文',
    homeAtoBOut: 'B 解密后看到',
    homeAtoBInvalidPrincipal: 'B principal 格式无效',
    homeAtoBCiphertextFormatError: '密文格式错误',
    homeAtoBIdentityMismatch: '当前登录身份不是密文目标 B',
    homeAtoBDecryptPermissionError: '解密失败：当前登录账号不是密文接收者，或密文与当前身份不匹配',
    homeAtoBLegacyCiphertext: '当前密文是旧版本格式，请让发送方在当前版本重新加密后再解密',
    homeAtoBRecipientMismatchPrefix: '密文目标账号与当前登录账号不一致',
    homeAtoBCallerMismatch: '当前页面显示身份与后端实际调用身份不一致，请先点击“切换账号登录”后重试',
    homeAtoBReplicaMismatch: '密文与当前本地链环境不匹配（可能已重启/重装本地网络），请让发送方重新加密',
    homeAtoBNeedLogin: '请先登录身份再执行',
    homeAtoBEmptyPlaintext: '发送明文不能为空',
    homeAtoBUnsupportedCipher: '当前 VetKeys 版本不支持密文序列化/反序列化',
    publicKeyOut: 'VetKD 公钥(hex)',
    encryptedKeyOut: '加密密钥(hex)',
    callerInputOut: 'Caller Input(hex)',
    roundTripOut: '解密结果',
    transportPublicKeyOut: '本次 Transport 公钥(hex)',
    keyNameLabel: 'Key 名称',
    contextLabel: 'Context',
    messageLabel: '测试明文',
    langZh: '中',
    langEn: 'EN'
  },
  en: {
    pageTitle: 'VetKD Feature Demo',
    title: 'VetKD Mission Console',
    desc: 'Home shows feature titles only. Click one to open a full-screen page with one action button.',
    backendReady: 'Backend: connected',
    backendMissing: 'Backend: not connected (deploy backend first)',
    idle: 'Status: idle',
    running: 'Running...',
    actionFailed: 'Action failed',
    moduleMissing: 'VetKeys module is unavailable (check frontend dependencies)',
    moduleHint: 'Uses bundled local @dfinity/vetkeys module and no CDN fallback.',
    loginTitle: 'Identity Login',
    loginHint: 'Identity provider is selected by environment: ic uses production II, others use local II.',
    loginBtn: 'Identity Login',
    switchLoginBtn: 'Switch Account',
    logoutBtn: 'Logout',
    principalLabel: 'Current Principal',
    ethAddressLabel: 'Current ETH Address',
    ethAddressPending: 'Loading...',
    loginDone: 'Login success',
    logoutDone: 'Switched back to anonymous identity',
    loginUnsupported: 'Unable to load identity login module',
    loginProviderMissing: 'Local Internet Identity is not configured for this network (CANISTER_ID_INTERNET_IDENTITY)',
    homeTitle: 'Feature Entry',
    homeHint: 'Click any feature to open its full-screen operation page',
    backHome: 'Back to Home',
    featureTipTitle: 'Feature Tip',
    featurePublicKeyTitle: 'Read VetKD Public Key',
    featurePublicKeyDesc: 'Call vetkd_public_key and read the derived public key for key + context.',
    featurePublicKeyAction: 'Run: Read Public Key',
    featureDeriveTitle: 'Derive Encrypted Key',
    featureDeriveDesc: 'Auto-generate Transport public key and call vetkd_derive_key.',
    featureDeriveAction: 'Run: Derive Key',
    featureCallerTitle: 'Read Caller Input',
    featureCallerDesc: 'Read caller bytes (hex) actually used by backend.',
    featureCallerAction: 'Run: Read Caller Input',
    featureRoundTripTitle: 'End-to-End Encryption',
    featureRoundTripDesc: 'derive -> decryptAndVerify -> IBE encrypt/decrypt validation flow.',
    featureRoundTripAction: 'Run: End-to-End Demo',
    homeAtoBTitle: 'A Sends Secret To B (Login)',
    homeAtoBDesc: 'A logs in and encrypts for B principal; B logs in and decrypts from ciphertext.',
    homeEthSigTitle: 'Threshold ECDSA (ETH): A Signs, B Verifies By Address',
    homeEthSigDesc:
      'A logs in and uses Threshold ECDSA (secp256k1) to create an Ethereum-style message signature; B verifies locally using only A ETH address.',
    homeEthSigEthExplain:
      'This demo uses Ethereum personal_sign hashing. A side derives ETH address from chain public key and emits a 65-byte signature (with recovery v); B verifies with message + signature + ETH address.',
    homeEthSigSignCard: 'A Side: Sign',
    homeEthSigVerifyCard: 'B Side: Verify',
    homeEthSigSignAction: 'A Create ETH Signature',
    homeEthSigVerifyAction: 'B Verify With ETH Address',
    homeEthSigMessageToSign: 'Text to sign (A)',
    homeEthSigMessageToVerify: 'Text to verify (B)',
    homeEthSigPublicKeyOut: 'A secp256k1 Public Key (hex, optional display)',
    homeEthSigSignatureOut: 'A ETH Signature (hex, 65 bytes with v)',
    homeEthSigEthAddressOut: 'A ETH Address',
    homeEthSigPublicKeyIn: 'A ETH Address (B input)',
    homeEthSigSignatureIn: 'A ETH Signature (B input)',
    homeEthSigVerifyOut: 'Verification Result',
    homeEthSigNeedLogin: 'Please login as A before signing',
    homeEthSigEmptyMessage: 'Signing text must not be empty',
    homeEthSigInvalidPublicKey: 'Invalid ETH address format (expected 0x + 40 hex chars)',
    homeEthSigInvalidSignature: 'Invalid signature format (expected 64 or 65 bytes hex)',
    homeEthSigVerifyPassed: 'Verification passed: signature recovers a public key that maps to A ETH address',
    homeEthSigVerifyRejected: 'Verification failed: message, signature or ETH address does not match',
    homeEthSigBackendUnsupported: 'Backend ECDSA demo methods are missing. Regenerate declarations and redeploy backend',
    homeEthSigRecoverFailed: 'Unable to recover a matching secp256k1 public key from signature',
    homeWalletTitle: 'II-Controlled Multi-Chain Wallet (Home Demo)',
    homeWalletDesc:
      'A wallet homepage driven by one login identity, with chain switching for ETH / SEPOLIA / SOL / SOL-DEVNET / BASE / APT / SUI / BTC / CKB / ICP.',
    homeWalletExplain:
      'This is a multi-chain wallet home UI. Only ETH/Base address reading is currently connected (derived from backend chain-key public key); other chains keep the chain switch + page structure only, without mock addresses or balances.',
    homeWalletAuthTitle: 'II Login (Wallet)',
    homeWalletAuthHint:
      'Use II login / account switching directly in wallet page. After login, ETH/Base will show the address mapped from current identity.',
    homeWalletLoginAction: 'II Login',
    homeWalletChainSwitch: 'Chain Switch',
    homeWalletOverview: 'Wallet Overview',
    homeWalletCurrentChain: 'Current Chain',
    homeWalletNetwork: 'Network',
    homeWalletAddress: 'Wallet Address',
    homeWalletAddressSource: 'Address Source',
    homeWalletSourceIi: 'II login identity (chain-key address)',
    homeWalletSourceIiRequired: 'II login required',
    homeWalletSourceUnavailable: 'Address not connected for this chain yet',
    homeWalletBoundIdentity: 'Bound Identity',
    homeWalletMode: 'Runtime Mode',
    homeWalletModeLoggedIn: 'Logged in (II controlled)',
    homeWalletModeAnonymous: 'Anonymous (display only)',
    homeWalletPrimaryBalance: 'Primary Balance',
    homeWalletNoBalance: 'Not connected',
    homeWalletAssets: 'Assets',
    homeWalletNoAssets: 'Asset query is not connected for this chain yet (no mock data shown)',
    homeWalletTokenTab: 'Token',
    homeWalletNftTab: 'NFT',
    homeWalletRefresh: 'Refresh',
    homeWalletTotalBalance: 'Total Balance',
    homeWalletAssetDetailTitle: 'Asset Detail',
    homeWalletOnChainBalance: 'On-chain Balance',
    homeWalletUsdPlaceholder: 'US$ --',
    homeWalletBackTokenList: 'Back to token list',
    homeWalletTransactionHistory: 'Transaction History',
    homeWalletNoHistory: 'No history',
    homeWalletReceiveSheetTitle: 'Receive',
    homeWalletReceiveAddressTitle: 'Receive Address',
    homeWalletReceiveAddressHint: 'Share this address with the sender',
    homeWalletCopy: 'Copy',
    homeWalletQrCode: 'QR',
    homeWalletQrNotReady: 'QR feature is not connected yet',
    homeWalletNoAddress: 'No available address for current chain',
    homeWalletActionNotReady: 'Backend capability is not connected for this action',
    homeWalletSendPageTitle: 'Send',
    homeWalletSendToLabel: 'To Address',
    homeWalletSendAmountLabel: 'Amount',
    homeWalletSendAmountHint: 'Real sending is not connected in this project yet (UI only)',
    homeWalletSendConfirm: 'Send',
    homeWalletClose: 'Close',
    homeWalletSwapAction: 'Swap',
    homeWalletBuyAction: 'Buy',
    homeWalletActions: 'Quick Actions',
    homeWalletReceiveAction: 'Receive',
    homeWalletSendAction: 'Send',
    homeWalletSignAction: 'Sign',
    homeWalletComingSoon: 'Chain-specific signing/transfer flows can be wired next',
    homeAtoBEncryptAction: 'A Encrypt To Ciphertext',
    homeAtoBDecryptAction: 'B Decrypt Ciphertext',
    homeAtoBPayload: 'Secret from A to B: meet at node at 20:00',
    homeAtoBRecipient: 'B Principal ID',
    homeAtoBPlaintext: 'Plaintext from A',
    homeAtoBEncryptCard: 'A Side: Encrypt',
    homeAtoBDecryptCard: 'B Side: Decrypt',
    homeAtoBCiphertextOut: 'Ciphertext produced by A',
    homeAtoBCiphertextIn: 'Ciphertext input by B',
    homeAtoBCiphertextBelow: 'Ciphertext used for decryption',
    homeAtoBOut: 'B decrypted text',
    homeAtoBInvalidPrincipal: 'Invalid B principal format',
    homeAtoBCiphertextFormatError: 'Invalid ciphertext format',
    homeAtoBIdentityMismatch: 'Current login identity is not ciphertext target B',
    homeAtoBDecryptPermissionError: 'Decryption failed: current login is not the intended recipient or ciphertext does not match this identity',
    homeAtoBLegacyCiphertext: 'This ciphertext was generated by an old format. Ask sender to re-encrypt with current app version',
    homeAtoBRecipientMismatchPrefix: 'Ciphertext recipient does not match current login principal',
    homeAtoBCallerMismatch: 'Displayed principal and backend caller identity are different. Click "Switch Account" and try again',
    homeAtoBReplicaMismatch: 'Ciphertext does not match current local chain environment (local network was likely reset). Ask sender to re-encrypt',
    homeAtoBNeedLogin: 'Please login before executing this flow',
    homeAtoBEmptyPlaintext: 'Plaintext must not be empty',
    homeAtoBUnsupportedCipher: 'Current VetKeys version does not support ciphertext serialization/deserialization',
    publicKeyOut: 'VetKD Public Key (hex)',
    encryptedKeyOut: 'Encrypted Key (hex)',
    callerInputOut: 'Caller Input (hex)',
    roundTripOut: 'Decrypted Output',
    transportPublicKeyOut: 'Transport Public Key (hex)',
    keyNameLabel: 'Key Name',
    contextLabel: 'Context',
    messageLabel: 'Test Plaintext',
    langZh: '中',
    langEn: 'EN'
  }
};

function App() {
  const [lang, setLang] = useState('zh');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState('');
  const [activeFeature, setActiveFeature] = useState(null);
  const [authClient, setAuthClient] = useState(null);
  const [backendActor, setBackendActor] = useState(defaultBackend);
  const [currentPrincipalText, setCurrentPrincipalText] = useState(Principal.anonymous().toText());
  const [currentEthAddress, setCurrentEthAddress] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const [aToBRecipientPrincipal, setAtoBRecipientPrincipal] = useState('');
  const [aToBPlaintext, setAtoBPlaintext] = useState('');
  const [aToBCiphertextOut, setAtoBCiphertextOut] = useState('');
  const [aToBCiphertextIn, setAtoBCiphertextIn] = useState('');
  const [aToBDecryptedText, setAtoBDecryptedText] = useState('');
  const [ethSignMessage, setEthSignMessage] = useState('');
  const [ethPublicKeyOut, setEthPublicKeyOut] = useState('');
  const [ethSignatureOut, setEthSignatureOut] = useState('');
  const [ethAddressOut, setEthAddressOut] = useState('');
  const [ethVerifyMessage, setEthVerifyMessage] = useState('');
  const [ethVerifyAddress, setEthVerifyAddress] = useState('');
  const [ethVerifySignatureHex, setEthVerifySignatureHex] = useState('');
  const [ethVerifyResult, setEthVerifyResult] = useState('');
  const [walletChainId, setWalletChainId] = useState(WALLET_NETWORK_ID.ETH);
  const [walletSelectedTokenSymbol, setWalletSelectedTokenSymbol] = useState('');
  const [walletSendPageOpen, setWalletSendPageOpen] = useState(false);
  const [walletReceiveModalOpen, setWalletReceiveModalOpen] = useState(false);
  const [walletSendTo, setWalletSendTo] = useState('');
  const [walletSendAmount, setWalletSendAmount] = useState('');
  const [walletOverviewLive, setWalletOverviewLive] = useState({
    networkId: '',
    loading: false,
    error: '',
    address: '',
    addressSource: '',
    backendReady: false,
    primaryAmountText: '',
    primaryAvailable: false
  });

  const t = messages[lang];
  const actorReady = Boolean(backendActor);
  const statusText = status || t.idle;
  const featureTipType = statusText.startsWith(`${t.actionFailed}:`) ? 'error' : busy ? 'running' : 'info';

  useEffect(() => {
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
    document.title = t.pageTitle;
  }, [lang, t.pageTitle]);

  const switchIdentity = (identity) => {
    if (!canisterId) {
      setBackendActor(undefined);
      setCurrentPrincipalText(Principal.anonymous().toText());
      setCurrentEthAddress('');
      setIsLoggedIn(false);
      return;
    }

    const actor = createActor(canisterId, identity ? { agentOptions: { identity } } : {});
    setBackendActor(actor);
    if (identity) {
      setCurrentPrincipalText(identity.getPrincipal().toText());
      setIsLoggedIn(true);
    } else {
      setCurrentPrincipalText(Principal.anonymous().toText());
      setCurrentEthAddress('');
      setIsLoggedIn(false);
    }
  };

  useEffect(() => {
    switchIdentity(null);
  }, []);

  useEffect(() => {
    let isCancelled = false;

    const restoreIdentity = async () => {
      const providerConfig = getIdentityProviderConfig();
      if (!providerConfig.ok) {
        switchIdentity(null);
        return;
      }

      try {
        const client = await AuthClient.create();
        if (isCancelled) {
          return;
        }
        setAuthClient(client);
        const authenticated = await client.isAuthenticated();
        if (isCancelled || !authenticated) {
          return;
        }
        switchIdentity(client.getIdentity());
      } catch (_) {
        // Keep anonymous identity if AuthClient is unavailable in current environment.
      }
    };

    void restoreIdentity();

    return () => {
      isCancelled = true;
    };
  }, []);

  useEffect(() => {
    setStatus(actorReady ? t.idle : t.backendMissing);
  }, [actorReady, t.idle, t.backendMissing]);

  useEffect(() => {
    let cancelled = false;

    const loadCurrentEthAddress = async () => {
      if (!isLoggedIn || !backendActor || typeof backendActor.ecdsaPublicKeyExample !== 'function') {
        setCurrentEthAddress('');
        return;
      }

      setCurrentEthAddress('');

      try {
        const result = parseTextResult(await backendActor.ecdsaPublicKeyExample(DEFAULT_ECDSA_KEY_NAME));
        if (cancelled || !result.ok) {
          return;
        }
        const publicKeyParsed = parseHexToBytes(result.value);
        if (!publicKeyParsed.ok) {
          return;
        }
        const address = deriveEthAddressFromPublicKeyBytes(Uint8Array.from(publicKeyParsed.bytes));
        if (!cancelled) {
          setCurrentEthAddress(address);
        }
      } catch (_) {
        if (!cancelled) {
          setCurrentEthAddress('');
        }
      }
    };

    void loadCurrentEthAddress();

    return () => {
      cancelled = true;
    };
  }, [isLoggedIn, backendActor, currentPrincipalText, activeFeature, walletChainId]);

  useEffect(() => {
    let cancelled = false;

    const loadWalletOverview = async () => {
      if (activeFeature !== 'iiMultiChainWallet' || !walletChainId) {
        setWalletOverviewLive((prev) => ({
          ...prev,
          networkId: '',
          loading: false,
          error: '',
          address: '',
          addressSource: '',
          backendReady: false,
          primaryAmountText: '',
          primaryAvailable: false
        }));
        return;
      }

      if (!backendActor || typeof backendActor.wallet_overview !== 'function') {
        setWalletOverviewLive((prev) => ({
          ...prev,
          networkId: walletChainId,
          loading: false,
          error: 'wallet_overview_not_available',
          address: '',
          addressSource: '',
          backendReady: false,
          primaryAmountText: '',
          primaryAvailable: false
        }));
        return;
      }

      const isEvmChain = EVM_WALLET_NETWORK_IDS.has(walletChainId);
      const isSolChain = walletChainId === WALLET_NETWORK_ID.SOL || walletChainId === WALLET_NETWORK_ID.SOL_TESTNET;
      if ((isEvmChain || isSolChain) && !isLoggedIn) {
        setWalletOverviewLive({
          networkId: walletChainId,
          loading: false,
          error: '',
          address: '',
          addressSource: 'ii_required',
          backendReady: true,
          primaryAmountText: '',
          primaryAvailable: false
        });
        return;
      }

      setWalletOverviewLive((prev) => ({
        ...prev,
        networkId: walletChainId,
        loading: true,
        error: '',
        address: '',
        addressSource: '',
        backendReady: true,
        primaryAmountText: '',
        primaryAvailable: false
      }));

      try {
        const result = parseVariantResult(await backendActor.wallet_overview(walletChainId, [], []));
        if (cancelled) {
          return;
        }
        if (!result.ok) {
          setWalletOverviewLive({
            networkId: walletChainId,
            loading: false,
            error: String(result.error ?? 'wallet_overview_failed'),
            address: '',
            addressSource: '',
            backendReady: true,
            primaryAmountText: '',
            primaryAvailable: false
          });
          return;
        }

        const out = result.value ?? {};
        const evmAddressFromBackend = fromCandidOptText(out.evmAddress);
        const evmPublicKeyHex = fromCandidOptText(out.evmPublicKeyHex);
        const primaryAmountText = fromCandidNatText(out.primaryAmount);
        const primaryAvailable = Boolean(out.primaryAvailable);
        let derivedAddress = evmAddressFromBackend;
        if (!derivedAddress && isEvmChain && evmPublicKeyHex) {
          derivedAddress = deriveEthAddressFromPublicKeyHex(evmPublicKeyHex);
        }
        const addressSource = isEvmChain || isSolChain
          ? derivedAddress
            ? 'ii'
            : isLoggedIn
              ? 'ii_pending'
              : 'ii_required'
          : 'not_connected';

        setWalletOverviewLive({
          networkId: walletChainId,
          loading: false,
          error: '',
          address: derivedAddress,
          addressSource,
          backendReady: true,
          primaryAmountText,
          primaryAvailable
        });
      } catch (error) {
        if (cancelled) {
          return;
        }
        setWalletOverviewLive({
          networkId: walletChainId,
          loading: false,
          error: error instanceof Error ? error.message : String(error),
          address: '',
          addressSource: '',
          backendReady: true,
          primaryAmountText: '',
          primaryAvailable: false
        });
      }
    };

    void loadWalletOverview();

    return () => {
      cancelled = true;
    };
  }, [activeFeature, walletChainId, backendActor, isLoggedIn]);

  const featureItems = useMemo(
    () => [
      { id: 'aToB', title: t.homeAtoBTitle, desc: t.homeAtoBDesc },
      { id: 'ethAddressVerify', title: t.homeEthSigTitle, desc: t.homeEthSigDesc },
      { id: 'iiMultiChainWallet', title: t.homeWalletTitle, desc: t.homeWalletDesc }
    ],
    [t.homeAtoBTitle, t.homeAtoBDesc, t.homeEthSigTitle, t.homeEthSigDesc, t.homeWalletTitle, t.homeWalletDesc]
  );

  const activeItem = featureItems.find((item) => item.id === activeFeature) ?? null;

  const walletChains = useMemo(
    () =>
      MULTICHAIN_WALLET_CHAIN_SPECS.map((chain) => {
        let runtime = buildWalletChainRuntime(chain.id, currentEthAddress, isLoggedIn);
        if (walletOverviewLive.networkId === chain.id && walletOverviewLive.backendReady) {
          if (walletOverviewLive.loading) {
            runtime = { ...runtime, address: '', addressSource: 'ii_pending' };
          } else if (walletOverviewLive.addressSource) {
            runtime = {
              ...runtime,
              address: walletOverviewLive.address || '',
              addressSource: walletOverviewLive.addressSource
            };
          }
          if (
            !walletOverviewLive.loading &&
            !walletOverviewLive.error &&
            walletOverviewLive.primaryAvailable &&
            walletOverviewLive.primaryAmountText !== ''
          ) {
            const displayPrimaryBalance = formatWalletPrimaryAmountDisplay(chain.id, walletOverviewLive.primaryAmountText);
            if (displayPrimaryBalance) {
              runtime = { ...runtime, primaryBalance: displayPrimaryBalance };
            }
          }
        }
        return {
          ...chain,
          address: runtime.address,
          addressSource: runtime.addressSource,
          primaryBalance: runtime.primaryBalance || t.homeWalletNoBalance,
          assets: runtime.assets
        };
      }),
    [currentEthAddress, isLoggedIn, t.homeWalletNoBalance, walletOverviewLive]
  );

  const activeWalletChain = walletChains.find((chain) => chain.id === walletChainId) ?? walletChains[0] ?? null;
  const walletDebugText = useMemo(() => {
    if (activeFeature !== 'iiMultiChainWallet') {
      return '';
    }
    if (!walletOverviewLive.loading && !walletOverviewLive.error) {
      return '';
    }
    const parts = [
      `chain=${walletChainId}`,
      `loading=${walletOverviewLive.loading ? '1' : '0'}`,
      `backendReady=${walletOverviewLive.backendReady ? '1' : '0'}`,
      `primaryAvailable=${walletOverviewLive.primaryAvailable ? '1' : '0'}`,
      `primary=${walletOverviewLive.primaryAmountText || '-'}`,
      `addressSource=${walletOverviewLive.addressSource || '-'}`,
      `address=${walletOverviewLive.address ? shortWalletText(walletOverviewLive.address) : '-'}`,
      `error=${walletOverviewLive.error || '-'}`
    ];
    return `wallet_overview debug | ${parts.join(' | ')}`;
  }, [activeFeature, walletChainId, walletOverviewLive]);
  const walletTokenRows = useMemo(() => {
    if (!activeWalletChain) {
      return [];
    }
    return [
      {
        symbol: activeWalletChain.symbol,
        name: activeWalletChain.name,
        network: activeWalletChain.network,
        family: activeWalletChain.family,
        address: activeWalletChain.address,
        addressSource: activeWalletChain.addressSource,
        displayBalance: activeWalletChain.primaryBalance || t.homeWalletNoBalance
      }
    ];
  }, [activeWalletChain, t.homeWalletNoBalance]);
  const walletSelectedToken = walletTokenRows.find((token) => token.symbol === walletSelectedTokenSymbol) ?? null;
  const walletPrimaryToken = walletTokenRows[0] ?? null;
  const walletActionToken = walletSelectedToken ?? walletPrimaryToken;
  const walletHeroBalance = useMemo(() => {
    if (!walletPrimaryToken) {
      return '--';
    }
    return `${walletPrimaryToken.displayBalance} ${walletPrimaryToken.symbol}`;
  }, [walletPrimaryToken]);
  const walletSelectedTokenAddress = walletActionToken?.address ?? '';
  const walletReceiveRows = walletActionToken
    ? [
        {
          id: `${walletChainId}-${walletActionToken.symbol}`,
          title: `${walletActionToken.symbol} ${t.homeWalletReceiveAddressTitle}`,
          address: walletSelectedTokenAddress
        }
      ]
    : [];

  const closeWalletTokenDetail = () => {
    setWalletSelectedTokenSymbol('');
    setWalletSendPageOpen(false);
    setWalletReceiveModalOpen(false);
    setWalletSendTo('');
    setWalletSendAmount('');
  };

  const handleWalletChainChange = (nextChainId) => {
    setWalletChainId(nextChainId);
    closeWalletTokenDetail();
  };

  const handleWalletRefresh = () => {
    setStatus(`${t.homeWalletRefresh}: ${t.homeWalletActionNotReady}`);
  };

  const copyWalletAddress = async (address) => {
    const text = String(address ?? '').trim();
    if (!text) {
      setStatus(`${t.actionFailed}: ${t.homeWalletNoAddress}`);
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      setStatus(`${t.homeWalletCopy}: ${shortWalletText(text)}`);
    } catch (error) {
      setStatus(`${t.actionFailed}: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const handleWalletAction = (action) => {
    const targetToken = walletActionToken;
    if (!targetToken) {
      setStatus(`${t.actionFailed}: ${t.homeWalletNoAddress}`);
      return;
    }
    if (!walletSelectedToken && targetToken.symbol) {
      setWalletSelectedTokenSymbol(targetToken.symbol);
    }
    if (action === 'receive') {
      if (!walletSelectedTokenAddress) {
        setStatus(`${t.actionFailed}: ${t.homeWalletNoAddress}`);
        return;
      }
      setWalletReceiveModalOpen(true);
      return;
    }
    if (action === 'send') {
      setWalletSendPageOpen(true);
      setWalletReceiveModalOpen(false);
      return;
    }
    setStatus(`${t.actionFailed}: ${t.homeWalletActionNotReady}`);
  };

  const submitWalletSend = () => {
    setStatus(`${t.actionFailed}: ${t.homeWalletActionNotReady}`);
  };

  const runAction = async (actionKey, action) => {
    if (!actorReady) {
      setStatus(t.backendMissing);
      return;
    }

    setBusy(actionKey);
    try {
      await action();
    } catch (error) {
      setStatus(`${t.actionFailed}: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setBusy('');
    }
  };

  const runLocalAction = async (actionKey, action) => {
    setBusy(actionKey);
    try {
      await action();
    } catch (error) {
      setStatus(`${t.actionFailed}: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setBusy('');
    }
  };

  const ensureLoggedIn = () => {
    if (!isLoggedIn) {
      setStatus(`${t.actionFailed}: ${t.homeAtoBNeedLogin}`);
      return false;
    }
    return true;
  };

  const handleLogin = async () => {
    await runLocalAction('login', async () => {
      const providerConfig = getIdentityProviderConfig();
      if (!providerConfig.ok) {
        setStatus(`${t.actionFailed}: ${t.loginProviderMissing}`);
        return;
      }

      let client = authClient;
      if (!client) {
        client = await AuthClient.create();
        setAuthClient(client);
      }

      try {
        await loginWithIdentityProviderFallback(client, providerConfig.identityProviders);
      } catch (error) {
        setStatus(
          `${t.actionFailed}: ${t.loginUnsupported}${error instanceof Error && error.message ? ` (${error.message})` : ''}`
        );
        return;
      }

      const identity = client.getIdentity();
      switchIdentity(identity);
      setStatus(`${t.loginDone}: ${identity.getPrincipal().toText()}`);
    });
  };

  const handleSwitchAccountLogin = async () => {
    await runLocalAction('switchLogin', async () => {
      const providerConfig = getIdentityProviderConfig();
      if (!providerConfig.ok) {
        setStatus(`${t.actionFailed}: ${t.loginProviderMissing}`);
        return;
      }

      let client = authClient;
      if (!client) {
        client = await AuthClient.create();
        setAuthClient(client);
      }

      await client.logout();
      switchIdentity(null);

      // 强制清理旧 session key 与 delegation，避免切换账号后仍复用旧 principal。
      await clearAuthClientStorage();
      client = await AuthClient.create();
      setAuthClient(client);

      await loginWithIdentityProviderFallback(client, providerConfig.identityProviders);

      const identity = client.getIdentity();
      switchIdentity(identity);
      setStatus(`${t.loginDone}: ${identity.getPrincipal().toText()}`);
    });
  };

  const handleLogout = async () => {
    await runLocalAction('logout', async () => {
      if (authClient) {
        await authClient.logout();
      }
      await clearAuthClientStorage();
      setAuthClient(null);
      switchIdentity(null);
      setStatus(t.logoutDone);
    });
  };

  const loadVetkeysOrFail = async () => {
    if (!VetKeys) {
      setStatus(`${t.actionFailed}: ${t.moduleMissing}`);
      return null;
    }
    return VetKeys;
  };

  const serializeIbeCiphertext = (ciphertext) => {
    if (typeof ciphertext.serialize === 'function') {
      return Uint8Array.from(ciphertext.serialize());
    }
    if (typeof ciphertext.toBytes === 'function') {
      return Uint8Array.from(ciphertext.toBytes());
    }
    if (typeof ciphertext.toByteArray === 'function') {
      return Uint8Array.from(ciphertext.toByteArray());
    }
    throw new Error(t.homeAtoBUnsupportedCipher);
  };

  const deserializeIbeCiphertext = (IbeCiphertextType, bytes) => {
    if (typeof IbeCiphertextType.deserialize === 'function') {
      return IbeCiphertextType.deserialize(bytes);
    }
    if (typeof IbeCiphertextType.fromBytes === 'function') {
      return IbeCiphertextType.fromBytes(bytes);
    }
    if (typeof IbeCiphertextType.fromByteArray === 'function') {
      return IbeCiphertextType.fromByteArray(Array.from(bytes));
    }
    throw new Error(t.homeAtoBUnsupportedCipher);
  };

  const handleAEncryptForB = async () => {
    await runAction('aEncrypt', async () => {
      if (!ensureLoggedIn()) {
        return;
      }

      const recipientText = aToBRecipientPrincipal.trim();
      let recipientPrincipal;
      try {
        recipientPrincipal = Principal.fromText(recipientText);
      } catch (_) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBInvalidPrincipal}`);
        return;
      }

      const plaintext = aToBPlaintext.trim();
      if (!plaintext) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBEmptyPlaintext}`);
        return;
      }

      const vetkeysModule = await loadVetkeysOrFail();
      if (!vetkeysModule) {
        return;
      }

      const { DerivedPublicKey, IbeCiphertext, IbeIdentity, IbeSeed } = vetkeysModule;
      if (!DerivedPublicKey || !IbeCiphertext || !IbeIdentity || !IbeSeed) {
        setStatus(`${t.actionFailed}: ${t.moduleMissing}`);
        return;
      }

      const publicKeyResult = parseTextResult(await backendActor.vetkdPublicKeyExample(DEFAULT_KEY_NAME, DEFAULT_CONTEXT));
      if (!publicKeyResult.ok) {
        setStatus(`${t.actionFailed}: ${publicKeyResult.error}`);
        return;
      }

      const publicKeyBytes = parseHexToBytes(publicKeyResult.value);
      if (!publicKeyBytes.ok) {
        setStatus(`${t.actionFailed}: invalid hex data`);
        return;
      }

      const derivedPublicKey = DerivedPublicKey.deserialize(Uint8Array.from(publicKeyBytes.bytes));
      const recipientIdentityBytes = recipientPrincipal.toUint8Array();
      const recipientIdentity = IbeIdentity.fromBytes(recipientIdentityBytes);
      const payload = new TextEncoder().encode(plaintext);
      const ciphertext = IbeCiphertext.encrypt(derivedPublicKey, recipientIdentity, payload, IbeSeed.random());
      const ciphertextBytes = serializeIbeCiphertext(ciphertext);
      const packagedCiphertextBytes = encodeCipherPackage({
        recipientBytes: recipientIdentityBytes,
        derivedPublicKeyBytes: Uint8Array.from(publicKeyBytes.bytes),
        ciphertextBytes
      });
      const ciphertextHex = bytesToHex(packagedCiphertextBytes);

      setAtoBCiphertextOut(ciphertextHex);
      setAtoBCiphertextIn(ciphertextHex);
      setAtoBDecryptedText('');
      setStatus(t.homeAtoBEncryptAction);
    });
  };

  const handleBDecryptCiphertext = async () => {
    await runAction('bDecrypt', async () => {
      if (!ensureLoggedIn()) {
        return;
      }
      setAtoBDecryptedText('');

      const ciphertextHex = aToBCiphertextIn.trim();
      if (!ciphertextHex) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBCiphertextFormatError}`);
        return;
      }
      const ciphertextInputBytes = parseHexToBytes(ciphertextHex);
      if (!ciphertextInputBytes.ok) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBCiphertextFormatError}`);
        return;
      }
      const decodedPackage = decodeCipherPackage(Uint8Array.from(ciphertextInputBytes.bytes));
      if (!decodedPackage.ok) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBCiphertextFormatError}`);
        return;
      }
      if (!decodedPackage.packaged) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBLegacyCiphertext}`);
        return;
      }

      const vetkeysModule = await loadVetkeysOrFail();
      if (!vetkeysModule) {
        return;
      }

      const { DerivedPublicKey, EncryptedVetKey, IbeCiphertext, TransportSecretKey } = vetkeysModule;
      if (!DerivedPublicKey || !EncryptedVetKey || !IbeCiphertext || !TransportSecretKey) {
        setStatus(`${t.actionFailed}: ${t.moduleMissing}`);
        return;
      }

      const transportSecretKey = TransportSecretKey.random();
      const transportPublicKeyBytes = Array.from(transportSecretKey.publicKeyBytes());
      const keyName = DEFAULT_KEY_NAME;
      const context = DEFAULT_CONTEXT;
      const deriveResult = parseTextResult(await backendActor.vetkdDeriveKeyExample(transportPublicKeyBytes, keyName, context));
      if (!deriveResult.ok) {
        setStatus(`${t.actionFailed}: ${deriveResult.error}`);
        return;
      }

      const publicKeyResult = parseTextResult(await backendActor.vetkdPublicKeyExample(keyName, context));
      if (!publicKeyResult.ok) {
        setStatus(`${t.actionFailed}: ${publicKeyResult.error}`);
        return;
      }

      const encryptedKeyBytes = parseHexToBytes(deriveResult.value);
      const derivedPublicKeyBytes = parseHexToBytes(publicKeyResult.value);
      const ciphertextBytes = parseHexToBytes(ciphertextHex);
      if (!encryptedKeyBytes.ok || !derivedPublicKeyBytes.ok || !ciphertextBytes.ok) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBCiphertextFormatError}`);
        return;
      }

      const callerInputHex = await backendActor.vetkdCallerInputHex();
      const callerInputParsed = parseHexToBytes(callerInputHex);
      if (!callerInputParsed.ok) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBCiphertextFormatError}`);
        return;
      }
      const callerInputBytes = Uint8Array.from(callerInputParsed.bytes);

      const displayPrincipalBytes = Principal.fromText(currentPrincipalText).toUint8Array();
      const displayPrincipalHex = bytesToHex(displayPrincipalBytes);
      if (displayPrincipalHex !== callerInputHex) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBCallerMismatch}`);
        return;
      }
      if (!bytesEqual(callerInputBytes, decodedPackage.recipientBytes)) {
        let recipientText = '-';
        try {
          recipientText = Principal.fromUint8Array(decodedPackage.recipientBytes).toText();
        } catch (_) {
          recipientText = bytesToHex(decodedPackage.recipientBytes);
        }
        setStatus(
          `${t.actionFailed}: ${t.homeAtoBRecipientMismatchPrefix} (target=${recipientText}, current=${currentPrincipalText})`
        );
        return;
      }
      let recipientTextForStatus = currentPrincipalText;
      try {
        recipientTextForStatus = Principal.fromUint8Array(decodedPackage.recipientBytes).toText();
      } catch (_) {
        recipientTextForStatus = bytesToHex(decodedPackage.recipientBytes);
      }

      try {
        const encryptedVetKey = EncryptedVetKey.deserialize(Uint8Array.from(encryptedKeyBytes.bytes));
        if (!bytesEqual(Uint8Array.from(derivedPublicKeyBytes.bytes), decodedPackage.derivedPublicKeyBytes)) {
          setStatus(`${t.actionFailed}: ${t.homeAtoBReplicaMismatch}`);
          return;
        }
        const effectiveDpkBytes = decodedPackage.derivedPublicKeyBytes;
        const effectiveCiphertextBytes = decodedPackage.ciphertextBytes;
        const derivedPublicKey = DerivedPublicKey.deserialize(effectiveDpkBytes);
        const identityBytes = callerInputBytes;
        const vetKey = encryptedVetKey.decryptAndVerify(transportSecretKey, derivedPublicKey, identityBytes);
        const ciphertext = deserializeIbeCiphertext(IbeCiphertext, effectiveCiphertextBytes);
        const decrypted = ciphertext.decrypt(vetKey);
        const decryptedText = new TextDecoder().decode(decrypted);
        setAtoBDecryptedText(decryptedText);
        setStatus(`${t.homeAtoBDecryptAction}: ${t.homeAtoBOut} = ${decryptedText}`);
      } catch (error) {
        const details = error instanceof Error ? error.message : String(error);
        const normalized = details.toLowerCase();
        if (normalized.includes('cannot mix bigint') || normalized.includes('decrypt') || normalized.includes('verify')) {
          setStatus(
            `${t.actionFailed}: ${t.homeAtoBDecryptPermissionError} (target=${recipientTextForStatus}, current=${currentPrincipalText})`
          );
          return;
        }
        setStatus(
          `${t.actionFailed}: ${t.homeAtoBDecryptPermissionError} (target=${recipientTextForStatus}, current=${currentPrincipalText})`
        );
      }
    });
  };

  const handleEthSign = async () => {
    await runAction('ethSign', async () => {
      if (!ensureLoggedIn()) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigNeedLogin}`);
        return;
      }
      if (
        !backendActor ||
        typeof backendActor.ecdsaPublicKeyExample !== 'function' ||
        typeof backendActor.ecdsaSignMessageHashExample !== 'function'
      ) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigBackendUnsupported}`);
        return;
      }

      const messageText = ethSignMessage;
      if (!messageText.trim()) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigEmptyMessage}`);
        return;
      }

      const keyName = DEFAULT_ECDSA_KEY_NAME;
      const messageHashBytes = ethereumPersonalMessageHash(messageText);
      const [publicKeyRaw, signatureRaw] = await Promise.all([
        backendActor.ecdsaPublicKeyExample(keyName),
        backendActor.ecdsaSignMessageHashExample(Array.from(messageHashBytes), keyName)
      ]);

      const publicKeyResult = parseTextResult(publicKeyRaw);
      if (!publicKeyResult.ok) {
        setStatus(`${t.actionFailed}: ${publicKeyResult.error}`);
        return;
      }
      const signatureResult = parseTextResult(signatureRaw);
      if (!signatureResult.ok) {
        setStatus(`${t.actionFailed}: ${signatureResult.error}`);
        return;
      }

      const publicKeyParsed = parseHexToBytes(publicKeyResult.value);
      const signatureParsed = parseHexToBytes(signatureResult.value);
      if (!publicKeyParsed.ok) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigRecoverFailed}`);
        return;
      }
      if (!signatureParsed.ok || signatureParsed.bytes.length !== 64) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigInvalidSignature}`);
        return;
      }

      const compressedPublicKeyBytes = Uint8Array.from(publicKeyParsed.bytes);
      let derivedEthAddress = '';
      try {
        derivedEthAddress = deriveEthAddressFromPublicKeyBytes(compressedPublicKeyBytes);
      } catch (_) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigRecoverFailed}`);
        return;
      }

      const compactSignatureBytes = Uint8Array.from(signatureParsed.bytes);
      const recoveryIdResult = findRecoveryIdByPublicKey(compactSignatureBytes, messageHashBytes, compressedPublicKeyBytes);
      if (!recoveryIdResult.ok) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigRecoverFailed}`);
        return;
      }
      const recoverableSignatureHex = encodeRecoverableEthSignatureHex(compactSignatureBytes, recoveryIdResult.value);

      setEthPublicKeyOut(publicKeyResult.value);
      setEthSignatureOut(recoverableSignatureHex);
      setEthAddressOut(derivedEthAddress);
      // B 侧改为手动输入验证数据，这里不再自动回填。
      setEthVerifyMessage('');
      setEthVerifyAddress('');
      setEthVerifySignatureHex('');
      setEthVerifyResult('');
      setStatus(`${t.homeEthSigSignAction} (${keyName})`);
    });
  };

  const handleEthVerify = async () => {
    await runLocalAction('ethVerify', async () => {
      const messageText = ethVerifyMessage;
      if (!messageText.trim()) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigEmptyMessage}`);
        return;
      }

      const addressResult = normalizeEthAddress(ethVerifyAddress);
      if (!addressResult.ok) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigInvalidPublicKey}`);
        return;
      }
      const signatureParsed = parseHexToBytes(ethVerifySignatureHex);
      if (!signatureParsed.ok || ![64, 65].includes(signatureParsed.bytes.length)) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigInvalidSignature}`);
        return;
      }

      const messageHashBytes = ethereumPersonalMessageHash(messageText);
      const signatureBytes = Uint8Array.from(signatureParsed.bytes);
      const compactSignatureBytes = signatureBytes.length === 65 ? signatureBytes.slice(0, 64) : signatureBytes;
      const recoveryCandidates = [];
      if (signatureBytes.length === 65) {
        const recoveryIdResult = parseRecoveryId(signatureBytes[64]);
        if (!recoveryIdResult.ok) {
          setStatus(`${t.actionFailed}: ${t.homeEthSigInvalidSignature}`);
          return;
        }
        recoveryCandidates.push(recoveryIdResult.value);
      } else {
        recoveryCandidates.push(0, 1, 2, 3);
      }

      let recoveredAddress = '';
      let recoveredPublicKeyHex = '';
      let isValid = false;
      let hadRecoverableBranch = false;

      for (const recoveryId of recoveryCandidates) {
        try {
          const recoveredCompressedPublicKey = recoverCompressedPublicKeyFromCompactSig(
            compactSignatureBytes,
            messageHashBytes,
            recoveryId
          );
          hadRecoverableBranch = true;
          const candidateAddress = deriveEthAddressFromPublicKeyBytes(recoveredCompressedPublicKey).toLowerCase();
          if (candidateAddress !== addressResult.value) {
            continue;
          }
          const verified = secp256k1.verify(compactSignatureBytes, messageHashBytes, recoveredCompressedPublicKey, {
            prehash: false
          });
          if (!verified) {
            continue;
          }
          isValid = true;
          recoveredAddress = candidateAddress;
          recoveredPublicKeyHex = bytesToHex(recoveredCompressedPublicKey);
          break;
        } catch (_) {
          // ignore invalid recovery branch
        }
      }

      if (!isValid && !hadRecoverableBranch) {
        setStatus(`${t.actionFailed}: ${t.homeEthSigRecoverFailed}`);
        setEthVerifyResult(t.homeEthSigRecoverFailed);
        return;
      }

      const resultText = isValid ? t.homeEthSigVerifyPassed : t.homeEthSigVerifyRejected;
      const suffixParts = [];
      if (recoveredAddress) {
        suffixParts.push(`ETH=${recoveredAddress}`);
      }
      if (recoveredPublicKeyHex) {
        suffixParts.push(`pubkey=${recoveredPublicKeyHex}`);
      }
      const suffix = suffixParts.length > 0 ? ` | ${suffixParts.join(' | ')}` : '';
      setEthVerifyResult(`${resultText}${suffix}`);
      setStatus(isValid ? resultText : `${t.actionFailed}: ${resultText}`);
    });
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="logo" aria-hidden="true" />
          <div>
            <p className="brand-kicker">VETKD LAB</p>
            <p className="brand-title">{t.title}</p>
            <p className="brand-subtitle">{t.desc}</p>
          </div>
        </div>
        <div className="lang-switch" role="group" aria-label="Language">
          <button className={`lang-btn ${lang === 'zh' ? 'active' : ''}`} onClick={() => setLang('zh')} type="button">
            {t.langZh}
          </button>
          <button className={`lang-btn ${lang === 'en' ? 'active' : ''}`} onClick={() => setLang('en')} type="button">
            {t.langEn}
          </button>
        </div>
      </header>

      <section className="status-ribbon">
        <div className={`backend-flag ${actorReady ? 'ready' : 'offline'}`}>{actorReady ? t.backendReady : t.backendMissing}</div>
        <p className="status-line">{statusText}</p>
      </section>

      <section className="login-ribbon">
        <div className="login-copy">
          <p className="login-title">{t.loginTitle}</p>
          <p className="login-hint">{t.loginHint}</p>
        </div>
        <div className="login-panel">
          <div className="login-actions">
            <button className="login-btn-main" disabled={busy === 'login'} onClick={handleLogin} type="button">
              {busy === 'login' ? t.running : t.loginBtn}
            </button>
            <button
              className="switch-login-btn-main"
              disabled={busy === 'switchLogin'}
              onClick={handleSwitchAccountLogin}
              type="button"
            >
              {busy === 'switchLogin' ? t.running : t.switchLoginBtn}
            </button>
            <button className="logout-btn-main" disabled={busy === 'logout'} onClick={handleLogout} type="button">
              {busy === 'logout' ? t.running : t.logoutBtn}
            </button>
          </div>
          <div className="login-meta-grid">
            <div className="login-meta-card">
              <p className="login-meta-label">{t.principalLabel}</p>
              <p className="login-meta-value">
                <strong>{currentPrincipalText}</strong> <span>{isLoggedIn ? '(login)' : '(anonymous)'}</span>
              </p>
            </div>
            <div className="login-meta-card">
              <p className="login-meta-label">{t.ethAddressLabel}</p>
              <p className="login-meta-value">
                <strong>{isLoggedIn ? currentEthAddress || t.ethAddressPending : '-'}</strong>
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="home-shell">
        <h1 className="home-title">{t.homeTitle}</h1>
        <p className="home-desc">{t.homeHint}</p>
        <div className="feature-grid">
          {featureItems.map((feature, index) => (
            <button className="feature-tile" key={feature.id} onClick={() => setActiveFeature(feature.id)} type="button">
              <span className="tile-index">{String(index + 1).padStart(2, '0')}</span>
              <span className="tile-title">{feature.title}</span>
              <span className="tile-desc">{feature.desc}</span>
              <span className="tile-arrow">OPEN</span>
            </button>
          ))}
        </div>
      </section>

      {activeItem ? (
        <div className="feature-overlay" role="dialog" aria-modal="true">
          <div className="feature-screen">
            <header className="overlay-top">
              <button className="back-btn" onClick={() => setActiveFeature(null)} type="button">
                {t.backHome}
              </button>
              <div className="lang-switch" role="group" aria-label="Language">
                <button className={`lang-btn ${lang === 'zh' ? 'active' : ''}`} onClick={() => setLang('zh')} type="button">
                  {t.langZh}
                </button>
                <button className={`lang-btn ${lang === 'en' ? 'active' : ''}`} onClick={() => setLang('en')} type="button">
                  {t.langEn}
                </button>
              </div>
            </header>

            <section className="feature-content">
              {activeFeature !== 'iiMultiChainWallet' ? (
                <>
                  <h2 className="feature-title">{activeItem.title}</h2>
                  <p className="feature-desc">{activeItem.desc}</p>
                  <div className={`feature-tip ${featureTipType}`}>
                    <span className="feature-tip-title">{t.featureTipTitle}</span>
                    <span className="feature-tip-text">{busy ? t.running : statusText}</span>
                  </div>
                  {activeFeature === 'aToB' ? <p className="feature-desc">{t.moduleHint}</p> : null}
                  <p className="feature-desc">
                    {t.principalLabel}: <strong>{currentPrincipalText}</strong> {isLoggedIn ? '(login)' : '(anonymous)'}
                  </p>
                </>
              ) : null}
              {activeFeature === 'aToB' ? (
                <div className="a2b-grid">
                  <article className="a2b-card">
                    <h3 className="a2b-card-title">{t.homeAtoBEncryptCard}</h3>
                    <label className="field" htmlFor="aToBRecipientPrincipal">
                      <span>{t.homeAtoBRecipient}</span>
                      <input
                        id="aToBRecipientPrincipal"
                        className="text-input"
                        value={aToBRecipientPrincipal}
                        onChange={(event) => setAtoBRecipientPrincipal(event.target.value)}
                      />
                    </label>
                    <label className="field" htmlFor="aToBPlaintext">
                      <span>{t.homeAtoBPlaintext}</span>
                      <textarea
                        id="aToBPlaintext"
                        className="text-area"
                        value={aToBPlaintext}
                        onChange={(event) => setAtoBPlaintext(event.target.value)}
                      />
                    </label>
                    <button className="action-btn" disabled={busy === 'aEncrypt'} onClick={handleAEncryptForB} type="button">
                      {busy === 'aEncrypt' ? t.running : t.homeAtoBEncryptAction}
                    </button>
                    <label className="field" htmlFor="aToBCiphertextOut">
                      <span>{t.homeAtoBCiphertextOut}</span>
                      <textarea
                        id="aToBCiphertextOut"
                        className="text-area text-area-cipher"
                        readOnly
                        value={aToBCiphertextOut}
                      />
                    </label>
                  </article>

                  <article className="a2b-card">
                    <h3 className="a2b-card-title">{t.homeAtoBDecryptCard}</h3>
                    <label className="field" htmlFor="aToBCiphertextIn">
                      <span>{t.homeAtoBCiphertextIn}</span>
                      <textarea
                        id="aToBCiphertextIn"
                        className="text-area text-area-cipher"
                        value={aToBCiphertextIn}
                        onChange={(event) => {
                          setAtoBCiphertextIn(event.target.value);
                          setAtoBDecryptedText('');
                        }}
                      />
                    </label>
                    <button className="action-btn" disabled={busy === 'bDecrypt'} onClick={handleBDecryptCiphertext} type="button">
                      {busy === 'bDecrypt' ? t.running : t.homeAtoBDecryptAction}
                    </button>
                    <label className="field" htmlFor="aToBDecryptedText">
                      <span>{t.homeAtoBOut}</span>
                      <textarea id="aToBDecryptedText" className="text-area text-area-cipher" readOnly value={aToBDecryptedText} />
                    </label>
                  </article>
                </div>
              ) : null}

              {activeFeature === 'ethAddressVerify' ? (
                <>
                  <p className="feature-desc">{t.homeEthSigEthExplain}</p>
                  <div className="a2b-grid">
                    <article className="a2b-card">
                      <h3 className="a2b-card-title">{t.homeEthSigSignCard}</h3>
                      <label className="field" htmlFor="ethSignMessage">
                        <span>{t.homeEthSigMessageToSign}</span>
                        <textarea
                          id="ethSignMessage"
                          className="text-area"
                          value={ethSignMessage}
                          onChange={(event) => setEthSignMessage(event.target.value)}
                        />
                      </label>
                      <button className="action-btn" disabled={busy === 'ethSign'} onClick={handleEthSign} type="button">
                        {busy === 'ethSign' ? t.running : t.homeEthSigSignAction}
                      </button>
                      <label className="field" htmlFor="ethPublicKeyOut">
                        <span>{t.homeEthSigPublicKeyOut}</span>
                        <textarea
                          id="ethPublicKeyOut"
                          className="text-area text-area-cipher"
                          readOnly
                          value={ethPublicKeyOut}
                        />
                      </label>
                      <label className="field" htmlFor="ethSignatureOut">
                        <span>{t.homeEthSigSignatureOut}</span>
                        <textarea
                          id="ethSignatureOut"
                          className="text-area text-area-cipher"
                          readOnly
                          value={ethSignatureOut}
                        />
                      </label>
                      <label className="field" htmlFor="ethAddressOut">
                        <span>{t.homeEthSigEthAddressOut}</span>
                        <input id="ethAddressOut" className="text-input" readOnly value={ethAddressOut} />
                      </label>
                    </article>

                    <article className="a2b-card">
                      <h3 className="a2b-card-title">{t.homeEthSigVerifyCard}</h3>
                      <label className="field" htmlFor="ethVerifyMessage">
                        <span>{t.homeEthSigMessageToVerify}</span>
                        <textarea
                          id="ethVerifyMessage"
                          className="text-area"
                          value={ethVerifyMessage}
                          onChange={(event) => {
                            setEthVerifyMessage(event.target.value);
                            setEthVerifyResult('');
                          }}
                        />
                      </label>
                      <label className="field" htmlFor="ethVerifyAddress">
                        <span>{t.homeEthSigPublicKeyIn}</span>
                        <textarea
                          id="ethVerifyAddress"
                          className="text-area text-area-cipher"
                          value={ethVerifyAddress}
                          onChange={(event) => {
                            setEthVerifyAddress(event.target.value);
                            setEthVerifyResult('');
                          }}
                        />
                      </label>
                      <label className="field" htmlFor="ethVerifySignatureHex">
                        <span>{t.homeEthSigSignatureIn}</span>
                        <textarea
                          id="ethVerifySignatureHex"
                          className="text-area text-area-cipher"
                          value={ethVerifySignatureHex}
                          onChange={(event) => {
                            setEthVerifySignatureHex(event.target.value);
                            setEthVerifyResult('');
                          }}
                        />
                      </label>
                      <button className="action-btn" disabled={busy === 'ethVerify'} onClick={handleEthVerify} type="button">
                        {busy === 'ethVerify' ? t.running : t.homeEthSigVerifyAction}
                      </button>
                      <label className="field" htmlFor="ethVerifyResult">
                        <span>{t.homeEthSigVerifyOut}</span>
                        <textarea
                          id="ethVerifyResult"
                          className="text-area text-area-cipher"
                          readOnly
                          value={ethVerifyResult}
                        />
                      </label>
                    </article>
                  </div>
                </>
              ) : null}

              {activeFeature === 'iiMultiChainWallet' && activeWalletChain ? (
                <>
                  <div className="wallet-shell">
                    <section className="wallet-card wallet-auth-card">
                      <div className="wallet-section-head">
                        <h3 className="wallet-section-title">{t.homeWalletAuthTitle}</h3>
                        <div className="wallet-chain-corner wallet-chain-corner-auth">
                          <select
                            id="walletChainSelect"
                            className="wallet-chain-select wallet-chain-select-corner wallet-chain-select-auth"
                            value={walletChainId}
                            onChange={(event) => handleWalletChainChange(event.target.value)}
                          >
                            {walletChains.map((chain) => (
                              <option key={chain.id} value={chain.id}>
                                {walletChainOptionLabel(chain)}
                              </option>
                            ))}
                          </select>
                        </div>
                      </div>
                      <p className="wallet-auth-hint">{t.homeWalletAuthHint}</p>
                      <div className="wallet-auth-actions">
                        <button className="login-btn-main" disabled={busy === 'login'} onClick={handleLogin} type="button">
                          {busy === 'login' ? t.running : t.homeWalletLoginAction}
                        </button>
                        <button
                          className="switch-login-btn-main"
                          disabled={busy === 'switchLogin'}
                          onClick={handleSwitchAccountLogin}
                          type="button"
                        >
                          {busy === 'switchLogin' ? t.running : t.switchLoginBtn}
                        </button>
                        <button className="logout-btn-main" disabled={busy === 'logout'} onClick={handleLogout} type="button">
                          {busy === 'logout' ? t.running : t.logoutBtn}
                        </button>
                      </div>
                      <div className="wallet-auth-meta">
                        <div className="wallet-auth-item">
                          <span className="wallet-auth-label">{t.principalLabel}</span>
                          <p className="wallet-auth-value">{currentPrincipalText}</p>
                        </div>
                      </div>
                      {walletDebugText ? <div className="wallet-debug-inline">{walletDebugText}</div> : null}
                    </section>

                    {walletSelectedToken && !walletSendPageOpen ? (
                      <section className="walletAssetPage">
                        <div className="walletAssetHero panel">
                          <div className="walletAssetHeroTop">
                            <button type="button" className="walletAssetRoundBtn" onClick={closeWalletTokenDetail}>
                              {'<'}
                            </button>
                            <button
                              type="button"
                              className="walletAssetRoundBtn"
                              onClick={() => setStatus(`${t.actionFailed}: ${t.homeWalletActionNotReady}`)}
                            >
                              ...
                            </button>
                          </div>
                          <div className="walletAssetTokenBadge">{walletSelectedToken.symbol}</div>
                          <div className="walletAssetBalance">
                            {walletSelectedToken.displayBalance} {walletSelectedToken.symbol}
                          </div>
                          <div className="walletAssetOnchain">
                            {t.homeWalletOnChainBalance}: {t.homeWalletNoBalance}
                          </div>
                          <div className="walletAssetUsd">{t.homeWalletUsdPlaceholder}</div>
                          <div className="walletAssetActionGrid">
                            <button type="button" onClick={() => handleWalletAction('receive')}>
                              {t.homeWalletReceiveAction}
                            </button>
                            <button type="button" onClick={() => handleWalletAction('send')}>
                              {t.homeWalletSendAction}
                            </button>
                            <button type="button" onClick={() => handleWalletAction('swap')}>
                              {t.homeWalletSwapAction}
                            </button>
                            <button type="button" onClick={() => handleWalletAction('buy')}>
                              {t.homeWalletBuyAction}
                            </button>
                          </div>
                        </div>

                        <div className="walletAssetAddress panel">
                          <div className="walletAssetAddressHead">
                            <strong>{t.homeWalletReceiveAddressTitle}</strong>
                            <button type="button" onClick={() => void copyWalletAddress(walletSelectedTokenAddress)}>
                              {t.homeWalletCopy}
                            </button>
                          </div>
                          <p>{t.homeWalletReceiveAddressHint}</p>
                          <div className="walletAssetAddressValue">
                            {walletSelectedTokenAddress || t.homeWalletSourceUnavailable}
                          </div>
                        </div>

                        <div className="walletAssetHistory">
                          <h3>{t.homeWalletTransactionHistory}</h3>
                          <div className="walletAssetEmpty panel">{t.homeWalletNoHistory}</div>
                        </div>
                      </section>
                    ) : walletSelectedToken && walletSendPageOpen ? (
                      <section className="walletSendPage">
                        <div className="walletSendCard panel">
                          <div className="walletAssetHeroTop">
                            <button type="button" className="walletAssetRoundBtn" onClick={() => setWalletSendPageOpen(false)}>
                              {'<'}
                            </button>
                            <button type="button" className="walletAssetRoundBtn" onClick={() => setWalletSendPageOpen(false)}>
                              x
                            </button>
                          </div>
                          <div className="walletAssetTokenBadge">{walletSelectedToken.symbol}</div>
                          <h3>
                            {t.homeWalletSendPageTitle} {walletSelectedToken.symbol}
                          </h3>

                          <div className="walletSendForm">
                            <label htmlFor="walletSendTo">{t.homeWalletSendToLabel}</label>
                            <input
                              id="walletSendTo"
                              type="text"
                              value={walletSendTo}
                              onChange={(event) => setWalletSendTo(event.target.value)}
                              placeholder={walletSelectedTokenAddress || t.homeWalletNoAddress}
                            />

                            <label htmlFor="walletSendAmount">{t.homeWalletSendAmountLabel}</label>
                            <input
                              id="walletSendAmount"
                              type="text"
                              value={walletSendAmount}
                              onChange={(event) => setWalletSendAmount(event.target.value)}
                              placeholder={t.homeWalletSendAmountHint}
                            />
                            <small>{t.homeWalletSendAmountHint}</small>
                          </div>

                          <div className="walletSendActions">
                            <button type="button" onClick={() => setWalletSendPageOpen(false)}>
                              {t.homeWalletClose}
                            </button>
                            <button type="button" onClick={submitWalletSend}>
                              {t.homeWalletSendConfirm}
                            </button>
                          </div>
                        </div>
                      </section>
                    ) : (
                      <>
                        <section className="walletHero panel">
                          <div className="walletHeroBalance">{walletHeroBalance}</div>
                          <div className="walletHeroSub">{t.homeWalletTotalBalance}</div>
                          <div className="walletHeroActions">
                            <button type="button" onClick={() => void copyWalletAddress(activeWalletChain.address)}>
                              {t.homeWalletReceiveAction}
                            </button>
                            <button
                              type="button"
                              onClick={() => setStatus(`${t.actionFailed}: ${t.homeWalletActionNotReady}`)}
                            >
                              {t.homeWalletSendAction}
                            </button>
                            <button
                              type="button"
                              onClick={() => setStatus(`${t.actionFailed}: ${t.homeWalletActionNotReady}`)}
                            >
                              {t.homeWalletSignAction}
                            </button>
                          </div>
                        </section>

                        <section className="walletTokenArea panel">
                          <div className="walletTokenTabs">
                            <button type="button" className="active">
                              {t.homeWalletTokenTab}
                            </button>
                            <button type="button" disabled>
                              {t.homeWalletNftTab}
                            </button>
                            <button type="button" onClick={handleWalletRefresh}>
                              {t.homeWalletRefresh}
                            </button>
                          </div>

                          <div className="walletTokenList">
                            {walletTokenRows.map((token) => (
                              <button
                                type="button"
                                className="walletTokenRow walletTokenRowButton"
                                key={`${activeWalletChain.id}-${token.symbol}`}
                                onClick={() => {
                                  setWalletSelectedTokenSymbol(token.symbol);
                                  setWalletSendPageOpen(false);
                                  setWalletReceiveModalOpen(false);
                                  setWalletSendTo('');
                                  setWalletSendAmount('');
                                }}
                              >
                                <div className="walletTokenLeft">
                                  <div className="walletTokenIcon">{token.symbol.slice(0, 2)}</div>
                                  <div className="walletTokenMeta">
                                    <strong>{token.symbol}</strong>
                                    <span>{token.name}</span>
                                  </div>
                                </div>
                                <div className="walletTokenRight">
                                  <strong className="walletTokenBalance">{token.displayBalance}</strong>
                                  <span className="walletTokenArrow">›</span>
                                </div>
                              </button>
                            ))}
                          </div>
                        </section>
                      </>
                    )}

                    {walletReceiveModalOpen && walletActionToken ? (
                      <div
                        className="walletReceiveOverlay"
                        role="dialog"
                        aria-modal="true"
                        aria-label={t.homeWalletReceiveSheetTitle}
                      >
                        <section className="walletReceiveModal panel">
                          <div className="walletReceiveModalHead">
                            <strong>{t.homeWalletReceiveSheetTitle}</strong>
                            <button
                              type="button"
                              className="walletAssetRoundBtn"
                              onClick={() => setWalletReceiveModalOpen(false)}
                            >
                              x
                            </button>
                          </div>

                          <div className="walletReceiveModalBody">
                            {walletReceiveRows.map((row) => (
                              <div className="walletReceiveAddressBlock" key={row.id}>
                                <h4>{row.title}</h4>
                                <div className="walletReceiveAddressRow">
                                  <div className="walletReceiveAddressMain">
                                    <div className="walletReceiveAddressLogo">{walletActionToken.symbol.slice(0, 2)}</div>
                                    <span>{row.address || t.homeWalletSourceUnavailable}</span>
                                  </div>
                                  <div className="walletReceiveAddressActions">
                                    <button
                                      type="button"
                                      className="walletReceiveIconBtn"
                                      onClick={() => setStatus(`${t.actionFailed}: ${t.homeWalletQrNotReady}`)}
                                      disabled={!row.address}
                                    >
                                      {t.homeWalletQrCode}
                                    </button>
                                    <button
                                      type="button"
                                      className="walletReceiveIconBtn"
                                      onClick={() => void copyWalletAddress(row.address)}
                                      disabled={!row.address}
                                    >
                                      {t.homeWalletCopy}
                                    </button>
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>

                          <div className="walletReceiveModalFoot">
                            <button type="button" onClick={() => setWalletReceiveModalOpen(false)}>
                              {t.homeWalletClose}
                            </button>
                          </div>
                        </section>
                      </div>
                    ) : null}
                  </div>
                </>
              ) : null}
            </section>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default App;
