import { useEffect, useMemo, useState } from 'react';
import { backend as defaultBackend, canisterId, createActor } from 'declarations/backend';
import { Principal } from '@dfinity/principal';
import { AuthClient } from '@dfinity/auth-client';
import * as VetKeys from '@dfinity/vetkeys';

const DEFAULT_KEY_NAME = 'test_key_1';
const DEFAULT_CONTEXT = 'motoko-show';
const DEFAULT_MESSAGE = 'hello vetkeys';

const isLocalhostEnvironment = () => {
  const hostname = typeof window === 'undefined' ? '' : window.location.hostname;
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.localhost');
};

const getIdentityProviderConfig = () => {
  const dfxNetwork = (process.env.DFX_NETWORK ?? '').toLowerCase();
  const iiCanisterId = process.env.CANISTER_ID_INTERNET_IDENTITY;
  if (dfxNetwork === 'ic') {
    return { ok: true, identityProvider: 'https://identity.ic0.app/#authorize' };
  }
  if (iiCanisterId) {
    return { ok: true, identityProvider: `http://${iiCanisterId}.localhost:4943/#authorize` };
  }
  if (dfxNetwork && dfxNetwork !== 'ic') {
    return { ok: false, reason: 'missing_local_ii' };
  }
  if (isLocalhostEnvironment()) {
    return { ok: false, reason: 'missing_local_ii' };
  }
  return { ok: true, identityProvider: 'https://identity.ic0.app/#authorize' };
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

const parseTextResult = (result) => {
  if (result && typeof result === 'object' && 'ok' in result) {
    return { ok: true, value: result.ok };
  }
  if (result && typeof result === 'object' && 'err' in result) {
    return { ok: false, error: result.err };
  }
  return { ok: false, error: 'unknown result' };
};

const bytesToHex = (bytes) => Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('');

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
    logoutBtn: '退出登录',
    principalLabel: '当前 Principal',
    loginDone: '登录成功',
    logoutDone: '已切回匿名身份',
    loginUnsupported: '无法加载 Identity 登录模块',
    loginProviderMissing: '当前网络缺少本地 Internet Identity 配置（CANISTER_ID_INTERNET_IDENTITY）',
    homeTitle: '功能入口',
    homeHint: '点击任意功能，进入独立全屏操作界面',
    backHome: '返回主页',
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
    homeAtoBEncryptAction: 'A 加密生成密文',
    homeAtoBDecryptAction: 'B 解密密文',
    homeAtoBPayload: 'A 发给 B 的密闻：节点汇合时间改为 20:00',
    homeAtoBRecipient: 'B Principal ID',
    homeAtoBPlaintext: 'A 要发送的明文',
    homeAtoBEncryptCard: 'A 侧：加密',
    homeAtoBDecryptCard: 'B 侧：解密',
    homeAtoBCiphertextOut: 'A 生成的密文',
    homeAtoBCiphertextIn: 'B 输入密文',
    homeAtoBOut: 'B 解密后看到',
    homeAtoBInvalidPrincipal: 'B principal 格式无效',
    homeAtoBCiphertextFormatError: '密文格式错误',
    homeAtoBIdentityMismatch: '当前登录身份不是密文目标 B',
    homeAtoBNeedLogin: '请先登录身份再执行',
    homeAtoBEmptyPlaintext: '发送明文不能为空',
    homeAtoBUnsupportedCipher: '当前 VetKeys 版本不支持密文序列化/反序列化',
    homeSignTitle: 'A 发文字，B 按 A principal 验签',
    homeSignDesc: 'A 用 Ed25519 私钥签名；B 用公钥验签，并验证公钥推导 principal 与 A 的 principal 一致。',
    homeSignAction: 'A 签名并让 B 验签',
    homeSignPayload: 'A 广播：版本 1.2.6 已冻结',
    homeSignPrincipalOut: 'A Principal',
    homeSignPublicKeyOut: 'A 公钥(hex)',
    homeSignSignatureOut: 'A 签名(hex)',
    homeSignVerifyOut: 'B 验签结果',
    homeSignVerifyPass: '通过（签名有效且 principal 匹配）',
    homeSignVerifyFail: '失败（签名无效或 principal 不匹配）',
    homeSignUnsupported: '当前环境不支持 WebCrypto Ed25519',
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
    logoutBtn: 'Logout',
    principalLabel: 'Current Principal',
    loginDone: 'Login success',
    logoutDone: 'Switched back to anonymous identity',
    loginUnsupported: 'Unable to load identity login module',
    loginProviderMissing: 'Local Internet Identity is not configured for this network (CANISTER_ID_INTERNET_IDENTITY)',
    homeTitle: 'Feature Entry',
    homeHint: 'Click any feature to open its full-screen operation page',
    backHome: 'Back to Home',
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
    homeAtoBEncryptAction: 'A Encrypt To Ciphertext',
    homeAtoBDecryptAction: 'B Decrypt Ciphertext',
    homeAtoBPayload: 'Secret from A to B: meet at node at 20:00',
    homeAtoBRecipient: 'B Principal ID',
    homeAtoBPlaintext: 'Plaintext from A',
    homeAtoBEncryptCard: 'A Side: Encrypt',
    homeAtoBDecryptCard: 'B Side: Decrypt',
    homeAtoBCiphertextOut: 'Ciphertext produced by A',
    homeAtoBCiphertextIn: 'Ciphertext input by B',
    homeAtoBOut: 'B decrypted text',
    homeAtoBInvalidPrincipal: 'Invalid B principal format',
    homeAtoBCiphertextFormatError: 'Invalid ciphertext format',
    homeAtoBIdentityMismatch: 'Current login identity is not ciphertext target B',
    homeAtoBNeedLogin: 'Please login before executing this flow',
    homeAtoBEmptyPlaintext: 'Plaintext must not be empty',
    homeAtoBUnsupportedCipher: 'Current VetKeys version does not support ciphertext serialization/deserialization',
    homeSignTitle: 'A Sends Text, B Verifies By A Principal',
    homeSignDesc: 'A signs with Ed25519 private key; B verifies signature and checks derived principal matches A principal.',
    homeSignAction: 'A Sign, B Verify',
    homeSignPayload: 'A broadcast: release 1.2.6 is frozen',
    homeSignPrincipalOut: 'A Principal',
    homeSignPublicKeyOut: 'A Public Key (hex)',
    homeSignSignatureOut: 'A Signature (hex)',
    homeSignVerifyOut: 'B Verification',
    homeSignVerifyPass: 'PASS (signature valid and principal matched)',
    homeSignVerifyFail: 'FAIL (invalid signature or principal mismatch)',
    homeSignUnsupported: 'WebCrypto Ed25519 is not supported in this environment',
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
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const [publicKeyHex, setPublicKeyHex] = useState('');
  const [encryptedKeyHex, setEncryptedKeyHex] = useState('');
  const [aToBRecipientPrincipal, setAtoBRecipientPrincipal] = useState('');
  const [aToBPlaintext, setAtoBPlaintext] = useState('');
  const [aToBCiphertextOut, setAtoBCiphertextOut] = useState('');
  const [aToBCiphertextIn, setAtoBCiphertextIn] = useState('');
  const [aToBOutput, setAtoBOutput] = useState('');
  const [signedByAPrincipal, setSignedByAPrincipal] = useState('');
  const [signedByAPublicKey, setSignedByAPublicKey] = useState('');
  const [signedByASignature, setSignedByASignature] = useState('');
  const [verifyByBResult, setVerifyByBResult] = useState('');

  const t = messages[lang];
  const actorReady = Boolean(backendActor);

  useEffect(() => {
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
    document.title = t.pageTitle;
  }, [lang, t.pageTitle]);

  useEffect(() => {
    if (!aToBPlaintext) {
      setAtoBPlaintext(t.homeAtoBPayload);
    }
  }, [aToBPlaintext, t.homeAtoBPayload]);

  const switchIdentity = (identity) => {
    if (!canisterId) {
      setBackendActor(undefined);
      setCurrentPrincipalText(Principal.anonymous().toText());
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

  const featureItems = useMemo(
    () => [
      { id: 'aToB', title: t.homeAtoBTitle, desc: t.homeAtoBDesc },
      { id: 'aSignVerify', title: t.homeSignTitle, desc: t.homeSignDesc }
    ],
    [
      t.homeAtoBTitle,
      t.homeAtoBDesc,
      t.homeSignTitle,
      t.homeSignDesc
    ]
  );

  const activeItem = featureItems.find((item) => item.id === activeFeature) ?? null;
  const activeMessageText = activeFeature === 'aToB' ? t.homeAtoBPayload : activeFeature === 'aSignVerify' ? t.homeSignPayload : DEFAULT_MESSAGE;

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

      const { identityProvider } = providerConfig;
      try {
        await new Promise((resolve, reject) => {
          client.login({
            identityProvider,
            onSuccess: resolve,
            onError: (error) => reject(error)
          });
        });
      } catch (error) {
        setStatus(`${t.actionFailed}: ${t.loginUnsupported}`);
        return;
      }

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
      const ciphertextHex = bytesToHex(serializeIbeCiphertext(ciphertext));

      const envelope = {
        version: 1,
        keyName: DEFAULT_KEY_NAME,
        context: DEFAULT_CONTEXT,
        recipientPrincipal: recipientPrincipal.toText(),
        derivedPublicKeyHex: publicKeyResult.value,
        ciphertextHex
      };

      const envelopeText = JSON.stringify(envelope);
      setPublicKeyHex(publicKeyResult.value);
      setAtoBCiphertextOut(envelopeText);
      setAtoBCiphertextIn(envelopeText);
      setAtoBOutput('');
      setStatus(t.homeAtoBEncryptAction);
    });
  };

  const handleBDecryptCiphertext = async () => {
    await runAction('bDecrypt', async () => {
      if (!ensureLoggedIn()) {
        return;
      }

      let envelope;
      try {
        envelope = JSON.parse(aToBCiphertextIn.trim());
      } catch (_) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBCiphertextFormatError}`);
        return;
      }

      if (
        !envelope ||
        typeof envelope !== 'object' ||
        typeof envelope.ciphertextHex !== 'string' ||
        typeof envelope.derivedPublicKeyHex !== 'string' ||
        typeof envelope.recipientPrincipal !== 'string'
      ) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBCiphertextFormatError}`);
        return;
      }

      if (envelope.recipientPrincipal !== currentPrincipalText) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBIdentityMismatch}`);
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
      const keyName = typeof envelope.keyName === 'string' && envelope.keyName ? envelope.keyName : DEFAULT_KEY_NAME;
      const context = typeof envelope.context === 'string' && envelope.context ? envelope.context : DEFAULT_CONTEXT;
      const deriveResult = parseTextResult(await backendActor.vetkdDeriveKeyExample(transportPublicKeyBytes, keyName, context));
      if (!deriveResult.ok) {
        setStatus(`${t.actionFailed}: ${deriveResult.error}`);
        return;
      }

      const encryptedKeyBytes = parseHexToBytes(deriveResult.value);
      const derivedPublicKeyBytes = parseHexToBytes(envelope.derivedPublicKeyHex);
      const ciphertextBytes = parseHexToBytes(envelope.ciphertextHex);
      if (!encryptedKeyBytes.ok || !derivedPublicKeyBytes.ok || !ciphertextBytes.ok) {
        setStatus(`${t.actionFailed}: ${t.homeAtoBCiphertextFormatError}`);
        return;
      }

      const encryptedVetKey = new EncryptedVetKey(Uint8Array.from(encryptedKeyBytes.bytes));
      const derivedPublicKey = DerivedPublicKey.deserialize(Uint8Array.from(derivedPublicKeyBytes.bytes));
      const identityBytes = Principal.fromText(currentPrincipalText).toUint8Array();
      const vetKey = encryptedVetKey.decryptAndVerify(transportSecretKey, derivedPublicKey, identityBytes);
      const ciphertext = deserializeIbeCiphertext(IbeCiphertext, Uint8Array.from(ciphertextBytes.bytes));
      const decrypted = ciphertext.decrypt(vetKey);

      setPublicKeyHex(envelope.derivedPublicKeyHex);
      setEncryptedKeyHex(deriveResult.value);
      setAtoBOutput(new TextDecoder().decode(decrypted));
      setStatus(t.homeAtoBDecryptAction);
    });
  };

  const handleSignAndVerifyHomeAction = async () => {
    await runLocalAction('aSignVerify', async () => {
      if (!globalThis.crypto?.subtle) {
        setStatus(`${t.actionFailed}: ${t.homeSignUnsupported}`);
        return;
      }

      let keyPair;
      try {
        keyPair = await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      } catch (_) {
        setStatus(`${t.actionFailed}: ${t.homeSignUnsupported}`);
        return;
      }

      const messageBytes = new TextEncoder().encode(t.homeSignPayload);
      const publicKeyBytes = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', keyPair.publicKey));
      const signatureBytes = new Uint8Array(await globalThis.crypto.subtle.sign('Ed25519', keyPair.privateKey, messageBytes));

      const principalA = Principal.selfAuthenticating(publicKeyBytes).toText();
      const publicKeyHex = bytesToHex(publicKeyBytes);
      const signatureHex = bytesToHex(signatureBytes);

      const parsedPublic = parseHexToBytes(publicKeyHex);
      const parsedSignature = parseHexToBytes(signatureHex);
      if (!parsedPublic.ok || !parsedSignature.ok) {
        setStatus(`${t.actionFailed}: invalid hex data`);
        return;
      }

      const receivedPublicKey = Uint8Array.from(parsedPublic.bytes);
      const receivedSignature = Uint8Array.from(parsedSignature.bytes);
      const derivedPrincipalByB = Principal.selfAuthenticating(receivedPublicKey).toText();
      const principalMatched = derivedPrincipalByB === principalA;

      const verifyKey = await globalThis.crypto.subtle.importKey('raw', receivedPublicKey, { name: 'Ed25519' }, true, ['verify']);
      const signatureValid = await globalThis.crypto.subtle.verify('Ed25519', verifyKey, receivedSignature, messageBytes);

      setSignedByAPrincipal(principalA);
      setSignedByAPublicKey(publicKeyHex);
      setSignedByASignature(signatureHex);
      setVerifyByBResult(signatureValid && principalMatched ? t.homeSignVerifyPass : t.homeSignVerifyFail);
      setStatus(t.homeSignAction);
    });
  };

  const currentAction = (() => {
    if (activeFeature === 'aSignVerify') {
      return { id: 'aSignVerify', label: t.homeSignAction, run: handleSignAndVerifyHomeAction };
    }
    return null;
  })();

  const renderFeatureResult = () => {
    if (activeFeature === 'aSignVerify') {
      return (
        <>
          <p className="output-line">
            {t.messageLabel}: <strong>{t.homeSignPayload}</strong>
          </p>
          <p className="output-line">
            {t.homeSignPrincipalOut}: <strong>{signedByAPrincipal || '-'}</strong>
          </p>
          <p className="output-line">
            {t.homeSignPublicKeyOut}: <strong>{signedByAPublicKey || '-'}</strong>
          </p>
          <p className="output-line">
            {t.homeSignSignatureOut}: <strong>{signedByASignature || '-'}</strong>
          </p>
          <p className="output-line">
            {t.homeSignVerifyOut}: <strong>{verifyByBResult || '-'}</strong>
          </p>
        </>
      );
    }
    return null;
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
        <p className="status-line">{status || t.idle}</p>
      </section>

      <section className="login-ribbon">
        <div className="login-copy">
          <p className="login-title">{t.loginTitle}</p>
          <p className="login-hint">{t.loginHint}</p>
        </div>
        <div className="login-actions">
          <button className="login-btn-main" disabled={busy === 'login'} onClick={handleLogin} type="button">
            {busy === 'login' ? t.running : t.loginBtn}
          </button>
          <button className="logout-btn-main" disabled={busy === 'logout'} onClick={handleLogout} type="button">
            {busy === 'logout' ? t.running : t.logoutBtn}
          </button>
          <p className="login-principal">
            {t.principalLabel}: <strong>{currentPrincipalText}</strong> {isLoggedIn ? '(login)' : '(anonymous)'}
          </p>
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

      {activeItem && (currentAction || activeFeature === 'aToB') ? (
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
              <h2 className="feature-title">{activeItem.title}</h2>
              <p className="feature-desc">{activeItem.desc}</p>
              {activeFeature === 'aToB' ? (
                <>
                  <p className="feature-desc">{t.moduleHint}</p>
                  <p className="feature-desc">
                    {t.principalLabel}: <strong>{currentPrincipalText}</strong> {isLoggedIn ? '(login)' : '(anonymous)'}
                  </p>
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
                        <textarea id="aToBCiphertextOut" className="text-area" readOnly value={aToBCiphertextOut} />
                      </label>
                    </article>

                    <article className="a2b-card">
                      <h3 className="a2b-card-title">{t.homeAtoBDecryptCard}</h3>
                      <label className="field" htmlFor="aToBCiphertextIn">
                        <span>{t.homeAtoBCiphertextIn}</span>
                        <textarea
                          id="aToBCiphertextIn"
                          className="text-area"
                          value={aToBCiphertextIn}
                          onChange={(event) => setAtoBCiphertextIn(event.target.value)}
                        />
                      </label>
                      <button className="action-btn" disabled={busy === 'bDecrypt'} onClick={handleBDecryptCiphertext} type="button">
                        {busy === 'bDecrypt' ? t.running : t.homeAtoBDecryptAction}
                      </button>
                      <p className="output-line">
                        {t.homeAtoBOut}: <strong>{aToBOutput || '-'}</strong>
                      </p>
                      <p className="output-line">
                        {t.publicKeyOut}: <strong>{publicKeyHex || '-'}</strong>
                      </p>
                      <p className="output-line">
                        {t.encryptedKeyOut}: <strong>{encryptedKeyHex || '-'}</strong>
                      </p>
                    </article>
                  </div>
                </>
              ) : (
                <>
                  <p className="feature-desc">{t.moduleHint}</p>

                  <div className="feature-meta">
                    <span className="meta-chip">
                      {t.keyNameLabel}: {DEFAULT_KEY_NAME}
                    </span>
                    <span className="meta-chip">
                      {t.contextLabel}: {DEFAULT_CONTEXT}
                    </span>
                    <span className="meta-chip">
                      {t.messageLabel}: {activeMessageText}
                    </span>
                  </div>

                  <div className="action-zone">
                    <button className="action-btn" disabled={busy === currentAction.id} onClick={currentAction.run} type="button">
                      {busy === currentAction.id ? t.running : currentAction.label}
                    </button>
                  </div>

                  <section className="result-box">{renderFeatureResult()}</section>
                </>
              )}
            </section>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default App;
