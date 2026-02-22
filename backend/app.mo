import EthAddressVerifyFeature "./eth/EthAddressVerifyFeature"; // 引入 ETH 地址验签功能模块（已迁到 eth 目录），对应主页 ETH 签名验签页。
import MultiChainWalletFeature "./iiwallet/MultiChainWalletFeature"; // 引入多链钱包功能模块（已迁到 iiwallet 目录），对应主页多链钱包功能页后端能力。
import Nat8 "mo:base/Nat8"; // 引入 Nat8，用于公开接口参数中的字节数组类型声明。
import Text "mo:base/Text"; // 引入 Text，用于字符串处理。
import VetkdAtoBFeature "./vetkd/VetkdAtoBFeature"; // 引入 VetKD A->B 功能模块（已迁到 vetkd 目录），对应主页 A 发密文给 B。

persistent actor MotokoShowcase { // 定义持久化 actor，保证变量跨升级保留。
  public type TextResult = { // 定义文本结果类型，仅返回 ok/err 文本。
    #ok : Text; // 成功分支，携带文本值。
    #err : Text; // 失败分支，携带错误文本。
  }; // 结束 TextResult 类型定义。

  public type WalletNetworkInfo = MultiChainWalletFeature.WalletNetworkInfo; // 定义多链钱包网络信息类型（转为模块别名）。
  public type WalletOverviewResult = MultiChainWalletFeature.WalletOverviewResult; // 定义多链钱包总览结果类型（转为模块别名）。

  // 用途：读取 VetKD 公钥（示例接口）。
  // 用法：传入 keyName 与 contextLabel，成功返回公钥 hex。
  public shared func vetkdPublicKeyExample(keyName : Text, contextLabel : Text) : async TextResult { // 定义获取 VetKD 公钥接口。
    await VetkdAtoBFeature.vetkdPublicKeyExample(keyName, contextLabel); // 委托 VetKD A->B 功能模块执行公钥读取逻辑。
  }; // 结束 vetkdPublicKeyExample 接口。

  // 用途：派生加密后的 VetKD 密钥（示例接口）。
  // 用法：传入 transportPublicKey、keyName、contextLabel，成功返回 encrypted_key 的 hex。
  public shared ({ caller }) func vetkdDeriveKeyExample( // 定义派生加密密钥接口。
    transportPublicKey : [Nat8], // 客户端 transport 公钥字节数组。
    keyName : Text, // key 名称。
    contextLabel : Text // context 文本。
  ) : async TextResult { // 返回文本结果。
    await VetkdAtoBFeature.vetkdDeriveKeyExample(caller, transportPublicKey, keyName, contextLabel); // 委托 VetKD A->B 功能模块执行派生密钥逻辑。
  }; // 结束 vetkdDeriveKeyExample 接口。

  // 用途：返回当前调用方用于 VetKD input 的字节（hex）。
  // 用法：前端做 decryptAndVerify 时使用本接口结果与后端 input 保持一致。
  public shared query ({ caller }) func vetkdCallerInputHex() : async Text { // 定义 caller input 导出接口。
    VetkdAtoBFeature.vetkdCallerInputHex(caller); // 委托 VetKD A->B 功能模块返回 caller principal blob 的 hex。
  }; // 结束 vetkdCallerInputHex 接口。

  // 用途：读取当前 caller 对应的 Threshold ECDSA 派生公钥（示例接口）。
  // 用法：前端 A 登录后调用，拿到压缩 secp256k1 公钥 hex；前端再推导 ETH 地址。
  public shared ({ caller }) func ecdsaPublicKeyExample(keyName : Text) : async TextResult { // 定义读取 ECDSA 公钥接口。
    await EthAddressVerifyFeature.ecdsaPublicKeyExample(caller, keyName); // 委托 ETH 地址验签功能模块执行公钥读取逻辑。
  }; // 结束 ecdsaPublicKeyExample 接口。

  // 用途：使用当前 caller 对应的 Threshold ECDSA 私钥对 32 字节哈希签名（示例接口）。
  // 用法：前端先按 ETH 规则计算消息哈希，再把 32 字节 hash 传入本接口，成功返回 64 字节签名 hex。
  public shared ({ caller }) func ecdsaSignMessageHashExample(messageHash : [Nat8], keyName : Text) : async TextResult { // 定义 ECDSA 签名接口。
    await EthAddressVerifyFeature.ecdsaSignMessageHashExample(caller, messageHash, keyName); // 委托 ETH 地址验签功能模块执行 ECDSA 签名逻辑。
  }; // 结束 ecdsaSignMessageHashExample 接口。

  // 用途：返回多链钱包支持的网络列表（精简版）。
  // 用法：前端钱包页初始化时调用，用于构建链下拉和能力标识。
  public shared query func wallet_networks() : async [WalletNetworkInfo] { // 定义钱包网络列表接口。
    MultiChainWalletFeature.walletNetworks(); // 委托多链钱包模块返回静态网络列表。
  }; // 结束 wallet_networks 接口。

  // 用途：返回当前 caller 在指定链的钱包总览基础信息（精简版）。
  // 用法：前端切换链后调用；当前先接入 ETH/Base 链钥公钥读取，余额和资产列表后续再接入。
  public shared ({ caller }) func wallet_overview( // 定义钱包总览接口（精简版）。
    network : Text, // 目标链 id（如 eth/base/sol...）。
    rpcUrl : ?Text, // 预留：RPC 地址（当前未使用）。
    erc20TokenAddress : ?Text // 预留：ERC20 合约地址（当前未使用）。
  ) : async WalletOverviewResult { // 返回钱包总览结果。
    await MultiChainWalletFeature.walletOverview(caller, network, rpcUrl, erc20TokenAddress); // 委托多链钱包模块执行业务逻辑。
  }; // 结束 wallet_overview 接口。

}; // 结束 actor 定义。
