import Blob "mo:base/Blob"; // 引入 Blob 工具，用于管理 canister 参数类型。
import Principal "mo:base/Principal"; // 引入 Principal，用于 caller 派生路径构造。
import Text "mo:base/Text"; // 引入 Text，用于字符串处理。

module { // 定义链钥签名功能模块，当前集中管理 Threshold ECDSA 类型与辅助函数。
  public type SchnorrAlgorithm = { // 定义 Schnorr 算法类型（iiwallet 内部用于读取 ed25519 公钥）。
    #ed25519; // ed25519 分支（用于 Solana 地址公钥读取）。
    #bip340secp256k1; // 保留 bip340 分支，便于后续扩展 BTC Taproot 风格签名/公钥读取。
  }; // 结束 SchnorrAlgorithm 类型定义。

  public type SchnorrKeyId = { // 定义 Schnorr key_id 结构（iiwallet 内部使用）。
    algorithm : SchnorrAlgorithm; // Schnorr 算法字段。
    name : Text; // key 名称字段。
  }; // 结束 SchnorrKeyId 类型定义。

  public type SchnorrPublicKeyArgs = { // 定义 schnorr_public_key 参数结构。
    canister_id : ?Principal; // 可选 canister_id，null 表示当前 canister。
    derivation_path : [Blob]; // Schnorr 派生路径数组。
    key_id : SchnorrKeyId; // Schnorr key_id 参数。
  }; // 结束 SchnorrPublicKeyArgs 类型定义。

  public type SchnorrPublicKeyResult = { // 定义 schnorr_public_key 返回结构。
    public_key : Blob; // 返回派生公钥二进制（ed25519 为 32 字节公钥）。
    chain_code : Blob; // 返回链码（当前示例前端不使用）。
  }; // 结束 SchnorrPublicKeyResult 类型定义。

  public type ECDSACurve = { // 定义 ECDSA 曲线类型（Threshold ECDSA 使用）。
    #secp256k1; // ECDSA 曲线分支：secp256k1（ETH/BTC 常用）。
  }; // 结束 ECDSACurve 类型定义。

  public type ECDSAKeyId = { // 定义 ECDSA key_id 结构。
    curve : ECDSACurve; // ECDSA key_id 的曲线字段。
    name : Text; // ECDSA key_id 的名称字段。
  }; // 结束 ECDSAKeyId 类型定义。

  public type ECDSAPublicKeyArgs = { // 定义 ecdsa_public_key 参数结构。
    canister_id : ?Principal; // 可选 canister_id，null 表示当前 canister。
    derivation_path : [Blob]; // ECDSA 派生路径数组。
    key_id : ECDSAKeyId; // ECDSA key_id 参数。
  }; // 结束 ECDSAPublicKeyArgs 类型定义。

  public type ECDSAPublicKeyResult = { // 定义 ecdsa_public_key 返回结构。
    public_key : Blob; // 返回的派生公钥二进制（通常为压缩 secp256k1 公钥）。
    chain_code : Blob; // 返回的链码（当前示例前端不使用）。
  }; // 结束 ECDSAPublicKeyResult 类型定义。

  public type SignWithECDSAArgs = { // 定义 sign_with_ecdsa 参数结构。
    message_hash : Blob; // 32 字节消息哈希。
    derivation_path : [Blob]; // ECDSA 派生路径数组。
    key_id : ECDSAKeyId; // ECDSA key_id 参数。
  }; // 结束 SignWithECDSAArgs 类型定义。

  public type SignWithECDSAResult = { // 定义 sign_with_ecdsa 返回结构。
    signature : Blob; // 返回 64 字节紧凑签名（r||s）。
  }; // 结束 SignWithECDSAResult 类型定义。

  public let signCycles : Nat = 26_153_846_153; // 定义链钥签名示例调用统一附加的 cycles 常量。

  // 用途：判断文本是否非空（模块内部复用）。
  // 用法：传入任意 Text，非空返回 true。
  func hasText(content : Text) : Bool { // 定义非空判断函数。
    Text.size(content) > 0; // 返回文本长度是否大于 0。
  }; // 结束 hasText 函数。

  // 用途：规范化 ECDSA key 名称。
  // 用法：本地环境建议传 dfx_test_key，主网演示可传 test_key_1 或 key_1。
  public func normalizeEcdsaKeyName(raw : Text) : Text { // 定义 ECDSA key 名称规范化函数。
    if (hasText(raw)) { // 判断入参是否非空。
      raw; // 非空时直接使用入参。
    } else { // 空字符串分支。
      "dfx_test_key"; // 回退到本地 dfx 默认测试 key。
    }; // 结束 key 名称规范化判断。
  }; // 结束 normalizeEcdsaKeyName 函数。

  // 用途：构造 Threshold ECDSA 的 key_id。
  // 用法：当前示例固定使用 secp256k1，返回 key_id 结构给管理 canister。
  public func buildEcdsaKeyId(name : Text) : ECDSAKeyId { // 定义 ECDSA key_id 构造函数。
    { // 返回 ECDSAKeyId 记录。
      curve = #secp256k1; // 固定使用 secp256k1 曲线。
      name = normalizeEcdsaKeyName(name); // 使用规范化后的 key 名称。
    }; // 结束 ECDSAKeyId 记录构造。
  }; // 结束 buildEcdsaKeyId 函数。

  // 用途：基于 caller 构造 ECDSA 派生路径。
  // 用法：把 caller principal blob 放入单段 derivation_path，实现按身份派生。
  public func ecdsaDerivationPathForCaller(caller : Principal) : [Blob] { // 定义 ECDSA 派生路径构造函数。
    [Principal.toBlob(caller)]; // 返回仅包含 caller blob 的派生路径数组。
  }; // 结束 ecdsaDerivationPathForCaller 函数。

  // 用途：基于 caller 构造 Schnorr(ed25519) 派生路径。
  // 用法：当前与 ECDSA 一样使用 caller principal blob 作为单段派生路径。
  public func schnorrDerivationPathForCaller(caller : Principal) : [Blob] { // 定义 Schnorr 派生路径构造函数。
    [Principal.toBlob(caller)]; // 返回仅包含 caller blob 的派生路径数组。
  }; // 结束 schnorrDerivationPathForCaller 函数。

  // 用途：构造用于 Solana 地址派生的 Schnorr(ed25519) key_id。
  // 用法：复用与 ECDSA 相同的 keyName fallback 习惯（如 dfx_test_key / test_key_1）。
  public func buildSchnorrEd25519KeyId(name : Text) : SchnorrKeyId { // 定义 Schnorr(ed25519) key_id 构造函数。
    { // 返回 SchnorrKeyId 记录。
      algorithm = #ed25519; // 固定使用 ed25519 算法。
      name = normalizeEcdsaKeyName(name); // 复用现有非空规范化与默认 key 名回退逻辑。
    }; // 结束 SchnorrKeyId 记录构造。
  }; // 结束 buildSchnorrEd25519KeyId 函数。

  // 用途：按 key 名称返回 ECDSA 签名示例需要附加的 cycles。
  // 用法：当前统一返回 signCycles，多余 cycles 会退款。
  public func ecdsaSignCyclesForKeyName(keyName : Text) : Nat { // 定义 ECDSA 签名 cycles 选择函数。
    ignore normalizeEcdsaKeyName(keyName); // 保留 key 名称规范化过程，便于后续扩展差异策略。
    signCycles; // 返回统一签名 cycles 常量。
  }; // 结束 ecdsaSignCyclesForKeyName 函数。
}; // 结束链钥签名功能模块定义。
