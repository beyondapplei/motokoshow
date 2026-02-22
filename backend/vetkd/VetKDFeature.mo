import Blob "mo:base/Blob"; // 引入 Blob 工具，用于上下文与二进制类型。
import Principal "mo:base/Principal"; // 引入 Principal，用于参数类型定义。
import Text "mo:base/Text"; // 引入 Text，用于字符串处理。

module { // 定义 VetKD 功能模块，集中管理 VetKD 类型与辅助函数。
  public type VetKDCurve = { // 定义 VetKD 曲线类型。
    #bls12_381_g2; // 当前示例使用的 VetKD 曲线分支。
  }; // 结束 VetKDCurve 类型定义。

  public type VetKDKeyId = { // 定义 VetKD key_id 结构。
    curve : VetKDCurve; // key_id 的曲线字段。
    name : Text; // key_id 的名称字段。
  }; // 结束 VetKDKeyId 类型定义。

  public type VetKDPublicKeyArgs = { // 定义 vetkd_public_key 参数结构。
    canister_id : ?Principal; // 可选 canister_id，null 表示当前 canister。
    context : Blob; // 上下文二进制。
    key_id : VetKDKeyId; // key_id 参数。
  }; // 结束 VetKDPublicKeyArgs 类型定义。

  public type VetKDPublicKeyResult = { // 定义 vetkd_public_key 返回结构。
    public_key : Blob; // 返回的公钥二进制。
  }; // 结束 VetKDPublicKeyResult 类型定义。

  public type VetKDDeriveKeyArgs = { // 定义 vetkd_derive_key 参数结构。
    context : Blob; // 上下文二进制。
    input : Blob; // 绑定身份输入二进制。
    key_id : VetKDKeyId; // key_id 参数。
    transport_public_key : Blob; // 客户端 transport 公钥二进制。
  }; // 结束 VetKDDeriveKeyArgs 类型定义。

  public type VetKDDeriveKeyResult = { // 定义 vetkd_derive_key 返回结构。
    encrypted_key : Blob; // 返回加密后的派生密钥。
  }; // 结束 VetKDDeriveKeyResult 类型定义。

  public let deriveKeyCycles : Nat = 26_153_846_153; // 定义 vetkd_derive_key 示例调用所需 cycles 常量。

  // 用途：判断文本是否非空（模块内部复用）。
  // 用法：传入任意 Text，非空返回 true。
  func hasText(content : Text) : Bool { // 定义非空判断函数。
    Text.size(content) > 0; // 返回文本长度是否大于 0。
  }; // 结束 hasText 函数。

  // 用途：规范化 VetKD key 名称。
  // 用法：若传空字符串则回退默认 key 名称。
  public func normalizeKeyName(raw : Text) : Text { // 定义 key 名称规范化函数。
    if (hasText(raw)) { // 判断入参是否非空。
      raw; // 非空时直接使用入参。
    } else { // 空字符串分支。
      "test_key_1"; // 返回默认 key 名称。
    }; // 结束 key 名称规范化判断。
  }; // 结束 normalizeKeyName 函数。

  // 用途：构造 VetKD 的 key_id。
  // 用法：传入 keyName，返回包含 curve + name 的结构。
  public func buildKeyId(name : Text) : VetKDKeyId { // 定义 key_id 构造函数。
    { // 返回 VetKDKeyId 记录。
      curve = #bls12_381_g2; // 固定使用 bls12_381_g2 曲线。
      name = normalizeKeyName(name); // 使用规范化后的 key 名称。
    }; // 结束 VetKDKeyId 记录构造。
  }; // 结束 buildKeyId 函数。

  // 用途：把 context 文本转为 Blob。
  // 用法：非空时 UTF-8 编码；为空时返回空 Blob。
  public func contextBlob(contextName : Text) : Blob { // 定义 context 编码函数。
    if (hasText(contextName)) { // 判断 context 是否非空。
      Text.encodeUtf8(contextName); // 非空时做 UTF-8 编码。
    } else { // 空字符串分支。
      Blob.fromArray([]); // 返回空 Blob。
    }; // 结束 context 编码判断。
  }; // 结束 contextBlob 函数。
}; // 结束 VetKD 功能模块定义。
