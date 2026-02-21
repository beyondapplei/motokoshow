import Array "mo:base/Array"; // 引入数组工具，保留旧稳定变量类型时会用到。
import Blob "mo:base/Blob"; // 引入 Blob 工具，用于二进制和文本编码。
import Error "mo:base/Error"; // 引入 Error，用于捕获并返回系统调用错误信息。
import Nat8 "mo:base/Nat8"; // 引入 Nat8，用于字节转十六进制。
import Principal "mo:base/Principal"; // 引入 Principal，用于 caller 身份和输入绑定。
import Text "mo:base/Text"; // 引入 Text，用于字符串处理。

persistent actor MotokoShowcase { // 定义持久化 actor，保证变量跨升级保留。
  public type CapabilityTier = { // 保留旧版本类型：能力层级枚举（兼容稳定内存）。
    #Core; // 保留 Core 枚举分支。
    #Advanced; // 保留 Advanced 枚举分支。
    #Expert; // 保留 Expert 枚举分支。
  }; // 结束 CapabilityTier 类型定义。

  public type Capability = { // 保留旧版本类型：能力记录（兼容稳定内存）。
    id : Nat; // 记录 id 字段。
    title : Text; // 记录标题字段。
    detail : Text; // 记录详情字段。
    tier : CapabilityTier; // 记录层级字段。
    tags : [Text]; // 记录标签数组字段。
    enabled : Bool; // 记录启用状态字段。
    owner : Principal; // 记录 owner principal 字段。
    createdAt : Int; // 记录创建时间字段。
  }; // 结束 Capability 类型定义。

  public type TextResult = { // 定义文本结果类型，仅返回 ok/err 文本。
    #ok : Text; // 成功分支，携带文本值。
    #err : Text; // 失败分支，携带错误文本。
  }; // 结束 TextResult 类型定义。

  public type VetKDCurve = { // 定义 VetKD 曲线类型。
    #bls12_381_g2; // 当前示例使用的 VetKD 曲线。
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

  public type SchnorrAlgorithm = { // 定义 Schnorr 算法类型（仅用于稳定类型兼容）。
    #ed25519; // Schnorr 算法分支：ed25519。
    #bip340secp256k1; // Schnorr 算法分支：bip340secp256k1。
  }; // 结束 SchnorrAlgorithm 类型定义。

  public type SchnorrAux = { // 定义 Schnorr 辅助参数类型（仅用于稳定类型兼容）。
    #bip341 : { // 定义 bip341 辅助参数分支。
      merkle_root_hash : Blob; // bip341 的 merkle root hash 字段。
    }; // 结束 bip341 分支字段定义。
  }; // 结束 SchnorrAux 类型定义。

  public type SchnorrKeyId = { // 定义 Schnorr key_id 结构（仅用于稳定类型兼容）。
    algorithm : SchnorrAlgorithm; // Schnorr key_id 的算法字段。
    name : Text; // Schnorr key_id 的名称字段。
  }; // 结束 SchnorrKeyId 类型定义。

  public type SignWithSchnorrArgs = { // 定义 sign_with_schnorr 参数结构（仅用于稳定类型兼容）。
    message : Blob; // 待签名消息二进制。
    derivation_path : [Blob]; // 派生路径参数。
    key_id : SchnorrKeyId; // Schnorr key_id 参数。
    aux : ?SchnorrAux; // 可选辅助参数。
  }; // 结束 SignWithSchnorrArgs 类型定义。

  public type SignWithSchnorrResult = { // 定义 sign_with_schnorr 返回结构（仅用于稳定类型兼容）。
    signature : Blob; // 签名结果二进制。
  }; // 结束 SignWithSchnorrResult 类型定义。

  let ic00 : actor { // 绑定管理 canister（aaaaa-aa）的 VetKD 接口。
    sign_with_schnorr : shared SignWithSchnorrArgs -> async SignWithSchnorrResult; // 兼容保留：旧版本稳定类型中的 Schnorr 签名接口字段。
    vetkd_public_key : shared query VetKDPublicKeyArgs -> async VetKDPublicKeyResult; // 声明获取 VetKD 公钥接口。
    vetkd_derive_key : shared query VetKDDeriveKeyArgs -> async VetKDDeriveKeyResult; // 声明派生加密密钥接口。
  } = actor ("aaaaa-aa"); // 完成管理 canister actor 绑定。

  // ---- 以下变量仅用于升级兼容，避免旧稳定变量在升级时被隐式丢弃 ----
  var greetingPrefix : Text = "Hello, "; // 兼容保留：旧问候前缀稳定变量。
  var nextCapabilityId : Nat = 1; // 兼容保留：旧能力自增 id 稳定变量。
  var updateCount : Nat = 0; // 兼容保留：旧更新计数稳定变量。
  var admin : ?Principal = null; // 兼容保留：旧管理员稳定变量。
  var capabilities : [Capability] = []; // 兼容保留：旧能力列表稳定变量。
  var logs : [Text] = []; // 兼容保留：旧日志稳定变量（当前版本不再写入日志）。
  let HEX_CHARS : [Char] = [ // 兼容保留：旧 HEX 字符表稳定变量。
    '0', // 十六进制字符 0。
    '1', // 十六进制字符 1。
    '2', // 十六进制字符 2。
    '3', // 十六进制字符 3。
    '4', // 十六进制字符 4。
    '5', // 十六进制字符 5。
    '6', // 十六进制字符 6。
    '7', // 十六进制字符 7。
    '8', // 十六进制字符 8。
    '9', // 十六进制字符 9。
    'a', // 十六进制字符 a。
    'b', // 十六进制字符 b。
    'c', // 十六进制字符 c。
    'd', // 十六进制字符 d。
    'e', // 十六进制字符 e。
    'f', // 十六进制字符 f。
  ]; // 结束 HEX 字符表。

  // 用途：判断文本是否非空。
  // 用法：传入任意 Text，非空返回 true。
  func hasText(content : Text) : Bool { // 定义非空判断函数。
    Text.size(content) > 0; // 返回文本长度是否大于 0。
  }; // 结束 hasText 函数。

  // 用途：规范化 VetKD key 名称。
  // 用法：若传空字符串则回退默认 key 名称。
  func normalizeVetKeyName(raw : Text) : Text { // 定义 key 名称规范化函数。
    if (hasText(raw)) { // 判断入参是否非空。
      raw; // 非空时直接使用入参。
    } else { // 空字符串分支。
      "test_key_1"; // 返回默认 key 名称。
    }; // 结束 key 名称规范化判断。
  }; // 结束 normalizeVetKeyName 函数。

  // 用途：构造 VetKD 的 key_id。
  // 用法：传入 keyName，返回包含 curve + name 的结构。
  func buildVetKeyId(name : Text) : VetKDKeyId { // 定义 key_id 构造函数。
    { // 返回 VetKDKeyId 记录。
      curve = #bls12_381_g2; // 固定使用 bls12_381_g2 曲线。
      name = normalizeVetKeyName(name); // 使用规范化后的 key 名称。
    }; // 结束 VetKDKeyId 记录构造。
  }; // 结束 buildVetKeyId 函数。

  // 用途：把 context 文本转为 Blob。
  // 用法：非空时 UTF-8 编码；为空时返回空 Blob。
  func contextBlob(contextName : Text) : Blob { // 定义 context 编码函数。
    if (hasText(contextName)) { // 判断 context 是否非空。
      Text.encodeUtf8(contextName); // 非空时做 UTF-8 编码。
    } else { // 空字符串分支。
      Blob.fromArray([]); // 返回空 Blob。
    }; // 结束 context 编码判断。
  }; // 结束 contextBlob 函数。

  // 用途：把单字节转成两位十六进制文本。
  // 用法：仅内部使用，供 blobToHex 逐字节编码。
  func byteHex(value : Nat8) : Text { // 定义单字节 hex 编码函数。
    let high = Nat8.toNat(value / 16); // 计算高 4 位索引。
    let low = Nat8.toNat(value % 16); // 计算低 4 位索引。
    Text.fromChar(HEX_CHARS[high]) # Text.fromChar(HEX_CHARS[low]); // 拼接两位 hex 字符并返回。
  }; // 结束 byteHex 函数。

  // 用途：把任意 Blob 转成十六进制文本。
  // 用法：用于把公钥/加密密钥等二进制结果返回给前端展示。
  func blobToHex(value : Blob) : Text { // 定义 Blob 到 hex 文本转换函数。
    var hex : Text = ""; // 初始化输出字符串。
    for (byte in Blob.toArray(value).vals()) { // 遍历 Blob 中每个字节。
      hex #= byteHex(byte); // 追加每个字节对应的两位 hex 文本。
    }; // 结束字节遍历。
    hex; // 返回最终 hex 字符串。
  }; // 结束 blobToHex 函数。

  // 用途：读取 VetKD 公钥（示例接口）。
  // 用法：传入 keyName 与 contextLabel，成功返回公钥 hex。
  public shared func vetkdPublicKeyExample(keyName : Text, contextLabel : Text) : async TextResult { // 定义获取 VetKD 公钥接口。
    let keyId = buildVetKeyId(keyName); // 构造 key_id 参数。
    let labelBlob = contextBlob(contextLabel); // 构造 context 参数。

    try { // 开始捕获系统调用异常。
      let result = await ic00.vetkd_public_key({ // 调用管理 canister 的 vetkd_public_key。
        canister_id = null; // 让系统按当前 canister 上下文处理。
        context = labelBlob; // 传入 context blob。
        key_id = keyId; // 传入 key_id。
      }); // 结束管理 canister 调用。

      #ok(blobToHex(result.public_key)); // 返回公钥 hex 文本。
    } catch (error) { // 捕获调用异常。
      #err("vetkd_public_key failed: " # Error.message(error)); // 返回错误文本。
    }; // 结束异常处理。
  }; // 结束 vetkdPublicKeyExample 接口。

  // 用途：派生加密后的 VetKD 密钥（示例接口）。
  // 用法：传入 transportPublicKey、keyName、contextLabel，成功返回 encrypted_key 的 hex。
  public shared ({ caller }) func vetkdDeriveKeyExample( // 定义派生加密密钥接口。
    transportPublicKey : [Nat8], // 客户端 transport 公钥字节数组。
    keyName : Text, // key 名称。
    contextLabel : Text // context 文本。
  ) : async TextResult { // 返回文本结果。
    if (Array.size(transportPublicKey) == 0) { // 校验 transport 公钥不能为空。
      return #err("transportPublicKey must not be empty"); // 返回参数错误。
    }; // 结束参数校验。

    let keyId = buildVetKeyId(keyName); // 构造 key_id 参数。
    let labelBlob = contextBlob(contextLabel); // 构造 context 参数。

    try { // 开始捕获系统调用异常。
      let result = await ic00.vetkd_derive_key({ // 调用管理 canister 的 vetkd_derive_key。
        context = labelBlob; // 传入 context blob。
        input = Principal.toBlob(caller); // 绑定 caller 作为派生输入。
        key_id = keyId; // 传入 key_id。
        transport_public_key = Blob.fromArray(transportPublicKey); // 传入 transport 公钥 blob。
      }); // 结束管理 canister 调用。

      #ok(blobToHex(result.encrypted_key)); // 返回加密密钥 hex 文本。
    } catch (error) { // 捕获调用异常。
      #err("vetkd_derive_key failed: " # Error.message(error)); // 返回错误文本。
    }; // 结束异常处理。
  }; // 结束 vetkdDeriveKeyExample 接口。

  // 用途：返回当前调用方用于 VetKD input 的字节（hex）。
  // 用法：前端做 decryptAndVerify 时使用本接口结果与后端 input 保持一致。
  public shared query ({ caller }) func vetkdCallerInputHex() : async Text { // 定义 caller input 导出接口。
    blobToHex(Principal.toBlob(caller)); // 返回 caller principal blob 的 hex。
  }; // 结束 vetkdCallerInputHex 接口。
}; // 结束 actor 定义。
