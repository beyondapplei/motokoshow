import Array "mo:base/Array"; // 引入数组工具，用于参数长度校验。
import Blob "mo:base/Blob"; // 引入 Blob 工具，用于管理 canister 参数与编码。
import Error "mo:base/Error"; // 引入 Error 工具，用于返回系统调用错误信息。
import ExperimentalCycles "mo:base/ExperimentalCycles"; // 引入 cycles 工具，用于附加管理 canister 调用 cycles。
import Nat8 "mo:base/Nat8"; // 引入 Nat8，用于 transport 公钥字节数组类型声明。
import Principal "mo:base/Principal"; // 引入 Principal，用于 caller 输入绑定。
import Text "mo:base/Text"; // 引入 Text，用于结果类型定义。
import HexCodec "./HexCodec"; // 引入十六进制编码工具模块（vetkd 功能目录内），统一输出 hex。
import VetKDFeature "./VetKDFeature"; // 引入 VetKD 模块（vetkd 功能目录内），复用类型与 key/context 构造逻辑。

module { // 定义 VetKD A->B 功能模块，对应主页“A 发密文给 B”功能所需后端能力。
  public type TextResult = { // 定义文本结果类型，与 app.mo 对外返回结构保持一致。
    #ok : Text; // 成功分支，携带文本结果。
    #err : Text; // 失败分支，携带错误信息。
  }; // 结束 TextResult 类型定义。

  // 用途：读取 VetKD 公钥（对应前端 A->B 加密流程的公钥获取步骤）。
  // 用法：传入 keyName 与 contextLabel，成功返回公钥 hex 文本。
  public func vetkdPublicKeyExample(keyName : Text, contextLabel : Text) : async TextResult { // 定义读取 VetKD 公钥示例函数。
    let keyId = VetKDFeature.buildKeyId(keyName); // 构造 VetKD key_id 参数。
    let labelBlob = VetKDFeature.contextBlob(contextLabel); // 构造 context 参数。
    let ic00VetkdQuery : actor { // 定义本次调用使用的 management actor（vetkd_public_key query 接口）。
      vetkd_public_key : shared query VetKDFeature.VetKDPublicKeyArgs -> async VetKDFeature.VetKDPublicKeyResult; // 声明 vetkd_public_key 接口签名。
    } = actor ("aaaaa-aa"); // 绑定管理 canister 主体。

    try { // 开始捕获系统调用异常。
      let result = await ic00VetkdQuery.vetkd_public_key({ // 调用管理 canister 的 vetkd_public_key。
        canister_id = null; // 让系统按当前 canister 上下文处理。
        context = labelBlob; // 传入 context blob。
        key_id = keyId; // 传入 key_id。
      }); // 结束管理 canister 调用。

      #ok(HexCodec.blobToHex(result.public_key)); // 返回公钥 hex 文本。
    } catch (error) { // 捕获调用异常。
      #err("vetkd_public_key failed: " # Error.message(error)); // 返回错误文本。
    }; // 结束异常处理。
  }; // 结束 vetkdPublicKeyExample 函数。

  // 用途：派生加密后的 VetKD 密钥（对应前端 A->B 解密流程的派生密钥步骤）。
  // 用法：传入 caller、transportPublicKey、keyName、contextLabel，成功返回 encrypted_key 的 hex。
  public func vetkdDeriveKeyExample( // 定义派生 VetKD 密钥示例函数。
    caller : Principal, // 当前登录调用方 principal（用于绑定派生输入）。
    transportPublicKey : [Nat8], // 前端生成的 transport 公钥字节数组。
    keyName : Text, // VetKD key 名称。
    contextLabel : Text // VetKD context 文本。
  ) : async TextResult { // 返回文本结果。
    if (Array.size(transportPublicKey) == 0) { // 校验 transport 公钥不能为空。
      return #err("transportPublicKey must not be empty"); // 返回参数错误。
    }; // 结束参数校验。

    let keyId = VetKDFeature.buildKeyId(keyName); // 构造 VetKD key_id 参数。
    let labelBlob = VetKDFeature.contextBlob(contextLabel); // 构造 context 参数。
    let ic00VetkdUpdate : actor { // 定义本次调用使用的 management actor（vetkd_derive_key update 接口）。
      vetkd_derive_key : shared VetKDFeature.VetKDDeriveKeyArgs -> async VetKDFeature.VetKDDeriveKeyResult; // 声明 vetkd_derive_key 接口签名。
    } = actor ("aaaaa-aa"); // 绑定管理 canister 主体。

    try { // 开始捕获系统调用异常。
      ExperimentalCycles.add<system>(VetKDFeature.deriveKeyCycles); // 在本次调用前附加 vetkd_derive_key 需要的 cycles。
      let result = await ic00VetkdUpdate.vetkd_derive_key({ // 调用 management canister 的 update 版 vetkd_derive_key。
        context = labelBlob; // 传入 context blob。
        input = Principal.toBlob(caller); // 绑定 caller 作为派生输入。
        key_id = keyId; // 传入 key_id。
        transport_public_key = Blob.fromArray(transportPublicKey); // 传入 transport 公钥 blob。
      }); // 结束管理 canister 调用。

      #ok(HexCodec.blobToHex(result.encrypted_key)); // 返回加密密钥 hex 文本。
    } catch (error) { // 捕获调用异常。
      #err("vetkd_derive_key failed: " # Error.message(error)); // 返回错误文本。
    }; // 结束异常处理。
  }; // 结束 vetkdDeriveKeyExample 函数。

  // 用途：返回当前调用方用于 VetKD input 的字节（hex）。
  // 用法：前端 decryptAndVerify 时调用，确保前后端使用完全一致的 caller 输入。
  public func vetkdCallerInputHex(caller : Principal) : Text { // 定义导出 caller input hex 函数。
    HexCodec.blobToHex(Principal.toBlob(caller)); // 返回 caller principal blob 的 hex 文本。
  }; // 结束 vetkdCallerInputHex 函数。
}; // 结束 VetKD A->B 功能模块定义。
