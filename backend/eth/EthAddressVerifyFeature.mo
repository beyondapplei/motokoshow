import Array "mo:base/Array"; // 引入数组工具，用于消息哈希长度校验。
import Blob "mo:base/Blob"; // 引入 Blob 工具，用于管理 canister 参数编码。
import Error "mo:base/Error"; // 引入 Error 工具，用于返回系统调用错误信息。
import ExperimentalCycles "mo:base/ExperimentalCycles"; // 引入 cycles 工具，用于附加管理 canister 调用 cycles。
import Nat8 "mo:base/Nat8"; // 引入 Nat8，用于消息哈希字节数组类型声明。
import Principal "mo:base/Principal"; // 引入 Principal，用于 caller 派生路径构造。
import Text "mo:base/Text"; // 引入 Text，用于结果类型定义。
import ChainKeyFeature "./ChainKeyFeature"; // 引入链钥签名模块（eth 功能目录内），复用 ECDSA 类型与辅助函数。
import HexCodec "./HexCodec"; // 引入十六进制编码工具模块（eth 功能目录内），统一输出 hex。

module { // 定义 ETH 地址验签功能模块，对应主页“ETH 地址验证签名”功能所需后端能力。
  public type TextResult = { // 定义文本结果类型，与 app.mo 对外返回结构保持一致。
    #ok : Text; // 成功分支，携带文本结果。
    #err : Text; // 失败分支，携带错误信息。
  }; // 结束 TextResult 类型定义。

  // 用途：读取当前 caller 对应的 Threshold ECDSA 派生公钥（供前端推导 ETH 地址）。
  // 用法：传入 caller 与 keyName，成功返回压缩 secp256k1 公钥 hex 文本。
  public func ecdsaPublicKeyExample(caller : Principal, keyName : Text) : async TextResult { // 定义读取 ECDSA 公钥示例函数。
    let keyId = ChainKeyFeature.buildEcdsaKeyId(keyName); // 构造 ECDSA key_id 参数。
    let derivationPath = ChainKeyFeature.ecdsaDerivationPathForCaller(caller); // 构造基于 caller 的派生路径。
    let ic00EcdsaQuery : actor { // 定义本次调用使用的 management actor（ecdsa_public_key 接口）。
      ecdsa_public_key : shared ChainKeyFeature.ECDSAPublicKeyArgs -> async ChainKeyFeature.ECDSAPublicKeyResult; // 声明 ecdsa_public_key 接口签名。
    } = actor ("aaaaa-aa"); // 绑定管理 canister 主体。

    try { // 开始捕获系统调用异常。
      let result = await ic00EcdsaQuery.ecdsa_public_key({ // 调用管理 canister 的 ecdsa_public_key。
        canister_id = null; // 使用当前 canister 上下文。
        derivation_path = derivationPath; // 传入 caller 派生路径。
        key_id = keyId; // 传入 ECDSA key_id。
      }); // 结束管理 canister 调用。

      #ok(HexCodec.blobToHex(result.public_key)); // 返回派生公钥 hex 文本。
    } catch (error) { // 捕获调用异常。
      #err("ecdsa_public_key failed: " # Error.message(error)); // 返回错误文本。
    }; // 结束异常处理。
  }; // 结束 ecdsaPublicKeyExample 函数。

  // 用途：使用当前 caller 对应的 Threshold ECDSA 私钥对 32 字节消息哈希签名。
  // 用法：前端先按 ETH personal_sign 规则计算消息哈希，再把 32 字节 hash 传入，成功返回 64 字节签名 hex。
  public func ecdsaSignMessageHashExample( // 定义 ECDSA 签名示例函数。
    caller : Principal, // 当前登录调用方 principal（用于派生路径绑定）。
    messageHash : [Nat8], // 32 字节消息哈希（ETH 验签输入）。
    keyName : Text // ECDSA key 名称。
  ) : async TextResult { // 返回文本结果。
    if (Array.size(messageHash) != 32) { // 校验消息哈希必须是 32 字节。
      return #err("messageHash must be exactly 32 bytes"); // 返回参数错误。
    }; // 结束参数校验。

    let keyId = ChainKeyFeature.buildEcdsaKeyId(keyName); // 构造 ECDSA key_id 参数。
    let derivationPath = ChainKeyFeature.ecdsaDerivationPathForCaller(caller); // 构造基于 caller 的派生路径。
    let signCycles = ChainKeyFeature.ecdsaSignCyclesForKeyName(keyName); // 计算本次签名需要附加的 cycles。
    let ic00EcdsaUpdate : actor { // 定义本次调用使用的 management actor（sign_with_ecdsa 接口）。
      sign_with_ecdsa : shared ChainKeyFeature.SignWithECDSAArgs -> async ChainKeyFeature.SignWithECDSAResult; // 声明 sign_with_ecdsa 接口签名。
    } = actor ("aaaaa-aa"); // 绑定管理 canister 主体。

    try { // 开始捕获系统调用异常。
      ExperimentalCycles.add<system>(signCycles); // 在本次调用前附加 sign_with_ecdsa 需要的 cycles。
      let result = await ic00EcdsaUpdate.sign_with_ecdsa({ // 调用管理 canister 的 sign_with_ecdsa。
        message_hash = Blob.fromArray(messageHash); // 传入 32 字节消息哈希。
        derivation_path = derivationPath; // 传入 caller 派生路径。
        key_id = keyId; // 传入 ECDSA key_id。
      }); // 结束管理 canister 调用。

      #ok(HexCodec.blobToHex(result.signature)); // 返回签名 hex 文本（r||s）。
    } catch (error) { // 捕获调用异常。
      #err("sign_with_ecdsa failed: " # Error.message(error)); // 返回错误文本。
    }; // 结束异常处理。
  }; // 结束 ecdsaSignMessageHashExample 函数。
}; // 结束 ETH 地址验签功能模块定义。
