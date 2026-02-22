import Error "mo:base/Error"; // 引入 Error，用于把管理 canister 调用错误转成文本。
import Principal "mo:base/Principal"; // 引入 Principal，用于基于 caller 构造派生路径。
import Text "mo:base/Text"; // 引入 Text，用于错误文本与 key 名称处理。
import AppConfig "../config/AppConfig"; // 引入应用配置，读取环境默认 ECDSA key 名称。
import ChainKeyFeature "../ChainKeyFeature"; // 引入链钥类型与 ECDSA key/派生路径辅助函数。
import HexCodec "../HexCodec"; // 引入 hex 工具，用于输出公钥 hex。

module { // 定义 iiwallet 的 EVM 链相关能力模块。
  // 用途：读取 caller 对应 EVM 链钥公钥（使用当前环境配置的默认 key 名称）。
  // 用法：内部或上层功能模块调用；key 名来源于 AppConfig.defaultEcdsaKeyName()。
  public func readEvmPublicKeyHex(caller : Principal) : async { #ok : Text; #err : Text } { // 定义 EVM 公钥读取函数。
    let keyName = AppConfig.defaultEcdsaKeyName(); // 读取当前环境唯一默认 ECDSA key 名称，避免循环试错。
    await readEcdsaPublicKeyHexByKeyName(caller, keyName); // 直接按默认 key 名读取公钥并返回结果。
  }; // 结束 readEvmPublicKeyHex 函数。

  // 用途：读取 caller 对应指定 keyName 的 Threshold ECDSA 公钥并输出 hex。
  // 用法：内部调用；失败时返回 management canister 错误文本。
  func readEcdsaPublicKeyHexByKeyName(caller : Principal, keyName : Text) : async { #ok : Text; #err : Text } { // 定义按 keyName 读取 ECDSA 公钥函数。
    let keyId = ChainKeyFeature.buildEcdsaKeyId(keyName); // 构造 ECDSA key_id。
    let derivationPath = ChainKeyFeature.ecdsaDerivationPathForCaller(caller); // 构造基于 caller 的派生路径。
    let ic00EcdsaQuery : actor { // 定义 management canister ECDSA query 接口。
      ecdsa_public_key : shared ChainKeyFeature.ECDSAPublicKeyArgs -> async ChainKeyFeature.ECDSAPublicKeyResult; // 声明 ecdsa_public_key 接口签名。
    } = actor ("aaaaa-aa"); // 绑定 management canister。

    try { // 捕获管理 canister 调用错误。
      let result = await ic00EcdsaQuery.ecdsa_public_key({ // 调用 ecdsa_public_key 获取派生公钥。
        canister_id = null; // 使用当前 canister 上下文。
        derivation_path = derivationPath; // 传入 caller 派生路径。
        key_id = keyId; // 传入 key_id。
      }); // 结束调用。
      #ok(HexCodec.blobToHex(result.public_key)); // 返回压缩公钥 hex 文本。
    } catch (error) { // 捕获异常。
      #err("ecdsa_public_key failed(" # keyName # "): " # Error.message(error)); // 返回带 keyName 的错误文本，方便前端定位。
    }; // 结束异常处理。
  }; // 结束 readEcdsaPublicKeyHexByKeyName 函数。
}; // 结束 iiwallet 的 EVM 链能力模块定义。
