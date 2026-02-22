import Blob "mo:base/Blob"; // 引入 Blob 工具，用于遍历字节数组。
import Nat8 "mo:base/Nat8"; // 引入 Nat8 工具，用于字节转十六进制索引。
import Text "mo:base/Text"; // 引入 Text 工具，用于拼接十六进制字符串。

module { // 定义十六进制编码工具模块，供各功能文件复用。
  let HEX_CHARS : [Char] = [ // 定义十六进制字符表（模块内部常量）。
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
  ]; // 结束十六进制字符表定义。

  // 用途：把单字节转成两位十六进制文本。
  // 用法：仅模块内部使用，供 blobToHex 逐字节编码。
  func byteHex(value : Nat8) : Text { // 定义单字节 hex 编码函数。
    let high = Nat8.toNat(value / 16); // 计算高 4 位索引。
    let low = Nat8.toNat(value % 16); // 计算低 4 位索引。
    Text.fromChar(HEX_CHARS[high]) # Text.fromChar(HEX_CHARS[low]); // 拼接两位 hex 字符并返回。
  }; // 结束 byteHex 函数。

  // 用途：把任意 Blob 转成十六进制文本。
  // 用法：供后端示例接口把公钥/签名/加密密钥等二进制结果返回给前端展示。
  public func blobToHex(value : Blob) : Text { // 定义 Blob 到 hex 文本转换函数。
    var hex : Text = ""; // 初始化输出字符串。
    for (byte in Blob.toArray(value).vals()) { // 遍历 Blob 中每个字节。
      hex #= byteHex(byte); // 追加每个字节对应的两位 hex 文本。
    }; // 结束字节遍历。
    hex; // 返回最终 hex 字符串。
  }; // 结束 blobToHex 函数。
}; // 结束十六进制编码工具模块定义。
