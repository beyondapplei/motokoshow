import Array "mo:base/Array"; // 引入 Array，用于判断字节数组长度。
import Buffer "mo:base/Buffer"; // 引入 Buffer，用于暂存逆序 Base58 字符。
import Nat8 "mo:base/Nat8"; // 引入 Nat8，用于字节转 Nat 参与编码运算。
import Text "mo:base/Text"; // 引入 Text，用于字符拼接输出文本。

module { // 定义 Solana 相关 Base58 编码工具模块。
  let BASE58_CHARS : [Char] = [ // 定义 Base58 字符表（Solana 地址编码使用）。
    '1', '2', '3', '4', '5', '6', '7', '8', '9', // 数字字符（去掉 0）。
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // 大写字符（去掉 I/O）。
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // 小写字符（去掉 l）。
  ]; // 结束 Base58 字符表定义。

  // 用途：把字节数组编码为 Base58 文本（适用于 Solana 地址编码）。
  // 用法：支持前导 0 字节（会映射成前导字符 '1'）。
  public func encode(bytes : [Nat8]) : Text { // 定义 Base58 编码函数。
    if (Array.size(bytes) == 0) { // 空字节数组直接返回空字符串。
      return ""; // 返回空字符串。
    }; // 结束空数组判断。

    var leadingZeroCount : Nat = 0; // 记录前导 0 字节数量，Base58 需要映射为前导 '1'。
    label countLeading for (byte in bytes.vals()) { // 遍历开头字节统计连续前导 0。
      if (Nat8.toNat(byte) == 0) { // 当前字节为 0 时继续计数。
        leadingZeroCount += 1; // 增加前导 0 计数。
      } else { // 遇到第一个非 0 字节。
        break countLeading; // 结束前导 0 统计。
      }; // 结束前导 0 判断。
    }; // 结束前导 0 统计循环。

    var numericValue : Nat = 0; // 初始化大整数容器，用于把 base256 字节流转换为数值。
    for (byte in bytes.vals()) { // 逐字节累积 base256 数值。
      numericValue := numericValue * 256 + Nat8.toNat(byte); // base256 左移并加上当前字节值。
    }; // 结束数值累积。

    let reversedChars = Buffer.Buffer<Char>(0); // 使用 Buffer 暂存逆序 Base58 字符（低位先出）。
    var remain : Nat = numericValue; // 初始化待编码数值。
    while (remain > 0) { // 持续做除 58 取余直到数值归零。
      let digitIndex = remain % 58; // 计算当前最低位 Base58 下标。
      reversedChars.add(BASE58_CHARS[digitIndex]); // 追加当前 Base58 字符到逆序缓存。
      remain := remain / 58; // 去掉已编码的最低位。
    }; // 结束除 58 编码循环。

    var out : Text = ""; // 初始化输出字符串。
    var zeroPrefixIndex : Nat = 0; // 初始化前导 '1' 补位计数器。
    while (zeroPrefixIndex < leadingZeroCount) { // 把前导 0 字节映射为 Base58 前导字符 '1'。
      out #= "1"; // 追加一个前导 '1'。
      zeroPrefixIndex += 1; // 增加补位计数器。
    }; // 结束前导补位循环。

    var reverseIndex : Nat = reversedChars.size(); // 初始化逆序字符遍历起点（从末尾向前）。
    while (reverseIndex > 0) { // 反向输出 Base58 字符，恢复正常顺序。
      reverseIndex -= 1; // 先减 1 再取值，确保索引落在有效范围。
      out #= Text.fromChar(reversedChars.get(reverseIndex)); // 追加当前字符到输出文本。
    }; // 结束逆序输出循环。

    out; // 返回最终 Base58 文本。
  }; // 结束 Base58.encode 函数。
}; // 结束 Solana Base58 编码工具模块定义。
