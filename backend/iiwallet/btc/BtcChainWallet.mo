module { // 定义 iiwallet 的 Bitcoin 链能力占位模块（后续接入地址/余额/签名逻辑）。
  public let chainId : Text = "btc"; // 标记当前模块对应的链 id。
  public let supportedAddressRead : Bool = false; // 当前版本 BTC 地址读取尚未接入。
}; // 结束 Bitcoin 链能力占位模块定义。
