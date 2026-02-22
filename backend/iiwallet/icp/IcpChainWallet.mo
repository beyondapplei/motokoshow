module { // 定义 iiwallet 的 ICP 链能力占位模块（后续接入账户/ICRC 余额逻辑）。
  public let chainId : Text = "icp"; // 标记当前模块对应的链 id。
  public let supportedAddressRead : Bool = false; // 当前版本 ICP 地址读取尚未接入。
}; // 结束 ICP 链能力占位模块定义。
