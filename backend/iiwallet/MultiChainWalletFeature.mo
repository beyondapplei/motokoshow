import Array "mo:base/Array"; // 引入 Array，用于公钥字节长度校验。
import Principal "mo:base/Principal"; // 引入 Principal，用于读取 caller 身份文本和 ECDSA 派生路径。
import Text "mo:base/Text"; // 引入 Text，用于 Base58 字符拼接。
import EvmChainWallet "./evm/EvmChainWallet"; // 引入 EVM 链能力模块，负责 ECDSA 公钥读取。
import RpcConfig "./config/RpcConfig"; // 引入 iiwallet RPC 配置模块，复用链配置、规范化与默认 RPC 配置。
import SolChainWallet "./sol/SolChainWallet"; // 引入 Solana 链能力模块，负责 ed25519 公钥与地址生成。

module { // 定义多链钱包后端功能模块（精简版，先提供网络列表和钱包总览基础信息）。
  public type WalletNetworkInfo = RpcConfig.WalletNetworkInfo; // 复用 RPC 配置模块里的钱包网络信息类型，避免重复维护。
  public type ShowcaseNetworkId = { // 定义当前项目钱包网络枚举，避免业务逻辑里散落字符串。
    #eth; // Ethereum 主网。
    #sepolia; // Sepolia 测试网。
    #base; // Base 主网。
    #sol; // Solana 主网。
    #solTestnet; // Solana Testnet 测试网。
    #apt; // Aptos 主网。
    #sui; // Sui 主网。
    #btc; // Bitcoin 主网。
    #ckb; // CKB 主网。
    #icp; // Internet Computer 主网。
  }; // 结束 ShowcaseNetworkId 枚举定义。

  type ShowcaseChainMeta = { // 定义当前项目钱包展示链的元信息类型（内部使用）。
    id : ShowcaseNetworkId; // 当前项目钱包网络枚举值（内部统一用枚举保持一致）。
    kind : Text; // 链类别（evm/ed25519/utxo/cell）。
    name : Text; // 展示名称。
    primarySymbol : Text; // 主资产符号。
  }; // 结束 ShowcaseChainMeta 类型定义。

  type WalletAddressReadOut = { // 定义链地址读取结果类型（内部使用）。
    address : ?Text; // 当前链地址（可为空，表示未接入或未生成）。
    publicKeyHex : ?Text; // 当前链公钥 hex（调试/前端推导用途）。
  }; // 结束 WalletAddressReadOut 类型定义。

  type PrimaryBalanceReadOut = { // 定义主资产余额读取结果类型（内部使用）。
    amount : Nat; // 主资产余额最小单位数值（如 lamports）。
    available : Bool; // 是否成功读取到真实余额。
  }; // 结束 PrimaryBalanceReadOut 类型定义。

  let SHOWCASE_CHAIN_METAS : [ShowcaseChainMeta] = [ // 定义当前项目钱包页面固定链列表（单一真源，避免多处重复维护）。
    { id = #eth; kind = "evm"; name = "Ethereum"; primarySymbol = "ETH" }, // Ethereum 主网。
    { id = #sepolia; kind = "evm"; name = "Sepolia"; primarySymbol = "ETH" }, // Sepolia 测试网。
    { id = #base; kind = "evm"; name = "Base"; primarySymbol = "ETH" }, // Base 主网。
    { id = #sol; kind = "ed25519"; name = "Solana"; primarySymbol = "SOL" }, // Solana 主网。
    { id = #solTestnet; kind = "ed25519"; name = "Solana Testnet"; primarySymbol = "SOL" }, // Solana Testnet 测试网。
    { id = #apt; kind = "ed25519"; name = "Aptos"; primarySymbol = "APT" }, // Aptos 主网。
    { id = #sui; kind = "ed25519"; name = "Sui"; primarySymbol = "SUI" }, // Sui 主网。
    { id = #btc; kind = "utxo"; name = "Bitcoin"; primarySymbol = "BTC" }, // Bitcoin 主网。
    { id = #ckb; kind = "cell"; name = "Nervos CKB"; primarySymbol = "CKB" }, // CKB 主网。
    { id = #icp; kind = "icp"; name = "Internet Computer"; primarySymbol = "ICP" }, // ICP 主网。
  ]; // 结束固定链列表定义。

  public type WalletBalanceItem = { // 定义钱包资产条目类型（当前先返回空列表，保留结构用于后续扩展）。
    symbol : Text; // 资产符号。
    name : Text; // 资产名称。
    network : Text; // 所属网络 id。
    decimals : Nat; // 精度。
    amount : Nat; // 余额最小单位数值。
    available : Bool; // 是否成功读取。
    address : Text; // 该资产接收地址。
    error : ?Text; // 错误信息（读取失败时）。
    tokenAddress : ?Text; // 合约地址（EVM token 时）。
    ledgerPrincipalText : ?Text; // Ledger Principal（ICRC1 时）。
  }; // 结束 WalletBalanceItem 类型定义。

  public type WalletOverviewOut = { // 定义钱包总览返回类型（精简版）。
    callerPrincipalText : Text; // 当前调用方 principal 文本（II 登录身份）。
    selectedNetwork : Text; // 当前选中的网络 id。
    primarySymbol : Text; // 当前网络主资产符号。
    primaryAmount : Nat; // 主资产余额（未接入时为 0）。
    primaryAvailable : Bool; // 主资产余额是否可用（当前为 false）。
    evmAddress : ?Text; // EVM 地址（当前后端未做 keccak 推导，先返回 null，前端可由公钥推导）。
    evmPublicKeyHex : ?Text; // 链公钥 hex（ETH/Base/Sepolia 为 ECDSA 公钥；Solana 暂复用该字段承载 ed25519 公钥）。
    balances : [WalletBalanceItem]; // 资产列表（当前先返回空数组）。
  }; // 结束 WalletOverviewOut 类型定义。

  public type WalletOverviewResult = { // 定义钱包总览结果类型（ok/err）。
    #ok : WalletOverviewOut; // 成功分支。
    #err : Text; // 失败分支。
  }; // 结束 WalletOverviewResult 类型定义。

  // 用途：返回多链钱包前端使用的网络列表。
  // 用法：前端进入钱包页后调用，构建链下拉列表与能力标识。
  public func walletNetworks() : [WalletNetworkInfo] { // 定义网络列表函数。
    Array.map<ShowcaseChainMeta, WalletNetworkInfo>( // 通过固定链元信息生成前端链配置，避免重复写多份配置。
      SHOWCASE_CHAIN_METAS, // 输入固定链列表。
      func(meta : ShowcaseChainMeta) : WalletNetworkInfo { // 定义链元信息到前端链配置的映射函数。
        walletNetworkInfoFromMeta(meta); // 复用统一构造函数生成链配置。
      },
    ); // 返回当前项目钱包链列表。
  }; // 结束 walletNetworks 函数。

  // 用途：返回当前 caller 在指定链的“钱包总览基础信息”（当前先接入 EVM 公钥读取）。
  // 用法：前端传入 network/rpcUrl/tokenAddress（后两者暂未使用），成功返回网络信息与 EVM 公钥（ETH/Base）。
  public func walletOverview( // 定义钱包总览函数（精简版）。
    caller : Principal, // 当前调用方 principal（用于链钥派生路径绑定）。
    network : Text, // 钱包网络 id（如 eth/sepolia/base/sol...）。
    _rpcUrl : ?Text, // 预留参数：RPC 地址（当前未使用）。
    _erc20TokenAddress : ?Text // 预留参数：ERC20 合约地址（当前未使用）。
  ) : async WalletOverviewResult { // 返回钱包总览结果。
    let selectedNetwork = normalizeShowcaseWalletNetwork(network); // 规范化为当前项目前端使用的链 id（eth/sepolia/base/sol...）。
    let selectedNetworkId = switch (showcaseNetworkIdFromText(selectedNetwork)) { // 把规范化文本转换成后端内部网络枚举。
      case (?id) id; // 转换成功，拿到枚举值供内部逻辑使用。
      case null return #err("unsupported wallet network: " # network); // 未命中枚举时直接返回错误。
    }; // 结束文本到枚举转换。
    let selectedNetworkInfo = showcaseWalletNetworkInfo(selectedNetworkId); // 查询当前项目钱包页面对应链配置。
    let chainInfo = switch (selectedNetworkInfo) { // 解包链配置，避免后续反复 switch。
      case (?cfg) cfg; // 使用已找到的链配置。
      case null return #err("unsupported wallet network: " # network); // 链不存在时直接返回错误。
    }; // 结束链配置解包。
    let callerPrincipalText = Principal.toText(caller); // 转换 caller principal 文本，供前端展示绑定身份。
    let addressRead = switch (await readShowcaseChainAddressData(caller, selectedNetworkId)) { // 读取当前链地址与公钥材料（按链枚举分发）。
      case (#ok(out)) out; // 地址读取成功，拿到地址与公钥。
      case (#err(errorText)) return #err(errorText); // 地址读取失败，直接返回错误给前端。
    }; // 结束地址读取。
    let primaryBalanceRead = await readShowcasePrimaryBalance(selectedNetworkId, _rpcUrl, addressRead); // 读取主资产余额（当前仅接 Solana 主网/Testnet）。

    #ok({ // 返回钱包总览（当前余额和资产列表先保留“未接入”状态）。
      callerPrincipalText = callerPrincipalText; // 返回 caller principal 文本。
      selectedNetwork = selectedNetwork; // 返回规范化后的网络 id。
      primarySymbol = chainInfo.primarySymbol; // 返回主资产符号。
      primaryAmount = primaryBalanceRead.amount; // 返回主资产余额（未接入或失败时为 0）。
      primaryAvailable = primaryBalanceRead.available; // 标记主资产余额是否成功读取。
      evmAddress = addressRead.address; // 返回当前链地址（EVM 仍为空；Solana 为后端生成 Base58 地址）。
      evmPublicKeyHex = addressRead.publicKeyHex; // 返回当前链公钥 hex（EVM/Solana 均可用于前端调试）。
      balances = []; // 当前未接入资产列表，返回空数组。
    }); // 结束成功返回。
  }; // 结束 walletOverview 函数。

  // 用途：按当前项目链 id 读取链地址与公钥材料。
  // 用法：EVM 链返回 ECDSA 公钥；Solana 返回后端生成地址 + ed25519 公钥；其他链返回空材料。
  func readShowcaseChainAddressData(caller : Principal, selectedNetwork : ShowcaseNetworkId) : async { #ok : WalletAddressReadOut; #err : Text } { // 定义按链枚举读取地址材料函数。
    if (isShowcaseEvmChain(selectedNetwork)) { // EVM 链只读取 ECDSA 公钥，地址仍由前端推导（当前版本保持兼容）。
      switch (await EvmChainWallet.readEvmPublicKeyHex(caller)) { // 调用 EVM 子模块按默认 key 读取链钥公钥。
        case (#ok(hexText)) { #ok({ address = null; publicKeyHex = ?hexText }) }; // 返回公钥 hex，地址暂为空。
        case (#err(errorText)) { #err(errorText) }; // 透传 EVM 公钥读取错误。
      }
    } else {
      switch (selectedNetwork) { // 对非 EVM 链做枚举分发，避免硬编码字符串比较。
        case (#sol) { // Solana 主网读取 ed25519 公钥并在后端生成 Base58 地址。
          switch (await SolChainWallet.readSolanaPublicKeyAndAddress(caller)) { // 调用 Sol 子模块按默认 key 读取公钥并生成地址。
            case (#ok(solOut)) { #ok({ address = ?solOut.address; publicKeyHex = ?solOut.publicKeyHex }) }; // 返回地址与公钥 hex。
            case (#err(errorText)) { #err(errorText) }; // 透传 Solana 公钥读取错误。
          }
        };
        case (#solTestnet) { // Solana Testnet 复用同一套 ed25519 链钥地址生成逻辑。
          switch (await SolChainWallet.readSolanaPublicKeyAndAddress(caller)) { // 调用 Sol 子模块按默认 key 读取公钥并生成地址。
            case (#ok(solOut)) { #ok({ address = ?solOut.address; publicKeyHex = ?solOut.publicKeyHex }) }; // 返回地址与公钥 hex。
            case (#err(errorText)) { #err(errorText) }; // 透传 Solana 公钥读取错误。
          }
        };
        case (_) { #ok({ address = null; publicKeyHex = null }) }; // 其他链当前未接入链钥地址读取。
      }; // 结束非 EVM 链枚举分发。
    }; // 结束链类型分发。
  }; // 结束 readShowcaseChainAddressData 函数。

  // 用途：按当前项目链枚举读取主资产余额（当前仅接入 Solana 主网/Testnet）。
  // 用法：wallet_overview 在读取地址后调用；失败时返回 `available=false`，不阻断整体钱包页面渲染。
  func readShowcasePrimaryBalance( // 定义主资产余额读取函数。
    selectedNetwork : ShowcaseNetworkId, // 当前选中链枚举。
    rpcUrlOverride : ?Text, // 前端可选传入的 RPC 地址覆盖项。
    addressRead : WalletAddressReadOut // 已读取到的链地址与公钥材料。
  ) : async PrimaryBalanceReadOut { // 返回主资产余额读取结果。
    switch (selectedNetwork) { // 按链枚举分发主资产余额读取逻辑。
      case (#sol) { // Solana 主网余额读取。
        await readSolanaPrimaryBalance(selectedNetwork, rpcUrlOverride, addressRead); // 复用 Solana 主资产余额读取实现。
      };
      case (#solTestnet) { // Solana Testnet 余额读取。
        await readSolanaPrimaryBalance(selectedNetwork, rpcUrlOverride, addressRead); // 复用 Solana 主资产余额读取实现。
      };
      case (_) { { amount = 0; available = false } }; // 其他链当前未接入主资产余额查询。
    }; // 结束链分发。
  }; // 结束 readShowcasePrimaryBalance 函数。

  // 用途：读取 Solana 主资产余额（lamports），供主网与 Testnet 共用。
  // 用法：内部由 `readShowcasePrimaryBalance` 调用；失败时返回 `available=false`。
  func readSolanaPrimaryBalance( // 定义 Solana 主资产余额读取实现。
    selectedNetwork : ShowcaseNetworkId, // 当前链枚举（#sol / #solTestnet）。
    rpcUrlOverride : ?Text, // 前端可选 RPC 覆盖项。
    addressRead : WalletAddressReadOut // 已读取到的 Solana 地址材料。
  ) : async PrimaryBalanceReadOut { // 返回主资产余额读取结果。
    let addressText = switch (addressRead.address) { // 读取地址文本（没有地址时无法查余额）。
      case (?addr) addr; // 使用已生成的 Solana 地址。
      case null return { amount = 0; available = false }; // 地址为空时直接返回未接入状态。
    }; // 结束地址解包。
    let rpcUrlText = switch (pickShowcaseRpcUrl(selectedNetwork, rpcUrlOverride)) { // 解析最终使用的 RPC URL。
      case (?url) url; // 使用传入覆盖值或默认 RPC。
      case null return { amount = 0; available = false }; // 无可用 RPC 时返回未接入状态。
    }; // 结束 RPC URL 解包。
    switch (await SolChainWallet.readSolanaBalanceLamports(addressText, rpcUrlText)) { // 调用 Sol 模块读取余额（lamports）。
      case (#ok(lamports)) { { amount = lamports; available = true } }; // 成功读取到真实余额。
      case (#err(_)) { { amount = 0; available = false } }; // 读取失败时不报错阻断页面，只标记不可用。
    } // 返回 Solana 余额读取结果。
  }; // 结束 readSolanaPrimaryBalance 函数。

  // 用途：根据链枚举和可选覆盖项选择最终 RPC URL。
  // 用法：优先使用前端传入的非空 rpcUrl；否则回退到当前链默认 RPC。
  func pickShowcaseRpcUrl(networkId : ShowcaseNetworkId, rpcUrlOverride : ?Text) : ?Text { // 定义 RPC URL 选择函数。
    switch (rpcUrlOverride) { // 优先使用前端传入的覆盖项（若非空）。
      case (?url) {
        if (Text.size(url) > 0) { // 过滤空字符串覆盖项。
          return ?url; // 返回前端显式指定的 RPC URL。
        };
      };
      case null {};
    }; // 结束覆盖项判断。
    showcaseDefaultRpcUrl(networkId); // 回退到当前链默认 RPC。
  }; // 结束 pickShowcaseRpcUrl 函数。

  // 用途：把前端/用户传入的链名规范化为当前项目钱包页面使用的短 id。
  // 用法：兼容 iiwallet RpcConfig 的规范化结果（如 ethereum/solana）并映射回 eth/sol。
  func normalizeShowcaseWalletNetwork(raw : Text) : Text { // 定义当前项目链 id 规范化函数。
    let normalized = RpcConfig.normalizeWalletNetwork(raw); // 先复用 iiwallet RpcConfig 做基础规范化。
    if (normalized == "ethereum") { "eth" } // 映射 Ethereum 主网到当前项目短 id。
    else if (normalized == "sepolia") { "sepolia" } // 保留 Sepolia 测试网 id。
    else if (normalized == "solana") { "sol" } // 映射 Solana 到当前项目短 id。
    else if (normalized == "sol_testnet" or normalized == "solana_testnet" or normalized == "solana-testnet" or normalized == "sol-testnet") { "sol_testnet" } // 兼容 Solana Testnet 输入。
    else if (normalized == "aptos") { "apt" } // 兼容可能的 Aptos 全名输入。
    else if (normalized == "bitcoin") { "btc" } // 兼容可能的 Bitcoin 全名输入。
    else if (normalized == "internet_computer") { "icp" } // 兼容 RpcConfig 的 ICP 标准化名称。
    else if (normalized == "nervos" or normalized == "nervos_ckb") { "ckb" } // 兼容可能的 CKB 全名输入。
    else { normalized }; // 其他情况直接使用规范化结果。
  }; // 结束 normalizeShowcaseWalletNetwork 函数。

  // 用途：把网络文本转换为当前项目钱包网络枚举。
  // 用法：wallet_overview 在业务处理前调用，确保后续逻辑统一基于枚举分支。
  func showcaseNetworkIdFromText(networkIdText : Text) : ?ShowcaseNetworkId { // 定义网络文本到枚举的转换函数。
    if (networkIdText == "eth") { ?#eth } // Ethereum 主网。
    else if (networkIdText == "sepolia") { ?#sepolia } // Sepolia 测试网。
    else if (networkIdText == "base") { ?#base } // Base 主网。
    else if (networkIdText == "sol") { ?#sol } // Solana 主网。
    else if (networkIdText == "sol_testnet") { ?#solTestnet } // Solana Testnet 测试网。
    else if (networkIdText == "apt") { ?#apt } // Aptos 主网。
    else if (networkIdText == "sui") { ?#sui } // Sui 主网。
    else if (networkIdText == "btc") { ?#btc } // Bitcoin 主网。
    else if (networkIdText == "ckb") { ?#ckb } // CKB 主网。
    else if (networkIdText == "icp") { ?#icp } // ICP 主网。
    else { null }; // 未知网络返回 null。
  }; // 结束 showcaseNetworkIdFromText 函数。

  // 用途：把当前项目钱包网络枚举转换为对外返回的短文本 id。
  // 用法：生成前端链列表与对外字段时统一使用，确保文本和值保持一致。
  func showcaseNetworkIdText(networkId : ShowcaseNetworkId) : Text { // 定义网络枚举到文本的转换函数。
    switch (networkId) { // 按枚举分支返回前端约定的短 id。
      case (#eth) { "eth" }; // Ethereum 主网。
      case (#sepolia) { "sepolia" }; // Sepolia 测试网。
      case (#base) { "base" }; // Base 主网。
      case (#sol) { "sol" }; // Solana 主网。
      case (#solTestnet) { "sol_testnet" }; // Solana Testnet 测试网。
      case (#apt) { "apt" }; // Aptos 主网。
      case (#sui) { "sui" }; // Sui 主网。
      case (#btc) { "btc" }; // Bitcoin 主网。
      case (#ckb) { "ckb" }; // CKB 主网。
      case (#icp) { "icp" }; // ICP 主网。
    }; // 结束枚举分支。
  }; // 结束 showcaseNetworkIdText 函数。

  // 用途：判断当前项目链 id 是否属于 EVM 链集合。
  // 用法：传入已经规范化的链 id，返回 true/false。
  func isShowcaseEvmChain(networkId : ShowcaseNetworkId) : Bool { // 定义 EVM 链判断函数（基于枚举）。
    switch (networkId) { // 枚举分支判断是否属于 EVM。
      case (#eth) true; // Ethereum 属于 EVM。
      case (#sepolia) true; // Sepolia 属于 EVM。
      case (#base) true; // Base 属于 EVM。
      case (_) false; // 其他链不是 EVM。
    }; // 结束 EVM 判断分支。
  }; // 结束 isShowcaseEvmChain 函数。

  // 用途：把当前项目链元信息转换成对外返回的 WalletNetworkInfo。
  // 用法：统一设置默认 RPC、supports 标记，避免多处手写重复链配置。
  func walletNetworkInfoFromMeta(meta : ShowcaseChainMeta) : WalletNetworkInfo { // 定义链元信息转 WalletNetworkInfo 函数。
    { // 返回统一格式的钱包链配置。
      id = showcaseNetworkIdText(meta.id); // 把内部网络枚举转换为前端约定短 id。
      kind = meta.kind; // 复用链类别。
      name = meta.name; // 复用链展示名称。
      primarySymbol = meta.primarySymbol; // 复用主资产符号。
      supportsSend = false; // 当前版本发送功能未接入。
      supportsBalance = false; // 当前版本余额查询未接入。
      defaultRpcUrl = showcaseDefaultRpcUrl(meta.id); // 按链 id 统一计算默认 RPC。
    }; // 结束 WalletNetworkInfo 构造。
  }; // 结束 walletNetworkInfoFromMeta 函数。

  // 用途：按当前项目链 id 返回默认 RPC（若存在）。
  // 用法：EVM 与 Solana 使用 iiwallet RpcConfig 的默认 RPC，其余链返回 null。
  func showcaseDefaultRpcUrl(networkId : ShowcaseNetworkId) : ?Text { // 定义当前项目默认 RPC 解析函数（基于枚举）。
    switch (networkId) { // 按网络枚举返回默认 RPC。
      case (#eth) { RpcConfig.effectiveRpcUrl("ethereum", null) }; // Ethereum 主网默认 RPC。
      case (#sepolia) { RpcConfig.effectiveRpcUrl("sepolia", null) }; // Sepolia 测试网默认 RPC。
      case (#base) { RpcConfig.effectiveRpcUrl("base", null) }; // Base 主网默认 RPC。
      case (#sol) { ?RpcConfig.effectiveSolanaRpcUrl(null) }; // Solana 主网默认 RPC。
      case (#solTestnet) { ?"https://solana-testnet-rpc.publicnode.com" }; // Solana Testnet 默认 RPC。
      case (#icp) { RpcConfig.effectiveRpcUrl("internet_computer", null) }; // ICP 主网默认 RPC。
      case (_) { null }; // 其余链当前未配置默认 RPC。
    }; // 结束默认 RPC 分支判断。
  }; // 结束 showcaseDefaultRpcUrl 函数。

  // 用途：返回当前项目钱包页面使用的链配置。
  // 用法：wallet_overview 内部调用，保持前端现有短 id 与展示名称不变。
  func showcaseWalletNetworkInfo(networkId : ShowcaseNetworkId) : ?WalletNetworkInfo { // 定义当前项目链配置查询函数（基于枚举）。
    for (meta in SHOWCASE_CHAIN_METAS.vals()) { // 遍历固定链列表查找目标链。
      if (meta.id == networkId) { // 找到目标链 id。
        return ?walletNetworkInfoFromMeta(meta); // 通过统一构造函数返回链配置。
      }; // 结束匹配判断。
    }; // 结束固定链列表遍历。
    null; // 未找到时返回 null。
  }; // 结束 showcaseWalletNetworkInfo 函数。
}; // 结束多链钱包后端功能模块定义。
