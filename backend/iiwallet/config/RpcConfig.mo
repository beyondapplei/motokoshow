import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import Nat "mo:base/Nat";
import Result "mo:base/Result";
import Text "mo:base/Text";

module {
  public type EvmNetworkConfig = {
    id : Text;
    name : Text;
    chainId : Nat;
    defaultRpcUrl : Text;
    primarySymbol : Text;
    aliases : [Text];
  };

  public type WalletNetworkInfo = {
    id : Text;
    kind : Text;
    name : Text;
    primarySymbol : Text;
    supportsSend : Bool;
    supportsBalance : Bool;
    defaultRpcUrl : ?Text;
  };

  // Reserved for future Solana wallet module.
  public let defaultSolanaRpcUrl : Text = "https://solana-rpc.publicnode.com";

  let evmNetworks : [EvmNetworkConfig] = [
    {
      id = "ethereum";
      name = "Ethereum";
      chainId = 1;
      defaultRpcUrl = "https://ethereum-rpc.publicnode.com";
      primarySymbol = "ETH";
      aliases = ["eth", "mainnet"];
    },
    {
      id = "sepolia";
      name = "Sepolia";
      chainId = 11155111;
      defaultRpcUrl = "https://ethereum-sepolia-rpc.publicnode.com";
      primarySymbol = "ETH";
      aliases = ["eth-sepolia", "ethereum-sepolia"];
    },
    {
      id = "base";
      name = "Base";
      chainId = 8453;
      defaultRpcUrl = "https://base-rpc.publicnode.com";
      primarySymbol = "ETH";
      aliases = [];
    },
    {
      id = "polygon";
      name = "Polygon";
      chainId = 137;
      defaultRpcUrl = "https://polygon-bor-rpc.publicnode.com";
      primarySymbol = "ETH";
      aliases = ["matic"];
    },
    {
      id = "arbitrum";
      name = "Arbitrum";
      chainId = 42161;
      defaultRpcUrl = "https://arbitrum-one-rpc.publicnode.com";
      primarySymbol = "ETH";
      aliases = ["arb", "arbitrum-one"];
    },
    {
      id = "optimism";
      name = "Optimism";
      chainId = 10;
      defaultRpcUrl = "https://optimism-rpc.publicnode.com";
      primarySymbol = "ETH";
      aliases = ["op", "optimism-mainnet"];
    },
    {
      id = "bsc";
      name = "BNB Chain";
      chainId = 56;
      defaultRpcUrl = "https://bsc-rpc.publicnode.com";
      primarySymbol = "ETH";
      aliases = ["bnb", "bsc-mainnet", "binance-smart-chain"];
    },
    {
      id = "avalanche";
      name = "Avalanche C-Chain";
      chainId = 43114;
      defaultRpcUrl = "https://avalanche-c-chain-rpc.publicnode.com";
      primarySymbol = "ETH";
      aliases = ["avax", "avalanche-c"];
    },
  ];

  let internetComputerNetwork : WalletNetworkInfo = {
    id = "internet_computer";
    kind = "icp";
    name = "Internet Computer";
    primarySymbol = "ICP";
    supportsSend = true;
    supportsBalance = true;
    defaultRpcUrl = null;
  };

  let solanaNetwork : WalletNetworkInfo = {
    id = "solana";
    kind = "solana";
    name = "Solana";
    primarySymbol = "SOL";
    supportsSend = true;
    supportsBalance = true;
    defaultRpcUrl = ?defaultSolanaRpcUrl;
  };

  // Canonical network names used by wallet send/balance APIs and tool validation.
  // Additional EVM chains can be addressed with custom syntax: eip155:<chainId>.
  public func supportedNetworks() : [Text] {
    Array.map<EvmNetworkConfig, Text>(
      evmNetworks,
      func(cfg : EvmNetworkConfig) : Text {
        cfg.id
      },
    )
  };

  public func walletNetworks() : [WalletNetworkInfo] {
    let out = Buffer.Buffer<WalletNetworkInfo>(Array.size(evmNetworks) + 2);
    out.add(internetComputerNetwork);
    for (cfg in evmNetworks.vals()) {
      out.add({
        id = cfg.id;
        kind = "evm";
        name = cfg.name;
        primarySymbol = cfg.primarySymbol;
        supportsSend = true;
        supportsBalance = true;
        defaultRpcUrl = ?cfg.defaultRpcUrl;
      });
    };
    out.add(solanaNetwork);
    Buffer.toArray(out)
  };

  public func normalizeNetwork(network : Text) : Text {
    let n = normalizeText(network);
    switch (findEvmByIdOrAlias(n)) {
      case (?cfg) cfg.id;
      case null n;
    }
  };

  public func normalizeWalletNetwork(network : Text) : Text {
    let n = normalizeText(network);
    if (n == "" or n == "internet_computer" or n == "internet-computer" or n == "icp" or n == "ic") {
      "internet_computer"
    } else if (n == "sol" or n == "solana") {
      "solana"
    } else {
      normalizeNetwork(n)
    }
  };

  public func walletNetworkInfo(network : Text) : ?WalletNetworkInfo {
    let n = normalizeWalletNetwork(network);
    if (n == internetComputerNetwork.id) {
      return ?internetComputerNetwork;
    };
    if (n == solanaNetwork.id) {
      return ?solanaNetwork;
    };
    switch (findEvmByIdOrAlias(n)) {
      case null null;
      case (?cfg) {
        ?{
          id = cfg.id;
          kind = "evm";
          name = cfg.name;
          primarySymbol = cfg.primarySymbol;
          supportsSend = true;
          supportsBalance = true;
          defaultRpcUrl = ?cfg.defaultRpcUrl;
        }
      };
    }
  };

  public func isSupported(network : Text) : Bool {
    switch (findEvmByIdOrAlias(normalizeText(network))) {
      case (?_) true;
      case null parseCustomChainId(network) != null;
    }
  };

  public func chainId(network : Text) : ?Nat {
    switch (findEvmByIdOrAlias(normalizeText(network))) {
      case (?cfg) ?cfg.chainId;
      case null parseCustomChainId(network);
    }
  };

  public func defaultRpcUrl(network : Text) : ?Text {
    switch (findEvmByIdOrAlias(normalizeText(network))) {
      case (?cfg) ?cfg.defaultRpcUrl;
      case null null;
    }
  };

  public func effectiveRpcUrl(network : Text, rpcUrl : ?Text) : ?Text {
    switch (rpcUrl) {
      case (?u) {
        let t = Text.trim(u, #char ' ');
        if (Text.size(t) > 0) return ?t;
      };
      case null {};
    };
    defaultRpcUrl(network)
  };

  public func resolveRpcUrl(network : Text, rpcUrl : ?Text) : Result.Result<Text, Text> {
    switch (effectiveRpcUrl(network, rpcUrl)) {
      case (?u) #ok(u);
      case null {
        if (parseCustomChainId(network) != null) {
          #err("rpcUrl is required for custom network: " # network)
        } else {
          #err("unsupported network: " # network)
        }
      };
    }
  };

  public func effectiveSolanaRpcUrl(rpcUrl : ?Text) : Text {
    switch (rpcUrl) {
      case (?u) {
        let t = Text.trim(u, #char ' ');
        if (Text.size(t) > 0) return t;
      };
      case null {};
    };
    defaultSolanaRpcUrl
  };

  func findEvmByIdOrAlias(network : Text) : ?EvmNetworkConfig {
    if (Text.size(network) == 0) return null;
    for (cfg in evmNetworks.vals()) {
      if (cfg.id == network) {
        return ?cfg;
      };
      for (alias in cfg.aliases.vals()) {
        if (alias == network) {
          return ?cfg;
        };
      };
    };
    null
  };

  func normalizeText(value : Text) : Text {
    Text.toLowercase(Text.trim(value, #char ' '))
  };

  func parseCustomChainId(network : Text) : ?Nat {
    let n = normalizeNetwork(network);
    let parts = Text.split(n, #char ':');
    let prefix = switch (parts.next()) {
      case null return null;
      case (?v) v;
    };
    let chainIdText = switch (parts.next()) {
      case null return null;
      case (?v) Text.trim(v, #char ' ');
    };
    if (parts.next() != null) return null;
    if (prefix != "eip155" and prefix != "chainid" and prefix != "evm") return null;
    switch (Nat.fromText(chainIdText)) {
      case null null;
      case (?0) null;
      case (?id) ?id;
    }
  };
}
