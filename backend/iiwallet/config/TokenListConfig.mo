import RpcConfig "./RpcConfig";
import Arbitrum "./token_list/Arbitrum";
import Avalanche "./token_list/Avalanche";
import Base "./token_list/Base";
import Bsc "./token_list/Bsc";
import Ethereum "./token_list/Ethereum";
import Icp "./token_list/Icp";
import Optimism "./token_list/Optimism";
import Polygon "./token_list/Polygon";
import Sepolia "./token_list/Sepolia";
import Solana "./token_list/Solana";

module {
  public type ConfiguredToken = {
    network : Text;
    symbol : Text;
    name : Text;
    tokenAddress : Text;
    decimals : Nat;
  };

  // Per-chain default contract tokens used by wallet asset list.
  // You can extend/update this table as needed.
  public func configuredTokens(network : Text) : [ConfiguredToken] {
    switch (RpcConfig.normalizeWalletNetwork(network)) {
      case ("internet_computer") Icp.tokens;
      case ("icp") Icp.tokens;
      case ("ethereum") Ethereum.tokens;
      case ("sepolia") Sepolia.tokens;
      case ("base") Base.tokens;
      case ("polygon") Polygon.tokens;
      case ("arbitrum") Arbitrum.tokens;
      case ("optimism") Optimism.tokens;
      case ("bsc") Bsc.tokens;
      case ("avalanche") Avalanche.tokens;
      case ("solana") Solana.tokens;
      case (_) [];
    }
  };
}
