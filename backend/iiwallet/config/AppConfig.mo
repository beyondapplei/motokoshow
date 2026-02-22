import Nat "mo:core/Nat";
import Principal "mo:core/Principal";
import Text "mo:core/Text";

module {
  public type AppMode = {
    #dev;
    #prod;
  };

  // Single switch for environment mode.
  public let mode : AppMode = #dev;

  public func isDevMode() : Bool {
    switch (mode) {
      case (#dev) true;
      case (#prod) false;
    }
  };

  // Production can enable strict owner auth; development bypasses auth.
  public func authEnabled() : Bool {
    not isDevMode()
  };

  // ICP ledger principals by environment.
  public let icpLedgerMainnetPrincipalText : Text = "ryjl3-tyaaa-aaaaa-aaaba-cai";
  public let icpLedgerLocalPrincipalText : Text = "umunu-kh777-77774-qaaca-cai";

  public func icpLedgerMainnetPrincipal() : Principal {
    Principal.fromText(icpLedgerMainnetPrincipalText)
  };

  public func icpLedgerLocalPrincipal() : Principal {
    Principal.fromText(icpLedgerLocalPrincipalText)
  };

  public func defaultIcpLedgerUseMainnet() : Bool {
    switch (mode) {
      case (#dev) false;
      case (#prod) true;
    }
  };

  // Default cycles budget for HTTP outcalls.
  public func defaultHttpCycles() : Nat {
    switch (mode) {
      case (#dev) 30_000_000_000;
      case (#prod) 30_000_000_000;
    }
  };

  // ECDSA key preference order by environment.
  public func defaultEcdsaKeyName() : Text {
    switch (mode) {
      case (#dev) "dfx_test_key";
      case (#prod) "key_1";
    }
  };

}
