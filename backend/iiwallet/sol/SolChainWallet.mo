import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Error "mo:base/Error";
import Int "mo:base/Int";
import Nat "mo:base/Nat";
import Nat64 "mo:base/Nat64";
import Nat8 "mo:base/Nat8";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import AppConfig "../config/AppConfig";
import Base58 "./Base58";
import ChainKeyFeature "../ChainKeyFeature";
import HexCodec "../HexCodec";
import SerdeCandid "mo:serde/Candid";
import SerdeJson "mo:serde/JSON";

module {
  public type SolBalanceResult = { #ok : Nat; #err : Text };

  type HttpMethod = { #get; #head; #post; #put; #delete; #patch; #options };
  type HttpHeader = { name : Text; value : Text };
  type HttpResponsePayload = { status : Nat; headers : [HttpHeader]; body : Blob };
  type TransformArgs = { response : HttpResponsePayload; context : Blob };
  type TransformContext = { function : shared query TransformArgs -> async HttpResponsePayload; context : Blob };
  type HttpRequestArgs = {
    url : Text;
    max_response_bytes : ?Nat64;
    method : HttpMethod;
    headers : [HttpHeader];
    body : ?Blob;
    transform : ?TransformContext;
  };

  public type SolAddressReadOut = {
    publicKeyHex : Text;
    address : Text;
  };



  public func readSolanaPublicKeyAndAddress(caller : Principal) : async { #ok : SolAddressReadOut; #err : Text } {
    let keyName = AppConfig.defaultEcdsaKeyName();
    await readSchnorrEd25519PublicKeyHexAndAddress(caller, keyName);
  };



  public func readSolanaBalanceLamports(address : Text, rpcUrl : Text) : async SolBalanceResult {
    switch (validateSolanaBalanceInputs(address, rpcUrl)) {
      case (?errorText) { return #err(errorText) };
      case null {};
    };
    let requestBodyText = buildSolanaGetBalanceRequestBody(address);
    let httpRequest = buildJsonRpcPostRequest(rpcUrl, requestBodyText);
    switch (await callJsonRpcHttp(httpRequest, "solana getBalance")) {
      case (#err(errorText)) { #err(errorText) };
      case (#ok(payloadText)) { parseSolanaGetBalanceResponse(payloadText) };
    };
  };



  func validateSolanaBalanceInputs(address : Text, rpcUrl : Text) : ?Text {
    if (Text.size(address) == 0) {
      return ?"solana address is empty";
    };
    if (Text.size(rpcUrl) == 0) {
      return ?"solana rpc url is empty";
    };
    null;
  };



  func buildSolanaGetBalanceRequestBody(address : Text) : Text {
    "{" #
    "\"jsonrpc\":\"2.0\"," #
    "\"id\":1," #
    "\"method\":\"getBalance\"," #
    "\"params\":[\"" # address # "\"]" #
    "}";
  };



  func buildJsonRpcPostRequest(rpcUrl : Text, bodyText : Text) : HttpRequestArgs {
    {
      url = rpcUrl;
      max_response_bytes = ?65_536;
      method = #post;
      headers = [{ name = "Content-Type"; value = "application/json" }];
      body = ?Text.encodeUtf8(bodyText);
      transform = null;
    };
  };



  func callJsonRpcHttp(request : HttpRequestArgs, actionLabel : Text) : async { #ok : Text; #err : Text } {
    let ic00Http : actor {
      http_request : shared HttpRequestArgs -> async HttpResponsePayload;
    } = actor ("aaaaa-aa");

    try {
      let httpResp = await (with cycles = AppConfig.defaultHttpCycles()) ic00Http.http_request(request);
      let payloadText = decodeHttpResponseBodyText(httpResp.body);
      if (httpResp.status < 200 or httpResp.status >= 300) {
        return #err(actionLabel # " http status " # Nat.toText(httpResp.status) # ": " # payloadText);
      };
      #ok(payloadText);
    } catch (error) {
      #err(actionLabel # " failed: " # Error.message(error));
    };
  };



  func decodeHttpResponseBodyText(body : Blob) : Text {
    switch (Text.decodeUtf8(body)) {
      case null "";
      case (?text) text;
    };
  };



  func parseSolanaGetBalanceResponse(payloadText : Text) : SolBalanceResult {
    switch (SerdeJson.toCandid(payloadText)) {
      case (#err(parseErrorText)) { #err("solana rpc json parse failed: " # parseErrorText) };
      case (#ok(rootValue)) {
        switch (extractSolanaRpcErrorMessage(rootValue)) {
          case (?rpcErrorMessage) { #err("solana rpc getBalance error: " # rpcErrorMessage) };
          case null {
            switch (extractSolanaBalanceValueLamports(rootValue)) {
              case (?lamports) { #ok(lamports) };
              case null { #err("solana rpc getBalance value missing") };
            };
          };
        };
      };
    };
  };



  func readSchnorrEd25519PublicKeyHexAndAddress(caller : Principal, keyName : Text) : async { #ok : SolAddressReadOut; #err : Text } {
    let keyId = ChainKeyFeature.buildSchnorrEd25519KeyId(keyName);
    let derivationPath = ChainKeyFeature.schnorrDerivationPathForCaller(caller);
    let ic00SchnorrQuery : actor {
      schnorr_public_key : shared ChainKeyFeature.SchnorrPublicKeyArgs -> async ChainKeyFeature.SchnorrPublicKeyResult;
    } = actor ("aaaaa-aa");

    try {
      let result = await ic00SchnorrQuery.schnorr_public_key({
        canister_id = null;
        derivation_path = derivationPath;
        key_id = keyId;
      });
      let publicKeyBytes = Blob.toArray(result.public_key);
      let publicKeyHex = HexCodec.blobToHex(result.public_key);
      switch (solanaAddressFromEd25519PublicKey(publicKeyBytes)) {
        case (?addressText) { #ok({ publicKeyHex = publicKeyHex; address = addressText }) };
        case null { #err("invalid ed25519 public key length for solana address") };
      };
    } catch (error) {
      #err("schnorr_public_key failed(" # keyName # "): " # Error.message(error));
    };
  };



  func solanaAddressFromEd25519PublicKey(publicKeyBytes : [Nat8]) : ?Text {
    if (Array.size(publicKeyBytes) != 32) {
      return null;
    };
    ?Base58.encode(publicKeyBytes);
  };



  func extractSolanaRpcErrorMessage(rootValue : SerdeCandid.Candid) : ?Text {
    let errorValue = switch (candidRecordField(rootValue, "error")) {
      case (?value) value;
      case null return null;
    };
    switch (candidRecordField(errorValue, "message")) {
      case (?(#Text(messageText))) ?messageText;
      case (_) null;
    };
  };



  func extractSolanaBalanceValueLamports(rootValue : SerdeCandid.Candid) : ?Nat {
    let resultValue = switch (candidRecordField(rootValue, "result")) {
      case (?value) value;
      case null return null;
    };
    let valueField = switch (candidRecordField(resultValue, "value")) {
      case (?value) value;
      case null return null;
    };
    candidNat(valueField);
  };



  func candidRecordField(value : SerdeCandid.Candid, key : Text) : ?SerdeCandid.Candid {
    switch (value) {
      case (#Record(fields) or #Map(fields)) { findCandidRecordField(fields, key) };
      case (_) null;
    };
  };



  func findCandidRecordField(fields : [(Text, SerdeCandid.Candid)], key : Text) : ?SerdeCandid.Candid {
    for ((fieldKey, fieldValue) in fields.vals()) {
      if (fieldKey == key) {
        return ?fieldValue;
      };
    };
    null;
  };



  func candidNat(value : SerdeCandid.Candid) : ?Nat {
    switch (value) {
      case (#Nat(n)) ?n;
      case (#Int(i)) {
        if (i < 0) { null } else { ?Int.abs(i) };
      };
      case (_) null;
    };
  };
};
