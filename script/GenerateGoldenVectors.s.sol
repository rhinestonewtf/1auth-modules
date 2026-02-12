// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";
import { WebAuthnValidatorV2 } from "src/WebAuthnValidator/WebAuthnValidatorV2.sol";
import { WebAuthnRecoveryBase } from "src/WebAuthnValidator/WebAuthnRecoveryBase.sol";

/// @notice Generates golden test vectors as JSON for cross-language validation.
/// @dev Run: forge script script/GenerateGoldenVectors.s.sol -vvv
///      Output: test/WebAuthnValidator/fixtures/golden-vectors.json
contract GenerateGoldenVectors is Script {
    bytes32 constant DIGEST_A = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;
    bytes32 constant DIGEST_B = 0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant DIGEST_C = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;

    function run() public {
        WebAuthnValidatorV2 validator = new WebAuthnValidatorV2();

        console2.log("Validator address:", address(validator));
        console2.log("Chain ID:", block.chainid);

        string memory root = "root";
        vm.serializeAddress(root, "validator_address", address(validator));
        vm.serializeUint(root, "chain_id", block.chainid);

        vm.serializeString(root, "typehashes", _buildTypehashes(validator));
        vm.serializeString(root, "passkey_digest", _buildPasskeyDigests(validator));
        vm.serializeString(root, "passkey_multichain", _buildPasskeyMultichains(validator));
        vm.serializeString(root, "recovery_digest", _buildRecoveryDigest(validator));
        vm.serializeString(root, "merkle", _buildMerkle());

        string memory finalJson = vm.serializeString(root, "_version", "1");
        vm.writeJson(finalJson, "test/WebAuthnValidator/fixtures/golden-vectors.json");
        console2.log("Written golden vectors.");
    }

    function _buildTypehashes(WebAuthnValidatorV2 v) internal returns (string memory) {
        string memory obj = "typehashes";
        vm.serializeBytes32(obj, "passkey_digest", v.PASSKEY_DIGEST_TYPEHASH());
        vm.serializeBytes32(obj, "passkey_multichain", v.PASSKEY_MULTICHAIN_TYPEHASH());
        return vm.serializeBytes32(obj, "recover_passkey", v.RECOVER_PASSKEY_TYPEHASH());
    }

    function _buildPasskeyDigests(WebAuthnValidatorV2 v) internal returns (string memory) {
        string memory arr = "passkey_digests";
        vm.serializeString(arr, "0", _digestVector("pd_a", DIGEST_A, v.getPasskeyDigest(DIGEST_A)));
        vm.serializeString(arr, "1", _digestVector("pd_b", DIGEST_B, v.getPasskeyDigest(DIGEST_B)));
        return vm.serializeString(arr, "2", _digestVector("pd_c", DIGEST_C, v.getPasskeyDigest(DIGEST_C)));
    }

    function _buildPasskeyMultichains(WebAuthnValidatorV2 v) internal returns (string memory) {
        string memory arr = "passkey_multichains";
        vm.serializeString(arr, "0", _digestVector("pm_a", DIGEST_A, v.getPasskeyMultichain(DIGEST_A)));
        vm.serializeString(arr, "1", _digestVector("pm_b", DIGEST_B, v.getPasskeyMultichain(DIGEST_B)));
        return vm.serializeString(arr, "2", _digestVector("pm_c", DIGEST_C, v.getPasskeyMultichain(DIGEST_C)));
    }

    function _digestVector(
        string memory key,
        bytes32 input,
        bytes32 output
    )
        internal
        returns (string memory)
    {
        vm.serializeBytes32(key, "input", input);
        return vm.serializeBytes32(key, "output", output);
    }

    function _buildRecoveryDigest(WebAuthnValidatorV2 v) internal returns (string memory) {
        string memory obj = "recovery";

        address account = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045;
        uint256 chainId = 31337;
        uint16 keyId = 1;
        uint256 pubKeyX = 0x580a9af0569ad3905b26a703201b358aa0904236642ebe79b22a19d00d373763;
        uint256 pubKeyY = 0x7d46f725a5427ae45a9569259bf67e1e16b187d7b3ad1ed70138c4f0409677d1;
        uint256 nonce = 42;
        uint48 expiry = 1_700_000_000;

        WebAuthnRecoveryBase.NewCredential memory cred = WebAuthnRecoveryBase.NewCredential({
            keyId: keyId,
            pubKeyX: bytes32(pubKeyX),
            pubKeyY: bytes32(pubKeyY)
        });

        bytes32 digest = v.getRecoverDigest(account, chainId, cred, nonce, expiry);

        vm.serializeAddress(obj, "account", account);
        vm.serializeUint(obj, "chain_id", chainId);
        vm.serializeUint(obj, "new_key_id", uint256(keyId));
        vm.serializeUint(obj, "new_pub_key_x", pubKeyX);
        vm.serializeUint(obj, "new_pub_key_y", pubKeyY);
        vm.serializeBool(obj, "new_require_uv", false);
        vm.serializeUint(obj, "nonce", nonce);
        vm.serializeUint(obj, "expiry", uint256(expiry));
        return vm.serializeBytes32(obj, "output", digest);
    }

    function _buildMerkle() internal returns (string memory) {
        string memory obj = "merkle";

        bytes32 leaf0 = keccak256(abi.encodePacked(uint8(0)));
        bytes32 leaf1 = keccak256(abi.encodePacked(uint8(1)));
        bytes32 leaf2 = keccak256(abi.encodePacked(uint8(2)));
        bytes32 pair01 = _hashPair(leaf0, leaf1);
        bytes32 root = _hashPair(pair01, leaf2);

        vm.serializeString(obj, "leaves", _serializeLeaves(leaf0, leaf1, leaf2));
        vm.serializeBytes32(obj, "root", root);
        vm.serializeString(obj, "proof_0", _serializeProof2("p0", leaf1, leaf2));
        vm.serializeString(obj, "proof_1", _serializeProof2("p1", leaf0, leaf2));
        return vm.serializeString(obj, "proof_2", _serializeProof1("p2", pair01));
    }

    function _serializeLeaves(bytes32 a, bytes32 b, bytes32 c) internal returns (string memory) {
        string memory arr = "leaves";
        vm.serializeBytes32(arr, "0", a);
        vm.serializeBytes32(arr, "1", b);
        return vm.serializeBytes32(arr, "2", c);
    }

    function _serializeProof2(string memory key, bytes32 a, bytes32 b) internal returns (string memory) {
        vm.serializeBytes32(key, "0", a);
        return vm.serializeBytes32(key, "1", b);
    }

    function _serializeProof1(string memory key, bytes32 a) internal returns (string memory) {
        return vm.serializeBytes32(key, "0", a);
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }
}
