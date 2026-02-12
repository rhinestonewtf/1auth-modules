// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "test/Base.t.sol";
import { OriginLib } from "src/WebAuthnValidator/lib/OriginLib.sol";

/// @dev Thin harness to expose OriginLib's internal function via an external call,
///      ensuring the input is passed as calldata (required by the assembly implementation).
contract OriginLibHarness {
    function extractOriginHashes(bytes calldata clientDataJSON)
        external
        pure
        returns (bytes32 originHash, bytes32 topOriginHash)
    {
        return OriginLib.extractOriginHashes(clientDataJSON);
    }
}

contract OriginLibTest is BaseTest {
    OriginLibHarness internal harness;

    function setUp() public override {
        BaseTest.setUp();
        harness = new OriginLibHarness();
    }

    /*//////////////////////////////////////////////////////////////////////////
                              BASIC ORIGIN EXTRACTION
    //////////////////////////////////////////////////////////////////////////*/

    function test_ExtractOriginHashes_BasicOrigin() public view {
        bytes memory json = bytes('{"origin":"https://example.com"}');
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("https://example.com"), "originHash mismatch");
        assertEq(topOriginHash, bytes32(0), "topOriginHash should be zero when absent");
    }

    function test_ExtractOriginHashes_NoTopOrigin() public view {
        bytes memory json =
            bytes('{"type":"webauthn.get","origin":"http://localhost:8080","crossOrigin":false}');
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("http://localhost:8080"), "originHash mismatch");
        assertEq(topOriginHash, bytes32(0), "topOriginHash should be zero");
    }

    /// @dev OriginLib scans for the lowercase `origin":"` pattern (0x6f726967696e223a22) and
    ///      disambiguates topOrigin by checking if preceded by `"top` (0x22746f70). This requires
    ///      the JSON key to be all-lowercase `"toporigin"`, not the standard WebAuthn camelCase
    ///      `"topOrigin"` (uppercase O = 0x4f does not match the lowercase `o` = 0x6f in the pattern).
    function test_ExtractOriginHashes_WithTopOrigin_Lowercase() public view {
        // Uses all-lowercase "toporigin" to match the assembly pattern
        bytes memory json = bytes(
            '{"type":"webauthn.get","origin":"https://passkey.1auth.box","crossOrigin":true,"toporigin":"https://game.xyz"}'
        );
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("https://passkey.1auth.box"), "originHash mismatch");
        assertEq(topOriginHash, keccak256("https://game.xyz"), "topOriginHash mismatch");
    }

    function test_ExtractOriginHashes_TopOriginBeforeOrigin() public view {
        // toporigin (lowercase) before origin
        bytes memory json = bytes(
            '{"toporigin":"https://game.xyz","origin":"https://passkey.1auth.box"}'
        );
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("https://passkey.1auth.box"), "originHash mismatch");
        assertEq(topOriginHash, keccak256("https://game.xyz"), "topOriginHash mismatch");
    }

    function test_ExtractOriginHashes_TopOriginAfterOrigin() public view {
        // toporigin (lowercase) after origin
        bytes memory json = bytes(
            '{"origin":"https://passkey.1auth.box","toporigin":"https://game.xyz"}'
        );
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("https://passkey.1auth.box"), "originHash mismatch");
        assertEq(topOriginHash, keccak256("https://game.xyz"), "topOriginHash mismatch");
    }

    /// @dev Standard WebAuthn Level 3 uses camelCase "topOrigin" (uppercase O). The assembly
    ///      now matches both `origin":"` (0x6f726967696e223a22) and `Origin":"` (0x4f726967696e223a22),
    ///      so camelCase "topOrigin" is correctly detected.
    function test_ExtractOriginHashes_CamelCaseTopOrigin() public view {
        // Standard WebAuthn camelCase "topOrigin" — detected by the pattern scanner
        bytes memory json = bytes(
            '{"origin":"https://passkey.1auth.box","crossOrigin":true,"topOrigin":"https://game.xyz"}'
        );
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("https://passkey.1auth.box"), "originHash mismatch");
        assertEq(topOriginHash, keccak256("https://game.xyz"), "camelCase topOrigin should be detected");
    }

    /// @dev When both lowercase "toporigin" and camelCase "topOrigin" appear in the same JSON,
    ///      the last match wins (scanner overwrites topOriginHash on each match). This test
    ///      verifies that both patterns are detected and the last one determines the final hash.
    function test_ExtractOriginHashes_MixedCase_BothDetected() public view {
        // lowercase "toporigin" first, then camelCase "topOrigin" — last match wins
        bytes memory json = bytes(
            '{"origin":"https://passkey.1auth.box","toporigin":"https://first.xyz","topOrigin":"https://second.xyz"}'
        );
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("https://passkey.1auth.box"), "originHash mismatch");
        // Last match wins: camelCase "topOrigin" value overwrites lowercase "toporigin"
        assertEq(topOriginHash, keccak256("https://second.xyz"), "last topOrigin match should win");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              EDGE CASES
    //////////////////////////////////////////////////////////////////////////*/

    function test_ExtractOriginHashes_EmptyInput() public view {
        bytes memory json = bytes("");
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, bytes32(0), "originHash should be zero for empty input");
        assertEq(topOriginHash, bytes32(0), "topOriginHash should be zero for empty input");
    }

    function test_ExtractOriginHashes_TooShort() public view {
        // Less than 9 bytes (the `origin":"` pattern length)
        bytes memory json = bytes("short");
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, bytes32(0), "originHash should be zero for short input");
        assertEq(topOriginHash, bytes32(0), "topOriginHash should be zero for short input");
    }

    function test_ExtractOriginHashes_EmptyOriginValue() public view {
        bytes memory json = bytes('{"origin":""}');
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256(""), "originHash should be hash of empty string");
        assertEq(topOriginHash, bytes32(0), "topOriginHash should be zero");
    }

    function test_ExtractOriginHashes_OriginWithPort() public view {
        bytes memory json = bytes('{"origin":"https://example.com:8443"}');
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("https://example.com:8443"), "originHash mismatch");
        assertEq(topOriginHash, bytes32(0), "topOriginHash should be zero");
    }

    /*//////////////////////////////////////////////////////////////////////////
                              REALISTIC WEBAUTHN DATA
    //////////////////////////////////////////////////////////////////////////*/

    function test_ExtractOriginHashes_RealClientDataJSON() public view {
        // Matches the format used in the existing test fixtures
        bytes memory json = bytes(
            '{"type":"webauthn.get","challenge":"9jEFijuhEWrM4SOW-tChJbUEHEP44VcjcJ-BqoXU9M8","origin":"http://localhost:8080","crossOrigin":false}'
        );
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("http://localhost:8080"), "originHash mismatch");
        assertEq(topOriginHash, bytes32(0), "topOriginHash should be zero");
    }

    function test_ExtractOriginHashes_CrossOriginWithTopOrigin() public view {
        // Cross-origin iframe scenario with lowercase toporigin (matching assembly pattern)
        bytes memory json = bytes(
            '{"type":"webauthn.get","challenge":"abc123","origin":"https://passkey.1auth.box","crossOrigin":true,"toporigin":"https://game.xyz"}'
        );
        (bytes32 originHash, bytes32 topOriginHash) = harness.extractOriginHashes(json);

        assertEq(originHash, keccak256("https://passkey.1auth.box"), "originHash mismatch");
        assertEq(topOriginHash, keccak256("https://game.xyz"), "topOriginHash mismatch");
    }
}
