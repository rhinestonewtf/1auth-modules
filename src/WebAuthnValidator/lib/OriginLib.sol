// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

/**
 * @title OriginLib
 * @notice Extracts origin and topOrigin hashes from a WebAuthn clientDataJSON byte sequence.
 * @dev Scans raw bytes for both `origin":"` (lowercase, 0x6f726967696e223a22) and
 *      `Origin":"` (uppercase, 0x4f726967696e223a22) patterns. The uppercase variant
 *      handles standard WebAuthn Level 3 camelCase `"topOrigin"`. Both cases are
 *      disambiguated from `"origin"` by checking the 4 bytes preceding the match for
 *      `"top` (0x22746f70). Returns keccak256 hashes of the extracted origin values.
 *
 *      Designed for calldata input to avoid memory copies when scanning clientDataJSON
 *      directly from packed signature data.
 *
 *      ASSUMPTIONS:
 *      - The input is well-formed WebAuthn authenticator output. This scanner does NOT
 *        handle JSON escape sequences (e.g. `\"` within origin values). Escaped quotes
 *        would cause premature termination of the value extraction, producing a truncated
 *        hash. This fails safely: the truncated hash won't match any stored UV exemption,
 *        so validation falls back to requireUV=true.
 *      - If duplicate `"origin"` keys appear, the last match wins. WebAuthn authenticators
 *        produce well-formed JSON with a single `origin` key.
 */
library OriginLib {
    /**
     * @notice Extract origin and topOrigin hashes from clientDataJSON bytes
     * @dev Scans for both `origin":"` (0x6f726967696e223a22, lowercase) and `Origin":"`
     *      (0x4f726967696e223a22, uppercase) patterns. The uppercase variant handles
     *      standard WebAuthn Level 3 camelCase `"topOrigin"`. When either pattern matches,
     *      checks if preceded by `"top` to distinguish `"topOrigin"` / `"toporigin"` from
     *      `"origin"`. Extracts the quoted value and hashes it with keccak256.
     *      topOriginHash is bytes32(0) if topOrigin is not present in the JSON.
     * @param clientDataJSON The raw clientDataJSON bytes from the WebAuthn authenticator
     * @return originHash keccak256 of the origin value string
     * @return topOriginHash keccak256 of the topOrigin value string (bytes32(0) if absent)
     */
    function extractOriginHashes(bytes calldata clientDataJSON)
        internal
        pure
        returns (bytes32 originHash, bytes32 topOriginHash)
    {
        assembly {
            let len := clientDataJSON.length
            let start := clientDataJSON.offset
            let end := add(start, len)
            let fmp := mload(0x40)

            // Pattern (lowercase): origin":"  (9 bytes = 0x6f726967696e223a22)
            // Pattern (uppercase): Origin":"  (9 bytes = 0x4f726967696e223a22)
            // Prefix:              "top       (4 bytes = 0x22746f70)
            // The uppercase variant handles standard WebAuthn camelCase "topOrigin".
            // To match both, we OR bit 5 of the first byte (0x20) to force lowercase,
            // then compare against the lowercase pattern. This converts 'O' (0x4f) to
            // 'o' (0x6f) without affecting an already-lowercase 'o'.
            for { let i := start } lt(add(i, 9), end) { i := add(i, 1) } {
                let word := calldataload(i)
                let candidate := shr(184, word) // top 9 bytes (72 bits)

                // Force first byte lowercase: OR 0x20 into bit position 64 (first byte of 9)
                // 0x20 << 64 = 0x200000000000000000 sets bit 5 of the leading byte
                if eq(or(candidate, 0x200000000000000000), 0x6f726967696e223a22) {
                    // Check if preceded by "top (4 bytes) — same prefix for both cases
                    let isTopOrigin := 0
                    if iszero(lt(i, add(start, 4))) {
                        let prefix := shr(224, calldataload(sub(i, 4))) // 4 bytes before
                        isTopOrigin := eq(prefix, 0x22746f70)
                    }

                    // Value starts after the 9-byte pattern
                    let valStart := add(i, 9)

                    // Find closing quote (0x22)
                    let valEnd := valStart
                    for { } lt(valEnd, end) { valEnd := add(valEnd, 1) } {
                        if eq(byte(0, calldataload(valEnd)), 0x22) { break }
                    }

                    // Copy value to memory at free memory pointer for hashing
                    let valLen := sub(valEnd, valStart)
                    calldatacopy(fmp, valStart, valLen)
                    let h := keccak256(fmp, valLen)

                    switch isTopOrigin
                    case 1 { topOriginHash := h }
                    default { originHash := h }

                    // Skip past this match
                    i := valEnd
                }
            }
        }
    }
}
