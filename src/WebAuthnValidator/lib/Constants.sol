// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.28;

/// @dev Maximum allowed merkle proof depth. Bounds-checks prevent DoS via oversized proofs.
///      32 levels supports trees with up to 2^32 (~4 billion) leaves.
uint256 constant MAX_MERKLE_DEPTH = 32;

/// @dev Maximum number of credentials per account. Prevents unbounded gas costs during
///      onUninstall iteration and limits storage growth.
uint256 constant MAX_CREDENTIALS = 64;
