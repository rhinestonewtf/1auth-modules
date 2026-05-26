// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Script, console2 } from "forge-std/Script.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { MockRWA } from "src/demo/MockRWA.sol";
import { MockSwap } from "src/demo/MockSwap.sol";

/// @notice Deploy the 1Auth interactive demo: MockRWA token + USDC→MockRWA swap.
/// @dev Defaults are tuned for Base Sepolia at 0.20 USDC / NVDAnon with a
///      small live-price wobble. Override via env vars:
///        TOKEN_NAME    (string)   e.g. "NVDAnon Tokenized Share"
///        TOKEN_SYMBOL  (string)   e.g. "NVDAnon"
///        USDC_ADDRESS  (address)  defaults to Circle's Base Sepolia USDC
///        PRICE_USDC    (uint)     baseline price, 6-decimal USDC per whole
///                                 RWA token. Default 200_000 = 0.20 USDC/share.
///        JITTER_USDC   (uint)     jitter range, 6-decimal USDC. The live price
///                                 walks within ±JITTER_USDC of the baseline.
///                                 Default 20_000 = ±0.02 USDC. Must be < PRICE_USDC.
///        SEED_AMOUNT   (uint)     RWA minted to the swap as initial liquidity
///                                 (18 decimals, default 1_000_000e18).
///
/// Run (Base Sepolia):
///   forge script script/DeployDemo.s.sol \
///     --rpc-url $BASE_SEPOLIA_RPC --broadcast --verify
contract DeployDemo is Script {
    /// @dev Circle's Base Sepolia USDC. Verified against
    ///      https://developers.circle.com/stablecoins/usdc-on-test-networks
    address internal constant BASE_SEPOLIA_USDC = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;

    function run() public returns (MockRWA token, MockSwap swap) {
        string memory tokenName = vm.envOr("TOKEN_NAME", string("NVDAnon Tokenized Share"));
        string memory tokenSymbol = vm.envOr("TOKEN_SYMBOL", string("NVDAnon"));
        address usdc = vm.envOr("USDC_ADDRESS", BASE_SEPOLIA_USDC);
        // 0.20 USDC per NVDAnon — the live-demo baseline.
        uint256 priceUsdc = vm.envOr("PRICE_USDC", uint256(200_000));
        // ±0.02 USDC wobble around the baseline so the ticker looks alive
        // ([0.18, 0.22] band).
        uint256 jitterUsdc = vm.envOr("JITTER_USDC", uint256(20_000));
        uint256 seedAmount = vm.envOr("SEED_AMOUNT", uint256(1_000_000e18));

        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        token = new MockRWA(tokenName, tokenSymbol, deployer);
        swap = new MockSwap(IERC20(usdc), token, priceUsdc, jitterUsdc, deployer);

        // Seed the swap with RWA liquidity so users can buy immediately.
        token.mint(address(swap), seedAmount);

        vm.stopBroadcast();

        console2.log("=== 1Auth Demo Deployment ===");
        console2.log("Chain ID:        ", block.chainid);
        console2.log("Deployer:        ", deployer);
        console2.log("USDC:            ", usdc);
        console2.log("MockRWA token:   ", address(token));
        console2.log("  name:          ", tokenName);
        console2.log("  symbol:        ", tokenSymbol);
        console2.log("MockSwap:        ", address(swap));
        console2.log("  baseline (1e6):", priceUsdc);
        console2.log("  jitter   (1e6):", jitterUsdc);
        console2.log("  seeded RWA:    ", seedAmount);
    }
}
