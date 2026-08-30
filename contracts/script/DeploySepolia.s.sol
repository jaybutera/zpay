// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {OfframpGlue} from "../src/OfframpGlue.sol";
import {MockUSDC, MockEscrowWithOrchestrator} from "./DeployLocalEnhanced.s.sol";

/// @title DeploySepolia
/// @notice Base Sepolia deployment: OfframpGlue plus a stand-in zk-p2p escrow.
///
/// zk-p2p's own Base Sepolia contracts are stale and ABI-incompatible with the
/// production EscrowV2 (see docs/testnet-deploy-plan.md), so the testnet run
/// deploys MockEscrowWithOrchestrator, which implements the EscrowV2 subset the
/// glue uses and also emits the OrchestratorV3 IntentSignaled/IntentFulfilled
/// events the keeper watches. The EscrowV2 encoding itself is verified on a
/// mainnet fork by scripts/dryrun/fork_base.sh.
///
/// Env:
///   PRIVATE_KEY    deployer (becomes owner and keeper of the glue)
///   USDC_ADDRESS   token to use; default Circle's Base Sepolia USDC.
///                  Set MOCK_USDC=true to deploy a mintable MockUSDC instead
///                  (for local anvil runs with --chain-id 84532).
///   ESCROW_ADDRESS reuse an already deployed stand-in escrow instead of deploying one
contract DeploySepolia is Script {
    address constant CIRCLE_USDC_BASE_SEPOLIA = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;

    function run() external returns (address usdc, address escrow, address glue) {
        require(block.chainid == 84532 || block.chainid == 31337, "DeploySepolia: use on Base Sepolia (84532) or a local anvil");

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        bool mockUsdc = vm.envOr("MOCK_USDC", false);
        address usdcAddr = vm.envOr("USDC_ADDRESS", CIRCLE_USDC_BASE_SEPOLIA);
        address escrowAddr = vm.envOr("ESCROW_ADDRESS", address(0));

        vm.startBroadcast(deployerPrivateKey);

        if (mockUsdc) {
            usdcAddr = address(new MockUSDC());
            console.log("MockUSDC deployed at:", usdcAddr);
        } else {
            require(usdcAddr.code.length > 0, "DeploySepolia: USDC_ADDRESS has no code");
            console.log("Using USDC at:", usdcAddr);
        }

        if (escrowAddr == address(0)) {
            escrowAddr = address(new MockEscrowWithOrchestrator(usdcAddr));
            console.log("MockEscrowWithOrchestrator deployed at:", escrowAddr);
        } else {
            require(escrowAddr.code.length > 0, "DeploySepolia: ESCROW_ADDRESS has no code");
            console.log("Using stand-in escrow at:", escrowAddr);
        }

        OfframpGlue offrampGlue = new OfframpGlue(usdcAddr, escrowAddr);
        console.log("OfframpGlue deployed at:", address(offrampGlue));
        console.log("Owner:", offrampGlue.owner());
        console.log("Keeper:", offrampGlue.keeper());

        vm.stopBroadcast();

        return (usdcAddr, escrowAddr, address(offrampGlue));
    }
}
