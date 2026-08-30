// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {OfframpGlue} from "../src/OfframpGlue.sol";

/// @title DeployOfframpGlue
/// @notice Deployment script for OfframpGlue contract
contract DeployOfframpGlue is Script {
    // Base Mainnet addresses
    address constant USDC_BASE_MAINNET = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    // zk-p2p EscrowV2 (the escrow production makers deposit into; paired with OrchestratorV3)
    address constant ZKP2P_ESCROW_BASE_MAINNET = 0x777777779d229cdF3110e9de47943791c26300Ef;

    // Base Sepolia: zk-p2p's testnet escrows (0x6a5e11c3..., 0x15EF83EB...) expose
    // createDeposit signatures that differ from EscrowV2, so the glue cannot be
    // deployed against them. Use script/DeploySepolia.s.sol, which deploys a
    // stand-in escrow, or pass ZKP2P_ESCROW_ADDRESS explicitly if an
    // EscrowV2-compatible testnet deployment appears.
    address constant USDC_BASE_SEPOLIA = 0x036CbD53842c5426634e7929541eC2318f3dCF7e;

    function run() external {
        uint256 chainId = block.chainid;

        address usdc;
        address zkp2pEscrow;

        if (chainId == 8453) {
            // Base Mainnet
            console.log("Deploying to Base Mainnet...");
            usdc = USDC_BASE_MAINNET;
            zkp2pEscrow = ZKP2P_ESCROW_BASE_MAINNET;
        } else if (chainId == 84532) {
            // Base Sepolia
            console.log("Deploying to Base Sepolia...");
            usdc = USDC_BASE_SEPOLIA;
            zkp2pEscrow = vm.envOr("ZKP2P_ESCROW_ADDRESS", address(0));
            require(
                zkp2pEscrow != address(0),
                "No EscrowV2-compatible zk-p2p escrow on Base Sepolia; use DeploySepolia.s.sol or set ZKP2P_ESCROW_ADDRESS"
            );
        } else {
            revert("Unsupported chain");
        }

        console.log("USDC:", usdc);
        console.log("ZKP2P Escrow:", zkp2pEscrow);

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        OfframpGlue glue = new OfframpGlue(usdc, zkp2pEscrow);

        console.log("OfframpGlue deployed at:", address(glue));
        console.log("Owner:", glue.owner());
        console.log("Keeper:", glue.keeper());

        vm.stopBroadcast();
    }
}

/// @title SetKeeper
/// @notice Script to update the keeper address
contract SetKeeper is Script {
    function run(address glueContract, address newKeeper) external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        OfframpGlue glue = OfframpGlue(glueContract);
        glue.setKeeper(newKeeper);

        console.log("Keeper updated to:", newKeeper);

        vm.stopBroadcast();
    }
}
