// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {OfframpGlue} from "../src/OfframpGlue.sol";

/// @title DeployOfframpGlue
/// @notice Deploys OfframpGlue against the USDC and zk-p2p escrow it is told to use.
///
/// Both addresses come from the environment. The built-in values are the Base
/// mainnet ones and are used only when the variable is unset, so a deploy to
/// any other chain has to name its own; nothing is inferred from the chain id
/// beyond the guard below.
///
/// Env:
///   DEPLOYER_PRIVATE_KEY  deployer; becomes owner and keeper of the glue.
///                         PRIVATE_KEY is accepted as a fallback.
///   USDC_ADDRESS          ERC-20 the glue escrows. Default: Base mainnet USDC.
///   ZKP2P_ESCROW_ADDRESS  EscrowV2 to deposit into. Default: Base mainnet EscrowV2.
///   EXPECTED_CHAIN_ID     refuse to run on any other chain. Default 8453.
///
/// Base Sepolia note: zk-p2p's testnet escrows (0x6a5e11c3..., 0x15EF83EB...)
/// expose createDeposit signatures that differ from EscrowV2, so the glue
/// cannot deposit into them. Use script/DeploySepolia.s.sol, which deploys a
/// stand-in escrow, unless an EscrowV2-compatible testnet deployment appears.
contract DeployOfframpGlue is Script {
    address constant USDC_BASE_MAINNET = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    // zk-p2p EscrowV2 (the escrow production makers deposit into; paired with OrchestratorV3)
    address constant ZKP2P_ESCROW_BASE_MAINNET = 0x777777779d229cdF3110e9de47943791c26300Ef;

    function run() external returns (address glueAddress) {
        uint256 expectedChainId = vm.envOr("EXPECTED_CHAIN_ID", uint256(8453));
        require(
            block.chainid == expectedChainId,
            "chain id does not match EXPECTED_CHAIN_ID; refusing to deploy"
        );

        address usdc = vm.envOr("USDC_ADDRESS", USDC_BASE_MAINNET);
        address zkp2pEscrow = vm.envOr("ZKP2P_ESCROW_ADDRESS", ZKP2P_ESCROW_BASE_MAINNET);

        // A glue pointing at an address with no code would accept createSession
        // and then revert on every deposit. Catch it here, not after paying for
        // the deploy.
        require(usdc.code.length > 0, "USDC_ADDRESS has no code on this chain");
        require(zkp2pEscrow.code.length > 0, "ZKP2P_ESCROW_ADDRESS has no code on this chain");

        console.log("Chain id:", block.chainid);
        console.log("USDC:", usdc);
        console.log("ZKP2P Escrow:", zkp2pEscrow);

        vm.startBroadcast(deployerKey());

        OfframpGlue glue = new OfframpGlue(usdc, zkp2pEscrow);

        console.log("OfframpGlue deployed at:", address(glue));
        console.log("Owner:", glue.owner());
        console.log("Keeper:", glue.keeper());

        vm.stopBroadcast();

        return address(glue);
    }

    /// @dev DEPLOYER_PRIVATE_KEY is the name the deploy scripts and .env use.
    ///      PRIVATE_KEY stays accepted so the older testnet and fork scripts
    ///      keep working unchanged.
    function deployerKey() internal view returns (uint256) {
        uint256 key = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        if (key == 0) key = vm.envUint("PRIVATE_KEY");
        return key;
    }
}

/// @title SetKeeper
/// @notice Script to update the keeper address
contract SetKeeper is Script {
    /// @notice Point the glue's keeper at `newKeeper`. Only the owner may.
    /// @dev Idempotent: if the keeper is already `newKeeper` this sends nothing,
    ///      so re-running the deploy sequence costs no gas the second time.
    function run(address glueContract, address newKeeper) external {
        require(newKeeper != address(0), "SetKeeper: keeper cannot be the zero address");
        require(glueContract.code.length > 0, "SetKeeper: glueContract has no code");

        OfframpGlue glue = OfframpGlue(glueContract);
        address current = glue.keeper();
        if (current == newKeeper) {
            console.log("Keeper is already", newKeeper);
            console.log("Nothing to do.");
            return;
        }

        uint256 key = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        if (key == 0) key = vm.envUint("PRIVATE_KEY");

        console.log("Keeper currently:", current);
        vm.startBroadcast(key);
        glue.setKeeper(newKeeper);
        vm.stopBroadcast();

        console.log("Keeper updated to:", newKeeper);
    }
}
