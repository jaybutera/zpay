//! zk-p2p ABIs the taker needs that the coordinator does not.
//!
//! The coordinator only ever reads intents. A taker writes them, so it needs
//! the exact `signalIntent` and `fulfillIntent` shapes, plus the StakeVault
//! behind OrchestratorV3's lifecycle hook.
//!
//! These were recovered from deployed bytecode on Base mainnet rather than from
//! a published ABI; `docs/taker-matching-design.md` records how, and
//! `scripts/taker/prove_open_signaling.sh` exercises them against a fork.

use alloy::sol;

sol! {
    /// zk-p2p OrchestratorV3, write side.
    ///
    /// `signalIntent` is selector 0xf3ff8655 and `fulfillIntent` is 0xac7a520c;
    /// both were confirmed against the code deployed at
    /// 0x014025fDE093f8701d86e9f38e2C3a9b779cb5c7.
    #[sol(rpc)]
    interface IOrchestratorWrite {
        struct Referrer {
            address referrer;
            uint256 fee;
        }

        struct SignalIntentParams {
            address escrow;
            uint256 depositId;
            uint256 amount;
            address to;
            bytes32 paymentMethod;
            bytes32 fiatCurrency;
            uint256 conversionRate;
            Referrer[] referrers;
            /// Empty when the deposit's intentGatingService is address(0),
            /// which is what OfframpGlue always sets.
            bytes gatingSignature;
            uint256 signatureExpiration;
            address postIntentHook;
            bytes data;
            bytes postIntentHookData;
        }

        struct FulfillIntentParams {
            /// Enclave-attested payment proof; see scripts/proof.
            bytes paymentProof;
            bytes32 intentHash;
            bytes verificationData;
            bytes postIntentHookData;
        }

        function signalIntent(SignalIntentParams calldata params) external;
        function fulfillIntent(FulfillIntentParams calldata params) external;
        function cancelIntent(bytes32 intentHash) external;
    }
}

sol! {
    /// zk-p2p StakeVault at 0x47c26258222e2f96424bD2B21bf173f0DA5034C7.
    ///
    /// OrchestratorV3's lifecycleHook locks stake equal to the intent amount
    /// when a taker signals. Without free stake, `signalIntent` reverts with
    /// `InsufficientFreeStake(taker, available, required)`.
    #[sol(rpc)]
    interface IStakeVault {
        function stakeToken() external view returns (address);
        function depositStake(uint256 amount) external;
        function withdrawStake(uint256 amount) external;
        function stakeBalance(address account) external view returns (uint256);
        function freeStake(address account) external view returns (uint256);
        function lockedStake(address account) external view returns (uint256);

        error InsufficientFreeStake(address taker, uint256 available, uint256 required);
    }
}

sol! {
    /// The subset of EscrowV2 a taker reads to price a deposit.
    #[sol(rpc)]
    interface IEscrowTaker {
        struct Range {
            uint256 min;
            uint256 max;
        }

        struct Deposit {
            address depositor;
            address delegate;
            address token;
            Range intentAmountRange;
            bool acceptingIntents;
            uint256 remainingDeposits;
            uint256 outstandingIntentAmount;
            address intentGuardian;
            bool retainOnEmpty;
        }

        function getDeposit(uint256 depositId) external view returns (Deposit memory);
        function depositCounter() external view returns (uint256);
    }
}
