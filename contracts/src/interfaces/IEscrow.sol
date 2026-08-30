// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IEscrow
/// @notice Subset of the zk-p2p EscrowV2 interface used by OfframpGlue
/// @dev Matches the verified deployment at 0x777777779d229cdF3110e9de47943791c26300Ef (Base mainnet).
///      Source: https://github.com/zkp2p/zkp2p-contracts/blob/main/contracts/interfaces/IEscrowV2.sol
///      Struct layouts here are part of the function selectors, so they must stay byte-for-byte
///      identical to EscrowV2's.
interface IEscrow {
    struct Range {
        uint256 min;
        uint256 max;
    }

    /// @dev Optional oracle-driven rate floor. adapter == address(0) disables it, in which case
    ///      minConversionRate is the only floor.
    struct OracleRateConfig {
        address adapter;
        bytes adapterConfig;
        int16 spreadBps;
        uint32 maxStaleness;
    }

    struct Currency {
        bytes32 code;                     // keccak256 hash of currency code (e.g., keccak256("USD"))
        uint256 minConversionRate;        // Minimum fiat per deposit token, 18 decimals (USD per USDC)
        OracleRateConfig oracleRateConfig; // Oracle floor config (adapter == address(0) means disabled)
    }

    struct DepositPaymentMethodData {
        address intentGatingService;  // Gating service that must sign signalIntent (address(0) = none)
        bytes32 payeeDetails;         // Payee details hash issued by the zk-p2p curator (hashedOnchainId)
        bytes data;                   // Additional verification data
    }

    struct CreateDepositParams {
        address token;                              // Token to deposit (USDC)
        uint256 amount;                             // Amount to deposit
        Range intentAmountRange;                    // Min/max per intent
        bytes32[] paymentMethods;                   // Supported payment methods
        DepositPaymentMethodData[] paymentMethodData; // Verification data per method
        Currency[][] currencies;                    // Currencies per payment method
        address delegate;                           // Optional delegate (address(0) for none)
        address intentGuardian;                     // Optional guardian (address(0) for none)
        bool retainOnEmpty;                         // Keep deposit open when empty
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

    /// @notice Create a new deposit. EscrowV2 returns nothing; the deposit id is the value of
    ///         depositCounter() immediately before the call.
    function createDeposit(CreateDepositParams calldata params) external;

    /// @notice Withdraw all remaining liquidity from a deposit (depositor only)
    function withdrawDeposit(uint256 depositId) external;

    /// @notice Id that the next createDeposit will be assigned
    function depositCounter() external view returns (uint256);

    /// @notice Get deposit details
    function getDeposit(uint256 depositId) external view returns (Deposit memory);

    // Events (EscrowV2 signatures)
    event DepositReceived(
        uint256 indexed depositId,
        address indexed depositor,
        address indexed token,
        uint256 amount,
        Range intentAmountRange,
        address delegate,
        address intentGuardian
    );

    event DepositPaymentMethodAdded(
        uint256 indexed depositId,
        bytes32 indexed paymentMethod,
        bytes32 indexed payeeDetails,
        address intentGatingService
    );

    event DepositWithdrawn(uint256 indexed depositId, address indexed depositor, uint256 amount);
}
