// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IEscrow
/// @notice Interface for zk-p2p Escrow contract
/// @dev Based on https://github.com/zkp2p/zkp2p-contracts/blob/main/contracts/interfaces/IEscrow.sol
interface IEscrow {
    struct Range {
        uint256 min;
        uint256 max;
    }

    struct Currency {
        bytes32 code;               // keccak256 hash of currency code (e.g., keccak256("USD"))
        uint256 minConversionRate;  // Minimum rate in 18 decimal precision
    }

    struct DepositPaymentMethodData {
        address intentGatingService;  // Gating service public key for intent verification
        bytes32 payeeDetails;         // Hash of payee details (e.g., Venmo username hash)
        bytes data;                   // Additional verification data (attester address, etc.)
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
        uint256 amount;
        Range intentAmountRange;
        bytes32[] acceptedPaymentMethods;
        address intentGuardian;
        bool retainOnEmpty;
        bool closed;
    }

    /// @notice Create a new deposit for off-ramping
    /// @param params Deposit creation parameters
    /// @return depositId The unique deposit identifier
    function createDeposit(CreateDepositParams calldata params) external returns (uint256 depositId);

    /// @notice Withdraw funds from a deposit
    /// @param depositId The deposit to withdraw from
    /// @param amount Amount to withdraw
    function withdrawDeposit(uint256 depositId, uint256 amount) external;

    /// @notice Get deposit details
    /// @param depositId The deposit to query
    /// @return Deposit struct
    function getDeposit(uint256 depositId) external view returns (Deposit memory);

    /// @notice Get all deposits for an account
    /// @param account Account to query
    /// @return Array of deposit IDs
    function getAccountDeposits(address account) external view returns (uint256[] memory);

    // Events
    event DepositCreated(
        uint256 indexed depositId,
        address indexed depositor,
        address indexed token,
        uint256 amount
    );

    event DepositWithdrawn(
        uint256 indexed depositId,
        address indexed depositor,
        uint256 amount
    );

    event DepositClosed(uint256 indexed depositId);
}
