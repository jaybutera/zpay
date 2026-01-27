//! Contract ABIs for zecp2p
//!
//! This module contains Alloy sol! macro definitions for:
//! - GlueContract (our contract)
//! - zk-p2p IEscrow interface
//! - IERC20 interface

use alloy::sol;

// IERC20 interface for USDC
sol! {
    #[sol(rpc)]
    interface IERC20 {
        function name() external view returns (string memory);
        function symbol() external view returns (string memory);
        function decimals() external view returns (uint8);
        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);

        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
    }
}

// zk-p2p Escrow interface (subset we need)
sol! {
    #[sol(rpc)]
    interface IEscrow {
        struct Range {
            uint256 min;
            uint256 max;
        }

        struct Currency {
            bytes32 code;
            uint256 minConversionRate;
        }

        struct DepositPaymentMethodData {
            address intentGatingService;
            bytes32 payeeDetails;
            bytes data;
        }

        struct CreateDepositParams {
            address token;
            uint256 amount;
            Range intentAmountRange;
            bytes32[] paymentMethods;
            DepositPaymentMethodData[] paymentMethodData;
            Currency[][] currencies;
            address delegate;
            address intentGuardian;
            bool retainOnEmpty;
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

        function createDeposit(CreateDepositParams calldata params) external returns (uint256 depositId);
        function withdrawDeposit(uint256 depositId, uint256 amount) external;
        function getDeposit(uint256 depositId) external view returns (Deposit memory);
        function getAccountDeposits(address account) external view returns (uint256[] memory);

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
    }
}

// zk-p2p Orchestrator interface (subset we need for monitoring)
sol! {
    #[sol(rpc)]
    interface IOrchestrator {
        struct Intent {
            address owner;
            address to;
            address escrow;
            uint256 depositId;
            uint256 amount;
            uint256 timestamp;
            bytes32 paymentMethod;
            bytes32 fiatCurrency;
            uint256 conversionRate;
            bytes32 payeeDetails;
            address referrer;
            uint256 referrerFee;
            address postIntentHook;
            bytes data;
        }

        function getIntent(bytes32 intentHash) external view returns (Intent memory);
        function getAccountIntents(address account) external view returns (bytes32[] memory);

        event IntentSignaled(
            bytes32 indexed intentHash,
            address indexed escrow,
            uint256 indexed depositId,
            bytes32 paymentMethod,
            address owner,
            address to,
            uint256 amount,
            bytes32 fiatCurrency,
            uint256 conversionRate,
            uint256 timestamp
        );

        event IntentFulfilled(
            bytes32 indexed intentHash,
            address indexed fundsTransferredTo,
            uint256 amount,
            bool isManualRelease
        );
    }
}

// GlueContract - our contract that bridges NEAR Intents to zk-p2p
// Note: Types are inlined because sol! blocks don't share types
sol! {
    #[sol(rpc)]
    contract OfframpGlue {
        // Inlined types from IEscrow that we need for processOfframp
        struct Currency {
            bytes32 code;
            uint256 minConversionRate;
        }

        struct DepositPaymentMethodData {
            address intentGatingService;
            bytes32 payeeDetails;
            bytes data;
        }

        struct Session {
            address user;
            bytes32 venmoIdHash;
            uint256 minConversionRate;
            uint256 expectedAmount;
            uint256 depositId;
            bool fulfilled;
            bool rescued;
        }

        // State
        address public owner;
        address public keeper;
        address public usdc;
        address public zkp2pEscrow;

        mapping(bytes32 => Session) public sessions;

        // Events
        event SessionCreated(
            bytes32 indexed sessionId,
            address indexed user,
            bytes32 venmoIdHash,
            uint256 expectedAmount
        );

        event OfframpProcessed(
            bytes32 indexed sessionId,
            uint256 indexed depositId,
            uint256 amount
        );

        event SessionRescued(
            bytes32 indexed sessionId,
            address indexed user,
            uint256 amount
        );

        event KeeperUpdated(address indexed oldKeeper, address indexed newKeeper);

        // Functions
        constructor(address _usdc, address _zkp2pEscrow);

        function createSession(
            bytes32 sessionId,
            address user,
            bytes32 venmoIdHash,
            uint256 minConversionRate,
            uint256 expectedAmount
        ) external;

        function processOfframp(
            bytes32 sessionId,
            bytes32[] calldata paymentMethods,
            DepositPaymentMethodData[] calldata paymentMethodData,
            Currency[][] calldata currencies
        ) external returns (uint256 depositId);

        function rescue(bytes32 sessionId) external;

        function withdrawFromZkp2p(bytes32 sessionId, uint256 amount) external;

        function setKeeper(address newKeeper) external;

        function getSession(bytes32 sessionId) external view returns (Session memory);

        function getContractUsdcBalance() external view returns (uint256);
    }
}

/// Payment method hash for Venmo
pub fn venmo_payment_method() -> alloy::primitives::B256 {
    alloy::primitives::keccak256(b"venmo")
}

/// Currency code hash for USD
pub fn usd_currency_code() -> alloy::primitives::B256 {
    alloy::primitives::keccak256(b"USD")
}
