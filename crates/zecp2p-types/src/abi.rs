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

// zk-p2p EscrowV2 interface (subset we need)
// Matches the verified deployment at 0x777777779d229cdF3110e9de47943791c26300Ef on Base.
sol! {
    #[sol(rpc)]
    interface IEscrow {
        struct Range {
            uint256 min;
            uint256 max;
        }

        struct OracleRateConfig {
            address adapter;
            bytes adapterConfig;
            int16 spreadBps;
            uint32 maxStaleness;
        }

        struct Currency {
            bytes32 code;
            uint256 minConversionRate;
            OracleRateConfig oracleRateConfig;
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
            Range intentAmountRange;
            bool acceptingIntents;
            uint256 remainingDeposits;
            uint256 outstandingIntentAmount;
            address intentGuardian;
            bool retainOnEmpty;
        }

        /// Returns nothing; the new deposit's id is depositCounter() before the call
        function createDeposit(CreateDepositParams calldata params) external;
        /// Withdraws all remaining liquidity (depositor only)
        function withdrawDeposit(uint256 depositId) external;
        function depositCounter() external view returns (uint256);
        function getDeposit(uint256 depositId) external view returns (Deposit memory);

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
        struct OracleRateConfig {
            address adapter;
            bytes adapterConfig;
            int16 spreadBps;
            uint32 maxStaleness;
        }

        struct Currency {
            bytes32 code;
            uint256 minConversionRate;
            OracleRateConfig oracleRateConfig;
        }

        struct DepositPaymentMethodData {
            address intentGatingService;
            bytes32 payeeDetails;
            bytes data;
        }

        struct Session {
            address user;
            bytes32 payeeDetailsHash;
            uint256 minConversionRate;
            uint256 expectedAmount;
            uint256 credited;
            uint256 deposited;
            uint256 depositId;
            bool processed;
            bool fulfilled;
            bool rescued;
            bool withdrawn;
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
            bytes32 payeeDetailsHash,
            uint256 expectedAmount
        );

        event SessionCredited(bytes32 indexed sessionId, uint256 amount, uint256 totalCredited);

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

        event SessionWithdrawn(
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
            bytes32 payeeDetailsHash,
            uint256 minConversionRate,
            uint256 expectedAmount
        ) external;

        function creditSession(bytes32 sessionId, uint256 amount) external;

        function processOfframp(
            bytes32 sessionId,
            bytes32[] calldata paymentMethods,
            DepositPaymentMethodData[] calldata paymentMethodData,
            Currency[][] calldata currencies
        ) external returns (uint256 depositId);

        function rescue(bytes32 sessionId) external;

        function withdrawFromZkp2p(bytes32 sessionId) external;

        function setKeeper(address newKeeper) external;

        function getSession(bytes32 sessionId) external view returns (Session memory);

        function getContractUsdcBalance() external view returns (uint256);

        function totalCommitted() external view returns (uint256);

        function unassignedBalance() external view returns (uint256);
    }
}

// MockUSDC interface for local testing (extends IERC20)
sol! {
    #[sol(rpc)]
    interface MockUSDC {
        function name() external view returns (string memory);
        function symbol() external view returns (string memory);
        function decimals() external view returns (uint8);
        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);

        /// Mint function for testing - not in real USDC
        function mint(address to, uint256 amount) external;

        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
    }
}

// MockEscrowWithOrchestrator interface for enhanced local testing
sol! {
    #[sol(rpc)]
    interface MockEscrowWithOrchestrator {
        // Escrow functions (EscrowV2 shapes)
        struct Range {
            uint256 min;
            uint256 max;
        }

        struct OracleRateConfig {
            address adapter;
            bytes adapterConfig;
            int16 spreadBps;
            uint32 maxStaleness;
        }

        struct Currency {
            bytes32 code;
            uint256 minConversionRate;
            OracleRateConfig oracleRateConfig;
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
            Range intentAmountRange;
            bool acceptingIntents;
            uint256 remainingDeposits;
            uint256 outstandingIntentAmount;
            address intentGuardian;
            bool retainOnEmpty;
        }

        function createDeposit(CreateDepositParams calldata params) external;
        function withdrawDeposit(uint256 depositId) external;
        function depositCounter() external view returns (uint256);
        function getDeposit(uint256 depositId) external view returns (Deposit memory);
        function getDepositPayeeDetails(uint256 depositId, bytes32 paymentMethod) external view returns (bytes32);

        // Orchestrator functions
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

        function signalIntent(
            uint256 depositId,
            address taker,
            uint256 amount,
            bytes32 paymentMethod,
            bytes32 fiatCurrency,
            uint256 conversionRate
        ) external returns (bytes32 intentHash);

        function fulfillIntent(bytes32 intentHash) external;

        function getIntent(bytes32 intentHash) external view returns (Intent memory);
        function getAccountIntents(address account) external view returns (bytes32[] memory);

        // Events
        event DepositReceived(
            uint256 indexed depositId,
            address indexed depositor,
            address indexed token,
            uint256 amount,
            Range intentAmountRange,
            address delegate,
            address intentGuardian
        );

        event DepositWithdrawn(uint256 indexed depositId, address indexed depositor, uint256 amount);

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

/// Build a zk-p2p `Currency` entry with a fixed rate floor and no oracle.
///
/// `min_conversion_rate` is fiat per deposit token in 18 decimals
/// (USD per USDC; 1e18 means the taker must pay at least 1 USD per USDC).
pub fn fixed_rate_currency(code: alloy::primitives::B256, min_conversion_rate: alloy::primitives::U256) -> OfframpGlue::Currency {
    OfframpGlue::Currency {
        code,
        minConversionRate: min_conversion_rate,
        oracleRateConfig: OfframpGlue::OracleRateConfig {
            adapter: alloy::primitives::Address::ZERO,
            adapterConfig: alloy::primitives::Bytes::new(),
            spreadBps: 0,
            maxStaleness: 0,
        },
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
