// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "./interfaces/IERC20.sol";
import {IEscrow} from "./interfaces/IEscrow.sol";

/// @title OfframpGlue
/// @notice Bridges NEAR Intents (ZEC → USDC) with zk-p2p (USDC → Venmo)
/// @dev Single deployment on Base, shared by all users via sessions
contract OfframpGlue {
    // ============ Structs ============

    struct Session {
        address user;           // User's address for rescue/withdraw
        bytes32 venmoIdHash;    // keccak256 of Venmo username
        uint256 minConversionRate; // Minimum acceptable rate (18 decimals)
        uint256 expectedAmount; // Expected USDC from NEAR Intent (6 decimals)
        uint256 depositId;      // zk-p2p deposit ID (0 until processed)
        bool fulfilled;         // Whether session is complete
        bool rescued;           // Whether user rescued funds
    }

    // ============ State ============

    address public immutable owner;
    address public keeper;
    IERC20 public immutable usdc;
    IEscrow public immutable zkp2pEscrow;

    mapping(bytes32 => Session) public sessions;

    // ============ Events ============

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

    // ============ Errors ============

    error Unauthorized();
    error SessionExists();
    error SessionNotFound();
    error SessionAlreadyProcessed();
    error SessionAlreadyRescued();
    error InsufficientBalance();
    error NoDepositToWithdraw();
    error ZeroAddress();
    error ZeroAmount();
    error TransferFailed();

    // ============ Modifiers ============

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyKeeper() {
        if (msg.sender != keeper && msg.sender != owner) revert Unauthorized();
        _;
    }

    // ============ Constructor ============

    constructor(address _usdc, address _zkp2pEscrow) {
        if (_usdc == address(0) || _zkp2pEscrow == address(0)) revert ZeroAddress();

        owner = msg.sender;
        keeper = msg.sender;
        usdc = IERC20(_usdc);
        zkp2pEscrow = IEscrow(_zkp2pEscrow);
    }

    // ============ Session Management ============

    /// @notice Create a new offramp session
    /// @param sessionId Unique session identifier (from coordinator)
    /// @param user User's address for rescue/withdraw operations
    /// @param venmoIdHash keccak256 hash of user's Venmo username
    /// @param minConversionRate Minimum acceptable USDC/fiat rate (18 decimals)
    /// @param expectedAmount Expected USDC amount from NEAR Intent (6 decimals)
    function createSession(
        bytes32 sessionId,
        address user,
        bytes32 venmoIdHash,
        uint256 minConversionRate,
        uint256 expectedAmount
    ) external onlyKeeper {
        if (sessions[sessionId].user != address(0)) revert SessionExists();
        if (user == address(0)) revert ZeroAddress();
        if (expectedAmount == 0) revert ZeroAmount();

        sessions[sessionId] = Session({
            user: user,
            venmoIdHash: venmoIdHash,
            minConversionRate: minConversionRate,
            expectedAmount: expectedAmount,
            depositId: 0,
            fulfilled: false,
            rescued: false
        });

        emit SessionCreated(sessionId, user, venmoIdHash, expectedAmount);
    }

    /// @notice Process received USDC by depositing to zk-p2p
    /// @param sessionId Session to process
    /// @param paymentMethods Payment methods for zk-p2p deposit (e.g., [keccak256("venmo")])
    /// @param paymentMethodData Payment verification data for each method
    /// @param currencies Accepted currencies for each payment method
    /// @return depositId The zk-p2p deposit ID
    function processOfframp(
        bytes32 sessionId,
        bytes32[] calldata paymentMethods,
        IEscrow.DepositPaymentMethodData[] calldata paymentMethodData,
        IEscrow.Currency[][] calldata currencies
    ) external onlyKeeper returns (uint256 depositId) {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (session.depositId != 0) revert SessionAlreadyProcessed();
        if (session.rescued) revert SessionAlreadyRescued();

        // Use actual balance (may differ from expectedAmount due to fees/slippage)
        uint256 balance = usdc.balanceOf(address(this));
        if (balance == 0) revert InsufficientBalance();

        // Approve zk-p2p escrow to spend USDC
        usdc.approve(address(zkp2pEscrow), balance);

        // Create deposit parameters
        IEscrow.CreateDepositParams memory params = IEscrow.CreateDepositParams({
            token: address(usdc),
            amount: balance,
            intentAmountRange: IEscrow.Range({
                min: balance,  // Single intent for full amount
                max: balance
            }),
            paymentMethods: paymentMethods,
            paymentMethodData: paymentMethodData,
            currencies: currencies,
            delegate: address(0),  // No delegate
            intentGuardian: address(0),  // No guardian
            retainOnEmpty: false  // Close deposit when drained
        });

        // Create the zk-p2p deposit
        depositId = zkp2pEscrow.createDeposit(params);

        session.depositId = depositId;

        emit OfframpProcessed(sessionId, depositId, balance);

        return depositId;
    }

    /// @notice Rescue USDC back to user if something fails before zk-p2p deposit
    /// @param sessionId Session to rescue
    function rescue(bytes32 sessionId) external {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (msg.sender != session.user) revert Unauthorized();
        if (session.depositId != 0) revert SessionAlreadyProcessed();
        if (session.rescued) revert SessionAlreadyRescued();

        uint256 balance = usdc.balanceOf(address(this));
        if (balance == 0) revert InsufficientBalance();

        session.rescued = true;

        bool success = usdc.transfer(session.user, balance);
        if (!success) revert TransferFailed();

        emit SessionRescued(sessionId, session.user, balance);
    }

    /// @notice Withdraw USDC from zk-p2p if no taker fulfilled
    /// @param sessionId Session to withdraw
    /// @param amount Amount to withdraw from zk-p2p deposit
    function withdrawFromZkp2p(bytes32 sessionId, uint256 amount) external {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (msg.sender != session.user) revert Unauthorized();
        if (session.depositId == 0) revert NoDepositToWithdraw();

        // Withdraw from zk-p2p
        zkp2pEscrow.withdrawDeposit(session.depositId, amount);

        // Transfer to user
        uint256 balance = usdc.balanceOf(address(this));
        if (balance > 0) {
            bool success = usdc.transfer(session.user, balance);
            if (!success) revert TransferFailed();
        }
    }

    // ============ Admin ============

    /// @notice Update the keeper address
    /// @param newKeeper New keeper address
    function setKeeper(address newKeeper) external onlyOwner {
        if (newKeeper == address(0)) revert ZeroAddress();

        address oldKeeper = keeper;
        keeper = newKeeper;

        emit KeeperUpdated(oldKeeper, newKeeper);
    }

    // ============ View Functions ============

    /// @notice Get session details
    /// @param sessionId Session to query
    /// @return Session struct
    function getSession(bytes32 sessionId) external view returns (Session memory) {
        return sessions[sessionId];
    }

    /// @notice Get contract's USDC balance
    /// @return balance USDC balance
    function getContractUsdcBalance() external view returns (uint256) {
        return usdc.balanceOf(address(this));
    }
}
