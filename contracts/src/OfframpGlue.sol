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
        bytes32 payeeDetailsHash; // zk-p2p payee details hash (curator-issued hashedOnchainId)
        uint256 minConversionRate; // Minimum acceptable rate (18 decimals)
        uint256 expectedAmount; // Expected USDC from NEAR Intent (6 decimals)
        uint256 depositId;      // zk-p2p deposit ID (meaningful once processed; EscrowV2 ids start at 0)
        bool processed;         // Whether USDC was deposited to zk-p2p
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
        bytes32 payeeDetailsHash,
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
    error PayeeDetailsMismatch();
    error DepositNotCreated();

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
    /// @param payeeDetailsHash zk-p2p payee details hash for the user's Venmo account.
    ///        This is the hashedOnchainId issued by the zk-p2p curator API when the
    ///        username is registered; it is not derivable from the username.
    /// @param minConversionRate Minimum acceptable USDC/fiat rate (18 decimals)
    /// @param expectedAmount Expected USDC amount from NEAR Intent (6 decimals)
    function createSession(
        bytes32 sessionId,
        address user,
        bytes32 payeeDetailsHash,
        uint256 minConversionRate,
        uint256 expectedAmount
    ) external onlyKeeper {
        if (sessions[sessionId].user != address(0)) revert SessionExists();
        if (user == address(0)) revert ZeroAddress();
        if (expectedAmount == 0) revert ZeroAmount();

        sessions[sessionId] = Session({
            user: user,
            payeeDetailsHash: payeeDetailsHash,
            minConversionRate: minConversionRate,
            expectedAmount: expectedAmount,
            depositId: 0,
            processed: false,
            fulfilled: false,
            rescued: false
        });

        emit SessionCreated(sessionId, user, payeeDetailsHash, expectedAmount);
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
        if (session.processed) revert SessionAlreadyProcessed();
        if (session.rescued) revert SessionAlreadyRescued();

        // Every payment method on the deposit must pay out to the payee registered
        // for this session; otherwise the keeper could route the user's USDC to
        // someone else's Venmo account.
        for (uint256 i = 0; i < paymentMethodData.length; i++) {
            if (paymentMethodData[i].payeeDetails != session.payeeDetailsHash) revert PayeeDetailsMismatch();
        }

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

        // EscrowV2.createDeposit returns nothing; it assigns depositCounter and
        // increments it. Read the counter before and verify it moved by exactly one.
        depositId = zkp2pEscrow.depositCounter();
        zkp2pEscrow.createDeposit(params);
        if (zkp2pEscrow.depositCounter() != depositId + 1) revert DepositNotCreated();

        session.depositId = depositId;
        session.processed = true;

        emit OfframpProcessed(sessionId, depositId, balance);

        return depositId;
    }

    /// @notice Rescue USDC back to user if something fails before zk-p2p deposit
    /// @param sessionId Session to rescue
    function rescue(bytes32 sessionId) external {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (msg.sender != session.user) revert Unauthorized();
        if (session.processed) revert SessionAlreadyProcessed();
        if (session.rescued) revert SessionAlreadyRescued();

        uint256 balance = usdc.balanceOf(address(this));
        if (balance == 0) revert InsufficientBalance();

        session.rescued = true;

        bool success = usdc.transfer(session.user, balance);
        if (!success) revert TransferFailed();

        emit SessionRescued(sessionId, session.user, balance);
    }

    /// @notice Withdraw the remaining USDC from the zk-p2p deposit if no taker fulfilled it
    /// @dev EscrowV2.withdrawDeposit returns everything not locked by an open intent
    ///      and closes the deposit; only the depositor (this contract) may call it.
    /// @param sessionId Session to withdraw
    function withdrawFromZkp2p(bytes32 sessionId) external {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (msg.sender != session.user) revert Unauthorized();
        if (!session.processed) revert NoDepositToWithdraw();

        // Withdraw from zk-p2p
        zkp2pEscrow.withdrawDeposit(session.depositId);

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
