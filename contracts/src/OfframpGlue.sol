// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "./interfaces/IERC20.sol";
import {IEscrow} from "./interfaces/IEscrow.sol";

/// @title OfframpGlue
/// @notice Bridges NEAR Intents (ZEC → USDC) with zk-p2p (USDC → Venmo)
/// @dev Single deployment on Base, shared by all users via sessions.
///
///      Every USDC amount this contract moves is drawn from a per-session
///      balance, never from `usdc.balanceOf(address(this))`. The contract holds
///      one pot but accounts for it in slices: `session.credited` is what a
///      session owns and `totalCommitted` is the sum of every unspent slice.
///      Only the difference between the token balance and `totalCommitted` is
///      available to credit, so a session can never be funded out of another
///      session's money, and every payout is bounded by what its own session
///      was credited. Concurrent sessions are therefore safe.
contract OfframpGlue {
    // ============ Structs ============

    struct Session {
        address user;           // User's address for rescue/withdraw
        bytes32 payeeDetailsHash; // zk-p2p payee details hash (curator-issued hashedOnchainId)
        uint256 minConversionRate; // Minimum acceptable rate (18 decimals)
        uint256 expectedAmount; // Expected USDC from NEAR Intent (6 decimals)
        uint256 credited;       // USDC this session owns and may spend (6 decimals)
        uint256 deposited;      // USDC this session put into zk-p2p (6 decimals)
        uint256 depositId;      // zk-p2p deposit ID (meaningful once processed; EscrowV2 ids start at 0)
        bool processed;         // Whether USDC was deposited to zk-p2p
        bool fulfilled;         // Whether session is complete
        bool rescued;           // Whether user rescued funds
        bool withdrawn;         // Whether the zk-p2p deposit was withdrawn back to the user
    }

    // ============ State ============

    address public immutable owner;
    address public keeper;
    IERC20 public immutable usdc;
    IEscrow public immutable zkp2pEscrow;

    mapping(bytes32 => Session) public sessions;

    /// @dev Reentrancy latch. USDC on Base is a standard non-callback token today,
    ///      but it sits behind an upgradeable proxy and this contract does not.
    ///      A token that called back into `creditSession` from inside the payout
    ///      in `withdrawFromZkp2p` could assign another session the money on its
    ///      way out the door, leaving `totalCommitted` above the real balance and
    ///      bricking every later credit. One slot is cheaper than that risk.
    uint256 private _entered;

    /// @notice Sum of every session's unspent `credited` balance.
    /// @dev The contract's USDC balance above this figure is unassigned and is
    ///      the only pool `creditSession` may draw on. Decremented whenever a
    ///      session's credit leaves the contract or is committed to zk-p2p.
    uint256 public totalCommitted;

    // ============ Events ============

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

    // ============ Errors ============

    error Unauthorized();
    error SessionExists();
    error SessionNotFound();
    error SessionAlreadyProcessed();
    error SessionAlreadyRescued();
    error SessionAlreadyWithdrawn();
    error InsufficientBalance();
    error InsufficientUnassignedBalance();
    error NoDepositToWithdraw();
    error NothingCredited();
    error ZeroAddress();
    error ZeroAmount();
    error TransferFailed();
    error PayeeDetailsMismatch();
    error DepositNotCreated();
    error EmptyPaymentMethods();
    error PaymentMethodLengthMismatch();
    error CreditExceedsExpected();
    error Reentrancy();

    // ============ Modifiers ============

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier onlyKeeper() {
        if (msg.sender != keeper && msg.sender != owner) revert Unauthorized();
        _;
    }

    modifier nonReentrant() {
        if (_entered == 1) revert Reentrancy();
        _entered = 1;
        _;
        _entered = 0;
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
            credited: 0,
            deposited: 0,
            depositId: 0,
            processed: false,
            fulfilled: false,
            rescued: false,
            withdrawn: false
        });

        emit SessionCreated(sessionId, user, payeeDetailsHash, expectedAmount);
    }

    /// @notice Assign arrived USDC to a session.
    /// @dev This is the only way money becomes spendable by a session, and it can
    ///      only draw on USDC that no other session already owns. `amount` is
    ///      capped at the session's `expectedAmount` so a keeper mistake cannot
    ///      hand one session more than the NEAR Intent quoted for it; the surplus
    ///      stays unassigned and can be credited to whichever session it belongs to.
    /// @param sessionId Session to credit
    /// @param amount USDC units (6 decimals) to assign to the session
    function creditSession(bytes32 sessionId, uint256 amount) public onlyKeeper nonReentrant {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (session.processed) revert SessionAlreadyProcessed();
        if (session.rescued) revert SessionAlreadyRescued();
        if (amount == 0) revert ZeroAmount();

        if (session.credited + amount > session.expectedAmount) revert CreditExceedsExpected();

        // Only USDC that no session owns yet may be assigned.
        if (usdc.balanceOf(address(this)) - totalCommitted < amount) {
            revert InsufficientUnassignedBalance();
        }

        session.credited += amount;
        totalCommitted += amount;

        emit SessionCredited(sessionId, amount, session.credited);
    }

    /// @notice Process a session's credited USDC by depositing it to zk-p2p
    /// @dev Deposits exactly `session.credited`, never the contract balance, so a
    ///      session cannot deposit money belonging to another session.
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
    ) external onlyKeeper nonReentrant returns (uint256 depositId) {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (session.processed) revert SessionAlreadyProcessed();
        if (session.rescued) revert SessionAlreadyRescued();

        // A zero-length paymentMethodData would make the payee loop below a no-op,
        // so the deposit would carry no checked payee at all. Require at least one
        // method, and require the three parallel arrays to line up.
        if (paymentMethods.length == 0) revert EmptyPaymentMethods();
        if (paymentMethods.length != paymentMethodData.length) revert PaymentMethodLengthMismatch();
        if (paymentMethods.length != currencies.length) revert PaymentMethodLengthMismatch();

        // Every payment method on the deposit must pay out to the payee registered
        // for this session; otherwise the keeper could route the user's USDC to
        // someone else's Venmo account.
        for (uint256 i = 0; i < paymentMethodData.length; i++) {
            if (paymentMethodData[i].payeeDetails != session.payeeDetailsHash) revert PayeeDetailsMismatch();
        }

        // Spend only what this session owns.
        uint256 amount = session.credited;
        if (amount == 0) revert NothingCredited();

        // Effects before the external calls: the credit is now spoken for by the
        // zk-p2p deposit rather than held here, so it leaves the committed pool.
        session.credited = 0;
        session.processed = true;
        totalCommitted -= amount;

        // Approve zk-p2p escrow to spend exactly this session's amount
        usdc.approve(address(zkp2pEscrow), amount);

        // Create deposit parameters
        IEscrow.CreateDepositParams memory params = IEscrow.CreateDepositParams({
            token: address(usdc),
            amount: amount,
            intentAmountRange: IEscrow.Range({
                min: amount,  // Single intent for full amount
                max: amount
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
        session.deposited = amount;

        emit OfframpProcessed(sessionId, depositId, amount);

        return depositId;
    }

    /// @notice Return a session's credited USDC to its user if something fails
    ///         before the zk-p2p deposit.
    /// @dev Callable by the session's user or by the keeper, but the money always
    ///      goes to `session.user` and is always exactly `session.credited`. The
    ///      user path is the escape hatch that does not depend on the keeper being
    ///      alive; the keeper path exists so the coordinator can unwind a failed
    ///      session without the user having to hold ETH for gas. Neither can take
    ///      anything belonging to another session.
    /// @param sessionId Session to rescue
    function rescue(bytes32 sessionId) external nonReentrant {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (msg.sender != session.user && msg.sender != keeper && msg.sender != owner) {
            revert Unauthorized();
        }
        if (session.processed) revert SessionAlreadyProcessed();
        if (session.rescued) revert SessionAlreadyRescued();

        uint256 amount = session.credited;
        if (amount == 0) revert InsufficientBalance();

        session.credited = 0;
        session.rescued = true;
        totalCommitted -= amount;

        bool success = usdc.transfer(session.user, amount);
        if (!success) revert TransferFailed();

        emit SessionRescued(sessionId, session.user, amount);
    }

    /// @notice Withdraw the remaining USDC from the zk-p2p deposit if no taker fulfilled it
    /// @dev EscrowV2.withdrawDeposit returns everything not locked by an open intent
    ///      and closes the deposit; only the depositor (this contract) may call it.
    ///      Only the USDC that this withdrawal actually returned is forwarded, measured
    ///      as the balance delta across the call, so an unrelated session's funds
    ///      sitting on the contract are never swept out with it. Callable once, by the
    ///      session's user or by the keeper, and always pays `session.user`.
    /// @param sessionId Session to withdraw
    function withdrawFromZkp2p(bytes32 sessionId) external nonReentrant {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (msg.sender != session.user && msg.sender != keeper && msg.sender != owner) {
            revert Unauthorized();
        }
        if (!session.processed) revert NoDepositToWithdraw();
        if (session.withdrawn) revert SessionAlreadyWithdrawn();

        session.withdrawn = true;

        // Measure what the escrow actually returned rather than reading the whole
        // balance, which would include other sessions' credited USDC.
        uint256 before = usdc.balanceOf(address(this));
        zkp2pEscrow.withdrawDeposit(session.depositId);
        uint256 returned = usdc.balanceOf(address(this)) - before;

        // The delta measures every USDC that arrived during the call, not only
        // what the escrow sent back. A NEAR settlement for another session landing
        // in the same transaction would otherwise be paid out here. This session
        // can never be owed more than it put in, so that is the ceiling.
        if (returned > session.deposited) {
            returned = session.deposited;
        }

        if (returned > 0) {
            bool success = usdc.transfer(session.user, returned);
            if (!success) revert TransferFailed();
        }

        emit SessionWithdrawn(sessionId, session.user, returned);
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

    /// @notice USDC held by this contract that no session owns yet.
    /// @dev What `creditSession` may draw on. Arrivals show up here first.
    function unassignedBalance() external view returns (uint256) {
        return usdc.balanceOf(address(this)) - totalCommitted;
    }
}
