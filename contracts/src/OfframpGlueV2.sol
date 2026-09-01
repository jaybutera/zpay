// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20} from "./interfaces/IERC20.sol";
import {IEscrow} from "./interfaces/IEscrow.sol";

/// @title OfframpGlueV2
/// @notice OfframpGlue plus a bounded, owner-settable protocol fee.
/// @dev PROTOTYPE. Not deployed. `OfframpGlue.sol` is the live contract at
///      0xafc314Ea35Bb05AaDb254F5B4A8e05db8e7739A9 and is not touched by this
///      file. Deploying this one is a redeploy, not an upgrade: the glue is
///      immutable by design and a fee cannot be added to a live deployment.
///
///      Every USDC amount this contract moves is drawn from a per-session
///      balance, never from `usdc.balanceOf(address(this))`. The contract holds
///      one pot but accounts for it in slices: `session.credited` is what a
///      session owns and `totalCommitted` is the sum of every unspent slice.
///      Only the difference between the token balance and `totalCommitted` is
///      available to credit, so a session can never be funded out of another
///      session's money, and every payout is bounded by what its own session
///      was credited. Concurrent sessions are therefore safe.
///
///      The fee adds the first balance this contract holds at rest. `accruedFees`
///      is money no session owns and the owner has not yet swept, so it joins
///      `totalCommitted` on the reserved side of the ledger: the pool
///      `creditSession` may draw on is the balance minus BOTH. Without that, an
///      accrued fee would be indistinguishable from an unassigned arrival and
///      would be credited away to the next session, and the sweep would then
///      have to come out of a live session's slice.
contract OfframpGlueV2 {
    // ============ Structs ============

    struct Session {
        address user;           // User's address for rescue/withdraw
        bytes32 payeeDetailsHash; // zk-p2p payee details hash (curator-issued hashedOnchainId)
        uint256 minConversionRate; // Minimum acceptable rate (18 decimals)
        uint256 expectedAmount; // Expected USDC from NEAR Intent (6 decimals)
        uint256 credited;       // USDC this session owns and may spend (6 decimals)
        uint256 deposited;      // USDC this session put into zk-p2p (6 decimals)
        uint256 feePaid;        // Protocol fee charged at processOfframp (6 decimals)
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
    /// @dev The contract's USDC balance above this figure and `accruedFees` is
    ///      unassigned and is the only pool `creditSession` may draw on.
    ///      Decremented whenever a session's credit leaves the contract or is
    ///      committed to zk-p2p.
    uint256 public totalCommitted;

    // ============ Fee state ============

    /// @notice Hard ceiling on the fee, in basis points. Not settable.
    /// @dev 100 bps = 1%. `setFeeBps` reverts above this, so the owner cannot
    ///      raise the fee to a level that meaningfully eats a user's principal,
    ///      and a reader can bound the worst case from the bytecode alone.
    uint256 public constant MAX_FEE_BPS = 100;

    uint256 private constant BPS_DENOMINATOR = 10_000;

    /// @notice Protocol fee in basis points, taken at `processOfframp`.
    /// @dev Starts at 0, so a deployment behaves exactly like the fee-less glue
    ///      until the owner turns the fee on deliberately.
    uint256 public feeBps;

    /// @notice Address the swept fees are sent to.
    address public feeRecipient;

    /// @notice USDC charged as fees and not yet swept.
    /// @dev Reserved money. It is excluded from the pool `creditSession` may
    ///      draw on, so it can never be credited to a session, and `sweepFees`
    ///      can only ever move this figure, never a session's slice.
    uint256 public accruedFees;

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

    /// @notice Emitted when a session is charged, alongside `OfframpProcessed`.
    /// @param gross What the session was credited before the fee.
    /// @param fee What the protocol kept.
    /// @param net What actually went into the zk-p2p deposit.
    event FeeCharged(bytes32 indexed sessionId, uint256 gross, uint256 fee, uint256 net);

    event FeeBpsUpdated(uint256 oldBps, uint256 newBps);

    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

    event FeesSwept(address indexed to, uint256 amount);

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
    error FeeTooHigh();
    error NoFeesToSweep();

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

    /// @param _usdc USDC token address
    /// @param _zkp2pEscrow zk-p2p EscrowV2 address
    /// @param _feeRecipient Where `sweepFees` sends accrued fees
    /// @dev The fee itself starts at zero. A deployment is fee-less until the
    ///      owner calls `setFeeBps`, so the fee can be switched on after the
    ///      contract has been observed working, rather than at the same moment.
    constructor(address _usdc, address _zkp2pEscrow, address _feeRecipient) {
        if (_usdc == address(0) || _zkp2pEscrow == address(0)) revert ZeroAddress();
        if (_feeRecipient == address(0)) revert ZeroAddress();

        owner = msg.sender;
        keeper = msg.sender;
        usdc = IERC20(_usdc);
        zkp2pEscrow = IEscrow(_zkp2pEscrow);
        feeRecipient = _feeRecipient;
    }

    // ============ Session Management ============

    /// @notice Create a new offramp session
    /// @param sessionId Unique session identifier (from coordinator)
    /// @param user User's address for rescue/withdraw operations
    /// @param payeeDetailsHash zk-p2p payee details hash for the user's Venmo account.
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
            feePaid: 0,
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
    ///      only draw on USDC that no other session already owns and that is not
    ///      reserved as an accrued fee. `amount` is capped at the session's
    ///      `expectedAmount` so a keeper mistake cannot hand one session more than
    ///      the NEAR Intent quoted for it.
    /// @param sessionId Session to credit
    /// @param amount USDC units (6 decimals) to assign to the session
    function creditSession(bytes32 sessionId, uint256 amount) public onlyKeeper nonReentrant {
        Session storage session = sessions[sessionId];

        if (session.user == address(0)) revert SessionNotFound();
        if (session.processed) revert SessionAlreadyProcessed();
        if (session.rescued) revert SessionAlreadyRescued();
        if (amount == 0) revert ZeroAmount();

        if (session.credited + amount > session.expectedAmount) revert CreditExceedsExpected();

        // Only USDC that no session owns yet, and that is not a reserved fee,
        // may be assigned.
        if (_unassignedBalance() < amount) {
            revert InsufficientUnassignedBalance();
        }

        session.credited += amount;
        totalCommitted += amount;

        emit SessionCredited(sessionId, amount, session.credited);
    }

    /// @notice Process a session's credited USDC by depositing it to zk-p2p,
    ///         net of the protocol fee.
    /// @dev The fee is a subtraction against `session.credited`, a number this
    ///      contract already holds and has already bounded. Gross leaves
    ///      `totalCommitted`; the fee moves to `accruedFees` and the remainder is
    ///      what reaches EscrowV2. Both destinations are reserved, so the
    ///      balance-minus-reserved identity holds across the call and no session's
    ///      slice is touched.
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
        uint256 gross = session.credited;
        if (gross == 0) revert NothingCredited();

        // The fee is read from storage once and applied to this session's own
        // credited amount. Integer division floors, so the fee is never more than
        // its exact share and `amount` is never zero while `gross` is non-zero
        // for any fee at or under the 100 bps ceiling.
        uint256 fee = (gross * feeBps) / BPS_DENOMINATOR;
        uint256 amount = gross - fee;

        // Effects before the external calls: the gross credit is no longer held
        // for the session. The fee half becomes reserved treasury money and the
        // rest is spoken for by the zk-p2p deposit.
        session.credited = 0;
        session.processed = true;
        session.feePaid = fee;
        totalCommitted -= gross;
        if (fee > 0) {
            accruedFees += fee;
        }

        // Approve zk-p2p escrow to spend exactly this session's net amount
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

        emit FeeCharged(sessionId, gross, fee, amount);
        emit OfframpProcessed(sessionId, depositId, amount);

        return depositId;
    }

    /// @notice Return a session's credited USDC to its user if something fails
    ///         before the zk-p2p deposit.
    /// @dev Refunds the full credited amount with no fee deducted. A session that
    ///      never became a deposit was never served, so charging it would be
    ///      charging for nothing, and it would also give a fee-setting owner a
    ///      reason to want sessions to fail. The fee is only ever taken on the
    ///      path where the protocol did its job.
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
    /// @dev Pays back what the escrow returned, capped at what this session put in.
    ///      The cap is `session.deposited`, which is already net of the fee, so an
    ///      unfilled session does not recover the fee here. That is deliberate and
    ///      it is the one place the fee is charged for a service that did not
    ///      complete; see the spec for why refunding it is worse.
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
        // balance, which would include other sessions' credited USDC and the
        // accrued fee pool.
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

    /// @notice Set the protocol fee, in basis points.
    /// @dev Bounded by `MAX_FEE_BPS` at 100 bps, which is a constant and not
    ///      settable, so the ceiling is readable from the bytecode and the owner
    ///      cannot raise it. A change only affects sessions processed after it;
    ///      sessions already deposited recorded their fee in `feePaid`.
    /// @param newFeeBps New fee in basis points, at most `MAX_FEE_BPS`
    function setFeeBps(uint256 newFeeBps) external onlyOwner {
        if (newFeeBps > MAX_FEE_BPS) revert FeeTooHigh();

        uint256 oldBps = feeBps;
        feeBps = newFeeBps;

        emit FeeBpsUpdated(oldBps, newFeeBps);
    }

    /// @notice Point fee sweeps at a new address.
    /// @param newRecipient New fee recipient
    function setFeeRecipient(address newRecipient) external onlyOwner {
        if (newRecipient == address(0)) revert ZeroAddress();

        address oldRecipient = feeRecipient;
        feeRecipient = newRecipient;

        emit FeeRecipientUpdated(oldRecipient, newRecipient);
    }

    /// @notice Send accrued fees to `feeRecipient`.
    /// @dev Permissionless to call but not to direct: the destination is
    ///      `feeRecipient`, never `msg.sender`, so anyone may push the sweep and
    ///      nobody may redirect it. Moves exactly `accruedFees` and zeroes it
    ///      first, so it can never reach a session's slice even if the token
    ///      calls back.
    function sweepFees() external nonReentrant {
        uint256 amount = accruedFees;
        if (amount == 0) revert NoFeesToSweep();

        accruedFees = 0;

        address to = feeRecipient;
        bool success = usdc.transfer(to, amount);
        if (!success) revert TransferFailed();

        emit FeesSwept(to, amount);
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

    /// @notice USDC held by this contract that no session owns and no fee reserves.
    /// @dev What `creditSession` may draw on. Arrivals show up here first.
    function unassignedBalance() external view returns (uint256) {
        return _unassignedBalance();
    }

    /// @notice What a given gross amount would be split into at the current fee.
    /// @dev Exposed so the coordinator and the front end quote the same net the
    ///      contract will actually deposit, rather than recomputing the rounding.
    /// @param gross Gross USDC units (6 decimals)
    /// @return fee The protocol fee
    /// @return net What would reach the zk-p2p deposit
    function previewFee(uint256 gross) external view returns (uint256 fee, uint256 net) {
        fee = (gross * feeBps) / BPS_DENOMINATOR;
        net = gross - fee;
    }

    // ============ Internal ============

    /// @dev Balance minus everything already spoken for. Sessions own
    ///      `totalCommitted`; the treasury owns `accruedFees`. Both are reserved
    ///      against the same pot, so both come off before anything is creditable.
    function _unassignedBalance() internal view returns (uint256) {
        return usdc.balanceOf(address(this)) - totalCommitted - accruedFees;
    }
}
