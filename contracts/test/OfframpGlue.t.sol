// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {OfframpGlue} from "../src/OfframpGlue.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {IEscrow} from "../src/interfaces/IEscrow.sol";

/// @notice Mock USDC for testing
contract MockUSDC is IERC20 {
    string public constant name = "USD Coin";
    string public constant symbol = "USDC";
    uint8 public constant decimals = 6;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;

    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
        _totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address owner, address spender) external view returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        _allowances[from][msg.sender] -= amount;
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

/// @notice Mock zk-p2p Escrow for testing
contract MockEscrow is IEscrow {
    uint256 public depositCounter;
    mapping(uint256 => Deposit) private _deposits;
    mapping(uint256 => mapping(bytes32 => bytes32)) private _payeeDetails;

    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    /// @dev Mirrors EscrowV2._createDeposit: checks, id = depositCounter++, no return value
    function createDeposit(CreateDepositParams calldata params) external {
        require(params.intentAmountRange.min > 0, "ZeroMinValue");
        require(params.intentAmountRange.min <= params.intentAmountRange.max, "InvalidRange");
        require(params.amount >= params.intentAmountRange.min, "AmountBelowMin");
        require(params.paymentMethods.length == params.paymentMethodData.length, "PaymentMethodDataLength");
        require(params.paymentMethods.length == params.currencies.length, "CurrenciesLength");

        uint256 depositId = depositCounter++;

        _deposits[depositId] = Deposit({
            depositor: msg.sender,
            delegate: params.delegate,
            token: params.token,
            intentAmountRange: params.intentAmountRange,
            acceptingIntents: true,
            remainingDeposits: params.amount,
            outstandingIntentAmount: 0,
            intentGuardian: params.intentGuardian,
            retainOnEmpty: params.retainOnEmpty
        });

        emit DepositReceived(
            depositId, msg.sender, params.token, params.amount, params.intentAmountRange, params.delegate, params.intentGuardian
        );

        for (uint256 i = 0; i < params.paymentMethods.length; i++) {
            require(params.paymentMethodData[i].payeeDetails != bytes32(0), "EmptyPayeeDetails");
            _payeeDetails[depositId][params.paymentMethods[i]] = params.paymentMethodData[i].payeeDetails;
            emit DepositPaymentMethodAdded(
                depositId,
                params.paymentMethods[i],
                params.paymentMethodData[i].payeeDetails,
                params.paymentMethodData[i].intentGatingService
            );
        }

        bool success = IERC20(params.token).transferFrom(msg.sender, address(this), params.amount);
        require(success, "Transfer failed");
    }

    /// @dev Mirrors EscrowV2.withdrawDeposit: depositor only, returns all remaining liquidity
    function withdrawDeposit(uint256 depositId) external {
        Deposit storage deposit = _deposits[depositId];
        require(deposit.depositor == msg.sender, "UnauthorizedCaller");

        uint256 returnAmount = deposit.remainingDeposits;
        deposit.remainingDeposits = 0;
        deposit.acceptingIntents = false;

        emit DepositWithdrawn(depositId, msg.sender, returnAmount);

        bool success = IERC20(deposit.token).transfer(msg.sender, returnAmount);
        require(success, "Transfer failed");
    }

    function getDeposit(uint256 depositId) external view returns (Deposit memory) {
        return _deposits[depositId];
    }

    /// @notice Test helper: payeeDetails recorded for a deposit's payment method
    function getDepositPayeeDetails(uint256 depositId, bytes32 paymentMethod) external view returns (bytes32) {
        return _payeeDetails[depositId][paymentMethod];
    }
}

contract OfframpGlueTest is Test {
    OfframpGlue public glue;
    MockUSDC public usdc;
    MockEscrow public escrow;

    address public owner = address(this);
    address public keeper = address(0x1);
    address public user = address(0x2);
    address public taker = address(0x3);

    bytes32 public constant VENMO_METHOD = keccak256("venmo");
    bytes32 public constant USD_CODE = keccak256("USD");
    // Stand-in for a curator-issued payee details hash (opaque bytes32 in production)
    bytes32 public constant PAYEE_HASH = keccak256("mock-zkp2p-payee:alice");

    /// USD at a fixed floor of 1 USD per USDC, no oracle
    function _usd() internal pure returns (IEscrow.Currency memory) {
        return IEscrow.Currency({
            code: USD_CODE,
            minConversionRate: 1e18,
            oracleRateConfig: IEscrow.OracleRateConfig({adapter: address(0), adapterConfig: "", spreadBps: 0, maxStaleness: 0})
        });
    }

    /// Deliver USDC to the glue and assign it to a session, the way the keeper does.
    ///
    /// Arrival and assignment are two steps on purpose: the token transfer is
    /// anonymous, so the keeper has to say which session the money is for.
    function _fund(bytes32 sessionId, uint256 amount) internal {
        usdc.mint(address(glue), amount);
        vm.prank(keeper);
        glue.creditSession(sessionId, amount);
    }

    /// The one-Venmo-method deposit shape every processOfframp call in these tests uses.
    function _methods() internal pure returns (bytes32[] memory methods) {
        methods = new bytes32[](1);
        methods[0] = VENMO_METHOD;
    }

    function _methodData(bytes32 payeeHash)
        internal
        pure
        returns (IEscrow.DepositPaymentMethodData[] memory methodData)
    {
        methodData = new IEscrow.DepositPaymentMethodData[](1);
        methodData[0] =
            IEscrow.DepositPaymentMethodData({intentGatingService: address(0), payeeDetails: payeeHash, data: ""});
    }

    function _currencies() internal pure returns (IEscrow.Currency[][] memory currencies) {
        currencies = new IEscrow.Currency[][](1);
        currencies[0] = new IEscrow.Currency[](1);
        currencies[0][0] = _usd();
    }

    function setUp() public {
        usdc = new MockUSDC();
        escrow = new MockEscrow(address(usdc));
        glue = new OfframpGlue(address(usdc), address(escrow));

        // Set keeper
        glue.setKeeper(keeper);
    }

    function test_Constructor() public view {
        assertEq(glue.owner(), owner);
        assertEq(glue.keeper(), keeper);
        assertEq(address(glue.usdc()), address(usdc));
        assertEq(address(glue.zkp2pEscrow()), address(escrow));
    }

    function test_CreateSession() public {
        bytes32 sessionId = keccak256("session1");
        bytes32 payeeHash = PAYEE_HASH;
        uint256 minRate = 1e18; // 1:1
        uint256 expectedAmount = 100e6; // 100 USDC

        vm.prank(keeper);
        glue.createSession(sessionId, user, payeeHash, minRate, expectedAmount);

        OfframpGlue.Session memory session = glue.getSession(sessionId);
        assertEq(session.user, user);
        assertEq(session.payeeDetailsHash, payeeHash);
        assertEq(session.minConversionRate, minRate);
        assertEq(session.expectedAmount, expectedAmount);
        assertEq(session.depositId, 0);
        assertFalse(session.processed);
        assertFalse(session.fulfilled);
        assertFalse(session.rescued);
    }

    function test_CreateSession_RevertIfNotKeeper() public {
        bytes32 sessionId = keccak256("session1");
        bytes32 payeeHash = PAYEE_HASH;

        vm.prank(user);
        vm.expectRevert(OfframpGlue.Unauthorized.selector);
        glue.createSession(sessionId, user, payeeHash, 1e18, 100e6);
    }

    function test_CreateSession_RevertIfExists() public {
        bytes32 sessionId = keccak256("session1");
        bytes32 payeeHash = PAYEE_HASH;

        vm.prank(keeper);
        glue.createSession(sessionId, user, payeeHash, 1e18, 100e6);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.SessionExists.selector);
        glue.createSession(sessionId, user, payeeHash, 1e18, 100e6);
    }

    function test_ProcessOfframp() public {
        bytes32 sessionId = keccak256("session1");
        bytes32 payeeHash = PAYEE_HASH;
        uint256 amount = 100e6;

        // Create session
        vm.prank(keeper);
        glue.createSession(sessionId, user, payeeHash, 1e18, amount);

        // Simulate NEAR Intent delivery, then the keeper assigning it to this session
        _fund(sessionId, amount);

        // Prepare zk-p2p params
        bytes32[] memory methods = new bytes32[](1);
        methods[0] = VENMO_METHOD;

        IEscrow.DepositPaymentMethodData[] memory methodData = new IEscrow.DepositPaymentMethodData[](1);
        methodData[0] = IEscrow.DepositPaymentMethodData({
            intentGatingService: address(0),
            payeeDetails: payeeHash,
            data: ""
        });

        IEscrow.Currency[][] memory currencies = new IEscrow.Currency[][](1);
        currencies[0] = new IEscrow.Currency[](1);
        currencies[0][0] = _usd();

        // Process offramp
        vm.prank(keeper);
        uint256 depositId = glue.processOfframp(sessionId, methods, methodData, currencies);

        // EscrowV2 ids start at 0 and are read from depositCounter, not a return value
        assertEq(depositId, 0);
        assertEq(escrow.depositCounter(), 1);

        OfframpGlue.Session memory session = glue.getSession(sessionId);
        assertEq(session.depositId, 0);
        assertTrue(session.processed);

        // The deposit carries the session's payee hash and the glue is the depositor
        assertEq(escrow.getDepositPayeeDetails(0, VENMO_METHOD), payeeHash);
        assertEq(escrow.getDeposit(0).depositor, address(glue));
        assertEq(escrow.getDeposit(0).remainingDeposits, amount);

        // Verify USDC moved to escrow
        assertEq(usdc.balanceOf(address(glue)), 0);
        assertEq(usdc.balanceOf(address(escrow)), amount);
    }

    function test_ProcessOfframp_RevertIfNotKeeper() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 100e6);

        _fund(sessionId, 100e6);

        bytes32[] memory methods = new bytes32[](0);
        IEscrow.DepositPaymentMethodData[] memory methodData = new IEscrow.DepositPaymentMethodData[](0);
        IEscrow.Currency[][] memory currencies = new IEscrow.Currency[][](0);

        vm.prank(user);
        vm.expectRevert(OfframpGlue.Unauthorized.selector);
        glue.processOfframp(sessionId, methods, methodData, currencies);
    }

    function test_ProcessOfframp_RevertIfPayeeMismatch() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 100e6);

        _fund(sessionId, 100e6);

        bytes32[] memory methods = new bytes32[](1);
        methods[0] = VENMO_METHOD;

        IEscrow.DepositPaymentMethodData[] memory methodData = new IEscrow.DepositPaymentMethodData[](1);
        methodData[0] = IEscrow.DepositPaymentMethodData({
            intentGatingService: address(0),
            payeeDetails: keccak256("someone-else"),
            data: ""
        });

        IEscrow.Currency[][] memory currencies = new IEscrow.Currency[][](1);
        currencies[0] = new IEscrow.Currency[](1);
        currencies[0][0] = _usd();

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.PayeeDetailsMismatch.selector);
        glue.processOfframp(sessionId, methods, methodData, currencies);

        // Funds stay in the glue contract, so the user can still rescue
        assertEq(usdc.balanceOf(address(glue)), 100e6);
    }

    function test_ProcessOfframp_RevertIfAlreadyProcessed() public {
        bytes32 sessionId = keccak256("session1");
        bytes32 payeeHash = PAYEE_HASH;

        vm.prank(keeper);
        glue.createSession(sessionId, user, payeeHash, 1e18, 100e6);

        _fund(sessionId, 100e6);

        bytes32[] memory methods = new bytes32[](1);
        methods[0] = VENMO_METHOD;

        IEscrow.DepositPaymentMethodData[] memory methodData = new IEscrow.DepositPaymentMethodData[](1);
        methodData[0] = IEscrow.DepositPaymentMethodData({
            intentGatingService: address(0),
            payeeDetails: payeeHash,
            data: ""
        });

        IEscrow.Currency[][] memory currencies = new IEscrow.Currency[][](1);
        currencies[0] = new IEscrow.Currency[](1);
        currencies[0][0] = _usd();

        vm.prank(keeper);
        glue.processOfframp(sessionId, methods, methodData, currencies);

        // Try again
        usdc.mint(address(glue), 100e6);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.SessionAlreadyProcessed.selector);
        glue.processOfframp(sessionId, methods, methodData, currencies);
    }

    function test_Rescue() public {
        bytes32 sessionId = keccak256("session1");
        uint256 amount = 100e6;

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, amount);

        _fund(sessionId, amount);

        vm.prank(user);
        glue.rescue(sessionId);

        assertEq(usdc.balanceOf(user), amount);
        assertEq(usdc.balanceOf(address(glue)), 0);

        OfframpGlue.Session memory session = glue.getSession(sessionId);
        assertTrue(session.rescued);
    }

    function test_Rescue_RevertIfNotUser() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 100e6);

        _fund(sessionId, 100e6);

        vm.prank(taker);
        vm.expectRevert(OfframpGlue.Unauthorized.selector);
        glue.rescue(sessionId);
    }

    function test_Rescue_RevertIfAlreadyProcessed() public {
        bytes32 sessionId = keccak256("session1");
        bytes32 payeeHash = PAYEE_HASH;

        vm.prank(keeper);
        glue.createSession(sessionId, user, payeeHash, 1e18, 100e6);

        _fund(sessionId, 100e6);

        bytes32[] memory methods = new bytes32[](1);
        methods[0] = VENMO_METHOD;

        IEscrow.DepositPaymentMethodData[] memory methodData = new IEscrow.DepositPaymentMethodData[](1);
        methodData[0] = IEscrow.DepositPaymentMethodData({
            intentGatingService: address(0),
            payeeDetails: payeeHash,
            data: ""
        });

        IEscrow.Currency[][] memory currencies = new IEscrow.Currency[][](1);
        currencies[0] = new IEscrow.Currency[](1);
        currencies[0][0] = _usd();

        vm.prank(keeper);
        glue.processOfframp(sessionId, methods, methodData, currencies);

        vm.prank(user);
        vm.expectRevert(OfframpGlue.SessionAlreadyProcessed.selector);
        glue.rescue(sessionId);
    }

    function test_WithdrawFromZkp2p() public {
        bytes32 sessionId = keccak256("session1");
        bytes32 payeeHash = PAYEE_HASH;
        uint256 amount = 100e6;

        vm.prank(keeper);
        glue.createSession(sessionId, user, payeeHash, 1e18, amount);

        _fund(sessionId, amount);

        bytes32[] memory methods = new bytes32[](1);
        methods[0] = VENMO_METHOD;

        IEscrow.DepositPaymentMethodData[] memory methodData = new IEscrow.DepositPaymentMethodData[](1);
        methodData[0] = IEscrow.DepositPaymentMethodData({
            intentGatingService: address(0),
            payeeDetails: payeeHash,
            data: ""
        });

        IEscrow.Currency[][] memory currencies = new IEscrow.Currency[][](1);
        currencies[0] = new IEscrow.Currency[](1);
        currencies[0][0] = _usd();

        vm.prank(keeper);
        glue.processOfframp(sessionId, methods, methodData, currencies);

        // User withdraws from zk-p2p
        vm.prank(user);
        glue.withdrawFromZkp2p(sessionId);

        assertEq(usdc.balanceOf(user), amount);
        assertEq(escrow.getDeposit(0).remainingDeposits, 0);
    }

    function test_WithdrawFromZkp2p_RevertIfNotProcessed() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 100e6);

        vm.prank(user);
        vm.expectRevert(OfframpGlue.NoDepositToWithdraw.selector);
        glue.withdrawFromZkp2p(sessionId);
    }

    function test_SetKeeper() public {
        address newKeeper = address(0x4);

        glue.setKeeper(newKeeper);

        assertEq(glue.keeper(), newKeeper);
    }

    function test_SetKeeper_RevertIfNotOwner() public {
        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.Unauthorized.selector);
        glue.setKeeper(address(0x4));
    }

    function test_OwnerCanActAsKeeper() public {
        // Owner should be able to create sessions even if not the keeper
        bytes32 sessionId = keccak256("session1");

        // Acting as owner (address(this))
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 100e6);

        OfframpGlue.Session memory session = glue.getSession(sessionId);
        assertEq(session.user, user);
    }

    // ================================================================
    // Regression tests for the 2026-08-31 audit findings.
    //
    // Each of these is one of the audit's proof-of-concept exploits with its
    // assertions inverted: it now asserts the attack fails. The names keep the
    // audit's PoC names so a re-audit can match them up.
    // ================================================================

    /// CRITICAL-1. Two sessions in flight at once, no attacker involved.
    ///
    /// The audit's PoC asserted that session B's deposit swallowed all 110 USDC
    /// when only 10 was B's, and that A could then neither rescue nor withdraw.
    /// With per-session accounting, B deposits exactly its own 10 and A's 100
    /// stays A's.
    function test_PoC_ConcurrentSessions_FundsMixed() public {
        bytes32 sA = keccak256("sessionA");
        bytes32 sB = keccak256("sessionB");
        address userA = address(0xA1);
        address userB = address(0xB1);
        bytes32 payeeA = keccak256("payee:alice");
        bytes32 payeeB = keccak256("payee:bob");

        vm.startPrank(keeper);
        glue.createSession(sA, userA, payeeA, 1e18, 100e6);
        glue.createSession(sB, userB, payeeB, 1e18, 10e6);
        vm.stopPrank();

        // Both deliveries land on the one contract.
        usdc.mint(address(glue), 100e6); // A's money
        usdc.mint(address(glue), 10e6); // B's money

        vm.startPrank(keeper);
        glue.creditSession(sA, 100e6);
        glue.creditSession(sB, 10e6);
        vm.stopPrank();

        vm.prank(keeper);
        uint256 depB = glue.processOfframp(sB, _methods(), _methodData(payeeB), _currencies());

        // B's deposit holds B's 10, not the whole 110.
        assertEq(escrow.getDeposit(depB).remainingDeposits, 10e6, "B took only its own USDC");

        // And A still has a working recovery path for the full 100.
        vm.prank(userA);
        glue.rescue(sA);
        assertEq(usdc.balanceOf(userA), 100e6, "A recovered its own money");
        assertEq(glue.totalCommitted(), 0);
    }

    /// CRITICAL-2. An attacker opens a session naming themselves and calls
    /// rescue while a victim's USDC is on the contract.
    ///
    /// The audit's PoC drained a victim's 100 USDC through a 1-unit session.
    /// Now the attacker can only ever move what their own session was credited,
    /// and crediting it requires unassigned balance that the victim's money is not.
    function test_PoC_AttackerRescuesVictimFunds() public {
        bytes32 victimSession = keccak256("victim");
        bytes32 attackerSession = keccak256("attacker");
        address victim = address(0x11);
        address attacker = address(0xBAD1);

        vm.startPrank(keeper);
        glue.createSession(victimSession, victim, PAYEE_HASH, 1e18, 100e6);
        glue.createSession(attackerSession, attacker, keccak256("payee:attacker"), 1e18, 1);
        vm.stopPrank();

        // The victim's USDC arrives and is assigned to the victim's session.
        usdc.mint(address(glue), 100e6);
        vm.prank(keeper);
        glue.creditSession(victimSession, 100e6);

        // The attacker's session owns nothing, so there is nothing to rescue.
        vm.prank(attacker);
        vm.expectRevert(OfframpGlue.InsufficientBalance.selector);
        glue.rescue(attackerSession);

        // Nor can the keeper be tricked into assigning the victim's money to it:
        // the victim's credit is not unassigned balance.
        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.InsufficientUnassignedBalance.selector);
        glue.creditSession(attackerSession, 1);

        assertEq(usdc.balanceOf(attacker), 0, "attacker took nothing");
        assertEq(usdc.balanceOf(address(glue)), 100e6, "victim's USDC is untouched");

        // The victim can still get it back.
        vm.prank(victim);
        glue.rescue(victimSession);
        assertEq(usdc.balanceOf(victim), 100e6);
    }

    /// CRITICAL-2, second shape. `rescue` must never pay anyone but the session
    /// owner, even if the caller is authorized for a different reason.
    function test_RescueAlwaysPaysTheSessionUserNotTheCaller() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 50e6);
        _fund(sessionId, 50e6);

        // The keeper may trigger the rescue, but the money goes to the user.
        vm.prank(keeper);
        glue.rescue(sessionId);

        assertEq(usdc.balanceOf(user), 50e6);
        assertEq(usdc.balanceOf(keeper), 0);
    }

    /// CRITICAL-1/2. `withdrawFromZkp2p` must return only what the escrow gave
    /// back for this deposit, not whatever balance happens to be sitting here.
    ///
    /// The audit's PoC had A's withdraw return 100 USDC when only 50 was A's.
    function test_PoC_WithdrawSweepsUnrelatedBalance() public {
        bytes32 sA = keccak256("sessionA");
        bytes32 sB = keccak256("sessionB");
        address userA = address(0xA1);
        address userB = address(0xB1);

        vm.startPrank(keeper);
        glue.createSession(sA, userA, PAYEE_HASH, 1e18, 50e6);
        glue.createSession(sB, userB, PAYEE_HASH, 1e18, 50e6);
        vm.stopPrank();

        _fund(sA, 50e6);
        vm.prank(keeper);
        glue.processOfframp(sA, _methods(), _methodData(PAYEE_HASH), _currencies());

        // B's money arrives while A's deposit is open.
        _fund(sB, 50e6);

        vm.prank(userA);
        glue.withdrawFromZkp2p(sA);

        assertEq(usdc.balanceOf(userA), 50e6, "A got back only its own deposit");
        assertEq(usdc.balanceOf(address(glue)), 50e6, "B's USDC stayed put");
        assertEq(glue.totalCommitted(), 50e6, "B's credit is intact");

        vm.prank(userB);
        glue.rescue(sB);
        assertEq(usdc.balanceOf(userB), 50e6);
    }

    /// MEDIUM-4. A second withdraw took 7 USDC belonging to a later arrival in
    /// the audit's PoC. Withdrawal is now once per session.
    function test_PoC_WithdrawIsRepeatable() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 50e6);
        _fund(sessionId, 50e6);

        vm.prank(keeper);
        glue.processOfframp(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies());

        vm.prank(user);
        glue.withdrawFromZkp2p(sessionId);
        assertEq(usdc.balanceOf(user), 50e6);

        // A later arrival belonging to someone else.
        usdc.mint(address(glue), 7e6);

        vm.prank(user);
        vm.expectRevert(OfframpGlue.SessionAlreadyWithdrawn.selector);
        glue.withdrawFromZkp2p(sessionId);

        assertEq(usdc.balanceOf(user), 50e6, "the second call took nothing");
        assertEq(usdc.balanceOf(address(glue)), 7e6);
    }

    /// MEDIUM-2. An empty `paymentMethodData` made the payee loop a no-op, so a
    /// deposit could be created with no payee check at all.
    function test_PoC_EmptyPaymentMethodDataSkipsPayeeCheck() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 100e6);
        _fund(sessionId, 100e6);

        bytes32[] memory noMethods = new bytes32[](0);
        IEscrow.DepositPaymentMethodData[] memory noData = new IEscrow.DepositPaymentMethodData[](0);
        IEscrow.Currency[][] memory noCurrencies = new IEscrow.Currency[][](0);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.EmptyPaymentMethods.selector);
        glue.processOfframp(sessionId, noMethods, noData, noCurrencies);
    }

    /// MEDIUM-2, second half: the three parallel arrays have to line up, or the
    /// payee loop checks fewer entries than the deposit carries.
    function test_ProcessOfframp_RevertIfArrayLengthsDisagree() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 100e6);
        _fund(sessionId, 100e6);

        bytes32[] memory twoMethods = new bytes32[](2);
        twoMethods[0] = VENMO_METHOD;
        twoMethods[1] = keccak256("cashapp");

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.PaymentMethodLengthMismatch.selector);
        glue.processOfframp(sessionId, twoMethods, _methodData(PAYEE_HASH), _currencies());
    }

    /// HIGH-1. The escape hatch has to work when the keeper is gone. The user
    /// signs for themselves, with no keeper transaction anywhere in the flow.
    function test_UserCanRescueWithoutTheKeeper() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 40e6);
        _fund(sessionId, 40e6);

        // Keeper is rotated to an address nobody controls; the user is on their own.
        glue.setKeeper(address(0xDEAD));

        vm.prank(user);
        glue.rescue(sessionId);

        assertEq(usdc.balanceOf(user), 40e6);
    }

    /// HIGH-1, the withdraw half of the same hatch.
    function test_UserCanWithdrawWithoutTheKeeper() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 40e6);
        _fund(sessionId, 40e6);

        vm.prank(keeper);
        glue.processOfframp(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies());

        glue.setKeeper(address(0xDEAD));

        vm.prank(user);
        glue.withdrawFromZkp2p(sessionId);

        assertEq(usdc.balanceOf(user), 40e6);
    }

    /// A stranger is still a stranger on both hatches.
    function test_WithdrawFromZkp2p_RevertIfNotUserOrKeeper() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 40e6);
        _fund(sessionId, 40e6);

        vm.prank(keeper);
        glue.processOfframp(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies());

        vm.prank(taker);
        vm.expectRevert(OfframpGlue.Unauthorized.selector);
        glue.withdrawFromZkp2p(sessionId);
    }

    /// Crediting is bounded by what the NEAR Intent quoted, so a keeper slip
    /// cannot over-assign one session out of the shared pot.
    function test_CreditSession_RevertIfAboveExpected() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 10e6);

        usdc.mint(address(glue), 100e6);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.CreditExceedsExpected.selector);
        glue.creditSession(sessionId, 11e6);
    }

    /// Crediting is the keeper's job; a user cannot assign themselves money.
    function test_CreditSession_RevertIfNotKeeper() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 10e6);
        usdc.mint(address(glue), 10e6);

        vm.prank(user);
        vm.expectRevert(OfframpGlue.Unauthorized.selector);
        glue.creditSession(sessionId, 10e6);
    }

    /// A partial delivery can be topped up as the rest arrives, and the running
    /// total never exceeds what the session expects.
    function test_CreditSession_AccumulatesUpToExpected() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 10e6);

        usdc.mint(address(glue), 4e6);
        vm.prank(keeper);
        glue.creditSession(sessionId, 4e6);

        usdc.mint(address(glue), 6e6);
        vm.prank(keeper);
        glue.creditSession(sessionId, 6e6);

        assertEq(glue.getSession(sessionId).credited, 10e6);
        assertEq(glue.totalCommitted(), 10e6);
        assertEq(glue.unassignedBalance(), 0);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.CreditExceedsExpected.selector);
        glue.creditSession(sessionId, 1);
    }

    /// A session with nothing credited has nothing to deposit; processing it
    /// must not reach for the contract balance.
    function test_ProcessOfframp_RevertIfNothingCredited() public {
        bytes32 sessionId = keccak256("session1");
        bytes32 otherSession = keccak256("other");

        vm.startPrank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 100e6);
        glue.createSession(otherSession, address(0xA1), PAYEE_HASH, 1e18, 100e6);
        vm.stopPrank();

        // Someone else's money is on the contract.
        _fund(otherSession, 100e6);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.NothingCredited.selector);
        glue.processOfframp(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies());
    }

    /// Accounting invariant across a full lifecycle: totalCommitted always
    /// equals the sum of live credits, and never exceeds the token balance.
    function test_TotalCommittedTracksLiveCredits() public {
        bytes32 sA = keccak256("sessionA");
        bytes32 sB = keccak256("sessionB");

        vm.startPrank(keeper);
        glue.createSession(sA, address(0xA1), PAYEE_HASH, 1e18, 30e6);
        glue.createSession(sB, address(0xB1), PAYEE_HASH, 1e18, 70e6);
        vm.stopPrank();

        _fund(sA, 30e6);
        assertEq(glue.totalCommitted(), 30e6);
        _fund(sB, 70e6);
        assertEq(glue.totalCommitted(), 100e6);
        assertLe(glue.totalCommitted(), usdc.balanceOf(address(glue)));

        vm.prank(keeper);
        glue.processOfframp(sA, _methods(), _methodData(PAYEE_HASH), _currencies());
        assertEq(glue.totalCommitted(), 70e6, "A's credit left with the deposit");

        vm.prank(address(0xB1));
        glue.rescue(sB);
        assertEq(glue.totalCommitted(), 0);
        assertEq(usdc.balanceOf(address(glue)), 0);
    }

    /// The property behind CRITICAL-1 and CRITICAL-2, stated directly and fuzzed:
    /// whatever the amounts, a session can never move more than it was credited,
    /// and one session's payout can never touch another's balance.
    function testFuzz_SessionNeverTakesMoreThanItWasCredited(uint96 amountA, uint96 amountB) public {
        amountA = uint96(bound(amountA, 1, 1_000_000e6));
        amountB = uint96(bound(amountB, 1, 1_000_000e6));

        bytes32 sA = keccak256("fuzzA");
        bytes32 sB = keccak256("fuzzB");
        address userA = address(0xA1);
        address userB = address(0xB1);

        vm.startPrank(keeper);
        glue.createSession(sA, userA, PAYEE_HASH, 1e18, amountA);
        glue.createSession(sB, userB, PAYEE_HASH, 1e18, amountB);
        vm.stopPrank();

        usdc.mint(address(glue), uint256(amountA) + uint256(amountB));

        vm.startPrank(keeper);
        glue.creditSession(sA, amountA);
        glue.creditSession(sB, amountB);
        vm.stopPrank();

        // A recovers. It gets its own amount exactly, never B's.
        vm.prank(userA);
        glue.rescue(sA);
        assertEq(usdc.balanceOf(userA), amountA);
        assertEq(usdc.balanceOf(address(glue)), amountB, "B's balance is untouched");
        assertEq(glue.totalCommitted(), amountB);

        // And B still recovers in full afterwards.
        vm.prank(userB);
        glue.rescue(sB);
        assertEq(usdc.balanceOf(userB), amountB);
        assertEq(usdc.balanceOf(address(glue)), 0);
        assertEq(glue.totalCommitted(), 0);
    }
}
