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

    /// @notice Test helper: extra USDC to send alongside a withdrawal.
    ///
    /// Stands in for anything that lands on the glue during the same call, such
    /// as a NEAR settlement for a different session. The glue must not forward
    /// it to whoever happened to be withdrawing.
    uint256 public withdrawBonus;

    function setWithdrawBonus(uint256 amount) external {
        withdrawBonus = amount;
    }

    /// @dev Mirrors EscrowV2.withdrawDeposit: depositor only, returns all remaining liquidity
    function withdrawDeposit(uint256 depositId) external {
        Deposit storage deposit = _deposits[depositId];
        require(deposit.depositor == msg.sender, "UnauthorizedCaller");

        uint256 returnAmount = deposit.remainingDeposits;
        deposit.remainingDeposits = 0;
        deposit.acceptingIntents = false;

        emit DepositWithdrawn(depositId, msg.sender, returnAmount);

        bool success = IERC20(deposit.token).transfer(msg.sender, returnAmount + withdrawBonus);
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

    /// A withdraw must never forward more than the session put in, even if other
    /// USDC lands on the contract during the same call.
    ///
    /// The payout is measured as a balance delta across `withdrawDeposit`, so
    /// anything arriving inside that window would otherwise be counted as this
    /// session's money. A NEAR settlement for another session, or a batched
    /// transaction, is enough to trigger it.
    function test_WithdrawIsCappedAtWhatTheSessionDeposited() public {
        bytes32 sessionId = keccak256("session1");

        vm.prank(keeper);
        glue.createSession(sessionId, user, PAYEE_HASH, 1e18, 40e6);
        _fund(sessionId, 40e6);

        vm.prank(keeper);
        glue.processOfframp(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies());

        // The escrow will hand back 40, and an unrelated 60 arrives too.
        escrow.setWithdrawBonus(60e6);
        usdc.mint(address(escrow), 60e6);

        vm.prank(user);
        glue.withdrawFromZkp2p(sessionId);

        assertEq(usdc.balanceOf(user), 40e6, "the user got back only what they deposited");
        assertEq(usdc.balanceOf(address(glue)), 60e6, "the surplus stayed on the contract");
    }

    // ================================================================
    // NEW-1 in the 2026-08-31 re-audit: the keeper decided how much a
    // session was owed from the shared unassigned pool rather than from
    // what 1Click reported that session's own swap settled for.
    //
    // The contract cannot catch this by itself. An ERC-20 transfer carries
    // no session id, so `creditSession` can only bound a credit by the
    // session's own `expectedAmount` and by the unassigned balance; it has
    // to take the keeper's word for whose money arrived. These tests run
    // both keeper rules against the real compiled contract and show the
    // difference in where the money ends up.
    //
    // The scenario is the audit's, with no attacker: Alice quoted 100.00
    // with a floor of 99.50, Bob quoted 10.00 with a floor of 9.95. Alice's
    // swap under-fills to 99.50, which 0.5% quote slippage makes ordinary.
    // Bob's fills in full.
    // ================================================================

    uint256 internal constant ALICE_EXPECTED = 100e6;
    uint256 internal constant ALICE_FLOOR = 99_500_000;
    uint256 internal constant ALICE_SETTLED = 99_500_000;
    uint256 internal constant BOB_EXPECTED = 10e6;
    uint256 internal constant BOB_FLOOR = 9_950_000;
    uint256 internal constant BOB_SETTLED = 10e6;

    /// The rule the keeper used before the fix: credit whatever is unassigned,
    /// capped at the quote. Mirrors `state.rs` at commit 5b1b6a6.
    function _creditOldRule(uint256 unassigned, uint256 expected, uint256 floor)
        internal
        pure
        returns (bool credits, uint256 amount)
    {
        if (unassigned < floor) return (false, 0);
        return (true, unassigned < expected ? unassigned : expected);
    }

    /// The rule the keeper uses now: credit what 1Click reported this session's
    /// own deposit address settled for, clamped to the quote, with the
    /// unassigned balance kept only as a sanity bound.
    function _creditNewRule(uint256 settled, uint256 unassigned, uint256 expected, uint256 floor)
        internal
        pure
        returns (bool credits, uint256 amount)
    {
        if (settled < floor) return (false, 0);
        uint256 credit = settled < expected ? settled : expected;
        if (unassigned < credit) return (false, 0);
        return (true, credit);
    }

    function _openAliceAndBob() internal returns (bytes32 alice, bytes32 bob) {
        alice = keccak256("alice");
        bob = keccak256("bob");

        vm.startPrank(keeper);
        glue.createSession(alice, address(0xA11CE), keccak256("payee:alice"), 1e18, ALICE_EXPECTED);
        glue.createSession(bob, address(0xB0B), keccak256("payee:bob"), 1e18, BOB_EXPECTED);
        vm.stopPrank();

        // Both swaps settle and both deliveries land on the one contract.
        usdc.mint(address(glue), ALICE_SETTLED);
        usdc.mint(address(glue), BOB_SETTLED);
    }

    /// NEW-1, reproduced. Under the old rule Alice is credited her full quote out
    /// of a pool that is 0.50 short of it, Bob is left below his floor and never
    /// promotes, and his money is stranded: he was never credited, so `rescue`
    /// reverts and there is no path back to him.
    function test_NEW1_ShortSettlementStealsFromTheConcurrentSession() public {
        (bytes32 alice, bytes32 bob) = _openAliceAndBob();

        uint256 pool = glue.unassignedBalance();
        assertEq(pool, ALICE_SETTLED + BOB_SETTLED, "109.50 sits unassigned");

        // The keeper's tick reaches Alice first. db.rs orders nothing, so which
        // session that is comes down to SQLite's row order.
        (bool creditsAlice, uint256 aliceCredit) = _creditOldRule(pool, ALICE_EXPECTED, ALICE_FLOOR);
        assertTrue(creditsAlice);
        assertEq(aliceCredit, ALICE_EXPECTED, "the old rule credits the quote, not the fill");
        assertGt(aliceCredit, ALICE_SETTLED, "0.50 of it was never Alice's");

        vm.prank(keeper);
        glue.creditSession(alice, aliceCredit);

        // Bob's turn. What is left is below his floor, so he never promotes, on
        // this tick or any later one.
        (bool creditsBob,) = _creditOldRule(glue.unassignedBalance(), BOB_EXPECTED, BOB_FLOOR);
        assertFalse(creditsBob, "Bob is stuck below his floor");
        assertEq(glue.unassignedBalance(), BOB_SETTLED - 500_000, "9.50 left, floor is 9.95");

        // Bob's escape hatch does not help: it pays `session.credited`, and he
        // was never credited.
        vm.prank(address(0xB0B));
        vm.expectRevert(OfframpGlue.InsufficientBalance.selector);
        glue.rescue(bob);

        // Alice walks off with the difference.
        vm.prank(address(0xA11CE));
        glue.rescue(alice);
        assertEq(usdc.balanceOf(address(0xA11CE)), ALICE_EXPECTED, "Alice took 100.00");
        assertEq(usdc.balanceOf(address(0xB0B)), 0, "Bob got nothing");
        assertEq(usdc.balanceOf(address(glue)), 9_500_000, "Bob's 9.50 is stranded on the glue");
    }

    /// The same delivery under the fixed rule. Each session is credited its own
    /// realized fill, and both users get their money back.
    function test_NEW1_CreditingTheSettledAmountKeepsEachSessionWhole() public {
        (bytes32 alice, bytes32 bob) = _openAliceAndBob();

        (bool creditsAlice, uint256 aliceCredit) =
            _creditNewRule(ALICE_SETTLED, glue.unassignedBalance(), ALICE_EXPECTED, ALICE_FLOOR);
        assertTrue(creditsAlice, "an under-fill above the floor still promotes");
        assertEq(aliceCredit, ALICE_SETTLED, "Alice is credited what her swap settled for");

        vm.prank(keeper);
        glue.creditSession(alice, aliceCredit);

        (bool creditsBob, uint256 bobCredit) =
            _creditNewRule(BOB_SETTLED, glue.unassignedBalance(), BOB_EXPECTED, BOB_FLOOR);
        assertTrue(creditsBob, "Bob's own money is still there for him");
        assertEq(bobCredit, BOB_SETTLED);

        vm.prank(keeper);
        glue.creditSession(bob, bobCredit);

        assertEq(glue.unassignedBalance(), 0, "every unit is assigned to whoever it arrived for");
        assertEq(glue.totalCommitted(), ALICE_SETTLED + BOB_SETTLED);

        vm.prank(address(0xA11CE));
        glue.rescue(alice);
        vm.prank(address(0xB0B));
        glue.rescue(bob);

        assertEq(usdc.balanceOf(address(0xA11CE)), ALICE_SETTLED, "Alice got her own fill");
        assertEq(usdc.balanceOf(address(0xB0B)), BOB_SETTLED, "Bob got his, in full");
        assertEq(usdc.balanceOf(address(glue)), 0, "nothing stranded");
        assertEq(glue.totalCommitted(), 0);
    }

    /// The ordering the audit called out. Whichever session the tick reaches
    /// first, the fixed rule credits the same amounts, because the amounts come
    /// from 1Click rather than from the pool.
    function test_NEW1_TheFixIsIndifferentToTickOrder() public {
        (bytes32 alice, bytes32 bob) = _openAliceAndBob();

        // Bob first this time.
        (, uint256 bobCredit) =
            _creditNewRule(BOB_SETTLED, glue.unassignedBalance(), BOB_EXPECTED, BOB_FLOOR);
        vm.prank(keeper);
        glue.creditSession(bob, bobCredit);

        (, uint256 aliceCredit) =
            _creditNewRule(ALICE_SETTLED, glue.unassignedBalance(), ALICE_EXPECTED, ALICE_FLOOR);
        vm.prank(keeper);
        glue.creditSession(alice, aliceCredit);

        assertEq(bobCredit, BOB_SETTLED);
        assertEq(aliceCredit, ALICE_SETTLED);
        assertEq(glue.getSession(bob).credited, BOB_SETTLED);
        assertEq(glue.getSession(alice).credited, ALICE_SETTLED);
        assertEq(glue.unassignedBalance(), 0);
    }

    /// An over-fill is clamped rather than credited, and the surplus stays
    /// unassigned. The contract enforces this independently, so the assertion is
    /// that the keeper never sends a transaction that can only revert.
    function test_NEW1_AnOverFillIsClampedToTheQuote() public {
        bytes32 alice = keccak256("alice");

        vm.prank(keeper);
        glue.createSession(alice, address(0xA11CE), keccak256("payee:alice"), 1e18, ALICE_EXPECTED);

        uint256 overFill = 101e6;
        usdc.mint(address(glue), overFill);

        (bool credits, uint256 amount) =
            _creditNewRule(overFill, glue.unassignedBalance(), ALICE_EXPECTED, ALICE_FLOOR);
        assertTrue(credits);
        assertEq(amount, ALICE_EXPECTED, "clamped to the quote");

        vm.prank(keeper);
        glue.creditSession(alice, amount);
        assertEq(glue.unassignedBalance(), 1e6, "the surplus stays unassigned");

        // And the contract would have refused the unclamped figure anyway.
        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.CreditExceedsExpected.selector);
        glue.creditSession(alice, 1e6);
    }

    /// A settlement below the guaranteed floor is not credited at all under
    /// either rule, so a genuinely short delivery cannot promote a session.
    function test_NEW1_ASettlementBelowTheFloorIsNotCredited() public {
        uint256 shortFill = 99_000_000; // below Alice's 99.50 floor

        (bool credits,) = _creditNewRule(shortFill, shortFill, ALICE_EXPECTED, ALICE_FLOOR);
        assertFalse(credits, "under the floor, nothing is credited");
    }

    /// Fuzzed: across arbitrary fills for two concurrent sessions, no session is
    /// ever credited more than its own swap settled for, and the sum of the
    /// credits never exceeds what actually arrived.
    function testFuzz_NEW1_NoSessionIsCreditedBeyondItsOwnFill(uint64 fillA, uint64 fillB) public {
        // Keep both inside their quotes and at or above their floors, which is
        // the band the fix has to be right across.
        uint256 settledA = ALICE_FLOOR + (uint256(fillA) % (ALICE_EXPECTED - ALICE_FLOOR + 1));
        uint256 settledB = BOB_FLOOR + (uint256(fillB) % (BOB_EXPECTED - BOB_FLOOR + 1));

        bytes32 alice = keccak256("alice");
        bytes32 bob = keccak256("bob");

        vm.startPrank(keeper);
        glue.createSession(alice, address(0xA11CE), keccak256("payee:alice"), 1e18, ALICE_EXPECTED);
        glue.createSession(bob, address(0xB0B), keccak256("payee:bob"), 1e18, BOB_EXPECTED);
        vm.stopPrank();

        usdc.mint(address(glue), settledA);
        usdc.mint(address(glue), settledB);

        (bool okA, uint256 creditA) =
            _creditNewRule(settledA, glue.unassignedBalance(), ALICE_EXPECTED, ALICE_FLOOR);
        assertTrue(okA);
        vm.prank(keeper);
        glue.creditSession(alice, creditA);

        (bool okB, uint256 creditB) =
            _creditNewRule(settledB, glue.unassignedBalance(), BOB_EXPECTED, BOB_FLOOR);
        assertTrue(okB, "the second session is never starved by the first");
        vm.prank(keeper);
        glue.creditSession(bob, creditB);

        assertLe(creditA, settledA, "Alice never gets more than her own fill");
        assertLe(creditB, settledB, "Bob never gets more than his own fill");
        assertEq(creditA + creditB, settledA + settledB, "and together they get all of it");
        assertEq(glue.unassignedBalance(), 0);

        // Both recoveries work, which is the property the old rule broke for Bob.
        vm.prank(address(0xA11CE));
        glue.rescue(alice);
        vm.prank(address(0xB0B));
        glue.rescue(bob);
        assertEq(usdc.balanceOf(address(0xA11CE)), settledA);
        assertEq(usdc.balanceOf(address(0xB0B)), settledB);
    }
}

/// A token that calls back into the glue on transfer.
///
/// USDC on Base does not do this today, but it is an upgradeable proxy and this
/// contract is not upgradeable at all. Without a reentrancy guard, a callback
/// landing inside `withdrawFromZkp2p`'s payout can credit another session out of
/// money that is already on its way out, leaving `totalCommitted` above the real
/// balance: every later `creditSession` and `unassignedBalance()` then reverts on
/// underflow, and the credited session's rescue reverts forever.
contract ReentrantUSDC is IERC20 {
    string public constant name = "Callback USDC";
    string public constant symbol = "cUSDC";
    uint8 public constant decimals = 6;

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;

    address public glue;
    bytes32 public targetSession;
    uint256 public creditAmount;
    bool public armed;
    bool public reentryAttempted;
    bool public reentrySucceeded;

    /// The reentrant call is made through this, so it arrives from the keeper.
    ///
    /// Calling `creditSession` as the token itself would be rejected by
    /// `onlyKeeper` for a reason that has nothing to do with reentrancy, and the
    /// test would pass whether or not a guard existed. The realistic case is a
    /// hostile or upgraded token reentering while the keeper's own transaction
    /// is on the stack, so the caller has to be the keeper.
    address public reenterAs;

    function arm(address _glue, bytes32 _session, uint256 _amount, address _reenterAs) external {
        glue = _glue;
        targetSession = _session;
        creditAmount = _amount;
        reenterAs = _reenterAs;
        armed = true;
    }

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
        _maybeReenter();
        return true;
    }

    function allowance(address owner_, address spender) external view returns (uint256) {
        return _allowances[owner_][spender];
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

    /// The hook: try to credit another session while the payout is in flight.
    function _maybeReenter() internal {
        if (!armed) return;
        armed = false;
        reentryAttempted = true;

        // Enter as the keeper, so authorization is not what stops this.
        Reenterer(reenterAs).creditFor(glue, targetSession, creditAmount);
        reentrySucceeded = Reenterer(reenterAs).lastCallSucceeded();
    }
}

/// Stands in for the keeper, so the reentrant call arrives authorized.
contract Reenterer {
    bool public lastCallSucceeded;

    function creditFor(address glue, bytes32 sessionId, uint256 amount) external {
        (bool ok,) =
            glue.call(abi.encodeWithSignature("creditSession(bytes32,uint256)", sessionId, amount));
        lastCallSucceeded = ok;
    }

    function creditSession(address glue, bytes32 sessionId, uint256 amount) external {
        OfframpGlue(glue).creditSession(sessionId, amount);
    }

    function processOfframp(
        address glue,
        bytes32 sessionId,
        bytes32[] calldata methods,
        IEscrow.DepositPaymentMethodData[] calldata methodData,
        IEscrow.Currency[][] calldata currencies
    ) external {
        OfframpGlue(glue).processOfframp(sessionId, methods, methodData, currencies);
    }
}

contract OfframpGlueReentrancyTest is Test {
    ReentrantUSDC public usdc;
    MockEscrow public escrow;
    OfframpGlue public glue;
    Reenterer public keeperContract;

    address public keeper;
    address public userA = address(0xA1);
    address public userB = address(0xB1);

    bytes32 public constant VENMO_METHOD = keccak256("venmo");
    bytes32 public constant PAYEE_HASH = keccak256("mock-zkp2p-payee:alice");

    function setUp() public {
        usdc = new ReentrantUSDC();
        escrow = new MockEscrow(address(usdc));
        glue = new OfframpGlue(address(usdc), address(escrow));

        // The keeper is a contract here, so the token's callback can re-enter
        // through it and arrive properly authorized.
        keeperContract = new Reenterer();
        keeper = address(keeperContract);
        glue.setKeeper(keeper);
    }

    function _methods() internal pure returns (bytes32[] memory methods) {
        methods = new bytes32[](1);
        methods[0] = VENMO_METHOD;
    }

    function _methodData() internal pure returns (IEscrow.DepositPaymentMethodData[] memory data) {
        data = new IEscrow.DepositPaymentMethodData[](1);
        data[0] =
            IEscrow.DepositPaymentMethodData({intentGatingService: address(0), payeeDetails: PAYEE_HASH, data: ""});
    }

    function _currencies() internal pure returns (IEscrow.Currency[][] memory currencies) {
        currencies = new IEscrow.Currency[][](1);
        currencies[0] = new IEscrow.Currency[](1);
        currencies[0][0] = IEscrow.Currency({
            code: keccak256("USD"),
            minConversionRate: 1e18,
            oracleRateConfig: IEscrow.OracleRateConfig({
                adapter: address(0),
                adapterConfig: "",
                spreadBps: 0,
                maxStaleness: 0
            })
        });
    }

    /// A callback token must not be able to credit a session out of money that is
    /// already leaving the contract.
    function test_ACallbackTokenCannotCreditDuringAPayout() public {
        bytes32 sA = keccak256("sessionA");
        bytes32 sB = keccak256("sessionB");

        vm.startPrank(keeper);
        glue.createSession(sA, userA, PAYEE_HASH, 1e18, 100e6);
        glue.createSession(sB, userB, PAYEE_HASH, 1e18, 100e6);
        vm.stopPrank();

        usdc.mint(address(glue), 100e6);
        keeperContract.creditSession(address(glue), sA, 100e6);

        keeperContract.processOfframp(
            address(glue), sA, _methods(), _methodData(), _currencies()
        );

        // The token will try to credit B, as the keeper, while A's withdrawal is
        // being paid out.
        usdc.arm(address(glue), sB, 100e6, address(keeperContract));

        vm.prank(userA);
        glue.withdrawFromZkp2p(sA);

        assertTrue(usdc.reentryAttempted(), "the test's callback must actually fire");
        assertFalse(usdc.reentrySucceeded(), "the reentrant creditSession must be rejected");

        // The books still balance: A was paid, B was never credited, and the
        // contract is not claiming to hold money it does not have.
        assertEq(usdc.balanceOf(userA), 100e6);
        assertEq(glue.getSession(sB).credited, 0);
        assertEq(glue.totalCommitted(), 0);
        assertLe(glue.totalCommitted(), usdc.balanceOf(address(glue)));

        // And unassignedBalance still answers rather than reverting on underflow.
        assertEq(glue.unassignedBalance(), usdc.balanceOf(address(glue)));
    }

    /// The rescue path, for the same callback.
    ///
    /// This one holds for a second reason on top of the guard: `rescue` zeroes
    /// the credit and decrements `totalCommitted` before it transfers, so a
    /// callback arriving mid-payout finds the money already accounted as leaving
    /// and there is no unassigned balance to take. Effects-before-interactions is
    /// doing the work here; the guard is the belt to that pair of braces. Both
    /// are asserted, because the ordering is easy to lose in a later edit.
    function test_ACallbackTokenCannotCreditDuringARescue() public {
        bytes32 sA = keccak256("sessionA");
        bytes32 sB = keccak256("sessionB");

        vm.startPrank(keeper);
        glue.createSession(sA, userA, PAYEE_HASH, 1e18, 50e6);
        glue.createSession(sB, userB, PAYEE_HASH, 1e18, 50e6);
        vm.stopPrank();

        usdc.mint(address(glue), 50e6);
        keeperContract.creditSession(address(glue), sA, 50e6);

        usdc.arm(address(glue), sB, 50e6, address(keeperContract));

        vm.prank(userA);
        glue.rescue(sA);

        assertTrue(usdc.reentryAttempted());
        assertFalse(usdc.reentrySucceeded(), "the reentrant creditSession must be rejected");
        assertEq(glue.totalCommitted(), 0);
        assertLe(glue.totalCommitted(), usdc.balanceOf(address(glue)));
    }
}
