// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {OfframpGlue} from "../src/OfframpGlue.sol";
import {IEscrow} from "../src/interfaces/IEscrow.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {MockUSDC, MockEscrow} from "./OfframpGlue.t.sol";

/// @notice Tests for the settable intent amount range on `processOfframpWithRange`.
///
/// The range exists because zk-p2p's quoting API will not list a deposit whose
/// intent range is a single point: it fits a fee-inclusive intent amount into
/// `[min, max]`, and the fee moves that amount by more than one unit per unit of
/// order size, so it steps over a lone admissible value. Widening the range is
/// what makes a deposit discoverable, and `min` is what stops a taker claiming a
/// trivial slice of it.
///
/// The range must not become a way to spend money a session does not own, so the
/// invariants the audits established are re-checked here against the new path
/// rather than only against the old one.
contract OfframpGlueIntentRangeTest is Test {
    OfframpGlue internal glue;
    MockUSDC internal usdc;
    MockEscrow internal escrow;

    address internal owner = address(this);
    address internal keeper = address(0x1);
    address internal user = address(0x2);
    address internal otherUser = address(0x4);

    bytes32 internal constant VENMO_METHOD = keccak256("venmo");
    bytes32 internal constant USD_CODE = keccak256("USD");
    bytes32 internal constant PAYEE_HASH = keccak256("mock-zkp2p-payee:alice");
    bytes32 internal constant OTHER_PAYEE = keccak256("mock-zkp2p-payee:bob");

    function setUp() public {
        usdc = new MockUSDC();
        escrow = new MockEscrow(address(usdc));
        glue = new OfframpGlue(address(usdc), address(escrow));
        glue.setKeeper(keeper);
    }

    function _usd() internal pure returns (IEscrow.Currency memory) {
        return IEscrow.Currency({
            code: USD_CODE,
            minConversionRate: 1e18,
            oracleRateConfig: IEscrow.OracleRateConfig({
                adapter: address(0),
                adapterConfig: "",
                spreadBps: 0,
                maxStaleness: 0
            })
        });
    }

    function _methods() internal pure returns (bytes32[] memory m) {
        m = new bytes32[](1);
        m[0] = VENMO_METHOD;
    }

    function _methodData(bytes32 payeeHash) internal pure returns (IEscrow.DepositPaymentMethodData[] memory d) {
        d = new IEscrow.DepositPaymentMethodData[](1);
        d[0] = IEscrow.DepositPaymentMethodData({intentGatingService: address(0), payeeDetails: payeeHash, data: ""});
    }

    function _currencies() internal pure returns (IEscrow.Currency[][] memory c) {
        c = new IEscrow.Currency[][](1);
        c[0] = new IEscrow.Currency[](1);
        c[0][0] = _usd();
    }

    function _fund(bytes32 sessionId, uint256 amount) internal {
        usdc.mint(address(glue), amount);
        vm.prank(keeper);
        glue.creditSession(sessionId, amount);
    }

    function _openSession(bytes32 sessionId, address who, bytes32 payee, uint256 amount) internal {
        vm.prank(keeper);
        glue.createSession(sessionId, who, payee, 1e18, amount);
        _fund(sessionId, amount);
    }

    // ============ The range reaches the escrow ============

    /// The live shape: a floor just under the amount, a ceiling at the amount.
    function test_RangeIsWrittenToTheDeposit() public {
        bytes32 sessionId = keccak256("range-live");
        uint256 amount = 4_875_438;
        uint256 min = 4_800_000;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        uint256 depositId = glue.processOfframpWithRange(
            sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), min, amount
        );

        IEscrow.Deposit memory d = escrow.getDeposit(depositId);
        assertEq(d.intentAmountRange.min, min, "min not applied");
        assertEq(d.intentAmountRange.max, amount, "max not applied");
        assertEq(d.remainingDeposits, amount, "deposit must still hold the whole credit");
    }

    /// Zero means "no preference" and reproduces the pre-change behaviour exactly.
    function test_ZeroRangeDefaultsToFullAmount() public {
        bytes32 sessionId = keccak256("range-default");
        uint256 amount = 100e6;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        uint256 depositId =
            glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 0, 0);

        IEscrow.Deposit memory d = escrow.getDeposit(depositId);
        assertEq(d.intentAmountRange.min, amount);
        assertEq(d.intentAmountRange.max, amount);
    }

    /// The old entry point is untouched: still one intent for the full amount.
    function test_LegacyProcessOfframpStillPinsTheRange() public {
        bytes32 sessionId = keccak256("range-legacy");
        uint256 amount = 100e6;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        uint256 depositId = glue.processOfframp(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies());

        IEscrow.Deposit memory d = escrow.getDeposit(depositId);
        assertEq(d.intentAmountRange.min, amount);
        assertEq(d.intentAmountRange.max, amount);
    }

    // ============ The range cannot exceed the money behind it ============

    /// A max above the session's credit would advertise a claim the deposit
    /// cannot honour. This is the invariant the whole change hangs on.
    function test_RevertWhenMaxExceedsCredited() public {
        bytes32 sessionId = keccak256("range-over");
        uint256 amount = 100e6;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.InvalidIntentRange.selector);
        glue.processOfframpWithRange(
            sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 1e6, amount + 1
        );
    }

    function test_RevertWhenMinAboveMax() public {
        bytes32 sessionId = keccak256("range-inverted");
        uint256 amount = 100e6;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.InvalidIntentRange.selector);
        glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 50e6, 40e6);
    }

    /// A min of zero is read as "unset" and becomes the amount, so the escrow's
    /// own ZeroMinValue guard is never the thing that has to catch it.
    function test_MinZeroWithExplicitMaxDefaultsMinToAmount() public {
        bytes32 sessionId = keccak256("range-minzero");
        uint256 amount = 100e6;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        uint256 depositId =
            glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 0, amount);

        IEscrow.Deposit memory d = escrow.getDeposit(depositId);
        assertEq(d.intentAmountRange.min, amount);
        assertEq(d.intentAmountRange.max, amount);
    }

    function test_FullWidthRangeIsAllowed() public {
        bytes32 sessionId = keccak256("range-wide");
        uint256 amount = 100e6;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        uint256 depositId =
            glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 1, amount);

        IEscrow.Deposit memory d = escrow.getDeposit(depositId);
        assertEq(d.intentAmountRange.min, 1);
        assertEq(d.intentAmountRange.max, amount);
    }

    /// The range is bounded by what this session credited, not by the contract's
    /// balance. A second session's money sitting on the glue must not raise it.
    function test_RangeIsBoundedByOwnCreditNotContractBalance() public {
        bytes32 mine = keccak256("range-mine");
        bytes32 theirs = keccak256("range-theirs");
        _openSession(mine, user, PAYEE_HASH, 10e6);
        _openSession(theirs, otherUser, OTHER_PAYEE, 90e6);

        assertEq(usdc.balanceOf(address(glue)), 100e6);

        // 50e6 is well under the contract balance but over this session's credit.
        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.InvalidIntentRange.selector);
        glue.processOfframpWithRange(mine, _methods(), _methodData(PAYEE_HASH), _currencies(), 1e6, 50e6);
    }

    // ============ Access control and payee binding are unchanged ============

    function test_OnlyKeeperOrOwnerMayCallWithRange() public {
        bytes32 sessionId = keccak256("range-auth");
        _openSession(sessionId, user, PAYEE_HASH, 100e6);

        vm.prank(address(0xBEEF));
        vm.expectRevert(OfframpGlue.Unauthorized.selector);
        glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 1e6, 100e6);
    }

    /// The range must not become a way around the payee check.
    function test_PayeeMismatchStillRevertsWithRange() public {
        bytes32 sessionId = keccak256("range-payee");
        _openSession(sessionId, user, PAYEE_HASH, 100e6);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.PayeeDetailsMismatch.selector);
        glue.processOfframpWithRange(sessionId, _methods(), _methodData(OTHER_PAYEE), _currencies(), 1e6, 100e6);
    }

    function test_DoubleProcessStillRevertsWithRange() public {
        bytes32 sessionId = keccak256("range-double");
        uint256 amount = 100e6;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 1e6, amount);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.SessionAlreadyProcessed.selector);
        glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 1e6, amount);
    }

    // ============ Accounting invariants ============

    /// `credited` is zeroed and `totalCommitted` drops by exactly this session's
    /// amount, regardless of what range was requested.
    function test_AccountingUnaffectedByRange() public {
        bytes32 mine = keccak256("acct-mine");
        bytes32 theirs = keccak256("acct-theirs");
        _openSession(mine, user, PAYEE_HASH, 40e6);
        _openSession(theirs, otherUser, OTHER_PAYEE, 60e6);
        assertEq(glue.totalCommitted(), 100e6);

        vm.prank(keeper);
        glue.processOfframpWithRange(mine, _methods(), _methodData(PAYEE_HASH), _currencies(), 30e6, 40e6);

        assertEq(glue.totalCommitted(), 60e6, "only this session leaves the committed pool");

        OfframpGlue.Session memory s = glue.getSession(mine);
        assertEq(s.credited, 0);
        assertEq(s.deposited, 40e6);
        assertTrue(s.processed);

        // The other session is untouched and can still be processed in full.
        OfframpGlue.Session memory o = glue.getSession(theirs);
        assertEq(o.credited, 60e6);
        assertFalse(o.processed);
    }

    /// Two concurrent sessions with different ranges stay isolated end to end.
    function test_ConcurrentSessionsStayIsolatedWithRanges() public {
        bytes32 a = keccak256("iso-a");
        bytes32 b = keccak256("iso-b");
        _openSession(a, user, PAYEE_HASH, 30e6);
        _openSession(b, otherUser, OTHER_PAYEE, 70e6);

        vm.prank(keeper);
        uint256 depA = glue.processOfframpWithRange(a, _methods(), _methodData(PAYEE_HASH), _currencies(), 25e6, 30e6);
        vm.prank(keeper);
        uint256 depB = glue.processOfframpWithRange(b, _methods(), _methodData(OTHER_PAYEE), _currencies(), 10e6, 70e6);

        IEscrow.Deposit memory dA = escrow.getDeposit(depA);
        IEscrow.Deposit memory dB = escrow.getDeposit(depB);
        assertEq(dA.remainingDeposits, 30e6);
        assertEq(dB.remainingDeposits, 70e6);
        assertEq(dA.intentAmountRange.min, 25e6);
        assertEq(dB.intentAmountRange.min, 10e6);
        assertEq(escrow.getDepositPayeeDetails(depA, VENMO_METHOD), PAYEE_HASH);
        assertEq(escrow.getDepositPayeeDetails(depB, VENMO_METHOD), OTHER_PAYEE);
        assertEq(glue.totalCommitted(), 0);
    }

    // ============ The escape hatch still works ============

    /// A ranged deposit that nobody took is still withdrawable by the user
    /// without the keeper, and pays the user rather than the caller.
    function test_UserCanWithdrawARangedDepositWithoutTheKeeper() public {
        bytes32 sessionId = keccak256("hatch-withdraw");
        uint256 amount = 4_875_438;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        glue.processOfframpWithRange(
            sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 4_800_000, amount
        );

        assertEq(usdc.balanceOf(user), 0);
        vm.prank(user);
        glue.withdrawFromZkp2p(sessionId);
        assertEq(usdc.balanceOf(user), amount, "user recovers the full deposit");
    }

    /// A ranged deposit's withdrawal still cannot sweep another session's money.
    function test_RangedWithdrawCannotTakeAnotherSessionsCredit() public {
        bytes32 mine = keccak256("hatch-mine");
        bytes32 theirs = keccak256("hatch-theirs");
        _openSession(mine, user, PAYEE_HASH, 10e6);
        _openSession(theirs, otherUser, OTHER_PAYEE, 90e6);

        vm.prank(keeper);
        glue.processOfframpWithRange(mine, _methods(), _methodData(PAYEE_HASH), _currencies(), 5e6, 10e6);

        // The escrow hands back extra USDC in the same call, standing in for a
        // settlement that lands mid-withdrawal.
        escrow.setWithdrawBonus(90e6);
        usdc.mint(address(escrow), 90e6);

        vm.prank(user);
        glue.withdrawFromZkp2p(mine);

        assertEq(usdc.balanceOf(user), 10e6, "capped at what this session deposited");
        assertEq(glue.totalCommitted(), 90e6, "the other session's credit is intact");
    }

    /// Rescue before processing is unaffected by the new path existing.
    function test_RescueStillWorksBeforeARangedProcess() public {
        bytes32 sessionId = keccak256("hatch-rescue");
        uint256 amount = 100e6;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(user);
        glue.rescue(sessionId);
        assertEq(usdc.balanceOf(user), amount);
        assertEq(glue.totalCommitted(), 0);

        vm.prank(keeper);
        vm.expectRevert(OfframpGlue.SessionAlreadyRescued.selector);
        glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 1e6, amount);
    }

    // ============ Owner still cannot move funds ============

    function test_OwnerCannotRedirectARangedDepositPayout() public {
        bytes32 sessionId = keccak256("owner-noloot");
        uint256 amount = 100e6;
        _openSession(sessionId, user, PAYEE_HASH, amount);

        vm.prank(keeper);
        glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), 50e6, amount);

        // The owner may call withdraw, but the money goes to session.user.
        uint256 ownerBefore = usdc.balanceOf(owner);
        glue.withdrawFromZkp2p(sessionId);
        assertEq(usdc.balanceOf(owner), ownerBefore, "owner gains nothing");
        assertEq(usdc.balanceOf(user), amount, "user is paid");
    }

    // ============ Fuzz: the range can never outrun the credit ============

    function testFuzz_RangeNeverExceedsCredit(uint256 amount, uint256 min, uint256 max) public {
        amount = bound(amount, 1, 1_000_000e6);
        min = bound(min, 0, 2_000_000e6);
        max = bound(max, 0, 2_000_000e6);

        bytes32 sessionId = keccak256(abi.encode("fuzz", amount, min, max));
        _openSession(sessionId, user, PAYEE_HASH, amount);

        uint256 effMin = min == 0 ? amount : min;
        uint256 effMax = max == 0 ? amount : max;

        vm.prank(keeper);
        if (effMin > effMax || effMax > amount) {
            vm.expectRevert(OfframpGlue.InvalidIntentRange.selector);
            glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), min, max);
        } else {
            uint256 depositId =
                glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), min, max);
            IEscrow.Deposit memory d = escrow.getDeposit(depositId);
            assertLe(d.intentAmountRange.max, amount, "max must never exceed the session credit");
            assertLe(d.intentAmountRange.min, d.intentAmountRange.max);
            assertGt(d.intentAmountRange.min, 0, "escrow rejects a zero min");
            assertEq(d.remainingDeposits, amount);
        }
    }
}

/// @notice Partial-fill behaviour, which only becomes reachable once the range
///         permits an intent smaller than the whole deposit.
///
/// The audits established that `withdrawFromZkp2p` measures the balance delta
/// and caps it at `session.deposited`. A partial fill makes the escrow return
/// *less* than `deposited`, which is the case the cap was never exercised
/// against before, because a point range made every fill all-or-nothing.
contract OfframpGluePartialFillTest is Test {
    OfframpGlue internal glue;
    MockUSDC internal usdc;
    PartialFillEscrow internal escrow;

    address internal keeper = address(0x1);
    address internal user = address(0x2);
    address internal otherUser = address(0x4);

    bytes32 internal constant VENMO_METHOD = keccak256("venmo");
    bytes32 internal constant USD_CODE = keccak256("USD");
    bytes32 internal constant PAYEE_HASH = keccak256("mock-zkp2p-payee:alice");
    bytes32 internal constant OTHER_PAYEE = keccak256("mock-zkp2p-payee:bob");

    function setUp() public {
        usdc = new MockUSDC();
        escrow = new PartialFillEscrow(address(usdc));
        glue = new OfframpGlue(address(usdc), address(escrow));
        glue.setKeeper(keeper);
    }

    function _usd() internal pure returns (IEscrow.Currency memory) {
        return IEscrow.Currency({
            code: USD_CODE,
            minConversionRate: 1e18,
            oracleRateConfig: IEscrow.OracleRateConfig({
                adapter: address(0),
                adapterConfig: "",
                spreadBps: 0,
                maxStaleness: 0
            })
        });
    }

    function _methods() internal pure returns (bytes32[] memory m) {
        m = new bytes32[](1);
        m[0] = VENMO_METHOD;
    }

    function _methodData(bytes32 p) internal pure returns (IEscrow.DepositPaymentMethodData[] memory d) {
        d = new IEscrow.DepositPaymentMethodData[](1);
        d[0] = IEscrow.DepositPaymentMethodData({intentGatingService: address(0), payeeDetails: p, data: ""});
    }

    function _currencies() internal pure returns (IEscrow.Currency[][] memory c) {
        c = new IEscrow.Currency[][](1);
        c[0] = new IEscrow.Currency[](1);
        c[0][0] = _usd();
    }

    function _openAndProcess(bytes32 sessionId, address who, uint256 amount, uint256 min)
        internal
        returns (uint256 depositId)
    {
        vm.prank(keeper);
        glue.createSession(sessionId, who, PAYEE_HASH, 1e18, amount);
        usdc.mint(address(glue), amount);
        vm.prank(keeper);
        glue.creditSession(sessionId, amount);
        vm.prank(keeper);
        depositId = glue.processOfframpWithRange(sessionId, _methods(), _methodData(PAYEE_HASH), _currencies(), min, amount);
    }

    /// A taker fills the minimum; the user withdraws the untaken remainder and
    /// gets exactly that remainder, never more.
    function test_PartialFillLeavesRemainderWithdrawableByUser() public {
        bytes32 sessionId = keccak256("partial-1");
        uint256 amount = 4_875_438;
        uint256 min = 4_800_000;
        uint256 depositId = _openAndProcess(sessionId, user, amount, min);

        // A taker claims the smallest permitted slice.
        escrow.simulateFill(depositId, min);

        vm.prank(user);
        glue.withdrawFromZkp2p(sessionId);

        assertEq(usdc.balanceOf(user), amount - min, "user gets exactly the untaken remainder");
        assertEq(glue.totalCommitted(), 0);
    }

    /// The remainder path must not be able to pay out more than was deposited,
    /// even if the escrow hands back extra in the same call.
    function test_PartialFillWithdrawIsStillCappedAtDeposited() public {
        bytes32 mine = keccak256("partial-mine");
        bytes32 theirs = keccak256("partial-theirs");
        uint256 amount = 10e6;
        uint256 depositId = _openAndProcess(mine, user, amount, 4e6);

        // A second session's money is parked on the glue.
        vm.prank(keeper);
        glue.createSession(theirs, otherUser, OTHER_PAYEE, 1e18, 90e6);
        usdc.mint(address(glue), 90e6);
        vm.prank(keeper);
        glue.creditSession(theirs, 90e6);

        escrow.simulateFill(depositId, 4e6);
        escrow.setWithdrawBonus(90e6);
        usdc.mint(address(escrow), 90e6);

        vm.prank(user);
        glue.withdrawFromZkp2p(mine);

        assertEq(usdc.balanceOf(user), amount - 4e6, "capped at the real remainder");
        assertEq(glue.totalCommitted(), 90e6, "other session untouched");
    }

    /// A fully filled ranged deposit returns nothing, and that is not an error.
    function test_FullFillLeavesNothingToWithdraw() public {
        bytes32 sessionId = keccak256("partial-full");
        uint256 amount = 4_875_438;
        uint256 depositId = _openAndProcess(sessionId, user, amount, 4_800_000);

        escrow.simulateFill(depositId, amount);

        vm.prank(user);
        glue.withdrawFromZkp2p(sessionId);
        assertEq(usdc.balanceOf(user), 0);
    }
}

/// @notice Escrow mock that supports a taker consuming part of a deposit.
contract PartialFillEscrow is IEscrow {
    uint256 public depositCounter;
    mapping(uint256 => Deposit) private _deposits;
    uint256 public withdrawBonus;

    constructor(address) {}

    function setWithdrawBonus(uint256 a) external {
        withdrawBonus = a;
    }

    /// Stands in for a taker fulfilling an intent: liquidity leaves the escrow.
    function simulateFill(uint256 depositId, uint256 amount) external {
        Deposit storage d = _deposits[depositId];
        require(amount >= d.intentAmountRange.min, "below min");
        require(amount <= d.intentAmountRange.max, "above max");
        require(amount <= d.remainingDeposits, "over remaining");
        d.remainingDeposits -= amount;
    }

    function createDeposit(CreateDepositParams calldata params) external {
        require(params.intentAmountRange.min > 0, "ZeroMinValue");
        require(params.intentAmountRange.min <= params.intentAmountRange.max, "InvalidRange");
        require(params.amount >= params.intentAmountRange.min, "AmountBelowMin");
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
        require(IERC20(params.token).transferFrom(msg.sender, address(this), params.amount), "transfer");
    }

    function withdrawDeposit(uint256 depositId) external {
        Deposit storage d = _deposits[depositId];
        require(d.depositor == msg.sender, "UnauthorizedCaller");
        uint256 amt = d.remainingDeposits;
        d.remainingDeposits = 0;
        d.acceptingIntents = false;
        require(IERC20(d.token).transfer(msg.sender, amt + withdrawBonus), "transfer");
    }

    function getDeposit(uint256 depositId) external view returns (Deposit memory) {
        return _deposits[depositId];
    }
}
