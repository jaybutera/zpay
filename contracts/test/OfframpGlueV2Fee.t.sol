// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {OfframpGlueV2} from "../src/OfframpGlueV2.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {IEscrow} from "../src/interfaces/IEscrow.sol";
import {MockUSDC, MockEscrow} from "./OfframpGlue.t.sol";

/// @notice Fee and treasury behaviour of the OfframpGlueV2 prototype.
///
/// The suite the live glue already has proves the per-session accounting holds
/// with no fee in the path. What these tests have to prove is that adding one
/// does not weaken it: the fee comes out of the session's own credited amount,
/// the accrued pool is unreachable by any session, and the escape hatch still
/// pays the user without the keeper.
contract OfframpGlueV2FeeTest is Test {
    OfframpGlueV2 public glue;
    MockUSDC public usdc;
    MockEscrow public escrow;

    address public owner = address(this);
    address public keeper = address(0x1);
    address public user = address(0x2);
    address public userB = address(0x4);
    address public treasury = address(0xFEE);

    bytes32 public constant VENMO_METHOD = keccak256("venmo");
    bytes32 public constant USD_CODE = keccak256("USD");
    bytes32 public constant PAYEE_HASH = keccak256("mock-zkp2p-payee:alice");
    bytes32 public constant PAYEE_HASH_B = keccak256("mock-zkp2p-payee:bob");

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

    function _fund(bytes32 sessionId, uint256 amount) internal {
        usdc.mint(address(glue), amount);
        vm.prank(keeper);
        glue.creditSession(sessionId, amount);
    }

    function _process(bytes32 sessionId, bytes32 payeeHash) internal returns (uint256) {
        vm.prank(keeper);
        return glue.processOfframp(sessionId, _methods(), _methodData(payeeHash), _currencies());
    }

    /// The identity every test below leans on: the contract's whole balance is
    /// exactly what sessions own plus what the treasury has accrued, and nothing
    /// else. If a fee ever came out of the wrong place, this is what breaks.
    function _assertLedgerBalances() internal view {
        assertEq(
            usdc.balanceOf(address(glue)),
            glue.totalCommitted() + glue.accruedFees(),
            "balance must equal committed plus accrued"
        );
    }

    function setUp() public {
        usdc = new MockUSDC();
        escrow = new MockEscrow(address(usdc));
        glue = new OfframpGlueV2(address(usdc), address(escrow), treasury);
        glue.setKeeper(keeper);

        vm.prank(keeper);
        glue.createSession(bytes32("s1"), user, PAYEE_HASH, 1e18, 100e6);
    }

    // ============ Defaults and bounds ============

    function test_FeeStartsAtZero() public view {
        assertEq(glue.feeBps(), 0, "a fresh deployment charges nothing");
        assertEq(glue.accruedFees(), 0);
        assertEq(glue.feeRecipient(), treasury);
    }

    function test_MaxFeeBpsIsOneHundred() public view {
        assertEq(glue.MAX_FEE_BPS(), 100, "hard ceiling is 1%");
    }

    function test_SetFeeBps() public {
        glue.setFeeBps(20);
        assertEq(glue.feeBps(), 20);
    }

    function test_SetFeeBps_RevertAboveMax() public {
        vm.expectRevert(OfframpGlueV2.FeeTooHigh.selector);
        glue.setFeeBps(101);
    }

    function test_SetFeeBps_AcceptsExactlyMax() public {
        glue.setFeeBps(100);
        assertEq(glue.feeBps(), 100);
    }

    function test_SetFeeBps_RevertIfNotOwner() public {
        vm.prank(keeper);
        vm.expectRevert(OfframpGlueV2.Unauthorized.selector);
        glue.setFeeBps(20);
    }

    function test_SetFeeRecipient_RevertIfNotOwner() public {
        vm.prank(keeper);
        vm.expectRevert(OfframpGlueV2.Unauthorized.selector);
        glue.setFeeRecipient(address(0xBAD));
    }

    function test_SetFeeRecipient_RevertIfZero() public {
        vm.expectRevert(OfframpGlueV2.ZeroAddress.selector);
        glue.setFeeRecipient(address(0));
    }

    /// The owner may not raise the ceiling, only move within it. `MAX_FEE_BPS`
    /// is a constant with no setter, which is the point: a user can bound their
    /// worst case by reading the bytecode rather than by trusting the operator.
    function test_TheCeilingItselfIsNotSettable() public view {
        // No selector exists for changing MAX_FEE_BPS. Assert the constant holds
        // after an owner has pushed the fee to its limit.
        assertEq(glue.MAX_FEE_BPS(), 100);
    }

    // ============ The fee arithmetic ============

    function test_ZeroFeeDepositsEverything() public {
        _fund(bytes32("s1"), 100e6);
        uint256 depositId = _process(bytes32("s1"), PAYEE_HASH);

        assertEq(escrow.getDeposit(depositId).remainingDeposits, 100e6, "no fee, full amount");
        assertEq(glue.accruedFees(), 0);
        assertEq(glue.getSession(bytes32("s1")).feePaid, 0);
        _assertLedgerBalances();
    }

    function test_FeeIsSubtractedFromTheSessionsOwnCredit() public {
        glue.setFeeBps(20); // 20 bps
        _fund(bytes32("s1"), 100e6);

        uint256 depositId = _process(bytes32("s1"), PAYEE_HASH);

        // 20 bps of 100 USDC is 0.20 USDC.
        assertEq(glue.accruedFees(), 0.2e6, "fee accrued");
        assertEq(escrow.getDeposit(depositId).remainingDeposits, 99.8e6, "net reached the escrow");
        assertEq(glue.getSession(bytes32("s1")).deposited, 99.8e6);
        assertEq(glue.getSession(bytes32("s1")).feePaid, 0.2e6);
        assertEq(glue.totalCommitted(), 0, "the gross left the committed pool");
        _assertLedgerBalances();
    }

    /// The gross is what the session was credited, so fee plus net is exactly
    /// the credit. No rounding leaks value in either direction.
    function testFuzz_FeePlusNetAlwaysEqualsGross(uint96 gross, uint8 bps) public {
        uint256 amount = uint256(bound(gross, 1, 1_000_000e6));
        uint256 feeBps_ = bound(bps, 0, 100);

        glue.setFeeBps(feeBps_);

        vm.prank(keeper);
        glue.createSession(bytes32("fz"), user, PAYEE_HASH, 1e18, amount);
        _fund(bytes32("fz"), amount);

        uint256 depositId = _process(bytes32("fz"), PAYEE_HASH);

        uint256 fee = glue.accruedFees();
        uint256 net = escrow.getDeposit(depositId).remainingDeposits;

        assertEq(fee + net, amount, "the split conserves the credit exactly");
        assertLe(fee * 10_000, amount * 100, "fee never exceeds the 100 bps ceiling of gross");
        _assertLedgerBalances();
    }

    /// Integer division floors, so a dust-sized session pays nothing rather than
    /// having its whole principal rounded into the treasury.
    function test_DustSessionRoundsTheFeeToZero() public {
        glue.setFeeBps(100); // the maximum
        vm.prank(keeper);
        glue.createSession(bytes32("dust"), user, PAYEE_HASH, 1e18, 99);
        _fund(bytes32("dust"), 99);

        uint256 depositId = _process(bytes32("dust"), PAYEE_HASH);

        assertEq(glue.accruedFees(), 0, "100 bps of 99 units floors to zero");
        assertEq(escrow.getDeposit(depositId).remainingDeposits, 99);
        _assertLedgerBalances();
    }

    /// A fee change binds the sessions processed after it, not the ones already
    /// deposited. `feePaid` is the per-session record of what was actually taken.
    function test_FeeChangeDoesNotRewriteASettledSession() public {
        glue.setFeeBps(10);
        _fund(bytes32("s1"), 100e6);
        _process(bytes32("s1"), PAYEE_HASH);
        assertEq(glue.getSession(bytes32("s1")).feePaid, 0.1e6);

        glue.setFeeBps(100);

        vm.prank(keeper);
        glue.createSession(bytes32("s2"), userB, PAYEE_HASH_B, 1e18, 100e6);
        _fund(bytes32("s2"), 100e6);
        _process(bytes32("s2"), PAYEE_HASH_B);

        assertEq(glue.getSession(bytes32("s1")).feePaid, 0.1e6, "the settled session is untouched");
        assertEq(glue.getSession(bytes32("s2")).feePaid, 1e6, "the new one pays the new rate");
        assertEq(glue.accruedFees(), 1.1e6);
        _assertLedgerBalances();
    }

    // ============ The invariant the audits established ============

    /// The reason `accruedFees` is subtracted in `_unassignedBalance`. Without
    /// it, an accrued fee looks exactly like an unassigned arrival and the next
    /// session credits it away; the sweep would then have to come out of a live
    /// session's slice.
    function test_AccruedFeesCannotBeCreditedToASession() public {
        glue.setFeeBps(100);
        _fund(bytes32("s1"), 100e6);
        _process(bytes32("s1"), PAYEE_HASH);

        assertEq(glue.accruedFees(), 1e6, "1 USDC is sitting on the contract as fee");
        assertEq(usdc.balanceOf(address(glue)), 1e6, "and it is really there");
        assertEq(glue.unassignedBalance(), 0, "but nothing is creditable");

        vm.prank(keeper);
        glue.createSession(bytes32("s2"), userB, PAYEE_HASH_B, 1e18, 100e6);

        // No new money arrived. The only balance is the fee, and it must be
        // out of reach.
        vm.prank(keeper);
        vm.expectRevert(OfframpGlueV2.InsufficientUnassignedBalance.selector);
        glue.creditSession(bytes32("s2"), 1e6);
    }

    /// Concurrent sessions with a fee in the path. Each session's deposit is its
    /// own credit net of its own fee, and neither can reach the other's money.
    function test_ConcurrentSessionsEachPayTheirOwnFee() public {
        glue.setFeeBps(50);

        vm.prank(keeper);
        glue.createSession(bytes32("s2"), userB, PAYEE_HASH_B, 1e18, 40e6);

        _fund(bytes32("s1"), 100e6);
        _fund(bytes32("s2"), 40e6);

        assertEq(glue.totalCommitted(), 140e6);

        uint256 d1 = _process(bytes32("s1"), PAYEE_HASH);
        uint256 d2 = _process(bytes32("s2"), PAYEE_HASH_B);

        assertEq(escrow.getDeposit(d1).remainingDeposits, 99.5e6, "s1 keeps its own net");
        assertEq(escrow.getDeposit(d2).remainingDeposits, 39.8e6, "s2 keeps its own net");
        assertEq(glue.accruedFees(), 0.5e6 + 0.2e6, "fees sum, they do not cross");
        assertEq(glue.totalCommitted(), 0);
        _assertLedgerBalances();
    }

    /// The property the audits pinned: no session can ever move more value than
    /// it was credited, fee or no fee.
    function testFuzz_NoSessionTakesMoreThanItsCredit(uint64 a, uint64 b, uint8 bps) public {
        uint256 amountA = uint256(bound(a, 1e6, 100_000e6));
        uint256 amountB = uint256(bound(b, 1e6, 100_000e6));
        glue.setFeeBps(bound(bps, 0, 100));

        vm.prank(keeper);
        glue.createSession(bytes32("fa"), user, PAYEE_HASH, 1e18, amountA);
        vm.prank(keeper);
        glue.createSession(bytes32("fb"), userB, PAYEE_HASH_B, 1e18, amountB);

        _fund(bytes32("fa"), amountA);
        _fund(bytes32("fb"), amountB);

        uint256 da = _process(bytes32("fa"), PAYEE_HASH);
        uint256 db = _process(bytes32("fb"), PAYEE_HASH_B);

        assertLe(escrow.getDeposit(da).remainingDeposits, amountA, "fa never exceeds its credit");
        assertLe(escrow.getDeposit(db).remainingDeposits, amountB, "fb never exceeds its credit");
        assertEq(
            escrow.getDeposit(da).remainingDeposits + escrow.getDeposit(db).remainingDeposits + glue.accruedFees(),
            amountA + amountB,
            "every unit is accounted for"
        );
        _assertLedgerBalances();
    }

    // ============ The escape hatch ============

    /// A session that never reached a deposit was never served. It refunds in
    /// full, and it accrues no fee, so a fee-setting owner gains nothing from a
    /// session failing.
    function test_RescueRefundsInFullAndChargesNoFee() public {
        glue.setFeeBps(100);
        _fund(bytes32("s1"), 100e6);

        vm.prank(user);
        glue.rescue(bytes32("s1"));

        assertEq(usdc.balanceOf(user), 100e6, "the user got all of it back");
        assertEq(glue.accruedFees(), 0, "and the protocol took nothing");
        _assertLedgerBalances();
    }

    /// The user path still works with the keeper uninvolved, which is the
    /// guarantee the escape hatch exists for.
    function test_UserCanStillRescueWithoutTheKeeper() public {
        glue.setFeeBps(50);
        _fund(bytes32("s1"), 100e6);

        vm.prank(user);
        glue.rescue(bytes32("s1"));

        assertEq(usdc.balanceOf(user), 100e6);
    }

    /// An unfilled deposit returns what it holds, which is already net of the
    /// fee taken when it was created. The user recovers their principal minus
    /// the fee, and the fee stays accrued.
    function test_WithdrawReturnsTheNetAndTheFeeStaysAccrued() public {
        glue.setFeeBps(50);
        _fund(bytes32("s1"), 100e6);
        _process(bytes32("s1"), PAYEE_HASH);

        vm.prank(user);
        glue.withdrawFromZkp2p(bytes32("s1"));

        assertEq(usdc.balanceOf(user), 99.5e6, "the user gets the net back");
        assertEq(glue.accruedFees(), 0.5e6, "the fee is still reserved");
        _assertLedgerBalances();
    }

    /// The withdraw cap is `session.deposited`, which is net of the fee. Money
    /// landing during the call must not let a session claw back more than that,
    /// and must not be able to reach the accrued pool either.
    function test_WithdrawCannotSweepTheAccruedFees() public {
        glue.setFeeBps(100);

        vm.prank(keeper);
        glue.createSession(bytes32("s2"), userB, PAYEE_HASH_B, 1e18, 100e6);

        _fund(bytes32("s1"), 100e6);
        _fund(bytes32("s2"), 100e6);
        _process(bytes32("s1"), PAYEE_HASH);
        _process(bytes32("s2"), PAYEE_HASH_B);

        assertEq(glue.accruedFees(), 2e6);

        // The escrow hands back extra alongside the withdrawal, standing in for
        // an unrelated arrival in the same transaction.
        escrow.setWithdrawBonus(5e6);
        usdc.mint(address(escrow), 5e6);

        vm.prank(user);
        glue.withdrawFromZkp2p(bytes32("s1"));

        assertEq(usdc.balanceOf(user), 99e6, "capped at what this session deposited");
        assertEq(glue.accruedFees(), 2e6, "the treasury pool is untouched");
    }

    // ============ Sweeping ============

    function test_SweepSendsToTheRecipientNotTheCaller() public {
        glue.setFeeBps(100);
        _fund(bytes32("s1"), 100e6);
        _process(bytes32("s1"), PAYEE_HASH);

        // Anyone may push the sweep; nobody may redirect it.
        vm.prank(address(0xDEAD));
        glue.sweepFees();

        assertEq(usdc.balanceOf(treasury), 1e6, "the treasury got it");
        assertEq(usdc.balanceOf(address(0xDEAD)), 0, "the caller got nothing");
        assertEq(glue.accruedFees(), 0);
    }

    function test_Sweep_RevertIfNothingAccrued() public {
        vm.expectRevert(OfframpGlueV2.NoFeesToSweep.selector);
        glue.sweepFees();
    }

    /// A sweep must never reach a live session's credited USDC, even though both
    /// sit in the same pot.
    function test_SweepCannotTouchALiveSessionsCredit() public {
        glue.setFeeBps(100);
        _fund(bytes32("s1"), 100e6);
        _process(bytes32("s1"), PAYEE_HASH);

        // A second session is credited and still in flight.
        vm.prank(keeper);
        glue.createSession(bytes32("s2"), userB, PAYEE_HASH_B, 1e18, 60e6);
        _fund(bytes32("s2"), 60e6);

        assertEq(usdc.balanceOf(address(glue)), 61e6, "60 committed plus 1 accrued");

        glue.sweepFees();

        assertEq(usdc.balanceOf(treasury), 1e6, "only the fee left");
        assertEq(usdc.balanceOf(address(glue)), 60e6, "the live session is intact");
        assertEq(glue.totalCommitted(), 60e6);

        // And that session can still complete.
        uint256 depositId = _process(bytes32("s2"), PAYEE_HASH_B);
        assertEq(escrow.getDeposit(depositId).remainingDeposits, 59.4e6);
    }

    function test_SweepAfterRecipientChangeGoesToTheNewAddress() public {
        glue.setFeeBps(100);
        _fund(bytes32("s1"), 100e6);
        _process(bytes32("s1"), PAYEE_HASH);

        address newTreasury = address(0xC0FFEE);
        glue.setFeeRecipient(newTreasury);
        glue.sweepFees();

        assertEq(usdc.balanceOf(newTreasury), 1e6);
        assertEq(usdc.balanceOf(treasury), 0);
    }

    // ============ previewFee ============

    /// The coordinator and the front end have to quote the same net the contract
    /// will deposit, including the rounding.
    function testFuzz_PreviewMatchesWhatProcessActuallyDoes(uint96 gross, uint8 bps) public {
        uint256 amount = uint256(bound(gross, 1, 1_000_000e6));
        glue.setFeeBps(bound(bps, 0, 100));

        (uint256 previewedFee, uint256 previewedNet) = glue.previewFee(amount);

        vm.prank(keeper);
        glue.createSession(bytes32("pv"), user, PAYEE_HASH, 1e18, amount);
        _fund(bytes32("pv"), amount);
        uint256 depositId = _process(bytes32("pv"), PAYEE_HASH);

        assertEq(previewedFee, glue.accruedFees(), "preview matches the accrual");
        assertEq(previewedNet, escrow.getDeposit(depositId).remainingDeposits, "preview matches the deposit");
    }
}
