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

        // Simulate NEAR Intent delivery
        usdc.mint(address(glue), amount);

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

        usdc.mint(address(glue), 100e6);

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

        usdc.mint(address(glue), 100e6);

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

        usdc.mint(address(glue), 100e6);

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

        usdc.mint(address(glue), amount);

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

        usdc.mint(address(glue), 100e6);

        vm.prank(taker);
        vm.expectRevert(OfframpGlue.Unauthorized.selector);
        glue.rescue(sessionId);
    }

    function test_Rescue_RevertIfAlreadyProcessed() public {
        bytes32 sessionId = keccak256("session1");
        bytes32 payeeHash = PAYEE_HASH;

        vm.prank(keeper);
        glue.createSession(sessionId, user, payeeHash, 1e18, 100e6);

        usdc.mint(address(glue), 100e6);

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

        usdc.mint(address(glue), amount);

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
}
