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
    uint256 private _nextDepositId = 1;
    mapping(uint256 => Deposit) private _deposits;
    mapping(address => uint256[]) private _accountDeposits;

    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function createDeposit(CreateDepositParams calldata params) external returns (uint256 depositId) {
        depositId = _nextDepositId++;

        // Transfer tokens from caller
        bool success = token.transferFrom(msg.sender, address(this), params.amount);
        require(success, "Transfer failed");

        _deposits[depositId] = Deposit({
            depositor: msg.sender,
            delegate: params.delegate,
            token: params.token,
            amount: params.amount,
            intentAmountRange: params.intentAmountRange,
            acceptedPaymentMethods: params.paymentMethods,
            intentGuardian: params.intentGuardian,
            retainOnEmpty: params.retainOnEmpty,
            closed: false
        });

        _accountDeposits[msg.sender].push(depositId);

        emit DepositCreated(depositId, msg.sender, params.token, params.amount);

        return depositId;
    }

    function withdrawDeposit(uint256 depositId, uint256 amount) external {
        Deposit storage deposit = _deposits[depositId];
        require(deposit.depositor == msg.sender, "Not depositor");
        require(deposit.amount >= amount, "Insufficient balance");

        deposit.amount -= amount;
        bool success = token.transfer(msg.sender, amount);
        require(success, "Transfer failed");

        emit DepositWithdrawn(depositId, msg.sender, amount);
    }

    function getDeposit(uint256 depositId) external view returns (Deposit memory) {
        return _deposits[depositId];
    }

    function getAccountDeposits(address account) external view returns (uint256[] memory) {
        return _accountDeposits[account];
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
        currencies[0][0] = IEscrow.Currency({
            code: USD_CODE,
            minConversionRate: 1e18
        });

        // Process offramp
        vm.prank(keeper);
        uint256 depositId = glue.processOfframp(sessionId, methods, methodData, currencies);

        assertEq(depositId, 1);

        OfframpGlue.Session memory session = glue.getSession(sessionId);
        assertEq(session.depositId, 1);

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
        currencies[0][0] = IEscrow.Currency({code: USD_CODE, minConversionRate: 1e18});

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
        currencies[0][0] = IEscrow.Currency({code: USD_CODE, minConversionRate: 1e18});

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
        currencies[0][0] = IEscrow.Currency({code: USD_CODE, minConversionRate: 1e18});

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
        currencies[0][0] = IEscrow.Currency({code: USD_CODE, minConversionRate: 1e18});

        vm.prank(keeper);
        glue.processOfframp(sessionId, methods, methodData, currencies);

        // User withdraws from zk-p2p
        vm.prank(user);
        glue.withdrawFromZkp2p(sessionId, amount);

        assertEq(usdc.balanceOf(user), amount);
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
