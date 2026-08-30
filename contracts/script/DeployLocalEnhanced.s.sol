// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {OfframpGlue} from "../src/OfframpGlue.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {IEscrow} from "../src/interfaces/IEscrow.sol";

/// @notice Mock USDC for local testing
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

/// @notice Mock zk-p2p Escrow that also acts as the Orchestrator
/// Emits IntentSignaled and IntentFulfilled events for testing the coordinator's event monitoring
contract MockEscrowWithOrchestrator is IEscrow {
    uint256 private _nextDepositId = 1;
    mapping(uint256 => Deposit) private _deposits;
    mapping(address => uint256[]) private _accountDeposits;

    // Orchestrator state
    mapping(bytes32 => Intent) private _intents;
    mapping(address => bytes32[]) private _accountIntents;

    IERC20 public token;

    // Intent struct matching IOrchestrator
    struct Intent {
        address owner;
        address to;
        address escrow;
        uint256 depositId;
        uint256 amount;
        uint256 timestamp;
        bytes32 paymentMethod;
        bytes32 fiatCurrency;
        uint256 conversionRate;
        bytes32 payeeDetails;
        address referrer;
        uint256 referrerFee;
        address postIntentHook;
        bytes data;
    }

    // Events from IOrchestrator
    event IntentSignaled(
        bytes32 indexed intentHash,
        address indexed escrow,
        uint256 indexed depositId,
        bytes32 paymentMethod,
        address owner,
        address to,
        uint256 amount,
        bytes32 fiatCurrency,
        uint256 conversionRate,
        uint256 timestamp
    );

    event IntentFulfilled(
        bytes32 indexed intentHash,
        address indexed fundsTransferredTo,
        uint256 amount,
        bool isManualRelease
    );

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

    // ============ Orchestrator Functions (for testing) ============

    /// @notice Simulate a taker signaling intent on a deposit
    /// @dev This is what a real taker would call on the real Orchestrator
    /// @param depositId The deposit to signal intent on
    /// @param taker The taker's address (who will receive USDC after payment proof)
    /// @param amount Amount of USDC requested
    /// @param paymentMethod Payment method hash (e.g., keccak256("venmo"))
    /// @param fiatCurrency Fiat currency hash (e.g., keccak256("USD"))
    /// @param conversionRate Conversion rate (18 decimals)
    /// @return intentHash The generated intent hash
    function signalIntent(
        uint256 depositId,
        address taker,
        uint256 amount,
        bytes32 paymentMethod,
        bytes32 fiatCurrency,
        uint256 conversionRate
    ) external returns (bytes32 intentHash) {
        Deposit storage deposit = _deposits[depositId];
        require(deposit.amount >= amount, "Insufficient deposit");
        require(amount >= deposit.intentAmountRange.min, "Below min amount");
        require(amount <= deposit.intentAmountRange.max, "Above max amount");

        // Generate intent hash (simplified for testing)
        intentHash = keccak256(abi.encodePacked(
            depositId,
            msg.sender,
            taker,
            amount,
            block.timestamp
        ));

        _intents[intentHash] = Intent({
            owner: msg.sender,
            to: taker,
            escrow: address(this),
            depositId: depositId,
            amount: amount,
            timestamp: block.timestamp,
            paymentMethod: paymentMethod,
            fiatCurrency: fiatCurrency,
            conversionRate: conversionRate,
            payeeDetails: bytes32(0),
            referrer: address(0),
            referrerFee: 0,
            postIntentHook: address(0),
            data: ""
        });

        _accountIntents[msg.sender].push(intentHash);

        emit IntentSignaled(
            intentHash,
            address(this),
            depositId,
            paymentMethod,
            msg.sender,
            taker,
            amount,
            fiatCurrency,
            conversionRate,
            block.timestamp
        );

        return intentHash;
    }

    /// @notice Simulate a taker fulfilling intent (after payment proof verified)
    /// @dev In real zk-p2p, this requires a valid payment proof
    /// @param intentHash The intent to fulfill
    function fulfillIntent(bytes32 intentHash) external {
        Intent storage intent = _intents[intentHash];
        require(intent.owner != address(0), "Intent not found");
        require(intent.owner == msg.sender, "Not intent owner");

        Deposit storage deposit = _deposits[intent.depositId];
        require(deposit.amount >= intent.amount, "Insufficient deposit");

        // Transfer USDC from deposit to taker
        deposit.amount -= intent.amount;
        bool success = token.transfer(intent.to, intent.amount);
        require(success, "Transfer failed");

        emit IntentFulfilled(
            intentHash,
            intent.to,
            intent.amount,
            false // not manual release
        );
    }

    /// @notice Get intent details
    function getIntent(bytes32 intentHash) external view returns (Intent memory) {
        return _intents[intentHash];
    }

    /// @notice Get all intents for an account
    function getAccountIntents(address account) external view returns (bytes32[] memory) {
        return _accountIntents[account];
    }
}

/// @title DeployLocalEnhanced
/// @notice Deployment script for enhanced local testing with Orchestrator mock
/// @dev Run with: forge script script/DeployLocalEnhanced.s.sol:DeployLocalEnhanced --rpc-url http://localhost:8545 --broadcast
contract DeployLocalEnhanced is Script {
    // Anvil's default private key (account[0])
    uint256 constant ANVIL_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run() external returns (address usdc, address escrow, address glue) {
        vm.startBroadcast(ANVIL_PRIVATE_KEY);

        // Deploy MockUSDC
        MockUSDC mockUsdc = new MockUSDC();
        console.log("MockUSDC deployed at:", address(mockUsdc));

        // Deploy MockEscrowWithOrchestrator (combined escrow + orchestrator)
        MockEscrowWithOrchestrator mockEscrow = new MockEscrowWithOrchestrator(address(mockUsdc));
        console.log("MockEscrowWithOrchestrator deployed at:", address(mockEscrow));

        // Deploy OfframpGlue
        OfframpGlue offrampGlue = new OfframpGlue(address(mockUsdc), address(mockEscrow));
        console.log("OfframpGlue deployed at:", address(offrampGlue));
        console.log("Owner:", offrampGlue.owner());
        console.log("Keeper:", offrampGlue.keeper());

        vm.stopBroadcast();

        return (address(mockUsdc), address(mockEscrow), address(offrampGlue));
    }
}
