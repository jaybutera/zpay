// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {OfframpGlue} from "../src/OfframpGlue.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {IEscrow} from "../src/interfaces/IEscrow.sol";

/// @notice Mock USDC for local testing - same as test mock
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

/// @notice Mock zk-p2p Escrow for local testing - same as test mock
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

/// @title DeployLocal
/// @notice Deployment script for local anvil testing with mocks
/// @dev Run with: forge script script/DeployLocal.s.sol:DeployLocal --rpc-url http://localhost:8545 --broadcast
contract DeployLocal is Script {
    // Anvil's default private key (account[0])
    uint256 constant ANVIL_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run() external returns (address usdc, address escrow, address glue) {
        vm.startBroadcast(ANVIL_PRIVATE_KEY);

        // Deploy MockUSDC
        MockUSDC mockUsdc = new MockUSDC();
        console.log("MockUSDC deployed at:", address(mockUsdc));

        // Deploy MockEscrow
        MockEscrow mockEscrow = new MockEscrow(address(mockUsdc));
        console.log("MockEscrow deployed at:", address(mockEscrow));

        // Deploy OfframpGlue
        OfframpGlue offrampGlue = new OfframpGlue(address(mockUsdc), address(mockEscrow));
        console.log("OfframpGlue deployed at:", address(offrampGlue));
        console.log("Owner:", offrampGlue.owner());
        console.log("Keeper:", offrampGlue.keeper());

        vm.stopBroadcast();

        return (address(mockUsdc), address(mockEscrow), address(offrampGlue));
    }
}

/// @title MintUsdc
/// @notice Helper script to mint USDC to an address
/// @dev Run with: forge script script/DeployLocal.s.sol:MintUsdc --sig "run(address,address,uint256)" <usdc> <to> <amount> --rpc-url http://localhost:8545 --broadcast
contract MintUsdc is Script {
    uint256 constant ANVIL_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run(address usdc, address to, uint256 amount) external {
        vm.startBroadcast(ANVIL_PRIVATE_KEY);
        MockUSDC(usdc).mint(to, amount);
        console.log("Minted", amount, "USDC to", to);
        vm.stopBroadcast();
    }
}
