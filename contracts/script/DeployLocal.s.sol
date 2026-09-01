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

/// @title DeployLocal
/// @notice Deployment script for local anvil testing with mocks
/// @dev Run with: forge script script/DeployLocal.s.sol:DeployLocal --rpc-url http://localhost:8545 --broadcast
contract DeployLocal is Script {
    // Anvil's default private key (account[0]): the deployer, and so the owner.
    uint256 constant ANVIL_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    // Anvil account[2]. The keeper is a separate address on purpose.
    //
    // It used to be account[0], the same key the tests signed the user's rescue
    // with, which meant every "the user recovers their funds" test was really
    // the keeper recovering them. That is what hid HIGH-1 in the 2026-08-31
    // audit: on mainnet the keeper is not the user and both calls reverted.
    // Three distinct roles here, so a test that conflates them fails.
    address constant LOCAL_KEEPER = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;

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

        // Separate the keeper from the owner and from the user.
        offrampGlue.setKeeper(LOCAL_KEEPER);

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
