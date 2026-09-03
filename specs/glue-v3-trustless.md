# Glue v3: the coordinator relays, and nothing it relays can be stolen

Status: design, 2026-09-02. Nothing here is built. This document covers the
1Click-to-zk-p2p route only. The native Zcash escrow in
`specs/zec-native-escrow.md` is a separate backend and is not changed by it.

The goal, in Casper's words: the coordinator "is simply relaying the glue" and
"the worst that can happen is funds are stuck until someone permissionlessly
moves them along." This spec is the contract, the client rules, and the
operator role that make that sentence true, plus a plain statement of what
still has to be trusted afterwards.

## 1. What the v2 keeper can do today

The live glue is `0x617544CC688F7f742cA68B5d9106890500b6C689`, deployed
2026-09-02. Its keeper is the coordinator's hot key. Three of its powers are
theft paths and one is a missing check.

| # | Power | Where | Why it is theft |
|---|---|---|---|
| T1 | The coordinator chooses the 1Click `recipient` and `refundTo` at quote time | `crates/zecp2p-coordinator/src/state.rs:190` | The user sees a ZEC deposit address and nothing else. A quote whose recipient is the coordinator's own wallet, or whose refund address is the coordinator's, looks identical to an honest one |
| T2 | USDC arrives at the glue with no on-chain session attribution; the keeper credits at will | `contracts/src/OfframpGlue.sol:153` (`createSession` has no `user != keeper` check), `:189` (`creditSession`), `:351` (`rescue` pays `session.user`); audit finding A3-8 | A keeper can create a session naming itself, credit a real user's uncredited arrival to it, and rescue to itself. The window is one poll interval |
| T3 | The keeper fixes `payeeDetailsHash` at creation | `state.rs:163`, `:218` | The `PayeeDetailsMismatch` check at `OfframpGlue.sol:285` guards a change after creation. It does nothing about a wrong hash at creation, and the user never sees the hash |
| M1 | `minConversionRate` is stored and never read | `OfframpGlue.sol:23` | `processOfframp` takes `currencies` from the keeper's calldata. A keeper can list the user's USDC at a rate of one wei of USD per USDC and a colluding taker pays nothing for it |

Everything else the keeper does (`processOfframp` timing, `rescue`,
`withdrawFromZkp2p`) is bounded: payouts go to `session.user` for that
session's own credit. Those are liveness powers and stay liveness powers.

## 2. The idea: the deposit address is the commitment

An ERC-20 transfer carries no session id. v2 works around that by having the
keeper say whose money arrived. v3 removes the question instead.

Every session gets its own receiving address on Base, derived by CREATE2 from
the glue's address and the session's terms. 1Click delivers USDC to that
address. Anyone can then call the glue to pull the balance out of the receiver
and credit it to the one session the address belongs to. There is nothing to
attribute because the address already did it.

The session id is the hash of the terms, and the terms are chosen by the
sender: their own payee hash, their own floor rate, their own return key. So
the receiver address commits to the terms, and the sender can check, before
sending a single zatoshi, that the 1Click quote pays exactly that address. If
it does, the only place the USDC can go is into a zk-p2p deposit paying the
sender's Venmo account at or above the sender's rate, or back to the sender's
own key. If it does not, the sender sends nothing.

The contract has no owner and no keeper. Every function is callable by anyone,
and the only power a caller has is to pay gas for the next step.

## 3. Terms, session id, receiver address

### 3.1 Terms

```solidity
struct Terms {
    address user;               // return key: rescue and withdraw pay here; may sign early unwinds
    bytes32 payeeDetailsHash;   // zk-p2p curator hashedOnchainId for the recipient's Venmo account
    uint256 minConversionRate;  // floor on every Currency the deposit lists, 18 decimals, USD per USDC
    uint256 minCredit;          // least USDC that may be listed; below it the session can only be rescued
    uint256 intentMin;          // per-intent floor, 0 = the whole credit
    uint256 intentMax;          // per-intent cap, 0 = the whole credit
    bytes32 depositTermsHash;   // keccak256(abi.encode(paymentMethods, paymentMethodData, currencies))
    uint64  unwindAfter;        // unix time after which anyone may rescue or withdraw to `user`
    bytes32 salt;               // client randomness so identical terms make distinct sessions
}
```

Every field is chosen by the sender's client. Nothing in it comes from the
coordinator. `depositTermsHash` covers the full zk-p2p deposit parameters,
which pins the payee, the gating service, the currency list and every rate in
it; `payeeDetailsHash` and `minConversionRate` are repeated as scalars so the
contract enforces them in code that an auditor can read, and so events carry
them.

### 3.2 Session id

```
sessionId = keccak256(abi.encode(TERMS_TAG, terms))
TERMS_TAG = keccak256("zpay.OfframpGlueV3.Terms.v1")
```

The tag keeps a v3 id from colliding with any other hash of the same struct.
The id is a pure function of the terms, so `createSession` cannot be given a
different id for the same terms or the same id for different terms.

### 3.3 Receiver address

```
receiver = address(uint160(uint256(keccak256(abi.encodePacked(
    hex"ff", glue, sessionId, RECEIVER_INITCODE_HASH)))))
```

`RECEIVER_INITCODE_HASH` is a public constant on the glue. The receiver's init
code takes no constructor arguments (it reads the glue as `msg.sender`), so
the hash is one value for every session and the client can pin it at build
time alongside the glue address. A client computes `receiver` locally from
those two constants and its own terms. It does not need an RPC to know where
its money should go, and an RPC that lies about `receiverFor` is caught by the
mismatch.

Only the glue can deploy code at that address, because CREATE2 addresses
include the deployer. USDC sent there before deployment sits at a codeless
address like any EOA balance and is collected on the first `sweep`.

## 4. Contract interface

Interface sketches only. Struct layouts for `IEscrow` are the existing ones in
`contracts/src/interfaces/IEscrow.sol` and are unchanged.

### 4.1 The receiver

```solidity
/// One per session, deployed by the glue on first sweep. Holds nothing it can
/// spend: the only function moves the whole USDC balance to the glue, and only
/// the glue may call it.
contract SessionReceiver {
    address public immutable glue;
    constructor() { glue = msg.sender; }
    function flush(address token) external returns (uint256 moved);  // onlyGlue
}
```

### 4.2 The glue

```solidity
interface IOfframpGlueV3 {
    // ---- constants and views ----
    function usdc() external view returns (address);            // immutable
    function zkp2pEscrow() external view returns (address);     // immutable
    function RECEIVER_INITCODE_HASH() external view returns (bytes32);
    function sessionIdFor(Terms calldata terms) external pure returns (bytes32);
    function receiverFor(bytes32 sessionId) external view returns (address);
    function getSession(bytes32 sessionId) external view returns (Session memory);
    function totalCommitted() external view returns (uint256);

    // ---- lifecycle, all callable by anyone ----
    function createSession(Terms calldata terms) external returns (bytes32 sessionId);
    function sweep(bytes32 sessionId) external returns (uint256 credited);
    function advance(
        bytes32 sessionId,
        bytes32[] calldata paymentMethods,
        IEscrow.DepositPaymentMethodData[] calldata paymentMethodData,
        IEscrow.Currency[][] calldata currencies
    ) external returns (uint256 depositId);

    // ---- unwinds: the user any time, anyone after unwindAfter ----
    function rescue(bytes32 sessionId) external;
    function withdraw(bytes32 sessionId) external;
    function rescueWithSig(bytes32 sessionId, uint256 validUntil, bytes calldata sig) external;
    function withdrawWithSig(bytes32 sessionId, uint256 validUntil, bytes calldata sig) external;
}

struct Session {
    Terms    terms;
    uint8    state;        // 0 None, 1 Open, 2 Listed
    uint256  credited;     // USDC this session owns on the glue and may spend
    uint256  deposited;    // USDC placed into the zk-p2p deposit
    uint256  returned;     // USDC withdrawn from that deposit and paid to user so far
    uint256  depositId;    // meaningful once Listed
}
```

No owner. No keeper. No setter. No pause. Constructor takes `usdc` and
`zkp2pEscrow` and nothing else. Any USDC transferred straight to the glue,
rather than to a receiver, is unreachable by everyone including the deployer;
section 9 says why that is the right trade.

### 4.3 Function by function

**`createSession(terms)`.** Computes the id, reverts if it exists, requires
`terms.user != 0`, `terms.minCredit > 0`, `terms.unwindAfter > block.timestamp`,
and a range that `advance` can satisfy: if `intentMax != 0` then
`minCredit >= intentMax`, and if both are non-zero then `intentMin <=
intentMax`. Without the first of those a client could pin an intent size above
its own floor and make `advance` unreachable for a fill between the two.
Stores the terms with state Open, emits `SessionCreated(sessionId, receiver,
user, payeeDetailsHash, minConversionRate, minCredit, unwindAfter)`. The caller has
no other input. Because the id is the hash of the terms, a caller who submits
different terms creates a different session whose receiver is a different
address; the sender's money is at the sender's receiver, and the sender's own
session can still be created afterwards by anyone who knows the terms. Funding
before creation is therefore safe, which is what makes the coordinator
optional rather than merely bounded.

**`sweep(sessionId)`.** Requires state Open or Listed. If the receiver has no
code, deploys it by CREATE2 with salt `sessionId`. Records the glue's USDC
balance, calls `receiver.flush(usdc)`, and credits the session with the
balance delta measured on the glue, not the amount the receiver reports.
`credited += delta`, `totalCommitted += delta`, emits `Swept(sessionId,
delta, credited)`. Callable repeatedly and in either state, so a second 1Click
transfer, an over-delivery, or a stray arrival after listing all end up as the
session's credit, where `rescue` can return them. There is no cap at an
expected amount: money at this receiver is this session's, whatever the
quote said.

**`advance(sessionId, paymentMethods, paymentMethodData, currencies)`.**
Sweeps first, then requires:

1. state Open and `block.timestamp < terms.unwindAfter`;
2. `credited >= terms.minCredit`;
3. `keccak256(abi.encode(paymentMethods, paymentMethodData, currencies)) == terms.depositTermsHash`;
4. `paymentMethods.length >= 1` and the three arrays equal in length;
5. every `paymentMethodData[i].payeeDetails == terms.payeeDetailsHash`;
6. every `currencies[i][j].minConversionRate >= terms.minConversionRate`, and
   every `currencies[i]` non-empty.

Checks 5 and 6 are implied by check 3 for a client that hashed what it meant.
They stay because they are the two properties this contract exists to
guarantee, and a reader should not have to trust a hash preimage they cannot
see to know they hold. The oracle floor in `Currency.oracleRateConfig` cannot
lower the rate: EscrowV2's `_getDepositCurrencyMinRate` takes the larger of
the fixed rate and the oracle spread rate, and a halted oracle returns zero,
which OrchestratorV3 rejects as `CurrencyNotSupported` rather than treating
as a floor of zero. An oracle config is therefore allowed and is pinned by the
hash like everything else.

Then: `amount = credited`; `min = intentMin == 0 ? amount : intentMin`; `max =
intentMax == 0 ? amount : intentMax`; require `min <= max && max <= amount`;
set `credited = 0`, `deposited = amount`, `totalCommitted -= amount`, state
Listed; approve and `createDeposit` with `token = usdc`, `delegate = 0`,
`intentGuardian = 0`, `retainOnEmpty = false`, hard-coded in the contract and
not taken from calldata; read `depositCounter` before and require it advanced
by one; emit `OfframpProcessed(sessionId, depositId, amount)` with the same
signature as v2 so the taker's scanner needs only a second address.

**`rescue(sessionId)`.** Sweeps, then pays `credited` to `terms.user` and
zeroes it. Allowed to `msg.sender == terms.user` at any time and in any state,
and to anyone once `block.timestamp >= terms.unwindAfter` or the state is
Listed. In state Open before `unwindAfter`, a third party may not rescue,
because that would let anyone cancel a live offramp and force the sender
through a back-swap. In state Listed the credit can only be a late arrival,
which `advance` will never touch, so returning it to the user is always the
right move and anyone may do it. Emits `SessionRescued(sessionId, user,
amount)`.

**`withdraw(sessionId)`.** Requires state Listed. Same caller rule as rescue:
the user any time, anyone after `unwindAfter`. A permissionless withdraw after
the deadline does not take anything from a taker mid-fill: `withdrawDeposit`
returns only unlocked funds, and a locked intent can still be fulfilled after
`acceptingIntents` is cleared. The fork test in section 10 should exercise
that order. Reads
`getDeposit(depositId).remainingDeposits`, caps at `deposited - returned`,
measures the glue's balance delta across `withdrawDeposit`, caps the delta at
that figure, pays it to `terms.user`, adds it to `returned`, emits
`SessionWithdrawn(sessionId, user, amount)`.

It is repeatable, and must be. EscrowV2's `withdrawDeposit` returns only
funds not locked by an open intent and sets `acceptingIntents = false`. When a
locked intent later expires and is pruned, `_reclaimLiquidityIfNecessary` adds
its amount back to `remainingDeposits` and leaves it in the escrow; nothing is
pushed to the depositor. A second `withdrawDeposit` collects it. So v3 drops
v2's `withdrawn` flag and lets the call run until the deposit is gone. Once
EscrowV2 has deleted the deposit, `withdrawDeposit` reverts with
`UnauthorizedCaller` because `depositor` reads as zero; the glue surfaces that
as `DepositClosed` and the session is finished.

Two EscrowV2 behaviours the sender should know. Funds locked by an intent are
not withdrawable until the taker fulfils, cancels, or the intent expires after
`intentExpirationPeriod()`, 21,600 seconds on the live escrow. And when a
deposit closes with `remainingDeposits` at or below `dustThreshold`, the
remainder goes to zk-p2p's `dustRecipient`, not back to the depositor.

**`rescueWithSig` and `withdrawWithSig`.** The same actions, authorised by an
EIP-712 signature from `terms.user` so a relayer with gas can run them before
`unwindAfter` on the user's behalf. Domain `{name: "OfframpGlueV3", version:
"1", chainId, verifyingContract}`; type `Unwind(bytes32 sessionId, uint8
action, uint256 validUntil)` with `action` 1 for rescue and 2 for withdraw. Require `block.timestamp <= validUntil` and the
recovered signer equal `terms.user`. The relayer chooses nothing: the payee is
`terms.user` and the amount is the session's. A replayed withdraw signature
inside its validity window repeats an action the user already asked for and
pays the user again from the user's own deposit, so no nonce is needed; a
replayed rescue finds `credited == 0` and reverts.

### 4.4 State machine

| State | Entered by | `sweep` | `advance` | `rescue` | `withdraw` |
|---|---|---|---|---|---|
| None | | reverts | reverts | reverts | reverts |
| Open | `createSession` | anyone | anyone, if `credited >= minCredit` and before `unwindAfter` | user; anyone after `unwindAfter` | reverts |
| Listed | `advance` | anyone | reverts | anyone (credit here is a late arrival) | user; anyone after `unwindAfter`; repeatable until the deposit is gone |

No `fulfilled` flag. Whether a taker paid is EscrowV2's and OrchestratorV3's
business; the status page reads `IntentFulfilled` from the orchestrator, as
the keeper does today.

### 4.5 Accounting invariants

- `usdc.balanceOf(glue) >= totalCommitted` always, where `totalCommitted` is
  the sum of every session's `credited`.
- Every debit from `credited` pays `terms.user` or funds a zk-p2p deposit
  whose payee is `terms.payeeDetailsHash`. There is no third destination.
- `deposited - returned` is the most `withdraw` can ever pay for a session, so
  a concurrent arrival in the same block cannot leak across sessions through
  the balance-delta measurement.
- Credit is only ever created by `sweep`, only from a receiver whose address
  was derived from the session being credited, and only by the glue's own
  balance delta. Nothing reads `balanceOf(glue)` to decide an amount.
- `nonReentrant` on `sweep`, `advance`, `rescue`, `withdraw` and both `WithSig`
  variants. Base USDC is a proxy; the latch is cheap insurance, as in v2.

## 5. Client-side verification rules

These rules are what turns the contract's properties into the sender's. They
live in the client, which means the CLI and the page. A client that skips one
reopens the corresponding v2 hole for that user.

**V1. The payee hash comes from the curator, never from the coordinator.** The
client calls `POST https://api.zkp2p.xyz/v2/makers/validate` and then
`/v2/makers/create` with `{"processorName": "venmo", "offchainId": <handle>}`
itself, over TLS to that host, and reads `hashedOnchainId`. Both calls answer
HTTP 200 whether the body is right or wrong, so the client keys on the body
(`"Maker data is valid"`, then a 32-byte hash), not the status code. The
coordinator may be told the handle for the taker listing in section 6; it is
never asked for the hash.

**V2. The client builds the terms and derives everything from them.** It
generates the session key (`terms.user`) locally, sets `minConversionRate`
and `intentMin`/`intentMax` from the user's requested payment, sets
`depositTermsHash` from the deposit parameters it intends (payment method
`venmo`, its own payee hash, the gating service it accepts or zero, USD at its
rate, oracle config off unless the user chose one), and picks `unwindAfter`.
It computes `sessionId` and `receiver` locally from the pinned glue address
and `RECEIVER_INITCODE_HASH`. If it also asks an RPC for `receiverFor`, the
answer must match or the client stops.

**V3. The 1Click quote is verified against 1Click, not against the
coordinator.** The client composes the quote request: `originAsset` ZEC,
`destinationAsset` the Base USDC id, `amount` the zatoshi it will send,
`recipient = receiver`, `recipientType DESTINATION_CHAIN`, `refundTo` a
transparent Zcash address the client controls (the session transparent
address of `docs/plans/ux-simplification.md` section 3.4, or the user's own),
`refundType ORIGIN_CHAIN`, `swapType EXACT_INPUT`, `depositMode SIMPLE`, and
the slippage and deadline it wants. The coordinator may relay this request, so a
JWT can be attached if the project ever holds one and the browser is not
rate-limited; today the coordinator sends the request unauthenticated and
1Click attaches its own 10 bps `appFees` entry. Whoever sent it, the
client then calls `GET https://1click.chaindefuser.com/v0/status?depositAddress=<D>`
directly and checks the echoed `quoteResponse`:

| Field | Must equal |
|---|---|
| `quoteRequest.recipient` | `receiver`, case-insensitive |
| `quoteRequest.recipientType` | `DESTINATION_CHAIN` |
| `quoteRequest.destinationAsset` | the pinned Base USDC asset id |
| `quoteRequest.originAsset` | the pinned ZEC asset id |
| `quoteRequest.amount` | the zatoshi the client will send |
| `quoteRequest.refundTo` | the client's own transparent address |
| `quoteRequest.refundType` | `ORIGIN_CHAIN` |
| `quoteRequest.swapType`, `depositMode` | `EXACT_INPUT`, `SIMPLE` |
| `quoteRequest.virtualChainRecipient`, `virtualChainRefundRecipient` | null |
| `quoteRequest.appFees` | the single 10 bps entry 1Click attaches on its own, or a list the client was built to accept; nothing else |
| `quote.depositAddress` | `D`, the address about to be shown |
| `quote.deadline` | later than now by the client's minimum margin |
| `quote.minAmountOut` | at least `terms.minCredit` |

Only after every row passes does the client display `D` as the address to
send ZEC to. The status endpoint is 1Click's own statement about its own
deposit address; a coordinator that forged a quote would have to defeat the
client's TLS connection to 1Click to pass this check. The 2026-08-31 live
fixture in `crates/zecp2p-coordinator/tests/fixtures/1click_status_success.json`
shows every one of these fields present in the response.

**V4. `minCredit` is the floor the user accepts, and the contract holds it.**
The client sets `terms.minCredit` at or below `quote.minAmountOut`. If 1Click
delivers less, `advance` refuses, the session can only be rescued, and the
USDC goes back to the session key for the back-swap. 1Click's floor is a
promise; `minCredit` is the enforcement.

**V5. The client reads outcomes from the chain, not from the coordinator.**
Receiver balance, `Swept`, `OfframpProcessed`, `IntentSignaled`,
`IntentFulfilled`, `SessionRescued`, `SessionWithdrawn`: all from the client's
own RPC. The coordinator's status API is a convenience view. A lying RPC can
delay the user's knowledge; it cannot move funds, because nothing the client
signs depends on what it reads after funding. The one read that matters
before funding is the receiver address, and rule V2 computes it locally.

**V6. If the coordinator is gone, the client says exactly what to do.**
Anyone with a funded Base account can call `createSession(terms)`,
`sweep(sessionId)`, `advance(sessionId, ...)` with the deposit parameters the
client committed, and after `unwindAfter`, `rescue` or `withdraw`. The client
stores the terms and the deposit parameters with the session (they are the
preimages of two hashes on chain) and can print them as `cast send` commands.
This is the "someone permissionlessly moves them along" clause, and it holds
for a stranger with no relationship to the sender.

**V7. Relayed unwinds are signed for one session and one action.** When the
page wants an early rescue or withdraw without gas, it signs the
`Unwind` struct from 4.3 with a `validUntil` of a few minutes and hands it to
the coordinator. The coordinator can delay it or drop it; it cannot redirect
it.

## 6. What the coordinator still does

The coordinator remains and remains useful. It just stops being trusted.

| Job | How | Power it carries |
|---|---|---|
| Quote relay | Forwards the client's 1Click quote request, returns the response | None: the client verifies against 1Click (V3) |
| Gas | Calls `createSession`, `sweep`, `advance` when the client's session is funded | Liveness only: anyone else can call the same functions with the same effect |
| Unwind relay | Broadcasts `rescueWithSig` / `withdrawWithSig`, and after `unwindAfter` the plain forms | Liveness only |
| Back-swap relay | Broadcasts the session key's EIP-3009 `transferWithAuthorization` to a 1Click deposit address for the USDC-to-ZEC return leg, per `docs/plans/ux-simplification.md` 4.2 | None: the authorization names the destination |
| Taker listing | `GET /deposits/open` with `depositId`, `venmoUsername`, amount, for takers to cross-check against the on-chain payee hash via the curator | Advisory; the taker verifies |
| Matching | If the sender's `depositTermsHash` names the coordinator as `intentGatingService`, signs `signalIntent` for the taker it picks; otherwise nothing | Can refuse to sign (liveness); cannot change the payee or the rate, both of which are in the deposit |
| Status and stats | Aggregates chain events for the page and the public read API | None over funds |

The disposition of every v2 keeper power:

| v2 power | v3 disposition |
|---|---|
| Choose 1Click recipient and refundTo (T1) | Sender-verifiable before funds move (V3). The coordinator can still propose; it cannot decide |
| Attribute arrivals, `creditSession` (T2) | Removed. Attribution is the receiver address; `sweep` is permissionless and mechanical |
| `createSession` naming any user (T2, A3-8) | Removed as a power. Anyone may create any session, and creating one gives the creator nothing |
| Fix the payee hash (T3) | Removed. The sender commits it (V1, V2); the contract enforces it |
| Choose `currencies` and the rate at `processOfframp` (M1) | Removed. Pinned by `depositTermsHash`; floor enforced in code |
| Choose the intent range | Removed. Pinned in terms |
| Choose `delegate`, `intentGuardian`, `retainOnEmpty`, `token` | Removed. Hard-coded |
| Time `processOfframp` | Liveness. Anyone may `advance` |
| `rescue` / `withdrawFromZkp2p` for a user | Liveness. User any time by signature, anyone after `unwindAfter`; payee is always `terms.user` |
| `setKeeper` | Gone. There is no keeper |
| Sweep uncredited USDC (A3-8) | Gone. There is no uncredited USDC that a session can claim; a direct transfer to the glue belongs to nobody |

## 7. Sequence

```
Client                          Coordinator            1Click            Glue v3              EscrowV2
  |-- validate, create handle -------------------------> curator (api.zkp2p.xyz)
  |<-------------------------------------------------- hashedOnchainId
  | build Terms, sessionId, receiver locally
  |-- quote request (recipient = receiver) -> |-- relay ---> |
  |<--------------------------------------- |<-- quote ---- |
  |-- GET /v0/status?depositAddress=D ----------------> |
  |<---------------------- quoteResponse (checked, V3) |
  | show D; user sends ZEC
  |                                          |            |-- USDC transfer --> receiver
  |                                          |-- createSession(terms) ---------> |
  |                                          |-- sweep(sessionId) ------------> | flush, credit
  |                                          |-- advance(sessionId, params) --> |-- createDeposit --> |
  | read OfframpProcessed via own RPC
  |                                                      taker signals, pays Venmo, proves; USDC to taker
  | read IntentFulfilled via own RPC
```

Failure branches: 1Click refunds ZEC to `refundTo` (the client's own address);
or `advance` refuses because `credited < minCredit` and the user rescues; or
nobody fills and, after `unwindAfter`, anyone withdraws to the session key;
then the back-swap of `docs/plans/ux-simplification.md` turns USDC at the
session key into ZEC.

## 8. Residual trust surface

What the sender still trusts after v3, stated so a reviewer can check the list
rather than infer it.

**1Click.** Holds the ZEC from deposit until it delivers USDC, and on the
return leg holds USDC until it delivers ZEC. Its refund goes only to a
transparent Zcash address. Its `minAmountOut` is a promise; the on-chain
recourse for a short fill is `minCredit`, which stops the listing but does not
recover the shortfall. A 1Click that delivered to an address other than the
quoted recipient would be stealing from every user it has, and nothing here
changes that. The client's verification also trusts that
`1click.chaindefuser.com` answers `/v0/status` honestly about its own quotes.

**zk-p2p.** The Nitro enclave whose server half is unpublished attests Venmo
payments; `AttestationVerifier` checks that signature against an
owner-settable witness list; the curator issues the payee hash and can, in
principle, issue one that maps the sender's handle to a different Venmo
account. EscrowV2's owner sets `dustThreshold` and `dustRecipient`, so a
deposit at or below the threshold when it closes is zk-p2p's. All of this is
unchanged from v2 and from any depositor on their escrow. Enclave and curator
are the same two parties named as residual in the native escrow spec.

**The taker.** Can signal an intent and let it expire, locking that portion
of the deposit for up to six hours. Cannot receive USDC without the enclave
attesting a payment to the committed payee.

**A gating service, if the sender names one.** Can decline to sign, which
stalls fills until the sender withdraws. Cannot change who is paid or how
much per USDC.

**The session key.** Held by the client, in a link and in browser storage on
the page. Losing it after a return has landed loses that return. Nothing sits
at it on the happy path.

**The client itself.** The page is served by the operator. A hostile build
could skip V1 to V4 and reintroduce T1 and T3 for users of that build. The
contract cannot protect a user from their own client. Mitigations are
reproducible builds, a published hash of the served bundle, and the CLI as an
independent implementation of the same rules. This is the largest remaining
trust in the operator and the honest answer to "is the coordinator fully
untrusted": the coordinator is; the operator who also serves the page is not.

**Base, the RPC, and TLS.** Reads through the client's RPC can be delayed or
false; funds do not move on reads. Chain liveness and finality are assumed.

## 9. Design choices worth defending

**No privileged sweep of unattributed USDC.** A transfer straight to the glue
is lost. An owner sweep would recover honest mistakes and would also be a key
that can take money, so it is the one thing this design refuses. The client
never presents the glue address as a destination; 1Click quotes are verified
to name a receiver; the receivers are the only place USDC is meant to land.

**Credit is not capped at the quote.** v2 caps `creditSession` at
`expectedAmount` because the keeper might attribute wrongly. With attribution
by address there is no wrong attribution to bound, and an over-delivery is
the sender's money.

**Anyone may create any session.** It costs the creator gas and gives them
nothing. Refusing it would need a signature from the session key, which
means the user must sign before funding, which means the coordinator could
withhold service by refusing to relay. Free creation keeps the coordinator
optional.

**Early unwinds are the user's alone.** A permissionless `rescue` on an Open
session before `unwindAfter` would let anyone cancel anyone's offramp for the
price of gas. The deadline is the sender's own choice of how long to wait.

**`OfframpProcessed` keeps its v2 signature.** The taker agent's scanner is
the one consumer of glue events outside this repo's coordinator; it adds an
address, not a decoder.

## 10. Deployment and migration

Nothing valuable sits in v2 for long. A v2 session lives for hours: USDC
arrives, is listed within a poll interval, and is either filled, rescued, or
withdrawn. At rest the v2 glue holds zero USDC. Migration is therefore a
cutover, not a data migration.

1. Build v3, run the Foundry suite plus a Base fork test that drives the real
   EscrowV2 through `advance` and two `withdraw` calls (the second after an
   intent expires), and verify the receiver's CREATE2 address against a
   client-side computation.
2. Deploy v3 with `(usdc, zkp2pEscrow)` from the deployer key. There is no
   `setKeeper` step because there is no keeper; the deployer holds nothing
   afterwards. Verify source on Basescan so `RECEIVER_INITCODE_HASH` and the
   bytecode are public.
3. Pin the v3 address and `RECEIVER_INITCODE_HASH` in the client (CLI and
   page), the coordinator config, and the taker config as a second glue to
   scan.
4. Stop opening v2 sessions. Let the in-flight ones finish. Rescue or withdraw
   any that will not. `withdrawFromZkp2p` on a v2 deposit must go through the
   v2 glue forever, because EscrowV2 lets only the depositor withdraw; v2 is
   immutable and stays callable, which is all that requires.
5. Once v2 holds no credit and has no open deposit, the v2 owner may
   `setKeeper` to a burn address. That is the only administrative act left
   and it removes a power rather than exercising one.
6. First mainnet run at the $1 size used for the native escrow test, with
   one deliberate deviation: turn the coordinator off between the USDC
   arrival and `advance`, and have a different funded key call `createSession`,
   `sweep` and `advance` from the client's printed commands. The property
   this design claims is that this works; the test should show it.

Coordinator changes: drop `creditSession`; replace `create_session` with
`createSession(terms)` submitted from the client's terms; replace the
1Click-status-driven `credit_decision` with a receiver-balance watch that
calls `sweep`; `process_offramp` becomes `advance` with the client's committed
parameters; `rescue` and `withdraw` become relays of signed unwinds before
`unwindAfter` and plain calls after. The single-session gate in
`refuse_if_a_session_is_in_flight` exists to protect against wrong
attribution and can go.

## 11. Open questions

1. **CORS on 1Click.** V3 needs the browser to call `/v0/status` directly.
   The repo has only ever called it from Rust. If 1Click does not send CORS
   headers, the page cannot do V3 without a proxy, and a proxy run by the
   operator is the trust being removed. Fallbacks in order: check whether
   1Click publishes the ed25519 key behind `quoteResponse.signature` so the
   page can verify a relayed quote offline; ask them for CORS; or require the
   CLI for the trustless path and say so on the page.
2. **1Click delivery mechanics to a codeless recipient.** It delivered to the
   v2 glue, a contract, by plain transfer. Confirm on the $1 test that it
   delivers to an address with no code by plain transfer as well, and that it
   never uses a call that would need the receiver deployed first.
3. **Curator hash stability.** Whether `/v2/makers/create` returns the same
   `hashedOnchainId` for the same handle on every call. If it can differ, the
   client must use the hash from its own call, and the taker's cross-check
   must tolerate multiple valid hashes for one handle.
4. **Default `unwindAfter`.** 1Click's deposit address lives about three days
   and an intent lock is six hours. A default around four days is the obvious
   shape; the number should come from the first runs.
5. **Gas for the permissionless path.** `sweep` deploys a receiver on first
   call and `advance` runs `createDeposit`, so a stranger moving a stuck
   session along pays a few hundred thousand gas on Base. Whether to publish
   a public "poke" that anyone can run, or to leave it to the printed
   commands, is a product question.
6. **Non-USDC tokens at a receiver.** `flush` moves only the token the glue
   names. Anything else sent to a receiver is stuck. A `flushOther(token)`
   that pays `terms.user` is cheap to add and adds no power; decide whether
   the case is worth the surface.
7. **`delegate` for the user.** EscrowV2 lets a delegate manage a deposit
   (rate updates, closing). Setting it to `terms.user` would let the session
   key act on the deposit directly through EscrowV2. Left at zero here because
   the delegate's full power set has not been read; worth reading.
8. **The oracle rate config.** Allowed and hash-pinned. Whether the client
   should ever build terms with one, given that a halted oracle stalls fills,
   is a client policy question, not a contract one.
9. **Sender-side proof of the contract.** V2 pins the glue address and
   initcode hash in the client build. Whether the page should also fetch the
   glue's code hash over its RPC and compare it to a pinned value, so a wrong
   pinned address is caught before funding, is a small addition worth making.
