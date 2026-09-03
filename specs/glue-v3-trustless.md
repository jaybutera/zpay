# Glue v3: the coordinator relays, and nothing it relays can be stolen

Status: design, 2026-09-02, revised the same day after review round 1
(`docs/status/glue-v3-review-1.md`). Nothing here is built. This document
covers the 1Click-to-zk-p2p route only. The native Zcash escrow in
`specs/zec-native-escrow.md` is a separate backend and is not changed by it.

The goal, in Casper's words: the coordinator "is simply relaying the glue" and
"the worst that can happen is funds are stuck until someone permissionlessly
moves them along." This spec is the contract, the client rules, and the
operator role that make that sentence true, plus a plain statement of what
still has to be trusted afterwards.

Round 1 found no theft path and three states with no mover. All three came
from the same habit: a check or a cap that was correct for v2, where the
keeper could always clean up, and is a trap in v3, where nobody can. The
revision removes every such check from the path a funded receiver takes to
its user, and puts the two hash preimages a stranger needs on chain at
creation. The review's should-fixes and its three empirical answers are
folded in where they belong.

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

Two rules follow from "no keeper" and are the shape of this revision. First,
once a receiver holds USDC, no check in the contract may stand between that
USDC and `terms.user`; a check that would have been a revert in v2 has to be
a downgrade to rescue in v3. Second, everything a stranger needs to finish a
session has to be readable from the chain, because the client that built the
session may be gone.

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

The three arrays behind `depositTermsHash` are called the deposit parameters
below. They are the second preimage a stranger needs, and section 4.3 puts
them on chain at creation.

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
address like any EOA balance and is collected on the first `sweep`. 1Click
delivers by a plain ERC-20 `transfer` from an EOA: the 2026-09-02 mainnet run
paid the v2 glue in Base transaction
`0xce436d96ed1f2b2327659e736d1c16bc66a1269e67d13065c15c159cd2661349` (block
50792687) from `0x248e379a0d40e79bfcbf62d37423c4d43400a99e`, an address with
no code, calling USDC `transfer(address,uint256)` with 68 bytes of calldata
and one `Transfer` log. Nothing on that path inspects the recipient, so a
codeless receiver is paid the same way the glue was.

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
    function createSession(
        Terms calldata terms,
        bytes32[] calldata paymentMethods,
        IEscrow.DepositPaymentMethodData[] calldata paymentMethodData,
        IEscrow.Currency[][] calldata currencies
    ) external returns (bytes32 sessionId);
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

event SessionCreated(
    bytes32 indexed sessionId,
    address indexed receiver,
    Terms terms,
    bytes32[] paymentMethods,
    IEscrow.DepositPaymentMethodData[] paymentMethodData,
    IEscrow.Currency[][] currencies
);
```

No owner. No keeper. No setter. No pause. Constructor takes `usdc` and
`zkp2pEscrow` and nothing else. Any USDC transferred straight to the glue,
rather than to a receiver, is unreachable by everyone including the deployer;
section 9 says why that is the right trade.

`SessionCreated` carries the whole `Terms` struct and the whole deposit
parameter triple, not a digest of them. That is the durable copy. Calldata
and event data on Base are public and permanent, and they are the cheapest
store this design has for the two preimages that everything after funding
depends on.

### 4.3 Function by function

**`createSession(terms, paymentMethods, paymentMethodData, currencies)`.**
Computes the id, reverts if it exists, and requires exactly one thing of the
terms: `terms.user != 0`, because a zero return key is the one field whose
absence makes rescue impossible. It does not check `unwindAfter` against the
clock, `minCredit` against zero, or the intent range against anything. Round
1 showed why: the receiver address is bound to the exact terms, so any check
here that a client can fail turns a funded receiver into a permanent loss.
A session whose `unwindAfter` has already passed is created and is rescuable
by anyone at once, which is the right outcome. A session with an impossible
intent range is created and `advance` refuses it, which downgrades it to
rescue, which pays the user.

If `paymentMethods.length > 0`, the call requires
`keccak256(abi.encode(paymentMethods, paymentMethodData, currencies)) ==
terms.depositTermsHash` and emits the triple. If the arrays are empty the
check is skipped, the emitted arrays are empty, and the session is created
anyway: creation must never be the step that strands a funded receiver, and a
session whose deposit parameters are unknown is still rescuable. The hash
check on a non-empty triple matters because anyone may create: without it a
creator could publish a wrong triple under a right session, and the event
would be worthless as a record. With it, whatever `SessionCreated` carries in
those arrays is the preimage.

Stores the terms with state Open and emits `SessionCreated(sessionId,
receiver, terms, paymentMethods, paymentMethodData, currencies)`. The caller
has no other input. Because the id is the hash of the terms, a caller who
submits different terms creates a different session whose receiver is a
different address; the sender's money is at the sender's receiver, and the
sender's own session can still be created afterwards by anyone who knows the
terms. The client creates before it shows the deposit address (rule V3), so
under an honest client no receiver is ever funded without its terms and
deposit parameters already on chain. Funding before creation remains safe as
a fallback rather than a plan: nothing in `createSession` can refuse a funded
receiver its session.

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
Sweeps first, strictly (a reverting `flush` stops the listing), then requires:

1. state Open and `block.timestamp < terms.unwindAfter`;
2. `credited > 0` and `credited >= terms.minCredit`;
3. `keccak256(abi.encode(paymentMethods, paymentMethodData, currencies)) == terms.depositTermsHash`;
4. `paymentMethods.length >= 1` and the three arrays equal in length;
5. every `paymentMethodData[i].payeeDetails == terms.payeeDetailsHash`;
6. every `currencies[i][j].minConversionRate >= terms.minConversionRate`, and
   every `currencies[i]` non-empty;
7. every `currencies[i][j].code == keccak256("USD")`, because
   `minConversionRate` is denominated in USD per USDC and a floor in another
   currency is not the floor the sender set.

Checks 5 to 7 are implied by check 3 for a client that hashed what it meant.
They stay because they are the properties this contract exists to guarantee,
and a reader should not have to trust a hash preimage they cannot see to know
they hold. The oracle floor in `Currency.oracleRateConfig` cannot lower the
rate: EscrowV2's `_getDepositCurrencyMinRate` takes the larger of the fixed
rate and the oracle spread rate, and a halted oracle returns zero, which
OrchestratorV3 rejects as `CurrencyNotSupported` rather than treating as a
floor of zero. An oracle config is therefore allowed and is pinned by the hash
like everything else.

Then: `amount = credited`; `min = intentMin == 0 ? amount : intentMin`; `max =
intentMax == 0 ? amount : intentMax`; require `min <= max && max <= amount`.
This is where the range is checked, and only here; a range that cannot be
satisfied makes `advance` revert and leaves the session rescuable. Then set
`credited = 0`, `deposited = amount`, `totalCommitted -= amount`, state
Listed; approve and `createDeposit` with `token = usdc`, `delegate = 0`,
`intentGuardian = 0`, `retainOnEmpty = false`, hard-coded in the contract and
not taken from calldata; read `depositCounter` before and require it advanced
by one; emit `OfframpProcessed(sessionId, depositId, amount)` with the same
signature as v2 so the taker's scanner needs only a second address.

`delegate` is zero on purpose and is not a field of `Terms`. EscrowV2's
delegate can call `setCurrencyMinRate` with any value including zero, plus
`setIntentRange`, `setRateManager` (a manager fee of up to 5% of each
release), `setAcceptingIntents`, and the currency and payment method setters.
A delegate can therefore remove the rate floor, which is the one property
check 6 exists to hold. Naming `terms.user` as delegate would hand that
power to whoever holds the session key, and the session key sits in a URL
fragment and browser storage. So no address gets it.

**`rescue(sessionId)`.** Pays the session's credit to `terms.user`, and
collects the receiver on the way if it can. Order: first pay `credited` to
`terms.user` and zero it; then attempt the sweep inside a `try` on
`receiver.flush`; if it succeeds, pay the delta to `terms.user` in the same
call; if it reverts, emit `SweepFailed(sessionId)` and finish anyway. The
`try` is the fix for round 1's R4: Base USDC is Circle's FiatToken, whose
`transfer` reverts when either party is blacklisted or the token is paused,
and a `rescue` that required the sweep would let a blacklisted receiver lock
credit that had already reached the glue. A paused token stops the payout
too and nothing here can help that; a blacklisted receiver must not.

Allowed to `msg.sender == terms.user` at any time and in any state, and to
anyone once `block.timestamp >= terms.unwindAfter` or the state is Listed. In
state Open before `unwindAfter`, a third party may not rescue, because that
would let anyone cancel a live offramp and force the sender through a
back-swap. In state Listed the credit can only be a late arrival, which
`advance` will never touch, so returning it to the user is always the right
move and anyone may do it. Emits `SessionRescued(sessionId, user, amount)`.

**`withdraw(sessionId)`.** Requires state Listed. Same caller rule as rescue:
the user any time, anyone after `unwindAfter`. It does not sweep; a late
arrival at the receiver is `rescue`'s business, and keeping the two apart is
what makes the balance-delta measurement below unambiguous. A permissionless
withdraw after the deadline does not take anything from a taker mid-fill:
`withdrawDeposit` returns only unlocked funds, and a locked intent can still
be fulfilled after `acceptingIntents` is cleared.

Measures the glue's USDC balance across `withdrawDeposit(depositId)`, caps
the delta at `deposited - returned`, pays it to `terms.user`, adds it to
`returned`, emits `SessionWithdrawn(sessionId, user, amount)`. There is no
read of `remainingDeposits` before the call and no cap derived from one. That
read was v2's (`OfframpGlue.sol:400`) and round 1's R1 showed it stranding
the default walk-away case: `getDeposit(id).remainingDeposits` excludes funds
locked by intents, while `withdrawDeposit` first prunes every expired intent,
moves their amounts back into `remainingDeposits`, and returns the whole
figure in the same call. With `intentMin = 0` one intent takes the whole
credit, so a taker who signals and never pays leaves a pre-call read of zero;
the cap would pay the user zero, the deposit would close inside the call, and
the full amount would sit on the glue credited to nobody, with no function
left to move it. The only USDC that can reach the glue during a `withdraw` is
EscrowV2's return for this deposit, because 1Click pays receivers, `sweep` is
a separate call under the same `nonReentrant` latch, and `withdraw` does not
sweep. So `deposited - returned` is the whole cap. If a second bound is
wanted for its own sake, the right one is `remainingDeposits` plus the
`reclaimableAmount` of `getExpiredIntents(depositId)`, which is exactly what
`withdrawDeposit` is about to return; it must never be the bare pre-read.

It is repeatable, and must be. `withdrawDeposit` returns only funds not
locked by a still-live intent and sets `acceptingIntents = false`. When a
locked intent later expires and is pruned by `pruneExpiredIntents` or
`unlockFunds`, its amount goes back to `remainingDeposits` and stays in the
escrow; nothing is pushed to the depositor. A second `withdrawDeposit`
collects it. So v3 drops v2's `withdrawn` flag and lets the call run until the
deposit is gone. Once EscrowV2 has deleted the deposit, `withdrawDeposit`
reverts with `UnauthorizedCaller` because `depositor` reads as zero; the glue
surfaces that as `DepositClosed` and the session is finished.

Three EscrowV2 behaviours the sender should know. Funds locked by an intent
are not withdrawable until the taker fulfils, cancels, or the intent expires
after `intentExpirationPeriod()`, 21,600 seconds on the live escrow as read on
2026-09-03 and owner-settable with no upper bound. Dust is taken only on the
fulfil path: when a partial release leaves at most `dustThreshold` behind
(100000, or 0.10 USDC, on chain today) with no intent outstanding, that
remainder goes to zk-p2p's `dustRecipient`. On the `withdrawDeposit` path the
depositor gets everything, because `remainingDeposits` is deleted before the
close check runs; and with `intentMin = 0` a single full intent leaves
nothing, so the default path never pays dust. Last, anyone may `addFunds` to
the glue's deposit or `depositTo(glue, ...)`; neither reaches a user, because
extra funds in a glue-owned deposit come back to the glue on `withdrawDeposit`
and are capped away by `deposited - returned`. They become nobody's, which is
the donor's problem and not a hole.

**`rescueWithSig` and `withdrawWithSig`.** The same actions, authorised by an
EIP-712 signature from `terms.user` so a relayer with gas can run them before
`unwindAfter` on the user's behalf. Domain `{name: "OfframpGlueV3", version:
"1", chainId, verifyingContract}`; type `Unwind(bytes32 sessionId, uint8
action, uint256 validUntil)` with `action` 1 for rescue and 2 for withdraw.
Require `block.timestamp <= validUntil` and the recovered signer equal
`terms.user`. The relayer chooses nothing: the payee is `terms.user` and the
amount is the session's. A replay inside the validity window repeats an
action the user already asked for: a replayed withdraw pays the user again
from the user's own deposit, and a replayed rescue either pays a late arrival
to the user or finds nothing and reverts. So no nonce is needed. `terms.user`
is an EOA session key; if it is ever a contract wallet, `ecrecover` cannot
authorise it and the plain `rescue` and `withdraw` must be called from that
contract.

### 4.4 State machine

| State | Entered by | `sweep` | `advance` | `rescue` | `withdraw` |
|---|---|---|---|---|---|
| None | | reverts | reverts | reverts | reverts |
| Open | `createSession`, at any time including after `unwindAfter` | anyone | anyone, if `credited >= minCredit` and before `unwindAfter` | user; anyone after `unwindAfter` | reverts |
| Listed | `advance` | anyone | reverts | anyone (credit here is a late arrival) | user; anyone after `unwindAfter`; repeatable until the deposit is gone |

No `fulfilled` flag. Whether a taker paid is EscrowV2's and OrchestratorV3's
business; the status page reads `IntentFulfilled` from the orchestrator, as
the keeper does today.

### 4.5 Accounting invariants

- `usdc.balanceOf(glue) >= totalCommitted` always, where `totalCommitted` is
  the sum of every session's `credited`.
- Every debit from `credited` pays `terms.user` or funds a zk-p2p deposit
  whose payee is `terms.payeeDetailsHash`. There is no third destination.
- `deposited - returned` is the most `withdraw` can ever pay for a session,
  and it is the only cap on `withdraw`. It keeps a concurrent arrival in the
  same block from leaking across sessions through the balance-delta
  measurement, and it never falls below what EscrowV2 is about to return.
- Credit is only ever created by `sweep`, only from a receiver whose address
  was derived from the session being credited, and only by the glue's own
  balance delta. Nothing reads `balanceOf(glue)` to decide an amount.
- For any `terms` with `user != 0`, `createSession` succeeds exactly once,
  whatever the clock says and whatever the other fields hold. Once a session
  exists, `rescue` by `terms.user` is always callable and never depends on
  the receiver being able to `flush`.
- `nonReentrant` on `sweep`, `advance`, `rescue`, `withdraw` and both `WithSig`
  variants. Base USDC is a proxy; the latch is cheap insurance, as in v2.

## 5. Client-side verification rules

These rules are what turns the contract's properties into the sender's. They
live in the client, which means the CLI and the page. A client that skips one
reopens the corresponding v2 hole for that user.

**V1. The payee hash comes from the curator, never from the coordinator.** The
client calls `POST https://api.zkp2p.xyz/v2/makers/validate` and then
`/v2/makers/create` with `{"processorName": "venmo", "offchainId": <handle>}`
itself, over TLS to that host, and reads `hashedOnchainId`. `validate`
answers HTTP 200 for a known and an unknown handle alike, with
`responseObject` true or false, so the client keys on the body there.
`create` returns the stored maker row for a known handle and HTTP 404 with
`"User not found"` for an unknown one. The row is stable: two consecutive
`create` calls on 2026-09-03 for the project's own handle returned the
identical record (id 6588, the same `createdAt`, the same `hashedOnchainId`),
so the endpoint is idempotent and the hash a client reads is the hash a taker
will read. The hash is not keccak256 of the handle or of any obvious
concatenation with the processor name, so nobody can derive it; a taker
checking a listing must ask the curator. The row also carries a `revoked`
field, which is the curator's power to fail that check later (section 8). The
coordinator may be told the handle for the taker listing in section 6; it is
never asked for the hash.

**V2. The client builds the terms and derives everything from them.** It
generates the session key (`terms.user`) locally, sets `minConversionRate`
and `intentMin`/`intentMax` from the user's requested payment, sets
`depositTermsHash` from the deposit parameters it intends (payment method
`venmo`, its own payee hash, the gating service it accepts or zero, currency
code `USD` at its rate, oracle config off unless the user chose one), and
picks `unwindAfter` per section 11 question 1. It keeps the deposit
parameters, not just their hash, because `createSession` publishes them. It
computes `sessionId` and `receiver` locally from the pinned glue address and
`RECEIVER_INITCODE_HASH`. If it also asks an RPC for `receiverFor`, the answer
must match or the client stops.

**V3. The session exists on chain before the deposit address is shown.** The
client submits `createSession(terms, paymentMethods, paymentMethodData,
currencies)` itself if it holds Base gas, and otherwise hands the calldata to
the coordinator or any relayer. Then it waits for `SessionCreated` for its
`sessionId` on its own RPC and checks that the emitted `terms` and the
emitted triple equal the ones it built. Only then may the flow continue to
V4. A relayer that alters anything creates a different session at a different
receiver, and the client never sees its own id confirmed, so it never shows
an address. A relayer that refuses is a liveness failure the user can route
around with any funded key. From this point the terms and the deposit
parameters are on chain; the browser is no longer the only copy of either,
which is what round 1's R3 required.

**V4. The 1Click quote is verified against 1Click, not against the
coordinator.** 1Click sends permissive CORS: probed 2026-09-03 with
`Origin: https://zpay.cash`, `OPTIONS /v0/quote` and `OPTIONS /v0/status`
answer 204 with `access-control-allow-origin: *`, and the `GET /v0/status`
response carries the same header itself, with an unauthenticated rate limit
of 1200 requests per 60 seconds. So the browser, like the CLI, sends the
quote request to `https://1click.chaindefuser.com/v0/quote` itself and the
coordinator is not in the quote path at all. The request: `originAsset` ZEC,
`destinationAsset` the Base USDC id, `amount` the zatoshi it will send,
`recipient = receiver`, `recipientType DESTINATION_CHAIN`, `refundTo` a
transparent Zcash address the client controls (the session transparent
address of `docs/plans/ux-simplification.md` section 3.4, or the user's own),
`refundType ORIGIN_CHAIN`, `depositType ORIGIN_CHAIN`, `swapType
EXACT_INPUT`, `depositMode SIMPLE`, `dry false`, and the slippage and deadline
it wants. The request is unauthenticated and 1Click attaches its own 10 bps
`appFees` entry; a JWT can be added if the project ever holds one. The client
then calls `GET https://1click.chaindefuser.com/v0/status?depositAddress=<D>`
and checks the echoed `quoteResponse`:

| Field | Must equal |
|---|---|
| `quoteRequest.recipient` | `receiver`, case-insensitive |
| `quoteRequest.recipientType` | `DESTINATION_CHAIN` |
| `quoteRequest.destinationAsset` | the pinned Base USDC asset id |
| `quoteRequest.originAsset` | the pinned ZEC asset id |
| `quoteRequest.amount` | the zatoshi the client will send |
| `quoteRequest.refundTo` | the client's own transparent address |
| `quoteRequest.refundType`, `depositType` | `ORIGIN_CHAIN`, `ORIGIN_CHAIN` |
| `quoteRequest.swapType`, `depositMode` | `EXACT_INPUT`, `SIMPLE` |
| `quoteRequest.dry` | `false`; a dry quote has no live deposit address |
| `quoteRequest.virtualChainRecipient`, `virtualChainRefundRecipient`, `referral` | null |
| `quoteRequest.appFees` | the single 10 bps entry 1Click attaches on its own, or a list the client was built to accept; nothing else |
| `quote.depositAddress` | `D`, the address about to be shown |
| `quote.deadline` | later than now by the client's minimum margin, and earlier than `terms.unwindAfter` by at least the margin in section 11 question 1 |
| `quote.minAmountOut` | at least `terms.minCredit` |

Two deadlines appear in the response and the table means the second.
`quoteRequest.deadline` is the client's own request parameter (three days in
the 2026-08-31 fixture); `quote.deadline` and `timeWhenInactive` are 1Click's
statement of how long the deposit address stays live (six days in the same
fixture). USDC can arrive until `quote.deadline`, so that is the one
`unwindAfter` must clear.

Only after every row passes does the client display `D` as the address to
send ZEC to. The status endpoint is 1Click's own statement about its own
deposit address; a coordinator that forged a quote would have to defeat the
client's TLS connection to 1Click to pass this check, and after V4 there is
no coordinator in the quote path to forge one. The fixture in
`crates/zecp2p-coordinator/tests/fixtures/1click_status_success.json` shows
every field in the table present in the response.

**V5. `minCredit` is the floor the user accepts, and the contract holds it.**
The client sets `terms.minCredit` at or below `quote.minAmountOut`. If 1Click
delivers less, `advance` refuses, the session can only be rescued, and the
USDC goes back to the session key for the back-swap. 1Click's floor is a
promise; `minCredit` is the enforcement.

**V6. The client reads outcomes from the chain, not from the coordinator.**
Receiver balance, `Swept`, `OfframpProcessed`, `IntentSignaled`,
`IntentFulfilled`, `SessionRescued`, `SessionWithdrawn`: all from the client's
own RPC. The coordinator's status API is a convenience view. A lying RPC can
delay the user's knowledge; it cannot move funds, because nothing the client
signs depends on what it reads after funding. The two reads that matter
before funding are the receiver address, which rule V2 computes locally, and
the `SessionCreated` event, which rule V3 compares field by field against
what the client built.

**V7. If the coordinator is gone, anyone can finish the session from the
chain.** After V3 a stranger with an RPC and the glue address reads `Terms`
and the deposit parameters out of `SessionCreated`, and can call
`sweep(sessionId)`, `advance(sessionId, ...)` with those parameters, and
after `unwindAfter`, `rescue` or `withdraw`. The client still stores both
preimages with the session and can print them as `cast send` commands, and
should, but losing that storage no longer loses anything. This is the
"someone permissionlessly moves them along" clause, and it holds for a
stranger with no relationship to the sender because the stranger needs
nothing the sender has.

**V8. Relayed unwinds are signed for one session and one action.** When the
page wants an early rescue or withdraw without gas, it signs the
`Unwind` struct from 4.3 with a `validUntil` of a few minutes and hands it to
the coordinator. The coordinator can delay it or drop it; it cannot redirect
it.

## 6. What the coordinator still does

The coordinator remains and remains useful. It just stops being trusted.

| Job | How | Power it carries |
|---|---|---|
| Creation relay | Submits the client's `createSession` calldata before the client shows a deposit address (V3) | Liveness only: a changed byte makes a different session the client never confirms; any funded key can submit the same calldata |
| Gas | Calls `sweep` and `advance` when a session is funded, from the parameters in `SessionCreated` | Liveness only, plus one ordering choice: while a user's signed `rescueWithSig` and a valid `advance` are both live, the coordinator picks which lands. Choosing `advance` forces a listing the user wanted to cancel, at the user's own terms, followed by a withdraw. A possibly unwanted fill or a back-swap round trip, not a theft |
| Unwind relay | Broadcasts `rescueWithSig` / `withdrawWithSig`, and after `unwindAfter` the plain forms | Liveness only |
| Back-swap relay | Broadcasts the session key's EIP-3009 `transferWithAuthorization` to a 1Click deposit address for the USDC-to-ZEC return leg, per `docs/plans/ux-simplification.md` 4.2 | None: the authorization names the destination |
| Taker listing | `GET /deposits/open` with `depositId`, `venmoUsername`, amount, for takers to cross-check against the on-chain payee hash by asking the curator (V1) | Advisory; the taker verifies |
| Matching | If the sender's `depositTermsHash` names the coordinator as `intentGatingService`, signs `signalIntent` for the taker it picks; otherwise nothing | Can refuse to sign (liveness); cannot change the payee or the rate, both of which are in the deposit |
| Status and stats | Aggregates chain events for the page and the public read API | None over funds |

The quote relay is gone. 1Click's CORS headers let the page call `/v0/quote`
and `/v0/status` directly (V4), so the coordinator no longer sees the quote
request or the response.

The disposition of every v2 keeper power:

| v2 power | v3 disposition |
|---|---|
| Choose 1Click recipient and refundTo (T1) | Removed. The client composes the quote and verifies it against 1Click (V4); the coordinator is not in the path |
| Attribute arrivals, `creditSession` (T2) | Removed. Attribution is the receiver address; `sweep` is permissionless and mechanical |
| `createSession` naming any user (T2, A3-8) | Removed as a power. Anyone may create any session, and creating one gives the creator nothing |
| Fix the payee hash (T3) | Removed. The sender commits it (V1, V2); the contract enforces it |
| Choose `currencies` and the rate at `processOfframp` (M1) | Removed. Pinned by `depositTermsHash`; floor and currency code enforced in code |
| Choose the intent range | Removed. Pinned in terms |
| Choose `delegate`, `intentGuardian`, `retainOnEmpty`, `token` | Removed. Hard-coded, `delegate` to zero for the reason in 4.3 |
| Time `processOfframp` | Liveness. Anyone may `advance` |
| `rescue` / `withdrawFromZkp2p` for a user | Liveness. User any time by signature, anyone after `unwindAfter`; payee is always `terms.user` |
| `setKeeper` | Gone. There is no keeper |
| Sweep uncredited USDC (A3-8) | Gone. There is no uncredited USDC that a session can claim; a direct transfer to the glue belongs to nobody |

## 7. Sequence

```
Client                          Coordinator            1Click            Glue v3              EscrowV2
  |-- validate, create handle -------------------------> curator (api.zkp2p.xyz)
  |<-------------------------------------------------- hashedOnchainId
  | build Terms + deposit params, sessionId, receiver locally
  |-- createSession(terms, params) calldata -> |-- submit ------------------> |
  | read SessionCreated via own RPC; emitted terms and params must match (V3)
  |-- POST /v0/quote (recipient = receiver) -----------> |
  |<---------------------------------------- quote ---- |
  |-- GET /v0/status?depositAddress=D ----------------> |
  |<---------------------- quoteResponse (checked, V4) |
  | show D; user sends ZEC
  |                                          |            |-- USDC transfer --> receiver
  |                                          |-- sweep(sessionId) ------------> | flush, credit
  |                                          |-- advance(sessionId, params) --> |-- createDeposit --> |
  | read OfframpProcessed via own RPC
  |                                                      taker signals, pays Venmo, proves; USDC to taker
  | read IntentFulfilled via own RPC
```

The coordinator column carries only calldata the client wrote and calls whose
inputs are already on chain. Every arrow into it can be redrawn to any funded
key without changing what lands.

Failure branches: 1Click refunds ZEC to `refundTo` (the client's own address);
or `advance` refuses because `credited < minCredit` and the user rescues; or
nobody fills and, after `unwindAfter`, anyone withdraws to the session key; or
a taker signals and walks away, the intent expires after 21,600 seconds, and
the first `withdraw` after that returns the full amount; then the back-swap of
`docs/plans/ux-simplification.md` turns USDC at the session key into ZEC.

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

**zk-p2p's owner key.** It is a custodian of every listed deposit from
`advance` until fulfil or withdraw, not merely a taker of dust. From the
verified EscrowV2 and OrchestratorV3 sources (Sourcify exact match,
2026-09-03):

- `setOrchestratorRegistry` lets the owner name any address as an
  orchestrator, and an orchestrator may `lockFunds` and then
  `unlockAndTransferFunds(depositId, intentHash, amount, to)` with a `to` of
  its choosing. That is custody of every open deposit with no proof required.
- `setPaymentVerifierRegistry` decides which verifier `fulfillIntent` trusts
  for the `venmo` method. A swapped verifier accepts any proof.
- `setIntentExpirationPeriod` rejects only zero. The six-hour lock is a
  current parameter, not a property.
- `pauseEscrow` blocks `createDeposit`, so `advance` fails while paused;
  `withdrawDeposit` and `pruneExpiredIntents` stay open, so a paused escrow
  degrades a session to rescue or withdraw rather than sticking it.
- `setLifecycleHook` on the orchestrator installs a hook that runs on every
  signal and settlement and can revert either, which stalls fills until the
  user withdraws.
- `dustThreshold` and `dustRecipient` are owner-set; dust is taken on the
  fulfil path as described in 4.3.
- The owner and `dustRecipient` are the same key today,
  `0x0bC26FF515411396DD588Abd6Ef6846E04470227`, on both contracts.

None of this is new to v3, none of it is fixable here, and every depositor on
their escrow carries it. It is stated because "the coordinator is untrusted"
must not be read as "nobody is".

**zk-p2p's enclave and curator.** The Nitro enclave whose server half is
unpublished attests Venmo payments; `AttestationVerifier` checks that
signature against an owner-settable witness list. The curator issues the
payee hash and can, in principle, issue one that maps the sender's handle to
a different Venmo account. It can also set the `revoked` field on a maker
row, which makes a taker's cross-check of a live listing fail and stalls
fills until the sender withdraws. Enclave and curator are the same two
parties named as residual in the native escrow spec.

**Circle.** Base USDC is Circle's FiatToken, with a blacklist and a pause. A
blacklisted receiver cannot `flush`; the `try` in `rescue` keeps that from
locking credit already on the glue, but the receiver's own balance waits on
Circle. A blacklisted `terms.user` can never be paid, and the session has no
alternate payee. A paused token stops every transfer in this design at once.

**The taker.** Can signal an intent and let it expire, locking that portion
of the deposit for the current expiration period, six hours today. Cannot
receive USDC without the enclave attesting a payment to the committed payee.
`allowMultipleIntents` is true on the live escrow, so one taker can hold
several intents on a ranged deposit; each still needs its own attestation to
be paid.

**A gating service, if the sender names one.** Can decline to sign, which
stalls fills until the sender withdraws. Cannot change who is paid or how
much per USDC.

**The session key.** Held by the client, in a link and in browser storage on
the page. Losing it after a return has landed loses that return. Nothing sits
at it on the happy path. It is deliberately not the deposit's delegate.

**The client itself.** The page is served by the operator. A hostile build
could skip V1 to V5 and reintroduce T1 and T3 for users of that build. The
contract cannot protect a user from their own client. Mitigations are
reproducible builds, a published hash of the served bundle, and the CLI as an
independent implementation of the same rules. This is the largest remaining
trust in the operator and the honest answer to "is the coordinator fully
untrusted": the coordinator is; the operator who also serves the page is not.

**Base, the sequencer, the RPC, and TLS.** Reads through the client's RPC can
be delayed or false; funds do not move on reads. The sequencer orders
transactions and so decides, like the coordinator in section 6, whether a
user's `rescueWithSig` or a stranger's `advance` lands first when both are
valid; it cannot make either pay anyone but the user or the user's payee.
Chain liveness and finality are assumed.

## 9. Design choices worth defending

**No privileged sweep of unattributed USDC.** A transfer straight to the glue
is lost. An owner sweep would recover honest mistakes and would also be a key
that can take money, so it is the one thing this design refuses. The client
never presents the glue address as a destination; 1Click quotes are verified
to name a receiver; the receivers are the only place USDC is meant to land.

**Creation checks nothing but the return key.** Every other validation was
moved to `advance` or deleted. A check at creation that a client can fail is
a check that can strand a funded receiver, because no other terms reach that
address and nobody can clean up afterwards. A check at `advance` that a
client fails costs the user a back-swap. The second is a bug; the first is a
loss.

**The preimages go on chain at creation.** Emitting a whole struct and three
arrays costs more gas than emitting five scalars. It buys the property V7
claims: a stranger can finish any session with an RPC and nothing else. The
alternative, trusting one browser's storage, was round 1's R3.

**Credit is not capped at the quote.** v2 caps `creditSession` at
`expectedAmount` because the keeper might attribute wrongly. With attribution
by address there is no wrong attribution to bound, and an over-delivery is
the sender's money.

**Withdraw is capped by the glue's own books, not by EscrowV2's view.** The
glue knows what it deposited and what it has returned. EscrowV2's
`remainingDeposits` is a snapshot that `withdrawDeposit` itself changes
mid-call. Capping at the snapshot was the v2 habit that stranded round 1's
R1.

**Anyone may create any session.** It costs the creator gas and gives them
nothing: a wrong triple fails the hash check, wrong terms make a different
session. Refusing it would need a signature from the session key, which
would make the coordinator's relay a chokepoint again and would close the
funding-before-creation fallback that keeps a client bug from becoming a
loss.

**Rescue does not depend on the receiver.** A user's credit on the glue and
the balance still at the receiver are two balances. Coupling them through one
revert lets a third party's blacklist decision lock the first; the `try`
uncouples them and costs nothing on the happy path.

**No delegate.** Set out in 4.3. A delegate can zero the rate floor, and the
only candidate for the role holds a key that lives in a URL fragment.

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

1. Build v3 and run the Foundry suite plus a Base fork test against the real
   EscrowV2 that covers, at least: `advance` followed by two `withdraw` calls
   with an intent expiring between them; the R1 case, a single intent for the
   whole credit that expires before one `withdraw`, asserting `terms.user`
   receives the full amount in that one call; `createSession` after
   `unwindAfter` followed by a stranger's `rescue`; `createSession` with empty
   deposit parameters followed by `advance` with the right ones; and a
   `rescue` against a receiver whose `flush` is made to revert, asserting the
   credited balance is still paid. Verify the receiver's CREATE2 address
   against a client-side computation, and decode `SessionCreated` back into
   `Terms` and the triple from a client.
2. Deploy v3 with `(usdc, zkp2pEscrow)` from the deployer key. There is no
   `setKeeper` step because there is no keeper; the deployer holds nothing
   afterwards. Verify source on Basescan so `RECEIVER_INITCODE_HASH` and the
   bytecode are public.
3. Pin the v3 address and `RECEIVER_INITCODE_HASH` in the client (CLI and
   page), the coordinator config, and the taker config as a second glue to
   scan. Teach the taker to fetch the payee hash for a listed handle from the
   curator rather than compute it, since it cannot be computed (V1).
4. Stop opening v2 sessions. Let the in-flight ones finish. Rescue or withdraw
   any that will not. `withdrawFromZkp2p` on a v2 deposit must go through the
   v2 glue forever, because EscrowV2 lets only the depositor withdraw; v2 is
   immutable and stays callable, which is all that requires.
5. Once v2 holds no credit and has no open deposit, the v2 owner may
   `setKeeper` to a burn address. That is the only administrative act left
   and it removes a power rather than exercising one.
6. First mainnet run at the $1 size used for the native escrow test, with
   one deliberate deviation: turn the coordinator off after `createSession`
   has landed and before the USDC arrives, and have a different funded key
   with no access to the client's storage read `SessionCreated`, then call
   `sweep` and `advance` from the event data alone. The property this design
   claims is that this works; the test should show it. The run also confirms
   on this contract what the 2026-09-02 transaction showed on v2, that 1Click
   pays a codeless receiver by plain transfer.

Coordinator changes: drop `creditSession`; replace `create_session` with a
relay that submits the client's `createSession` calldata unchanged and
returns the transaction hash; drop the 1Click quote relay, since the client
calls 1Click itself; replace the 1Click-status-driven `credit_decision` with
a receiver-balance watch that calls `sweep`; `process_offramp` becomes
`advance` with parameters decoded from `SessionCreated`, not from local state,
so a coordinator restarted from nothing can still advance every open session;
`rescue` and `withdraw` become relays of signed unwinds before `unwindAfter`
and plain calls after. The single-session gate in
`refuse_if_a_session_is_in_flight` exists to protect against wrong
attribution and can go. The taker listing gains nothing new but should link
each `depositId` to the curator lookup a taker has to perform.

## 11. Open questions

Round 1 answered the original questions 1 (CORS), 2 (delivery mechanics), 3
(curator hash stability) and 7 (delegate); the answers are in sections 3.3,
4.3, 5 and 8. What remains:

1. **Default `unwindAfter`.** It has to clear the last moment USDC can
   arrive, which is `quote.deadline` (six days in the 2026-08-31 fixture, not
   the three-day `quoteRequest.deadline` the client itself chose), plus one
   intent lock (21,600 seconds today, owner-settable), plus margin for the
   withdraw to be reached in one attempt. The earlier draft's "around four
   days" is shorter than the fixture's `quote.deadline`. A short
   `unwindAfter` does not lose funds, since USDC that lands after it is
   rescuable by anyone, but it costs the user a back-swap; the client should
   either derive `unwindAfter` from the quote it is about to accept or
   reject a quote whose `quote.deadline` runs past it, and V4's table now
   requires the latter.
2. **Gas for the permissionless path.** `createSession` now emits a struct
   and three arrays, `sweep` deploys a receiver on first call, and `advance`
   runs `createDeposit`, so a stranger moving a stuck session along pays a
   few hundred thousand gas on Base. Whether to publish a public "poke" that
   reads `SessionCreated` and runs the next step for any session, or to leave
   it to the printed commands, is a product question.
3. **Non-USDC tokens at a receiver.** `flush` moves only the token the glue
   names. Anything else sent to a receiver is stuck. A `flushOther(token)`
   that pays `terms.user` is cheap to add and adds no power; decide whether
   the case is worth the surface.
4. **The oracle rate config.** Allowed and hash-pinned. Whether the client
   should ever build terms with one, given that a halted oracle stalls fills,
   is a client policy question, not a contract one.
5. **Sender-side proof of the contract.** V2 pins the glue address and
   initcode hash in the client build. Whether the page should also fetch the
   glue's code hash over its RPC and compare it to a pinned value, so a wrong
   pinned address is caught before funding, is a small addition worth making.
6. **Republishing the deposit parameters.** If a session is created with
   empty deposit parameters and the client that knew them is gone, the only
   way they reach the chain is a successful `advance`. A `publishDepositParams`
   that checks the hash and re-emits would close that corner for the price of
   one more function. Under V3 the corner is unreachable from an honest
   client; decide whether to pay for it anyway.
