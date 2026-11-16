# PoC — Bull SDK `lock()`: server-chosen locker + unbounded approval

## What it proves

The Bull SDK (`bull.mjs`, https://www.bull.family/sdk/bull.mjs) claims:
> "Safety: the API server is not trusted with your wallet. Every transaction
> it returns is checked before it is sent."

`lock()` breaks that promise. It takes the vesting/locker contract address
from the **server's own response** (parsed out of the approve step) and it
never checks the approve amount, the token, the locked amount, the
beneficiary, or the schedule. Its guard (`#guard`) allows an `approve()` to
any such "locker" up to `2**200 - 1` — effectively unlimited for any real
token. A compromised/malicious API server can therefore name an attacker
contract as the locker and drain the victim's **entire** token balance.

Contrast (in the same file):
- `consent()` fully verifies the server's message via `#checkConsent()`.
- `claim()` requires the caller to pass a trusted `{ locker }` address.
- `lock()` does neither.

## Run (local only — no real funds, no mainnet, no Bull infrastructure)

```bash
# 1. Start Anvil (Foundry) on port 8545
anvil --port 8545 --chain-id 31337

# 2. Run (from this directory)
node run-poc.mjs
```

What happens:
1. Deploys `MockERC20`, mints 1,000,000 tokens to the victim.
2. Deploys `AttackerLocker` (attacker contract).
3. Starts a mock Bull API on `127.0.0.1:8787`. Its `POST /api/v1/vesting`
   returns two steps: `approve(attackerLocker, 2**200-1)` + `createLock(...)`.
4. The **real** Bull SDK (`bull-sdk.mjs`, verbatim copy — sha256 below)
   executes both steps and returns `lockId: 1` with **no error, no warning**.
5. The attacker calls `drain()` and takes the victim's whole balance.

## Result (verified 16 Nov 2026)

```
SDK returned lockId: 1 — NO ERROR, NO WARNING
approval actually granted by SDK: 2**200-1  (granted == 2**200-1 ? true)
tokens actually 'locked' in locker: 100
victim balance after drain: 0
attacker balance after drain: 999900
EXPLOITED: victim lost 100% of their balance (1,000,000 tokens).
```

(The remaining 100 tokens sit in the attacker-controlled locker; the attacker
owns that contract too. Victim balance is 0 either way.)

## Files

- `bull-sdk.mjs` — verbatim copy of https://www.bull.family/sdk/bull.mjs
  (sha256 `b8abb874115915485012abd954e9a0ea9951d66b42edb84e84583b5f52d52a0c` —
  identical to `~/workspace/bull-audit/src/bull-sdk.mjs`)
- `mock-api.mjs` — malicious mock Bull API (localhost only)
- `run-poc.mjs` — the PoC driver (real SDK + real EVM execution on Anvil)
- `chain/src/Mocks.sol` — MockERC20 + AttackerLocker (Foundry project)
- `poc-result.json` — machine-readable result of the last run

## Do NOT publish yet

This PoC is prepared for the Bull bug-bounty report form (whose PoC field
asks for a LINK). It must be published (gist/repo) **only together with the
report submission**, after the user approves the draft — never before
(Bull's rules: no public disclosure until fixed). It contains no private
keys, no seed phrases, no real credentials: all wallets are throwaway keys
generated fresh on each run on a local Anvil chain.
