/**
 * chain.js — direct client → Sepolia reads of the KeyRegistry contract.
 *
 * SECURITY MODEL (docs/crypto-design.md §3(d)1, §8.11): this module is the
 * client side of the on-chain key-transparency check. Everything is
 * computed locally — the identity hash (keccak256 of the username), the
 * calldata, and the decode of the result — and the JSON-RPC request goes
 * straight to a public Sepolia endpoint, never through the mailbox server.
 * Routing this lookup through the server would let a compromised server
 * answer its own integrity check, which is precisely the attack the
 * registry exists to expose.
 *
 * Failure semantics are the CALLER's job and differ by call site:
 * the pre-encrypt gate must FAIL CLOSED on any RPC failure (an active
 * network attacker who can block the RPC must not be able to silently
 * disable the check), so this module never swallows errors — it returns
 * either a decoded record or a status:'error' result the caller must act on.
 */

import { CHAIN } from './config.js';
import { keccak256 } from './keccak.js';

// First 4 bytes of keccak256("getKey(bytes32)") — fixed by the contract ABI.
// (Constant, so it is hardcoded rather than recomputed; the Keccak
// implementation itself is vector-tested separately.)
const GET_KEY_SELECTOR = '12aaac70';

const bytesToHex = (bytes) =>
  Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');

/** keccak256(username) — the registry's identity scheme, computed locally. */
export function identityHash(username) {
  return bytesToHex(keccak256(new TextEncoder().encode(username)));
}

/**
 * Read KeyRegistry.getKey(keccak256(username)) directly over JSON-RPC.
 *
 * @returns one of:
 *   { status: 'ok', registered: boolean, version: number,
 *     keyB64: string|null, updatedAt: number|null, revoked: boolean }
 *   { status: 'error', reason: string }   — RPC unreachable, bad response,
 *     or registry address not configured. The pre-encrypt gate treats this
 *     as a hard stop (fail closed, explicit typed override only).
 */
export async function getOnChainKey(username) {
  if (!CHAIN.keyRegistryAddress) {
    return { status: 'error', reason: 'KeyRegistry address not configured on this client.' };
  }

  const data = '0x' + GET_KEY_SELECTOR + identityHash(username);

  let res;
  try {
    res = await fetch(CHAIN.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_call',
        params: [{ to: CHAIN.keyRegistryAddress, data }, 'latest'],
      }),
    });
  } catch (err) {
    return { status: 'error', reason: `RPC unreachable: ${err.message}` };
  }
  if (!res.ok) {
    return { status: 'error', reason: `RPC returned HTTP ${res.status}` };
  }

  let body;
  try {
    body = await res.json();
  } catch {
    return { status: 'error', reason: 'RPC returned a non-JSON response' };
  }
  if (body.error) {
    return { status: 'error', reason: `RPC error: ${body.error.message ?? JSON.stringify(body.error)}` };
  }

  // getKey returns (bytes32 x25519Key, uint32 version, uint64 updatedAt,
  // bool revoked) — four static 32-byte words, decoded by slicing; no ABI
  // library needed for a fixed layout.
  const hex = (body.result ?? '').replace(/^0x/, '');
  if (hex.length !== 4 * 64) {
    return { status: 'error', reason: `Unexpected eth_call result length ${hex.length}` };
  }

  const keyHex = hex.slice(0, 64);
  const version = parseInt(hex.slice(64, 128), 16);
  const updatedAt = parseInt(hex.slice(128, 192), 16);
  const revoked = parseInt(hex.slice(192, 256), 16) === 1;

  if (version === 0) {
    return { status: 'ok', registered: false, version: 0, keyB64: null, updatedAt: null, revoked: false };
  }

  const keyBytes = new Uint8Array(keyHex.match(/.{2}/g).map((h) => parseInt(h, 16)));
  return {
    status: 'ok',
    registered: true,
    version,
    keyB64: btoa(String.fromCharCode(...keyBytes)),
    updatedAt,
    revoked,
  };
}
