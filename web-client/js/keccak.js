/**
 * keccak.js — Keccak-256 (the Ethereum variant), implemented from scratch.
 *
 * Why this exists: the on-chain KeyRegistry identifies users by
 * keccak256(username), and the whole point of the client-side registry
 * check is that the CLIENT computes everything itself and talks to the
 * chain directly — trusting the server to hash the identity would let a
 * compromised server answer its own integrity check. No browser API
 * provides Keccak-256: Web Crypto's SHA-3 (where available) uses the
 * standardized SHA-3 padding (0x06), while Ethereum uses the original
 * Keccak submission padding (0x01), producing entirely different digests.
 *
 * Implementation notes:
 *   - Keccak-f[1600] with 64-bit lanes as BigInt. Performance is
 *     irrelevant here (inputs are usernames, a few bytes, hashed once per
 *     lookup); clarity and auditability win over a bit-sliced fast path.
 *   - rate = 1088 bits (136 bytes), capacity = 512, output = 256 bits.
 *   - Verified against fixed vectors (see tests) including values produced
 *     by web3.py and observed live on-chain during backend integration:
 *       keccak256("alice") = 9c0257114eb9399a2985f8e75dad7600c5d89fe3824ffa99ec1c3eb8bf3b0501
 */

const RATE_BYTES = 136;                 // 1088-bit rate for Keccak-256
const U64_MASK = (1n << 64n) - 1n;

// Round constants for Keccak-f[1600] (24 rounds).
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
  0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
  0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
  0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets, indexed [x][y] per the Keccak reference.
const RHO = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

function rotl64(v, n) {
  n = BigInt(n);
  if (n === 0n) return v;
  return ((v << n) | (v >> (64n - n))) & U64_MASK;
}

/** One Keccak-f[1600] permutation over a 5×5 lane state (BigInt[25], index x + 5y). */
function keccakF(s) {
  for (let round = 0; round < 24; round++) {
    // θ (theta)
    const c = new Array(5);
    for (let x = 0; x < 5; x++) {
      c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) s[x + 5 * y] ^= d;
    }

    // ρ (rho) + π (pi)
    const b = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(s[x + 5 * y], RHO[x][y]);
      }
    }

    // χ (chi)
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        s[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y] & U64_MASK) & b[((x + 2) % 5) + 5 * y]);
      }
    }

    // ι (iota)
    s[0] ^= RC[round];
  }
}

/**
 * Keccak-256 digest of a byte array.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array} 32-byte digest
 */
export function keccak256(bytes) {
  const state = new Array(25).fill(0n);

  // Pad: Keccak (pre-SHA-3) multi-rate padding — 0x01 ... 0x80.
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / RATE_BYTES) * RATE_BYTES);
  padded.set(bytes);
  padded[bytes.length] = 0x01;
  padded[padded.length - 1] |= 0x80;

  // Absorb, one rate-sized block at a time (lanes are little-endian u64).
  for (let off = 0; off < padded.length; off += RATE_BYTES) {
    for (let i = 0; i < RATE_BYTES / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) {
        lane = (lane << 8n) | BigInt(padded[off + i * 8 + b]);
      }
      state[i] ^= lane;
    }
    keccakF(state);
  }

  // Squeeze: 256 bits fit inside one rate block — read 4 lanes.
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = state[i];
    for (let b = 0; b < 8; b++) {
      out[i * 8 + b] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

/** Keccak-256 of a UTF-8 string, as lowercase hex (no 0x prefix). */
export function keccak256Hex(str) {
  const digest = keccak256(new TextEncoder().encode(str));
  return Array.from(digest).map((b) => b.toString(16).padStart(2, '0')).join('');
}
