/**
 * verify-key.js — Key Verification Page.
 *
 * Cross-checks a user's encryption key across three independent sources and
 * renders a verdict:
 *   1. On-chain KeyRegistry, read DIRECTLY from Sepolia (chain.js) — never
 *      through the mailbox server, so a compromised server cannot answer its
 *      own integrity check (docs/crypto-design.md §8.11).
 *   2. The server's current view (GET /users/{username}?onchain=1) — the
 *      key the server would hand a sender right now, plus its stored
 *      registration tx hash.
 *   3. This browser's TOFU pin, if the viewer previously communicated with
 *      the user (read-only — viewing never creates a pin).
 *
 * The block number for the registration tx is fetched with a second direct
 * eth_getTransactionReceipt call on the same public RPC, covering the
 * brief's "block number / timestamp" without a new backend endpoint.
 */

import { API, CHAIN } from './config.js';
import { getOnChainKey, identityHash } from './chain.js';
import { keyFingerprint, getPin } from './crypto.js';

const ETHERSCAN = 'https://sepolia.etherscan.io';
const getUsername = () => localStorage.getItem('sm_username');

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('kv-form').addEventListener('submit', handleVerify);
  const q = new URLSearchParams(location.search).get('u');
  if (q) {
    document.getElementById('kv-username').value = q;
    document.getElementById('kv-form').requestSubmit();
  }
});

async function handleVerify(e) {
  e.preventDefault();
  const username = document.getElementById('kv-username').value.trim();
  const btn = document.getElementById('kv-btn');
  const err = document.getElementById('kv-error');
  const result = document.getElementById('kv-result');
  if (!username) return;

  err.style.display = 'none';
  result.classList.remove('show');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Verifying…';

  try {
    // Server view (also confirms the user exists) + on-chain read in parallel.
    const [serverRes, chain] = await Promise.all([
      fetch(`${API}/users/${encodeURIComponent(username)}?onchain=1`),
      getOnChainKey(username),
    ]);
    if (serverRes.status === 404) throw new Error(`User "${username}" not found.`);
    if (!serverRes.ok) throw new Error(`Server error (HTTP ${serverRes.status}).`);
    const server = await serverRes.json();

    await render(username, server, chain);
    result.classList.add('show');
    result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (ex) {
    err.textContent = ex.message;
    err.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Verify Key';
  }
}

function setVerdict(kind, title, subtitle) {
  const banner = document.getElementById('kv-banner');
  banner.className = `result-banner ${kind === 'ok' ? 'pass' : 'fail'}`;
  document.getElementById('kv-icon').textContent =
    kind === 'ok' ? '✓' : kind === 'warn' ? '!' : '✗';
  document.getElementById('kv-title').textContent = title;
  document.getElementById('kv-subtitle').textContent = subtitle;
}

function pill(kind, text) {
  return `<span class="kv-pill ${kind}">${text}</span>`;
}

async function render(username, server, chain) {
  const serverKey = server.public_key ?? null;
  const serverFp = serverKey ? await keyFingerprint(serverKey) : '(server has no key on record)';

  // ── Overall verdict ──────────────────────────────────────────────────────
  if (chain.status === 'error') {
    setVerdict('warn', 'On-chain check unavailable',
      `Could not read the registry: ${chain.reason}. Showing the server's view only.`);
  } else if (!chain.registered) {
    setVerdict('warn', 'Not on the registry',
      `"${username}" has no on-chain key record yet (a pre-registry account, or the ` +
      `registration transaction has not landed). Only TOFU protects this contact.`);
  } else if (chain.revoked) {
    setVerdict('bad', 'Key revoked on-chain',
      `"${username}"'s key is marked REVOKED in the registry. Do not encrypt new files to it.`);
  } else if (serverKey && chain.keyB64 === serverKey) {
    setVerdict('ok', 'Verified — server key matches the chain',
      `The key the server reports for "${username}" matches the public on-chain registry ` +
      `(version ${chain.version}).`);
  } else {
    setVerdict('bad', 'MISMATCH — server key differs from the chain',
      `The key the server reports for "${username}" does NOT match the on-chain registry. ` +
      `This can be a very recent rotation, or a server substituting a key. Verify out-of-band.`);
  }

  // ── On-chain record ──────────────────────────────────────────────────────
  const os = document.getElementById('kv-onchain-status');
  const ofp = document.getElementById('kv-onchain-fp');
  if (chain.status === 'error') {
    os.innerHTML = pill('warn', 'unavailable');
    ofp.textContent = '—';
    document.getElementById('kv-version').textContent = '—';
    document.getElementById('kv-updated').textContent = '—';
  } else if (!chain.registered) {
    os.innerHTML = pill('neutral', 'not registered');
    ofp.textContent = '—';
    document.getElementById('kv-version').textContent = '0';
    document.getElementById('kv-updated').textContent = '—';
  } else {
    os.innerHTML = chain.revoked ? pill('bad', 'revoked') : pill('ok', 'active');
    ofp.textContent = await keyFingerprint(chain.keyB64);
    document.getElementById('kv-version').textContent = String(chain.version);
    document.getElementById('kv-updated').textContent =
      chain.updatedAt ? new Date(chain.updatedAt * 1000).toLocaleString() : '—';
  }

  // ── Server's view ────────────────────────────────────────────────────────
  const sfp = document.getElementById('kv-server-fp');
  sfp.textContent = serverFp;
  if (chain.status === 'ok' && chain.registered && serverKey) {
    sfp.innerHTML = `${serverFp} ${chain.keyB64 === serverKey ? pill('ok', 'matches chain') : pill('bad', 'differs from chain')}`;
  }

  // TOFU pin (read-only; only meaningful when logged in on this browser).
  const me = getUsername();
  const pinEl = document.getElementById('kv-pin');
  if (!me) {
    pinEl.textContent = '(sign in to compare against your pinned key)';
  } else if (me === username) {
    pinEl.textContent = '(this is your own account)';
  } else {
    const pin = await getPin(me, username);
    if (!pin) {
      pinEl.textContent = 'not pinned yet on this device';
    } else {
      const pinFp = await keyFingerprint(pin.publicKeyB64);
      const matches = serverKey && pin.publicKeyB64 === serverKey;
      pinEl.innerHTML =
        `pinned ${new Date(pin.firstSeen).toLocaleDateString()} ` +
        (matches ? pill('ok', 'matches server') : pill('bad', 'differs from server'));
    }
  }

  // ── Blockchain evidence links ────────────────────────────────────────────
  document.getElementById('kv-identity').textContent = '0x' + identityHash(username);

  const contractEl = document.getElementById('kv-contract');
  if (CHAIN.keyRegistryAddress) {
    contractEl.innerHTML =
      `<a href="${ETHERSCAN}/address/${CHAIN.keyRegistryAddress}" target="_blank" rel="noopener noreferrer">` +
      `${CHAIN.keyRegistryAddress}</a>`;
  } else {
    contractEl.textContent = '(registry address not configured on this client)';
  }

  const txEl = document.getElementById('kv-tx');
  const blockEl = document.getElementById('kv-block');
  const txHash = server.onchain?.tx_hash ?? null;
  if (txHash) {
    txEl.innerHTML =
      `<a href="${ETHERSCAN}/tx/${txHash}" target="_blank" rel="noopener noreferrer" style="word-break:break-all">${txHash}</a>`;
    blockEl.textContent = 'looking up…';
    const blockNum = await fetchBlockNumber(txHash);
    blockEl.textContent = blockNum != null ? `#${blockNum}` : '(unavailable)';
  } else {
    txEl.textContent = '(no registration transaction recorded)';
    blockEl.textContent = '—';
  }
}

/** eth_getTransactionReceipt on the same public RPC → decimal block number. */
async function fetchBlockNumber(txHash) {
  try {
    const res = await fetch(CHAIN.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getTransactionReceipt', params: [txHash] }),
    });
    if (!res.ok) return null;
    const body = await res.json();
    const bn = body.result?.blockNumber;
    return bn ? parseInt(bn, 16) : null;
  } catch {
    return null;
  }
}
