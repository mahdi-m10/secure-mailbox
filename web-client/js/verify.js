/**
 * verify.js — Blockchain integrity verification for verify.html
 *
 * Verification flow:
 *   1. GET /messages/{id}/download          — message metadata (sender, subject, AAD)
 *   2. GET /messages/{id}/blockchain-proof  — server-computed keccak256 comparison
 *                                             + Sepolia on-chain lookup
 *
 * The backend computes keccak256(ciphertext) and compares it to the stored
 * integrity_hash, then optionally fetches the matching hash from the Sepolia
 * smart contract for cryptographic proof of anchoring.
 */

const API = 'https://team10.theburkenator.com';

const ETHERSCAN_TX = 'https://sepolia.etherscan.io/tx/';

const getToken = () => localStorage.getItem('sm_token');

document.addEventListener('DOMContentLoaded', () => {
  const loggedIn = !!getToken();
  const warning  = document.getElementById('auth-warning');
  if (warning) warning.style.display = loggedIn ? 'none' : 'flex';

  document.getElementById('verify-form').addEventListener('submit', handleVerify);

  const idParam = new URLSearchParams(window.location.search).get('id');
  if (idParam) {
    document.getElementById('verify-msg-id').value = idParam;
    document.getElementById('verify-form').requestSubmit();
  }
});

async function handleVerify(e) {
  e.preventDefault();

  const msgId  = document.getElementById('verify-msg-id').value.trim();
  const btn    = document.getElementById('verify-btn');
  const errEl  = document.getElementById('verify-error');
  const result = document.getElementById('verify-result');

  if (!msgId) return;

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Verifying…';
  errEl.style.display = 'none';
  result.classList.remove('show');

  try {
    const headers = getToken() ? { Authorization: `Bearer ${getToken()}` } : {};

    const [msgRes, proofRes] = await Promise.all([
      fetch(`${API}/messages/${encodeURIComponent(msgId)}/download`,          { headers }),
      fetch(`${API}/messages/${encodeURIComponent(msgId)}/blockchain-proof`,  { headers }),
    ]);

    if (msgRes.status === 401) throw new Error('Authentication required — please sign in first.');
    if (msgRes.status === 403) throw new Error('You do not have permission to access this message.');
    if (msgRes.status === 404) throw new Error('Message not found, or it has been deleted.');
    if (!msgRes.ok)            throw new Error(`Server error (HTTP ${msgRes.status}).`);

    const msg   = await msgRes.json();
    const proof = proofRes.ok ? await proofRes.json() : null;

    renderResult({ msg, proof });

  } catch (err) {
    errEl.textContent    = err.message;
    errEl.style.display  = 'block';
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Verify Integrity';
  }
}

function renderResult({ msg, proof }) {
  const result = document.getElementById('verify-result');
  const banner = document.getElementById('result-banner');

  // ── Hash comparison (from blockchain-proof endpoint) ──────────────────────
  const storedHash   = proof?.stored_hash   ?? msg.integrity_hash ?? '';
  const computedHash = proof?.computed_hash ?? '';
  const hashMatch    = proof?.hash_match    ?? false;

  // ── Determine overall pass/fail ───────────────────────────────────────────
  // Primary: on-chain match (strongest proof — hash cannot be faked on Ethereum)
  // Fallback: local SQLite match (stored hash == freshly computed hash)
  const onChain       = proof?.on_chain;
  const onChainMatch  = proof?.on_chain_match;   // null = not yet on chain

  const fullyVerified = onChainMatch === true;   // on-chain AND matching
  const localVerified = hashMatch && onChainMatch === null;  // SQLite ok, tx pending
  const pass          = fullyVerified || localVerified;

  // Banner
  banner.className = `result-banner ${pass ? 'pass' : 'fail'}`;
  document.getElementById('result-icon').textContent  = pass ? '✓' : '✗';
  document.getElementById('result-title').textContent =
    fullyVerified ? 'Blockchain Verified' :
    localVerified ? 'Locally Verified (anchoring pending)' :
    'Integrity Check Failed';
  document.getElementById('result-subtitle').textContent =
    fullyVerified
      ? 'Hash matches the on-chain record — cryptographic proof of integrity.'
      : localVerified
        ? 'Ciphertext matches the stored hash. Ethereum anchoring in progress.'
        : storedHash
          ? 'Hash mismatch — the ciphertext may have been altered after recording.'
          : 'No integrity hash found for this message.';

  // Hash rows
  document.getElementById('hash-stored').textContent    = storedHash   || '(not present)';
  document.getElementById('hash-computed').textContent  = computedHash || '(unavailable)';
  document.getElementById('hash-stored').className   = `hash-value ${hashMatch ? 'match' : storedHash ? 'mismatch' : ''}`;
  document.getElementById('hash-computed').className = `hash-value ${hashMatch ? 'match' : storedHash ? 'mismatch' : ''}`;

  // ── Ethereum anchor section ───────────────────────────────────────────────
  const statusEl  = document.getElementById('chain-status');
  const detailDiv = document.getElementById('chain-detail-rows');

  if (!proof) {
    statusEl.textContent  = 'Unavailable (proof endpoint error)';
    statusEl.className    = 'hash-value';
    detailDiv.style.display = 'none';
  } else if (!proof.eth_tx_hash) {
    statusEl.textContent  = proof.has_chain_record
      ? 'Pending — transaction not yet submitted to Sepolia'
      : 'No blockchain record found';
    statusEl.className    = 'hash-value';
    detailDiv.style.display = 'none';
  } else if (!onChain?.exists) {
    statusEl.textContent  = 'Transaction submitted — hash not yet confirmed on-chain';
    statusEl.className    = 'hash-value';
    detailDiv.style.display = 'none';

    // Show the tx hash even if on-chain lookup failed
    detailDiv.style.display = 'block';
    _fillTxHash(proof.eth_tx_hash);
    document.getElementById('chain-onchain-hash').textContent = '(confirming…)';
    document.getElementById('chain-timestamp').textContent    = '(confirming…)';
    document.getElementById('chain-recorder').textContent     = '(confirming…)';
  } else {
    statusEl.textContent = fullyVerified ? 'Anchored on Sepolia ✓' : 'Anchored — hash mismatch ✗';
    statusEl.className   = `hash-value ${fullyVerified ? 'match' : 'mismatch'}`;
    detailDiv.style.display = 'block';

    _fillTxHash(proof.eth_tx_hash);
    document.getElementById('chain-onchain-hash').textContent =
      onChain.hash ?? '—';
    document.getElementById('chain-timestamp').textContent =
      onChain.timestamp
        ? new Date(onChain.timestamp * 1000).toLocaleString() + ' (UTC block time)'
        : '—';
    document.getElementById('chain-recorder').textContent =
      onChain.recorder ?? '—';
  }

  // ── Message metadata ──────────────────────────────────────────────────────
  document.getElementById('meta-msg-id').textContent    = msg.id;
  document.getElementById('meta-sender').textContent    = msg.sender_username ?? 'Unknown';
  document.getElementById('meta-read').textContent      = msg.is_read ? 'Yes' : 'No';
  document.getElementById('meta-timestamp').textContent =
    new Date(msg.created_at + (msg.created_at.endsWith('Z') ? '' : 'Z')).toLocaleString();
  document.getElementById('meta-subject').textContent   = msg.subject ?? '(no subject)';

  const aadEl = document.getElementById('meta-aad');
  aadEl.textContent = msg.associated_data ?? '(none)';

  result.classList.add('show');
  result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function _fillTxHash(txHash) {
  const el = document.getElementById('chain-tx-hash');
  const link = document.createElement('a');
  link.href   = ETHERSCAN_TX + txHash;
  link.target = '_blank';
  link.rel    = 'noopener noreferrer';
  link.textContent = txHash;
  link.style.wordBreak = 'break-all';
  el.textContent = '';
  el.appendChild(link);
}
