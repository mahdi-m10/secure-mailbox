/**
 * verify.js — Blockchain integrity verification for verify.html
 *
 * How integrity_hash is computed by the backend (messages.py):
 *   stored_blob    = base64(nonce_12B ‖ ciphertext_with_tag)   [the `ciphertext` DB column]
 *   integrity_hash = sha256(stored_blob.encode()).hexdigest()
 *
 * i.e. SHA-256 of the UTF-8 bytes of the base64 string.
 * The download endpoint returns `ciphertext` = that exact stored_blob.
 * So: sha256(TextEncoder.encode(msg.ciphertext)) must equal integrity_hash.
 */

import { sha256Hex } from './crypto.js';

const API = 'https://team10.theburkenator.com';

const getToken = () => localStorage.getItem('sm_token');

document.addEventListener('DOMContentLoaded', () => {
  const loggedIn = !!getToken();
  const warning  = document.getElementById('auth-warning');
  if (warning) warning.style.display = loggedIn ? 'none' : 'flex';

  document.getElementById('verify-form').addEventListener('submit', handleVerify);
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
    const res = await fetch(`${API}/messages/${encodeURIComponent(msgId)}/download`, { headers });

    if (res.status === 401) throw new Error('Authentication required — please sign in first.');
    if (res.status === 403) throw new Error('You do not have permission to access this message.');
    if (res.status === 404) throw new Error('Message not found, or it has been deleted.');
    if (!res.ok)            throw new Error(`Server error (HTTP ${res.status}).`);

    const msg = await res.json();

    // Re-compute integrity hash the same way the backend does:
    //   sha256( utf8_bytes( stored_blob_base64_string ) )
    const computedHash = await sha256Hex(msg.ciphertext);
    const storedHash   = msg.integrity_hash ?? '';
    const pass         = storedHash.length > 0 && computedHash === storedHash;

    renderResult({ msg, computedHash, storedHash, pass });

  } catch (err) {
    errEl.textContent    = err.message;
    errEl.style.display  = 'block';
  } finally {
    btn.disabled  = false;
    btn.textContent = 'Verify Integrity';
  }
}

function renderResult({ msg, computedHash, storedHash, pass }) {
  const result = document.getElementById('verify-result');
  const banner = document.getElementById('result-banner');

  // Banner
  banner.className = `result-banner ${pass ? 'pass' : 'fail'}`;
  document.getElementById('result-icon').textContent     = pass ? '✓' : '✗';
  document.getElementById('result-title').textContent    = pass ? 'Integrity Verified' : 'Integrity Check Failed';
  document.getElementById('result-subtitle').textContent = pass
    ? 'The stored ciphertext matches its recorded hash — no tampering detected.'
    : storedHash
      ? 'Hash mismatch — the stored ciphertext may have been modified after it was recorded.'
      : 'No integrity hash found for this message.';

  // Hash comparison
  document.getElementById('hash-stored').textContent    = storedHash   || '(not present)';
  document.getElementById('hash-computed').textContent  = computedHash;
  document.getElementById('hash-stored').className   = `hash-value ${pass ? 'match' : storedHash ? 'mismatch' : ''}`;
  document.getElementById('hash-computed').className = `hash-value ${pass ? 'match' : storedHash ? 'mismatch' : ''}`;

  // Message metadata
  document.getElementById('meta-msg-id').textContent    = msg.id;
  document.getElementById('meta-sender').textContent    = msg.sender_username ?? 'Unknown';
  document.getElementById('meta-read').textContent      = msg.is_read ? 'Yes' : 'No';
  document.getElementById('meta-timestamp').textContent =
    new Date(msg.created_at + (msg.created_at.endsWith('Z') ? '' : 'Z')).toLocaleString();
  document.getElementById('meta-subject').textContent   = msg.subject ?? '(no subject)';

  // Canonical AAD (informational)
  const aadEl = document.getElementById('meta-aad');
  aadEl.textContent = msg.associated_data ?? '(none)';

  result.classList.add('show');
  result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
