/**
 * chat.js — Inbox, sent box, and compose for chat.html
 *
 * Encryption flow (send):
 *   1. Fetch recipient's SPKI public key from GET /users/{username}
 *   2. encryptMessage(plaintext, recipientPublicKeyB64, senderPrivKey) → {ciphertext, nonce, encryptedKey}
 *      HPKE Mode_Auth: dh1=X25519(ek_priv,recip_pub), dh2=X25519(sender_priv,recip_pub)
 *   3. POST /messages/send with {ciphertext, nonce, encrypted_key: ek_pub_32B, ...}
 *
 * Decryption flow (receive):
 *   1. GET /messages/{id}/download → {ciphertext: storedBlob, nonce, encrypted_key: ek_pub_32B}
 *      storedBlob = base64(nonce_12B ‖ ciphertext_with_tag)
 *   2. GET /users/{sender_username} → senderPublicKeyB64
 *   3. Extract ciphertext_with_tag: base64decode(storedBlob)[12:]
 *   4. decryptMessage(ctB64, nonceB64, encryptedKeyB64, privKey, senderPublicKeyB64) → plaintext
 */

import { encryptMessage, decryptMessage, loadPrivateKey, b64ToBuffer, bufToB64 } from './crypto.js';

const API = 'http://localhost:8000';

const getToken    = () => localStorage.getItem('sm_token');
const getUsername = () => localStorage.getItem('sm_username');
const authHeaders = () => ({ Authorization: `Bearer ${getToken()}` });

function authFetch(url, opts = {}) {
  return fetch(url, {
    ...opts,
    headers: { ...authHeaders(), ...(opts.headers ?? {}) },
  });
}

// ---------- Bootstrap ---------------------------------------------------------

let allUsers = [];

document.addEventListener('DOMContentLoaded', async () => {
  if (!getToken()) { window.location.href = 'index.html'; return; }

  const user = getUsername();
  document.getElementById('username-display').textContent = user ?? '';
  document.getElementById('user-avatar').textContent      = (user?.[0] ?? '?').toUpperCase();

  document.getElementById('logout-btn').addEventListener('click', doLogout);
  document.getElementById('new-msg-btn').addEventListener('click', () => switchTab('compose'));
  document.getElementById('back-btn').addEventListener('click', () => {
    showPanel('empty');
    document.querySelectorAll('.message-item').forEach(el => el.classList.remove('active'));
  });
  document.getElementById('decrypt-btn').addEventListener('click', handleDecrypt);
  document.getElementById('compose-form').addEventListener('submit', handleSend);

  document.querySelectorAll('.nav-tab').forEach(tab =>
    tab.addEventListener('click', () => switchTab(tab.dataset.tab))
  );

  const recipInput = document.getElementById('recipient');
  recipInput.addEventListener('input',  onRecipientInput);
  recipInput.addEventListener('blur',   () => {
    setTimeout(() => { document.getElementById('recipient-suggestions').innerHTML = ''; }, 160);
  });

  await loadUsers();
  switchTab('inbox');
});

// ---------- Tab / panel switching --------------------------------------------

function switchTab(tab) {
  document.querySelectorAll('.nav-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.tab === tab)
  );
  if (tab === 'compose') {
    showPanel('compose');
  } else {
    showPanel('empty');
    if (tab === 'inbox') loadInbox();
    else if (tab === 'sent') loadSent();
  }
}

function showPanel(which) {
  document.getElementById('compose-panel').classList.toggle('hidden', which !== 'compose');
  document.getElementById('message-view-panel').classList.toggle('hidden', which !== 'message-view');
  document.getElementById('empty-panel').classList.toggle('hidden', which !== 'empty');
}

// ---------- Load users (for autocomplete) ------------------------------------

async function loadUsers() {
  try {
    const res = await fetch(`${API}/users?limit=500`);
    allUsers  = res.ok ? await res.json() : [];
  } catch { allUsers = []; }
}

// ---------- Inbox / Sent -----------------------------------------------------

async function loadInbox() {
  renderListLoading();
  try {
    const res = await authFetch(`${API}/messages/inbox?limit=100`);
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    if (!res.ok) throw new Error();
    const items = await res.json();

    const unread = items.filter(m => !m.is_read).length;
    const badge  = document.getElementById('unread-badge');
    if (badge) {
      badge.textContent     = unread || '';
      badge.style.display   = unread ? 'inline-flex' : 'none';
    }

    renderList(items, 'inbox');
  } catch {
    renderListError('Failed to load inbox.');
  }
}

async function loadSent() {
  renderListLoading();
  try {
    const res = await authFetch(`${API}/messages/sent?limit=100`);
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    if (!res.ok) throw new Error();
    renderList(await res.json(), 'sent');
  } catch {
    renderListError('Failed to load sent messages.');
  }
}

function renderListLoading() {
  document.getElementById('message-list').innerHTML =
    '<div class="message-list-loading">Loading…</div>';
}

function renderListError(msg) {
  document.getElementById('message-list').innerHTML =
    `<div class="message-list-empty">${esc(msg)}</div>`;
}

function renderList(items, mode) {
  const list = document.getElementById('message-list');
  if (!items.length) {
    list.innerHTML = `<div class="message-list-empty">${
      mode === 'inbox' ? 'Your inbox is empty.' : 'No sent messages.'
    }</div>`;
    return;
  }

  list.innerHTML = items.map(item => {
    const label   = mode === 'inbox'
      ? (item.sender_username ?? 'Unknown sender')
      : 'Sent';  // recipient_username not returned by the sent-list endpoint
    const subject = item.subject ?? '(no subject)';
    const unread  = mode === 'inbox' && !item.is_read ? ' unread' : '';
    return `<div class="message-item${unread}" data-id="${item.id}" data-mode="${mode}">
      <div class="message-item-header">
        <span class="message-item-from">${esc(label)}</span>
        <span class="message-item-date">${fmtDate(item.created_at)}</span>
      </div>
      <div class="message-item-subject">${esc(subject)}</div>
    </div>`;
  }).join('');

  list.querySelectorAll('.message-item').forEach(el => {
    el.addEventListener('click', () => openMessage(+el.dataset.id, el.dataset.mode, el));
  });
}

// ---------- Message detail ---------------------------------------------------

let _currentDownload = null;

async function openMessage(id, mode, el) {
  document.querySelectorAll('.message-item').forEach(e => e.classList.remove('active'));
  el.classList.add('active');
  el.classList.remove('unread');

  _currentDownload = null;

  showPanel('message-view');

  // Reset view
  const subjectEl = document.getElementById('msg-subject');
  const fromEl    = document.getElementById('msg-from');
  const dateEl    = document.getElementById('msg-date');
  const previewEl = document.getElementById('msg-ciphertext-preview');
  const plainEl   = document.getElementById('msg-plaintext');
  const errEl     = document.getElementById('msg-decrypt-error');
  const decBtn    = document.getElementById('decrypt-btn');
  const intgEl    = document.getElementById('msg-integrity');

  subjectEl.textContent = '…';
  fromEl.innerHTML = '';
  dateEl.textContent = '';
  previewEl.textContent = '';
  previewEl.classList.remove('hidden');
  plainEl.textContent = '';
  plainEl.classList.add('hidden');
  errEl.classList.remove('alert-error'); errEl.textContent = ''; errEl.style.display = 'none';
  decBtn.classList.remove('hidden');
  decBtn.disabled = false;
  decBtn.innerHTML = '🔓 Decrypt Message';
  if (intgEl) intgEl.textContent = '';

  try {
    const res = await authFetch(`${API}/messages/${id}/download`);
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail ?? 'Could not load message.');
    }
    const msg = await res.json();
    _currentDownload = msg;

    subjectEl.textContent = msg.subject ?? '(no subject)';
    fromEl.innerHTML      = `<strong>From:</strong> ${esc(msg.sender_username ?? 'Unknown')}`;
    dateEl.textContent    = new Date(msg.created_at + (msg.created_at.endsWith('Z') ? '' : 'Z')).toLocaleString();
    previewEl.textContent = msg.ciphertext.slice(0, 140) + '…';

    if (intgEl && msg.integrity_hash) {
      intgEl.textContent = '🔒 Integrity hash on record';
    }

    if (mode === 'sent') {
      decBtn.classList.add('hidden');
      plainEl.textContent = '(Sent messages are encrypted for the recipient — decryption not available.)';
      plainEl.classList.remove('hidden');
      previewEl.classList.add('hidden');
    }

  } catch (err) {
    showMsgError(errEl, err.message);
  }
}

async function handleDecrypt() {
  if (!_currentDownload) return;
  const msg   = _currentDownload;
  const btn   = document.getElementById('decrypt-btn');
  const errEl = document.getElementById('msg-decrypt-error');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Decrypting…';
  errEl.style.display = 'none';

  try {
    const user    = getUsername();
    const privKey = await loadPrivateKey(user);
    if (!privKey) throw new Error(
      'No private key found on this device. ' +
      'Sign out and sign back in to generate a new key pair.'
    );
    if (!msg.encrypted_key) throw new Error(
      'This message has no encapsulated key — it may not have been encrypted for you.'
    );
    if (!msg.sender_username) throw new Error(
      'Sender identity unknown — cannot perform Mode_Auth decryption.'
    );

    // Fetch sender's public key for HPKE Mode_Auth authentication (dh2 computation)
    const senderRes = await fetch(`${API}/users/${encodeURIComponent(msg.sender_username)}`);
    if (!senderRes.ok) throw new Error(`Could not retrieve sender's public key.`);
    const senderUser = await senderRes.json();
    if (!senderUser.public_key) throw new Error(
      `Sender "${msg.sender_username}" has no registered public key.`
    );

    // Download response `ciphertext` = base64(nonce_12B ‖ ct_with_tag)
    // Extract ct_with_tag by skipping the 12-byte nonce prefix
    const raw   = new Uint8Array(b64ToBuffer(msg.ciphertext));
    const ctB64 = bufToB64(raw.slice(12));

    const plaintext = await decryptMessage(
      ctB64, msg.nonce, msg.encrypted_key, privKey, senderUser.public_key
    );

    document.getElementById('msg-ciphertext-preview').classList.add('hidden');
    const plainEl = document.getElementById('msg-plaintext');
    plainEl.textContent = plaintext;
    plainEl.classList.remove('hidden');
    btn.classList.add('hidden');

  } catch (err) {
    showMsgError(errEl, `Decryption failed: ${err.message}`);
    btn.disabled = false;
    btn.innerHTML = '🔓 Decrypt Message';
  }
}

// ---------- Compose ----------------------------------------------------------

function onRecipientInput() {
  const val = this.value.trim().toLowerCase();
  const box = document.getElementById('recipient-suggestions');
  if (!val) { box.innerHTML = ''; return; }

  const me      = getUsername();
  const matches = allUsers
    .filter(u => u.username !== me && u.username.toLowerCase().includes(val))
    .slice(0, 7);

  box.innerHTML = matches.map(u =>
    `<div class="suggestion-item" data-username="${esc(u.username)}" data-pubkey="${esc(u.public_key ?? '')}">
      <div>${esc(u.username)}</div>
      ${u.public_key
        ? '<div class="suggestion-key">🔑 Public key registered</div>'
        : '<div class="suggestion-key" style="color:var(--red-500)">⚠ No public key — cannot encrypt</div>'
      }
    </div>`
  ).join('');

  box.querySelectorAll('.suggestion-item').forEach(item => {
    item.addEventListener('mousedown', () => {
      document.getElementById('recipient').value = item.dataset.username;
      box.innerHTML = '';
    });
  });
}

async function handleSend(e) {
  e.preventDefault();
  const btn     = document.getElementById('send-btn');
  const statusEl = document.getElementById('compose-status');

  const recipUsername = document.getElementById('recipient').value.trim();
  const subject       = document.getElementById('subject').value.trim();
  const body          = document.getElementById('message-body').value.trim();

  if (!recipUsername) return showStatus(statusEl, 'Please enter a recipient.', 'error');
  if (!body)          return showStatus(statusEl, 'Message body cannot be empty.', 'error');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Encrypting…';
  statusEl.style.display = 'none';

  try {
    // Fetch recipient's public key
    const userRes = await fetch(`${API}/users/${encodeURIComponent(recipUsername)}`);
    if (!userRes.ok) throw new Error(`User "${recipUsername}" not found.`);
    const recipient = await userRes.json();
    if (!recipient.public_key) throw new Error(
      `${recipUsername} has no registered public key and cannot receive encrypted messages.`
    );

    const senderPrivKey = await loadPrivateKey(getUsername());
    if (!senderPrivKey) throw new Error('No private key found on this device. Please sign out and sign in again.');

    const { ciphertext, nonce, encryptedKey } = await encryptMessage(body, recipient.public_key, senderPrivKey);

    btn.innerHTML = '<span class="spinner"></span> Sending…';

    const sendRes = await authFetch(`${API}/messages/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipient_username: recipUsername,
        ciphertext,
        nonce,
        encrypted_key:    encryptedKey,
        subject:          subject || null,
        associated_data:  null,
      }),
    });

    const result = await sendRes.json();
    if (!sendRes.ok) throw new Error(result.detail ?? 'Send failed.');

    showStatus(statusEl, '✓ Message sent and encrypted.', 'success');
    document.getElementById('compose-form').reset();
    setTimeout(() => switchTab('sent'), 1600);

  } catch (err) {
    showStatus(statusEl, err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🔒 Send Encrypted';
  }
}

// ---------- Logout -----------------------------------------------------------

async function doLogout() {
  const refresh = localStorage.getItem('sm_refresh_token');
  if (refresh) {
    await authFetch(`${API}/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refresh }),
    }).catch(() => {});
  }
  clearSession();
  window.location.href = 'index.html';
}

function clearSession() {
  ['sm_token', 'sm_refresh_token', 'sm_username'].forEach(k => localStorage.removeItem(k));
}

// ---------- Utilities --------------------------------------------------------

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtDate(iso) {
  if (!iso) return '';
  const d    = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'));
  const now  = new Date();
  const diff = now - d;
  if (diff < 60_000)     return 'just now';
  if (diff < 3_600_000)  return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function showStatus(el, msg, type) {
  el.textContent   = msg;
  el.className     = `alert alert-${type}`;
  el.style.display = 'block';
}

function showMsgError(el, msg) {
  el.textContent  = msg;
  el.className    = 'alert alert-error';
  el.style.display = 'block';
}
