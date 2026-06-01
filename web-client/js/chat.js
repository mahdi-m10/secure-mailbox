/**
 * chat.js — WhatsApp-style chat UI for chat.html
 *
 * Encryption flow (send / reply):
 *   1. Fetch recipient's SPKI public key from GET /users/{username}
 *   2. encryptMessage(plaintext, recipientPublicKeyB64, senderPrivKey)
 *      HPKE Mode_Auth: dh1=X25519(ek_priv,recip_pub), dh2=X25519(sender_priv,recip_pub)
 *   3. POST /messages/send with {ciphertext, nonce, encrypted_key, ...}
 *
 * Decryption flow (inline per bubble):
 *   1. GET /messages/{id}/download → full message blob
 *   2. GET /users/{sender_username} → sender public key (for Mode_Auth auth)
 *   3. Extract ct_with_tag: base64decode(storedBlob)[12:]
 *   4. decryptMessage(ctB64, nonce, encryptedKey, privKey, senderPubKey) → plaintext
 */

import { encryptMessage, decryptMessage, loadPrivateKey, b64ToBuffer, bufToB64 } from './crypto.js';

const API = 'https://team10.theburkenator.com';

const getToken    = () => localStorage.getItem('sm_token');
const getUsername = () => localStorage.getItem('sm_username');
const authHeaders = () => ({ Authorization: `Bearer ${getToken()}` });

function authFetch(url, opts = {}) {
  return fetch(url, {
    ...opts,
    headers: { ...authHeaders(), ...(opts.headers ?? {}) },
  });
}

// ── State ──────────────────────────────────────────────────────────────────────

let allInboxMessages = [];   // full inbox, loaded once
let allSentMessages  = [];   // full sent box, loaded once
let currentSender    = null; // sender username of open conversation
let allUsers         = [];   // user list for autocomplete

// ── Bootstrap ──────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  if (!getToken()) { window.location.href = 'index.html'; return; }

  const user = getUsername();
  document.getElementById('username-display').textContent = user ?? '';
  document.getElementById('user-avatar').textContent      = (user?.[0] ?? '?').toUpperCase();

  // Wire up static event listeners
  document.getElementById('logout-btn').addEventListener('click', doLogout);
  document.getElementById('new-msg-btn').addEventListener('click', showCompose);
  document.getElementById('new-msg-empty-btn').addEventListener('click', showCompose);

  document.getElementById('back-btn').addEventListener('click', () => {
    currentSender = null;
    document.querySelectorAll('.convo-item').forEach(el => el.classList.remove('active'));
    showPanel('empty');
  });

  document.getElementById('reply-send-btn').addEventListener('click', handleReply);
  document.getElementById('compose-form').addEventListener('submit', handleSend);

  const recipInput = document.getElementById('recipient');
  recipInput.addEventListener('input', onRecipientInput);
  recipInput.addEventListener('blur', () => {
    setTimeout(() => { document.getElementById('recipient-suggestions').innerHTML = ''; }, 160);
  });

  setupAutoResize(document.getElementById('reply-body'));
  setupAutoResize(document.getElementById('message-body'));

  document.getElementById('reply-body').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleReply(); }
  });
  document.getElementById('message-body').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); document.getElementById('send-btn').click(); }
  });

  // Render static Lucide icons in the base HTML
  lucide.createIcons();

  await Promise.all([loadUsers(), loadInbox(), loadSent()]);
  renderSidebar();
});

// ── Panel switching ────────────────────────────────────────────────────────────

function showPanel(which) {
  document.getElementById('conversation-panel').classList.toggle('hidden', which !== 'conversation');
  document.getElementById('compose-panel').classList.toggle('hidden',      which !== 'compose');
  document.getElementById('empty-panel').classList.toggle('hidden',        which !== 'empty');
}

function showCompose() {
  currentSender = null;
  document.querySelectorAll('.convo-item').forEach(el => el.classList.remove('active'));

  document.getElementById('recipient').value   = '';
  document.getElementById('message-body').value = '';
  document.getElementById('message-body').style.height = 'auto';
  document.getElementById('compose-thread').innerHTML  = composePlaceholderHTML();

  const statusEl = document.getElementById('compose-status');
  statusEl.style.display = 'none';

  showPanel('compose');
  lucide.createIcons();
  document.getElementById('recipient').focus();
}

function composePlaceholderHTML() {
  return `<div class="compose-hint">
    <i data-lucide="message-square-plus"></i>
    <p>Select a recipient above to start an encrypted conversation.</p>
  </div>`;
}

// ── Load users (autocomplete) ──────────────────────────────────────────────────

async function loadUsers() {
  try {
    const res = await fetch(`${API}/users?limit=500`);
    allUsers  = res.ok ? await res.json() : [];
  } catch { allUsers = []; }
}

// ── Inbox ──────────────────────────────────────────────────────────────────────

async function loadInbox() {
  document.getElementById('message-list').innerHTML =
    '<div class="list-placeholder"><span class="spinner"></span> Loading…</div>';

  try {
    const res = await authFetch(`${API}/messages/inbox?limit=100`);
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    if (!res.ok) throw new Error();
    allInboxMessages = await res.json();

    const unread = allInboxMessages.filter(m => !m.is_read).length;
    const badge  = document.getElementById('unread-badge');
    badge.textContent   = unread || '';
    badge.style.display = unread ? 'inline-flex' : 'none';
  } catch {
    document.getElementById('message-list').innerHTML =
      '<div class="list-placeholder">Failed to load messages.</div>';
  }
}

async function loadSent() {
  try {
    const res = await authFetch(`${API}/messages/sent?limit=100`);
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    allSentMessages = res.ok ? await res.json() : [];
    console.log('[loadSent] raw response:', allSentMessages);
  } catch { allSentMessages = []; }
}

// ── Sidebar ────────────────────────────────────────────────────────────────────

function renderSidebar() {
  const list = document.getElementById('message-list');

  if (!allInboxMessages.length && !allSentMessages.length) {
    list.innerHTML = '<div class="list-placeholder">No messages yet.</div>';
    return;
  }

  // Build a contact map keyed by username; keep the most-recent message per contact
  const map = new Map();

  for (const msg of allInboxMessages) {
    const contact = msg.sender_username ?? 'Unknown';
    if (!map.has(contact) || msg.created_at > map.get(contact).created_at) {
      map.set(contact, msg);
    }
  }

  for (const msg of allSentMessages) {
    const contact = msg.recipient_username;
    if (!contact) continue;
    if (!map.has(contact) || msg.created_at > map.get(contact).created_at) {
      map.set(contact, msg);
    }
  }

  const convos = [...map.entries()]
    .sort((a, b) => new Date(b[1].created_at) - new Date(a[1].created_at));

  list.innerHTML = convos.map(([sender, msg]) => {
    const unreadCount = allInboxMessages.filter(
      m => m.sender_username === sender && !m.is_read
    ).length;
    const initial = (sender?.[0] ?? '?').toUpperCase();
    return `<div class="convo-item" data-sender="${esc(sender)}">
      <div class="convo-avatar">${esc(initial)}</div>
      <div class="convo-body">
        <div class="convo-row">
          <span class="convo-name">${esc(sender)}</span>
          <span class="convo-time">${fmtDate(msg.created_at)}</span>
        </div>
        <div class="convo-preview">
          <i data-lucide="lock" style="width:11px;height:11px;flex-shrink:0"></i>
          <span>Encrypted message</span>
          ${unreadCount ? `<span class="convo-unread">${unreadCount}</span>` : ''}
        </div>
      </div>
    </div>`;
  }).join('');

  list.querySelectorAll('.convo-item').forEach(el => {
    el.addEventListener('click', () => openConversation(el.dataset.sender, el));
  });

  lucide.createIcons();
}

// ── Conversation view ──────────────────────────────────────────────────────────

function openConversation(senderName, el) {
  currentSender = senderName;

  document.querySelectorAll('.convo-item').forEach(e => e.classList.remove('active'));
  el.classList.add('active');

  const initial = (senderName?.[0] ?? '?').toUpperCase();
  document.getElementById('chat-header-avatar').textContent = initial;
  document.getElementById('chat-contact-name').textContent  = senderName;

  // Received from this person
  const received = allInboxMessages
    .filter(m => m.sender_username === senderName)
    .map(m => ({ ...m, _dir: 'in' }));

  // Sent to this person — requires recipient_username in the sent API response
  const sent = allSentMessages
    .filter(m => m.recipient_username === senderName)
    .map(m => ({ ...m, _dir: 'out' }));

  // Merge and sort chronologically
  const merged = [...received, ...sent]
    .sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

  const thread = document.getElementById('chat-thread');
  thread.innerHTML = merged.map(m =>
    m._dir === 'in' ? renderBubble(m) : renderSentHistoryBubble(m)
  ).join('');
  lucide.createIcons();

  // Decrypt listeners for received bubbles
  thread.querySelectorAll('.b-decrypt-btn').forEach(btn => {
    btn.addEventListener('click', () => handleInlineDecrypt(+btn.dataset.id, btn));
  });

  // Delete / revoke listeners for sent history bubbles
  thread.querySelectorAll('.bubble-wrap.out[data-msg-id]').forEach(wrap => {
    const msgId = +wrap.dataset.msgId;
    wrap.querySelector('.b-delete-btn')
      ?.addEventListener('click', () => handleDeleteMessage(msgId, wrap));
    wrap.querySelector('.b-revoke-btn')
      ?.addEventListener('click', () => handleRevokeMessage(msgId, wrap));
  });

  // Reset reply bar
  const replyBody = document.getElementById('reply-body');
  replyBody.value = '';
  replyBody.style.height = 'auto';
  document.getElementById('reply-status').style.display = 'none';

  showPanel('conversation');
  thread.scrollTop = thread.scrollHeight;
  replyBody.focus();
}

function renderBubble(msg) {
  const id      = msg.id;
  const preview = esc((msg.ciphertext ?? '').slice(0, 80)) + '…';
  return `<div class="bubble-wrap in">
    <div class="bubble">
      <div class="b-cipher" id="bc-${id}">
        <div class="b-cipher-label">
          <i data-lucide="lock-keyhole" style="width:12px;height:12px"></i>
          Encrypted message
        </div>
        <div class="b-cipher-preview">${preview}</div>
        <div class="b-cipher-actions">
          <button class="b-decrypt-btn" data-id="${id}">
            <i data-lucide="unlock-keyhole" style="width:12px;height:12px"></i>
            Decrypt
          </button>
          <a href="verify.html?id=${id}" class="b-verify-link">
            <i data-lucide="shield" style="width:11px;height:11px"></i>
            Verify
          </a>
        </div>
      </div>
      <div class="b-plain hidden" id="bp-${id}"></div>
      <div class="b-error hidden" id="be-${id}"></div>
    </div>
    <div class="b-time">${fmtDate(msg.created_at)}</div>
  </div>`;
}

// Sent message loaded from history (ciphertext only — plaintext not available).
// Exception: if _plaintext was stashed at send time (session-only), show it directly.
function renderSentHistoryBubble(msg) {
  if (msg._plaintext != null) return renderSentBubble(msg._plaintext, msg.id);
  const id = msg.id;
  return `<div class="bubble-wrap out" data-msg-id="${id}">
    <div class="bubble">
      <div class="b-cipher-label">
        <i data-lucide="lock-keyhole" style="width:12px;height:12px"></i>
        Sent encrypted
      </div>
    </div>
    <div class="b-sent-actions">
      <button class="b-action-btn b-revoke-btn" title="Revoke recipient access">
        <i data-lucide="shield-off" style="width:12px;height:12px"></i>
        Revoke
      </button>
      <button class="b-action-btn b-delete-btn" title="Delete message">
        <i data-lucide="trash-2" style="width:12px;height:12px"></i>
        Delete
      </button>
    </div>
    <div class="b-time">${fmtDate(msg.created_at)}</div>
  </div>`;
}

function renderSentBubble(text, msgId) {
  const actions = msgId ? `
    <div class="b-sent-actions">
      <button class="b-action-btn b-revoke-btn" title="Revoke recipient access">
        <i data-lucide="shield-off" style="width:12px;height:12px"></i>
        Revoke
      </button>
      <button class="b-action-btn b-delete-btn" title="Delete message">
        <i data-lucide="trash-2" style="width:12px;height:12px"></i>
        Delete
      </button>
    </div>` : '';
  return `<div class="bubble-wrap out">
    <div class="bubble">
      <div class="b-plain">${esc(text)}</div>
    </div>
    ${actions}
    <div class="b-time">just now</div>
  </div>`;
}

function appendSentBubble(threadId, text, msgId) {
  const thread = document.getElementById(threadId);
  thread.insertAdjacentHTML('beforeend', renderSentBubble(text, msgId));

  const wrap = thread.lastElementChild;
  lucide.createIcons();

  if (msgId) {
    wrap.querySelector('.b-delete-btn')
      ?.addEventListener('click', () => handleDeleteMessage(msgId, wrap));
    wrap.querySelector('.b-revoke-btn')
      ?.addEventListener('click', () => handleRevokeMessage(msgId, wrap));
  }

  thread.scrollTop = thread.scrollHeight;
}

// ── Delete / Revoke ────────────────────────────────────────────────────────────

async function handleDeleteMessage(msgId, bubbleWrap) {
  if (!confirm('Delete this message? This cannot be undone.')) return;

  try {
    const res = await authFetch(`${API}/messages/${msgId}`, { method: 'DELETE' });
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail ?? 'Delete failed.');
    }
    // Fade out then remove from DOM
    bubbleWrap.classList.add('deleting');
    bubbleWrap.addEventListener('animationend', () => bubbleWrap.remove(), { once: true });
  } catch (err) {
    alert(`Could not delete: ${err.message}`);
  }
}

async function handleRevokeMessage(msgId, bubbleWrap) {
  try {
    const res = await authFetch(`${API}/messages/${msgId}/revoke`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({}),   // empty body → recipient_username=None → full revocation
    });
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail ?? 'Revoke failed.');
    }
    // Replace bubble content with a revoked indicator; remove action buttons
    bubbleWrap.querySelector('.bubble').innerHTML =
      `<div class="b-revoked-note">
        <i data-lucide="shield-off" style="width:13px;height:13px"></i>
        Access revoked — recipients can no longer decrypt this message.
      </div>`;
    bubbleWrap.querySelector('.b-sent-actions')?.remove();
    lucide.createIcons();
  } catch (err) {
    alert(`Could not revoke: ${err.message}`);
  }
}

// ── Inline decrypt ─────────────────────────────────────────────────────────────

async function handleInlineDecrypt(msgId, btn) {
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';

  const errEl = document.getElementById(`be-${msgId}`);
  errEl.classList.add('hidden');

  try {
    const res = await authFetch(`${API}/messages/${msgId}/download`);
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail ?? 'Could not load message.');
    }
    const msg = await res.json();

    const user    = getUsername();
    const privKey = await loadPrivateKey(user);
    if (!privKey) throw new Error(
      'No private key found on this device. Sign out and sign back in to generate a new key pair.'
    );
    if (!msg.encrypted_key) throw new Error(
      'This message has no encapsulated key — it may not have been encrypted for you.'
    );
    if (!msg.sender_username) throw new Error(
      'Sender identity unknown — cannot perform authenticated decryption.'
    );

    // Fetch sender public key for HPKE Mode_Auth (dh2 computation)
    const senderRes = await fetch(`${API}/users/${encodeURIComponent(msg.sender_username)}`);
    if (!senderRes.ok) throw new Error(`Could not retrieve sender's public key.`);
    const senderUser = await senderRes.json();
    if (!senderUser.public_key) throw new Error(
      `Sender "${msg.sender_username}" has no registered public key.`
    );

    // storedBlob = base64(nonce_12B ‖ ciphertext_with_tag); extract ct_with_tag
    const raw   = new Uint8Array(b64ToBuffer(msg.ciphertext));
    const ctB64 = bufToB64(raw.slice(12));

    const plaintext = await decryptMessage(
      ctB64, msg.nonce, msg.encrypted_key, privKey, senderUser.public_key
    );

    document.getElementById(`bc-${msgId}`).classList.add('hidden');
    const plainEl = document.getElementById(`bp-${msgId}`);
    plainEl.textContent = plaintext;
    plainEl.classList.remove('hidden');

  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="unlock-keyhole" style="width:12px;height:12px"></i> Retry';
    lucide.createIcons();
  }
}

// ── Reply (conversation panel) ─────────────────────────────────────────────────

async function handleReply() {
  if (!currentSender) return;

  const btn      = document.getElementById('reply-send-btn');
  const textarea = document.getElementById('reply-body');
  const statusEl = document.getElementById('reply-status');
  const body     = textarea.value.trim();
  if (!body) return;

  btn.disabled = true;
  statusEl.style.display = 'none';

  try {
    const userRes = await fetch(`${API}/users/${encodeURIComponent(currentSender)}`);
    if (!userRes.ok) throw new Error(`User "${currentSender}" not found.`);
    const recipient = await userRes.json();
    if (!recipient.public_key) throw new Error(
      `${currentSender} has no registered public key.`
    );

    const senderPrivKey = await loadPrivateKey(getUsername());
    if (!senderPrivKey) throw new Error(
      'No private key found on this device. Please sign out and sign in again.'
    );

    const { ciphertext, nonce, encryptedKey } = await encryptMessage(
      body, recipient.public_key, senderPrivKey
    );

    const sendRes = await authFetch(`${API}/messages/send`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        recipient_username: currentSender,
        ciphertext,
        nonce,
        encrypted_key:   encryptedKey,
        subject:         null,
        associated_data: null,
      }),
    });

    const result = await sendRes.json();
    if (!sendRes.ok) throw new Error(result.detail ?? 'Send failed.');

    textarea.value = '';
    textarea.style.height = 'auto';
    appendSentBubble('chat-thread', body, result.id);

  } catch (err) {
    showStatus(statusEl, err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

// ── Compose send ───────────────────────────────────────────────────────────────

async function handleSend(e) {
  e.preventDefault();

  const btn           = document.getElementById('send-btn');
  const statusEl      = document.getElementById('compose-status');
  const recipUsername = document.getElementById('recipient').value.trim();
  const body          = document.getElementById('message-body').value.trim();

  if (!recipUsername) return showStatus(statusEl, 'Please enter a recipient.', 'error');
  if (!body)          return showStatus(statusEl, 'Message body cannot be empty.', 'error');

  btn.disabled = true;
  statusEl.style.display = 'none';

  try {
    const userRes = await fetch(`${API}/users/${encodeURIComponent(recipUsername)}`);
    if (!userRes.ok) throw new Error(`User "${recipUsername}" not found.`);
    const recipient = await userRes.json();
    if (!recipient.public_key) throw new Error(
      `${recipUsername} has no registered public key and cannot receive encrypted messages.`
    );

    const senderPrivKey = await loadPrivateKey(getUsername());
    if (!senderPrivKey) throw new Error(
      'No private key found on this device. Please sign out and sign in again.'
    );

    const { ciphertext, nonce, encryptedKey } = await encryptMessage(
      body, recipient.public_key, senderPrivKey
    );

    const sendRes = await authFetch(`${API}/messages/send`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        recipient_username: recipUsername,
        ciphertext,
        nonce,
        encrypted_key:   encryptedKey,
        subject:         null,
        associated_data: null,
      }),
    });

    const result = await sendRes.json();
    if (!sendRes.ok) throw new Error(result.detail ?? 'Send failed.');

    // Stash the new message locally so the sidebar and thread reflect it immediately
    allSentMessages.unshift({
      id:                 result.id,
      recipient_username: recipUsername,
      created_at:         result.created_at ?? new Date().toISOString(),
      _plaintext:         body,   // session-only; lets the thread show readable text
    });

    renderSidebar();

    // Navigate to the conversation thread with the recipient
    const convoEl = [...document.querySelectorAll('.convo-item')]
      .find(el => el.dataset.sender === recipUsername);
    if (convoEl) {
      openConversation(recipUsername, convoEl);
    }

  } catch (err) {
    showStatus(statusEl, err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

// ── Recipient autocomplete ─────────────────────────────────────────────────────

function onRecipientInput() {
  const val = this.value.trim().toLowerCase();
  const box = document.getElementById('recipient-suggestions');
  if (!val) { box.innerHTML = ''; return; }

  const me      = getUsername();
  const matches = allUsers
    .filter(u => u.username !== me && u.username.toLowerCase().includes(val))
    .slice(0, 7);

  box.innerHTML = matches.map(u =>
    `<div class="suggestion-item" data-username="${esc(u.username)}">
      <div>${esc(u.username)}</div>
      ${u.public_key
        ? '<div class="suggestion-key"><i data-lucide="key-round" style="width:11px;height:11px"></i> Public key registered</div>'
        : '<div class="suggestion-key" style="color:var(--red-500)"><i data-lucide="triangle-alert" style="width:11px;height:11px"></i> No public key — cannot encrypt</div>'
      }
    </div>`
  ).join('');

  lucide.createIcons();

  box.querySelectorAll('.suggestion-item').forEach(item => {
    item.addEventListener('mousedown', () => {
      const username = item.dataset.username;
      document.getElementById('recipient').value = username;
      box.innerHTML = '';

      // If this contact already has a conversation in the sidebar, go there now
      const convoEl = [...document.querySelectorAll('.convo-item')]
        .find(el => el.dataset.sender === username);
      if (convoEl) openConversation(username, convoEl);
    });
  });
}

// ── Logout ─────────────────────────────────────────────────────────────────────

async function doLogout() {
  const refresh = localStorage.getItem('sm_refresh_token');
  if (refresh) {
    await authFetch(`${API}/auth/logout`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ refresh_token: refresh }),
    }).catch(() => {});
  }
  clearSession();
  window.location.href = 'index.html';
}

function clearSession() {
  ['sm_token', 'sm_refresh_token', 'sm_username'].forEach(k => localStorage.removeItem(k));
}

// ── Utilities ──────────────────────────────────────────────────────────────────

function setupAutoResize(textarea) {
  textarea.addEventListener('input', () => {
    textarea.style.height = 'auto';
    textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
  });
}

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
