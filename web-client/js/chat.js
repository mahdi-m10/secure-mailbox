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
  document.getElementById('settings-btn').addEventListener('click', openSettingsModal);
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

  // Received bubbles — decrypt, forward, download
  thread.querySelectorAll('.bubble-wrap.in[data-msg-id]').forEach(wrap => {
    const msgId = +wrap.dataset.msgId;
    const msg   = received.find(m => m.id === msgId);

    wrap.querySelector('.b-decrypt-btn')
      ?.addEventListener('click', e => handleInlineDecrypt(msgId, e.currentTarget));
    wrap.querySelector('.b-forward-btn')
      ?.addEventListener('click', () => showForwardUI(msgId, wrap));
    wrap.querySelector('.b-download-btn')
      ?.addEventListener('click', e => handleDownloadReceived(msgId, msg, wrap, e.currentTarget));
  });

  // Sent history bubbles — delete, revoke, download
  thread.querySelectorAll('.bubble-wrap.out[data-msg-id]').forEach(wrap => {
    const msgId = +wrap.dataset.msgId;
    const msg   = allSentMessages.find(m => m.id === msgId);

    wrap.querySelector('.b-delete-btn')
      ?.addEventListener('click', () => handleDeleteMessage(msgId, wrap));
    wrap.querySelector('.b-revoke-btn')
      ?.addEventListener('click', () => handleRevokeMessage(msgId, wrap));
    wrap.querySelector('.b-download-btn')
      ?.addEventListener('click', () => {
        if (msg?._plaintext) triggerDownload(msgId, null, msg.created_at, msg._plaintext);
        else if (msg)         handleDownloadSentMetadata(msg);
      });
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
  const id       = msg.id;
  const preview  = esc((msg.ciphertext ?? '').slice(0, 80)) + '…';
  const fwdLabel = msg.is_forwarded
    ? `<div class="b-forwarded-label">&#x21AA; Forwarded</div>`
    : '';
  return `<div class="bubble-wrap in" data-msg-id="${id}">
    <div class="bubble">
      ${fwdLabel}<div class="b-cipher" id="bc-${id}">
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
    <div class="b-in-actions">
      <button class="b-action-btn b-forward-btn" title="Forward message">
        <i data-lucide="forward" style="width:12px;height:12px"></i>
        Forward
      </button>
      <button class="b-action-btn b-download-btn" title="Download message">
        <i data-lucide="download" style="width:12px;height:12px"></i>
        Download
      </button>
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
      <button class="b-action-btn b-download-btn" title="Download metadata">
        <i data-lucide="download" style="width:12px;height:12px"></i>
        Download
      </button>
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
      <button class="b-action-btn b-download-btn" title="Download message">
        <i data-lucide="download" style="width:12px;height:12px"></i>
        Download
      </button>
      <button class="b-action-btn b-revoke-btn" title="Revoke recipient access">
        <i data-lucide="shield-off" style="width:12px;height:12px"></i>
        Revoke
      </button>
      <button class="b-action-btn b-delete-btn" title="Delete message">
        <i data-lucide="trash-2" style="width:12px;height:12px"></i>
        Delete
      </button>
    </div>` : '';
  return `<div class="bubble-wrap out"${msgId ? ` data-msg-id="${msgId}"` : ''}>
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
    wrap.querySelector('.b-download-btn')
      ?.addEventListener('click', () => {
        const content = [
          `SecureMsg — Sent Message`,
          `Date:    ${new Date().toLocaleString()}`,
          `ID:      ${msgId}`,
          ``,
          text,
        ].join('\n');
        downloadTxt(`sent-${msgId}.txt`, content);
      });
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

// ── Forward ───────────────────────────────────────────────────────────────────

function showForwardUI(msgId, bubbleWrap) {
  if (bubbleWrap.querySelector('.b-forward-ui')) return; // already open

  bubbleWrap.classList.add('b-forwarding');

  const ui = document.createElement('div');
  ui.className = 'b-forward-ui';
  ui.innerHTML = `
    <div class="b-forward-row">
      <div class="b-forward-recipient-wrap">
        <input type="text" class="b-forward-input" placeholder="Forward to username…" autocomplete="off">
        <div class="b-forward-drop"></div>
      </div>
      <button class="b-action-btn b-forward-confirm" title="Send">
        <i data-lucide="send" style="width:12px;height:12px"></i>
      </button>
      <button class="b-action-btn b-forward-cancel" title="Cancel">
        <i data-lucide="x" style="width:12px;height:12px"></i>
      </button>
    </div>
    <div class="b-forward-status"></div>`;

  // Insert between .bubble and .b-in-actions
  bubbleWrap.querySelector('.b-in-actions').before(ui);
  lucide.createIcons();

  const input   = ui.querySelector('.b-forward-input');
  const drop    = ui.querySelector('.b-forward-drop');
  const confirm = ui.querySelector('.b-forward-confirm');
  const cancel  = ui.querySelector('.b-forward-cancel');
  const status  = ui.querySelector('.b-forward-status');

  let chosenUser = '';

  input.focus();

  input.addEventListener('input', () => {
    const val = input.value.trim().toLowerCase();
    drop.innerHTML = '';
    chosenUser = '';
    if (!val) return;
    const me = getUsername();
    allUsers
      .filter(u => u.username !== me && u.username.toLowerCase().includes(val))
      .slice(0, 6)
      .forEach(u => {
        const item = document.createElement('div');
        item.className = 'b-forward-item';
        item.textContent = u.username;
        item.addEventListener('mousedown', () => {
          input.value = u.username;
          chosenUser  = u.username;
          drop.innerHTML = '';
        });
        drop.appendChild(item);
      });
  });

  input.addEventListener('blur', () => {
    setTimeout(() => { drop.innerHTML = ''; }, 150);
  });

  cancel.addEventListener('click', () => {
    ui.remove();
    bubbleWrap.classList.remove('b-forwarding');
  });

  confirm.addEventListener('click', async () => {
    const recipient = chosenUser || input.value.trim();
    if (!recipient) return;

    confirm.disabled = true;
    confirm.innerHTML = '<span class="spinner"></span>';
    status.textContent = '';

    try {
      // ── Step 1: obtain plaintext ──────────────────────────────────────
      const plainEl  = document.getElementById(`bp-${msgId}`);
      const errEl    = document.getElementById(`be-${msgId}`);
      let   plaintext = '';

      if (plainEl && !plainEl.classList.contains('hidden') && plainEl.textContent.trim()) {
        plaintext = plainEl.textContent.trim();
      } else {
        // Decrypt the bubble first, then read the result from the DOM
        const decryptBtn = bubbleWrap.querySelector('.b-decrypt-btn');
        if (!decryptBtn) throw new Error('Message must be decrypted before forwarding.');
        await handleInlineDecrypt(msgId, decryptBtn);
        plaintext = plainEl?.textContent.trim() ?? '';
        if (!plaintext || (errEl && !errEl.classList.contains('hidden'))) {
          throw new Error('Could not decrypt message. Cannot forward.');
        }
      }

      // ── Step 2: fetch new recipient's public key ──────────────────────
      const userRes = await fetch(`${API}/users/${encodeURIComponent(recipient)}`);
      if (!userRes.ok) throw new Error(`User "${recipient}" not found.`);
      const recipientUser = await userRes.json();
      if (!recipientUser.public_key)
        throw new Error(`${recipient} has no registered public key.`);

      // ── Step 3: re-encrypt for the new recipient ──────────────────────
      const privKey = await loadPrivateKey(getUsername());
      if (!privKey) throw new Error('No private key found. Please sign out and back in.');

      const { ciphertext, nonce, encryptedKey } = await encryptMessage(
        plaintext, recipientUser.public_key, privKey
      );

      // ── Step 4: send re-encrypted payload to backend ──────────────────
      const res = await authFetch(`${API}/messages/${msgId}/forward`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          recipient_username: recipient,
          new_ciphertext:     ciphertext,
          new_nonce:          nonce,
          new_encrypted_key:  encryptedKey,
        }),
      });
      if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail ?? 'Forward failed.');
      }

      status.textContent = `Forwarded to ${recipient}.`;
      status.style.color = 'var(--green-600)';
      input.disabled = true;
      confirm.remove();
      setTimeout(() => {
        ui.remove();
        bubbleWrap.classList.remove('b-forwarding');
      }, 2000);
    } catch (err) {
      status.textContent = err.message;
      status.style.color = 'var(--red-600)';
      confirm.disabled = false;
      confirm.innerHTML = '<i data-lucide="send" style="width:12px;height:12px"></i>';
      lucide.createIcons();
    }
  });
}

// ── Download ───────────────────────────────────────────────────────────────────

async function handleDownloadReceived(msgId, msg, bubbleWrap, btn) {
  const plainEl = document.getElementById(`bp-${msgId}`);
  const errEl   = document.getElementById(`be-${msgId}`);

  // Already decrypted — grab visible text and save
  if (plainEl && !plainEl.classList.contains('hidden') && plainEl.textContent.trim()) {
    triggerDownload(msgId, msg?.sender_username, msg?.created_at, plainEl.textContent.trim());
    return;
  }

  // Decrypt first, then save
  const decryptBtn = bubbleWrap.querySelector('.b-decrypt-btn');
  if (!decryptBtn) return;

  const savedHTML = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';

  await handleInlineDecrypt(msgId, decryptBtn);

  // Check decrypt succeeded (error element is hidden and plain text is visible)
  const text = plainEl?.textContent.trim() ?? '';
  if (text && (!errEl || errEl.classList.contains('hidden'))) {
    triggerDownload(msgId, msg?.sender_username, msg?.created_at, text);
  }

  btn.disabled = false;
  btn.innerHTML = savedHTML;
  lucide.createIcons();
}

function handleDownloadSentMetadata(msg) {
  const date = new Date((msg.created_at ?? '') + (msg.created_at?.endsWith('Z') ? '' : 'Z'));
  const content = [
    `SecureMsg — Sent Message`,
    `To:      ${msg.recipient_username ?? 'Unknown'}`,
    `Date:    ${date.toLocaleString()}`,
    `ID:      ${msg.id}`,
    ``,
    `Note: Sent messages are encrypted for the recipient.`,
    `      The sender cannot decrypt their own sent messages.`,
  ].join('\n');
  downloadTxt(`sent-${msg.id}.txt`, content);
}

function triggerDownload(msgId, fromUsername, createdAt, plaintext) {
  const date = new Date((createdAt ?? '') + ((createdAt ?? '').endsWith('Z') ? '' : 'Z'));
  const content = [
    `SecureMsg — Message`,
    `From:    ${fromUsername ?? 'Unknown'}`,
    `Date:    ${date.toLocaleString()}`,
    `ID:      ${msgId}`,
    ``,
    plaintext,
  ].join('\n');
  downloadTxt(`message-${msgId}.txt`, content);
}

function downloadTxt(filename, content) {
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(new Blob([content], { type: 'text/plain' }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Settings modal (change password) ──────────────────────────────────────────

function openSettingsModal() {
  const modal = document.getElementById('settings-modal');
  document.getElementById('change-password-form').reset();
  document.getElementById('pw-status').style.display = 'none';
  document.getElementById('pw-submit').disabled = false;
  document.getElementById('pw-submit').innerHTML =
    '<i data-lucide="key-round"></i> Change Password';
  modal.style.display = 'flex';
  lucide.createIcons();
  document.getElementById('pw-current').focus();

  // Wire close targets each time the modal opens (avoids duplicate listeners)
  const close = () => { modal.style.display = 'none'; };

  document.getElementById('settings-modal-close').onclick  = close;
  document.getElementById('settings-modal-cancel').onclick = close;

  // Click outside the card closes it
  modal.onclick = e => { if (e.target === modal) close(); };

  document.getElementById('change-password-form').onsubmit = handleChangePassword;
}

async function handleChangePassword(e) {
  e.preventDefault();

  const oldPw  = document.getElementById('pw-current').value;
  const newPw  = document.getElementById('pw-new').value;
  const confPw = document.getElementById('pw-confirm').value;
  const status = document.getElementById('pw-status');
  const btn    = document.getElementById('pw-submit');

  if (newPw !== confPw) {
    showStatus(status, 'New passwords do not match.', 'error');
    return;
  }
  if (newPw.length < 8) {
    showStatus(status, 'New password must be at least 8 characters.', 'error');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Saving…';
  status.style.display = 'none';

  try {
    const res = await authFetch(`${API}/auth/password`, {
      method:  'PUT',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ old_password: oldPw, new_password: newPw }),
    });

    const body = await res.json().catch(() => ({}));

    if (!res.ok) {
      throw new Error(body.detail ?? 'Password change failed.');
    }

    // All sessions are invalidated server-side after a password change.
    showStatus(status, 'Password changed. Signing out…', 'success');
    setTimeout(() => {
      clearSession();
      window.location.href = 'index.html';
    }, 1500);

  } catch (err) {
    showStatus(status, err.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="key-round"></i> Change Password';
    lucide.createIcons();
  }
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
