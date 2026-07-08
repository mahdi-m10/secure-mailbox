/**
 * files.js — encrypted file mailbox UI for files.html
 *
 * Upload flow:
 *   1. Pick a local file (≤ 8 MiB) + recipient.
 *   2. Fetch the recipient's public key and gate it through the TOFU pin
 *      store (hard warning + explicit override on key change).
 *   3. aad = buildFileAad(me, recipient, file.name)  — binds the filename
 *      into the GCM tag so the server cannot relabel the ciphertext.
 *   4. encryptFile(bytes, recipientPub, myPriv, aad)  (HPKE Mode_Auth)
 *   5. POST /files/upload with ciphertext, nonce, encrypted_key, metadata,
 *      and the canonical associated_data string (server cross-checks it).
 *
 * Download flow (shared-with-me):
 *   1. GET /files/{id}/download
 *   2. Fetch the OWNER's public key, gate through the TOFU pin store.
 *   3. Rebuild aad locally from (owner_username, me, filename) — never
 *      trust the server-returned associated_data string; the GCM tag
 *      verification against the locally built value is the actual check.
 *   4. decryptFile → save the plaintext bytes as a browser download.
 *
 * A decryption failure here means: tampered ciphertext, a relabelled
 * filename, a substituted sender key, or the wrong local key — all
 * fail closed with the same error.
 *
 * NOTE (deliberate): there is NO fallback to AAD-less decryption for legacy
 * ciphertexts. A fallback would let a malicious server strip relabelling
 * protection by making decryption downgrade. Files uploaded by the old
 * message client are not readable in this UI.
 */

import { API } from './config.js';
import {
  buildFileAad, checkTofuPin, decryptFile, encryptFile, keyFingerprint,
  overridePin, b64ToBuffer, bufToB64,
  keyPairStatus, unlockKeyPair, saveWrappedKeyPair, generateKeyPair,
  migrateLocalStorageKey,
} from './crypto.js';

const MAX_PLAINTEXT_BYTES = 8 * 1024 * 1024;   // mirror of the server-side cap

const getToken    = () => localStorage.getItem('sm_token');
const getUsername = () => localStorage.getItem('sm_username');
const authHeaders = () => ({ Authorization: `Bearer ${getToken()}` });

function authFetch(url, opts = {}) {
  return fetch(url, { ...opts, headers: { ...authHeaders(), ...(opts.headers ?? {}) } });
}

// ── State ──────────────────────────────────────────────────────────────────────

let sharedFiles = [];
let ownedFiles  = [];
let allUsers    = [];
let activeTab   = 'shared';

// The unlocked (non-extractable) private key for this page load, produced by
// unlockKeyPair(). null = vault locked → every crypto verb is blocked.
// CryptoKeys cannot be kept in sessionStorage; re-prompting per page load is
// the intended behaviour.
let sessionKey  = null;

// ── Bootstrap ──────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  if (!getToken()) { window.location.href = 'index.html'; return; }

  const user = getUsername();
  document.getElementById('username-display').textContent = user ?? '';
  document.getElementById('user-avatar').textContent      = (user?.[0] ?? '?').toUpperCase();

  document.getElementById('logout-btn').addEventListener('click', doLogout);
  document.getElementById('settings-btn').addEventListener('click', openSettingsModal);
  document.getElementById('upload-btn').addEventListener('click', openUploadModal);
  document.getElementById('upload-empty-btn')?.addEventListener('click', openUploadModal);

  document.querySelectorAll('.file-tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  document.getElementById('upload-form').addEventListener('submit', handleUpload);
  document.getElementById('upload-modal-close').addEventListener('click', closeUploadModal);
  document.getElementById('upload-modal-cancel').addEventListener('click', closeUploadModal);

  const recipInput = document.getElementById('upload-recipient');
  recipInput.addEventListener('input', onRecipientInput);
  recipInput.addEventListener('blur', () => {
    setTimeout(() => { document.getElementById('recipient-suggestions').innerHTML = ''; }, 160);
  });

  document.getElementById('upload-file-input').addEventListener('change', onFileChosen);

  document.getElementById('vault-locked-banner').addEventListener('click', ensureVault);

  lucide.createIcons();

  // Vault first: unlock / create / upgrade before anything encrypted is
  // touchable. Listings load either way — browsing works with a locked vault.
  await ensureVault();
  await Promise.all([loadUsers(), refreshLists()]);
});

async function refreshLists() {
  await Promise.all([loadShared(), loadOwned()]);
  renderActiveTab();
}

// ── Data loading ───────────────────────────────────────────────────────────────

async function loadUsers() {
  try {
    const res = await fetch(`${API}/users?limit=500`);
    allUsers  = res.ok ? await res.json() : [];
  } catch { allUsers = []; }
}

async function loadShared() {
  try {
    const res = await authFetch(`${API}/files/shared?limit=200`);
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    sharedFiles = res.ok ? await res.json() : [];

    const unread = sharedFiles.filter(f => !f.is_read).length;
    const badge  = document.getElementById('unread-badge');
    badge.textContent   = unread || '';
    badge.style.display = unread ? 'inline-flex' : 'none';
  } catch { sharedFiles = []; }
}

async function loadOwned() {
  try {
    const res = await authFetch(`${API}/files/owned?limit=200`);
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    ownedFiles = res.ok ? await res.json() : [];
  } catch { ownedFiles = []; }
}

// ── Tabs & rendering ───────────────────────────────────────────────────────────

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.file-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.tab === tab));
  renderActiveTab();
}

function renderActiveTab() {
  const list  = document.getElementById('file-list');
  const files = activeTab === 'shared' ? sharedFiles : ownedFiles;

  if (!files.length) {
    list.innerHTML = `<div class="empty-state" style="margin-top:40px">
      <div class="empty-icon-wrap"><i data-lucide="folder-open"></i></div>
      <h3>${activeTab === 'shared' ? 'No files shared with you yet' : 'No uploads yet'}</h3>
      <p>${activeTab === 'shared'
        ? 'Files other users encrypt for you will appear here.'
        : 'Encrypt and upload a file to get started.'}</p>
    </div>`;
    lucide.createIcons();
    return;
  }

  list.innerHTML = files.map(f =>
    activeTab === 'shared' ? renderSharedRow(f) : renderOwnedRow(f)
  ).join('');
  lucide.createIcons();

  list.querySelectorAll('[data-action]').forEach(btn => {
    const id = +btn.closest('.file-row').dataset.fileId;
    btn.addEventListener('click', () => handleAction(btn.dataset.action, id, btn));
  });
}

function renderSharedRow(f) {
  return `<div class="file-row ${f.is_read ? '' : 'unread'}" data-file-id="${f.id}">
    <div class="file-icon"><i data-lucide="file-lock-2"></i></div>
    <div class="file-meta">
      <div class="file-name">${esc(f.filename || f.subject || '(unnamed file)')}
        ${f.is_forwarded ? '<span class="file-tag">shared on</span>' : ''}
        ${f.is_read ? '' : '<span class="file-tag new">new</span>'}
      </div>
      <div class="file-sub">
        from <strong>${esc(f.owner_username ?? 'unknown')}</strong>
        · ${fmtSize(f.size_bytes)} · ${fmtDate(f.created_at)}
      </div>
    </div>
    <div class="file-actions">
      <button class="b-action-btn" data-action="download" title="Decrypt & download">
        <i data-lucide="download"></i> Decrypt
      </button>
      <button class="b-action-btn" data-action="share" title="Re-encrypt for another user">
        <i data-lucide="forward"></i> Share
      </button>
      <a class="b-action-btn" href="verify.html?id=${f.id}" title="Blockchain integrity proof">
        <i data-lucide="shield"></i> Verify
      </a>
    </div>
  </div>`;
}

function renderOwnedRow(f) {
  return `<div class="file-row" data-file-id="${f.id}">
    <div class="file-icon owned"><i data-lucide="file-key-2"></i></div>
    <div class="file-meta">
      <div class="file-name">${esc(f.filename || f.subject || '(unnamed file)')}</div>
      <div class="file-sub">
        to <strong>${esc(f.recipient_username ?? 'unknown')}</strong>
        · ${fmtSize(f.size_bytes)} · ${fmtDate(f.created_at)}
      </div>
    </div>
    <div class="file-actions">
      <button class="b-action-btn" data-action="revoke" title="Remove all recipients' access">
        <i data-lucide="shield-off"></i> Revoke
      </button>
      <button class="b-action-btn danger" data-action="delete" title="Delete this upload">
        <i data-lucide="trash-2"></i> Delete
      </button>
      <a class="b-action-btn" href="verify.html?id=${f.id}" title="Blockchain integrity proof">
        <i data-lucide="shield"></i> Verify
      </a>
    </div>
  </div>`;
}

function handleAction(action, fileId, btn) {
  if (action === 'download') return handleDownload(fileId, btn);
  if (action === 'share')    return handleShare(fileId, btn);
  if (action === 'revoke')   return handleRevoke(fileId);
  if (action === 'delete')   return handleDelete(fileId);
}

// ── TOFU gate ──────────────────────────────────────────────────────────────────

// ── Key vault (passphrase-wrapped private key) ─────────────────────────────────
//
// The private key exists in IndexedDB only as an AES-GCM blob wrapped under a
// PBKDF2-derived key (crypto.js). This block owns the page's vault lifecycle:
//   wrapped → prompt passphrase, unwrapKey → non-extractable session key
//   none    → create a vault (new passphrase; migrates a legacy localStorage
//             JWK into the vault if one exists, preserving the key)
//   legacy  → pre-vault non-extractable CryptoKey record: it CANNOT be
//             wrapped retroactively, so it is replaced — new wrapped keypair,
//             new public key uploaded, old record overwritten. Files
//             encrypted to the old key become unreadable (told to the user).
// There is no path that yields a usable key without the passphrase.

function updateVaultUI() {
  document.getElementById('vault-locked-banner').style.display =
    sessionKey ? 'none' : 'flex';
}

/** The single gate every crypto verb goes through. */
async function requireSessionKey() {
  if (sessionKey) return sessionKey;
  await ensureVault();                     // re-offer the modal
  if (sessionKey) return sessionKey;
  throw new Error('Key vault is locked — unlock it to encrypt or decrypt files.');
}

/** Show the vault modal in the right mode; resolves when the vault is
 *  unlocked/created or the user skips (browse-only). */
async function ensureVault() {
  const me = getUsername();
  const status = await keyPairStatus(me);
  const hasLegacyJwk = !!localStorage.getItem(`sm_privkey_${me}`);

  const mode = status === 'wrapped' ? 'unlock'
             : status === 'legacy'  ? 'upgrade'
             : hasLegacyJwk         ? 'migrate'
             :                        'create';

  const texts = {
    unlock: {
      title: 'Unlock your key vault',
      explain: 'Enter your key-vault passphrase to decrypt files shared with ' +
               'you and to upload new ones. This is the passphrase you set ' +
               'when your encryption key was created — not your login password.',
      button: 'Unlock', repeat: false,
    },
    create: {
      title: 'Create your key vault',
      explain: 'No encryption key exists for this account on this device. ' +
               'Choose a key-vault passphrase (different from your login ' +
               'password) — it encrypts your new private key on this device, ' +
               'is never sent to the server, and cannot be recovered. ' +
               'Files previously encrypted to a key from another device will ' +
               'not be readable here.',
      button: 'Create vault', repeat: true,
    },
    migrate: {
      title: 'Protect your existing key',
      explain: 'An encryption key from an older version of this app was found ' +
               'on this device. Choose a key-vault passphrase (different from ' +
               'your login password) to encrypt it at rest — your existing ' +
               'files stay readable.',
      button: 'Encrypt my key', repeat: true,
    },
    upgrade: {
      title: 'Key upgrade required',
      explain: 'Your encryption key predates passphrase protection and cannot ' +
               'be upgraded in place (its bytes are sealed inside the browser ' +
               'and cannot be re-encrypted). A NEW key will be generated and ' +
               'stored passphrase-encrypted. Files encrypted to the old key ' +
               'will no longer be readable — the sender must re-share them.',
      button: 'Generate new key', repeat: true,
    },
  }[mode];

  return new Promise(resolve => {
    const modal   = document.getElementById('vault-modal');
    const form    = document.getElementById('vault-form');
    const pass1   = document.getElementById('vault-pass');
    const pass2   = document.getElementById('vault-pass2');
    const stat    = document.getElementById('vault-status');
    const submit  = document.getElementById('vault-submit');

    document.getElementById('vault-title-text').textContent = texts.title;
    document.getElementById('vault-explain').textContent    = texts.explain;
    document.getElementById('vault-pass2-group').style.display =
      texts.repeat ? '' : 'none';
    submit.textContent = texts.button;
    pass1.value = ''; pass2.value = '';
    stat.style.display = 'none';

    let attemptsLeft = 3;   // unlock mode only

    const close = () => {
      modal.style.display = 'none';
      form.onsubmit = null;
      document.getElementById('vault-skip').onclick = null;
      updateVaultUI();
      resolve();
    };

    const fail = (msg) => {
      stat.textContent = msg;
      stat.className = 'alert alert-error';
      stat.style.display = 'block';
    };

    document.getElementById('vault-skip').onclick = close;

    form.onsubmit = async (e) => {
      e.preventDefault();
      const p1 = pass1.value, p2 = pass2.value;
      if (p1.length < 8) return fail('Passphrase must be at least 8 characters.');
      if (texts.repeat && p1 !== p2) return fail('Passphrases do not match.');

      submit.disabled = true;
      submit.innerHTML = '<span class="spinner"></span> Deriving key…';
      try {
        if (mode === 'unlock') {
          const unlocked = await unlockKeyPair(me, p1);
          if (!unlocked) {
            attemptsLeft--;
            if (attemptsLeft <= 0) {
              toast('Vault locked — browsing only. Use the sidebar button to retry.');
              return close();
            }
            return fail(`Wrong passphrase. ${attemptsLeft} attempt(s) left.`);
          }
          sessionKey = unlocked.privateKey;
        } else if (mode === 'migrate') {
          const ok = await migrateLocalStorageKey(me, p1);
          if (!ok) return fail('Migration failed — the stored key is unusable. Reload to create a fresh key.');
          sessionKey = (await unlockKeyPair(me, p1)).privateKey;
          toast('Existing key encrypted into your new vault.');
        } else {  // create | upgrade — fresh keypair, wrapped, public key published
          const { publicKeyB64, privateKey } = await generateKeyPair();
          await saveWrappedKeyPair(me, publicKeyB64, privateKey, p1);
          // (the extractable reference goes out of scope here — only the
          //  wrapped blob persists)
          const res = await authFetch(`${API}/users/keys`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ public_key: publicKeyB64 }),
          });
          if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            return fail(parseApiError(body, 'Could not publish your new public key.'));
          }
          // Round-trip through unwrapKey so the session key is the
          // non-extractable form, same as every future unlock.
          sessionKey = (await unlockKeyPair(me, p1)).privateKey;
          toast(mode === 'upgrade' ? 'New key generated and vaulted.' : 'Key vault created.');
        }
        close();
      } catch (err) {
        fail(err.message ?? 'Vault operation failed.');
      } finally {
        submit.disabled = false;
        submit.textContent = texts.button;
      }
    };

    modal.style.display = 'flex';
    lucide.createIcons();
    pass1.focus();
  });
}

/**
 * Fetch a peer's public key and enforce the TOFU pin.
 * - first sighting → pin silently + toast
 * - match          → proceed
 * - MISMATCH       → hard-block modal with both fingerprints; proceeding
 *                    requires an explicit "Trust new key" click (re-pins).
 * @returns {Promise<string>} the verified public key (base64)
 * @throws  if the peer has no key or the user aborts on mismatch
 */
async function getVerifiedPeerKey(peerUsername) {
  const res = await fetch(`${API}/users/${encodeURIComponent(peerUsername)}`);
  if (!res.ok) throw new Error(`User "${peerUsername}" not found.`);
  const peer = await res.json();
  if (!peer.public_key) throw new Error(`${peerUsername} has no registered public key.`);

  const me  = getUsername();
  const pin = await checkTofuPin(me, peerUsername, peer.public_key);

  if (pin.status === 'first-use') {
    toast(`First contact with ${peerUsername} — their key has been pinned on this device.`);
    return peer.public_key;
  }
  if (pin.status === 'match') return peer.public_key;

  // Mismatch — the §3(d)1 scenario. Block until an explicit decision.
  const [oldFp, newFp] = await Promise.all([
    keyFingerprint(pin.pinnedKeyB64), keyFingerprint(peer.public_key),
  ]);
  const proceed = await showKeyChangeWarning(peerUsername, oldFp, newFp, pin.pinnedSince);
  if (!proceed) throw new Error(`Aborted: ${peerUsername}'s key does not match the pinned key.`);

  await overridePin(me, peerUsername, peer.public_key);
  toast(`New key pinned for ${peerUsername}.`);
  return peer.public_key;
}

/** Modal returning a Promise<boolean>; Cancel is the default/safe path. */
function showKeyChangeWarning(peer, oldFp, newFp, pinnedSince) {
  return new Promise(resolve => {
    const modal = document.getElementById('tofu-modal');
    document.getElementById('tofu-peer').textContent      = peer;
    document.getElementById('tofu-old-fp').textContent    = oldFp;
    document.getElementById('tofu-new-fp').textContent    = newFp;
    document.getElementById('tofu-since').textContent     =
      pinnedSince ? new Date(pinnedSince).toLocaleString() : 'unknown';
    modal.style.display = 'flex';
    lucide.createIcons();

    const done = (answer) => { modal.style.display = 'none'; resolve(answer); };
    document.getElementById('tofu-cancel').onclick = () => done(false);
    document.getElementById('tofu-trust').onclick  = () => done(true);
    modal.onclick = e => { if (e.target === modal) done(false); };
  });
}

// ── Upload ─────────────────────────────────────────────────────────────────────

let chosenFile = null;

function openUploadModal() {
  chosenFile = null;
  document.getElementById('upload-form').reset();
  document.getElementById('upload-file-label').textContent = 'Choose a file…';
  const status = document.getElementById('upload-status');
  status.style.display = 'none';
  document.getElementById('upload-modal').style.display = 'flex';
  lucide.createIcons();
  document.getElementById('upload-recipient').focus();
}

function closeUploadModal() {
  document.getElementById('upload-modal').style.display = 'none';
}

function onFileChosen(e) {
  chosenFile = e.target.files[0] ?? null;
  const label = document.getElementById('upload-file-label');
  if (!chosenFile) { label.textContent = 'Choose a file…'; return; }
  label.textContent = `${chosenFile.name} (${fmtSize(chosenFile.size)})`;
}

async function handleUpload(e) {
  e.preventDefault();
  const btn       = document.getElementById('upload-submit');
  const status    = document.getElementById('upload-status');
  const recipient = document.getElementById('upload-recipient').value.trim();
  const subject   = document.getElementById('upload-subject').value.trim();

  status.style.display = 'none';
  if (!recipient)  return showStatus(status, 'Choose a recipient.', 'error');
  if (!chosenFile) return showStatus(status, 'Choose a file to upload.', 'error');
  if (chosenFile.size > MAX_PLAINTEXT_BYTES) {
    return showStatus(status, `File is too large — the limit is ${fmtSize(MAX_PLAINTEXT_BYTES)}.`, 'error');
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Encrypting…';

  try {
    const me      = getUsername();
    const privKey = await requireSessionKey();

    // TOFU-gated recipient key — encrypting to an unverified key is exactly
    // the MitM the pin store exists to catch.
    const recipientKey = await getVerifiedPeerKey(recipient);

    const bytes = await chosenFile.arrayBuffer();
    const aadBytes = buildFileAad(me, recipient, chosenFile.name);
    const { ciphertext, nonce, encryptedKey } =
      await encryptFile(bytes, recipientKey, privKey, aadBytes);

    btn.innerHTML = '<span class="spinner"></span> Uploading…';
    const res = await authFetch(`${API}/files/upload`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipient_username: recipient,
        ciphertext,
        nonce,
        encrypted_key:   encryptedKey,
        filename:        chosenFile.name,
        content_type:    chosenFile.type || null,
        size_bytes:      chosenFile.size,
        subject:         subject || null,
        associated_data: new TextDecoder().decode(aadBytes),
      }),
    });
    const body = await res.json().catch(() => ({}));
    if (res.status === 401) { clearSession(); window.location.href = 'index.html'; return; }
    if (!res.ok) throw new Error(parseApiError(body, 'Upload failed.'));

    closeUploadModal();
    toast(`Encrypted and uploaded "${chosenFile.name}" for ${recipient}.`);
    await refreshLists();
    switchTab('owned');

  } catch (err) {
    showStatus(status, err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="upload"></i> Encrypt & Upload';
    lucide.createIcons();
  }
}

// ── Download (decrypt) ─────────────────────────────────────────────────────────

async function fetchAndDecrypt(fileId) {
  const res = await authFetch(`${API}/files/${fileId}/download`);
  if (res.status === 401) { clearSession(); window.location.href = 'index.html'; throw new Error('Session expired'); }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? 'Could not load the file.');
  }
  const dl = await res.json();

  if (!dl.encrypted_key)   throw new Error('No encapsulated key — this file was not encrypted for you.');
  if (!dl.owner_username)  throw new Error('Uploader identity unknown — cannot perform authenticated decryption.');

  const me      = getUsername();
  const privKey = await requireSessionKey();

  // TOFU-gated owner (sender) key — Mode_Auth authenticates against it.
  const ownerKey = await getVerifiedPeerKey(dl.owner_username);

  // storedBlob = base64(nonce_12B ‖ ciphertext_with_tag); strip the nonce
  // prefix — the nonce is re-derived from the key schedule.
  const raw   = new Uint8Array(b64ToBuffer(dl.ciphertext));
  const ctB64 = bufToB64(raw.slice(12));

  // Rebuild the AAD locally from response metadata + our own username.
  // If the server relabelled the filename, this AAD differs from the one
  // the sender bound, and decryptFile() throws — which IS the detection.
  const aadBytes = buildFileAad(dl.owner_username, me, dl.filename ?? null);

  const bytes = await decryptFile(ctB64, dl.encrypted_key, privKey, ownerKey, aadBytes);
  return { dl, bytes };
}

async function handleDownload(fileId, btn) {
  const saved = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';

  try {
    const { dl, bytes } = await fetchAndDecrypt(fileId);
    saveBlob(bytes, dl.filename || `file-${fileId}`, dl.content_type || 'application/octet-stream');
    toast(`Decrypted "${dl.filename ?? 'file'}" — authenticity and integrity verified.`);
    await loadShared();          // is_read flipped server-side
    renderActiveTab();
  } catch (err) {
    alert(
      `Decryption failed.\n\n${err.message}\n\n` +
      'If this persists it can mean the ciphertext was tampered with, the ' +
      'filename was relabelled, or the uploader\'s key does not match.'
    );
  } finally {
    btn.disabled = false;
    btn.innerHTML = saved;
    lucide.createIcons();
  }
}

function saveBlob(bytes, filename, contentType) {
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(new Blob([bytes], { type: contentType }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Share (decrypt + re-encrypt for a new recipient) ───────────────────────────

async function handleShare(fileId, btn) {
  const recipient = prompt('Share with (username):')?.trim();
  if (!recipient) return;

  const saved = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';

  try {
    const me = getUsername();

    // 1. Decrypt locally (TOFU-gated owner key, AAD verified).
    const { dl, bytes } = await fetchAndDecrypt(fileId);

    // 2. TOFU-gated new-recipient key, then re-encrypt with an AAD naming
    //    US as the sender — the share creates a new file row owned by us.
    const recipientKey = await getVerifiedPeerKey(recipient);
    const privKey      = await requireSessionKey();
    const aadBytes     = buildFileAad(me, recipient, dl.filename ?? null);
    const { ciphertext, nonce, encryptedKey } =
      await encryptFile(bytes, recipientKey, privKey, aadBytes);

    // 3. Hand the re-encrypted payload to the share endpoint.
    const res = await authFetch(`${API}/files/${fileId}/share`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        recipient_username: recipient,
        new_ciphertext:     ciphertext,
        new_nonce:          nonce,
        new_encrypted_key:  encryptedKey,
      }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(parseApiError(body, 'Share failed.'));

    toast(`Re-encrypted and shared with ${recipient}.`);
    await refreshLists();
  } catch (err) {
    alert(`Could not share: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = saved;
    lucide.createIcons();
  }
}

// ── Revoke / Delete (owner actions) ────────────────────────────────────────────

async function handleRevoke(fileId) {
  if (!confirm('Revoke access for ALL recipients? They will no longer be able to download this file.')) return;
  try {
    const res = await authFetch(`${API}/files/${fileId}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail ?? 'Revoke failed.');
    toast('Access revoked for all recipients.');
  } catch (err) {
    alert(`Could not revoke: ${err.message}`);
  }
}

async function handleDelete(fileId) {
  if (!confirm('Delete this upload? This cannot be undone.')) return;
  try {
    const res = await authFetch(`${API}/files/${fileId}`, { method: 'DELETE' });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail ?? 'Delete failed.');
    await refreshLists();
  } catch (err) {
    alert(`Could not delete: ${err.message}`);
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
      document.getElementById('upload-recipient').value = item.dataset.username;
      box.innerHTML = '';
    });
  });
}

// ── Settings modal (change password) ───────────────────────────────────────────

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

  const close = () => { modal.style.display = 'none'; };
  document.getElementById('settings-modal-close').onclick  = close;
  document.getElementById('settings-modal-cancel').onclick = close;
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

  if (newPw !== confPw)  return showStatus(status, 'New passwords do not match.', 'error');
  if (newPw.length < 8)  return showStatus(status, 'New password must be at least 8 characters.', 'error');

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
    if (!res.ok) throw new Error(body.detail ?? 'Password change failed.');

    showStatus(status, 'Password changed. Signing out…', 'success');
    setTimeout(() => { clearSession(); window.location.href = 'index.html'; }, 1500);
  } catch (err) {
    showStatus(status, err.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="key-round"></i> Change Password';
    lucide.createIcons();
  }
}

// ── Logout / session ───────────────────────────────────────────────────────────

async function doLogout() {
  const refresh = localStorage.getItem('sm_refresh_token');
  if (refresh) {
    await authFetch(`${API}/auth/logout`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ refresh_token: refresh }),
    }).catch(() => {});
  }
  sessionKey = null;   // drop the unlocked key with the session
  clearSession();
  window.location.href = 'index.html';
}

function clearSession() {
  ['sm_token', 'sm_refresh_token', 'sm_username'].forEach(k => localStorage.removeItem(k));
}

// ── Utilities ──────────────────────────────────────────────────────────────────

/**
 * FastAPI returns validation errors as
 *   { detail: [ { loc, msg, type }, … ] }   (422)
 * and plain errors as { detail: "string" }.  Pydantic v2 prefixes
 * value_error messages with "Value error, " — strip it.
 */
function parseApiError(data, fallback) {
  const { detail } = data ?? {};
  if (!detail) return fallback;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    return detail
      .map(e => (e.msg ?? '').replace(/^Value error,\s*/i, ''))
      .filter(Boolean)
      .join(' ') || fallback;
  }
  return fallback;
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtSize(bytes) {
  if (bytes == null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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

let _toastTimer = null;
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), 4000);
}
