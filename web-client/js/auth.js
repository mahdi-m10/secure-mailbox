/**
 * auth.js — Login and registration logic for index.html
 *
 * Key-management strategy:
 *   - On register: generate X25519 key pair, store the private key as a
 *     non-extractable CryptoKey in IndexedDB, upload public key to the server.
 *   - On login: ensure IndexedDB holds a key for this device; migrate any legacy
 *     localStorage JWK first, otherwise generate a fresh pair and upload it.
 *   - Private key NEVER leaves the browser crypto engine or transits the network.
 */

import { API } from './config.js';
import { generateKeyPair, saveKeyPair, hasKeyPair, migrateLocalStorageKey } from './crypto.js';

// ---------- Session helpers ---------------------------------------------------

function saveSession(token, refreshToken, username) {
  localStorage.setItem('sm_token',    token);
  localStorage.setItem('sm_username', username);
  if (refreshToken) localStorage.setItem('sm_refresh_token', refreshToken);
}

function isLoggedIn() { return !!localStorage.getItem('sm_token'); }

// ---------- Page init ---------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  // Already authenticated → go straight to the mailbox
  if (isLoggedIn()) { window.location.href = 'files.html'; return; }

  // Tab switching
  document.querySelectorAll('.auth-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.dataset.target;
      document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(targetId).classList.add('active');
    });
  });

  document.getElementById('login-form').addEventListener('submit', handleLogin);
  document.getElementById('register-form').addEventListener('submit', handleRegister);
});

// ---------- Register ----------------------------------------------------------

async function handleRegister(e) {
  e.preventDefault();
  const form   = e.target;
  const btn    = form.querySelector('[type="submit"]');
  const status = document.getElementById('register-status');

  const username = form.querySelector('#reg-username').value.trim();
  const email    = form.querySelector('#reg-email').value.trim();
  const password = form.querySelector('#reg-password').value;

  clearStatus(status);
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Generating keys…';

  try {
    const { publicKeyB64, privateKey } = await generateKeyPair();

    const res  = await fetch(`${API}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password, public_key: publicKeyB64 }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(parseApiError(data, 'Registration failed.'));

    // Store the non-extractable private key in IndexedDB.
    // Key bytes are permanently inaccessible to JavaScript — XSS can use the
    // key this session but cannot read or exfiltrate the raw material.
    await saveKeyPair(username, publicKeyB64, privateKey);

    setStatus(status, 'Account created. You can now sign in.', 'success');
    form.reset();

    // Auto-switch to login tab and prefill username
    document.querySelector('[data-target="login-form"]').click();
    document.getElementById('login-username').value = username;

  } catch (err) {
    setStatus(status, err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Account';
  }
}

// ---------- Login -------------------------------------------------------------

async function handleLogin(e) {
  e.preventDefault();
  const form   = e.target;
  const btn    = form.querySelector('[type="submit"]');
  const status = document.getElementById('login-status');

  const username = form.querySelector('#login-username').value.trim();
  const password = form.querySelector('#login-password').value;

  clearStatus(status);
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Signing in…';

  try {
    const res  = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(parseApiError(data, 'Login failed.'));

    saveSession(data.access_token, data.refresh_token, username);

    // Ensure a non-extractable X25519 private key is available in IndexedDB.
    if (!(await hasKeyPair(username))) {
      btn.innerHTML = '<span class="spinner"></span> Setting up encryption keys…';

      // First, try migrating a legacy JWK left in localStorage by an older build.
      // migrateLocalStorageKey() always clears localStorage on exit whether it
      // succeeds or not, so legacy key material is never left behind.
      const migrated = await migrateLocalStorageKey(username);

      if (!migrated) {
        // Nothing to migrate — generate a fresh key pair and publish the public key.
        // Note: messages encrypted to any previous public key will no longer be
        // decryptable on this device (expected behaviour for a new device / key loss).
        const { publicKeyB64, privateKey } = await generateKeyPair();
        await saveKeyPair(username, publicKeyB64, privateKey);

        const keyRes = await fetch(`${API}/users/keys`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${data.access_token}`,
          },
          body: JSON.stringify({ public_key: publicKeyB64 }),
        });
        if (!keyRes.ok) {
          const err = await keyRes.json().catch(() => ({}));
          throw new Error(err.detail ?? 'Failed to register your public key. Please try again.');
        }
      }
    } else {
      // Key already in IndexedDB — remove any co-existing legacy JWK from localStorage
      // so extractable key material does not linger after a partial migration.
      localStorage.removeItem(`sm_privkey_${username}`);
      localStorage.removeItem(`sm_pubkey_${username}`);
    }

    window.location.href = 'files.html';

  } catch (err) {
    setStatus(status, err.message, 'error');
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }
}

// ---------- API error helpers -------------------------------------------------

/**
 * FastAPI returns validation errors as:
 *   { detail: [ { loc, msg, type }, … ] }   (422 Unprocessable Entity)
 * and plain errors as:
 *   { detail: "some string" }
 *
 * Pydantic v2 prefixes value_error messages with "Value error, " — strip it.
 */
function parseApiError(data, fallback) {
  const { detail } = data;
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

// ---------- Status helpers ----------------------------------------------------

function setStatus(el, msg, type) {
  el.textContent   = msg;
  el.className     = `alert alert-${type}`;
  el.style.display = 'block';
}

function clearStatus(el) {
  el.textContent   = '';
  el.className     = 'alert';
  el.style.display = 'none';
}
