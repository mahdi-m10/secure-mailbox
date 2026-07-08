/**
 * auth.js — Login and registration logic for index.html
 *
 * Key-management strategy:
 *   - On register: prompt for a key-vault passphrase (distinct from the
 *     login password), generate an X25519 key pair, and store the private
 *     key ONLY passphrase-wrapped (crypto.js saveWrappedKeyPair) before
 *     registering the account with its public key.
 *   - On login: no key work here — files.html owns the vault lifecycle
 *     (unlock / create / legacy upgrade) and prompts for the passphrase
 *     before any encrypt/decrypt can run.
 *   - The private key never leaves the browser crypto engine or transits
 *     the network, and is never stored unwrapped.
 */

import { API } from './config.js';
import { generateKeyPair, saveWrappedKeyPair, deleteKeyPair } from './crypto.js';

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

  const username  = form.querySelector('#reg-username').value.trim();
  const email     = form.querySelector('#reg-email').value.trim();
  const password  = form.querySelector('#reg-password').value;
  const vaultPass = form.querySelector('#reg-vault-pass').value;
  const vaultRep  = form.querySelector('#reg-vault-pass2').value;

  clearStatus(status);

  // Vault passphrase rules: it protects the private key AT REST, so it must
  // not equal the login password (which the server sees at login and which
  // an attacker tries first).
  if (vaultPass.length < 8)     return setStatus(status, 'Key-vault passphrase must be at least 8 characters.', 'error');
  if (vaultPass !== vaultRep)   return setStatus(status, 'Key-vault passphrases do not match.', 'error');
  if (vaultPass === password)   return setStatus(status, 'The key-vault passphrase must be different from your login password.', 'error');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Generating keys…';

  try {
    const { publicKeyB64, privateKey } = await generateKeyPair();

    // Wrap-and-store BEFORE registering: if wrapping fails we abort with no
    // account created, rather than an account whose key was never persisted.
    // The extractable reference is dropped when this scope exits — only the
    // wrapped form is stored.
    btn.innerHTML = '<span class="spinner"></span> Encrypting key vault…';
    await saveWrappedKeyPair(username, publicKeyB64, privateKey, vaultPass);

    btn.innerHTML = '<span class="spinner"></span> Creating account…';
    const res  = await fetch(`${API}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password, public_key: publicKeyB64 }),
    });
    const data = await res.json();
    if (!res.ok) {
      // Don't leave an orphan vault behind for an account that was never
      // created (e.g. username taken).
      await deleteKeyPair(username).catch(() => {});
      throw new Error(parseApiError(data, 'Registration failed.'));
    }

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

    // All key-vault work (unlock / create / legacy upgrade / localStorage
    // migration) happens on files.html, which prompts for the vault
    // passphrase before any encrypt/decrypt operation is possible.
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
