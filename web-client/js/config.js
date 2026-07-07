/**
 * config.js — shared client configuration.
 *
 * API base URL: the web client is served by the backend itself (mounted at
 * /app), so same-origin is always correct — and matches the CSP's
 * connect-src 'self'. The hardcoded host is only a fallback for the odd
 * case of opening the HTML from disk (file://) during development.
 */
export const API = window.location.origin.startsWith('http')
  ? window.location.origin
  : 'https://team10.theburkenator.com';
