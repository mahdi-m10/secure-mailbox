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

/**
 * On-chain KeyRegistry configuration.
 *
 * The client reads the registry DIRECTLY over JSON-RPC — deliberately not
 * via our own backend: a compromised server must not be able to answer its
 * own integrity check (docs/crypto-design.md §8.11). The RPC endpoint is a
 * public, keyless Sepolia node (publicnode.com): no API key to leak in
 * page source, at the cost of public-endpoint rate limits — recorded as a
 * known limitation in the design doc.
 *
 * localStorage overrides (sm_chain_rpc / sm_chain_registry) exist so the
 * same build can point at a local Hardhat node during development and
 * integration testing without editing source.
 *
 * keyRegistryAddress defaults to the live Sepolia deployment (see
 * docs/deployment.md). The sm_chain_registry localStorage override points the
 * same build at a local Hardhat node for development/integration testing. If
 * the default is ever cleared to empty, the chain check reports "unconfigured"
 * (treated as an RPC failure: fail closed with an explicit override, never
 * silently skipped).
 */
export const CHAIN = {
  rpcUrl:
    localStorage.getItem('sm_chain_rpc') ??
    'https://ethereum-sepolia-rpc.publicnode.com',
  keyRegistryAddress:
    localStorage.getItem('sm_chain_registry') ??
    '0x230c56Ab59535625c8eAeF18f8394b7D222a889D',
};
