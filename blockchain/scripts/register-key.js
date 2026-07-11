const { ethers } = require("hardhat");

// Register a NEW identity's X25519 public key in the live KeyRegistry.
//
// Config via env (all optional except the address):
//   KEY_REGISTRY_ADDRESS  deployed KeyRegistry address (required)
//   REGISTRY_USERNAME     application username to register (default "demo-user")
//   X25519_KEY            32-byte key as 0x-hex; if unset a fresh random key
//                         is generated and printed (so rotate/revoke can reuse
//                         the same identity).
//
// NOTE: env var is REGISTRY_USERNAME, not USERNAME — USERNAME already exists
// in the OS environment (the login name) and dotenv won't override it.
async function main() {
  const address = process.env.KEY_REGISTRY_ADDRESS;
  if (!address) throw new Error("Set KEY_REGISTRY_ADDRESS in .env first");
  const username = process.env.REGISTRY_USERNAME || "demo-user";
  const key = process.env.X25519_KEY || ethers.hexlify(ethers.randomBytes(32));

  const identity = ethers.keccak256(ethers.toUtf8Bytes(username));
  const [signer] = await ethers.getSigners();
  const registry = await ethers.getContractAt("KeyRegistry", address);

  console.log("registry:      ", address);
  console.log("registrar:     ", signer.address);
  console.log("username:      ", username);
  console.log("identity:      ", identity);
  console.log("x25519 key:    ", key);

  const tx = await registry.registerKey(identity, key);
  console.log("register tx:   ", tx.hash);
  const rc = await tx.wait();
  console.log("mined in block:", rc.blockNumber);

  const [k, v, updatedAt, revoked] = await registry.getKey(identity);
  console.log("on-chain now:   key=%s version=%s updatedAt=%s revoked=%s",
    k, v.toString(), updatedAt.toString(), revoked);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
