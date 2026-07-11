const { ethers } = require("hardhat");

// Rotate an existing identity's key in the live KeyRegistry (bumps version,
// clears any revocation). Reverts if the identity is not registered or if the
// new key equals the current one.
//
// Config via env:
//   KEY_REGISTRY_ADDRESS  deployed KeyRegistry address (required)
//   REGISTRY_USERNAME     username to rotate (default "demo-user")
//   X25519_KEY            new 32-byte key as 0x-hex; if unset a fresh random
//                         key is generated (guaranteed != current key).
async function main() {
  const address = process.env.KEY_REGISTRY_ADDRESS;
  if (!address) throw new Error("Set KEY_REGISTRY_ADDRESS in .env first");
  const username = process.env.REGISTRY_USERNAME || "demo-user";

  const identity = ethers.keccak256(ethers.toUtf8Bytes(username));
  const [signer] = await ethers.getSigners();
  const registry = await ethers.getContractAt("KeyRegistry", address);

  const [current] = await registry.getKey(identity);
  let key = process.env.X25519_KEY;
  if (!key) {
    do { key = ethers.hexlify(ethers.randomBytes(32)); } while (key === current);
  }

  console.log("registry:      ", address);
  console.log("registrar:     ", signer.address);
  console.log("username:      ", username);
  console.log("identity:      ", identity);
  console.log("current key:   ", current);
  console.log("new key:       ", key);

  const tx = await registry.rotateKey(identity, key);
  console.log("rotate tx:     ", tx.hash);
  const rc = await tx.wait();
  console.log("mined in block:", rc.blockNumber);

  const [k, v, updatedAt, revoked] = await registry.getKey(identity);
  console.log("on-chain now:   key=%s version=%s updatedAt=%s revoked=%s",
    k, v.toString(), updatedAt.toString(), revoked);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
