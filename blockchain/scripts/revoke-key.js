const { ethers } = require("hardhat");

// Revoke an existing identity's key in the live KeyRegistry. The record stays
// readable (version/key preserved) with revoked=true, so clients can tell
// "revoked" apart from "never registered". Reverts if not registered or
// already revoked.
//
// Config via env:
//   KEY_REGISTRY_ADDRESS  deployed KeyRegistry address (required)
//   REGISTRY_USERNAME     username to revoke (default "demo-user")
async function main() {
  const address = process.env.KEY_REGISTRY_ADDRESS;
  if (!address) throw new Error("Set KEY_REGISTRY_ADDRESS in .env first");
  const username = process.env.REGISTRY_USERNAME || "demo-user";

  const identity = ethers.keccak256(ethers.toUtf8Bytes(username));
  const [signer] = await ethers.getSigners();
  const registry = await ethers.getContractAt("KeyRegistry", address);

  console.log("registry:      ", address);
  console.log("registrar:     ", signer.address);
  console.log("username:      ", username);
  console.log("identity:      ", identity);

  const tx = await registry.revokeKey(identity);
  console.log("revoke tx:     ", tx.hash);
  const rc = await tx.wait();
  console.log("mined in block:", rc.blockNumber);

  const [k, v, updatedAt, revoked] = await registry.getKey(identity);
  console.log("on-chain now:   key=%s version=%s updatedAt=%s revoked=%s",
    k, v.toString(), updatedAt.toString(), revoked);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
