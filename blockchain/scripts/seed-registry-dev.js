const { ethers } = require("hardhat");

// Development/test seeding for client-integration testing against a local
// Hardhat node: deploys KeyRegistry and creates one identity in each state
// a client must distinguish —
//   alice: registered (v1)
//   bob:   rotated    (v2)
//   carol: revoked
//   (dave: never registered — nothing to do)
// Prints the registry address and the exact keys used so the test driver
// can assert against them.
async function main() {
  const KeyRegistry = await ethers.getContractFactory("KeyRegistry");
  const registry = await KeyRegistry.deploy();
  await registry.waitForDeployment();
  const address = await registry.getAddress();

  const id = (name) => ethers.keccak256(ethers.toUtf8Bytes(name));
  const key = (seed) => ethers.keccak256(ethers.toUtf8Bytes("x25519-" + seed));

  await (await registry.registerKey(id("alice"), key("alice-v1"))).wait();

  await (await registry.registerKey(id("bob"), key("bob-v1"))).wait();
  await (await registry.rotateKey(id("bob"), key("bob-v2"))).wait();

  await (await registry.registerKey(id("carol"), key("carol-v1"))).wait();
  await (await registry.revokeKey(id("carol"))).wait();

  console.log(JSON.stringify({
    registry: address,
    alice_key: key("alice-v1"),
    bob_key: key("bob-v2"),
    carol_key: key("carol-v1"),
  }));
}

main().catch((err) => { console.error(err); process.exitCode = 1; });
