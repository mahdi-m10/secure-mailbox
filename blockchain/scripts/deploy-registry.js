const { ethers } = require("hardhat");

// Deploys the two blockchain-brief contracts (KeyRegistry, MessageReceipt).
// Kept separate from deploy.js, which deploys the pre-existing MessageDigest
// contract already live on Sepolia — running this script never touches or
// re-deploys that contract.
async function deployOne(name) {
  const Factory = await ethers.getContractFactory(name);
  const contract = await Factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  const tx = contract.deploymentTransaction();
  console.log(`${name} deployed to: ${address}`);
  console.log(`  deployment tx: ${tx.hash}`);
  return { name, address, txHash: tx.hash };
}

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying with account:", deployer.address);
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("Account balance:", ethers.formatEther(balance), "ETH\n");

  const results = [];
  results.push(await deployOne("KeyRegistry"));
  results.push(await deployOne("MessageReceipt"));

  console.log("\nAdd to your .env:");
  for (const { name, address } of results) {
    const envVar = name === "KeyRegistry" ? "KEY_REGISTRY_ADDRESS" : "MESSAGE_RECEIPT_ADDRESS";
    console.log(`${envVar}=${address}`);
  }

  console.log("\nRecord these addresses, tx hashes, and their Etherscan links in docs/deployment.md.");
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
