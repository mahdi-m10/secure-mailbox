const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying MessageDigest with account:", deployer.address);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("Account balance:", ethers.formatEther(balance), "ETH");

  const MessageDigest = await ethers.getContractFactory("MessageDigest");
  const contract = await MessageDigest.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("MessageDigest deployed to:", address);
  console.log("\nAdd to your .env:");
  console.log(`CONTRACT_ADDRESS=${address}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
