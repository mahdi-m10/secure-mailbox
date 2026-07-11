const { ethers, network } = require("hardhat");

// No-cost preflight: confirms the RPC is reachable, the deployer key loaded,
// the network is Sepolia, and the wallet has enough ETH to deploy. Sends no
// transaction. Run this before deploying so a missing key / wrong network /
// empty balance fails here instead of half-way through a live deploy.
async function main() {
  const [signer] = await ethers.getSigners();
  if (!signer) throw new Error("No signer — is DEPLOYER_PRIVATE_KEY set in ../.env?");

  const net = await ethers.provider.getNetwork();
  const balance = await ethers.provider.getBalance(signer.address);
  const eth = ethers.formatEther(balance);

  console.log("hardhat network:", network.name);
  console.log("chainId:        ", net.chainId.toString(), net.chainId === 11155111n ? "(Sepolia ✓)" : "(NOT Sepolia ✗)");
  console.log("deployer:       ", signer.address);
  console.log("balance:        ", eth, "ETH");

  if (net.chainId !== 11155111n) throw new Error("Not connected to Sepolia (chainId 11155111).");
  if (balance === 0n) throw new Error("Deployer has 0 ETH — fund it from a Sepolia faucet first.");
  if (balance < ethers.parseEther("0.01"))
    console.log("WARNING: balance is low; deploy + 4 txs may need ~0.01+ Sepolia ETH.");
  console.log("\nPreflight OK — safe to deploy.");
}

main().catch((e) => { console.error(e.message || e); process.exitCode = 1; });
