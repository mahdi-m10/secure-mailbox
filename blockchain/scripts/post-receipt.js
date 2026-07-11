const { ethers } = require("hardhat");

// Post an inclusion receipt for a ciphertext hash in the live MessageReceipt
// contract. Reverts on replay (one hash → one receipt, forever).
//
// Config via env:
//   MESSAGE_RECEIPT_ADDRESS   deployed MessageReceipt address (required)
//   RECEIPT_SENDER            sender username    (default "demo-sender")
//   RECEIPT_RECIPIENT         recipient username (default "demo-recipient")
//   RECEIPT_CIPHERTEXT_HASH   0x-hex 32-byte ciphertext hash; if unset a fresh
//                             random hash is generated and printed.
async function main() {
  const address = process.env.MESSAGE_RECEIPT_ADDRESS;
  if (!address) throw new Error("Set MESSAGE_RECEIPT_ADDRESS in .env first");
  const sender = process.env.RECEIPT_SENDER || "demo-sender";
  const recipient = process.env.RECEIPT_RECIPIENT || "demo-recipient";
  const ciphertextHash =
    process.env.RECEIPT_CIPHERTEXT_HASH || ethers.hexlify(ethers.randomBytes(32));

  const senderHash = ethers.keccak256(ethers.toUtf8Bytes(sender));
  const recipientHash = ethers.keccak256(ethers.toUtf8Bytes(recipient));
  const [signer] = await ethers.getSigners();
  const receipts = await ethers.getContractAt("MessageReceipt", address);

  console.log("contract:      ", address);
  console.log("server:        ", signer.address);
  console.log("sender:        ", sender, senderHash);
  console.log("recipient:     ", recipient, recipientHash);
  console.log("ciphertextHash:", ciphertextHash);

  const tx = await receipts.postReceipt(ciphertextHash, senderHash, recipientHash);
  console.log("receipt tx:    ", tx.hash);
  const rc = await tx.wait();
  console.log("mined in block:", rc.blockNumber);

  const [exists, sh, rh, ts, bn] = await receipts.getReceipt(ciphertextHash);
  console.log("on-chain now:   exists=%s senderHash=%s recipientHash=%s timestamp=%s blockNumber=%s",
    exists, sh, rh, ts.toString(), bn.toString());
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
