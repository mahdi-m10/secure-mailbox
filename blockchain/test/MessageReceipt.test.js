const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { anyUint } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

describe("MessageReceipt", function () {
  async function deployFixture() {
    const [server, other] = await ethers.getSigners();
    const MessageReceipt = await ethers.getContractFactory("MessageReceipt");
    const contract = await MessageReceipt.deploy();

    const ciphertextHash = ethers.id("ciphertext-blob-1");
    const senderHash = ethers.id("alice");
    const recipientHash = ethers.id("bob");

    return { contract, server, other, ciphertextHash, senderHash, recipientHash };
  }

  it("deploys with the deployer as server", async function () {
    const { contract, server } = await loadFixture(deployFixture);
    expect(await contract.server()).to.equal(server.address);
  });

  // ── postReceipt ──────────────────────────────────────────────────────────

  it("posts a receipt and emits ReceiptPosted", async function () {
    const { contract, ciphertextHash, senderHash, recipientHash } = await loadFixture(
      deployFixture
    );

    await expect(contract.postReceipt(ciphertextHash, senderHash, recipientHash))
      .to.emit(contract, "ReceiptPosted")
      .withArgs(ciphertextHash, senderHash, recipientHash, anyUint);
  });

  it("getReceipt reflects the posted data with correct block number", async function () {
    const { contract, ciphertextHash, senderHash, recipientHash } = await loadFixture(
      deployFixture
    );

    const tx = await contract.postReceipt(ciphertextHash, senderHash, recipientHash);
    const receipt = await tx.wait();
    const block = await ethers.provider.getBlock(receipt.blockNumber);

    const [exists, sHash, rHash, timestamp, blockNumber] = await contract.getReceipt(
      ciphertextHash
    );
    expect(exists).to.equal(true);
    expect(sHash).to.equal(senderHash);
    expect(rHash).to.equal(recipientHash);
    expect(timestamp).to.equal(BigInt(block.timestamp));
    expect(blockNumber).to.equal(BigInt(receipt.blockNumber));
  });

  it("reverts posting a zero ciphertext hash", async function () {
    const { contract, senderHash, recipientHash } = await loadFixture(deployFixture);
    await expect(
      contract.postReceipt(ethers.ZeroHash, senderHash, recipientHash)
    ).to.be.revertedWith("MessageReceipt: zero hash");
  });

  it("reverts replay: posting a receipt for an already-receipted ciphertext", async function () {
    const { contract, ciphertextHash, senderHash, recipientHash } = await loadFixture(
      deployFixture
    );

    await contract.postReceipt(ciphertextHash, senderHash, recipientHash);

    // Replay attempt — even with different parties, the ciphertext hash is
    // the key: one ciphertext, one immutable receipt, forever.
    const otherSender = ethers.id("mallory");
    await expect(
      contract.postReceipt(ciphertextHash, otherSender, recipientHash)
    ).to.be.revertedWith("MessageReceipt: receipt exists");
  });

  it("reverts when a non-server address calls postReceipt", async function () {
    const { contract, other, ciphertextHash, senderHash, recipientHash } = await loadFixture(
      deployFixture
    );
    await expect(
      contract.connect(other).postReceipt(ciphertextHash, senderHash, recipientHash)
    ).to.be.revertedWith("MessageReceipt: caller is not server");
  });

  // ── getReceipt ───────────────────────────────────────────────────────────

  it("returns exists=false for a ciphertext hash with no receipt", async function () {
    const { contract } = await loadFixture(deployFixture);
    const unknownHash = ethers.id("never-uploaded");

    const [exists, senderHash, recipientHash, timestamp, blockNumber] = await contract.getReceipt(
      unknownHash
    );
    expect(exists).to.equal(false);
    expect(senderHash).to.equal(ethers.ZeroHash);
    expect(recipientHash).to.equal(ethers.ZeroHash);
    expect(timestamp).to.equal(0);
    expect(blockNumber).to.equal(0);
  });

  it("keeps receipts independent per ciphertext hash", async function () {
    const { contract, senderHash, recipientHash } = await loadFixture(deployFixture);
    const hashA = ethers.id("file-a");
    const hashB = ethers.id("file-b");

    await contract.postReceipt(hashA, senderHash, recipientHash);

    const [existsA] = await contract.getReceipt(hashA);
    const [existsB] = await contract.getReceipt(hashB);
    expect(existsA).to.equal(true);
    expect(existsB).to.equal(false);
  });

  // ── transferServer ───────────────────────────────────────────────────────

  it("transfers the server role and old server loses access", async function () {
    const { contract, server, other, ciphertextHash, senderHash, recipientHash } =
      await loadFixture(deployFixture);

    await expect(contract.transferServer(other.address))
      .to.emit(contract, "ServerTransferred")
      .withArgs(server.address, other.address);

    await expect(
      contract.postReceipt(ciphertextHash, senderHash, recipientHash)
    ).to.be.revertedWith("MessageReceipt: caller is not server");
    await expect(
      contract.connect(other).postReceipt(ciphertextHash, senderHash, recipientHash)
    ).to.not.be.reverted;
  });
});
