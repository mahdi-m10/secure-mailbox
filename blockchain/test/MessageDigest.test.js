const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

describe("MessageDigest", function () {
  async function deployFixture() {
    const [owner, other] = await ethers.getSigners();
    const MessageDigest = await ethers.getContractFactory("MessageDigest");
    const contract = await MessageDigest.deploy();
    return { contract, owner, other };
  }

  it("deploys with the deployer as owner", async function () {
    const { contract, owner } = await loadFixture(deployFixture);
    expect(await contract.owner()).to.equal(owner.address);
  });

  it("records a hash and verifies it was stored", async function () {
    const { contract } = await loadFixture(deployFixture);
    const hash = ethers.id("hello world");

    await contract.recordHash(hash);

    expect(await contract.digestCount()).to.equal(1n);
    const { exists } = await contract.getIndexByHash(hash);
    expect(exists).to.be.true;
  });

  it("getDigest returns the correct hash and timestamp", async function () {
    const { contract } = await loadFixture(deployFixture);
    const hash = ethers.id("message content");

    const tx = await contract.recordHash(hash);
    const receipt = await tx.wait();
    const block = await ethers.provider.getBlock(receipt.blockNumber);

    const [storedHash, storedTimestamp] = await contract.getDigest(0);
    expect(storedHash).to.equal(hash);
    expect(storedTimestamp).to.equal(BigInt(block.timestamp));
  });

  it("rejects a duplicate hash", async function () {
    const { contract } = await loadFixture(deployFixture);
    const hash = ethers.id("duplicate");

    await contract.recordHash(hash);
    await expect(contract.recordHash(hash)).to.be.revertedWith(
      "MessageDigest: hash already recorded"
    );
  });

  it("reverts when a non-owner calls recordHash", async function () {
    const { contract, other } = await loadFixture(deployFixture);
    const hash = ethers.id("unauthorized");

    await expect(contract.connect(other).recordHash(hash)).to.be.revertedWith(
      "MessageDigest: caller is not owner"
    );
  });
});
