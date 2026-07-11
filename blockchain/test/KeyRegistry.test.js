const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { anyUint } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");

describe("KeyRegistry", function () {
  async function deployFixture() {
    const [registrar, other] = await ethers.getSigners();
    const KeyRegistry = await ethers.getContractFactory("KeyRegistry");
    const contract = await KeyRegistry.deploy();

    const aliceIdentity = ethers.id("alice");
    const bobIdentity = ethers.id("bob");
    const aliceKey = ethers.id("alice-x25519-pubkey-v1");
    const aliceKeyV2 = ethers.id("alice-x25519-pubkey-v2");

    return { contract, registrar, other, aliceIdentity, bobIdentity, aliceKey, aliceKeyV2 };
  }

  it("deploys with the deployer as registrar", async function () {
    const { contract, registrar } = await loadFixture(deployFixture);
    expect(await contract.registrar()).to.equal(registrar.address);
  });

  // ── registerKey ──────────────────────────────────────────────────────────

  it("registers a new identity at version 1 and emits KeyRegistered", async function () {
    const { contract, aliceIdentity, aliceKey } = await loadFixture(deployFixture);

    await expect(contract.registerKey(aliceIdentity, aliceKey))
      .to.emit(contract, "KeyRegistered")
      .withArgs(aliceIdentity, aliceKey, 1, anyUint);

    const [key, version, , revoked] = await contract.getKey(aliceIdentity);
    expect(key).to.equal(aliceKey);
    expect(version).to.equal(1);
    expect(revoked).to.equal(false);
  });

  it("reverts on double registration of the same identity", async function () {
    const { contract, aliceIdentity, aliceKey, aliceKeyV2 } = await loadFixture(deployFixture);

    await contract.registerKey(aliceIdentity, aliceKey);
    await expect(contract.registerKey(aliceIdentity, aliceKeyV2)).to.be.revertedWith(
      "KeyRegistry: already registered"
    );
  });

  it("reverts registering a zero key", async function () {
    const { contract, aliceIdentity } = await loadFixture(deployFixture);
    await expect(
      contract.registerKey(aliceIdentity, ethers.ZeroHash)
    ).to.be.revertedWith("KeyRegistry: zero key");
  });

  it("reverts when a non-registrar calls registerKey", async function () {
    const { contract, other, aliceIdentity, aliceKey } = await loadFixture(deployFixture);
    await expect(
      contract.connect(other).registerKey(aliceIdentity, aliceKey)
    ).to.be.revertedWith("KeyRegistry: caller is not registrar");
  });

  // ── rotateKey ────────────────────────────────────────────────────────────

  it("rotates a key, bumping the version and re-emitting KeyRegistered", async function () {
    const { contract, aliceIdentity, aliceKey, aliceKeyV2 } = await loadFixture(deployFixture);

    await contract.registerKey(aliceIdentity, aliceKey);
    await expect(contract.rotateKey(aliceIdentity, aliceKeyV2))
      .to.emit(contract, "KeyRegistered")
      .withArgs(aliceIdentity, aliceKeyV2, 2, anyUint);

    const [key, version] = await contract.getKey(aliceIdentity);
    expect(key).to.equal(aliceKeyV2);
    expect(version).to.equal(2);
  });

  it("clears revocation on rotation", async function () {
    const { contract, aliceIdentity, aliceKey, aliceKeyV2 } = await loadFixture(deployFixture);

    await contract.registerKey(aliceIdentity, aliceKey);
    await contract.revokeKey(aliceIdentity);
    await contract.rotateKey(aliceIdentity, aliceKeyV2);

    const [, , , revoked] = await contract.getKey(aliceIdentity);
    expect(revoked).to.equal(false);
  });

  it("reverts rotating an unregistered identity", async function () {
    const { contract, aliceIdentity, aliceKey } = await loadFixture(deployFixture);
    await expect(contract.rotateKey(aliceIdentity, aliceKey)).to.be.revertedWith(
      "KeyRegistry: not registered"
    );
  });

  it("reverts rotating to the same key", async function () {
    const { contract, aliceIdentity, aliceKey } = await loadFixture(deployFixture);
    await contract.registerKey(aliceIdentity, aliceKey);
    await expect(contract.rotateKey(aliceIdentity, aliceKey)).to.be.revertedWith(
      "KeyRegistry: key unchanged"
    );
  });

  it("reverts when a non-registrar calls rotateKey", async function () {
    const { contract, other, aliceIdentity, aliceKey, aliceKeyV2 } = await loadFixture(
      deployFixture
    );
    await contract.registerKey(aliceIdentity, aliceKey);
    await expect(
      contract.connect(other).rotateKey(aliceIdentity, aliceKeyV2)
    ).to.be.revertedWith("KeyRegistry: caller is not registrar");
  });

  // ── revokeKey ────────────────────────────────────────────────────────────

  it("revokes a registered key and emits KeyRevoked", async function () {
    const { contract, aliceIdentity, aliceKey } = await loadFixture(deployFixture);
    await contract.registerKey(aliceIdentity, aliceKey);

    await expect(contract.revokeKey(aliceIdentity))
      .to.emit(contract, "KeyRevoked")
      .withArgs(aliceIdentity, 1, anyUint);

    const [key, version, , revoked] = await contract.getKey(aliceIdentity);
    // Revoked records stay readable — clients must distinguish "revoked"
    // from "never registered", which requires the key to still be visible.
    expect(key).to.equal(aliceKey);
    expect(version).to.equal(1);
    expect(revoked).to.equal(true);
  });

  it("reverts revoking an unregistered identity", async function () {
    const { contract, aliceIdentity } = await loadFixture(deployFixture);
    await expect(contract.revokeKey(aliceIdentity)).to.be.revertedWith(
      "KeyRegistry: not registered"
    );
  });

  it("reverts double revocation", async function () {
    const { contract, aliceIdentity, aliceKey } = await loadFixture(deployFixture);
    await contract.registerKey(aliceIdentity, aliceKey);
    await contract.revokeKey(aliceIdentity);
    await expect(contract.revokeKey(aliceIdentity)).to.be.revertedWith(
      "KeyRegistry: already revoked"
    );
  });

  it("reverts when a non-registrar calls revokeKey", async function () {
    const { contract, other, aliceIdentity, aliceKey } = await loadFixture(deployFixture);
    await contract.registerKey(aliceIdentity, aliceKey);
    await expect(contract.connect(other).revokeKey(aliceIdentity)).to.be.revertedWith(
      "KeyRegistry: caller is not registrar"
    );
  });

  // ── getKey ───────────────────────────────────────────────────────────────

  it("returns version 0 for an identity that was never registered", async function () {
    const { contract, bobIdentity } = await loadFixture(deployFixture);
    const [key, version, updatedAt, revoked] = await contract.getKey(bobIdentity);
    expect(key).to.equal(ethers.ZeroHash);
    expect(version).to.equal(0);
    expect(updatedAt).to.equal(0);
    expect(revoked).to.equal(false);
  });

  it("keeps identities independent", async function () {
    const { contract, aliceIdentity, bobIdentity, aliceKey } = await loadFixture(deployFixture);
    await contract.registerKey(aliceIdentity, aliceKey);

    const [, bobVersion] = await contract.getKey(bobIdentity);
    expect(bobVersion).to.equal(0);
  });

  // ── transferRegistrar ────────────────────────────────────────────────────

  it("transfers the registrar role and old registrar loses access", async function () {
    const { contract, registrar, other, aliceIdentity, aliceKey } = await loadFixture(
      deployFixture
    );

    await expect(contract.transferRegistrar(other.address))
      .to.emit(contract, "RegistrarTransferred")
      .withArgs(registrar.address, other.address);

    await expect(contract.registerKey(aliceIdentity, aliceKey)).to.be.revertedWith(
      "KeyRegistry: caller is not registrar"
    );
    await expect(contract.connect(other).registerKey(aliceIdentity, aliceKey)).to.not.be.reverted;
  });
});
