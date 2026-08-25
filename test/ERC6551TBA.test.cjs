/**
 * ERC6551TBA.test.cjs
 *
 * Hardhat / Chai tests for issue #79:
 *   ERC-6551 Token Bound Accounts for SpooVault NFTs.
 *
 * Covers:
 *  - Deterministic TBA address computation (same inputs → same address)
 *  - TBA deployment via ERC6551Registry.createAccount
 *  - Idempotent deployment (second call returns existing address)
 *  - owner() reflects live ERC-721 ownership (updates on transfer)
 *  - token() decodes (chainId, tokenContract, tokenId) correctly
 *  - executeCall: owner can forward ETH transfers and contract calls
 *  - executeCall: non-owner is rejected
 *  - executeCall: reverts bubble up from callee
 *  - TBA can receive and hold ETH
 *  - TBA can receive ERC-721 tokens (nested document sub-tokens)
 *  - state nonce increments on each execution
 *  - Access delegation via executeCall on SpooVault
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySpooVault } = require("./helpers/deploySpooVault.cjs");

describe("ERC-6551 Token Bound Accounts", function () {
  let registry;
  let implementation;
  let spooVault;

  let owner;
  let guardian1;
  let guardian2;
  let beneficiary;
  let other;

  // Token ID minted for `owner` during vault creation
  const VAULT_TOKEN_ID = 1;
  const SALT = 0;

  beforeEach(async function () {
    [owner, guardian1, guardian2, beneficiary, other] =
      await ethers.getSigners();

    // Deploy registry and implementation
    const Registry = await ethers.getContractFactory("ERC6551Registry");
    registry = await Registry.deploy();
    await registry.waitForDeployment();

    const Impl = await ethers.getContractFactory("SpooAccountImplementation");
    implementation = await Impl.deploy(await registry.getAddress());
    await implementation.waitForDeployment();

    // Deploy SpooVault and create a vault so owner receives a vault NFT
    spooVault = await deploySpooVault();
    await spooVault.waitForDeployment();

    // Create vault: owner + guardian1 → threshold 1
    await spooVault
      .connect(owner)
      .createVault("TBA Vault", "ERC-6551 test vault", [guardian1.address], 1);

    // Mint vault NFT to owner (tokenId 1). Owner is guardian of vault 1.
    await spooVault.connect(owner).mintAccessToken(1, owner.address, "ipfs://tba-test");
  });

  // ── Helpers ──────────────────────────────────────────────────────────────

  /** Returns the pre-computed TBA address for the given token */
  async function computeTBA(tokenId) {
    const chainId = (await ethers.provider.getNetwork()).chainId;
    return registry.account(
      await implementation.getAddress(),
      chainId,
      await spooVault.getAddress(),
      tokenId,
      SALT
    );
  }

  /** Deploys (or retrieves) the TBA for the given token */
  async function deployTBA(tokenId) {
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const tx = await registry.createAccount(
      await implementation.getAddress(),
      chainId,
      await spooVault.getAddress(),
      tokenId,
      SALT,
      "0x"
    );
    await tx.wait();
    return computeTBA(tokenId);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // 1. Registry: deterministic address computation
  // ─────────────────────────────────────────────────────────────────────────

  describe("ERC6551Registry – deterministic addressing", function () {
    it("account() returns the same address for identical inputs", async function () {
      const addr1 = await computeTBA(VAULT_TOKEN_ID);
      const addr2 = await computeTBA(VAULT_TOKEN_ID);
      expect(addr1).to.equal(addr2);
    });

    it("account() returns different addresses for different tokenIds", async function () {
      const chainId = (await ethers.provider.getNetwork()).chainId;
      const implAddr = await implementation.getAddress();
      const nftAddr = await spooVault.getAddress();

      const addr1 = await registry.account(implAddr, chainId, nftAddr, 1, SALT);
      const addr2 = await registry.account(implAddr, chainId, nftAddr, 2, SALT);
      expect(addr1).to.not.equal(addr2);
    });

    it("account() returns different addresses for different salts", async function () {
      const chainId = (await ethers.provider.getNetwork()).chainId;
      const implAddr = await implementation.getAddress();
      const nftAddr = await spooVault.getAddress();

      const addr1 = await registry.account(implAddr, chainId, nftAddr, 1, 0);
      const addr2 = await registry.account(implAddr, chainId, nftAddr, 1, 1);
      expect(addr1).to.not.equal(addr2);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 2. Registry: createAccount deployment
  // ─────────────────────────────────────────────────────────────────────────

  describe("ERC6551Registry – createAccount", function () {
    it("deploys a TBA at the pre-computed address", async function () {
      const precomputed = await computeTBA(VAULT_TOKEN_ID);
      const deployed = await deployTBA(VAULT_TOKEN_ID);
      expect(deployed).to.equal(precomputed);
    });

    it("emits ERC6551AccountCreated on first deployment", async function () {
      const chainId = (await ethers.provider.getNetwork()).chainId;
      await expect(
        registry.createAccount(
          await implementation.getAddress(),
          chainId,
          await spooVault.getAddress(),
          VAULT_TOKEN_ID,
          SALT,
          "0x"
        )
      ).to.emit(registry, "ERC6551AccountCreated");
    });

    it("is idempotent: second createAccount returns same address, no event", async function () {
      const chainId = (await ethers.provider.getNetwork()).chainId;
      const implAddr = await implementation.getAddress();
      const nftAddr = await spooVault.getAddress();

      // First deployment
      await registry.createAccount(implAddr, chainId, nftAddr, VAULT_TOKEN_ID, SALT, "0x");

      // Second call must not emit the event (account already exists)
      await expect(
        registry.createAccount(implAddr, chainId, nftAddr, VAULT_TOKEN_ID, SALT, "0x")
      ).to.not.emit(registry, "ERC6551AccountCreated");
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 3. SpooAccountImplementation – token() context decoding
  // ─────────────────────────────────────────────────────────────────────────

  describe("SpooAccountImplementation – token()", function () {
    it("decodes chainId, tokenContract, and tokenId correctly", async function () {
      const tbaAddr = await deployTBA(VAULT_TOKEN_ID);
      const tba = await ethers.getContractAt(
        "SpooAccountImplementation",
        tbaAddr
      );

      const chainId = (await ethers.provider.getNetwork()).chainId;
      const [tbaChainId, tbaContract, tbaTokenId] = await tba.token();

      expect(tbaChainId).to.equal(chainId);
      expect(tbaContract.toLowerCase()).to.equal(
        (await spooVault.getAddress()).toLowerCase()
      );
      expect(tbaTokenId).to.equal(VAULT_TOKEN_ID);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 4. SpooAccountImplementation – owner()
  // ─────────────────────────────────────────────────────────────────────────

  describe("SpooAccountImplementation – owner()", function () {
    it("returns the current NFT owner", async function () {
      const tbaAddr = await deployTBA(VAULT_TOKEN_ID);
      const tba = await ethers.getContractAt(
        "SpooAccountImplementation",
        tbaAddr
      );
      expect(await tba.owner()).to.equal(owner.address);
    });

    it("reflects ownership after NFT transfer", async function () {
      const tbaAddr = await deployTBA(VAULT_TOKEN_ID);
      const tba = await ethers.getContractAt(
        "SpooAccountImplementation",
        tbaAddr
      );

      // Transfer NFT from owner → beneficiary
      await spooVault
        .connect(owner)
        .transferFrom(owner.address, beneficiary.address, VAULT_TOKEN_ID);

      expect(await tba.owner()).to.equal(beneficiary.address);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 5. SpooAccountImplementation – executeCall
  // ─────────────────────────────────────────────────────────────────────────

  describe("SpooAccountImplementation – executeCall", function () {
    let tba;
    let tbaAddr;

    beforeEach(async function () {
      tbaAddr = await deployTBA(VAULT_TOKEN_ID);
      tba = await ethers.getContractAt("SpooAccountImplementation", tbaAddr);
    });

    it("allows owner to forward an ETH transfer", async function () {
      // Fund the TBA first
      await owner.sendTransaction({ to: tbaAddr, value: ethers.parseEther("1") });

      const beforeBalance = await ethers.provider.getBalance(beneficiary.address);

      await tba
        .connect(owner)
        .executeCall(beneficiary.address, ethers.parseEther("0.5"), "0x");

      const afterBalance = await ethers.provider.getBalance(beneficiary.address);
      expect(afterBalance - beforeBalance).to.equal(ethers.parseEther("0.5"));
    });

    it("emits Executed event on success", async function () {
      await owner.sendTransaction({ to: tbaAddr, value: ethers.parseEther("0.1") });

      await expect(
        tba
          .connect(owner)
          .executeCall(beneficiary.address, ethers.parseEther("0.01"), "0x")
      ).to.emit(tba, "Executed");
    });

    it("increments state nonce on each execution", async function () {
      await owner.sendTransaction({ to: tbaAddr, value: ethers.parseEther("0.2") });

      const before = await tba.state();
      await tba.connect(owner).executeCall(beneficiary.address, ethers.parseEther("0.01"), "0x");
      await tba.connect(owner).executeCall(beneficiary.address, ethers.parseEther("0.01"), "0x");
      const after = await tba.state();

      expect(after - before).to.equal(2n);
    });

    it("reverts if caller is not the NFT owner", async function () {
      await expect(
        tba
          .connect(other)
          .executeCall(beneficiary.address, 0, "0x")
      ).to.be.revertedWithCustomError(tba, "NotTokenOwner");
    });

    it("bubbles up revert reason from callee", async function () {
      // Encode a call to createVault with invalid args (no external guardians)
      const badData = spooVault.interface.encodeFunctionData("createVault", [
        "Bad",
        "Bad",
        [],
        1,
      ]);
      await expect(
        tba
          .connect(owner)
          .executeCall(await spooVault.getAddress(), 0, badData)
      ).to.be.revertedWithCustomError(spooVault, "AtLeastOneGuardian");
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 6. TBA as asset holder
  // ─────────────────────────────────────────────────────────────────────────

  describe("SpooAccountImplementation – asset holding", function () {
    it("TBA can receive and hold ETH", async function () {
      const tbaAddr = await deployTBA(VAULT_TOKEN_ID);

      await owner.sendTransaction({
        to: tbaAddr,
        value: ethers.parseEther("1"),
      });

      const balance = await ethers.provider.getBalance(tbaAddr);
      expect(balance).to.equal(ethers.parseEther("1"));
    });

    it("TBA can receive an ERC-721 token (nested document token)", async function () {
      // Mint a second vault NFT representing a nested document credential
      await spooVault
        .connect(owner)
        .createVault("Sub Vault", "Nested", [guardian2.address], 1);
      await spooVault.connect(owner).mintAccessToken(2, owner.address, "ipfs://sub-vault");

      const tbaAddr = await deployTBA(VAULT_TOKEN_ID);

      // Transfer the second vault NFT into the TBA
      await spooVault
        .connect(owner)
        .transferFrom(owner.address, tbaAddr, 2);

      expect(await spooVault.ownerOf(2)).to.equal(tbaAddr);
    });
  });

  // ─────────────────────────────────────────────────────────────────────────
  // 7. Access delegation via executeCall on SpooVault
  // ─────────────────────────────────────────────────────────────────────────

  describe("Access delegation through TBA", function () {
    it("TBA owner can register a public key on SpooVault via executeCall", async function () {
      const tbaAddr = await deployTBA(VAULT_TOKEN_ID);
      const tba = await ethers.getContractAt(
        "SpooAccountImplementation",
        tbaAddr
      );

      const pubKey = "TBA_PUBLIC_KEY_BASE64_PLACEHOLDER";
      const callData = spooVault.interface.encodeFunctionData(
        "registerPublicKey",
        [pubKey]
      );

      await expect(
        tba
          .connect(owner)
          .executeCall(await spooVault.getAddress(), 0, callData)
      )
        .to.emit(spooVault, "PublicKeyRegistered")
        .withArgs(tbaAddr, pubKey);
    });
  });
});
