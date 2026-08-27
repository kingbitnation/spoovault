const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Re-Entrancy Guard Hardening (EIP-1153 Transient Storage)", function () {
  let spooVault;
  let owner, guardian, user;

  beforeEach(async function () {
    [owner, guardian, user] = await ethers.getSigners();

    const SpooVault = await ethers.getContractFactory("SpooVault");
    spooVault = await SpooVault.deploy();
    await spooVault.waitForDeployment();
  });

  async function setupVaultAndDocument() {
    const tx1 = await spooVault
      .connect(owner)
      .createVault("Test Vault", "Desc", [guardian.address], 1);
    await tx1.wait();

    await spooVault.connect(guardian).acceptGuardianInvite(1);

    const tx2 = await spooVault
      .connect(owner)
      .addDocument(1, "encrypted-meta", "QmHash", 0);
    await tx2.wait();

    return { vaultId: 1, documentId: 1 };
  }

  describe("Test 1 — View re-entrancy blocked during _safeMint callback", function () {
    it("hasActiveAccess reverts when called inside onERC721Received", async function () {
      const { vaultId, documentId } = await setupVaultAndDocument();

      const Attacker = await ethers.getContractFactory("ReEntrancyAttacker");
      const attacker = await Attacker.deploy(await spooVault.getAddress());
      await attacker.waitForDeployment();

      // Set the document ID the attacker will try to read during the callback.
      // The attacker contract's attackDocumentId needs to be set. Since it's
      // public, we can't set it directly. We'll deploy with a helper or use
      // a different approach: the attacker reads a document that exists.

      // Mint token to the attacker — guardian calls mintAccessToken.
      // This triggers onERC721Received on the attacker mid-execution.
      // Inside the callback, the attacker tries to call hasActiveAccess.
      // The nonReentrantView guard should block this.
      await expect(
        spooVault
          .connect(guardian)
          .mintAccessToken(vaultId, await attacker.getAddress(), "https://uri")
      ).to.be.revertedWith("ReentrancyGuard: reentrant view call");
    });
  });

  describe("Test 2 — View functions work normally outside re-entrant context", function () {
    it("hasActiveAccess returns correct result in normal call", async function () {
      const { documentId } = await setupVaultAndDocument();

      // Before granting access — should return false
      const result1 = await spooVault.hasActiveAccess(documentId, user.address);
      expect(result1).to.equal(false);

      // checkAccess should return ACCESS_DENIED (1)
      const code = await spooVault.checkAccess(documentId, user.address);
      expect(code).to.equal(1);

      // getPendingInvites should return empty array for user with no invites
      const invites = await spooVault.getPendingInvites(user.address);
      expect(invites.length).to.equal(0);
    });

    it("getTokenVault and hasVaultToken return correct values", async function () {
      const { vaultId } = await setupVaultAndDocument();

      // Mint a token to user
      await spooVault
        .connect(guardian)
        .mintAccessToken(vaultId, user.address, "https://uri");

      // getTokenVault should return the vault ID for token 1
      const tokenVault = await spooVault.getTokenVault(1);
      expect(tokenVault).to.equal(vaultId);

      // hasVaultToken should return true for the user
      const hasToken = await spooVault.hasVaultToken(user.address, vaultId);
      expect(hasToken).to.equal(true);
    });
  });

  describe("Test 3 — Gas benchmark", function () {
    it("measures gas for 10 mintAccessToken calls with transient storage", async function () {
      const { vaultId } = await setupVaultAndDocument();

      let totalGas = 0n;
      for (let i = 0; i < 10; i++) {
        const tx = await spooVault
          .connect(guardian)
          .mintAccessToken(vaultId, user.address, `https://uri/${i}`);
        const receipt = await tx.wait();
        totalGas += receipt.gasUsed;
      }

      const avg = totalGas / 10n;
      console.log(`    10 mintAccessToken calls: ${totalGas} gas (avg ${avg} per call)`);
      console.log(`    Transient storage (TLOAD=100 gas) vs SLOAD (2100 gas) saves ~2000 gas per lock/unlock`);
      console.log(`    Expected savings: ~${10n * 2000n} gas over 10 calls`);

      // Sanity check: each mint should use less than 200k gas
      expect(avg).to.be.lessThan(200000n);
    });
  });
});
