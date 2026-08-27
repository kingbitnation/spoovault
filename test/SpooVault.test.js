import { expect } from "chai";
import hre from "hardhat";
const { ethers } = hre;
import { time, mine } from "@nomicfoundation/hardhat-network-helpers";
import { createRequire } from "module";
const { deploySpooVault } = createRequire(import.meta.url)("./helpers/deploySpooVault.cjs");

describe("SpooVault EVM Contract Unit Tests", function () {
  let spooVault;
  let owner;
  let guardian1;
  let guardian2;
  let beneficiary;

  beforeEach(async function () {
    [owner, guardian1, guardian2, beneficiary] = await ethers.getSigners();

    spooVault = await deploySpooVault();
  });

  describe("Public Key Registry", function () {
    it("should allow a user to register an X25519 public key", async function () {
      const pubKey = "B64_PUBLIC_KEY_TEST_STRING_12345";
      await expect(spooVault.connect(beneficiary).registerPublicKey(pubKey))
        .to.emit(spooVault, "PublicKeyRegistered")
        .withArgs(beneficiary.address, pubKey);

      const registeredKey = await spooVault.userPublicKeys(beneficiary.address);
      expect(registeredKey).to.equal(pubKey);
    });
  });

  describe("Vault Creation & Guardian Thresholds", function () {
    it("should create a vault with valid threshold and guardian invite list", async function () {
      const guardians = [guardian1.address, guardian2.address];
      const threshold = 2;

      const tx = await spooVault
        .connect(owner)
        .createVault(
          "Executive Vault",
          "Confidential legal documents",
          guardians,
          threshold
        );

      await expect(tx).to.emit(spooVault, "VaultCreated");

      const vault = await spooVault.vaults(1);
      expect(vault.name).to.equal("Executive Vault");
      expect(vault.creator).to.equal(owner.address);
      expect(vault.approvalThreshold).to.equal(threshold);
      expect(vault.isActive).to.equal(true);
    });

    it("should revert vault creation if no external guardians are provided", async function () {
      await expect(
        spooVault.connect(owner).createVault("Single Vault", "Desc", [], 1)
      ).to.be.revertedWithCustomError(spooVault, "AtLeastOneGuardian");
    });

    it("should revert if approval threshold is zero or exceeds total guardian count", async function () {
      const guardians = [guardian1.address];
      await expect(
        spooVault
          .connect(owner)
          .createVault("Invalid Threshold Vault", "Desc", guardians, 0)
      ).to.be.revertedWithCustomError(spooVault, "InvalidApprovalThreshold");

      await expect(
        spooVault
          .connect(owner)
          .createVault("Over Threshold Vault", "Desc", guardians, 5)
      ).to.be.revertedWithCustomError(spooVault, "InvalidApprovalThreshold");
    });
  });

  describe("Vault Release State & Proof of Life", function () {
    it("should allow vault creator to record proof of life", async function () {
      const guardians = [guardian1.address];
      await spooVault
        .connect(owner)
        .createVault("Inheritance Vault", "Desc", guardians, 1);

      await expect(spooVault.connect(owner).proveLife(1)).to.emit(
        spooVault,
        "ProofOfLifeRecorded"
      );
    });

    it("should allow vault creator to toggle emergency mode", async function () {
      const guardians = [guardian1.address];
      await spooVault
        .connect(owner)
        .createVault("Emergency Vault", "Desc", guardians, 1);

      await expect(spooVault.connect(owner).setEmergencyMode(1, true))
        .to.emit(spooVault, "EmergencyModeUpdated")
        .withArgs(1, true);
    });
  });

  describe("Beneficiary Registry", function () {
    beforeEach(async function () {
      await spooVault.connect(owner).createVault("Beneficiary Vault", "Desc", [guardian1.address], 1);
    });

    it("should allow the vault creator to set a beneficiary", async function () {
      await expect(spooVault.connect(owner).setBeneficiary(1, beneficiary.address))
        .to.emit(spooVault, "BeneficiarySet")
        .withArgs(1, beneficiary.address);

      expect(await spooVault.getBeneficiary(1)).to.equal(beneficiary.address);
    });

    it("should default to the zero address when no beneficiary is set", async function () {
      expect(await spooVault.getBeneficiary(1)).to.equal(ethers.ZeroAddress);
    });

    it("should revert when setting a zero-address beneficiary", async function () {
      await expect(
        spooVault.connect(owner).setBeneficiary(1, ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(spooVault, "ZeroAddressBeneficiary");
    });

    it("should revert when a non-creator tries to set the beneficiary", async function () {
      await expect(
        spooVault.connect(guardian1).setBeneficiary(1, beneficiary.address)
      ).to.be.revertedWithCustomError(spooVault, "OnlyVaultCreator");
    });

    it("should revert when the beneficiary is already set", async function () {
      await spooVault.connect(owner).setBeneficiary(1, beneficiary.address);

      await expect(
        spooVault.connect(owner).setBeneficiary(1, guardian2.address)
      ).to.be.revertedWithCustomError(spooVault, "BeneficiaryAlreadySet");
    });
  });

  describe("Guardian Invites", function () {
    it("should allow a guardian to accept an invite and become an active guardian", async function () {
      await spooVault
        .connect(owner)
        .createVault("Vault A", "Desc", [guardian1.address], 1);

      const pendingBefore = await spooVault.getPendingInvites(
        guardian1.address
      );
      expect(pendingBefore.length).to.equal(1);
      expect(pendingBefore[0].vaultId).to.equal(1);
      expect(pendingBefore[0].accepted).to.equal(false);

      await expect(spooVault.connect(guardian1).acceptGuardianInvite(1))
        .to.emit(spooVault, "GuardianAdded")
        .withArgs(1, guardian1.address);

      const pendingAfter = await spooVault.getPendingInvites(guardian1.address);
      expect(pendingAfter.length).to.equal(0);

      const isGuardian = await spooVault.isGuardian(1, guardian1.address);
      expect(isGuardian).to.be.true;
    });

    it("should revert acceptGuardianInvite for non-existent invite", async function () {
      await spooVault
        .connect(owner)
        .createVault("Vault A", "Desc", [guardian2.address], 1);

      await expect(
        spooVault.connect(guardian1).acceptGuardianInvite(1)
      ).to.be.revertedWithCustomError(spooVault, "NoValidInvite");
    });

    it("should return pending invites for a user across multiple vaults", async function () {
      await spooVault
        .connect(owner)
        .createVault("Vault A", "Desc", [guardian1.address], 1);
      await spooVault
        .connect(owner)
        .createVault("Vault B", "Desc", [guardian1.address], 1);

      const pending = await spooVault.getPendingInvites(guardian1.address);
      expect(pending.length).to.equal(2);
      const vaultIds = pending.map((inv) => Number(inv.vaultId)).sort();
      expect(vaultIds).to.deep.equal([1, 2]);
    });

    it("should not include accepted invites in getPendingInvites", async function () {
      await spooVault
        .connect(owner)
        .createVault("Vault A", "Desc", [guardian1.address], 1);
      await spooVault.connect(guardian1).acceptGuardianInvite(1);

      const pending = await spooVault.getPendingInvites(guardian1.address);
      expect(pending.length).to.equal(0);
    });

    it("should revert acceptGuardianInvite for expired invite", async function () {
      await spooVault
        .connect(owner)
        .createVault("Vault A", "Desc", [guardian1.address], 1);

      await time.increase(7 * 24 * 60 * 60 + 1);

      await expect(
        spooVault.connect(guardian1).acceptGuardianInvite(1)
      ).to.be.revertedWithCustomError(spooVault, "InviteExpired");
    });

    it("should exclude expired invites from getPendingInvites", async function () {
      await spooVault
        .connect(owner)
        .createVault("Vault A", "Desc", [guardian1.address], 1);

      await time.increase(7 * 24 * 60 * 60 + 1);

      const pending = await spooVault.getPendingInvites(guardian1.address);
      expect(pending.length).to.equal(0);
    });
  });

  describe("Post-Death Release: timestamp + block confirmation", function () {
    it("should NOT unlock post-death release from timestamp manipulation alone without block progression", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);
      await spooVault.connect(owner).configureVaultRelease(1, 1 * 24 * 60 * 60); // 1 day

      // Simulate a manipulated/skewed timestamp far in the future while only
      // a single block has actually been mined since the last proof of life.
      await time.increase(2 * 24 * 60 * 60);
      await mine(1);

      const state = await spooVault.getVaultReleaseState(1);
      expect(state.postDeathUnlocked).to.equal(false);
    });

    it("should unlock post-death release once both the timestamp threshold and targetBlocks have elapsed", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);
      await spooVault.connect(owner).configureVaultRelease(1, 1 * 24 * 60 * 60); // 1 day

      await time.increase(2 * 24 * 60 * 60);
      const targetBlocks = await spooVault.getTargetBlocks(1);
      await mine(targetBlocks);

      const state = await spooVault.getVaultReleaseState(1);
      expect(state.postDeathUnlocked).to.equal(true);
    });

    it("should compute targetBlocks dynamically from inactivity period and median block interval", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);
      await spooVault.connect(owner).configureVaultRelease(1, 30 * 24 * 60 * 60); // 30 days

      const targetBlocks = await spooVault.getTargetBlocks(1);
      // With the default 12s block interval, 30 days = 2592000s / 12 = 216000 blocks
      expect(targetBlocks).to.be.gte(200000n);
      expect(targetBlocks).to.be.lte(300000n);
    });

    it("should NOT unlock post-death release when timestamp is spoofed but targetBlocks not reached", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);
      await spooVault.connect(owner).configureVaultRelease(1, 30 * 24 * 60 * 60); // 30 days

      const targetBlocks = await spooVault.getTargetBlocks(1);

      // Simulate timestamp manipulation: advance timestamp far into the future
      // but only mine a fraction of the required blocks.
      await time.increase(60 * 24 * 60 * 60); // 60 days in the future
      await mine(Math.floor(Number(targetBlocks) / 2)); // Only half the required blocks

      const state = await spooVault.getVaultReleaseState(1);
      expect(state.postDeathUnlocked).to.equal(false);
    });

    it("should NOT unlock post-death release when blocks are mined but timestamp not reached", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);
      await spooVault.connect(owner).configureVaultRelease(1, 30 * 24 * 60 * 60); // 30 days

      const targetBlocks = await spooVault.getTargetBlocks(1);

      // Mine enough blocks but don't advance timestamp enough
      await mine(Math.floor(Number(targetBlocks) * 1.5));
      await time.increase(15 * 24 * 60 * 60); // Only 15 days

      const state = await spooVault.getVaultReleaseState(1);
      expect(state.postDeathUnlocked).to.equal(false);
    });

    it("should unlock post-death release only when BOTH timestamp and targetBlocks are satisfied", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);
      await spooVault.connect(owner).configureVaultRelease(1, 30 * 24 * 60 * 60); // 30 days

      const targetBlocks = await spooVault.getTargetBlocks(1);

      // Advance both timestamp and blocks sufficiently
      await time.increase(31 * 24 * 60 * 60); // 31 days
      await mine(Math.floor(Number(targetBlocks) * 1.2)); // 120% of required blocks

      const state = await spooVault.getVaultReleaseState(1);
      expect(state.postDeathUnlocked).to.equal(true);
    });

    it("should resist single-block timestamp spoofing via median block interval", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);

      // Record multiple proof-of-life heartbeats to populate the ring buffer
      for (let i = 0; i < 10; i++) {
        await spooVault.connect(owner).proveLife(1);
        await mine(1);
      }

      const medianInterval = await spooVault.getMedianBlockInterval();
      // Median interval should be reasonable (between 1 and 30 seconds)
      expect(medianInterval).to.be.gte(1n);
      expect(medianInterval).to.be.lte(30n);
    });

    it("should use default block interval when ring buffer has insufficient samples", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);

      // No proof-of-life recorded yet, ring buffer is empty
      const medianInterval = await spooVault.getMedianBlockInterval();
      expect(medianInterval).to.equal(12n); // Default 12 seconds
    });

    it("should scale targetBlocks proportionally with inactivity period", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);

      // Configure with 1 day inactivity period
      await spooVault.connect(owner).configureVaultRelease(1, 1 * 24 * 60 * 60);
      const targetBlocks1Day = await spooVault.getTargetBlocks(1);

      // Create another vault and configure with 30 days
      await spooVault.connect(owner).createVault("Vault 2", "Desc", guardians, 1);
      await spooVault.connect(owner).configureVaultRelease(2, 30 * 24 * 60 * 60);
      const targetBlocks30Days = await spooVault.getTargetBlocks(2);

      // 30 days should require ~30x more blocks than 1 day
      const ratio = Number(targetBlocks30Days) / Number(targetBlocks1Day);
      expect(ratio).to.be.gte(25);
      expect(ratio).to.be.lte(35);
    });
  });
});
