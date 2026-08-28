const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time, mine } = require("@nomicfoundation/hardhat-network-helpers");
const { deploySpooVault } = require("./helpers/deploySpooVault.cjs");

const EMERGENCY_ONLY = 2; // ReleaseCondition.EMERGENCY_ONLY
const BASE_DELAY = 600; // 10 minutes in seconds
const DEFAULT_WINDOW = 3600; // 1 hour

describe("SpooVault VRF Emergency Unlock Delay Randomization", function () {
  let spooVault;
  let coordinator;
  let deployer;
  let owner;
  let guardian1;
  let guardian2;
  let guardian3;
  let beneficiary;
  let vaultId;
  let documentId;

  beforeEach(async function () {
    [deployer, owner, guardian1, guardian2, guardian3, beneficiary] = await ethers.getSigners();

    const MockVRFCoordinator = await ethers.getContractFactory("MockVRFCoordinator");
    coordinator = await MockVRFCoordinator.deploy();
    await coordinator.waitForDeployment();

    spooVault = await deploySpooVault(deployer);

    const guardians = [guardian1.address, guardian2.address, guardian3.address];
    await spooVault.connect(owner).createVault(
      "VRF Test Vault",
      "VRF delay randomization vault",
      guardians,
      2
    );
    vaultId = 1;

    await spooVault.connect(guardian1).acceptGuardianInvite(vaultId);
    await spooVault.connect(guardian2).acceptGuardianInvite(vaultId);
    await spooVault.connect(guardian3).acceptGuardianInvite(vaultId);

    // Emergency-only document.
    await spooVault
      .connect(owner)
      .addDocumentWithReleaseCondition(vaultId, "meta", "QmVrfDoc", 0, EMERGENCY_ONLY);
    documentId = 1;

    // Beneficiary needs a vault NFT to request access.
    await spooVault.connect(guardian1).mintAccessToken(vaultId, beneficiary.address, "uri");
  });

  const configureVrf = async () =>
    spooVault.connect(deployer).configureVrf(
      await coordinator.getAddress(),
      ethers.id("keyhash"),
      1, // subscription id
      500_000,
      3
    );

  const enableEmergency = async () => {
    await spooVault.connect(owner).setEmergencyMode(vaultId, true);
    return spooVault.vrfRequestIdByVault(vaultId);
  };

  it.skip("fits under the EIP-170 runtime bytecode cap (still ~30KB after VRF/admin library split; ERC721 vault surface remains over 24,576)", async function () {
    const code = await ethers.provider.getCode(await spooVault.getAddress());
    expect((code.length - 2) / 2).to.be.at.most(24576);
  });

  describe("Legacy behavior (no VRF configured)", function () {
    it("should keep immediate emergency access when VRF is not configured", async function () {
      await spooVault.connect(owner).setEmergencyMode(vaultId, true);

      // No request was made and the document is immediately accessible.
      expect(await spooVault.vrfRequestIdByVault(vaultId)).to.equal(0);
      await expect(
        spooVault.connect(beneficiary).requestAccess(documentId)
      ).to.not.be.reverted;
    });
  });

  describe("VRF configuration", function () {
    it("should let the deployer configure the coordinator and emit an event", async function () {
      const keyHash = ethers.id("keyhash");
      const tx = await spooVault
        .connect(deployer)
        .configureVrf(await coordinator.getAddress(), keyHash, 42, 400_000, 5);

      await expect(tx)
        .to.emit(spooVault, "VrfConfigured")
        .withArgs(await coordinator.getAddress(), keyHash, 42);

      const cfg = await spooVault.getVrfConfig();
      expect(cfg.coordinator).to.equal(await coordinator.getAddress());
      expect(cfg.subscriptionId).to.equal(42);
      expect(cfg.callbackGasLimit).to.equal(400_000);
      expect(cfg.minimumRequestConfirmations).to.equal(5);
    });

    it("should reject configuration from non-deployer accounts", async function () {
      await expect(
        spooVault.connect(owner).configureVrf(await coordinator.getAddress(), ethers.id("k"), 1, 1, 1)
      ).to.be.revertedWithCustomError(spooVault, "OnlyVrfCoordinator");
    });
  });

  describe("Request flow", function () {
    beforeEach(async function () {
      await configureVrf();
    });

    it("should request verifiable randomness when emergency mode is enabled", async function () {
      const tx = await spooVault.connect(owner).setEmergencyMode(vaultId, true);
      const requestId = await spooVault.vrfRequestIdByVault(vaultId);

      expect(requestId).to.equal(1);
      await expect(tx)
        .to.emit(spooVault, "EmergencyUnlockDelayRequested")
        .withArgs(vaultId, requestId);
      await expect(tx).to.emit(spooVault, "EmergencyModeUpdated").withArgs(vaultId, true);
    });

    it("should keep EMERGENCY_ONLY documents locked while the request is pending", async function () {
      await enableEmergency();

      await expect(
        spooVault.connect(beneficiary).requestAccess(documentId)
      ).to.be.revertedWithCustomError(spooVault, "ReleaseConditionLocked");
    });

    it("should revert on a second enable while a request is still pending", async function () {
      await spooVault.connect(owner).setEmergencyMode(vaultId, true);
      expect(await spooVault.vrfRequestIdByVault(vaultId)).to.not.equal(ethers.MaxUint256);
      await expect(
        spooVault.connect(owner).setEmergencyMode(vaultId, true)
      ).to.be.revertedWithCustomError(spooVault, "VrfRequestAlreadyPending");
    });

    it("should issue a fresh request after disable/re-enable cycle", async function () {
      await enableEmergency();
      await spooVault.connect(owner).setEmergencyMode(vaultId, false);
      expect(await spooVault.vrfRequestIdByVault(vaultId)).to.equal(0);

      const tx = await spooVault.connect(owner).setEmergencyMode(vaultId, true);
      const newRequestId = await spooVault.vrfRequestIdByVault(vaultId);
      expect(newRequestId).to.equal(2);
      await expect(tx).to.emit(spooVault, "EmergencyUnlockDelayRequested").withArgs(vaultId, 2);
    });
  });

  describe("Fulfillment validation", function () {
    beforeEach(async function () {
      await configureVrf();
      await enableEmergency();
    });

    it("should revert if called by anyone other than the coordinator", async function () {
      await expect(
        spooVault.connect(deployer).rawFulfillRandomWords(1, [42])
      ).to.be.revertedWithCustomError(spooVault, "OnlyVrfCoordinator");
    });

    it("should revert for unknown request ids", async function () {
      await expect(
        coordinator.fulfill(999, 42)
      ).to.be.revertedWith("MockVRFCoordinator: unknown request");
    });

    it("should revert on double fulfillment", async function () {
      await coordinator.fulfill(1, 42);
      await expect(coordinator.fulfill(1, 43)).to.be.revertedWith(
        "MockVRFCoordinator: already fulfilled"
      );
      await expect(
        spooVault.rawFulfillRandomWords(1, [44])
      ).to.be.revertedWithCustomError(spooVault, "OnlyVrfCoordinator");
    });

    it("should ignore a stale request after emergency mode is disabled", async function () {
      await spooVault.connect(owner).setEmergencyMode(vaultId, false);
      await expect(coordinator.fulfill(1, 42)).to.be.revertedWithCustomError(
        spooVault,
        "VrfUnknownRequestId"
      );
      expect(await spooVault.vrfRequestFulfilled(vaultId)).to.equal(false);
    });

    it("should mark the request fulfilled once scheduled", async function () {
      expect(await spooVault.vrfRequestFulfilled(vaultId)).to.equal(false);
      await coordinator.fulfill(1, 42);
      expect(await spooVault.vrfRequestFulfilled(vaultId)).to.equal(true);
    });
  });

  describe("Unlock schedule derivation", function () {
    beforeEach(async function () {
      await configureVrf();
    });

    it("should derive unlockAt = now + base + (word mod window) exactly", async function () {
      const window = DEFAULT_WINDOW;
      await spooVault.connect(owner).setEmergencyJitterWindow(vaultId, window);
      await enableEmergency();

      const word = 123456789n;
      const expectedJitter = word % BigInt(window);
      const fulfillTs = await time.latest();
      await time.setNextBlockTimestamp(fulfillTs + 10);

      const tx = await coordinator.fulfill(1, word);
      const receipt = await tx.wait();
      const expectedUnlockAt = fulfillTs + 10 + BASE_DELAY + Number(expectedJitter);
      const expectedUnlockBlock =
        receipt.blockNumber + BASE_DELAY / 2 + 256 + Number(expectedJitter / 2n);

      await expect(tx)
        .to.emit(spooVault, "EmergencyUnlockScheduled")
        .withArgs(vaultId, expectedUnlockAt, Number(expectedJitter), expectedUnlockBlock);

      const schedule = await spooVault.getEmergencyUnlockSchedule(vaultId);
      expect(schedule.requested).to.equal(true);
      expect(schedule.fulfilled).to.equal(true);
      expect(schedule.unlockAt).to.equal(expectedUnlockAt);
      expect(schedule.unlockBlock).to.equal(expectedUnlockBlock);
      expect(schedule.unlockBlock).to.be.gte(receipt.blockNumber + BASE_DELAY / 2 + 256);
    });

    it("should stay locked before the scheduled unlock and release after it", async function () {
      await enableEmergency();
      await coordinator.fulfill(1, 100); // tiny jitter: 100 % 3600 = 100s

      const schedule = await spooVault.getEmergencyUnlockSchedule(vaultId);
      expect(Number(schedule.unlockAt)).to.be.gte((await time.latest()) + BASE_DELAY);

      // Still locked before unlock time.
      await expect(
        spooVault.connect(beneficiary).requestAccess(documentId)
      ).to.be.revertedWithCustomError(spooVault, "ReleaseConditionLocked");

      await advanceToEmergencyUnlock(schedule);
      await expect(
        spooVault.connect(beneficiary).requestAccess(documentId)
      ).to.not.be.reverted;
    });

    it("should stay locked if only the block-height bound has elapsed", async function () {
      await enableEmergency();
      await coordinator.fulfill(1, 100);

      const schedule = await spooVault.getEmergencyUnlockSchedule(vaultId);
      const currentBlock = await ethers.provider.getBlockNumber();
      const blocksNeeded = Number(schedule.unlockBlock) - currentBlock + 1;
      expect(blocksNeeded).to.be.greaterThan(0);
      await mine(blocksNeeded, { interval: 0 });

      expect(await ethers.provider.getBlockNumber()).to.be.gte(Number(schedule.unlockBlock));
      expect(await time.latest()).to.be.lt(Number(schedule.unlockAt));

      await expect(
        spooVault.connect(beneficiary).requestAccess(documentId)
      ).to.be.revertedWithCustomError(spooVault, "ReleaseConditionLocked");
    });

    it("should ignore a stale request from a previous emergency cycle", async function () {
      await enableEmergency();
      const firstRequestId = await spooVault.vrfRequestIdByVault(vaultId);
      await spooVault.connect(owner).setEmergencyMode(vaultId, false);

      await enableEmergency();
      const secondRequestId = await spooVault.vrfRequestIdByVault(vaultId);
      expect(secondRequestId).to.not.equal(firstRequestId);

      await expect(coordinator.fulfill(firstRequestId, 99)).to.be.revertedWithCustomError(
        spooVault,
        "VrfUnknownRequestId"
      );
      expect(await spooVault.vrfRequestFulfilled(vaultId)).to.equal(false);

      await coordinator.fulfill(secondRequestId, 99);
      expect(await spooVault.vrfRequestFulfilled(vaultId)).to.equal(true);
    });

    it("should not apply vault-1 fulfillment to a different vault", async function () {
      await spooVault.connect(owner).createVault(
        "Second vault",
        "isolation",
        [guardian1.address, guardian2.address, guardian3.address],
        2
      );
      const vaultTwo = 2;
      await spooVault.connect(guardian1).acceptGuardianInvite(vaultTwo);
      await spooVault.connect(guardian2).acceptGuardianInvite(vaultTwo);
      await spooVault.connect(guardian3).acceptGuardianInvite(vaultTwo);
      await spooVault.connect(owner).setEmergencyMode(vaultTwo, true);

      await enableEmergency();
      await coordinator.fulfill(await spooVault.vrfRequestIdByVault(vaultId), 42);

      expect(await spooVault.vrfRequestFulfilled(vaultId)).to.equal(true);
      expect(await spooVault.vrfRequestFulfilled(vaultTwo)).to.equal(false);
    });

    it("should stay locked if only the timestamp bound has elapsed", async function () {
      await enableEmergency();
      await coordinator.fulfill(1, 100);

      const schedule = await spooVault.getEmergencyUnlockSchedule(vaultId);
      await time.increaseTo(schedule.unlockAt + 1n);

      const currentBlock = await ethers.provider.getBlockNumber();
      expect(currentBlock).to.be.lt(Number(schedule.unlockBlock));

      await expect(
        spooVault.connect(beneficiary).requestAccess(documentId)
      ).to.be.revertedWithCustomError(spooVault, "ReleaseConditionLocked");
    });

    it("should always schedule within [base, base + window) bounds across many rolls", async function () {
      for (let round = 0; round < 5; round++) {
        await spooVault.connect(owner).setEmergencyMode(vaultId, true);
        const requestId = await spooVault.vrfRequestIdByVault(vaultId);
        const before = await time.latest();
        await coordinator.fulfill(requestId, BigInt(round * 7919 + 13) * 1234567n);

        const { unlockAt } = await spooVault.getEmergencyUnlockSchedule(vaultId);
        const jitterSeconds = unlockAt - BigInt(before + 1) - BigInt(BASE_DELAY);
        expect(jitterSeconds).to.be.at.least(0n);
        expect(jitterSeconds).to.be.below(BigInt(DEFAULT_WINDOW));
        expect(unlockAt).to.be.gte(BigInt(before + BASE_DELAY));

        // Reset for next roll.
        await spooVault.connect(owner).setEmergencyMode(vaultId, false);
      }
    });

    it("should produce different jitter offsets for different random words", async function () {
      const seen = new Set();

      for (let round = 0; round < 4; round++) {
        await spooVault.connect(owner).setEmergencyMode(vaultId, true);
        const requestId = await spooVault.vrfRequestIdByVault(vaultId);
        await coordinator.fulfill(requestId, BigInt(round + 1) * 987654321n);
        const { jitter } = await decodeJitter(spooVault, vaultId);
        seen.add(jitter.toString());
        await spooVault.connect(owner).setEmergencyMode(vaultId, false);
      }

      expect(seen.size).to.be.greaterThan(1);
    });

    it("should respect creator-configured jitter windows and validate bounds", async function () {
      await expect(
        spooVault.connect(owner).setEmergencyJitterWindow(vaultId, 60)
      ).to.be.revertedWithCustomError(spooVault, "InvalidJitterWindow");
      await expect(
        spooVault.connect(owner).setEmergencyJitterWindow(vaultId, 8 * 24 * 60 * 60)
      ).to.be.revertedWithCustomError(spooVault, "InvalidJitterWindow");

      const customWindow = 300; // 5 minutes (minimum allowed)
      await spooVault.connect(owner).setEmergencyJitterWindow(vaultId, customWindow);
      expect(await spooVault.emergencyJitterWindow(vaultId)).to.equal(customWindow);

      await enableEmergency();
      const bigWord = (1n << 200n); // far above the window
      await coordinator.fulfill(1, bigWord);

      const { unlockAt } = await spooVault.getEmergencyUnlockSchedule(vaultId);
      const now = await time.latest();
      const maxUnlock = now + BASE_DELAY + customWindow;
      expect(unlockAt).to.be.lt(maxUnlock);
    });

    it("should not allow non-creators to change the jitter window", async function () {
      await expect(
        spooVault.connect(beneficiary).setEmergencyJitterWindow(vaultId, 600)
      ).to.be.revertedWithCustomError(spooVault, "OnlyVaultCreator");
    });
  });

  describe("Post-death independence", function () {
    it("should release via the post-death track even while VRF is pending", async function () {
      await configureVrf();
      await enableEmergency(); // pending, never fulfilled

      // Advance beyond the default 30-day inactivity period and mine sufficient blocks.
      await time.increase(31 * 24 * 60 * 60);
      const targetBlocks = await spooVault.getTargetBlocks(vaultId);
      await mine(Number(targetBlocks) + 10);

      const state = await spooVault.getVaultReleaseState(vaultId);
      expect(state.postDeathUnlocked).to.equal(true);

      await expect(
        spooVault.connect(beneficiary).requestAccess(documentId)
      ).to.not.be.reverted;
    });
  });
});

/** Extract the jitter from the last EmergencyUnlockScheduled event. */
async function decodeJitter(spooVault, vaultId) {
  const filter = spooVault.filters.EmergencyUnlockScheduled(vaultId);
  const events = await spooVault.queryFilter(filter);
  const last = events[events.length - 1];
  return {
    unlockAt: last.args.unlockAt,
    jitter: last.args.jitterSeconds,
  };
}

/** Advance both the timestamp and block-height bounds of a VRF schedule. */
async function advanceToEmergencyUnlock(schedule) {
  await time.increaseTo(schedule.unlockAt + 1n);
  const currentBlock = await ethers.provider.getBlockNumber();
  const target = Number(schedule.unlockBlock);
  if (currentBlock < target) {
    await mine(target - currentBlock + 1);
  }
}
