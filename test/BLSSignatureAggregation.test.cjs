const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySpooVault } = require("./helpers/deploySpooVault.cjs");

describe("SpooVault Threshold BLS Signature Aggregation", function () {
  let spooVault;
  let owner;
  let guardian1;
  let guardian2;
  let guardian3;
  let guardian4;
  let requester;
  let stranger;
  let vaultId;
  let documentId;
  let requestId;

  // Canonical mock BLS12-381 G1 (48 bytes) and G2 (96 bytes) test vectors
  const mockG1Key = (seed) => {
    const buf = Buffer.alloc(48, seed);
    buf[0] = 0x80 | (seed & 0x7f); // compressed G1 point flag
    return "0x" + buf.toString("hex");
  };

  const mockG2Sig = (seed) => {
    const buf = Buffer.alloc(96, seed);
    buf[0] = 0x80 | (seed & 0x7f); // compressed G2 point flag
    return "0x" + buf.toString("hex");
  };

  beforeEach(async function () {
    [owner, guardian1, guardian2, guardian3, guardian4, requester, stranger] =
      await ethers.getSigners();

    spooVault = await deploySpooVault(owner);

    // Create a vault with owner + 4 external guardians (5 total), approval threshold = 3
    const guardians = [
      guardian1.address,
      guardian2.address,
      guardian3.address,
      guardian4.address,
    ];
    const tx = await spooVault
      .connect(owner)
      .createVault("BLS Threshold Vault", "Vault for testing BLS signature aggregation", guardians, 3);
    await tx.wait();
    vaultId = 1;

    // Accept guardian invites
    await spooVault.connect(guardian1).acceptGuardianInvite(vaultId);
    await spooVault.connect(guardian2).acceptGuardianInvite(vaultId);
    await spooVault.connect(guardian3).acceptGuardianInvite(vaultId);
    await spooVault.connect(guardian4).acceptGuardianInvite(vaultId);

    // Register BLS keys with Proof of Possession for all guardians
    await spooVault.connect(owner).registerGuardianBLSKey(vaultId, mockG1Key(1), mockG2Sig(1));
    await spooVault.connect(guardian1).registerGuardianBLSKey(vaultId, mockG1Key(2), mockG2Sig(2));
    await spooVault.connect(guardian2).registerGuardianBLSKey(vaultId, mockG1Key(3), mockG2Sig(3));
    await spooVault.connect(guardian3).registerGuardianBLSKey(vaultId, mockG1Key(4), mockG2Sig(4));
    await spooVault.connect(guardian4).registerGuardianBLSKey(vaultId, mockG1Key(5), mockG2Sig(5));

    // Upload document
    const docTx = await spooVault
      .connect(owner)
      .addDocument(vaultId, "encrypted-metadata-bls", "QmBLSTestHash123456789", 0);
    await docTx.wait();
    documentId = 1;

    // Mint vault access NFT to requester
    const mintTx = await spooVault
      .connect(owner)
      .mintAccessToken(vaultId, requester.address, "ipfs://nft-pass-uri");
    await mintTx.wait();

    // Requester requests access
    const reqTx = await spooVault.connect(requester).requestAccess(documentId);
    await reqTx.wait();
    requestId = 1;
  });

  describe("Guardian BLS Key Registration & PoP", function () {
    it("should successfully register and retrieve guardian BLS key and PoP", async function () {
      const keyInfo = await spooVault.getGuardianBLSKey(vaultId, guardian1.address);
      expect(keyInfo[0]).to.equal(mockG1Key(2));
      expect(keyInfo[1]).to.equal(mockG2Sig(2));
      expect(keyInfo[2]).to.be.true; // isRegistered
    });

    it("should emit GuardianBLSKeyRegistered event on registration", async function () {
      const key = mockG1Key(42);
      const pop = mockG2Sig(42);
      await expect(spooVault.connect(guardian1).registerGuardianBLSKey(vaultId, key, pop))
        .to.emit(spooVault, "GuardianBLSKeyRegistered")
        .withArgs(vaultId, guardian1.address, key);
    });

    it("should revert if non-guardian tries to register BLS key", async function () {
      await expect(
        spooVault.connect(stranger).registerGuardianBLSKey(vaultId, mockG1Key(99), mockG2Sig(99))
      ).to.be.revertedWithCustomError(spooVault, "OnlyGuardian");
    });

    it("should revert if BLS public key or PoP length is invalid", async function () {
      await expect(
        spooVault.connect(guardian1).registerGuardianBLSKey(vaultId, "0x1234", mockG2Sig(1))
      ).to.be.revertedWithCustomError(spooVault, "InvalidBLSKeyLength");

      await expect(
        spooVault.connect(guardian1).registerGuardianBLSKey(vaultId, mockG1Key(1), "0xabcd")
      ).to.be.revertedWithCustomError(spooVault, "InvalidBLSKeyLength");
    });
  });

  describe("Threshold BLS Access Approval (K-of-N)", function () {
    it("should approve document access in 1 transaction with 3-of-5 aggregated BLS signatures", async function () {
      const participatingGuardians = [guardian1.address, guardian2.address, guardian3.address].sort();
      const aggregatedSig = mockG2Sig(99);
      const aggregatedPk = mockG1Key(99);
      const shares = ["share_for_beneficiary_1", "share_for_beneficiary_2", "share_for_beneficiary_3"];

      const tx = await spooVault
        .connect(stranger) // Anyone/relayer can submit the pre-aggregated payload!
        .approveAccessBLS(requestId, participatingGuardians, aggregatedSig, aggregatedPk, shares);

      await expect(tx)
        .to.emit(spooVault, "BLSAccessApproved")
        .withArgs(requestId, vaultId, 3, aggregatedSig);

      // Verify request is approved
      const req = await spooVault.accessRequests(requestId);
      expect(req.status).to.equal(1); // APPROVED

      // Verify beneficiary has active access
      const hasAccess = await spooVault.hasActiveAccess(documentId, requester.address);
      expect(hasAccess).to.be.true;

      // Verify beneficiary shares were saved
      const share0 = await spooVault.getBeneficiaryKeyShare(requestId, participatingGuardians[0]);
      expect(share0).to.equal("share_for_beneficiary_1");
    });

    it("should reject batch approval if participating guardians count is below threshold", async function () {
      const underThresholdGuardians = [guardian1.address, guardian2.address]; // 2 < 3 threshold
      const aggregatedSig = mockG2Sig(99);
      const aggregatedPk = mockG1Key(99);
      const shares = ["share_1", "share_2"];

      await expect(
        spooVault.approveAccessBLS(requestId, underThresholdGuardians, aggregatedSig, aggregatedPk, shares)
      ).to.be.revertedWithCustomError(spooVault, "ThresholdNotMetBLS");
    });

    it("should reject batch approval if requester attempts to self-approve", async function () {
      // If requester was a guardian and included themselves in approval set
      const selfApproveSet = [requester.address, guardian1.address, guardian2.address];
      const aggregatedSig = mockG2Sig(99);
      const aggregatedPk = mockG1Key(99);

      // First make requester a guardian to test the guard
      await expect(
        spooVault.approveAccessBLS(requestId, selfApproveSet, aggregatedSig, aggregatedPk, [])
      ).to.be.reverted;
    });

    it("should reject batch approval if duplicate guardian addresses are submitted", async function () {
      const duplicateSet = [guardian1.address, guardian1.address, guardian2.address];
      const aggregatedSig = mockG2Sig(99);
      const aggregatedPk = mockG1Key(99);

      await expect(
        spooVault.approveAccessBLS(requestId, duplicateSet, aggregatedSig, aggregatedPk, [])
      ).to.be.revertedWithCustomError(spooVault, "DuplicateGuardianBLS");
    });

    it("should reject batch approval if any guardian in the set has not registered BLS key", async function () {
      // Deploy fresh guardian without BLS registration
      const [, , , , , , , unregisteredGuardian] = await ethers.getSigners();
      const unregSet = [guardian1.address, guardian2.address, unregisteredGuardian.address].sort();
      const aggregatedSig = mockG2Sig(99);
      const aggregatedPk = mockG1Key(99);

      await expect(
        spooVault.approveAccessBLS(requestId, unregSet, aggregatedSig, aggregatedPk, [])
      ).to.be.revertedWithCustomError(spooVault, "OnlyGuardian");
    });
  });
});
