const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("SpooVault EIP-712 Guardian Delegation (#101)", function () {
  let spooVault;
  let owner;
  let guardian;
  let delegate;
  let beneficiary;
  let otherUser;
  let domain;
  let types;

  const getLatestBlockTimestamp = async () => {
    const block = await ethers.provider.getBlock("latest");
    return block.timestamp;
  };

  beforeEach(async function () {
    [owner, guardian, delegate, beneficiary, otherUser] = await ethers.getSigners();

    const SpooVault = await ethers.getContractFactory("SpooVault");
    spooVault = await SpooVault.deploy();
    await spooVault.waitForDeployment();

    const spooVaultAddress = await spooVault.getAddress();
    const network = await ethers.provider.getNetwork();

    domain = {
      name: "SpooVault",
      version: "1",
      chainId: network.chainId,
      verifyingContract: spooVaultAddress,
    };

    types = {
      GuardianDelegation: [
        { name: "guardian", type: "address" },
        { name: "delegate", type: "address" },
        { name: "vaultId", type: "uint256" },
        { name: "validUntil", type: "uint256" },
        { name: "nonce", type: "uint256" },
      ],
    };

    // Setup: Create vault with owner + guardian (threshold = 2)
    const guardians = [guardian.address];
    await spooVault.connect(owner).createVault("Secure Vault", "EIP712 delegation testing", guardians, 2);
    // Guardian accepts invite
    await spooVault.connect(guardian).acceptGuardianInvite(1);

    // Add document
    await spooVault.connect(owner).addDocument(1, "encrypted-metadata", "QmDocumentIpfsHash", 0);

    // Mint access token for beneficiary
    await spooVault.connect(owner).mintAccessToken(1, beneficiary.address, "https://spoovault.io/nft/1");
  });

  describe("EIP-712 signature verification (verifyDelegation)", function () {
    it("returns true for a valid signature from an active guardian", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now + 3600;
      const nonce = 101;

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);
      const isValid = await spooVault.verifyDelegation(
        guardian.address,
        delegate.address,
        1,
        validUntil,
        nonce,
        signature
      );

      expect(isValid).to.equal(true);
    });

    it("returns false for an expired delegation", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now - 100; // In the past
      const nonce = 102;

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);
      const isValid = await spooVault.verifyDelegation(
        guardian.address,
        delegate.address,
        1,
        validUntil,
        nonce,
        signature
      );

      expect(isValid).to.equal(false);
    });

    it("returns false if signer is not a guardian in the specified vault", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now + 3600;
      const nonce = 103;

      const value = {
        guardian: otherUser.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await otherUser.signTypedData(domain, types, value);
      const isValid = await spooVault.verifyDelegation(
        otherUser.address,
        delegate.address,
        1,
        validUntil,
        nonce,
        signature
      );

      expect(isValid).to.equal(false);
    });

    it("returns false if verified against the wrong delegate address", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now + 3600;
      const nonce = 104;

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);
      const isValid = await spooVault.verifyDelegation(
        guardian.address,
        otherUser.address, // Mismatched delegate
        1,
        validUntil,
        nonce,
        signature
      );

      expect(isValid).to.equal(false);
    });
  });

  describe("On-Chain Nonce Revocation Registry (revokeDelegation)", function () {
    it("allows a guardian to revoke a delegation nonce", async function () {
      const nonce = 201;
      expect(await spooVault.revokedNonces(guardian.address, nonce)).to.equal(false);

      await expect(spooVault.connect(guardian).revokeDelegation(nonce))
        .to.emit(spooVault, "DelegationRevoked")
        .withArgs(guardian.address, nonce);

      expect(await spooVault.revokedNonces(guardian.address, nonce)).to.equal(true);
    });

    it("causes verifyDelegation to return false for revoked nonces", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now + 3600;
      const nonce = 202;

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);

      // Verify valid before revocation
      expect(
        await spooVault.verifyDelegation(
          guardian.address,
          delegate.address,
          1,
          validUntil,
          nonce,
          signature
        )
      ).to.equal(true);

      // Revoke nonce
      await spooVault.connect(guardian).revokeDelegation(nonce);

      // Verify invalid after revocation
      expect(
        await spooVault.verifyDelegation(
          guardian.address,
          delegate.address,
          1,
          validUntil,
          nonce,
          signature
        )
      ).to.equal(false);
    });
  });

  describe("Delegated Approval Execution (approveAccessDelegated)", function () {
    let requestId;

    beforeEach(async function () {
      // Beneficiary requests access
      await spooVault.connect(beneficiary).requestAccess(1);
      requestId = 1;
    });

    it("allows authorized delegate to submit approval on behalf of guardian", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now + 3600;
      const nonce = 301;

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);

      // Delegate approves on behalf of guardian
      await expect(
        spooVault
          .connect(delegate)
          ["approveAccessDelegated(uint256,address,uint256,uint256,bytes)"](
            requestId,
            guardian.address,
            validUntil,
            nonce,
            signature
          )
      )
        .to.emit(spooVault, "AccessApproved")
        .withArgs(requestId, guardian.address)
        .and.to.emit(spooVault, "DelegatedApprovalSubmitted")
        .withArgs(requestId, guardian.address, delegate.address);

      expect(await spooVault.hasApprovedRequest(requestId, guardian.address)).to.equal(true);
    });

    it("allows delegate to submit approval with encrypted share for beneficiary", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now + 3600;
      const nonce = 302;
      const share = "encrypted-beneficiary-share-payload";

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);

      await expect(
        spooVault
          .connect(delegate)
          ["approveAccessDelegated(uint256,address,uint256,uint256,bytes,string)"](
            requestId,
            guardian.address,
            validUntil,
            nonce,
            signature,
            share
          )
      )
        .to.emit(spooVault, "ShareSubmittedForBeneficiary")
        .withArgs(requestId, guardian.address, share);

      expect(await spooVault.beneficiaryKeyShares(requestId, guardian.address)).to.equal(share);
    });

    it("reverts with DelegationInvalidOrExpired if delegation is expired", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now - 10;
      const nonce = 303;

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);

      await expect(
        spooVault
          .connect(delegate)
          ["approveAccessDelegated(uint256,address,uint256,uint256,bytes)"](
            requestId,
            guardian.address,
            validUntil,
            nonce,
            signature
          )
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");
    });

    it("reverts with DelegationInvalidOrExpired if nonce is revoked", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now + 3600;
      const nonce = 304;

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);

      // Guardian revokes nonce
      await spooVault.connect(guardian).revokeDelegation(nonce);

      await expect(
        spooVault
          .connect(delegate)
          ["approveAccessDelegated(uint256,address,uint256,uint256,bytes)"](
            requestId,
            guardian.address,
            validUntil,
            nonce,
            signature
          )
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");
    });

    it("reverts if a non-delegate caller attempts to use the delegation", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now + 3600;
      const nonce = 305;

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);

      // otherUser attempts to use delegate's signature
      await expect(
        spooVault
          .connect(otherUser)
          ["approveAccessDelegated(uint256,address,uint256,uint256,bytes)"](
            requestId,
            guardian.address,
            validUntil,
            nonce,
            signature
          )
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");
    });

    it("completes quorum when delegated approval meets threshold and grants access", async function () {
      const now = await getLatestBlockTimestamp();
      const validUntil = now + 3600;
      const nonce = 306;

      const value = {
        guardian: guardian.address,
        delegate: delegate.address,
        vaultId: 1,
        validUntil,
        nonce,
      };

      const signature = await guardian.signTypedData(domain, types, value);

      // 1. Owner approves directly (1 approval)
      await spooVault.connect(owner).approveAccess(requestId);

      // 2. Delegate approves for guardian (2nd approval, reaches threshold of 2)
      await expect(
        spooVault
          .connect(delegate)
          ["approveAccessDelegated(uint256,address,uint256,uint256,bytes)"](
            requestId,
            guardian.address,
            validUntil,
            nonce,
            signature
          )
      )
        .to.emit(spooVault, "AccessGranted")
        .withArgs(requestId, 1, beneficiary.address);

      expect(await spooVault.hasActiveAccess(1, beneficiary.address)).to.equal(true);
    });
  });
});
