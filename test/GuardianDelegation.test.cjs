const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

const GUARDIAN_DELEGATION_TYPES = {
  GuardianDelegation: [
    { name: "guardian", type: "address" },
    { name: "delegate", type: "address" },
    { name: "vaultId", type: "uint256" },
    { name: "validUntil", type: "uint256" },
    { name: "nonce", type: "uint256" },
  ],
};

const TYPESTRING =
  "GuardianDelegation(address guardian,address delegate,uint256 vaultId,uint256 validUntil,uint256 nonce)";

describe("SpooVault EIP-712 Guardian Delegation", function () {
  let spooVault;
  let owner;
  let guardian1;
  let delegate;
  let outsider;
  let beneficiary;
  let vaultId;
  let domain;

  async function signDelegation(signer, value) {
    return signer.signTypedData(domain, GUARDIAN_DELEGATION_TYPES, value);
  }

  async function requestAccessFrom(documentId, requester) {
    const tx = await spooVault.connect(requester).requestAccess(documentId);
    const receipt = await tx.wait();
    const evt = receipt.logs
      .map((log) => {
        try {
          return spooVault.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed && parsed.name === "AccessRequested");
    return evt.args.requestId;
  }

  beforeEach(async function () {
    [owner, guardian1, delegate, outsider, beneficiary] = await ethers.getSigners();

    const SpooVault = await ethers.getContractFactory("SpooVault");
    spooVault = await SpooVault.deploy();
    await spooVault.waitForDeployment();

    await spooVault
      .connect(owner)
      .createVault("Delegation Vault", "EIP-712 guardian coverage", [guardian1.address], 1);
    vaultId = 1;
    await spooVault.connect(guardian1).acceptGuardianInvite(vaultId);

    await spooVault.connect(owner).addDocument(vaultId, "encrypted-metadata", "QmDelegationDoc", 0);
    await spooVault.connect(owner).mintAccessToken(vaultId, beneficiary.address, "https://token.uri");

    const { chainId } = await ethers.provider.getNetwork();
    domain = {
      name: "SpooVault",
      version: "1",
      chainId,
      verifyingContract: await spooVault.getAddress(),
    };
  });

  describe("EIP-712 domain separator hashing", function () {
    it("matches IERC-5267 eip712Domain fields and ethers TypedDataEncoder.hashDomain", async function () {
      const [, name, version, chainId, verifyingContract, salt, extensions] =
        await spooVault.eip712Domain();

      expect(name).to.equal("SpooVault");
      expect(version).to.equal("1");
      expect(chainId).to.equal(domain.chainId);
      expect(verifyingContract).to.equal(domain.verifyingContract);
      expect(salt).to.equal(ethers.ZeroHash);
      expect(extensions).to.deep.equal([]);

      expect(ethers.TypedDataEncoder.hashDomain(domain)).to.equal(
        ethers.TypedDataEncoder.hashDomain({
          name,
          version,
          chainId,
          verifyingContract,
        })
      );
    });

    it("uses the canonical GuardianDelegation typehash in the struct digest", async function () {
      expect(ethers.id(TYPESTRING)).to.equal(
        ethers.keccak256(ethers.toUtf8Bytes(TYPESTRING))
      );

      const value = {
        guardian: guardian1.address,
        delegate: delegate.address,
        vaultId,
        validUntil: (await time.latest()) + 3600,
        nonce: 7n,
      };

      const offchainDigest = ethers.TypedDataEncoder.hash(
        domain,
        GUARDIAN_DELEGATION_TYPES,
        value
      );
      const signature = await signDelegation(guardian1, value);

      expect(ethers.verifyTypedData(domain, GUARDIAN_DELEGATION_TYPES, value, signature)).to.equal(
        guardian1.address
      );
      expect(ethers.recoverAddress(offchainDigest, signature)).to.equal(guardian1.address);

      await expect(
        spooVault.verifyDelegation(
          value.guardian,
          value.delegate,
          value.vaultId,
          value.validUntil,
          value.nonce,
          signature
        )
      ).to.not.be.reverted;
    });
  });

  describe("signature verification", function () {
    it("accepts a guardian-signed delegation for the named delegate and vault", async function () {
      const validUntil = (await time.latest()) + 7 * 24 * 60 * 60;
      const nonce = 1n;
      const signature = await signDelegation(guardian1, {
        guardian: guardian1.address,
        delegate: delegate.address,
        vaultId,
        validUntil,
        nonce,
      });

      await expect(
        spooVault.verifyDelegation(
          guardian1.address,
          delegate.address,
          vaultId,
          validUntil,
          nonce,
          signature
        )
      ).to.not.be.reverted;
    });

    it("reverts DelegationInvalidOrExpired when the signer is not the guardian", async function () {
      const validUntil = (await time.latest()) + 3600;
      const signature = await signDelegation(outsider, {
        guardian: guardian1.address,
        delegate: delegate.address,
        vaultId,
        validUntil,
        nonce: 0n,
      });

      await expect(
        spooVault.verifyDelegation(
          guardian1.address,
          delegate.address,
          vaultId,
          validUntil,
          0n,
          signature
        )
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");
    });

    it("reverts DelegationInvalidOrExpired for a malformed signature", async function () {
      const validUntil = (await time.latest()) + 3600;
      await expect(
        spooVault.verifyDelegation(
          guardian1.address,
          delegate.address,
          vaultId,
          validUntil,
          0n,
          "0x"
        )
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");
    });
  });

  describe("delegated approvals", function () {
    it("lets a delegate submit an approval that is recorded against the guardian", async function () {
      const requestId = await requestAccessFrom(1, beneficiary);
      const validUntil = (await time.latest()) + 3600;
      const nonce = 42n;
      const signature = await signDelegation(guardian1, {
        guardian: guardian1.address,
        delegate: delegate.address,
        vaultId,
        validUntil,
        nonce,
      });

      await expect(
        spooVault
          .connect(delegate)
          .approveAccessByDelegation(requestId, guardian1.address, validUntil, nonce, signature, "")
      )
        .to.emit(spooVault, "AccessApproved")
        .withArgs(requestId, guardian1.address)
        .and.to.emit(spooVault, "AccessGranted");

      expect(await spooVault.hasApprovedRequest(requestId, guardian1.address)).to.equal(true);
      expect(await spooVault.hasApprovedRequest(requestId, delegate.address)).to.equal(false);
      expect(await spooVault.hasActiveAccess(1, beneficiary.address)).to.equal(true);
    });

    it("lets a delegate attach a beneficiary key share on behalf of the guardian", async function () {
      const requestId = await requestAccessFrom(1, beneficiary);
      const validUntil = (await time.latest()) + 3600;
      const nonce = 3n;
      const signature = await signDelegation(guardian1, {
        guardian: guardian1.address,
        delegate: delegate.address,
        vaultId,
        validUntil,
        nonce,
      });
      const share = "encrypted-share-for-beneficiary";

      await expect(
        spooVault
          .connect(delegate)
          .approveAccessByDelegation(
            requestId,
            guardian1.address,
            validUntil,
            nonce,
            signature,
            share
          )
      )
        .to.emit(spooVault, "ShareSubmittedForBeneficiary")
        .withArgs(requestId, guardian1.address, share);

      expect(await spooVault.getBeneficiaryKeyShare(requestId, guardian1.address)).to.equal(share);
    });

    it("rejects a caller who is not the signed delegate", async function () {
      const requestId = await requestAccessFrom(1, beneficiary);
      const validUntil = (await time.latest()) + 3600;
      const nonce = 1n;
      const signature = await signDelegation(guardian1, {
        guardian: guardian1.address,
        delegate: delegate.address,
        vaultId,
        validUntil,
        nonce,
      });

      await expect(
        spooVault
          .connect(outsider)
          .approveAccessByDelegation(requestId, guardian1.address, validUntil, nonce, signature, "")
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");
    });
  });

  describe("expiry and nonce revocation", function () {
    it("reverts DelegationInvalidOrExpired after validUntil", async function () {
      const validUntil = (await time.latest()) + 60;
      const nonce = 9n;
      const signature = await signDelegation(guardian1, {
        guardian: guardian1.address,
        delegate: delegate.address,
        vaultId,
        validUntil,
        nonce,
      });

      await time.increaseTo(BigInt(validUntil) + 1n);

      await expect(
        spooVault.verifyDelegation(
          guardian1.address,
          delegate.address,
          vaultId,
          validUntil,
          nonce,
          signature
        )
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");

      const requestId = await requestAccessFrom(1, beneficiary);
      await expect(
        spooVault
          .connect(delegate)
          .approveAccessByDelegation(requestId, guardian1.address, validUntil, nonce, signature, "")
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");
    });

    it("lets a guardian revoke a nonce and immediately invalidates the signature", async function () {
      const validUntil = (await time.latest()) + 7 * 24 * 60 * 60;
      const nonce = 11n;
      const signature = await signDelegation(guardian1, {
        guardian: guardian1.address,
        delegate: delegate.address,
        vaultId,
        validUntil,
        nonce,
      });

      await expect(spooVault.connect(guardian1).revokeDelegation(nonce))
        .to.emit(spooVault, "DelegationNonceRevoked")
        .withArgs(guardian1.address, nonce);

      expect(await spooVault.revokedNonces(guardian1.address, nonce)).to.equal(true);

      await expect(
        spooVault.verifyDelegation(
          guardian1.address,
          delegate.address,
          vaultId,
          validUntil,
          nonce,
          signature
        )
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");

      const requestId = await requestAccessFrom(1, beneficiary);
      await expect(
        spooVault
          .connect(delegate)
          .approveAccessByDelegation(requestId, guardian1.address, validUntil, nonce, signature, "")
      ).to.be.revertedWithCustomError(spooVault, "DelegationInvalidOrExpired");
    });

    it("does not revoke a sibling nonce belonging to the same guardian", async function () {
      const validUntil = (await time.latest()) + 3600;
      const liveNonce = 2n;
      await spooVault.connect(guardian1).revokeDelegation(1n);

      const signature = await signDelegation(guardian1, {
        guardian: guardian1.address,
        delegate: delegate.address,
        vaultId,
        validUntil,
        nonce: liveNonce,
      });

      await expect(
        spooVault.verifyDelegation(
          guardian1.address,
          delegate.address,
          vaultId,
          validUntil,
          liveNonce,
          signature
        )
      ).to.not.be.reverted;
    });
  });
});
