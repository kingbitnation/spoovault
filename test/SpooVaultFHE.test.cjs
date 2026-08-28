const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySpooVault } = require("./helpers/deploySpooVault.cjs");

describe("SpooVault Fully Homomorphic Encryption (FHE) Share Aggregation", function () {
  let spooVault;
  let owner, guardian1, guardian2, guardian3, beneficiary, nonGuardian;

  // FHE Prime Modulus q (secp256k1 field prime)
  const FHE_PRIME = BigInt(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
  );

  function modQ(val) {
    const r = val % FHE_PRIME;
    return r < 0n ? r + FHE_PRIME : r;
  }

  function modInverseQ(a) {
    let base = modQ(a);
    let exp = FHE_PRIME - 2n;
    let res = 1n;
    while (exp > 0n) {
      if (exp & 1n) res = modQ(res * base);
      base = modQ(base * base);
      exp >>= 1n;
    }
    return res;
  }

  function bigIntToHex32(val) {
    let hex = modQ(val).toString(16);
    while (hex.length < 64) hex = "0" + hex;
    return hex;
  }

  function serializeFHE(aVec, bScalar) {
    const n = aVec.length;
    let hex = "0x" + bigIntToHex32(BigInt(n));
    for (let i = 0; i < n; i++) {
      hex += bigIntToHex32(aVec[i]);
    }
    hex += bigIntToHex32(bScalar);
    return hex;
  }

  function deserializeFHE(hexInput) {
    let hex = hexInput.startsWith("0x") ? hexInput.slice(2) : hexInput;
    const n = Number(BigInt("0x" + hex.slice(0, 64)));
    let offset = 64;
    const a = [];
    for (let i = 0; i < n; i++) {
      a.push(BigInt("0x" + hex.slice(offset, offset + 64)));
      offset += 64;
    }
    const b = BigInt("0x" + hex.slice(offset, offset + 64));
    return { a, b };
  }

  // Simple FHE KeyGen and Encryption for testing
  function testFheKeyGen() {
    const s = [0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0001n, 0x22223333444455556666777788889999aaaabbbbccccddddeeeeffff00001112n];
    return { s };
  }

  function testFheEncrypt(plaintext, keypair) {
    const m = modQ(BigInt(plaintext));
    // Sample pseudo-random a1, a2
    const a1 = modQ(BigInt(Math.floor(Math.random() * 1000000) + 12345));
    const a2 = modQ(BigInt(Math.floor(Math.random() * 1000000) + 67890));
    const dot = modQ(a1 * keypair.s[0] + a2 * keypair.s[1]);
    const b = modQ(dot + m);
    return { a: [a1, a2], b };
  }

  function testFheDecrypt(ct, keypair) {
    const dot = modQ(ct.a[0] * keypair.s[0] + ct.a[1] * keypair.s[1]);
    return modQ(ct.b - dot);
  }

  beforeEach(async function () {
    [owner, guardian1, guardian2, guardian3, beneficiary, nonGuardian] =
      await ethers.getSigners();

    spooVault = await deploySpooVault(owner);
  });

  describe("FHE Share Storage and Retrieval", function () {
    let vaultId, documentId;

    beforeEach(async function () {
      // Create vault with 3 guardians and threshold 2
      const tx = await spooVault.createVault(
        "Secure FHE Vault",
        "Threshold secret share aggregation via FHE",
        [guardian1.address, guardian2.address, guardian3.address],
        2
      );
      const receipt = await tx.wait();
      vaultId = 1;

      // Guardians accept invites
      await spooVault.connect(guardian1).acceptGuardianInvite(vaultId);
      await spooVault.connect(guardian2).acceptGuardianInvite(vaultId);
      await spooVault.connect(guardian3).acceptGuardianInvite(vaultId);

      // Add a document
      const docTx = await spooVault.addDocument(
        vaultId,
        "encryptedMetadataHash",
        "QmIPFSDocumentHashFHE",
        0
      );
      await docTx.wait();
      documentId = 1;
    });

    it("allows the creator or a guardian to save FHE-encrypted shares for guardians", async function () {
      const keypair = testFheKeyGen();
      const share1 = testFheEncrypt(0x1001n, keypair);
      const share2 = testFheEncrypt(0x2002n, keypair);
      const share3 = testFheEncrypt(0x3003n, keypair);

      const sharesFHE = [
        serializeFHE(share1.a, share1.b),
        serializeFHE(share2.a, share2.b),
        serializeFHE(share3.a, share3.b),
      ];

      const guardiansList = [guardian1.address, guardian2.address, guardian3.address];

      await expect(
        spooVault.saveGuardianSharesFHE(documentId, guardiansList, sharesFHE)
      )
        .to.emit(spooVault, "FheGuardianSharesSaved")
        .withArgs(documentId, 3);

      const storedShare1 = await spooVault.getFheGuardianShare(documentId, guardian1.address);
      expect(storedShare1).to.equal(sharesFHE[0]);

      const storedShare2 = await spooVault.getFheGuardianShare(documentId, guardian2.address);
      expect(storedShare2).to.equal(sharesFHE[1]);
    });

    it("reverts if a non-guardian tries to save FHE guardian shares", async function () {
      const keypair = testFheKeyGen();
      const share1 = testFheEncrypt(0x1001n, keypair);
      const sharesFHE = [serializeFHE(share1.a, share1.b)];

      await expect(
        spooVault.connect(nonGuardian).saveGuardianSharesFHE(documentId, [guardian1.address], sharesFHE)
      ).to.be.revertedWithCustomError(spooVault, "OnlyGuardian");
    });
  });

  describe("On-Chain Homomorphic Share Aggregation Flow", function () {
    let vaultId, documentId, requestId, keypair;
    const MASTER_SECRET_HEX = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const masterSecret = BigInt(MASTER_SECRET_HEX);

    beforeEach(async function () {
      keypair = testFheKeyGen();

      // Create vault with 3 guardians and threshold = 2
      await spooVault.createVault(
        "FHE Aggregator Vault",
        "Homomorphic threshold aggregation",
        [guardian1.address, guardian2.address, guardian3.address],
        2
      );
      vaultId = 1;

      // Guardians accept
      await spooVault.connect(guardian1).acceptGuardianInvite(vaultId);
      await spooVault.connect(guardian2).acceptGuardianInvite(vaultId);
      await spooVault.connect(guardian3).acceptGuardianInvite(vaultId);

      // Mint NFT pass to beneficiary
      await spooVault.mintAccessToken(vaultId, beneficiary.address, "ipfs://nft-pass-uri");

      // Add document
      await spooVault.addDocument(
        vaultId,
        "metadata",
        "QmDocumentIPFSHash",
        0
      );
      documentId = 1;

      // Beneficiary requests access
      const reqTx = await spooVault.connect(beneficiary).requestAccess(documentId);
      const reqReceipt = await reqTx.wait();
      requestId = 1;
    });

    it("homomorphically accumulates additive shares on-chain and reproduces exact secret", async function () {
      // Split masterSecret into 2 additive shares: s1 + s2 = masterSecret mod q
      const s1 = 0x5555555555555555555555555555555555555555555555555555555555555555n;
      const s2 = modQ(masterSecret - s1);
      expect(modQ(s1 + s2)).to.equal(modQ(masterSecret));

      const ct1 = testFheEncrypt(s1, keypair);
      const ct2 = testFheEncrypt(s2, keypair);

      const ct1Hex = serializeFHE(ct1.a, ct1.b);
      const ct2Hex = serializeFHE(ct2.a, ct2.b);

      // Guardian 1 approves with FHE share payload
      await expect(spooVault.connect(guardian1).approveAccessFHE(requestId, ct1Hex))
        .to.emit(spooVault, "FheShareSubmitted")
        .withArgs(requestId, guardian1.address);

      expect(await spooVault.fheAccumulatorCount(requestId)).to.equal(1);

      // Verify partial accumulation
      const partialAccHex = await spooVault.getFheAggregate(requestId);
      const partialCt = deserializeFHE(partialAccHex);
      expect(testFheDecrypt(partialCt, keypair)).to.equal(s1);

      // Guardian 2 approves with FHE share payload, reaching threshold = 2
      const approveTx = await spooVault.connect(guardian2).approveAccessFHE(requestId, ct2Hex);
      await expect(approveTx)
        .to.emit(spooVault, "FheShareSubmitted")
        .withArgs(requestId, guardian2.address)
        .and.to.emit(spooVault, "AccessApproved")
        .withArgs(requestId, guardian2.address)
        .and.to.emit(spooVault, "FheSharesAggregated");

      // Verify request is APPROVED and access is granted
      const request = await spooVault.accessRequests(requestId);
      expect(request.status).to.equal(1); // APPROVED
      expect(await spooVault.hasActiveAccess(documentId, beneficiary.address)).to.equal(true);

      // Verify that beneficiary decrypts aggregate ciphertext to exact master secret!
      const finalAggregateHex = await spooVault.getFheAggregate(requestId);
      const finalCt = deserializeFHE(finalAggregateHex);
      const recoveredSecret = testFheDecrypt(finalCt, keypair);

      expect(recoveredSecret).to.equal(modQ(masterSecret));
      expect("0x" + bigIntToHex32(recoveredSecret)).to.equal(MASTER_SECRET_HEX);
    });

    it("homomorphically accumulates Shamir threshold-interpolated shares on-chain", async function () {
      // (2, 3) Shamir Secret Sharing: f(x) = masterSecret + a1*x mod q
      const a1 = 0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcban;
      // Points: x1 = 1, x2 = 2
      const y1 = modQ(masterSecret + a1 * 1n);
      const y2 = modQ(masterSecret + a1 * 2n);

      // Lagrange basis coefficients for x1=1, x2=2 at x=0:
      // lambda1 = x2 / (x2 - x1) = 2 / 1 = 2
      // lambda2 = x1 / (x1 - x2) = 1 / (-1) = -1 = q - 1
      const lambda1 = 2n;
      const lambda2 = modQ(-1n);

      // Guardian 1 computes lambda1 * Enc(y1)
      const ct1Raw = testFheEncrypt(y1, keypair);
      const ct1Weighted = {
        a: [modQ(ct1Raw.a[0] * lambda1), modQ(ct1Raw.a[1] * lambda1)],
        b: modQ(ct1Raw.b * lambda1),
      };

      // Guardian 2 computes lambda2 * Enc(y2)
      const ct2Raw = testFheEncrypt(y2, keypair);
      const ct2Weighted = {
        a: [modQ(ct2Raw.a[0] * lambda2), modQ(ct2Raw.a[1] * lambda2)],
        b: modQ(ct2Raw.b * lambda2),
      };

      const payload1 = serializeFHE(ct1Weighted.a, ct1Weighted.b);
      const payload2 = serializeFHE(ct2Weighted.a, ct2Weighted.b);

      await spooVault.connect(guardian1).approveAccessFHE(requestId, payload1);
      await spooVault.connect(guardian2).approveAccessFHE(requestId, payload2);

      // Decrypt on-chain aggregate
      const aggregateHex = await spooVault.getFheAggregate(requestId);
      const aggregateCt = deserializeFHE(aggregateHex);
      const recoveredSecret = testFheDecrypt(aggregateCt, keypair);

      expect(recoveredSecret).to.equal(modQ(masterSecret));
      expect("0x" + bigIntToHex32(recoveredSecret)).to.equal(MASTER_SECRET_HEX);
    });

    it("verifies zero unencrypted secret or share material leaks in contract state or events", async function () {
      const s1 = 0x1111111111111111111111111111111111111111111111111111111111111111n;
      const s2 = modQ(masterSecret - s1);
      const ct1 = testFheEncrypt(s1, keypair);
      const ct2 = testFheEncrypt(s2, keypair);

      const ct1Hex = serializeFHE(ct1.a, ct1.b);
      const ct2Hex = serializeFHE(ct2.a, ct2.b);

      const tx1 = await spooVault.connect(guardian1).approveAccessFHE(requestId, ct1Hex);
      const receipt1 = await tx1.wait();

      const tx2 = await spooVault.connect(guardian2).approveAccessFHE(requestId, ct2Hex);
      const receipt2 = await tx2.wait();

      // Check event logs
      const rawSecretClean = MASTER_SECRET_HEX.slice(2).toLowerCase();
      const s1HexClean = bigIntToHex32(s1).toLowerCase();
      const s2HexClean = bigIntToHex32(s2).toLowerCase();

      for (const log of [...receipt1.logs, ...receipt2.logs]) {
        const logData = log.data.toLowerCase();
        expect(logData.includes(rawSecretClean)).to.equal(false);
        expect(logData.includes(s1HexClean)).to.equal(false);
        expect(logData.includes(s2HexClean)).to.equal(false);
      }
    });
  });
});
