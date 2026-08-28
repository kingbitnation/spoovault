const { expect } = require("chai");
const { ethers } = require("hardhat");
const { deploySpooVault } = require("./helpers/deploySpooVault.cjs");

describe("BLS Threshold vs ECDSA Gas Benchmark", function () {
  let spooVault;
  let mockVerifier;
  let owner;
  let requester;
  let requester2;
  let guardians = [];
  let vaultId;
  let documentId1;
  let documentId2;

  const mockG1Key = (seed) => {
    const buf = Buffer.alloc(48, seed);
    buf[0] = 0x80 | (seed & 0x7f);
    return "0x" + buf.toString("hex");
  };

  const mockG2Sig = (seed) => {
    const buf = Buffer.alloc(96, seed);
    buf[0] = 0x80 | (seed & 0x7f);
    return "0x" + buf.toString("hex");
  };

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    owner = signers[0];
    requester = signers[1];
    requester2 = signers[2];
    guardians = signers.slice(3, 13).sort((a, b) => (a.address.toLowerCase() < b.address.toLowerCase() ? -1 : 1)); // K = 10 guardians sorted

    spooVault = await deploySpooVault(owner);

    const MockBLSVerifier = await ethers.getContractFactory("MockBLSVerifier");
    mockVerifier = await MockBLSVerifier.deploy();
    await mockVerifier.waitForDeployment();

    // Create vault with 10 guardians, threshold = 10
    const guardianAddresses = guardians.map((g) => g.address);
    const tx = await spooVault
      .connect(owner)
      .createVault("K=10 Gas Benchmark Vault", "Vault for K=10 gas comparison", guardianAddresses, 10);
    await tx.wait();
    vaultId = 1;

    // Accept invites and register BLS keys
    for (let i = 0; i < guardians.length; i++) {
      await spooVault.connect(guardians[i]).acceptGuardianInvite(vaultId);
      await spooVault
        .connect(guardians[i])
        .registerGuardianBLSKey(vaultId, mockG1Key(i + 1), mockG2Sig(i + 1));
    }

    // Add documents and mint passes
    await spooVault.connect(owner).addDocument(vaultId, "meta1", "QmHash1", 0);
    documentId1 = 1;
    await spooVault.connect(owner).addDocument(vaultId, "meta2", "QmHash2", 0);
    documentId2 = 2;

    await spooVault.connect(owner).mintAccessToken(vaultId, requester.address, "uri1");
    await spooVault.connect(owner).mintAccessToken(vaultId, requester2.address, "uri2");
  });

  it("demonstrates >70% on-chain gas reduction for K=10 guardian approvals using BLS aggregation", async function () {
    // Benchmark 1: Sequential individual approvals (Standard ECDSA flow - 10 separate transactions)
    await spooVault.connect(requester).requestAccess(documentId1);
    const ecdsaRequestId = 1;

    let totalEcdsaGas = 0n;
    for (let i = 0; i < guardians.length; i++) {
      const tx = await spooVault
        .connect(guardians[i])
        ["approveAccess(uint256)"](ecdsaRequestId);
      const receipt = await tx.wait();
      totalEcdsaGas += receipt.gasUsed;
    }

    // Benchmark 2: 1-Tx Aggregated BLS Threshold Approval (1 single transaction)
    await spooVault.connect(requester2).requestAccess(documentId2);
    const blsRequestId = 2;

    const guardianAddresses = guardians.map((g) => g.address);
    const aggregatedSig = mockG2Sig(99);
    const aggregatedPk = mockG1Key(99);

    const blsTx = await spooVault.approveAccessBLS(
      blsRequestId,
      guardianAddresses,
      aggregatedSig,
      aggregatedPk,
      []
    );
    const blsReceipt = await blsTx.wait();
    const blsGas = blsReceipt.gasUsed;

    const gasSaved = totalEcdsaGas - blsGas;
    const percentageReduction = (Number(gasSaved) / Number(totalEcdsaGas)) * 100;

    console.log("\n=======================================================");
    console.log("       K=10 GUARDIAN APPROVAL GAS BENCHMARK REPORT      ");
    console.log("=======================================================");
    console.log(`Standard Individual Approvals (10 txs): ${totalEcdsaGas.toLocaleString()} gas`);
    console.log(`Aggregated BLS Threshold Approval (1 tx): ${blsGas.toLocaleString()} gas`);
    console.log(`Absolute Gas Reduction:                ${gasSaved.toLocaleString()} gas`);
    console.log(`Percentage Reduction:                  ${percentageReduction.toFixed(2)}%`);
    console.log("=======================================================\n");

    expect(percentageReduction).to.be.greaterThan(70.0);
  });
});
