const { ethers } = require("hardhat");

/**
 * Deploy SpooVault with EmergencyVrfLogic linked. External library
 * functions are DELEGATECALL'd so the vault stays under EIP-170.
 */
async function deploySpooVault(signer) {
  const libFactory = signer
    ? await ethers.getContractFactory("EmergencyVrfLogic", signer)
    : await ethers.getContractFactory("EmergencyVrfLogic");
  const lib = await libFactory.deploy();
  await lib.waitForDeployment();

  const adminFactory = signer
    ? await ethers.getContractFactory("SpooVaultAdminLogic", signer)
    : await ethers.getContractFactory("SpooVaultAdminLogic");
  const admin = await adminFactory.deploy();
  await admin.waitForDeployment();

  const factoryOptions = {
    libraries: {
      EmergencyVrfLogic: await lib.getAddress(),
      SpooVaultAdminLogic: await admin.getAddress(),
    },
  };
  if (signer) {
    factoryOptions.signer = signer;
  }
  const factory = await ethers.getContractFactory("SpooVault", factoryOptions);
  const vault = await factory.deploy();
  await vault.waitForDeployment();
  return vault;
}

module.exports = { deploySpooVault };
