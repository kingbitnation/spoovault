/**
 * SpooVault Contract Deployment Script
 *
 * Deploys the updated SpooVault.sol to Avalanche Fuji Testnet.
 *
 * Prerequisites:
 *   npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox dotenv
 *   Set DEPLOYER_PRIVATE_KEY in .env
 *
 * Usage:
 *   node scripts/deploy.mjs
 *
 * The script will:
 *   1. Compile the contract via solc (expects ABI + bytecode JSON from hardhat artifacts)
 *   2. Deploy to Fuji using the signer derived from DEPLOYER_PRIVATE_KEY
 *   3. Print the new contract address
 *   4. Remind you to update VITE_CONTRACT_ADDRESS in .env
 */

import { readFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Load .env manually (no dotenv package required in this script)
const envPath = resolve(__dirname, "../.env");
if (existsSync(envPath)) {
  const envContent = readFileSync(envPath, "utf-8");
  for (const line of envContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx < 0) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const value = trimmed.slice(eqIdx + 1).trim();
    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

const PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY;
if (!PRIVATE_KEY) {
  console.error(
    "\n❌ DEPLOYER_PRIVATE_KEY is not set in .env\n" +
      "   Add: DEPLOYER_PRIVATE_KEY=0x<your_private_key>\n" +
      "   ⚠️  Never commit your private key. Use a throwaway wallet for testnet.\n"
  );
  process.exit(1);
}

const RPC_URL =
  process.env.VITE_AVALANCHE_RPC ||
  "https://api.avax-test.network/ext/bc/C/rpc";

// Hardhat artifacts path (run `npx hardhat compile` first)
const ARTIFACT_PATH = resolve(
  __dirname,
  "../artifacts/contracts/SpooVault.sol/SpooVault.json"
);

if (!existsSync(ARTIFACT_PATH)) {
  console.error(
    "\n❌ Contract artifact not found at:\n   " +
      ARTIFACT_PATH +
      "\n\n" +
      "   Run: npx hardhat compile\n" +
      "   (Install Hardhat first: npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox)\n"
  );
  process.exit(1);
}

const artifact = JSON.parse(readFileSync(ARTIFACT_PATH, "utf-8"));
const { abi } = artifact;

const LIB_ARTIFACT_PATH = resolve(
  __dirname,
  "../artifacts/contracts/libraries/EmergencyVrfLogic.sol/EmergencyVrfLogic.json"
);
if (!existsSync(LIB_ARTIFACT_PATH)) {
  console.error(
    "\n❌ EmergencyVrfLogic artifact not found.\n   Run: npx hardhat compile\n"
  );
  process.exit(1);
}
const ADMIN_ARTIFACT_PATH = resolve(
  __dirname,
  "../artifacts/contracts/libraries/SpooVaultAdminLogic.sol/SpooVaultAdminLogic.json"
);
if (!existsSync(ADMIN_ARTIFACT_PATH)) {
  console.error(
    "\n❌ SpooVaultAdminLogic artifact not found.\n   Run: npx hardhat compile\n"
  );
  process.exit(1);
}
const adminArtifact = JSON.parse(readFileSync(ADMIN_ARTIFACT_PATH, "utf-8"));

function linkBytecode(unlinked, linkReferences, libraries) {
  let bytecode = unlinked.startsWith("0x") ? unlinked : `0x${unlinked}`;
  for (const file of Object.keys(linkReferences || {})) {
    for (const name of Object.keys(linkReferences[file])) {
      const address = libraries[name];
      if (!address) {
        throw new Error(`Missing linked library ${name}`);
      }
      const hex = address.toLowerCase().replace(/^0x/, "");
      for (const loc of linkReferences[file][name]) {
        const start = 2 + loc.start * 2;
        bytecode =
          bytecode.slice(0, start) + hex + bytecode.slice(start + loc.length * 2);
      }
    }
  }
  if (bytecode.includes("__")) {
    throw new Error("Bytecode still contains unlinked library placeholders");
  }
  return bytecode;
}

// Dynamic import of ethers (already in package.json)
const { ethers } = await import("ethers");

async function main() {
  console.log("\n🚀 SpooVault Deployment Script");
  console.log("================================");
  console.log("Network :", RPC_URL);

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

  const balance = await provider.getBalance(wallet.address);
  console.log("Deployer:", wallet.address);
  console.log("Balance :", ethers.formatEther(balance), "AVAX");

  if (balance === 0n) {
    console.warn(
      "\n⚠️  Deployer balance is 0 AVAX. Get testnet AVAX from:\n" +
        "   https://core.app/tools/testnet-faucet/\n"
    );
  }

  console.log("\nDeploying EmergencyVrfLogic library...");
  const libFactory = new ethers.ContractFactory(libArtifact.abi, libArtifact.bytecode, wallet);
  const lib = await libFactory.deploy();
  await lib.waitForDeployment();
  const libAddress = await lib.getAddress();
  console.log("Library :", libAddress);

  console.log("\nDeploying SpooVaultAdminLogic library...");
  const adminFactory = new ethers.ContractFactory(adminArtifact.abi, adminArtifact.bytecode, wallet);
  const admin = await adminFactory.deploy();
  await admin.waitForDeployment();
  const adminAddress = await admin.getAddress();
  console.log("Admin lib:", adminAddress);

  const bytecode = linkBytecode(artifact.bytecode, artifact.linkReferences, {
    EmergencyVrfLogic: libAddress,
    SpooVaultAdminLogic: adminAddress,
  });

  console.log("\nDeploying SpooVault...");
  const factory = new ethers.ContractFactory(abi, bytecode, wallet);
  const contract = await factory.deploy();

  console.log("Tx hash :", contract.deploymentTransaction()?.hash);
  console.log("Waiting for confirmation...");

  await contract.waitForDeployment();

  const address = await contract.getAddress();
  const deployed = new ethers.Contract(address, abi, wallet);
  const code = await provider.getCode(address);
  const runtimeBytes = (code.length - 2) / 2;
  if (runtimeBytes > 24576) {
    console.warn(
      `\n⚠️  Runtime bytecode is ${runtimeBytes} bytes (EIP-170 limit 24576). ` +
        "This deployment may be rejected on networks that enforce the cap."
    );
  }

  const vrfCoordinator = process.env.VRF_COORDINATOR || process.env.CHAINLINK_VRF_COORDINATOR;
  if (vrfCoordinator && vrfCoordinator !== ethers.ZeroAddress) {
    const keyHash = process.env.VRF_KEY_HASH || process.env.CHAINLINK_VRF_KEY_HASH;
    const subscriptionId = process.env.VRF_SUBSCRIPTION_ID || process.env.CHAINLINK_VRF_SUBSCRIPTION_ID;
    if (!keyHash || !subscriptionId) {
      console.warn(
        "\n⚠️  VRF_COORDINATOR is set but VRF_KEY_HASH / VRF_SUBSCRIPTION_ID are missing. Skipping configureVrf."
      );
    } else {
      const callbackGasLimit = Number(process.env.VRF_CALLBACK_GAS_LIMIT || 500000);
      const confirmations = Number(process.env.VRF_REQUEST_CONFIRMATIONS || 3);
      console.log("\nConfiguring Chainlink VRF v2.5...");
      const tx = await deployed.configureVrf(
        vrfCoordinator,
        keyHash,
        subscriptionId,
        callbackGasLimit,
        confirmations
      );
      await tx.wait();
      console.log("VRF coordinator:", vrfCoordinator);
    }
  } else {
    console.log(
      "\nVRF not configured (set VRF_COORDINATOR, VRF_KEY_HASH, VRF_SUBSCRIPTION_ID to enable jittered emergency unlocks)."
    );
  }

  console.log("\n✅ SpooVault deployed at:", address);
  console.log("\n📝 Next steps:");
  console.log("   1. Update your .env file:");
  console.log("      VITE_CONTRACT_ADDRESS=" + address);
  console.log("   2. Get the deploy block from Snowtrace:");
  console.log("      https://testnet.snowtrace.io/address/" + address);
  console.log("      VITE_CONTRACT_DEPLOY_BLOCK=<block_number>");
  console.log("   3. Rebuild and redeploy the frontend.\n");
}

main().catch((err) => {
  console.error("\n❌ Deployment failed:", err.message || err);
  process.exit(1);
});
