/**
 * Runs `cargo test` for the Soroban crate.
 *
 * Build artifacts go under the OS temp directory so Windows Defender
 * Application Control policies that block executables under Documents
 * do not fail `cargo test --lib`.
 */
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const crateDir = join(root, "contracts-stellar");
const targetDir = process.env.CARGO_TARGET_DIR || join(tmpdir(), "spoovault-stellar-target");

const extraArgs = process.argv.slice(2);
const result = spawnSync("cargo", ["test", ...extraArgs], {
  cwd: crateDir,
  stdio: "inherit",
  env: { ...process.env, CARGO_TARGET_DIR: targetDir },
  shell: true,
});

process.exit(result.status === null ? 1 : result.status);
