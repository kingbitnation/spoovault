# upgrade_fixture

Test-only fixture crate. It is a minimal, independently-versioned Soroban
contract used exclusively as the "new version" Wasm blob by the
`upgrade_contract` integration test in `contracts-stellar/src/test.rs`
(imported there via `soroban_sdk::contractimport!`).

It is never deployed and is not part of the SpooVault product surface. CI
builds it to `wasm32-unknown-unknown` before running the main crate's test
suite with `--features upgrade-tests`, since `contractimport!` reads the
compiled `.wasm` file at compile time. Local `cargo test` (and `npm run test:stellar`)
skips those upgrade tests unless the feature is enabled.

To build it locally and run upgrade tests:

```sh
cd contracts-stellar/upgrade_fixture
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
cd ..
cargo test --features upgrade-tests
```
