// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../contracts/SpooVault.sol";
import "./SpooVaultFuzzBytecode.sol";

/**
 * @title FuzzGuardian
 * @dev A second on-chain identity distinct from `SpooVaultFuzz` itself.
 *      Solidity's `msg.sender` for a nested call is the immediate caller,
 *      so every `vault.*` call made directly by `SpooVaultFuzz` is seen by
 *      the vault as coming from `address(SpooVaultFuzz)`, no matter which
 *      externally-owned address the fuzzer used to trigger the wrapper.
 *      Approval flows need a *second* distinct guardian address (the
 *      requester can never approve their own request), so this tiny relay
 *      contract is registered as guardian #2 and used only to call
 *      `approveAccess` on the harness's behalf.
 */
contract FuzzGuardian {
    SpooVault private immutable vault;

    constructor(SpooVault _vault) {
        vault = _vault;
    }

    function approve(uint256 requestId) external {
        vault.approveAccess(requestId);
    }
}

/**
 * @title SpooVaultFuzz
 * @dev Differential / invariant fuzzing harness for the SpooVault EVM contract.
 *
 *      Consumed by:
 *        - Echidna  (https://github.com/crytic/echidna)  -> checks `echidna_*` properties
 *        - Medusa   (https://github.com/crytic/medusa)   -> checks `invariant_*` properties
 *
 *      Design notes:
 *        * The harness does NOT inherit SpooVault. It composes an internal
 *          `SpooVault` instance, so the fuzzer can only reach the contract's
 *          mutating entry points through the `fuzz_*` wrappers defined here.
 *          This keeps the harness's shadow accounting (trackedSupply,
 *          approvalCounts) exact, because there is no way for the fuzzer to
 *          mint/burn/approve the underlying contract without going through
 *          these wrappers.
 *        * The harness contract itself (`address(this)`) is the vault's
 *          first guardian (vault sees `msg.sender == address(this)` for
 *          every direct call the harness makes) and also holds a vault
 *          access NFT, so it can act as both document uploader and access
 *          requester. `FuzzGuardian` is a second, distinct guardian identity
 *          used only to approve requests, since a requester can never
 *          approve their own request.
 *        * The original deployer (`msg.sender` at construction time) is
 *          additionally minted a vault access NFT so it remains a valid
 *          fuzzing actor for the mint/burn/ownership properties, matching
 *          the harness's original behavior.
 */
contract SpooVaultFuzz {
    // Fixed address that never appears anywhere else in this harness: never
    // passed as a guardian, never minted a token, never a requester. Used by
    // `echidna_unauthorized_user_cannot_access` to prove the vault never
    // grants access or guardian rights to an address outside its explicit
    // authorization flows.
    address private constant UNAUTHORIZED_USER = address(0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF);

    SpooVault private vault;
    FuzzGuardian private guardian2;

    uint256 public vaultId;
    uint256[] private documentIds;
    uint256[] private requestIds;
    uint256[] private mintedTokens;
    mapping(uint256 => bool) private burnedTokens;
    mapping(uint256 => uint256) private approvalCounts;

    uint256 private trackedSupply;

    constructor() {
        address vrfLib = SpooVaultFuzzBytecode.deployEmergencyVrfLogic();
        address adminLib = SpooVaultFuzzBytecode.deploySpooVaultAdminLogic();
        vault = SpooVault(payable(SpooVaultFuzzBytecode.deployLinkedVault(vrfLib, adminLib)));
        guardian2 = new FuzzGuardian(vault);

        // `address(this)` becomes the vault's first guardian automatically
        // (vault.createVault pushes msg.sender, which is the harness itself
        // for this call); `guardian2` is registered as the sole required
        // external guardian.
        address[] memory guardians = new address[](1);
        guardians[0] = address(guardian2);
        vaultId = vault.createVault("Fuzz Vault", "fuzz", guardians, 1);

        // Mint an access NFT to the original deployer so it remains a valid
        // fuzzing actor for the mint/burn/ownership properties.
        uint256 deployerTid = vault.mintAccessToken(vaultId, msg.sender, "fuzz-token");
        mintedTokens.push(deployerTid);
        trackedSupply += 1;

        // Mint an access NFT to the harness itself so it can request access
        // to documents (requestAccess requires the requester to own a vault
        // access token).
        uint256 selfTid = vault.mintAccessToken(vaultId, address(this), "fuzz-token-self");
        mintedTokens.push(selfTid);
        trackedSupply += 1;

        // Seed one document so request/approve flows have something to act on.
        uint256 did = vault.addDocument(vaultId, "fuzz-meta", "QmFuzzSeed", SpooVault.AccessLevel.READ);
        documentIds.push(did);
    }

    // ------------------------------------------------------------------
    // Fuzzable actions (Echidna/Medusa call these with random arguments)
    // ------------------------------------------------------------------

    function fuzz_addDocument() external {
        uint256 did = vault.addDocument(vaultId, "fuzz-meta", "QmFuzzHash", SpooVault.AccessLevel.READ);
        documentIds.push(did);
    }

    function fuzz_request() external {
        if (documentIds.length == 0) return;
        uint256 did = documentIds[documentIds.length - 1];
        uint256 rid = vault.requestAccess(did);
        requestIds.push(rid);
    }

    /// @dev Approves through the distinct `guardian2` identity so the call
    ///      can actually succeed (the harness itself is always the
    ///      requester, and a requester can never approve its own request).
    ///      Reverts (already approved, request not pending, etc.) are
    ///      swallowed via try/catch and simply don't advance the shadow
    ///      `approvalCounts` counter, matching how Echidna/Medusa treat
    ///      reverts as "rejected input" rather than a failure.
    function fuzz_approve(uint256 idx) external {
        if (idx >= requestIds.length) return;
        uint256 rid = requestIds[idx];
        try guardian2.approve(rid) {
            approvalCounts[rid] += 1;
        } catch {}
    }

    function fuzz_mint() external {
        uint256 tid = vault.mintAccessToken(vaultId, msg.sender, "fuzz-token");
        trackedSupply += 1;
        mintedTokens.push(tid);
    }

    function fuzz_burn(uint256 idx) external {
        if (idx >= mintedTokens.length) return;
        uint256 tid = mintedTokens[idx];
        if (burnedTokens[tid]) return;
        vault.burnAccessToken(tid);
        burnedTokens[tid] = true;
        trackedSupply -= 1;
    }

    // ------------------------------------------------------------------
    // Invariant helpers
    // ------------------------------------------------------------------

    /// @dev Supply accounting: every mint (via fuzz_mint) increments
    ///      `trackedSupply` and every burn (via fuzz_burn) decrements it.
    ///      Because the fuzzer can only mint/burn through these wrappers,
    ///      `trackedSupply` must always equal the contract's own totalSupply().
    function _checkSupply() private view returns (bool) {
        return vault.totalSupply() == trackedSupply;
    }

    /// @dev Ownership accounting: every token this harness minted that has not
    ///      been burned is owned by a non-zero address.
    function _checkOwnership() private view returns (bool) {
        for (uint256 i = 0; i < mintedTokens.length; i++) {
            uint256 tid = mintedTokens[i];
            if (burnedTokens[tid]) continue;
            address owner = vault.ownerOf(tid);
            if (owner == address(0)) return false;
        }
        return true;
    }

    /// @dev Quorum accounting: a request can only reach `approvedBy.length`
    ///      counted by `fuzz_approve`'s successful calls, and the vault
    ///      flips a request out of PENDING as soon as it hits the vault's
    ///      approval threshold (1 for this harness's single required
    ///      guardian). Because `hasApprovedRequest` blocks a guardian from
    ///      approving the same request twice, and the status guard blocks
    ///      approving a non-pending request, the shadow count of successful
    ///      approvals must never exceed the configured threshold.
    function _checkApprovalThreshold() private view returns (bool) {
        for (uint256 i = 0; i < requestIds.length; i++) {
            if (approvalCounts[requestIds[i]] > 1) return false;
        }
        return true;
    }

    /// @dev Access-control accounting: `UNAUTHORIZED_USER` is never passed
    ///      as a guardian, never minted a token, and never used as a
    ///      requester or approver anywhere in this harness, so it must never
    ///      be recognized as a guardian or granted document access.
    function _checkUnauthorizedAccess() private view returns (bool) {
        if (vault.isGuardian(vaultId, UNAUTHORIZED_USER)) return false;
        for (uint256 i = 0; i < documentIds.length; i++) {
            if (vault.hasAccess(documentIds[i], UNAUTHORIZED_USER)) return false;
        }
        return true;
    }

    // ------------------------------------------------------------------
    // Property functions
    // ------------------------------------------------------------------

    function echidna_vault_balance_sum_equals_total_supply() public view returns (bool) {
        return _checkSupply();
    }

    function echidna_minted_tokens_remain_owned() public view returns (bool) {
        return _checkOwnership();
    }

    function echidna_approval_threshold_never_exceeded() public view returns (bool) {
        return _checkApprovalThreshold();
    }

    function echidna_unauthorized_user_cannot_access() public view returns (bool) {
        return _checkUnauthorizedAccess();
    }

    // Medusa uses the `invariant_*` convention (mirrors the echidna properties).
    function invariant_vault_balance_sum_equals_total_supply() public view returns (bool) {
        return _checkSupply();
    }

    function invariant_minted_tokens_remain_owned() public view returns (bool) {
        return _checkOwnership();
    }

    function invariant_approval_threshold_never_exceeded() public view returns (bool) {
        return _checkApprovalThreshold();
    }

    function invariant_unauthorized_user_cannot_access() public view returns (bool) {
        return _checkUnauthorizedAccess();
    }
}
