// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "../ISpooVault.sol";

/// @title ReEntrancyAttacker — test-only contract that attempts read-only
///        re-entrancy via onERC721Received callback during mintAccessToken.
contract ReEntrancyAttacker is ERC721Holder {
    ISpooVault public target;

    constructor(ISpooVault _target) {
        target = _target;
    }

    /// @dev ERC-721 receiver callback — triggered by _safeMint inside mintAccessToken.
    ///      Calls hasActiveAccess to test that nonReentrantView blocks the re-entrant read.
    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public override returns (bytes4) {
        // This should revert with "ReentrancyGuard: reentrant view call"
        // because mintAccessToken holds the nonReentrant lock.
        target.hasActiveAccess(1, address(this));
        return this.onERC721Received.selector;
    }
}
