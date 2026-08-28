// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Patches linked-library placeholders in unlinked creation bytecode and
///      deploys the result. Used by the Echidna/Medusa harness because
///      SpooVault pulls in external libraries for EIP-170 size.
library BytecodeLibraryLinker {
    error DeployFailed();

    function linkAt(
        bytes memory bytecode,
        uint256 byteOffset,
        address libraryAddress
    ) internal pure returns (bytes memory) {
        bytes20 libBytes = bytes20(libraryAddress);
        for (uint256 i = 0; i < 20; i++) {
            bytecode[byteOffset + i] = libBytes[i];
        }
        return bytecode;
    }

    function deploy(bytes memory creationCode) internal returns (address addr) {
        assembly {
            addr := create(0, add(creationCode, 0x20), mload(creationCode))
        }
        if (addr == address(0)) revert DeployFailed();
    }
}
