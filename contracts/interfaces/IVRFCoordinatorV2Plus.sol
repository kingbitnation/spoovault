// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @dev Minimal subset of the Chainlink VRF v2.5 coordinator interface
 * (IVRFCoordinatorV2Plus) required by SpooVault. Declared locally so the
 * protocol does not need the full chainlink contracts package.
 * Signature-compatible with Chainlink VRF v2.5 deployments, which take a
 * {RandomWordsRequest} struct rather than a flattened argument list.
 */
interface IVRFCoordinatorV2Plus {
    struct RandomWordsRequest {
        bytes32 keyHash;
        uint256 subId;
        uint16 requestConfirmations;
        uint32 callbackGasLimit;
        uint32 numWords;
        bytes extraArgs;
    }

    function requestRandomWords(RandomWordsRequest calldata req) external returns (uint256 requestId);
}
