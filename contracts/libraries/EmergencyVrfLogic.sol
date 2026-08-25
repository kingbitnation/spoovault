// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IVRFCoordinatorV2Plus.sol";

/// @dev Linked library for Chainlink VRF v2.5 emergency-unlock jitter.
/// External functions are DELEGATECALL'd from SpooVault so the main contract
/// stays under the EIP-170 24,576-byte runtime cap.
library EmergencyVrfLogic {
    uint256 internal constant EMERGENCY_UNLOCK_BASE_DELAY = 10 minutes;
    uint256 internal constant DEFAULT_EMERGENCY_JITTER_WINDOW = 1 hours;
    uint256 internal constant MIN_JITTER_WINDOW = 5 minutes;
    uint256 internal constant MAX_JITTER_WINDOW = 7 days;
    uint256 internal constant MIN_EMERGENCY_UNLOCK_BLOCK_DELTA = 256;
    uint256 internal constant EMERGENCY_SECONDS_PER_BLOCK = 2;
    bytes4 internal constant VRF_EXTRA_ARGS_V1_TAG = bytes4(keccak256("VRF ExtraArgsV1"));

    error OnlyVrfCoordinator();
    error VrfRequestAlreadyPending();
    error VrfUnknownRequestId();
    error VrfAlreadyFulfilled();
    error InvalidJitterWindow();

    event EmergencyUnlockDelayRequested(uint256 indexed vaultId, uint256 indexed requestId);
    event EmergencyUnlockScheduled(
        uint256 indexed vaultId,
        uint256 indexed unlockAt,
        uint256 jitterSeconds,
        uint256 unlockBlock
    );
    event VrfConfigured(address indexed coordinator, bytes32 keyHash, uint256 subscriptionId);
    event EmergencyJitterWindowSet(uint256 indexed vaultId, uint256 jitterWindow);

    struct Store {
        address coordinator;
        bytes32 keyHash;
        uint256 subscriptionId;
        uint32 callbackGasLimit;
        uint16 minimumRequestConfirmations;
        mapping(uint256 => uint256) unlockAt;
        mapping(uint256 => uint256) unlockBlock;
        mapping(uint256 => uint256) requestIdByVault;
        mapping(uint256 => uint256) vaultIdByRequestId;
        mapping(uint256 => uint256) jitterWindow;
        mapping(uint256 => uint256) epoch;
        mapping(uint256 => uint256) epochByRequestId;
    }

    function configure(
        Store storage self,
        address coordinator,
        bytes32 keyHash,
        uint256 subscriptionId,
        uint32 callbackGasLimit,
        uint16 minimumRequestConfirmations
    ) external {
        self.coordinator = coordinator;
        self.keyHash = keyHash;
        self.subscriptionId = subscriptionId;
        self.callbackGasLimit = callbackGasLimit;
        self.minimumRequestConfirmations = minimumRequestConfirmations;
        emit VrfConfigured(coordinator, keyHash, subscriptionId);
    }

    function setJitterWindow(Store storage self, uint256 vaultId, uint256 jitterWindow) external {
        if (jitterWindow < MIN_JITTER_WINDOW || jitterWindow > MAX_JITTER_WINDOW) {
            revert InvalidJitterWindow();
        }
        self.jitterWindow[vaultId] = jitterWindow;
        emit EmergencyJitterWindowSet(vaultId, jitterWindow);
    }

    function requestUnlock(Store storage self, uint256 vaultId) external {
        if (self.requestIdByVault[vaultId] != 0 && self.unlockAt[vaultId] == 0) {
            revert VrfRequestAlreadyPending();
        }
        _clear(self, vaultId);
        uint256 epoch = self.epoch[vaultId] + 1;
        self.epoch[vaultId] = epoch;
        // Non-zero sentinel so a reentrant enable is rejected before the
        // coordinator returns the real request id (CEI).
        self.requestIdByVault[vaultId] = type(uint256).max;

        uint256 requestId = IVRFCoordinatorV2Plus(self.coordinator).requestRandomWords(
            IVRFCoordinatorV2Plus.RandomWordsRequest({
                keyHash: self.keyHash,
                subId: self.subscriptionId,
                requestConfirmations: self.minimumRequestConfirmations,
                callbackGasLimit: self.callbackGasLimit,
                numWords: 1,
                extraArgs: abi.encodeWithSelector(VRF_EXTRA_ARGS_V1_TAG, false)
            })
        );
        self.requestIdByVault[vaultId] = requestId;
        self.vaultIdByRequestId[requestId] = vaultId;
        self.epochByRequestId[requestId] = epoch;
        // slither-disable-next-line reentrancy-events
        emit EmergencyUnlockDelayRequested(vaultId, requestId);
    }

    function fulfill(
        Store storage self,
        uint256 requestId,
        uint256[] calldata randomWords,
        bool emergencyMode
    ) external {
        if (self.coordinator == address(0) || msg.sender != self.coordinator) {
            revert OnlyVrfCoordinator();
        }
        if (randomWords.length == 0) revert VrfUnknownRequestId();

        uint256 vaultId = self.vaultIdByRequestId[requestId];
        if (vaultId == 0 || self.requestIdByVault[vaultId] != requestId) revert VrfUnknownRequestId();
        if (self.epochByRequestId[requestId] != self.epoch[vaultId]) revert VrfUnknownRequestId();
        if (!emergencyMode) revert VrfUnknownRequestId();
        if (self.unlockAt[vaultId] != 0) revert VrfAlreadyFulfilled();

        uint256 window = self.jitterWindow[vaultId] != 0
            ? self.jitterWindow[vaultId]
            : DEFAULT_EMERGENCY_JITTER_WINDOW;
        if (window == 0) revert InvalidJitterWindow();
        uint256 jitter = randomWords[0] % window;
        uint256 unlockAt = block.timestamp + EMERGENCY_UNLOCK_BASE_DELAY + jitter;
        uint256 baseDelayBlocks = EMERGENCY_UNLOCK_BASE_DELAY / EMERGENCY_SECONDS_PER_BLOCK;
        uint256 unlockBlock = block.number
            + baseDelayBlocks
            + MIN_EMERGENCY_UNLOCK_BLOCK_DELTA
            + (jitter / EMERGENCY_SECONDS_PER_BLOCK);

        self.unlockAt[vaultId] = unlockAt;
        self.unlockBlock[vaultId] = unlockBlock;
        emit EmergencyUnlockScheduled(vaultId, unlockAt, jitter, unlockBlock);
    }

    function clear(Store storage self, uint256 vaultId) external {
        _clear(self, vaultId);
    }

    function _clear(Store storage self, uint256 vaultId) private {
        uint256 oldRequestId = self.requestIdByVault[vaultId];
        if (oldRequestId != 0) {
            delete self.vaultIdByRequestId[oldRequestId];
            delete self.epochByRequestId[oldRequestId];
            delete self.requestIdByVault[vaultId];
        }
        delete self.unlockAt[vaultId];
        delete self.unlockBlock[vaultId];
    }

    function isReleased(Store storage self, uint256 vaultId) external view returns (bool) {
        uint256 scheduledAt = self.unlockAt[vaultId];
        // Timestamp is one of two required bounds; block.number is the other,
        // so miner timestamp drift alone cannot unlock.
        // slither-disable-next-line timestamp
        return scheduledAt != 0
            && self.unlockBlock[vaultId] != 0
            && block.timestamp >= scheduledAt
            && block.number >= self.unlockBlock[vaultId];
    }
}
