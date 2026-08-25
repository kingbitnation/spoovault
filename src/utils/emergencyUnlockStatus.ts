export interface EmergencyUnlockScheduleView {
  requested: boolean;
  fulfilled: boolean;
  unlockAt: number;
  unlockBlock: number;
}

export type EmergencyUnlockLoadState = "ready" | "loading" | "error";

export interface EmergencyUnlockStatus {
  label: string;
  detail: string | null;
  /** Client hint only. Authorization is always decided on-chain. */
  claimsUnlocked: boolean;
}

/**
 * Human-readable emergency-unlock status for vault cards.
 * Never reports documents as unlocked from local clocks/blocks; that decision
 * stays on-chain via the dual timestamp + height bounds.
 */
export const describeEmergencyUnlock = (
  emergencyMode: boolean,
  schedule: EmergencyUnlockScheduleView | undefined,
  loadState: EmergencyUnlockLoadState = "ready"
): EmergencyUnlockStatus => {
  if (loadState === "loading") {
    return {
      label: "Loading unlock status",
      detail:
        "Fetching the on-chain emergency unlock schedule. Emergency documents stay locked until the contract authorizes release.",
      claimsUnlocked: false,
    };
  }

  if (loadState === "error") {
    return {
      label: "Unlock status unavailable",
      detail:
        "Could not load the on-chain unlock schedule. Emergency documents stay locked until the contract authorizes release.",
      claimsUnlocked: false,
    };
  }

  if (!emergencyMode) {
    return { label: "Emergency OFF", detail: null, claimsUnlocked: false };
  }

  if (schedule?.requested && !schedule.fulfilled) {
    return {
      label: "Awaiting randomness",
      detail:
        "Emergency mode is on. Unlock timing is waiting for on-chain randomness; the final schedule is not confirmed yet. Emergency documents stay locked.",
      claimsUnlocked: false,
    };
  }

  if (schedule?.fulfilled) {
    const when = schedule.unlockAt > 0 ? new Date(schedule.unlockAt * 1000).toISOString() : "pending";
    return {
      label: "Random delay scheduled",
      detail: `Emergency documents stay locked until both on-chain bounds pass: timestamp ${when} and block/ledger ${schedule.unlockBlock}.`,
      claimsUnlocked: false,
    };
  }

  return {
    label: "Emergency ON",
    detail: "No VRF coordinator is configured, so emergency documents follow the legacy immediate-unlock path.",
    claimsUnlocked: false,
  };
};
