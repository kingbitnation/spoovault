import { describe, it, expect } from "vitest";
import { describeEmergencyUnlock } from "../utils/emergencyUnlockStatus";

describe("describeEmergencyUnlock", () => {
  it("does not claim unlock when emergency is off", () => {
    const status = describeEmergencyUnlock(false, {
      requested: true,
      fulfilled: true,
      unlockAt: 1,
      unlockBlock: 1,
    });
    expect(status.claimsUnlocked).toBe(false);
    expect(status.label).toBe("Emergency OFF");
    expect(status.detail).toBeNull();
  });

  it("shows pending randomness while a VRF request is outstanding", () => {
    const status = describeEmergencyUnlock(true, {
      requested: true,
      fulfilled: false,
      unlockAt: 0,
      unlockBlock: 0,
    });
    expect(status.claimsUnlocked).toBe(false);
    expect(status.label).toBe("Awaiting randomness");
    expect(status.detail).toMatch(/waiting for on-chain randomness/i);
  });

  it("shows scheduled bounds after fulfillment without claiming unlock", () => {
    const status = describeEmergencyUnlock(true, {
      requested: true,
      fulfilled: true,
      unlockAt: 1_700_000_000,
      unlockBlock: 12_345,
    });
    expect(status.claimsUnlocked).toBe(false);
    expect(status.label).toBe("Random delay scheduled");
    expect(status.detail).toMatch(/block\/ledger 12345/);
    expect(status.detail).toMatch(/both on-chain bounds/i);
  });

  it("describes legacy immediate unlock when no VRF request exists", () => {
    const status = describeEmergencyUnlock(true, {
      requested: false,
      fulfilled: false,
      unlockAt: 0,
      unlockBlock: 0,
    });
    expect(status.claimsUnlocked).toBe(false);
    expect(status.label).toBe("Emergency ON");
    expect(status.detail).toMatch(/legacy immediate-unlock/i);
  });

  it("shows a loading state without claiming unlock", () => {
    const status = describeEmergencyUnlock(
      true,
      { requested: true, fulfilled: true, unlockAt: 1, unlockBlock: 1 },
      "loading"
    );
    expect(status.claimsUnlocked).toBe(false);
    expect(status.label).toBe("Loading unlock status");
    expect(status.detail).toMatch(/stay locked/i);
  });

  it("shows an error state without claiming unlock", () => {
    const status = describeEmergencyUnlock(
      true,
      { requested: true, fulfilled: true, unlockAt: 1, unlockBlock: 1 },
      "error"
    );
    expect(status.claimsUnlocked).toBe(false);
    expect(status.label).toBe("Unlock status unavailable");
    expect(status.detail).toMatch(/could not load/i);
  });
});
