// @vitest-environment jsdom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { EmergencyUnlockStatusView } from "../components/EmergencyUnlockStatusView";

afterEach(() => {
  cleanup();
});

describe("EmergencyUnlockStatusView", () => {
  it("renders pending randomness copy", () => {
    render(
      <EmergencyUnlockStatusView
        emergencyMode
        schedule={{ requested: true, fulfilled: false, unlockAt: 0, unlockBlock: 0 }}
      />
    );
    expect(screen.getByTestId("emergency-unlock-status")).toHaveTextContent("Awaiting randomness");
    expect(screen.getByTestId("emergency-unlock-detail")).toHaveTextContent(/waiting for on-chain randomness/i);
  });

  it("renders loading without claiming unlock", () => {
    render(
      <EmergencyUnlockStatusView
        emergencyMode
        schedule={{ requested: true, fulfilled: true, unlockAt: 9, unlockBlock: 9 }}
        loadState="loading"
      />
    );
    expect(screen.getByTestId("emergency-unlock-status")).toHaveTextContent("Loading unlock status");
    expect(screen.getByTestId("emergency-unlock-detail")).toHaveTextContent(/stay locked/i);
  });

  it("renders fetch errors without claiming unlock", () => {
    render(
      <EmergencyUnlockStatusView
        emergencyMode
        schedule={undefined}
        loadState="error"
      />
    );
    expect(screen.getByTestId("emergency-unlock-status")).toHaveTextContent("Unlock status unavailable");
    expect(screen.getByTestId("emergency-unlock-detail")).toHaveTextContent(/could not load/i);
  });
});
