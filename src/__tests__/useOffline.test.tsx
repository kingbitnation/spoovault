// @vitest-environment jsdom
import "fake-indexeddb/auto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { useOffline } from "../hooks/useOffline";
import { useOfflineVaults } from "../hooks/useOfflineVaults";
import { __setOfflineDbFactoryForTests, putVaults, putDocuments } from "../services/offline/db";
import { enqueueAction } from "../services/offline/offlineQueue.service";

// ---------------------------------------------------------------------------
// useOffline
// ---------------------------------------------------------------------------

vi.mock("../services/offline/replay.service", () => ({
  replayPendingActions: vi.fn().mockResolvedValue({ synced: 1, failed: 0, remaining: 0, attempted: 1, stoppedForOffline: false }),
  onReplayEvent: vi.fn(() => () => {}),
}));

describe("useOffline hook", () => {
  beforeEach(() => {
    __setOfflineDbFactoryForTests(new IDBFactory(), IDBKeyRange);
    vi.stubGlobal("navigator", { onLine: true });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    __setOfflineDbFactoryForTests(null);
  });

  it("reports online state by default", async () => {
    const { result } = renderHook(() => useOffline());

    // Allow initial state refresh to settle
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    expect(result.current.isOnline).toBe(true);
    expect(result.current.pending).toBe(0);
    expect(result.current.failed).toBe(0);
    expect(result.current.hasQueuedActions).toBe(false);
    expect(result.current.isSyncing).toBe(false);
  });

  it("reflects queued actions in pending count", async () => {
    await enqueueAction("register-public-key", { publicKey: "pk-test" });

    const { result } = renderHook(() => useOffline());

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    expect(result.current.pending).toBeGreaterThanOrEqual(1);
    expect(result.current.hasQueuedActions).toBe(true);
  });

  it("transitions isSyncing during syncNow call", async () => {
    let resolveSync!: () => void;
    const { replayPendingActions } = await import("../services/offline/replay.service");
    vi.mocked(replayPendingActions).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveSync = () =>
            resolve({ synced: 0, failed: 0, remaining: 0, attempted: 0, stoppedForOffline: false });
        })
    );

    const { result } = renderHook(() => useOffline());

    let syncPromise!: Promise<void>;
    act(() => {
      syncPromise = result.current.syncNow();
    });

    // isSyncing should be true while in-flight
    expect(result.current.isSyncing).toBe(true);

    await act(async () => {
      resolveSync();
      await syncPromise;
    });

    expect(result.current.isSyncing).toBe(false);
  });

  it("does not call replayPendingActions when offline", async () => {
    vi.stubGlobal("navigator", { onLine: false });
    const { replayPendingActions } = await import("../services/offline/replay.service");
    const spy = vi.mocked(replayPendingActions);
    spy.mockClear();

    const { result } = renderHook(() => useOffline());

    await act(async () => {
      await result.current.syncNow();
    });

    expect(spy).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// useOfflineVaults
// ---------------------------------------------------------------------------

const ACCOUNT = "0xabc0000000000000000000000000000000000001";

describe("useOfflineVaults hook", () => {
  beforeEach(() => {
    __setOfflineDbFactoryForTests(new IDBFactory(), IDBKeyRange);
  });

  afterEach(() => {
    __setOfflineDbFactoryForTests(null);
  });

  it("returns empty arrays with isLoaded=true when account is null", async () => {
    const { result } = renderHook(() => useOfflineVaults(null, "avalanche"));

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    expect(result.current.isLoaded).toBe(true);
    expect(result.current.vaults).toHaveLength(0);
    expect(result.current.documents).toHaveLength(0);
  });

  it("reads cached vaults and documents from IndexedDB", async () => {
    await putVaults(ACCOUNT, "avalanche", [
      {
        id: 1,
        creator: ACCOUNT,
        name: "Test Vault",
        description: "desc",
        guardians: [],
        approvalThreshold: 1,
        isActive: true,
        createdAt: 1700000000,
      },
    ]);
    await putDocuments(ACCOUNT, "avalanche", [
      {
        id: 10,
        vaultId: 1,
        encryptedMetadata: "{}",
        ipfsHash: "QmTest",
        uploadedBy: ACCOUNT,
        uploadedAt: 1700000100,
        requiredAccess: 1,
      },
    ]);

    const { result } = renderHook(() => useOfflineVaults(ACCOUNT, "avalanche"));

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    expect(result.current.isLoaded).toBe(true);
    expect(result.current.vaults).toHaveLength(1);
    expect(result.current.vaults[0].name).toBe("Test Vault");
    expect(result.current.documents).toHaveLength(1);
    expect(result.current.documents[0].ipfsHash).toBe("QmTest");
  });

  it("scopes results to the correct network", async () => {
    await putVaults(ACCOUNT, "avalanche", [
      {
        id: 1,
        creator: ACCOUNT,
        name: "EVM Vault",
        description: "",
        guardians: [],
        approvalThreshold: 1,
        isActive: true,
        createdAt: 1700000000,
      },
    ]);
    await putVaults(ACCOUNT, "stellar", [
      {
        id: 2,
        creator: ACCOUNT,
        name: "Stellar Vault",
        description: "",
        guardians: [],
        approvalThreshold: 1,
        isActive: true,
        createdAt: 1700000001,
      },
    ]);

    const { result } = renderHook(() => useOfflineVaults(ACCOUNT, "stellar"));

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    expect(result.current.vaults).toHaveLength(1);
    expect(result.current.vaults[0].name).toBe("Stellar Vault");
  });
});
