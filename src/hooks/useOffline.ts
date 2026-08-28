/**
 * useOffline — reactive hook for offline status and queue state.
 *
 * Subscribes to navigator.onLine events and the Dexie-backed action queue so
 * any component can render offline-aware UI without duplicating listener
 * setup.
 *
 * @example
 *   const { isOnline, pending, failed, syncNow } = useOffline();
 */

import { useCallback, useEffect, useState } from "react";
import {
  subscribeToQueue,
  refreshQueueState,
  type QueueState,
} from "../services/offline/offlineQueue.service";
import { replayPendingActions } from "../services/offline/replay.service";

export interface UseOfflineReturn {
  /** True when navigator.onLine is true and the queue subscription confirms it. */
  isOnline: boolean;
  /** Number of pending (not-yet-attempted) queued actions. */
  pending: number;
  /** Number of actions that failed with a non-network error. */
  failed: number;
  /** Number of actions currently being processed. */
  processing: number;
  /** Number of actions that have been successfully synced. */
  synced: number;
  /** True if any actions are waiting to sync (pending + failed). */
  hasQueuedActions: boolean;
  /** Imperatively trigger a queue drain. Resolves when draining completes. */
  syncNow: () => Promise<void>;
  /** True while syncNow() is in flight. */
  isSyncing: boolean;
}

export const useOffline = (): UseOfflineReturn => {
  const [state, setState] = useState<QueueState>({
    pending: 0,
    failed: 0,
    processing: 0,
    synced: 0,
    online: true,
  });
  const [isSyncing, setIsSyncing] = useState(false);

  useEffect(() => {
    const unsubscribe = subscribeToQueue(setState);
    void refreshQueueState();

    const handleNetworkChange = () => void refreshQueueState();
    window.addEventListener("online", handleNetworkChange);
    window.addEventListener("offline", handleNetworkChange);

    return () => {
      unsubscribe();
      window.removeEventListener("online", handleNetworkChange);
      window.removeEventListener("offline", handleNetworkChange);
    };
  }, []);

  const syncNow = useCallback(async () => {
    if (!navigator.onLine) return;
    setIsSyncing(true);
    try {
      await replayPendingActions();
    } finally {
      setIsSyncing(false);
    }
  }, []);

  return {
    isOnline: state.online,
    pending: state.pending,
    failed: state.failed,
    processing: state.processing,
    synced: state.synced,
    hasQueuedActions: state.pending + state.failed > 0,
    syncNow,
    isSyncing,
  };
};
