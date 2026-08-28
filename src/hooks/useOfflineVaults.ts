/**
 * useOfflineVaults — returns cached vault and document data from IndexedDB.
 *
 * Useful for components that want to display stale cached data while offline
 * without going through contractService's live fetch path.
 *
 * @example
 *   const { vaults, documents, isLoaded } = useOfflineVaults(account, "avalanche");
 */

import { useEffect, useState } from "react";
import {
  getCachedVaults,
  getCachedDocuments,
  type CachedVault,
  type CachedDocument,
  type OfflineNetwork,
} from "../services/offline/db";

export interface UseOfflineVaultsReturn {
  /** Cached vaults from IndexedDB (empty while loading or if nothing cached). */
  vaults: CachedVault[];
  /** Cached documents from IndexedDB (empty while loading or if nothing cached). */
  documents: CachedDocument[];
  /** True once the initial IndexedDB read has completed. */
  isLoaded: boolean;
}

export const useOfflineVaults = (
  account: string | null | undefined,
  network: OfflineNetwork
): UseOfflineVaultsReturn => {
  const [vaults, setVaults] = useState<CachedVault[]>([]);
  const [documents, setDocuments] = useState<CachedDocument[]>([]);
  const [isLoaded, setIsLoaded] = useState(false);

  useEffect(() => {
    if (!account) {
      setVaults([]);
      setDocuments([]);
      setIsLoaded(true);
      return;
    }

    let cancelled = false;

    const load = async () => {
      try {
        const [cachedVaults, cachedDocuments] = await Promise.all([
          getCachedVaults(account, network),
          getCachedDocuments(account, network),
        ]);

        if (!cancelled) {
          setVaults(cachedVaults);
          setDocuments(cachedDocuments);
        }
      } catch {
        // IndexedDB unavailable — silently serve empty arrays
      } finally {
        if (!cancelled) {
          setIsLoaded(true);
        }
      }
    };

    setIsLoaded(false);
    void load();

    return () => {
      cancelled = true;
    };
  }, [account, network]);

  return { vaults, documents, isLoaded };
};
