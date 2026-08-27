/**
 * Real-time GraphQL indexer & WebSocket subscription client (issue #144)
 *
 * Replaces polling-based RPC contract reads with a single GraphQL query
 * (dashboard load) plus push-based subscriptions (live updates), against
 * a Goldsky / Envio / Subsquid-style indexer that ingests SpooVault's
 * on-chain events (Avalanche EVM + Stellar Soroban) into one queryable
 * schema.
 *
 * NOTE: this repo does not yet have a deployed indexer. This client is
 * written against the schema below and is fully covered by tests using
 * an in-memory mock GraphQL/WebSocket server (see
 * src/__tests__/indexerGraphQL.service.test.ts). Pointing it at a real
 * indexer only requires setting VITE_INDEXER_HTTP_URL / VITE_INDEXER_WS_URL
 * -- no client code changes are needed.
 */

import { Client, cacheExchange, fetchExchange, subscriptionExchange, gql } from "@urql/core";
import { createClient as createWsClient, type Client as WsClient } from "graphql-ws";
import { buildSchema } from "graphql";

/* ------------------------------------------------------------------ */
/* Schema                                                              */
/* ------------------------------------------------------------------ */

export const INDEXER_SCHEMA_SDL = /* GraphQL */ `
  type Vault {
    gid: ID!
    chainId: String!
    vaultId: Int!
    owner: String!
    documentCount: Int!
    emergencyMode: Boolean!
    inactivityPeriod: Int!
    lastProofOfLife: String!
    postDeathUnlocked: Boolean!
  }

  type Document {
    id: ID!
    vaultGid: ID!
    cid: String!
    fileName: String!
    uploadedAt: String!
  }

  type AccessRequest {
    id: ID!
    vaultGid: ID!
    requester: String!
    status: String!
    requestedAt: String!
  }

  type GuardianApproval {
    id: ID!
    vaultGid: ID!
    guardian: String!
    approved: Boolean!
    approvedAt: String
  }

  type ActivityLog {
    id: ID!
    vaultGid: ID!
    action: String!
    actor: String!
    occurredAt: String!
  }

  type DashboardData {
    vaults: [Vault!]!
    documents: [Document!]!
    accessRequests: [AccessRequest!]!
    guardianApprovals: [GuardianApproval!]!
    activityLog: [ActivityLog!]!
  }

  type Query {
    dashboard(owner: String!): DashboardData!
  }

  type Subscription {
    vaultActivity(vaultGid: ID!): ActivityLog!
  }
`;

/** Parsed once so callers/tests can validate the SDL structurally. */
export const indexerSchema = buildSchema(INDEXER_SCHEMA_SDL);

/* ------------------------------------------------------------------ */
/* Types                                                                */
/* ------------------------------------------------------------------ */

export interface IndexedVault {
  gid: string;
  chainId: string;
  vaultId: number;
  owner: string;
  documentCount: number;
  emergencyMode: boolean;
  inactivityPeriod: number;
  lastProofOfLife: string;
  postDeathUnlocked: boolean;
}

export interface IndexedDocument {
  id: string;
  vaultGid: string;
  cid: string;
  fileName: string;
  uploadedAt: string;
}

export interface IndexedAccessRequest {
  id: string;
  vaultGid: string;
  requester: string;
  status: string;
  requestedAt: string;
}

export interface IndexedGuardianApproval {
  id: string;
  vaultGid: string;
  guardian: string;
  approved: boolean;
  approvedAt: string | null;
}

export interface IndexedActivityLog {
  id: string;
  vaultGid: string;
  action: string;
  actor: string;
  occurredAt: string;
}

export interface DashboardIndexerData {
  vaults: IndexedVault[];
  documents: IndexedDocument[];
  accessRequests: IndexedAccessRequest[];
  guardianApprovals: IndexedGuardianApproval[];
  activityLog: IndexedActivityLog[];
}

/* ------------------------------------------------------------------ */
/* Queries / subscriptions                                             */
/* ------------------------------------------------------------------ */

/**
 * Single query covering every dashboard list -- satisfies "All dashboard
 * list queries execute via single optimized GraphQL request".
 */
export const DASHBOARD_QUERY = gql`
  query Dashboard($owner: String!) {
    dashboard(owner: $owner) {
      vaults {
        gid
        chainId
        vaultId
        owner
        documentCount
        emergencyMode
        inactivityPeriod
        lastProofOfLife
        postDeathUnlocked
      }
      documents {
        id
        vaultGid
        cid
        fileName
        uploadedAt
      }
      accessRequests {
        id
        vaultGid
        requester
        status
        requestedAt
      }
      guardianApprovals {
        id
        vaultGid
        guardian
        approved
        approvedAt
      }
      activityLog {
        id
        vaultGid
        action
        actor
        occurredAt
      }
    }
  }
`;

export const VAULT_ACTIVITY_SUBSCRIPTION = gql`
  subscription VaultActivity($vaultGid: ID!) {
    vaultActivity(vaultGid: $vaultGid) {
      id
      vaultGid
      action
      actor
      occurredAt
    }
  }
`;

/* ------------------------------------------------------------------ */
/* Client factory                                                      */
/* ------------------------------------------------------------------ */

export interface IndexerClientConfig {
  httpUrl: string;
  wsUrl: string;
}

export interface IndexerClientHandle {
  client: Client;
  wsClient: WsClient;
  dispose: () => void;
}

/**
 * Build a urql Client wired to a GraphQL-WS subscription transport. Query
 * behaviour (dashboard reads) goes over HTTP; subscriptions (live updates)
 * go over the WebSocket link.
 */
export function createIndexerClient(config: IndexerClientConfig): IndexerClientHandle {
  const wsClient = createWsClient({ url: config.wsUrl });

  const client = new Client({
    url: config.httpUrl,
    preferGetMethod: false,
    exchanges: [
      cacheExchange,
      subscriptionExchange({
        forwardSubscription(request: any) {
          const input = { ...request, query: request.query ?? "" };
          return {
            subscribe(sink: any) {
              const unsubscribe = wsClient.subscribe(input, sink);
              return { unsubscribe };
            },
          };
        },
      }),
      fetchExchange,
    ],
  });

  return {
    client,
    wsClient,
    dispose: () => {
      wsClient.dispose();
    },
  };
}

/**
 * Execute the single combined dashboard query.
 */
export async function fetchDashboardData(
  client: Client,
  owner: string
): Promise<DashboardIndexerData> {
  const result = await client.query(DASHBOARD_QUERY, { owner }).toPromise();
  if (result.error) {
    throw new Error(`Indexer dashboard query failed: ${result.error.message}`);
  }
  const data = result.data?.dashboard as DashboardIndexerData | undefined;
  if (!data) {
    throw new Error("Indexer dashboard query returned no data");
  }
  return data;
}

/**
 * Subscribe to live activity for a single vault. Returns an unsubscribe
 * function -- callers should invoke it on unmount / vault-switch to avoid
 * leaking the underlying WebSocket subscription.
 */
export function subscribeToVaultActivity(
  client: Client,
  vaultGid: string,
  onEvent: (event: IndexedActivityLog) => void,
  onError?: (error: Error) => void
): () => void {
  const { unsubscribe } = client
    .subscription(VAULT_ACTIVITY_SUBSCRIPTION, { vaultGid })
    .subscribe((result: any) => {
      if (result.error) {
        onError?.(new Error(result.error.message));
        return;
      }
      const event = result.data?.vaultActivity as IndexedActivityLog | undefined;
      if (event) onEvent(event);
    });
  return unsubscribe;
}

/* ------------------------------------------------------------------ */
/* Optimistic cache reconciliation                                     */
/* ------------------------------------------------------------------ */

export interface ReconciledVaults {
  /** Vaults confirmed by the indexer (indexer is source of truth for these fields). */
  confirmed: IndexedVault[];
  /**
   * Vaults present only in local optimistic state (e.g. a just-created
   * vault the indexer hasn't ingested yet). Kept visible so the UI
   * doesn't flicker the item away while the indexer catches up.
   */
  pending: IndexedVault[];
}

/**
 * Reconcile an indexer response with local optimistic UI state. The
 * indexer is authoritative for any vault it knows about (by gid); any
 * vault that only exists in local optimistic state (not yet reflected by
 * the indexer) is surfaced separately as "pending" rather than dropped.
 */
export function reconcileOptimisticVaults(
  remoteVaults: IndexedVault[],
  optimisticLocalVaults: IndexedVault[]
): ReconciledVaults {
  const remoteGidSet = new Set(remoteVaults.map((vault) => vault.gid));
  const pending = optimisticLocalVaults.filter((vault) => !remoteGidSet.has(vault.gid));
  return {
    confirmed: remoteVaults,
    pending,
  };
}

export const indexerGraphQLService = {
  createIndexerClient,
  fetchDashboardData,
  subscribeToVaultActivity,
  reconcileOptimisticVaults,
};