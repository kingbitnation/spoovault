import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { FreighterShim } from '../services/stellar.service';

vi.mock('@stellar/stellar-sdk', () => {
  const mockAccount = { sequence: '0', accountId: 'GABC' };
  const mockServer = {
    getAccount: vi.fn().mockResolvedValue(mockAccount),
    simulateTransaction: vi.fn().mockResolvedValue({
      result: { retval: { _type: 'scvU32', u32: 42 } },
    }),
    sendTransaction: vi.fn().mockResolvedValue({ status: 'PENDING', hash: 'txhash123' }),
    getTransaction: vi.fn().mockResolvedValue({
      status: 'SUCCESS',
      returnValue: { _type: 'scvU32', u32: 42 },
    }),
  };
  return {
    Contract: vi.fn().mockImplementation(function () {
      return { call: vi.fn(() => 'mock-op') };
    }),
    Operation: {
      invokeContractFunction: vi.fn(() => 'mock-op'),
    },
    Address: vi.fn().mockImplementation(function (addr: string) {
      return {
        toScVal: vi.fn(() => ({ _type: 'scvAddress' })),
        toString: () => addr,
      };
    }),
    xdr: {
      ScVal: {
        scvVoid: vi.fn(() => ({ _type: 'scvVoid' })),
      },
    },
    nativeToScVal: vi.fn(() => ({ _type: 'scvMock' })),
    scValToNative: vi.fn(() => 'decoded-value'),
    Networks: { TESTNET: 'Test SDF Network ; September 2015' },
    TransactionBuilder: Object.assign(
      vi.fn().mockImplementation(function () {
        return {
          addOperation: vi.fn().mockReturnThis(),
          setTimeout: vi.fn().mockReturnThis(),
          build: vi.fn(() => ({ toXDR: () => 'mock-xdr' })),
        };
      }),
      { fromXDR: vi.fn(() => 'parsed-tx') },
    ),
    BASE_FEE: '100',
    rpc: {
      Server: vi.fn().mockImplementation(function () {
        return mockServer;
      }),
      Api: {
        isSimulationError: vi.fn(() => false),
        GetTransactionStatus: {
          NOT_FOUND: 'NOT_FOUND',
          SUCCESS: 'SUCCESS',
          FAILED: 'FAILED',
        },
      },
      assembleTransaction: vi.fn(() => ({
        build: () => ({ toXDR: () => 'assembled-xdr' }),
      })),
    },
  };
});

vi.mock('@stellar/freighter-api', () => ({
  isConnected: vi.fn().mockResolvedValue(true),
  getPublicKey: vi.fn().mockResolvedValue('GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB'),
  signTransaction: vi.fn().mockResolvedValue('signed-xdr'),
}));

import { stellarService } from '../services/stellar.service';
import * as freighter from '@stellar/freighter-api';

class MockLocalStorage {
  private store: Record<string, string> = {};
  getItem(key: string): string | null { return this.store[key] || null; }
  setItem(key: string, value: string): void { this.store[key] = String(value); }
  removeItem(key: string): void { delete this.store[key]; }
  clear(): void { this.store = {}; }
}

const setupWallet = async (overrides?: Partial<FreighterShim>) => {
  const mock: FreighterShim = {
    isConnected: vi.fn().mockResolvedValue(true),
    getAddress: vi.fn().mockResolvedValue('GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB'),
    signTransaction: vi.fn().mockResolvedValue('signed-xdr'),
    getNetwork: vi.fn().mockResolvedValue('TESTNET'),
    ...overrides,
  };
  stellarService.setMockFreighter(mock);
  await stellarService.connectWallet();
  return mock;
};

beforeEach(() => {
  if (typeof globalThis.localStorage === 'undefined') {
    (globalThis as any).localStorage = new MockLocalStorage();
  }
  globalThis.localStorage.clear();
  vi.clearAllMocks();
  vi.unstubAllEnvs();
  stellarService.clear();
  stellarService.setMockFreighter(null as any);
  (freighter.isConnected as any).mockResolvedValue(true);
  (freighter.getPublicKey as any).mockResolvedValue('GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB');
  (freighter.signTransaction as any).mockResolvedValue('signed-xdr');

  vi.stubEnv('VITE_STELLAR_CONTRACT_ADDRESS', 'CCTESTCONTRACT1234567890ABCDEF');
});

// ---------------------------------------------------------------------------
// 2. createVault
// ---------------------------------------------------------------------------
describe('stellarService - createVault', () => {
  it('should invoke the contract successfully', async () => {
    await setupWallet();
    const result = await stellarService.createVault('My Vault', 'Desc', ['GABC'], 1);
    expect(typeof result).toBe('number');
  });

  it('should throw when wallet not connected', async () => {
    stellarService.clear();
    await expect(
      stellarService.createVault('Test', 'Desc', [], 1)
    ).rejects.toThrow('Wallet not connected');
  });

  it('should fall back to local mock storage (not throw) when the contract is not configured', async () => {
    vi.stubEnv('VITE_STELLAR_CONTRACT_ADDRESS', '');
    await setupWallet();

    const result = await stellarService.createVault('Test', 'Desc', [], 1);
    expect(typeof result).toBe('number');
  });
});

// ---------------------------------------------------------------------------
// 3. addDocument
// ---------------------------------------------------------------------------
describe('stellarService - addDocument', () => {
  it('should invoke successfully', async () => {
    await setupWallet();
    const result = await stellarService.addDocument(1, 'encrypted-metadata', 'ipfs-hash', 0);
    expect(typeof result).toBe('number');
  });

  it('should throw when wallet not connected', async () => {
    stellarService.clear();
    await expect(
      stellarService.addDocument(1, 'enc', 'ipfs', 0)
    ).rejects.toThrow('Wallet not connected');
  });
});

// ---------------------------------------------------------------------------
// 4. requestAccess
// ---------------------------------------------------------------------------
describe('stellarService - requestAccess', () => {
  it('should invoke successfully', async () => {
    await setupWallet();
    const result = await stellarService.requestAccess(42);
    expect(typeof result).toBe('number');
  });

  it('should throw when wallet not connected', async () => {
    stellarService.clear();
    await expect(stellarService.requestAccess(1)).rejects.toThrow('Wallet not connected');
  });
});

// ---------------------------------------------------------------------------
// 5. approveAccess
// ---------------------------------------------------------------------------
describe('stellarService - approveAccess', () => {
  it('should invoke with encrypted share', async () => {
    await setupWallet();
    await stellarService.approveAccess(1, 'encrypted-share-data');
  });

  it('should invoke without encrypted share', async () => {
    await setupWallet();
    await stellarService.approveAccess(1);
  });

  it('should throw when wallet not connected', async () => {
    stellarService.clear();
    await expect(stellarService.approveAccess(1)).rejects.toThrow('Wallet not connected');
  });
});

// ---------------------------------------------------------------------------
// 6. acceptGuardianInvite
// ---------------------------------------------------------------------------
describe('stellarService - acceptGuardianInvite', () => {
  it('should invoke successfully', async () => {
    await setupWallet();
    await stellarService.acceptGuardianInvite(7);
  });

  it('should throw when wallet not connected', async () => {
    stellarService.clear();
    await expect(stellarService.acceptGuardianInvite(1)).rejects.toThrow('Wallet not connected');
  });
});

// ---------------------------------------------------------------------------
// 7. registerPublicKey
// ---------------------------------------------------------------------------
describe('stellarService - registerPublicKey', () => {
  it('should invoke successfully', async () => {
    await setupWallet();
    await stellarService.registerPublicKey('stellar-pub-key-123');
  });

  it('should throw when wallet not connected', async () => {
    stellarService.clear();
    await expect(stellarService.registerPublicKey('key')).rejects.toThrow('Wallet not connected');
  });
});

// ---------------------------------------------------------------------------
// 8. user declined errors – Freighter signing rejection propagates as-is
//    across all 6 functions. `executeSorobanCall` (stellar.service.ts) does
//    not normalize the underlying wallet error into any fixed message, so
//    these assert the raw rejection surfaces unchanged to the caller.
//    The rejection must be set on the wallet actually in use: `setupWallet`
//    injects a mock via `stellarService.setMockFreighter`, which takes
//    priority over the `@stellar/freighter-api` module mock (see
//    `loadFreighter` in stellar.service.ts), so it has to be configured via
//    `setupWallet`'s overrides rather than by mutating the module mock.
// ---------------------------------------------------------------------------
describe('stellarService - user declined errors', () => {
  const rejectingSigner = (message: string) => ({
    signTransaction: vi.fn().mockRejectedValue(new Error(message)),
  });

  it('should propagate rejection in createVault', async () => {
    await setupWallet(rejectingSigner('User declined'));

    await expect(
      stellarService.createVault('Test', 'Desc', [], 1)
    ).rejects.toThrow('User declined');
  });

  it('should propagate rejection in addDocument', async () => {
    await setupWallet(rejectingSigner('User declined'));

    await expect(
      stellarService.addDocument(1, 'enc', 'ipfs', 0)
    ).rejects.toThrow('User declined');
  });

  it('should propagate rejection in requestAccess', async () => {
    await setupWallet(rejectingSigner('User declined'));

    await expect(
      stellarService.requestAccess(1)
    ).rejects.toThrow('User declined');
  });

  it('should propagate rejection in approveAccess', async () => {
    await setupWallet(rejectingSigner('User declined'));

    await expect(
      stellarService.approveAccess(1, 'share')
    ).rejects.toThrow('User declined');
  });

  it('should propagate rejection in acceptGuardianInvite', async () => {
    await setupWallet(rejectingSigner('User declined'));

    await expect(
      stellarService.acceptGuardianInvite(1)
    ).rejects.toThrow('User declined');
  });

  it('should propagate rejection in registerPublicKey', async () => {
    await setupWallet(rejectingSigner('User declined'));

    await expect(
      stellarService.registerPublicKey('key')
    ).rejects.toThrow('User declined');
  });

  it('should propagate a "cancel" rejection in createVault', async () => {
    await setupWallet(rejectingSigner('cancel'));

    await expect(
      stellarService.createVault('Test', 'Desc', [], 1)
    ).rejects.toThrow('cancel');
  });
});

// ---------------------------------------------------------------------------
// 9. Cross-Chain Identity Resolution
// ---------------------------------------------------------------------------
describe('stellarService - Cross-Chain Identity Resolution', () => {
  it('should register and resolve EVM address to Stellar address and public key', async () => {
    const stellarAddress = 'GBZXN7PIRZGNMHGA72STUFTOAITGM522NM3TVYLZMJOXOALPUYSTZFEF';
    const evmAddress = '0x64128680775Ef626379DeF6E5c815AeA8F4707Ef';
    const pubKey = '0x04bfcab5516089d846985a12';

    await stellarService.registerCrossChainIdentity(stellarAddress, evmAddress, pubKey);

    const resolvedStellar = await stellarService.resolveEvmToStellar(evmAddress);
    expect(resolvedStellar).toBe(stellarAddress);

    const resolvedEvm = await stellarService.resolveStellarToEvm(stellarAddress);
    expect(resolvedEvm).toBe(evmAddress.toLowerCase());

    const resolvedPubKey = await stellarService.resolveEvmToPublicKey(evmAddress);
    expect(resolvedPubKey).toBe(pubKey);
  });

  it('should return null for unregistered addresses', async () => {
    const resolved = await stellarService.resolveEvmToStellar('0x0000000000000000000000000000000000000000');
    expect(resolved).toBeNull();
  });

  it('should resolve Stellar to EVM after registration', async () => {
    const stellar = 'GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB';
    const evm = '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12';

    await stellarService.registerCrossChainIdentity(stellar, evm);

    const resolved = await stellarService.resolveStellarToEvm(stellar);
    expect(resolved).toBe(evm.toLowerCase());
  });

  it('should return null for unregistered Stellar to EVM', async () => {
    const resolved = await stellarService.resolveStellarToEvm('GZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ');
    expect(resolved).toBeNull();
  });

  it('should resolve EVM to public key via Stellar fallback', async () => {
    const stellar = 'GBZXN7PIRZGNMHGA72STUFTOAITGM522NM3TVYLZMJOXOALPUYSTZFEF';
    const evm = '0x64128680775Ef626379DeF6E5c815AeA8F4707Ef';
    const pubKey = 'mypubkey123';

    await stellarService.registerCrossChainIdentity(stellar, evm, pubKey);
    const resolved = await stellarService.resolveEvmToPublicKey(evm);
    expect(resolved).toBe(pubKey);
  });
});

// ---------------------------------------------------------------------------
// 10. utility functions
// ---------------------------------------------------------------------------
describe('stellarService - utility functions', () => {
  it('getRpcUrl should return default when no env var set', () => {
    vi.stubEnv('VITE_STELLAR_RPC_URL', '');
    const url = stellarService.getRpcUrl();
    expect(url).toContain('soroban-testnet.stellar.org');
  });

  it('getRpcUrl should return env var when set', () => {
    vi.stubEnv('VITE_STELLAR_RPC_URL', 'https://custom-rpc.example.com');
    const url = stellarService.getRpcUrl();
    expect(url).toBe('https://custom-rpc.example.com');
  });

  it('getContractId should return the configured contract address', () => {
    const id = stellarService.getContractId();
    expect(id).toBe('CCTESTCONTRACT1234567890ABCDEF');
  });

  it('getContractId should return empty string when not configured', () => {
    vi.stubEnv('VITE_STELLAR_CONTRACT_ADDRESS', '');
    const id = stellarService.getContractId();
    expect(id).toBe('');
  });

  it('isConfigured should return true when contract address is set', () => {
    expect(stellarService.isConfigured()).toBe(true);
  });

    it('isConfigured should return false when contract address is empty', () => {
    vi.stubEnv('VITE_STELLAR_CONTRACT_ADDRESS', '');
    expect(stellarService.isConfigured()).toBe(false);
  });
});

describe('stellarService - emergency unlock delay', () => {
  beforeEach(async () => {
    vi.stubEnv('VITE_STELLAR_CONTRACT_ADDRESS', '');
    stellarService.clear();
    await stellarService.initialize('');
    await setupWallet();
  });

  it('keeps a pending mock schedule until fulfillment', async () => {
    await stellarService.setEmergencyMode(1, true);
    const pending = await stellarService.getEmergencyUnlockSchedule(1);
    expect(pending.requested).toBe(true);
    expect(pending.fulfilled).toBe(false);

    await expect(stellarService.fulfillEmergencyUnlockDelay(1)).rejects.toThrow(
      /confirmations not met/i
    );
  });

  it('stores dual bounds after mock fulfillment', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    await stellarService.setEmergencyMode(1, true);
    vi.setSystemTime(new Date('2026-01-01T00:00:16Z'));
    await stellarService.fulfillEmergencyUnlockDelay(1);
    vi.useRealTimers();

    const schedule = await stellarService.getEmergencyUnlockSchedule(1);
    expect(schedule.fulfilled).toBe(true);
    expect(schedule.unlockAt).toBeGreaterThan(0);
    expect(schedule.unlockBlock).toBeGreaterThan(0);
    const state = await stellarService.getReleaseState(1);
    expect(state.emergencyMode).toBe(true);
  });
});
