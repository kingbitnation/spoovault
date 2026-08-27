import { openDB, type DBSchema, type IDBPDatabase } from 'idb';
import { ethers } from 'ethers';
import {
  generateBLSKeyPair,
  deriveBLSKeyFromMnemonic,
  getBLSPublicKey,
  createProofOfPossession,
  encodeApprovalMessage,
  signBLS,
  verifyAggregatedBLSSignature,
  aggregateGuardianApprovalShares
} from '../utils/blsCrypto';
import {
  BLSKeyPair,
  BLSSignatureShare,
  BLSAggregatedApprovalPayload,
  BLSThresholdVerificationResult,
  BLSKeyBackup
} from '../types/bls';

interface StoredBLSKey {
  id?: number;
  guardianAddress: string;
  privateKey: string;
  publicKey: string;
  proofOfPossession: string;
  createdAt: number;
  vaultIds: number[];
  isActive: boolean;
}

interface SpooVaultBLSDBSchema extends DBSchema {
  keys: {
    key: number;
    value: StoredBLSKey;
    indexes: {
      guardianAddress: string;
    };
  };
}

export class BLSKeyringService {
  private static instance: BLSKeyringService;
  private dbPromise: Promise<IDBPDatabase<SpooVaultBLSDBSchema> | null> | null = null;
  private activeKey: BLSKeyPair | null = null;
  private memoryFallback: Map<string, StoredBLSKey> = new Map();

  private constructor() {}

  private async getDb(): Promise<IDBPDatabase<SpooVaultBLSDBSchema> | null> {
    if (typeof globalThis.indexedDB === 'undefined') return null;
    if (!this.dbPromise) {
      this.dbPromise = openDB<SpooVaultBLSDBSchema>('SpooVaultBLSDB', 1, {
        upgrade(db) {
          const store = db.createObjectStore('keys', { keyPath: 'id', autoIncrement: true });
          store.createIndex('guardianAddress', 'guardianAddress', { unique: true });
        },
      }).catch(() => null);
    }
    return this.dbPromise;
  }

  public static getInstance(): BLSKeyringService {
    if (!BLSKeyringService.instance) {
      BLSKeyringService.instance = new BLSKeyringService();
    }
    return BLSKeyringService.instance;
  }

  /**
   * Generate and store a fresh BLS12-381 keypair for a guardian.
   */
  public async generateKeyForGuardian(guardianAddress: string): Promise<BLSKeyPair> {
    const normalizedAddress = ethers.getAddress(guardianAddress);
    const keyPair = generateBLSKeyPair();
    keyPair.guardianAddress = normalizedAddress;
    keyPair.vaultIds = [];

    await this.saveKey(normalizedAddress, keyPair);
    this.activeKey = keyPair;
    return keyPair;
  }

  /**
   * Derive and store a BLS12-381 keypair from a mnemonic seed phrase.
   */
  public async deriveFromMnemonic(guardianAddress: string, mnemonic: string, accountIndex = 0): Promise<BLSKeyPair> {
    const normalizedAddress = ethers.getAddress(guardianAddress);
    const keyPair = deriveBLSKeyFromMnemonic(mnemonic, accountIndex);
    keyPair.guardianAddress = normalizedAddress;
    keyPair.vaultIds = [];

    await this.saveKey(normalizedAddress, keyPair);
    this.activeKey = keyPair;
    return keyPair;
  }

  /**
   * Import an existing BLS12-381 private key.
   */
  public async importPrivateKey(guardianAddress: string, privateKeyHex: string): Promise<BLSKeyPair> {
    const normalizedAddress = ethers.getAddress(guardianAddress);
    const cleanPrivKey = privateKeyHex.startsWith('0x') ? privateKeyHex : `0x${privateKeyHex}`;
    const pubKeyHex = getBLSPublicKey(cleanPrivKey);
    const popHex = createProofOfPossession(cleanPrivKey, pubKeyHex);

    const keyPair: BLSKeyPair = {
      privateKey: cleanPrivKey,
      publicKey: pubKeyHex,
      proofOfPossession: popHex,
      createdAt: Date.now(),
      guardianAddress: normalizedAddress,
      vaultIds: []
    };

    await this.saveKey(normalizedAddress, keyPair);
    this.activeKey = keyPair;
    return keyPair;
  }

  /**
   * Retrieve active or stored BLS keypair for a guardian address.
   */
  public async getKeyForGuardian(guardianAddress: string): Promise<BLSKeyPair | null> {
    const normalizedAddress = ethers.getAddress(guardianAddress);

    if (this.activeKey && this.activeKey.guardianAddress === normalizedAddress) {
      return this.activeKey;
    }

    try {
      const db = await this.getDb();
      if (db) {
        const stored = await db.getFromIndex('keys', 'guardianAddress', normalizedAddress);
        if (stored) {
          const keyPair: BLSKeyPair = {
            privateKey: stored.privateKey,
            publicKey: stored.publicKey,
            proofOfPossession: stored.proofOfPossession,
            createdAt: stored.createdAt,
            guardianAddress: stored.guardianAddress,
            vaultIds: stored.vaultIds
          };
          this.activeKey = keyPair;
          return keyPair;
        }
      }
    } catch {
      const mem = this.memoryFallback.get(normalizedAddress);
      if (mem) {
        return {
          privateKey: mem.privateKey,
          publicKey: mem.publicKey,
          proofOfPossession: mem.proofOfPossession,
          createdAt: mem.createdAt,
          guardianAddress: mem.guardianAddress,
          vaultIds: mem.vaultIds
        };
      }
    }

    return null;
  }

  /**
   * Check if guardian has a registered BLS key in the keyring.
   */
  public async hasKeyForGuardian(guardianAddress: string): Promise<boolean> {
    const key = await this.getKeyForGuardian(guardianAddress);
    return key !== null;
  }

  /**
   * Associate a vault ID with a guardian's BLS key.
   */
  public async linkVaultToKey(guardianAddress: string, vaultId: number): Promise<void> {
    const normalizedAddress = ethers.getAddress(guardianAddress);
    const key = await this.getKeyForGuardian(normalizedAddress);
    if (!key) throw new Error(`No BLS key found for guardian ${guardianAddress}`);

    const vaultIds = key.vaultIds || [];
    if (!vaultIds.includes(vaultId)) {
      vaultIds.push(vaultId);
      key.vaultIds = vaultIds;
      await this.saveKey(normalizedAddress, key);
    }
  }

  /**
   * Produce a BLS signature share for a pending vault access request.
   */
  public async signAccessApproval(
    guardianAddress: string,
    requestId: number,
    vaultId: number,
    documentId: number,
    beneficiary: string,
    encryptedBeneficiaryShare?: string,
    fheBeneficiaryShare?: string,
    chainId = 31337
  ): Promise<BLSSignatureShare> {
    const normalizedAddress = ethers.getAddress(guardianAddress);
    const key = await this.getKeyForGuardian(normalizedAddress);
    if (!key) {
      throw new Error(`Cannot sign approval: No BLS key found for guardian ${guardianAddress}`);
    }

    const msgBytes = encodeApprovalMessage(requestId, vaultId, documentId, beneficiary, chainId);
    const signature = signBLS(msgBytes, key.privateKey);

    return {
      guardianAddress: normalizedAddress,
      publicKey: key.publicKey,
      signature,
      requestId,
      vaultId,
      documentId,
      beneficiary: ethers.getAddress(beneficiary),
      timestamp: Date.now(),
      encryptedBeneficiaryShare,
      fheBeneficiaryShare
    };
  }

  /**
   * Aggregate K-of-N guardian approval shares into a single on-chain submission payload.
   */
  public aggregateApprovalShares(
    shares: BLSSignatureShare[],
    requestId: number,
    vaultId: number,
    documentId: number,
    beneficiary: string,
    threshold: number,
    chainId = 31337
  ): BLSAggregatedApprovalPayload {
    return aggregateGuardianApprovalShares(
      shares,
      requestId,
      vaultId,
      documentId,
      beneficiary,
      threshold,
      chainId
    );
  }

  /**
   * Verify an aggregated BLS signature against participating guardians.
   */
  public verifyAggregatedApproval(
    payload: BLSAggregatedApprovalPayload,
    requiredThreshold: number,
    chainId = 31337
  ): BLSThresholdVerificationResult {
    const participating = payload.guardianAddresses.length;
    const thresholdReached = participating >= requiredThreshold;

    if (!thresholdReached) {
      return {
        isValid: false,
        thresholdReached: false,
        requiredThreshold,
        participatingGuardians: participating,
        aggregatedPublicKey: payload.aggregatedPublicKey,
        aggregatedSignature: payload.aggregatedSignature,
        error: `Insufficient guardians: ${participating}/${requiredThreshold}`
      };
    }

    const msgBytes = encodeApprovalMessage(
      payload.requestId,
      payload.vaultId,
      payload.documentId,
      payload.beneficiary,
      chainId
    );

    const isValid = verifyAggregatedBLSSignature(
      payload.aggregatedSignature,
      msgBytes,
      payload.aggregatedPublicKey
    );

    return {
      isValid,
      thresholdReached: true,
      requiredThreshold,
      participatingGuardians: participating,
      aggregatedPublicKey: payload.aggregatedPublicKey,
      aggregatedSignature: payload.aggregatedSignature
    };
  }

  /**
   * Export an encrypted backup of the BLS keypair.
   */
  public async exportEncryptedBackup(guardianAddress: string, password: string): Promise<BLSKeyBackup> {
    const normalizedAddress = ethers.getAddress(guardianAddress);
    const key = await this.getKeyForGuardian(normalizedAddress);
    if (!key) throw new Error('No key found to export');

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const derivedKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const encryptedContent = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      derivedKey,
      enc.encode(key.privateKey)
    );

    return {
      version: '1.0',
      guardianAddress: normalizedAddress,
      encryptedPrivateKey: ethers.hexlify(new Uint8Array(encryptedContent)),
      salt: ethers.hexlify(salt),
      iv: ethers.hexlify(iv),
      publicKey: key.publicKey,
      proofOfPossession: key.proofOfPossession,
      createdAt: key.createdAt
    };
  }

  /**
   * Import an encrypted BLS key backup.
   */
  public async importEncryptedBackup(backup: BLSKeyBackup, password: string): Promise<BLSKeyPair> {
    const salt = ethers.getBytes(backup.salt);
    const iv = ethers.getBytes(backup.iv);
    const encryptedData = ethers.getBytes(backup.encryptedPrivateKey);

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const derivedKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt as unknown as BufferSource, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      derivedKey,
      encryptedData as unknown as BufferSource
    );

    const privateKeyHex = new TextDecoder().decode(decrypted);
    return this.importPrivateKey(backup.guardianAddress, privateKeyHex);
  }

  private async saveKey(guardianAddress: string, keyPair: BLSKeyPair): Promise<void> {
    const record: StoredBLSKey = {
      guardianAddress,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      proofOfPossession: keyPair.proofOfPossession,
      createdAt: keyPair.createdAt,
      vaultIds: keyPair.vaultIds || [],
      isActive: true
    };

    try {
      const db = await this.getDb();
      if (db) {
        const existing = await db.getFromIndex('keys', 'guardianAddress', guardianAddress);
        if (existing && existing.id) {
          record.id = existing.id;
          await db.put('keys', record);
        } else {
          await db.add('keys', record);
        }
      } else {
        this.memoryFallback.set(guardianAddress, record);
      }
    } catch {
      this.memoryFallback.set(guardianAddress, record);
    }
  }
}

export const blsKeyringService = BLSKeyringService.getInstance();
