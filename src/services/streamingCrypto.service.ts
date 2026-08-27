/**
 * Web Streams AES-256-GCM chunked encryption for multi-gigabyte files.
 *
 * Wire format (version 1):
 *   Header (16 bytes):
 *     magic[4]      = "SVSC" (SpooVault Streaming Crypto)
 *     version[1]    = 0x01
 *     flags[1]      = 0x00
 *     chunkSize[4]  = uint32 BE plaintext chunk size (default 65536)
 *     reserved[6]   = zeros
 *   Frame (repeated until stream end; at least one frame, including empty files):
 *     plaintextLen[4] = uint32 BE (0..chunkSize)
 *     iv[12]          = random per-chunk AES-GCM IV
 *     ciphertext      = AES-GCM(plaintext) including 16-byte auth tag
 *                       AAD = chunkIndex as uint32 BE (prevents reorder/splice)
 *
 * Peak working memory is O(chunkSize), not O(fileSize).
 */

import { ipfsService } from "./ipfs.service";

export const STREAMING_CRYPTO_MAGIC = new Uint8Array([0x53, 0x56, 0x53, 0x43]); // "SVSC"
export const STREAMING_CRYPTO_VERSION = 1;
export const STREAMING_CHUNK_SIZE = 64 * 1024;
export const STREAMING_HEADER_SIZE = 16;
export const STREAMING_IV_LENGTH = 12;
export const STREAMING_TAG_LENGTH = 16;

const HEX_KEY_PATTERN = /^[0-9a-fA-F]{64}$/;

export type StreamingProgress = {
  phase: "encrypting" | "decrypting" | "uploading" | "downloading";
  bytesProcessed: number;
  totalBytes?: number;
};

export type StreamingProgressCallback = (progress: StreamingProgress) => void;

export type StreamingMemoryStats = {
  /** High-water mark of transform-local buffers (bytes). */
  peakBufferBytes: number;
  bytesIn: number;
  bytesOut: number;
  chunkCount: number;
};

type EncryptTransformOptions = {
  chunkSize?: number;
  onProgress?: StreamingProgressCallback;
  totalBytes?: number;
  stats?: StreamingMemoryStats;
};

type DecryptTransformOptions = {
  onProgress?: StreamingProgressCallback;
  totalBytes?: number;
  stats?: StreamingMemoryStats;
};

const getWebCrypto = (): Crypto => {
  const cryptoObj =
    (typeof globalThis !== "undefined" ? globalThis.crypto : undefined) ??
    (typeof window !== "undefined" ? window.crypto : undefined);
  if (!cryptoObj?.subtle) {
    throw new Error("Web Crypto API (crypto.subtle) is not available in this environment");
  }
  return cryptoObj;
};

/**
 * Extract the ArrayBuffer backing a Uint8Array view.
 * Returns the underlying buffer directly when the view covers it entirely
 * (zero-copy); otherwise slices just the view's portion (one copy).
 */
const toExactBuffer = (view: Uint8Array): ArrayBuffer => {
  if (view.byteOffset === 0 && view.byteLength === view.buffer.byteLength) {
    return view.buffer as ArrayBuffer;
  }
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
};

const concatBytes = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  if (a.byteLength > 0) out.set(a, 0);
  if (b.byteLength > 0) out.set(b, a.byteLength);
  return out;
};

/**
 * Efficiently drain `count` bytes from the front of a chunk list.
 * Returns a single Uint8Array; fully consumed source chunks are removed
 * so their ArrayBuffers can be garbage-collected.
 */
const drainChunks = (chunks: Uint8Array[], count: number): Uint8Array => {
  const out = new Uint8Array(count);
  let offset = 0;
  while (offset < count) {
    const head = chunks[0];
    const take = Math.min(head.byteLength, count - offset);
    out.set(head.subarray(0, take), offset);
    offset += take;
    if (take === head.byteLength) {
      chunks.shift();
    } else {
      chunks[0] = head.subarray(take);
    }
  }
  return out;
};

const writeUint32BE = (view: DataView, offset: number, value: number): void => {
  view.setUint32(offset, value, false);
};

const readUint32BE = (bytes: Uint8Array, offset: number): number => {
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false);
};

const chunkIndexAad = (chunkIndex: number): Uint8Array => {
  const aad = new Uint8Array(4);
  writeUint32BE(new DataView(aad.buffer), 0, chunkIndex >>> 0);
  return aad;
};

const touchStats = (stats: StreamingMemoryStats | undefined, bufferBytes: number): void => {
  if (!stats) return;
  if (bufferBytes > stats.peakBufferBytes) {
    stats.peakBufferBytes = bufferBytes;
  }
};

/**
 * Import a 32-byte hex key (same format as generateEncryptionKey) as AES-256-GCM.
 */
export async function importStreamingKey(keyHex: string): Promise<CryptoKey> {
  if (!HEX_KEY_PATTERN.test(keyHex)) {
    throw new Error("Streaming encryption key must be a 64-character hex string (32 bytes)");
  }
  const keyBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    keyBytes[i] = Number.parseInt(keyHex.slice(i * 2, i * 2 + 2), 16);
  }
  try {
    return await getWebCrypto().subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  } finally {
    keyBytes.fill(0);
  }
}

export function isStreamingEncryptedPrefix(bytes: Uint8Array): boolean {
  if (bytes.byteLength < STREAMING_CRYPTO_MAGIC.byteLength) return false;
  for (let i = 0; i < STREAMING_CRYPTO_MAGIC.byteLength; i++) {
    if (bytes[i] !== STREAMING_CRYPTO_MAGIC[i]) return false;
  }
  return true;
}

export function createMemoryStats(): StreamingMemoryStats {
  return { peakBufferBytes: 0, bytesIn: 0, bytesOut: 0, chunkCount: 0 };
}

function buildHeader(chunkSize: number): Uint8Array {
  const header = new Uint8Array(STREAMING_HEADER_SIZE);
  header.set(STREAMING_CRYPTO_MAGIC, 0);
  header[4] = STREAMING_CRYPTO_VERSION;
  header[5] = 0;
  writeUint32BE(new DataView(header.buffer), 6, chunkSize >>> 0);
  return header;
}

function parseHeader(header: Uint8Array): { chunkSize: number } {
  if (header.byteLength < STREAMING_HEADER_SIZE) {
    throw new Error("Truncated streaming crypto header");
  }
  if (!isStreamingEncryptedPrefix(header)) {
    throw new Error("Not a SpooVault streaming ciphertext (missing SVSC magic)");
  }
  if (header[4] !== STREAMING_CRYPTO_VERSION) {
    throw new Error(`Unsupported streaming crypto version: ${header[4]}`);
  }
  const chunkSize = readUint32BE(header, 6);
  if (chunkSize < 1 || chunkSize > 16 * 1024 * 1024) {
    throw new Error(`Invalid streaming chunk size: ${chunkSize}`);
  }
  return { chunkSize };
}

/**
 * TransformStream that frames and AES-GCM-encrypts plaintext in fixed-size chunks.
 */
export function createEncryptTransform(
  key: CryptoKey,
  options: EncryptTransformOptions = {}
): TransformStream<Uint8Array, Uint8Array> {
  const chunkSize = options.chunkSize ?? STREAMING_CHUNK_SIZE;
  const stats = options.stats;
  const pendingChunks: Uint8Array[] = [];
  let pendingLen = 0;
  let chunkIndex = 0;
  let headerSent = false;
  let bytesProcessed = 0;

  const encryptChunk = async (plaintext: Uint8Array): Promise<Uint8Array> => {
    const iv = new Uint8Array(STREAMING_IV_LENGTH);
    getWebCrypto().getRandomValues(iv);

    const ciphertext = new Uint8Array(
      await getWebCrypto().subtle.encrypt(
        {
          name: "AES-GCM",
          iv: toExactBuffer(iv),
          additionalData: toExactBuffer(chunkIndexAad(chunkIndex)),
          tagLength: STREAMING_TAG_LENGTH * 8,
        },
        key,
        toExactBuffer(plaintext)
      )
    );

    const frame = new Uint8Array(4 + STREAMING_IV_LENGTH + ciphertext.byteLength);
    writeUint32BE(new DataView(frame.buffer), 0, plaintext.byteLength);
    frame.set(iv, 4);
    frame.set(ciphertext, 4 + STREAMING_IV_LENGTH);

    chunkIndex += 1;
    if (stats) {
      stats.chunkCount += 1;
      stats.bytesOut += frame.byteLength;
    }
    return frame;
  };

  return new TransformStream<Uint8Array, Uint8Array>({
    start(controller) {
      controller.enqueue(buildHeader(chunkSize));
      headerSent = true;
      if (stats) stats.bytesOut += STREAMING_HEADER_SIZE;
    },
    async transform(chunk, controller) {
      if (!(chunk instanceof Uint8Array)) {
        throw new Error("Encrypt transform expects Uint8Array chunks");
      }
      if (stats) stats.bytesIn += chunk.byteLength;
      pendingChunks.push(chunk);
      pendingLen += chunk.byteLength;
      touchStats(stats, pendingLen + chunkSize + STREAMING_IV_LENGTH + STREAMING_TAG_LENGTH);

      while (pendingLen >= chunkSize) {
        const plain = drainChunks(pendingChunks, chunkSize);
        pendingLen -= chunkSize;
        const frame = await encryptChunk(plain);
        controller.enqueue(frame);
        bytesProcessed += chunkSize;
        options.onProgress?.({
          phase: "encrypting",
          bytesProcessed,
          totalBytes: options.totalBytes,
        });
        touchStats(stats, pendingLen + chunkSize);
      }
    },
    async flush(controller) {
      if (!headerSent) {
        controller.enqueue(buildHeader(chunkSize));
      }
      // Always emit a final frame (including empty plaintext) so decrypt can authenticate EOF.
      const remaining = pendingLen > 0
        ? drainChunks(pendingChunks, pendingLen)
        : new Uint8Array(0);
      const frame = await encryptChunk(remaining);
      controller.enqueue(frame);
      bytesProcessed += remaining.byteLength;
      pendingChunks.length = 0;
      pendingLen = 0;
      options.onProgress?.({
        phase: "encrypting",
        bytesProcessed,
        totalBytes: options.totalBytes,
      });
    },
  });
}

/**
 * TransformStream that parses SVSC frames and AES-GCM-decrypts them in order.
 */
export function createDecryptTransform(
  key: CryptoKey,
  options: DecryptTransformOptions = {}
): TransformStream<Uint8Array, Uint8Array> {
  const stats = options.stats;
  const bufferChunks: Uint8Array[] = [];
  let bufferLen = 0;
  let headerParsed = false;
  let chunkSize = STREAMING_CHUNK_SIZE;
  let chunkIndex = 0;
  let bytesProcessed = 0;
  let finalized = false;

  const take = (n: number): Uint8Array | null => {
    if (bufferLen < n) return null;
    const out = drainChunks(bufferChunks, n);
    bufferLen -= n;
    return out;
  };

  return new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      if (finalized) {
        throw new Error("Unexpected data after final streaming crypto frame");
      }
      if (!(chunk instanceof Uint8Array)) {
        throw new Error("Decrypt transform expects Uint8Array chunks");
      }
      if (stats) stats.bytesIn += chunk.byteLength;
      bufferChunks.push(chunk);
      bufferLen += chunk.byteLength;
      touchStats(stats, bufferLen);

      if (!headerParsed) {
        if (bufferLen < STREAMING_HEADER_SIZE) return;
        const header = take(STREAMING_HEADER_SIZE)!;
        ({ chunkSize } = parseHeader(header));
        headerParsed = true;
      }

      while (true) {
        if (bufferLen < 4) return;
        const plaintextLen = readUint32BE(bufferChunks[0], 0);
        if (plaintextLen > chunkSize) {
          throw new Error(
            `Invalid streaming frame length ${plaintextLen} (max ${chunkSize})`
          );
        }
        const frameBodyLen = 4 + STREAMING_IV_LENGTH + plaintextLen + STREAMING_TAG_LENGTH;
        if (bufferLen < frameBodyLen) return;

        const frame = take(frameBodyLen)!;
        const iv = frame.subarray(4, 4 + STREAMING_IV_LENGTH);
        const ciphertext = frame.subarray(4 + STREAMING_IV_LENGTH);

        let plaintext: ArrayBuffer;
        try {
          plaintext = await getWebCrypto().subtle.decrypt(
            {
              name: "AES-GCM",
              iv: toExactBuffer(iv),
              additionalData: toExactBuffer(chunkIndexAad(chunkIndex)),
              tagLength: STREAMING_TAG_LENGTH * 8,
            },
            key,
            toExactBuffer(ciphertext)
          );
        } catch {
          throw new Error(
            `Streaming decryption failed at chunk ${chunkIndex} (wrong key or corrupted ciphertext)`
          );
        }

        chunkIndex += 1;
        if (stats) {
          stats.chunkCount += 1;
          stats.bytesOut += plaintext.byteLength;
        }

        const plainBytes = new Uint8Array(plaintext);
        if (plainBytes.byteLength > 0) {
          controller.enqueue(plainBytes);
        }
        bytesProcessed += plainBytes.byteLength;
        options.onProgress?.({
          phase: "decrypting",
          bytesProcessed,
          totalBytes: options.totalBytes,
        });

        // A short (or empty) frame marks the end of the stream.
        if (plaintextLen < chunkSize) {
          finalized = true;
          if (bufferLen > 0) {
            throw new Error("Trailing bytes after final streaming crypto frame");
          }
          return;
        }
      }
    },
    flush() {
      if (!headerParsed) {
        throw new Error("Truncated streaming ciphertext (missing header)");
      }
      if (!finalized) {
        throw new Error("Truncated streaming ciphertext (missing final frame)");
      }
      if (bufferLen > 0) {
        throw new Error("Trailing bytes after streaming ciphertext");
      }
    },
  });
}

/**
 * Encrypt a ReadableStream of Uint8Array chunks, returning the ciphertext stream.
 */
export function encryptStream(
  plaintext: ReadableStream<Uint8Array>,
  key: CryptoKey,
  options: EncryptTransformOptions = {}
): ReadableStream<Uint8Array> {
  return plaintext.pipeThrough(createEncryptTransform(key, options));
}

/**
 * Decrypt a ReadableStream of SVSC ciphertext frames.
 */
export function decryptStream(
  ciphertext: ReadableStream<Uint8Array>,
  key: CryptoKey,
  options: DecryptTransformOptions = {}
): ReadableStream<Uint8Array> {
  return ciphertext.pipeThrough(createDecryptTransform(key, options));
}

/**
 * Encrypt a File/Blob via File.stream() without buffering the whole file.
 */
export async function encryptFileStream(
  file: Blob,
  keyHex: string,
  options: Omit<EncryptTransformOptions, "totalBytes"> & { totalBytes?: number } = {}
): Promise<ReadableStream<Uint8Array>> {
  const key = await importStreamingKey(keyHex);
  const totalBytes = options.totalBytes ?? file.size;
  return encryptStream(file.stream() as ReadableStream<Uint8Array>, key, {
    ...options,
    totalBytes,
  });
}

/**
 * Pipe an encrypted ReadableStream to Pinata / IPFS as a multipart HTTP body
 * without materializing the full ciphertext in memory.
 */
export async function uploadEncryptedStreamToIpfs(
  encryptedStream: ReadableStream<Uint8Array>,
  options: {
    filename?: string;
    metadata?: Record<string, unknown>;
    signal?: AbortSignal;
    onProgress?: StreamingProgressCallback;
    /** Approximate ciphertext length for progress (plaintextSize * overhead). */
    totalBytes?: number;
  } = {}
): Promise<{ hash: string; size: number }> {
  options.onProgress?.({
    phase: "uploading",
    bytesProcessed: 0,
    totalBytes: options.totalBytes,
  });

  const result = await ipfsService.uploadStream(encryptedStream, {
    filename: options.filename ?? "document.svsc",
    metadata: options.metadata,
    signal: options.signal,
    contentType: "application/octet-stream",
  });

  options.onProgress?.({
    phase: "uploading",
    bytesProcessed: result.size,
    totalBytes: options.totalBytes ?? result.size,
  });

  return result;
}

/**
 * Encrypt a file and upload the ciphertext stream directly to IPFS.
 */
export async function encryptAndUploadFile(
  file: Blob,
  keyHex: string,
  options: {
    filename?: string;
    metadata?: Record<string, unknown>;
    signal?: AbortSignal;
    onProgress?: StreamingProgressCallback;
    chunkSize?: number;
    stats?: StreamingMemoryStats;
  } = {}
): Promise<{ hash: string; size: number }> {
  const encrypted = await encryptFileStream(file, keyHex, {
    chunkSize: options.chunkSize,
    onProgress: options.onProgress,
    stats: options.stats,
    totalBytes: file.size,
  });

  return uploadEncryptedStreamToIpfs(encrypted, {
    filename: options.filename,
    metadata: options.metadata,
    signal: options.signal,
    onProgress: options.onProgress,
  });
}

/**
 * Download an encrypted IPFS object and decrypt into a writable sink
 * (FileSystemWritableFileStream or any WritableStream<Uint8Array>).
 */
export async function decryptIpfsDownloadToWritable(
  ipfsUrl: string,
  keyHex: string,
  writable: WritableStream<Uint8Array>,
  options: {
    signal?: AbortSignal;
    onProgress?: StreamingProgressCallback;
    stats?: StreamingMemoryStats;
  } = {}
): Promise<void> {
  options.onProgress?.({ phase: "downloading", bytesProcessed: 0 });

  const response = await fetch(ipfsUrl, { signal: options.signal });
  if (!response.ok) {
    throw new Error(`Failed to download encrypted file (${response.status})`);
  }
  if (!response.body) {
    throw new Error("IPFS response body is not readable as a stream");
  }

  await decryptResponseToWritable(response, keyHex, writable, options);
}

/**
 * Decrypt an already-fetched IPFS Response body into a writable sink.
 */
export async function decryptResponseToWritable(
  response: Response,
  keyHex: string,
  writable: WritableStream<Uint8Array>,
  options: {
    signal?: AbortSignal;
    onProgress?: StreamingProgressCallback;
    stats?: StreamingMemoryStats;
  } = {}
): Promise<void> {
  if (!response.body) {
    throw new Error("IPFS response body is not readable as a stream");
  }

  const key = await importStreamingKey(keyHex);
  const contentLengthHeader = response.headers.get("content-length");
  const totalBytes = contentLengthHeader ? Number(contentLengthHeader) : undefined;

  const decrypted = decryptStream(response.body as ReadableStream<Uint8Array>, key, {
    onProgress: options.onProgress,
    totalBytes,
    stats: options.stats,
  });

  await decrypted.pipeTo(writable, { signal: options.signal });
}

/**
 * Peek the first bytes of a response body to detect SVSC streaming ciphertext.
 * Returns a replacement body stream that still includes the peeked prefix.
 */
export async function detectStreamingCiphertext(
  body: ReadableStream<Uint8Array>
): Promise<{ isStreaming: boolean; stream: ReadableStream<Uint8Array> }> {
  const reader = body.getReader();
  const prefixChunks: Uint8Array[] = [];
  let prefix: Uint8Array = new Uint8Array(0);

  while (prefix.byteLength < STREAMING_CRYPTO_MAGIC.byteLength) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value && value.byteLength > 0) {
      prefixChunks.push(value);
      prefix = concatBytes(prefix, value);
    }
  }

  const isStreaming = isStreamingEncryptedPrefix(prefix);
  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        for (const chunk of prefixChunks) {
          controller.enqueue(chunk);
        }
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value && value.byteLength > 0) {
            controller.enqueue(value);
          }
        }
        controller.close();
      } catch (error) {
        controller.error(error);
      }
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });

  return { isStreaming, stream };
}

/**
 * SHA-256 hash of a Uint8Array stream without buffering the full payload.
 * Uses an incremental SHA-256 implementation (SubtleCrypto.digest requires the
 * whole input at once, which defeats multi-GB streaming).
 */
export async function hashStreamSha256(
  stream: ReadableStream<Uint8Array>
): Promise<string> {
  const hasher = createSha256();
  const reader = stream.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) hasher.update(value);
  }
  return hasher.digestHex();
}

/** Collect a stream into one Uint8Array (tests / small payloads only). */
export async function collectStream(
  stream: ReadableStream<Uint8Array>
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      total += value.byteLength;
    }
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/**
 * Round-trip encrypt → decrypt for a synthetic payload of `sizeBytes`,
 * verifying SHA-256 equality and reporting peak transform buffer usage.
 */
export async function benchmarkStreamingRoundTrip(
  sizeBytes: number,
  options: { chunkSize?: number; patternSeed?: number } = {}
): Promise<{
  sizeBytes: number;
  elapsedMs: number;
  peakBufferBytes: number;
  inputHash: string;
  outputHash: string;
  match: boolean;
}> {
  const chunkSize = options.chunkSize ?? STREAMING_CHUNK_SIZE;
  const seed = options.patternSeed ?? 0x5eed;
  const keyHex = "a".repeat(64);

  const plaintextStream = createPatternReadableStream(sizeBytes, seed);
  const inputHashStream = createPatternReadableStream(sizeBytes, seed);
  const inputHash = await hashStreamSha256(inputHashStream);

  const encStats = createMemoryStats();
  const decStats = createMemoryStats();
  const key = await importStreamingKey(keyHex);

  const started = Date.now();
  const encrypted = encryptStream(plaintextStream, key, { chunkSize, stats: encStats });
  const decrypted = decryptStream(encrypted, key, { stats: decStats });
  const outputHash = await hashStreamSha256(decrypted);
  const elapsedMs = Date.now() - started;

  return {
    sizeBytes,
    elapsedMs,
    peakBufferBytes: Math.max(encStats.peakBufferBytes, decStats.peakBufferBytes),
    inputHash,
    outputHash,
    match: inputHash === outputHash,
  };
}

function createPatternReadableStream(
  sizeBytes: number,
  seed: number
): ReadableStream<Uint8Array> {
  let remaining = sizeBytes;
  let offset = 0;
  const slice = STREAMING_CHUNK_SIZE;

  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (remaining <= 0) {
        controller.close();
        return;
      }
      const n = Math.min(slice, remaining);
      const chunk = new Uint8Array(n);
      for (let i = 0; i < n; i++) {
        // Cheap deterministic pattern (not a CSPRNG) for integrity benchmarks.
        chunk[i] = (seed + offset + i * 17) & 0xff;
      }
      offset += n;
      remaining -= n;
      controller.enqueue(chunk);
    },
  });
}

/**
 * Minimal incremental SHA-256 (FIPS 180-4) for stream hashing in tests/benchmarks.
 * Avoids buffering multi-GB payloads that SubtleCrypto.digest would require.
 */
function createSha256() {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
  ]);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const block = new Uint8Array(64);
  let blockOffset = 0;
  let bytesHashed = 0;

  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

  const processBlock = () => {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      const j = i * 4;
      w[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  };

  return {
    update(data: Uint8Array) {
      bytesHashed += data.byteLength;
      let offset = 0;
      while (offset < data.byteLength) {
        const n = Math.min(64 - blockOffset, data.byteLength - offset);
        block.set(data.subarray(offset, offset + n), blockOffset);
        blockOffset += n;
        offset += n;
        if (blockOffset === 64) {
          processBlock();
          blockOffset = 0;
        }
      }
    },
    digestHex(): string {
      // Capture message length before padding (FIPS 180-4).
      const savedLen = bytesHashed;
      const pushPad = (data: Uint8Array) => {
        let offset = 0;
        while (offset < data.byteLength) {
          const n = Math.min(64 - blockOffset, data.byteLength - offset);
          block.set(data.subarray(offset, offset + n), blockOffset);
          blockOffset += n;
          offset += n;
          if (blockOffset === 64) {
            processBlock();
            blockOffset = 0;
          }
        }
      };

      pushPad(new Uint8Array([0x80]));
      while (blockOffset !== 56) {
        pushPad(new Uint8Array([0x00]));
      }

      const bitLenHi = Math.floor(savedLen / 0x20000000);
      const bitLenLo = (savedLen << 3) >>> 0;
      const lenBlock = new Uint8Array(8);
      lenBlock[0] = (bitLenHi >>> 24) & 0xff;
      lenBlock[1] = (bitLenHi >>> 16) & 0xff;
      lenBlock[2] = (bitLenHi >>> 8) & 0xff;
      lenBlock[3] = bitLenHi & 0xff;
      lenBlock[4] = (bitLenLo >>> 24) & 0xff;
      lenBlock[5] = (bitLenLo >>> 16) & 0xff;
      lenBlock[6] = (bitLenLo >>> 8) & 0xff;
      lenBlock[7] = bitLenLo & 0xff;
      pushPad(lenBlock);

      const digest = new Uint8Array(32);
      const words = [h0, h1, h2, h3, h4, h5, h6, h7];
      for (let i = 0; i < 8; i++) {
        digest[i * 4] = (words[i] >>> 24) & 0xff;
        digest[i * 4 + 1] = (words[i] >>> 16) & 0xff;
        digest[i * 4 + 2] = (words[i] >>> 8) & 0xff;
        digest[i * 4 + 3] = words[i] & 0xff;
      }
      return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
    },
  };
}

export const streamingCryptoService = {
  STREAMING_CHUNK_SIZE,
  STREAMING_CRYPTO_MAGIC,
  importStreamingKey,
  isStreamingEncryptedPrefix,
  createMemoryStats,
  createEncryptTransform,
  createDecryptTransform,
  encryptStream,
  decryptStream,
  encryptFileStream,
  uploadEncryptedStreamToIpfs,
  encryptAndUploadFile,
  decryptIpfsDownloadToWritable,
  decryptResponseToWritable,
  detectStreamingCiphertext,
  hashStreamSha256,
  collectStream,
  benchmarkStreamingRoundTrip,
};
