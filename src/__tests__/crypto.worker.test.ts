import { afterEach, describe, expect, it, vi } from "vitest";
import { CryptoClientService } from "../services/crypto-client";

/**
 * CryptoClientService constructs a module Worker. Node Vitest has no Worker
 * global, so stub one that detaches transferred ArrayBuffers like a real Worker.
 */
class MockWorker {
  onmessage: ((event: MessageEvent<{ status: string; hash: ArrayBuffer }>) => void) | null =
    null;
  onerror: ((event: unknown) => void) | null = null;

  constructor(_url?: unknown, _opts?: unknown) {}

  postMessage(
    message: { type: string; buffer: ArrayBuffer },
    transfer?: Transferable[]
  ) {
    if (transfer?.length) {
      structuredClone(message, { transfer });
    }
    // Resolve synchronously so detachment can be asserted and await does not hang
    // after the test terminates the worker.
    this.onmessage?.({
      data: { status: "ok", hash: new ArrayBuffer(32) },
    } as MessageEvent<{ status: string; hash: ArrayBuffer }>);
  }

  terminate() {}
}

describe("CryptoWorker Zero-Copy Transfer (#42)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("detaches ArrayBuffer ownership upon postMessage invocation", async () => {
    vi.stubGlobal("Worker", MockWorker);

    const client = new CryptoClientService();
    const buffer = new ArrayBuffer(1024 * 1024); // 1 MB payload

    expect(buffer.byteLength).toBe(1024 * 1024);

    const promise = client.computeHash(buffer);

    // Verify zero-copy detachment: sender side buffer byteLength becomes 0 after transfer
    expect(buffer.byteLength).toBe(0);

    client.terminate();
    await expect(promise).resolves.toMatchObject({ status: "ok" });
  });
});
