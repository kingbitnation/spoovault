import { describe, it, expect, beforeEach } from "vitest";
import { CrossChainRelayerService, CrossChainPayload } from "../services/crossChainRelayer.service";

describe("Axelar Cross-Chain Message Relayer", () => {
  const secretKey = "relayer-secret-key-12345";
  let relayer: CrossChainRelayerService;

  beforeEach(() => {
    relayer = new CrossChainRelayerService();
  });

  const mockPayload: CrossChainPayload = {
    vaultGID: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    guardian: "0x1111111111111111111111111111111111111111",
    approvalType: 1,
    timestamp: Date.now(),
  };

  it("signs and verifies cross-chain approval payload", () => {
    const signedPayload = CrossChainRelayerService.signPayload(mockPayload, secretKey);
    expect(signedPayload.signature).toBeDefined();

    const result = relayer.processMessage(signedPayload, secretKey);
    expect(result.success).toBe(true);
    expect(result.messageHash).toBeDefined();
  });

  it("prevents replay attacks on duplicate execution", () => {
    const signedPayload = CrossChainRelayerService.signPayload(mockPayload, secretKey);
    
    relayer.processMessage(signedPayload, secretKey);

    expect(() => relayer.processMessage(signedPayload, secretKey)).toThrow(
      "Replay attack detected: Message already processed"
    );
  });
});
