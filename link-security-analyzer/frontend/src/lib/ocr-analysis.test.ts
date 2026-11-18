import { describe, expect, it } from "vitest";
import { analyzeOcrText } from "./ocr-analysis";

describe("analyzeOcrText", () => {
  it("detects the reference repository's fear and authority example", () => {
    const result = analyzeOcrText(
      "You are under investigation for money laundering. Stay on the line and do not disconnect.",
    );
    expect(result.signature).toBe("fear_authority");
    expect(result.score).toBe(0.9);
    expect(result.reasons).toHaveLength(5);
  });

  it("detects greed and opportunity phrases", () => {
    const result = analyzeOcrText(
      "Limited time offer! Guaranteed returns and double your money.",
    );
    expect(result.signature).toBe("greed_opportunity");
    expect(result.score).toBe(0.9);
  });

  it("extracts links for the existing URL analyzer", () => {
    expect(analyzeOcrText("Please visit https://example.com/login.").urls).toEqual([
      "https://example.com/login",
    ]);
  });

  it("flags the supplied SBI account-block message and lookalike domain", () => {
    const result = analyzeOcrText(`
      Dear Customer,
      Your SBI account will be blocked within 24 hours due to unusual activity.
      To avoid permanent suspension, verify your account now: https://sbi-verify.in
      Failure to verify will result in account closure. State Bank of India
    `);
    expect(result.signature).toBe("fear_authority");
    expect(result.score).toBe(0.9);
    expect(result.reasons).toContain(
      "SBI is named in the message, but its link uses a non-official, credential-themed lookalike domain.",
    );
    expect(result.urls).toEqual(["https://sbi-verify.in"]);
  });

  it("flags the Zenith KYC suspension message but ignores its OTP safety warning", () => {
    const result = analyzeOcrText(`
      Dear customer, your Zenith Bank account will be suspended today due to incomplete KYC verification.
      Update immediately at znb-secure-verify.com/login to avoid blockage.
      Do not share this link. For assistance call 98765 43210.
      Do not share OTP or debit card details with anyone. This is an automated alert.
    `);
    expect(result.signature).toBe("fear_authority");
    expect(result.score).toBe(0.9);
    expect(result.reasons).toContain(
      "Zenith Bank is named in the message, but its link uses a non-official, credential-themed lookalike domain.",
    );
    expect(result.reasons).not.toContain("Matched fear/authority pattern: 'share your otp to verify'");
  });

  it("leaves ordinary text unflagged", () => {
    expect(analyzeOcrText("Your parcel arrives tomorrow.")).toMatchObject({
      signature: "none",
      score: 0,
      reasons: [],
      urls: [],
    });
  });
});
