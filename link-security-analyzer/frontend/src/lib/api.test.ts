import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  fetchScanReport,
  submitScan,
  validateScanInput,
} from "./api";

const accepted = {
  scan_id: "scan-id",
  status: "COMPLETED",
  fast_path_summary: {
    payload_type: "UPI_DEEP_LINK",
    domain: null,
    is_punycode: false,
    shannon_entropy: 0,
    domain_age_days: null,
    threat_feed_matches: 0,
  },
  poll_url: "http://localhost:8000/api/v1/scan/scan-id",
};

afterEach(() => vi.unstubAllGlobals());

describe("API client", () => {
  it("validates empty and overlong input on the client", () => {
    expect(validateScanInput(" \n")).toContain("Enter a URL");
    expect(validateScanInput("x".repeat(2049))).toContain("2,048");
    expect(validateScanInput("upi://pay?pa=demo%40okaxis")).toBeNull();
  });

  it("submits input and validates the API contract", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(accepted), { status: 202 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(submitScan("upi://pay?pa=demo%40okaxis")).resolves.toEqual(accepted);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/v1/scan",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("shows validation details for HTTP 422", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "input is too long" }), { status: 422 }),
      ),
    );
    await expect(submitScan("x")).rejects.toMatchObject({
      status: 422,
      message: "Please check the input: input is too long",
    });
  });

  it("includes Retry-After in rate-limit errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "rate limited" }), {
          status: 429,
          headers: { "Retry-After": "23" },
        }),
      ),
    );
    await expect(submitScan("x")).rejects.toMatchObject({
      status: 429,
      retryAfter: "23",
      message: expect.stringContaining("23 seconds"),
    });
  });

  it("rejects a poll URL on an unexpected origin", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(fetchScanReport("https://other.example/scan/id")).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports a network failure as a recoverable API error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("network down")));
    await expect(submitScan("https://example.com")).rejects.toMatchObject({
      status: 0,
      message: expect.stringContaining("Could not reach the TrueIntent API"),
    });
  });
});
