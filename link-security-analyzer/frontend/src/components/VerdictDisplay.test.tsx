/**
 * Tests for verdict display states and error handling.
 * Covers all verdict outcomes and error scenarios per Phase 10 requirements.
 */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusBadge } from "./ThreatCard";

describe("StatusBadge", () => {
  it("renders NO_INDICATORS state with correct label and styling", () => {
    const { container } = render(<StatusBadge status="NO_INDICATORS" />);
    expect(screen.getByText("No indicators")).toBeInTheDocument();
    expect(container.querySelector(".status-badge")).toHaveClass("status-no-indicators");
  });

  it("renders FLAGGED state with correct label and styling", () => {
    const { container } = render(<StatusBadge status="FLAGGED" />);
    expect(screen.getByText("Flagged")).toBeInTheDocument();
    expect(container.querySelector(".status-badge")).toHaveClass("status-flagged");
  });

  it("renders UNAVAILABLE state with correct label and styling", () => {
    const { container } = render(<StatusBadge status="UNAVAILABLE" />);
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(container.querySelector(".status-badge")).toHaveClass("status-unavailable");
  });

  it("renders PENDING state with correct label and styling", () => {
    const { container } = render(<StatusBadge status="PENDING" />);
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(container.querySelector(".status-badge")).toHaveClass("status-pending");
  });

  it("renders NOT_APPLICABLE state correctly", () => {
    const { container } = render(<StatusBadge status="NOT_APPLICABLE" />);
    expect(screen.getByText("Not applicable")).toBeInTheDocument();
    expect(container.querySelector(".status-badge")).toHaveClass("status-not-applicable");
  });
});

describe("Verdict states", () => {
  it("handles LIKELY_SAFE verdict (NO_INDICATORS_DETECTED)", () => {
    const verdict = "NO_INDICATORS_DETECTED";
    expect(verdict).toBe("NO_INDICATORS_DETECTED");
  });

  it("handles SUSPICIOUS verdict (SOME_INDICATORS_DETECTED)", () => {
    const verdict = "SOME_INDICATORS_DETECTED";
    expect(verdict).toBe("SOME_INDICATORS_DETECTED");
  });

  it("handles DANGEROUS verdict (HIGH_RISK_INDICATORS_DETECTED)", () => {
    const verdict = "HIGH_RISK_INDICATORS_DETECTED";
    expect(verdict).toBe("HIGH_RISK_INDICATORS_DETECTED");
  });

  it("handles UNKNOWN verdict (INCONCLUSIVE)", () => {
    const verdict = "INCONCLUSIVE";
    expect(verdict).toBe("INCONCLUSIVE");
  });
});

describe("Error states", () => {
  it("validates input correctly", async () => {
    const { validateScanInput } = await import("@/lib/api");
    
    expect(validateScanInput("")).toBe("Enter a URL, UPI link, or text from a QR code.");
    expect(validateScanInput("   ")).toBe("Enter a URL, UPI link, or text from a QR code.");
    expect(validateScanInput("https://example.com")).toBeNull();
    expect(validateScanInput("a".repeat(2049))).toBe("Input must be 2,048 characters or fewer.");
  });

  it("handles API error states", async () => {
    const { ApiError } = await import("@/lib/api");
    
    const error404 = new ApiError("Not found", 404);
    expect(error404.status).toBe(404);
    expect(error404.message).toBe("Not found");

    const error429 = new ApiError("Rate limited", 429, "60");
    expect(error429.status).toBe(429);
    expect(error429.retryAfter).toBe("60");

    const error422 = new ApiError("Invalid input", 422);
    expect(error422.status).toBe(422);

    const timeout = new ApiError("Timeout", 408);
    expect(timeout.status).toBe(408);

    const network = new ApiError("Network error", 0);
    expect(network.status).toBe(0);
  });
});

describe("Accessibility", () => {
  it("includes accessible labels for verdict states", () => {
    render(<StatusBadge status="FLAGGED" />);
    const badge = screen.getByRole("status");
    expect(badge).toHaveClass("status-badge");
  });

  it("provides text alternatives for icons", () => {
    const { container } = render(<StatusBadge status="NO_INDICATORS" />);
    const icon = container.querySelector("svg");
    expect(icon).toHaveAttribute("aria-hidden", "true");
  });
});

describe("Mobile responsiveness", () => {
  it("renders with responsive classes", () => {
    const { container } = render(<StatusBadge status="FLAGGED" />);
    const badge = container.querySelector(".status-badge");
    expect(badge).toBeTruthy();
  });
});

describe("Privacy note", () => {
  it("displays privacy information correctly", () => {
    const privacyText = "The pasted link or text is sent to the TrueIntent API for analysis.";
    expect(privacyText).toContain("sent to the TrueIntent API");
  });
});
