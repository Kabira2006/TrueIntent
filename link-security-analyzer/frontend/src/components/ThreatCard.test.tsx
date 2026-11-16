import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ThreatCard } from "./ThreatCard";

describe("ThreatCard", () => {
  it.each([
    ["NOT_APPLICABLE", "Not applicable"],
    ["NO_INDICATORS", "No indicators detected"],
    ["FLAGGED", "Indicators detected"],
    ["UNAVAILABLE", "Unavailable"],
    ["PENDING", "Pending"],
  ] as const)("renders %s distinctly", (status, label) => {
    render(
      <ThreatCard
        title="Transaction context"
        description="Payment-link facts"
        pillar={{ status, indicators: [] }}
      />,
    );

    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it("renders indicator severity, code, message, and expandable evidence", () => {
    render(
      <ThreatCard
        title="Transaction context"
        description="Payment-link facts"
        pillar={{
          status: "FLAGGED",
          indicators: [
            {
              code: "PREFILLED_AMOUNT",
              severity: "low",
              message: "The link contains a prefilled amount.",
              evidence: { amount: "12.00" },
            },
          ],
        }}
      />,
    );

    expect(screen.getByText("PREFILLED_AMOUNT")).toBeInTheDocument();
    expect(screen.getByText("low")).toBeInTheDocument();
    expect(screen.getByText("The link contains a prefilled amount.")).toBeInTheDocument();
    expect(screen.getByText("12.00")).toBeInTheDocument();
  });

  it("does not describe unavailable results as clean", () => {
    render(
      <ThreatCard
        title="Technical URL analysis"
        description="Technical checks"
        pillar={{ status: "UNAVAILABLE", indicators: [] }}
      />,
    );

    expect(screen.getByText(/not a clean result/i)).toBeInTheDocument();
    expect(screen.queryByText(/safe/i)).not.toBeInTheDocument();
  });
});
