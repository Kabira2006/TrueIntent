import React from "react";
import {
  AlertCircle,
  CheckCircle2,
  CircleDot,
  CircleDashed,
  Clock3,
  FileQuestion,
  ShieldAlert,
} from "lucide-react";

import type { AdvisoryPillar, PillarStatus } from "@/lib/api";

const STATUS_COPY: Record<
  PillarStatus,
  { label: string; explanation: string; icon: typeof CheckCircle2 }
> = {
  NOT_APPLICABLE: {
    label: "Not applicable",
    explanation: "This check does not apply to the submitted input type.",
    icon: FileQuestion,
  },
  NO_INDICATORS: {
    label: "No indicators detected",
    explanation: "This check completed without reporting indicators.",
    icon: CheckCircle2,
  },
  FLAGGED: {
    label: "Indicators detected",
    explanation: "One or more indicators were reported by this check.",
    icon: ShieldAlert,
  },
  UNAVAILABLE: {
    label: "Unavailable",
    explanation: "This check did not complete; its result is not a clean result.",
    icon: AlertCircle,
  },
  PENDING: {
    label: "Pending",
    explanation: "This check has not finished yet.",
    icon: Clock3,
  },
};

const SEVERITY_ORDER = ["info", "low", "medium", "high"] as const;

export function StatusBadge({ status }: { status: PillarStatus }) {
  const config = STATUS_COPY[status];
  const Icon = config.icon;
  return (
    <span className={`status-badge status-${status.toLowerCase()}`}>
      {status === "PENDING" ? (
        <CircleDashed aria-hidden="true" size={15} className="spin" />
      ) : (
        <Icon aria-hidden="true" size={15} />
      )}
      <span>{config.label}</span>
    </span>
  );
}

export function ThreatCard({
  title,
  description,
  pillar,
}: {
  title: string;
  description: string;
  pillar: AdvisoryPillar;
}) {
  const config = STATUS_COPY[pillar.status];
  const highestSeverity =
    [...pillar.indicators].sort(
      (left, right) =>
        SEVERITY_ORDER.indexOf(right.severity) -
        SEVERITY_ORDER.indexOf(left.severity),
    )[0]?.severity ?? "info";

  return (
    <section
      className={`pillar-card pillar-${pillar.status.toLowerCase()} severity-${highestSeverity}`}
      aria-label={title}
    >
      <div className="pillar-heading">
        <div>
          <p className="eyebrow">ANALYSIS PILLAR</p>
          <h3>{title}</h3>
        </div>
        <StatusBadge status={pillar.status} />
      </div>
      <p className="pillar-description">{description}</p>
      <p className="status-explanation">{config.explanation}</p>
      {pillar.indicators.length > 0 ? (
        <ul className="indicator-list">
          {pillar.indicators.map((indicator, index) => (
            <li className="indicator-item" key={`${indicator.code}-${index}`}>
              <div className="indicator-topline">
                <span className={`severity-label severity-${indicator.severity}`}>
                  <span className="severity-dot" aria-hidden="true" />
                  {indicator.severity}
                </span>
                <code>{indicator.code}</code>
              </div>
              <p>{indicator.message}</p>
              {Object.keys(indicator.evidence).length > 0 && (
                <details className="evidence-details">
                  <summary>View supporting details</summary>
                  <dl>
                    {Object.entries(indicator.evidence).map(([key, value]) => (
                      <div className="evidence-row" key={key}>
                        <dt>{key.replaceAll("_", " ")}</dt>
                        <dd>{value === null ? "Not provided" : String(value)}</dd>
                      </div>
                    ))}
                  </dl>
                </details>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <div className="empty-pillar">
          <CircleDot aria-hidden="true" size={17} />
          <span>
            {pillar.status === "NO_INDICATORS"
              ? "No indicators were reported by this check."
              : pillar.status === "NOT_APPLICABLE"
                ? "No analysis was attempted for this pillar."
                : pillar.status === "PENDING"
                  ? "Waiting for this analysis to finish."
                  : "No indicator details are available."}
          </span>
        </div>
      )}
    </section>
  );
}
