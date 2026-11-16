import React from "react";
import { Check, CircleDashed, Clock3, FileQuestion } from "lucide-react";

import type { PayloadType, ScanStatus } from "@/lib/api";

const STEPS = ["Fast checks", "Sandbox analysis", "Report"];

export function AnalysisProgress({
  status,
  payloadType,
}: {
  status: ScanStatus;
  payloadType: PayloadType;
}) {
  const activeIndex = status === "FAST_PATH_DONE" ? 1 : 2;
  const failed = status === "FAILED";
  return (
    <ol className="progress-list" aria-label="Analysis progress">
      {STEPS.map((step, index) => {
        const notApplicable = index === 1 && payloadType !== "URL";
        const complete = index < activeIndex && !failed && !notApplicable;
        const active =
          (index === activeIndex || (failed && index === 2)) && !notApplicable;
        return (
          <li
            className={`progress-step ${complete ? "is-complete" : ""} ${active ? "is-active" : ""} ${notApplicable ? "is-not-applicable" : ""} ${failed && active ? "is-failed" : ""}`}
            key={step}
            aria-current={active ? "step" : undefined}
          >
            <span className="progress-icon">
              {notApplicable ? (
                <FileQuestion aria-hidden="true" size={15} />
              ) : complete ? (
                <Check aria-hidden="true" size={15} />
              ) : failed && active ? (
                <Clock3 aria-hidden="true" size={15} />
              ) : active ? (
                <CircleDashed aria-hidden="true" size={15} className="spin" />
              ) : (
                <span>{index + 1}</span>
              )}
            </span>
            <span>{notApplicable ? "Sandbox (not applicable)" : step}</span>
          </li>
        );
      })}
    </ol>
  );
}
