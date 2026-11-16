"use client";

import {
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  Clock3,
  Fingerprint,
  Link2,
  LoaderCircle,
  QrCode,
  ShieldCheck,
  WalletCards,
  X,
} from "lucide-react";
import useSWR from "swr";
import { useCallback, useEffect, useState } from "react";

import { AnalysisProgress } from "@/components/AnalysisProgress";
import { StatusBadge, ThreatCard } from "@/components/ThreatCard";
import {
  ApiError,
  fetchScanReport,
  type ScanAccepted,
  type ScanReport,
  submitScan,
  validateScanInput,
} from "@/lib/api";

const MAX_INPUT_LENGTH = 2048;
const MAX_POLL_DURATION_MS = 60_000;
const API_DOCS_URL = `${process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/+$/, "") ?? "http://localhost:8000"}/docs`;
const EXAMPLES = [
  {
    label: "Web address",
    icon: Link2,
    value: "https://example.com",
  },
  {
    label: "UPI payment",
    icon: WalletCards,
    value:
      "upi://pay?pa=demo%40okaxis&pn=Demo%20Merchant&am=12.00&cu=INR&tr=order-123",
  },
  {
    label: "UPI collect",
    icon: ShieldCheck,
    value: "upi://collect?pa=demo%40okaxis&pn=Demo%20Merchant&tr=sample-456",
  },
  {
    label: "Pasted QR text",
    icon: QrCode,
    value: "Payment details: https://example.com/pay",
  },
];

interface ActiveScan {
  accepted: ScanAccepted;
  startedAt: number;
}

export default function DashboardPage() {
  const [input, setInput] = useState("");
  const [activeScan, setActiveScan] = useState<ActiveScan | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);
  const [timedOut, setTimedOut] = useState(false);
  const [elapsed, setElapsed] = useState(0);

  const pollKey = activeScan ? [activeScan.accepted.poll_url, retryKey] : null;
  const terminal = (data?: ScanReport) =>
    data?.status === "COMPLETED" || data?.status === "FAILED";
  const poller = useSWR<ScanReport>(
    pollKey,
    ([url]) => fetchScanReport(url),
    {
      refreshInterval: (latest) =>
        terminal(latest) || timedOut ? 0 : 1500,
      revalidateOnFocus: false,
      shouldRetryOnError: !timedOut,
      errorRetryCount: 3,
      errorRetryInterval: 2000,
      onErrorRetry: (error, _key, _config, revalidate, { retryCount }) => {
        if (retryCount >= 3 || error instanceof ApiError && error.status === 404) {
          return;
        }
        window.setTimeout(() => revalidate({ retryCount }), 2000);
      },
    },
  );
  const report = poller.data;
  const fastSummary = activeScan?.accepted.fast_path_summary;
  const remainingChars = MAX_INPUT_LENGTH - input.length;
  const isWorking = submitting || (activeScan !== null && !terminal(report) && !timedOut);
  const overall = report?.overall_indicator ?? "INCONCLUSIVE";

  useEffect(() => {
    if (!activeScan || terminal(report) || timedOut) return;
    const timer = window.setInterval(() => {
      const seconds = Math.floor((Date.now() - activeScan.startedAt) / 1000);
      setElapsed(seconds);
      if (Date.now() - activeScan.startedAt >= MAX_POLL_DURATION_MS) {
        setTimedOut(true);
      }
    }, 500);
    return () => window.clearInterval(timer);
  }, [activeScan, report, timedOut]);

  const startScan = useCallback(async () => {
    const error = validateScanInput(input);
    if (error) {
      setFormError(error);
      return;
    }
    const trimmed = input.trim();
    setSubmitting(true);
    setFormError(null);
    setActiveScan(null);
    setTimedOut(false);
    setElapsed(0);
    poller.mutate(undefined, { revalidate: false });
    try {
      const accepted = await submitScan(trimmed);
      setActiveScan({ accepted, startedAt: Date.now() });
    } catch (error) {
      setFormError(
        error instanceof Error
          ? error.message
          : "The scan could not be submitted. Please try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }, [input, poller]);

  const clearResult = () => {
    setActiveScan(null);
    setTimedOut(false);
    setElapsed(0);
    setFormError(null);
    setInput("");
    poller.mutate(undefined, { revalidate: false });
  };

  const retryPolling = () => {
    setTimedOut(false);
    setRetryKey((current) => current + 1);
    if (activeScan) {
      setActiveScan({ ...activeScan, startedAt: Date.now() });
      setElapsed(0);
    }
    void poller.mutate();
  };

  const reportError =
    poller.error instanceof Error ? poller.error.message : null;

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="TrueIntent home">
          <span className="brand-mark">
            <Fingerprint aria-hidden="true" size={23} strokeWidth={1.8} />
          </span>
          <span className="brand-name">trueintent<span>.</span></span>
        </a>
        <nav className="top-nav" aria-label="Main navigation">
          <a className="nav-link active" href="#analyze">Analyze</a>
          <a className="nav-link" href="#how-it-works">How it works</a>
          <a className="api-link" href={API_DOCS_URL} target="_blank" rel="noreferrer">
            API docs <ArrowUpRight aria-hidden="true" size={14} />
          </a>
        </nav>
        <div className="service-state"><span className="live-dot" /> Advisory engine</div>
      </header>

      <section className="hero" id="analyze">
        <div className="hero-copy">
          <p className="overline"><span /> LINK INTELLIGENCE / MODULE A</p>
          <h1>Look closer.<br /><em>Decide with context.</em></h1>
          <p className="hero-description">
            Inspect a web address, UPI link, or QR text. TrueIntent surfaces
            explainable signals so you can make a more informed decision.
          </p>
          <div className="hero-proof">
            <span><ShieldCheck size={15} /> Explainable indicators</span>
            <span><Fingerprint size={15} /> Privacy-minded analysis</span>
          </div>
        </div>
        <div className="hero-index" aria-hidden="true">
          <div className="index-orbit orbit-one" />
          <div className="index-orbit orbit-two" />
          <div className="index-core"><Fingerprint size={48} strokeWidth={1.25} /></div>
          <span className="orbit-tag tag-one">URL</span>
          <span className="orbit-tag tag-two">UPI</span>
          <span className="orbit-tag tag-three">QR</span>
          <span className="orbit-caption">SIGNAL / CONTEXT / CLARITY</span>
        </div>
      </section>

      <section className="workspace" aria-label="Link analysis workspace">
        <div className="input-panel panel" id="analyze-form">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">START A NEW CHECK <span>01 / INPUT</span></p>
              <h2>What would you like to inspect?</h2>
            </div>
            <span className="input-limit">{input.length.toLocaleString()} / {MAX_INPUT_LENGTH}</span>
          </div>
          <label className="sr-only" htmlFor="analysis-input">URL, UPI link, or QR text</label>
          <textarea
            id="analysis-input"
            value={input}
            onChange={(event) => {
              setInput(event.target.value);
              if (formError) setFormError(null);
            }}
            maxLength={MAX_INPUT_LENGTH}
            placeholder="Paste a link or the text decoded from a QR code..."
            rows={4}
            aria-describedby="input-hint input-error"
            aria-invalid={Boolean(formError)}
            disabled={submitting}
          />
          <div className="input-meta">
            <span id="input-hint">We identify the input type from the server response.</span>
            <span className={remainingChars < 100 ? "limit-warning" : ""}>{remainingChars.toLocaleString()} characters left</span>
          </div>
          {formError && (
            <div className="alert alert-error" id="input-error" role="alert">
              <X aria-hidden="true" size={17} /> {formError}
            </div>
          )}
          <div className="input-footer">
            <div className="examples">
              <span className="examples-label">TRY AN EXAMPLE</span>
              <div className="example-buttons">
                {EXAMPLES.map(({ label, icon: Icon, value }) => (
                  <button
                    className="example-button"
                    type="button"
                    key={label}
                    onClick={() => {
                      setInput(value);
                      setFormError(null);
                    }}
                    disabled={submitting}
                  >
                    <Icon size={14} aria-hidden="true" /> {label}
                  </button>
                ))}
              </div>
            </div>
            <button
              className="analyze-button"
              type="button"
              onClick={() => void startScan()}
              disabled={submitting || isWorking || !input.trim()}
            >
              {submitting ? <LoaderCircle size={17} className="spin" /> : <>Analyze <ArrowRight size={17} /></>}
            </button>
          </div>
        </div>

        {activeScan && (
          <section className="results-section" aria-live="polite">
            <div className="results-header">
              <div>
                <p className="eyebrow">ANALYSIS REPORT <span>02 / RESULTS</span></p>
                <h2>Your scan, with context.</h2>
              </div>
              <button className="icon-button" type="button" onClick={clearResult} aria-label="Clear scan result">
                <X size={18} />
              </button>
            </div>

            <div className={`overall-banner overall-${overall.toLowerCase()}`}>
              <div className="overall-symbol"><ShieldCheck size={22} /></div>
              <div className="overall-copy">
                <span className="eyebrow">OVERALL INDICATOR</span>
                <h3>{report ? overallLabel(overall) : "Awaiting persisted report"}</h3>
                <p>{report ? overallDescription(overall) : "The API accepted the scan. Waiting for its saved report."}</p>
              </div>
              <StatusBadge status={report ? overallStatus(report) : "PENDING"} />
            </div>

            <div className="scan-meta panel">
              <div className="meta-item">
                <span>Scan ID</span>
                <code>{activeScan.accepted.scan_id}</code>
              </div>
              <div className="meta-item">
                <span>Payload type</span>
                <strong>{formatPayload(fastSummary?.payload_type)}</strong>
              </div>
              <div className="meta-item">
                <span>Status</span>
                <strong className="scan-status">{report?.status ?? activeScan.accepted.status}</strong>
              </div>
              {fastSummary && (
                <div className="meta-item">
                  <span>Domain / host</span>
                  <strong>{fastSummary.domain ?? "Not applicable"}</strong>
                </div>
              )}
            </div>

            {report && (
              <AnalysisProgress
                status={report.status}
                payloadType={activeScan.accepted.fast_path_summary.payload_type}
              />
            )}

            {reportError && !report && (
              <div className="alert alert-error report-error" role="alert">
                <X size={17} /> {reportError}
                <button type="button" className="text-button" onClick={retryPolling}>Retry report</button>
              </div>
            )}
            {timedOut && !terminal(report) && (
              <div className="alert alert-warning" role="status">
                <Clock3 size={18} />
                <span>
                  Polling paused after 60 seconds. {report ? "The latest partial report is shown below." : "No report has arrived yet."}
                </span>
                <button type="button" className="text-button" onClick={retryPolling}>Continue checking</button>
              </div>
            )}
            {report?.status === "FAILED" && (
              <div className="alert alert-warning" role="status">
                <X size={18} />
                The scan did not finish successfully. Any available indicators below are retained partial results.
              </div>
            )}
            {!report && !reportError && (
              <div className="loading-report" role="status">
                <LoaderCircle className="spin" size={20} />
                <span>Waiting for the first saved report…</span>
                <span className="elapsed">{elapsed}s</span>
              </div>
            )}
            {report && (
              <div className="pillar-grid">
                <ThreatCard
                  title="Technical URL analysis"
                  description="Address structure, domain and available infrastructure checks."
                  pillar={report.advisory_report.technical_url_analysis}
                />
                <ThreatCard
                  title="Visual brand analysis"
                  description="Page behavior and visual similarity checks run in the isolated browser."
                  pillar={report.advisory_report.visual_brand_analysis}
                />
                <ThreatCard
                  title="Transaction context"
                  description="Payment-link fields and transaction wording, when present."
                  pillar={report.advisory_report.transaction_context_analysis}
                />
              </div>
            )}

            <div className="fast-summary">
              <div className="fast-summary-heading">
                <div><p className="eyebrow">FAST-PATH SUMMARY</p><h3>Available link facts</h3></div>
                <ArrowDown size={16} aria-hidden="true" />
              </div>
              <div className="summary-grid">
                <SummaryFact label="Domain age" value={fastSummary?.domain_age_days == null ? "Unknown" : `${fastSummary.domain_age_days} days`} />
                <SummaryFact label="Punycode" value={fastSummary?.is_punycode ? "Present" : "Not detected"} />
                <SummaryFact label="Shannon entropy" value={fastSummary?.shannon_entropy.toFixed(2) ?? "Unavailable"} />
                <SummaryFact label="Threat-feed matches reported" value={String(fastSummary?.threat_feed_matches ?? 0)} />
                <p className="privacy-note">
                  The pasted link or text is sent to the TrueIntent API for analysis.
                  Page screenshots, when a web scan runs, are processed in memory and
                  discarded rather than stored.
                </p>
              </div>
              <p className="summary-note">A missing or unavailable check is not evidence of a clean result. Threat-feed matches are counts returned by configured providers.</p>
            </div>
          </section>
        )}
      </section>

      {!activeScan && (
        <>
          <section className="history-note" aria-labelledby="history-title">
            <div className="history-icon"><Clock3 size={18} aria-hidden="true" /></div>
            <div>
              <h2 id="history-title">Scan history</h2>
              <p>The current API does not provide a history endpoint. Keep a scan ID to reopen a report through the API.</p>
            </div>
          </section>
          <section className="how-section" id="how-it-works">
            <div className="how-heading">
              <p className="eyebrow">A CLEARER WAY TO REVIEW LINKS</p>
              <h2>Signals, not snap judgments.</h2>
            </div>
            <div className="how-grid">
              <HowStep number="01" title="Paste the source" text="Submit a URL, UPI deep link, or the text carried by a QR code." />
              <HowStep number="02" title="Checks run in context" text="The API classifies the input and runs relevant fast checks. Web pages may receive a guarded background review." />
              <HowStep number="03" title="Review the indicators" text="Read each pillar and its evidence. Missing checks remain clearly marked as unavailable." />
            </div>
          </section>
        </>
      )}

      <footer className="footer">
        <p><ShieldCheck size={16} /> Indicators are automated signals, not a verdict. When in doubt, don&apos;t pay or log in; contact the organization using its official number.</p>
        <span>TRUEINTENT / RESEARCH PROTOTYPE</span>
      </footer>
    </main>
  );
}

function SummaryFact({ label, value }: { label: string; value: string }) {
  return <div className="summary-fact"><span>{label}</span><strong>{value}</strong></div>;
}

function HowStep({ number, title, text }: { number: string; title: string; text: string }) {
  return <article className="how-step"><span>{number}</span><h3>{title}</h3><p>{text}</p></article>;
}

function formatPayload(payload?: string): string {
  if (payload === "UPI_DEEP_LINK") return "UPI deep link";
  if (payload === "QR_TEXT") return "QR text";
  if (payload === "URL") return "Web address";
  return "Waiting for classification";
}

function overallLabel(value: string): string {
  switch (value) {
    case "NO_INDICATORS_DETECTED": return "No indicators detected";
    case "SOME_INDICATORS_DETECTED": return "Some indicators detected";
    case "HIGH_RISK_INDICATORS_DETECTED": return "High-risk indicators detected";
    default: return "Inconclusive";
  }
}

function overallDescription(value: string): string {
  switch (value) {
    case "NO_INDICATORS_DETECTED": return "The completed checks did not report indicators. This is not a guarantee about the link.";
    case "SOME_INDICATORS_DETECTED": return "One or more checks reported signals that deserve your attention.";
    case "HIGH_RISK_INDICATORS_DETECTED": return "At least one high-severity indicator was reported. Review its evidence carefully.";
    default: return "One or more relevant checks are unavailable or still pending. Do not interpret missing results as a clean outcome.";
  }
}

function overallStatus(report: ScanReport): "NO_INDICATORS" | "FLAGGED" | "UNAVAILABLE" {
  if (report.overall_indicator === "NO_INDICATORS_DETECTED") return "NO_INDICATORS";
  if (report.overall_indicator === "INCONCLUSIVE") return "UNAVAILABLE";
  return "FLAGGED";
}
