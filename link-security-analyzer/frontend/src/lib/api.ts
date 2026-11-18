export type PayloadType = "URL" | "UPI_DEEP_LINK" | "QR_TEXT";
export type ScanStatus =
  | "PENDING"
  | "FAST_PATH_DONE"
  | "sandbox_queued"
  | "sandbox_running"
  | "COMPLETED"
  | "complete_partial"
  | "FAILED";
export type PillarStatus =
  | "NOT_APPLICABLE"
  | "NO_INDICATORS"
  | "FLAGGED"
  | "UNAVAILABLE"
  | "PENDING";
export type OverallIndicator =
  | "NO_INDICATORS_DETECTED"
  | "SOME_INDICATORS_DETECTED"
  | "HIGH_RISK_INDICATORS_DETECTED"
  | "INCONCLUSIVE";

export interface Indicator {
  code: string;
  severity: "info" | "low" | "medium" | "high";
  message: string;
  evidence: Record<string, string | number | boolean | null>;
}

export interface AdvisoryPillar {
  status: PillarStatus;
  indicators: Indicator[];
}

export interface FastPathSummary {
  payload_type: PayloadType;
  domain: string | null;
  is_punycode: boolean;
  shannon_entropy: number;
  domain_age_days: number | null;
  threat_feed_matches: number;
}

export interface ScanAccepted {
  scan_id: string;
  status: "FAST_PATH_DONE" | "COMPLETED" | "complete_partial";
  fast_path_summary: FastPathSummary;
  poll_url: string;
  verdict: {
    verdict: "DANGEROUS" | "SUSPICIOUS" | "LIKELY_SAFE" | "UNKNOWN";
    risk_score: number;
    reasons: string[];
  };
}

export interface ScanReport {
  scan_id: string;
  status: ScanStatus;
  overall_indicator: OverallIndicator;
  advisory_report: {
    technical_url_analysis: AdvisoryPillar;
    visual_brand_analysis: AdvisoryPillar;
    transaction_context_analysis: AdvisoryPillar;
  };
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfter: string | null = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/+$/, "") ??
  "http://localhost:8000";
const REQUEST_TIMEOUT_MS = 15_000;

export async function submitScan(input: string): Promise<ScanAccepted> {
  const response = await request(`${API_BASE_URL}/api/v1/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input }),
  });
  const body = await readJson(response);
  if (!isScanAccepted(body)) {
    throw new ApiError("The API returned an incomplete scan response.", 502);
  }
  return body;
}

export async function fetchScanReport(
  pollUrl: string,
  signal?: AbortSignal,
): Promise<ScanReport> {
  const url = new URL(pollUrl, `${API_BASE_URL}/`);
  const apiOrigin = new URL(API_BASE_URL).origin;
  if (url.origin !== apiOrigin) {
    throw new ApiError("The API returned a poll URL on an unexpected host.", 502);
  }
  const response = await request(url.toString(), { signal });
  const body = await readJson(response);
  if (!isScanReport(body)) {
    throw new ApiError("The API returned an incomplete report.", 502);
  }
  return body;
}

export function validateScanInput(input: string): string | null {
  if (!input.trim()) return "Enter a URL, UPI link, or text from a QR code.";
  if (input.trim().length > 2048) return "Input must be 2,048 characters or fewer.";
  return null;
}

async function request(
  url: string,
  init: RequestInit,
): Promise<Response> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const relayAbort = () => controller.abort();
  init.signal?.addEventListener("abort", relayAbort, { once: true });
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) {
      const detail = await getErrorDetail(response);
      const retryAfter = response.headers.get("Retry-After");
      const message =
        response.status === 422
          ? `Please check the input: ${detail}`
          : response.status === 429
            ? `Request limit reached. Try again in ${retryAfter ?? "a short while"} seconds.`
            : detail;
      throw new ApiError(message, response.status, retryAfter);
    }
    return response;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted && !init.signal?.aborted) {
      throw new ApiError("The API request timed out. Please try again.", 408);
    }
    throw new ApiError(
      "Could not reach the TrueIntent API. Check that the services are running and try again.",
      0,
    );
  } finally {
    window.clearTimeout(timeout);
    init.signal?.removeEventListener("abort", relayAbort);
  }
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new ApiError("The API returned an unreadable response.", 502);
  }
}

async function getErrorDetail(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      return body.detail
        .map((item: { msg?: unknown }) =>
          typeof item.msg === "string" ? item.msg : "",
        )
        .filter(Boolean)
        .join("; ");
    }
  } catch {
    return `The API returned HTTP ${response.status}.`;
  }
  return `The API returned HTTP ${response.status}.`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPayloadType(value: unknown): value is PayloadType {
  return value === "URL" || value === "UPI_DEEP_LINK" || value === "QR_TEXT";
}

function isPillarStatus(value: unknown): value is PillarStatus {
  return (
    value === "NOT_APPLICABLE" ||
    value === "NO_INDICATORS" ||
    value === "FLAGGED" ||
    value === "UNAVAILABLE" ||
    value === "PENDING"
  );
}

function isIndicator(value: unknown): value is Indicator {
  return (
    isRecord(value) &&
    typeof value.code === "string" &&
    (value.severity === "info" ||
      value.severity === "low" ||
      value.severity === "medium" ||
      value.severity === "high") &&
    typeof value.message === "string" &&
    isRecord(value.evidence)
  );
}

function isPillar(value: unknown): value is AdvisoryPillar {
  return (
    isRecord(value) &&
    isPillarStatus(value.status) &&
    Array.isArray(value.indicators) &&
    value.indicators.every(isIndicator)
  );
}

function isScanAccepted(value: unknown): value is ScanAccepted {
  if (!isRecord(value) || !isRecord(value.fast_path_summary)) return false;
  const summary = value.fast_path_summary;
  return (
    typeof value.scan_id === "string" &&
    isRecord(value.verdict) &&
    (value.verdict.verdict === "DANGEROUS" ||
      value.verdict.verdict === "SUSPICIOUS" ||
      value.verdict.verdict === "LIKELY_SAFE" ||
      value.verdict.verdict === "UNKNOWN") &&
    typeof value.verdict.risk_score === "number" &&
    Array.isArray(value.verdict.reasons) &&
    value.verdict.reasons.every((reason) => typeof reason === "string") &&
    (value.status === "FAST_PATH_DONE" ||
      value.status === "COMPLETED" ||
      value.status === "complete_partial") &&
    typeof value.poll_url === "string" &&
    isPayloadType(summary.payload_type) &&
    (typeof summary.domain === "string" || summary.domain === null) &&
    typeof summary.is_punycode === "boolean" &&
    typeof summary.shannon_entropy === "number" &&
    (typeof summary.domain_age_days === "number" ||
      summary.domain_age_days === null) &&
    typeof summary.threat_feed_matches === "number"
  );
}

function isScanReport(value: unknown): value is ScanReport {
  if (!isRecord(value) || !isRecord(value.advisory_report)) return false;
  const report = value.advisory_report;
  return (
    typeof value.scan_id === "string" &&
    (value.status === "PENDING" ||
      value.status === "FAST_PATH_DONE" ||
      value.status === "sandbox_queued" ||
      value.status === "sandbox_running" ||
      value.status === "COMPLETED" ||
      value.status === "complete_partial" ||
      value.status === "FAILED") &&
    (value.overall_indicator === "NO_INDICATORS_DETECTED" ||
      value.overall_indicator === "SOME_INDICATORS_DETECTED" ||
      value.overall_indicator === "HIGH_RISK_INDICATORS_DETECTED" ||
      value.overall_indicator === "INCONCLUSIVE") &&
    isPillar(report.technical_url_analysis) &&
    isPillar(report.visual_brand_analysis) &&
    isPillar(report.transaction_context_analysis)
  );
}
