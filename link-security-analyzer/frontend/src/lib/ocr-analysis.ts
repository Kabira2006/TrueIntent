export interface OcrTextAnalysis {
  score: number;
  signature: "fear_authority" | "greed_opportunity" | "none";
  reasons: string[];
  urls: string[];
  ml_status: string;
}

const KEYWORDS = {
  fear_authority: [
    "under investigation", "stay on the line", "stay on the call",
    "do not disconnect", "do not hang up", "digital arrest", "arrest warrant",
    "money laundering", "you are under", "cbi officer", "police officer",
    "court order", "legal action will be taken",
    "verify immediately or you will be arrested", "share your otp to verify",
    "keep this confidential from your family",
    "blocked within 24 hours", "unusual activity", "verify your account now",
    "permanent suspension", "failure to verify", "account closure",
    "account will be suspended today", "incomplete kyc verification",
    "update immediately", "avoid blockage", "suspended today",
  ],
  greed_opportunity: [
    "guaranteed returns", "limited time", "double your money", "risk-free profit",
    "risk free profit", "assured returns", "100% profit", "join our trading group",
    "exclusive stock tip", "invest now before", "hurry invest",
    "zero risk high return",
  ],
} as const;

export function analyzeOcrText(text: string): OcrTextAnalysis {
  const normalized = text
    .toLocaleLowerCase()
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, " ");
  const fearHits = KEYWORDS.fear_authority.filter((phrase) => normalized.includes(phrase));
  const greedHits = KEYWORDS.greed_opportunity.filter((phrase) => normalized.includes(phrase));
  const signature: OcrTextAnalysis["signature"] =
    fearHits.length === 0 && greedHits.length === 0
      ? "none"
      : fearHits.length >= greedHits.length
        ? "fear_authority"
        : "greed_opportunity";
  const hitCount = Math.max(fearHits.length, greedHits.length);
  const reasons = [
    ...fearHits.map((phrase) => `Matched fear/authority pattern: '${phrase}'`),
    ...greedHits.map((phrase) => `Matched greed/opportunity pattern: '${phrase}'`),
  ];
  const urls = (text.match(/(?:https?:\/\/|www\.)[^\s"'<>]+|(?<![@\w])(?:[a-z\d-]+\.)+(?:com|net|org|in|co|info|biz|app|site|online|xyz|top)(?:\/[^\s"'<>]*)?/gi) ?? [])
    .map((url) => url.replace(/[.,;:!?)'\"]+$/, ""));
  const impersonatedBrands = [
    { name: "SBI", mentioned: /\b(?:sbi|state bank of india)\b/i.test(normalized), hostTokens: ["sbi"], officialHosts: ["sbi.co.in", "onlinesbi.sbi", "sbicard.com"] },
    { name: "Zenith Bank", mentioned: /\bzenith bank\b/i.test(normalized), hostTokens: ["znb", "zenith"], officialHosts: ["zenithbank.com"] },
  ];
  const brandMismatchReasons = impersonatedBrands.flatMap((brand) => {
    if (!brand.mentioned) return [];
    const mismatch = urls.some((url) => {
      try {
        const normalizedUrl = /^https?:\/\//i.test(url) ? url : `https://${url}`;
        const host = new URL(normalizedUrl).hostname.toLowerCase();
        const isOfficial = brand.officialHosts.some((official) => host === official || host.endsWith(`.${official}`));
        const looksLikeBrand = brand.hostTokens.some((token) => host.includes(token));
        const looksLikeCredentialUrl = /(?:verify|secure|login|account|kyc)/i.test(host);
        return !isOfficial && looksLikeBrand && looksLikeCredentialUrl;
      } catch {
        return false;
      }
    });
    return mismatch
      ? [`${brand.name} is named in the message, but its link uses a non-official, credential-themed lookalike domain.`]
      : [];
  });
  reasons.push(...brandMismatchReasons);
  const effectiveHitCount = Math.max(hitCount, brandMismatchReasons.length ? 3 : 0);
  const effectiveScore = effectiveHitCount === 0 ? 0 : effectiveHitCount === 1 ? 0.55 : effectiveHitCount === 2 ? 0.75 : 0.9;
  return {
    score: effectiveScore,
    signature,
    reasons,
    urls,
    ml_status: "rules_only (model unavailable; keyword baseline)",
  };
}
