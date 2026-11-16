# TrueIntent System Diagnosis & Baseline (Phase 0)

Date: 2026-11-16  
Branch: `rebuild/phase-0-baseline`  
Component: TrueIntent Module B (link-security-analyzer)

---

## 1. Executive Summary

This diagnostic report establishes the empirical baseline of why link scans have returned `Inconclusive` and `Unavailable` across technical pillars. Each finding below is verified with command output and code inspection.

---

## 2. Diagnosis Matrix (Items a through g)

| # | Item | Symptom / Status | Evidence (Command + Output Excerpt) | Root Cause | Fix Planned |
|---|---|---|---|---|---|
| **a** | **Lexical Analyzer** | Stubbed / Missing | `Get-ChildItem backend/app/core/lexical.py` returned nonexistent. `_run_lexical()` catches `ImportError` and returns `CHECK_UNAVAILABLE`. | `app.core.lexical` was never authored; code only had a dynamic `importlib.import_module("app.core.lexical")` try/except block. | **Phase 2**: Author real URL lexical feature extractor (entropy, length, tokens, IP usage, Levenshtein distance). |
| **b** | **Threat Feed Keys** | Feeds report `UNAVAILABLE` | `.env` has empty `GSB_API_KEY=` and `VT_API_KEY=`. `check_threat_feeds()` immediately degrades with `THREAT_FEED_UNAVAILABLE`. | Threat feeds were 100% reliant on external paid/freemium API keys with no local cache or open feed fallback. | **Phase 3 & 4**: Ingest local open threat feeds (URLhaus/OpenPhish/Tranco) and preserve graceful degradation for GSB/VT. |
| **c** | **RDAP / WHOIS Timeouts** | Domain age frequently `UNKNOWN` or times out | `python -c "_run_infrastructure('urlscan.io', ...)"` took 7.69s and timed out against 3s WHOIS budget; DNS query against ISP resolver timed out on UDP. | (1) RDAP bootstrap did not resolve `.io` TLD directly, falling back to synchronous TCP whois. (2) `asyncwhois` used 3s timeout which failed on slow registries. (3) Local router DNS (`10.244.88.25`) dropped concurrent UDP query bursts. | **Phase 4**: Add RDAP bootstrap coverage, configure public fallback resolvers (`8.8.8.8`), cache domain age in Redis/Postgres, and treat unknown age as uninformative rather than an error. |
| **d** | **Celery Task Consumption** | Tasks get queued but never completed if worker is down | In local Windows environments, Celery container (`trueintent-worker-1`) was offline. Jobs remained indefinitely in `FAST_PATH_DONE`. | The Celery worker was container-only. When Docker Desktop engine is stopped, no background worker consumes tasks from Redis. | **Phase 5 & 8**: Provide clear dev worker runner, healthcheck ping endpoint, and fallback when async queue is unreachable. |
| **e** | **Playwright / Chromium in Worker** | Playwright launches cleanly when invoked | Local execution: `Browser launched successfully: <BrowserType name=chromium> version=153.0.8010.12`. Page screenshot test: `200 status, 35482 bytes PNG`. Container worker: `Dockerfile.worker` builds on `mcr.microsoft.com/playwright/python:v1.63.0-jammy` with `pwuser`. | Playwright and Chromium are fully installed and functional. Previous failures were due to the Celery worker process itself not running, not a missing Chromium binary. | **Phase 5 & 7**: Verified functional; implement brand visual comparison with genuine seeds. |
| **f** | **Scoring & Verdict Logic** | Any single unavailable check results in `INCONCLUSIVE` | In `aggregator.py`: `any_unavailable = any(pillar.status in {"UNAVAILABLE", "PENDING"} ...); if any_unavailable: overall = "INCONCLUSIVE"`. | The aggregator required 100% of checks to succeed. If lexical was missing (always) or threat feed was unconfigured (always without keys), `overall_indicator` was permanently forced to `INCONCLUSIVE`. System also lacked a definitive verdict (`LIKELY SAFE`, `SUSPICIOUS`, `DANGEROUS`). | **Phase 1 & 8**: Decouple unavailable checks from verdicts. Replace fragile placeholder heuristic with calibrated Bayesian/Rule verdict engine. |
| **g** | **Existing Test Suite** | 177 passed, 1 deselected | `python -m pytest -q` passed 177 tests in 15.53s. Ruff linter: `All checks passed!`. | Existing test coverage across unit models, netguard, and upi parsing is solid. | **Maintain in all phases**: Keep tests green and add test coverage with every phase. |

---

## 3. Reproduction Artifacts

Saved full JSON outputs for the 4 canonical test cases under [`docs/diagnosis/`](file:///c:/Users/Dell/OneDrive/Desktop/AI%20CP/project/TrueIntent/docs/diagnosis):
1. `example_com.json`: Returned `INCONCLUSIVE` due to missing lexical and threat feed stubs.
2. `google_com.json`: Returned `INCONCLUSIVE` despite being a top-ranked benign domain.
3. `sbi_fake.json`: Returned `INCONCLUSIVE` because lexical and typosquat rules were absent.
4. `upi_collect.json`: Returned `SOME_INDICATORS_DETECTED` correctly identifying `UPI_COLLECT_REQUEST`.

---

## 4. Stack Health Verification

Added rich `GET /api/v1/health` endpoint:
```json
{
  "status": "degraded",
  "app_version": "0.1.0",
  "git_commit": "31cc43b",
  "database": false,
  "redis": false,
  "worker": false,
  "playwright_launch": true,
  "threat_feeds": {
    "google_safe_browsing": "unconfigured",
    "virustotal": "unconfigured"
  }
}
```
*Note: In the local test session without background Docker containers, database/redis/worker report `false` cleanly without crashing, while Playwright confirms local Chromium launchability.*
