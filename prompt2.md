I couldn't open your repo (`Kabira2006/TrueIntent`). My search only returned other projects with the same name, so I haven't seen what's in it. Chunk 0 handles both cases. It checks the repo state first, never deletes or restructures existing files, and stops for your decision if it finds an unexpected layout.

What changed in the nine chunks:
- **New Chunk 0.** It sets up the repo, `AGENTS.md`, `.gitignore`, the skeleton and the journal file, and writes the "big picture" chapter.
- **Journal protocol in `AGENTS.md`.** Every chunk appends a chapter to `docs/PROJECT_JOURNAL.md` in a fixed format: plain-words summary, why, a Mermaid diagram plus how it works, decisions with rejected alternatives, what was built, what actually happened (real test output, bugs and deviations), honest limits, a 30-second judge pitch and new terms. GitHub renders Mermaid, so the diagrams show up directly on the repo page.
- **Git protocol.** After the tests pass, it stages explicit paths, scans for secrets, commits as `chunk-N: ...` and pushes. If tests fail, it pushes to a `wip/` branch, not `main`. It never force-pushes.
- **Layout.** Module A lives in `link-security-analyzer/` inside the repo, so your other modules can sit beside it later. Paths in the chunks are relative to that folder.

Run order: Chunk 0, then the skills prompt, then Chunks 1 to 9. After the skills prompt finishes, add this at its end so the skills get committed:

```
Final step: follow the Git Protocol in AGENTS.md. Commit .opencode/ and AGENTS.md as "setup: install agent skills" and push.
```

---

### Chunk 0: Repo setup, rules, journal

`````
You are setting up the TrueIntent repository. Work only on this chunk. Do not implement any application code.

STEP 1: Locate the repo.
- Run `git rev-parse --show-toplevel` and `git remote -v`. If the current folder is already a clone of https://github.com/Kabira2006/TrueIntent, use it. Otherwise, if the folder is not a git repo, run `git clone https://github.com/Kabira2006/TrueIntent.git` and work inside it. If the folder is a different repo, STOP and tell me.
- Print `git remote -v`, `git branch --show-current`, `git log --oneline -n 10`, `ls -la`, and the first 40 lines of README.md if it exists.
- If the repo already contains application code or a folder structure beyond README/LICENSE/.gitignore, DO NOT restructure or delete anything. Print a summary of what is there and STOP so I can decide.

STEP 2: Write `AGENTS.md` at the repo root with the content between the === lines. If AGENTS.md already exists, MERGE: keep every existing section (for example "## Skills") and add the new ones; report what you merged.

=== AGENTS.md ===
# TrueIntent: rules for coding agents

## Repo layout
TrueIntent/
  AGENTS.md
  README.md
  docs/PROJECT_JOURNAL.md          (living journal, see Documentation Protocol)
  link-security-analyzer/          (Module A: URLs, UPI deep links, QR text)
    docker-compose.yml, .env.example, backend/, frontend/, eval/
Other modules (text scam engine, screenshot OCR, call audio) will be added later as sibling folders. Do not create them now.
All Module A paths below are relative to link-security-analyzer/ unless they start with docs/ or are AGENTS.md or README.md.

## Module A purpose
Given a URL, UPI deep link, or pasted QR text, return explainable risk INDICATORS (not verdicts) across three pillars: technical URL analysis, visual brand analysis, transaction context analysis. Also expose a flat numeric `signal_vector` and a heuristic score so a later fusion layer can combine it with a text-scam classifier. The module must be callable as a library (a service function), not only through HTTP, because other modules will call it with URLs extracted from screenshots and call transcripts.

## Stack
Backend: Python 3.11+, FastAPI, uvicorn, Celery + Redis, PostgreSQL 16, SQLAlchemy 2.x (async for the API, sync sessionmaker for the Celery worker), Alembic, tldextract, idna, asyncwhois, dnspython, httpx, cryptography, pyOpenSSL, beautifulsoup4, playwright, imagehash, Pillow, pydantic v2 + pydantic-settings.
Frontend: Next.js 14 (App Router), TypeScript, Tailwind, lucide-react, SWR.
Infra: docker-compose (postgres, redis, backend, worker, frontend).

## Module A structure
backend/app/{main.py,config.py,db/{session.py,models.py},api/v1/{endpoints.py,schemas.py},core/{lexical.py,infrastructure.py,threat_feeds.py,upi.py,input_router.py,netguard.py,aggregator.py,service.py},workers/{celery_app.py,tasks.py}}
backend/{tests/,scripts/,data/,alembic/}
frontend/src/{app/page.tsx,app/report/[id]/page.tsx,components/{ThreatCard.tsx,AnalysisProgress.tsx},lib/api.ts}
eval/

## Engineering rules
1. Work only on the chunk you are given. Do not start later chunks or add unrequested features.
2. Pin dependency versions in requirements.txt / package.json to versions that actually install today. Before using any library API, check the installed version's real API (asyncwhois, playwright, tldextract change between releases). Do not guess signatures.
3. Type hints everywhere, pydantic v2 models for all data contracts, ruff-clean, small functions.
4. Unit tests with pytest (+ pytest-asyncio). Unit tests must NOT touch the network, Redis, or Postgres; mock them. Integration tests are marked `@pytest.mark.integration`.
5. Secrets only via environment variables; maintain `.env.example`; never commit real keys.
6. Privacy: never log full URLs or query strings at INFO level; log scan_id only. Never store screenshots; store only perceptual hashes.
7. Safety: user-supplied URLs are hostile. Any code that connects to a user-supplied host must go through `core/netguard.py` (added in Chunk 4).
8. UI/advisory wording: never use "safe", "100%", "guaranteed", "confirmed fraud". Use "indicators detected / no indicators detected / inconclusive".
9. Stable indicator shape everywhere: {code: str, severity: "info"|"low"|"medium"|"high", message: str, evidence: dict}.
10. At the end of every chunk print: (a) files created/changed, (b) ruff and pytest results, (c) any deviation from the spec and why, (d) anything you could not verify, (e) the journal chapter path, (f) the commit hash and push result.

## Documentation Protocol (mandatory, every chunk)
The file docs/PROJECT_JOURNAL.md is the living explanation of this project. Append exactly one chapter per chunk, in order, and update the table of contents at the top of the file. Do not rewrite earlier chapters except to fix a factual error (add a dated "Correction" note at the end of that chapter).
- Audience: a smart teammate who does not code, and a judge. Use plain words and short sentences. Define every technical term the first time it appears, in one sentence, ideally with an everyday analogy. No unexplained acronyms.
- Write the chapter AFTER the chunk's code is finished and the tests have run, so that "What actually happened" reflects reality.
- Truthfulness: only claim what a command output or test showed. Include real numbers (test counts, timings, metric values). Include failures, dead ends, bugs, fixes and deviations from the plan. Mark anything unverified as "not verified". Never invent results.
- Never put secrets, API keys, real user data or live malicious URLs in the journal. Use example.com-style placeholders; defang real malicious examples (hxxp, [.]).
- Every chapter has at least one Mermaid diagram (flowchart, sequenceDiagram or erDiagram): simple, quoted node labels, at most 15 nodes, with a one-sentence caption below it saying what to notice. After writing, re-read each diagram for syntax errors.
- Keep a chapter under about 250 lines.
Chapter template (use these exact headings):
## Chapter N: <title>
Date: YYYY-MM-DD | Commit message: chunk-N: <title>
### 1. In one minute
(plain words: what we built and what it is for)
### 2. Why we did this
(the problem it solves; what would go wrong without it)
### 3. How it works
(Mermaid diagram, caption, then a step-by-step walk-through in plain words)
### 4. Decisions and reasoning
(table: decision | options considered | why we chose this | trade-off)
### 5. What we built
(files, one line each)
### 6. What actually happened
(real command outputs summarized: test counts, errors hit and how they were fixed, deviations from the plan, things that surprised us)
### 7. Limits and honest weaknesses
### 8. How to explain this to a judge in 30 seconds
### 9. New terms
(term: one-sentence plain definition)

## Git Protocol (mandatory, every chunk)
1. Before starting: run `git status --short`, `git branch --show-current`, `git pull --ff-only`. Work on `main` with a clean tree. If the tree has changes you did not make, STOP and report.
2. The remote must be https://github.com/Kabira2006/TrueIntent.git. If `origin` is missing or different, report it and STOP; do not change it silently.
3. NEVER: force-push, rewrite history, run `git reset --hard`, delete files you did not create, change global git config, commit .env files or any secret, commit files larger than 5 MB, or commit downloaded datasets, screenshots or model files (eval/data/raw is git-ignored; the small locked test CSV and manual CSV may be committed).
4. At close-out, only if ruff and pytest pass: stage explicit paths (never a blind `git add -A`), run `git diff --cached --stat`, scan the staged diff for secrets (patterns such as API_KEY=, SECRET, TOKEN, BEGIN PRIVATE KEY, AIza, sk-), then commit with the message `chunk-N: <short title>` plus a body listing what changed, and `git push origin main`.
5. If tests fail: still write the journal chapter, mark its title "(INCOMPLETE)", commit and push to a branch named `wip/chunk-N-<slug>` instead of main, and say so clearly.
6. If a push is rejected, run `git pull --rebase origin main` once and retry. If it still fails, STOP and report the exact error. If authentication fails, tell me what is needed. Never put tokens in files or in the remote URL.

## Skills
(If this section already exists, keep it as is.)
=== END ===

STEP 3: Create or merge `.gitignore` (Python, Node, .env, .venv, __pycache__, node_modules, .next, *.log, *.pem, *.key, link-security-analyzer/eval/data/raw/, model files). Do not remove existing entries.

STEP 4: Create the empty Module A skeleton from the structure above (directories with `.gitkeep`; Python packages with `__init__.py`). Nothing else.

STEP 5: Create `docs/PROJECT_JOURNAL.md` with:
- A title, a short "What is this file" section, and a "How to read this journal" guide for non-technical teammates (read the "In one minute" and "Judge" sections first).
- A table of contents listing Chapter 0 now, with a placeholder note that chapters 1 to 9 will be appended.
- Chapter 0, "The big picture and setup", using the template. It must explain in plain words: the problem (scam links, UPI payment links, QR codes and why people fall for them); what Module A does and does NOT do (it reports indicators, never a verdict, and why); the three pillars (technical URL analysis, visual brand analysis, transaction context); a Mermaid flowchart of the whole system (frontend, API, fast checks, background browser sandbox, database, cache); a Mermaid flowchart of the build roadmap (Chunks 0 to 9, one line each); a table of technology choices with the reason for each (FastAPI, Celery, Playwright, PostgreSQL, Redis, Next.js); the safety stance (every submitted URL is treated as hostile); and what comes later (other modules). In section 6, record what you actually found in the repo and what you created.

STEP 6: Create README.md at the repo root if missing (otherwise append a "Project journal" section without changing existing content): a short project intro and a link to docs/PROJECT_JOURNAL.md.

STEP 7: Close-out. Follow the Git Protocol: commit `chunk-0: repo rules, skeleton and journal` and push. Then print the final report from rule 10.
`````

### Chunk 1: Docker, config, database

````
Read AGENTS.md first and follow its Documentation Protocol and Git Protocol. All paths are relative to link-security-analyzer/ unless stated. This is Chunk 1: infrastructure scaffold, config, DB models, migration. Nothing else.

1. `docker-compose.yml` with services: postgres:16, redis:7, backend (uvicorn, reload in dev), worker (Celery; use the official Playwright Python image whose version matches the pinned `playwright` package), frontend (placeholder for now). Add healthchecks, a named postgres volume, and for the worker: `mem_limit`, `cpus`, `shm_size` suitable for Chromium, non-root user.
2. `.env.example` with: DATABASE_URL, SYNC_DATABASE_URL, REDIS_URL, GSB_API_KEY, VT_API_KEY, WHOIS_TIMEOUT_SECONDS=3.0, DNS_TIMEOUT_SECONDS=2.0, FAST_PATH_BUDGET_SECONDS=5.0, SANDBOX_ENABLED=true, SANDBOX_PAGE_TIMEOUT_SECONDS=15, ENTROPY_THRESHOLD=4.5, ENTROPY_MIN_LENGTH=24, PHASH_DISTANCE_THRESHOLD=10, RATE_LIMIT_SCAN_PER_MIN=20, RATE_LIMIT_GET_PER_MIN=120, CORS_ORIGINS.
3. `backend/Dockerfile`, `backend/requirements.txt` (pinned), `backend/app/config.py` (pydantic-settings BaseSettings reading the above).
4. `backend/app/db/session.py`: async engine + async session dependency for FastAPI, plus a sync engine/sessionmaker for the Celery worker.
5. `backend/app/db/models.py` (SQLAlchemy 2.x typed models) and an initial Alembic migration for these tables, matching the spec:
   - `domain_records` (id uuid pk, domain_name unique not null, registered_at timestamptz, age_days int, registrar, has_mx_records bool default false, updated_at)
   - `brand_references` (id, brand_name, official_domain, phash_signature varchar(64), created_at)
   - `scan_jobs` (id, input_payload text, payload_type in ('URL','UPI_DEEP_LINK','QR_TEXT'), status in ('PENDING','FAST_PATH_DONE','COMPLETED','FAILED') default 'PENDING', JSONB columns lexical_indicators, infrastructure_indicators, threat_feed_indicators, transaction_indicators, sandbox_indicators (default '{}'), final_advisory_status varchar(50) default 'UNKNOWN', created_at, completed_at)
   Deviations I want: use `gen_random_uuid()` (built in) instead of uuid-ossp; add to scan_jobs nullable columns `signal_vector JSONB`, `heuristic_score FLOAT`, `error_message TEXT`; keep indexes on scan_jobs(status) and domain_records(domain_name). Treat `age_days` as a cached convenience: always derive from `registered_at` when reading.
6. `backend/app/main.py` with FastAPI app, CORS from config, and `GET /healthz` that checks DB and Redis connectivity.

Definition of done: `docker compose up` brings up postgres, redis, backend; `alembic upgrade head` succeeds; `/healthz` returns 200. Add a pytest for config loading (no network).

CLOSE-OUT (mandatory): Append Chapter 1 "Infrastructure, config and database" to docs/PROJECT_JOURNAL.md and update the table of contents, following the template. It must specifically explain in plain words: what Docker and containers are (use a shipping-container analogy) and what each service is for (Postgres as the long-term notebook, Redis as fast short-term memory, backend, worker); why settings live in a .env file and why secrets never go into Git; each database table and why it exists; why indicators are stored as JSONB; what a migration is and why we use one; the deviations from the original plan (gen_random_uuid, extra columns) with reasons. Diagrams: a flowchart of the containers and how they connect, and an erDiagram of the three tables. Record real results (did docker compose start, migration output, health check, test count). Then commit `chunk-1: infrastructure, config and database` and push.
````

### Chunk 2: Lexical engine

````
Read AGENTS.md first and follow its Documentation Protocol and Git Protocol. All paths are relative to link-security-analyzer/. This is Chunk 2: `backend/app/core/lexical.py` plus data files and tests. Pure functions, no network.

Public API: `analyze_lexical(url: str, settings) -> LexicalResult` where LexicalResult has `indicators: list[Indicator]` and `features: dict[str, float|int|bool|str]`.

Implement:
1. Parsing: robust URL parse (add a scheme if missing for analysis only), then `tldextract` split into subdomain / registered domain / suffix. Configure tldextract to use its bundled snapshot with no network fetch.
2. Host forms: IP-literal host (decimal, hex, octal, IPv6), punycode (`xn--`) with `idna` decode, mixed-script detection per label using `unicodedata`, and a small confusable/homoglyph skeleton map (Cyrillic/Greek lookalikes, digit/letter swaps like 0/o, 1/l). Flag when the skeleton of the host matches a known brand but the host is not the official domain.
3. Structure: subdomain depth, hyphen count, digit ratio, host length, '@' in authority, non-standard port, `data:`/`javascript:` schemes, excessive percent-encoding or double-encoding, number of query params, very long URL.
4. Lists loaded from JSON files in `backend/data/` (create them, easy to edit): `suspicious_tlds.json` (e.g. top, xyz, click, icu, live, support, shop, vip, cfd, sbs, rest, cyou), `url_shorteners.json` (bit.ly, tinyurl.com, t.co, goo.gl, cutt.ly, rb.gy, is.gd, ow.ly, etc.), `brands.json` (name, official_domains[], keywords[] for Indian context: SBI, HDFC, ICICI, Axis, PhonePe, Paytm, Google Pay, Flipkart, Amazon, IRCTC, UIDAI/Aadhaar, India Post, Income Tax), `scam_keywords.json` (kyc, refund, verify, update, reward, claim, offer, login, secure, upi, aadhaar, pan, lottery, expire, suspend, etc.).
5. Brand signals: brand keyword in subdomain or path while registered domain is not official; typosquat via Levenshtein distance <= 2 between the registered-domain label and a brand keyword (skip very short keywords to avoid false positives); brand + scam keyword combos in the host.
6. Shannon entropy: implement H = -sum p*log2(p). Compute it on the longest of (subdomain, registered-domain label, path+query) and flag only if length >= ENTROPY_MIN_LENGTH and H > ENTROPY_THRESHOLD. Also export the raw entropy values as features.
7. Every indicator uses the shared shape from AGENTS.md with a stable `code` (e.g. PUNYCODE_HOST, MIXED_SCRIPT, HOMOGLYPH_BRAND_MATCH, IP_HOST, SUSPICIOUS_TLD, URL_SHORTENER, BRAND_IN_SUBDOMAIN, TYPOSQUAT_BRAND, HIGH_ENTROPY, AT_SYMBOL, NONSTANDARD_PORT, DEEP_SUBDOMAIN) and a plain-English message a non-technical person understands.

Tests: at least 30 table-driven cases covering legitimate URLs that must produce NO high-severity indicators (google.com, onlinesbi.sbi, amazon.in, a long legitimate path), and hostile ones (paypa1-style homoglyphs, xn-- IDN lookalike, flipkart-offers-refund.top, http://192.168.0.1.evil.com, bit.ly links, 40-char random subdomain). Report any false positives you could not resolve.

CLOSE-OUT (mandatory): Append Chapter 2 "Reading the URL itself (lexical engine)" to docs/PROJECT_JOURNAL.md and update the table of contents. It must specifically explain in plain words: the anatomy of a URL (subdomain, registered domain, suffix, path, query) with a labeled example; each family of indicators (look-alike characters, brand words in the wrong place, typos of brand names, random-looking text, suspicious endings, shorteners, IP addresses) with a plain example of how scammers use it and why we flag it; Shannon entropy explained with a small worked example computed by you for one random-looking and one normal string; why the entropy rule only applies above a minimum length (and the fix we made versus the original plan); the editable data lists and how a teammate can add a brand; how false positives were handled, with the real cases that triggered them. Include a table: indicator code | plain meaning | example. Diagrams: a flowchart of the analysis steps and a URL anatomy diagram. Record real test counts and any unresolved false positives. Then commit `chunk-2: lexical URL analysis engine` and push.
````

### Chunk 3: Input router and UPI parser

````
Read AGENTS.md first and follow its Documentation Protocol and Git Protocol. All paths are relative to link-security-analyzer/. This is Chunk 3: `backend/app/core/input_router.py` and `backend/app/core/upi.py` plus tests. Pure functions, no network.

1. `classify_input(raw: str) -> InputClassification` (payload_type in URL | UPI_DEEP_LINK | QR_TEXT, plus normalized payload). Rules: trim, reject empty or longer than 2048 chars, strip control characters and zero-width characters. `upi://...` is UPI_DEEP_LINK. A bare http(s) URL (or a domain-like string) is URL. Any other text is QR_TEXT: extract the first http(s) URL or upi:// link inside it if present and record it as `embedded_payload`; otherwise return an "unrecognized" classification.
2. `analyze_upi(payload: str) -> UpiResult` with `indicators` and `features`. Parse `upi://pay` and `upi://collect` (and `upi://mandate`) with `urllib.parse`. Extract and URL-decode `pa` (payee VPA), `pn`, `am`, `tr`, `tn`, `cu`, `mode`, `mc`.
3. Indicators (stable codes, plain-English messages, shared Indicator shape):
   - UPI_COLLECT_REQUEST: scheme/path is collect or mandate (a collect request asks you to PAY, which is commonly abused in "refund" scams).
   - INVALID_VPA_FORMAT: `pa` fails `^[A-Za-z0-9.\-_]{2,256}@[A-Za-z]{2,64}$`.
   - UNKNOWN_PSP_HANDLE: handle not in a configurable list in `backend/data/upi_handles.json` (okhdfcbank, oksbi, okicici, okaxis, ybl, ibl, axl, paytm, apl, upi, etc.). Low severity only.
   - PREFILLED_AMOUNT: `am` present; severity rises with amount thresholds from config.
   - PAYEE_NAME_BRAND_MISMATCH: `pn` contains a brand or authority word (bank, SBI, police, govt, refund, support) but the VPA handle/local part looks unrelated.
   - MISSING_TRANSACTION_REF, NON_INR_CURRENCY, SUSPICIOUS_NOTE_TEXT (`tn` with urgent/refund/KYC words).
   - UPI_EMBEDDED_IN_WEB_URL: an https URL carrying `pa=`/`pn=` query params.
4. The module only reports facts about the link. It must NOT claim to know the user's context (it cannot tell whether they expect to receive or send money). Include in the `UPI_COLLECT_REQUEST` message the plain-language guidance that you never need a PIN to receive money.

Tests: at least 20 cases including malformed URIs, percent-encoded values, missing params, unicode in `pn`, and QR_TEXT with embedded URLs.

CLOSE-OUT (mandatory): Append Chapter 3 "Understanding what was pasted (input router and UPI links)" to docs/PROJECT_JOURNAL.md and update the table of contents. It must specifically explain in plain words: why the system first decides what kind of input it received; what a UPI payment link is and the anatomy of one (a table of pa, pn, am, tr, tn, cu, mode, mc with what each means); how a UPI "collect request" differs from a "pay" link and why scammers abuse it; what a QR code actually contains; why the module reports facts about the link and does not guess the user's situation (state the honest limit). Include a table: indicator code | plain meaning | example (use fake VPAs on example handles). Diagrams: a flowchart of how input is classified and routed, and a labeled breakdown of one sample UPI link. Record real test counts and edge cases that surprised you. Then commit `chunk-3: input router and UPI analysis` and push.
````

### Chunk 4: Netguard, infrastructure, threat feeds

````
Read AGENTS.md first and follow its Documentation Protocol and Git Protocol. All paths are relative to link-security-analyzer/. This is Chunk 4: `backend/app/core/netguard.py`, `infrastructure.py`, `threat_feeds.py`, plus tests with all network calls mocked.

1. `core/netguard.py` (security-critical, used by everything that connects to user-supplied hosts):
   - `async def assert_public_target(url_or_host) -> ResolvedTarget` : allow only http/https; resolve A and AAAA with dnspython; reject if ANY resolved address is private, loopback, link-local (including 169.254.169.254), multicast, reserved, unspecified, CGNAT (100.64.0.0/10), or an IPv4-mapped IPv6 of those; reject IP-literal hosts in decimal/hex/octal forms by normalizing first; reject hostnames like `localhost`, `*.internal`, `*.local`, and docker service names (`redis`, `postgres`, `backend`, `worker`) via a configurable denylist.
   - Raise a typed `BlockedTargetError` with a reason code. Unit-test heavily: 127.0.0.1, 10.x, 172.16.x, 192.168.x, [::1], 0x7f000001, 2130706433, 169.254.169.254, a hostname resolving to a private IP (mock DNS), and valid public targets.
2. `core/infrastructure.py`:
   - `get_domain_info(domain)`: check the Postgres `domain_records` cache first (TTL 7 days, passed as a repository callable so it can be mocked). Otherwise RDAP first (httpx, IANA bootstrap file `dns.json`, cached in Redis for 24h), then fall back to `asyncwhois`. Wrap in `asyncio.wait_for` with `WHOIS_TIMEOUT_SECONDS`. On timeout or failure return domain_age as UNKNOWN with an info-level indicator `WHOIS_TIMEOUT_OR_UNAVAILABLE`; never raise to the caller.
   - Indicators: DOMAIN_VERY_NEW (< 7 days high, < 30 days medium, < 90 days low), REGISTRAR_PRIVACY_PROXY (info only).
   - `resolve_dns(domain)`: A, AAAA, MX, NS with `DNS_TIMEOUT_SECONDS`; indicators NO_A_RECORD, NO_MX_RECORD (info only; many legitimate sites have no MX), FAST_FLUX_LIKE (many A records with very low TTL, low severity).
   - Optional `get_tls_info(host)`: connect on 443 through `netguard` first, short timeout, extract issuer, not_before, SAN match against host. Indicators: TLS_CERT_VERY_NEW (weak signal, low severity; note in the message that free certificates are common and not suspicious by themselves), TLS_HOSTNAME_MISMATCH, NO_TLS.
3. `core/threat_feeds.py`:
   - Google Safe Browsing v4 `threatMatches:find` via httpx POST (key from env). VirusTotal v3: GET `/urls/{id}` where id is base64url(url) without padding. Do NOT submit URLs for scanning by default (that would upload the user's URL to a third party); only look up existing reports.
   - Cache each lookup result in Redis for 24h keyed by sha256(url). Respect VT free-tier limits (4/min, 500/day) with a Redis-based limiter. If a key is missing or the API errors, return status UNAVAILABLE rather than failing the scan.
   - Indicators: GSB_MATCH (high), VT_MALICIOUS_VENDORS (severity scales with vendor count; include count and total in evidence).

Tests: mock httpx, dnspython and Redis. Include timeout paths and missing-API-key paths.

CLOSE-OUT (mandatory): Append Chapter 4 "Safe network checks (netguard, domain age, threat feeds)" to docs/PROJECT_JOURNAL.md and update the table of contents. It must specifically explain in plain words: what SSRF is, told as a short story (a hostile link tricks OUR server into visiting private places such as the cloud metadata address), and exactly how netguard blocks it, with the list of blocked address types and the tricky IP forms (decimal, hex); why a domain's age matters and what RDAP and WHOIS are (a public registry lookup, like checking a business registration); why timeouts end in "unknown" and never in a guess (and why the plan's 1-second timeout was changed to 3 seconds); what Google Safe Browsing and VirusTotal are, why we only look up existing reports and never upload the user's link, and why results are cached; the principle "one failed check must never crash the scan". Include a table of the blocked address ranges. Diagrams: a flowchart of the netguard decision and a sequenceDiagram of one URL passing through the fast checks with a timeout branch. Record real test counts and the hardest edge cases. State honestly that DNS rebinding is not fully solved here. Then commit `chunk-4: netguard, infrastructure checks and threat feeds` and push.
````

### Chunk 5: Aggregator, service layer, API

````
Read AGENTS.md first and follow its Documentation Protocol and Git Protocol. All paths are relative to link-security-analyzer/. This is Chunk 5: `core/aggregator.py`, `core/service.py`, `api/v1/schemas.py`, `api/v1/endpoints.py`, rate limiting, and tests. The sandbox worker is NOT part of this chunk; leave a clearly marked hook for it.

1. `core/aggregator.py`: `build_report(lexical, infra, feeds, upi, sandbox|None) -> AdvisoryReport` producing three pillars: `technical_url_analysis`, `visual_brand_analysis`, `transaction_context_analysis`. Each has status in NOT_APPLICABLE | NO_INDICATORS | FLAGGED | UNAVAILABLE | PENDING plus a list of indicators. Overall indicator in: NO_INDICATORS_DETECTED, SOME_INDICATORS_DETECTED, HIGH_RISK_INDICATORS_DETECTED, INCONCLUSIVE (when key checks were unavailable). Enforce the wording rules in AGENTS.md with a unit test that fails if any forbidden phrase appears in any generated message.
2. Also produce `signal_vector: dict[str, float|int|bool]` (flat, numeric: entropy values, domain age days or -1 if unknown, subdomain depth, flags as 0/1, GSB/VT hit counts, UPI flags) and `heuristic_score` in [0,1] from a documented weighted sum of indicator severities. Document in code and in the schema that the score is an UNCALIBRATED heuristic that will later be replaced by a trained model; it must never be shown to users as a probability.
3. `core/service.py`: `async def run_fast_path(raw_input: str) -> FastPathResult`: classify the input, run lexical + (for URLs) infrastructure + threat feeds concurrently with `asyncio.gather` under an overall `FAST_PATH_BUDGET_SECONDS`, run UPI analysis for UPI/QR payloads, and cache by sha256 of the normalized input in Redis for 1 hour. One slow or failed check must degrade to UNAVAILABLE, never crash the scan. This function is the library entry point other modules will call.
4. Endpoints (`/api/v1`):
   - `POST /scan` body {"input": str}, validate length, call `run_fast_path`, persist a `scan_jobs` row, set status FAST_PATH_DONE, and return 202 with `scan_id`, `status`, `fast_path_summary` (payload_type, domain, is_punycode, shannon_entropy, domain_age_days or null, threat_feed_matches) and `poll_url`. If the payload is a URL and SANDBOX_ENABLED, call `enqueue_sandbox(scan_id)` (a stub that logs for now; Chunk 6 implements it) and keep the status FAST_PATH_DONE; otherwise mark COMPLETED immediately.
   - `GET /scan/{scan_id}` returns the report shape from the spec (scan_id, status, overall_indicator, advisory_report with the three pillars). 404 on unknown id, 422 on invalid UUID.
   - Redis fixed-window rate limiting per client IP: RATE_LIMIT_SCAN_PER_MIN for POST, RATE_LIMIT_GET_PER_MIN for GET; return 429 with Retry-After.
5. Tests: aggregator unit tests (including the forbidden-wording test), service tests with mocked checks (including a timeout case), and API tests using FastAPI's TestClient with dependency overrides for DB and Redis.

Definition of done: with docker compose up, `curl -X POST /api/v1/scan` with a sample URL returns 202 and a readable report on GET.

CLOSE-OUT (mandatory): Append Chapter 5 "Putting the checks together (report, score and API)" to docs/PROJECT_JOURNAL.md and update the table of contents. It must specifically explain in plain words: the three pillars and the stable indicator shape (code, severity, message, evidence) and why a stable shape matters; why the system says "indicators detected" and never "safe" or "fraud" (the wording rules and the reasoning about harm from false confidence); what the signal_vector is, what the heuristic score is, why it is explicitly uncalibrated and never shown as a percentage, and how a later machine-learning model and the text-scam engine will use them; the time budget and why one slow check must not break the scan; why the scan is split into a fast answer plus a later sandbox result; rate limiting and caching in plain words. Include one REAL sample API response from your run (defang the domain, no secrets) with a line-by-line reading guide. Diagrams: a sequenceDiagram of POST then polling GET, and a flowchart of how indicators become pillars and an overall result. Record real test counts and the end-to-end curl result. Then commit `chunk-5: aggregator, service layer and API` and push.
````

### Chunk 6: Playwright sandbox worker

````
Read AGENTS.md first and follow its Documentation Protocol and Git Protocol. All paths are relative to link-security-analyzer/. This is Chunk 6: Celery + Playwright sandbox. Security is the top priority; treat every URL as hostile.

1. `backend/app/workers/celery_app.py`: Celery with Redis broker/backend, task time limit (soft and hard), `worker_concurrency=2`, `task_acks_late=True`, retries disabled for sandbox tasks. Replace the `enqueue_sandbox` stub from Chunk 5 with a real `.delay(scan_id)`.
2. `backend/app/workers/tasks.py`: task `sandbox_scan(scan_id)`: load the job with the sync session, run the async Playwright routine with `asyncio.run`, write `sandbox_indicators`, recompute the report via `aggregator.build_report`, update status to COMPLETED (or FAILED with `error_message`), set `completed_at`. A failed or timed-out sandbox must never lose the fast-path results.
3. Browser routine (`async_playwright`, headless Chromium, a FRESH context per scan, closed in `finally`):
   - Before navigating, call `netguard.assert_public_target`. Install `context.route("**/*", handler)`: for EVERY request (document, redirects, subresources) re-run the netguard check on the request URL and abort blocked ones; abort schemes other than http/https; abort downloads, websockets, and media; record each blocked attempt as a `SANDBOX_BLOCKED_REQUEST` indicator (a page trying to reach internal addresses is itself noteworthy).
   - Context settings: viewport 1280x720, no persistent storage, service workers blocked, permissions denied, `accept_downloads=False`, auto-dismiss dialogs, a fixed generic user agent. Page timeout `SANDBOX_PAGE_TIMEOUT_SECONDS`, cap total navigations and total bytes.
   - Redirect chain: capture HTTP redirects (301/302/303/307/308 via `request.redirected_from`) and client-side navigations (`framenavigated`); record the ordered chain with hosts only (not full query strings) and the final URL. Indicators: REDIRECT_CHAIN_LONG, REDIRECT_CROSS_DOMAIN, REDIRECT_TO_SHORTENER.
   - DOM audit with BeautifulSoup on `page.content()`: forms whose `action` host differs from the page host, forms posting over http, password fields, input fields whose name/placeholder/label suggest OTP, UPI PIN, card number, CVV or Aadhaar, hidden iframes, meta-refresh redirects, and login-like forms on a domain whose age is under 30 days (use the fast-path domain info). Indicators: FORM_POSTS_TO_DIFFERENT_DOMAIN, SENSITIVE_FIELD_REQUESTED, HIDDEN_IFRAME, etc.
   - Screenshot: capture a 1280x720 viewport PNG IN MEMORY, compute `imagehash.phash`, and discard the image. Never write screenshots to disk or the DB. Store only the hex hash in `sandbox_indicators`. (Brand comparison arrives in Chunk 7.)
4. Docker hardening in `docker-compose.yml` for the worker: non-root user, Chromium's own sandbox enabled if the image/user setup allows it (follow Playwright's Docker docs, using the recommended seccomp profile; if `--no-sandbox` is unavoidable, document it in the README as a residual risk), memory and CPU limits, a tmpfs for /tmp. Add a README section "Sandbox threat model" (in link-security-analyzer/README.md) that states the residual risks honestly: DNS rebinding between the check and the connection, and that the worker shares a Docker network with Redis and Postgres, with a recommended egress firewall rule for production.

Tests: unit-test the netguard integration (the route handler aborts internal addresses and non-http schemes) and the DOM audit functions against local HTML fixtures. Add an `@pytest.mark.integration` test that scans a local test server with a redirect chain and a cross-domain form (the local server must be allowed only via an explicit test flag that is OFF by default and impossible to enable via environment in production mode).

CLOSE-OUT (mandatory): Append Chapter 6 "The background browser sandbox" to docs/PROJECT_JOURNAL.md and update the table of contents. It must specifically explain in plain words: why some signals need a real browser (redirects, hidden forms and what a page actually asks for are invisible from the link alone); what a sandbox is (a disposable room with a locked door that is thrown away after each visit); what Celery and a message queue are (a restaurant order ticket: the waiter, the kitchen, the ticket rail) and why the heavy work is done in the background; step by step what the worker does for one scan; what we deliberately do NOT do (no screenshots saved, no downloads, no internal addresses); a threat model table (threat | what we did | residual risk) including the honest residual risks (DNS rebinding, shared Docker network, whether Chromium's own sandbox was enabled or `--no-sandbox` was needed, with the real answer from your run). Diagrams: a sequenceDiagram of API, queue, worker, browser, database, and a flowchart of the per-request netguard check inside the browser. Record real test counts, whether the integration test ran, and any Playwright or Docker problems and how they were fixed. Then commit `chunk-6: playwright sandbox worker` and push.
````

### Chunk 7: Brand references and pHash

````
Read AGENTS.md first and follow its Documentation Protocol and Git Protocol. All paths are relative to link-security-analyzer/. This is Chunk 7: visual brand matching. Depends on Chunks 2 and 6.

1. `backend/data/brand_seed.yaml`: brands with name, official_domain(s), and the official page URL to fingerprint. Include: SBI (onlinesbi.sbi), HDFC Bank (hdfcbank.com), ICICI Bank (icicibank.com), Axis Bank (axisbank.com), PhonePe (phonepe.com), Paytm (paytm.com), Flipkart (flipkart.com), Amazon India (amazon.in), IRCTC (irctc.co.in), UIDAI (uidai.gov.in), India Post (indiapost.gov.in), Income Tax e-filing (incometax.gov.in). Verify each domain actually resolves and loads; mark any that fail or need human review in the script output instead of silently guessing.
2. `backend/scripts/seed_brands.py`: for each brand, load the official page through the SAME sandbox routine and netguard rules, take the viewport screenshot in memory, compute pHash, and upsert into `brand_references`. Support multiple reference hashes per brand (e.g. desktop landing page and login page) and a `--refresh` flag. Print a table of brand, domain, hash, and status.
3. In the sandbox task: after computing the page's pHash, compare to every `brand_references` row with Hamming distance (XOR popcount over the 64-bit hash). If distance <= PHASH_DISTANCE_THRESHOLD and the page's registered domain is NOT one of the brand's official domains, add indicator `VISUAL_BRAND_IMPERSONATION` (severity high) with evidence {brand, distance, threshold}. Otherwise no indicator. Also add a low-severity `VISUAL_SIMILARITY_WEAK` only if the distance is within threshold + 4.
4. Messages must say "the page layout resembles the <brand> reference, but the domain is not the brand's official domain", never "this is a fake <brand> site".
5. Tests: hamming distance function, threshold logic, official-domain exclusion, and a fixture-based test using two locally generated images (one slightly perturbed) to verify near and far distances. Document in link-security-analyzer/README.md that full-page pHash is fragile (cookie banners, A/B tests, dynamic content), so this pillar is a supporting signal only.

CLOSE-OUT (mandatory): Append Chapter 7 "Spotting look-alike pages (visual brand check)" to docs/PROJECT_JOURNAL.md and update the table of contents. It must specifically explain in plain words: the idea (a copycat page looks like the real one even when its address is different); what a perceptual hash is (shrink the picture to a tiny blurry thumbnail and write down its light and dark pattern, like a fingerprint that survives small changes); what Hamming distance means with a small worked example of two short bit strings; why the threshold is 10 and what moving it does (more catches versus more false alarms); why we compare against the official domain list; why the wording is careful ("resembles", never "fake"); the real results of the seeding script as a table (brand | status | notes, including any brand that failed or needed review); why this is the weakest of the three pillars and the honest reasons (cookie banners, A/B tests, dynamic content). Diagrams: a flowchart from screenshot to hash to comparison to indicator, and a small illustration (table or diagram) of near versus far hashes. Record real test counts. Then commit `chunk-7: brand fingerprints and visual matching` and push.
````

### Chunk 8: Next.js frontend

````
Read AGENTS.md first and follow its Documentation Protocol and Git Protocol. All paths are relative to link-security-analyzer/. This is Chunk 8: the frontend, in `frontend/` (Next.js 14 App Router, TypeScript, Tailwind, lucide-react, SWR). Backend contracts are in `backend/app/api/v1/schemas.py`; read them and generate matching TypeScript types in `frontend/src/lib/api.ts`.

1. `frontend/src/lib/api.ts`: typed client for `POST /api/v1/scan` and `GET /api/v1/scan/{id}`, base URL from `NEXT_PUBLIC_API_BASE_URL`, with error handling for 422 and 429 (show the Retry-After value).
2. `frontend/src/app/page.tsx`: landing page with one input box and three labeled helper hints (URL, UPI link, pasted QR text). Client-side validation (non-empty, max 2048 chars). On submit, call the API and navigate to `/report/[id]`. Include a short plain-language privacy note: what is sent (the pasted link/text), that screenshots are not stored, and that results are advisory only.
3. `frontend/src/app/report/[id]/page.tsx`: poll with SWR every 1.5s until status is COMPLETED or FAILED, stop after 60s and show partial results with a note. Layout: overall indicator banner at top, `AnalysisProgress` stepper (Fast checks, Sandbox analysis, Report), then three pillar cards (technical URL, visual brand, transaction context).
4. `components/ThreatCard.tsx`: shows pillar title, status chip (NOT_APPLICABLE gray, NO_INDICATORS neutral blue, FLAGGED amber or red by max severity, UNAVAILABLE gray with a tooltip, PENDING with a spinner), and the indicator list (message, severity, expandable evidence). `components/AnalysisProgress.tsx`: live stepper driven by the status.
5. Wording: follow AGENTS.md rule 8 everywhere; footer text: "Indicators are automated signals, not a verdict. When in doubt, don't pay or log in; contact the organization using its official number." Add the national cybercrime helpline and portal references only if you can verify them from an official source; otherwise leave a clearly marked placeholder.
6. Accessibility and states: keyboard-navigable, color is never the only signal (icons and text labels), loading, empty, and error states for every view, responsive down to 360px.
7. Add the real frontend Dockerfile and wire the service into docker-compose.

Done when: the full flow works against the running backend. Add a small component test (Vitest or Jest, your choice, pin versions) for ThreatCard status rendering.

CLOSE-OUT (mandatory): Append Chapter 8 "The web interface" to docs/PROJECT_JOURNAL.md and update the table of contents. It must specifically explain in plain words: the user's journey step by step (paste, wait, read the result); why the page polls (asks "is it done yet?" every 1.5 seconds) and what happens at 60 seconds; what each pillar card shows and how to read the status chips and severity; the wording and privacy decisions and why (never "safe", the privacy note, no screenshot storage); the accessibility choices (color never the only signal, keyboard use, 360px width); whether the helpline reference was verified or left as a placeholder, and why. If you can run the app and capture screenshots of OUR OWN UI using a placeholder input such as example.com, save them in docs/img/ (small PNGs) and embed them; otherwise say they were not captured. Diagrams: a flowchart of the user journey and a sequenceDiagram of the polling loop. Record real test counts and the result of the full end-to-end run. Then commit `chunk-8: next.js frontend` and push.
````

### Chunk 9: Evaluation, docs and final recap

````
Read AGENTS.md first and follow its Documentation Protocol and Git Protocol. All paths are relative to link-security-analyzer/ unless stated. This is Chunk 9: evaluation and documentation. Do not change detection logic in this chunk; if you find a bug or false-positive pattern, list it in the report instead of silently tuning thresholds.

1. `eval/build_dataset.py`: build a labeled URL set. Malicious: OpenPhish community feed and URLhaus (and PhishTank only if an API key is configured); benign: a random sample from Tranco ranks 1k to 100k (NOT only the top 1k). Check each source's license/terms and print them. Deduplicate, then SPLIT BY REGISTERED DOMAIN (never random by URL) into train/dev/test with a fixed seed; write the test split to `eval/data/test_locked.csv` and add a header comment plus a README line: the locked test split must not be used for tuning. Raw downloads go to `eval/data/raw/` (git-ignored).
2. `eval/run_eval.py` with two modes: `--offline` (lexical + UPI only, no network) and `--online` (adds infrastructure and threat feeds, rate-limited, resumable). Output: for each indicator code, hit rate on malicious vs benign (so you can see which indicators actually help), and for the heuristic score: precision/recall/F1 and false-positive rate at several thresholds, plus a precision-recall curve saved as PNG and a CSV of the worst 25 false positives and 25 false negatives for manual review.
3. Include a small hand-labeled Indian-context set at `eval/data/india_manual.csv` (30+ rows you can seed from the sample cases in tests: UPI links, KYC lures, shortened links; mark every row `synthetic=true`) and report its metrics separately, clearly labeled as synthetic.
4. `link-security-analyzer/README.md`: architecture diagram (Mermaid) of the fast path, async sandbox, and storage; a plain-English explanation of each pillar and indicator for non-technical teammates and judges; the data-flow privacy statement; the sandbox threat model; how to run, test, and evaluate; the integration contract for other modules (how to call `run_fast_path`, the `signal_vector` fields, and the heuristic-score caveat); a "known limitations" section (full-page pHash fragility, WHOIS/RDAP gaps, rules-only scoring, DNS rebinding residual risk).
5. Update the repo-root README.md with a quick start and a link to docs/PROJECT_JOURNAL.md.
6. Final report: full pytest output, the eval summary table, and the three biggest weaknesses the evaluation exposed.

CLOSE-OUT (mandatory): Append Chapter 9 "Does it actually work? (evaluation)" and then a final Chapter 10 "Whole-system recap and demo guide" to docs/PROJECT_JOURNAL.md and update the table of contents. Chapter 9 must specifically explain in plain words: what precision, recall and false-positive rate mean using a simple everyday example with made-up numbers, and why a scam checker that cries wolf is also a failure; why we split by domain and not by link (tell the leakage story: if one domain's links land in both train and test, the score is fake); where the data came from and each source's license note; the REAL results as tables (per-indicator hit rates on malicious versus benign, metrics at several thresholds, the synthetic Indian set shown separately and labeled); which indicators helped and which did not; the worst false positives and false negatives with a plain explanation of why each happened; the three biggest weaknesses, honestly. Chapter 10 must contain: a Mermaid end-to-end diagram of the finished system; a step-by-step demo script (what to paste, what the judges will see, what to say); a "likely judge questions" section with at least 10 questions and honest answers (including "why not just use Google Safe Browsing?", "what about false alarms?", "how do you stop your server being attacked by hostile links?", "what is the score and can I trust it?"); and a "what we would do next" list that includes training a model on the stored signal_vector and combining Module A with the text-scam engine. Then commit `chunk-9: evaluation, documentation and final recap` and push.
````

When each chunk finishes, read its journal chapter on GitHub (the Mermaid diagrams render there). If a diagram shows a syntax error, tell me which one. At the end of the day, paste any section you found hard to follow and I'll quiz you on it.
