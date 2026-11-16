# AI Coding Tool Prompts — Link Analyzer Rebuild (13 phases + 1 optional)

Companion to `LINK_ANALYZER_PROJECT_SPEC.md`. The spec says *what* and *why*; this file says *do it, in this order*.

## How to use this file

1. Put `LINK_ANALYZER_PROJECT_SPEC.md` into the repo at `docs/` **before Phase 0** (the prompts tell the tool to read it).
2. Give the tool **one phase prompt at a time**, in order. Do not skip. Do not paste two phases together.
3. Each phase ends with a **Closeout** (append a journal chapter, commit, push). Before pasting the next phase, check three things yourself (2 minutes):
   - GitHub shows the new commit and tag `phase-N-done`.
   - The journal has a new `Chapter R<N>` at the bottom.
   - The "Acceptance" commands in the phase printed what they should.
4. If a phase fails its acceptance, paste the tool's error back and say: *"Fix this, do not move on, then redo the Closeout."* Never ask the tool to "just continue".
5. **Minimum working cut** if time is short: Phases 0 → 1 → 2 → 3 → 4 → 5 → 8 → 10. Then 6, 7, 9, 11, 12.
6. Phase 0 installs the rules below into `AGENTS.md`, so later prompts only say "follow the Rebuild Rules". If your tool ignores `AGENTS.md`, paste Section A at the top of every prompt.

---

## Section A — Rebuild Rules (Phase 0 copies this into `AGENTS.md`)

````text
REBUILD RULES (apply to every phase)

R1. Read first. At the start of every phase read: AGENTS.md, docs/LINK_ANALYZER_PROJECT_SPEC.md, the last two chapters of the project journal, and docs/DIAGNOSIS.md (once it exists). Do not redesign anything the spec already decides. If you believe the spec is wrong, say so in the journal and ask; do not silently deviate.

R2. Honesty over appearance. Never fake a result, never hard-code expected outputs to make a test pass, never claim something ran if it did not. If something could not be run (no Docker, no network, no API key), write exactly that in the journal ("not run: reason"). Numbers in documents must come from a script output that is committed.

R3. One phase at a time. Do only the current phase. Do not start the next one. Small, readable commits are fine inside a phase; the phase ends with the Closeout.

R4. Resilience principle. Every external dependency (network, API, file, browser) is wrapped with a timeout and returns a structured "unavailable" result instead of raising into the scan. A single failing check must never make the whole scan fail or become "Inconclusive".

R5. Security principle. User links are hostile. All outbound requests go through netguard. Never enter data into pages. Never log secrets or full query strings. Never commit .env, API keys, feed dumps, or screenshots. Add or keep .gitignore entries.

R6. Tests. Write tests with the code. Before closeout run the full backend test suite and the linter (ruff) and report the real counts. Do not delete or weaken existing tests; if a test must change, explain why in the journal.

R7. Backward compatibility. Keep existing endpoints working unless the phase says otherwise. Add fields; do not rename existing ones silently.

R8. Environment. Python dependencies go in the project's existing dependency file with pinned versions. Everything must run through the existing docker compose. Document every new env var in .env.example (placeholders only).

R9. PHASE CLOSEOUT PROTOCOL (mandatory, last step of every phase):
  a) Run: tests, ruff, and the phase's Acceptance commands. Capture the real outputs.
  b) APPEND one chapter to the end of the project journal (find it: docs/PROJECT_JOURNAL.md; if elsewhere, use the existing one; never create a second journal; never rewrite earlier chapters except to add the new chapter's link to the Table of Contents). Chapter heading: "## Chapter R<phase number>: <title>" then a line "Date: <YYYY-MM-DD> | Commit message: <message>". Use exactly these sections, in this order, same style as earlier chapters (plain words first, jargon defined):
     1. In one minute
     2. Why we did this
     3. How it works (include a mermaid diagram when the phase changes the flow, and a one-line caption starting with "Notice")
     4. Decisions and reasoning (table: decision | options considered | why we chose this | trade-off)
     5. What we built (files created/changed, one line each)
     6. What actually happened (real test counts, real command outputs summarized, mistakes made and how they were fixed, anything NOT run and why)
     7. Limits and honest weaknesses
     8. How to explain this to a judge in 30 seconds
     9. New terms
     Every chapter must explicitly answer: WHAT was done, WHY, and HOW.
  c) Git: work on branch rebuild/phase-<N>-<short-name>. Commit with message "phase-<N>: <summary>". Then: git push -u origin <branch>; merge into main with --no-ff; git push origin main; create tag phase-<N>-done and push it (git push origin phase-<N>-done).
  d) If push fails (no remote, auth), do NOT try to store credentials or tokens. Stop, print the exact commands the human must run, and record "push pending" in the journal.
  e) End your final message with: a 5-line summary, the test counts, the commit hash, the tag, and "NEXT PHASE: <N+1>" (do not start it).
````

---

## Phase 0 — Diagnose, baseline, GitHub, install the rules

````text
You are working on the TrueIntent project, Module B (link-security-analyzer). It is reported as "not working at all": results are Inconclusive/Unavailable. We are doing a full rebuild to a WORKING product. Read docs/LINK_ANALYZER_PROJECT_SPEC.md (put it in docs/ if the human has not; it is provided alongside this prompt) and the existing project journal first.

GOAL: find out exactly why it does not work today, get the stack running, put the repo on solid Git/GitHub footing, and install the Rebuild Rules.

TASKS
1. Git/GitHub: run git status, git remote -v, git branch -a. Report whether a GitHub remote named origin exists and whether main exists. If origin is missing, do not invent one: print the commands the human should run (gh repo create or git remote add origin <url>) and continue locally. Make sure .gitignore covers .env, *.joblib only if large (decide), data/raw/, node_modules, __pycache__, .venv, screenshots/, *.log.
2. Install the rules: copy Section A "REBUILD RULES" (the text block provided with this prompt pack, AI_CODING_PROMPTS.md) into AGENTS.md under a heading "Rebuild Rules", keeping existing content. Also copy LINK_ANALYZER_PROJECT_SPEC.md into docs/ if absent.
3. Bring the stack up: docker compose up --build for postgres, redis, backend, worker. If Docker is unavailable on this machine, say so clearly and run the backend and tests locally instead; record exactly what could not be verified.
4. Reproduce the failure: send POST /api/v1/scan for https://example.com, https://www.google.com, http://sbi-secure-login-verify.xyz/ and a upi://collect?pa=test@ybl&am=5000&tn=refund link. Save each full JSON response under docs/diagnosis/ (no secrets).
5. Diagnose with evidence, one by one: (a) is app.core.lexical a stub; (b) are GSB/VT keys missing; (c) do RDAP/WHOIS lookups time out and why (which TLDs, which timeouts); (d) does the Celery worker start and consume tasks; (e) is Chromium actually installed in the worker image and does a minimal Playwright launch + goto + screenshot of https://example.com work inside the container; if not, capture the exact error; (f) does the score/summary logic turn any single unavailable check into Inconclusive; (g) which tests exist and do they all pass.
6. Add GET /api/v1/health returning JSON: db ok, redis ok, worker ping ok, playwright launch ok (cached 60 s), feeds status (empty for now), app version, git commit if available. Each part wrapped with a short timeout.
7. Write docs/DIAGNOSIS.md: a table "Symptom | Evidence (command + output excerpt) | Root cause | Fix planned in phase N". Do not fix the causes in this phase except the Docker/Playwright installation if it is a trivial image problem (if you fix it, say so).

ACCEPTANCE
- docs/DIAGNOSIS.md exists with evidence for each of (a)-(g).
- GET /api/v1/health works and honestly reports playwright status.
- The existing test suite result is reported with real counts.
- AGENTS.md contains the Rebuild Rules.

CLOSEOUT: Follow R9. Chapter title: "Chapter R0: Why it did not work, and the rules for the rebuild". Commit message: "phase-0: diagnosis, health endpoint, rebuild rules". Branch: rebuild/phase-0-diagnosis. In the journal, include the full diagnosis table in section 6 and a mermaid diagram of the planned 13-phase rebuild in section 3.
````

---

## Phase 1 — Resilient check runner and verdict skeleton

````text
Follow the Rebuild Rules in AGENTS.md. Do only Phase 1.

GOAL: make it structurally impossible for one failing check to ruin a scan, and introduce the verdict skeleton (see spec sections 8, 9, 12).

TASKS
1. Create app/core/runner.py with the check contract from the spec: dataclasses/Pydantic models CheckResult(name, status in {ok, unavailable, skipped}, signals, detail, reason, took_ms) and Signal(id, points, severity, explain, evidence). Provide async run_checks(checks, ctx) that runs checks concurrently with a per-check timeout (asyncio.wait_for), catches ALL exceptions (including CancelledError from timeouts) and converts them to unavailable results with reason "timeout" or "error:<ExceptionName>" (never include secrets in reason). Add a decorator @check(name, timeout_s, group) where group is one of: lexical, reputation, infrastructure, external_reputation, sandbox, visual, transaction.
2. Create app/core/verdict.py with: compute_coverage(results) -> {completed:[groups], unavailable:[{group,reason}], level: low|medium|high}; and a TEMPORARY simple scorer: risk_score = clamp(sum(points),0,100); verdict mapping per spec 9.3 (DANGEROUS >=70 or hard override signal; SUSPICIOUS 35-69; LIKELY_SAFE <35 with minimum coverage; otherwise UNKNOWN). Keep the thresholds in a config module, not hard-coded inline.
3. Wire the EXISTING checks (netguard, UPI parser, whatever currently produces indicators) into the runner without changing their logic: wrap each as a check. The scan service must now always produce: verdict, risk_score, risk_score_note ("Heuristic risk score, not a probability."), coverage, reasons (from signals, template text), checks[] (name, status, took_ms, reason). Keep the old "pillars" fields working (R7).
4. Replace any logic that returns Inconclusive because one check was unavailable. A scan where everything but the UPI parser failed must return UNKNOWN with coverage low, not an error.
5. Write the "fast then final" status model (spec section 7): statuses fast_running, fast_done, sandbox_queued, sandbox_running, complete, complete_partial, rejected, error. Persist status transitions; the GET poll shows phase "fast" or "final".
6. Tests (new): (a) a check that sleeps beyond its timeout -> unavailable/timeout and the scan still completes; (b) a check that raises -> unavailable/error; (c) all checks unavailable -> UNKNOWN; (d) hard override -> DANGEROUS; (e) coverage computed correctly; (f) reasons ordered by points; (g) concurrency: 5 checks of 1 s each finish in about 1 s total.

ACCEPTANCE: new tests pass; old tests pass (or are adapted with explanations); POST+GET for a UPI link and for https://example.com return a verdict object (it may be UNKNOWN for now) and a non-empty checks[] with honest statuses.

CLOSEOUT: R9. Chapter title: "Chapter R1: One broken check can no longer break the scan". Commit: "phase-1: resilient check runner and verdict skeleton". Branch: rebuild/phase-1-runner. The decision table MUST record the reversal of the earlier "indicators, not verdicts" decision (spec 3.4) with reasoning and the honesty safeguards (UNKNOWN state, coverage, non-probability note).
````

---

## Phase 2 — Real lexical analysis, typosquat detection, brand list

````text
Follow the Rebuild Rules. Do only Phase 2. Spec sections 8 (Stage 0, 1, 6) and Appendix A apply.

GOAL: replace the stubbed app.core.lexical with a real analyzer and add brand/typosquat logic. Everything here is offline and fast.

TASKS
1. Input router hardening (app/core/router.py): trim, strip zero-width/control characters, length cap 2048, classify url / bare_domain / upi / unsupported_scheme / invalid. Normalize host (lowercase, IDNA: keep raw punycode for analysis and a decoded display form), drop default ports. Use tldextract with the Public Suffix List INCLUDING private suffixes to compute registrable_domain (so abc.github.io and x.vercel.app are separate sites). Ensure tldextract does not make network calls at runtime (bundle or cache the suffix list; document how).
2. Implement app/core/lexical.py producing: (a) a numeric feature dict (url_len, host_len, path_len, entropy of registrable label, digit_count, hyphen_count, dot_count, subdomain_count, has_ip_host incl. decimal/hex/octal IP forms, has_at, has_punycode, tld, tld_risk_bucket, is_https, port_nonstandard, keyword_counts, is_shortener) and (b) Signals for every row of spec Stage 1 table with the starter weights. All must be pure functions with no network.
3. Brand data: create app/core/brands.yaml with 25-30 brands from spec Appendix A using the schema in spec 22. VERIFY each official domain by fetching the brand's official homepage in a normal way if network is available; where you cannot verify, mark verified: false and list them in the journal. Create app/core/brands.py to load it.
4. Typosquat engine: compare the normalized registrable label (and each subdomain label) to brand labels/keywords using rapidfuzz or Levenshtein; apply a confusable map (rn->m, vv->w, 0->o, 1->l, l->i variants, cyrillic/greek homoglyphs via unicode normalization/confusables if available); emit TYPOSQUAT_BRAND, BRAND_IN_SUBDOMAIN, BRAND_IN_PATH. Official domains and their legitimate subdomains must NEVER trigger (e.g. netbanking.hdfcbank.com, www.sbi.co.in, pay.google.com).
5. Shortener list and risky TLD list as data files (yaml/txt), easy to edit.
6. UPI parser polish: verify upi://pay and upi://collect parsing, intent:// variants, percent-decoding, missing fields, absurd lengths; produce signals from spec Stage 6.
7. Register lexical, brand and UPI checks in the runner with group "lexical" (and "transaction" for UPI), timeout 0.5 s.
8. Tests: a table-driven file with at least 80 URLs: 25 clearly benign (including Indian bank/government sites and shared-hosting subdomains), 25 clearly suspicious (typosquats, IP hosts, punycode, @ tricks, keyword-stuffed hosts), 15 tricky borderline, 10 UPI links, 5 malformed. Assert the specific signal ids expected, not just "flagged". Include false-positive guards.

ACCEPTANCE: tests pass; the scan of http://sbi-secure-login-verify.xyz/ now returns SUSPICIOUS or higher using ONLY offline checks; https://www.sbi.co.in/ returns no lexical risk signals; app.core.lexical is no longer a stub (show by a test).

CLOSEOUT: R9. Chapter title: "Chapter R2: Reading the address itself (spelling, look-alikes, brands)". Commit: "phase-2: lexical analyzer, typosquat engine, brand list". Branch: rebuild/phase-2-lexical. List unverified brand domains in section 7.
````

---

## Phase 3 — Local reputation data: Tranco and phishing feeds

````text
Follow the Rebuild Rules. Do only Phase 3. Spec sections 8 (Stage 2a), 9.2, 10.

GOAL: give the system offline knowledge: popularity (Tranco) and known-bad lists (OpenPhish, URLhaus, optionally others), with honest freshness reporting.

TASKS
1. scripts/download_feeds.py: downloads (a) Tranco top-1M list (use the official tranco-list.eu download; record the list id/date), (b) OpenPhish community feed, (c) URLhaus data (CHECK the current access method and terms: if it needs a free abuse.ch Auth-Key, read it from env ABUSECH_AUTH_KEY and skip gracefully if absent), (d) optionally Phishing.Database or PhishTank if freely accessible (verify license and signup requirements first; skip if unclear and say so). For each source write to data/raw/ (gitignored) and record source, fetched_at, row_count, license_note in a feed_meta table. Handle failures per source; never crash the whole script. Use httpx with timeouts; identify with a polite User-Agent; respect rate limits.
2. Storage: Alembic migration (or the project's existing migration approach) creating tables: tranco_rank(registrable_domain PK, rank), blocklist_entries(id, url_norm, registrable_domain, source, first_seen, fetched_at, threat_type), feed_meta. Add indexes on registrable_domain and url_norm. Loading must be idempotent and handle 1M rows efficiently (bulk COPY/executemany; report time taken).
3. app/core/reputation.py: lookups wrapped as runner checks (group "reputation", timeout 1 s): popularity signals POPULAR_TOP_10K/100K/1M; BLOCKLIST_URL_HIT (exact normalized URL, critical) and BLOCKLIST_DOMAIN_HIT (registrable domain match, high — but NEVER for shared-hosting suffixes where the registrable domain is a platform: maintain a shared_hosting_suffixes list and match only the full host in that case). URL normalization for matching: lowercase host, strip fragment, optionally strip tracking params, trailing slash handling — test it.
4. Shared-hosting rule: domains under github.io, vercel.app, blogspot.com, netlify.app, pages.dev, web.app, firebaseapp.com, herokuapp.com, weebly.com, wixsite.com, etc. are NEVER given popularity credit.
5. Add feed status into GET /api/v1/health and GET /api/v1/feeds/status (counts, fetched_at, age in hours, stale flag if >48 h).
6. Add a scheduled refresh (Celery beat or documented cron) and a make/CLI target. Do not auto-download on container start without a flag, to keep tests offline.
7. Tests with small fixture feeds (do not download in tests): popularity buckets, blocklist exact and domain hits, shared-hosting exclusion, normalization, stale feed flag, missing table/empty data -> check returns unavailable (reason "feed_empty") rather than OK.

ACCEPTANCE: after running the download script (if network allowed) report row counts; scanning https://www.google.com shows POPULAR_TOP_10K; scanning a URL taken from today's OpenPhish feed returns BLOCKLIST_URL_HIT and verdict DANGEROUS; if the network is not available, say so and prove the logic with fixtures.

CLOSEOUT: R9. Chapter title: "Chapter R3: Remembering the good and the bad (popularity and blocklists)". Commit: "phase-3: tranco and phishing feed reputation". Branch: rebuild/phase-3-reputation. Journal must list each feed's actual terms/limits you observed and any that were unavailable.
````

---

## Phase 4 — Infrastructure checks and optional external reputation

````text
Follow the Rebuild Rules. Do only Phase 4. Spec section 8 (Stage 2b, 2c).

GOAL: domain age that actually works, DNS and TLS facts, and optional Google Safe Browsing / VirusTotal that degrade gracefully.

TASKS
1. app/core/infra.py RDAP domain age: load the IANA RDAP bootstrap (data.iana.org/rdap/dns.json) with a cached copy; query the TLD's RDAP server with httpx (follow redirects, max 4 s); parse the "registration" event date (and "last changed"); handle ccTLDs without RDAP by falling back to a redirector (rdap.org) then python-whois in a thread with a hard timeout. Cache successes 7 days and failures 1 hour in Redis. Signals DOMAIN_AGE_LT_7D/30D/90D, DOMAIN_AGE_GT_2Y, DOMAIN_AGE_UNKNOWN (weak +3). Record which source answered. Use recorded JSON fixtures in tests (.com, .in, .co.in, .xyz, .io, and a not-found case).
2. DNS check (dnspython async or thread pool): A/AAAA/NS/MX with 2 s budget; if any resolved IP is blocked by netguard, the scan becomes rejected (not scored). Signals NO_DNS_RESOLUTION etc.
3. TLS check using ssl with a 3 s timeout, only for https URLs and only to validated IPs: issuer, notBefore, notAfter, SAN match. Signals TLS_CERT_NEW_LT_7D, TLS_HOST_MISMATCH, TLS_EXPIRED, NO_TLS. Do not penalize Let's Encrypt.
4. app/core/threatintel.py: Google Safe Browsing Lookup API v4 (key GSB_API_KEY) and VirusTotal (VT_API_KEY) existing-report lookup by URL id; DO NOT upload URLs for scanning. Redis cache 24 h; a token-bucket limiter for VT sized to its current free limits (verify them and write the values you verified into the journal). No key -> check status unavailable with reason "no_api_key" (not an error, not scary). Signals GSB_THREAT (critical), VT_MALICIOUS_GE3 (high), VT_MALICIOUS_1_2.
5. Register all as runner checks: infrastructure group (RDAP 4 s, DNS 2 s, TLS 3 s), external_reputation group (3 s). They run in parallel with the offline checks; the fast verdict (v0) must return within ~3 s even if RDAP is slow (use whatever finished within the budget; late results can be added to the final verdict).
6. Add small sample .env.example entries (placeholders) and a docs/KEYS.md explaining, in beginner words, how to get the free GSB and VT keys and that the product works without them.
7. Tests: mocked responses for every provider; malformed JSON; 429 rate limit; timeout; no key; cache hit avoids a second call; netguard rejection via DNS result.

ACCEPTANCE: run live checks (if network allowed) on google.com, a 2-year-old .in domain, and a very new domain; report real domain ages and sources used. Run the scan with NO keys and show it still returns a verdict with external_reputation unavailable. Show timings.

CLOSEOUT: R9. Chapter title: "Chapter R4: Who owns this domain, how old is it, and what do others say". Commit: "phase-4: rdap age, dns, tls, optional gsb and virustotal". Branch: rebuild/phase-4-infra. Record real RDAP success rate by TLD from your live runs in section 6.
````

---

## Phase 5 — A sandbox that really works

````text
Follow the Rebuild Rules. Do only Phase 5. Spec section 8 (Stage 3) and 15.

GOAL: Playwright/Chromium visits a page safely inside Docker and returns usable facts. The Phase 0 diagnosis says why it failed before; fix the root cause properly.

TASKS
1. Docker: base the worker image on the official Playwright Python image matching the pinned playwright version (browsers preinstalled), or run playwright install --with-deps chromium at build time. Run as a non-root user. Set memory/cpu limits, shm_size or --disable-dev-shm-usage, and the minimum necessary flags. If --no-sandbox is unavoidable inside Docker, document the trade-off and compensate with container hardening (non-root, cap_drop ALL, no secrets, network isolation).
2. Network isolation: place the worker's browser traffic where it cannot reach Postgres/Redis (separate Docker network for the browser process, or firewall rules via compose), and say honestly what is and is not achieved.
3. app/sandbox/browser.py: async function visit(url, budget_s=15) that: creates a FRESH context per scan (no storage, no cookies, downloads blocked, permissions denied, viewport 1366x768, locale en-IN), installs route interception that sends every request through netguard (initial and redirects and subrequests) and enforces caps (<=150 requests, <=8 MB, <=10 redirects), navigates with domcontentloaded plus a <=3 s settle, then returns a typed result: final_url, redirect_chain[{url,status}], http_status, title, rendered_html (capped ~500 KB), response headers subset, contacted_hosts with third_party_ratio, screenshot_png bytes (in memory), favicon bytes (best effort), download_attempted flag, blocked_requests list, timings, errors. NEVER click or type.
4. Celery task run_sandbox(scan_id): loads the scan, calls visit, stores a compact result (no raw HTML yet beyond what Phase 6 needs; store screenshot as a temp file under an artifacts dir with a TTL timestamp), updates status transitions (sandbox_queued -> sandbox_running -> complete/complete_partial). Sandbox failure -> check status unavailable with a specific reason (timeout, dns, ssl_error, blocked_by_netguard, browser_crash) and the scan completes partially.
5. Playwright browser reuse: launch one browser per worker process, one context per scan; recycle the browser after N scans or on crash. Worker concurrency default 1-2 (env).
6. Local test server fixture (tests only, ALLOW_TEST_LOOPBACK=true via test settings, never in compose defaults) hosting: benign page, page with delayed JS-rendered form, redirect chain (3 hops), page that triggers a download, slow page (>20 s), page that redirects to http://169.254.169.254/, page with 200 requests. Integration tests assert the sandbox behaviour for each (the metadata redirect MUST be blocked and reported).
7. /health shows playwright ok with real launch test.

ACCEPTANCE: from the running compose stack, scanning https://example.com returns a final_url, title "Example Domain", a screenshot file, and contacted_hosts; scanning the local slow page ends in a timeout reason within ~16 s without hanging the worker; the metadata-IP redirect test passes. Paste actual outputs. If you cannot run Docker, state it plainly and run the same tests locally.

CLOSEOUT: R9. Chapter title: "Chapter R5: The locked room that actually opens pages". Commit: "phase-5: working playwright sandbox with netguard and caps". Branch: rebuild/phase-5-sandbox. Section 6 must include the root cause fix of the earlier failure and measured memory use per scan.
````

---

## Phase 6 — DOM analyzer (forms, payments, brands, urgency, trust)

````text
Follow the Rebuild Rules. Do only Phase 6. Spec section 8 (Stage 4).

GOAL: turn the rendered page into meaningful signals using BeautifulSoup with lxml. (BeautifulSoup parses the rendered HTML Playwright returns; it does NOT replace Playwright.)

TASKS
1. app/sandbox/dom_analyzer.py: pure function analyze(html, page_url, final_url, headers, brands) -> list[Signal] + evidence dict. Implement every signal in the spec Stage 4 table: HAS_PASSWORD_FIELD, HAS_CARD_FIELDS, HAS_UPI_ID_FIELD, HAS_OTP_PIN_FIELD, FORM_POSTS_CROSS_DOMAIN (resolve relative actions against the final URL; compare registrable domains), FORM_POSTS_TO_HTTP, FORM_ACTION_EMPTY_OR_JS, BRAND_TEXT_DOMAIN_MISMATCH (title/h1/h2/alt/logo filenames/meta og:site_name vs brands.yaml and the page's registrable domain), HIDDEN_IFRAME, META_REFRESH_REDIRECT, URGENCY_LANGUAGE (English plus Hinglish/Hindi phrases in a data file), OBFUSCATED_JS, RIGHT_CLICK_DISABLED, NO_TRUST_PAGES, RECOGNIZED_GATEWAY (Razorpay, Stripe, PayU, Cashfree, PayPal, Paytm gateway — detect by script src/form action on the gateway's official domains), AUTO_DOWNLOAD_ATTEMPT (from sandbox flag), PAGE_UNREACHABLE, REDIRECT_CHAIN_CROSS_DOMAIN.
2. Implement the three COMBINATION rules from the spec (credential-or-payment on young domain; payment without known gateway; brand look-alike on foreign domain). Combination rules take the other checks' signals as input, so implement them in the scoring layer interface (a function that receives all signals) and test them there.
3. Evidence extraction for the UI: list of forms {action_domain, method, fields[{type,name_or_label}]}, third-party script domains, top external links, detected brands, contact/privacy/terms link presence, a 300-char visible text excerpt (escaped, no scripts).
4. Treat all page content as untrusted: size caps, parser timeouts, never execute anything, escape on output.
5. Wire it as a runner check in group "sandbox" that runs after visit().
6. Fixtures and tests: create at least 18 HTML fixtures under tests/fixtures/dom/: plain blog; legit shop with Razorpay checkout; fake bank login with cross-domain form; fake KYC page with Aadhaar/PAN/OTP fields; UPI collect-harvesting page; hidden iframe; meta refresh; urgency text in English and Hinglish; no-trust-pages page; obfuscated script; legit login on same domain (should NOT trigger cross-domain); legit bank page on an official domain mentioning its own brand (should NOT trigger mismatch); a page with a password field only (low points alone); shadow of a forum with the word "bank" in text only; non-English page; huge page; malformed HTML. Assert the exact signals.
7. False-positive review: for each legit fixture assert that total points stay below the SUSPICIOUS threshold when combined with typical benign infra signals.

ACCEPTANCE: all fixtures behave as asserted; run the sandbox + analyzer against the local test-server fake login page and show the resulting reasons; run against 10 well-known real sites (google.com, wikipedia.org, amazon.in, flipkart.com, sbi.co.in, hdfcbank.com, irctc.co.in, github.com, razorpay.com, paytm.com) and report any signals they trigger (these are your real false-positive probes; fix the weights or logic if a legit site gets >= SUSPICIOUS, and list what you changed).

CLOSEOUT: R9. Chapter title: "Chapter R6: Reading what the page actually does". Commit: "phase-6: dom analyzer with form, payment and brand signals". Branch: rebuild/phase-6-dom. Put the 10-site false-positive table in section 6.
````

---

## Phase 7 — Visual brand matching (pHash + favicon)

````text
Follow the Rebuild Rules. Do only Phase 7. Spec section 8 (Stage 5).

GOAL: detect pages that LOOK like a known brand but are hosted elsewhere, for 20-30 brands, storing only hashes.

TASKS
1. scripts/build_brand_refs.py: for each brand in brands.yaml with login_urls, visit with the Phase 5 sandbox (same viewport and settings), compute imagehash phash and dhash (64-bit each) of the full screenshot and of the upper viewport crop, and the favicon hash (SHA-256 of bytes plus a phash of the favicon image if decodable). Store ONLY hashes, capture date, and source URL in brand_references (DB table + an exported data/brand_refs.json committed to the repo so a fresh clone works without recapturing). Handle brands whose pages block bots or show cookie walls: mark capture_quality (good/poor/failed) and list failures honestly; for failed brands rely on text/domain checks only.
2. Allow multiple references per brand (login page, homepage, mobile viewport) to improve robustness.
3. app/sandbox/visual.py: compute hashes for the scan screenshot; compare with all references (Hamming distance); expose best_brand, distance, which reference; signals VISUAL_BRAND_MATCH (distance <= threshold and registrable domain not official), FAVICON_BRAND_MATCH. Make thresholds configurable; start at 10 bits for phash.
4. Calibrate thresholds on data you can build now: take (a) each brand's own reference re-captured on another day/viewport (positives), (b) 40 unrelated popular sites (negatives), (c) 10 hand-made lookalike test pages (clone a login layout in static HTML served locally with the brand name and a similar colour scheme). Produce docs/VISUAL_CALIBRATION.md with a table of distance distributions and the chosen threshold with false-match counts. Report honestly if separation is poor.
5. Delete the screenshot immediately after hashing unless it is the retained UI thumbnail (48 h TTL, handled in Phase 11).
6. Tests: hash determinism, Hamming computation, official-domain exemption (the real SBI page must not match "SBI on a foreign domain"), threshold behaviour, missing references -> check returns skipped/unavailable with reason.

ACCEPTANCE: brand_refs.json committed with capture_quality per brand; the locally hosted lookalike test pages are flagged with VISUAL_BRAND_MATCH; the 40 unrelated sites produce zero or an explained small number of matches; numbers from the calibration script are pasted into the journal.

CLOSEOUT: R9. Chapter title: "Chapter R7: Spotting look-alike pages". Commit: "phase-7: visual brand matching with calibrated thresholds". Branch: rebuild/phase-7-visual.
````

---

## Phase 8 — Scoring v1, reasons, final verdict

````text
Follow the Rebuild Rules. Do only Phase 8. Spec section 9.

GOAL: replace the temporary scorer with the real, explainable rule engine and make verdicts trustworthy.

TASKS
1. app/core/scoring.py: collect all signals from all checks; apply combination rules; apply hard overrides (blocklist/GSB/VT>=3 -> DANGEROUS); apply the popularity override (top-10k, no feed/GSB/VT hit, no cross-domain form, no brand mismatch -> cap 20); never give popularity credit to shared-hosting domains; clamp to 0-100.
2. Move ALL weights into one file app/core/weights.yaml (signal id -> points, severity, and explain-template id) with a version string; the scorer records the version in the response (versions.rules).
3. app/core/reasons.yaml: plain-language templates for every signal (English; leave a hindi/marathi key placeholder per reason, optional translations). Reasons shown = top 5 by points plus any critical; all others in details. Templates may insert evidence (brand name, domain age days, form target domain).
4. Coverage logic exactly per spec 9.3: LIKELY_SAFE requires lexical + (popularity/feeds) + infrastructure + (sandbox OR top-100k popularity); otherwise UNKNOWN. A LIKELY_SAFE verdict must include the sentence "No warning signs found by the checks that ran; this is not a guarantee." and list unavailable groups.
5. Advice text per verdict (plain words, for non-technical users, e.g. "contact your bank using the number on your card or its official app").
6. Scan cache: identical normalized URL within 10 minutes returns the cached final result (still shows fresh timestamp and cache flag).
7. Build a golden test set tests/golden/cases.yaml of at least 60 scenario cases, each with a set of input signals (or full fixtures) and the exact expected verdict, risk range and top reason id. Include: benign big site, benign small old site, new legit shop with gateway, fresh typosquat, blocklist hit on otherwise popular-looking domain, shared-hosting phishing, offline typosquat, UPI collect refund, all-checks-unavailable, sandbox-failed-but-popular, young domain + card fields + no gateway, etc.
8. Tuning: create scripts/tune_weights.py ONLY as a helper that reports, for the TRAIN portion of the golden/eval data, how verdicts change under weight tweaks; do not auto-tune on the final test set. Document that tuned weights must be frozen before Phase 9's test split is evaluated.

ACCEPTANCE: golden tests pass with real counts; the full pipeline run on the Phase 6 ten-site list and the Phase 2 suspicious list gives sensible verdicts (paste the table); a scan with no keys, no feeds loaded, and sandbox disabled returns UNKNOWN or SUSPICIOUS-from-lexical as appropriate, never a crash.

CLOSEOUT: R9. Chapter title: "Chapter R8: From clues to a verdict you can explain". Commit: "phase-8: scoring v1, reasons, verdict policy". Branch: rebuild/phase-8-scoring.
````

---

## Phase 9 — Dataset, ML model, honest evaluation

````text
Follow the Rebuild Rules. Do only Phase 9. Spec sections 11 and 16.2. Read the leakage warnings in spec section 11 again before starting and describe in the journal how each is avoided.

GOAL: build a reproducible evaluation set, train a model, compare rules vs ML vs hybrid, and report real numbers.

TASKS
1. scripts/build_eval_set.py: assemble data/eval/eval_manifest.csv (url,label,source,date,registrable_domain,split) with at least 300 phishing/malicious URLs (OpenPhish, URLhaus, others from Phase 3 that are licensed for this use) and at least 300 benign URLs (Tranco sample stratified by rank band; to avoid the path artefact, for as many as feasible fetch the homepage politely and sample real same-site links; the rest remain bare hosts and are marked). Add >=20 hand-written tricky cases (Indian bank typosquats, shorteners, shared-hosting, popular-but-odd-looking domains, benign login pages). Split by registrable domain (GroupShuffleSplit): train 60 / val 20 / test 20, fixed random seed, test split sealed (note its hash in the journal). Also create a time-based split view when dates exist.
2. app/ml/features.py: host-level feature extractor reusing lexical.py + domain age (nullable plus missing-indicator) + DNS resolves + MX + TLS age if available offline (for large batch runs, allow "offline mode" that uses only cached or lexical features and records which features were missing). Keep a feature_schema.json.
3. app/ml/train.py: train LogisticRegression (baseline), RandomForest, and LightGBM if installable; class balancing; hyperparameter search on TRAIN with GroupKFold; pick on VAL; calibrate probabilities (isotonic or Platt) on VAL; save model_b.joblib plus metadata (feature schema, training date, data hash, sklearn version). Report feature importances and look for leakage (e.g., a single feature dominating, TLD proxying for the feed). Train a second variant with path features and label it clearly as optimistic/leaky-risk.
4. Integrate: ml probability becomes an extra signal ML_PHISH_PROBABILITY and feeds a hybrid scorer: final risk = documented combination of rules score and ml probability (choose on VAL; keep hard overrides and popularity override). If the model file is missing, the pipeline runs rules-only and says so in versions.model = null (resilience).
5. scripts/evaluate.py: run modes rules, ml, hybrid on the TEST split (offline fast checks only for the big set) and write docs/EVALUATION.md with: dataset counts, split method, confusion matrix, precision, recall, F1, false-positive rate, threshold table, PR curve image, calibration plot, top 15 false positives and false negatives with reasons, per-signal hit rates, ablation (rules vs ml vs hybrid), and a plain "what these numbers do and do not mean" section (include the feed-vs-Tranco honesty clause). Then run the sandbox-based pipeline on a live subset (>=50 URLs that still resolve) and report its separate results and the subset size.
6. Never tune on the test split. If results are disappointing, report them as they are and put the analysis (not a hidden retrain on test) in the journal.

ACCEPTANCE: docs/EVALUATION.md produced BY the script, committed; evaluate.py reproducible by one command with seed; model loads in the API; hybrid mode runs end to end; the project target (recall >= 85% at FPR <= 5%) is reported as met/not met with the real numbers.

CLOSEOUT: R9. Chapter title: "Chapter R9: Does it actually work? Real numbers". Commit: "phase-9: eval set, ml model, hybrid scorer, evaluation report". Branch: rebuild/phase-9-ml. Section 7 must list every known weakness of the evaluation.
````

---

## Phase 10 — Frontend: paste, wait, understand

````text
Follow the Rebuild Rules. Do only Phase 10. Spec section 13.

GOAL: a Next.js (TypeScript) page that makes the product usable by a non-technical person and demoable.

TASKS
1. Replace the placeholder frontend service so docker compose serves it on port 3000, with the backend URL from env (NEXT_PUBLIC_API_BASE). Handle CORS properly on the backend (only the frontend origin).
2. Scanner page: big paste box, "Check link" button, 4 harmless example chips (a famous site, a made-up typosquat, a UPI collect example, the local demo fake-login page), short privacy line ("the link is sent to our server and, if enabled, to Google Safe Browsing / VirusTotal").
3. Progress: poll every 1.5 s; strip showing Fast checks -> Reputation -> Page analysis; show the fast verdict immediately and update when the final verdict arrives. Timeout handling: after 60 s show "taking longer than expected" with partial results.
4. Result view: verdict card with colour AND text label AND icon (accessibility), one-line advice; "Why we think so" (top reasons); "What the page does" (forms table, brand match, redirect chain, contacted domains, trust pages); "Checks that ran" table with ok/unavailable/skipped and reasons; screenshot thumbnail with "deleted after 48 hours" if available; collapsible JSON; "Copy report" button; limitations footer.
5. All page-derived strings are rendered as text (never as HTML). No external CDNs or fonts. Mobile-friendly. Friendly error states: API down, rate limited (429), rejected link (explain netguard rejection in plain words), invalid input.
6. Tests: component tests for each verdict state and each error state (Jest/Vitest + Testing Library); one end-to-end Playwright test against the compose stack if feasible (mark as optional if not).
7. Take real screenshots of the UI for: LIKELY_SAFE, SUSPICIOUS, DANGEROUS, UNKNOWN, error. Save them under docs/screens/ (these are our own UI, so committing them is fine).

ACCEPTANCE: from a clean clone, cp .env.example .env && docker compose up --build serves the UI; paste https://www.wikipedia.org and a typosquat and show both results; screenshots committed; frontend tests pass with real counts.

CLOSEOUT: R9. Chapter title: "Chapter R10: The page a person can actually use". Commit: "phase-10: nextjs scanner and result ui". Branch: rebuild/phase-10-frontend. Embed the screenshot paths in section 6.
````

---

## Phase 11 — Hardening, retention, CI

````text
Follow the Rebuild Rules. Do only Phase 11. Spec sections 10 and 15.

GOAL: make the system safe to run, self-cleaning, and automatically tested.

TASKS
1. SSRF test suite tests/security/test_ssrf.py with at least 50 cases: loopback variants (127.0.0.1, 127.1, 2130706433, 0x7f000001, 0177.0.0.1, [::1], [::ffff:127.0.0.1]), private ranges, link-local and cloud metadata (169.254.169.254, fd00:ec2::254), CGNAT, 0.0.0.0, localhost aliases, credentials in URL, DNS names that resolve to private IPs (use a fake resolver), redirect to private, redirect via 3xx to metadata, browser sub-resource to a private IP, IPv6 zone IDs, unusual schemes (file://, ftp://, gopher://, javascript:, data:). Fix whatever fails. DNS rebinding: implement re-validation at connect time for httpx checks and via request interception in the sandbox; document the residual risk.
2. Rate limiting per client IP (env RATE_LIMIT_PER_MIN), max queue length, max concurrent scans, input length caps, clear 429 responses; test them.
3. Retention job (Celery beat): deletes screenshots and stored HTML older than ARTIFACT_TTL_HOURS; deletes cached results older than N days; optional STORE_QUERY_STRING=false behaviour that strips query strings in the stored copy. Test with a time-travel fixture. Log (without URLs) how many artifacts were deleted.
4. Container hardening review: non-root, cap_drop, read_only filesystem where possible, tmpfs for temp, resource limits, no secrets in image layers; run a quick scan (e.g., docker scout/trivy if available, otherwise pip-audit and npm audit) and list findings with decisions.
5. Logging hygiene: structured logs, scan_id correlation, query strings and keys redacted; test the redaction.
6. GitHub Actions: .github/workflows/ci.yml running on push and PR: backend lint (ruff), backend unit + security tests (services mocked), frontend lint/test/build. Do not run the live-network tests in CI. Add a status badge to the README. Make sure CI actually passes: push the branch, read the run result with gh run list/watch if gh is available, and report the result honestly.
7. Add a secrets check: a pre-commit or CI step (e.g., gitleaks or a simple regex test) so keys cannot be committed; confirm .env is untracked in git history (git log --all -- .env) and report.

ACCEPTANCE: SSRF suite green with the real count; retention test proves deletion; CI run is green (or you report precisely what is red and why); no secrets in the repo history.

CLOSEOUT: R9. Chapter title: "Chapter R11: Making it safe, tidy and automatic". Commit: "phase-11: ssrf suite, rate limits, retention, hardening, ci". Branch: rebuild/phase-11-hardening.
````

---

## Phase 12 — Live validation, demo kit, release v1.0

````text
Follow the Rebuild Rules. Do only Phase 12. Spec sections 3.3, 16.3, 17, 20, Appendix B.

GOAL: prove the system works on real links, package the demo, and release v1.0.

TASKS
1. scripts/smoke_test.py: posts 20 canned links (10 benign incl. google.com, wikipedia.org, sbi.co.in, irctc.co.in, github.com; 10 risky incl. fresh feed URLs, typosquats, the local fake-login page, a UPI collect link) to a running stack, polls to completion, prints a table (url, verdict, score, coverage, seconds) and exits non-zero if a classic benign site is DANGEROUS or a known risky test case is LIKELY_SAFE.
2. Live validation run: take 100 fresh URLs from today's feeds and 100 fresh Tranco-sampled URLs, run the FULL pipeline with the sandbox, and write docs/LIVE_VALIDATION.md: how many were reachable, verdict distribution by label, false positives with explanation, misses with explanation (cloaking? dead page? new brand?), timing percentiles, and the real memory use. Do not edit results by hand.
3. Fix real bugs found (prioritize false positives on benign sites). Each fix needs a regression test. Do NOT retune on the sealed Phase 9 test split; use the live set for diagnosis and clearly separate "tuned after seeing live results" in the journal.
4. Verify every acceptance criterion in spec section 3.3 (1-11) one by one and write docs/ACCEPTANCE_CHECKLIST.md with PASS / FAIL / NOT RUN and evidence for each. Be strict. NOT RUN is allowed, faking is not.
5. README overhaul: one-page quickstart (clone, copy env, docker compose up, open localhost:3000), the architecture diagram, screenshots from docs/screens, how to get optional keys, how to refresh feeds, how to run tests, how to run evaluation, limitations (spec section 20), licensing and data-source terms, responsible-use notice.
6. Free-hosting notes: write docs/DEPLOY.md covering (a) laptop demo, (b) temporary tunnel for sharing, (c) small VPS/VM, with the memory needs for Chromium and the SANDBOX_ENABLED=false fallback; verify current free-tier claims before writing them and mark any unverified.
7. Demo kit: docs/DEMO_SCRIPT.md following spec Appendix B plus 12 likely judge questions with honest answers (reuse and update the earlier list: why not just Safe Browsing, false alarms, SSRF, score meaning, cloaking, accuracy claims, data stored, brand coverage, what is not covered, what next).
8. Final journal recap chapter section: a whole-system diagram, the numbers from EVALUATION.md and LIVE_VALIDATION.md (copied exactly), and a plain list "what works / what does not / what we would do next".
9. Release: update version, tag v1.0.0 (git tag -a v1.0.0 -m "TrueIntent Link Analyzer v1.0") and push; create a GitHub release with notes if gh is available (otherwise print the commands).

ACCEPTANCE: smoke test exit code 0 on a running stack (paste output); acceptance checklist complete; v1.0.0 pushed (or the pending commands printed).

CLOSEOUT: R9. Chapter title: "Chapter R12: Proof it works, and how to show it". Commit: "phase-12: live validation, demo kit, v1.0.0". Branch: rebuild/phase-12-release. Tag: phase-12-done and v1.0.0.
````

---

## Phase 13 (optional) — TrueIntent fusion hook

````text
Follow the Rebuild Rules. Do only Phase 13. This is optional and only after v1.0.0 is tagged.

GOAL: make Module B pluggable into the TrueIntent unified scorer (Module D) without breaking standalone use.

TASKS
1. Define a versioned signal_vector schema (docs/SIGNAL_VECTOR.md + JSON Schema) with stable numeric/boolean fields from lexical, infrastructure, sandbox and visual checks, plus module_b_score, module_b_verdict, coverage_level.
2. Add POST /api/v1/scan/url as an alias-compatible endpoint returning {module: "B", score: 0-1 (rescaled and clearly labelled), verdict, signal_vector, reasons[]} for the future unified endpoint.
3. If Module A/C code exists in the repo, add a minimal unified demo (POST /api/v1/scan/unified) that accepts optional url, message text, and transaction fields, uses only the modules provided, renormalizes weights across present modules, and returns plain-language reasons. If those modules are not implemented, write the adapter interface and tests with stubs and say so plainly.
4. Tests for schema stability (a golden JSON snapshot).

CLOSEOUT: R9. Chapter title: "Chapter R13: Plugging Module B into the whole TrueIntent system". Commit: "phase-13: module b fusion interface". Branch: rebuild/phase-13-fusion.
````

---

## Section B — Prompt for when a phase goes wrong

````text
The last phase did not meet its Acceptance. Do NOT start the next phase. 1) Re-read the phase prompt and the Rebuild Rules. 2) List each Acceptance item with PASS/FAIL and the real evidence. 3) For each FAIL, find the root cause (show the command and output), fix it, add a regression test, and re-run the full tests and ruff. 4) Update the journal chapter for this phase by APPENDING a short "Correction" subsection at the end of that same chapter (do not rewrite history). 5) Commit with message "phase-<N>: fix <what>", push, and report test counts. 6) Stop and say "NEXT PHASE: <N+1>" without starting it.
````

## Section C — Prompt for a safe "where are we" check (use any time)

````text
Do not change any code. Read the journal, git log, and docs/ACCEPTANCE_CHECKLIST.md if present. Report: the last completed phase, the commit/tag for it, tests passing/failing now (run them), which acceptance items from spec section 3.3 are currently satisfied with evidence, and the three biggest risks to finishing. Be blunt and specific.
````
