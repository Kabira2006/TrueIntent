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
- Truthfulness: only claim what a command output or test showed. Include real numbers (test counts, timings, metric values). Include failures, dead ends, bugs, fixes and deviations from the plan. Mark anything unverified as "not verified".
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
