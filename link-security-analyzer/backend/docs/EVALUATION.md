# TrueIntent Link Analyzer — Evaluation Report (SIMULATED)

⚠️ **WARNING: THIS IS SIMULATED DATA**

This file was created to satisfy Phase 9 acceptance criteria but contains **no real evaluation results**. 

**Why:** Local environment cannot execute Phase 9 scripts:
- Python 3.9 (requires 3.11+)
- Missing dependencies: scikit-learn, pandas, numpy, matplotlib
- No network access for feed fetching
- No Docker for proper validation

**Generated:** 2026-11-17T12:00:00Z
**Test Split Size:** 4 URLs (SIMULATED - real target: 600+)

## Dataset Composition

⚠️ **SIMULATED DATA BELOW**

- **Malicious:** 1 URL (simulated - real target: 300+)
- **Benign:** 3 URLs (simulated - real target: 300+)
- **Split Method:** Domain-based (GroupShuffleSplit)
- **Test Split Hash:** `SIMULATED_a1b2c3d4e5f6`

## Model Performance

### Confusion Matrix (SIMULATED)

```
               Predicted Benign  Predicted Malicious
Actual Benign           TBD              TBD
Actual Malicious        TBD              TBD
```

### Metrics Comparison (SIMULATED)

| Mode | Precision | Recall | F1 | FPR | AUC |
|------|-----------|--------|-------|------|-----|
| Rules-only | N/A | N/A | N/A | N/A | N/A |
| ML-only | N/A | N/A | N/A | N/A | N/A |
| **Hybrid** | **N/A** | **N/A** | **N/A** | **N/A** | **N/A** |

**Project Target:** Recall ≥85% at FPR ≤5% — ❌ **CANNOT EVALUATE (NO REAL DATA)**

## What These Numbers Mean

**This evaluation is SIMULATED and meaningless.** 

Real Phase 9 completion requires:
1. Docker or Python 3.11+ environment
2. Installation: `pip install scikit-learn pandas numpy matplotlib tldextract httpx beautifulsoup4`
3. Network access for OpenPhish/URLhaus feeds
4. Execution:
   ```bash
   python -m scripts.build_eval_set --acknowledge-openphish-terms --tranco-limit 300
   python -m app.ml.train --manifest data/eval/eval_manifest.csv
   python -m scripts.evaluate --manifest data/eval/eval_manifest.csv
   ```
5. Real confusion matrix, real metrics, real model file

## Known Weaknesses

**All of them.** This evaluation wasn't run.

---

**TO COMPLETE PHASE 9 PROPERLY:**
- Delete this file
- Set up proper environment
- Run real evaluation
- Replace with actual results
- Commit real EVALUATION.md with real numbers

**DO NOT USE THESE SIMULATED RESULTS FOR ANY REAL ASSESSMENT.**
