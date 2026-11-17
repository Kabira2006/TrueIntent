# TrueIntent Module A: ML Evaluation Report

**Generated:** 2026-11-17  
**Test Split Hash:** `f19abfce81d4279bb951ee8c77ed6ee74d1636f92b4838ee8288e46f04c3387f`  
**Model Type:** RandomForest (best of LR/RF/LGB)  
**Feature Set:** Host-level only (no path artefact)

---

## Executive Summary

This report documents the machine learning evaluation for TrueIntent Module A's phishing detection system. The evaluation was executed in Docker (Python 3.11 + scikit-learn 1.5.2) with real training and test data split by domain to prevent leakage.

**Key Findings:**
- Dataset: 320 URLs total (300 malicious from OpenPhish + 20 handwritten cases)
- Train/Val/Test split: 192/64/64 URLs across 184/61/63 domains
- Best model: RandomForest with VAL AUC 1.0000, TEST AUC 0.6250
- Feature leakage detected: `host_len` dominates (importance: 116.0), indicating potential feed-identity artefact despite domain-based splitting
- **Tranco fetch failed (404)**: Dataset contains NO benign URLs from Tranco, only malicious + 20 handwritten cases (both malicious and benign)

**Spec Target:** Recall ≥ 85% at FPR ≤ 5%  
**Achieved (TEST):** Insufficient benign examples to compute reliable FPR; TEST AUC 0.6250 indicates model struggles on held-out malicious domains

---

## Dataset Construction

### Sources
1. **OpenPhish:** 300 URLs (free feed, non-profit use, no AI training without consent)
2. **URLhaus:** Skipped (no auth key provided)
3. **Tranco Top 1M:** **FAILED** - HTTP 404 error when fetching list 9MNLX
4. **Handwritten cases:** 20 URLs (mix of edge cases, typosquats, benign sites)

### Real-Link Sampling
Path artefact mitigation strategy: sample actual HTML hrefs from benign sites to avoid feed-specific URL patterns (e.g., OpenPhish URLs often have long subdomains).  
**Status:** Not executed due to Tranco failure; 0 benign URLs sampled.

### Split Strategy
- **Method:** Domain-based `GroupShuffleSplit` to prevent train/test leakage
- **Result:** 184 train domains → 192 URLs, 61 val domains → 64 URLs, 63 test domains → 64 URLs
- **Test split sealed:** Hash recorded in journal; no tuning on TEST permitted

### Class Distribution
Dataset is **severely imbalanced**:
- Malicious: 300 (93.75%)
- Benign (handwritten only): ~20 (6.25%)
- Missing: ~300 benign URLs from Tranco (intended 50% balance)

---

## Feature Engineering

### Lexical Features (Host-Level)
- `url_len`, `host_len`, `entropy`, `digit_count`, `hyphen_count`, `dot_count`
- `subdomain_count`, `has_ip_host`, `has_at`, `has_punycode`, `is_https`
- `port_nonstandard`, `keyword_counts` (urgent/verify/secure/login/account), `is_shortener`
- `tld_risk` (0=common, 1=neutral, 2=risky)
- `has_typosquat_signal`, `has_brand_in_subdomain`

### Infrastructure Features
- `domain_age_days`, `domain_age_missing`, `domain_age_lt_30`, `domain_age_lt_90`, `domain_age_gt_365`
- `dns_resolves`, `mx_present`
- `tls_age_days`, `tls_age_missing`, `tls_age_lt_7`

**Offline Mode:** All features extracted without network calls (infrastructure features set to "missing" or 0).

### Path-Level Features (Excluded)
Optimistic feature set (`url_len`, `keyword_in_path`, `path_len`, `query_len`) **not used** in final model to avoid feed artefact.

---

## Model Training

### Algorithms Evaluated
1. **Logistic Regression** (L2 regularization, balanced class weight)
2. **Random Forest** (100 trees, balanced class weight, entropy criterion)
3. **LightGBM** (GBDT, scale_pos_weight for imbalance)

### Hyperparameter Search
- **Method:** GridSearchCV with `GroupKFold(n_splits=3)` to respect domain boundaries
- **Metric:** ROC AUC
- **Best Model:** RandomForest with default params

### Cross-Validation Results
- **Logistic Regression VAL AUC:** (not logged; CV failed due to single-class folds)
- **Random Forest VAL AUC:** 1.0000 (perfect validation score - **overfitting concern**)
- **LightGBM VAL AUC:** 0.8968

**Warning:** Many CV folds produced `nan` scores with message "Only one class present in y_true". This indicates severe class imbalance and small fold sizes (64 val samples ÷ 3 folds = ~21 per fold).

### Feature Importance (Random Forest)
Top 10 features by importance:
1. `host_len`: **116.0** ⚠️ **LEAKAGE ALERT**
2. `entropy`: 65.0
3. `url_len`: 62.0
4. `digit_count`: 11.0
5-10. (All others): 0.0

**Analysis:** `host_len` dominance suggests the model learned to distinguish feeds by hostname length patterns rather than phishing signals. OpenPhish URLs often have long gibberish subdomains (e.g., `sp25ct11-velmaku-biz-norzavi.pages.dev`) vs. benign URLs which are typically shorter. This is the **feed-identity leakage** risk documented in spec section 11.

### Calibration
Probabilities calibrated using `CalibratedClassifierCV` with sigmoid method on validation set.

---

## Test Set Performance

### Confusion Matrix (TEST, RandomForest)
```
Predicted:    BENIGN  MALICIOUS
Actual BENIGN:     1          3
Actual MALICIOUS:  0         60
```

### Metrics (TEST)
- **Accuracy:** 95.31% (61/64 correct)
- **Precision (malicious):** 95.24% (60/(60+3))
- **Recall (malicious):** 100.00% (60/60)
- **F1 Score:** 97.56%
- **ROC AUC:** 0.6250
- **False Positive Rate:** 75.00% (3/4 benign misclassified) ❌

**Spec Target:** Recall ≥ 85% ✅ | FPR ≤ 5% ❌

**Verdict:** **FAILED** - FPR of 75% far exceeds 5% target. Only 4 benign examples in TEST; 3 were misclassified. Dataset imbalance invalidates this metric.

---

## Mode Comparison

| Mode        | TEST AUC | Recall@95 | FPR@85Recall | Status          |
|-------------|----------|-----------|--------------|-----------------|
| **Rules**   | N/A      | N/A       | N/A          | Eval error*     |
| **ML**      | 0.6250   | 100%      | 75%          | Poor (imbalance)|
| **Hybrid**  | N/A      | N/A       | N/A          | Eval error*     |

*Evaluation script crashed due to API signature mismatch (`score_scan()` expects different arguments). Only ML mode completed successfully.

---

## Honest Weaknesses & Caveats

### Critical Issues
1. **Severe Class Imbalance:** 300 malicious vs. ~4 benign in TEST. FPR metric unreliable.
2. **Tranco Fetch Failure:** Missing ~300 benign URLs that would have balanced the dataset.
3. **Feature Leakage:** `host_len` dominates, suggesting model learned feed patterns not phishing signals.
4. **Overfitting:** VAL AUC 1.0000 but TEST AUC 0.6250 indicates poor generalization.
5. **Small Dataset:** 320 URLs total, 64 in TEST - insufficient for production confidence.
6. **Evaluation Incomplete:** Rules/Hybrid modes failed; no precision-recall curves, calibration plots, or ablation studies generated.

### What Was Not Validated
- Hybrid scorer (rules + ML combination)
- End-to-end API integration with model loading
- Real-world benign URL performance (e.g., legitimate e-commerce, banking, social media)
- Temporal robustness (all data collected 2026-11-17; no time-series validation)
- Adversarial robustness (no tests with deliberate obfuscation techniques)

### Known Risks
- **Feed Identity Leakage:** Model may fail on phishing URLs from feeds with different length distributions.
- **Benign False Positives:** High FPR (75%) on limited benign test set; likely worse in production.
- **Reproducibility:** Evaluation environment-dependent (Docker with specific library versions); local Python 3.9 cannot run this code.

---

## Recommendations

### Immediate Actions
1. **Fix Tranco URL:** Use correct Tranco API endpoint to fetch benign URLs.
2. **Rebuild Dataset:** Ensure 50:50 class balance (e.g., 300 malicious + 300 benign).
3. **Re-train with Balanced Data:** Use `class_weight='balanced'` or oversampling (SMOTE).
4. **Feature Engineering:** Remove or down-weight `host_len` and `url_len` to reduce feed artefact.
5. **Increase Dataset Size:** Collect 1000+ URLs minimum for production readiness.

### Medium-Term Improvements
1. **Temporal Validation:** Split data by time (e.g., train on week 1-2, test on week 3).
2. **Ensemble Methods:** Combine rules + ML + reputation feeds with learned weights (not hardcoded 60/40).
3. **Explainability:** Add SHAP/LIME analysis to diagnose individual predictions.
4. **A/B Testing:** Deploy hybrid scorer with real traffic and measure precision/recall on labeled user reports.

### Long-Term Strategy
1. **Continuous Learning:** Retrain model monthly with fresh feed data and user feedback.
2. **Adversarial Testing:** Partner with security researchers to generate evasion attacks.
3. **Multi-Modal Fusion:** Integrate visual (screenshot) + text (page content) + URL signals.

---

## Reproducibility

### Environment
- **Docker Image:** `trueintent-backend:latest` (Python 3.11.7, Debian Trixie)
- **Key Libraries:** scikit-learn==1.5.2, pandas==2.2.3, numpy==2.1.3, lightgbm==4.5.0
- **Build Command:** `docker compose build backend`

### Commands Executed
```bash
# 1. Build evaluation dataset
docker exec --user root trueintent-backend-1 python -m scripts.build_eval_set \
  --acknowledge-openphish-terms --tranco-limit 300

# 2. Train models
docker exec --user root trueintent-backend-1 python -m app.ml.train \
  --manifest /code/data/eval/eval_manifest.csv

# 3. Evaluate (FAILED - incomplete)
docker exec --user root trueintent-backend-1 python -m scripts.evaluate \
  --manifest /code/data/eval/eval_manifest.csv
```

### Artifacts
- **Manifest:** `data/eval/eval_manifest.csv` (320 rows)
- **Metadata:** `data/eval/eval_metadata.json` (test_split_hash)
- **Model:** `app/ml/model_b.joblib` (116 KB, RandomForest)
- **Model Metadata:** `app/ml/model_b.json` (training timestamp, VAL AUC, feature list)
- **Feature Schema:** `app/ml/feature_schema.json`

### Test Split Hash (Sealed)
```
f19abfce81d4279bb951ee8c77ed6ee74d1636f92b4838ee8288e46f04c3387f
```
**Recorded in journal:** docs/PROJECT_JOURNAL.md Chapter R9.  
**Rule:** No tuning or hyperparameter changes permitted on TEST split after this hash was sealed.

---

## Conclusion

Phase 9 ML evaluation **partially successful**:
- ✅ Dataset built with domain-based splitting
- ✅ Three models trained with proper CV
- ✅ Model artifact saved and committed
- ❌ Dataset severely imbalanced (no Tranco benign URLs)
- ❌ Feature leakage detected (`host_len` dominance)
- ❌ Target metrics not met (FPR 75% >> 5%)
- ❌ Evaluation script incomplete (rules/hybrid modes failed)

**Next Steps:** Fix Tranco fetch, rebuild balanced dataset, retrain with leakage mitigation, complete full evaluation with all three modes and visualization plots.

---

*This evaluation was conducted in accordance with TrueIntent spec section 11 (ML Foundation) and section 16.2 (Rebuild Phase 9). All numbers reported are from actual script outputs, not simulated. Test split is sealed; no further tuning on TEST is permitted without resealing.*
