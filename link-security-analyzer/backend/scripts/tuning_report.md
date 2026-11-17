# Weight Tuning Report (Phase 8 - Pre-Evaluation)

**Status:** Evaluation dataset not yet created (Phase 9)

## Current Weights Summary

**Weights version:** 1.0
**Total signals configured:** 56

### Signal distribution by severity

- **medium:** 19 signals
- **high:** 17 signals
- **low:** 12 signals
- **info:** 8 signals

### Point distribution

| Range | Count | Examples |
|---|---|---|
| +100 | 3 | `BLOCKLIST_URL_HIT`, `GSB_THREAT`, `VT_MALICIOUS_GE3` |
| +80 | 1 | `BLOCKLIST_DOMAIN_HIT` |
| +40 | 2 | `VT_SUSPICIOUS_GE2`, `VISUAL_BRAND_MATCH` |
| +30 | 6 | `TYPOSQUAT_BRAND`, `DOMAIN_AGE_LT_7D`, `FORM_POSTS_CROSS_DOMAIN` (+3 more) |
| +25 | 3 | `IP_ADDRESS_HOST`, `TLS_CERT_MISMATCH`, `BRAND_LOOKALIKE_ON_FOREIGN_DOMAIN` |
| +20 | 6 | `BRAND_KEYWORD_IN_SUBDOMAIN`, `DOMAIN_AGE_LT_30D`, `VT_SUSPICIOUS_1` (+3 more) |
| +15 | 7 | `SUSPICIOUS_TLD`, `SUSPICIOUS_PORT`, `DNS_LOOKUP_FAILED` (+4 more) |
| +12 | 1 | `PUNYCODE_DOMAIN` |
| +10 | 8 | `URL_SHORTENER`, `DOMAIN_AGE_LT_180D`, `HAS_CARD_FIELDS` (+5 more) |
| +8 | 7 | `EXCESSIVE_SUBDOMAINS`, `HIGH_ENTROPY`, `NO_MX_RECORDS` (+4 more) |
| +5 | 4 | `EXCESSIVE_URL_LENGTH`, `DOMAIN_AGE_UNKNOWN`, `TLS_UNAVAILABLE` (+1 more) |
| +3 | 1 | `RIGHT_CLICK_DISABLED` |
| +2 | 1 | `PAGE_UNREACHABLE` |
| +0 | 3 | `CHECK_UNAVAILABLE`, `THREAT_FEED_UNAVAILABLE`, `INFRASTRUCTURE_UNAVAILABLE` |
| -10 | 2 | `POPULARITY_TOP_100K`, `RECOGNIZED_GATEWAY` |
| -20 | 1 | `POPULARITY_TOP_10K` |

---

**Next step:** Run Phase 9 to create evaluation dataset, then re-run this script.