# Getting API Keys for External Threat Feeds

The TrueIntent link analyzer works **without any API keys**. External threat feeds (Google Safe Browsing and VirusTotal) are optional and only add extra checks when configured.

## Why API keys are optional

The system has many offline checks that work without keys:
- URL spelling and brand typosquat detection
- Local blocklists (Tranco, OpenPhish, URLhaus)
- Domain age via RDAP
- DNS and network checks

Adding API keys gives you two extra external opinions, but the system gives a verdict either way.

## Google Safe Browsing (GSB)

**What it does:** Checks if Google already knows about a URL being used for phishing or malware.

**Cost:** Free for non-commercial use

**How to get a key:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or use an existing one)
3. Enable the "Safe Browsing API"
4. Go to "APIs & Services" → "Credentials"
5. Click "Create Credentials" → "API Key"
6. Copy the key and add to your `.env` file:
   ```
   GSB_API_KEY=AIzaSy...your-key-here
   ```

**Limits:** Google's free tier allows thousands of lookups per day (verify current limits at [cloud.google.com/safe-browsing](https://cloud.google.com/safe-browsing))

**Privacy note:** When you use Google Safe Browsing, Google receives the URL you are checking.

## VirusTotal

**What it does:** Checks if security vendors have already reported a URL as malicious.

**Cost:** Free tier available

**How to get a key:**
1. Go to [virustotal.com](https://www.virustotal.com/)
2. Sign up for a free account
3. Go to your profile → "API Key"
4. Copy the key and add to your `.env` file:
   ```
   VT_API_KEY=your-64-character-key-here
   ```

**Limits:** Free tier allows about **4 requests per minute** and **500 requests per day**. We automatically cache results for 24 hours and rate-limit our queries to stay within these limits.

**Important:** We only look up *existing reports* by URL ID. We never upload or scan URLs through VirusTotal.

**Privacy note:** When you use VirusTotal, they receive a hash-based identifier of the URL you are checking.

## URLhaus (Blocklist Feed Download)

**What it does:** Provides a list of known malware distribution URLs (used during feed downloads, not live scans).

**Cost:** Free for non-commercial use

**How to get a key:**
1. Visit [urlhaus.abuse.ch/api/](https://urlhaus.abuse.ch/api/)
2. Request a free API key following their instructions
3. Add to your `.env` file:
   ```
   ABUSECH_AUTH_KEY=your-key-here
   ```

**Usage:** This key is only used by `scripts/download_feeds.py` to download the URLhaus feed. It's not used during live scans.

## What happens without keys

If no keys are configured:
- The system runs all offline checks (lexical analysis, local blocklists, RDAP, DNS)
- External reputation checks report status="unavailable" with reason="no_api_key"
- The verdict is still computed using whatever checks succeeded
- Coverage is reported as "medium" or "low" instead of "high"
- No URLs are sent to Google or VirusTotal

This is by design: the system must work in environments where external API calls are restricted or when keys are not available.

## Testing without keys

To verify the system works without keys:
1. Leave `GSB_API_KEY` and `VT_API_KEY` empty in `.env`
2. Submit a scan via the API or web interface
3. Check the response: `threat_feeds` will show "unconfigured"
4. The verdict will be computed using offline checks only
5. `coverage_level` will reflect reduced coverage

## Rate limiting

Even with keys, the system respects API limits:
- VirusTotal: max 4 requests/minute, 500/day (token bucket enforcer)
- Google Safe Browsing: no enforced limit (relies on Google's quota)
- Both: 24-hour Redis cache to minimize repeated lookups

## Security notes

- Never commit API keys to Git
- Keys are read from `.env` (which is git-ignored)
- Keys are never logged or included in error messages
- Use separate keys for development and production
- Rotate keys periodically following each provider's best practices
