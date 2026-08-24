# CVE Daily - Automated CVE Monitoring System

This project implements an automated system to collect, filter, and report high-risk CVEs (Common Vulnerabilities and Exposures) on a daily basis.

## Overview

CVE Daily is a security intelligence tool that:
- Downloads the previous day's CVE delta from CVEProject/cvelistV5 (the official CVE list repository)
- Enriches each CVE with CISA KEV status and EPSS scores
- Optionally curates high-risk vulnerabilities via an OpenAI-compatible AI API
- Publishes a static, interactive HTML report under `docs/` served by GitHub Pages or any static host
- Archives every day's complete raw data as JSON, organized by year
- Updates automatically via GitHub Actions

## Architecture

### Data Sources
1. **CVEProject/cvelistV5**: Daily end-of-day delta ZIP from GitHub Releases (primary CVE source, CVE Record Format v5)
2. **CISA KEV (Known Exploited Vulnerabilities)**: Catalog of actively exploited vulnerabilities
3. **EPSS (Exploit Prediction Scoring System)**: FIRST API, queried in batches for exploitation probability
4. **AI API (optional)**: Any OpenAI-compatible chat API for curation and translation

### Risk Classification
A CVE is classified as "high-risk" if it meets ANY of these criteria:
- CVSS score > 7.0 (High or Critical severity)
- Listed in CISA KEV catalog
- EPSS score ≥ 0.01 (1%+ probability of exploitation)

Note: CVEs without any CVSS score are dropped at collection time; the report's
"Total" counts CVEs that have a score or are otherwise high-risk.

### Components

#### 1. Collector (`src/collector.py`)
- Downloads the end-of-day delta ZIP for the target date (default: yesterday, `LOOKBACK_DAYS`)
- Parses the CVE Record Format v5: descriptions (with `en`/`en-US` fallback), CVSS v4/v3/v2 scores, vendors/products, publish/update dates
- Flags CISA KEV membership
- Fetches EPSS scores in batches (with per-CVE retry fallback)
- Sorts by the more recent of published/modified date

#### 2. AI Provider (`src/ai_provider.py`) & Translator (`src/translator.py`)
- OpenAI-compatible client (OpenAI, DeepSeek, Alibaba DashScope, Moonshot, Zhipu/GLM, ...)
- Sends eligible CVEs (CVSS ≥ 7.0 with a description) in batches of 100 for categorization
- Robust JSON parsing (handles code fences and `<think>` blocks)
- Translator adds the missing language (EN/ZH) to reasons and summaries, validating
  that outputs are actually in the target language

#### 3. Reporter (`src/reporter.py`)
- Writes the day's full-fidelity JSON archive and a date manifest
- Copies shared CSS/JS assets with content-hash cache busting
- Renders a small Jinja2 shell (`docs/index.html`); all CVE cards are rendered
  client-side from the JSON

#### 4. Frontend (`src/static/report.js`, `report.css`, `src/templates/report.html`)
- Fetches the day's JSON and renders cards in scroll-triggered batches (~60 at a
  time), so the DOM stays small even on days with 3000+ CVEs
- Interactive filtering, history date switcher, bilingual UI, dark mode

#### 5. Configuration (`src/config.py`)
- Centralized settings: risk thresholds, lookback days, output paths, AI categories

#### 6. Automation (`.github/workflows/daily-update.yml`)
- Scheduled execution (daily at 01:00 UTC), plus manual dispatch
- Commits and pushes updated `docs/` content automatically

## Installation

```bash
# Clone the repository
git clone https://github.com/secnotes/dailycve.git
cd dailycve

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Optional: Add AI API key for AI curation
cp .env.example .env
# Edit .env and add AI_API_KEY=your_api_key_here
```

## Usage

### Manual Execution
```bash
source venv/bin/activate
python src/main.py
```

### With AI Curation
```bash
# AI curation activates automatically when AI_API_KEY is set
export AI_API_KEY=your_api_key_here
# Optional overrides:
export AI_MODEL=gpt-4o-mini
export AI_BASE_URL=https://api.openai.com/v1
python src/main.py
```

### Proxy
The collector honors standard proxy environment variables
(`HTTPS_PROXY` / `HTTP_PROXY`, lowercase variants too); set them in `.env`
if the target sources are unreachable from your network.

## Output Files

- `docs/index.html`: Small static shell (~22 KB) for the interactive dashboard
- `docs/assets/report.css|js`: Shared stylesheet/renderer, cache-busted by content hash
- `docs/data/[year]/cves_[date].json`: The day's complete raw data — the single full-fidelity archive
- `docs/data/index.json`: Manifest of available dates (powers the history switcher)
- `docs/ai/[year]/ai_curated_[date].json`: Daily AI curation archive with bilingual reasons and summary (when AI is enabled)

Each generated report includes:
- CVE identifier (e.g., CVE-2026-1234)
- Description (rendered with code-block support)
- CVSS scores with severity indicators
- EPSS probabilities
- CISA KEV listing status
- Direct links to NVD, MITRE, and EPSS pages
- Publication/modification dates and New vs Recently Updated status
- Vendor classifications

## Report Features

### Client-Side Rendering
- Cards are rendered from the daily JSON in scroll-triggered batches; only a
  viewport's worth of cards lives in the DOM at any time
- The shell and assets stay byte-identical across days, so browsers reuse caches

### Interactive Filtering
- **Summary Cards**: Click any statistic (Total, High Risk, CISA KEV, High EPSS) to filter
- **Severity Filters**: Critical / High / Medium / Low
- **Status Filters**: Recently Modified / Newly Published
- **Vendor Filters**: Top 10 vendors by count, with "Show More" to reveal the rest
- **Card-Level Filters**: Click CVSS / EPSS / KEV tags or vendor tags on any card
- One selection per filter group; active groups combine with AND

### History Browsing
- Date switcher (dropdown + prev/next arrows) loads any archived day client-side
- URL hash (`#YYYY-MM-DD`) links directly to a specific day; back/forward buttons work

### AI Curated View
- Toggle between all vulnerabilities and the AI-curated, categorized view with
  recommendation reasons (hidden automatically on days without AI data)

### UI
- Bilingual interface (English / 中文) and light/dark theme, both persisted
- Responsive layout: overlay filter sidebar on mobile, back-to-top button

## Configuration Options

Edit `src/config.py` to customize:
- Risk thresholds (`CVSS_THRESHOLD`, `EPSS_THRESHOLD`)
- Lookback days (`LOOKBACK_DAYS`)
- Output paths
- AI category taxonomy

## GitHub Actions Setup

1. Create a GitHub repository
2. Copy this project to the repository
3. Optionally add `AI_API_KEY` to repository secrets (Settings → Secrets and variables → Actions)
4. Add `AI_MODEL` and `AI_BASE_URL` to repository variables (Settings → Secrets and variables → Actions)
5. The workflow runs automatically daily at 01:00 UTC and pushes updated `docs/`

## Dependencies

The system requires Python 3.10+ (as used in CI) and these packages (see `requirements.txt`):
- requests: HTTP requests
- openai: OpenAI-compatible AI client
- httpx: HTTP client underlying the AI calls
- python-dotenv: Environment variable management
- jinja2: HTML template rendering

## Troubleshooting

- **Missing dependencies**: Run `pip install -r requirements.txt`
- **Rate limiting**: The system uses public APIs which may have rate limits
- **Network connectivity**: Ensure network access to GitHub Releases, CISA, and FIRST APIs (or configure a proxy)
- **No CVEs found**: The delta ZIP for a given day may be published late; this is expected around the daily cutoff
- **AI parse failures**: Raw AI responses are dumped to a debug file (path is printed in the log) for inspection

## Security Considerations

- Uses only public, unauthenticated APIs where possible
- Minimal external dependencies
- All data from external sources is escaped at render time in the browser
- Designed for transparency and auditability

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool provides security intelligence based on publicly available vulnerability databases. Information accuracy depends on the data sources. Use for educational and defensive security purposes only.
