<div align="center">

# 🐞 Daily CVE

[English](README.md) | [中文](README_CN.md)

[![Daily Update](https://github.com/secnotes/dailycve/actions/workflows/daily-update.yml/badge.svg)](https://github.com/secnotes/dailycve/actions/workflows/daily-update.yml)
[![Last Commit](https://img.shields.io/github/last-commit/secnotes/dailycve)](https://github.com/secnotes/dailycve/commits)
[![License](https://img.shields.io/github/license/secnotes/dailycve)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://www.python.org/)

Automated daily CVE monitoring system that collects all vulnerability information from MITRE CVE and generates human-readable reports, allowing for quick customization to filter high-risk vulnerabilities.

</div>

## 🚀 Features

- **MITRE CVE Focused**: Fetches all CVE information daily from MITRE CVE database and associated sources
- **Intelligent Filtering**: Identifies high-risk vulnerabilities based on:
  - CVSS score > 7.0 (High/Critical severity)
  - Presence in CISA KEV (Known Exploited Vulnerabilities) List
  - EPSS score ≥ 0.01 (Exploitation probability)
- **AI Enhancement**: Uses OpenAI-compatible APIs to intelligently categorize and curate high-risk vulnerabilities (optional)
  - Filters CVSS ≥ 7.0 vulnerabilities with descriptions for AI analysis
  - Categorizes into domains: Desktop OS, Mobile, IoT, Cloud, Network, ICS, Web, Database/Middleware
  - Provides AI-generated recommendation reasons for each curated CVE
- **Interactive Reports**: Generates rich HTML reports with filtering capabilities including:
  - CVSS severity filters (Critical, High, Medium, Low)
  - Status filters (Recently Modified, Newly Published)
  - Vendor filters with "Show More" functionality
  - Enhanced code block rendering for technical details
- **Historical Archiving**: Stores each day's complete raw data as JSON organized by year (`docs/data/`)
- **History Browsing**: A date switcher in the report loads any archived day's data client-side - the URL hash (`#YYYY-MM-DD`) makes any day directly linkable; days without AI curation degrade gracefully (the AI view is hidden for them)
- **Automated Updates**: Scheduled execution via GitHub Actions

## ⚙️ Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/secnotes/dailycve.git
   cd dailycve
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment (optional)**:
   ```bash
   cp .env.example .env
   # Add your AI API key to .env for AI curation feature
   # Requires AI_API_KEY
   ```

4. **Run locally**:
   ```bash
   python src/main.py
   ```

## 🛠️ Configuration

The system uses several configuration parameters located in `src/config.py`:

- `CVSS_THRESHOLD`: Minimum CVSS score to consider a vulnerability high-risk (default: 7.0)
- `EPSS_THRESHOLD`: Minimum EPSS score for high-risk classification (default: 0.01)
- `LOOKBACK_DAYS`: Number of days to look back for new CVEs (default: 1)

## 📊 Risk Classification Criteria

High-risk vulnerabilities are identified by meeting ANY of these criteria:
- CVSS score > 7.0 (High or Critical severity)
- Listed in CISA KEV (Known Exploited Vulnerabilities catalog)
- EPSS score ≥ 0.01 (higher probability of exploitation)

## 🔧 Customization

You can customize the system behavior by modifying `src/config.py`:
- Adjust risk thresholds
- Change report output paths
- Modify data source URLs
- Enable/disable AI curation

## 🤖 AI Curation

The system supports AI-powered intelligent curation of high-risk vulnerabilities using OpenAI-compatible APIs. To enable:

1. Add your API key to the `.env` file:
   ```bash
   # Configure AI API key (supports multiple providers)
   AI_API_KEY=your_api_key_here
   AI_MODEL=gpt-4o-mini
   AI_BASE_URL=https://api.openai.com/v1
   ```
2. The system will automatically:
   - Filter CVEs with CVSS ≥ 7.0 and non-empty descriptions
   - Send them to AI for analysis and categorization
   - Generate an "AI Curated" view with categorized vulnerabilities and recommendation reasons
3. Supported providers: OpenAI, DeepSeek, Alibaba (DashScope), Moonshot, Zhipu (GLM), and any OpenAI-compatible API

### AI Categories

Vulnerabilities are categorized into the following domains:

| Category | Description |
|----------|-------------|
| 💻 Desktop OS | Windows, macOS, Linux desktop vulnerabilities |
| 📱 Mobile | Android, iOS, mobile app vulnerabilities |
| 📡 IoT | Routers, cameras, embedded devices |
| ☁️ Cloud | AWS, Azure, GCP, cloud services |
| 🌐 Network | Cisco, Fortinet, network infrastructure |
| 🏭 ICS | SCADA, industrial control systems |
| 🔐 Web | Browsers, web frameworks, CMS |
| 🗄️ Database & Middleware | Oracle, MySQL, Apache, Nginx |
| 📌 Other | Anything not fitting above categories |

## ⚠️ Disclaimer

This is an **independent, community-driven project**. It is NOT affiliated with, endorsed by, or connected to MITRE, the CVE Program, NVD, CISA, or any other official vulnerability database. "CVE" and the CVE logo are registered trademarks of The MITRE Corporation. This project merely aggregates publicly available data from these sources for informational purposes. Data accuracy and timeliness depend entirely on the upstream sources; always refer to the official sources for authoritative vulnerability information.