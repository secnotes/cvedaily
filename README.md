# CVE Daily

[English](README.md) | [中文](README_CN.md)

Automated daily CVE monitoring system that collects all vulnerability information from MITRE CVE and generates human-readable reports, allowing for quick customization to filter high-risk vulnerabilities.

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

### UI Toggle

When AI curation is enabled, the HTML report displays a toggle button at the top of the sidebar:
- **📋 All Vulnerabilities**: Default view showing all collected CVEs
- **🤖 AI Curated**: AI-filtered view with categorized vulnerabilities and recommendation reasons

## 📈 Output Files

After execution, the system generates:

- `docs/index.html`: Small static shell (~85 KB) for the interactive dashboard - cards are rendered client-side from the daily JSON in scroll-triggered batches, so the DOM only holds a viewport's worth of cards even on days with 3000+ CVEs
- `docs/assets/report.css|js`: Shared stylesheet/renderer, cache-busted by content hash (browsers reuse them across days)
- `docs/data/[year]/cves_[date].json`: The day's complete raw data - single full-fidelity archive consumed by the report page (bilingual EN/ZH, dark mode, filtering, AI curation toggle all work as before)
- `docs/ai/[year]/ai_curated_[date].json`: Daily AI curation archive with bilingual (EN/ZH) reasons and summary (when AI is enabled); the report's AI view is derived from this data at generation time

Note: daily Markdown archives (`docs/reports/`) were superseded by the JSON data files; existing historical reports remain in git history.