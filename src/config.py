import os
from datetime import datetime

# Configuration for Daily CVE
class Config:
    # CISA KEV feed
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Thresholds for high-risk classification
    CVSS_THRESHOLD = 7.0  # Consider vulnerabilities with CVSS score higher than this as high-risk
    EPSS_THRESHOLD = 0.01  # Consider vulnerabilities with EPSS score higher than or equal to this as high-risk

    # Number of days to look back for new CVEs
    LOOKBACK_DAYS = 1

    # Output settings
    REPORT_HTML_PATH = "docs/index.html"

    # AI Curation settings (requires AI_API_KEY in environment)
    AI_CURATION_ENABLED = os.getenv('AI_API_KEY') is not None
    # Dated archives mirroring the markdown report layout:
    # docs/ai/2026/ai_curated_20260818.json
    AI_CURATED_DIR = "docs/ai"

    # CVE-specific AI categories (English-primary; the curated JSON is
    # generated in English, the HTML adds Chinese at render time)
    AI_CVE_CATEGORIES = [
        "Desktop OS",
        "Mobile Security",
        "IoT Security",
        "Cloud Security",
        "Network Devices",
        "Industrial Control",
        "Web Security",
        "Databases & Middleware",
        "Other",
    ]

    # zh-CN display names for the English category keys above
    AI_CATEGORY_ZH = {
        "Desktop OS": "桌面操作系统",
        "Mobile Security": "移动安全",
        "IoT Security": "IoT安全",
        "Cloud Security": "云安全",
        "Network Devices": "网络设备",
        "Industrial Control": "工业控制",
        "Web Security": "Web安全",
        "Databases & Middleware": "数据库与中间件",
        "Other": "其他",
    }

    # Legacy Chinese category names (old caches) -> English keys, so
    # reports regenerated from an old cache still render with new keys
    AI_CATEGORY_ZH_TO_EN = {zh: en for en, zh in {
        "Desktop OS": "桌面操作系统",
        "Mobile Security": "移动安全",
        "IoT Security": "IoT安全",
        "Cloud Security": "云安全",
        "Network Devices": "网络设备",
        "Industrial Control": "工业控制",
        "Web Security": "Web安全",
        "Databases & Middleware": "数据库与中间件",
        "Other": "其他",
    }.items()}

    # Category icon mapping for HTML display (keyed by English name)
    AI_CATEGORY_ICONS = {
        "Desktop OS": "💻",
        "Mobile Security": "📱",
        "IoT Security": "📡",
        "Cloud Security": "☁️",
        "Network Devices": "🌐",
        "Industrial Control": "🏭",
        "Web Security": "🔐",
        "Databases & Middleware": "🗄️",
        "Other": "📌",
    }

    @staticmethod
    def get_daily_ai_curated_path(date=None):
        """Dated AI curated archive path: docs/ai/2026/ai_curated_20260818.json"""
        d = date or datetime.now()
        return f"{Config.AI_CURATED_DIR}/{d.year}/ai_curated_{d.strftime('%Y%m%d')}.json"