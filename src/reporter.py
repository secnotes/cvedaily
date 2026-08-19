import os
import hashlib
from datetime import datetime
from jinja2 import Template
import html
import re
from decimal import Decimal, ROUND_HALF_UP

def sanitize_vendor_id(name):
    """Sanitize names to create safe IDs for HTML elements.

    The legacy replacement `[^a-zA-Z0-9] -> _` is kept for ASCII names
    so the JS regex in this same file (vendor-filter selection) still
    matches the same id. When the name contains no ASCII letters/digits
    — e.g. the CJK CVE category names like 工业控制 / 网络设备 — fall
    back to a short sha1 prefix so distinct names no longer collapse
    onto the same all-underscore id (which made 移动安全 / 云安全 /
    网络设备 / 工业控制 all share '____' and scrollToCategory could
    only reach the first DOM occurrence).
    """
    sanitized = re.sub(r'[^a-zA-Z0-9]', '_', name).strip('_')
    if sanitized:
        return sanitized
    return hashlib.sha1(name.encode('utf-8')).hexdigest()[:10]  # 40 bits

def round_epss_score(score):
    """Round EPSS score to 3 decimal places with proper rounding"""
    if score is None:
        return 0.0
    # Convert to Decimal for precise rounding
    decimal_score = Decimal(str(score))
    rounded = decimal_score.quantize(Decimal('0.001'), rounding=ROUND_HALF_UP)
    return float(rounded)


def convert_markdown_code_blocks(text):
    """Convert markdown code blocks (backticks) to HTML <code> and <pre><code> tags"""
    import re

    # First, handle triple backtick blocks (```code```) - these should become <pre><code> blocks
    # This handles both indented and non-indented triple backticks
    pattern_block = r'```(\w*)\n?(.*?)```'
    def replace_block(match):
        lang = match.group(1)  # Language identifier if present
        code = match.group(2)
        return f'<pre><code class="{lang}">{html.escape(code.strip())}</code></pre>'

    result = re.sub(pattern_block, replace_block, text, flags=re.DOTALL)

    # Then, handle inline code (single backticks) - these should remain as <code> spans
    pattern_inline = r'`([^`]+)`'
    result = re.sub(pattern_inline, r'<code>\1</code>', result)

    return result

def escape_liquid_syntax(text):
    """Escape Liquid template syntax to prevent Jekyll parsing errors"""
    if not text:
        return text
    # Simple escape using HTML entities to prevent Liquid parsing
    text = text.replace('{%', '&#123;&#37;')
    text = text.replace('%}', '&#37;&#125;')
    text = text.replace('{{', '&#123;&#123;')
    text = text.replace('}}', '&#125;&#125;')
    return text


def generate_markdown_report(cves, output_path='docs/reports/YYYY/daily_cve_YYYYMMDD.md', total_cve_count=None):
    """Generate Markdown report with CVE data"""

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Calculate statistics
    high_risk_count = sum(1 for cve in cves if cve.get('cvss_score', 0) > 7.0)
    cisa_kev_count = sum(1 for cve in cves if cve.get('in_cisa_kev', False))
    epss_high_count = sum(1 for cve in cves if cve.get('epss_score', 0) >= 0.01)
    modified_count = sum(1 for cve in cves if cve.get('entry_type') == 'modified')
    published_count = sum(1 for cve in cves if cve.get('entry_type') == 'published')

    # Add CVSS severity counts
    critical_count = sum(1 for cve in cves if cve.get('cvss_score', 0) >= 9.0)
    high_count = sum(1 for cve in cves if 7.0 <= cve.get('cvss_score', 0) < 9.0)
    medium_count = sum(1 for cve in cves if 4.0 <= cve.get('cvss_score', 0) < 7.0)
    low_count = sum(1 for cve in cves if 0 < cve.get('cvss_score', 0) < 4.0)

    # Collect all unique vendors
    all_vendors = set()
    vendor_counts = {}
    for cve in cves:
        for vendor in cve.get('vendors', []):
            all_vendors.add(vendor)
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

    # Sort vendors by count and limit to top 10
    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)
    top_vendors = dict(sorted_vendors[:10])  # Top 10 vendors

    # Start generating markdown content
    md_content = f"# Daily CVE Report - {datetime.now().strftime('%Y-%m-%d')}\n\n"
    md_content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    md_content += f"Total Vulnerabilities: {total_cve_count if total_cve_count is not None else len(cves)}\n\n"

    # Add Top Vendors table
    md_content += "## Top Vendors by Vulnerability Count\n"
    md_content += "| Vendor | Count |\n"
    md_content += "|--------|-------|\n"
    for vendor, count in top_vendors.items():
        md_content += f"| {vendor} | {count} |\n"
    md_content += "\n\n---\n\n"

    # Add each CVE
    for cve in cves:
        severity = 'low'
        if cve.get('cvss_score', 0) >= 9.0:
            severity = 'critical'
        elif cve.get('cvss_score', 0) >= 7.0:
            severity = 'high'
        elif cve.get('cvss_score', 0) >= 4.0:
            severity = 'medium'

        # Format entry type
        status_text = "Newly Published" if cve.get('entry_type') == 'published' else "Recently Modified"

        # Format vendors
        vendor_list = ', '.join(cve.get('vendors', [])) if cve.get('vendors') else 'N/A'

        md_content += f"## {cve['id']}\n\n"
        # Add both CVSS and EPSS scores to the markdown report
        md_content += f"**CVSS Score:** {cve.get('cvss_score', 0):.1f} | **EPSS Score:** {round_epss_score(cve.get('epss_score', 0)):.3f} | **Status:** {status_text} | **Vendors:** {vendor_list}\n\n"
        # Escape Liquid syntax in description to prevent Jekyll parsing errors
        description = cve.get('description', '') or '（无英文描述）'
        description = escape_liquid_syntax(description)
        md_content += f"{description}\n\n"

        # Add publication and modification dates
        pub_date = cve.get('published_date', '')[:10] if cve.get('published_date') else 'Unknown'
        mod_date = cve.get('last_modified', '')[:10] if cve.get('last_modified') else 'Unknown'
        md_content += f"*Published: {pub_date}*\n"
        if mod_date != pub_date:
            md_content += f"*Last Modified: {mod_date}*\n"
        else:
            md_content += f"*Last Modified: {pub_date}*\n"
        md_content += "\n---\n\n"

    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(md_content)

    print(f"Markdown report generated: {output_path}")


def generate_ai_curated_html(ai_curated, cve_lookup):
    """Generate HTML for AI curated view (returns plain HTML string).

    Category keys in the curated JSON are English (post-migration); old
    caches with Chinese keys are normalized via Config.AI_CATEGORY_ZH_TO_EN.
    Every user-visible string is emitted twice (lang-en / lang-zh spans)
    so the page toggles languages client-side.
    """
    if not ai_curated:
        return ('<div class="no-ai-data"><p>🤖 <span class="lang-en">AI curated data not generated yet</span>'
                '<span class="lang-zh">AI精选数据暂未生成</span></p>'
                '<p><span class="lang-en">Configure an AI API key to enable AI curation</span>'
                '<span class="lang-zh">请配置 AI API 密钥以启用AI精选功能</span></p></div>')

    from config import Config

    category_icons = Config.AI_CATEGORY_ICONS
    category_zh = Config.AI_CATEGORY_ZH
    categories_html = []

    # Model name shown as a badge next to the heading.
    # Prefer the model recorded in the curated cache; fall back to the env var
    # (so reports regenerated from an older cache still display the right model).
    model_name = ai_curated.get('model') or os.environ.get('AI_MODEL') or 'gpt-4o-mini'

    categories = ai_curated.get('categories', {})
    for category_name, curated_cves in categories.items():
        if not curated_cves:
            continue

        # Normalize legacy Chinese keys to English
        en_name = Config.AI_CATEGORY_ZH_TO_EN.get(category_name, category_name)
        zh_name = category_zh.get(en_name, en_name)
        icon = category_icons.get(en_name, '📌')
        cves_html = []

        for curated_cve in curated_cves:
            cve_id = curated_cve.get('id', '')
            # Bilingual reason: prefer explicit *_zh/_en fields added by the
            # translator; fall back to whichever single field exists
            reason_en = curated_cve.get('reason_en') or curated_cve.get('reason', '')
            reason_zh = curated_cve.get('reason_zh') or curated_cve.get('reason', '')

            # Look up full CVE data from the lookup dict
            full_cve = cve_lookup.get(cve_id, {})
            description = full_cve.get('description', '') or 'No description provided yet; see NVD for details.'
            cvss_score = full_cve.get('cvss_score', 0)
            in_cisa = full_cve.get('in_cisa_kev', False)
            epss_score = full_cve.get('epss_score', 0)
            vendors = full_cve.get('vendors', [])

            # Determine severity
            severity = 'low'
            severity_class = 'severity-low'
            if cvss_score >= 9.0:
                severity = 'Critical'
                severity_class = 'severity-critical'
            elif cvss_score >= 7.0:
                severity = 'High'
                severity_class = 'severity-high'
            elif cvss_score >= 4.0:
                severity = 'Medium'
                severity_class = 'severity-medium'

            # Truncate description for card display
            if len(description) > 200:
                description = description[:200] + '...'

            vendors_str = ', '.join(vendors[:5]) if vendors else 'N/A'
            if len(vendors) > 5:
                vendors_str += f' (+{len(vendors)-5})'

            reason_html = ''
            if reason_en or reason_zh:
                reason_html = (
                    f'<div class="ai-cve-reason">💡 '
                    f'<span class="lang-en"><strong>Why it matters:</strong> {html.escape(reason_en)}</span>'
                    f'<span class="lang-zh"><strong>推荐理由:</strong> {html.escape(reason_zh)}</span>'
                    f'</div>'
                )

            cves_html.append(f'''
            <div class="ai-cve-card">
                <div class="ai-cve-header">
                    <a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" class="ai-cve-id">{cve_id}</a>
                    <span class="cve-severity {severity_class}">{severity} ({cvss_score:.1f})</span>
                </div>
                <div class="ai-cve-description">{html.escape(description)}</div>
                <div class="ai-cve-meta">
                    <span>🏢 {vendors_str}</span>
                    {"<span>🇺🇸 CISA KEV</span>" if in_cisa else ""}
                    {f'<span>📈 EPSS: {epss_score:.4f}</span>' if epss_score > 0 else ""}
                </div>
                {reason_html}
            </div>''')

        categories_html.append(f'''
        <div class="ai-category" id="ai-category-{sanitize_vendor_id(en_name)}">
            <h3 class="ai-category-title">{icon} <span class="lang-en">{html.escape(en_name)}</span><span class="lang-zh">{html.escape(zh_name)}</span> ({len(curated_cves)})</h3>
            {"".join(cves_html)}
        </div>''')

    summary_en = ai_curated.get('summary_en') or ai_curated.get('summary', '')
    summary_zh = ai_curated.get('summary_zh') or ai_curated.get('summary', '')
    analysis_date = ai_curated.get('analysis_date', '')
    total_analyzed = ai_curated.get('total_analyzed', 0)

    result_html = f'''
    <div class="ai-summary">
        <h3>🤖 <span class="lang-en">AI Analysis Summary</span><span class="lang-zh">AI智能分析摘要</span> <span class="model-badge" title="{"Model used for this AI curation batch / 本批次 AI 精选所用模型"}">{html.escape(model_name)}</span></h3>
        <div class="ai-summary-text"><span class="lang-en">{html.escape(summary_en)}</span><span class="lang-zh">{html.escape(summary_zh)}</span></div>
        <div class="ai-summary-meta">
            <span><span class="lang-en">Analysis date:</span><span class="lang-zh">分析日期:</span> {analysis_date}</span>
            <span><span class="lang-en">Curated:</span><span class="lang-zh">精选漏洞:</span> {sum(len(v) for v in categories.values())}</span>
            <span><span class="lang-en">Analyzed:</span><span class="lang-zh">候选漏洞:</span> {total_analyzed}</span>
        </div>
    </div>
    {"".join(categories_html)}'''

    return result_html


def generate_ai_category_nav(ai_curated):
    """Generate category navigation for AI sidebar (bilingual)"""
    if not ai_curated:
        return ('<li style="color:var(--meta-text)"><span class="lang-en">No categories</span>'
                '<span class="lang-zh">暂无分类数据</span></li>')

    from config import Config

    category_icons = Config.AI_CATEGORY_ICONS
    category_zh = Config.AI_CATEGORY_ZH
    categories = ai_curated.get('categories', {})
    nav_items = []

    for category_name, curated_cves in categories.items():
        if curated_cves:
            en_name = Config.AI_CATEGORY_ZH_TO_EN.get(category_name, category_name)
            zh_name = category_zh.get(en_name, en_name)
            icon = category_icons.get(en_name, '📌')
            count = len(curated_cves)
            safe_id = sanitize_vendor_id(en_name)
            nav_items.append(
                f'<li onclick="scrollToCategory(\'{safe_id}\')">{icon} '
                f'<span class="lang-en">{html.escape(en_name)}</span>'
                f'<span class="lang-zh">{html.escape(zh_name)}</span> ({count})</li>'
            )

    if not nav_items:
        return ('<li style="color:var(--meta-text)"><span class="lang-en">No categories</span>'
                '<span class="lang-zh">暂无分类数据</span></li>')
    return ''.join(nav_items)


def generate_html_report(cves, output_path='index.html', total_cve_count=None, ai_curated=None):
    """Generate HTML report with CVE data"""

    # Define the HTML template as a string
    html_template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Daily CVE Report - {{ date }}</title>
    <style>
        :root {
            --primary-color: #d32f2f;
            --secondary-color: #1976d2;
            --tertiary-color: #388e3c;
            --warning-color: #ffa726;
            --light-bg: #f5f5f5;
            --card-shadow: 0 4px 8px rgba(0,0,0,0.1);

            /* Light theme colors */
            --bg-color: #f0f2f5;
            --text-color: #333;
            --card-bg: white;
            --border-color: #e0e0e0;
            --input-bg: #f8f9fa;
            --input-border: #e9ecef;
            --meta-text: #666;
            --link-bg: #f0f0f0;
            --link-hover-bg: #e0e0e0;
            --vendor-bg: #e9ecef;
            --vendor-hover-bg: #dee2e6;
            --scrollbar-track: #f1f1f1;
            --scrollbar-thumb: #c1c1c1;
            --scrollbar-hover: #a8a8a8;
            --code-bg: #f4f4f4;
            --code-border: #eaeaea;
            --code-color: #d6336c;
            --pre-bg: #f8f8f8;
            --pre-border: #e1e4e8;
            --summary-gradient-start: #e3f2fd;
            --summary-gradient-end: #f5f5f5;
            --header-border: #d1d5db;

            /* Semantic tag palette — WCAG-validated (fg on bg >= 4.5:1).
               Severity: red -> orange -> yellow -> green (hues kept apart).
               Metric tags: neutral for CVSS (a number, not an alert),
               violet for EPSS, blue for CISA, amber for update/exploit. */
            --critical-fg: #b91c1c;  --critical-bg: #fee2e2;
            --high-fg: #9a3412;      --high-bg: #ffedd5;
            --medium-fg: #a16207;    --medium-bg: #fef9c3;
            --low-fg: #15803d;       --low-bg: #dcfce7;

            --tag-cvss-fg: #334155;  --tag-cvss-bg: #f1f5f9;
            --tag-epss-fg: #4338ca;  --tag-epss-bg: #eef2ff;
            --tag-cisa-fg: #1d4ed8;  --tag-cisa-bg: #dbeafe;
            --tag-exp-fg: #b45309;   --tag-exp-bg: #fffbeb;

            /* Neutral UI chrome — red is reserved for severity + brand */
            --headline-color: #1f2937;
            --github-corner-bg: #24292e;   /* GitHub dark, neutral */
            --github-corner-cat: #ffffff;
            --toggle-active-bg: #374151;
            --show-all-btn-bg: #2e7d32;
            --show-all-btn-hover: #1b5e20;
            --show-more-btn-bg: #1976d2;
            --show-more-btn-hover: #1565c0;
            --ai-accent: #4f46e5;        /* lines / borders on card bg */
            --ai-badge-bg: #4f46e5;      /* badge bg behind white text */
        }

        /* Dark theme colors */
        [data-theme="dark"] {
            --primary-color: #ff6b6b;
            --secondary-color: #64b5f6;
            --tertiary-color: #81c784;
            --warning-color: #ffb74d;
            --light-bg: #1e1e1e;
            --card-shadow: 0 4px 8px rgba(255,255,255,0.05);

            --bg-color: #121212;
            --text-color: #e0e0e0;
            --card-bg: #1e1e1e;
            --border-color: #333;
            --input-bg: #2d2d2d;
            --input-border: #444;
            --meta-text: #aaa;
            --link-bg: #2d2d2d;
            --link-hover-bg: #3d3d3d;
            --vendor-bg: #2d2d2d;
            --vendor-hover-bg: #3d3d3d;
            --scrollbar-track: #2d2d2d;
            --scrollbar-thumb: #555;
            --scrollbar-hover: #666;
            --code-bg: #2d2d2d;
            --code-border: #444;
            --code-color: #f07178;
            --pre-bg: #1e1e1e;
            --pre-border: #333;
            --summary-gradient-start: #1a237e;
            --summary-gradient-end: #1e1e1e;
            --header-border: #374151;

            /* Dark tag palette — same roles, stepped for the dark surface
               (all fg-on-bg pairs validated >= 4.5:1 on their bg) */
            --critical-fg: #ff8a80;  --critical-bg: #4a1c1c;
            --high-fg: #ffab40;      --high-bg: #4a2c00;
            --medium-fg: #ffd740;    --medium-bg: #4a3c00;
            --low-fg: #a5d6a7;       --low-bg: #1c4a1c;

            --tag-cvss-fg: #cbd5e1;  --tag-cvss-bg: #1e293b;
            --tag-epss-fg: #c7d2fe;  --tag-epss-bg: #312e81;
            --tag-cisa-fg: #82b1ff;  --tag-cisa-bg: #1a237e;
            --tag-exp-fg: #ffab40;   --tag-exp-bg: #4a2c00;

            --headline-color: #f3f4f6;
            --github-corner-bg: #d1d5db;
            --github-corner-cat: #1f2937;
            --toggle-active-bg: #52525b;
            --show-all-btn-bg: #2e7d32;
            --show-all-btn-hover: #388e3c;
            --show-more-btn-bg: #1565c0;
            --show-more-btn-hover: #1976d2;
            --ai-accent: #818cf8;        /* lighter indigo reads on dark card */
            --ai-badge-bg: #4f46e5;      /* white badge text: 6.29:1 */
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            transition: background-color 0.3s ease, color 0.3s ease;
        }

        /* Theme switch performance: the page holds thousands of CVE cards;
           animating color properties on all of them at once freezes the
           main thread. Kill ALL transitions for one frame around the
           data-theme flip so colors change instantly, while hover/other
           transitions keep working normally afterwards. */
        .theme-switching *,
        .theme-switching *::before,
        .theme-switching *::after {
            transition: none !important;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 1fr 300px;
            gap: 25px;
        }

        .main-content {
            background-color: var(--card-bg);
            padding: 25px;
            border-radius: 12px;
            box-shadow: var(--card-shadow);
            transition: background-color 0.3s ease, box-shadow 0.3s ease;
        }

        .sidebar {
            background-color: var(--card-bg);
            padding: 20px;
            border-radius: 12px;
            box-shadow: var(--card-shadow);
            height: fit-content;
            position: sticky;
            top: 20px;
            max-height: 90vh;  /* 增加最大高度到90vh，提供更多空间 */
            overflow-y: auto;  /* 允许垂直滚动 */
            transition: background-color 0.3s ease, box-shadow 0.3s ease;
        }

        /* 自定义滚动条样式 */
        .sidebar::-webkit-scrollbar {
            width: 8px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: var(--scrollbar-track);
            border-radius: 4px;
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: var(--scrollbar-thumb);
            border-radius: 4px;
        }

        .sidebar::-webkit-scrollbar-thumb:hover {
            background: var(--scrollbar-hover);
        }

        header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 3px solid var(--header-border);
            padding-bottom: 15px;
        }

        h1 {
            color: var(--headline-color);
            margin: 0;
            font-size: 2.2em;
        }

        .filter-status {
            margin-bottom: 25px;
        }

        .current-filters {
            padding: 10px;
            background-color: var(--input-bg);
            border-radius: 8px;
            border: 1px solid var(--input-border);
        }

        .current-filters strong {
            display: block;
            margin-bottom: 5px;
            color: var(--text-color);
        }

        #active-filters {
            color: var(--meta-text);
            font-size: 0.9em;
        }

        .filter-section:not(:last-child) {
            margin-bottom: 30px;
        }

        .filter-title {
            font-weight: bold;
            margin-bottom: 10px;
            color: var(--text-color);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 5px;
        }

        .filter-list {
            list-style: none;
            padding: 0;
        }

        .filter-item {
            padding: 2px 0;
            cursor: pointer;
            color: var(--secondary-color);
        }

        .filter-item:hover {
            text-decoration: underline;
        }

        .extra-vendor {
            background-color: transparent;
        }

        /* CVSS severity filter styles */
        .filter-critical {
            background-color: var(--critical-bg);
            color: var(--critical-fg);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            margin: 2px 5px 2px 0;
            display: inline-block;
            cursor: pointer;
            font-weight: normal;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .filter-critical:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        .filter-high {
            background-color: var(--high-bg);
            color: var(--high-fg);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            margin: 2px 5px 2px 0;
            display: inline-block;
            cursor: pointer;
            font-weight: normal;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .filter-high:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        .filter-medium {
            background-color: var(--medium-bg);
            color: var(--medium-fg);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            margin: 2px 5px 2px 0;
            display: inline-block;
            cursor: pointer;
            font-weight: normal;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .filter-medium:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        .filter-low {
            background-color: var(--low-bg);
            color: var(--low-fg);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            margin: 2px 5px 2px 0;
            display: inline-block;
            cursor: pointer;
            font-weight: normal;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .filter-low:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        /* Status filter styles */
        .filter-modified-item {
            background-color: var(--tag-cisa-bg);
            color: var(--tag-cisa-fg);
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 4px;
            display: block;
        }

        .filter-published-item {
            background-color: var(--low-bg);
            color: var(--low-fg);
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 4px;
            display: block;
        }

        /* Card-style metric tags for sidebar */
        .filter-metric-tag {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: normal;
            cursor: pointer;
            margin: 2px 5px 2px 0;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .filter-metric-tag:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
            text-decoration: underline;
        }

        .filter-metric-tag.selected {
            font-weight: bold;
            text-decoration: underline;
            /* keep the semantic bg/fg colors; selection is marked by
               weight + underline + a ring, not by repainting the chip */
            outline: 2px solid var(--text-color);
            outline-offset: 1px;
        }

        .filter-tag-exp {
            background-color: var(--tag-exp-bg);
            color: var(--tag-exp-fg);
        }

        .filter-tag-cvss {
            background-color: var(--tag-cvss-bg);
            color: var(--tag-cvss-fg);
        }

        .summary-box {
            background: linear-gradient(135deg, var(--summary-gradient-start), var(--summary-gradient-end));
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 25px;
            transition: background 0.3s ease;
        }

        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .stat-card {
            background: var(--card-bg);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            box-shadow: var(--card-shadow);
            cursor: pointer;
            transition: transform 0.2s, background-color 0.3s ease, box-shadow 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-3px);
        }

        .stat-number {
            font-size: 1.8em;
            font-weight: bold;
            color: var(--headline-color);
        }

        .cve-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }

        .cve-card {
            border: 1px solid var(--border-color);
            border-radius: 10px;
            overflow: hidden;
            /* no color transitions: thousands of cards animating bg/border
               on theme switch janks; hover transform/shadow is per-card */
            transition: transform 0.2s, box-shadow 0.2s;
            background: var(--card-bg);
            display: none; /* Initially hide all cards */
            max-height: 700px; /* 增加卡片最大高度以容纳更多内容 */
            display: flex;
            flex-direction: column;
            box-sizing: border-box; /* 确保padding包含在高度内 */
            min-height: 320px; /* 设置最小高度以保持一致性 */
        }

        .cve-card.filtered-in {
            display: flex;
        }

        .cve-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 16px rgba(0,0,0,0.15);
        }

        .cve-header {
            background: linear-gradient(135deg, var(--card-bg), var(--input-bg));
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-shrink: 0; /* 防止头部被压缩 */
        }

        .cve-id {
            font-weight: bold;
            font-size: 1.1em;
            color: var(--secondary-color);
        }

        .cve-severity {
            font-weight: bold;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
        }

        .severity-critical {
            background-color: var(--critical-bg);
            color: var(--critical-fg);
        }

        .severity-high {
            background-color: var(--high-bg);
            color: var(--high-fg);
        }

        .severity-medium {
            background-color: var(--medium-bg);
            color: var(--medium-fg);
        }

        .severity-low {
            background-color: var(--low-bg);
            color: var(--low-fg);
        }

        .cve-metrics {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 10px 0;
        }

        .metric-tag {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: 500;
            cursor: pointer;
        }

        .metric-tag:hover {
            opacity: 0.8;
        }

        .tag-cvss {
            background-color: var(--tag-cvss-bg);
            color: var(--tag-cvss-fg);
        }

        .tag-epss {
            background-color: var(--tag-epss-bg);
            color: var(--tag-epss-fg);
        }

        .tag-cisa {
            background-color: var(--tag-cisa-bg);
            color: var(--tag-cisa-fg);
        }

        .tag-exp {
            background-color: var(--tag-exp-bg);
            color: var(--tag-exp-fg);
        }

        .cve-vendors {
            margin: 10px 0;
            padding: 10px;
            background-color: var(--input-bg);
            border-radius: 8px;
            font-size: 0.9em;
        }

        .cve-vendor-tag {
            display: inline-block;
            padding: 3px 8px;
            margin: 2px;
            background-color: var(--vendor-bg);
            border-radius: 10px;
            font-size: 0.8em;
            cursor: pointer;
            transition: none; /* thousands of these; hover bg flip is fine without animation */
        }

        .cve-vendor-tag:hover {
            background-color: var(--vendor-hover-bg);
        }

        .cve-body {
            padding: 20px;
            display: flex;
            flex-direction: column;
            flex: 1;
            overflow: hidden;
            min-height: 0; /* Allow content to scroll if needed */
        }

        .cve-description {
            margin-bottom: 15px;
            line-height: 1.6; /* 调整行高 */
            overflow: hidden;
            text-overflow: ellipsis;
            display: -webkit-box;
            -webkit-line-clamp: 6; /* 限制为6行 */
            -webkit-box-orient: vertical;
            word-break: break-word; /* 确保长单词也能适当换行 */
            flex-shrink: 0; /* 防止被压缩 */
        }

        /* Code block styling */
        code {
            background-color: var(--code-bg);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', Consolas, Monaco, monospace;
            font-size: 0.9em;
            color: var(--code-color);
            border: 1px solid var(--code-border);
        }

        pre {
            background-color: var(--pre-bg);
            border: 1px solid var(--pre-border);
            border-radius: 6px;
            padding: 12px;
            overflow: auto;
            font-family: 'Courier New', Consolas, Monaco, monospace;
            line-height: 1.4;
            margin: 10px 0;
        }

        pre code {
            background: none;
            padding: 0;
            border: none;
            color: inherit;
        }

        /* Container for elements that should be grouped at the bottom */
        .cve-content-group {
            display: flex;
            flex-direction: column;
            margin-top: auto; /* Push to the bottom */
            flex-shrink: 0; /* Prevent from shrinking */
        }

        .cve-links {
            margin-top: 15px;
            padding-top: 10px;
            border-top: 1px solid var(--border-color);
            flex-shrink: 0; /* 防止被压缩 */
        }

        .link-item {
            display: inline-block;
            margin-right: 15px;
            margin-bottom: 8px;
        }

        .link-btn {
            display: inline-block;
            padding: 6px 12px;
            background-color: var(--link-bg);
            color: var(--text-color);
            text-decoration: none;
            border-radius: 6px;
            font-size: 0.85em;
            transition: none; /* thousands of these across cards */
        }

        .link-btn:hover {
            background-color: var(--link-hover-bg);
        }

        .cve-meta {
            font-size: 0.85em;
            color: var(--meta-text);
            padding-top: 10px;
            border-top: 1px dashed var(--border-color);
            flex-shrink: 0; /* 防止被压缩 */
        }

        .no-cves {
            text-align: center;
            padding: 60px 20px;
            color: var(--meta-text);
            font-size: 1.2em;
        }

        .info-icon {
            margin-right: 5px;
        }

        .show-all-btn {
            display: block;
            width: 100%;
            padding: 10px;
            background-color: var(--show-all-btn-bg);
            color: white;
            text-align: center;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 15px;
            font-weight: bold;
        }

        .show-all-btn:hover {
            background-color: var(--show-all-btn-hover);
        }

        .show-more-btn {
            display: block;
            width: 100%;
            padding: 8px;
            background-color: var(--show-more-btn-bg);
            color: white;
            text-align: center;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 10px;
            font-size: 0.9em;
        }

        .show-more-btn:hover {
            background-color: var(--show-more-btn-hover);
        }

        .filter-item.selected {
            font-weight: bold;
            background-color: var(--input-bg);
            padding: 3px 0;
            text-decoration: underline;
        }

        @media (max-width: 1200px) {
            }
        }

        @media (min-width: 1201px) and (min-height: 801px) and (max-height: 1000px) {
            /* 中等高度屏幕 */
            .sidebar {
                max-height: 80vh;
            }
        }

        @media (min-width: 1201px) and (min-height: 1001px) {
            /* 高屏幕 */
            .sidebar {
                max-height: 85vh;
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: 15px;
                grid-template-columns: 1fr;
            }

            .cve-grid {
                grid-template-columns: 1fr;
            }

            .cve-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }

            .cve-metrics {
                width: 100%;
            }

            .cve-card {
                max-height: none; /* 在移动设备上去除卡片最大高度限制，允许内容完全展开 */
                min-height: auto; /* 让卡片高度适应内容 */
            }

            .cve-description {
                -webkit-line-clamp: 10; /* 在移动设备上允许显示更多行文本 */
            }
        }

        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 40px 20px;
            color: var(--meta-text);
            font-size: 0.85rem;
        }

        .footer a {
            color: var(--secondary-color);
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }

        .footer p {
            margin: 5px 0;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .separator {
            color: var(--meta-text);
        }

        .github-link {
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }

        .github-icon {
            width: 16px;
            height: 16px;
            vertical-align: -0.15em;
            margin-right: 4px;
        }

        @media (max-width: 480px) {
            /* 针对更小的屏幕进行额外优化 */
            .cve-card {
                min-height: auto;
            }

            .cve-header {
                padding: 12px 15px; /* 减少内边距 */
            }

            .cve-body {
                padding: 15px; /* 减少内边距 */
            }

            .cve-description {
                -webkit-line-clamp: 8; /* 在极小屏幕上显示较少的行数 */
            }

            .metric-tag {
                padding: 3px 8px; /* 减少标签内边距 */
                font-size: 0.75em; /* 稍微缩小字体 */
            }

            .cve-vendor-tag {
                padding: 2px 6px; /* 减少供应商标签内边距 */
                font-size: 0.75em; /* 稍微缩小字体 */
            }
        }

        /* Dark theme for severity/filter/tag chips and buttons is carried
           entirely by the CSS variables above — no per-class overrides. */
    </style>

    <!-- Toast animation styles -->
    <style>
        @keyframes fadeInOut {
            0% { opacity: 0; transform: translate(-50%, 20px); }
            15% { opacity: 1; transform: translate(-50%, 0); }
            85% { opacity: 1; transform: translate(-50%, 0); }
            100% { opacity: 0; transform: translate(-50%, 20px); }
        }

        .filter-count-toast {
            position: fixed;
            bottom: 30px;
            left: 50%;
            background-color: rgba(0, 0, 0, 0.85);
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 15px;
            font-weight: bold;
            z-index: 10000;
            animation: fadeInOut 2s ease-in-out;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }

        /* View toggle buttons */
        .view-toggle {
            display: flex;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 15px;
            border: 1px solid var(--border-color);
            transition: border-color 0.3s ease;
        }

        .view-toggle-btn {
            flex: 1;
            padding: 10px 15px;
            border: none;
            cursor: pointer;
            font-size: 0.95em;
            font-weight: 500;
            background-color: var(--input-bg);
            color: var(--text-color);
            transition: all 0.3s ease;
        }

        .view-toggle-btn:first-child {
            border-right: 1px solid var(--border-color);
        }

        .view-toggle-btn:hover {
            background-color: var(--vendor-hover-bg);
        }

        .view-toggle-btn.active {
            background-color: var(--toggle-active-bg);
            color: white;
        }

        /* View switching */
        .original-view {
            display: block;
        }

        .original-view.hidden {
            display: none;
        }

        .ai-view {
            display: none;
        }

        .ai-view.active {
            display: block;
        }

        .sidebar-section {
            transition: all 0.3s ease;
        }

        .sidebar-section.hidden {
            display: none;
        }

        /* AI category section */
        .ai-category {
            margin-bottom: 2rem;
        }

        .ai-category-title {
            font-size: 1.3rem;
            color: var(--text-color);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--ai-accent);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* AI summary block */
        .ai-summary {
            padding: 0.5rem 0 1.5rem 0;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
        }

        .ai-summary h3 {
            margin-bottom: 0.75rem;
            color: var(--text-color);
            font-size: 1.2rem;
            font-weight: 600;
        }

        .model-badge {
            display: inline-block;
            background: var(--ai-badge-bg);
            color: white;
            font-size: 0.7rem;
            padding: 3px 12px;
            border-radius: 12px;
            font-weight: 500;
            margin-left: 10px;
            vertical-align: middle;
            letter-spacing: 0.3px;
            box-shadow: 0 1px 3px rgba(79, 70, 229, 0.3);
        }

        .ai-summary-text {
            color: var(--meta-text);
            line-height: 1.7;
            padding-left: 1rem;
            border-left: 3px solid var(--ai-accent);
            margin-bottom: 0.75rem;
        }

        .ai-summary-meta {
            display: flex;
            gap: 1.5rem;
            color: var(--meta-text);
            font-size: 0.85rem;
            flex-wrap: wrap;
        }

        /* AI CVE card */
        .ai-cve-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.2rem 1.5rem;
            margin-bottom: 1rem;
            box-shadow: var(--card-shadow);
            /* no color transitions: thousands of cards animating bg/border
               on theme switch janks; hover transform/shadow is per-card */
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .ai-cve-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 16px rgba(0,0,0,0.12);
        }

        .ai-cve-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }

        .ai-cve-id {
            font-weight: bold;
            font-size: 1.05em;
            color: var(--secondary-color);
            text-decoration: none;
        }

        .ai-cve-id:hover {
            text-decoration: underline;
        }

        .ai-cve-description {
            color: var(--text-color);
            font-size: 0.92em;
            line-height: 1.6;
            margin-bottom: 0.75rem;
        }

        .ai-cve-meta {
            display: flex;
            gap: 1rem;
            color: var(--meta-text);
            font-size: 0.85rem;
            flex-wrap: wrap;
        }

        .ai-cve-reason {
            color: var(--meta-text);
            font-size: 0.88rem;
            margin-top: 0.75rem;
            padding-top: 0.75rem;
            border-top: 1px dashed var(--border-color);
            line-height: 1.5;
        }

        /* AI category navigation in sidebar */
        .ai-category-nav {
            background: var(--input-bg);
            border-radius: 8px;
            padding: 1rem;
            transition: background-color 0.3s ease;
        }

        .ai-category-nav h4 {
            margin-bottom: 0.75rem;
            color: var(--text-color);
        }

        .ai-category-nav ul {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .ai-category-nav li {
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            color: var(--secondary-color);
            transition: all 0.2s ease;
        }

        .ai-category-nav li:hover {
            color: var(--primary-color);
            padding-left: 5px;
        }

        .ai-category-nav li:last-child {
            border-bottom: none;
        }

        /* No AI data placeholder */
        .no-ai-data {
            text-align: center;
            padding: 3rem 2rem;
            color: var(--meta-text);
            background: var(--input-bg);
            border-radius: 12px;
            font-size: 1.1em;
            line-height: 1.8;
        }

        /* AI sidebar stats */
        .ai-sidebar-stats {
            margin-top: 1rem;
            padding: 0.75rem;
            background: var(--input-bg);
            border-radius: 8px;
            font-size: 0.85rem;
            color: var(--meta-text);
            transition: background-color 0.3s ease;
        }
    </style>

    <!-- Theme + language initialization - must be in head to prevent flash -->
    <script>
        (function() {
            const savedTheme = localStorage.getItem('theme');
            const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

            if (savedTheme) {
                document.documentElement.setAttribute('data-theme', savedTheme);
            } else if (systemPrefersDark) {
                document.documentElement.setAttribute('data-theme', 'dark');
            }

            // Default to English; 'zh' opts into the Chinese UI
            if (localStorage.getItem('cve-lang') === 'zh') {
                document.documentElement.classList.add('lang-mode-zh');
            }
        })();
    </script>
    <!-- Bilingual content: English by default, Chinese only in ZH mode -->
    <style>
        .lang-zh { display: none; }
        html.lang-mode-zh .lang-en { display: none; }
        html.lang-mode-zh .lang-zh { display: inline; }
        html.lang-mode-zh .lang-zh.lang-block { display: block; }
    </style>
</head>
<body>
    <a href="https://github.com/secnotes/dailycve" class="github-corner" aria-label="View source on GitHub">
        <svg width="80" height="80" viewBox="0 0 250 250" class="github-corner-svg" aria-hidden="true">
            <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z" class="github-corner-bg"></path>
            <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
            <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
        </svg>
    </a>
    <style>
        /* Standard top-right ribbon SVG rotated -90° into the top-left
           corner — the octocat path was drawn for the top-right triangle,
           so rotating the whole SVG (not mirroring) keeps the cat inside
           the triangle. */
        .github-corner-svg {
            fill: var(--github-corner-bg);
            color: var(--github-corner-cat);
            position: fixed;
            top: 0;
            border: 0;
            left: 0;
            /* mirror the standard top-right ribbon into the top-left corner:
               scaleX(-1) (origin 0,0) flips it to x<0, the leading
               translateX(80px) shifts it back so the (80,0)-(80,80)-(0,80)
               triangle lands on (0,0)-(0,80)-(80,80) with the hypotenuse
               facing into the page; the octocat mirrors with it */
            transform: translateX(80px) scaleX(-1);
            transform-origin: 0 0;
            z-index: 1000;
            transition: fill 0.3s ease;
        }

        .github-corner:hover .octo-arm{animation:octocat-wave 560ms ease-in-out}
        @keyframes octocat-wave{
            0%,100%{transform:rotate(0)}
            20%,60%{transform:rotate(-25deg)}
            40%,80%{transform:rotate(10deg)}
        }
        @media (max-width:500px){
            .github-corner:hover .octo-arm{animation:none}
            .github-corner .octo-arm{animation:octocat-wave 560ms ease-in-out}
        }
    </style>
    <!-- Floating controls: theme + language (top-right), back-to-top (bottom-right) -->
    <style>
        .float-controls {
            position: fixed;
            top: 16px;
            right: 16px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            z-index: 1100;
        }
        .float-btn {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            border: 1px solid var(--border-color);
            background: var(--card-bg);
            color: var(--text-color);
            box-shadow: var(--card-shadow);
            cursor: pointer;
            font-size: 1.05rem;
            line-height: 1;
            transition: all 0.2s ease;
        }
        .float-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        .float-btn svg {
            width: 20px;
            height: 20px;
            fill: var(--text-color);
            transition: fill 0.3s ease;
        }
        .float-btn .sun-icon { display: none; }
        .float-btn .moon-icon { display: block; }
        [data-theme="dark"] .float-btn .sun-icon { display: block; }
        [data-theme="dark"] .float-btn .moon-icon { display: none; }
        .float-btn .lang-label-en { display: block; }
        .float-btn .lang-label-zh { display: none; }
        html.lang-mode-zh .float-btn .lang-label-en { display: none; }
        html.lang-mode-zh .float-btn .lang-label-zh { display: block; }

        #back-to-top {
            position: fixed;
            bottom: 24px;
            right: 16px;
            width: 44px;
            height: 44px;
            border-radius: 50%;
            border: none;
            background: var(--toggle-active-bg);
            color: white;
            font-size: 1.3rem;
            cursor: pointer;
            box-shadow: 0 4px 10px rgba(0,0,0,0.25);
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.3s ease, visibility 0.3s ease;
            z-index: 1100;
        }
        #back-to-top.show {
            opacity: 1;
            visibility: visible;
        }
    </style>
    <div class="float-controls">
        <button class="float-btn" onclick="toggleTheme()" aria-label="Toggle theme" title="Dark mode / 深色模式">
            <svg class="moon-icon" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 3c.132 0 .263 0 .393 0a7.5 7.5 0 0 0 7.92 12.446a9 9 0 1 1 -8.313 -12.454z"/>
            </svg>
            <svg class="sun-icon" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37a.996.996 0 00-1.41 0 .996.996 0 000 1.41l1.06 1.06c.39.39 1.03.39 1.41 0 .39-.39.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96a.996.996 0 000-1.41.996.996 0 00-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36a.996.996 0 000-1.41.996.996 0 00-1.41 0L4.58 18.36c-.39.39-.39 1.03 0 1.41.39.39 1.03.39 1.41 0l1.06-1.06z"/>
            </svg>
        </button>
        <button class="float-btn" onclick="toggleLang()" aria-label="Switch language / 切换语言" title="切换到中文 / Switch to Chinese" style="font-weight: 700;">
            <span class="lang-label-en">中</span>
            <span class="lang-label-zh">EN</span>
        </button>
    </div>
    <button id="back-to-top" onclick="scrollToTop()" title="Back to top / 回到顶部">↑</button>
    <div class="container">
        <div class="main-content">
            <header>
                <h1>🔍 <span class="lang-en">Daily CVE Report - {{ date }}</span><span class="lang-zh">每日CVE报告 - {{ date }}</span></h1>
                <p>
                    <span class="lang-en">An advanced automated vulnerability monitoring system that sources data from MITRE CVE,<br />enabling quick filtering of high-risk vulnerabilities with intuitive visual reports.</span>
                    <span class="lang-zh">一个先进的自动化漏洞监测系统，数据来源于 MITRE CVE，<br />通过直观的可视化报告快速筛选高危漏洞。</span>
                </p>
            </header>

            <div class="summary-box">
                <h2>📊 <span class="lang-en">Summary</span><span class="lang-zh">摘要</span></h2>
                <p><strong><span class="lang-en">Report Generated:</span><span class="lang-zh">报告生成时间:</span></strong> {{ generated_time }}</p>

                <div class="summary-stats">
                    <div class="stat-card" onclick="applySingleFilter('all')">
                        <div class="stat-number">{{ cve_count }}</div>
                        <div><span class="lang-en">Total Vulnerabilities</span><span class="lang-zh">漏洞总数</span></div>
                    </div>
                    <div class="stat-card" onclick="applySingleFilter('high-risk')">
                        <div class="stat-number">{{ high_risk_count }}</div>
                        <div><span class="lang-en">High Risk (CVSS &gt; 7.0)</span><span class="lang-zh">高危 (CVSS &gt; 7.0)</span></div>
                    </div>
                    <div class="stat-card" onclick="applySingleFilter('cisa')">
                        <div class="stat-number">{{ cisa_kev_count }}</div>
                        <div><span class="lang-en">In CISA KEV</span><span class="lang-zh">CISA KEV 收录</span></div>
                    </div>
                    <div class="stat-card" onclick="applySingleFilter('epss')">
                        <div class="stat-number">{{ epss_high_count }}</div>
                        <div><span class="lang-en">High EPSS (≥0.01)</span><span class="lang-zh">高 EPSS (≥0.01)</span></div>
                    </div>
                </div>
            </div>

            <!-- Original View (All Vulnerabilities) -->
            <div class="original-view" id="original-view">
            {% if cves %}
                <div class="cve-grid" id="cve-grid">
                    {% for cve in cves %}
                    <div class="cve-card filtered-in" id="cve-{{ cve.id|replace('-', '_') }}"
                         data-cvss="{{ cve.cvss_score }}"
                         data-epss="{{ cve.epss_score }}"
                         data-cisa="{{ cve.in_cisa_kev|lower }}"
                         data-modified="{{ 'True' if cve.entry_type == 'modified' else 'False' }}"
                         data-vendors="{{ cve.vendors|join(',') }}">
                        <div class="cve-header">
                            <div class="cve-id">{{ cve.id }}</div>
                            <div class="cve-severity severity-{{ cve.severity }}">{{ cve.severity|title }}</div>
                        </div>

                        <div class="cve-body">
                            <div class="cve-description">
                                {{ convert_md_code(cve.description)|safe }}
                            </div>

                            <!-- Group all other content together to align at bottom -->
                            <div class="cve-content-group">
                                {% if cve.cvss_score >= 0 or cve.epss_score > 0 or cve.in_cisa_kev %}
                                <div class="cve-metrics">
                                    <span class="metric-tag tag-cvss" onclick="applySingleFilterByCVSS({{ cve.cvss_score }})">🛡️ CVSS: {{ "%.1f"|format(cve.cvss_score) }}</span>

                                    {% if cve.epss_score > 0 %}
                                        <span class="metric-tag tag-epss" onclick="applySingleFilterByEPSS({{ "%.3f"|format(round_epss(cve.epss_score)) }})">📈 EPSS: {{ "%.3f"|format(round_epss(cve.epss_score)) }}</span>
                                    {% endif %}

                                    {% if cve.in_cisa_kev %}
                                        <span class="metric-tag tag-cisa" onclick="toggleStatusFilter('cisa')">🇺🇸 CISA KEV</span>
                                    {% endif %}

                                    {% if cve.entry_type == 'modified' %}
                                        <span class="metric-tag tag-exp" onclick="toggleStatusFilter('modified')">🔄 <span class="lang-en">Recently Updated</span><span class="lang-zh">最近更新</span></span>
                                    {% else %}
                                        <span class="metric-tag tag-cisa" onclick="toggleStatusFilter('published')">🆕 <span class="lang-en">New Entry</span><span class="lang-zh">新条目</span></span>
                                    {% endif %}

                                    {% if cve.exploits %}
                                        <span class="metric-tag tag-exp">💥 <span class="lang-en">Known Exploits</span><span class="lang-zh">已知利用</span></span>
                                    {% endif %}
                                </div>
                                {% endif %}

                                {% if cve.vendors %}
                                <div class="cve-vendors">
                                    <strong><span class="lang-en">Vendors:</span><span class="lang-zh">厂商:</span></strong>
                                    {% for vendor in cve.vendors %}
                                    <span class="cve-vendor-tag" onclick="toggleVendorFilter('{{ vendor }}')">{{ vendor }}</span>
                                    {% endfor %}
                                </div>
                                {% endif %}

                                <div class="cve-links">
                                    <div class="link-item">
                                        <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ cve.id }}" target="_blank" class="link-btn">📝 MITRE CVE</a>
                                    </div>
                                    <div class="link-item">
                                        <a href="https://nvd.nist.gov/vuln/detail/{{ cve.id }}" target="_blank" class="link-btn">🔍 <span class="lang-en">NVD Details</span><span class="lang-zh">NVD 详情</span></a>
                                    </div>
                                    {% if cve.epss_score > 0 %}
                                    <div class="link-item">
                                        <a href="https://epss.cyentia.com/?cve={{ cve.id }}" target="_blank" class="link-btn">📊 <span class="lang-en">EPSS Score</span><span class="lang-zh">EPSS 评分</span></a>
                                    </div>
                                    {% endif %}
                                </div>

                                <div class="cve-meta">
                                    <strong><span class="lang-en">Published:</span><span class="lang-zh">发布:</span></strong> {{ cve.published_date[:10] if cve.published_date else 'Unknown' }}
                                    {% if cve.last_modified and cve.last_modified != cve.published_date %}
                                    | <strong><span class="lang-en">Modified:</span><span class="lang-zh">更新:</span></strong> {{ cve.last_modified[:10] }}
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            {% else %}
                <div class="no-cves">
                    <p>✅ <span class="lang-en">No high-risk vulnerabilities detected for {{ date }}.</span><span class="lang-zh">{{ date }} 未检测到高危漏洞。</span></p>
                </div>
            {% endif %}
            </div>

            <!-- AI Curated View -->
            <div class="ai-view" id="ai-view">
                {{ ai_curated_html|safe }}
            </div>
        </div>

        <div class="sidebar">
            {% if ai_curated %}
            <!-- View Toggle Buttons -->
            <div class="view-toggle">
                <button class="view-toggle-btn" onclick="switchView('ai')">🤖 <span class="lang-en">AI Curated</span><span class="lang-zh">AI精选</span></button>
                <button class="view-toggle-btn active" onclick="switchView('original')">📋 <span class="lang-en">All Vulnerabilities</span><span class="lang-zh">全部漏洞</span></button>
            </div>
            {% endif %}

            <!-- Original Sidebar (Filters) -->
            <div class="sidebar-section" id="original-sidebar">
            <div class="filter-section">
                <div class="filter-title">🛡️ <span class="lang-en">Filter by CVSS Severity</span><span class="lang-zh">按 CVSS 严重度筛选</span></div>
                <div style="display: flex; flex-wrap: wrap; gap: 5px;">
                    <span class="filter-item filter-critical" id="filter-critical" onclick="applySingleFilterBySeverity('critical')">Critical ({{ critical_count }})</span>
                    <span class="filter-item filter-high" id="filter-high" onclick="applySingleFilterBySeverity('high')">High ({{ high_count }})</span>
                    <span class="filter-item filter-medium" id="filter-medium" onclick="applySingleFilterBySeverity('medium')">Medium ({{ medium_count }})</span>
                    <span class="filter-item filter-low" id="filter-low" onclick="applySingleFilterBySeverity('low')">Low ({{ low_count }})</span>
                </div>
            </div>

            <div class="filter-section">
                <div class="filter-title">🏷️ <span class="lang-en">Filter by Status</span><span class="lang-zh">按状态筛选</span></div>
                <div style="display: flex; flex-wrap: wrap; gap: 5px;">
                    <span class="filter-metric-tag filter-tag-exp" id="filter-modified" onclick="toggleStatusFilter('modified')">🔄 <span class="lang-en">Recently Modified ({{ modified_count }})</span><span class="lang-zh">最近修改 ({{ modified_count }})</span></span>
                    <span class="filter-metric-tag filter-tag-cvss" id="filter-published" onclick="toggleStatusFilter('published')">🆕 <span class="lang-en">Newly Published ({{ published_count }})</span><span class="lang-zh">新发布 ({{ published_count }})</span></span>
                </div>
            </div>

            {% if all_vendors_list %}
            <div class="filter-section">
                <div class="filter-title">🏢 <span class="lang-en">Filter by Vendor</span><span class="lang-zh">按厂商筛选</span></div>
                <ul class="filter-list" id="vendor-filter-list">
                    {% for vendor in initial_vendors %}
                    <li class="filter-item" id="filter-vendor-{{ sanitize_vendor_id(vendor) }}" onclick="toggleVendorFilter('{{ vendor }}')" style="display:block;">{{ vendor }} ({{ all_sorted_vendors[vendor] }})</li>
                    {% endfor %}
                    {% for vendor in all_vendors_list %}
                    <li class="filter-item extra-vendor" id="filter-vendor-{{ sanitize_vendor_id(vendor) }}" onclick="toggleVendorFilter('{{ vendor }}')" style="display:none;">{{ vendor }} ({{ all_sorted_vendors[vendor] }})</li>
                    {% endfor %}
                </ul>
                {% if all_vendors_list|length > 19 %}
                <button class="show-more-btn" onclick="toggleMoreVendors()" id="show-more-btn"><span class="lang-en">Show More Vendors ({{ all_vendors_list|length - 19 }} more)</span><span class="lang-zh">显示更多厂商 (还有 {{ all_vendors_list|length - 19 }})</span></button>
                {% endif %}
            </div>
            {% endif %}
            </div>

            <!-- AI Sidebar (Category Navigation) -->
            {% if ai_curated %}
            <div class="sidebar-section hidden" id="ai-sidebar">
                <div class="ai-category-nav">
                    <h4>📋 <span class="lang-en">Categories</span><span class="lang-zh">分类目录</span></h4>
                    <ul>
                        {{ ai_category_nav|safe }}
                    </ul>
                </div>
                <div class="ai-sidebar-stats">
                    <p>🤖 <span class="lang-en">AI Analysis</span><span class="lang-zh">AI智能分析</span></p>
                    <p><span class="lang-en">Analysis date:</span><span class="lang-zh">分析日期:</span> {{ ai_curated_date }}</p>
                    <p><span class="lang-en">Curated:</span><span class="lang-zh">精选漏洞:</span> {{ ai_curated_count }}</p>
                    <p><span class="lang-en">Analyzed:</span><span class="lang-zh">候选漏洞:</span> {{ ai_total_analyzed }}</p>
                    <p><span class="lang-en">Model:</span><span class="lang-zh">模型来源:</span> {{ ai_model_name }}</p>
                </div>
            </div>
            {% endif %}

        </div>
    </div>

    <script>
        // Current UI language ('en' default; 'zh' opts into the Chinese UI)
        let currentLang = localStorage.getItem('cve-lang') === 'zh' ? 'zh' : 'en';
        // Pick a string by current language: t('English', '中文')
        function t(en, zh) { return currentLang === 'zh' ? zh : en; }

        // Toggle theme function.
        // Pauses all CSS transitions for one frame around the flip —
        // with 2700+ cards animating colors simultaneously the switch
        // would otherwise jank badly.
        function toggleTheme() {
            const root = document.documentElement;
            const currentTheme = root.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

            root.classList.add('theme-switching');
            root.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);

            // remove after two frames (styles applied, nothing left to
            // animate); setTimeout fallback covers rAF-throttled pages
            const remove = () => root.classList.remove('theme-switching');
            requestAnimationFrame(() => requestAnimationFrame(remove));
            setTimeout(remove, 100);
        }

        // Toggle UI language (English <-> Chinese)
        function toggleLang() {
            setLang(currentLang === 'zh' ? 'en' : 'zh');
        }
        function setLang(lang) {
            currentLang = lang;
            document.documentElement.classList.toggle('lang-mode-zh', lang === 'zh');
            localStorage.setItem('cve-lang', lang);
        }

        // Back to top
        function scrollToTop() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
        window.addEventListener('scroll', function() {
            document.getElementById('back-to-top').classList.toggle('show', window.scrollY > 600);
        });

        // Initialize all CVEs as visible and initialize filter state
        document.addEventListener('DOMContentLoaded', function() {
            const allCards = document.querySelectorAll('.cve-card');
            allCards.forEach(card => {
                card.classList.add('filtered-in');
            });

            // Initialize active filters object
            window.activeFilters = {
                severities: [],    // CVSS severity filters (critical, high, medium, low)
                status: [],        // Status filters (cisa, epss, modified, published)
                vendors: []        // Vendor filters (mutually exclusive)
            };
        });

        // Variable to track if more vendors are shown
        let moreVendorsShown = false;

        // Toggle status filter (mutually exclusive - only one status at a time)
        function toggleStatusFilter(filterType) {
            const index = window.activeFilters.status.indexOf(filterType);
            if (index > -1) {
                // Remove filter (deselect current status)
                window.activeFilters.status = [];
            } else {
                // Handle mutually exclusive filters (modified/published)
                if (filterType === 'modified' || filterType === 'published') {
                    window.activeFilters.status = [filterType];
                } else {
                    // Replace with new filter (select only this status)
                    window.activeFilters.status = [filterType];
                }
            }

            const count = applyAllFilters();
            updateSelectedFiltersHighlight();
            showFilterCount(count);
        }

        // Toggle vendor filter (mutually exclusive - only one vendor at a time)
        function toggleVendorFilter(vendor) {
            const index = window.activeFilters.vendors.indexOf(vendor);
            if (index > -1) {
                // Remove filter (deselect current vendor)
                window.activeFilters.vendors = [];
            } else {
                // Replace with new filter (select only this vendor)
                window.activeFilters.vendors = [vendor];
            }

            const count = applyAllFilters();
            updateSelectedFiltersHighlight();
            showFilterCount(count);
        }

        // Apply single filter (for summary stats clicks - mutually exclusive)
        function applySingleFilter(filterType) {
            if (filterType === 'all') {
                clearAllFilters();
            } else if (filterType === 'high-risk') {
                // Apply high risk filter - keep severity and vendor filters
                window.activeFilters.status = ['high-risk'];
                const count = applyAllFilters();
                updateSelectedFiltersHighlight();
                showFilterCount(count);
            } else if (filterType === 'cisa') {
                // Apply CISA KEV filter - keep severity and vendor filters
                window.activeFilters.status = ['cisa'];
                const count = applyAllFilters();
                updateSelectedFiltersHighlight();
                showFilterCount(count);
            } else if (filterType === 'epss') {
                // Apply High EPSS filter - keep severity and vendor filters
                window.activeFilters.status = ['epss'];
                const count = applyAllFilters();
                updateSelectedFiltersHighlight();
                showFilterCount(count);
            }
        }

        // Apply CVSS-specific filter
        function applySingleFilterByCVSS(minScore) {
            window.activeFilters = {
                status: [`cvss-${minScore}`],
                vendors: []
            };
            applyAllFilters();
        }

        // Apply CVSS severity filter (mutually exclusive - only one severity at a time)
        function applySingleFilterBySeverity(severity) {
            const index = window.activeFilters.severities.indexOf(severity);
            if (index > -1) {
                // Remove severity filter (toggle off)
                window.activeFilters.severities = [];
            } else {
                // Replace with new severity filter (mutually exclusive)
                window.activeFilters.severities = [severity];
            }

            const count = applyAllFilters();
            updateSelectedFiltersHighlight();
            showFilterCount(count);
        }

        // Apply EPSS-specific filter
        function applySingleFilterByEPSS(minScore) {
            window.activeFilters = {
                status: [`epss-${minScore}`],
                vendors: []
            };
            applyAllFilters();
        }

        // Apply all active filters
        function applyAllFilters() {
            const allCards = document.querySelectorAll('.cve-card');

            allCards.forEach(card => {
                let showCard = true;

                // Apply CVSS severity filter (mutually exclusive)
                if (window.activeFilters.severities.length > 0) {
                    const cvssScore = parseFloat(card.getAttribute('data-cvss')) || 0;
                    const severity = window.activeFilters.severities[0];

                    switch(severity) {
                        case 'critical':
                            if (cvssScore < 9.0) showCard = false;
                            break;
                        case 'high':
                            if (cvssScore < 7.0 || cvssScore >= 9.0) showCard = false;
                            break;
                        case 'medium':
                            if (cvssScore < 4.0 || cvssScore >= 7.0) showCard = false;
                            break;
                        case 'low':
                            if (cvssScore >= 4.0 || cvssScore === 0) showCard = false;
                            break;
                    }
                }

                // Apply status filter (mutually exclusive)
                if (showCard && window.activeFilters.status.length > 0) {
                    const filter = window.activeFilters.status[0];
                    switch(filter) {
                        case 'cisa':
                            if (card.getAttribute('data-cisa') !== 'true') {
                                showCard = false;
                            }
                            break;
                        case 'epss':
                            if ((parseFloat(card.getAttribute('data-epss')) || 0) < 0.01) {
                                showCard = false;
                            }
                            break;
                        case 'modified':
                            if (card.getAttribute('data-modified') !== 'True') {
                                showCard = false;
                            }
                            break;
                        case 'published':
                            if (card.getAttribute('data-modified') !== 'False') {
                                showCard = false;
                            }
                            break;
                        case 'high-risk':
                            if ((parseFloat(card.getAttribute('data-cvss')) || 0) <= 7.0) {
                                showCard = false;
                            }
                            break;
                        default:
                            // Handle CVSS specific filter
                            if (filter.startsWith('cvss-')) {
                                const minCvss = parseFloat(filter.split('-')[1]);
                                if ((parseFloat(card.getAttribute('data-cvss')) || 0) < minCvss) {
                                    showCard = false;
                                }
                            }
                            // Handle EPSS specific filter
                            else if (filter.startsWith('epss-')) {
                                const minEpss = parseFloat(filter.split('-')[1]);
                                if ((parseFloat(card.getAttribute('data-epss')) || 0) < minEpss) {
                                    showCard = false;
                                }
                            }
                            break;
                    }
                }

                // Apply vendor filter (mutually exclusive)
                if (showCard && window.activeFilters.vendors.length > 0) {
                    const cardVendorsStr = card.getAttribute('data-vendors') || '';
                    const cardVendors = cardVendorsStr.split(',');
                    const vendor = window.activeFilters.vendors[0];

                    if (!cardVendors.includes(vendor)) {
                        showCard = false;
                    }
                }

                // Update card visibility
                if (showCard) {
                    card.style.display = 'block';
                    card.classList.add('filtered-in');
                } else {
                    card.style.display = 'none';
                    card.classList.remove('filtered-in');
                }
            });

            // Update the display of active filters
            updateActiveFiltersDisplay();

            // Return the count of filtered CVEs
            return document.querySelectorAll('.cve-card.filtered-in').length;
        }

        // Clear all filters
        function clearAllFilters() {
            window.activeFilters = {
                severities: [],
                status: [],
                vendors: []
            };

            const allCards = document.querySelectorAll('.cve-card');
            allCards.forEach(card => {
                card.style.display = 'block';
                card.classList.add('filtered-in');
            });

            updateActiveFiltersDisplay();
            updateSelectedFiltersHighlight();
        }

        // Show filter count toast
        function showFilterCount(count) {
            // Remove existing toast if any
            const existingToast = document.querySelector('.filter-count-toast');
            if (existingToast) {
                existingToast.remove();
            }

            // Create toast element
            const toast = document.createElement('div');
            toast.className = 'filter-count-toast';
            toast.textContent = t(`${count} CVE${count !== 1 ? 's' : ''} found`, `找到 ${count} 个漏洞`);
            document.body.appendChild(toast);

            // Remove toast after animation completes
            setTimeout(() => {
                toast.remove();
            }, 2000);
        }

        // Update the display of active filters
        function updateActiveFiltersDisplay() {
            const activeFiltersDiv = document.getElementById('active-filters');
            if (!activeFiltersDiv) return;

            let filterText = [];

            // Add severity filters
            for (let severity of window.activeFilters.severities) {
                filterText.push(t('Severity: ', '严重度: ') + t(severity, {critical: '严重', high: '高危', medium: '中危', low: '低危'}[severity] || severity));
            }

            // Add status filters
            for (let status of window.activeFilters.status) {
                switch(status) {
                    case 'cisa':
                        filterText.push('CISA KEV');
                        break;
                    case 'epss':
                        filterText.push(t('High EPSS', '高 EPSS'));
                        break;
                    case 'modified':
                        filterText.push(t('Recently Modified', '最近修改'));
                        break;
                    case 'published':
                        filterText.push(t('Newly Published', '新发布'));
                        break;
                    case 'high-risk':
                        filterText.push(t('High Risk (CVSS > 7.0)', '高危 (CVSS > 7.0)'));
                        break;
                    default:
                        if (status.startsWith('cvss-')) {
                            const minCvss = parseFloat(status.split('-')[1]);
                            filterText.push(`CVSS ≥ ${minCvss}`);
                        } else if (status.startsWith('epss-')) {
                            const minEpss = parseFloat(status.split('-')[1]);
                            filterText.push(`EPSS ≥ ${minEpss}`);
                        }
                        break;
                }
            }

            // Add vendor filters
            for (let vendor of window.activeFilters.vendors) {
                filterText.push(t('Vendor: ', '厂商: ') + vendor);
            }

            if (filterText.length === 0) {
                activeFiltersDiv.textContent = t('None', '无');
            } else {
                activeFiltersDiv.textContent = filterText.join(', ');
            }
        }

        // Update highlight for selected filters in sidebar
        function updateSelectedFiltersHighlight() {
            // Remove all selected classes from CVSS severity filters
            const allFilterItems = document.querySelectorAll('.filter-item');
            allFilterItems.forEach(item => {
                item.classList.remove('selected');
            });

            // Remove all selected classes from status filters
            const allMetricTags = document.querySelectorAll('.filter-metric-tag');
            allMetricTags.forEach(tag => {
                tag.classList.remove('selected');
            });

            // Add selected class to active severity filters
            if (window.activeFilters.severities.length > 0) {
                window.activeFilters.severities.forEach(severity => {
                    const elementId = 'filter-' + severity;
                    const element = document.getElementById(elementId);
                    if (element) {
                        element.classList.add('selected');
                    }
                });
            }

            // Add selected class to active status filters
            if (window.activeFilters.status.length > 0) {
                window.activeFilters.status.forEach(status => {
                    let elementId = null;
                    switch(status) {
                        case 'cisa':
                            elementId = 'filter-cisa';
                            break;
                        case 'epss':
                            elementId = 'filter-epss';
                            break;
                        case 'modified':
                            elementId = 'filter-modified';
                            break;
                        case 'published':
                            elementId = 'filter-published';
                            break;
                        case 'high-risk':
                            elementId = 'filter-high-risk';
                            break;
                        default:
                            // Skip specific CVSS and EPSS filters as they are not in the sidebar
                            break;
                    }

                    if (elementId) {
                        const element = document.getElementById(elementId);
                        if (element) {
                            element.classList.add('selected');
                        }
                    }
                });
            }

            // Add selected class to active vendor filter (mutually exclusive)
            if (window.activeFilters.vendors.length > 0) {
                const vendor = window.activeFilters.vendors[0];
                // Sanitize vendor name for use in ID - replace any non-alphanumeric characters with underscores
                const sanitizedVendor = vendor.replace(/[^a-zA-Z0-9]/g, '_');
                const vendorId = 'filter-vendor-' + sanitizedVendor;
                const vendorElement = document.getElementById(vendorId);
                if (vendorElement) {
                    vendorElement.classList.add('selected');
                }
            }
        }

        // Clear all filters
        function clearAllFilters() {
            window.activeFilters = {
                severities: [],
                status: [],
                vendors: []
            };

            const allCards = document.querySelectorAll('.cve-card');
            allCards.forEach(card => {
                card.style.display = 'block';
                card.classList.add('filtered-in');
            });

            updateActiveFiltersDisplay();
            updateSelectedFiltersHighlight();
        }

        // Toggle more vendors
        function toggleMoreVendors() {
            const extraVendors = document.querySelectorAll('.extra-vendor');
            const showMoreBtn = document.getElementById('show-more-btn');

            if (!moreVendorsShown) {
                // Show all extra vendors
                extraVendors.forEach(item => {
                    item.style.display = 'block';
                });

                showMoreBtn.textContent = t('Show Less Vendors', '收起厂商列表');
                moreVendorsShown = true;
            } else {
                // Hide extra vendors (keep only the first 20)
                extraVendors.forEach((item, index) => {
                    item.style.display = 'none';
                });

                showMoreBtn.textContent = t('Show More Vendors ({{ all_vendors_list|length - 19 }} more)', '显示更多厂商 (还有 {{ all_vendors_list|length - 19 }})');
                moreVendorsShown = false;
            }
        }

        // Switch between original view and AI curated view
        function switchView(view) {
            const originalView = document.getElementById('original-view');
            const aiView = document.getElementById('ai-view');
            const originalSidebar = document.getElementById('original-sidebar');
            const aiSidebar = document.getElementById('ai-sidebar');
            const buttons = document.querySelectorAll('.view-toggle-btn');

            buttons.forEach(btn => btn.classList.remove('active'));

            if (view === 'original') {
                originalView.classList.remove('hidden');
                aiView.classList.remove('active');
                originalSidebar.classList.remove('hidden');
                if (aiSidebar) aiSidebar.classList.add('hidden');
                buttons[1].classList.add('active');
            } else {
                originalView.classList.add('hidden');
                aiView.classList.add('active');
                originalSidebar.classList.add('hidden');
                if (aiSidebar) aiSidebar.classList.remove('hidden');
                buttons[0].classList.add('active');
            }
        }

        // Scroll to a specific AI category
        function scrollToCategory(safeId) {
            const el = document.getElementById('ai-category-' + safeId);
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
    </script>

    <!-- Footer -->
    <div class="footer">
        <p>
                &copy; 2026 <a href="https://github.com/secnotes" target="_blank">Security Notes</a>
            <span class="separator">|</span>
            <a href="https://github.com/secnotes/dailycve" target="_blank" class="github-link">
                <svg class="github-icon" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.938 9.9 9.207 11.387.68.113.893-.261.893-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.218.694.825.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
                Star on GitHub
            </a>
            <span class="separator">|</span>
            <a href="reports/{{ date[:4] }}/daily_cve_{{ date|replace('-', '') }}.md" target="_blank" rel="noopener noreferrer">
                📄 <span class="lang-en">Markdown Report</span><span class="lang-zh">Markdown 报告</span>
            </a>
        </p>
        <p><span class="lang-en">Generated on</span><span class="lang-zh">生成时间</span> {{ generated_time }}</p>
    </div>
</body>
</html>
    """

    # Create template and add our custom filter
    template = Template(html_template_str)
    template.globals['sanitize_vendor_id'] = sanitize_vendor_id
    template.globals['round_epss'] = round_epss_score
    template.globals['convert_md_code'] = convert_markdown_code_blocks

    # Calculate statistics
    high_risk_count = sum(1 for cve in cves if cve.get('cvss_score', 0) > 7.0)
    cisa_kev_count = sum(1 for cve in cves if cve.get('in_cisa_kev', False))
    epss_high_count = sum(1 for cve in cves if cve.get('epss_score', 0) >= 0.01)
    modified_count = sum(1 for cve in cves if cve.get('entry_type') == 'modified')
    published_count = sum(1 for cve in cves if cve.get('entry_type') == 'published')

    # Add CVSS severity counts
    critical_count = sum(1 for cve in cves if cve.get('cvss_score', 0) >= 9.0)
    high_count = sum(1 for cve in cves if 7.0 <= cve.get('cvss_score', 0) < 9.0)
    medium_count = sum(1 for cve in cves if 4.0 <= cve.get('cvss_score', 0) < 7.0)
    low_count = sum(1 for cve in cves if 0 < cve.get('cvss_score', 0) < 4.0)

    # Collect all unique vendors
    all_vendors = set()
    vendor_counts = {}
    for cve in cves:
        for vendor in cve.get('vendors', []):
            all_vendors.add(vendor)
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

    # Sort vendors by count and limit to top 15 in the sidebar
    sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)
    top_vendors = dict(sorted_vendors[:15])  # Top 15 vendors
    all_sorted_vendors = dict(sorted_vendors)  # All vendors sorted by count

    # Prepare data for template
    initial_vendors = list(top_vendors.keys())

    # Format the data for the template
    formatted_cves = []
    for cve in cves:
        # Determine severity based on CVSS score
        severity = 'low'
        if cve.get('cvss_score', 0) >= 9.0:
            severity = 'critical'
        elif cve.get('cvss_score', 0) >= 7.0:
            severity = 'high'
        elif cve.get('cvss_score', 0) >= 4.0:
            severity = 'medium'

        # Determine entry type for display
        entry_type = cve.get('entry_type', 'published')
        entry_label = ''
        if entry_type == 'modified':
            entry_label = '🔄 Updated'
        else:
            entry_label = '📅 New'

        formatted_cves.append({
            'id': cve['id'],
            'description': html.escape(cve['description']) if cve['description'] else (
                '<span class="lang-en">No description provided by the CNA yet — check NVD details via the link below.</span>'
                '<span class="lang-zh">CNA 暂未提供描述 — 可点击下方 NVD 链接查看详情。</span>'
            ),
            'cvss_score': cve.get('cvss_score', 0),
            'epss_score': cve.get('epss_score', 0),
            'in_cisa_kev': cve.get('in_cisa_kev', False),
            'exploits': cve.get('exploits', False),
            'published_date': cve.get('published_date', ''),
            'last_modified': cve.get('last_modified', ''),
            'severity': severity,
            'entry_type': entry_type,
            'entry_label': entry_label,
            'vendors': cve.get('vendors', []),
            'products': []  # Remove products from UI
        })

    # Build CVE lookup dict for AI curated view (keyed by CVE ID)
    cve_lookup = {}
    for cve in cves:
        cve_lookup[cve['id']] = {
            'description': cve.get('description', ''),
            'cvss_score': cve.get('cvss_score', 0),
            'epss_score': cve.get('epss_score', 0),
            'in_cisa_kev': cve.get('in_cisa_kev', False),
            'vendors': cve.get('vendors', []),
        }

    # Prepare AI curated HTML content
    ai_curated_html = generate_ai_curated_html(ai_curated, cve_lookup)
    ai_category_nav = generate_ai_category_nav(ai_curated) if ai_curated else ''

    # AI sidebar metadata
    ai_curated_date = ai_curated.get('analysis_date', '-') if ai_curated else '-'
    ai_curated_count = sum(len(v) for v in ai_curated.get('categories', {}).values()) if ai_curated else 0
    ai_total_analyzed = ai_curated.get('total_analyzed', 0) if ai_curated else 0
    ai_model_name = (ai_curated.get('model') if ai_curated else None) or os.environ.get('AI_MODEL') or 'gpt-4o-mini'

    # Render the template
    html_content = template.render(
        date=datetime.now().strftime('%Y-%m-%d'),
        generated_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        cve_count=total_cve_count if total_cve_count is not None else len(formatted_cves),
        high_risk_count=high_risk_count,
        cisa_kev_count=cisa_kev_count,
        epss_high_count=epss_high_count,
        modified_count=modified_count,
        published_count=published_count,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        cves=formatted_cves,
        initial_vendors=initial_vendors,
        all_vendors_list=list(all_sorted_vendors.keys()),
        all_sorted_vendors=all_sorted_vendors,
        ai_curated=ai_curated,
        ai_curated_html=ai_curated_html,
        ai_category_nav=ai_category_nav,
        ai_curated_date=ai_curated_date,
        ai_curated_count=ai_curated_count,
        ai_total_analyzed=ai_total_analyzed,
        ai_model_name=ai_model_name
    )

    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"HTML report generated: {output_path}")