import os
import re
import json
import shutil
import hashlib
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import html


def sanitize_vendor_id(name):
    """Sanitize names to create safe IDs for HTML elements.

    The legacy replacement `[^a-zA-Z0-9] -> _` is kept for ASCII names
    so the JS regex in report.js (vendor-filter selection) still matches
    the same id. When the name contains no ASCII letters/digits - e.g.
    the CJK CVE category names like 工业控制 / 网络设备 - fall back to a
    short sha1 prefix so distinct names no longer collapse onto the same
    all-underscore id (which made 移动安全 / 云安全 / 网络设备 / 工业控制
    all share '____' and scrollToCategory could only reach the first DOM
    occurrence).
    """
    sanitized = re.sub(r'[^a-zA-Z0-9]', '_', name).strip('_')
    if sanitized:
        return sanitized
    return hashlib.sha1(name.encode('utf-8')).hexdigest()[:10]  # 40 bits


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


def build_daily_data(cves, total_cve_count, ai_curated, date_str, generated_str, stats):
    """Build the compact daily JSON payload the client-side renderer
    consumes. Descriptions are stored RAW (unescaped) - report.js escapes
    at render time, which also closes the old injection vector where
    description text reached the page unescaped via |safe.

    AI curation is normalized here (legacy Chinese category keys -> English,
    zh display names + icons + safe DOM ids resolved server-side) so the
    JS side gets render-ready structures with no Config knowledge.
    """
    from config import Config

    payload_cves = []
    for cve in cves:
        payload_cves.append({
            'id': cve['id'],
            'st': cve.get('state', 'PUBLISHED'),
            'd': cve.get('description', ''),
            'cvss': cve.get('cvss_score', 0),
            'epss': cve.get('epss_score', 0),
            'kev': bool(cve.get('in_cisa_kev', False)),
            'mod': cve.get('entry_type') == 'modified',
            'pub': cve.get('published_date', ''),
            'upd': cve.get('last_modified', ''),
            'vendors': cve.get('vendors', []),
            'vp': cve.get('vpairs', []),
        })

    ai_data = None
    if ai_curated:
        categories = []
        for category_name, curated_cves in ai_curated.get('categories', {}).items():
            if not curated_cves:
                continue
            en_name = Config.AI_CATEGORY_ZH_TO_EN.get(category_name, category_name)
            items = [{
                'id': c.get('id', ''),
                'reason_en': c.get('reason_en') or c.get('reason', ''),
                'reason_zh': c.get('reason_zh') or c.get('reason', ''),
            } for c in curated_cves]
            categories.append({
                'id': sanitize_vendor_id(en_name),
                'en': en_name,
                'zh': Config.AI_CATEGORY_ZH.get(en_name, en_name),
                'icon': Config.AI_CATEGORY_ICONS.get(en_name, '📌'),
                'items': items,
            })

        model_name = (ai_curated.get('model')
                      or os.environ.get('AI_MODEL') or 'gpt-4o-mini')
        ai_data = {
            'model': model_name,
            'date': ai_curated.get('analysis_date', ''),
            'analyzed': ai_curated.get('total_analyzed', 0),
            'curated_count': sum(len(v) for v in ai_curated.get('categories', {}).values()),
            'summary_en': ai_curated.get('summary_en') or ai_curated.get('summary', ''),
            'summary_zh': ai_curated.get('summary_zh') or ai_curated.get('summary', ''),
            'categories': categories,
        }

    return {
        'date': date_str,
        'generated': generated_str,
        'total': total_cve_count if total_cve_count is not None else len(cves),
        'stats': stats,
        'cves': payload_cves,
        'ai': ai_data,
    }


def write_data_manifest(docs_dir):
    """Write docs/data/index.json listing every date that has a data file.
    The date switcher fetches this to populate its picker; days before the
    client-side-rendering era have no JSON and simply don't appear.
    Returns the date list (newest first)."""
    import glob as _glob

    dates = set()
    pattern = os.path.join(docs_dir, 'data', '*', 'cves_*.json')
    for path in _glob.glob(pattern):
        base = os.path.basename(path)          # cves_YYYYMMDD.json
        stamp = base[len('cves_'):-len('.json')]
        if len(stamp) == 8 and stamp.isdigit():
            dates.add(f'{stamp[:4]}-{stamp[4:6]}-{stamp[6:]}')

    manifest_path = os.path.join(docs_dir, 'data', 'index.json')
    date_list = sorted(dates, reverse=True)
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump({'dates': date_list}, f, ensure_ascii=False, separators=(',', ':'))
    return date_list


def _copy_asset(src_path, assets_dir, url_prefix):
    """Copy a static asset into docs/assets/ and return (url, version).

    The version is a short content hash used as a cache-busting query
    string, so browsers keep the (byte-identical across days) css/js
    cached but pick up changes the moment the content changes.
    """
    os.makedirs(assets_dir, exist_ok=True)
    shutil.copyfile(src_path, os.path.join(assets_dir, os.path.basename(src_path)))
    with open(src_path, 'rb') as f:
        version = hashlib.sha1(f.read()).hexdigest()[:10]
    name = os.path.basename(src_path)
    return f'{url_prefix}{name}?v={version}', version


def generate_html_report(cves, output_path='index.html', total_cve_count=None, ai_curated=None):
    """Generate the HTML report.

    Since the data/template split the output is a small static shell
    (rendered from src/templates/report.html with summary stats and the
    vendor filter list) plus a full-data JSON file under docs/data/ that
    report.js fetches and renders in scroll-triggered batches. Markdown
    reports were dropped in favor of the JSON being the single archive.
    """
    now = datetime.now()
    date_str = now.strftime('%Y-%m-%d')
    generated_str = now.strftime('%Y-%m-%d %H:%M:%S')

    # All outputs live next to index.html (docs/); assets and data in
    # subdirectories referenced with relative URLs
    docs_dir = os.path.dirname(output_path) or '.'
    assets_dir = os.path.join(docs_dir, 'assets')
    data_dir = os.path.join(docs_dir, 'data', str(now.year))

    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    css_url, css_version = _copy_asset(os.path.join(static_dir, 'report.css'), assets_dir, 'assets/')
    js_url, js_version = _copy_asset(os.path.join(static_dir, 'report.js'), assets_dir, 'assets/')
    data_url = f'data/{now.year}/cves_{now.strftime("%Y%m%d")}.json'

    # ---- statistics (unchanged definitions) ----
    high_risk_count = sum(1 for cve in cves if cve.get('cvss_score', 0) > 7.0)
    cisa_kev_count = sum(1 for cve in cves if cve.get('in_cisa_kev', False))
    epss_high_count = sum(1 for cve in cves if cve.get('epss_score', 0) >= 0.01)
    modified_count = sum(1 for cve in cves if cve.get('entry_type') == 'modified')
    published_count = sum(1 for cve in cves if cve.get('entry_type') == 'published')
    critical_count = sum(1 for cve in cves if cve.get('cvss_score', 0) >= 9.0)
    high_count = sum(1 for cve in cves if 7.0 <= cve.get('cvss_score', 0) < 9.0)
    medium_count = sum(1 for cve in cves if 4.0 <= cve.get('cvss_score', 0) < 7.0)
    low_count = sum(1 for cve in cves if 0 < cve.get('cvss_score', 0) < 4.0)
    na_count = sum(1 for cve in cves if cve.get('cvss_score', 0) == 0)
    stats = {
        'total': total_cve_count if total_cve_count is not None else len(cves),
        'high_risk': high_risk_count,
        'cisa': cisa_kev_count,
        'epss': epss_high_count,
        'modified': modified_count,
        'published': published_count,
        'critical': critical_count,
        'high': high_count,
        'medium': medium_count,
        'low': low_count,
        'na': na_count,
    }

    # ---- daily data JSON: the single full-fidelity archive ----
    daily_data = build_daily_data(cves, total_cve_count, ai_curated, date_str, generated_str, stats)
    os.makedirs(data_dir, exist_ok=True)
    data_path = os.path.join(data_dir, f'cves_{now.strftime("%Y%m%d")}.json')
    with open(data_path, 'w', encoding='utf-8') as f:
        json.dump(daily_data, f, ensure_ascii=False, separators=(',', ':'))
    print(f'Daily data JSON saved as {data_path} ({len(cves)} CVEs)')

    # ---- date manifest for the history switcher ----
    available_dates = write_data_manifest(docs_dir)
    print(f'Date manifest lists {len(available_dates)} day(s)')

    # ---- render the shell ----
    ai_category_nav = generate_ai_category_nav(ai_curated) if ai_curated else ''

    env = Environment(loader=FileSystemLoader(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')))
    env.globals['sanitize_vendor_id'] = sanitize_vendor_id
    template = env.get_template('report.html')

    html_content = template.render(
        date=date_str,
        generated_time=generated_str,
        cve_count=total_cve_count if total_cve_count is not None else len(cves),
        high_risk_count=high_risk_count,
        cisa_kev_count=cisa_kev_count,
        epss_high_count=epss_high_count,
        modified_count=modified_count,
        published_count=published_count,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        na_count=na_count,
        ai_curated=ai_curated,
        ai_category_nav=ai_category_nav,
        ai_curated_date=ai_curated.get('analysis_date', '-') if ai_curated else '-',
        ai_curated_count=sum(len(v) for v in ai_curated.get('categories', {}).values()) if ai_curated else 0,
        ai_total_analyzed=ai_curated.get('total_analyzed', 0) if ai_curated else 0,
        ai_model_name=(ai_curated.get('model') if ai_curated else None)
                      or os.environ.get('AI_MODEL') or 'gpt-4o-mini',
        css_version=css_version,
        js_version=js_version,
        data_url=data_url,
        ai_data_url=None,  # AI data ships inside the daily JSON
    )

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f'HTML report saved as {output_path}')
