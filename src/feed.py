#!/usr/bin/env python3
"""
RSS feed generators for the daily AI-curated CVEs.

Converts the day's curated JSON (docs/ai/YYYY/ai_curated_YYYYMMDD.json,
produced by ai_provider/translator) into two language-specific RSS 2.0
documents instead of one mixed-language feed:

- feed.xml:    English  (<language>en</language>)
- feed_zh.xml: Chinese  (<language>zh-CN</language>)

Each feed carries only its own language in item/channel descriptions
(falling back to the other language when a field is missing), so readers
subscribing to either language get a clean monolingual stream. Both feeds
are overwritten daily and only carry the current day's items, mirroring
the "source is the current day's AI curation" contract.
"""

import os
from datetime import datetime, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape


def _rfc822_date(date_str):
    """Convert the curated JSON's 'YYYY-MM-DD' analysis_date to RFC 822.
    Falls back to the current UTC time when the date is missing/invalid."""
    if date_str:
        try:
            dt = datetime.strptime(date_str[:10], '%Y-%m-%d').replace(
                tzinfo=timezone.utc)
            return format_datetime(dt)
        except ValueError:
            pass
    return format_datetime(datetime.now(timezone.utc))


def _lang_texts(category_en, cve):
    """Resolve the display name and bilingual reason for one curated CVE.

    Category names come from the hardcoded Config mapping (deterministic, no
    API round-trip); reasons fall back to whichever language exists so a
    feed item never shows a blank description.
    """
    from config import Config

    category_zh = Config.AI_CATEGORY_ZH.get(category_en, category_en)
    reason_en = cve.get('reason_en') or cve.get('reason', '')
    reason_zh = cve.get('reason_zh') or cve.get('reason', '')
    return category_zh, reason_en, reason_zh


def _item_xml(cve_id, category, reason, pub_date):
    """Build one <item> element for a curated CVE."""
    nvd_url = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
    description = escape(reason) if reason else \
        'See the NVD entry for details.'

    return (
        '<item>'
        f'<title>{escape(f"{cve_id} — {category}")}</title>'
        f'<link>{escape(nvd_url)}</link>'
        f'<guid isPermaLink="false">{escape(cve_id)}</guid>'
        f'<category>{escape(category)}</category>'
        f'<description>{description}</description>'
        f'<pubDate>{pub_date}</pubDate>'
        '</item>'
    )


def generate_feed_xml(ai_curated, output_path, lang='en'):
    """Write one language-specific RSS 2.0 feed for the day's AI-curated CVEs.

    lang='en' renders titles/categories/reasons in English (feed.xml),
    lang='zh' in Chinese (feed_zh.xml). Silently does nothing when
    ai_curated is empty so callers can pass the (possibly None) curation
    result straight through.
    """
    if not ai_curated:
        return

    from config import Config

    site_url = Config.SITE_URL.rstrip('/') + '/'
    # Legacy caches carry Chinese category keys; normalize like reporter.py
    zh_to_en = Config.AI_CATEGORY_ZH_TO_EN

    categories = ai_curated.get('categories', {})
    if not categories:
        return

    analysis_date = ai_curated.get('analysis_date', '')
    pub_date = _rfc822_date(analysis_date)
    now_rfc822 = format_datetime(datetime.now(timezone.utc))

    if lang == 'zh':
        channel_title = 'CVE 日报 — AI 精选'
        channel_lang = 'zh-CN'
        summary = ai_curated.get('summary_zh') or ai_curated.get('summary') \
            or '每日 AI 精选高危漏洞。'
        channel_desc = summary
    else:
        channel_title = 'CVE Daily — AI Curated'
        channel_lang = 'en'
        summary = ai_curated.get('summary_en') or ai_curated.get('summary') \
            or 'Daily AI-curated high-risk CVEs.'
        channel_desc = summary

    items = []
    for category_name, curated_cves in categories.items():
        if not curated_cves:
            continue
        category_en = zh_to_en.get(category_name, category_name)
        category_zh, _, _ = _lang_texts(category_en, {})
        for cve in curated_cves:
            cve_id = cve.get('id', '')
            if not cve_id:
                continue
            _, reason_en, reason_zh = _lang_texts(category_en, cve)
            if lang == 'zh':
                items.append(_item_xml(
                    cve_id, category_zh, reason_zh or reason_en, pub_date))
            else:
                items.append(_item_xml(
                    cve_id, category_en, reason_en or reason_zh, pub_date))

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0">\n'
        '<channel>\n'
        f'<title>{escape(channel_title)}</title>\n'
        f'<link>{escape(site_url)}</link>\n'
        f'<description>{escape(channel_desc)}</description>\n'
        f'<language>{channel_lang}</language>\n'
        f'<lastBuildDate>{now_rfc822}</lastBuildDate>\n'
        f'<pubDate>{pub_date}</pubDate>\n'
        '<generator>cvedaily</generator>\n'
        + '\n'.join(items) + ('\n' if items else '') +
        '</channel>\n'
        '</rss>\n'
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(xml)
    print(f'RSS feed ({lang}) saved as {output_path} ({len(items)} items)')


def generate_feeds(ai_curated):
    """Write both language feeds to their configured paths."""
    from config import Config
    generate_feed_xml(ai_curated, Config.FEED_PATH, lang='en')
    generate_feed_xml(ai_curated, Config.FEED_PATH_ZH, lang='zh')
