#!/usr/bin/env python3
"""
Translation Module for AI-curated CVE data
Adds the missing language to curated content (reason / summary) via an
OpenAI-compatible AI API, reusing ai_provider.AIProvider — same design as
the secnews project's translator.

The curated JSON is generated in English (English category keys, English
reasons/summary); this module adds the Chinese counterparts, so the HTML
report can toggle languages client-side with zero extra requests.

- Category names are converted via the hardcoded Config.AI_CATEGORY_ZH
  mapping at render time — deterministic, no API round-trip.
- When translation fails for an item, the field falls back to the source
  text so the page never shows blanks.
- translate_ai_curated() is a no-op without an API key.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Number of texts per AI translation batch
TRANSLATE_BATCH_SIZE = 30


def _cjk_count(text: str) -> int:
    """Return the number of CJK characters in text"""
    if not text:
        return 0
    return sum(1 for c in text if '一' <= c <= '鿿')


def _cjk_ratio(text: str) -> float:
    """Return ratio of CJK characters among non-space characters"""
    if not text:
        return 0.0
    chars = [c for c in text if not c.isspace()]
    if not chars:
        return 0.0
    return _cjk_count(text) / len(chars)


def detect_language(text: str) -> str:
    """Detect whether text is Chinese ('zh') or English ('en').

    Any text containing a couple of hanzi is treated as Chinese: mixed
    security text like "Linux内核漏洞 CVE-2026-64563" has a low CJK
    *ratio*, but an English string would never contain hanzi at all.
    """
    return 'zh' if _cjk_count(text) >= 2 else 'en'


def _is_translated(text: str, target: str) -> bool:
    """Check whether a translated text actually reads like the target language.

    Models sometimes echo the source text back instead of translating, so
    translations are validated before being applied: English output must be
    virtually CJK-free, Chinese output only needs a couple of hanzi (CVE ids
    and product names may keep it otherwise latin-heavy).
    """
    if not text:
        return False
    if target == 'en':
        return _cjk_ratio(text) <= 0.15
    return _cjk_count(text) >= 2


def _strip_code_fences(text: str) -> str:
    """Strip markdown code fences from an AI response"""
    text = text.strip()
    if text.startswith('```json'):
        text = text[7:]
    elif text.startswith('```'):
        text = text[3:]
    if text.endswith('```'):
        text = text[:-3]
    return text.strip()


def _parse_translations(response: str) -> List[Dict[str, Any]]:
    """Parse {"translations":[{"index":N,"text":"..."}]} from an AI response"""
    import json as _json
    text = _strip_code_fences(response)

    data: Optional[Dict[str, Any]] = None
    try:
        data = _json.loads(text)
    except _json.JSONDecodeError:
        # Model wrapped the JSON in prose - slice between first/last brace
        first, last = text.find('{'), text.rfind('}')
        if first != -1 and last > first:
            try:
                data = _json.loads(text[first:last + 1])
            except _json.JSONDecodeError:
                data = None
    if data is None:
        logger.error("Failed to parse translation response as JSON")
        return []

    result = []
    for item in data.get('translations', []):
        if isinstance(item, dict) and 'index' in item:
            try:
                result.append({
                    'index': int(item['index']),
                    'text': str(item.get('text', '') or ''),
                })
            except (TypeError, ValueError):
                continue
    return result


def _run_translation(provider, requests: List[Dict[str, Any]]) -> Dict[int, str]:
    """Translate a list of requests in batches, grouped by target language.

    Each request: {'index': int, 'lang': 'zh'|'en', 'text': str} where
    'lang' is the SOURCE language. Returns {index: translated_text}.
    """
    import json as _json

    by_target: Dict[str, List[Dict[str, Any]]] = {'en': [], 'zh': []}
    for req in requests:
        target = 'en' if req['lang'] == 'zh' else 'zh'
        by_target[target].append(req)

    results: Dict[int, str] = {}

    for target, group in by_target.items():
        direction_text = 'Chinese -> English' if target == 'en' else 'English -> Chinese'
        system_prompt = f"""You are a professional cybersecurity translation engine translating vulnerability analysis text ({direction_text}).
Rules:
1. Use standard information-security terminology; keep the translation accurate and concise
2. Keep CVE ids, product names, and vendor names untranslated
3. The output must be in the target language: when translating to English keep no Chinese hanzi; when translating to Chinese keep only necessary English proper nouns (CVE ids, product names)
4. Output ONLY one JSON object directly parseable by Python json.loads(); no markdown fences, preface, <think> blocks, or any extra characters"""

        for i in range(0, len(group), TRANSLATE_BATCH_SIZE):
            batch = group[i:i + TRANSLATE_BATCH_SIZE]

            lines = [f"{req['index']}. {req['text']}" for req in batch]

            prompt = f"""Translate the following {len(batch)} vulnerability analysis texts (direction: {direction_text}).

## Text list
{chr(10).join(lines)}

## Output format
One JSON object only, index matching the input numbering:
{{"translations":[{{"index":number,"text":"translated text"}}]}}"""

            try:
                response = provider.analyze(prompt, system_prompt, temperature=0.1)
                applied = 0
                valid_indexes = {req['index'] for req in batch}
                for item in _parse_translations(response):
                    if item['index'] in valid_indexes and item['text']:
                        results[item['index']] = item['text']
                        applied += 1
                logger.info(
                    f"Translation batch done ({direction_text}, "
                    f"{len(batch)} items, {applied} parsed)"
                )
            except Exception as e:
                logger.error(f"Translation batch failed ({direction_text}): {str(e)}")
                continue

    return results


def translate_ai_curated(curated: Dict[str, Any], provider) -> int:
    """Add dual-language fields to AI curated data in place.

    Adds reason_zh/reason_en per curated CVE and summary_zh/summary_en on
    the top-level dict. Returns the number of real translations applied.
    """
    if not curated:
        return 0

    requests: List[Dict[str, Any]] = []
    lookup: Dict[int, Dict[str, Any]] = {}  # index -> {'obj', 'prefix', 'target'}

    def _add(obj: Dict[str, Any], prefix: str, text: str) -> None:
        if not text:
            return
        lang = detect_language(text)
        target = 'en' if lang == 'zh' else 'zh'
        obj.setdefault(f'{prefix}_{lang}', text)
        index = len(requests)
        requests.append({'index': index, 'lang': lang, 'text': text})
        lookup[index] = {'obj': obj, 'prefix': prefix, 'target': target}

    for cat_cves in curated.get('categories', {}).values():
        for cve in cat_cves:
            _add(cve, 'reason', cve.get('reason', ''))

    _add(curated, 'summary', curated.get('summary', ''))

    if not requests:
        return 0

    results = _run_translation(provider, requests)

    def _apply(entry: Dict[str, Any], result_text: Optional[str]) -> bool:
        """Apply a translation if it actually is in the target language"""
        obj, prefix, target = entry['obj'], entry['prefix'], entry['target']
        if not result_text or not _is_translated(result_text, target):
            return False
        obj[f'{prefix}_{target}'] = result_text
        return True

    translated = 0
    invalid_indexes = []
    for index, entry in lookup.items():
        obj, prefix, target = entry['obj'], entry['prefix'], entry['target']
        if _apply(entry, results.get(index)):
            translated += 1
        else:
            invalid_indexes.append(index)
        # Fall back to the source text so rendering never shows blanks
        obj.setdefault(f'{prefix}_{target}', obj.get(prefix, ''))

    # One retry round for items the model echoed back in the source language
    if invalid_indexes:
        logger.info(
            f"Retrying {len(invalid_indexes)} curated items whose translation "
            f"was not in the target language"
        )
        retry_requests = [requests[i] for i in invalid_indexes]
        retry_results = _run_translation(provider, retry_requests)
        for i in invalid_indexes:
            if _apply(lookup[i], retry_results.get(i)):
                translated += 1

    return translated


def translate_curated_if_possible(curated: Dict[str, Any]) -> bool:
    """Translate curated data in place when an API key is configured.

    Returns False (no-op) when no provider is available, so the caller
    keeps its original behavior in that case.
    """
    if not curated:
        return False
    try:
        from ai_provider import AIProvider
        provider = AIProvider()
    except ValueError as e:
        logger.info(f"Translation skipped: {str(e)}")
        return False
    except ImportError as e:
        logger.warning(f"Translation skipped: {str(e)}")
        return False

    count = translate_ai_curated(curated, provider)
    logger.info(f"Translation completed: {count} curated texts translated")
    return True
