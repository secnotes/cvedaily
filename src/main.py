import os
from collector import CVECollector
from reporter import generate_html_report
from config import Config

def main():
    # Create necessary directories
    os.makedirs('docs', exist_ok=True)

    # Surface proxy configuration so the operator can confirm what's in effect.
    # requests / httpx read these env vars natively; this is purely diagnostic.
    for proxy_var in ('HTTPS_PROXY', 'HTTP_PROXY', 'https_proxy', 'http_proxy'):
        proxy_value = os.environ.get(proxy_var)
        if proxy_value:
            print(f"🔌 Using proxy ({proxy_var}): {proxy_value}")
            break

    # Initialize collector
    collector = CVECollector()

    # Collect daily CVEs
    all_cves = collector.collect_daily_cves(days=Config.LOOKBACK_DAYS)

    # Get the total count of CVEs processed
    total_cve_count = getattr(collector, 'total_collected_cves', len(all_cves))

    # Filter high-risk CVEs for the summary printout (the HTML report
    # shows everything; filters are client-side)
    high_risk_cves = [cve for cve in all_cves if (
        cve.get('cvss_score', 0) > Config.CVSS_THRESHOLD or
        cve.get('in_cisa_kev', False) or
        cve.get('epss_score', 0) >= Config.EPSS_THRESHOLD
    )]

    # --- AI Curation ---
    ai_curated = None
    if Config.AI_CURATION_ENABLED:
        ai_curated = collector.ai_curate_cves(all_cves)
        if ai_curated:
            # Add the missing language (zh) to reasons/summary before caching
            from translator import translate_curated_if_possible
            translate_curated_if_possible(ai_curated)
            collector.save_ai_curated_cache(ai_curated)
            curated_count = sum(len(v) for v in ai_curated.get('categories', {}).values())
            print(f"AI curation completed: {curated_count} CVEs curated into categories")
        else:
            print("AI curation did not produce results")
    else:
        # Try loading cached AI results for report regeneration
        ai_curated = collector.load_ai_curated_cache()
    # --- END AI Curation ---

    # Generate HTML report (static shell + daily JSON data file; the
    # markdown archive was replaced by the JSON as the single data source)
    generate_html_report(all_cves, Config.REPORT_HTML_PATH, total_cve_count, ai_curated=ai_curated)

    print(f"Daily CVE collection completed!")
    print(f"Found {len(high_risk_cves)} high-risk vulnerabilities")
    print(f"Total CVEs collected: {total_cve_count}")
    print(f"HTML report saved as {Config.REPORT_HTML_PATH}")

if __name__ == "__main__":
    main()