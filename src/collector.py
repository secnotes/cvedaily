import os
import json
import requests
import zipfile
import io
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from config import Config

class CVECollector:
    def __init__(self):
        self.cisa_kev_list = []
        self.epss_data = {}

        # Load CISA KEV data
        self.load_cisa_kev()

    def load_cisa_kev(self):
        """Load CISA Known Exploited Vulnerabilities list"""
        try:
            response = requests.get(Config.CISA_KEV_URL)
            if response.status_code == 200:
                data = response.json()
                # Extract CVE IDs from the list
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID")
                    if cve_id:
                        self.cisa_kev_list.append(cve_id)
        except Exception as e:
            print(f"Error loading CISA KEV: {e}")

    def load_epss_data_batch(self, cve_ids):
        """Load EPSS scores for specific CVE IDs using the FIRST API"""
        try:
            if not cve_ids:
                return

            # Process CVEs in smaller batches to avoid potential API issues
            batch_size = 20  # Smaller batch size to reduce API load
            for i in range(0, len(cve_ids), batch_size):
                batch = cve_ids[i:i + batch_size]

                # Format CVE IDs as comma-separated string
                cve_list = ','.join(batch)

                # Use the FIRST API to get EPSS scores
                url = f"https://api.first.org/data/v1/epss?cve={cve_list}"

                try:
                    response = requests.get(url, timeout=30)
                except requests.exceptions.SSLError as ssl_err:
                    print(f"SSL error when requesting EPSS data: {ssl_err}")
                    print(f"Retrying with reduced batch size for {len(batch)} CVEs...")
                    # Retry one by one for the current batch
                    for single_cve in batch:
                        single_url = f"https://api.first.org/data/v1/epss?cve={single_cve}"
                        try:
                            single_response = requests.get(single_url, timeout=30)
                            if single_response.status_code == 200:
                                data = single_response.json()
                                if 'data' in data:
                                    for item in data['data']:
                                        cve_id = item.get('cve')
                                        epss_score_str = item.get('epss')
                                        if cve_id and epss_score_str is not None:
                                            try:
                                                epss_score = float(epss_score_str)
                                                self.epss_data[cve_id] = epss_score
                                            except ValueError:
                                                continue
                        except Exception as e:
                            print(f"Error getting EPSS for {single_cve}: {e}")
                    continue  # Skip processing this batch since we handled individually
                except Exception as e:
                    print(f"Error fetching batch of {len(batch)} CVEs: {e}")
                    continue

                if response.status_code == 200:
                    data = response.json()

                    # Parse the response and populate epss_data dictionary
                    if 'data' in data:
                        for item in data['data']:
                            cve_id = item.get('cve')
                            epss_score_str = item.get('epss')

                            if cve_id and epss_score_str is not None:
                                try:
                                    epss_score = float(epss_score_str)
                                    self.epss_data[cve_id] = epss_score
                                except ValueError:
                                    # Skip entries with invalid EPSS score values
                                    continue
                else:
                    print(f"Warning: Failed to fetch EPSS data for batch. Status code: {response.status_code}")

                    # Still try individual requests for this batch
                    for single_cve in batch:
                        single_url = f"https://api.first.org/data/v1/epss?cve={single_cve}"
                        try:
                            single_response = requests.get(single_url, timeout=30)
                            if single_response.status_code == 200:
                                data = single_response.json()
                                if 'data' in data:
                                    for item in data['data']:
                                        cve_id = item.get('cve')
                                        epss_score_str = item.get('epss')
                                        if cve_id and epss_score_str is not None:
                                            try:
                                                epss_score = float(epss_score_str)
                                                self.epss_data[cve_id] = epss_score
                                            except ValueError:
                                                continue
                        except Exception as e:
                            print(f"Error getting EPSS for {single_cve}: {e}")
        except Exception as e:
            print(f"Error loading EPSS data: {str(e).encode('ascii', 'ignore').decode('ascii')}")

    def ai_curate_cves(self, cves):
        """Use AI to categorize and recommend important CVEs"""
        try:
            from ai_provider import AIProvider
        except ImportError:
            print("ai_provider module not found, skipping AI curation")
            return None

        # Filter CVEs suitable for AI analysis: CVSS >= 7.0 with non-empty description
        eligible_cves = [
            cve for cve in cves
            if cve.get('cvss_score', 0) >= 7.0 and cve.get('description')
        ]

        if not eligible_cves:
            print("No eligible CVEs for AI curation (need CVSS >= 7.0 with description)")
            return None

        print(f"AI curation: analyzing {len(eligible_cves)} eligible CVEs...")

        try:
            api_key = os.environ.get('AI_API_KEY')
            provider = AIProvider(api_key=api_key)
            result = provider.analyze_cves(eligible_cves, categories=Config.AI_CVE_CATEGORIES)
            return result
        except ValueError as e:
            print(f"AI curation skipped: {e}")
            return None
        except Exception as e:
            print(f"Error during AI curation: {e}")
            return None

    def save_ai_curated_cache(self, curated_data, path=None):
        """Save AI curated results to the dated JSON archive (docs/ai/YYYY/)"""
        if not curated_data:
            return
        path = path or Config.get_daily_ai_curated_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(curated_data, f, ensure_ascii=False, indent=2)
        print(f"AI curated data cached to {path}")

    def load_ai_curated_cache(self, path=None):
        """Load AI curated results: today's dated archive first, legacy
        docs/ai_curated.json as fallback (old caches carry Chinese
        category keys; the reporter normalizes those at render time)."""
        candidates = [path] if path else [
            Config.get_daily_ai_curated_path(),
            Config.AI_CURATED_CACHE_PATH,  # legacy pre-archive cache
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                try:
                    with open(candidate, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    print(f"Loaded cached AI curation results from {candidate}")
                    return data
                except Exception as e:
                    print(f"Error loading AI cache {candidate}: {e}")
        return None

    def collect_daily_cves(self, days=Config.LOOKBACK_DAYS):
        """Collect CVEs from the new CVEProject/cvelistV5 source"""
        print(f"Collecting CVEs from the last {days} day(s) from CVEProject/cvelistV5...")

        # Calculate the date for which we need to download the delta (yesterday)
        target_date = datetime.now() - timedelta(days=days)

        # Ensure we don't try to fetch future dates - if target date is today or in the future,
        # go back another day until we find a past date that we can fetch
        while target_date.date() >= datetime.now().date():
            target_date = target_date - timedelta(days=1)

        date_str = target_date.strftime("%Y-%m-%d")
        print(f"Adjusted to fetch CVEs for date: {date_str}")

        # Get CVEs from CVEProject/cvelistV5
        cvelistv5_cves = self.get_cvelistv5_cves_for_date(target_date)
        print(f"Found {len(cvelistv5_cves)} high-risk CVEs from CVEProject/cvelistV5")

        # Store the total number of collected CVEs before filtering
        self.total_collected_cves = len(cvelistv5_cves)

        # Store all collected CVEs before high-risk filtering (for markdown report)
        self.all_collected_cves = cvelistv5_cves.copy()

        # Combine and deduplicate
        all_cves = {}

        for cve in cvelistv5_cves:
            cve_id = cve['id']
            if cve_id not in all_cves:
                all_cves[cve_id] = cve

        # Now that we have all CVEs, fetch their EPSS scores in batches
        cve_ids = list(all_cves.keys())
        print(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
        self.load_epss_data_batch(cve_ids)

        # Update each CVE with the fetched EPSS score
        result = []
        for cve in all_cves.values():
            cve_id = cve['id']
            if cve_id in self.epss_data:
                cve['epss_score'] = self.epss_data[cve_id]
            else:
                # If no EPSS score is found, default to 0
                cve['epss_score'] = 0

            result.append(cve)

        # Sort by the more recent of published_date or last_modified date
        def get_sort_date(cve):
            pub_date_str = cve.get('published_date', '')
            mod_date_str = cve.get('last_modified', '')

            # Convert date strings to datetime objects for comparison
            pub_date = datetime.min
            mod_date = datetime.min

            if pub_date_str:
                try:
                    pub_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00').split('+')[0])
                except ValueError:
                    pass

            if mod_date_str:
                try:
                    mod_date = datetime.fromisoformat(mod_date_str.replace('Z', '+00:00').split('+')[0])
                except ValueError:
                    pass

            # Return the later of the two dates
            return max(pub_date, mod_date)

        result.sort(key=get_sort_date, reverse=True)

        # Count the high-risk ones separately for reporting
        high_risk_count = sum(1 for cve in result if (
            cve.get('cvss_score', 0) > Config.CVSS_THRESHOLD or
            cve.get('in_cisa_kev', False) or
            cve.get('epss_score', 0) >= Config.EPSS_THRESHOLD
        ))

        print(f"Total high-risk CVEs: {high_risk_count}")
        print(f"Total CVEs collected: {len(result)}")
        return result

    def get_cvelistv5_cves_for_date(self, target_date):
        """Fetch CVEs from CVEProject/cvelistV5 for a specific date"""
        cves = []
        try:
            date_str = target_date.strftime("%Y-%m-%d")

            print(f"Attempting to download CVEs for date: {date_str}")

            # Construct the URL for the delta ZIP file
            zip_url = f"https://github.com/CVEProject/cvelistV5/releases/download/cve_{date_str}_at_end_of_day/{date_str}_delta_CVEs_at_end_of_day.zip"

            print(f"Downloading from: {zip_url}")

            # Try downloading directly
            try:
                response = requests.get(zip_url, timeout=60)
            except:
                print("Download failed.")
                return []

            if response.status_code == 200:
                print(f"Successfully downloaded the ZIP file for {date_str}")

                # Extract the ZIP file in memory (skip saving to disk)
                with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                    print(f"Extracting {len(zip_file.namelist())} files from the ZIP...")

                    for file_info in zip_file.filelist:
                        if file_info.filename.endswith('.json'):
                            # Read the JSON file
                            with zip_file.open(file_info.filename) as json_file:
                                try:
                                    cve_data = json.loads(json_file.read().decode('utf-8'))

                                    # Process the CVE data according to the v5 schema
                                    cve_id = cve_data.get('cveMetadata', {}).get('cveId', '')
                                    if cve_id:
                                        # Extract description.
                                        # cvelistV5 records carry both 'en' and
                                        # regional tags like 'en-US' depending
                                        # on the submitting CNA — matching only
                                        # 'en' left ~45% of CVEs descriptionless.
                                        # Prefer exact 'en', then any 'en-*',
                                        # then fall back to the first non-empty
                                        # value (better than a blank card).
                                        description = ""
                                        desc_fallback = ""
                                        descriptions = cve_data.get('containers', {}).get('cna', {}).get('descriptions', [])
                                        for desc in descriptions:
                                            lang = (desc.get('lang') or '').lower()
                                            value = desc.get('value', '')
                                            if not value:
                                                continue
                                            if lang.startswith('en'):
                                                description = value
                                                if lang == 'en':
                                                    break
                                            elif not desc_fallback:
                                                desc_fallback = value
                                        description = description or desc_fallback

                                        # Decode HTML entities to convert &#x27; back to ' and other entities
                                        import html
                                        description = html.unescape(description)

                                        # Extract CVSS metrics
                                        cvss_score = 0
                                        metrics = cve_data.get('containers', {}).get('cna', {}).get('metrics', [])
                                        for metric_group in metrics:
                                            # Check for CVSS v4.x
                                            if 'cvssV4_0' in metric_group:
                                                cvss_data = metric_group['cvssV4_0']
                                                cvss_score = cvss_data.get('baseScore', 0)
                                            # Check for CVSS v3.x
                                            elif 'cvssV3_1' in metric_group:
                                                cvss_data = metric_group['cvssV3_1']
                                                cvss_score = cvss_data.get('baseScore', 0)
                                            elif 'cvssV3_0' in metric_group:
                                                cvss_data = metric_group['cvssV3_0']
                                                cvss_score = cvss_data.get('baseScore', 0)
                                            # Check for CVSS v2
                                            elif 'cvssV2_0' in metric_group:
                                                cvss_data = metric_group['cvssV2_0']
                                                cvss_score = cvss_data.get('baseScore', 0)

                                        # Extract vendor and product information from affected
                                        vendors = set()
                                        products = set()

                                        affected_list = cve_data.get('containers', {}).get('cna', {}).get('affected', [])
                                        for affected in affected_list:
                                            vendor = affected.get('vendor', '')
                                            product = affected.get('product', '')

                                            if vendor and vendor.lower() not in ['-', '*', '']:
                                                vendors.add(vendor.lower())
                                            if product and product.lower() not in ['-', '*', '']:
                                                products.add(product.lower())

                                            # Also check for platforms, modules, etc.
                                            platforms = affected.get('platforms', [])
                                            for platform in platforms:
                                                if platform and platform.lower() not in ['-', '*', '']:
                                                    vendors.add(platform.lower())

                                            # Process versions to extract more vendor/product info
                                            versions = affected.get('versions', [])
                                            for version in versions:
                                                if 'changes' in version:
                                                    for change in version['changes']:
                                                        value = change.get('value', '')
                                                        if value and value.lower() not in ['-', '*', '']:
                                                            vendors.add(value.lower())

                                        # Extract publication date
                                        published_date = cve_data.get('cveMetadata', {}).get('datePublished', '')
                                        last_modified = cve_data.get('cveMetadata', {}).get('dateUpdated', '')

                                        # Determine entry type based on dates
                                        target_date_str = target_date.strftime("%Y-%m-%d")
                                        entry_type = 'published'  # Default assumption

                                        # If published date matches target date, it's newly published
                                        if published_date and published_date.startswith(target_date_str):
                                            entry_type = 'published'
                                        # If published earlier but modified on target date, it's modified
                                        elif (published_date and not published_date.startswith(target_date_str) and
                                              last_modified and last_modified.startswith(target_date_str)):
                                            entry_type = 'modified'
                                        # If no published date but has modification on target date, consider as modified
                                        elif (not published_date and last_modified and
                                              last_modified.startswith(target_date_str)):
                                            entry_type = 'modified'
                                        # Otherwise, treat as published if it has data for the target date
                                        else:
                                            entry_type = 'published'

                                        # Check if it's high risk (based only on available data at collection time)
                                        # Full evaluation with EPSS happens after batch EPSS retrieval
                                        is_high_risk_initial = (
                                            cvss_score > Config.CVSS_THRESHOLD or
                                            cve_id in self.cisa_kev_list
                                        )

                                        # Include in results if it's high risk based on current data
                                        # or if it has CVSS score > 0 (we might later find high EPSS)
                                        include_in_results = is_high_risk_initial or cvss_score > 0

                                        if include_in_results:
                                            cves.append({
                                                'id': cve_id,
                                                'description': description,
                                                'cvss_score': cvss_score,
                                                'epss_score': 0,  # Will be updated later
                                                'in_cisa_kev': cve_id in self.cisa_kev_list,
                                                'vendors': list(vendors),
                                                'products': list(products),  # Keep products for processing but we'll not use them in the UI
                                                'published_date': published_date,
                                                'last_modified': last_modified,
                                                'entry_type': entry_type
                                            })

                                except json.JSONDecodeError:
                                    print(f"Could not decode JSON for file: {file_info.filename}")
                                    continue
                                except Exception as e:
                                    print(f"Error processing {file_info.filename}: {str(e)}")
                                    continue

                print(f"Processed {len(cves)} high-risk CVEs from {date_str} delta")
            else:
                print(f"Failed to download CVEs for {date_str}. Status code: {response.status_code}")

        except Exception as e:
            print(f"Error fetching CVEs from CVEProject/cvelistV5: {e}")

        return cves