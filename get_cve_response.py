import logging
import sys
import ast
import threading
import requests
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import json
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('get_CVEs_API_response.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global thread-safe collections for API call tracking
api_calls_log = []
api_calls_lock = threading.Lock()


def log_api_call(cpe_pattern, url, status_code, response_json):
    """Thread-safe function to log API calls with timestamp"""
    with api_calls_lock:
        api_calls_log.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'cpe_pattern': cpe_pattern,
            'url': url,
            'status_code': status_code,
            'response_json': response_json
        })
        logger.debug(f"Logged API call for CPE pattern: {cpe_pattern}, Status: {status_code}")

def nvd_cpe_pattern_search(cpe_pattern):
    headers = {
        'apiKey': ''
    }
    cve_det = pd.DataFrame()
    # adding this 30 sconds sleep time due to issue reported on 30/01/2026
    # the issue: since pipeline ran as scheduler parallely, it got 429 error code viz, too many requests,
    # so decided to have 30 seconds sleep time. further time can be changed by modifying the below variable
    sleep_seconds = 30
    retry_count = 0
    max_retries = 3

    logger.debug(f"Starting CPE pattern search for: {cpe_pattern}")

    while True:
        # Step 1: Query CPE API
        nvd_cpe_url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString={cpe_pattern}"
        try:
            logger.debug(f"Querying CPE API for pattern: {cpe_pattern}")
            res = requests.get(nvd_cpe_url, headers=headers)
            logger.info(f'CPE API response status code: {res.status_code} for pattern: {cpe_pattern}')

            # Log API call with response
            try:
                response_json = json.dumps(res.json())
            except:
                response_json = res.text
            log_api_call(cpe_pattern, nvd_cpe_url, res.status_code, response_json)
        except Exception as e:
            logger.error(f"Exception during CPE API call for pattern {cpe_pattern}: {e}")
            log_api_call(cpe_pattern, nvd_cpe_url, "ERROR", str(e))
            return cve_det, "CPE API call failed", {'cpe_pattern': cpe_pattern}

        if res.status_code == 403:
            logger.warning(f"Permission denied (403) for CPE pattern: {cpe_pattern}. Retrying...")
            time.sleep(5)
            continue
        if res.status_code == 429:
            logger.warning(
                f"Rate limit exceeded (429) for CPE pattern: {cpe_pattern}. Retrying after {sleep_seconds} seconds...")
            time.sleep(sleep_seconds)
            continue
        if res.status_code != 200:
            logger.error(f"Invalid CPE pattern (status {res.status_code}): {cpe_pattern}")
            return cve_det, "Invalid CPE pattern", {'cpe_pattern': cpe_pattern}

        data = res.json()
        if data.get('totalResults', 0) == 0:
            logger.warning(f"CPE Pattern returned no results: {cpe_pattern}")
            return cve_det, "CPE Pattern does not contain any results, Manual Check Needed", None

        # Step 2: Find first non-deprecated CPE
        new_cpe_pattern = None
        for product in data.get('products', []):
            cpe_info = product.get('cpe', {})
            if not cpe_info.get('deprecated', False):
                new_cpe_pattern = cpe_info.get('cpeName')
                logger.info(f"Found non-deprecated CPE pattern: {new_cpe_pattern} (original: {cpe_pattern})")
                break
        if not new_cpe_pattern:
            logger.warning(f"All CPEs deprecated for pattern: {cpe_pattern}")
            return cve_det, "All CPEs deprecated", {'cpe_pattern': cpe_pattern}

        # Step 3: Query CVE API with new CPE pattern
        nvd_cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={new_cpe_pattern}"
        try:
            logger.debug(f"Querying CVE API with CPE: {new_cpe_pattern}")
            res = requests.get(nvd_cve_url, headers=headers)
            logger.info(f"CVE API response status code: {res.status_code} for CPE: {new_cpe_pattern}")

            # Log API call with response
            try:
                response_json = json.dumps(res.json())
            except:
                response_json = res.text
            log_api_call(cpe_pattern, nvd_cve_url, res.status_code, response_json)
        except Exception as e:
            logger.error(f"Exception during CVE API call for CPE {new_cpe_pattern}: {e}")
            log_api_call(cpe_pattern, nvd_cve_url, "ERROR", str(e))
            return cve_det, "CVE API call failed", {'cpe_pattern': cpe_pattern}

        if res.status_code == 403:
            logger.warning(f"Permission denied (403) for CVE search. Retrying...")
            time.sleep(5)
            continue
        if res.status_code == 429:
            logger.warning(
                f"Rate limit exceeded (429) for CVE search. Retrying after {sleep_seconds} seconds...")
            time.sleep(sleep_seconds)
            continue
        if res.status_code != 200:
            logger.error(f"Invalid CVE request (status {res.status_code}) for CPE: {new_cpe_pattern}")
            return cve_det, "Invalid CVE pattern", {'cpe_pattern': cpe_pattern}

        data = res.json()
        total_cves = data.get('totalResults', 0)
        if total_cves == 0:
            logger.info(f"No CVEs found for CPE: {new_cpe_pattern} (original pattern: {cpe_pattern})")
            return cve_det, "No Vulnerabilities detected", None

        # Step 4: Collect CVE data
        cve_list = [item['cve'] for item in data.get('vulnerabilities', [])]
        if cve_list:
            logger.info(f"Found {len(cve_list)} CVEs for CPE: {new_cpe_pattern}")
            df = pd.DataFrame(cve_list)
            cve_det = pd.concat([cve_det, df], axis=0, ignore_index=True)
            cve_det.drop_duplicates(subset="id", keep="first", inplace=True)
            logger.debug(f"Total unique CVEs collected so far: {len(cve_det)}")
        return cve_det, f"{len(cve_list)} CVEs Found", None

def isInvalidCpePattern(name, version):
    invalid = False

    if 'Proprietary' in name or 'Not provided' in name or 'release' in name or ',' in name or '(' in name or ')' in name or '/' in name:
        invalid = True
        logger.debug(f"Invalid CPE pattern detected (special characters): {name} - {version}")

    if type(version) == str and 'Not provided' in version:
        invalid = True
        logger.debug(f"Invalid CPE pattern detected (version not provided): {name} - {version}")

    return invalid

def process_component(sa, component_idx, total_components):
    """
    Process a single component and return CVE details and invalid patterns.
    Thread-safe function for concurrent processing.

    Args:
        sa: SBOM component dictionary
        component_idx: Index of component for logging
        total_components: Total number of components for logging

    Returns:
        Tuple of (cve_details_list, invalid_pattern_dict or None)
    """
    logger.debug(f'Processing component: [{component_idx}/{total_components}] - {sa.get("name", "unknown")}')
    vendor = '*'
    name = sa['name']
    version = sa['version']
    logger.debug(f"Component details - Name: {name}, Version: {version}")

    # ------------------------------------
    # check for opensource licenses ONLY
    # ------------------------------------
    if 'licenses' in sa:
        licenses = sa['licenses']
        if 'license' in licenses[0]:
            if name == 'zlib':
                logger.debug(f"Processing zlib component")
                pass
            elif 'id' not in licenses[0]['license']:
                logger.debug(f"Skipping {name} - No license ID found")
                return [], None

    if len(name) > 60:
        logger.debug(f"Skipping {name} - Name too long ({len(name)} characters)")
        return [], None

    if isInvalidCpePattern(name, version):
        logger.debug(f"Skipping {name} - Invalid CPE pattern")
        return [], None
    # ------------------------------------
    # change the name for dtc
    # ------------------------------------
    if 'dtc' in name:
        logger.debug(f"Changing dtc name to dtc_project")
        name = 'dtc_project'

    if isinstance(name, str) and name.strip():
        name = name.strip().lower()
        if name in ("mbed", "mbedtls"):
            logger.debug(f"Changing mbedtls/mbed name to arm")
            name = 'arm'

    if '.' in name:
        name = name.split('.')[0]

        if '-' in name:
            name = name.split('-')[0]

        if 'edk2' in name and '-' not in version:
            logger.debug(f"Skipping edk2 component - invalid version format")
            return [], None

    if type(version) == str and '-' in version:
        version = version.split('-')[1]

        if 'stable' in version:
            version = version.replace("stable", "")

    if type(version) is str:
        if version.lower() == 'n/a':
            logger.debug(f"Skipping {name} - Version not available")
            return [], None

    cpe_pattern = f"cpe:2.3:a:*:{name}:{version}:*:*:*:*:*:*:*"
    if cpe_pattern.find('+') != -1:
        logger.debug(f"Removing '+' from CPE pattern")
        cpe_pattern = cpe_pattern.replace('+', '')
    if cpe_pattern.find(' ') != -1:
        logger.debug(f"Removing spaces from CPE pattern")
        cpe_pattern = cpe_pattern.replace(' ', '')

    logger.info(f"Searching CVEs for CPE pattern: {cpe_pattern}")
    data, cve_results, invalid_cpe_pattern = nvd_cpe_pattern_search(cpe_pattern)

    nvd_details = []
    if not data.empty:
        logger.info(f"Found {len(data)} CVEs for {sa['name']} v{sa['version']}")
        for idx, i in data.iterrows():
            payload = {'name': sa['name'], 'version': sa['version'], 'cpe_pattern': cpe_pattern,
                       'id': i['id'], 'published': i['published']}
            descriptions = i['descriptions']
            payload['descriptions'] = descriptions[0]['value']
            if i['metrics']:
                metrics = i['metrics']
                for i in metrics:
                    payload['cvss_ver'] = metrics[i][0]['cvssData']['version']
                    payload['score'] = metrics[i][0]['cvssData']['baseScore']
                    payload['CVSSString'] = metrics[i][0]['cvssData']['vectorString']
                    break
            nvd_details.append(payload)
    else:
        logger.debug(f"No CVEs found for {sa['name']} v{sa['version']}")

    return nvd_details, invalid_cpe_pattern

def parse_sbom_file(path):
    # Check _Sbom_file
    components = None
    logger.info(f"Starting to parse SBOM file: {path}")
    # read SBOM file
    try:
        f = open(path, 'r', encoding='utf-8')
        content = f.read()
    except FileNotFoundError:
        logger.error(f"SBOM file not found: {path}")
        return None
    except Exception as e:
        logger.error(f"Error reading SBOM file {path}: {e}")
        return None

    # parse component from SBOM file
    if content != '':
        try:
            res = ast.literal_eval(content)
            if 'components' in res:
                components = res['components']
            elif 'metadata' in res:
                if 'component' in res['metadata']:
                    if 'components' in res['metadata']['component']:
                        components = res['metadata']['component']['components']
            else:
                logger.warning(f"No components found in SBOM structure")
                return None
        except Exception as e:
            logger.error(f"Error occurred while processing SBOM content file. Error: {str(e)}")
            return None
    else:
        logger.error("SBOM content file is empty")
        return None
    logger.info(f"Successfully parsed SBOM file. Found {len(components)} components")
    return components

def generate_api_calls_report():
    """
    Generate an Excel sheet containing all API calls made during CVE search.
    Includes timestamp, CPE pattern, URL, status code, and response JSON.
    """
    global api_calls_log

    if not api_calls_log:
        logger.warning("No API calls logged - report will be empty")
        return

    logger.info(f"Generating API calls report with {len(api_calls_log)} entries")

    # Create DataFrame from API calls log
    df = pd.DataFrame(api_calls_log)

    # Generate Excel file name
    api_report_name = "API_Calls_Report.xlsx"

    try:
        # Create Excel writer
        with pd.ExcelWriter(api_report_name, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='API Calls')

            # Adjust column widths for better readability
            worksheet = writer.sheets['API Calls']
            worksheet.column_dimensions['A'].width = 20  # Timestamp
            worksheet.column_dimensions['B'].width = 60  # CPE pattern
            worksheet.column_dimensions['C'].width = 100  # URL
            worksheet.column_dimensions['D'].width = 15   # Status code
            worksheet.column_dimensions['E'].width = 150  # Response JSON

            # Enable text wrapping for better visibility
            from openpyxl.styles import Alignment
            for row in worksheet.iter_rows():
                for cell in row:
                    cell.alignment = Alignment(wrap_text=True, vertical='top')

        logger.info(f"API calls report successfully generated: {api_report_name} with {len(df)} API calls")
    except Exception as e:
        logger.error(f"Failed to generate API calls report: {e}", exc_info=True)

def generate_cves(output_cdx_name, max_workers=10):
    """
    Generate CVE Excel sheet using multi-threaded API calls.

    Args:
        output_cdx_name: Path to the CDX JSON file
        max_workers: Number of concurrent threads for API calls (default: 10)
    """
    global api_calls_log

    # Clear previous API calls log for fresh start
    api_calls_log = []

    logger.info(f"Starting CVE generation from CDX file: {output_cdx_name}")
    sbom_components = parse_sbom_file(output_cdx_name)
    if sbom_components is None:
        logger.error(f"Failed to parse SBOM components from {output_cdx_name}")
        sys.exit(1)

    logger.info(f"Total components to process: {len(sbom_components)}")

    # Thread-safe collections
    nvd_components_details = []
    invalid_cpe_pattern_list = []
    lock = threading.Lock()
    processed_count = [0]  # Use list to track count in nested function

    def process_and_collect(idx, sa):
        """Wrapper function to process component and safely collect results"""
        try:
            nvd_details, invalid_pattern = process_component(sa, idx, len(sbom_components))

            # Thread-safe collection of results
            with lock:
                nvd_components_details.extend(nvd_details)
                if invalid_pattern is not None:
                    invalid_cpe_pattern_list.append(invalid_pattern)
                processed_count[0] += 1
                if processed_count[0] % 10 == 0:
                    logger.info(f"Progress: {processed_count[0]}/{len(sbom_components)} components processed")
        except Exception as e:
            logger.error(f"Error processing component {idx}: {e}", exc_info=True)
            with lock:
                processed_count[0] += 1

    # Use ThreadPoolExecutor for concurrent processing
    logger.info(f"Starting multi-threaded processing with {max_workers} workers")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(process_and_collect, idx, sa)
            for idx, sa in enumerate(sbom_components)
        ]

        # Wait for all futures to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error processing component: {e}", exc_info=True)

    logger.info(f"Completed processing all {len(sbom_components)} components")
    logger.info(f"Invalid CPE patterns found: {len(invalid_cpe_pattern_list)}")

    # Generate API calls report
    logger.info("Generating API calls report...")
    generate_api_calls_report()

    df = pd.DataFrame(nvd_components_details)
    if df.empty:
        logger.warning("No CVE data found - Excel file will be empty")
        return None, None, None

    initial_count = len(df)
    df = df.drop_duplicates(subset=['id'], keep='first')
    final_count = len(df)

    logger.info(f"Total CVEs collected: {initial_count}")
    logger.info(f"Unique CVEs after deduplication: {final_count}")
    logger.info(f"Duplicate CVEs removed: {initial_count - final_count}")

    nameofexcel = "CVE_List.xlsx"
    try:
        df.to_excel(nameofexcel, index=False)
        logger.info(f"Excel file successfully generated: {nameofexcel} with {final_count} unique CVEs")
    except Exception as e:
        logger.error(f"Failed to generate Excel file: {e}", exc_info=True)
        sys.exit(1)


generate_cves('edk.cdx.json')