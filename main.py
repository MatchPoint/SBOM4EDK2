#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import os
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

import pandas as pd
import requests
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'edk2_json_generator_{time.strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global session and CPE cache for NVD API
_nvd_session = None
_cpe_cache = {}  # Simple per-CPE pattern cache
_cpe_cache_lock = threading.Lock()

# Initialize a requests Session with retry strategy for NVD API
def create_nvd_session():
    """Create a requests Session with retry/backoff for NVD API calls."""
    session = requests.Session()
    retry_strategy = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def get_nvd_session():
    """Get or create the global NVD API session."""
    global _nvd_session
    if _nvd_session is None:
        _nvd_session = create_nvd_session()
    return _nvd_session

def isInvalidCpePattern(name, version):
    invalid = False

    if 'Proprietary' in name or 'Not provided' in name or 'release' in name or ',' in name or '(' in name or ')' in name or '/' in name:
        invalid = True
        logger.debug(f"Invalid CPE pattern detected (special characters): {name} - {version}")

    if type(version) == str and 'Not provided' in version:
        invalid = True
        logger.debug(f"Invalid CPE pattern detected (version not provided): {name} - {version}")

    return invalid


def nvd_cpe_pattern_search(cpe_pattern, api_key):
    headers = {
        'apiKey': api_key
    }
    cve_det = pd.DataFrame()

    # Check cache first
    with _cpe_cache_lock:
        if cpe_pattern in _cpe_cache:
            logger.debug(f"Cache hit for CPE pattern: {cpe_pattern}")
            return _cpe_cache[cpe_pattern]

    # Get the persistent session with retry strategy
    session = get_nvd_session()

    logger.debug(f"Starting CPE pattern search for: {cpe_pattern}")

    # Step 1: Query CPE API
    nvd_cpe_url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString={cpe_pattern}"
    try:
        logger.debug(f"Querying CPE API for pattern: {cpe_pattern}")
        res = session.get(nvd_cpe_url, headers=headers, timeout=30)
        logger.info(f'CPE API response status code: {res.status_code} for pattern: {cpe_pattern}')
    except Exception as e:
        logger.error(f"Exception during CPE API call for pattern {cpe_pattern}: {e}")
        result = (cve_det, "CPE API call failed", {'cpe_pattern': cpe_pattern})
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    if res.status_code == 403:
        logger.warning(f"Permission denied (403) for CPE pattern: {cpe_pattern}")
        result = (cve_det, "Permission denied", {'cpe_pattern': cpe_pattern})
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    if res.status_code != 200:
        logger.error(f"Invalid CPE pattern (status {res.status_code}): {cpe_pattern}")
        result = (cve_det, "Invalid CPE pattern", {'cpe_pattern': cpe_pattern})
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    try:
        data = res.json()
    except Exception as e:
        logger.error(f"Failed to parse CPE API response as JSON: {e}")
        result = (cve_det, "Invalid JSON response", {'cpe_pattern': cpe_pattern})
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    if data.get('totalResults', 0) == 0:
        logger.warning(f"CPE Pattern returned no results: {cpe_pattern}")
        result = (cve_det, "CPE Pattern does not contain any results, Manual Check Needed", None)
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

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
        result = (cve_det, "All CPEs deprecated", {'cpe_pattern': cpe_pattern})
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    # Step 3: Query CVE API with new CPE pattern
    nvd_cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={new_cpe_pattern}"
    try:
        logger.debug(f"Querying CVE API with CPE: {new_cpe_pattern}")
        res = session.get(nvd_cve_url, headers=headers, timeout=30)
        logger.info(f"CVE API response status code: {res.status_code} for CPE: {new_cpe_pattern}")
    except Exception as e:
        logger.error(f"Exception during CVE API call for CPE {new_cpe_pattern}: {e}")
        result = (cve_det, "CVE API call failed", {'cpe_pattern': cpe_pattern})
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    if res.status_code == 403:
        logger.warning(f"Permission denied (403) for CVE search")
        result = (cve_det, "Permission denied", {'cpe_pattern': cpe_pattern})
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    if res.status_code != 200:
        logger.error(f"Invalid CVE request (status {res.status_code}) for CPE: {new_cpe_pattern}")
        result = (cve_det, "Invalid CVE request", {'cpe_pattern': cpe_pattern})
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    try:
        data = res.json()
    except Exception as e:
        logger.error(f"Failed to parse CVE API response as JSON: {e}")
        result = (cve_det, "Invalid JSON response", {'cpe_pattern': cpe_pattern})
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    total_cves = data.get('totalResults', 0)
    if total_cves == 0:
        logger.info(f"No CVEs found for CPE: {new_cpe_pattern} (original pattern: {cpe_pattern})")
        result = (cve_det, "No Vulnerabilities detected", None)
        with _cpe_cache_lock:
            _cpe_cache[cpe_pattern] = result
        return result

    # Step 4: Collect CVE data
    cve_list = [item['cve'] for item in data.get('vulnerabilities', [])]
    if cve_list:
        logger.info(f"Found {len(cve_list)} CVEs for CPE: {new_cpe_pattern}")
        df = pd.DataFrame(cve_list)
        cve_det = pd.concat([cve_det, df], axis=0, ignore_index=True)
        cve_det.drop_duplicates(subset="id", keep="first", inplace=True)
        logger.debug(f"Total unique CVEs collected: {len(cve_det)}")

    result = (cve_det, f"{len(cve_list)} CVEs Found", None)
    with _cpe_cache_lock:
        _cpe_cache[cpe_pattern] = result
    return result


def process_component(sa, component_idx, total_components, api_key):
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
    # Guard against missing name/version
    if 'name' not in sa or not sa.get('name'):
        logger.debug(f'Skipping component {component_idx}: missing or empty name')
        return [], None

    if 'version' not in sa or not sa.get('version'):
        logger.debug(f'Skipping component {component_idx} ({sa.get("name")}): missing or empty version')
        return [], None

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
    data, cve_results, invalid_cpe_pattern = nvd_cpe_pattern_search(cpe_pattern, api_key)

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
    """Parse SBOM file and extract CycloneDX components safely using json.load."""
    logger.info(f"Starting to parse SBOM file: {path}")
    components = []

    # read SBOM file using json.load
    try:
        with open(path, 'r', encoding='utf-8') as f:
            res = json.load(f)
    except FileNotFoundError:
        logger.error(f"SBOM file not found: {path}")
        return components
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in SBOM file {path}: {e}")
        return components
    except Exception as e:
        logger.error(f"Error reading SBOM file {path}: {e}")
        return components

    # Extract components from standard CycloneDX structure
    if isinstance(res, dict):
        # Try standard top-level 'components' first
        if 'components' in res:
            components = res.get('components', [])
        # Try metadata.component.components structure
        elif 'metadata' in res and isinstance(res['metadata'], dict):
            if 'component' in res['metadata'] and isinstance(res['metadata']['component'], dict):
                components = res['metadata']['component'].get('components', [])

        if not components:
            logger.warning(f"No components found in SBOM structure")
            return []

    if not isinstance(components, list):
        logger.warning(f"Components is not a list, returning empty list")
        return []

    logger.info(f"Successfully parsed SBOM file. Found {len(components)} components")
    return components


def generate_cves(output_cdx_name, api_key, max_workers=6):
    """
    Generate CVE Excel sheet using multi-threaded API calls with reduced concurrency.

    Args:
        output_cdx_name: Path to the CDX JSON file
        api_key: NVD API Key for CVE generation
        max_workers: Number of concurrent threads for API calls (default: 6 for CVE generation)
    """
    logger.info(f"Starting CVE generation from CDX file: {output_cdx_name}")
    sbom_components = parse_sbom_file(output_cdx_name)

    # parse_sbom_file now returns empty list instead of None
    if not sbom_components:
        logger.warning(f"No components found in SBOM file {output_cdx_name}")
        return

    logger.info(f"Total components to process: {len(sbom_components)}")

    # Thread-safe collections
    nvd_components_details = []
    invalid_cpe_pattern_list = []
    lock = threading.Lock()
    processed_count = [0]  # Use list to track count in nested function

    def process_and_collect(idx, sa):
        """Wrapper function to process component and safely collect results"""
        try:
            nvd_details, invalid_pattern = process_component(sa, idx, len(sbom_components), api_key)

            # Thread-safe collection of results
            with lock:
                nvd_components_details.extend(nvd_details)
                if invalid_pattern is not None:
                    invalid_cpe_pattern_list.append(invalid_pattern)
                processed_count[0] += 1
                # if processed_count[0] % 10 == 0:
                logger.info(f"Progress: {processed_count[0]}/{len(sbom_components)} components processed")
        except Exception as e:
            logger.error(f"Error processing component {idx}: {e}", exc_info=True)
            with lock:
                processed_count[0] += 1

    # Use ThreadPoolExecutor for concurrent processing with reduced workers for CVE
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
    logger.info(f'Invalid CPE Patterns: {invalid_cpe_pattern_list}')
    logger.info(f"Invalid CPE patterns found: {len(invalid_cpe_pattern_list)}")

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


def main():
    parser = argparse.ArgumentParser(description='Clone git repo and generate SBOM with CVE analysis')
    parser.add_argument('-r', '--repo', required=True, help='Git repository URL')
    parser.add_argument('-o', '--output', required=True, help='Output CDX filename (without extension)')
    parser.add_argument('-k', '--apikey', default=None, help='NVD API Key for CVE generation (or set NVD_API_KEY in .env)')
    
    args = parser.parse_args()

    api_key = args.apikey or os.environ.get('NVD_API_KEY')
    if not api_key:
        logger.error("NVD API key is required. Provide via -k flag or set NVD_API_KEY in .env file.")
        sys.exit(1)
    
    repo_url = args.repo
    output_filename = args.output
    cdx_file = f"{output_filename}.cdx.json"
    
    # Store original directory to restore later if needed
    original_dir = os.getcwd()

    # 1. Clone/Update uswid-data repository first
    uswid_data_dir = 'uswid-data'
    uswid_data_url = 'https://github.com/hughsie/uswid-data.git'

    if os.path.exists(uswid_data_dir):
        logger.info(f"Directory {uswid_data_dir} already exists, pulling latest changes...")
        try:
            os.chdir(uswid_data_dir)
            result = subprocess.run(['git', 'pull'])

            if result.returncode != 0:
                logger.error(f"Failed to pull latest changes for {uswid_data_dir}")
                os.chdir(original_dir)
                sys.exit(1)

            logger.info(f"{uswid_data_dir} updated successfully")
            os.chdir(original_dir)
        except Exception as e:
            logger.error(f"Error updating {uswid_data_dir}: {e}")
            os.chdir(original_dir)
            sys.exit(1)
    else:
        logger.info(f"Cloning {uswid_data_url}...")
        result = subprocess.run(['git', 'clone', uswid_data_url, uswid_data_dir])

        if result.returncode != 0:
            logger.error(f"Failed to clone {uswid_data_dir}")
            sys.exit(1)

        logger.info(f"{uswid_data_dir} cloned successfully")

    # 2. Clone/Update target repository
    logger.info(f"Processing repository: {repo_url}")
    clone_dir = output_filename

    if os.path.exists(clone_dir):
        logger.info(f"Directory {clone_dir} already exists, pulling latest changes...")
        try:
            os.chdir(clone_dir)
            result = subprocess.run(['git', 'pull'])

            if result.returncode != 0:
                logger.error(f"Failed to pull latest changes")
                os.chdir(original_dir)
                sys.exit(1)

            logger.info(f"Repository updated successfully")

            # Update submodules after pull
            logger.info(f"Updating git submodules...")
            result = subprocess.run(['git', 'submodule', 'update', '--init', '--recursive'])

            if result.returncode != 0:
                logger.error(f"Failed to update git submodules")
                os.chdir(original_dir)
                sys.exit(1)

            logger.info(f"Git submodules updated successfully")
            os.chdir(original_dir)

        except Exception as e:
            logger.error(f"Error updating repository: {e}")
            os.chdir(original_dir)
            sys.exit(1)
    else:
        logger.info(f"Cloning repository: {repo_url}")
        result = subprocess.run(['git', 'clone', repo_url, clone_dir])

        if result.returncode != 0:
            logger.error(f"Failed to clone repository")
            sys.exit(1)

        logger.info(f"Repository cloned successfully")

        try:
            os.chdir(clone_dir)
            logger.info(f"Initializing git submodules...")
            result = subprocess.run(['git', 'submodule', 'update', '--init', '--recursive'])

            if result.returncode != 0:
                logger.error(f"Failed to update git submodules")
                os.chdir(original_dir)
                sys.exit(1)

            logger.info(f"Git submodules updated successfully")
            os.chdir(original_dir)

        except Exception as e:
            logger.error(f"Error initializing submodules: {e}")
            os.chdir(original_dir)
            sys.exit(1)

    # 3. Run uswid command to generate CDX
    logger.info(f"Running uswid to generate CDX file...")
    result = subprocess.run(['uswid', '--verbose', '--find', clone_dir,'--fallback-path', 'uswid-data','--save', cdx_file])

    if result.returncode != 0:
        logger.error(f"Failed to generate CDX file")
        sys.exit(1)

    # Validate that CDX file was created
    if not os.path.exists(cdx_file):
        logger.error(f"CDX file was not created: {cdx_file}")
        sys.exit(1)

    logger.info(f"CDX file generated: {cdx_file}")

    # 4. Generate CVEs from CDX file
    logger.info(f"Generating CVE analysis...")
    generate_cves(cdx_file, api_key, max_workers=6)

    logger.info("Completed successfully!")


if __name__ == '__main__':
    main()
