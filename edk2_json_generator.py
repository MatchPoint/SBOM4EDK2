# TODO(Copilot-refactor):
# 1) Add CLI args:
#    --uswid-data (path to uswid-data) [optional]
#    --parent-yaml (path to parent YAML) [optional]
#    --max-workers (default 12)
# 2) In process_inf_file: call uswid with --load <inf> --fixup [--fallback-path <uswid-data>] --save <out>
# 3) Replace final --find merge with explicit --load merge:
#    - list_cdx_files() to gather only *.cdx.json from output folder
#    - merge_cdx_files(): supports parent YAML (loaded once at first merge), adds --fixup and optional --fallback-path,
#      chunks merges into intermediate files if needed, then produces final <jsonname>.cdx.json
# 4) Replace ast.literal_eval() SBOM parsing with json.load(); extract CycloneDX "components" safely
# 5) CVE/NVD phase:
#    - Build requests.Session with retries/backoff for 429/5xx; cache per CPE pattern
#    - Reduce max_workers for CVE to 6
#    - Add guards for missing name/version fields; keep normalization minimal
# 6) Maintain existing logging and error handling style; keep the rest of the flow unchanged



import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

import pandas as pd
import requests

parser = argparse.ArgumentParser(description='Run uswid over all .inf files under a location')
parser.add_argument('-l', '--location', required=True, help='Root location to scan')
parser.add_argument('-n', '--jsonname', required=True, help='Name of final json file to generate. Give the name without extension.')
parser.add_argument('-k', '--apikey', required=True, help='NVD API Key for CVE generation')
parser.add_argument('--uswid-data', default=None, help='Path to uswid-data repository for dependency fallback')
parser.add_argument('--parent-yaml', default=None, help='Optional parent component YAML to load first')
parser.add_argument('--max-workers', type=int, default=12, help='Concurrency for INF processing (default: 12)')
args = parser.parse_args()

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


# Global session and CPE cache for NVD API
_nvd_session = None
_cpe_cache = {}  # Simple per-CPE pattern cache
_cpe_cache_lock = threading.Lock()


def get_nvd_session():
    """Get or create the global NVD API session."""
    global _nvd_session
    if _nvd_session is None:
        _nvd_session = create_nvd_session()
    return _nvd_session


def nvd_cpe_pattern_search(cpe_pattern):
    headers = {
        'apiKey': args.apikey
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


def list_cdx_files(folder):
    """
    List all *.cdx.json files in a folder.
    
    Args:
        folder: Directory to search for CDX files
    
    Returns:
        List of absolute paths to CDX files (*.cdx.json)
    """
    cdx_files = []
    try:
        for fn in os.listdir(folder):
            if fn.lower().endswith('.cdx.json'):
                full_path = os.path.join(folder, fn)
                cdx_files.append(full_path)
                logger.debug(f"Found CDX file: {full_path}")
    except Exception as e:
        logger.error(f"Error listing CDX files in {folder}: {e}")
    
    logger.info(f"Found {len(cdx_files)} CDX files in {folder}")
    return sorted(cdx_files)


def sanitize_cdx_file(cdx_path):
    """
    Sanitize a CDX JSON file to fix components with None/missing source_dir.
    This works around a bug in uswid where it crashes on None source_dir values.
    
    Args:
        cdx_path: Path to the CDX JSON file to sanitize
    
    Returns:
        True if sanitized successfully, False otherwise
    """
    try:
        with open(cdx_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        logger.warning(f"Could not read {cdx_path} for sanitization: {e}")
        return False
    
    # Check if file has components
    components = data.get('components', [])
    if not components:
        logger.debug(f"No components found in {cdx_path}")
        return True
    
    # Fix components with None or missing source_dir
    modified = False
    for component in components:
        if isinstance(component, dict):
            source_dir = component.get('source-dir')
            # If source_dir is None or missing, set it to empty string
            if source_dir is None:
                component['source-dir'] = ""
                modified = True
                logger.debug(f"Fixed None source-dir in component: {component.get('name', 'unknown')}")
    
    # Write back only if modifications were made
    if modified:
        try:
            with open(cdx_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Sanitized CDX file: {cdx_path}")
        except Exception as e:
            logger.error(f"Failed to write sanitized CDX file {cdx_path}: {e}")
            return False
    
    return True


def merge_cdx_files(cdx_files, final_save, parent_yaml=None, fallback_path=None):
    """
    Merge multiple CDX files using hierarchical multi-pass chunking.
    
    Splits input files into chunks (<=100 per command), merges each chunk into an 
    intermediate file, then repeats with the intermediates until one file remains.
    Ensures all chunks are properly merged together through multiple passes.
    
    Args:
        cdx_files: List of CDX file paths to merge
        final_save: Path where the final merged CDX file should be saved
        parent_yaml: Optional YAML file to load only in first chunk of first pass
        fallback_path: Optional path to pass as --fallback-path to uswid (on every merge)
    
    Returns:
        Return code (0 for success, non-zero for failure)
    """
    if not cdx_files:
        logger.error("No CDX files to merge")
        return 1
    
    logger.info(f"Starting hierarchical multi-pass merge of {len(cdx_files)} CDX files")
    
    # Sanitize parent YAML/CDX file if provided
    if parent_yaml:
        if parent_yaml.lower().endswith('.cdx.json'):
            logger.info(f"Sanitizing parent CDX file: {parent_yaml}")
            if not sanitize_cdx_file(parent_yaml):
                logger.error(f"Failed to sanitize parent CDX file: {parent_yaml}")
                return 1
        else:
            # For YAML files, attempt sanitization if it's actually a CDX JSON file
            try:
                with open(parent_yaml, 'r', encoding='utf-8') as f:
                    test_data = json.load(f)
                    if 'components' in test_data or 'metadata' in test_data:
                        logger.info(f"Parent file appears to be CDX JSON, sanitizing: {parent_yaml}")
                        if not sanitize_cdx_file(parent_yaml):
                            logger.error(f"Failed to sanitize parent file: {parent_yaml}")
                            return 1
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Not JSON, likely actual YAML - skip sanitization
                logger.debug(f"Parent file is not JSON (likely YAML): {parent_yaml}")
    
    # Sanitize all input CDX files to work around uswid bug with None source_dir values
    logger.info("Sanitizing input CDX files to work around uswid source_dir handling...")
    for cdx_file in cdx_files:
        if not sanitize_cdx_file(cdx_file):
            logger.warning(f"Could not sanitize {cdx_file}, proceeding anyway")
    
    # Use smaller chunk size (100 files) to stay well under Windows command-line limits (~32KB)
    # With ~200 char file paths, 100 files = ~20KB of path data plus overhead
    max_files_per_chunk = 100
    intermediate_files = []  # Track all intermediate files for cleanup
    current_files = cdx_files[:]  # Start with input files
    pass_num = 1
    parent_yaml_loaded = False  # Track whether we've already loaded parent YAML
    
    # Multi-pass merging until only one file remains
    while len(current_files) > 1:
        logger.info(f"Pass {pass_num}: Merging {len(current_files)} files into chunks")
        next_pass_files = []
        
        # Split current files into chunks and merge each
        for chunk_idx in range(0, len(current_files), max_files_per_chunk):
            chunk = current_files[chunk_idx:chunk_idx + max_files_per_chunk]
            chunk_num = (chunk_idx // max_files_per_chunk) + 1
            
            # Build output filename for this chunk's merge
            output_file = os.path.join(
                os.path.dirname(final_save),
                f"intermediate_pass{pass_num}_chunk{chunk_num}.cdx.json"
            )
            
            logger.info(
                f"Pass {pass_num}, Chunk {chunk_num}: Merging {len(chunk)} file(s) to {output_file}"
            )
            
            # Build uswid command
            cmd = ['uswid']
            
            # Load parent YAML only in the first chunk of the first pass
            if parent_yaml and not parent_yaml_loaded and pass_num == 1 and chunk_idx == 0:
                cmd.extend(['--load', parent_yaml])
                parent_yaml_loaded = True
                logger.debug(f"Loading parent YAML in first chunk: {parent_yaml}")
            
            # Add all files in this chunk
            for cdx_file in chunk:
                cmd.extend(['--load', cdx_file])
            
            # Add --fixup and --fallback-path to EVERY merge operation
            cmd.append('--fixup')
            if fallback_path:
                cmd.extend(['--fallback-path', fallback_path])
                logger.debug(f"Using fallback-path: {fallback_path}")
            
            # Save to output file
            cmd.extend(['--save', output_file])
            
            # Run merge command
            result = run_cmd(cmd)
            if result != 0:
                logger.error(f"Pass {pass_num}, Chunk {chunk_num} merge failed (exit code: {result})")
                return result
            
            # Sanitize intermediate file after merge to ensure it's valid for next pass
            logger.debug(f"Sanitizing intermediate file after merge: {output_file}")
            if not sanitize_cdx_file(output_file):
                logger.warning(f"Could not sanitize intermediate file {output_file}, continuing anyway")
            
            # Track this intermediate file
            next_pass_files.append(output_file)
            intermediate_files.append(output_file)
        
        # Move to next pass with intermediate files as input
        current_files = next_pass_files
        pass_num += 1
    
    # At this point, current_files should have exactly one file
    final_intermediate = current_files[0]
    logger.info(f"All merges complete. Final intermediate file: {final_intermediate}")
    
    # Move final file to desired location if different
    if final_intermediate != final_save:
        logger.info(f"Moving final file from {final_intermediate} to {final_save}")
        try:
            shutil.move(final_intermediate, final_save)
            logger.info(f"Final CDX file successfully saved to: {final_save}")
        except Exception as e:
            logger.error(f"Failed to move final file to {final_save}: {e}", exc_info=True)
            return 1
        
        # Remove final_intermediate from cleanup list since we moved it
        if final_intermediate in intermediate_files:
            intermediate_files.remove(final_intermediate)
    else:
        logger.info(f"Final file already at desired location: {final_save}")
    
    # Clean up all intermediate files
    if intermediate_files:
        logger.info(f"Cleaning up {len(intermediate_files)} intermediate file(s)")
        for f in intermediate_files:
            if os.path.exists(f):
                try:
                    os.remove(f)
                    logger.debug(f"Deleted intermediate file: {f}")
                except Exception as e:
                    logger.warning(f"Failed to delete intermediate file {f}: {e}")
    
    logger.info("CDX hierarchical merge completed successfully")
    return 0


def generate_cves(output_cdx_name, max_workers=6):
    """
    Generate CVE Excel sheet using multi-threaded API calls with reduced concurrency.

    Args:
        output_cdx_name: Path to the CDX JSON file
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
            nvd_details, invalid_pattern = process_component(sa, idx, len(sbom_components))

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


def run_cmd(cmd):
    logger.info(f"Running command: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)

        if proc.stdout:
            stdout_clean = proc.stdout.strip()
            logger.info(f"Command stdout: {stdout_clean}")
            print(f"STDOUT: {stdout_clean}")

        if proc.stderr:
            stderr_clean = proc.stderr.strip()
            logger.error(f"Command stderr: {stderr_clean}")
            print(f"STDERR: {stderr_clean}")

        if proc.returncode == 0:
            logging.info(f"Command output {proc.stdout}")
            logger.info(f"Command executed successfully")
        else:
            logging.warning(f"Command failed with output: {proc.stdout}")
            logging.warning(f"Command failed with error: {proc.stderr}")
            logger.warning(f"Command failed with return code: {proc.returncode}")
        return proc.returncode
    except Exception as e:
        logger.error(f"Failed to run command: {e}", exc_info=True)
        print(f"Exception: {e}")
        return 1


def find_inf_files(root):
    logger.debug(f"Searching for .inf files in: {root}")
    inf_files = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith('.inf'):
                inf_path = os.path.join(dirpath, fn)
                inf_files.append(inf_path)
                logger.debug(f"Found .inf file: {inf_path}")
    logger.info(f"Found {len(inf_files)} .inf files in total")
    return inf_files


def process_inf_file(inf, output_folder):
    """Process a single .inf file and return success status and failure details"""
    logger.info(f"Processing .inf file: {inf}")

    # Verify file exists before processing
    if not os.path.exists(inf):
        logger.error(f"File does not exist: {inf}")
        print(f"ERROR: File does not exist: {inf}")
        return False, None

    # Check if file is readable
    try:
        with open(inf, 'r', encoding='utf-8') as f:
            # Try to read first few lines to verify it's a valid file
            first_line = f.readline()
        logger.info(f"File is readable. First line: {first_line.strip()}")
    except Exception as e:
        logger.error(f"Cannot read file {inf}: {e}")
        print(f"ERROR: Cannot read file {inf}: {e}")
        return False, None

    # Print file info for debugging
    file_stat = os.stat(inf)
    logger.info(f"File size: {file_stat.st_size} bytes")
    logger.info(f"File path (absolute): {os.path.abspath(inf)}")
    print(f"DEBUG: Processing file: {os.path.abspath(inf)}")
    print(f"DEBUG: File size: {file_stat.st_size} bytes")

    base = os.path.splitext(os.path.basename(inf))[0]
    out = os.path.join(output_folder, f"{base}.cdx.json")
    
    # Build uswid command with --fixup and optional --fallback-path
    cmd = ['uswid', '--load', inf, '--fixup']
    
    # Add --fallback-path if uswid-data is provided
    if args.uswid_data:
        cmd.extend(['--fallback-path', args.uswid_data])
    
    cmd.extend(['--save', out])
    
    code = run_cmd(cmd)

    if code:
        logger.error(f'Command failed for {inf} (exit code: {code})')
        return False, None
    logger.info(f"Successfully generated CDX JSON: {out}")
    return True, None


def main():
    logger.info("=" * 80)
    logger.info("Starting EDK2 JSON Generator")
    logger.info("=" * 80)

    location = os.path.abspath(args.location)
    logger.info(f"Location to scan: {location}")
    logger.info(f"Output JSON name: {args.jsonname}")
    if args.uswid_data:
        logger.info(f"uswid-data path: {args.uswid_data}")
    if args.parent_yaml:
        logger.info(f"Parent YAML: {args.parent_yaml}")
    logger.info(f"Max workers for INF processing: {args.max_workers}")

    # Create output folder for CDX JSON files
    cdx_output_folder = os.path.join(os.getcwd(), 'cdx_json_output')
    if not os.path.exists(cdx_output_folder):
        os.makedirs(cdx_output_folder)
        logger.info(f"Created output folder: {cdx_output_folder}")
    else:
        logger.info(f"Using existing output folder: {cdx_output_folder}")

    uswid_presence_cmd = ['uswid', '--version']
    if run_cmd(uswid_presence_cmd) != 0:
        logger.error('`uswid` not found in PATH.')
        logger.error('Run cmd: pip install git+https://github.com/hughsie/python-uswid.git')
        sys.exit(1)

    # 1) For each .inf file: process with --fixup and optional --fallback-path
    any_failed = False
    failed_files = []  # Track failed files with their locations and error messages
    inf_files = find_inf_files(location)

    if not inf_files:
        logger.warning("No .inf files found in the specified location")
    else:
        logger.info(f"Processing {len(inf_files)} .inf files with {args.max_workers} concurrent workers...")

        # # Process files concurrently using ThreadPoolExecutor
        # with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        #     futures = {executor.submit(process_inf_file, inf, cdx_output_folder): inf for inf in inf_files}
        #     completed = 0
        #     for future in as_completed(futures):
        #         completed += 1
        #         result, error_msg = future.result()
        #         if not result:
        #             failed_files.append({'file': futures[future], 'error': error_msg})
        #             logger.warning('Failed to process .inf file: {}'.format(futures[future]))
        #         if completed % 5 == 0:
        #             logger.info(f"Progress: [{completed}/{len(inf_files)}] .inf files processed")

        # # Process files sequentially
        # for idx, inf in enumerate(inf_files):
        #     completed = 0
        #     logger.info('--------------------------------------------------------------------------------')
        #     if inf =='E:\edk2_old_tag\edk2-stable-202408\CryptoPkg\Library\OpensslLib\OpensslLibAccel.inf':
        #         print('debug')
        #     logging.info('Proceessing file {}/{}: {}'.format(idx + 1, len(inf_files), inf))
        #     result, error_msg = process_inf_file(inf, cdx_output_folder)
        #     if not result:
        #         failed_files.append({'file': inf, 'error': error_msg})
        #         logger.warning('Failed to process .inf file: {}'.format(inf))
        #     completed += 1
        #     if completed % 5 == 0:
        #         logger.info(f"Progress: [{completed}/{len(inf_files)}] .inf files processed")
        #     logger.info('--------------------------------------------------------------------------------\n')
        # logger.info(f"Completed processing all {len(inf_files)} .inf files")
        # logger.info(f'Failed files count: {len(failed_files)}')
        # if failed_files:
        #     logger.error("Failed to process the following .inf files:")
        #     logger.info('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
        #     for failed in failed_files:
        #         logger.error(f"File: {failed['file']}")
        #     logger.info('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')

        if inf_files:
            logger.info(f"Processing {len(inf_files)} .inf files with 5 concurrent workers...")
            
            completed = [0]  # Use list to track count in thread-safe manner
            lock = threading.Lock()
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(process_inf_file, inf, cdx_output_folder): inf for inf in inf_files}
                
                for future in as_completed(futures):
                    inf = futures[future]
                    try:
                        result, error_msg = future.result()
                        if not result:
                            failed_files.append({'file': inf, 'error': error_msg})
                            logger.warning(f'Failed to process .inf file: {inf}')
                    except Exception as e:
                        logger.error(f'Exception processing {inf}: {e}', exc_info=True)
                        failed_files.append({'file': inf, 'error': str(e)})
                    
                    # Thread-safe progress tracking
                    with lock:
                        completed[0] += 1
                        if completed[0] % 5 == 0:
                            logger.info(f"Progress: [{completed[0]}/{len(inf_files)}] .inf files processed")
            
            logger.info(f"Completed processing all {len(inf_files)} .inf files")
            logger.info(f'Failed files count: {len(failed_files)}')
            if failed_files:
                logger.error("Failed to process the following .inf files:")
                logger.info('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++')
                for failed in failed_files:
                    logger.error(f"File: {failed['file']}")
                logger.info('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')

    # 2) Merge CDX files with optional parent YAML and fallback path
    output_cdx_name = f"{args.jsonname}.cdx.json"
    final_save = os.path.join(cdx_output_folder, output_cdx_name)
    logger.info(f"Generating combined CDX JSON: {final_save}")
    
    # List all generated CDX files
    cdx_files = list_cdx_files(cdx_output_folder)
    
    if not cdx_files:
        logger.error("No CDX files found to merge")
        any_failed = True
    else:
        # Merge CDX files with explicit --load entries
        final_code = merge_cdx_files(cdx_files, final_save, 
                                     parent_yaml=args.parent_yaml, 
                                     fallback_path=args.uswid_data)
        if final_code != 0:
            logger.error(f'Final CDX merge failed (exit code: {final_code})')
            any_failed = True
        else:
            logger.info(f"Final CDX JSON successfully generated at: {final_save}")

    if any_failed:
        logger.error("Script completed with errors")
        logger.info("=" * 80)
        sys.exit(2)

    logger.info('All .inf files processed successfully.')

    # 3) Generate CVEs from the CDX JSON with reduced worker count
    logger.info("Starting CVE generation from CDX JSON...")
    generate_cves(final_save, max_workers=6)
    logger.info("=" * 80)
    logger.info("Script completed successfully")
    logger.info("=" * 80)


if __name__ == '__main__':
    main()
