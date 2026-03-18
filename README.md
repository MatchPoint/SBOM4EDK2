# SBOM4EDK2
Tool to generate an SBOM from TIanocore EDKII source code. CVE list are also be generated against the SBOM.

First:
1. Request NVD API key here: https://nvd.nist.gov/developers/request-an-api-key 
2. Install Python 3.14.2 or later
3. python -m venv venv
4. venv\Scripts\activate
5. pip install -r requirements.txt
 
By running the below commands, the script will automatically clone/update edk2 repo and run the script
   python main.py -o <o/p filename viz cdx json> -k <nvd_api_key> -r <edk2 repository>
   Example: python main.py -o "edk2" -k "ABC-1234-qwer-5678" -r "https://github.com/tianocore/edk2.git"

Outputs:
- CVE_List.xlsx
- edk2_json_generator.log

Note:
- If the API key is invalid, the CDX JSONs are still generated, but NVD responses may fail.
