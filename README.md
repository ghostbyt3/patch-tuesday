# Microsoft Patch Tuesday Analyzer

A Python script to fetch, analyze, and report on Microsoft Security Updates (Patch Tuesday releases) from the MSRC API.

> For a better viewing experience, visit: [https://patch-tuesday.pwnfuzz.com/](https://patch-tuesday.pwnfuzz.com/)  

## Features

- Fetch Microsoft Security Update data from the MSRC API
- Filter vulnerabilities by product category or specific product
- Display detailed vulnerability information
- Generate comprehensive statistics and summaries
- Save processed data to compact JSON files
- Load and analyze previously saved data
- Identify exploited and high-risk vulnerabilities

## Usage

Basic Usage
```bash
python patch_review.py YYYY-mmm
```

Example:
```bash
python patch_review.py 2025-Mar
```

Command Line Options
```text
positional arguments:
  security_update       Date string for the report query in format YYYY-mmm OR path to JSON file

options:
  -h, --help            show this help message and exit
  --full                Print full list of CVEs with details
  --filter-category FILTER_CATEGORY
                        Filter by product category (e.g., "Azure", "Windows", "Office")
  --filter-product FILTER_PRODUCT
                        Filter by specific product name (e.g., "Azure CLI", "Windows 11")
  --list-products       List all available products and categories
  --detailed            Show detailed information for each vulnerability
  --save-json SAVE_JSON
                        Save processed data to JSON file (specify filename or use auto-generated)
  --from-json FROM_JSON
                        Load data from existing JSON file instead of API
  --stats               Show statistics summary
  --summary             Show vulnerability summary

```

### Examples

Show summary of March 2025 updates:
```bash
python3 patch_review.py 2023-Nov --summary
```

Save data to JSON file:
```bash
python3 patch_review.py 2023-Nov --save-json msrc_nov2023.json
```

Load from JSON and show statistics:
```bash
python3 patch_review.py msrc_nov2023.json --stats
```

Filter for Windows vulnerabilities:
```bash
python3 patch_review.py 2023-Nov --filter-category Windows
```

### Sample Output

Summary View
```text
$ python3 patch_review.py 2025-Mar --summary

[+] Processing March 2025 Security Updates
[+] Total vulnerabilities: 538
[+] Total products: 87

[+] Found a total of 538 vulnerabilities
  [-] 29 Elevation of Privilege Vulnerabilities
  [-] 3 Security Feature Bypass Vulnerabilities
  [-] 24 Remote Code Execution Vulnerabilities
  [-] 4 Information Disclosure Vulnerabilities
  [-] 1 Denial of Service Vulnerabilities
  [-] 3 Spoofing Vulnerabilities
  [-] 18 Edge - Chromium Vulnerabilities
[+] Found 6 exploited in the wild
  [-] CVE-2025-24983 - 7.0 - Windows Win32 Kernel Subsystem Elevation of Privilege Vulnerability
  [-] CVE-2025-24984 - 4.6 - Windows NTFS Information Disclosure Vulnerability
  [-] CVE-2025-24985 - 7.8 - Windows Fast FAT File System Driver Remote Code Execution Vulnerability
  [-] CVE-2025-24991 - 5.5 - Windows NTFS Information Disclosure Vulnerability
  [-] CVE-2025-24993 - 7.8 - Windows NTFS Remote Code Execution Vulnerability
  [-] CVE-2025-26633 - 7.0 - Microsoft Management Console Security Feature Bypass Vulnerability
[+] Highest Rated Vulnerabilities (CVSS >= 8.0)
  [-] CVE-2025-24035 - 8.1 - Windows Remote Desktop Services Remote Code Execution Vulnerability
  [-] CVE-2025-29807 - 8.7 - Microsoft Dataverse Remote Code Execution Vulnerability
  [-] CVE-2025-29814 - 9.3 - Microsoft Partner Center Elevation of Privilege Vulnerability
  [-] CVE-2025-26683 - 8.1 - Azure Playwright Elevation of Privilege Vulnerability
  [-] CVE-2025-21384 - 8.3 - Azure Health Bot Elevation of Privilege Vulnerability
  [-] CVE-2025-24045 - 8.1 - Windows Remote Desktop Services Remote Code Execution Vulnerability
  [-] CVE-2025-24051 - 8.8 - Windows Routing and Remote Access Service (RRAS) Remote Code Execution Vulnerability
  [-] CVE-2025-24056 - 8.8 - Windows Telephony Service Remote Code Execution Vulnerability
  [-] CVE-2025-24064 - 8.1 - Windows  Domain Name Service Remote Code Execution Vulnerability
  [-] CVE-2025-24049 - 8.4 - Azure Command Line Integration (CLI) Elevation of Privilege Vulnerability
  [-] CVE-2025-26645 - 8.8 - Remote Desktop Client Remote Code Execution Vulnerability
  [-] CVE-2024-52338 - 9.8 - None
  [-] CVE-2024-33599 - 8.1 - None
  [-] CVE-2024-3727 - 8.3 - None
  [-] CVE-2017-17522 - 8.8 - None
  [-] CVE-2007-4559 - 9.8 - None
  [-] CVE-2024-45337 - 9.1 - None
  [-] CVE-2024-36623 - 8.1 - None
  [-] CVE-2025-0665 - 9.8 - None
  [-] CVE-2024-45492 - 9.8 - None
  [-] CVE-2016-9840 - 8.8 - None
  [-] CVE-2016-9841 - 9.8 - None
  [-] CVE-2016-9842 - 8.8 - None
  [-] CVE-2016-9843 - 9.8 - None
  [-] CVE-2023-25564 - 8.2 - None
  [-] CVE-2025-23359 - 8.3 - None
  [-] CVE-2024-45491 - 9.8 - None
  [-] CVE-2023-44398 - 8.8 - None
  [-] CVE-2017-12652 - 9.8 - None
  [-] CVE-2018-7263 - 9.8 - None
  [-] CVE-2023-39976 - 9.8 - None
  [-] CVE-2022-26592 - 8.8 - None
  [-] CVE-2022-37434 - 9.8 - None
  [-] CVE-2024-34402 - 8.6 - None
  [-] CVE-2025-27363 - 8.1 - None
  [-] CVE-2024-53427 - 8.1 - None
  [-] CVE-2025-24084 - 8.4 - Windows Subsystem for Linux (WSL2) Kernel Remote Code Execution Vulnerability
[+] Found 11 vulnerabilities more likely to be exploited
  [-] CVE-2025-24035 - https://www.cve.org/CVERecord?id=CVE-2025-24035
  [-] CVE-2024-9157 - https://www.cve.org/CVERecord?id=CVE-2024-9157
  [-] CVE-2025-24044 - https://www.cve.org/CVERecord?id=CVE-2025-24044
  [-] CVE-2025-21180 - https://www.cve.org/CVERecord?id=CVE-2025-21180
  [-] CVE-2025-24995 - https://www.cve.org/CVERecord?id=CVE-2025-24995
  [-] CVE-2025-21247 - https://www.cve.org/CVERecord?id=CVE-2025-21247
  [-] CVE-2025-24045 - https://www.cve.org/CVERecord?id=CVE-2025-24045
  [-] CVE-2025-24061 - https://www.cve.org/CVERecord?id=CVE-2025-24061
  [-] CVE-2025-24066 - https://www.cve.org/CVERecord?id=CVE-2025-24066
  [-] CVE-2025-24067 - https://www.cve.org/CVERecord?id=CVE-2025-24067
  [-] CVE-2025-24992 - https://www.cve.org/CVERecord?id=CVE-2025-24992

```

## Acknowledgements
- Shoutout to [msrc-api](https://github.com/Immersive-Labs-Sec/msrc-api) by [Immersive-Labs-Sec](https://github.com/Immersive-Labs-Sec) for their work.