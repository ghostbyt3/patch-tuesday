import argparse
import requests
import re
import json
import os
from datetime import datetime
from bs4 import BeautifulSoup

base_url = 'https://api.msrc.microsoft.com/cvrf/v2.0/'
headers = {'Accept': 'application/json'}

vuln_types = [
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',
    'Spoofing',
    'Edge - Chromium'
]

def check_data_format(date_string):
    date_pattern = '\\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
    return re.match(date_pattern, date_string, re.IGNORECASE)

def extract_product_tree(release_json):
    """Extract product information from ProductTree"""
    product_map = {}
    product_tree = release_json.get('ProductTree', {})
    
    def traverse_branch(branch, parent_name=""):
        for item in branch:
            name = item.get('Name', '')
            items = item.get('Items', [])
            
            if items:
                for product in items:
                    product_id = product.get('ProductID')
                    product_name = product.get('Value', '')
                    if product_id:
                        product_map[product_id] = {
                            'name': product_name,
                            'category': name,
                            'full_path': f"{name}/{product_name}" if name else product_name
                        }
                
                traverse_branch(items, name)
    
    branches = product_tree.get('Branch', [])
    traverse_branch(branches)
    
    return product_map

def filter_vulnerabilities_by_product(all_vulns, product_map, filter_category=None, filter_product=None):
    """Filter vulnerabilities based on product category or specific product name"""
    filtered_vulns = []
    
    for vuln in all_vulns:
        vuln_affects_target = False
        affected_products = []
        
        for threat in vuln.get('Threats', []):
            product_ids = threat.get('ProductID', [])
            for product_id in product_ids:
                if product_id in product_map:
                    product_info = product_map[product_id]
                    
                    matches_filter = False
                    if filter_category and filter_category.lower() in product_info['category'].lower():
                        matches_filter = True
                    elif filter_product and filter_product.lower() in product_info['name'].lower():
                        matches_filter = True
                    elif not filter_category and not filter_product:
                        matches_filter = True
                    
                    if matches_filter:
                        vuln_affects_target = True
                        affected_products.append(product_info)
        
        if vuln_affects_target:
            vuln['affected_products'] = affected_products
            filtered_vulns.append(vuln)
    
    return filtered_vulns

def get_vulnerability_details(vuln):
    """Extract key details from a vulnerability"""
    cve = vuln.get("CVE", "N/A")
    title = vuln.get("Title", {}).get("Value", "N/A")
    
    # Get CVSS score
    score = "-"
    cvss = vuln.get("CVSSScoreSets", [])
    if cvss:
        score = str(cvss[0].get("BaseScore", "-"))
    
    # Check exploitation status
    exploited = "No"
    likely = "No"
    for threat in vuln.get("Threats", []):
        if threat.get("Type") == 1:
            desc = threat.get("Description", {}).get("Value", "").lower()
            if "exploited:yes" in desc or "exploitation detected" in desc:
                exploited = "Yes"
            if "exploitation more likely" in desc:
                likely = "Yes"
    
    # Get threat types
    threat_types = []
    for threat in vuln.get("Threats", []):
        if threat.get("Type") == 0:
            threat_desc = threat.get("Description", {}).get("Value", "")
            if threat_desc and threat_desc not in threat_types:
                threat_types.append(threat_desc)
    
    # Get primary product category
    primary_category = "N/A"
    if vuln.get('affected_products', []):
        primary_category = vuln['affected_products'][0]['category']
    
    return {
        'cve': cve,
        'title': title,
        'score': score,
        'exploited': exploited,
        'likely': likely,
        'threat_types': threat_types,
        'affected_products': vuln.get('affected_products', []),
        'primary_category': primary_category
    }

def print_filtered_results(filtered_vulns, filter_description):
    """Print filtered vulnerability results"""
    if not filtered_vulns:
        print(f"\n[+] No vulnerabilities found for {filter_description}")
        return
    
    print(f"\n[+] {filter_description} Vulnerabilities ({len(filtered_vulns)} total):")
    print("    CVE ID               | CVSS | Exploited | Exploit Likely | Category           | Threat Type | Affected Products")
    print("    ---------------------|------|-----------|----------------|--------------------|-------------|------------------")
    
    for vuln in filtered_vulns:
        details = get_vulnerability_details(vuln)
        
        threat_type = details['threat_types'][0] if details['threat_types'] else "N/A"
        if len(threat_type) > 20:
            threat_type = threat_type[:17] + "..."
        
        product_names = [p['name'] for p in details['affected_products']]
        products_str = ", ".join(product_names)
        if len(products_str) > 30:
            products_str = products_str[:27] + "..."
        
        print(f"    {details['cve']:<21} | {details['score']:<4} | {details['exploited']:^9} | {details['likely']:^14} | {details['primary_category'][:18]:<18} | {threat_type:<11} | {products_str}")

def print_detailed_vulnerability(vuln):
    """Print detailed information about a single vulnerability"""
    details = get_vulnerability_details(vuln)
    
    print(f"\n--- {details['cve']} ---")
    print(f"Title: {details['title']}")
    print(f"CVSS Score: {details['score']}")
    print(f"Exploited: {details['exploited']}")
    print(f"Exploitation Likely: {details['likely']}")
    
    if details['threat_types']:
        print(f"Threat Types: {', '.join(details['threat_types'])}")
    
    print("Affected Products:")
    for product in details['affected_products']:
        print(f"  - {product['full_path']}")

def save_to_json(release_json, all_vulns, product_map, output_file=None):
    """Save processed vulnerability data to JSON file"""
    if not output_file:
        title = release_json.get('DocumentTitle', {}).get('Value', 'Unknown Release')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"msrc_data_{timestamp}.json"
    
    # Process vulnerabilities with minimal data
    processed_vulns = []
    for vuln in all_vulns:
        processed_vuln = {
            'cve': vuln.get("CVE", "N/A"),
            'title': vuln.get("Title", {}).get("Value", "N/A"),
            'cvss_score': None,
            'exploited': False,
            'exploitation_likely': False,
            'threat_types': [],
            'affected_products': []
        }
        
        # Get CVSS score
        cvss = vuln.get("CVSSScoreSets", [])
        if cvss:
            processed_vuln['cvss_score'] = cvss[0].get("BaseScore")
        
        # Process threats
        for threat in vuln.get("Threats", []):
            if threat.get("Type") == 1:
                desc = threat.get("Description", {}).get("Value", "").lower()
                if "exploited:yes" in desc or "exploitation detected" in desc:
                    processed_vuln['exploited'] = True
                if "exploitation more likely" in desc:
                    processed_vuln['exploitation_likely'] = True
            
            elif threat.get("Type") == 0:
                threat_desc = threat.get("Description", {}).get("Value", "")
                if threat_desc and threat_desc not in processed_vuln['threat_types']:
                    processed_vuln['threat_types'].append(threat_desc)
            
            # Map affected products (only IDs to save space)
            product_ids = threat.get('ProductID', [])
            for product_id in product_ids:
                if product_id in product_map:
                    product_info = {
                        'id': product_id,
                        'name': product_map[product_id]['name'],
                        'category': product_map[product_id]['category']
                    }
                    if product_info not in processed_vuln['affected_products']:
                        processed_vuln['affected_products'].append(product_info)
        
        processed_vulns.append(processed_vuln)
    
    # Create the final JSON structure
    json_data = {
        'metadata': {
            'title': release_json.get('DocumentTitle', {}).get('Value', 'Unknown Release'),
            'tracking_id': release_json.get('DocumentTracking', {}).get('Identification', {}).get('ID', 'N/A'),
            'release_date': release_json.get('DocumentTracking', {}).get('InitialReleaseDate', 'N/A'),
            'current_release_date': release_json.get('DocumentTracking', {}).get('CurrentReleaseDate', 'N/A'),
            'total_vulnerabilities': len(all_vulns),
            'processed_date': datetime.now().isoformat(),
            'script_version': '2.1'
        },
        'products': {pid: {'name': info['name'], 'category': info['category']} for pid, info in product_map.items()},
        'vulnerabilities': processed_vulns
    }
    
    # Save to file with compact encoding
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=None, separators=(',', ':'), ensure_ascii=False)
    
    print(f"[+] Data saved to {output_file} (size: {os.path.getsize(output_file)/1024:.1f} KB)")
    return output_file

def load_from_json(json_file):
    """Load vulnerability data from JSON file"""
    if not os.path.exists(json_file):
        print(f"[!] JSON file not found: {json_file}")
        return None, None, None
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        metadata = json_data.get('metadata', {})
        product_map = json_data.get('products', {})
        vulnerabilities = json_data.get('vulnerabilities', [])
        
        print(f"[+] Loaded {metadata.get('title', 'Unknown Release')}")
        print(f"[+] Total vulnerabilities: {len(vulnerabilities)}")
        print(f"[+] Total products: {len(product_map)}")
        
        return metadata, product_map, vulnerabilities
    
    except json.JSONDecodeError as e:
        print(f"[!] Error parsing JSON file: {e}")
        return None, None, None
    except Exception as e:
        print(f"[!] Error loading JSON file: {e}")
        return None, None, None

def filter_json_vulnerabilities(vulnerabilities, product_map, filter_category=None, filter_product=None):
    """Filter vulnerabilities from JSON data based on product category or name"""
    filtered_vulns = []
    
    for vuln in vulnerabilities:
        # Check if this vulnerability affects any of the filtered products
        vuln_affects_target = False
        
        for product_info in vuln.get('affected_products', []):
            # Check if this product matches our filter criteria
            matches_filter = False
            if filter_category and filter_category.lower() in product_info.get('category', '').lower():
                matches_filter = True
            elif filter_product and filter_product.lower() in product_info.get('name', '').lower():
                matches_filter = True
            elif not filter_category and not filter_product:
                matches_filter = True
            
            if matches_filter:
                vuln_affects_target = True
                break
        
        if vuln_affects_target:
            filtered_vulns.append(vuln)
    
    return filtered_vulns

def print_json_results(vulnerabilities, filter_description="All"):
    """Print vulnerability results from JSON data"""
    if not vulnerabilities:
        print(f"\n[+] No vulnerabilities found for {filter_description}")
        return
    
    print(f"\n[+] {filter_description} Vulnerabilities ({len(vulnerabilities)} total):")
    print("    CVE ID               | CVSS | Exploited | Exploit Likely | Threat Type | Affected Products")
    print("    ---------------------|------|-----------|----------------|-------------|------------------")
    
    for vuln in vulnerabilities:
        cve = vuln.get('cve', 'N/A')
        score = str(vuln.get('cvss_score', '-')) if vuln.get('cvss_score') else '-'
        exploited = "Yes" if vuln.get('exploited', False) else "No"
        likely = "Yes" if vuln.get('exploitation_likely', False) else "No"
        
        # Get first threat type for display
        threat_types = vuln.get('threat_types', [])
        threat_type = threat_types[0] if threat_types else "N/A"
        if len(threat_type) > 20:
            threat_type = threat_type[:17] + "..."
        
        # Get affected product names
        affected_products = vuln.get('affected_products', [])
        product_names = [p.get('name', 'N/A') for p in affected_products]
        products_str = ", ".join(product_names)
        if len(products_str) > 30:
            products_str = products_str[:27] + "..."
        
        print(f"    {cve:<21} | {score:<4} | {exploited:^9} | {likely:^14} | {threat_type:<11} | {products_str}")

def print_detailed_json_vulnerability(vuln):
    """Print detailed information about a single vulnerability from JSON data"""
    print(f"\n--- {vuln.get('cve', 'N/A')} ---")
    print(f"Title: {vuln.get('title', 'N/A')}")
    print(f"CVSS Score: {vuln.get('cvss_score', 'N/A')}")
    print(f"Exploited: {'Yes' if vuln.get('exploited', False) else 'No'}")
    print(f"Exploitation Likely: {'Yes' if vuln.get('exploitation_likely', False) else 'No'}")
    
    threat_types = vuln.get('threat_types', [])
    if threat_types:
        print(f"Threat Types: {', '.join(threat_types)}")
    
    print("Affected Products:")
    for product in vuln.get('affected_products', []):
        print(f"  - {product.get('full_path', product.get('name', 'N/A'))}")

def print_statistics(vulnerabilities, filter_description="All"):
    """Print statistics for vulnerability set"""
    if not vulnerabilities:
        return
    
    total = len(vulnerabilities)
    exploited = len([v for v in vulnerabilities if v.get('exploited', False)])
    likely = len([v for v in vulnerabilities if v.get('exploitation_likely', False)])
    
    # CVSS statistics
    cvss_scores = [v.get('cvss_score') for v in vulnerabilities if v.get('cvss_score')]
    high_severity = len([s for s in cvss_scores if s >= 7.0])
    critical_severity = len([s for s in cvss_scores if s >= 9.0])
    
    print(f"\n[+] {filter_description} Statistics:")
    print(f"    Total CVEs: {total}")
    print(f"    Exploited: {exploited}")
    print(f"    Exploitation Likely: {likely}")
    print(f"    High Severity (≥7.0): {high_severity}")
    print(f"    Critical Severity (≥9.0): {critical_severity}")
    
    if cvss_scores:
        avg_score = sum(cvss_scores) / len(cvss_scores)
        print(f"    Average CVSS Score: {avg_score:.2f}")

def list_json_products(product_map):
    """List all products from JSON data organized by category"""
    print("\n[+] Available Products:")
    categories = {}
    for product_id, product_info in product_map.items():
        category = product_info.get('category', 'Unknown')
        if category not in categories:
            categories[category] = []
        categories[category].append(product_info.get('name', 'Unknown'))
    
    for category, products in categories.items():
        print(f"\n  {category}:")
        for product in sorted(products):
            print(f"    - {product}")

def print_summary(all_vulns):
    """Print summary statistics for vulnerabilities"""
    print(f'\n[+] Found a total of {len(all_vulns)} vulnerabilities')
    
    for vuln_type in vuln_types:
        count = count_type(vuln_type, all_vulns)
        print(f'  [-] {count} {vuln_type} Vulnerabilities')
    
    exploited = count_exploited(all_vulns)
    print(f'[+] Found {exploited["counter"]} exploited in the wild')
    for cve in exploited['cves']:
        print(f'  [-] {cve}')
    
    base_score = 8.0
    print('[+] Highest Rated Vulnerabilities (CVSS >= 8.0)')
    for vuln in all_vulns:
        title = vuln.get('Title', {'Value': 'Not Found'}).get('Value')
        cve_id = vuln.get('CVE', '')
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if len(cvss_sets) > 0:
            cvss_score = cvss_sets[0].get('BaseScore', 0)
            if cvss_score >= base_score:
                print(f'  [-] {cve_id} - {cvss_score} - {title}')
    
    exploitation = exploitation_likely(all_vulns)
    print(f'[+] Found {exploitation["counter"]} vulnerabilities more likely to be exploited')
    for cve in exploitation['cves']:
        print(f'  [-] {cve.split()[0]} - https://www.cve.org/CVERecord?id={cve.split()[0]}')

def count_exploited(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        cvss_score = 0.0
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if cvss_sets:
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)

        for threat in vuln.get('Threats', []):
            if threat.get('Type') == 1:
                description = threat.get('Description', {}).get('Value', '')
                if 'Exploited:Yes' in description or 'Exploitation Detected' in description:
                    counter += 1
                    cves.append(f'{vuln["CVE"]} - {cvss_score} - {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}

def count_type(search_type, all_vulns):
    counter = 0
    for vuln in all_vulns:
        for threat in vuln.get('Threats', []):
            if threat.get('Type') == 0:
                if search_type == "Edge - Chromium":
                    if threat.get('ProductID', [])[0] == '11655':
                        counter += 1
                        break
                elif threat.get('Description', {}).get('Value') == search_type:
                    if threat.get('ProductID', [])[0] == '11655':
                        break
                    counter += 1
                    break
    return counter

def exploitation_likely(all_vulns):
    counter = 0
    cves = []
    for vuln in all_vulns:
        for threat in vuln.get('Threats', []):
            if threat.get('Type') == 1:
                description = threat.get('Description', {}).get('Value', '')
                if 'Exploitation More Likely'.lower() in description.lower():
                    counter += 1
                    cves.append(f'{vuln["CVE"]} -- {vuln["Title"]["Value"]}')
                    break
    return {'counter': counter, 'cves': cves}

def extract_republished_cves(release_json):
    html = release_json.get("DocumentNotes", [])[0].get("Value", "")
    soup = BeautifulSoup(html, "html.parser")
    republished_section = soup.find("h2", id="we-are-republishing-22-non-microsoft-cves")
    if not republished_section:
        return set()
    table = republished_section.find_next("table")
    cve_ids = set()
    for row in table.find_all("tr")[1:]:
        cols = row.find_all("td")
        if len(cols) >= 3:
            cve_link = cols[2].find("a")
            if cve_link and "CVE-" in cve_link.text:
                cve_ids.add(cve_link.text.strip())
    return cve_ids

def print_cve_list(label, vuln_list):
    print(f"\n[+] {label} CVEs ({len(vuln_list)} total):")
    print("    CVE ID               | CVSS | Exploited | Exploit Likely | Title")
    print("    ---------------------|------|-----------|----------------|------")
    for v in vuln_list:
        cve = v.get("CVE", "N/A")
        title = v.get("Title", {}).get("Value", "N/A")
        score = "-"
        cvss = v.get("CVSSScoreSets", [])
        if cvss:
            score = str(cvss[0].get("BaseScore", "-"))

        exploited = "No"
        likely = "No"
        for threat in v.get("Threats", []):
            if threat.get("Type") == 1:
                desc = threat.get("Description", {}).get("Value", "").lower()
                if "exploited:yes" in desc or "exploitation detected" in desc:
                    exploited = "Yes"
                if "exploitation more likely" in desc:
                    likely = "Yes"

        print(f"    {cve:<21} | {score:<4} | {exploited:^9} | {likely:^14} | {title}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read vulnerability stats for a Patch Tuesday release.')
    parser.add_argument('security_update', nargs='?', help="Date string for the report query in format YYYY-mmm OR path to JSON file")
    parser.add_argument('--full', action='store_true', help='Print full list of CVEs with details')
    parser.add_argument('--filter-category', help='Filter by product category (e.g., "Azure", "Windows", "Office")')
    parser.add_argument('--filter-product', help='Filter by specific product name (e.g., "Azure CLI", "Windows 11")')
    parser.add_argument('--list-products', action='store_true', help='List all available products and categories')
    parser.add_argument('--detailed', action='store_true', help='Show detailed information for each vulnerability')
    parser.add_argument('--save-json', help='Save processed data to JSON file (specify filename or use auto-generated)')
    parser.add_argument('--from-json', help='Load data from existing JSON file instead of API')
    parser.add_argument('--stats', action='store_true', help='Show statistics summary')
    parser.add_argument('--summary', action='store_true', help='Show vulnerability summary')
    args = parser.parse_args()

    # Determine if we're working with JSON file or API
    if args.from_json:
        # Load from existing JSON file
        metadata, product_map, vulnerabilities = load_from_json(args.from_json)
        if metadata is None:
            exit(1)
        
        # List products if requested
        if args.list_products:
            list_json_products(product_map)
            exit()
        
        # Apply filters if specified
        if args.filter_category or args.filter_product:
            filtered_vulns = filter_json_vulnerabilities(
                vulnerabilities, product_map, args.filter_category, args.filter_product
            )
            
            filter_desc = []
            if args.filter_category:
                filter_desc.append(f"Category: {args.filter_category}")
            if args.filter_product:
                filter_desc.append(f"Product: {args.filter_product}")
            
            filter_description = " & ".join(filter_desc)
            
            if args.detailed:
                print(f"\n[+] Detailed {filter_description} Vulnerabilities:")
                for vuln in filtered_vulns:
                    print_detailed_json_vulnerability(vuln)
            else:
                print_json_results(filtered_vulns, filter_description)
            
            if args.stats:
                print_statistics(filtered_vulns, filter_description)
        else:
            # Show all vulnerabilities
            if args.detailed:
                print("\n[+] Detailed Vulnerabilities:")
                for vuln in vulnerabilities:
                    print_detailed_json_vulnerability(vuln)
            else:
                print_json_results(vulnerabilities)
            
            if args.stats:
                print_statistics(vulnerabilities)
    
    elif args.security_update and args.security_update.endswith('.json'):
        # If the argument looks like a JSON file, load it
        metadata, product_map, vulnerabilities = load_from_json(args.security_update)
        if metadata is None:
            exit(1)
        
        # Same logic as --from-json
        if args.list_products:
            list_json_products(product_map)
            exit()
        
        if args.filter_category or args.filter_product:
            filtered_vulns = filter_json_vulnerabilities(
                vulnerabilities, product_map, args.filter_category, args.filter_product
            )
            
            filter_desc = []
            if args.filter_category:
                filter_desc.append(f"Category: {args.filter_category}")
            if args.filter_product:
                filter_desc.append(f"Product: {args.filter_product}")
            
            filter_description = " & ".join(filter_desc)
            
            if args.detailed:
                print(f"\n[+] Detailed {filter_description} Vulnerabilities:")
                for vuln in filtered_vulns:
                    print_detailed_json_vulnerability(vuln)
            else:
                print_json_results(filtered_vulns, filter_description)
            
            if args.stats:
                print_statistics(filtered_vulns, filter_description)
        else:
            if args.detailed:
                print("\n[+] Detailed Vulnerabilities:")
                for vuln in vulnerabilities:
                    print_detailed_json_vulnerability(vuln)
            else:
                print_json_results(vulnerabilities)
            
            if args.stats:
                print_statistics(vulnerabilities)
    
    else:
        # Original API-based functionality
        if not args.security_update:
            print("[!] Please provide security update date or JSON file path")
            exit(1)
        
        if not check_data_format(args.security_update):
            print("[!] Invalid date format please use 'yyyy-mmm'")
            exit()

        response = requests.get(f'{base_url}cvrf/{args.security_update}', headers=headers)
        if response.status_code != 200:
            print(f"[!] Error {response.status_code} from MSRC API — No release notes yet?")
            exit()

        release_json = response.json()
        title = release_json.get('DocumentTitle', {}).get('Value', 'Unknown Release')
        all_vulns = release_json.get('Vulnerability', [])
        
        # Extract product information
        product_map = extract_product_tree(release_json)
        
        # Save to JSON if requested
        if args.save_json:
            output_file = args.save_json if args.save_json.endswith('.json') else f"{args.save_json}.json"
            save_to_json(release_json, all_vulns, product_map, output_file)
        
        # List products if requested
        if args.list_products:
            print(f"\n[+] Available Products in {title}:")
            categories = {}
            for product_id, product_info in product_map.items():
                category = product_info['category']
                if category not in categories:
                    categories[category] = []
                categories[category].append(product_info['name'])
            
            for category, products in categories.items():
                print(f"\n  {category}:")
                for product in sorted(products):
                    print(f"    - {product}")
            
            if not args.save_json:
                exit()
        
        print(f"\n[+] Processing {title}")
        print(f"[+] Total vulnerabilities: {len(all_vulns)}")
        print(f"[+] Total products: {len(product_map)}")
        
        # Apply filters if specified
        if args.filter_category or args.filter_product:
            filtered_vulns = filter_vulnerabilities_by_product(
                all_vulns, product_map, args.filter_category, args.filter_product
            )
            
            filter_desc = []
            if args.filter_category:
                filter_desc.append(f"Category: {args.filter_category}")
            if args.filter_product:
                filter_desc.append(f"Product: {args.filter_product}")
            
            filter_description = " & ".join(filter_desc)
            
            if args.detailed:
                print(f"\n[+] Detailed {filter_description} Vulnerabilities:")
                for vuln in filtered_vulns:
                    print_detailed_vulnerability(vuln)
            else:
                print_filtered_results(filtered_vulns, filter_description)

    # After loading data (either from API or JSON), add this:
    if args.summary:
        if args.from_json or (args.security_update and args.security_update.endswith('.json')):
            # Convert JSON vulnerabilities back to API-like format for summary functions
            api_like_vulns = []
            for vuln in vulnerabilities:
                api_like_vuln = {
                    'CVE': vuln.get('cve'),
                    'Title': {'Value': vuln.get('title')},
                    'CVSSScoreSets': [{'BaseScore': vuln.get('cvss_score')}] if vuln.get('cvss_score') is not None else [],
                    'Threats': []
                }
                
                # Add threat types
                for threat_type in vuln.get('threat_types', []):
                    api_like_vuln['Threats'].append({
                        'Type': 0,
                        'Description': {'Value': threat_type},
                        'ProductID': [p['id'] for p in vuln.get('affected_products', [])]
                    })
                
                # Add exploitation status
                if vuln.get('exploited'):
                    api_like_vuln['Threats'].append({
                        'Type': 1,
                        'Description': {'Value': 'Exploited:Yes'}
                    })
                if vuln.get('exploitation_likely'):
                    api_like_vuln['Threats'].append({
                        'Type': 1,
                        'Description': {'Value': 'Exploitation More Likely'}
                    })
                
                api_like_vulns.append(api_like_vuln)
            
            print_summary(api_like_vulns)
        else:
            print_summary(all_vulns)
        exit()