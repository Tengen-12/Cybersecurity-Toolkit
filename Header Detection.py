import re
import requests
from datetime import datetime
from urllib.parse import urlparse
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize colorama
init(autoreset=True)

SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS and code injection attacks",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME type sniffing",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser features access",
    "Cross-Origin-Embedder-Policy": "Controls cross-origin embedding",
    "Cross-Origin-Resource-Policy": "Restricts cross-origin access",
    "Cross-Origin-Opener-Policy": "Isolates browsing contexts"
}

def print_banner():
    """Display a styled banner"""
    print(f"""
{Fore.BLUE}╔════════════════════════════════════════════╗
║{Fore.YELLOW}       SECURITY HEADER CHECKER v2.0         {Fore.BLUE}║
║{Fore.WHITE}         Missing Header Reporter            {Fore.BLUE}║
╚════════════════════════════════════════════╝""")

def validate_url(url):
    """Ensure URL has valid format and scheme"""
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"https://{url}"
    return url

def get_headers(url):
    """Fetch headers from website"""
    try:
        response = requests.get(
            url,
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=10,
            allow_redirects=True
        )
        return response.headers, response.url
    except Exception as e:
        raise RuntimeError(f"Connection failed: {str(e)}")

def analyze_headers(headers):
    """Check for missing security headers"""
    missing = []
    present_headers = {k.lower(): v for k, v in headers.items()}
    
    for header, description in SECURITY_HEADERS.items():
        if header.lower() not in present_headers:
            missing.append({
                "Header": header,
                "Description": description,
                "Severity": "High" if "Policy" in header else "Medium"
            })
    
    return missing

def generate_report(missing_headers, url):
    """Generate formatted report of missing headers"""
    if not missing_headers:
        return f"{Fore.GREEN}\n[+] All security headers are present!"
    
    table = []
    for idx, header in enumerate(missing_headers, 1):
        table.append([
            idx,
            header["Header"],
            header["Severity"],
            header["Description"]
        ])

    report = f"""
{Fore.CYAN}=== Missing Security Headers Report ===
{Fore.WHITE}Target URL: {url}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{tabulate(table, headers=['#', 'Missing Header', 'Severity', 'Description'], tablefmt='fancy_grid')}

{Fore.YELLOW}Recommendations:
- High severity: Should be implemented immediately
- Medium severity: Recommended for security best practices
"""
    return report

def clean_ansi_codes(text):
    """Remove ANSI escape codes from text"""
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def save_report(report, filename):
    """Save cleaned report to file with UTF-8 encoding"""
    try:
        clean_report = clean_ansi_codes(report)
        with open(filename, 'w', encoding='utf-8') as f:  # Add encoding here
            f.write(clean_report)
        print(f"{Fore.GREEN}\n[+] Report saved successfully as {filename} (UTF-8 encoded)")
    except Exception as e:
        print(f"{Fore.RED}\n[!] Error saving file: {str(e)}")

def main():
    """Main interactive program flow"""
    print_banner()
    
    while True:
        try:
            url = input(f"\n{Fore.WHITE}Enter website URL (or 'q' to quit): {Fore.YELLOW}").strip()
            
            if url.lower() in ('q', 'quit', 'exit'):
                print(f"{Fore.GREEN}Exiting...")
                break
                
            if not url:
                print(f"{Fore.RED}Please enter a valid URL")
                continue
                
            validated_url = validate_url(url)
            print(f"{Fore.BLUE}\n[*] Scanning {validated_url}...")
            
            headers, final_url = get_headers(validated_url)
            missing_headers = analyze_headers(headers)
            
            report = generate_report(missing_headers, final_url)
            print(report)
            
            # Save prompt
            save_choice = input(f"\n{Fore.CYAN}Would you like to save this report? (y/N): {Fore.YELLOW}").strip().lower()
            if save_choice == 'y':
                filename = input(f"{Fore.CYAN}Enter filename (default: security_report.txt): {Fore.YELLOW}").strip()
                filename = filename or "security_report.txt"
                save_report(report, filename)
            
        except Exception as e:
            print(f"{Fore.RED}\n[!] Error: {str(e)}")
            continue

if __name__ == "__main__":
    main()
