import requests
import re
import json
import time
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Display a styled banner"""
    print(f"""
{Fore.CYAN}╔════════════════════════════════════════════╗
║{Fore.WHITE}          ADVANCED API DISCOVERY TOOL       {Fore.CYAN}║
║{Fore.WHITE}         Web Crawler • Network Sniffer      {Fore.CYAN}║
╚════════════════════════════════════════════╝
{Fore.YELLOW}Scan Types: [1] Quick Scan (15s) | [2] Deep Scan (45s)""")

def validate_url(url):
    """Validate and normalize URL input"""
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"{Fore.RED}Invalid URL: No domain found")
    return url

def find_html_apis(url):
    """Find API endpoints in HTML/scripts with improved patterns"""
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all potential API endpoints in page
        api_pattern = re.compile(
            r'''(["']https?://[^"'\s]+?/(?:api|v\d+|graphql|rest|json|data)[^"'\s]*)''',
            re.IGNORECASE
        )
        
        # Find in scripts, links, and meta tags
        sources = [
            *[script['src'] for script in soup.find_all('script', src=True)],
            *[link['href'] for link in soup.find_all('a', href=True)],
            *[meta['content'] for meta in soup.find_all('meta', {'content': True})]
        ]
        
        # Check all found sources
        apis = set()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for source in sources:
                if not source.startswith('http'):
                    source = urljoin(url, source)
                futures.append(executor.submit(
                    requests.get, source, timeout=5
                ))
            
            for future in as_completed(futures):
                try:
                    response = future.result()
                    apis.update(api_pattern.findall(response.text))
                except Exception:
                    continue

        return {api.strip('"\'') for api in apis if any(x in api.lower() for x in ['api', 'json', 'graphql', 'data'])}
    
    except Exception as e:
        print(f"{Fore.RED}HTML Scan Error: {str(e)}")
        return set()

def capture_network_apis(url):
    """Reliable network traffic analysis using CDP"""
    print(f"\n{Fore.BLUE}[*] Starting advanced network capture...")
    
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")
    chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

    try:
        service = Service(executable_path=ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        
        # Enable Network domain
        driver.execute_cdp_cmd('Network.enable', {})
        
        # Store captured requests
        api_requests = set()
        
        # Navigate to page
        print(f"{Fore.YELLOW}[*] Loading page and monitoring network...")
        driver.get(url)
        
        # Wait for initial load
        WebDriverWait(driver, 15).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
        
        # Simulate user interactions
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(3)
        driver.execute_script("window.scrollTo(0, 0);")
        time.sleep(2)
        
        # Capture network logs
        logs = driver.get_log('performance')
        
        # Process logs for API calls
        api_pattern = re.compile(
            r'(api|v\d+|graphql|rest|json|data|ws(s)?)',
            re.IGNORECASE
        )
        
        for log in logs:
            try:
                message = json.loads(log['message'])['message']
                if message['method'] == 'Network.requestWillBeSent':
                    url = message['params']['request']['url']
                    if api_pattern.search(url):
                        api_requests.add(url)
            except Exception:
                continue
                
        driver.quit()
        return api_requests
    
    except Exception as e:
        print(f"{Fore.RED}Network Capture Error: {str(e)}")
        return set()

def display_results(apis, source):
    """Display results in formatted tables"""
    if not apis:
        print(f"\n{Fore.YELLOW}[-] No APIs found via {source}")
        return
    
    table = [[i+1, api] for i, api in enumerate(sorted(apis))]
    print(f"\n{Fore.GREEN}[+] Discovered APIs ({source}):")
    print(tabulate(table, headers=['#', 'Endpoint'], tablefmt='fancy_grid'))

def main():
    """Main interactive program flow"""
    print_banner()
    
    try:
        url = input(f"\n{Fore.WHITE}Enter target URL {Fore.CYAN}(e.g. api.example.com){Fore.WHITE}: ")
        validated_url = validate_url(url)
        
        scan_type = input(f"{Fore.WHITE}Choose scan type {Fore.YELLOW}(1/2){Fore.WHITE}: ").strip()
        
        start_time = time.time()
        
        if scan_type == '1':
            print(f"\n{Fore.BLUE}[*] Starting Quick Scan...")
            apis = find_html_apis(validated_url)
            print(f"{Fore.GREEN}[+] Quick scan completed in {time.time()-start_time:.1f}s")
            display_results(apis, "HTML Analysis")
            
        elif scan_type == '2':
            print(f"\n{Fore.BLUE}[*] Starting Deep Scan...")
            with ThreadPoolExecutor() as executor:
                html_future = executor.submit(find_html_apis, validated_url)
                network_future = executor.submit(capture_network_apis, validated_url)
                
                html_apis = html_future.result()
                network_apis = network_future.result()
            
            print(f"{Fore.GREEN}[+] Deep scan completed in {time.time()-start_time:.1f}s")
            display_results(html_apis, "HTML Analysis")
            display_results(network_apis, "Network Analysis")
            apis = html_apis.union(network_apis)
        
        if apis:
            save = input(f"\n{Fore.CYAN}Save results? {Fore.WHITE}(y/N): ").lower()
            if save == 'y':
                filename = input(f"{Fore.CYAN}Enter filename {Fore.WHITE}(default: api_report.txt): ") or "api_report.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("\n".join(sorted(apis)))
                print(f"{Fore.GREEN}Report saved to {filename}")
        else:
            print(f"\n{Fore.YELLOW}[-] No APIs found. Try these solutions:")
            print(f"{Fore.WHITE}1. Use Deep Scan option for JavaScript-heavy sites")
            print(f"{Fore.WHITE}2. Try known API endpoints like /api/v1/users")
            print(f"{Fore.WHITE}3. Test with API-rich sites (github.com, reddit.com)")
            
        print(f"\n{Fore.BLUE}[*] Total execution time: {time.time()-start_time:.1f} seconds")
        
    except Exception as e:
        print(f"{Fore.RED}\n[!] Error: {str(e)}")
    finally:
        input(f"\n{Fore.CYAN}Press Enter to exit...")

if __name__ == "__main__":
    main()