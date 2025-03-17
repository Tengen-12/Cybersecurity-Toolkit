import requests
from bs4 import BeautifulSoup
import urllib3
import re
from urllib.parse import urljoin, urlparse
from typing import List, Optional
import argparse

# Configure colored output
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RESET = "\033[0m"

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_url(url: str) -> bool:
    """Validate URL format using regex"""
    pattern = re.compile(
        r'^(?:http|ftp)s?://'  # Protocol
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # Domain
        r'localhost|'  # Localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IPv4
        r'(?::\d+)?'  # Port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(pattern, url) is not None

def get_user_input(prompt: str, validation_func) -> str:
    """Get and validate user input with retry logic"""
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input):
            return user_input
        print(f"{COLOR_RED}Invalid input. Please try again.{COLOR_RESET}")

def fetch_url_content(url: str, verify_ssl: bool = False) -> Optional[str]:
    """Fetch URL content with error handling"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        response = requests.get(
            url,
            headers=headers,
            verify=verify_ssl,
            timeout=10,
            allow_redirects=True
        )
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"{COLOR_RED}Request failed: {e}{COLOR_RESET}")
        return None

def extract_urls(html: str, base_url: str) -> List[str]:
    """Extract and normalize URLs from HTML content"""
    soup = BeautifulSoup(html, 'html.parser')
    urls = []
    
    for tag in soup.find_all(['a', 'link', 'script', 'img'], href=True):
        url = tag['href'].strip()
        absolute_url = urljoin(base_url, url)
        urls.append(absolute_url)
    
    return sorted(set(urls))  # Remove duplicates and sort

def save_results(urls: List[str], filename: str) -> bool:
    """Save extracted URLs to file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("\n".join(urls))
        print(f"{COLOR_GREEN}Successfully saved {len(urls)} URLs to {filename}{COLOR_RESET}")
        return True
    except IOError as e:
        print(f"{COLOR_RED}File save failed: {e}{COLOR_RESET}")
        return False

def main():
    """Main execution flow"""
    print(f"{COLOR_GREEN}\n=== URL Extractor 2.0 ==={COLOR_RESET}")
    
    # Get validated user input
    target_url = get_user_input(
        "Enter target URL (http/https): ",
        is_valid_url
    )
    
    output_file = get_user_input(
        "Enter output filename (default: urls.txt): ",
        lambda x: x.endswith('.txt') or x == ''
    ) or 'urls.txt'

    # Security confirmation
    verify_ssl = input("Verify SSL certificates? (y/N): ").lower() == 'y'
    
    # Fetch and process content
    if html_content := fetch_url_content(target_url, verify_ssl):
        print(f"{COLOR_YELLOW}Processing {target_url}...{COLOR_RESET}")
        urls = extract_urls(html_content, target_url)
        
        if urls:
            save_results(urls, output_file)
        else:
            print(f"{COLOR_YELLOW}No URLs found on the page{COLOR_RESET}")
    else:
        print(f"{COLOR_RED}Failed to extract content from {target_url}{COLOR_RESET}")

if __name__ == "__main__":
    main()
