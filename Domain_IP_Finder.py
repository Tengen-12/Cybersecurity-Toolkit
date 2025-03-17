import socket
import re
from colorama import Fore, init
import concurrent.futures

# Initialize colorama for cross-platform colored text
init(autoreset=True)

def is_valid_domain(domain):
    """Validate domain format using regex."""
    pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def is_valid_ip(ip):
    """Validate IPv4 and IPv6 addresses."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def domain_to_ip(domain):
    """Convert domain to IP address with multiple records and validation."""
    if not is_valid_domain(domain):
        print(f"{Fore.RED}[-] Invalid domain format: {domain}")
        return None

    try:
        # Get all IP addresses for the domain
        addr_info = socket.getaddrinfo(domain, None)
        ips = {info[4][0] for info in addr_info}
        
        print(f"{Fore.GREEN}[+] Domain: {domain}")
        for ip in ips:
            print(f"{Fore.CYAN}  -> IP: {ip}")
        return list(ips)
    except (socket.gaierror, socket.timeout) as e:
        print(f"{Fore.RED}[-] Resolution failed for {domain}: {str(e)}")
        return None

def ip_to_domain(ip):
    """Convert IP address to domain with reverse lookup and validation."""
    if not is_valid_ip(ip):
        print(f"{Fore.RED}[-] Invalid IP address: {ip}")
        return None

    try:
        # Get full reverse DNS information
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        print(f"{Fore.GREEN}[+] IP: {ip}")
        print(f"{Fore.CYAN}  -> Primary Hostname: {hostname}")
        if aliases:
            print(f"{Fore.CYAN}  -> Aliases: {', '.join(aliases)}")
        return hostname
    except (socket.herror, socket.timeout) as e:
        print(f"{Fore.RED}[-] Reverse lookup failed for {ip}: {str(e)}")
        return None

def bulk_lookup(items, lookup_type):
    """Perform bulk lookups using threading."""
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for item in items:
            item = item.strip()
            if item:
                if lookup_type == "domain":
                    futures.append(executor.submit(domain_to_ip, item))
                else:
                    futures.append(executor.submit(ip_to_domain, item))
        
        for future in concurrent.futures.as_completed(futures):
            future.result()

def print_banner():
    """Display a formatted banner."""
    banner = f"""
    {Fore.BLUE}╔══════════════════════════════╗
    ║       {Fore.WHITE}DNS LOOKUP TOOL       {Fore.BLUE}║
    ╚══════════════════════════════╝
    """
    print(banner)

if __name__ == "__main__":
    # Set timeout for DNS operations (in seconds)
    socket.setdefaulttimeout(10)
    
    print_banner()
    
    while True:
        print(f"\n{Fore.YELLOW}Options:")
        print(f"{Fore.WHITE}1. Domain to IP lookup")
        print(f"{Fore.WHITE}2. IP to Domain lookup")
        print(f"{Fore.WHITE}3. Bulk domain lookup")
        print(f"{Fore.WHITE}4. Bulk IP lookup")
        print(f"{Fore.WHITE}5. Exit")
        
        choice = input(f"\n{Fore.YELLOW}Enter your choice (1-5): ").strip()
        
        if choice == "1":
            domain = input(f"{Fore.WHITE}Enter domain: ").strip()
            domain_to_ip(domain)
        elif choice == "2":
            ip = input(f"{Fore.WHITE}Enter IP address: ").strip()
            ip_to_domain(ip)
        elif choice == "3":
            file_path = input(f"{Fore.WHITE}Enter path to domains file: ").strip()
            try:
                with open(file_path, 'r') as f:
                    domains = f.readlines()
                bulk_lookup(domains, "domain")
            except FileNotFoundError:
                print(f"{Fore.RED}[-] File not found: {file_path}")
        elif choice == "4":
            file_path = input(f"{Fore.WHITE}Enter path to IPs file: ").strip()
            try:
                with open(file_path, 'r') as f:
                    ips = f.readlines()
                bulk_lookup(ips, "ip")
            except FileNotFoundError:
                print(f"{Fore.RED}[-] File not found: {file_path}")
        elif choice == "5":
            print(f"{Fore.GREEN}[+] Exiting...")
            break
        else:
            print(f"{Fore.RED}[-] Invalid choice. Please try again.")