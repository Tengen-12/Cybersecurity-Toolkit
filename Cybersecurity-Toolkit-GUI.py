import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
from tkinter.ttk import Notebook
from tkinter import Frame, Button, Entry, Label
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import socket

class CybersecurityToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity Toolkit")
        self.root.geometry("1000x600")
        self.root.minsize(800, 500)  # Set a minimum size for the window

        # Notebook for tabs
        self.notebook = Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Prevent duplicate tab creation
        if hasattr(self, 'tabs'):
            return

        # Tabs for each tool, Disclaimer first, Help last
        self.tabs = {
            "Disclaimer": self.create_disclaimer_tab(),
            "URL Extractor": self.create_tab("URL Extractor", self.run_url_extractor),
            "Header Detection": self.create_tab("Header Detection", self.run_header_detection),
            "Domain/IP Finder": self.create_tab("Domain/IP Finder", self.run_domain_ip_finder),
            "Buffer Overflow Test": self.create_tab("Buffer Overflow Test", self.run_buffer_overflow),
            "API Testing": self.create_tab("API Testing", self.run_api_testing),
            "API Finder": self.create_tab("API Finder", self.run_api_finder),
            "Help": self.create_help_tab(),  # Help tab moved to the end
        }

        # Bind tab change event to clear history
        self.notebook.bind("<<NotebookTabChanged>>", self.clear_fields)

    def create_tab(self, title, run_command):
        """Create a tab with input, output fields, and buttons. Cybersecurity themed UI."""
        tab = Frame(self.notebook, bg="#181c20")
        # Prevent duplicate tab creation
        for i in range(self.notebook.index("end")):
            if self.notebook.tab(i, "text") == title:
                return {"input": None, "output": None}
        self.notebook.add(tab, text=title)
        # Add green border below tab label area
        border_color = "#39ff14"
        border_frame = Frame(tab, bg=border_color, height=3)
        border_frame.grid(row=0, column=0, sticky="ew", columnspan=2)
        # Shift all content down by 1 row
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(4, weight=1)
        label_fg = "#39ff14"  # neon green
        label_bg = "#181c20"
        entry_bg = "#23272b"
        entry_fg = "#39ff14"
        output_bg = "#101215"
        output_fg = "#39ff14"
        button_bg = "#23272b"
        button_fg = "#39ff14"
        label_style = {"font": ("Consolas", 13, "bold"), "fg": label_fg, "bg": label_bg}
        # Input label and field (use tk.Entry, not ttk.Entry)
        input_label = Label(tab, text=f"{title} Input", **label_style)
        input_label.grid(row=1, column=0, sticky="w", padx=10, pady=5)
        input_field = tk.Entry(tab, width=80, font=("Consolas", 11), bg=entry_bg, fg=entry_fg, insertbackground=entry_fg, highlightbackground=border_color, highlightcolor=border_color, highlightthickness=1, relief="flat")
        input_field.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        # Output label and area
        output_label = Label(tab, text=f"{title} Output", **label_style)
        output_label.grid(row=3, column=0, sticky="w", padx=10, pady=5)
        output_area = scrolledtext.ScrolledText(tab, wrap=tk.WORD, bg=output_bg, fg=output_fg, insertbackground=output_fg, font=("Consolas", 11), borderwidth=2, relief="flat", highlightbackground=border_color, highlightcolor=border_color, highlightthickness=1)
        output_area.grid(row=4, column=0, sticky="nsew", padx=10, pady=5)
        # Button frame and buttons
        button_frame = Frame(tab, bg=label_bg)
        button_frame.grid(row=5, column=0, pady=10)
        def themed_button(text, command):
            return Button(button_frame, text=text, command=command, width=10, font=("Consolas", 11, "bold"), bg=button_bg, fg=button_fg, activebackground=label_fg, activeforeground=label_bg, relief="flat", highlightbackground=border_color, highlightcolor=border_color, highlightthickness=1)
        themed_button("Run", lambda: run_command(input_field, output_area)).grid(row=0, column=0, padx=5)
        themed_button("Clear", lambda: self.clear_fields(input_field, output_area)).grid(row=0, column=1, padx=5)
        themed_button("Cancel", self.root.quit).grid(row=0, column=2, padx=5)
        return {"input": input_field, "output": output_area}

    def create_disclaimer_tab(self):
        """Create a Disclaimer tab with cybersecurity theme."""
        tab = Frame(self.notebook, bg="#181c20")
        self.notebook.add(tab, text="Disclaimer")
        # Add green border below tab label area
        border_color = "#39ff14"
        border_frame = Frame(tab, bg=border_color, height=3)
        border_frame.pack(fill="x", side="top")
        disclaimer = (
            "This application may process sensitive data such as URLs, IPs, and headers.\n"
            "By using this tool, you agree to comply with GDPR and other data protection regulations.\n"
            "Ensure you have permission to analyze the provided data."
        )
        label = tk.Label(tab, text=disclaimer, wraplength=800, justify="left", font=("Consolas", 13, "bold"), fg="#39ff14", bg="#181c20")
        label.pack(padx=20, pady=20, anchor="w")
        return {"input": None, "output": None}

    def create_help_tab(self):
        """Create a Help tab with instructions for each tool."""
        tab = Frame(self.notebook, bg="#181c20")
        self.notebook.add(tab, text="Help")
        # Add green border below tab label area
        border_color = "#39ff14"
        border_frame = Frame(tab, bg=border_color, height=3)
        border_frame.pack(fill="x", side="top")
        help_text = (
            "How to Use Each Section:\n\n"
            "URL Extractor:\n"
            "  - Enter a valid URL (e.g., https://example.com) in the input field.\n"
            "  - Click 'Run' to extract all URLs from the page.\n\n"
            "Header Detection:\n"
            "  - Enter a website URL.\n"
            "  - Click 'Run' to check for missing security headers.\n\n"
            "Domain/IP Finder:\n"
            "  - Enter a domain (e.g., example.com) to get its IP, or an IP to get its domain.\n"
            "  - Click 'Run' to resolve.\n\n"
            "Buffer Overflow Test:\n"
            "  - Enter target as host:port (e.g., 127.0.0.1:80).\n"
            "  - Click 'Run' to send a test payload.\n\n"
            "API Testing:\n"
            "  - Enter an API endpoint URL.\n"
            "  - Click 'Run', choose HTTP method, and optionally enter JSON data for POST/PUT.\n\n"
            "API Finder:\n"
            "  - Enter a website URL.\n"
            "  - Click 'Run' to search for possible API endpoints in the site and its JS files.\n\n"
            "General:\n"
            "  - Use 'Clear' to reset input/output fields.\n"
            "  - Use 'Cancel' to exit the application.\n"
        )
        label = tk.Label(
            tab,
            text=help_text,
            wraplength=900,
            justify="left",
            font=("Consolas", 12),
            fg="#39ff14",
            bg="#181c20"
        )
        label.pack(padx=20, pady=20, anchor="w")
        return {"input": None, "output": None}

    def clear_fields(self, event=None, input_field=None, output_area=None):
        """Clear input and output fields."""
        try:
            if input_field and output_area:
                input_field.delete(0, tk.END)
                output_area.delete(1.0, tk.END)
            else:
                for tab in self.tabs.values():
                    if tab["input"] is not None:
                        tab["input"].delete(0, tk.END)
                    if tab["output"] is not None:
                        tab["output"].delete(1.0, tk.END)
        except Exception:
            pass

    def log_output(self, output_area, text):
        """Log output to the output area."""
        try:
            output_area.insert(tk.END, text + "\n")
            output_area.see(tk.END)
        except Exception:
            pass

    def run_url_extractor(self, input_field, output_area):
        """Logic for URL Extractor."""
        def is_valid_url(url):
            pattern = re.compile(
                r'^(?:http|ftp)s?://'  # Protocol
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # Domain
                r'localhost|'  # Localhost
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IPv4
                r'(?::\d+)?'  # Port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            return re.match(pattern, url) is not None

        def extract_urls(html, base_url):
            try:
                soup = BeautifulSoup(html, 'html.parser')
                urls = []
                for tag in soup.find_all(['a', 'link', 'script', 'img'], href=True):
                    url = tag['href'].strip()
                    absolute_url = urljoin(base_url, url)
                    urls.append(absolute_url)
                return sorted(set(urls))  # Remove duplicates and sort
            except Exception:
                return []

        target_url = input_field.get().strip()
        if not target_url or not is_valid_url(target_url):
            self.log_output(output_area, "Invalid URL. Please try again.")
            return

        try:
            response = requests.get(target_url, timeout=10)
            response.raise_for_status()
            urls = extract_urls(response.text, target_url)
            if not urls:
                self.log_output(output_area, "No URLs found.")
            else:
                self.log_output(output_area, f"Extracted URLs from {target_url}:")
                for url in urls:
                    self.log_output(output_area, url)
        except requests.RequestException as e:
            self.log_output(output_area, f"Error fetching URL content: {e}")

    def run_header_detection(self, input_field, output_area):
        """Logic for Header Detection."""
        SECURITY_HEADERS = {
            "Content-Security-Policy": "Prevents XSS and code injection attacks",
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-Content-Type-Options": "Prevents MIME type sniffing",
            "Referrer-Policy": "Controls referrer information leakage",
            "Permissions-Policy": "Controls browser features access",
        }

        target_url = input_field.get().strip()
        if not target_url:
            self.log_output(output_area, "Invalid URL. Please try again.")
            return

        try:
            response = requests.get(target_url, timeout=10)
            headers = response.headers
            missing_headers = [header for header in SECURITY_HEADERS if header not in headers]
            if missing_headers:
                self.log_output(output_area, f"Missing security headers for {target_url}:")
                for header in missing_headers:
                    self.log_output(output_area, f"- {header}: {SECURITY_HEADERS[header]}")
            else:
                self.log_output(output_area, "All recommended security headers are present.")
        except requests.RequestException as e:
            self.log_output(output_area, f"Error fetching headers: {e}")

    def run_domain_ip_finder(self, input_field, output_area):
        """Logic for Domain/IP Finder."""
        target = input_field.get().strip()
        if not target:
            self.log_output(output_area, "Invalid input. Please try again.")
            return

        try:
            if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', target):  # Domain
                try:
                    ip = socket.gethostbyname(target)
                    self.log_output(output_area, f"Domain {target} resolved to IP: {ip}")
                except Exception as e:
                    self.log_output(output_area, f"Error resolving domain: {e}")
            elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):  # IP
                try:
                    domain = socket.gethostbyaddr(target)[0]
                    self.log_output(output_area, f"IP {target} resolved to Domain: {domain}")
                except Exception as e:
                    self.log_output(output_area, f"Error resolving IP: {e}")
            else:
                self.log_output(output_area, "Invalid domain or IP format.")
        except Exception as e:
            self.log_output(output_area, f"Unexpected error: {e}")

    def run_buffer_overflow(self, input_field, output_area):
        """Logic for Buffer Overflow Test: Send a large payload to the given host and port."""
        target = input_field.get().strip()
        if not target:
            self.log_output(output_area, "Please enter target in the format host:port.")
            return
        if ':' not in target:
            self.log_output(output_area, "Target must be in the format host:port.")
            return
        host, port = target.split(':', 1)
        try:
            port = int(port)
        except ValueError:
            self.log_output(output_area, "Port must be an integer.")
            return
        payload = b'A' * 4096  # 4KB payload
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((host, port))
                s.sendall(payload)
                self.log_output(output_area, f"Sent buffer overflow payload to {host}:{port}.")
        except Exception as e:
            self.log_output(output_area, f"Error during buffer overflow test: {e}")

    def run_api_testing(self, input_field, output_area):
        """Logic for API Testing: Send a request to the given API endpoint."""
        url = input_field.get().strip()
        if not url:
            self.log_output(output_area, "Please enter an API endpoint URL.")
            return
        method = simpledialog.askstring("HTTP Method", "Enter HTTP method (GET, POST, PUT, DELETE):", initialvalue="GET")
        if not method:
            self.log_output(output_area, "No HTTP method provided.")
            return
        method = method.upper()
        data = None
        if method in ("POST", "PUT", "PATCH"):
            data = simpledialog.askstring("Request Body", "Enter JSON body (optional):", initialvalue="")
        try:
            headers = {'Content-Type': 'application/json'}
            if method == "GET":
                resp = requests.get(url, timeout=10)
            elif method == "POST":
                resp = requests.post(url, data=data, headers=headers, timeout=10)
            elif method == "PUT":
                resp = requests.put(url, data=data, headers=headers, timeout=10)
            elif method == "DELETE":
                resp = requests.delete(url, timeout=10)
            else:
                self.log_output(output_area, f"Unsupported HTTP method: {method}")
                return
            self.log_output(output_area, f"Status: {resp.status_code}")
            self.log_output(output_area, f"Response:\n{resp.text if resp.text else '[No Content]'}")
        except requests.RequestException as e:
            self.log_output(output_area, f"Error during API request: {e}")

    def run_api_finder(self, input_field, output_area):
        """Logic for API Finder: Find possible API endpoints in the given URL."""
        target_url = input_field.get().strip()
        if not target_url:
            self.log_output(output_area, "Invalid URL. Please try again.")
            return
        try:
            response = requests.get(target_url, timeout=10)
            response.raise_for_status()
            html = response.text
            api_pattern = re.compile(r'(["\'])(/api/[^"\'> ]+)', re.IGNORECASE)
            apis = set(match[1] for match in api_pattern.findall(html))
            soup = BeautifulSoup(html, 'html.parser')
            js_urls = [urljoin(target_url, script['src']) for script in soup.find_all('script', src=True)]
            for js_url in js_urls:
                try:
                    js_resp = requests.get(js_url, timeout=5)
                    apis.update(match[1] for match in api_pattern.findall(js_resp.text))
                except Exception:
                    continue
            if apis:
                self.log_output(output_area, f"Possible API endpoints found on {target_url}:")
                for api in sorted(apis):
                    self.log_output(output_area, api)
            else:
                self.log_output(output_area, "No API endpoints found.")
        except requests.RequestException as e:
            self.log_output(output_area, f"Error fetching or parsing: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CybersecurityToolkitGUI(root)
    root.mainloop()
