import requests
import argparse
import json
from urllib.parse import urljoin, urlparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import warnings
import os
import re
import socket
from colorama import init, Fore, Style
import ssl
import subprocess

try:
    from dns import resolver, exception
except ImportError:
    sys.exit(f"{Fore.RED+Style.BRIGHT}[!] FATAL: Pustaka 'dnspython' tidak ditemukan. Harap instal: pip install dnspython{Style.RESET_ALL}")

init(autoreset=True)
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class TColors:
    HEADER = Fore.MAGENTA + Style.BRIGHT; SECTION = Fore.YELLOW + Style.BRIGHT
    TARGET = Fore.CYAN + Style.BRIGHT; INFO = Fore.CYAN; SUCCESS = Fore.GREEN
    ERROR = Fore.RED; CRITICAL = Fore.RED + Style.BRIGHT; HIGH = Fore.YELLOW
    MEDIUM = Fore.BLUE; RESET = Style.RESET_ALL

COMMON_PORTS = {80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 25: "SMTP", 3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Alt"}
TOP_100_PORTS = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 1027, 9090, 2001, 515, 7000, 9000, 513, 49152, 631, 1028, 389, 8008, 1029, 444, 2049, 1030, 8081, 1433, 6000, 1024, 13, 20, 7, 17, 19, 9, 11, 10, 1, 15, 37, 42, 43, 49, 50, 69, 70, 79, 88, 106, 109, 123, 161, 162, 177, 194, 220, 256, 257, 259, 264, 280, 311, 318]

REMOTE_CHECKS = [
    {"path": "/.env", "risk": "KRITIS", "description": "Exposed Environment File (.env)"},
    {"path": "/.git/config", "risk": "KRITIS", "description": "Exposed Git Config"},
    {"path": "/storage/logs/laravel.log", "risk": "TINGGI", "description": "Exposed Application Log"},
    {"path": "/vendor/", "risk": "KRITIS", "description": "Directory Listing: /vendor"},
    {"path": "/telescope", "risk": "TINGGI", "description": "Exposed Telescope Panel"},
    {"path": "/phpinfo.php", "risk": "TINGGI", "description": "Exposed phpinfo() file"},
    {"path": "/info.php", "risk": "TINGGI", "description": "Exposed phpinfo() file"},
    {"path": "/log-viewer", "risk": "TINGGI", "description": "Exposed Log Viewer Panel"},
    {"path": "/pma/", "risk": "KRITIS", "description": "Exposed phpMyAdmin Panel"},
    {"path": "/phpmyadmin/", "risk": "KRITIS", "description": "Exposed phpMyAdmin Panel"},
    {"path": "/login", "risk": "INFO", "description": "Login Page Found"},
    {"path": "/admin", "risk": "INFO", "description": "Admin Panel Found"},
    {"path": "/dashboard", "risk": "INFO", "description": "Dashboard Found"},
    {"path": "/cpanel", "risk": "INFO", "description": "cPanel Login Found"},
]

DIRECTORY_LISTING_CHECKS = ["/storage/", "/public/uploads/", "/uploads/", "/images/", "/assets/"]


class LaravelAuditor:
    def __init__(self, target, threads=10, timeout=10, ports_to_scan=None):
        self.target = target
        self.max_threads = threads
        self.timeout = timeout
        self.findings = []
        self.lock = threading.Lock()
        self.scan_mode = 'local' if os.path.isdir(target) else 'remote'
        self.ports_to_scan = ports_to_scan
        
        if self.scan_mode == 'remote':
            self.base_url = target.rstrip('/')
            self.domain_name = urlparse(self.base_url).netloc
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': 'red-config-scanner/1.0'})
            self.session.verify = False
            self.stats = {'Target': self.base_url, 'Scan Mode': 'Remote', 'Server IP': 'N/A', 'Hosting Provider': 'N/A', 'OS': 'N/A', 'HTTP Version': 'N/A', 'Web Server': 'N/A', 'WAF Detected': 'None', 'Laravel Version': 'Unknown', 'Open Ports': [], 'SSL Info': {}}
        else:
            self.stats = {'Target': target, 'Scan Mode': 'Local (SAST)', 'Laravel Version': 'Unknown', 'Discovered Routes': []}

    def _update_status(self, message, status, status_color=TColors.SUCCESS, is_final=False):
        padded_message = f"{TColors.INFO}[*] {message.ljust(35)}"
        status_text = f"{status_color}{status}{TColors.RESET}"
        terminator = '\n' if is_final else ''
        clear_padding = ' ' * 20 
        sys.stdout.write(f"\r{padded_message}: {status_text}{clear_padding}{terminator}")
        sys.stdout.flush()

    def run_audit(self):
        self._print_header(f"Mode: {self.stats['Scan Mode']}")
        if self.scan_mode == 'remote':
            self._run_remote_audit()
        else:
            self._run_local_audit()
        self._print_final_summary()

    def _print_header(self, title): print(f"\n{TColors.SECTION}[+] {title}{TColors.RESET}")

    def _run_remote_audit(self):
        self._print_header("Phase 1: Remote Reconnaissance")
        self._run_reconnaissance()
        self._detect_waf() 
        self._discover_subdomains()
        self._run_traceroute()
        self._print_header("Phase 2: Configuration Audit")
        self._run_port_scan()
        self._check_remote_debug_mode()
        self._check_csrf_token()
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self._perform_remote_check, REMOTE_CHECKS)
            executor.map(self._check_directory_listing, DIRECTORY_LISTING_CHECKS)

    def _run_local_audit(self):
        pass

    def _run_reconnaissance(self):
        msg = "Resolving Target IP"
        self._update_status(msg, "...")
        try:
            self.stats['Server IP'] = socket.gethostbyname(self.domain_name)
            self._update_status(msg, self.stats['Server IP'], is_final=True)
        except socket.gaierror:
            self._update_status(msg, "Failed", TColors.ERROR, is_final=True); return
        
        msg = "Fetching Server Info & Hosting"
        self._update_status(msg, "...")
        try:
            r_server = self.session.get(self.base_url, timeout=self.timeout)
            http_version_map = {11: "HTTP/1.1", 20: "HTTP/2"}; self.stats['HTTP Version'] = http_version_map.get(r_server.raw.version, "Unknown")
            self.stats['Web Server'] = r_server.headers.get('Server', 'N/A')
            r_hosting = requests.get(f"http://ip-api.com/json/{self.stats['Server IP']}", timeout=self.timeout)
            if r_hosting.status_code == 200 and r_hosting.json().get('status') == 'success':
                self.stats['Hosting Provider'] = r_hosting.json().get('isp', 'N/A')
            self._update_status(msg, "Done", is_final=True)
        except Exception: 
            self._update_status(msg, "Failed", TColors.ERROR, is_final=True)

        if self.base_url.startswith("https://"): self._check_ssl_certificate()
        
    def _check_ssl_certificate(self):
        msg = "Analyzing SSL/TLS Certificate"
        self._update_status(msg, "...")
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain_name) as s:
                s.settimeout(self.timeout); s.connect((self.domain_name, 443)); cert = s.getpeercert()
            issuer = dict(x[0] for x in cert.get('issuer', []))
            self.stats['SSL Info']['Issuer'] = issuer.get('organizationName', 'N/A')
            self.stats['SSL Info']['Valid Until'] = cert.get('notAfter')
            sans = [v for k, v in cert.get('subjectAltName', []) if k == 'DNS']
            self.stats['SSL Info']['Other Domains'] = sans if sans else ['None']
            self._update_status(msg, "Done", is_final=True)
        except Exception: 
            self._update_status(msg, "Failed", TColors.ERROR, is_final=True)
    
    def _detect_waf(self):
        msg = "Detecting WAF/Firewall"
        self._update_status(msg, "...")
        payload = {'id': '<script>alert("WAF Test")</script>'}
        waf_found = "None"
        try:
            r = self.session.get(self.base_url, params=payload, timeout=self.timeout)
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = r.text.lower()
            if 'cloudflare' in headers.get('server', '') or 'cf-ray' in headers:
                waf_found = "Cloudflare"
            elif 'X-Sucuri-ID' in headers:
                waf_found = "Sucuri"
            elif 'AkamaiGHost' in headers.get('server', ''):
                 waf_found = "Akamai"
            elif 'awselb' in headers.get('server', ''):
                 waf_found = "AWS Elastic Load Balancer"
            elif "incapsula" in body:
                waf_found = "Incapsula"
            elif "f5" in body:
                waf_found = "F5 BIG-IP"
            elif r.status_code in [403, 406, 429]:
                 waf_found = f"Generic WAF (Blocked with status {r.status_code})"
            self.stats['WAF Detected'] = waf_found
            self._update_status(msg, waf_found if waf_found != "None" else "Not Detected", is_final=True)
        except requests.RequestException:
            self._update_status(msg, "Error", TColors.ERROR, is_final=True)
    
    def _discover_subdomains(self):
        self._print_header("Phase 1.2: Subdomain Discovery")
        msg = "Searching for subdomains"
        self._update_status(msg, "...")
        
        subdomains = set()
        url = f"https://crt.sh/?q=%.{self.domain_name}&output=json"
        try:
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        names = name_value.split('\n')
                        for name in names:
                            if name.strip() and '*' not in name and name.strip() != self.domain_name:
                                subdomains.add(name.strip())
            
            if subdomains:
                self._update_status(msg, f"Found {len(subdomains)} subdomains", is_final=True)
                for sub in sorted(list(subdomains)):
                    self._add_finding("INFO", "Subdomain Found", sub, "Informational: Review this subdomain for security misconfigurations.")
            else:
                self._update_status(msg, "No subdomains found", is_final=True)

        except (requests.RequestException, json.JSONDecodeError):
             self._update_status(msg, "Failed to query or parse from crt.sh", TColors.ERROR, is_final=True)


    def _run_traceroute(self):
        self._print_header("Phase 1.5: Traceroute Analysis")
        print(f"{TColors.INFO}Performing traceroute to {self.domain_name}. This may take a moment...")
        try:
            command = ["tracert", self.domain_name] if sys.platform == "win32" else ["traceroute", self.domain_name]
            result = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True, timeout=120)
            print(TColors.SUCCESS + "Traceroute successful:")
            print(result)
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception) as e:
            print(f"{TColors.ERROR}[!] Traceroute failed. Reason: {e}")

    def _run_port_scan(self):
        ports_to_scan = self.ports_to_scan or COMMON_PORTS.keys()
        port_dict = {p: COMMON_PORTS.get(p, 'Unknown') for p in ports_to_scan}
        port_dict.update({p: 'Top-100' for p in ports_to_scan if p in TOP_100_PORTS and p not in COMMON_PORTS})
        msg = f"Scanning {len(ports_to_scan)} specified ports"
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            f = {executor.submit(self._check_port, p): p for p in ports_to_scan}
            for i, future in enumerate(as_completed(f), 1):
                port, is_open = future.result()
                if is_open: open_ports.append(f"{port}/{port_dict.get(port, 'Custom')}")
                self._update_status(msg, f"Scanning {i}/{len(ports_to_scan)}")
        self.stats['Open Ports'] = open_ports or ['None detected']
        self._update_status(msg, "Done", is_final=True)

    def _check_port(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5); return port, s.connect_ex((self.stats['Server IP'], port)) == 0
    
    def _check_remote_debug_mode(self):
        msg = "Detecting Debug Mode"
        self._update_status(msg, "...")
        try:
            r = self.session.get(urljoin(self.base_url, f"/{time.time()}"), timeout=self.timeout)
            if r.status_code == 500 and ("Whoops!" in r.text or "Ignition" in r.text):
                self._add_finding("KRITIS", "Debug Mode is Active on Production", self.base_url, "Matikan debug mode di file .env (APP_DEBUG=false).")
            self._update_status(msg, "Done", is_final=True)
        except requests.RequestException: 
            self._update_status(msg, "Done", is_final=True)

    def _check_csrf_token(self):
        msg = "Checking for CSRF Token"
        self._update_status(msg, "...")
        try:
            r = self.session.get(self.base_url, timeout=self.timeout)
            meta_token = re.search(r'<meta\s+name=["\']csrf-token["\']\s+content=["\'](.*?)["\']', r.text)
            input_token = re.search(r'<input\s+type=["\']hidden["\']\s+name=["\']_token["\']\s+value=["\'](.*?)["\']', r.text)
            if meta_token or input_token:
                self._add_finding("INFO", "CSRF Token Detected", "Good security practice. Found in page source.", "N/A")
                self._update_status(msg, "Detected", TColors.SUCCESS, is_final=True)
            else:
                self._add_finding("MEDIUM", "CSRF Token Not Found", "State-changing forms might be vulnerable. Manual check required.", "Implement CSRF protection on all state-changing forms.")
                self._update_status(msg, "Not Found", TColors.HIGH, is_final=True)
        except requests.RequestException:
            self._update_status(msg, "Error", TColors.ERROR, is_final=True)

    def _perform_remote_check(self, check):
        url = urljoin(self.base_url, check['path'])
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200:
                 self._add_finding(check['risk'], check['description'], url)
        except requests.RequestException: pass

    def _check_directory_listing(self, path):
        url = urljoin(self.base_url, path)
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200 and ("Index of /" in r.text or "Parent Directory" in r.text):
                self._add_finding("MEDIUM", f"Directory Listing enabled for: {path}", url)
        except requests.RequestException:
            pass

    def _add_finding(self, risk, description, location, remediation=None):
        with self.lock:
            if remediation is None:
                remediation = "Segera batasi akses ke file/direktori ini. Konfigurasi web server Anda (Nginx/Apache) untuk menolak akses langsung."
            if risk == "KRITIS" and ".env" in description: 
                remediation = "SANGAT KRITIS! Segera batasi akses, rotasi semua kredensial, dan periksa log untuk aktivitas mencurigakan."
            self.findings.append({'risk': risk, 'description': description, 'location': location, 'remediation': remediation})

    def _print_final_summary(self):
        print("\n\n" + TColors.HEADER + "--- SECURITY AUDIT SUMMARY ---" + TColors.RESET)
        print("\n[+] RECONNAISSANCE & FINGERPRINTING")
        print("-" * 60)
        
        for key, value in self.stats.items():
            if key == 'Discovered Routes': continue
            
            if key == 'SSL Info':
                if not value or 'Issuer' not in value:
                    print(f"  {'SSL Info'.ljust(25)}: {TColors.SUCCESS}N/A{TColors.RESET}")
                else:
                    print(f"  {'SSL Info (Issuer)'.ljust(25)}: {TColors.SUCCESS}{value.get('Issuer', 'N/A')}{TColors.RESET}")
                    print(f"  {'Valid Until'.ljust(25)}: {TColors.SUCCESS}{value.get('Valid Until', 'N/A')}{TColors.RESET}")
                    other_domains_str = ", ".join(value.get('Other Domains', ['N/A']))
                    print(f"  {'Other Domains'.ljust(25)}: {TColors.SUCCESS}{other_domains_str}{TColors.RESET}")
            else:
                value_str = ", ".join(value) if isinstance(value, list) else str(value)
                print(f"  {key.ljust(25)}: {TColors.SUCCESS}{value_str}{TColors.RESET}")
        
        print("-" * 60)
        
        if not self.findings: print(f"\n{TColors.SUCCESS}[✓] Audit complete. No common misconfigurations were found.{TColors.RESET}")
        else:
            print(f"\n{TColors.CRITICAL}[!] FOUND {len(self.findings)} POTENTIAL SECURITY ISSUES:{TColors.RESET}")
            for finding in sorted(self.findings, key=lambda x: ['KRITIS', 'TINGGI', 'MEDIUM', 'INFO'].index(x['risk'])):
                color = {"KRITIS": TColors.CRITICAL, "TINGGI": TColors.HIGH, "MEDIUM": TColors.MEDIUM, "INFO": TColors.INFO}.get(finding['risk'])
                print(f"  {color}[{finding['risk'].ljust(7)}] {finding['description'].ljust(25)}{TColors.TARGET}{finding['location']}{TColors.RESET}")

    def save_reports_interactively(self):
        if not self.findings and self.scan_mode == 'remote' and not self.stats.get('Open Ports'): return
        print("\n" + TColors.SECTION + "[+] Save Report Option" + TColors.RESET)
        while True:
            choice = input("Save report? [1] JSON  [2] TXT [3] No: ")
            if choice in ['1', '2']:
                file_format = 'json' if choice == '1' else 'txt'
                default_name = f"report_{self.domain_name or os.path.basename(self.target)}.{file_format}"
                filename = input(f"Enter filename (default: {default_name}): ") or default_name
                report_data = {'scan_summary': self.stats, 'findings': self.findings}
                try:
                    if choice == '1':
                        with open(filename, 'w', encoding='utf-8') as f: json.dump(report_data, f, indent=4)
                    else:
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write(f"--- Laravel Security Audit Report: {self.target} ---\n\n"); [f.write(f"- {k}: {v}\n") for k, v in self.stats.items()]
                            f.write("\n\n--- Findings ---\n\n"); [f.write(f"[{item['risk']}] {item['description']}\nLocation: {item['location']}\nRemediation: {item['remediation']}\n\n") for item in self.findings]
                    print(f"{TColors.SUCCESS}[✓] Report successfully saved to {filename}{TColors.RESET}")
                except Exception as e: print(f"{TColors.ERROR}[-] Failed to save file: {e}{TColors.RESET}")
                break
            elif choice == '3' or choice == '': print("[i] Skipping report saving."); break
            else: print(f"{TColors.ERROR}Invalid option, please try again.{TColors.RESET}")

def parse_ports(port_string):
    if not port_string: return None
    if port_string.lower() == 'top-100': return TOP_100_PORTS
    ports = set()
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 0 < start <= end < 65536: ports.update(range(start, end + 1))
            except ValueError: print(f"{TColors.ERROR}Invalid port range: {part}")
        else:
            try:
                port = int(part)
                if 0 < port < 65536: ports.add(port)
            except ValueError: print(f"{TColors.ERROR}Invalid port number: {part}")
    return sorted(list(ports))

def main():
    parser = argparse.ArgumentParser(
        description="red config - Laravel Configuration Exposure & Security Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example: python3 redconfig.py https://example.com --ports top-100 -w /path/to/wordlist.txt"
    )
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument("target", metavar="TARGET", help="The root URL of the web application to be scanned (e.g., https://example.com).")
    discovery_group = parser.add_argument_group('Discovery & Enumeration Options')
    discovery_group.add_argument("--ports", metavar="<PORTS>", help="Specify ports to scan. Examples:\n  '80,443,8080'    - Scan specific ports.\n  '1-1024'         - Scan a range of ports.\n  'top-100'        - Scan the 100 most common ports.\n(Default: Scans a small list of common web-related ports).")
    discovery_group.add_argument("-w", "--wordlist", metavar="<FILE>", help="Path to a custom wordlist file (one path per line) for discovering\nadditional files and directories.")
    performance_group = parser.add_argument_group('Performance & Control')
    performance_group.add_argument("-t", "--threads", metavar="<NUM>", type=int, default=10, help="Set the number of concurrent scanning threads (default: 10).")
    performance_group.add_argument("--timeout", metavar="<SECONDS>", type=int, default=7, help="Set the request timeout in seconds (default: 7).")

    args = parser.parse_args()

    if args.wordlist:
        print(f"{TColors.INFO}[*] Loading custom wordlist from: {args.wordlist}{TColors.RESET}")
        try:
            with open(args.wordlist, 'r') as f:
                custom_paths = [line.strip() for line in f if line.strip()]
                for path in custom_paths:
                    REMOTE_CHECKS.append({"path": path, "risk": "INFO", "description": f"Custom Path Found: {path}"})
            print(f"{TColors.SUCCESS}[+] Successfully loaded {len(custom_paths)} custom paths.{TColors.RESET}")
        except FileNotFoundError:
            print(f"{TColors.ERROR}[!] Wordlist file not found at: {args.wordlist}. Exiting.{TColors.RESET}")
            sys.exit(1)

    ascii_art = f"""{TColors.CRITICAL}██████╗  ██████╗██████╗{TColors.RESET}      ██████╗ ██████╗ ███╗   ██╗███████╗██╗██████╗ 
{TColors.CRITICAL}██╔══██╗██╔════╝██╔══██╗{TColors.RESET}    ██╔════╝██╔═══██╗████╗  ██║██╔════╝██║██╔════╝ 
{TColors.CRITICAL}██████╔╝█████╗  ██║  ██║{TColors.RESET}    ██║     ██║   ██║██╔██╗ ██║█████╗  ██║██║  ███╗
{TColors.CRITICAL}██╔══██╗██╔══╝  ██║  ██║{TColors.RESET}    ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║██║   ██║
{TColors.CRITICAL}██║  ██║███████╗██████╔╝{TColors.RESET}    ╚██████╗╚██████╔╝██║ ╚████║██║     ██║╚██████╔╝
{TColors.CRITICAL}╚═╝  ╚═╝╚══════╝╚═════╝ {TColors.RESET}     ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝ ╚═════╝ 
"""
    
    title_line_1 = "Laravel Configuration Exposure & Security Scanner(beta)"
    title_line_2 = "by: github.com/shitodcy"

    banner = (
        f"\n{ascii_art}\n"
        f"{TColors.SECTION}{title_line_1}\n"
        f"{TColors.INFO}         {title_line_2}{TColors.RESET}\n"
    )
    print(banner)
    print(f"Hello: {TColors.TARGET}{socket.gethostname()}{TColors.RESET}")
    print(f"Scan Target: {TColors.TARGET}{args.target}{TColors.RESET}")
    
    ports_to_scan = parse_ports(args.ports)

    auditor = LaravelAuditor(target=args.target, threads=args.threads, timeout=args.timeout, ports_to_scan=ports_to_scan)
    try:
        auditor.run_audit()
    except KeyboardInterrupt:
        print(f"\n{TColors.ERROR}[!] Audit interrupted by user.{TColors.RESET}")
    finally:
        auditor.save_reports_interactively()
        print("\n" + "="*60 + f"\n{TColors.SUCCESS}✅ AUDIT COMPLETE{TColors.RESET}\n")

if __name__ == "__main__":
    main()
