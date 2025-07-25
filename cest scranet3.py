"""
CyberSentry Security Scanner Pro
An advanced ethical security assessment tool for identifying common vulnerabilities
Author: exploit_hub8
Version: 2.1 (Color Enhanced)
"""

import socket
import requests
import dns.resolver
import ssl
import subprocess
import os
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

def display_banner():
    """
    Display the colorful ASCII art banner and tool information
    """
    print(Fore.CYAN + r"""
     ____           _     ____                            _    _____ 
    / ___|_   _ ___| |_  / ___|  ___ _ __ __ _ _ __   ___| |_ |___ / 
   | |   | | | / __| __| \___ \ / __| '__/ _` | '_ \ / _ \ __|  |_ \ 
   | |___| |_| \__ \ |_   ___) | (__| | | (_| | | | |  __/ |_  ___) |
    \____|\__,_|___/\__| |____/ \___|_|  \__,_|_| |_|\___|\__||____/ 
    """ + Fore.YELLOW + "~ Advanced Ethical Security Scanner ~" + Fore.RED + "By exploit_hub8")
    print

class CyberSentryPro:
    """
    Advanced scanner class that performs comprehensive security assessments
    Includes port scanning, HTTP analysis, DNS checks, SSL/TLS analysis, and more
    """
    
    def __init__(self, target):
        """
        Initialize the scanner with target information
        
        Args:
            target (str): IP address or domain name to scan
        """
        self.target = target
        # Expanded list of common ports with services
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        # Dictionary of potential attacks for each port
        self.port_attacks = {
            21: "FTP - Brute force, Anonymous login, File upload vulns",
            22: "SSH - Brute force, Version vulns, Shellshock",
            23: "Telnet - Brute force, Cleartext credentials",
            25: "SMTP - Open relay, Spoofing, Enumeration",
            53: "DNS - Zone transfer, Cache poisoning, DDoS amplification",
            80: "HTTP - XSS, SQLi, Directory traversal, Server vulns",
            110: "POP3 - Brute force, Cleartext auth",
            143: "IMAP - Brute force, Cleartext auth",
            443: "HTTPS - SSL/TLS vulns, Web app attacks",
            445: "SMB - EternalBlue, Brute force, Share enumeration",
            3306: "MySQL - SQLi, Brute force, Database dumping",
            3389: "RDP - Brute force, BlueKeep, Credential theft",
            5900: "VNC - Brute force, Session hijacking",
            8080: "HTTP-Alt - Same as HTTP but different apps",
            8443: "HTTPS-Alt - Often used for admin interfaces"
        }
        # Security headers to check
        self.security_headers = [
            "X-XSS-Protection",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Feature-Policy"
        ]
        # SSL/TLS protocols to check
        self.ssl_protocols = {
            "SSLv2": False,
            "SSLv3": False,
            "TLSv1": False,
            "TLSv1.1": False,
            "TLSv1.2": False,
            "TLSv1.3": False
        }

    def get_possible_attacks(self, port):
        """Returns possible attacks for a given open port"""
        return self.port_attacks.get(port, "Unknown service - General network attacks possible")

    def scan_port(self, port):
        """Scan a single port on the target system"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    service = self.common_ports.get(port, "unknown")
                    return (f"{Fore.GREEN}🚪 Port {port} ({service}) is OPEN", port)
        except (socket.error, socket.gaierror, socket.timeout):
            pass
        return (None, None)

    def full_port_scan(self):
        """Perform a comprehensive port scan with attack information"""
        print(f"\n{Fore.BLUE}🔍 Scanning {self.target} for open ports...")
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = list(executor.map(self.scan_port, self.common_ports.keys()))
        
        open_ports = [res for res in results if res[0]]
        
        if open_ports:
            for result in open_ports:
                message, port = result
                print(message)
                print(f"{Fore.YELLOW}   ⚠️ Potential attacks: {self.get_possible_attacks(port)}\n")
        else:
            print(f"{Fore.RED}🔒 No open ports found.")

    def check_http_headers(self):
        """Analyze HTTP response headers for security best practices"""
        try:
            print(f"\n{Fore.BLUE}🌐 Checking HTTP security headers for {self.target}...")
            
            # Try both HTTP and HTTPS
            schemes = ['http', 'https']
            for scheme in schemes:
                try:
                    url = f"{scheme}://{self.target}"
                    response = requests.get(url, timeout=5, allow_redirects=True)
                    
                    print(f"\n{Fore.CYAN}🛡️ Security Header Report ({scheme.upper()}):")
                    for header in self.security_headers:
                        if header in response.headers:
                            print(f"{Fore.GREEN}{header:>28}: ✅ {response.headers[header]}")
                        else:
                            print(f"{Fore.RED}{header:>28}: ❌ Missing")
                    
                    # Check for server header
                    server = response.headers.get('Server', 'Not disclosed')
                    color = Fore.YELLOW if server != "Not disclosed" else Fore.GREEN
                    print(f"{color}{'Server':>28}: {server}")
                    
                    # Check for common web vulnerabilities
                    self.check_web_vulns(response.text)
                    break
                except requests.exceptions.SSLError:
                    continue
                except requests.exceptions.RequestException:
                    continue
                    
        except Exception as e:
            print(f"{Fore.RED}⚠️ HTTP check failed: {e}")

    def check_web_vulns(self, html_content):
        """Check for common web application vulnerabilities"""
        print(f"\n{Fore.BLUE}🔎 Checking for common web vulnerabilities...")
        
        # Check for exposed version information
        version_patterns = [
            r"WordPress (\d+\.\d+\.\d+)",
            r"Joomla! (\d+\.\d+\.\d+)",
            r"Drupal (\d+\.\d+\.\d+)"
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, html_content)
            if match:
                print(f"{Fore.YELLOW}⚠️ Detected CMS version: {match.group(0)} - Check for known vulnerabilities")
        
        # Check for common exposed files
        common_files = [
            "robots.txt",
            ".git/",
            ".env",
            "phpinfo.php"
        ]
        
        for file in common_files:
            try:
                response = requests.get(f"http://{self.target}/{file}", timeout=3)
                if response.status_code == 200:
                    print(f"{Fore.YELLOW}⚠️ Exposed file found: /{file}")
            except:
                pass

    def dns_enumeration(self):
        """Perform basic DNS enumeration"""
        print(f"\n{Fore.BLUE}📡 Performing DNS enumeration for {self.target}...")
        
        try:
            # Check if target is IP or domain
            try:
                socket.inet_aton(self.target)
                is_ip = True
            except socket.error:
                is_ip = False
            
            if not is_ip:
                resolver = dns.resolver.Resolver()
                
                # Common DNS record checks
                record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
                
                for record in record_types:
                    try:
                        answers = resolver.resolve(self.target, record)
                        print(f"\n{Fore.CYAN}{record} Records:")
                        for rdata in answers:
                            print(f"{Fore.WHITE}  {rdata}")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        pass
                
                # Check for subdomains (brute-force with common names)
                common_subdomains = ['www', 'mail', 'ftp', 'admin', 'webmail', 'test']
                print(f"\n{Fore.CYAN}🔍 Checking common subdomains...")
                for sub in common_subdomains:
                    full_domain = f"{sub}.{self.target}"
                    try:
                        answers = resolver.resolve(full_domain, 'A')
                        print(f"{Fore.GREEN}  Found: {full_domain} -> {answers[0]}")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        pass
        except Exception as e:
            print(f"{Fore.RED}⚠️ DNS enumeration failed: {e}")

    def ssl_tls_analysis(self):
        """Analyze SSL/TLS configuration of the target"""
        print(f"\n{Fore.BLUE}🔐 Analyzing SSL/TLS configuration for {self.target}...")
        
        try:
            # Create SSL context and test protocols
            for protocol in self.ssl_protocols.keys():
                try:
                    context = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{protocol}"))
                    with socket.create_connection((self.target, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                            self.ssl_protocols[protocol] = True
                except:
                    self.ssl_protocols[protocol] = False
            
            # Display protocol support
            print(f"\n{Fore.CYAN}🔒 SSL/TLS Protocol Support:")
            for protocol, supported in self.ssl_protocols.items():
                color = Fore.GREEN if supported else Fore.RED
                status = "✅ Supported" if supported else "❌ Not supported"
                print(f"{color}{protocol:>10}: {status}")
            
            # Check certificate information
            print(f"\n{Fore.CYAN}📜 Certificate Information:")
            cert = ssl.get_server_certificate((self.target, 443))
            x509 = ssl.PEM_cert_to_DER_cert(cert)
            cert_obj = ssl.DER_cert_to_PEM_cert(x509)
            for line in cert_obj.split('\n')[0:6]:  # Print basic cert info
                print(f"{Fore.WHITE}{line}")
            
            # Check for weak ciphers (simplified)
            weak_ciphers = [
                "DES", "3DES", "RC4", "MD5", 
                "CBC", "NULL", "EXPORT", "ANON"
            ]
            
            print(f"\n{Fore.CYAN}🔍 Checking for weak cipher suites (simplified check)...")
            try:
                result = subprocess.run(
                    ["openssl", "s_client", "-connect", f"{self.target}:443", "-cipher", "ALL"],
                    capture_output=True, text=True, timeout=10
                )
                for cipher in weak_ciphers:
                    if cipher in result.stdout:
                        print(f"{Fore.YELLOW}⚠️ Potential weak cipher detected: {cipher}")
            except:
                print(f"{Fore.RED}⚠️ Could not perform detailed cipher check (openssl required)")
            
        except Exception as e:
            print(f"{Fore.RED}⚠️ SSL/TLS analysis failed: {e}")

    def basic_vulnerability_scan(self):
        """Perform basic vulnerability checks"""
        print(f"\n{Fore.BLUE}🛡️ Performing basic vulnerability checks for {self.target}...")
        
        # Check for common vulnerabilities
        try:
            # Check if target is a web server
            response = requests.get(f"http://{self.target}", timeout=5)
            
            # Check for directory listing
            test_dir = "/images/"
            dir_response = requests.get(f"http://{self.target}{test_dir}", timeout=3)
            if "Index of" in dir_response.text:
                print(f"{Fore.YELLOW}⚠️ Directory listing enabled at: {test_dir}")
            
            # Check for admin interfaces
            admin_paths = ["/admin", "/wp-admin", "/administrator"]
            for path in admin_paths:
                admin_response = requests.get(f"http://{self.target}{path}", timeout=3)
                if admin_response.status_code == 200:
                    print(f"{Fore.YELLOW}⚠️ Admin interface found at: {path}")
            
        except requests.exceptions.RequestException:
            pass

if __name__ == "__main__":
    """Main execution block"""
    display_banner()
    
    target = input(f"{Fore.YELLOW}🎯 Enter target IP/Domain: ").strip()
    
    scanner = CyberSentryPro(target)
    
    # Run comprehensive scans
    scanner.full_port_scan()
    scanner.check_http_headers()
    scanner.dns_enumeration()
    scanner.ssl_tls_analysis()
    scanner.basic_vulnerability_scan()
    
    print(f"\n{Fore.GREEN}✨ Scan completed. Report vulnerabilities responsibly!")