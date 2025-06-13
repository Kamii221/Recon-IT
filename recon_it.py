#!/usr/bin/env python3

import typer
import whois
import dns.resolver
import requests
import nmap
import socket
import json
import re
import os
import sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import Optional, List, Set, Dict, Any
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import urllib3
import certifi
from OTXv2 import OTXv2
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from rich.markdown import Markdown

# Initialize Typer app and Rich console first
app = typer.Typer(help="Recon-IT: A comprehensive reconnaissance tool for penetration testing")
console = Console()

# Banner
BANNER = """
[bold red]
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██╗████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██║╚══██╔══╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██║   ██║   
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██║   ██║   
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║   ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝   ╚═╝   
[/bold red]
[bold blue]A Comprehensive Reconnaissance Tool[/bold blue]
[italic]Version 1.0.0[/italic]
"""

def display_menu():
    """Display the main menu."""
    menu = """
Recon-IT Main Menu

[1] WHOIS Lookup
[2] DNS Enumeration
[3] Subdomain Enumeration
[4] Full Passive Scan (All Passive Modules)
[5] Port Scanning
[6] Banner Grabbing
[7] Technology Detection
[8] Full Active Scan (All Active Modules)
[9] Full Reconnaissance (All Modules)
[10] Custom Scan
[11] Help
[12] Exit

Select an option (1-12): """
    
    while True:
        rprint(Panel(BANNER))
        choice = input(menu)
        
        if choice == '1':
            return 'whois'
        elif choice == '2':
            return 'dns'
        elif choice == '3':
            return 'subdomains'
        elif choice == '4':
            return 'passive'
        elif choice == '5':
            return 'ports'
        elif choice == '6':
            return 'banner'
        elif choice == '7':
            return 'tech'
        elif choice == '8':
            return 'active'
        elif choice == '9':
            return 'full'
        elif choice == '10':
            return 'custom'
        elif choice == '11':
            display_help()
        elif choice == '12':
            sys.exit(0)
        else:
            rprint("[red]Invalid option. Please try again.[/red]")

def display_help():
    """Display help information."""
    help_text = """
[bold cyan]Recon-IT Help[/bold cyan]

[bold]Available Commands:[/bold]

[1] WHOIS Lookup
    - Domain registration information
    - Registrar details
    - Creation and expiration dates
    - Name servers
    - Contact information

[2] DNS Enumeration
    - A Records (IPv4 addresses)
    - AAAA Records (IPv6 addresses)
    - MX Records (Mail servers)
    - TXT Records (SPF, DKIM, etc.)
    - NS Records (Name servers)
    - CNAME Records (Aliases)
    - SOA Records (Zone information)

[3] Subdomain Enumeration
    - Certificate Transparency (crt.sh)
    - AlienVault OTX
    - HackerTarget
    - ThreatCrowd
    - DNSDumpster

[4] Full Passive Scan
    - Combines WHOIS, DNS, and Subdomain enumeration
    - No active scanning involved

[5] Port Scanning
    - TCP SYN scan
    - Service detection
    - Version detection
    - OS fingerprinting
    - Custom port ranges

[6] Banner Grabbing
    - Service identification
    - Version information
    - Protocol details
    - Common ports: 21,22,23,25,80,443,3306,3389,8080

[7] Technology Detection
    - Web technologies
    - Frameworks
    - CMS platforms
    - Server software
    - Security headers
    - Analytics tools

[8] Full Active Scan
    - Port scanning
    - Banner grabbing
    - Technology detection

[9] Full Reconnaissance
    - All passive modules
    - All active modules
    - Complete target analysis

[10] Custom Scan
    - Choose specific modules
    - Customize scan options
    - Flexible configuration

[bold]Usage Examples:[/bold]

1. Interactive Mode (Default):
   python recon_it.py

2. Quick Scan:
   python recon_it.py example.com --no-interactive

3. Specific Module:
   python recon_it.py example.com --no-interactive --module whois

[bold]Report Formats:[/bold]
- TXT (default): Plain text report
- HTML: Formatted HTML report with styling

[bold]Additional Options:[/bold]
--verbose, -v        Enable verbose logging
--output, -o         Output directory for reports (default: reports)
--format             Report format (txt or html, default: txt)

Press Enter to return to main menu...
"""
    rprint(Markdown(help_text))
    input()

def setup_logging(verbose: bool = False):
    """Configure logging with different verbosity levels."""
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Generate log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"recon_it_{timestamp}.log"
    
    # Set up logging format
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Configure root logger
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=log_format,
        datefmt=date_format,
        handlers=[
            # File handler for all logs
            logging.FileHandler(log_file, encoding='utf-8'),
            # Console handler with appropriate level
            logging.StreamHandler()
        ]
    )
    
    # Create a logger for the application
    logger = logging.getLogger('ReconIT')
    
    # Set console handler level based on verbose flag
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Log initial information
    logger.info("=" * 80)
    logger.info("Recon-IT Logging Started")
    logger.info("=" * 80)
    logger.info(f"Log file: {log_file}")
    logger.info(f"Verbose mode: {'Enabled' if verbose else 'Disabled'}")
    logger.info("=" * 80)
    
    return logger

# Try importing Wappalyzer with fallback
WAPPALYZER_AVAILABLE = False
try:
    from wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    console.print("[yellow]Wappalyzer not available. Technology detection will be limited.[/yellow]")
    console.print("[yellow]To enable full technology detection, install Wappalyzer:[/yellow]")
    console.print("[yellow]pip install python-Wappalyzer[/yellow]")

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ReconIT:
    def __init__(self, target, output_dir="reports", threads=10, verbose=False):
        self.target = target
        self.threads = threads
        self.verbose = verbose
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            "active_recon": {},
            "passive_recon": {}
        }
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.logger = setup_logging(verbose)
        self.logger.info(f"Initializing ReconIT for target: {target}")
        self.logger.debug(f"Output directory: {output_dir}")
        self.logger.debug(f"Threads: {threads}")
        self.logger.debug(f"Verbose mode: {verbose}")

    def whois_lookup(self) -> dict:
        """Perform WHOIS lookup on the target domain."""
        try:
            self.logger.info(f"Starting WHOIS lookup for {self.target}")
            console.print("[bold blue]Performing WHOIS lookup...[/bold blue]")
            w = whois.whois(self.target)
            self.logger.debug(f"WHOIS lookup successful: {w}")
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails if hasattr(w, 'emails') else []
            }
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {str(e)}", exc_info=True)
            return {"error": str(e)}

    def dns_enumeration(self) -> dict:
        """Perform DNS enumeration (A, MX, TXT, NS records)."""
        self.logger.info(f"Starting DNS enumeration for {self.target}")
        results = {}
        record_types = ['A', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        
        console.print("[bold blue]Performing DNS enumeration...[/bold blue]")
        for record_type in record_types:
            try:
                self.logger.debug(f"Querying {record_type} records")
                answers = dns.resolver.resolve(self.target, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
                self.logger.debug(f"{record_type} records found: {results[record_type]}")
            except Exception as e:
                if self.verbose:
                    self.logger.warning(f"Failed to get {record_type} records: {str(e)}")
                results[record_type] = []
        
        return results

    def enumerate_from_crtsh(self) -> Set[str]:
        """Enumerate subdomains from crt.sh."""
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=10, verify=False)
            data = response.json()
            
            subdomains = set()
            for entry in data:
                name = entry['name_value'].lower()
                if name.endswith(self.target):
                    # Clean up the subdomain
                    name = name.strip()
                    if name.startswith('*.'):
                        name = name[2:]
                    subdomains.add(name)
            return subdomains
        except Exception as e:
            logging.error(f"crt.sh enumeration failed: {str(e)}")
            return set()

    def enumerate_from_otx(self, api_key: str) -> Set[str]:
        """Enumerate subdomains from AlienVault OTX."""
        if not api_key:
            return set()
            
        try:
            otx = OTXv2(api_key)
            results = otx.get_indicator_details_by_section("domain", self.target, "passive_dns")
            
            subdomains = set()
            for entry in results.get("passive_dns", []):
                hostname = entry.get("hostname", "").lower()
                if hostname.endswith(self.target):
                    subdomains.add(hostname)
            return subdomains
        except Exception as e:
            logging.error(f"OTX enumeration failed: {str(e)}")
            return set()

    def enumerate_from_hackertarget(self) -> Set[str]:
        """Enumerate subdomains from hackertarget.com."""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            response = requests.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                subdomains = set()
                for line in response.text.splitlines():
                    if line:
                        subdomain = line.split(',')[0].lower()
                        if subdomain.endswith(self.target):
                            subdomains.add(subdomain)
                return subdomains
            return set()
        except Exception as e:
            logging.error(f"hackertarget enumeration failed: {str(e)}")
            return set()

    def enumerate_from_threatcrowd(self) -> Set[str]:
        """Enumerate subdomains from threatcrowd.org."""
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target}"
            response = requests.get(url, timeout=10, verify=False)
            data = response.json()
            
            subdomains = set()
            if 'subdomains' in data:
                for subdomain in data['subdomains']:
                    if subdomain.endswith(self.target):
                        subdomains.add(subdomain.lower())
            return subdomains
        except Exception as e:
            logging.error(f"threatcrowd enumeration failed: {str(e)}")
            return set()

    def enumerate_from_dnsdumpster(self) -> Set[str]:
        """Enumerate subdomains from dnsdumpster.com."""
        try:
            url = "https://dnsdumpster.com/"
            session = requests.Session()
            session.verify = False
            
            # Get CSRF token
            response = session.get(url)
            csrf_token = re.search(r'name="csrfmiddlewaretoken" value="(.*?)"', response.text)
            if not csrf_token:
                return set()
                
            csrf_token = csrf_token.group(1)
            
            # Get subdomains
            headers = {
                'Referer': url,
                'X-CSRFToken': csrf_token
            }
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.target
            }
            response = session.post(url, headers=headers, data=data)
            
            # Parse response
            subdomains = set()
            soup = BeautifulSoup(response.text, 'html.parser')
            for subdomain in soup.find_all('td', {'class': 'col-md-4'}):
                subdomain = subdomain.text.strip().lower()
                if subdomain.endswith(self.target):
                    subdomains.add(subdomain)
            return subdomains
        except Exception as e:
            logging.error(f"dnsdumpster enumeration failed: {str(e)}")
            return set()

    def enumerate_subdomains(self, target: str) -> Set[str]:
        """Enumerate subdomains using DNS brute force."""
        subdomains = set()
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'ns3', 'ns4', 'admin', 'forum', 'blog', 'dev', 'staging', 'test', 'api',
            'secure', 'vpn', 'm', 'mobile', 'shop', 'store', 'app', 'beta', 'stage',
            'portal', 'support', 'help', 'docs', 'status', 'cdn', 'static', 'media',
            'img', 'images', 'img', 'js', 'css', 'assets', 'files', 'download',
            'upload', 'backup', 'db', 'sql', 'mysql', 'oracle', 'postgres', 'redis',
            'cache', 'search', 'auth', 'login', 'signup', 'register', 'account',
            'profile', 'user', 'users', 'admin', 'administrator', 'root', 'system',
            'sys', 'server', 'servers', 'service', 'services', 'api', 'apis', 'rest',
            'soap', 'xml', 'json', 'graphql', 'rpc', 'ws', 'wss', 'socket', 'sockets',
            'stream', 'streaming', 'live', 'video', 'audio', 'media', 'cdn', 'static',
            'assets', 'files', 'download', 'upload', 'backup', 'db', 'sql', 'mysql',
            'oracle', 'postgres', 'redis', 'cache', 'search', 'auth', 'login', 'signup',
            'register', 'account', 'profile', 'user', 'users', 'admin', 'administrator',
            'root', 'system', 'sys', 'server', 'servers', 'service', 'services'
        ]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[blue]Enumerating subdomains...", total=len(common_subdomains))
            
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{target}"
                    try:
                        answers = dns.resolver.resolve(full_domain, 'A')
                        if answers:
                            subdomains.add(full_domain)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                    except Exception as e:
                        if self.verbose:
                            logging.debug(f"Error resolving {full_domain}: {str(e)}")
                except Exception as e:
                    if self.verbose:
                        logging.debug(f"Error processing {subdomain}: {str(e)}")
                progress.update(task, advance=1)
        
        return subdomains

    def subdomain_enumeration(self, virustotal_api_key: str = None, otx_api_key: str = None) -> List[str]:
        """Enumerate subdomains using multiple sources."""
        console.print("[bold blue]Enumerating subdomains...[/bold blue]")
        
        # First try DNS brute force
        dns_subdomains = self.enumerate_subdomains(self.target)
        
        # Then try external sources
        enum_functions = [
            self.enumerate_from_crtsh,
            self.enumerate_from_hackertarget,
            self.enumerate_from_threatcrowd,
            self.enumerate_from_dnsdumpster,
            lambda: self.enumerate_from_otx(otx_api_key)
        ]
        
        # Run enumeration in parallel
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(lambda f: f(), enum_functions))
        
        # Combine all results
        all_subdomains = dns_subdomains.copy()
        for subdomains in results:
            all_subdomains.update(subdomains)
        
        # Filter and clean subdomains
        filtered_subdomains = set()
        for subdomain in all_subdomains:
            # Clean the subdomain
            subdomain = subdomain.strip().lower()
            
            # Remove wildcards
            if subdomain.startswith('*.'):
                subdomain = subdomain[2:]
            
            # Remove any trailing dots
            subdomain = subdomain.rstrip('.')
            
            # Only add if it's a valid subdomain of our target
            if subdomain.endswith(self.target) and subdomain != self.target:
                filtered_subdomains.add(subdomain)
        
        # Sort the results
        sorted_subdomains = sorted(list(filtered_subdomains))
        
        # Log the results
        if self.verbose:
            console.print(f"[green]Found {len(sorted_subdomains)} unique subdomains[/green]")
            for subdomain in sorted_subdomains:
                console.print(f"[blue]  - {subdomain}[/blue]")
        
        return sorted_subdomains

    def port_scan(self, ports: str = "1-1000") -> dict:
        """Perform port scanning using nmap."""
        self.logger.info(f"Starting port scan for {self.target} on ports {ports}")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[blue]Performing port scan...", total=None)
            
            try:
                # Check for Nmap installation
                nmap_paths = [
                    "nmap.exe",  # Current directory
                    r"C:\Program Files (x86)\Nmap\nmap.exe",  # 32-bit Windows
                    r"C:\Program Files\Nmap\nmap.exe",  # 64-bit Windows
                    "/usr/bin/nmap",  # Linux
                    "/usr/local/bin/nmap"  # macOS
                ]
                
                nmap_found = False
                for path in nmap_paths:
                    if os.path.exists(path):
                        nmap_found = True
                        self.logger.debug(f"Found Nmap at: {path}")
                        break
                
                if not nmap_found:
                    error_msg = (
                        "Nmap not found. Please install Nmap:\n"
                        "1. Download from: https://nmap.org/download.html\n"
                        "2. Run the installer\n"
                        "3. Add Nmap to your system PATH"
                    )
                    self.logger.error("Nmap not found in system")
                    console.print(f"[bold red]{error_msg}[/bold red]")
                    self.results['active_recon']['port_scan'] = {"error": error_msg}
                    progress.update(task, description="[red]Port scan failed - Nmap not installed")
                    return {"error": error_msg}
                
                # Initialize Nmap scanner
                nm = nmap.PortScanner()
                
                # Perform the scan
                self.logger.info(f"Starting Nmap scan on ports {ports}")
                console.print(f"[yellow]Scanning ports {ports}...[/yellow]")
                nm.scan(self.target, ports, arguments='-sV -sS -T4')
                
                results = {}
                for host in nm.all_hosts():
                    results[host] = {
                        "state": nm[host].state(),
                        "ports": {}
                    }
                    
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            results[host]["ports"][port] = {
                                "state": nm[host][proto][port]["state"],
                                "service": nm[host][proto][port].get("name", "unknown"),
                                "product": nm[host][proto][port].get("product", "unknown"),
                                "version": nm[host][proto][port].get("version", "unknown")
                            }
                
                self.logger.info("Port scan completed successfully")
                self.logger.debug(f"Port scan results: {results}")
                self.results['active_recon']['port_scan'] = results
                progress.update(task, description="[green]Port scan completed")
                return results
                
            except Exception as e:
                error_msg = f"Port scanning failed: {str(e)}"
                self.logger.error(error_msg, exc_info=True)
                self.results['active_recon']['port_scan'] = {"error": error_msg}
                progress.update(task, description="[red]Port scan failed")
                return {"error": error_msg}

    def _parse_ports(self, ports: str) -> List[int]:
        """Parse port string into list of integers."""
        if not ports or ports.lower() == 'default':
            return [21, 22, 23, 25, 80, 443, 3306, 3389, 8080]
        
        port_list = []
        try:
            # Handle comma-separated ports
            if ',' in ports:
                for port in ports.split(','):
                    port = port.strip()
                    if port.isdigit():
                        port_list.append(int(port))
            
            # Handle port ranges (e.g., "1-1000")
            elif '-' in ports:
                start, end = map(int, ports.split('-'))
                port_list.extend(range(start, end + 1))
            
            # Handle single port
            elif ports.isdigit():
                port_list.append(int(ports))
            
        except Exception as e:
            logging.error(f"Error parsing ports: {str(e)}")
            return []
        
        return sorted(list(set(port_list)))  # Remove duplicates and sort

    def detect_technologies(self, url: str) -> Dict[str, List[str]]:
        """Detect technologies using multiple methods."""
        self.logger.info(f"Starting technology detection for {url}")
        try:
            console.print("[bold blue]Detecting technologies...[/bold blue]")
            results = {}
            
            # Try Wappalyzer first
            if WAPPALYZER_AVAILABLE:
                try:
                    self.logger.debug("Attempting Wappalyzer detection")
                    wappalyzer = Wappalyzer.latest()
                    webpage = WebPage.new_from_url(url, verify=False)
                    wapp_results = wappalyzer.analyze_with_versions(webpage)
                    if wapp_results:
                        results.update(wapp_results)
                        self.logger.info("Wappalyzer detection successful")
                        self.logger.debug(f"Wappalyzer results: {wapp_results}")
                        console.print("[green]Wappalyzer detection successful[/green]")
                except Exception as e:
                    self.logger.warning(f"Wappalyzer detection failed: {str(e)}")
                    console.print("[yellow]Wappalyzer detection failed, falling back to other methods[/yellow]")
            
            # Try whatweb-like detection
            self.logger.debug("Attempting whatweb-like detection")
            whatweb_results = self._whatweb_detection(url)
            if whatweb_results:
                results.update(whatweb_results)
                self.logger.info("Whatweb-like detection successful")
                self.logger.debug(f"Whatweb results: {whatweb_results}")
                console.print("[green]Whatweb-like detection successful[/green]")
            
            # Basic technology detection as fallback
            self.logger.debug("Attempting basic technology detection")
            basic_results = self._basic_tech_detection(url)
            if basic_results:
                results.update(basic_results)
                self.logger.info("Basic technology detection successful")
                self.logger.debug(f"Basic detection results: {basic_results}")
                console.print("[green]Basic technology detection successful[/green]")
            
            if not results:
                self.logger.warning("No technologies detected")
                console.print("[yellow]No technologies detected[/yellow]")
            else:
                self.logger.info(f"Detected {len(results)} technology categories")
                console.print(f"[green]Detected {len(results)} technology categories[/green]")
            
            return results
        except Exception as e:
            self.logger.error(f"Technology detection failed: {str(e)}", exc_info=True)
            console.print(f"[red]Technology detection failed: {str(e)}[/red]")
            return {}

    def _whatweb_detection(self, url: str) -> Dict[str, List[str]]:
        """Perform whatweb-like technology detection."""
        results = {}
        try:
            # Try HTTPS first, fall back to HTTP if needed
            try:
                response = requests.get(url, verify=False, timeout=10)
            except requests.exceptions.SSLError:
                url = url.replace('https://', 'http://')
                response = requests.get(url, verify=False, timeout=10)
            
            headers = response.headers
            content = response.text.lower()
            
            # Server detection
            if 'server' in headers:
                results['Server'] = [headers['server']]
            
            # Framework detection
            frameworks = {
                'Django': ['django', 'csrfmiddlewaretoken'],
                'Flask': ['flask', 'werkzeug'],
                'Rails': ['rails', 'ruby'],
                'Laravel': ['laravel', 'csrf-token'],
                'Express': ['express', 'node'],
                'ASP.NET': ['asp.net', 'aspxauth'],
                'PHP': ['php', 'phpsessid'],
                'WordPress': ['wordpress', 'wp-content'],
                'Drupal': ['drupal', 'drupal.settings'],
                'Joomla': ['joomla', 'joomla!'],
                'Magento': ['magento', 'magento_version'],
                'Shopify': ['shopify', 'shopify.theme'],
                'React': ['react', 'reactjs'],
                'Angular': ['angular', 'ng-'],
                'Vue.js': ['vue', 'vuejs'],
                'jQuery': ['jquery', 'jquery.min.js'],
                'Bootstrap': ['bootstrap', 'bootstrap.min.css'],
                'Tailwind': ['tailwind', 'tailwindcss'],
                'Material-UI': ['material-ui', 'mui'],
                'Font Awesome': ['font-awesome', 'fa-']
            }
            
            for framework, indicators in frameworks.items():
                if any(indicator in content for indicator in indicators):
                    results['Framework'] = results.get('Framework', []) + [framework]
            
            # CMS detection
            cms_indicators = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Drupal': ['drupal.js', 'drupal.css'],
                'Joomla': ['joomla', 'com_content'],
                'Magento': ['magento', 'skin/frontend'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'WooCommerce': ['woocommerce', 'wc-api'],
                'Ghost': ['ghost', 'ghost.min.js'],
                'Squarespace': ['squarespace', 'static.squarespace.com'],
                'Wix': ['wix', 'wixsite.com'],
                'Webflow': ['webflow', 'webflow.com']
            }
            
            for cms, indicators in cms_indicators.items():
                if any(indicator in content for indicator in indicators):
                    results['CMS'] = results.get('CMS', []) + [cms]
            
            # Security headers
            security_headers = {
                'X-Frame-Options': 'X-Frame-Options',
                'X-XSS-Protection': 'X-XSS-Protection',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'Content-Security-Policy': 'Content-Security-Policy',
                'Strict-Transport-Security': 'Strict-Transport-Security',
                'X-Permitted-Cross-Domain-Policies': 'X-Permitted-Cross-Domain-Policies',
                'Referrer-Policy': 'Referrer-Policy',
                'Feature-Policy': 'Feature-Policy',
                'Permissions-Policy': 'Permissions-Policy'
            }
            
            for header, value in security_headers.items():
                if header in headers:
                    results['Security'] = results.get('Security', []) + [f"{header}: {headers[header]}"]
            
            # Analytics and tracking
            analytics = {
                'Google Analytics': ['google-analytics.com', 'ga.js'],
                'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
                'Facebook Pixel': ['connect.facebook.net', 'fbevents.js'],
                'Hotjar': ['hotjar.com', 'hotjar.js'],
                'Mixpanel': ['mixpanel.com', 'mixpanel.js'],
                'Segment': ['segment.com', 'analytics.js'],
                'Piwik': ['piwik.js', 'matomo.js'],
                'New Relic': ['newrelic.com', 'nr.js'],
                'Sentry': ['sentry.io', 'sentry.js'],
                'Cloudflare': ['cloudflare.com', 'cf.js']
            }
            
            for service, indicators in analytics.items():
                if any(indicator in content for indicator in indicators):
                    results['Analytics'] = results.get('Analytics', []) + [service]
            
            return results
        except Exception as e:
            logging.error(f"Whatweb detection failed: {str(e)}")
            return {}

    def _basic_tech_detection(self, url: str) -> Dict[str, List[str]]:
        """Basic technology detection using headers and response analysis."""
        tech = {}
        try:
            # Try HTTPS first, fall back to HTTP if needed
            try:
                response = requests.get(url, verify=False, timeout=10)
            except requests.exceptions.SSLError:
                url = url.replace('https://', 'http://')
                response = requests.get(url, verify=False, timeout=10)
            
            headers = response.headers
            
            # Server detection
            if 'server' in headers:
                tech['Server'] = [headers['server']]
            
            # Framework detection
            if 'x-powered-by' in headers:
                tech['Framework'] = [headers['x-powered-by']]
            
            # CMS detection
            if 'x-generator' in headers:
                tech['CMS'] = [headers['x-generator']]
            
            # Security headers
            security_headers = ['x-frame-options', 'x-xss-protection', 'x-content-type-options']
            for header in security_headers:
                if header in headers:
                    tech['Security'] = tech.get('Security', []) + [f"{header}: {headers[header]}"]
            
            # Content-Type detection
            if 'content-type' in headers:
                tech['Content-Type'] = [headers['content-type']]
            
            return tech
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed during basic technology detection: {str(e)}")
            return {}
        except Exception as e:
            logging.error(f"Basic technology detection failed: {str(e)}")
            return {}

    def perform_banner_grab(self, ports: str) -> Dict[str, Any]:
        """Perform banner grabbing on specified ports."""
        results = {}
        port_list = self._parse_ports(ports)
        
        if not port_list:
            logging.error("No valid ports specified for banner grabbing")
            return results
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task("Grabbing banners...", total=len(port_list))
            
            for port in port_list:
                try:
                    banner = self.banner_grab(port)
                    if banner:
                        results[str(port)] = banner
                        if self.verbose:
                            console.print(f"[green]Port {port}: {banner}[/green]")
                except Exception as e:
                    if self.verbose:
                        logging.error(f"Error grabbing banner from port {port}: {str(e)}")
                progress.update(task, advance=1)
        
        return results

    def banner_grab(self, port: int) -> Optional[str]:
        """Attempt to grab banner from a specific port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            # Protocol-specific requests
            if port == 80 or port == 443:
                protocol = "https" if port == 443 else "http"
                try:
                    response = requests.get(f"{protocol}://{self.target}:{port}", timeout=2, verify=False)
                    return f"HTTP/{response.status_code} {response.reason}\nServer: {response.headers.get('Server', 'Unknown')}"
                except:
                    return None
                
            elif port == 21:  # FTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.send(b"USER anonymous\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return f"{banner}\n{response}"
            
            elif port == 22:  # SSH
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
            
            elif port == 23:  # Telnet
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
            
            elif port == 25:  # SMTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.send(b"HELO example.com\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return f"{banner}\n{response}"
            
            elif port == 3306:  # MySQL
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
            
            elif port == 3389:  # RDP
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
            
            else:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
            
        except Exception as e:
            if self.verbose:
                logging.error(f"Error grabbing banner from port {port}: {str(e)}")
            return None
        finally:
            sock.close()

    def generate_report(self, results: dict, format: str = "txt"):
        """Generate a comprehensive report of all findings."""
        if format == "html":
            self._generate_html_report(results)
        else:
            self._generate_txt_report(results)

    def _generate_txt_report(self, results: dict):
        """Generate a text-based report with command-line focused information."""
        report_file = self.output_dir / f"recon_report_{self.target}_{self.timestamp}.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write(f"Recon-IT Report for {self.target}\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # WHOIS Information
            if 'whois' in results and results['whois']:
                f.write("WHOIS Information\n")
                f.write("-" * 80 + "\n")
                if isinstance(results['whois'], dict):
                    for key, value in results['whois'].items():
                        if isinstance(value, list):
                            f.write(f"{key}:\n")
                            for item in value:
                                f.write(f"  - {item}\n")
                        else:
                            f.write(f"{key}: {value}\n")
                f.write("\n")
            
            # DNS Information
            if 'dns' in results and results['dns']:
                f.write("DNS Records\n")
                f.write("-" * 80 + "\n")
                for record_type, records in results['dns'].items():
                    if records:  # Only show if there are records
                        f.write(f"{record_type} Records:\n")
                        for record in records:
                            f.write(f"  - {record}\n")
                        f.write("\n")
            
            # Subdomains
            if 'subdomains' in results and results['subdomains']:
                f.write("Subdomains\n")
                f.write("-" * 80 + "\n")
                for subdomain in sorted(results['subdomains']):
                    f.write(f"- {subdomain}\n")
                f.write("\n")
            
            # Port Scan Results
            if 'port_scan' in results and results['port_scan'] and not isinstance(results['port_scan'], dict):
                f.write("Port Scan Results\n")
                f.write("-" * 80 + "\n")
                for host, data in results['port_scan'].items():
                    if isinstance(data, dict):
                        f.write(f"Host: {host} ({data.get('state', 'unknown')})\n")
                        if 'ports' in data:
                            for port in sorted(data['ports'].keys(), key=int):
                                port_data = data['ports'][port]
                                if port_data.get('state') == 'open':
                                    f.write(f"  Port {port}: {port_data.get('service', 'unknown')}")
                                    if port_data.get('product'):
                                        f.write(f" ({port_data['product']} {port_data.get('version', '')})")
                                    f.write("\n")
                f.write("\n")
            
            # Banner Grab Results
            if 'banner_grab' in results and results['banner_grab']:
                f.write("Banner Grab Results\n")
                f.write("-" * 80 + "\n")
                for port, banner in sorted(results['banner_grab'].items(), key=lambda x: int(x[0])):
                    if banner:
                        f.write(f"Port {port}:\n")
                        f.write(f"  {banner}\n\n")
            
            # Technologies
            if 'technologies' in results and results['technologies']:
                f.write("Detected Technologies\n")
                f.write("-" * 80 + "\n")
                
                # Group technologies by category
                categories = {
                    'Server': [],
                    'Framework': [],
                    'CMS': [],
                    'Security': [],
                    'Analytics': [],
                    'Other': []
                }
                
                for tech, versions in sorted(results['technologies'].items()):
                    # Determine category
                    category = 'Other'
                    for cat in categories.keys():
                        if tech in categories[cat] or any(tech.lower() in v.lower() for v in categories[cat]):
                            category = cat
                            break
                    
                    # Add to appropriate category
                    if versions:
                        categories[category].append(f"{tech}: {', '.join(versions)}")
                    else:
                        categories[category].append(tech)
                
                # Write categorized results
                for category, techs in categories.items():
                    if techs:
                        f.write(f"\n{category}:\n")
                        for tech in sorted(techs):
                            f.write(f"  - {tech}\n")
                
                f.write("\n")
            
            # Command Summary
            f.write("Command Summary\n")
            f.write("-" * 80 + "\n")
            commands = []
            if 'whois' in results:
                commands.append("WHOIS lookup")
            if 'dns' in results:
                commands.append("DNS enumeration")
            if 'subdomains' in results:
                commands.append("Subdomain enumeration")
            if 'port_scan' in results:
                commands.append("Port scanning")
            if 'banner_grab' in results:
                commands.append("Banner grabbing")
            if 'technologies' in results:
                commands.append("Technology detection")
            
            for cmd in commands:
                f.write(f"- {cmd}\n")
            
            # Footer
            f.write("\n" + "=" * 80 + "\n")
            f.write("Report generated by Recon-IT\n")
            f.write("=" * 80 + "\n")

    def _generate_html_report(self, results: dict):
        """Generate an HTML-based report with command-line focused information."""
        report_file = self.output_dir / f"recon_report_{self.target}_{self.timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Recon-IT Report for {self.target}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    border-radius: 5px;
                }}
                h1, h2 {{
                    color: #2c3e50;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }}
                .section {{
                    margin: 20px 0;
                    padding: 15px;
                    background-color: #fff;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }}
                pre {{
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 3px;
                    overflow-x: auto;
                }}
                .timestamp {{
                    color: #7f8c8d;
                    font-size: 0.9em;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Recon-IT Report for {self.target}</h1>
                <p class="timestamp">Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="section">
                    <h2>Command Summary</h2>
                    <ul>
                        {''.join(f'<li>{cmd}</li>' for cmd in [
                            "WHOIS lookup" if 'whois' in results else None,
                            "DNS enumeration" if 'dns' in results else None,
                            "Subdomain enumeration" if 'subdomains' in results else None,
                            "Port scanning" if 'port_scan' in results else None,
                            "Banner grabbing" if 'banner_grab' in results else None,
                            "Technology detection" if 'technologies' in results else None
                        ] if cmd)}
                    </ul>
                </div>
                
                <div class="section">
                    <h2>WHOIS Information</h2>
                    <pre>{json.dumps(results.get('whois', {}), indent=2)}</pre>
                </div>
                
                <div class="section">
                    <h2>DNS Records</h2>
                    <pre>{json.dumps(results.get('dns', {}), indent=2)}</pre>
                </div>
                
                <div class="section">
                    <h2>Subdomains</h2>
                    <ul>
                        {''.join(f'<li>{subdomain}</li>' for subdomain in sorted(results.get('subdomains', [])))}
                    </ul>
                </div>
                
                <div class="section">
                    <h2>Port Scan Results</h2>
                    <pre>{json.dumps(results.get('port_scan', {}), indent=2)}</pre>
                </div>
                
                {f'''
                <div class="section">
                    <h2>Banner Grab Results</h2>
                    <pre>{json.dumps(results.get('banner_grab', {}), indent=2)}</pre>
                </div>
                ''' if 'banner_grab' in results else ''}
                
                {f'''
                <div class="section">
                    <h2>Detected Technologies</h2>
                    <pre>{json.dumps(results.get('technologies', {}), indent=2)}</pre>
                </div>
                ''' if 'technologies' in results else ''}
                
                <div class="section">
                    <p>Report generated by Recon-IT</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        console.print(f"[bold green]HTML report generated: {report_file}[/bold green]")

def run_interactive_menu():
    """Run the tool in interactive menu mode."""
    rprint(Panel(BANNER))
    scan_type = display_menu()
    target = input("Enter target domain or IP: ")
    
    if not target:
        console.print("[red]Error: Target is required[/red]")
        sys.exit(1)
    
    # Set default options based on scan type
    options = {
        'whois': False,
        'dns': False,
        'subdomains': False,
        'ports': "",
        'banner': False,
        'tech': False,
        'format': "txt",
        'verbose': False
    }
    
    if scan_type == 'whois':
        options['whois'] = True
    elif scan_type == 'dns':
        options['dns'] = True
    elif scan_type == 'subdomains':
        options['subdomains'] = True
    elif scan_type == 'passive':
        options['whois'] = options['dns'] = options['subdomains'] = True
    elif scan_type == 'ports':
        options['ports'] = input("Enter port range (default: 1-1000): ") or "1-1000"
    elif scan_type == 'banner':
        options['banner'] = True
        options['ports'] = input("Enter ports to grab banners from (comma-separated, default: 21,22,23,25,80,443,3306,3389,8080): ") or "21,22,23,25,80,443,3306,3389,8080"
    elif scan_type == 'tech':
        options['tech'] = True
    elif scan_type == 'active':
        options['ports'] = input("Enter port range (default: 1-1000): ") or "1-1000"
        options['banner'] = options['tech'] = True
    elif scan_type == 'full':
        options['whois'] = options['dns'] = options['subdomains'] = True
        options['ports'] = input("Enter port range (default: 1-1000): ") or "1-1000"
        options['banner'] = options['tech'] = True
    elif scan_type == 'custom':
        options['whois'] = input("Perform WHOIS lookup? (y/n): ").lower() == 'y'
        options['dns'] = input("Perform DNS enumeration? (y/n): ").lower() == 'y'
        options['subdomains'] = input("Enumerate subdomains? (y/n): ").lower() == 'y'
        options['ports'] = input("Enter port range (default: 1-1000): ") or "1-1000"
        options['banner'] = input("Perform banner grabbing? (y/n): ").lower() == 'y'
        options['tech'] = input("Detect technologies? (y/n): ").lower() == 'y'
        options['format'] = input("Enter report format (txt/html, default: txt): ").lower() or "txt"
        options['verbose'] = input("Enable verbose logging? (y/n): ").lower() == 'y'
    
    return target, options

@app.command(no_args_is_help=False)
def main(
    target: str = typer.Argument(
        None,
        help="Target domain or IP address to scan",
        show_default=False
    ),
    interactive: bool = typer.Option(
        True,
        "--interactive",
        "-i",
        help="Launch interactive menu mode",
        show_default=True
    ),
    whois: bool = typer.Option(
        False,
        "--whois",
        "-w",
        help="Perform WHOIS lookup",
        show_default=False
    ),
    dns: bool = typer.Option(
        False,
        "--dns",
        "-d",
        help="Perform DNS enumeration",
        show_default=False
    ),
    subdomains: bool = typer.Option(
        False,
        "--subdomains",
        "-s",
        help="Enumerate subdomains",
        show_default=False
    ),
    passive: bool = typer.Option(
        False,
        "--passive",
        "-p",
        help="Perform full passive scan (WHOIS + DNS + Subdomains)",
        show_default=False
    ),
    ports: str = typer.Option(
        None,
        "--ports",
        help="Port range to scan (e.g., '80,443,8080' or '1-1000')",
        show_default=False
    ),
    banner: bool = typer.Option(
        False,
        "--banner",
        "-b",
        help="Perform banner grabbing",
        show_default=False
    ),
    tech: bool = typer.Option(
        False,
        "--tech",
        "-t",
        help="Detect technologies",
        show_default=False
    ),
    active: bool = typer.Option(
        False,
        "--active",
        "-a",
        help="Perform full active scan (Ports + Banner + Tech)",
        show_default=False
    ),
    full: bool = typer.Option(
        False,
        "--full",
        "-f",
        help="Perform full reconnaissance (All modules)",
        show_default=False
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
        show_default=False
    ),
    output: str = typer.Option(
        "reports",
        "--output",
        "-o",
        help="Output directory for reports",
        show_default=True
    ),
    format: str = typer.Option(
        "txt",
        "--format",
        help="Report format (txt or html)",
        show_default=True
    )
):
    """Recon-IT: A comprehensive reconnaissance tool for penetration testing.
    
    This tool performs various reconnaissance tasks including WHOIS lookup,
    DNS enumeration, subdomain enumeration, port scanning, banner grabbing,
    and technology detection.
    
    The tool can be used in two modes:
    1. Interactive Menu Mode (default)
       - Provides a user-friendly menu interface
       - Guides you through the scanning process
       - Offers all features with clear options
    
    2. Command Line Mode
       - For automated or scripted usage
       - Use --no-interactive to disable menu
    
    Examples:
        # Launch interactive menu
        python recon_it.py
        
        # WHOIS lookup
        python recon_it.py example.com --whois
        
        # DNS enumeration
        python recon_it.py example.com --dns
        
        # Full passive scan
        python recon_it.py example.com --passive
        
        # Port scanning
        python recon_it.py example.com --ports 1-1000
        
        # Full active scan
        python recon_it.py example.com --active
        
        # Full reconnaissance
        python recon_it.py example.com --full
    """
    
    # Display banner
    rprint(Panel(BANNER))
    
    # Check if any command-line options are specified
    has_cli_options = any([
        whois, dns, subdomains, passive, ports is not None,
        banner, tech, active, full
    ])
    
    # If no target is provided or no CLI options specified, show menu
    if target is None or (interactive and not has_cli_options):
        target, options = run_interactive_menu()
        if target is None:
            console.print("[red]Error: Target is required[/red]")
            sys.exit(1)
    else:
        # Command line mode
        if not target:
            console.print("[red]Error: Target is required[/red]")
            sys.exit(1)
            
        # Clean up target URL/domain
        target = target.strip().lower()
        if target.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            target = urlparse(target).netloc
        if target.startswith('www.'):
            target = target[4:]
        
        # Set options based on command line arguments
        options = {
            'whois': whois,
            'dns': dns,
            'subdomains': subdomains,
            'ports': ports,
            'banner': banner,
            'tech': tech,
            'format': format,
            'verbose': verbose,
            'output': output
        }
        
        # Handle combined scan options
        if passive:
            options['whois'] = options['dns'] = options['subdomains'] = True
        if active:
            options['ports'] = ports or "1-1000"
            options['banner'] = options['tech'] = True
        if full:
            options['whois'] = options['dns'] = options['subdomains'] = True
            options['ports'] = ports or "1-1000"
            options['banner'] = options['tech'] = True
    
    # Initialize ReconIT with options
    recon = ReconIT(
        target,
        output_dir=options.get('output', 'reports'),
        threads=10,
        verbose=options.get('verbose', False)
    )
    
    results = {}
    
    # Execute selected modules
    if options.get('whois'):
        console.print("[bold blue]Performing WHOIS lookup...[/bold blue]")
        results['whois'] = recon.whois_lookup()
    
    if options.get('dns'):
        console.print("[bold blue]Performing DNS enumeration...[/bold blue]")
        results['dns'] = recon.dns_enumeration()
    
    if options.get('subdomains'):
        console.print("[bold blue]Enumerating subdomains...[/bold blue]")
        results['subdomains'] = recon.subdomain_enumeration()
    
    if options.get('ports'):
        console.print("[bold blue]Performing port scan...[/bold blue]")
        results['port_scan'] = recon.port_scan(options['ports'])
    
    if options.get('banner'):
        console.print("[bold blue]Performing banner grabbing...[/bold blue]")
        results['banner_grab'] = recon.perform_banner_grab(options.get('ports', "21,22,23,25,80,443,3306,3389,8080"))
    
    if options.get('tech'):
        console.print("[bold blue]Detecting technologies...[/bold blue]")
        try:
            url = f"https://{target}"
            try:
                results['technologies'] = recon.detect_technologies(url)
            except requests.exceptions.RequestException:
                url = f"http://{target}"
                results['technologies'] = recon.detect_technologies(url)
        except Exception as e:
            logging.error(f"Technology detection failed: {str(e)}")
            results['technologies'] = {}
    
    # Generate report
    recon.generate_report(results, options.get('format', 'txt'))
    console.print("[bold green]Reconnaissance completed successfully![/bold green]")

if __name__ == "__main__":
    try:
        app()
    except Exception as e:
        if "Missing parameter: target" in str(e):
            # If no target provided, switch to interactive menu
            main(None)
        else:
            raise e