![image](https://github.com/user-attachments/assets/bc8bbcdd-7a4b-46b4-86f6-789f337c7571)# Recon-IT: A Comprehensive Reconnaissance Tool

Recon-IT is a powerful reconnaissance tool designed for penetration testing and security assessments. It combines both passive and active reconnaissance techniques to gather comprehensive information about target domains.

## Features

### Passive Reconnaissance
- WHOIS lookup
- DNS enumeration (A, MX, TXT, NS, CNAME, SOA records)
- Subdomain enumeration using multiple sources:
  - Certificate Transparency (crt.sh)
  - AlienVault OTX
  - HackerTarget
  - ThreatCrowd
  - DNSDumpster

### Active Reconnaissance
- Port scanning (via Nmap)
- Banner grabbing
- Technology detection (using Wappalyzer)

### Reporting
- Generate detailed reports in TXT or HTML format
- Include timestamps and IP resolution details
- Comprehensive summary of findings

## Installation

### Prerequisites
- Python 3.7+
- Nmap (for port scanning)
- Required Python packages (install via pip):
  ```bash
  pip install -r requirements.txt
  ```

### Quick Install
```bash
git clone https://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@github.com/Kamii221/Recon-IT
cd recon-it
pip install -r requirements.txt

python3 -m venv venv
source venv/bin/activate

```

## Usage

### Basic Usage
```bash
python recon_it.py example.com
```

### Command Line Options
```bash
python recon_it.py [OPTIONS] TARGET

Options:
  --quick, -q           Perform quick scan (WHOIS + DNS)
  --full, -f            Perform full scan (all modules)
  --whois, -w           Perform WHOIS lookup
  --dns, -d             Perform DNS enumeration
  --subdomains, -s      Enumerate subdomains
  --ports, -p TEXT      Port range to scan (e.g., '80,443,8080' or '1-1000')
  --output, -o TEXT     Output directory for reports
  --threads, -t INTEGER Number of threads for subdomain enumeration
  --virustotal-key TEXT VirusTotal API key for additional subdomain enumeration
  --otx-key TEXT        AlienVault OTX API key for additional subdomain enumeration
  --format TEXT         Report format (txt or html)
  --verbose, -v         Enable verbose logging
  --banner, -b          Perform banner grabbing
  --tech                Detect technologies
```

### Examples

1. Quick scan:
```bash
python recon_it.py example.com --quick
```

2. Full scan:
```bash
python recon_it.py example.com --full
```

3. Custom scan:
```bash
python recon_it.py example.com --whois --dns --ports 80,443,8080
```

4. Banner grabbing:
```bash
python recon_it.py example.com --banner --ports 21,22,80,443
```

## Docker Support

Build and run using Docker:
```bash
docker build -t recon-it .
docker run -v $(pwd)/reports:/app/reports recon-it example.com
```

## Output

Reports are generated in the specified output directory (default: `reports/`) with the following naming convention:
- Text report: `recon_report_example.com_YYYYMMDD_HHMMSS.txt`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before performing any security testing. 
