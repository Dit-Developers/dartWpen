# dartWpen

```bash
       __           __ _       __               
  ____/ /___ ______/ /| |     / /___  ___  ____ 
 / __  / __ `/ ___/ __/ | /| / / __ \/ _ \/ __ \
/ /_/ / /_/ / /  / /_ | |/ |/ / /_/ /  __/ / / /
\__,_/\__,_/_/   \__/ |__/|__/ .___/\___/_/ /_/
                        https://msusuport.vercel.app/
```

A simple Dart-based web security scanner that performs various security checks on a target URL.

## Features
- HTTP Headers Analysis
- Directory Enumeration (using SecLists)
- Subdomain Discovery (via crt.sh)
- Basic SQL Injection Testing
- XSS Vulnerability Detection
- Port Scanning (Common Ports)
- Security Headers Check

## Prerequisites
- Dart SDK installed
- Internet connection for fetching wordlists and subdomains

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/Dit-Developers/dartWpen.git
   cd dartWpen
   ```
2. Install dependencies (if needed):
   ```sh
   dart pub get
   ```

## Usage
Run the script using Dart:
```sh
  dart scanner.dart
```

Enter the target URL when prompted (e.g., `http://example.com`). The script will perform various security checks and display the results.

## Code Overview
The script performs the following tasks:
1. **HTTP Headers Analysis** - Retrieves and displays HTTP headers.
2. **Directory Enumeration** - Checks for common directories using SecLists.
3. **Subdomain Discovery** - Uses crt.sh to find subdomains.
4. **SQL Injection Testing** - Sends common SQL payloads to test for vulnerabilities.
5. **XSS Testing** - Checks for Cross-Site Scripting vulnerabilities.
6. **Port Scanning** - Scans common ports (21, 22, 80, 443, 3306, 8080).
7. **Security Headers Check** - Identifies missing security headers.

## Disclaimer
This tool is for educational and security testing purposes only. Unauthorized scanning of websites without permission is illegal. Use responsibly.

## License
MIT License

## Author
Muhammad Sudais Usmani

