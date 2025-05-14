Description
Sigma Ghost is a multi-purpose offensive security tool designed for black hat hacking and attacking testing. It combines three critical modules in a single intuitive GUI:

SSH Bruteforce: Credential cracking with proxy support

Port Scanner: Fast multi-threaded port discovery

Web Vulnerability Scanner: Automated detection of SQLi/XSS/Directory Traversal

Built with a retro matrix-style terminal interface, it provides real-time feedback while maintaining a stealthy footprint. Ideal for security researchers and red teamers.

Installation
Requirements:

Python 3.6+

Linux/macOS (Windows not recommended)

PIP COMMMAND ===> # Install dependencies
pip install paramiko requests beautifulsoup4 colorama

# For GUI support (if not installed)
sudo apt-get install python3-tk  # Debian/Ubuntu

Usage: python3 sigma-run.py

Key Features:

1: SSH Bruteforce

Load username/password wordlists

Proxy rotation for anonymity

Adjustable threads/timeout

2: Port Scanner

Custom port ranges (1-65535)

Multi-threaded scanning

Instant open port detection

3: Web Vulnerability Scanner

Built-in & custom payload support

Automatic site crawling

Checks for:

SQL Injection

Cross-Site Scripting (XSS)

Directory Traversal

Sensitive file exposure


Disclaimer
❗ This tool is not for authorized security testing and educational purposes only.
❗ Always use it against systems you don't own or have permission to test.
❗ The developers assume no liability for misuse or damage caused by this tool.
