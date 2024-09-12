# FastVulnVerify

```
⠄⠄⠄⣾⣿⠿⠿⠶⠿⢿⣿⣿⣿⣿⣦⣤⣄⢀⡅⢠⣾⣛⡉⠄⠄⠄⠸⢀⣿
⠄⠄⢀⡋⣡⣴⣶⣶⡀⠄⠄⠙⢿⣿⣿⣿⣿⣿⣴⣿⣿⣿⢃⣤⣄⣀⣥⣿⣿
⠄⠄⢸⣇⠻⣿⣿⣿⣧⣀⢀⣠⡌⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⣿⣿⣿       FastVulnVerify
⠄⢀⢸⣿⣷⣤⣤⣤⣬⣙⣛⢿⣿⣿⣿⣿⣿⣿⡿⣿⣿⡍⠄⠄⢀⣤⣄⠉⠋       Vulnerability Analysis & Fast Verification Script BETA
⠄⣼⣖⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⢇⣿⣿⡷⠶⠶⢿⣿⣿⠇⢀       For Penetration Testers & Bug Hunters
⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣽⣿⣿⣿⡇⣿⣿⣿⣿⣿⣿⣷⣶⣥⣴⣿       Developped ßy 0xhav0c
⢀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟
⢸⣿⣦⣌⣛⣻⣿⣿⣧⠙⠛⠛⡭⠅⠒⠦⠭⣭⡻⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃
⠘⣿⣿⣿⣿⣿⣿⣿⣿⡆⠄⠄⠄⠄⠄⠄⠄⠄⠹⠈⢋⣽⣿⣿⣿⣿⣵⣾⠃
⠄⠘⣿⣿⣿⣿⣿⣿⣿⣿⠄⣴⣿⣶⣄⠄⣴⣶⠄⢀⣾⣿⣿⣿⣿⣿⣿⠃⠄
⠄⠄⠈⠻⣿⣿⣿⣿⣿⣿⡄⢻⣿⣿⣿⠄⣿⣿⡀⣾⣿⣿⣿⣿⣛⠛⠁⠄⠄
```

FastVulnVerify is an advanced Python tool developed to quickly identify common vulnerabilities encountered during penetration testing and vulnerability verification processes. This script offers a modular framework that allows you to rapidly detect and verify vulnerabilities in system and network infrastructures. By automating vulnerability tests on IP addresses and ports based on various attack vectors, it minimizes the time lost in manual processes.

This tool was developed around two years ago to eliminate the time wasted in the repetitive manual verification of common vulnerabilities. At that time, it was a frequent hassle to constantly check notes, cheat sheets, and various resources while manually verifying potential vulnerabilities detected by tools like Nessus. The reason I didn't share this tool back then was my concern about Penetration Testers losing their technical skills. However, today, by sharing this script, my goal is to accelerate pentesting processes and enable security professionals to dedicate more time to research.

## Who need this

- Penetration Testers
- Bug Hunters

## Features

- Module-Based Scanning: The script supports various test modules, allowing you to select and run them for quick and efficient scans.
- Streamlined Output: Unnecessary outputs are trimmed, making it easier to capture clean screenshots.
- Over 100 Modules

## Modules List

- Nmap Specific Port Scanner
- SSL Version 2 and 3 Protocol Detection
- iLO Version Based Vulnerabilities
- SSL Anonymous Cipher Suites Supported
- MS12-020: Vulnerabilities in Remote Desktop Could Allow Remote Code Execution
- SNMP Agent Default Community Name (public)
- ESXi Version Based Multiple Vulnerabilities
- MS17-010: Security Update for Microsoft Windows SMB Server ETERNALBLUE
- DNS Server Cache Snooping Remote Information Disclosure
- MS17-010: Security Update for Microsoft Windows SMB Server ETERNALBLUE (2)
- MS12-020: Vulnerabilities in Remote Desktop Could Allow RCE
- IPMI v2.0 Password Hash Disclosure
- SSL/TLS EXPORT_RSA <= 512-bit/1024-bit Cipher Suites Supported (FREAK)
- OpenSSL 'ChangeCipherSpec' MiTM Vulnerability
- Network Time Protocol (NTP) Mode 6 Scanner
- Sybase ASA Client Connection Broadcast Remote Information Disclosure
- SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)
- SSH Weak Algorithms Supported
- Terminal Services Doesn't Use Network Level Authentication (NLA) Only
- SSL Certificate Expiry
- SSL Weak Cipher Suites Supported
- Unsupported Windows OS
- SSL Medium Strength Cipher Suites Supported (SWEET32)
- SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection
- SSL Certificate Signed Using Weak Hashing Algorithm
- Microsoft DNS Server Remote Code Execution (SIGRed)
- MS14-066: Vulnerability in Schannel Could Allow Remote Code Execution
- SSL Certificate Cannot Be Trusted
- Microsoft RDP RCE (CVE-2019-0708) (BlueKeep)
- SSL RC4 Cipher Suites Supported (Bar Mitzvah)
- SMB Signing not required
- SSL Certificate Chain Contains RSA Keys Less Than 2048 bits
- SSL Certificate Chain Contains Weak RSA Keys
- Apache Tomcat AJP Connector Request Injection (Ghostcat)
- HTTP TRACE / TRACK Methods Allowed
- Oracle TNS Listener Remote Poisoning
- Microsoft Windows SMBv1 Multiple Vulnerabilities
- SAP MaxDB Multiple Vulnerabilities
- Transport Layer Security (TLS) Protocol CRIME Vulnerability
- iLO 3 / iLO 4 Denial of Service Vulnerability
- X11 Server Unauthenticated Access
- Oracle GlassFish Server Multiple Vulnerabilities
- Microsoft SQL Server Unsupported Version Detection
- OpenSSL Heartbeat Information Disclosure (Heartbleed)
- Jetty < 4.2.19 HTTP Server HttpRequest.java Content-Length Handling Remote Overflow DoS
- Kibana ESA-2018-17
- SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)
- OpenSSL AES-NI Padding Oracle MitM Information Disclosure
- SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)
- SSL Null Cipher Suites Supported
- SSH Protocol Version 1 Session Key Retrieval
- Cisco CallManager TFTP File Detection
- Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key
- Netatalk OpenSession Remote Code Execution
- MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution
- Conficker Worm Detection
- Oracle WebLogic Server RCE
- Microsoft Windows SMB Shares Unprivileged Access
- Microsoft Windows SMB Shares Unprivileged Access (2)
- Microsoft Exchange Server proxylogon (CVE-2021-26855)
- Network Time Protocol Daemon (ntpd) monlist Command Enabled DoS
- Web Server HTTP Header Internal IP Disclosure
- Unsupported Web Server
- SNMP Request Cisco Router Information Disclosure
- iSCSI Unauthenticated Target Detection
- Microsoft Exchange Client Access Server Information Disclosure
- Microsoft Exchange Server Proxyshell (CVE-2021-34473)
- SuperMicro IPMI PSBlock File Plaintext Password Disclosure
- X Display Manager Control Protocol (XDMCP) Detection
- iLO 4 < 2.53 Remote Code Execution Vulnerability (CVE-2017-12542)
- F5 BIG-IP Cookie Remote Information Disclosure
- Atlassian Confluence Server Webwork OGNL Injection (CVE-2021-26084)
- Web Server PROPFIND Method Internal IP Disclosure
- SSH Known Hard Coded Private Keys
- SSL / TLS Certificate Known Hard Coded Private Keys
- Atlassian Confluence Server Webwork OGNL Injection (CVE-2021-26084)
- Microsoft ASP.NET Application Tracing trace.axd Information Disclosure
- Oracle WebLogic WLS9-async Remote Code Execution (remote check)
- VMware vCenter Server 6.5 / 6.7 / 7.0 Multiple Vulnerabilities (VMSA-2021-0010)
- F5 BIG-IP RCE (CVE-2021-22986)
- Multiple Server Crafted Request WEB-INF Directory Information Disclosure
- SMB Use Host SID to Enumerate Local Users Without Credentials
- DNS Server Recursive Query Cache Poisoning Weakness
- Apache Cassandra Information Disclosure Vulnerability
- MongoDB Service Without Authentication Detection
- Tenable Multiple Vulnerabilities
- Samba Badlock Vulnerability
- Elasticsearch ESA-2018-10
- QNAP QTS / QuTS Hero Multiple Vulnerabilities
- PostgreSQL Default Unpassworded Account
- F5 BIG-IP RCE (CVE-2022-1388)
- MS08-067:Service Crafted RPC Request Handling Remote Code Execution
- Cisco IOS IKEv1 Packet Handling Remote Information Disclosure
- Finger Service Remote Information Disclosure
- MongoDB 3.4.x < 3.4.10 / 3.5.x < 3.6.0-rc0 mongod
- Apache Tomcat Version Based Vulnerabilities (Curl)
- nginx Version Based Vulnerabilities
- Oracle Database Unsupported Version Detection
- TLS Version 1.0 & TLS 1.1 Protocol Detection
- Dropbear SSH Server < 2016.72 Multiple Vulnerabilities
- Jetty HttpParser Error Remote Memory Disclosure
- MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (Python)
- Unencrypted Telnet Server

## Requirements

- Python 3.9 or higher
- nmap
- Metasploit Framework
- crackmapexec
- testssl
- openssl
- cqlsh
- smbmap
- snmp-check
- psql
- Required Python libraries (`requests`, `urllib3`, `termcolor`)

## Installation

```bash
git clone https://github.com/0xhav0c/FastVulnVerify.git
pip install -r requirements.txt
python3 fast-vuln-verify.py
```

## Usage

So simply.  You need just `search` or `use` command. When u selected method, give IP and port number.

## Contribute

Community members can also contribute to this project by developing new modules, optimizing existing ones, and making FastVulnVerify more suitable for a broader range of uses. If you encounter any bugs or have suggestions for improvements, feel free to provide feedback via the "Issues" section on GitHub or contribute directly via "Pull Requests."

My aim is to turn this tool into a more comprehensive and capable cybersecurity solution, where everyone can contribute. With your contributions, we can expand the modular structure of the script to create a more powerful and effective vulnerability verification tool.

## Notes
The exploit and nmap scripts used in the script were obtained from public repos long ago. If the owners write, I can add them here as a thank you ^^
