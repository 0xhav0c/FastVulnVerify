modules = [
    {
        "ID": 1,
        "Title": "Nmap Specific Port Scanner",
        "Description": "Nmap port scanner for version based vulnerabilities.",
        "os_code": "nmap -sV -p{RPORT} {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 2,
        "Title": "SSL Version 2 and 3 Protocol Detection",
        "Description": "Detect the SSL Version 2 and 3 Protocol Detection with testssl",
        "os_code": "testssl -p {RHOST}:{RPORT} | grep -v '^ rDNS\|^ Service'"
    },
    {
        "ID": 3,
        "Title": "iLO Version Based Vulnerabilities",
        "Description": "Detection the ilo version based vulnerabilities with http-hp-ilo-info nmap script.",
        "os_code": "nmap --script http-hp-ilo-info -p{RPORT} -sV {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 4,
        "Title": "SSL Anonymous Cipher Suites Supported",
        "Description": "SSL Anonymous Cipher Suites Supported",
        "os_code": "testssl -s {RHOST}:{RPORT}"
    },
    {
        "ID": 5,
        "Title": "MS12-020: Vulnerabilities in Remote Desktop Could Allow Remote Code Execution",
        "Description": "MS12-020: Vulnerabilities in Remote Desktop Could Allow RCE with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/rdp/ms12_020_check;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 6,
        "Title": "SNMP Agent Default Community Name (public)",
        "Description": "Detection to configured default SNMP community name (public) ",
        "os_code": "snmp-check -c public {RHOST}"
    },
    {
        "ID": 7,
        "Title": "ESXi Version Based Multiple Vulnerabilities",
        "Description": "Detect the ESXi version with nmap vmware-version script.",
        "os_code": "nmap --script vmware-version -p{RPORT} {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 8,
        "Title": "MS17-010: Security Update for Microsoft Windows SMB Server ETERNALBLUE",
        "Description": "Detect the ETERNALBLUE vulnerability with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/smb/smb_ms17_010;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 9,
        "Title": "DNS Server Cache Snooping Remote Information Disclosure",
        "Description": "Detect the DNS Server Cache Snooping Remote Information Disclosure with nmap",
        "os_code": "sudo nmap -sU -p{RPORT}  --script dns-cache-snoop.nse --script-args 'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={beamteknoloji.com,google.com,youtube.com}' {RHOST} && sudo nmap -sU -p{RPORT} --script dns-cache-snoop.nse {RHOST}"
    },
    {
        "ID": 10,
        "Title": "MS17-010: Security Update for Microsoft Windows SMB Server ETERNALBLUE (2)",
        "Description": "Detect the ETERNALBLUE vulnerability with nmap",
        "os_code": "nmap -p{RPORT} --script smb-vuln-ms17-010 {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 11,
        "Title": "MS12-020: Vulnerabilities in Remote Desktop Could Allow RCE",
        "Description": "Detect the MS12-020 Vulnerabilities with nmap",
        "os_code": "nmap -sV -p{RPORT} --script=rdp-vuln-ms12-020 {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 12,
        "Title": "IPMI v2.0 Password Hash Disclosure",
        "Description": "Detect the IPMI v2.0 Password Hash Disclosure vulnerability with Metasploit Framework.",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 13,
        "Title": "SSL/TLS EXPORT_RSA <= 512-bit/1024-bit Cipher Suites Supported (FREAK)",
        "Description": "Detect the SSL/TLS EXPORT_RSA FREAK Vulnerabilities with testssl",
        "os_code": "testssl -F {RHOST}:{RPORT}"
    },
    {
        "ID": 14,
        "Title": "OpenSSL 'ChangeCipherSpec' MiTM Vulnerability",
        "Description": "Detect the OpenSSL 'ChangeCipherSpec' MiTM Vulnerability with testssl",
        "os_code": "testssl -I {RHOST}:{RPORT}"
    },
    {
        "ID": 15,
        "Title": "Network Time Protocol (NTP) Mode 6 Scanner",
        "Description": "Detect the Network Time Protocol (NTP) Mode 6 Scanner vulnerability with nmap",
        "os_code": "sudo nmap -sU -p{RPORT} --script ntp-info {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 16,
        "Title": "Sybase ASA Client Connection Broadcast Remote Information Disclosure",
        "Description": "Detect the Sybase ASA Client Connection Broadcast Remote Information Disclosure vulnerability with nmap",
        "os_code": "sudo nmap -p{RPORT} --script broadcast-sybase-asa-discover {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 17,
        "Title": "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
        "Description": "Detect SSLv3 POODLE Vulnerability with testssl",
        "os_code": "testssl -O {RHOST}:{RPORT}"
    },
    {
        "ID": 18,
        "Title": "SSH Weak Algorithms Supported",
        "Description": "Detect the Weak SSH Algorithms with nmap",
        "os_code": "nmap -p{RPORT} --script ssh2-enum-algos {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 19,
        "Title": "Terminal Services Doesn't Use Network Level Authentication (NLA) Only",
        "Description": "Detect the Terminal Services Doesn't Use the (NLA) Only Vulnerability with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/rdp/rdp_scanner;set rhosts {RHOST};set rport {RPORT};set verbose true;run;exit'"
    },
    {
        "ID": 20,
        "Title": "SSL Certificate Expiry",
        "Description": "Detect the Expired SSL Certificate with testssl",
        "os_code": "testssl -S {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|Certificate Validity.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 21,
        "Title": "SSL Weak Cipher Suites Supported",
        "Description": "Detect the Expired SSL Certificate with testssl",
        "os_code": "testssl -s {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|NULL.*|Anonymous.*|Export.*|LOW.*|Triple.*|Obsolete.*|Strong.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 22,
        "Title": "Unsupported Windows OS",
        "Description": "Detect the Unsupported Windows OS with nmap",
        "os_code": "nmap -p{RPORT} --script smb-os-discovery.nse {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 23,
        "Title": "SSL Medium Strength Cipher Suites Supported (SWEET32)",
        "Description": "Detect the SWEET32 Vulnerability with testssl",
        "os_code": "testssl -W {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|SWEET.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 24,
        "Title": "SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection",
        "Description": "Detect the Renegotiation Handshakes MiTM Plaintext Data Injection Vulnerability with testssl",
        "os_code": "testssl -R {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|Secure.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 25,
        "Title": "SSL Certificate Signed Using Weak Hashing Algorithm",
        "Description": "Detect the Weak Hashing Algorithm Vulnerability with testssl",
        "os_code": "testssl -S {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|Signature.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 26,
        "Title": "Microsoft DNS Server Remote Code Execution (SIGRed)",
        "Description": "Detect the DNS Server Remote Code Execution (SIGRed) with nmap",
        "os_code": "sudo nmap -sSU -p{RPORT} --script ./nmap-scripts/CVE-2020-1350.nse {RHOST} | grep -v -e 'Host is*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 27,
        "Title": "MS14-066: Vulnerability in Schannel Could Allow Remote Code Execution",
        "Description": "Detect the MS14-066 Vulnerability with testssl",
        "os_code": "testssl -WS {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|Winshock.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 28,
        "Title": "SSL Certificate Cannot Be Trusted",
        "Description": "Detect the Cannot Be Trusted Vulnerability with testssl",
        "os_code": "testssl -S {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|Common.*|Issuer.*|Trust.*|Chain.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 29,
        "Title": "Microsoft RDP RCE (CVE-2019-0708) (BlueKeep)",
        "Description": "Detect the BlueKeep Vulnerability with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 30,
        "Title": "SSL RC4 Cipher Suites Supported (Bar Mitzvah)",
        "Description": "Detect the RC4 Bar Mitzvah Vulnerability with testssl",
        "os_code": "testssl -4 {RHOST}:{RPORT} | grep -E 'Start.*|Checking.*|RC4.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 31,
        "Title": "SMB Signing not required",
        "Description": "Detect the SMB Signing not required with nmap",
        "os_code": "nmap -p{RPORT} --script smb2-security-mode {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 32,
        "Title": "SSL Certificate Chain Contains RSA Keys Less Than 2048 bits",
        "Description": "Detect the Less Than 2048 bits RSA Keys Vulnerability with testssl",
        "os_code": "testssl -S {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|Server.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 33,
        "Title": "SSL Certificate Chain Contains Weak RSA Keys",
        "Description": "Detect the Weak RSA Keys Vulnerability with testssl",
        "os_code": "testssl -S {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|Signature.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 34,
        "Title": "Apache Tomcat AJP Connector Request Injection (Ghostcat)",
        "Description": "Detect the Apache Tomcat AJP Connector Request Injection (Ghostcat)",
        "os_code": "python3 ./exploits/CVE-2020-1938.py http://{RHOST}:{RPORT}/demo 8009 /WEB-INF/web.xml read"
    },
    {
        "ID": 35,
        "Title": "HTTP TRACE / TRACK Methods Allowed",
        "Description": "Detect the HTTP TRACE / TRACK Methods Allowed with nmap",
        "os_code": "nmap -p{RPORT} --script http-trace {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 36,
        "Title": "Oracle TNS Listener Remote Poisoning",
        "Description": "Detect the Oracle TNS Listener Remote Poisoning Vulnerability with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/oracle/tnspoison_checker;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 37,
        "Title": "Microsoft Windows SMBv1 Multiple Vulnerabilities",
        "Description": "Detect the SMBv1 Vulnerability with CrackMapExec",
        "os_code": "crackmapexec smb {RHOST}"
    },
    {
        "ID": 38,
        "Title": "SAP MaxDB Multiple Vulnerabilities",
        "Description": "Detect the SAP MaxDB Multiple Vulnerabilities with nmap",
        "os_code": "nmap -p{RPORT} -sV --script http-sap-netweaver-leak.nse {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 39,
        "Title": "Transport Layer Security (TLS) Protocol CRIME Vulnerability",
        "Description": "Detect the CRIME Vulnerability with testssl",
        "os_code": "testssl -C {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|CRIME.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 40,
        "Title": "iLO 3 / iLO 4  Denial of Service Vulnerability",
        "Description": "Detect the iLO Denial of Service Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} -sV --script http-hp-ilo-info.nse {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 41,
        "Title": "X11 Server Unauthenticated Access",
        "Description": "Detect the X11 Server Unauthenticated Access with nmap",
        "os_code": "nmap -p{RPORT} -sV {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered' -e 'closed'"
    },
    {
        "ID": 42,
        "Title": "Oracle GlassFish Server Multiple Vulnerabilities",
        "Description": "Detect the Oracle GlassFish Server Multiple Vulnerabilities with nmap",
        "os_code": "nmap -p{RPORT} -sV {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 43,
        "Title": "Microsoft SQL Server Unsupported Version Detection",
        "Description": "Detect the Unsupported Microsoft SQL Server with nmap",
        "os_code": "nmap -p{RPORT} -sV {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 44,
        "Title": "OpenSSL Heartbeat Information Disclosure (Heartbleed)",
        "Description": "Detect the Heartbleed Vulnerability with testssl",
        "os_code": "testssl -H {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|Heartbleed.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 45,
        "Title": "Jetty < 4.2.19 HTTP Server HttpRequest.java Content-Length Handling Remote Overflow DoS",
        "Description": "Detect the Jetty Remote Overflow DoS Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} -sV {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 46,
        "Title": "Kibana ESA-2018-17",
        "Description": "Detect the Kibana ESA-2018-17 Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} -sV {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 47,
        "Title": "SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)",
        "Description": "Detect the SSL DROWN Attack Vulnerability with testssl",
        "os_code": "testssl -D {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|Heartbleed.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 48,
        "Title": "OpenSSL AES-NI Padding Oracle MitM Information Disclosure",
        "Description": "Detect the OpenSSL AES-NI MitM Information Disclosure Vulnerability with testssl",
        "os_code": "testssl -s {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|NULL.*|Anonymous.*|Export.*|LOW.*|Triple.*|Obsolete.*|Strong.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 49,
        "Title": "SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)",
        "Description": "Detect the Logjam Vulnerability with testssl",
        "os_code": "testssl -J {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|LOGJAM.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 50,
        "Title": "SSL Null Cipher Suites Supported",
        "Description": "Detect the SSL Null Cipher Suites Supported with testssl",
        "os_code": "testssl -s {RHOST}:{RPORT} | grep -E 'Start.*|Testing.*|NULL.*|Anonymous.*|Export.*|LOW.*|Triple.*|Obsolete.*|Strong.*|Done.*' | awk '{print $0 \"\\n\"}'"
    },
    {
        "ID": 51,
        "Title": "SSH Protocol Version 1 Session Key Retrieval",
        "Description": "Detect the SSH Protocol Version 1 Session Key Retrieval Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} -sV --script ssh-hostkey --script-args ssh_hostkey=full {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 52,
        "Title": "Cisco CallManager TFTP File Detection",
        "Description": "Detect the SSH Protocol Version 1 Session Key Retrieval Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} -sV --script tftp-enum.nse {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 53,
        "Title": "Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key",
        "Description": "Detect the IKE Aggressive Mode with Pre-Shared Key Vulnerability with ike-scan",
        "os_code": "ike-scan {RHOST} -M -A"
    },
    {
        "ID": 54,
        "Title": "Netatalk OpenSession Remote Code Execution",
        "Description": "Detect the Netatalk OpenSession Remote Code Execution Vulnerability",
        "os_code": "python3 ./exploits/CVE-2018-1160.py -i {RHOST} -lv"
    },
    {
        "ID": 55,
        "Title": "MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution",
        "Description": "Detect MS09-001 Vulnerability with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/dos/windows/smb/ms09_001_write;set rhosts {RHOST};run;exit'"
    },
    {
        "ID": 56,
        "Title": "Conficker Worm Detection",
        "Description": "Detect the Conficker Worm Detection Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} -sV --script smb-vuln-conficker.nse {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 57,
        "Title": "Oracle WebLogic Server RCE",
        "Description": "Detect the Oracle WebLogic Server RCE Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} -sV {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 58,
        "Title": "Microsoft Windows SMB Shares Unprivileged Access",
        "Description": "Detect the Microsoft Windows SMB Shares Unprivileged Access",
        "os_code": "crackmapexec smb {RHOST} -u '' -p '' --shares"
    },
    {
        "ID": 59,
        "Title": "Microsoft Windows SMB Shares Unprivileged Access (2)",
        "Description": "Detect the Microsoft Windows SMB Shares Unprivileged Access",
        "os_code": "smbmap -H {RHOST} && smbmap -H {RHOST} -R"
    },
    {
        "ID": 60,
        "Title": "Microsoft Exchange Server proxylogon (CVE-2021-26855)",
        "Description": "Detect the SSH Protocol Authentication Bypass Vulnerability",
        "os_code": "nmap -p{RPORT} -sV --script ./nmap-scripts/CVE-2021-26855.nse {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 61,
        "Title": "Network Time Protocol Daemon (ntpd) monlist Command Enabled DoS",
        "Description": "Detect the Network Time Protocol Daemon (ntpd) monlist Command Enabled DoS Vulnerability",
        "os_code": "python3 ./exploits/CVE-2013-5211.py {RHOST}"
    },
    {
        "ID": 62,
        "Title": "Web Server HTTP Header Internal IP Disclosure",
        "Description": "Detect the Web Server HTTP Header Internal IP Disclosure Vulnerability",
        "os_code": " echo Target IP Address is : {RHOST} && python3 ./exploits/CVE-2000-0649.py {RHOST} {RPORT}"
    },
    {
        "ID": 63,
        "Title": "Unsupported Web Server",
        "Description": "Detect the Unsupported Web Servers with nmap",
        "os_code": "nmap -p{RPORT} -sV {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 64,
        "Title": "SNMP Request Cisco Router Information Disclosure",
        "Description": "Detect the SNMP Request Cisco Router Information Disclosure with nmap",
        "os_code": "sudo nmap -sU -p{RPORT} -sV --script snmp-sysdescr {RHOST} | grep -v -e 'Host*' for -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 65,
        "Title": "iSCSI Unauthenticated Target Detection",
        "Description": "Detect the iSCSI Unauthenticated Target Vulnerability",
        "os_code": "iscsiadm -m discovery -t st -p {RHOST}:{RPORT}"
    },
    {
        "ID": 66,
        "Title": "Microsoft Exchange Client Access Server Information Disclosure",
        "Description": "Detect the Microsoft Exchange Client Access Server Information Disclosure",
        "os_code": "openssl s_client -host {RHOST} -port {RPORT} && GET /autodiscover/autodiscover.xml HTTP/1.0 && GET / HTTP/1.0"
    },
    {
        "ID": 67,
        "Title": "Microsoft Exchange Server Proxyshell (CVE-2021-34473)",
        "Description": "Detect the VxWorks WDB Debug Service Detection",
        "os_code": "nmap -p{RPORT} -sV --script ./nmap-scripts/CVE-2021-34473.nse {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 68,
        "Title": "SuperMicro IPMI PSBlock File Plaintext Password Disclosure",
        "Description": "Detect the SNMP Request Cisco Router Information Disclosure with nmap",
        "os_code": "nmap -p{RPORT} --script supermicro-ipmi-conf {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 69,
        "Title": "X Display Manager Control Protocol (XDMCP) Detection",
        "Description": "Detect the X Display Manager Control Protocol (XDMCP) Detection with nmap",
        "os_code": "sudo nmap -sU -p{RPORT} --script xdmcp-discover {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 70,
        "Title": "iLO 4 < 2.53 Remote Code Execution Vulnerability (CVE-2017-12542)",
        "Description": "Detect the iLO 4 < 2.53 Remote Code Execution Vulnerability",
        "os_code": "python3 ./exploits/CVE-2017-12542.py -t {RHOST} && python3 ./exploits/CVE-2017-12542.py -e -u admin -p password {RHOST} && echo 'Credentials => admin/password has been created'"
    },
    {
        "ID": 71,
        "Title": "F5 BIG-IP Cookie Remote Information Disclosure",
        "Description": "Detect F5 BIG-IP Cookie Remote Information Disclosure with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/gather/f5_bigip_cookie_disclosure;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 72,
        "Title": "Atlassian Confluence Server Webwork OGNL Injection (CVE-2021-26084)",
        "Description": "Detect the Atlassian Confluence Server Webwork OGNL Injection (CVE-2021-26084)",
        "os_code": "python3 ./exploits/CVE-2021-26084.py -u https://{RHOST} && python3 ./exploits/CVE-2021-26084.py -u https://{RHOST} -e whoami && python3 ./exploits/CVE-2021-26084.py -u https://{RHOST} -e 'cat /etc/passwd'"
    },
    {
        "ID": 73,
        "Title": "Web Server PROPFIND Method Internal IP Disclosure",
        "Description": "Detect the Web Server PROPFIND Method Internal IP Disclosure with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/http/webdav_internal_ip;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 74,
        "Title": "SSH Known Hard Coded Private Keys",
        "Description": "Detect the SSH Known Hard Coded Private Keys Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} -sV -sC {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 75,
        "Title": "SSL / TLS Certificate Known Hard Coded Private Keys",
        "Description": "Detect the SSL/TLS Known Hard Coded Private Keys Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} -sV --script ssl-known-key {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 76,
        "Title": "Atlassian Confluence Server Webwork OGNL Injection (CVE-2021-26084)",
        "Description": "Detect the Atlassian Confluence Server Webwork OGNL Injection (CVE-2021-26084)",
        "os_code": "curl -L http://{RHOST}:{RPORT}/apex/f\?p\=4600:6:1982718168701680::::: | grep 'Application Express 4'"
    },
    {
        "ID": 77,
        "Title": "Microsoft ASP.NET Application Tracing trace.axd Information Disclosure",
        "Description": "Detect the ASP.NET Tracing trace.axd Information Disclosure with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/http/trace_axd;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 78,
        "Title": "Oracle WebLogic WLS9-async Remote Code Execution (remote check)",
        "Description": "Detect the Oracle WebLogic WLS9-async Remote Code Execution (CVE-2019-2725)",
        "os_code": "python3 ./exploits/CVE-2019-2725.py -u http://{RHOST}:{RPORT}"
    },
    {
        "ID": 79,
        "Title": "VMware vCenter Server 6.5 / 6.7 / 7.0 Multiple Vulnerabilities (VMSA-2021-0010)",
        "Description": "Detect the VMware vCenter Server VMSA-2021-0010 Vulnerability  with nmap",
        "os_code": "nmap -p{RPORT} -sV --script ./nmap-scripts/CVE-2021-21985.nse {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 80,
        "Title": "F5 BIG-IP RCE (CVE-2021-22986)",
        "Description": "Exploit the F5 BIG-IP RCE (CVE-2021-22986)",
        "os_code": "python3 ./exploits/CVE-2021-22986.py -a true -u https://{RHOST} -c 'cat /etc/os-release && id'"
    },
    {
        "ID": 81,
        "Title": "Multiple Server Crafted Request WEB-INF Directory Information Disclosure",
        "Description": "Detect the WEB-INF Directory Information Disclosure with curl",
        "os_code": "curl https://{RHOST}:{RPORT}/WEB-INF./web.xml"
    },
    {
        "ID": 82,
        "Title": "SMB Use Host SID to Enumerate Local Users Without Credentials",
        "Description": "Detect the SMB Use Host SID to Enumerate Local Users Without Credentials with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/smb/smb_lookupsid;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 83,
        "Title": "DNS Server Recursive Query Cache Poisoning Weakness",
        "Description": "Detect the DNS Server Recursive Query Cache Poisoning Vulnerability with nmap",
        "os_code": "sudo nmap -Pn -sU -p{RPORT} --script=dns-recursion {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 84,
        "Title": "Apache Cassandra  Information Disclosure Vulnerability",
        "Description": "Detect the Apache Cassandra  Information Disclosure Vulnerability",
        "os_code": "cqlsh {RHOST} && echo 'You can run 'desc system_auth' and 'SELECT * from system_auth.roles;' '"
    },
    {
        "ID": 85,
        "Title": "MongoDB Service Without Authentication Detection",
        "Description": "Detect the MongoDB Service Without Authentication Detection with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/mongodb/mongodb_login;set rhosts {RHOST};set rport {RPORT};run;exit'"
    },
    {
        "ID": 86,
        "Title": "Tenable Multiple Vulnerabilities",
        "Description": "Scan the Tenable Multiple Vulnerabilities ",
        "os_code": "curl -k https://{RHOST}:{RPORT}/server/properties"
    },
    {
        "ID": 87,
        "Title": "Samba Badlock Vulnerability",
        "Description": "Detect the Samba Badlock Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} --script=smb-os-discovery {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 88,
        "Title": "Elasticsearch ESA-2018-10",
        "Description": "Scan the Tenable Multiple Vulnerabilities ",
        "os_code": "curl -k http://{RHOST}:{RPORT}/_cat/indices?v"
    },
    {
        "ID": 89,
        "Title": "QNAP QTS / QuTS Hero Multiple Vulnerabilities",
        "Description": "Detect the QNAP QTS / QuTS Hero Multiple Vulnerabilities with nmap",
        "os_code": "nmap -p{RPORT} --script http-qnap-nas-info {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 90,
        "Title": "PostgreSQL Default Unpassworded Account",
        "Description": "Scan the PostgreSQL Default Unpassworded Account",
        "os_code": "psql -h {RHOST} -p {RPORT} -U postgres"
    },
    {
        "ID": 91,
        "Title": "F5 BIG-IP RCE (CVE-2022-1388)",
        "Description": "Exploit the F5 BIG-IP RCE (CVE-2021-22986)",
        "os_code": "python3 ./exploits/CVE-2022-1388.py -t {RHOST} -c 'cat /etc/os-release && id'"
    },
    {
        "ID": 92,
        "Title": "MS08-067:Service Crafted RPC Request Handling Remote Code Execution",
        "Description": "Detect the MS08-067 Vulnerability with nmap",
        "os_code": "nmap -p{RPORT} --script smb-vuln-ms08-067.nse {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 93,
        "Title": "Cisco IOS IKEv1 Packet Handling Remote Information Disclosure",
        "Description": "Detect the Cisco IOS IKEv1 Packet Handling Remote Information Disclosure with Metasploit Framework",
        "os_code": "msfconsole -q -x 'use auxiliary/scanner/ike/cisco_ike_benigncertain;set rhosts {RHOST};set rport {RPORT};set verbose True;run;exit'"
    },
    {
        "ID": 94,
        "Title": "Finger Service Remote Information Disclosure",
        "Description": "Detect the Finger Service Remote Information Disclosure",
        "os_code": "echo 'root' | nc -vn {RHOST} {RPORT} && finger '|/bin/ls -a /@{RHOST}'"
    },
    {
        "ID": 95,
        "Title": "MongoDB 3.4.x < 3.4.10 / 3.5.x < 3.6.0-rc0 mongod",
        "Description": "Detect the MongoDB 3.4.x < 3.4.10 / 3.5.x < 3.6.0-rc0 mongod with nmap",
        "os_code": "nmap -p{RPORT} -sV --script mongodb-info {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 96,
        "Title": "Apache Tomcat Version Based Vulnerabilities (Curl)",
        "Description": "Detect the Apache Tomcat Version with curl",
        "os_code": "echo 'Target Adres: {RHOST}:{RPORT}' && curl 'http://{RHOST}:{RPORT}/non-exit-page' | lynx -dump -stdin | grep -v '^  %\|^    Dload\|^100'"
    },
    {
        "ID": 97,
        "Title": "nginx Version Based Vulnerabilities",
        "Description": "Detect the nginx Version with nmap",
        "os_code": "nmap -sV -p{RPORT} {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 98,
        "Title": "Oracle Database Unsupported Version Detection",
        "Description": "Detect the unsupported Oracle Database Version with nmap",
        "os_code": "nmap -sV -p{RPORT} {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 99,
        "Title": "TLS Version 1.0 & TLS 1.1 Protocol Detection",
        "Description": "Detect the TLS Version 1.0 & TLS 1.1 Protocol Detection with testssl",
        "os_code": "testssl -p {RHOST}:{RPORT} | grep -v '^ rDNS\|^ Service'"
    },
    {
        "ID": 100,
        "Title": "Dropbear SSH Server < 2016.72 Multiple Vulnerabilities",
        "Description": "Detection the Dropbear SSH Server Version with nmap.",
        "os_code": "nmap -p{RPORT} -sV {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
    {
        "ID": 101,
        "Title": "Jetty HttpParser Error Remote Memory Disclosure",
        "Description": "Detect the Jetty HttpParser Error Remote Memory Disclosure",
        "os_code": "python3 ./exploits/CVE-2015-2080.py http://{RHOST} {RPORT}"
    },
    {
        "ID": 102,
        "Title": "MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (Python)",
        "Description": "Detect the MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution",
        "os_code": "python3 ./exploits/CVE-2008-4834.py {RHOST}"
    },
    {
        "ID": 103,
        "Title": "Unencrypted Telnet Server",
        "Description": "Detection the Unencrypted Telnet Server with nmap.",
        "os_code": "nmap -p{RPORT} --script telnet-encryption {RHOST} | grep -v -e 'Host*' -e 'Service Info*' -e 'closed' -e 'filtered'"
    },
]