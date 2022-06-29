## Networking

- **Difference between router and switch?**
    
    
    | Router | Switch |
    | --- | --- |
    | A Router is a Layer 3 Device. (Network Layer) | A Switch is a Layer 2 Device. (Data-link Layer) |
    | A Router is used to connect various networks. | A Switch is used to connect various devices in a network. |
    | Router can work with both wired & wireless networks. | Switch can only work with the wired network. |
    | A Router is compatible with NAT. | A Switch is not compatible with NAT. |
- **Difference between TCP and UDP?**
    
    
    | TCP | UDP |
    | --- | --- |
    | TCP is a connection-oriented protocol. | UDP is a connectionless protocol. |
    | TCP is comparatively slower than UDP. | UDP is faster and more efficient than TCP. |
    | TCP can guarantee delivery of data to the destination. | UDP cannot guarantee delivery of data to the destination. |
    | Retransmission of lost packets is possible in TCP. | UDP cannot retransmit lost packets. |
- **Difference between HTTP 1.0 and HTTP 1.1?**
    
    
    | HTTP 1.0 | HTTP 1.1 |
    | --- | --- |
    | Single request/response per connection. | Multiple requests/responses per connection. |
    | The host header is optional in HTTP 1.0 | The host header is required in HTTP 1.1 |
    | HTTP 1.0 can define 16 status codes. | HTTP 1.1 can define 24 status codes. |
    | In HTTP 1.0, authentication is unsafe as it is not encrypted. | In HTTP 1.1, authentication is safe as it uses a checksum of username, password and one time value. |
- **What is error 402, error 302 & error 02?**
    
    **402** - Payment Required 
    
    Indicates that the requested content is not available until the client makes a payment.
    
    **302** - Found Redirect 
    
    Indicates that the requested URL has been temporarily moved to a specific URL given by the location header.
    
    **202** - Accepted Response 
    
    Indicates that the request has been accepted for processing, but the processing has not been completed (or not even started).
    
- **Difference between TLS 1.0 and SSL 3.0?**
- **Difference between HTTP 1.1 and HTTP 2.0?**
    
    
    | HTTP 1.1 | HTTP 2.0 |
    | --- | --- |
    | It works on the textual format which means it sends messages as plain text. | It works on the binary protocol which means it encodes messages into binary data. |
    | It compresses data by itself. | It uses HPACK for data compression. |
    
        
- **Difference between HTTP and HTTPS?**
    
    
    | HTTP | HTTPS |
    | --- | --- |
    | Not Secure | Secure Connection |
    | Not Encrypted  | Highly Encrypted |
    | Works at Application Layer. | Works at Transport Layer. |
    | SSL certificates are not required. | SSL certificates are required. |
    | Faster than HTTPS. | Slower than HTTP due to encryption. |
- **OSI Model**
   
    https://github.com/itsRiyanshu/Cyber_Security_Knowledge_Base/blob/f93be94343e0044b05153f4ff0f73e1bc1be0230/The_OSI_Model.md

- **Different Port numbers**

    https://github.com/itsRiyanshu/Cyber_Security_Knowledge_Base/blob/f93be94343e0044b05153f4ff0f73e1bc1be0230/Ports_and_Protocols.md
    
- **TCP 3-Way Handshake**

    https://github.com/itsRiyanshu/Cyber_Security_Knowledge_Base/blob/f93be94343e0044b05153f4ff0f73e1bc1be0230/TCP_3-way_Handshake.md

- **HTTP Status Codes**

    https://github.com/itsRiyanshu/Cyber_Security_Knowledge_Base/blob/f93be94343e0044b05153f4ff0f73e1bc1be0230/HTTP_Status_Codes.md

## Ethical Hacking

- **What is active recon & passive recon?**
    - Active recon is where an attacker engages with the targeted company.
    
    For example: port scanning via nmap or vulnerability exploitation via metasploit.
    
    - Passive recon is an attempt to to gain information about the targeted company without actively engaging with the systems.
    
    For example: social engineering, using shodan to gather information.
    
- **What is Vulnerability Assessment and Ethical Hacking?**
    
    A vulnerability assessment is a systematic review of security weaknesses in an information system or network infrastructure. It refers to the process of identifying risks and vulnerabilities in computer networks, systems, hardware, applications, and other parts of IP ecosystem.
    
    Ethical Hacking is an authorized practice of detecting vulnerabilities in an application, system organization’s infrastructure and bypassing system security to identify potential data breaches and threats in a network. It is an authorized attempt to gain unauthorized access to a computer system, application or data.
    
- **What is XMAS Scan**?
    
    XMAS Scan is a type of inverse TCP scanning technique with the FIN, URG and PUSH flags set to send a TCP frame to a remote device. If the target has open port, you’ll receive no response, if the target has closed port, you’ll receive a remote system reply with an RST.
    
    This port scanning technique can be used to scan large networks and find which host is up and what services it is offering.
    
- **How application security works?**
    
    Application security is the process of developing, adding, and testing security features within applications to prevent security vulnerabilities against threats such as unauthorized access and modification.
    
- **What is CIA Triad?**
    
    The CIA Triad is an information security model designed to guide policies within an organization. The CIA stands for Confidentiality, Integrity and Availability.
    
    Confidentiality is a set of rules that limits access to information.
    
    Integrity is the assurance that the information is trustworthy and accurate.
    
    Availability is a guarantee of reliable access to the information by authorized people.
    
- **What is Cyber Kill Chain?**
    
    The cyber kill chain framework is part of the Intelligence Driven Defense model for identification and prevention of cyber intrusions activity.
    
    The Cyber Kill Chain is an efficient and effective way of illustrating how an adversary can attack the target organization which helps to understand various possible threats at every stage of an attack and the necessary countermeasures to defend against such attacks.
    
    **Cyber Kill Chain Methodology**
    
    The cyber kill chain methodology is a component of intelligent-driven defense for the identification and prevention of malicious intrusion activities. The various phases included in cyber kill chain methodology are:
    
    1. Reconnaissance
    2. Weaponization
    3. Delivery
    4. Exploitation
    5. Installation
    6. Command and Control
    7. Actions on Objectives
- **What is MITRE ATT&CK Framework?**
    
    The MITRE ATT&CK stands for MITRE Adversarial Tactics, Techniques and Common Knowledge (ATT&CK) .MITRE ATT&CK Framework created by MITRE in 2013 is an open framework and knowledge base of adversary tactics and techniques based to real-world observations. 
    
    The MITRE ATT&CK Framework is commonly used by threat hunters, red teamers and defenders to better classify attacks and assess an organization’s risk.
    
- **OWASP Top 10**
    
    The OWASP Top 10 is a standard awareness document for developers and web application security. It is a research project that offers ranking and remediation advice for the top 10 most serious web application security dangers.
    
    The Top 10 Web Application Security Risks are:
    
    1. Broken Access Control
    2. Cryptographic Failures
    3. Injection
    4. Insecure Design
    5. Security Misconfiguration
    6. Vulnerable and Outdated Components
    7. Identification and Authentication Failures
    8. Software and Data Integrity Failures
    9. Security Logging and Monitoring Failures
    10. Server-Side Request Forgery (SSRF)
- **Tools used in Penetration Testing**
    
    There are different tools used in penetration testing:
    
    1. Nmap (Port Scanner)
    2. Metasploit
    3. Wireshark (Packer Analyzer)
    4. John the Ripper (Password Cracker)
    5. Hashcat (Password Cracker / Password Recovery tool)
    6. Hydra (Parallelized Network Login Cracker)
    7. Burp Suite (Web Application Security Testing)
    8. OWASP Zap (Web Application Security Testing)
    9. sqlmap ( Penetration Testing tool for detecting and exploiting SQL Injection flaws)
    10. aircrack-ng (Used to access WiFi network security)
    
- **Penetration Testing Phases**
    
    There are mainly 5 phases of penetration testing:
    
    1. Reconnaissance - A tester gathers as much information about the target company as possible so as to plan an effective attack strategy.
    2. Scanning - Using the information gathered in the Reconnaissance phase, a tester then scan network and checks for open ports and services running on that network.
    3. Vulnerability Assessment - Using the information gather in the Reconnaissance and Scanning phase, a tester scans all the information to identify potential vulnerabilities and determine whether they can be exploited.
    4. Exploitation - When the vulnerability is identified, the tester attempts to exploit the vulnerability and access the target system.
    5. Reporting - Once the exploitation phase is complete, the tester prepares a report documenting all of the findings which can be used to fix any vulnerabilities found in the system and improve the organization’s security infrastructure.
- **OWASP Zap**
    
    The OWASP ZAP stands for Zed Attack Proxy. It is one of the world’s most popular security tools. OWASP Zap is an open source web application security scanner tool allowing security testers to perform penetration tests on web applications.
    
- **If a website is given to you, how will you do PT on it?**
    
    
- **How imp is VAPT Documenting, How you make it and how to analyze it?**
    
    A Penetration Testing report is a document that contains a detailed analysis of the vulnerabilities uncovered during the security test. It records the weaknesses, the threat they pose and possible remedial steps.
    
    VAPT Documenting is important as it gives you a complete overview of vulnerabilities with a POC (Proof of Concept) and remediation to fix those vulnerabilities. It also gives a score against each found issue and how much it can impact your application/website.
    
    
    
- **Penetration Testing on IOT devices.**
    
    The Internet of Things (IoT) is the network of physical objects such as devices, vehicles and other items embedded with electronics, software, sensors and network connectivity
    
    Penetration Testing on IOT devices is critical to accessing the overall strength of your company’s defense against cyber criminals targeting IOT devices. There are different penetration testing methods to analyze the security of IoT devices such as Device hardware pen-test, Firmware pen-test, Radio Security analysis and many more.
    
- **Ways of Penetration Testing**
    
    There are mainly three ways to performing a penetration test. These are:
    
    1. Black-Box Testing - In black box testing, the tester has no knowledge about the infrastructure of the target company.
    2. White-Box Testing - In white box testing, the tester is familiar with the internal infrastructure and the program of the target company.
    3. Grey-Box Testing - Grey box testing is a combination of both black box and white box penetration testing in which only limited information is shared with the tester.
- **What is Zero day vulnerability?**

A zero-day vulnerability is a vulnerability in a system or device that has disclosed but is not yet patched.

- A **zero-day vulnerability** is a software vulnerability discovered by attackers before the vendors has become aware of it.
- A **zero-day exploit** is the method hackers use to attack systems with a previously unidentified vulnerability.
- A **zero-day attack** is the use of a zero-day exploit to cause damage to or steal data from a system affected by a vulnerability.

## Web Application Security

- **How will you exploit Reflected XSS?**
    
    To exploit reflected XSS, an attacker must trick the user into sending data to the target site, which is often done by tricking the user into clicking maliciously crafted link. In many cases, reflected XSS rely on phishing emails and shortened URLs sent to targeted users.
    
- **Broken Access Control and its mitigation?**
    
    Broken Access Control is a web application security flaw where the application fails to properly protect access to its data and functionality, potentially enabling an attacker to view other users’ sensitive data held on the servers and carry out privileged action.
    
    How to prevent broken access control?
    
    1. Continuous Inspection and Testing Access Controls.
    2. Deny Access to resources and functionality by default which are not meant to be public. 
    3. By enabling role-based access control or permission-based access control.
    4. Limiting Cross-Origin Resource Sharing (CORS) protocol usage.
    
    CORS protocol provides a controlled way to share cross-origins resources. The implementation of CORS relies on the Hypertext Transfer Protocol (HTTP) headers used in the communication between the client and the target application. When CORS protocol is misconfigured, it makes it possible for a domain to be controlled by a malicious party to send requests to your domain.
    
- **How is Broken Access Control related with IoT hacking?**
    
    As large number of IoT devices communicate autonomously across multiple standards and protocols, it makes security more complex than other computing environments which is why the right access controls and authentication frameworks enables companies to identify IoT devices, isolate compromised nodes, ensures the integrity of data and authenticate users and authorize different levels of data access. Therefore, broken access control is a vulnerability commonly found in IoT devices.
    
- **What is SQL Injection?**
    
    SQL Injection attack is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This code injection technique makes it possible to execute malicious SQL statements to bypass application security measures.
    
- **Log4j Attack**
    
    Log4j is a severe critical vulnerability affecting many versions of the apache Log4j application. The vulnerability allows unauthenticated remote code execution. With a Log4j vulnerability, attackers can break into systems, steal passwords and logins, extract data, and infect networks with malicious software.
    
    Mitigation:
    
    1. Updating servers - Log4j 1.x is not impacted by this vulnerability.
    2. Using firewall - Using outgoing firewall rules on servers is a good mitigation technique to prevent attacks.
    3. Remove the jar files - Simply removing the jar files will break logging via log4j 2.
    
    ### **Tools for detecting and scanning Log4j**
    
    **. log4j-scan**
    
    You can use the Log4j scanning tool to check your system. This tool is a fully automated, accurate, and extensive scanner for finding log4j RCE CVE-2021-44228. You can download from the **[Github repository](https://github.com/fullhunt/log4j-scan)** and install the requirements easily.
    
    **Installation:** You need to clone the Github repository and install the required dependencies.
    
    ```
    $ git clone https://github.com/fullhunt/log4j-scan
    
    ```
    
    ![https://www.prplbx.com/static/10d61edf871fb29d9620a9bf38a3620a/fcda8/log4j-scan_installation.png](https://www.prplbx.com/static/10d61edf871fb29d9620a9bf38a3620a/fcda8/log4j-scan_installation.png)
    
    ```
    $ pip3 install -r requirements.txt
    
    ```
    
    ![https://www.prplbx.com/static/d62212ff750b5e836ab228ca8721d5d0/fcda8/log4j-scan_installation-1-.png](https://www.prplbx.com/static/d62212ff750b5e836ab228ca8721d5d0/fcda8/log4j-scan_installation-1-.png)
    
    **Usage:** You can run your log4j-scan script now if everything works fine.
    
    ![https://www.prplbx.com/static/9ef127bcd1c5bda88be03ebe752a7a8b/fcda8/log4j-scan_tool_usage.png](https://www.prplbx.com/static/9ef127bcd1c5bda88be03ebe752a7a8b/fcda8/log4j-scan_tool_usage.png)
    
    If you want to scan a single URL:
    
    ```
    $ python3 log4j-scan.py -u <your_url>
    
    ```
    
    If you want scan a Single URL using all Request Methods: GET, POST (url-encoded form), POST (JSON body):
    
    ```
    $ python3 log4j-scan.py -u <your_url> --run-all-tests
    
    ```
    
    If you want to discover WAF bypasses on your environment:
    
    ```
    $ python3 log4j-scan.py -u <your_url> --waf-bypass
    
    ```
    
    If the target is not vulnerable, log4j-scan tool output is “Targets do not seem to be vulnerable.
    
    ![https://www.prplbx.com/static/c49e2ae85a9fe62db27d183a8bce011e/fcda8/log4j-scan_target_is_not_vulnerable.png](https://www.prplbx.com/static/c49e2ae85a9fe62db27d183a8bce011e/fcda8/log4j-scan_target_is_not_vulnerable.png)
    
    If the target is vulnerable, log4j-scan tool output is “[!!!] Target Affected”
    
    ![https://www.prplbx.com/static/3894a2c6fc50e2d09510ccab068708f4/fcda8/log4j-scan_target_is_vulnerable.png](https://www.prplbx.com/static/3894a2c6fc50e2d09510ccab068708f4/fcda8/log4j-scan_target_is_vulnerable.png)
    
    **b. Huntress Log4Shell Vulnerability Tester**
    
    **[This tool](https://log4shell.huntress.com/)** works by generating a random unique identifier which you can use when testing input fields. If an input field or application is vulnerable, it will reach out to this website over LDAP. Our LDAP server will immediately terminate the connection, and log it for a short time.
    
    ![https://www.prplbx.com/static/fa238db44609f379d9aa72a53e34ea32/fcda8/huntress_vulnerability_results.png](https://www.prplbx.com/static/fa238db44609f379d9aa72a53e34ea32/fcda8/huntress_vulnerability_results.png)
    
    **c. BurpSuite Log4Shell Scanner**
    
    You can find a Burp Extender Plugin for Enterprise and Professional related to Log4j vulnerability. The plugin is available in the BApp Store under the name **[Log4Shell Scanner.](https://portswigger.net/bappstore/b011be53649346dd87276bca41ce8e8f)**
    
    ![https://www.prplbx.com/static/843c3040b4f81fcded6ac8eea8db5066/fcda8/burpsuite_log4shell_scanner.png](https://www.prplbx.com/static/843c3040b4f81fcded6ac8eea8db5066/fcda8/burpsuite_log4shell_scanner.png)
    
    **d. Others**
    
    Many companies such as **[Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2021/12/10/apache-log4j2-zero-day-exploited-in-the-wild-log4shell)**, **[Nessus](https://www.tenable.com/plugins/was/113075)**, **[Datto](https://www.datto.com/blog/datto-releases-log4shell-rmm-component-for-datto-partners-and-msp-community)**, **[Cloudflare](https://blog.cloudflare.com/log4j-cloudflare-logs-mitigation/)** which provide cybersecurity and vulnerability management services, announced that they have added plugins and controls related to this critical vulnerability. You can check all details from their knowledge base libraries.
    
    ![https://www.prplbx.com/static/f8cddaec0e0df51e9cbc09eccf33e376/fcda8/qualys_log4j_knowledgebase.png](https://www.prplbx.com/static/f8cddaec0e0df51e9cbc09eccf33e376/fcda8/qualys_log4j_knowledgebase.png)
    
- **Cross-site Scripting (XSS)**
    
    Cross-site Scripting is a web application vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application.
    
    Cross-site scripting works by manipulating a vulnerable website so that it returns malicious JavaScript to users. When the malicious code executes inside a victim’s browser, the attacker can fully compromise their interaction with the application.
    
    There are mainly three types of XSS attacks:
    
    1. **Reflected XSS**, where the malicious script comes from the current HTTP request.
    2. **Stored XSS**, where the malicious script comes from the website’s database.
    3. **DOM-based XSS**, where the vulnerability exists in client-side code rather that server-side code.
- **Cross Site Request Forgery (CSRF)**
    
    CSRF is a web application vulnerability that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated.
    
- **Server Side Request Forgery (SSRF)**
    
    SSRF is a web application vulnerability which involves an attacker abusing the functionality on the server to access and modify resources.
    
    A successful SSRF attack can often result in unauthorized actions or access to data within the organization, either in the vulnerable application itself or on other back-end systems that the application can communicate with.
    
- **What is CRLF Injection?**
    
    CRLF (**Carriage Return** & **Line Feed**) 
    
    CRLF Injection (or HTTP Response splitting) is a software application coding vulnerability that occurs when an attacker injects a CRLF character sequence where it is not expected. It can lead to Cross-site scripting (XSS) and web cache poisoning.
    

## Firewall

- **What is a checkpoint firewall?**
- **How will you attack a windows machine with firewall enabled through metasploit framework?**
    
    We won’t be able to attack a windows machine with firewall enabled as firewall filters every traffic travelling through its servers according to its configuration rules.
    
- **Why does IPsec VPN usually works over UDP?**
    
    Because IPsec is an UDP protocol. UDP sends data in a stream and only has a checksum to ensure that the data arrives uncorrupted at the receiver end. UDP connections have almost no error correction, nor does it care about lost packets during transit. It’s more error prone than TCP, but it sends data much faster.
    
- **What is the purpose of firewall?**
    
    A firewall is a network security device used to monitor incoming and outgoing traffic and prevents unauthorized access.
    

## SIEM

- **Correlation Rules**
    
    A Correlation Rule is a logical expression that causes a system to take specific action if a particular event occurs, For example: If a computer has a virus, a correlation rule will alert the user.
    
- **Normalisation**
    
    Normalisation is a processing of logs into readable and structured format, extracting important data from them and mapping the different fields they contain.
    
- 

## Miscellaneous

- **How did you get into cyber security?**
- **How well you are good at practical knowledge?**
