# Wazuh-ModSecurity-Fail2Ban-Integration
A comprehensive guide to integrating Wazuh SIEM with ModSecurity (WAF) and Fail2Ban for centralized security monitoring.


This project demonstrates the integration of Wazuh (a Security Information and Event Management system) with ModSecurity (a Web Application Firewall) and Fail2Ban (an Intrusion Prevention System) to create a unified, real-time security monitoring and response solution.

**Project Objective**

The main goal was to build a centralized security monitoring environment that can:

Detect web-based attacks (e.g., SQL injection, XSS, brute-force attempts)
Correlate security events from multiple tools in one dashboard
Automate responses to malicious activity
Improve visibility and reduce incident response time

**Tools and Their Roles**

**Wazuh Manager**

Acts as the central SIEM platform
Collects, analyzes, and stores security logs
Provides a dashboard for alert visualization and threat analysis

**ModSecurity**

Functions as a Web Application Firewall for the Nginx web server
Inspects HTTP traffic and blocks malicious requests
Generates detailed audit logs of web attacks

**Fail2Ban**

Monitors log files for repeated malicious behavior
Automatically bans offending IP addresses
Useful for preventing brute-force and automated scanning attacks

**What I Did**

Deployed Wazuh components (Manager, Indexer, Dashboard) to serve as the central analysis and monitoring hub.
Installed and configured ModSecurity on a Kali Linux web server to detect and block web application attacks.
Configured Fail2Ban to watch for suspicious login attempts and repeated abuse, with automatic IP blocking.
Integrated Wazuh Agent on the web server to forward ModSecurity and Fail2Ban logs to the Wazuh Manager.

**Linked all systems together so that:**

ModSecurity detects malicious HTTP requests
Fail2Ban reacts to repeated abuse
Wazuh collects logs from both and displays alerts in one dashboard
Tested the setup by simulating different attacks to confirm detection, alert generation, and response.

**Documented the results and configuration in detail (see docs/Wazuh-ModSecurity-Fail2Ban-Integration.pdf).**

**Benefits of This Integration**

Unified View — All security events are visible in one dashboard.
Faster Response — Real-time detection and automated blocking reduce attack impact.
Better Threat Intelligence — Combining firewall, intrusion prevention, and SIEM data improves context.
Practical SOC Workflow — Mimics real-world Security Operations Center processes.

**Results**

**After integration:**

Attacks detected by ModSecurity appeared instantly in the Wazuh Dashboard.
Fail2Ban bans were logged, forwarded to Wazuh, and visible in real time.
The system could distinguish between false positives and real threats.
Response time to incidents was significantly reduced due to centralized monitoring.


**Author**

Mucyo Patrick — Cybersecurity & Network Professional

LinkedIn: linkedin.com/in/mucyo-patrick-60457b240
GitHub: github.com/Mr-mucyo


