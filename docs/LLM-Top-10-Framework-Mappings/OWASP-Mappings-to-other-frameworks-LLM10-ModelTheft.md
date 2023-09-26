# LLM10: Model Theft

## Summary
Unauthorized access to proprietary large language models risks theft, competitive advantage, and dissemination of sensitive information.

## Description

Unauthorized access and theft of proprietary large language models can undermine competitive advantage and lead to data breaches. 

Attackers can exploit weak access controls, insufficient monitoring, vulnerable components, and insider threats to infiltrate systems and steal valuable LLMs. Successful attacks enable adversaries to acquire sensitive data, launch advanced prompt engineering attacks, and financially damage organizations.

Prevention requires strong access controls, network security, authentication, and monitoring. LLMs should have restricted network access and regular auditing of related logs and activities. Robust MLOps governance, input filtering, and output encoding can help prevent extraction attacks. Physical security and watermarking also help mitigate risks. Proactively securing LLMs against theft is crucial for maintaining confidentiality of intellectual property.

## CWE

[CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Flawed authorization allows unauthorized model access.

[CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication - Weak authentication enables unauthorized access.

[CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function - Lack of authentication could allow unauthorized access.

[CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm - Weak cryptography could enable interception of model data.

[CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error - Failing to validate input source can allow unauthorized access.

[CWE-639](https://cwe.mitre.org/data/definitions/639.html): Authorization Bypass Through User-Controlled Key - User keys could enable authorization bypass. 

[CWE-703](https://cwe.mitre.org/data/definitions/703.html): Improper Check or Handling of Exceptional Conditions - May prevent detection of extraction attacks.

[CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data - Insufficient output encoding risks data exfiltration.

[CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials - Hard-coded credentials with excessive permissions risk unauthorized access.

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Inclusion of untrusted components poses unauthorized access risks.

[CWE-384](https://cwe.mitre.org/data/definitions/384.html): Session Fixation - Session fixation could allow adversary to steal authenticated sessions to access models.

[CWE-913](https://cwe.mitre.org/data/definitions/913.html): Improper Control of Dynamically-Managed Code Resources - Could allow execution of unauthorized code enabling model access/theft.

[CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) - SSRF could enable unauthorized access to internal model storage.



---
---
# WIP: Ignore below this line for now
---
---





## NIST CSF

**Subcategories:**

- PR.AC-1: Identities and credentials are managed. Essential for access control.

- PR.AC-3: Remote access is managed. Limits attack surface.  

- PR.AC-4: Access permissions and authorizations are managed. Critical for least privilege.

- PR.AC-5: Network integrity is protected. Segmentation limits lateral movement. 

- PR.DS-6: Integrity checking mechanisms are used. Can detect unauthorized changes.

- PR.PT-3: Access to systems and assets is controlled. Limits access to only what is needed.

**Detect Functions:**

- DE.AE-1: A baseline of network operations is established. Anomalies may indicate an attack.

- DE.AE-2: Detected events are analyzed. Identifies tactics, techniques used.

- DE.CM-4: Malicious code is detected. Can detect malware used in attacks.

- DE.CM-7: Monitoring for unauthorized activity is performed. Critical for detection.

**Respond Functions:**

- RS.RP-1: Response plan is executed. Defines courses of action during incidents.

- RS.CO-1: Personnel know their roles during response. Enables coordinated response. 

- RS.AN-1: Notifications from detection systems are investigated. Determines if incident has occurred.

- RS.MI-1: Incidents are contained. Limits damage from incidents.

- RS.MI-2: Incidents are mitigated. Removes malware, patches vulnerabilities. 

**Recover Functions:**  

- RC.RP-1: Recovery plan is executed. Guides restoration of capabilities.

- RC.IM-1: Recovery plans incorporate lessons learned. Allows continual improvement.

- RC.IM-2: Recovery strategies are updated. Keeps strategies effective over time.



## MITRE ATT&CK

**Tactics:**

- TA0001: Initial Access. Vectors for gaining initial foothold like phishing. 

- TA0002: Execution. Running adversary code post-compromise.

- TA0003: Persistence. Maintaining access like valid accounts. 

- TA0005: Defense Evasion.  - Adversaries may use evasion to conceal model theft activities.  

- TA0010: Exfiltration. Retrieving extracted data.

- TA0011: Command and Control. Managing operations via C2 channels.

**Techniques:**

- T1586: Compromise Infrastructure. Targeting operational systems.

- T1078: Valid Accounts. Leveraging compromised credentials. 

- T1569: System Services. Abusing services for access.

- T1499: Endpoint Denial of Service. Disrupting monitoring.

- T1011: Exfiltration Over Other Medium. Transferring data. 

- T1567: Exfiltration Over Web Service. Using web services to extract data.

- T1102: Web Service. Using legitimate web APIs and services.


## CIS Controls

**Safeguards:**

- 1.4: Maintain Detailed Asset Inventory. Critical for managing assets and access.

- 3.4: Deploy Automated Software Patch Management Tools. Keeps systems updated to prevent exploits.

- 5.1: Establish Secure Configurations. Prevents misconfigurations that enable access.

- 6.2: Ensure Only Approved Ports, Protocols and Services Are Running. Reduces attack surface. 

- 8.1: Manage Authentication Systems. Strong authentication prevents unauthorized access. 

- 16.12: Perform Routine Incident Scenario Exercises. Improves incident response capabilities.

- 17.6: Conduct Penetration Tests and Red Team Exercises. Identifies gaps in defenses.

- 18.2: Analyze Malware. Detects malware used in attacks.
    

## FAIR 

**Threat Communities:**

- TC.EX.01: Cyber criminals - Financial motivation makes them likely threat actors.

- TC.IN.01: Insiders - May abuse authorized access for theft. 

- TC.AC.01: Hacktivists - Ideological motivation to steal IP.

- TC.NS.01: Nation states - Government-sponsored theft of trade secrets.

**Loss Factors:**

- LF.PR.01: Productivity - Disruption during recovery affects output.

- LF.RE.01: Response - Incident response and remediation costs. 

- LF.RP.01: Replacement - Restoring compromised assets.

- LF.FJ.01: Fines and judgments - Regulatory and legal penalties.

- LF.BR.01: Reputation - Damage to brand trust and market position.

- LF.IP.01: Intellectual Property - Loss of proprietary model details/advantage.

## BSIMM

**Governance:**

- SM: Strategy & Metrics - Guides security efforts.
- CP: Compliance & Policy - Policies can define authorized model usage.

**Intelligence:**

- TM: Threat Modeling - Identify model theft risks.

- SF: Security Features & Design - Incorporate security into architecture.

- SR: Standards & Requirements - Define security standards to meet.

**SSDL Touchpoints:**

- AA: Architecture Analysis - Analyze risks early in SDLC. 

- CR: Code Review - Find flaws enabling unauthorized access.

- ST: Security Testing - Find weaknesses through testing.

**Deployment:**

- OE: Operations Enablement - Prepare monitoring and response capabilities.

- VM: Vulnerability Management - Identify and remediate vulnerabilities. 

- ES: Endpoint Security - Protect endpoints housing models.

- SO: Security Operations - Monitoring can detect unauthorized access or usage.



## ENISA

**Threats:**

- T10: IP Theft - Theft of model architecture, parameters, and weights. 

- T11: Model Extraction - Replicating model via crafted inputs.

- T15: Unauthorized Use - Misuse of stolen model.

- T16: Data Exfiltration - Unauthorized extraction of model data.

**Controls:**

- C4: Access Control - Manage authorization to AI systems. 

- C9: Anomaly Detection - Detect attacks like model extraction.

- C11: Continuous Monitoring - Ongoing monitoring for malicious activity. 

- C15: Cryptography - Encryption prevents unauthorized access.

- C19: Incident Response - Define processes to detect, respond to incidents.

- C21: Network Security - Use network controls like segmentation.


## OAIR

**Vulnerabilities:**

- V3: Weak Access Controls - Inadequate access controls enable unauthorized access. 

- V4: Lack of Input Validation - Failing to validate inputs enables attacks.

- V9: Poor Cryptography - Weak cryptography allows interception of data.

- V12: Insufficient Logging - Lack of logging limits detection.

**Threat Scenarios:**

- TS3: IP Theft - Theft of proprietary model details causes competitive harm.

- TS7: Unauthorized Access - Access to model environments enables theft. 

- TS9: Data Exfiltration - Exfiltration of model data violates confidentiality. 

**Harms:**

- H1: Financial Loss - Theft causes revenue loss, recovery costs.

- H3: Unfair Outcomes - Stolen models may enable unfair outcomes.

- H5: Reputational Harm - Theft damages brand reputation and trust. 

- H6: Loss of Competitive Advantage - Theft erodes competitive edge from IP loss.
  


## ATLAS

**Tactics:**

- TA0001: Initial Access - Gain initial foothold into environments.

- TA0003: Persistence - Maintain access to internal networks. 

- TA0006: Credential Access - Obtain credentials for lateral movement.

- TA0010: Exfiltration - Retrieve extracted model data.

- TA0043: Reconnaissance - Research and scanning facilitates theft targeting.

**Techniques:** 

- T1586: Compromise Infrastructure - Target cloud, enterprise systems.

- T1078: Valid Accounts - Use compromised credentials.

- T1005: Data from Local System - Extract data from systems.

- T1567: Exfiltration Over Web Service - Exfiltrate over encrypted web services. 
  
- T1592: Network Sniffing - Sniffing can reveal model environments and data.

**Procedures:**

- P002: Develop Capabilities - Build tools and exploits. 

- P006: Establish Infrastructure - Setup infrastructure to support operations.

- P007: Develop Operational Resources - Obtain computing resources.
