By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM05: Supply Chain Vulnerabilities

## Summary 
Depending upon compromised components, services or datasets undermine system integrity, causing data breaches and system failures.


## Description

Supply chain vulnerabilities arise when compromised third-party components undermine system integrity. Attackers can exploit these to cause data breaches, biased outputs, and system failures.

Vulnerable components like unpatched libraries, contaminated datasets, and compromised model artifacts enable attackers to infiltrate systems. They may manipulate training data to insert biases, backdoors, or errors that degrade model integrity. Successful attacks can lead to IP theft, privacy violations, security breaches, and non-compliance with regulations.

Prevention involves extensive supplier vetting, integrity checks, and monitoring. Only use trusted suppliers and ensure alignment of security policies. Scrutinize third-party plugins before integration. Maintain updated inventories of components, and implement code signing for models. Audit supplier security regularly.


## CWE

[CWE-494](https://cwe.mitre.org/data/definitions/494.html): Download of Code Without Integrity Check - Applicable as unauthorized third-party code may be downloaded without integrity checks.

[CWE-733](https://cwe.mitre.org/data/definitions/733.html): Compiler Optimization Removal or Modification of Security-critical Code - Applicable as optimizations could remove security controls in third-party code. 

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as third-party code introduces risks of untrusted functionality.

[CWE-915](https://cwe.mitre.org/data/definitions/915.html): Improperly Controlled Modification of Dynamically-Determined Object Attributes - Applicable as lack of control over dynamic attributes in third-party code poses risks.

[CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) - Applicable as third-party requests may not be properly validated, enabling SSRF.

[CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A5 - Security Misconfiguration - Applicable as misconfigured third-party components pose risks per OWASP guidelines. 

[CWE-916](https://cwe.mitre.org/data/definitions/916.html): Use of Password Hash With Insufficient Computational Effort - Applicable if third-party code uses weak hashing.




---
---
# WIP: Ignore below this line for now
---
---




## NIST CSF

**Identify - Asset Management:**
- ID.AM-1: Physical devices and systems within the organization are inventoried. This helps maintain an inventory of pre-trained models and other software assets to identify vulnerable or outdated components.

**Identify - Risk Assessment:**  
- ID.RA-1: Asset vulnerabilities are identified and documented. This enables identifying vulnerabilities in pre-trained models, third-party components, etc.

**Protect - Identity Management and Access Control:**
- PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes. This enables access control on external systems and suppliers.

**Protect - Information Protection:**  
- PR.IP-1: Baseline configuration of systems are created and maintained. Helps prevent misconfigurations of third-party components.

**Detect - Anomalies and Events:**
- DE.AE-1: A baseline of network operations and expected data flows is established and managed. Anomalies can indicate malicious third-party code execution or data exfiltration.

**Detect - Security Continuous Monitoring:**
- DE.CM-1: The network is monitored to detect potential cybersecurity events. Can help detect vulnerabilities or unauthorized plugin usage.

**Detect - Detection Processes:**
- DE.DP-1: Roles and responsibilities for detection are well defined to ensure accountability. Clarifies who monitors for supply chain events. 

**Respond - Response Planning:**
- RS.RP-1: Response processes and procedures are executed and maintained. This includes having an incident response plan to address supply chain attacks.

**Recover - Recovery Planning:**
- RC.RP-1: Recovery processes and procedures are executed and maintained to ensure timely restoration of systems or assets affected by cybersecurity incidents. Helps recover from incidents involving supply chain compromise.

**Recover - Improvements:**  
- RC.IM-1: Recovery planning and processes are improved by incorporating lessons learned. Improves supply chain risk management based on past incidents.


## MITRE ATT&CK

**Tactics**

- Initial Access (TA0001): An attacker could exploit overreliance by gaining initial access to poison the LLM.  

- Execution (TA0002): Manipulate LLM inputs and outputs through techniques like scripting.

**Techniques** 

- Supply Chain Compromise (T1195): Manipulate training data or other inputs through supply chain.

- Valid Accounts (T1078): Compromise accounts with LLM access to manipulate inputs/outputs.

- Scripting (T1064): Use scripts to automate poisoning of LLM via inputs. 

- Exploit Public-Facing Application (T1190): Exploit public LLMs by manipulating prompts and inputs.



## CIS Controls

- Audit Log Reviews (ID 023): Reviewing system logs could identify suspicious activities like manipulation of LLM inputs/outputs.

- Malware Defenses (ID 018): Tools to detect malware like logic bombs could identify backdoors used to poison LLM data.

- Data Protection (ID 017): Cryptographic validation of LLM outputs could mitigate risks of tampering.

## FAIR 

**Threat Communities:**

- Organized crime groups: Motivated by financial gain, may compromise supply chain to steal data or IP.

- Hacktivists: Motivated by ideology, may poison data or models as a form of protest. 

- Nation states: Motivated by espionage or sabotage, may compromise supply chain to infiltrate or disrupt operations.

**Loss Factors:** 

- Productivity loss: Disruption of operations from supply chain compromise affects productivity.

- Response costs: Incident response and recovery costs from supply chain attacks.

- Fines and legal costs: Penalties and legal costs from non-compliance, IP theft, etc. enabled by supply chain compromise.


## BSIMM 

**Strategy & Metrics:**

- SM2.1: Create an SBOM for internally developed software to inventory components. Can help identify risky third-party dependencies.

**Compliance & Policy:** 

- CP2.1: Create security standards for coding and testing. Can mandate security requirements for third-party code review and testing.

**Attack Models:**

- AM3.2: Use threat modeling to identify risks. Can uncover supply chain threat scenarios. 

**Security Testing:**

- ST2.3: Perform application fuzz testing to uncover flaws. Helps finds vulnerabilities in third-party code.

**Software Environment:**

- SE3.6: Use static and dynamic analysis security testing tools. Can analyze third-party code for vulnerabilities.


## ENISA

**Threats:**

- T10 - Increased Attack Surface: More third-party components increase potential attack surface.

- T14 - Vulnerable Software Dependencies: Vulnerable open source software and models create risks.

- T15 - Supply Chain Threats: Manipulation of hardware, software or data from suppliers.

**Controls:**

- C10 - Secure Software Deployment: Signing and integrity checks on third-party code and models.

- C26 - Software Bill of Materials: Inventory of third-party components to manage risks. 

- C41 - Supply Chain Assurance: Security measures applied throughout the supply chain lifecycle.


## OAIR

**Vulnerabilities:**

- V3 - Data Dependencies: Vulnerabilities in training data from third parties creates biases or manipulation. 

- V7 - Supply Chain: Vulnerabilities introduced via third-party hardware, software, or data supply chains.

**Threat Scenarios:**

- TS03 - Data Poisoning: Manipulation of training data from suppliers to alter model behavior. 

- TS04 - Model Theft: Theft of proprietary models by compromising third-party systems.

**Harms:**

- H1 - Safety & Wellbeing: Biased models from data poisoning can negatively impact individuals.

- H3 - Economic: Financial damage from IP theft enabled by supply chain attacks.


## ATLAS

**Reconnaissance:**

- TTP-R-001 Open Source Intelligence Collection: Gather public info on supply chain providers to enable targeting.

**Weaponization:**

- TTP-W-001 Malware Development: Create malware to leverage vulnerabilities in third-party software.

**Delivery:**

- TTP-D-001 third Party Software Deployment: Deliver malware via legitimate software deployment channels.

**Exploitation:**

- TTP-E-004 Supply Chain Compromise: Exploit the supply chain to establish persistence undetected.

**Command & Control:**

- TTP-C2-002 Multi-Hop Proxy: Obfuscate C2 using compromised third-party systems. 
