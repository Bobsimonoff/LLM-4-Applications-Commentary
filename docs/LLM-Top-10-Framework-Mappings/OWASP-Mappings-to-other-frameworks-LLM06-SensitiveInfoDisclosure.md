# LLM06: Sensitive Information Disclosure

## Summary
Failure to protect against disclosure of sensitive information in LLM outputs can result in legal consequences or a loss of competitive advantage.

## Description

Failure to protect against unauthorized exposure of confidential data in LLM outputs can enable adversaries to steal intellectual property and sensitive information. 

Inadequate data handling, weak access controls, and insufficient input/output validation allow attackers to insert malicious prompts or directly access sensitive data. Successful attacks can lead to privacy violations, intellectual property theft, reputational damage, and regulatory noncompliance.

Prevention involves robust data sanitization, input filtering, and output validation. Strict access controls should be implemented, limiting data access to only authorized purposes. LLM training data must be carefully filtered to exclude sensitive information. Comprehensive data governance and privacy policies can help mitigate risks. Monitoring systems for anomalous behavior can also help detect potential unauthorized access attempts. Securing LLMs against sensitive data exposure is critical for maintaining trust and competitive advantage.

## CWE

[CWE-202](https://cwe.mitre.org/data/definitions/202.html): Exposure of Sensitive Information to an Unauthorized Actor - Applicable when sensitive data is exposed to unauthorized users.

[CWE-208](https://cwe.mitre.org/data/definitions/208.html): Observable Discrepancy - Applicable when differences between expected and actual LLM behavior allow inference of sensitive information.

[CWE-209](https://cwe.mitre.org/data/definitions/209.html): Information Exposure Through an Error Message - Applicable if error messages reveal sensitive information. 

[CWE-215](https://cwe.mitre.org/data/definitions/215.html): Information Exposure Through Debug Information - Applicable if debug logs contain sensitive data.

[CWE-538](https://cwe.mitre.org/data/definitions/538.html): File and Directory Information Exposure - Applicable if filesystem information is exposed.

[CWE-541](https://cwe.mitre.org/data/definitions/541.html): Information Exposure Through Include Source Code - Applicable if source code containing sensitive data is exposed.

[CWE-649](https://cwe.mitre.org/data/definitions/649.html): Reliance on Obfuscation or Protection Mechanism - Applicable if relying solely on obfuscation without proper access controls.

[CWE-922](https://cwe.mitre.org/data/definitions/922.html): Insecure Storage of Sensitive Information - Applicable if sensitive data is stored insecurely.



---
---
# WIP: Ignore below this line for now
---
---




## NIST CSF

**Identify - Asset Management**
- ID.AM-1: Physical devices and systems within the organization are inventoried. This helps identify assets containing sensitive information.

**Identify - Risk Assessment**
- ID.RA-1: Asset vulnerabilities are identified and documented. Allows assessing risks of sensitive data exposure.  

**Protect - Identity Management and Access Control**  
- PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes. Restricts access to sensitive information.

**Protect - Data Security**
- PR.DS-1: Data-at-rest is protected. Safeguards sensitive data storage.

**Detect - Anomalies and Events**
- DE.AE-1: A baseline of network operations and expected data flows is established and managed. Deviations could indicate unauthorized data access.

**Detect - Security Continuous Monitoring**  
- DE.CM-1: The network is monitored to detect potential cybersecurity events. Can detect potential unauthorized access to sensitive data.

**Respond - Communications**
- RS.CO-1: Personnel are informed of detected cybersecurity incidents. Required for investigating sensitive data exposure incidents. 

**Recover - Recovery Planning**
- RC.RP-1: Recovery processes and procedures are executed and maintained to ensure timely restoration of systems or assets affected by cybersecurity incidents. Helps recover from incidents involving sensitive data exposure.

## MITRE ATT&CK 

**Discovery - OS Credential Dumping:**
- T1003 - Dumps credentials from OSs and stores for use in password cracking. Could obtain credentials to access sensitive data.

**Collection - Data from Local System:**
- T1005 - Gathers sensitive data from local system sources like files, databases, memory.

**Exfiltration - Exfiltration Over C2 Channel:**
- T1041 - Sensitive data is aggregated and exfiltrated over an existing C2 channel.


## CIS Controls

**CSC 1 - Inventory and Control of Enterprise Assets**

- CSC 1-1: Deploy an automated asset inventory discovery tool and use it to build a preliminary inventory of systems connected to an organization's public and private network(s). This helps identify assets containing sensitive data.

**CSC 4 - Continuous Vulnerability Management**

- CSC 4-11: Compare the results from back-to-back vulnerability scans to verify that vulnerabilities were addressed, either by patching, implementing a compensating control, or documenting and accepting a reasonable business risk. Helps detect new vulnerabilities that could enable data exposure.

**CSC 13 - Data Protection**

- CSC 13-4: Deploy an automated tool on network perimeters that monitors for sensitive data (SSN, PHI, PCI, etc.), keywords, and other document characteristics to discover unauthorized attempts to exfiltrate data across network boundaries and block such transfers while alerting information security professionals. Detects potential unauthorized access. 

**CSC 16 - Account Monitoring and Control**

- CSC 16-5: Validate that all accounts have an expiration date, and when the expiration date has passed, automatically disable accounts and provision a method to recover them in the event that past employees return. Enforces access control on sensitive data.

## FAIR 

**Threat Communities:**

- Hacktivists: Ideologically motivated actors who could steal and leak sensitive data.

- Organized crime groups: Financially driven groups that may steal sensitive data like customer info for profit.

- Insiders: Malicious insiders like employees who could abuse access to steal IP or data.

**Loss Factors:**

- Reputation loss: Disclosure of sensitive data harms brand reputation.

- Lost revenue: Leaked IP or loss of competitive advantage reduces revenue. 

- Liability costs: Regulatory fines, legal fees for data breaches involving sensitive info.



## BSIMM

**Strategy & Metrics**

- SM1.2: Maintain an inventory of sensitive assets. Helps identify assets containing sensitive data. 

**Compliance & Policy**

- CP3.1: Create a data classification scheme and inventory. Allows properly classifying and protecting sensitive data.

**Attack Models** 

- AM2.1: Perform application threat modeling. Helps identify sensitive data exposure risks.

**Security Testing**

- ST1.2: Perform static analysis security testing. Can detect flaws that could lead to data exposure.

**Software Environment**

- SE2.6: Perform secrets management. Securely manages credentials that provide access to sensitive data.


## ENISA

**Threats:**

- T07 - Data Leakage: Unintentional exposure of private or sensitive data.

- T19 - Override of Privacy Protection: Circumvention of controls to access personal data. 

**Controls:**

- C08 - Data Protection: Safeguards for sensitive data like encryption and access controls.

- C20 - Access Control: Strict limits on access to sensitive data and systems.  

- C24 - Anomaly Detection: Monitoring for deviations that could indicate unauthorized data access.


## OAIR

**Vulnerabilities:**

- V4 - Ambiguous Model Outputs: Ambiguous outputs from the LLM can lead to unintentional information disclosure.

- V8 - Unconventional Architecture: Unique architectures like LLMs may expose unintended behaviors leading to sensitive data exposure.

**Threat Scenarios:**

- TS02 - Model Inversion: Attempts to reverse engineer the training data using the model's outputs. 

- TS05 - Membership Inference: Attempts to determine if a data record was used in the model's training data.

**Harms:** 

- H2 - Psychological: Exposure of sensitive psychological or health data causes individual distress.

- H4 - Political: Disclosure can undermine political processes like elections if targeting data is exposed.


## ATLAS

**Reconnaissance:**

- TTP-R-001: Open Source Intelligence Collection - Gathering public information to enable targeting sensitive data.

**Resource Development:**

- TTP-RD-001: Acquire Infrastructure - Acquiring infrastructure and tools to collect sensitive data. 

**Initial Access:**

- TTP-IA-001: Spearphishing - Phishing users with access to sensitive data.

**Command & Control:**

- TTP-C2-001: Domain Fronting - Using whitelisted domains to blend C2 with normal traffic to extract data.