By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM03: Training Data Poisoning

## Summary

Tampered training data can impair LLM models leading to responses that may compromise security, accuracy, or ethical behavior.

## Description

Training Data Poisoning involves manipulating the data used to train LLMs to impair model capabilities and outputs. 

Poisoned training data like falsified, biased, or malicious content can lead to compromised security, accuracy, or ethical model behavior. Attackers may target pre-training data or data used for fine-tuning and embeddings. Impacts include unreliable outputs, biases, information leakage, reputation damage, and flawed decisions.

Prevention involves verifying supply chain integrity, validating legitimacy of data sources, isolating training environments, sanitizing inputs, and incorporating adversarial robustness techniques. Monitoring model behavior and using human review loops can help detect poisoning attacks.


## CWE

[CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Applicable as lack of validation enables poisoning of training data.

[CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function - Applicable as lack of authentication of data sources can allow poisoning.

[CWE-502](https://cwe.mitre.org/data/definitions/502.html): Deserialization of Untrusted Data - Applicable as deserializing untrusted training data poses risks.

[CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure - Added as failure of protections can enable poisoning.

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as poisoned data introduces unintended functionality.

[CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities - Added as vulnerable components could enable poisoning.



---
---
# WIP: Ignore below this line for now
---
---




## NIST CSF 

**Subcategories**

- PR.DS-1: Data-at-rest is protected
- PR.DS-3: Assets are formally managed throughout removal, transfers, and disposition  
- PR.IP-12: A vulnerability management plan is developed and implemented

**Detect Functions**

- DE.CM-4: Malicious code is detected
- DE.CM-7: Monitoring for unauthorized personnel, connections, devices and software is performed
- DE.DP-5: Detection processes are continuously improved

**Respond Functions**

- RS.AN-1: Notifications from detection systems are investigated
- RS.MI-1: Incidents are contained 
- RS.MI-2: Incidents are mitigated

**Recover Functions**

- RC.IM-1: Recovery plans incorporate lessons learned
- RC.IM-2: Recovery strategies are updated


## MITRE ATT&CK

**Tactics**

- Initial Access - Gain initial access, e.g. via social engineering

- Execution - Execute adversarial code and commands on local systems

- Persistence - Maintain persistent access to compromised systems

**Techniques**  

- Spearphishing Attachment - Deliver malicious payloads via documents

- Supply Chain Compromise - Compromise 3rd party components and libraries

- Windows Management Instrumentation - Execute code and payloads on Windows systems


## CIS Controls

**Safeguards**

- CIS Control 1 - Inventory and Control of Hardware Assets: Maintain inventory of assets interacting with data to support defenses. Metrics - percentage of assets inventoried.

- CIS Control 2 - Inventory and Control of Software Assets: Understand software assets that ingest and process data to identify poisoning risks. Metrics - percentage of assets with authorized software.

- CIS Control 11 - Secure Configuration for Network Devices: Use firewall rules, proxies etc. to filter malicious data. Metrics - percentage of devices with secure configuration.

- CIS Control 19 - Incident Response and Management: Define IR plan and processes to detect and respond to poisoning. Metrics - time to detect and contain incidents. 


## FAIR

**Threat Communities** 

- External attackers: Malicious actors manipulating training data from outside the organization.

- Insiders: Internal employees intentionally or unintentionally poisoning data. 

- Third-party suppliers: Data sources that supply poisoned training data.

**Loss Factors**

- Productivity loss: Impacts to operations from unreliable models.

- Reputation loss: Brand and credibility impacts from biases and errors.

- Fines and legal costs: Penalties from regulatory non-compliance. 


## BSIMM

**Practices**

- Practice 1 - Architecture Analysis: Analyze architecture for weaknesses that enable data poisoning. 

- Practice 3 - Compliance & Policy: Establish secure data policies like proper sourcing, sanitization, access controls.

- Practice 9 - Security Testing: Perform fuzzing, fault injection etc. to test system robustness against poisoned data.

- Practice 12 - Operational Enablement: Monitor data integrity, model behavior to detect poisoning.


## ENISA

**Threats**

- Data poisoning: Manipulating training data to introduce vulnerabilities or skew model behavior.

- Model evasion: Crafting manipulated training data that causes incorrect model outputs.

- Model inversion: Reconstructing sensitive attributes from manipulated training data.

**Controls**

- Data governance: Proper data management including classification, access control, sanitization.

- Anomaly detection: Detecting abnormal patterns in training data that may indicate poisoning.

- Input validation: Validating integrity of training data inputs before ingestion.


## OAIR 

**Vulnerabilities**

- Data poisoning: Contaminating training data to manipulate model behavior.

- Backdoors: Introducing hidden malicious functions through poisoned training data.

- Evasion: Manipulated training data causes incorrect model outputs.

**Threat Scenarios** 

- Data poisoning: Manipulate training data to induce model biases or errors.

- Backdoor insertion: Introduce backdoors into models via poisoned training data.

- Evasion: Craft adversarial training data that evades detection.

**Harms**

- System failures: Unreliable models lead to system malfunctions and failures.

- Biases and unfairness: Skewed training data can lead to biased and unethical models.

- Financial fraud: Poisoning can enable models to facilitate fraud.

## ATLAS

**Tactics**

- Initial Access: Gain initial access through vectors like phishing.

- Execution: Execute payloads and code like scripts on local systems.

**Techniques**

- Phishing: Spearphishing Attachment - Inject payloads via document files.

- Scripting: Python/PowerShell - Execute data poisoning payloads using scripts.

**Procedures** 

- Analyze training data integrity checks: Fingerprint data protections to circumvent. 

- Insert manipulated training data: Inject skewed data into datasets.
