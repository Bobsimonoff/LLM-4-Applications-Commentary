By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM01: Prompt Injection

## Summary

Manipulating LLMs via crafted inputs can lead to unauthorized access, data breaches, and compromised decision-making. Attackers can directly inject rogue prompts into the LLM (called "jailbreaking") or indirectly inject prompts through external inputs.

## Description

Prompt injection attacks involve crafting malicious prompts that manipulate LLMs into executing unintended and potentially harmful actions. These attacks exploit the lack of segregation between instructions and data in LLMs. 

Attackers can directly inject rogue prompts into the LLM, an attack called "jailbreaking", which overrides safeguards. Indirect prompt injection involves embedding malicious prompts in external content like websites, which then manipulates the LLM's behavior and output when processed.

Successful attacks can lead to impacts like unauthorized access, data breaches, financial fraud, and compromised decision-making. Compromised LLMs may also circumvent safeguards, act as intermediaries to manipulate information or exploit backend systems, allowing attackers to achieve objectives undetected.

Prevention involves restricting LLM access, requiring confirmation, isolating prompts, establishing trust boundaries, and indicating untrustworthy responses.

## CWE

[CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Failure to properly validate user inputs such as prompts enables the introduction of malicious payloads that can manipulate LLM behavior. This inadequate input validation is a primary factor enabling prompt injection attacks.

[CWE-114](https://cwe.mitre.org/data/definitions/114.html): Process Control - The lack of separation between user prompts and external content leads to a loss of control over LLM processing, enabling unintended and potentially harmful actions. Prompt injections exploit the lack of segregation of prompts and data.

[CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Prompt injections can bypass access controls, enabling attackers to achieve privilege escalation and gain unauthorized access to systems and data. Injections bypass authorization checks.

[CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication - Weak authentication mechanisms allow attackers to remotely manipulate the LLM while evading detection. Poor authentication enables undetected attacks. 

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Prompt injections introduce untrusted instructions into the control sphere of the LLM, allowing adversaries to manipulate intended functionality. Injections directly manipulate LLM functionality.

[CWE-74](https://cwe.mitre.org/data/definitions/74.html): Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Failures to properly encode or neutralize special elements in outputs to the LLM allows injections to manipulate downstream processing in unintended ways. Provides additional coverage of weaknesses allowing downstream impacts.

[CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error - Not properly validating the origin of inputs such as prompts leaves the system open to manipulation through malicious external sources. Lack of origin validation is a contributing factor. 

[CWE-472](https://cwe.mitre.org/data/definitions/472.html): External Control of Assumed-Immutable Web Parameter - Prompt injections can manipulate inputs that are assumed to be immutable by the LLM, modifying behavior in unintended ways. Exploits assumptions of parameter immutability.


---
---
# WIP: Ignore below this line for now
---
---



## SCF

ATH-02 - Authentication & Access Control: Multi-Factor Authentication
Reason: Requiring multi-factor authentication makes it harder for attackers to manipulate LLMs undetected.

CRY-01 - Cryptographic Protections: Use of Cryptographic Controls
Reason: Encrypting inputs and outputs of LLMs protects against data exfiltration and manipulation. 

IAM-02 - Logical Access Controls: User Authentication 
Reason: Strong authentication prevents attackers from manipulating the LLM while evading detection.

IAM-04 - Identity & Access Management: Least Privilege 
Reason: Enforcing least privilege access controls can prevent privilege escalation and unauthorized access from compromised LLMs.

LLM01 - Human-Machine Interfaces, Controls & Configuration: Sanitize User-Supplied Input
Reason: Sanitizing user inputs such as prompts before processing by the LLM can prevent malicious payloads from manipulating the model's behavior.

NET-01 - Network Security: Network Segmentation
Reason: Network segmentation and micro-segmentation helps contain compromised LLMs and prevent lateral movement.

SAI-01 - Software Assurance & Integrity: Protect Software Integrity
Reason: Software protections can prevent unauthorized modifications that introduce prompt injection vulnerabilities.

SEA-01 - Secure Engineering Principles: Industry Standard Secure Engineering Practices
Reason: Following secure engineering practices during LLM development can prevent vulnerabilities that enable prompt injection. 

THR-01 - Threat Management: Threat Intelligence Program
Reason: Threat intelligence can provide insights into emerging prompt injection techniques that can be addressed proactively.

WEB-01 - Web Application Security: Server-Side Input Validation
Reason: Server-side input validation helps prevent malicious payloads or unexpected inputs that could manipulate LLMs.




## NIST CSF

**Subcategories**

- PR.AC-1: Identity Management and Access Control - Managing identities and access is critical for mitigating impacts of malicious prompts.

- PR.AC-4: Access Permissions - Controlling access permissions is key to limit capabilities of injected prompts. 

**Detect Functions** 

- DE.CM-4: Malicious Code Detection - Detecting prompt injection payloads and exploits is key to defense.

- DE.CM-7: Monitoring for Unauthorized Personnel/Connections - Can detect potential attackers accessing systems to conduct prompt injection. 

**Respond Functions**

- RS.RP-1: Response Planning - Planning and testing incident response processes for prompt injection events.  

- RS.CO-2: Communications - Coordinating communications for prompt injection incidents across stakeholders.

- RS.AN-1: Notifications - Notifying appropriate parties of detected prompt injection events. 

- RS.MI-2: Incident Mitigation - Effective mitigation controls are needed to contain and resolve prompt injection incidents.


**Recover Functions**

- RC.IM-1: Recovery Planning - Planning recovery processes to restore systems compromised by prompt injections.



## MITRE ATT&CT

**Tactics**

- Initial Access (TA0001) - Techniques that use various entry vectors to gain their initial foothold within a network.  

- Execution (TA0002) - Techniques that result in execution of attacker-controlled code on a local or remote system.

- Persistence (TA0003) - Techniques that adversaries use to keep access and maintain control of systems across restarts, changed credentials, and other interruptions.

- Privilege Escalation (TA0004) - Techniques that adversaries use to gain higher-level permissions on a system or network.

- Defense Evasion (TA0005) - Techniques that adversaries use to avoid detection throughout their compromise.

**Techniques**

- Supply Chain Compromise (T1195) - Compromise the integrity of provider software or hardware to infiltrate the supply chain and ultimately organizations that use the compromised products.

- Spearphishing Attachment (T1193) - Spearphishing with a malicious file attachment is sent to specific individuals within an organization. 

- Command and Scripting Interpreter (T1059) - Use of command-line interfaces and scripting to execute adversarial behaviors and payloads.

- Obfuscated Files or Information (T1027) - Encrypting, encoding, and otherwise obfuscating files or code to conceal actions and evade defenses.

- Valid Accounts (T1078) - Use of legitimate user accounts, often compromised ones, to hide unauthorized behaviors.


## CIS Controls  

**Safeguards**

- CIS Control 3: Data Protection - Protecting data like prompts via access controls, encryption etc. can help mitigate injection impact.

- CIS Control 5: Secure Configuration - Establishing secure system configurations for components involved in LLM apps mitigates attack surface.

- CIS Control 8: Audit Log Management - Logging and monitoring LLM interactions for anomalies is key to detecting potential prompt injections. 

- CIS Control 16: Account Monitoring & Control - Monitoring compromised accounts that could be used to inject malicious prompts.

- CIS Control 18: Application Software Security - Building LLM apps securely and validating inputs helps counter injection risks.


## FAIR

**Threat Communities**

- Partners - Business partners interfacing with systems could be a source of prompt injection attacks.

- Customers - Customers engaging with public interfaces like web portals could inject malicious prompts.

- Privileged Users - Users with privileged access could abuse their capabilities to conduct prompt injections.

- Suppliers: Third-party suppliers like cloud infrastructure providers that support systems could potentially introduce prompt injection risks through compromised components or services. 

**Loss Factors**

- Productivity Loss - Disruption from prompt injections could result in lost labor hours and decreased productivity. 

- Fines/Judgments - Regulatory or legal penalties could arise from privacy breaches enabled by prompt injections.

- Reputation Loss - Public awareness of prompt injection incidents may negatively impact an organization's reputation.

- Strategic Loss - Prompt injections that expose intellectual property could undermine competitive advantage.

- Restoration Costs - Costs may be incurred to restore compromised data or systems affected by prompt injection. 

- Lost Revenue - Dependent on the system, downtime/disruption from prompt injection could directly result in lost revenue.


## BSIMM

**Governance**

- SM1.1 - Strategy & Metrics - Establish strategic guidance and metrics to address prompt injection risks.

**Intelligence**

- CMVM2 - Vulnerability Management - Identify vulnerabilities in components that could lead to prompt injection. 

- STDT1 - Standards - Adhere to secure coding standards that help mitigate injection flaws.

**SSDL Touchpoints** 

- AA1.1 - Architecture Analysis - Analyze architecture for risks and controls like input validation to mitigate injection.

- RDT2.1 - Requirements-Driven Testing - Perform security testing focused on identifying prompt injection flaws.

- SE2.6 - Software Environment - Harden and configure software environments to prevent injections.

**Deployment**

- OP2.1 - Operations - Monitor systems for anomalies and incidents indicative of prompt injections.


## ENISA

**Threats**

- T16 - Data poisoning - Contaminating training data can manipulate model behavior. Prompt injection enables this by injecting rogue prompts.

- T17 - Evasion - Crafting adversarial inputs like malicious prompts aims to cause incorrect model outputs, undermining reliability.  

- T18 - Extraction - Prompt injections could aid in reconstructing intimate knowledge about training datasets and attributes.

**Controls**

- C2 - Data governance - Proper data governance practices including prompt classification, sanitization etc. can help counter injection of bad prompts.

- C8 - Input validation - Validation and filtering of prompts as inputs to the model can detect and block potentially malicious ones.  

- C24 - Anomaly detection - Monitoring model inputs like prompts for anomalous patterns can reveal potential injection attempts.


## OAIR

**Vulnerabilities** TODO - these are certainly wrong it seems

- V3 - Data poisoning - Contaminating training data can manipulate model behavior. Prompt injection enables this by injecting malicious prompts.

- V5 - Model extraction - Prompt injections could aid in reconstructing model parameters through probing. 

- V6 - Backdoors - Prompt injection can create hidden backdoors activated by triggers to control models.

**Threat Scenarios** 

- TS2 - Training data poisoning - Manipulating training data via injected prompts maliciously alters model behavior.

- TS4 - Backdoor insertion - Prompt injection during training/fine-tuning introduces hidden backdoors controlling models. 

- TS5 - Model inversion - Prompt injections aid in reconstructing intimate knowledge about training datasets.

**Harms**

- H2 - Financial fraud - Manipulated models via prompt injection enable fraudulent transactions. 

- H3 - Reputational damage - Unethical model behavior caused by prompt injections damages trust.

- H4 - Privacy violation - Prompt injections can extract private data about individuals from the model.



## ATLAS

**Tactics**

- TTP-TA0001 - Initial Access - Gain initial access to systems, e.g. via phishing, to conduct prompt injection. 

- TTP-TA0002 - Execution - Execute adversarial code and commands like injected prompts.

- TTP-TA0003 - Persistence - Maintain access to systems to enable repeated prompt injections.

**Techniques** 

- TTP-T1195 - Supply Chain Compromise - Compromise third-party components to introduce prompt injection risks.

- TTP-T1193 - Spearphishing Attachment - Send attachment-based phishing emails to deliver payloads.

- TTP-T1059 - Scripting - Use scripts and interpreters to execute prompt injections. 

**Procedures**

- TTP-P0097 - Cloud Compute Instance Abuse - Manipulate cloud compute instances supporting systems to enable prompt injections. 

- TTP-P1086 - Abuse PowerShell - Use PowerShell commands to execute prompt injection payloads.


