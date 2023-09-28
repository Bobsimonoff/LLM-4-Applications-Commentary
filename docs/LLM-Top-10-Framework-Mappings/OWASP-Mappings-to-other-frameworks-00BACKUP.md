

# Introduction
The OWASP Top 10 provides the top 10 critical security risks for web applications. The OWASP Top 10 for Large Language Model Applications project aims to provide a similar standard set of risks specifically for applications integrated with language models. To augment these LLM risks, we will map the OWASP Top 10 for LLM applications to several complementary cybersecurity frameworks for a more holistic perspective:

- The [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) serves as a dictionary of software weaknesses. CWEs provide standardized concepts that classify the types of weaknesses related to the OWASP LLM risks. Mapping CWEs helps identify the core vulnerability types that could lead to or underlie the OWASP risks.

- [MITRE ATT&CK](https://attack.mitre.org/) is a knowledge base of real-world adversary tactics and techniques. Mapping ATT&CK techniques provides insights into how adversaries could actually exploit the OWASP LLM risks in practice. This intelligence can inform threat modeling and defenses.

- The [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) delivers guidelines and best practices for managing organizational cybersecurity risk. Mapping NIST CSF helps relate the OWASP risks to recognized standards and controls, providing mature mitigation guidance.

- [CIS Controls](https://www.cisecurity.org/controls/) provides prescriptive cybersecurity safeguards and metrics. Mapping CIS Controls gives tangible, measurable security steps to prevent, detect, and respond to the OWASP LLM risks.

- [FAIR](https://www.riskmanagementinsight.com/) supports quantitative cyber risk analysis. Mapping FAIR provides data-driven risk evaluation of the potential loss impacts related to the OWASP LLM risks.

- [BSIMM](https://www.bsimm.com/) documents real-world software security best practices. Mapping BSIMM helps relate the OWASP risks to proven security processes and maturity benchmarks.

- [ENISA Threat Landscape](https://www.enisa.europa.eu/) examines emerging threats to AI systems. Mapping ENISA helps identify OWASP LLM risks unique to the AI domain that may not be highlighted in traditional frameworks.

- [OAIR Framework](https://www.operationalizingai.org/) identifies risks across the AI system lifecycle. Mapping OAIR relates the OWASP risks to AI-specific vulnerabilities and harms providing visibility into AI relevance.

- [ATLAS](https://www.anthropic.com/) documents observed real-world attacks against AI. Mapping ATLAS builds understanding of how the OWASP risks manifest in actual AI threat scenarios based on evidence.


![alt text](./images/Security-Frameworks-Template.png)



1. **Vulnerabilities & Weaknesses**
   - CWE weakness types
   - OAIR vulnerabilities
   - Arc: exposes OWASP Risk

2. **Threats & Attack Vectors**
   - MITRE ATT&CK tactics and techniques
   - ATLAS tactics, techniques, and procedures
   - ENISA threats
   - OAIR Threat Scenarios
   - Arc: targets OWASP Risk

3. **Threat Actors**
   - FAIR threat communities
   - Arc: exploit OWASP Risk

4. **Impacts & Harms**
   - OAIR harms
   - FAIR loss factors
   - Arc: result from OWASP Risk

5. **Controls & Mitigations**
   - CIS Controls Safeguards
   - ENISA controls
   - NIST CSF Subcategories
   - Arc: mitigates OWASP Risk

6. **Processes & Practices**
   - BSIMM software security practices
   - BSIMM metrics
   - CIS Controls metrics
   - Arc: manages OWASP Risk

7. **Detection Strategies**
   - NIST CSF detect function
   - MITRE ATT&CK Detection
   - Arc: addresses OWASP Risk

8. **Response Strategies**
   - NIST CSF respond function
   - NIST CSF recover function
   - MITRE ATT&CK Response
   - Arc: manages OWASP Risk


TODO: expand definitions like this

ATT&CK tactics represent the high-level steps or stages in the adversary's plan to accomplish the goal of successfully performing a prompt injection attack. For example, common tactics relevant to prompt injection may include initial access, execution, persistence, and exfiltration.
ATT&CK techniques demonstrate the specific methods and means through which the adversary executes each of those high-level attack steps or tactics. For example, spearphishing attachment and supply chain compromise are techniques an attacker could use to achieve the initial access tactic in a prompt injection attack.


# LLM01: Prompt Injection

## CWE
- CWE-20: Improper Input Validation - Applicable as inadequate input validation enables malicious payloads that manipulate LLM behavior.
- CWE-114: Process Control - Applicable as lack of input validation and separation of prompts from external content leads to loss of control over LLM processing.
- CWE-285: Improper Authorization - Applicable as prompt injections can bypass access controls, enabling privilege escalation and unauthorized access.  
- CWE-287: Improper Authentication - Applicable as weak authentication allows attackers to manipulate the LLM while evading detection.
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere - Applicable as injections introduce untrusted instructions, allowing manipulation of LLM functionality.


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




# LM02: Insecure Output Handling

## CWE
- CWE-78: OS Command Injection - Applicable as lack of output validation could allow command injection when passed to system functions.
- CWE-79: Cross-site Scripting - Applicable as inadequate output encoding risks XSS vulnerabilities in web contexts.
- CWE-89: SQL Injection - Applicable as passing unvalidated LLM outputs to SQL can lead to injection.
- CWE-94: Code Injection - Applicable as directly executing unvalidated output could allow arbitrary code execution. 
- CWE-285: Improper Authorization - Applicable as excessive LLM privileges increase the impacts of malicious output.
- CWE-306: Missing Authentication for Critical Function - Applicable as unauthenticated LLM output could enable unauthorized access.
- CWE-502: Deserialization of Untrusted Data - Applicable as deserializing untrusted outputs could trigger vulnerabilities.
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere - Applicable as untrusted outputs may trigger unintended functionality.

## NIST CSF
**NIST CSF Subcategories** 

- PR.DS-2: Data in transit is protected
- PR.DS-5: Protections against data leaks are implemented
- PR.PT-3: The principle of least functionality is incorporated by configuring systems to provide only essential capabilities

**NIST CSF Detect Functions**

- DE.CM-4: Malicious code is detected 
- DE.CM-7: Monitoring for unauthorized personnel, connections, devices and software is performed

**NIST CSF Respond Functions**

- RS.MI-1: Incidents are contained
- RS.MI-2: Incidents are mitigated

**NIST CSF Recover Functions**

- RC.IM-1: Recovery plans incorporate lessons learned


## MITRE ATT&CK

**MITRE ATT&CK Tactics**

- Initial Access - Tactics that gain initial access to systems, like drive-by compromise via web apps.

- Execution - Tactics to execute adversarial code/commands on local systems.

- Persistence - Maintain presence on systems, like valid accounts or remote services. 

- Privilege Escalation - Gain higher-level permissions, like process injection or forged credentials.

**MITRE ATT&CK Techniques**

- Drive-by Compromise - Gain access by exploiting web apps through user visiting malicious pages.

- Exploitation for Client Execution - Exploit client-side apps like browsers to execute code via crafted data. 

- Process Injection - Inject adversary code into legitimate processes, like via DLL injection.

- Forge Web Credentials - Forge cookies or headers for impersonation or session hijacking.

## CIS Controls

**Safeguards**

- CIS Control 3 - Secure Configurations for Hardware and Software on Mobile Devices, Laptops, Workstations and Servers: Establish secure configurations and harden systems to reduce attack surface. Metrics - Percentage of systems adhering to secure configuration baseline.

- CIS Control 5 - Secure Configuration for Network Devices like Firewalls, Routers and Switches: Implement firewall rules, proxies and VLANs to control and filter network traffic. Metrics - Percentage of network devices adhering to documented secure configuration baseline. 

- CIS Control 6 - Maintenance, Monitoring and Analysis of Audit Logs: Collect, manage and analyze audit logs to understand insecure output handling attack details. Metrics - Percentage of systems with sufficient logging enabled.


## FAIR 

**Threat Communities**

- Partners - Business partners connecting systems for data sharing may be sources of attacks on outputs.

- Service Providers - Cloud infrastructure providers supporting systems could enable insecure output risks.

- Customers - Customers engaging with web apps and APIs can be threat communities exploiting output handling flaws.

**Loss Factors** 

- Productivity Loss - Disruption from compromised systems affects productivity. 

- Response Costs - Investigation and remediation costs from incidents.

- Fines and Legal Costs - Penalties and costs from non-compliance with regulations.

- Reputation Loss - Public awareness of incidents damages brand reputation. 


## BSIMM

**Practices**

- Practice 1 - Architecture Analysis: Analyze architecture and design review to identify and address output handling risks.

- Practice 2 - Code Review: Perform manual code reviews and use static analysis to catch output handling flaws.

- Practice 9 - Security Testing: Conduct dynamic scanning, fuzz testing to catch insecure output handling issues.

- Practice 12 - Operational Enablement: Monitor systems for anomalies in traffic, errors indicating potential handling issues.



## ENISA

**Threats**

- Data poisoning - Contaminating data like LLM outputs to manipulate model behavior or cause misinterpretation.  

- Model evasion - Crafting inputs that produce incorrect model outputs, undermining reliability.

- Model inversion - Reconstructing sensitive attributes from model outputs and behaviors. 

**Controls**

- Input validation - Validate and filter inputs to prevent malicious inputs from reaching outputs.

- Anomaly detection - Detect anomalous patterns in model inputs and outputs indicating potential manipulation.

- Access control - Control and limit access to model outputs to prevent unauthorized exposure.

## OAIR

**Vulnerabilities**

- Data poisoning - Contaminating data like model outputs can manipulate behaviors. 

- Backdoors - Hidden model manipulations activated by crafted inputs.

- Evasion - Carefully crafted inputs mislead models into incorrect outputs.

**Threat Scenarios** 

- Data poisoning - Manipulating outputs via poisoning to undermine integrity.

- Backdoor triggering - Activate backdoors through crafted inputs to model outputs.  

- Evasion - Generate adversarial examples to evade detection by models.

**Harms**

- Availability loss - System crashes or denial of service from malicious outputs.

- Integrity loss - Data corruption and operational disruption from poisoned outputs. 

- Infrastructure loss - Damage to systems and data from malicious outputs.


## ATLAS

**Tactics**

- Initial Access - Gain access to systems, like via drive-by compromise of web apps.

- Execution - Execute adversarial code/commands on local systems.

- Persistence - Maintain presence on compromised systems.

- Privilege Escalation - Escalate privileges to expand impact.

**Techniques**

- Drive-by Compromise - Gain initial access by exploiting vulnerabilities in web-facing apps.

- Command and Scripting Interpreter - Execute commands/scripts via languages like Python, JavaScript. 

- Scripting - Use scripts to automate and scale execution of operations.

- Process Injection - Inject code into running processes, like via DLL injection. 

**Procedures**

- Analyze application security configurations - Fingerprint apps to uncover vulnerabilities.

- Enumerate browser plugins - Identify client-side apps like browsers to target.

- Analyze process binaries - Reverse engineer processes to identify injection points.



# LLM03: Training Data Poisoning

## CWE
- CWE-20: Improper Input Validation - Applicable as lack of validation enables poisoning of training data.
- CWE-24: Use of Hard-coded Credentials - Applicable as hard-coded credentials in data could enable access for poisoning.
- CWE-306: Missing Authentication for Critical Function - Applicable as lack of authentication of data sources can allow poisoning. 
- CWE-502: Deserialization of Untrusted Data - Applicable as deserializing untrusted training data poses risks.
- CWE-787: Out-of-bounds Write - Applicable as malicious data could trigger buffer overflows.
- CWE-798: Use of Hard-coded Cryptographic Key - Applicable as exposed keys in data pose cryptographic risks.
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere - Applicable as poisoned data introduces unintended functionality.


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



# LLM04: Denial of Service

## CWE

- CWE-16: Configuration - Applicable as misconfigurations could trigger resource issues.
- CWE-20: Improper Input Validation - Applicable as validation failures enable malicious requests. 
- CWE-285: Improper Authorization - Applicable as unauthorized requests could abuse resources.
- CWE-400: Uncontrolled Resource Consumption - Applicable as malicious interactions can exhaust LLM resources. 
- CWE-770: Allocation of Resources Without Limits or Throttling - Applicable as lack of throttling enables resource exhaustion.
- CWE-799: Improper Control of Interaction Frequency - Applicable as lack of frequency control allows flooding.

## NIST CSF

**Subcategories**

- PR.IP-1: A baseline configuration of information technology/industrial control systems is created and maintained
- PR.IP-3: Configuration change control processes are in place
- PR.IP-9: Response plans (Incident Response and Business Continuity) and recovery plans (Incident Recovery and Disaster Recovery) are in place and managed

**Detect Functions**

- DE.AE-5: Processes are established to receive, analyze and respond to vulnerabilities disclosed to the organization from internal and external sources.
- DE.CM-4: Malicious code is detected
- DE.CM-7: Monitoring for unauthorized personnel, connections, devices and software is performed

**Respond Functions** 

- RS.RP-1: Response plan is executed during or after an event
- RS.CO-2: Incidents are reported consistent with established criteria
- RS.CO-3: Information is shared consistent with response plans
- RS.CO-5: Voluntary information sharing occurs with external stakeholders to achieve broader cybersecurity situational awareness

**Recover Functions**

- RC.RP-1: Recovery plan is executed during or after a cybersecurity incident
- RC.IM-2: Recovery strategies are updated


## MITRE ATT&CK

**Tactics**

- Initial Access - Gain initial access to target networks/systems

- Execution - Execute adversarial payloads and commands on local systems

- Impact - Disrupt availability and integrity of systems and data

**Techniques**

- Drive-by Compromise - Gain initial access by exploiting web-facing apps 

- Exploitation for Client Execution - Exploit client-side apps like browsers to execute code

- Resource Exhaustion FLOOD - Overwhelm systems with high volumes of traffic/requests

- Service Stop - Disable or degrade critical system services


## CIS Controls 

**Safeguards**

- CIS Control 1 - Inventory and Control of Enterprise Assets: Inventory assets to support DoS defenses. Metrics - percentage of assets inventoried.

- CIS Control 10 - Data Recovery Capabilities: Ensure backup and recovery to restore after DoS incidents. Metrics - time to recover from attacks.

- CIS Control 16 - Account Monitoring and Control: Monitor accounts to detect DoS attacks. Metrics - accounts monitored, unauthorized access detected.



## FAIR

**Threat Communities**

- Hacktivists - Hacktivist groups performing ideologically motivated attacks.

- Organized Crime - Criminal groups attacking for financial gain. 

- Nation States - State-sponsored attackers pursuing strategic objectives.

**Loss Factors**

- Productivity Loss - Operational disruption decreasing productivity.

- Response Costs - Expenses for incident handling and recovery.

- Fines and Legal Costs - Regulatory and contractual penalties.

- Reputation Loss - Damage to brand credibility. 


## BSIMM

**Practices**

- Practice 1 - Architecture Analysis: Architect resiliency into system design.

- Practice 9 - Security Testing: Stress test system robustness against DoS.

- Practice 12 - Operational Enablement: Monitor systems for DoS indicators and impact.


## ENISA

**Threats**

- Data poisoning - Flood systems with maliciously crafted data to overwhelm resources.

- Model evasion - Craft inputs to force costly inference, draining resources.

- Logic corruption - Manipulate model logic to trigger unstable behavior.

**Controls**

- Anomaly detection - Detect abnormal spikes in resource usage indicating DoS.

- Rate limiting - Throttle traffic to mitigate resource exhaustion. 

- Input filtering - Filter excessive inputs to maintain operational capacity.


## OAIR

**Vulnerabilities**

- Resource exhaustion - Systems lack protections against resource exhaustion.

- Logic corruption - Models are susceptible to unstable logic.

**Threat Scenarios**

- Flooding attacks - Overwhelm systems with excessive requests. 

- Recursion attacks - Trigger repeated expensive processing.

**Harms**

- Denial of service - Systems become unresponsive to legitimate users.

- Financial loss - Downtime and recovery costs due to DoS incidents.


## ATLAS 

**Tactics**

- Initial Access - Gain initial foothold on systems.

- Execution - Execute malicious payloads and commands.

- Impact - Disrupt system availability and integrity.

**Techniques** 

- Drive-by Compromise - Gain initial access by exploiting web apps.

- Command and Scripting Interpreter - Execute payloads via languages like Python. 

- Process Injection - Inject code into running processes.

- Service Stop - Disable or degrade critical system services. 

**Procedures**

- Fingerprint service vulnerabilities - Identify potential denial of service vectors.

- Craft recursive queries - Engineer queries to cause repeated expensive processing. 

- Amplify network requests - Use techniques to magnify traffic volume.


# LLM05: Supply Chain Vulnerabilities

## CWE

- CWE-494: Download of Code Without Integrity Check - Applicable as unauthorized third-party code may be downloaded without integrity checks.
- CWE-733: Compiler Optimization Removal or Modification of Security-critical Code - Applicable as optimizations could remove security controls in third-party code.
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere - Applicable as third-party code introduces risks of untrusted functionality. 
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes - Applicable as lack of control over dynamic attributes in third-party code poses risks.
- CWE-918: Server-Side Request Forgery (SSRF) - Applicable as third-party requests may not be properly validated, enabling SSRF. 
- CWE-937: OWASP Top Ten 2013 Category A5 - Security Misconfiguration - Applicable as misconfigured third-party components pose risks per OWASP guidelines.


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


# LLM06: Sensitive Information Disclosure

## CWE
- CWE-202: Exposure of Sensitive Information to an Unauthorized Actor: This applies when sensitive data is exposed to unauthorized users, such as via insufficient LLM output filtering.
- CWE-208: Observable Discrepancy: This applies when differences between expected and actual LLM behavior could allow inference of sensitive information.
- CWE-209: Information Exposure Through an Error Message: This applies if LLM error messages reveal sensitive information or internal behavior insights. 
- CWE-215: Information Exposure Through Debug Information: If debug logs contain sensitive data, this CWE is relevant.
- CWE-538: File and Directory Information Exposure: This applies if the LLM exposes sensitive filesystem information.
- CWE-541: Information Exposure Through Include Source Code: If LLM source code is exposed, it can lead to information exposure. 
- CWE-649: Reliance on Obfuscation or Protection Mechanism: Relying solely on obfuscation without proper access controls poses sensitive data risks.
- CWE-922: Insecure Storage of Sensitive Information: This applies if sensitive data is stored insecurely, allowing unauthorized access.


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



# Insecure Plugin Design

## CWEs
- CWE-20: Improper Input Validation: This applies when plugins fail to validate inputs properly, enabling manipulation.
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'): This applies if plugins do not neutralize untrusted web inputs, risking XSS.
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'): This applies if plugins accept raw SQL inputs, leading to SQLi risks.
- CWE-284: Improper Access Control: This applies when plugins have excessive privileges or inadequate mutual access control. 
- CWE-306: Missing Authentication for Critical Function: If plugins lack authentication, it can enable unauthorized access.
- CWE-346: Origin Validation Error: Failing to validate request origins poses risks of unauthorized remote access.
- CWE-732: Inadequate Encoding of Output Data: If plugin output lacks encoding, XSS and other injection risks arise when embedded.
- CWE-807: Reliance on Untrusted Inputs in a Security Decision: Plugin reliance on unvalidated inputs is insecure.
- CWE-862: Missing Authorization: If plugins lack authorization checks, it can lead to unauthorized actions. 


## NIST CSF

**Identify - Asset Management**
- ID.AM-1: Physical devices and systems within the organization are inventoried. Helps maintain an inventory of plugins.

**Identify - Business Environment**
- ID.BE-4: Dependencies and critical functions for delivery of critical services are established. Identifies critical plugins.

**Protect - Identity Management and Access Control**
- PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes. Applies access control to plugins.  

**Protect - Data Security** 
- PR.DS-5: Protections against data leaks are implemented. Prevents plugin data leakage.

**Detect - Anomalies and Events**
- DE.AE-2: Detected events are analyzed to understand attack targets and methods. Helps analyze plugin attack behaviors.

**Detect - Security Continuous Monitoring**  
- DE.CM-7: Monitoring for unauthorized personnel, connections, devices, and software is performed. Can detect unauthorized plugin actions.

**Respond - Analysis** 
- RS.AN-2: Forensics are performed to determine attack scope, targets, and techniques. Analyzes plugin attacks.

**Recover - Recovery Planning**
- RC.RP-1: Recovery processes and procedures are executed and maintained to ensure timely restoration of systems or assets affected by cybersecurity incidents. Helps recover from plugin attacks. 

## MITRE ATT&CK

**Initial Access - External Remote Services**
- T1133 - Obtains access through external remote services like VPNs exposed by plugins. 

**Execution - Scripting**
- T1064 - Uses scripts like JavaScript in exploited plugins for execution.

**Privilege Escalation - Valid Accounts**  
- T1078 - Reuses compromised plugin credentials for privilege escalation.

**Defense Evasion - Scripting**
- T1220 - Uses scripts to evade defenses when exploiting plugins.

**Discovery - Application Window Discovery** 
- T1010 - Discovers application windows via plugins to learn about target.


## CIS Controls

**CSC 4 - Continuous Vulnerability Assessment and Remediation**

- CSC 4-8: Perform authorized penetration testing against all enterprise devices and systems on the network to identify vulnerabilities and attack vectors that can be used to exploit enterprise systems successfully. Helps identify plugin vulnerabilities.

**CSC 7 - Email and Web Browser Protections**

- CSC 7-7: Prevent outgoing web traffic that originates from untrusted content run in a browser. Prevents malicious browser-based plugin actions.

**CSC 13 - Data Protection**  

- CSC 13-14: Protect all media types that contain sensitive data and securely dispose of such media when no longer needed. Prevents data leakage through plugins.

**CSC 18 - Application Software Security**

- CSC 18-8: For in-house developed applications, ensure that explicit error checking is performed and documented for all input, including for size, data type, and acceptable ranges or formats. Validates plugin inputs.

## FAIR 

**Threat Communities:**

- Cyber criminals: Attackers looking for financial gain by exploiting plugins.

- Hacktivists: Ideologically driven actors who could manipulate or sabotage via plugins.

- Insiders: Malicious insiders who could misuse access to abuse plugins.

**Loss Factors:**

- Response costs: Incident response and remediation costs from plugin attacks.

- Reputation loss: Damage to brand reputation from plugin-related incidents. 

- Productivity loss: Business disruption from exploited plugins being unavailable.


## BSIMM

**Strategy & Metrics**

- SM1.2: Maintain an inventory of internet-facing assets and associated software. Helps track plugins.

**Compliance & Policy**

- CP2.1: Create security standards for coding and testing. Provides secure plugin coding guidance.

**Architecture Analysis**

- AA2.1: Perform application security architecture reviews. Reviews plugin integration architecture.

**Security Testing** 

- ST2.3: Perform application fuzz testing. Fuzz tests plugins to uncover flaws.  

- ST2.4: Perform static analysis security testing (SAST). SAST examines plugin code for flaws.

## ENISA

**Threats:**

- T14 - Vulnerable Software Dependencies: Vulnerabilities in third-party plugins create risks.

- T17 - Manipulation of Hardware and Software: Tampering with plugins to add flaws or backdoors.

**Controls:** 

- C10 - Secure Software Deployment: Applying integrity checks and signing plugins to ensure legitimacy.

- C18 - Input Validation and Sanitization: Validating and sanitizing plugin inputs to prevent exploitation.

- C41 - Supply Chain Assurance: Applying security measures throughout the plugin supply chain lifecycle.



## OAIR

**Vulnerabilities:**

- V7 - Supply Chain: Vulnerabilities introduced via third-party plugins as part of supply chain.

- V9 - Configuration: Insecure plugin configuration like excessive permissions creates risks.

**Threat Scenarios:**

- TS07 - Manipulated Execution: Exploiting flaws in plugins to manipulate execution.

- TS08 - Data Breaches: Using vulnerable plugins to steal data.

**Harms:**

- H3 - Economic: Financial losses from fraud or theft enabled by insecure plugins.

- H5 - Operational: Disruption of services and operations due to unavailable or unstable plugins.

## ATLAS

**Reconnaissance:**

- TTP-R-001: Open Source Intelligence Collection - Gathering intelligence to identify plugin targets.

**Resource Development:** 

- TTP-RD-002: Procure Infrastructure - Acquiring infrastructure to analyze and exploit plugins.

**Initial Access:**

- TTP-IA-001: Spearphishing - Phishing plugin developers to gain access. 

**Command & Control:**

- TTP-C2-004: Multilayer Encryption - Encrypting C2 communications when exploiting plugins to evade detection.

**Impact:**

- TTP-I-001: Endpoint Denial of Service - Exploiting plugins for denial of service attacks.



# LLM08: Excessive Agency

## CWE
- CWE-250: Execution with Unnecessary Privileges: ecution of LLM plugins and tools with excessive privileges increases the impact of potential unauthorized actions.
- CWE-272: Least Privilege Violation: This applies when excessive permissions are granted beyond functional needs.
- CWE-284: Improper Access Control: If plugins lack access controls, it can lead to unauthorized actions.
- CWE-285: Improper Authorization: This applies when improper authorization enables unauthorized actions.
- CWE-347: Improper Verification of Cryptographic Signature: Failure to verify signatures on LLM operations poses authorization risks.
- CWE-732: Inadequate Encoding of Output Data: If plugin output lacks encoding, it risks enabling unintended actions when processed.
- CWE-798: Use of Hard-coded Credentials: Hard-coded credentials with excessive permissions pose unauthorized action risks.   
- CWE-799: Improper Control of Interaction Frequency: Lack of frequency control poses risks of excessive unauthorized actions.
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere: Inclusion of unnecessary untrusted functionality in LLM tools and plugins increases potential for unauthorized actions.
- CWE-862: Missing Authorization: This applies when LLMs do not properly check authorization before performing actions, potentially leading to unauthorized actions and privilege escalation. 



## NIST CSF

### Identify Function

**ID.AM-3: Organizational communication and data flows are mapped**

Mapping how data flows between systems and applications to understand what actions and access LLMs may have. This enables identifying excessive permissions and functionality.

**ID.BE-5: Dependencies and critical functions for delivery of critical services are established** 

Identifying critical services and dependencies allows evaluating potential impacts of excessive LLM agency.

**ID.GV-1: Organizational information security policy is established**

Establishing security policies provides standards to assess whether LLM functionality and agency align with policy. 

**ID.RA-1: Asset vulnerabilities are identified and documented**

Documenting asset vulnerabilities helps identify where excessive LLM agency could be exploited.

### Protect Function


**PR.PT-1: Audit/log records are determined, documented, implemented, and reviewed in accordance with policy**

Auditing LLM actions provides tracing for excessive agency incidents.

**PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes**

Proper identity and credential management prevents the use of excessive privileges by LLM plugins.

**PR.AC-3: Remote access is managed**

Managing remote access prevents unauthorized remote actions by LLMs.

**PR.AC-4: Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties** 

Least privilege limits the impact of excessive agency.

**PR.AC-5: Network integrity is protected (e.g., network segregation, network segmentation)**

Network controls protect unauthorized LLM network activity.


**PR.DS-5: Protections against data leaks are implemented** 

Protecting against data leaks limits exfiltration enabled by excessive LLM agency.

**PR.IP-1: A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles (e.g. concept of least functionality)**

Least functionality baseline configurations prevent unnecessary LLM functionality.


**PR.PT-3: The principle of least functionality is incorporated by configuring systems to provide only essential capabilities**

Least functionality limits potential impact of excessive LLM agency.

**ID.RA-2: Cyber threat intelligence is received from information sharing forums and sources**

Threat intel can provide insights into emerging excessive agency vulnerabilities to address in third-party components.

### Detect Function

**DE.DP-2: Detection activities comply with all applicable requirements**

Ensures excessive agency detection aligns with legal/regulatory policies.

**DE.AE-1: A baseline of network operations and expected data flows for users and systems is established and managed**

Baselines help detect anomalous actions from excessive LLM agency.

**DE.AE-2: Detected events are analyzed to understand attack targets and methods** 

Analyzing events helps determine root causes like excessive permissions. 

**DE.CM-1: The network is monitored to detect potential cybersecurity events**

Monitoring can detect malicious activity from excessive agency.

**DE.CM-3: Personnel activity is monitored to detect potential cybersecurity events**

Monitoring user activity helps detect unauthorized actions.

**DE.CM-4: Malicious code is detected**

Malicious code detection can identify malware enabling excessive agency.

**DE.CM-7: Monitoring for unauthorized personnel, connections, devices, and software is performed** 

Monitoring helps detect malicious unauthorized actions.

### Respond Function 

**RS.MI-2: Incidents are mitigated**

Mitigating incidents stemming from excessive agency limits damage.

**RS.CO-2: Events are reported consistent with established criteria**

Reporting excessive agency events facilitates response. 

**RS.CO-3: Information is shared consistent with response plans** 

Sharing information on excessive agency incidents enables better response.

**RS.AN-1: Notifications from detection systems are investigated**

Investigating alerts can identify unauthorized actions.

**RS.IM-1: Response plans incorporate lessons learned**

Incorporating lessons around excessive agency strengthens response.

**RS.IM-2: Response strategies are updated**

Updating response strategies improves capability to address excessive agency incidents.

**RS.RP-1: Response plan is executed during or after an event**

Executing response plans helps recover from excessive agency events.


### Recover Function

**RC.RP-1: Recovery plan is executed during or after a cybersecurity incident**

Recovery planning helps restore capabilities impaired by excessive agency incidents.


## MITRE ATT&CK

### Initial Access

**T1190 - Exploit Public-Facing Application**

Exploiting vulnerabilities in public apps accessed by LLMs can enable initial access for unauthorized actions. 

**T1133 - External Remote Services**

LLMs may connect to external services, which if excessive permissions exist, can enable initial unauthorized access.

**T1189 - Drive-by Compromise** 

LLMs may connect to external facing components vulnerable to drive-by attacks, providing initial access.

### Execution

**T1106 - Execution through API** 

APIs exposed to LLMs with excessive permissions allow execution of unintended functions.

**T1203 - Exploitation for Client Execution** 

Exploiting client apps accessed by LLMs can lead to unintended code execution.

**T1059 - Command and Scripting Interpreter**

Excessive permissions may allow LLMs to access interpreters and execute unintended commands.

**T1064 - Scripting**

LLMs may be able to access and abuse script interpreters.

### Persistence

**T1136 - Create Account**

Excessive permissions could enable LLMs to create unauthorized accounts. 

**T1197 - BITS Jobs** 

LLMs could use BITS jobs for persistence of unauthorized access.


### Privilege Escalation  

**T1078 - Valid Accounts**

Excessive permissions granted to accounts used by LLMs may enable privilege escalation.

**T1548 - Abuse Elevation Control Mechanism**

LLMs could exploit elevation control mechanisms to gain privilege escalation.

**T1088 - Bypass User Account Control**

Excessive LLM agency could enable UAC bypass on endpoints.

### Defense Evasion

**T1562 - Impair Defenses**

Excessive permissions may enable LLMs to impair defenses like disabling security tools.

**T1554 - Compromise Client Software Binary**

LLMs could tamper with client software they access to evade defenses.  

### Credential Access

**T1555 - Credentials from Password Stores** 

LLMs may access credentials in stores like password managers. 

**T1081 - Credentials in Files**

LLMs could access credential files they have permissions to.

**T1528 - Steal Application Access Token**

LLMs may be able to steal tokens.

### Discovery

**T1083 - File and Directory Discovery**

Excessive permissions may enable LLMs to discover unauthorized files and directories. 

**T1010 - Application Window Discovery** 

LLMs could discover applications to identify targets.

### Lateral Movement 

**T1563 - Remote Service Session Hijacking**

LLMs with excessive privileges could hijack other user remote sessions.

**T1105 - Remote File Copy**

LLMs may copy remote files they shouldn't have access to.

### Collection

**T1005 - Data from Local System**

LLMs could collect and exfiltrate local data they have excessive access to.  

**T1119 - Automated Collection**

Excessive permissions may enable automated collection of unauthorized data.

### Exfiltration

**T1022 - Data Encrypted**

LLMs may encrypt data prior to exfiltration to avoid detection.

**T1567 - Exfiltration Over Web Service**

LLMs with excessive permissions could exfiltrate data over web services.

### Impact

**T1499 - Endpoint Denial of Service** 

LLMs could trigger denial of service on endpoints they have access to.

**T1485 - Data Destruction**

Excessive permissions may allow LLMs to destroy or corrupt data.


## CIS CONTROLS

Here are the CIS Controls mapped with metrics:

**3.4 Use VLANs to segment networks**

Segmenting networks limits potential impact of excessive LLM network access.

Metrics: Percentage of systems using VLANs or other network segmentation

**4.5 Use multifactor authentication**

MFA protects access to systems LLMs interface with. 

Metrics: Percentage of systems using MFA

**5.1 Establish secure configurations**

Establishing secure system configurations limits unnecessary functionality accessible to LLMs.

Metrics: Percentage of systems with secure configurations applied

**5.7 Employ application isolation and sandboxing** 

Isolating/sandboxing applications limits what LLMs can impact.

Metrics: Percentage of applications isolated or sandboxed

**6.2 Ensure software is still supported**

Unsupported software is more likely to have excessive agency vulnerabilities.

Metrics: Percentage of EOL systems 

**8.4 Conduct regular pen testing of externally facing apps**

Pen testing helps find excessive access/functionality issues in external apps.

Metrics: Frequency of external pen testing

**9.1 Limit access to authorized users and processes**

Limiting access to authorized users/processes prevents LLMs from taking unauthorized actions.

Metrics: Percentage of systems properly restricting access

**10.1 Use application whitelisting** 

Whitelisting limits applications LLMs can execute code in.

Metrics: Percentage of systems using application whitelisting

**11.4 Deploy intrusion detection and prevention systems**

IDS/IPS can detect malicious activity resulting from excessive LLM agency.

Metrics: Percentage of systems covered by IDS/IPS

**16.8 Conduct penetration testing and red team exercises**

Pen testing helps identify excessive permissions issues. 

Metrics: Frequency of penetration testing and red teams

**16.12 Conduct crisis management exercises**

Exercises prep response to excessive agency crises.

Metrics: Frequency of crisis management exercises


## FAIR

**Malicious User Threat Community** 

Attackers could exploit excessive LLM agency to achieve malicious goals.

**Unintentional Actor Threat Community**

Excessive agency may enable unintentional harmful actions by authorized LLM users. 

**Partners Threat Community**

Business partners could exploit excessive access granted through integrations.

**Service Providers Threat Community** 

Vendors servicing systems could misuse excessive privileges.

**Loss Event Frequency Factor**

Frequency that loss events resulting from excessive agency may occur. 

**Loss Magnitude Factor** 

Impact/severity of losses from incidents enabled by excessive LLM agency.

**Secondary Loss Events Factor**

Follow-on damages like outages during recovery from excessive agency incidents.

**Loss Event Duration Factor**

Length of time losses are incurred during excessive agency events.


## BSIMM

**Practice 2: Architecture Analysis**

Analyzing architecture identifies high-risk components prone to excessive agency.  


**Practice 9: Standards and Requirements**

Establishing security standards ensures excessive agency risks are addressed.


**Practice 10: Strategy and Metrics** 

Developing metrics to track excessive agency risks helps inform security strategy. 


**Practice 12: Compliance and Policy**

Compliance policies can mandate controls limiting excessive agency.


## ENISA

**Threat T16: Manipulation of the training data**

Manipulated training data could lead models prone to generating outputs that trigger excessive unauthorized actions when automated.


**Threat T10: Unexpected malicious input triggers undesired behavior**

Malicious inputs could exploit excessive agency by triggering damaging actions. 


**Control C10: Software security**

Applying security practices like least privilege limits potential impact of excessive agency.


**Control C21: Formally verify, validate and test** 

Formal verification, validation and testing helps identify excessive agency risks.


## OAIR

**Misuse vulnerability**

LLMs with excessive permissions and inadequate constraints on functionality are vulnerable to misuse, enabling adversaries to achieve malicious objectives.

**Unintended functionality vulnerability**

Excessive LLM functionality increases the potential for unintended consequences when commands are incorrectly interpreted.

**Unanticipated misuse threat scenario**

Adversaries could craft inputs to exploit excessive LLM permissions to carry out harmful unintended actions.

**Quantity harm** 

Excessive automation paired with excessive agency risks quantitatively more frequent or severe harms.

## ATLAS

**Reconnaissance TTPs**

Adversaries may probe systems interfaced by LLMs to identify excessive permissions to exploit.

**Development TTPs**

Adversaries may develop customized payloads tailored to abuse excessive LLM functionality. 

**Insertion TTPs**

Threat actors could insert malicious inputs or code to hijack excessive LLM permissions.

**Execution TTPs** 

Adversaries may use command execution tactics to leverage excessive LLM capabilities.

**Exfiltration TTPs**

Threat actors could leverage excessive LLM permissions to steal data.

**Command and Control TTPs**

Adversaries may exploit excessive permissions to establish C2 channels.


# LLM09: Overreliance

## CWE

N/A

## NIST CSF 

N/A


## MITRE ATT&CK

**Tactics**

N/A

**Techniques**

N/A


## CIS Controls

N/A 

## FAIR 

**Threat Communities:**
- Competitors (TC.CP): Could exploit overreliance to damage reputation with inaccurate outputs.
- Hacktivists (TC.ACT): Could leverage overreliance to spread disinformation.

**Loss Factors:**

- Productivity Loss (LF.P): Overreliance issues degrade productivity through inaccurate responses to prompts.

- Fines & Judgements (LF.FJ): Overreliance could lead to lawsuits, fines, and legal judgements.

- Reputation Loss (LF.R): Inaccurate outputs damage brand reputation.


## BSIMM

N/A


## ENISA

**Threats**

N/A

**Controls** 

N/A

## OAIR

**Vulnerabilities**

N/A

**Threat Scenarios**

N/A

**Harms**

N/A

## ATLAS

**Tactics**
N/A

**Techniques**
N/A

**Procedures**
N/A



# LLM10: Model Theft

## CWE

- CWE-285: Improper Authorization: Flawed authorization allows unauthorized model access.

- CWE-287: Improper Authentication: Weak authentication enables unauthorized model access.   

- CWE-306: Missing Authentication for Critical Function - Lack of auth could allow unauthorized model access.

- CWE-327: Use of a Broken or Risky Cryptographic Algorithm - Weak crypto could enable interception of model data.

- CWE-346: Origin Validation Error: Failing to validate input source can allow unauthorized access.

- CWE-639: Authorization Bypass Through User-Controlled Key: User-controlled keys could enable authorization bypass. 

- CWE-703: Improper Check or Handling of Exceptional Conditions - May prevent detection of extraction attacks.

- CWE-732: Inadequate Encoding of Output Data: Insufficient output encoding risks data exfiltration.

- CWE-798: Use of Hard-coded Credentials: Hard-coded credentials with excessive permissions risk unauthorized access.

- CWE-829: Inclusion of Functionality from Untrusted Control Sphere: Inclusion of untrusted components poses risks of unauthorized access.

- CWE-384: Session Fixation: Session fixation could allow adversary to steal authenticated sessions to access models.

- CWE-913: Improper Control of Dynamically-Managed Code Resources: Could allow execution of unauthorized code enabling model access/theft.

- CWE-918: Server-Side Request Forgery (SSRF): SSRF could enable unauthorized access to internal model storage.


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
