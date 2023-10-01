By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM01: Prompt Injection

### Summary

Manipulating LLMs via crafted inputs can lead to unauthorized access, data breaches, and compromised decision-making. Attackers can directly inject rogue prompts into the LLM (called "jailbreaking") or indirectly inject prompts through external inputs.

### Description

Prompt injection attacks involve crafting malicious prompts that manipulate LLMs into executing unintended and potentially harmful actions. These attacks exploit the lack of segregation between instructions and data in LLMs. 

Attackers can directly inject rogue prompts into the LLM, an attack called "jailbreaking", which overrides safeguards. Indirect prompt injection involves embedding malicious prompts in external content like websites, which then manipulates the LLM's behavior and output when processed.

Successful attacks can lead to impacts like unauthorized access, data breaches, financial fraud, and compromised decision-making. Compromised LLMs may also circumvent safeguards, act as intermediaries to manipulate information or exploit backend systems, allowing attackers to achieve objectives undetected.

Prevention involves restricting LLM access, requiring confirmation, isolating prompts, establishing trust boundaries, and indicating untrustworthy responses.

### Common Examples of Risk

1. An attacker overwrites the system prompt to make the LLM return sensitive information without restrictions.

2. An attacker embeds a malicious prompt in a website's text. When summarized by the LLM, it tricks the LLM into stealing data. 

3. An attacker uploads a resume with a hidden prompt injection. When summarized by the LLM, it causes biased and incorrect outputs.

4. A website exploits an LLM shopping plugin with a malicious prompt to make unauthorized purchases. 

5. A website exploits other LLM plugins with malicious prompts to scam users.

### Prevention and Mitigation Strategies

1. Restrict the LLM's access to backends and APIs using the principle of least privilege.

2. Require user approval before allowing the LLM to take sensitive actions. 

3. Separate and label external text from user prompts.

4. Treat the LLM as untrusted and maintain user control over decisions.

5. Visually highlight potentially untrustworthy LLM responses to users.

### Example Attack Scenarios

1. An attacker overwrites the prompt to force the LLM to steal data by exploiting vulnerabilities.

2. A website injects a prompt telling the LLM to delete a user's emails using a plugin.

3. A website tricks the LLM into stealing user data via JavaScript when summarizing malicious text. 

4. An attacker uploads a resume with a prompt causing the LLM to incorrectly assess qualifications.

5. A website uses a malicious prompt to exploit a shopping plugin to make purchases without user consent.


### Common Weakness Enumeration (CWE)

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Description: Missing or inadequate input validation leads to unchecked tainted input used directly/indirectly resulting in dangerous downstream behaviors.

  Justification: Lack of prompt input validation allows attackers to directly inject malicious instructions into the LLM system.

- [CWE-77](https://cwe.mitre.org/data/definitions/77.html): Improper Neutralization of Special Elements Used in a Command ('Command Injection')

  Description: Failure to properly encode special characters like semicolons, backticks, and quotes in prompts allows attackers to terminate the intended command and inject new malicious system commands on backend servers accessible through the LLM.

  Justification: For prompt injection, lack of input sanitization allows injecting malicious system commands.

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

  Description: Failure to properly handle special elements results in altered intended SQL command logic.

  Justification: Lack of input sanitization enables attackers to inject malicious SQL commands through prompts to access or modify databases.

- [CWE-114](https://cwe.mitre.org/data/definitions/114.html): Process Control 

  Description: The lack of isolation between user prompts and external untrusted data sources like websites allows injected instructions in one to influence and manipulate processing of the other. This loss of control enables unintended actions through prompt injections from malicious external sources.

  Justification: Mixing prompts and external sources enables injected instructions due to lack of isolation.

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Description: Injected prompts with special syntax can grant higher privileges, add fake credentials, or directly disable access controls. This allows bypassing restrictions on what actions the LLM can perform, enabling escalated unauthorized access to backend systems.

  Justification: Injected prompts can bypass access controls, enabling privilege escalation on backend systems and unauthorized access through the LLM.

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication

  Description: Weak or missing authentication mechanisms for LLM access allows attackers to remotely inject malicious prompts while evading detection. Without sufficiently verifying identities, remote prompt injection can go unnoticed.

  Justification: Weak authentication allows remote attackers to inject prompts and manipulate the LLM while evading detection.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error

  Description: Not verifying the source of prompt inputs allows attackers to hijack LLM conversations by injecting prompts from malicious external sources disguised as the user or authorized systems.

  Justification: Lack of origin validation allows injecting prompts from untrusted external sources.


### MITRE ATT&CK® Techniques 

- [T1059](https://attack.mitre.org/techniques/T1059/): Command and Scripting Interpreter

  Description: Adversaries leverage command interpreters and scripting engines used for automation and program execution to run malicious commands and scripts. Commands injected into prompts through lack of input validation could take advantage of these interpreters on backend servers and systems accessible through the LLM to achieve arbitrary remote code execution.

  Justification: Can directly enable code execution from injected prompt commands.

- [T1078](https://attack.mitre.org/techniques/T1078/): Valid Accounts

  Description: Adversaries may obtain credentials from compromised accounts with the needed privileges for LLM access. Privileged valid credentials could enable bypassing access controls when injecting prompts.

  Justification: Compromised privileged accounts can allow prompt injection while bypassing access controls.

- [T1090](https://attack.mitre.org/techniques/T1090/): Proxy

  Description: Adversaries may compromise systems and use them as a proxy for prompting the LLM to hide their true identity. Proxies could be leveraged to deliver prompts with injected malicious instructions.

  Justification: Proxies can obscure the source of injected prompts.

- [T1566](https://attack.mitre.org/techniques/T1566/): Phishing

  Description: Adversaries deploy phishing messages containing malicious attachments or links to get users to unknowingly download malware, visit credential harvesting sites, or provide sensitive information. Similarly, phishing messages could be crafted to manipulate users into interacting with the LLM in ways that inject malicious prompts, tricking the LLM into carrying out unintended and potentially harmful actions on behalf of the user.

  Justification: Could deliver injected prompts through phishing messages.


### MITRE ATLAS™ Techniques 

- AML.T0006: Active Scanning

  Description: Adversaries may actively probe the LLM system to identify vulnerabilities in input validation, authentication, and access controls that could enable prompt injection attacks.

  Justification: Active scanning can discover avenues for prompt injection by mapping out weak points in validation logic, insufficient authentication, and inadequate access controls.

- AML.T0012: Valid Accounts

  Description: Adversaries may compromise credentials or API keys granting LLM access in order to directly inject malicious prompts while bypassing access controls.

  Justification: Valid credentials provide an authenticated session for adversaries to directly inject prompts, bypassing access restrictions.
  
- AML.T0040: ML Model Inference API Access

  Description: Adversaries may use inference API access as a vector to directly inject malicious prompts designed to manipulate LLM behaviors and access restricted functionality by exploiting vulnerabilities in input validation and authentication.

  Justification: Inference API access enables overriding prompts with injections that manipulate model behaviors by exploiting insufficient validation.

- AML.T0043: Craft Adversarial Data

  Description: Adversaries may carefully craft prompts with injected instructions that manipulate LLM behaviors and access functionality exceeding permission levels by exploiting inadequate input validation.

  Justification: Carefully crafted prompts precisely control behaviors via injected commands that sidestep validation checks.

- AML.T0044: Full ML Model Access

  Description: Full access provides adversaries total control to inject prompts and override safeguards by exploiting lacking input validation and authentication controls, enabling optimal manipulation.

  Justification: Unconstrained access optimally exploits lacking controls by enabling complete manipulation of prompts.

- AML.T0047: ML-Enabled Product or Service

  Description: Access to LLM-enabled services provides adversaries an attack vector for indirect prompt injection by submitting crafted external inputs containing malicious prompts that are unintentionally triggered when processed.

  Justification: LLM-enabled services can inadvertently activate injected prompts from crafted external inputs.


### MITRE ATT&CK® Mitigations

- [M1037](https://attack.mitre.org/mitigations/M1037/): Application Configuration

  Description: Adversaries may take advantage of application configurations that enable access without proper restrictions. Properly configuring access controls, permissions, trusts, and authentication mechanisms helps reduce the attack surface for prompt injections.

  Justification: Hardening application configurations reduces attack surface.

- [M1041](https://attack.mitre.org/mitigations/M1041/): Restrict Web-Based Content

  Description: Limiting web content execution through allowlisting, sandboxing, or blocking scripts helps prevent web pages from manipulating the LLM through injected prompts when summarizing text. This reduces the risk of indirect prompt injection.

  Justification: Limits web vectors that could enable injected prompts.

- [M1043](https://attack.mitre.org/mitigations/M1043/): Isolate System or Network

  Description: Isolating the network segments, systems, and access between the LLM, user inputs, and backend resources helps prevent lateral movement and exploitation through injected prompts.

  Justification: Limits impact of injected prompts.

- [M1047](https://attack.mitre.org/mitigations/M1047/): Implement Software Restriction Policies

  Description: Implementing whitelisting policies restricting code execution and scripting helps prevent untrusted code and payloads from being executed through injected prompts.

  Justification: Prevents execution of code from injected prompts.



### MITRE ATLAS™ Mitigations

- AML.M0002: Passive ML Output Obfuscation
  Description: Decreasing the fidelity of model outputs provided to the end user can reduce an adversaries ability to extract information about the model and optimize attacks for the model.

- AML.M0004: Restrict Number of ML Model Queries
  Description: Limit the total number and rate of queries a user can perform.

- AML.M0005: Control Access to ML Models and Data at Rest
  Description: Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users.

- AML.M0011: Restrict Library Loading
  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for loading of malicious libraries.

- AML.M0015: Adversarial Input Detection
  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

- AML.M0017: Model Distribution Methods
  Description: Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model. 
