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


### MITRE ATT&CK Techniques 

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


### MITRE ATLAS Techniques

- [AML.T0040](/techniques/AML.T0040): ML Model Inference API Access - Use of the ML model inference API to send crafted input data and manipulate model behavior. Adversaries could craft malicious prompts and inject them into the model via the inference API. This allows adversaries to directly inject prompts into the model to manipulate its behavior.

- [AML.T0047](/techniques/AML.T0047): ML-Enabled Product or Service - Exploitation of an existing machine learning product/service by taking advantage of vulnerabilities. Adversaries could exploit prompt vulnerabilities in commercial services that use LLMs under the hood. External services provide a pathway for adversaries to inject malicious prompts.

- [AML.T0044](/techniques/AML.T0044): Full ML Model Access - Gaining complete access to the target ML model, including its architecture and parameters. With full white-box access, adversaries could directly manipulate the model with malicious prompts. Full access allows adversaries to optimize prompt injections.

- [AML.T0043](/techniques/AML.T0043): Craft Adversarial Data - Carefully crafting input data designed to manipulate model behavior. Adversaries could craft prompts designed to manipulate model behavior. Allows adversaries to tailor injection payloads. 

- [AML.T0012](/techniques/AML.T0012): Valid Accounts - Obtaining and abusing credentials of existing accounts as a means of gaining initial access. Compromised credentials could allow adversaries to bypass authentication and directly interact with the model. Provides API access for prompt injections.

- [AML.T0016](/techniques/AML.T0016): Obtain Capabilities - Obtaining tools, exploits, and frameworks to support operations. Adversaries may obtain tools to aid in crafting effective prompt injections. Supports developing injection payloads. 

- [AML.T0010](/techniques/AML.T0010): ML Supply Chain Compromise - Manipulation of ML components and services. Could allow adversaries to introduce vulnerabilities via compromised model artifacts. Introduces weaknesses enabling injections.

- [AML.T0011](/techniques/AML.T0011): User Execution - Users tricked into executing adversary payloads. Users may unknowingly execute prompts containing injections from documents. Causes unintentional execution of injections.

- [AML.T0019](/techniques/AML.T0019): Publish Poisoned Data - Distribution of contaminated datasets. Adversaries could poison public datasets with malicious prompts that exploit models trained on the data. Poisons datasets to persistently embed injections.


### MITRE ATT&CK Mitigations

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
  

### MITRE ATLAS Mitigations

- [AML.M0004](/mitigations/AML.M0004): Restrict Number of ML Model Queries - Limiting the number and frequency of queries to the ML model. Limit total queries and rate. Prevents excessive probing of model to craft attacks. Restricts adversary reconnaissance. 

- [AML.M0015](/mitigations/AML.M0015): Adversarial Input Detection - Detecting and blocking potentially malicious input data. Detect and block malicious prompts before reaching model. Directly blocks injection attempts. Stops injections at network edge.

- [AML.M0014](/mitigations/AML.M0014): Verify ML Artifacts - Checking ML artifacts for integrity and signs of tampering. Verify artifacts not modified or contain injections. Checks for prompt tampering. Identifies injected artifacts.

- [AML.M0013](/mitigations/AML.M0013): Code Signing - Enforcing integrity checks on software and binaries. Prevent execution of unverified code that could enable injections. Blocks untrusted code execution. Prevents unverified execution. 

- [AML.M0018](/mitigations/AML.M0018): User Training - Educating users about adversary TTPs and disinformation. Train users on potential injection risks. Reduces likelihood of unknowingly enabling injections. Improves threat awareness.

- [AML.M0016](/mitigations/AML.M0016): Vulnerability Scanning - Scanning systems and assets for flaws and weaknesses. Scan for potential injection flaws. Identifies vulnerabilities for remediation. Discovers injection risks.

- [AML.M0007](/mitigations/AML.M0007): Sanitize Training Data - Detecting and removing malicious training data. Remove injected prompts from training data. Addresses poisoning risks that could lead to injection. Limits data persistence.



