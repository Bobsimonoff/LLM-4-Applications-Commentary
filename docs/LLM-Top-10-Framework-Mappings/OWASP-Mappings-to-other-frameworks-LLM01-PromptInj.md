By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

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

  Justification: Insufficient input validation not only allows attackers to inject malicious instructions but can also compromise the integrity and availability of the LLM, thereby making it a critical concern for secure LLM deployments.

- [CWE-77](https://cwe.mitre.org/data/definitions/77.html): Improper Neutralization of Special Elements Used in a Command ('Command Injection')

  Description: Failure to properly encode special characters like semicolons, backticks, and quotes in prompts allows attackers to terminate the intended command and inject new malicious system commands on backend servers accessible through the LLM.

  Justification: For prompt injection, lack of input sanitization allows injecting malicious system commands.


- [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

  Description: The failure to sanitize user input can allow an attacker to inject scripts that are executed in the user's browser.

  Justification: Attackers can exploit this weakness to inject malicious scripts into prompts, potentially impacting LLMs that interact with web-based content, like chatbots.

  
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

  Description: Failure to properly handle special elements results in altered intended SQL command logic.

  Justification: Lack of input sanitization not only allows SQL command injections via prompts but can also lead to unauthorized data access, financial fraud, and other high-risk vulnerabilities when interacting with backend databases.

- [CWE-114](https://cwe.mitre.org/data/definitions/114.html): Process Control

  Description: The lack of isolation between user prompts and external untrusted data sources like websites allows injected instructions in one to influence and manipulate processing of the other. This loss of control enables unintended actions through prompt injections from malicious external sources.

  Justification: Lack of prompt segregation allows external untrusted data to mix with user-generated prompts, leading to potential exploitation through prompt injections.
  
- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Description: Injected prompts with special syntax can grant higher privileges, add fake credentials, or directly disable access controls. This allows bypassing restrictions on what actions the LLM can perform, enabling escalated unauthorized access to backend systems.

  Justification: Injected prompts can bypass access controls, enabling privilege escalation on backend systems and unauthorized access through the LLM.
  
- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication

  Description: Weak or missing authentication mechanisms for LLM access allows attackers to remotely inject malicious prompts while evading detection. Without sufficiently verifying identities, remote prompt injection can go unnoticed.

  Justification: Weak authentication allows remote attackers to inject prompts and manipulate the LLM while evading detection.
  
- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error

  Description: Not verifying the source of prompt inputs allows attackers to hijack LLM conversations by injecting prompts from malicious external sources disguised as the user or authorized systems.

  Justification: Lack of origin validation allows injecting prompts from untrusted external sources.


### Techniques

### MITRE ATT&CK® Techniques

- [T1059](https://attack.mitre.org/techniques/T1059/): Command and Scripting Interpreter

  Description: Adversaries leverage command interpreters and scripting engines used for automation and program execution to run malicious commands and scripts. Commands injected into prompts through lack of input validation could take advantage of these interpreters on backend servers and systems accessible through the LLM to achieve arbitrary remote code execution.

  Justification: Enables code execution and potentially provides a gateway for an attacker to escalate privileges or perform lateral movement, making it a high-risk vector for LLM systems.

- [T1078](https://attack.mitre.org/techniques/T1078/): Valid Accounts

  Description: Adversaries may obtain credentials from compromised accounts with the needed privileges for LLM access. Privileged valid credentials could enable bypassing access controls when injecting prompts.

  Justification: Compromised privileged accounts not only allow prompt injection but also enable attackers to access more secure and sensitive parts of the system, thereby increasing the risk magnitude significantly.

- [T1090](https://attack.mitre.org/techniques/T1090/): Proxy

  Description: Adversaries may compromise systems and use them as a proxy for prompting the LLM to hide their true identity. Proxies could be leveraged to deliver prompts with injected malicious instructions.

  Justification: Proxies can obscure the source of injected prompts.

- [T1190](https://attack.mitre.org/techniques/T1190/): Exploit Public-Facing Application

  Description: Adversaries may exploit vulnerabilities in public-facing applications to facilitate prompt injection attacks.

  Justification: Prompt injection in a large language model can be a significant threat when the LLM is part of a public-facing application.


- [T1548](https://attack.mitre.org/techniques/T1548/): Abuse Elevation Control Mechanism

  Description: Attackers may bypass permission schemes for higher-level access to systems.

  Justification: Especially relevant for systems where LLMs are a part of complex permission and access control structures, potentially being manipulated to elevate privileges.

- [T1550](https://attack.mitre.org/techniques/T1550/): Use Alternate Authentication Material

  Description: Attackers may use different types of credentials as a way to authenticate and bypass the regular security mechanisms.

  Justification: This is particularly relevant as LLMs may store or have access to multiple types of credentials. 

- [T1566](https://attack.mitre.org/techniques/T1566/): Phishing

  Description: Adversaries deploy phishing messages containing malicious attachments or links to get users to unknowingly download malware, visit credential harvesting sites, or provide sensitive information. Similarly, phishing messages could be crafted to manipulate users into interacting with the LLM in ways that inject malicious prompts, tricking the LLM into carrying out unintended and potentially harmful actions on behalf of the user.

  Justification: Phishing campaigns can cleverly deliver prompts that manipulate LLMs into executing malicious actions, thereby directly impacting user data and system integrity.


### MITRE ATLAS™ Techniques

- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006/): Active Scanning

  Description: Adversaries may actively probe the LLM system to identify vulnerabilities in input validation, authentication, and access controls that could enable prompt injection attacks.

  Justification: Active scanning can discover avenues for prompt injection by mapping out weak points in validation logic, insufficient authentication, and inadequate access controls.

- [AML.T0012](https://atlas.mitre.org/techniques/AML.T0012/): Valid Accounts

  Description: Adversaries may compromise credentials or API keys granting LLM access in order to directly inject malicious prompts while bypassing access controls.

  Justification: Valid credentials provide an authenticated session for adversaries to directly inject prompts, bypassing access restrictions.
  
- [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020/): Poison Training Data

  Description: Adversaries may attempt to poison datasets used by a ML model by modifying the underlying data or its labels. This allows the adversary to embed vulnerabilities in ML models trained on the data that may not be easily detectable. Data poisoning attacks may or may not require modifying the labels.

  Justification: Data poisoning could make the LLM more susceptible to prompt injection by weakening its ability to identify malicious input.

- [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040/): ML Model Inference API Access

  Description: Adversaries may use inference API access as a vector to directly inject malicious prompts designed to manipulate LLM behaviors and access restricted functionality by exploiting vulnerabilities in input validation and authentication.

  Justification: Direct access to Inference APIs exposes the LLM to targeted prompt injections, which can be exploited if input validation is inadequate.

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data

  Description: Adversaries may carefully craft prompts with injected instructions that manipulate LLM behaviors and access functionality exceeding permission levels by exploiting inadequate input validation.

  Justification: Beyond simply controlling behaviors, adversaries can use these carefully crafted prompts to gain unauthorized access or privilege escalation, thus increasing the potential harm.

- [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044/): Full ML Model Access

  Description: Full access provides adversaries total control to inject prompts and override safeguards by exploiting lacking input validation and authentication controls, enabling optimal manipulation.

  Justification: Unconstrained access optimally exploits lacking controls by enabling complete manipulation of prompts.

- [AML.T0047](https://atlas.mitre.org/techniques/AML.T0047/): ML-Enabled Product or Service

  Description: Access to LLM-enabled services provides adversaries an attack vector for indirect prompt injection by submitting crafted external inputs containing malicious prompts that are unintentionally triggered when processed.

  Justification: LLM-enabled services can inadvertently activate injected prompts from crafted external inputs.
  
- [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020/): Poison Training Data

  Description: Adversaries may attempt to poison datasets used by a ML model by modifying the underlying data or its labels. This allows the adversary to embed vulnerabilities in ML models trained on the data that may not be easily detectable. Data poisoning attacks may or may not require modifying the labels.

  Justification: Data poisoning could make the LLM more susceptible to prompt injection by weakening its ability to identify malicious input.


### Mitigations

### MITRE ATT&CK® Mitigations

- [M1027](https://attack.mitre.org/mitigations/M1027/): Password Policies

  Description: Set and enforce secure password policies for accounts.

  Justification: Implementing strong password policies is essential for mitigating the risk of unauthorized access that could facilitate prompt injection attacks.

- [M1032](https://attack.mitre.org/mitigations/M1032/): Multi-factor Authentication

  Description: Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.

  Justification: Multi-factor authentication makes unauthorized prompt injection significantly more difficult by requiring multiple forms of verification.

- [M1038](https://attack.mitre.org/mitigations/M1038/): Execution Prevention

  Description: Block execution of code on a system through application control, and/or script blocking.

  Justification: Preventing arbitrary code execution helps limit the impact of injected code execution commands. 

- [M1042](https://attack.mitre.org/mitigations/M1042/): Disable or Remove Feature or Program

  Description: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

  Justification: By narrowing down the software stack to essential components, we not only reduce the attack surface but also simplify the task of monitoring and securing remaining components, thereby enhancing the effectiveness of countermeasures against prompt injection attacks.

### MITRE ATLAS™ Mitigations

- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002): Passive ML Output Obfuscation

  Description: Decreasing the fidelity of model outputs provided to the end user can reduce an adversaries ability to extract information about the model and optimize attacks for the model.

  Justification: Obfuscating outputs can help prevent attackers from fine-tuning prompt injections to maximize impact.

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004): Restrict Number of ML Model Queries

  Description: Limit the total number and rate of queries a user can perform.

  Justification: Restricting queries limits opportunities for attackers to test and refine prompt injections.

- [AML.M0005](https://atlas.mitre.org/mitigations/AML.M0005): Control Access to ML Models and Data at Rest

  Description: Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users.

  Justification: Limiting access to both the machine learning models and training data can significantly reduce the risk of unauthorized prompt injections and should be a part of the overall security posture.

- [AML.M0011](https://atlas.mitre.org/mitigations/AML.M0011): Restrict Library Loading

  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for loading of malicious libraries.

  Justification: Library loading restrictions can help prevent execution of arbitrary code injected via prompts.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015): Adversarial Input Detection

  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

  Justification: Detecting anomalies in prompts can identify potential injection attempts.

- [AML.M0017](https://atlas.mitre.org/mitigations/AML.M0017): Model Distribution Methods

  Description: Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model.

  Justification: Centralized model serving limits access that could be exploited for direct prompt injection.

### Additional Mitigations


- User Training

  Description: Train users to recognize and report potential indicators of prompt injection attacks.

  Justification: Well-informed users can act as an additional layer of security against prompt injection, potentially recognizing malicious prompts before they can be executed.
  
- Application Isolation and Sandboxing

  Description: Limit the resources and interactions an application has access to by running it in a sandbox or similar isolation environment.

  Justification: Isolating the LLM environment can reduce the impact of successful prompt injection attacks by limiting what resources the LLM can access or interact with.


- Query Auditing

  Description: Audit and monitor queries made to the ML model to identify suspicious activity.

  Justification: Real-time auditing can provide insights into potential malicious activity, allowing for timely intervention.
  
- Input Sanitization and Validation

  Description: Implement rigorous input validation and sanitization mechanisms to filter out malicious prompts or commands.

  Justification: One of the most effective ways to mitigate prompt injection is to validate and sanitize all incoming inputs, thereby eliminating or escaping harmful sequences.


### STRIDE Analysis (generated by clause.ai)

Prompt injection attacks can impact multiple components of the STRIDE threat model:

**Spoofing**

- Attackers can spoof the origin of injected prompts to disguise their source. 
- Injected prompts could also spoof user identity or authentication credentials to access restricted data and functions.

**Tampering** 

- Malicious prompts can tamper with model behaviors, predictions, system interactions, and data.
- Carefully crafted prompts precisely control model actions through malicious injected instructions.

**Repudiation**

- Lack of logging around injected prompts can complicate attack attribution.
- Prompt injection attacks could also tamper with or disable logging to undermine attribution.

**Information Disclosure**

- Injected prompts can trick models into revealing sensitive information about users, systems, or training data.
- Indirect injection through web inputs could extract sensitive data via malicious text processing.

**Denial of Service**

- Specially crafted prompts could trigger crashes, resource exhaustion, or make models unusable.
- Web inputs with recursive prompts could cause infinite inference loops.

**Elevation of Privilege**

- Injected prompts could escalate privileges or disable access controls on backend systems.  
- Compromised credentials enable bypassing access controls when injecting prompts.

In summary, prompt injection primarily threatens integrity via tampering, availability through denial of service, and confidentiality by exposing sensitive information. Spoofing disguises attack origin, while elevation of privilege is a common secondary impact.
