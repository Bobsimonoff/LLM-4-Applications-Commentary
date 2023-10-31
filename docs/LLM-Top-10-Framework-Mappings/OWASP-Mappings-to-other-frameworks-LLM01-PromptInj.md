By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM01: Prompt Injection

### Summary

Crafted prompts can manipulate LLMs to cause unauthorized access, data breaches, and compromised decision-making.

### Description

Prompt injection attacks involve crafting malicious prompts that manipulate LLMs into executing unintended and potentially harmful actions. These attacks exploit the lack of segregation between instructions and data in LLMs. 

Attackers can directly inject rogue prompts into the LLM, an attack called "jailbreaking", which overrides safeguards. Indirect prompt injection involves embedding malicious prompts in external content like websites, which then manipulates the LLM's behavior and output when processed.

Successful attacks can lead to impacts like unauthorized access, data breaches, financial fraud, and compromised decision-making. Compromised LLMs may also circumvent safeguards, act as intermediaries to manipulate information or exploit backend systems, allowing attackers to achieve objectives undetected.

Prevention involves restricting LLM access, requiring confirmation, isolating prompts, establishing trust boundaries, and indicating untrustworthy responses.

Not to be confused with:

- LLM07: Insecure Plugin Design - While flaws like insufficient output sanitization in the plugin could enable insecure plugins to become vectors for indirect prompt injection, indirect prompt injections could come from LLMs accessing external systems directly or from 3rd party plugins which are not addressed by insecure plugin design.

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


### MITRE ATLAS™ 

#### Techniques
- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data - Prompt injection attacks involve carefully crafting prompts (adversarial data) that manipulate the LLM to produce unintended and potentially harmful outputs. The crafted prompts exploit vulnerabilities in the LLM's training and design to achieve objectives like unauthorized access, financial fraud, etc.

#### Mitigations

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004/): Restrict Number of ML Model Queries. Limit the total number and rate of queries a user can perform. Suggested approaches: - Limit the number of queries users can perform in a given interval to hinder an attacker's ability to send computationally expensive inputs - Limit the amount of information an attacker can learn about a model's ontology through API queries. - Limit the volume of API queries in a given period of time to regulate the amount and fidelity of potentially sensitive information an attacker can learn. - Limit the number of queries users can perform in a given interval to shrink the attack surface for black-box attacks. - Limit the number of queries users can perform in a given interval to prevent a denial of service.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.

#### Possible Additions

**New Technique Proposals**

- AML.TXXXX: Insert Malicious Prompt via User Upload - Adding a malicious prompt to user-provided content like resumes, support tickets, etc. that then compromises the LLM when processed.

- AML.TXXXX: Embed Malicious Prompt in External Data Source - Embedding a malicious prompt in any external data sources like files, databases, websites, etc. that compromises the LLM when processed. 

- AML.TXXXX: Exploit LLM Plugin - Exploiting vulnerabilities in LLM plugins to manipulate behavior with a malicious prompt.

**New Mitigation Proposals**

- AML.MXXXX: Sanitize User Uploads - Remove or neutralize potentially malicious prompts from user-provided content before processing to prevent compromise.

- AML.MXXXX: Isolate External Data - Run any external data sources like files, databases, websites in an isolated environment to prevent malicious prompts from impacting the LLM.

- AML.MXXXX: LLM Plugin Security Review - Rigorously review LLM plugins for potential injection flaws before deployment to prevent compromise.

- AML.MXXXX: Prompt Request/Response Auditing - Log and audit prompt requests and responses to identify anomalies indicating potential attacks.

- AML.MXXXX: Prompt Input Validation & Sanitization - Validate and sanitize prompt inputs to neutralize potentially malicious prompts before processing.


### STRIDE Analysis (generated by claude.ai)

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


### Common Weakness Enumeration (CWE)

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Summary: Not validating or incorrectly validating input allows attackers to craft inputs that can exploit the system in unexpected ways.

  Exploit: Without proper validation of user prompts, an attacker could inject additional instructions, special characters, or malicious code sequences that when processed by the LLM could lead to unintended behavior, such as executing unwanted commands, accessing unauthorized data, or bypassing restrictions. Lack of prompt input validation provides the opening for attackers to craft carefully designed prompts that manipulate model behavior.

- [CWE-74](https://cwe.mitre.org/data/definitions/74.html): Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')

  Summary: The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.


- [CWE-77](https://cwe.mitre.org/data/definitions/77.html): Improper Neutralization of Special Elements used in a Command ('Command Injection')

  Summary: Improper neutralization of special elements in user prompts could allow injected instructions to modify and extend the intended command.

  Exploit: When processing prompts, the LLM may construct system commands to perform required queries or data fetching operations. If prompts contain un-neutralized special elements like backticks, an attacker could terminate the intended command and inject new malicious commands that get executed on backend systems accessible through the LLM interface. This command injection can lead to unauthorized actions like data exfiltration, privilege escalation, and denial of service.

- [CWE-114](https://cwe.mitre.org/data/definitions/114.html): Process Control

  Summary: Lack of isolation between user prompts and external data sources could enable unintended processing behavior.

  Exploit: Often LLMs incorporate external data from websites, databases, etc. into prompts to provide contextual grounding. If prompts and external data are not properly isolated, an attacker could inject malicious instructions into the external data source. When the compromised data source text gets incorporated into a prompt, the injected instructions could manipulate the LLM into executing unintended and potentially harmful actions.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error

  Summary: Not validating the source of input enables spoofing and injection from untrusted sources.

  Exploit: When processing user prompts, failing to validate the origin of the input could allow an attacker to impersonate a legitimate user and inject malicious prompts. Without checking the source, spoofed input from unauthorized external systems can manipulate LLM behavior in unintended ways. Proper origin validation restricts ability to inject prompts from untrusted origins.


---

# IGNORE the below FOR NOW - NEED RE-REVIEW


### MITRE ATT&CK® 

#### Techniques

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

#### Mitigations

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

