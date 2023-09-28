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

## Common Weakness Enumeration (CWE)

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation. Failure to properly validate user inputs such as prompts enables the introduction of malicious payloads that can manipulate LLM behavior. Could allow direct injection of malicious prompts.

- [CWE-114](https://cwe.mitre.org/data/definitions/114.html): Process Control. The lack of separation between user prompts and external data leads to a loss of control over LLM processing, enabling unintended actions. Could allow injection of prompts from untrusted external sources.

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization. Prompt injections can bypass access controls, enabling attackers to achieve privilege escalation and gain unauthorized access to systems and data. Could enable escalation for both direct and indirect prompt injection.  

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication. Weak authentication mechanisms allow attackers to remotely manipulate the LLM while evading detection. Could allow undetected remote prompt injection.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error. Not properly validating the origin of inputs such as prompts leaves the system open to manipulation through malicious external sources. Could enable injection from untrusted external sources.


## ATT&CK Techniques

- [T1059](https://attack.mitre.org/techniques/T1059/) - Command and Scripting Interpreter. Executes commands via interpreters. Could enable code execution from injections.

- [T1566](https://attack.mitre.org/techniques/T1566/) - Phishing. Deploys messages to manipulate users. Could deliver injected prompts.  

- [T1571](https://attack.mitre.org/techniques/T1571/) - Non-Standard Port. Uses non-standard ports. Could access systems to inject prompts.

## ATT&CK Mitigations

- [M1041](https://attack.mitre.org/mitigations/M1041/) - Restrict Web-Based Content. Limits web content execution. Could block web-based prompt injection.

- [M1042](https://attack.mitre.org/mitigations/M1042/) - Disable or Remove Feature or Program. Removes risky features. Could eliminate vulnerable plugin functions.

- [M1043](https://attack.mitre.org/mitigations/M1043/) - Isolate System or Network. Isolates systems and networks. Could prevent lateral movement from injected prompts.


## MITRE ATLAS Techniques

- AML.T0040: ML Model Inference API Access. Adversaries could craft malicious prompts and inject them into the model via the inference API.

- AML.T0047: ML-Enabled Product or Service. Adversaries could exploit prompt vulnerabilities in commercial services that use LLMs under the hood. 

- AML.T0044: Full ML Model Access. With full white-box access, adversaries could directly manipulate the model with malicious prompts.

- AML.T0043: Craft Adversarial Data. Adversaries could craft prompts designed to manipulate model behavior.

- AML.T0012: Valid Accounts. Compromised credentials could allow adversaries to bypass authentication and directly interact with the model. 

- AML.T0016: Obtain Capabilities. Adversaries may obtain tools to aid in crafting effective prompt injections.

- AML.T0010: ML Supply Chain Compromise. Could allow adversaries to introduce vulnerabilities via compromised model artifacts. 

- AML.T0011: User Execution. Users may unknowingly execute prompts containing injections from documents.

- AML.T0019: Publish Poisoned Data. Adversaries could poison public datasets with malicious prompts that exploit models trained on the data.


## MITRE ATLAS Mitigations

- AML.M0004: Restrict Number of ML Model Queries. Limit total queries and rate. Prevents excessive probing of model to craft attacks.

- AML.M0015: Adversarial Input Detection. Detect and block malicious prompts before reaching model. Directly blocks injection attempts. 

- AML.M0014: Verify ML Artifacts. Verify artifacts not modified or contain injections. Checks for prompt tampering. 

- AML.M0013: Code Signing. Prevent execution of unverified code that could enable injections. Blocks untrusted code execution.

- AML.M0018: User Training. Train users on potential injection risks. Reduces likelihood of unknowingly enabling injections. 

- AML.M0016: Vulnerability Scanning. Scan for potential injection flaws. Identifies vulnerabilities for remediation.

- AML.M0007: Sanitize Training Data. Remove injected prompts from training data. Addresses poisoning risks that could lead to injection.


