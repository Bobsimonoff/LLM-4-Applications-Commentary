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

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Failure to properly validate input data. Failure to properly validate user inputs such as prompts enables the introduction of malicious payloads that can manipulate LLM behavior. Could allow direct injection of malicious prompts by failing to validate prompt inputs. 

- [CWE-77](https://cwe.mitre.org/data/definitions/77.html): Improper Neutralization of Special Elements Used in a Command ('Command Injection') - Failure to properly neutralize special elements that could modify the intended command. Lack of input neutralization could allow injecting prompts that execute commands by failing to neutralize special characters in prompts.

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Input Validation - Weakness in input validation. Lack of prompt input validation enables injecting malicious prompts by failing to properly validate prompt inputs.

- [CWE-114](https://cwe.mitre.org/data/definitions/114.html): Process Control - Lack of control over processes triggered by external inputs. The lack of separation between user prompts and external data leads to a loss of control over LLM processing, enabling unintended actions. Could allow injection of prompts from untrusted external sources due to lack of isolation between prompts and external data.

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Failure to restrict access to authorized users. Prompt injections can bypass access controls, enabling attackers to achieve privilege escalation and gain unauthorized access to systems and data. Could enable escalation for both direct and indirect prompt injection by bypassing access controls.  

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication - Failure to adequately authenticate entities. Weak authentication mechanisms allow attackers to remotely manipulate the LLM while evading detection. Could allow undetected remote prompt injection due to weak authentication.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error - Failure to validate input source. Not properly validating the origin of inputs such as prompts leaves the system open to manipulation through malicious external sources. Could enable injection from untrusted external sources due to lack of origin validation.

## ATT&CK Techniques 

- [T1059](https://attack.mitre.org/techniques/T1059/): Command and Scripting Interpreter - Use of interpreters to execute commands. Executes commands via interpreters. Could enable code execution from injections by executing injected prompt commands.

- [T1566](https://attack.mitre.org/techniques/T1566/): Phishing - Use of fraudulent messages to deliver payloads. Deploys messages to manipulate users. Could deliver injected prompts through phishing messages.  

- [T1571](https://attack.mitre.org/techniques/T1571/): Non-Standard Port - Use of non-standard ports to bypass restrictions. Uses non-standard ports. Could access systems to inject prompts by bypassing defenses via obscure ports. 


## MITRE ATLAS Techniques

- [AML.T0040](/techniques/AML.T0040): ML Model Inference API Access - Use of the ML model inference API to send crafted input data and manipulate model behavior. Adversaries could craft malicious prompts and inject them into the model via the inference API. This allows adversaries to directly inject prompts into the model to manipulate its behavior.

- [AML.T0047](/techniques/AML.T0047): ML-Enabled Product or Service - Exploitation of an existing machine learning product/service by taking advantage of vulnerabilities. Adversaries could exploit prompt vulnerabilities in commercial services that use LLMs under the hood. External services provide a pathway for adversaries to inject malicious prompts.

- [AML.T0044](/techniques/AML.T0044): Full ML Model Access - Gaining complete access to the target ML model, including its architecture and parameters. With full white-box access, adversaries could directly manipulate the model with malicious prompts. Full access allows adversaries to optimize prompt injections.

- [AML.T0043](/techniques/AML.T0043): Craft Adversarial Data - Carefully crafting input data designed to manipulate model behavior. Adversaries could craft prompts designed to manipulate model behavior. Allows adversaries to tailor injection payloads. 

- [AML.T0012](/techniques/AML.T0012): Valid Accounts - Obtaining and abusing credentials of existing accounts as a means of gaining initial access. Compromised credentials could allow adversaries to bypass authentication and directly interact with the model. Provides API access for prompt injections.

- [AML.T0016](/techniques/AML.T0016): Obtain Capabilities - Obtaining tools, exploits, and frameworks to support operations. Adversaries may obtain tools to aid in crafting effective prompt injections. Supports developing injection payloads. 

- [AML.T0010](/techniques/AML.T0010): ML Supply Chain Compromise - Manipulation of ML components and services. Could allow adversaries to introduce vulnerabilities via compromised model artifacts. Introduces weaknesses enabling injections.

- [AML.T0011](/techniques/AML.T0011): User Execution - Users tricked into executing adversary payloads. Users may unknowingly execute prompts containing injections from documents. Causes unintentional execution of injections.

- [AML.T0019](/techniques/AML.T0019): Publish Poisoned Data - Distribution of contaminated datasets. Adversaries could poison public datasets with malicious prompts that exploit models trained on the data. Poisons datasets to persistently embed injections.


## ATT&CK Mitigations

- [M1041](https://attack.mitre.org/mitigations/M1041/): Restrict Web-Based Content - Limit web content execution. Limits web content execution. Could block web-based prompt injection by restricting web content execution.

- [M1042](https://attack.mitre.org/mitigations/M1042/): Disable or Remove Feature or Program - Disabling or removing risky features or programs. Removes risky features. Could eliminate vulnerable plugin functions enabling injections by disabling them. 

- [M1043](https://attack.mitre.org/mitigations/M1043/): Isolate System or Network - Isolating systems from untrusted networks. Isolates systems and networks. Could prevent lateral movement from injected prompts by isolating compromised systems.


## MITRE ATLAS Mitigations

- [AML.M0004](/mitigations/AML.M0004): Restrict Number of ML Model Queries - Limiting the number and frequency of queries to the ML model. Limit total queries and rate. Prevents excessive probing of model to craft attacks. Restricts adversary reconnaissance. 

- [AML.M0015](/mitigations/AML.M0015): Adversarial Input Detection - Detecting and blocking potentially malicious input data. Detect and block malicious prompts before reaching model. Directly blocks injection attempts. Stops injections at network edge.

- [AML.M0014](/mitigations/AML.M0014): Verify ML Artifacts - Checking ML artifacts for integrity and signs of tampering. Verify artifacts not modified or contain injections. Checks for prompt tampering. Identifies injected artifacts.

- [AML.M0013](/mitigations/AML.M0013): Code Signing - Enforcing integrity checks on software and binaries. Prevent execution of unverified code that could enable injections. Blocks untrusted code execution. Prevents unverified execution. 

- [AML.M0018](/mitigations/AML.M0018): User Training - Educating users about adversary TTPs and disinformation. Train users on potential injection risks. Reduces likelihood of unknowingly enabling injections. Improves threat awareness.

- [AML.M0016](/mitigations/AML.M0016): Vulnerability Scanning - Scanning systems and assets for flaws and weaknesses. Scan for potential injection flaws. Identifies vulnerabilities for remediation. Discovers injection risks.

- [AML.M0007](/mitigations/AML.M0007): Sanitize Training Data - Detecting and removing malicious training data. Remove injected prompts from training data. Addresses poisoning risks that could lead to injection. Limits data persistence.



