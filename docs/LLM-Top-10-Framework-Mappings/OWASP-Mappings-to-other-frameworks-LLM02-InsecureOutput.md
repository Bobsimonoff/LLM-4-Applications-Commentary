By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LM02: Insecure Output Handling

### Summary

Neglecting to validate Large Language Model outputs may lead to downstream security exploits, including code execution that compromises systems and exposes data.

### Description

Insecure Output Handling arises when downstream components blindly accept LLM outputs without scrutiny, enabling attackers to indirectly access functionality or trigger exploits.

Neglecting to validate or sanitize LLM-generated outputs before passing them to backend systems, browsers, or other downstream components can enable code execution, system compromise, and data exposure. Attackers can manipulate LLM output via crafted prompts, similar to providing indirect user access. 

Successful attacks can lead to privilege escalation, command injection, XSS, SSRF, and remote code execution. High LLM privileges and external prompt injection increase impacts.

Prevention involves treating the LLM as any other user, applying input validation and sanitization per OWASP guidelines, and encoding outputs to mitigate code execution. LLM access should be limited using least privilege principles.


### Common Examples of Risk 

1. Executing unchecked LLM output in system shells enabling command injection.

2. Returning unvalidated JavaScript/Markdown from LLM to browsers causing XSS.

### Prevention and Mitigation Strategies

1. Validate LLM outputs to backends per OWASP input validation guidelines.

2. Encode LLM outputs to users per OWASP output encoding guidance.

### Example Attack Scenarios

1. Unvalidated chatbot response executed as system commands, allowing RCE.

2. Website summarizer exfiltrates data through LLM output encoding. 

3. LLM generates malicious SQL query that wipes database after execution.

4. Attacker uses prompt injection for LLM to return unsanitized XSS payload.



### Common Weakness Enumeration (CWE)

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html): OS Command Injection

  Description: The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.

  Justification: Failure to validate outputs could allow command injection when passed to system functions.

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

  Description: The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

  Justification: Inadequate output encoding risks XSS vulnerabilities in web contexts.

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

  Description: The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.

  Justification: Passing outputs to SQL could lead to injection.

- [CWE-94](https://cwe.mitre.org/data/definitions/94.html): Improper Control of Generation of Code ('Code Injection')

  Description: The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.

  Justification: Direct execution of outputs could allow arbitrary code execution.

- [CWE-200](https://cwe.mitre.org/data/definitions/200.html): Exposure of Sensitive Information to an Unauthorized Actor 

  Description: The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

  Justification: Insecure handling could expose sensitive data through improper access controls.

- [CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control

  Description: The software does not restrict or incorrectly restricts access to a resource from an actor that is not explicitly authorized to access the resource.

  Justification: Lack of access control could enable exploits through unauthorized access.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: The software imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

  Justification: Untrusted outputs could trigger unintended functionality.

- [CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities

  Description: The software is out-of-date, lacking patches, or makes use of third-party components with publicly known vulnerabilities.

  Justification: Vulnerable components could mishandle outputs.


### MITRE ATT&CK Techniques

- [T1190](https://attack.mitre.org/techniques/T1190/): Exploit Public-Facing Application

  Description: Adversaries may attempt to take advantage of a weakness in an internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. Public facing applications, including APIs and cloud-based services, are common targets.

  Justification: Could exploit public model APIs by targeting exposed services that inadequately validate outputs. 

- [T1499](https://attack.mitre.org/techniques/T1499/): Endpoint Denial of Service

  Description: Adversaries may disrupt services by targeting endpoints, which are networked computing devices such as PCs, servers, and mobile devices. Different types of DoS operations can consume all available network bandwidth, exhaust computational resources, and disable services and system crash. 

  Justification: Resource exhaustion denial of service could occur from flooding endpoints with excessive outputs.


### MITRE ATLAS Techniques

- AML.T0011: User Execution 

  Description: An adversary may rely upon a user executing malicious code or outputs from a system. Users may inadvertently execute unsafe code or outputs that were not properly validated or sanitized by the system before being presented to the user.

  Justification: A user could execute unchecked malicious outputs from an LLM system, enabling exploits like XSS on the user's browser due to lack of output encoding.

- AML.T0043: Craft Adversarial Data

  Description: An adversary carefully crafts adversarial inputs to manipulate the behavior of a machine learning model and influence the outputs it generates. The modifications to the inputs are designed to achieve the adversary's objectives.

  Justification: Specially crafted prompts provided to an LLM system could produce intentionally insecure outputs, such as unvalidated code snippets, that take advantage of lack of validation in downstream systems.

- AML.T0044: Full ML Model Access

  Description: An adversary gains complete white-box access to a machine learning model, meaning they have full knowledge of the model architecture, parameters, training data, and other implementation details. This level of access enables them to meticulously craft inputs to manipulate model behavior.

  Justification: With full access to the LLM, an adversary could carefully tune prompts to maximize generation of insecure outputs such as injection payloads tailored to vulnerabilities in downstream systems.

- AML.T0045: ML Intellectual Property Theft

  Description: An adversary may exfiltrate proprietary machine learning artifacts and data in order to steal intellectual property and cause economic harm to an organization. Lack of proper validation and encoding of model outputs could enable unauthorized access to sensitive artifacts and data.

  Justification: Failure to properly handle model outputs could inadvertently expose sensitive intellectual property or enable an adversary to steal data assets due to lack of proper access controls.

- AML.T0046: Spamming ML System with Chaff Data

  Description: An adversary may overwhelm a machine learning system with a large volume of chaff data designed to increase false positives and waste the time of human analysts tasked with reviewing system outputs.

  Justification: A high volume of meaningless outputs produced by an LLM could waste substantial analyst time if incorrectly passed downstream to human reviewers without additional validation.

- AML.T0047: ML-Enabled Product or Service

  Description: An adversary leverages access to a product or service that utilizes machine learning internally to gain access to the underlying ML model. This access could then be abused to craft malicious inputs and insecure outputs.

  Justification: By gaining access to an LLM-enabled product or service, an adversary could potentially craft inputs that produce insecure outputs by exploiting the product's access to the underlying LLM.

### MITRE ATT&CK Mitigations

- [M1041](https://attack.mitre.org/mitigations/M1041/): Restrict Web-Based Content

  Description: Limiting the execution of web content including scripts helps reduce attack surface. Allowlisting trusted sources, sandboxing, and blocking unnecessary scripting helps prevent exploitation of improper output handling in web contexts.

  Justification: Could prevent execution of malicious web outputs by restricting web content.

- [M1042](https://attack.mitre.org/mitigations/M1042/): Disable or Remove Feature or Program

  Description: Disabling or removing unnecessary features and programs reduces attack surface. Disabling plugin functionalities that improperly handle outputs removes pathways for potential exploitation.

  Justification: Could eliminate plugins mishandling outputs by disabling them. 

- [M1049](https://attack.mitre.org/mitigations/M1049/): Disable or Remove Feature or Program

  Description: Disabling or removing unnecessary features and programs reduces attack surface. Disabling plugin functionalities that improperly handle outputs removes pathways for potential exploitation.

  Justification: Could eliminate plugins mishandling outputs by disabling them.


### MITRE ATLAS Mitigations 

- AML.M0018: User Training - Educating users about adversary TTPs. Train users on potential output risks. Reduces unknowing execution of insecure outputs by improving user awareness. 

- AML.M0002: Passive ML Output Obfuscation - Decreasing output fidelity to limit exposed details. Decrease output fidelity. Limits information leaked through outputs by reducing output precision. 

- AML.M0004: Restrict Number of ML Model Queries - Limiting queries to reduce attack surface. Limit total queries and rate. Reduces attack surface by restricting overall model access.

- AML.M0015: Adversarial Input Detection - Detecting and blocking malicious inputs. Detect and block malicious prompts. Blocks attempts to generate insecure outputs by identifying malicious queries. 

- AML.M0003: Model Hardening - Increasing model robustness to manipulation. Make models more robust to manipulation. Hardens model against generating insecure outputs through adversarial training.

- AML.M0007: Sanitize Training Data - Detecting and removing malicious training data. Remove data enabling insecure outputs. Addresses training data risks by cleansing datasets. 

- AML.M0014: Verify ML Artifacts - Checking artifacts for signs of tampering. Detect tampered artifacts designed to produce insecure outputs. Identifies tampering by validating artifacts.

- AML.M0016: Vulnerability Scanning - Discovering flaws and weaknesses. Scan for flaws that could lead to insecure outputs. Finds weaknesses to address through active scanning.

- AML.M0001: Limit Model Artifact Release - Reducing public release of model details. Limit public release of model details. Reduces available information to exploit models by restricting public knowledge.

- AML.M0013: Code Signing - Enforcing integrity checks on software and code. Enforce signing of model artifacts. Validates artifact integrity through cryptography. 

- AML.M0005: Control Access to ML Models and Data at Rest - Implementing access controls on models and data. Limit access to models. Reduces attack surface by restricting access. 

- AML.M0017: Model Distribution Methods - Limiting model deployment scopes. Avoid distributing models to edge devices. Limits adversary access by minimizing deployments.

- AML.M0012: Encrypt Sensitive Information - Protecting confidentiality through cryptography. Encrypt models and data. Protects artifacts by encoding them.

