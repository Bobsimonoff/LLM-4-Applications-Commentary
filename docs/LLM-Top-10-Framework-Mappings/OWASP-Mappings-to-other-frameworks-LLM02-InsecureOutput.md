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

  Justification: Failure to adequately encode LLM outputs can introduce XSS vulnerabilities when these outputs are rendered in web pages.

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

  Description: The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.

  Justification: LLM outputs that are directly passed into SQL queries without validation can lead to SQL injection vulnerabilities.

- [CWE-94](https://cwe.mitre.org/data/definitions/94.html): Improper Control of Generation of Code ('Code Injection')

  Description: The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.

  Justification: Direct execution of outputs could allow arbitrary code execution.

- [CWE-200](https://cwe.mitre.org/data/definitions/200.html): Exposure of Sensitive Information to an Unauthorized Actor 

  Description: The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

  Justification: LLM outputs that inadvertently contain sensitive information can be exposed to unauthorized actors due to insecure handling.

- [CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control

  Description: The software does not restrict or incorrectly restricts access to a resource from an actor that is not explicitly authorized to access the resource.

  Justification: Lack of access control could enable exploits through unauthorized access.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: The software imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

  Justification: Using LLMs that are not adequately vetted can lead to inclusion of malicious or untrusted functionalities.

- [CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities

  Description: The software is out-of-date, lacking patches, or makes use of third-party components with publicly known vulnerabilities.

  Justification: Vulnerable components could mishandle outputs.


### MITRE ATT&CK® Techniques

- [T1190](https://attack.mitre.org/techniques/T1190/): Exploit Public-Facing Application

  Description: Adversaries may attempt to take advantage of a weakness in an internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. Public facing applications, including APIs and cloud-based services, are common targets.

  Justification: Could exploit public model APIs by targeting exposed services that inadequately validate outputs. 


### MITRE ATLAS™ Techniques

- AML.T0040: ML Model Inference API Access

  Description: Adversaries may use inference API access to an LLM to craft malicious prompts designed to generate insecure outputs containing unvalidated code snippets or injection payloads. These payloads take advantage of inadequate output handling in downstream systems.

  Justification: Inference API access provides the ability to tune prompts to maximize insecure output generation.

- AML.T0043: Craft Adversarial Data

  Description: Adversaries may carefully craft prompts to manipulate the LLM into generating insecure outputs designed to exploit lack of validation in downstream systems. The prompts can be tuned to produce unvalidated code or injection payloads.

  Justification: Crafting prompts precisely controls LLM outputs, enabling generation of malicious payloads by exploiting inadequate downstream validation.
  
- AML.T0044: Full ML Model Access

  Description: Full white-box access enables adversaries to meticulously tune prompts to optimally exploit vulnerabilities in downstream systems by maximizing generation of insecure outputs like unvalidated code snippets or injection payloads.

  Justification: With full access, adversaries can precisely craft prompts to generate extremely tailored insecure outputs exploiting downstream systems.

- AML.T0045: ML Intellectual Property Theft

  Description: Adversaries may attempt to exfiltrate artifacts or data by manipulating LLM outputs to encode and embed sensitive information that is then decoded downstream. Insecure handling that fails to sanitize outputs could enable this exfiltration.  

  Justification: The absence of proper output sanitization mechanisms directly enables attackers to encode and embed stolen intellectual property or sensitive data, which can be subsequently decoded and exfiltrated, posing severe security and financial risks.

- AML.T0047: ML-Enabled Product or Service

  Description: By gaining access to an LLM-enabled product/service, an adversary could potentially craft prompts designed to generate insecure outputs by exploiting the product's access to the underlying LLM and lack of output validation in connected downstream systems.

  Justification: Access to LLM-enabled services provides prompting access that could produce insecure outputs.



### MITRE ATT&CK® Mitigations

- [M1027](https://attack.mitre.org/mitigations/M1027): Password Policies  

  Description: Set and enforce secure password policies for accounts.

  Justification: Strong password policies raise the bar for compromised credentials that could enable generating insecure outputs.

- [M1038](https://attack.mitre.org/mitigations/M1038): Execution Prevention

  Description: Block execution of code on a system through application control, and/or script blocking.

  Justification: Prevents arbitrary remote code execution from malicious outputs.

- [M1042](https://attack.mitre.org/mitigations/M1042): Disable or Remove Feature or Program

  Description: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

  Justification: Reduces available downstream avenues for exploiting insecure outputs.


### MITRE ATLAS™ Mitigations

- AML.M0002: Passive ML Output Obfuscation
  Description: Decreasing the fidelity of model outputs provided to the end user can reduce an adversaries ability to extract information about the model and optimize attacks for the model.

- AML.M0004: Restrict Number of ML Model Queries
  Description: Limit the total number and rate of queries a user can perform.

- AML.M0005: Control Access to ML Models and Data at Rest
  Description: Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users.

- AML.M0011: Restrict Library Loading
  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for loading of malicious libraries.

- AML.M0012: Encrypt Sensitive Information
  Description: Encrypt sensitive data such as ML models to protect against adversaries attempting to access sensitive data.

- AML.M0015: Adversarial Input Detection
  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

- AML.M0017: Model Distribution Methods
  Description: Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model. 


---


## Common Weakness Enumeration (CWE)

### Remove
- **CWE-200**: This CWE is more about exposure of sensitive information rather than insecure output handling. The focus here is on the failure to validate or sanitize LLM-generated outputs.

### Add
- [CWE-116](https://cwe.mitre.org/data/definitions/116.html): Improper Encoding or Escaping of Output

  **Description**: The software does not encode or escape data properly, leading to an issue when the data is read by a downstream component.

  **Justification**: In the context of LLMs, improper encoding or escaping of output can make downstream systems vulnerable to injection attacks.

### Update
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html): OS Command Injection

  **Old Justification**: Failure to validate outputs could allow command injection when passed to system functions.

  **New Justification**: LLM outputs that are not properly sanitized or validated can be exploited to inject malicious OS commands in downstream systems.

## MITRE ATT&CK® Techniques

### Remove
- None

### Add
- None

### Update
- None

## MITRE ATLAS™ Techniques

### Remove
- **AML.T0045**: ML Intellectual Property Theft is more related to data theft rather than insecure output handling.

### Add
- None

### Update
- None

## MITRE ATT&CK® Mitigations

### Remove
- **M1027**: Password Policies are generally not related to the handling of insecure outputs by LLMs.

### Add
- None

### Update
- None

## MITRE ATLAS™ Mitigations

### Remove
- **AML.M0002**: Passive ML Output Obfuscation is more about protecting the model rather than mitigating risks related to insecure outputs.

### Add
- **AML.M0018**: Output Validation and Sanitization

  **Description**: Implement comprehensive validation and sanitization routines for LLM-generated outputs before passing them to downstream systems.

  **Justification**: Proper validation and sanitization of LLM outputs will mitigate risks related to insecure output handling, including command injection, XSS, and SQL injection.

### Update
- None


---
# Consolidated
---

### Common Weakness Enumeration (CWE)

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html): OS Command Injection

  Description: The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.

  Justification: LLM outputs that are not properly sanitized or validated can be exploited to inject malicious OS commands in downstream systems.

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

  Description: The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

  Justification: Failure to adequately encode LLM outputs can introduce XSS vulnerabilities when these outputs are rendered in web pages.

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')  

  Description: The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.

  Justification: LLM outputs that are directly passed into SQL queries without validation can lead to SQL injection vulnerabilities.

- [CWE-94](https://cwe.mitre.org/data/definitions/94.html): Improper Control of Generation of Code ('Code Injection')

  Description: The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.

  Justification: Direct execution of outputs could allow arbitrary code execution.

- [CWE-116](https://cwe.mitre.org/data/definitions/116.html): Improper Encoding or Escaping of Output

  Description: The software does not encode or escape data properly, leading to an issue when the data is read by a downstream component.

  Justification: In the context of LLMs, improper encoding or escaping of output can make downstream systems vulnerable to injection attacks.

- [CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control

  Description: The software does not restrict or incorrectly restricts access to a resource from an actor that is not explicitly authorized to access the resource.

  Justification: Lack of access control could enable exploits through unauthorized access.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: The software imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

  Justification: Using LLMs that are not adequately vetted can lead to inclusion of malicious or untrusted functionalities.

- [CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities

  Description: The software is out-of-date, lacking patches, or makes use of third-party components with publicly known vulnerabilities.

  Justification: Vulnerable components could mishandle outputs.

#### Rejected CWE Review Comments

- None

### Techniques

#### MITRE ATT&CK® Techniques

- [T1190](https://attack.mitre.org/techniques/T1190/): Exploit Public-Facing Application

  Description: Adversaries may attempt to take advantage of a weakness in an internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. Public facing applications, including APIs and cloud-based services, are common targets.

  Justification: Could exploit public model APIs by targeting exposed services that inadequately validate outputs.

#### MITRE ATLASTM Techniques

- AML.T0040: ML Model Inference API Access

  Description: Adversaries may use inference API access to an LLM to craft malicious prompts designed to generate insecure outputs containing unvalidated code snippets or injection payloads. These payloads take advantage of inadequate output handling in downstream systems.

  Justification: Inference API access provides the ability to tune prompts to maximize insecure output generation.

- AML.T0043: Craft Adversarial Data

  Description: Adversaries may carefully craft prompts to manipulate the LLM into generating insecure outputs designed to exploit lack of validation in downstream systems. The prompts can be tuned to produce unvalidated code or injection payloads.

  Justification: Crafting prompts precisely controls LLM outputs, enabling generation of malicious payloads by exploiting inadequate downstream validation.

- AML.T0044: Full ML Model Access

  Description: Full white-box access enables adversaries to meticulously tune prompts to optimally exploit vulnerabilities in downstream systems by maximizing generation of insecure outputs like unvalidated code snippets or injection payloads.

  Justification: With full access, adversaries can precisely craft prompts to generate extremely tailored insecure outputs exploiting downstream systems.

- AML.T0047: ML-Enabled Product or Service

  Description: By gaining access to an LLM-enabled product/service, an adversary could potentially craft prompts designed to generate insecure outputs by exploiting the product's access to the underlying LLM and lack of output validation in connected downstream systems.

  Justification: Access to LLM-enabled services provides prompting access that could produce insecure outputs.

#### Rejected Technique Review Comments

- None

### Mitigations

#### MITRE ATT&CK® Mitigations

- [M1038](https://attack.mitre.org/mitigations/M1038): Execution Prevention

  Description: Block execution of code on a system through application control, and/or script blocking.

  Justification: Prevents arbitrary remote code execution from malicious outputs.  

- [M1042](https://attack.mitre.org/mitigations/M1042): Disable or Remove Feature or Program

  Description: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

  Justification: Reduces available downstream avenues for exploiting insecure outputs.

#### MITRE ATLASTM Mitigations

- AML.M0011: Restrict Library Loading

  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for loading of malicious libraries.

  Justification: Restricting arbitrary library loading can prevent exploits from malicious outputs designed to load untrusted code.

- AML.M0015: Adversarial Input Detection

  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

  Justification: Detecting crafted prompts designed to generate insecure outputs can prevent attacks.

- AML.M0018: Output Validation and Sanitization

  Description: Implement comprehensive validation and sanitization routines for LLM-generated outputs before passing them to downstream systems.

  Justification: Proper validation and sanitization of LLM outputs will mitigate risks related to insecure output handling, including command injection, XSS, and SQL injection.

#### Rejected Mitigation Review Comments

- None
- 