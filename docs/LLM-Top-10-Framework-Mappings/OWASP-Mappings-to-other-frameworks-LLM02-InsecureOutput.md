By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LM02: Insecure Output Handling

#### Summary 

Failing to validate LLM outputs enables attackers to indirectly access functionality or trigger exploits through crafted prompts.

#### Description

Insecure output handling stems from downstream blind trust in LLM outputs without proper validation or sanitization, granting attackers indirect access similar to user input.

This enables arbitrary code execution, system compromise, data theft, XSS, CSRF, SSRF, RCE through crafted prompts, with high LLM privilege escalating risk. 

What it is not:

- Lack of validation by downstream components (LLM07: Insecure Plugin Design) 
- Overreliance on incorrect LLM outputs (LLM09: Overreliance)
- Excessive LLM permissions  (LLM08: Excessive Agency)
- LLM leaking sensitive information (LLM06: Sensitive Information Disclosure

This risk focuses specifically on the need to sanitize and validate LLM outputs before passing downstream.


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



### Techniques

#### MITRE ATT&CK® Techniques

- [T1190](https://attack.mitre.org/techniques/T1190/): Exploit Public-Facing Application

  Description: Adversaries may attempt to take advantage of a weakness in an internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. Public facing applications, including APIs and cloud-based services, are common targets.

  Justification: Could exploit public model APIs by targeting exposed services that inadequately validate outputs.

#### MITRE ATLAS™ Techniques

- [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040/): ML Model Inference API Access

  Description: Adversaries may use inference API access to an LLM to craft malicious prompts designed to generate insecure outputs containing unvalidated code snippets or injection payloads. These payloads take advantage of inadequate output handling in downstream systems.

  Justification: Inference API access provides the ability to tune prompts to maximize insecure output generation.

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data

  Description: Adversaries may carefully craft prompts to manipulate the LLM into generating insecure outputs designed to exploit lack of validation in downstream systems. The prompts can be tuned to produce unvalidated code or injection payloads.

  Justification: Crafting prompts precisely controls LLM outputs, enabling generation of malicious payloads by exploiting inadequate downstream validation.

- [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044/): Full ML Model Access

  Description: Full white-box access enables adversaries to meticulously tune prompts to optimally exploit vulnerabilities in downstream systems by maximizing generation of insecure outputs like unvalidated code snippets or injection payloads.

  Justification: With full access, adversaries can precisely craft prompts to generate extremely tailored insecure outputs exploiting downstream systems. 

- [AML.T0047](https://atlas.mitre.org/techniques/AML.T0040/): ML-Enabled Product or Service

  Description: By gaining access to an LLM-enabled product/service, an adversary could potentially craft prompts designed to generate insecure outputs by exploiting the product's access to the underlying LLM and lack of output validation in connected downstream systems.

  Justification: Access to LLM-enabled services provides prompting access that could produce insecure outputs.



### Mitigations

#### MITRE ATT&CK® Mitigations

- [M1038](https://attack.mitre.org/mitigations/M1038): Execution Prevention

  Description: Block execution of code on a system through application control, and/or script blocking.

  Justification: Prevents arbitrary remote code execution from malicious outputs.

- [M1042](https://attack.mitre.org/mitigations/M1042): Disable or Remove Feature or Program

  Description: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

  Justification: Reduces available downstream avenues for exploiting insecure outputs.

#### MITRE ATLAS™ Mitigations  

- [AML.M0011](https://atlas.mitre.org/mitigations/AML.M0011/): Restrict Library Loading

  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for loading of malicious libraries.

  Justification: Restricting arbitrary library loading can prevent exploits from malicious outputs designed to load untrusted code.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection

  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

  Justification: Detecting crafted prompts designed to generate insecure outputs can prevent attacks.  


#### Additional Mitigations
- Output Validation and Sanitization

  Description: Implement comprehensive validation and sanitization routines for LLM-generated outputs before passing them to downstream systems.

  Justification: Proper validation and sanitization of LLM outputs will mitigate risks related to insecure output handling, including command injection, XSS, and SQL injection.


Here is a comprehensive STRIDE analysis section for the OWASP Insecure Output Handling risk:

### STRIDE Analysis (generated by clause.ai)

Insecure output handling vulnerabilities can enable threats across multiple STRIDE categories:

**Spoofing**

- Attackers could spoof downstream systems by manipulating LLM outputs to impersonate expected data structures and bypass security checks.

- Malicious outputs could also spoof user identity or authentication credentials to access restricted data and functions.

**Tampering**

- Injected payloads via insecure outputs could tamper with downstream systems' control flows, causing unauthorized state changes.

- Carefully engineered outputs precisely control downstream behaviors through malicious instructions.

**Repudiation** 

- Lack of logging around LLM outputs complicates attack attribution and forensic investigations.

- Tampering with or disabling logs could also undermine attack attribution.

**Information Disclosure**

- Insecure handling of outputs could leak sensitive data like credentials, personal information, or intellectual property.

- Error messages and logs may reveal information if outputs are not properly sanitized.

**Denial of Service**

- Memory corruption, resource exhaustion, crashes, and instability could occur in downstream systems when processing malicious outputs.

- Infinite loops or complexity attacks could also be triggered by harmful outputs.

**Elevation of Privilege**

- Code execution via insecure outputs could allow escalating from low to high privilege levels on downstream systems.

- Horizontal privilege escalation is also possible through compromised credentials or bypassed access controls.

Proper validation, sanitization, logging, and access controls mitigates these STRIDE threats. Sandboxing provides additional protections. Conducting thorough STRIDE analysis is critical during design and implementation.

