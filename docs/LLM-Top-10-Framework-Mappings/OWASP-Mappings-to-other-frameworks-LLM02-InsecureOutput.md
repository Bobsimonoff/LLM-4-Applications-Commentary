By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM02: Insecure Output Handling

### Summary 

Failing to validate, sanitize and filter LLM outputs enables attackers to indirectly access systems or trigger exploits via crafted prompts.

### Description

Insecure output handling stems from downstream blind trust in LLM outputs without proper validation or sanitization, granting attackers indirect access similar to user input.

This enables arbitrary code execution, system compromise, data theft, XSS, CSRF, SSRF, RCE through crafted prompts, with high LLM privilege escalating risk. 


Not to be confused with:
- LLM07: Insecure Plugin Design - Lack of validation by downstream components 

- LLM09: Overreliance - Placing too much trust in the accuracy of LLM outputs 

- LLM08: Excessive Agency - Excessive LLM permissions or autonomy to perform actions

- LLM06: Sensitive Information Disclosure - LLM leaking sensitive information 

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


### MITRE ATLAS™ 

#### Techniques
- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043): Craft Adversarial Data - An adversary could exploit insecure output handling by crafting prompts containing adversarial text or code that gets embedded in the LLM's output. When these adversarial outputs are passed unchecked to downstream systems, they could trigger exploits.

- [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044): Full ML Model Access - With full white-box access to the model, an adversary could perform prompt injections to trigger the model to generate insecure outputs. The downstream client's failure to sanitize these adversarial outputs enables exploit.

- [AML.T0047](https://atlas.mitre.org/techniques/AML.T0047): ML-Enabled Product or Service - An adversary could use a public API or product service powered by an LLM backend model to generate malicious outputs that exploit insecure handling by the client application. The adversary crafts inputs that induce the model to generate harmful outputs. The downstream client application fails to properly sanitize these outputs before passing them to vulnerable components. 

- [AML.T0050](https://atlas.mitre.org/techniques/AML.T0050): Command and Scripting Interpreter - Executing unchecked commands from an LLM could enable code injection or remote code execution. 


#### Mitigations
- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002): Passive ML Output Obfuscation - Reducing output fidelity restricts adversary's ability to optimize attacks.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015): Adversarial Input Detection - Detect and block prompts likely to generate malicious outputs.


#### Possible Additions

**New Technique Proposals**

- Downstream System Spoofing - An adversary could manipulate LLM output formats, identifiers, and credentials to impersonate trusted downstream services and bypass authentication checks. This causes improper access and misleading log data.

- Control Flow Tampering - By injecting malicious logic bombs, loops, recursion, and other control flow altering payloads into LLM outputs, an adversary can disrupt downstream system operations. This could cause crashes, instability, or unauthorized changes. 

- Log Tampering - An adversary may tamper with logging configurations or directly modify log data related to LLM outputs to remove evidence of their attack. This complicates investigation and attribution by auditors.

- Information Leakage Amplification - Carefully crafted LLM outputs can trigger verbose error messages and logging from downstream systems. An adversary can extract sensitive details and troubleshooting data.

- Privilege Escalation - If LLM outputs allow code execution on downstream systems, an adversary can perform vertical privilege escalation by compromising process/service accounts and executing commands. Lateral movement with stolen credentials expands access.

**New Mitigation Proposals** 

- Input Validation - Thoroughly validating data inputs and command structures before they are passed to an LLM will prevent injection of malicious prompts that could generate harmful outputs.

- Output Encoding - Properly encoding LLM outputs based on the downstream execution context (e.g. browsers, OS shells, DBs) prevents exploits like XSS, command injection, and SQLi.

- LLM Output Sandboxing - Running LLM outputs in an isolated sandbox environment limits the damage and systemic impact of any malicious payloads generated. However, this may reduce functionality.

- LLM Output Logging - Securely logging all LLM outputs to an immutable audit log enables attack investigation, forensics, and attribution after incidents. Proper access controls on logs are critical.


### STRIDE Analysis (generated by claude.ai)

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


### Common Weakness Enumeration (CWE)


- [CWE-74](https://cwe.mitre.org/data/definitions/74.html): Improper Neutralization of Special Elements in Output Used by a Downstream Component

  Summary: Failure to sanitize special elements in outputs enables injection attacks on downstream components.

  Exploit: An attacker could craft prompts that induce the LLM to generate malicious outputs containing unneutralized special elements like shell metacharacters. When passed unchecked to a downstream OS command execution module, these adversarial outputs could allow arbitrary command injection on backend servers.

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html): Improper Neutralization of Special Elements used in an OS Command

  Summary: Failure to sanitize outputs allows OS command injection.

  Exploit: By injecting crafted prompts, an attacker tricks the LLM into producing malicious output payloads containing unneutralized OS command separators and metacharacters. An unsanitized downstream execution of these outputs risks arbitrary command injection on backend OS shells.

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Improper Neutralization of Input During Web Page Generation

  Summary: Failure to sanitize web outputs enables injection of malicious scripts.

  Exploit: An attacker spoofs prompts to induce generation of unencoded LLM outputs containing malicious scripts. Downstream use of these unchecked outputs in web pages allows cross-site scripting attacks when the pages are rendered in users' browsers.  

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Neutralization of Special Elements used in an SQL Command

  Summary: Failure to sanitize outputs enables SQL injection.

  Exploit: By injecting carefully crafted prompts, an attacker causes the LLM to generate malicious SQL query outputs containing unneutralized separators and conditionals. Direct unchecked execution of these outputs by downstream SQL engines risks SQL injection attacks.

- [CWE-94](https://cwe.mitre.org/data/definitions/94.html): Improper Control of Generation of Code

  Summary: Failure to sanitize outputs allows arbitrary code execution.

  Deailed Exploit: An attacker uses adversarial prompts to induce the LLM to generate unrestrained outputs containing exploits, scripts or arbitrary code payloads. Direct unchecked execution of these outputs risks arbitrary remote code execution.

- [CWE-116](https://cwe.mitre.org/data/definitions/116.html): Improper Encoding or Escaping of Output

  Summary: Failure to properly encode/escape output leads to issues when read downstream.

  Exploit: Absence of proper output encoding or escaping allows an attacker to craft prompts inducing generation of malicious exploit payloads and injection attack vectors in LLM outputs. These adversarial outputs can compromise downstream components when consumed without validation.

- [CWE-838](https://cwe.mitre.org/data/definitions/838.html): Inappropriate Encoding for Output Context

  Summary: Using wrong encoding for outputs leads to misinterpretation.

  Exploit: An attacker tricks the LLM into generating malicious payload outputs using encodings inappropriate for the downstream context. This allows the payloads to bypass protection mechanisms and successfully exploit vulnerabilities when improperly handled by downstream components.


---

# IGNORE FOR NOW - NEED RE-REVIEW


### MITRE ATT&CK® 

#### Techniques

- [T1190](https://attack.mitre.org/techniques/T1190/): Exploit Public-Facing Application

  Description: Adversaries may attempt to take advantage of a weakness in an internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. Public facing applications, including APIs and cloud-based services, are common targets.

  Justification: Could exploit public model APIs by targeting exposed services that inadequately validate outputs.


#### Mitigations

- [M1038](https://attack.mitre.org/mitigations/M1038): Execution Prevention

  Description: Block execution of code on a system through application control, and/or script blocking.

  Justification: Prevents arbitrary remote code execution from malicious outputs.

- [M1042](https://attack.mitre.org/mitigations/M1042): Disable or Remove Feature or Program

  Description: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

  Justification: Reduces available downstream avenues for exploiting insecure outputs.
