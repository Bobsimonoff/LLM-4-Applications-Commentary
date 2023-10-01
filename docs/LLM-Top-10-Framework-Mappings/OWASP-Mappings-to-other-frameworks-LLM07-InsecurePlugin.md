By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main

# LLM07: Insecure Plugin Design

### Summary
LLM plugins processing untrusted inputs and having insufficient access control risk severe exploits like remote code execution.

### Description
LLM plugins are extensions that, when enabled, are called automatically by the model during user interactions. The model integration platform drives them,  and the application may have no control over the execution, especially when the model is hosted by another party. Furthermore, plugins are likely to implement free-text inputs from the model with no validation or type-checking to deal with context-size limitations. This allows a potential attacker to construct a malicious request to the plugin, which could result in a wide range of undesired behaviors, up to and including remote code execution. 

The harm of malicious inputs often depends on insufficient access controls and the failure to track authorization across plugins. Inadequate access control allows a plugin to blindly trust other plugins and assume that the end user provided the inputs. Such inadequate access control can enable malicious inputs to have harmful consequences ranging from data exfiltration, remote code execution, and privilege escalation.

This item focuses on creating LLM plugins rather than third-party plugins, which LLM-Supply-Chain-Vulnerabilities cover. 

### Common Examples of Vulnerability

1. Plugin accepts all parameters in one unvalidated text field.

2. Plugin accepts unsafe configuration strings overriding settings. 

3. Plugin accepts raw SQL or code statements without parameterization.

4. Authentication without authorization checks per plugin.

5. Plugin assumes LLM content is from user and performs any requested actions without authorization.

### How to Prevent

1. Enforce parameterized inputs with validation and sanitization. Inspect unstructured inputs for unsafe methods.

2. Apply OWASP input validation and sanitization guidelines.

3. Thoroughly test plugins for validation issues using SAST, DAST, IAST scans. 

4. Minimize exploit impact through least privilege access control per OWASP.

5. Use proper authentication like OAuth2 and API keys for authorization decisions. 

6. Require manual user approval before allowing sensitive actions.

7. Apply OWASP API security guidance to plugins.

###v Example Attack Scenarios

1. Attacker exploits plugin URL parameter injection to inject malicious content.

2. Unvalidated plugin input enables reconnaissance and exploitation.

3. Attacker overrides plugin configuration to access unauthorized data sources. 

4. SQL injection through unchecked plugin input.

5. Prompt injection exploits code management plugin to lock out user.


### Common Weakness Enumeration (CWE) 

- [CWE-300](https://cwe.mitre.org/data/definitions/300.html): Channel Accessible by Non-Endpoint ('Man-in-the-Middle')

  Description: A communication channel is exposed to intermediaries, enabling information disclosure or spoofing.

  Justification: Applicable as poisoning attacks manipulate training data in transit.

- [CWE-451](https://cwe.mitre.org/data/definitions/451.html): User Interface (UI) Misrepresentation of Critical Information

  Description: Incorrect or misleading user interface presentation that masks or misrepresents critical information.

  Justification: Relevant as data poisoning can cause misrepresentation of information.

- [CWE-920: Improper Restriction of Power Consumption](https://cwe.mitre.org/data/definitions/920.html)

  Description: Not limiting resource consumption enables denial of service.

  Justification: Applicable as data poisoning aims to consume excessive resources.

- [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html): Insecure Default Initialization of Resource

  Description: Failure to change default initial settings makes the component vulnerable.

  Justification: Relevant as models often use default data sources vulnerable to poisoning.

- [CWE-1286](https://cwe.mitre.org/data/definitions/1286.html): Insufficient Data Validation

  Description: Accepting input data without sufficient validation enables malicious activity.

  Justification: Highly applicable as lack of validation enables data poisoning attacks.

### MITRE ATT&CK Techniques

- [T1190](https://attack.mitre.org/techniques/T1190/): Exploit Public-Facing Application

  Description: Attacker exploits vulnerabilities in public-facing applications like APIs and plugins.

  Justification: Directly relevant as plugins are public interfaces that may contain flaws.


### MITRE ATLAS Techniques

- AML.T0006: Active Scanning

  Description: Adversaries actively probe and scan LLM plugin interfaces to identify vulnerabilities in input validation, sanitization, access controls or other weaknesses that could enable exploitation through crafted malicious inputs. Thorough scanning reveals flaws adversaries can later exploit.

  Justification: Active scanning of LLM plugin systems is a key technique adversaries use to identify vulnerabilities to exploit through malicious plugin inputs. 

- AML.T0011: User Execution

  Description: Adversaries manipulate users into executing unsafe plugin outputs generated due to insufficient input validation. Lack of sanitization enables adversaries to exploit plugins by crafting inputs that trigger malicious logic when executed by users.

  Justification: User execution of unsafe plugin outputs generated from insufficient input validation enables adversaries to exploit plugins through crafted malicious inputs.

- AML.T0043: Craft Adversarial Data

  Description: Adversaries exploit validation flaws in LLM plugins by carefully crafting malicious plugin inputs containing payloads designed to trigger unintended behaviors. Crafted inputs take advantage of insufficient validation to compromise plugin logic.

  Justification: Insecure LLM plugins enable adversaries to easily exploit systems by crafting malicious plugin inputs that exploit insufficient input validation. 

- AML.T0044: Full ML Model Access

  Description: Full white-box access to LLM plugins enables adversaries to thoroughly analyze them to optimally craft malicious inputs tailored to reliably exploit any vulnerability discovered through extensive probing of logic flaws.

  Justification: Complete LLM plugin access allows adversaries to deeply probe vulnerabilities to optimize malicious inputs for exploitation.

- AML.T0045: ML Intellectual Property Theft

  Description: Failure to sanitize LLM plugin outputs enables adversaries to exfiltrate intellectual property or sensitive organizational data by manipulating upstream systems. Adversaries exploit lack of output encoding to stealthily steal assets.

  Justification: Lack of output sanitization by LLM plugins provides a pathway for IP and data theft through adversary manipulation.

- AML.T0047: ML-Enabled Product or Service

  Description: By compromising an ML-enabled product's integration with vulnerable LLM plugins, adversaries can exploit plugin flaws to manipulate backend systems. Insecure plugin integration vectors provide exposure.

  Justification: Products integrated with flawed LLM plugins expose backend systems by enabling adversary exploitation of plugin vulnerabilities.



### MITRE ATT&CK Mitigations

- [M1042](https://attack.mitre.org/mitigations/M1042/): Disable or Remove Feature or Program

  Description: Disable or remove problematic features or programs like insecure plugins.

  Justification: Highly applicable mitigation to reduce attack surface by removing vulnerable plugins.

- [M1043](https://attack.mitre.org/mitigations/M1043/): Isolate System or Network

  Description: Isolate systems like those hosting plugins from other resources.

  Justification: Segmentation could limit impact of any plugin exploits.

- [M1049](https://attack.mitre.org/mitigations/M1049/): Disable or Remove Feature or Program

  Description: Disable or remove problematic features like insecure plugins.

  Justification: Directly applicable mitigation to reduce attack surface by eliminating vulnerable plugins.



### MITRE ATLAS Mitigations
 
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

- AML.M0018: User Training
  Description: Educate ML model developers on secure coding practices and ML vulnerabilities.




