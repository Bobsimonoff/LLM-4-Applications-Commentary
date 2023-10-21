By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM07: Insecure Plugin Design 

### Summary

LLM plugins processing untrusted inputs without proper validation or access controls risk severe exploits like remote code execution.

### Description

LLM plugins are extensions called automatically during interactions. The platform drives them with little application control, especially for remotely hosted models. Plugins may implement free-text model inputs without validation due to context limitations. This allows malformed inputs leading to undesired behaviors like remote code execution. 

Inadequate access control exacerbates this by letting plugins blindly trust each other. Lack of authorization tracking enables malicious inputs to cause harm through data theft, code execution, and privilege escalation.

Proper input sanitization, access controls, isolation, logging, testing, and zero trust design are essential. Don't blindly trust models or plugins. Validate and authorize all inputs and actions. 

What this is not:

- Insecure output handling (LLM02): Failing to validate model outputs before use.

- Excessive agency (LLM08): Granting unchecked autonomy to models.

This risk focuses on creating LLM plugins rather than third-party plugins, which LLM-Supply-Chain-Vulnerabilities cover. 


### Examples of Risk

1. Plugin accepts all parameters in one unvalidated text field.

2. Plugin accepts unsafe configuration strings overriding settings. 

3. Plugin accepts raw SQL or code statements without parameterization.

4. Authentication without authorization checks per plugin.

5. Plugin assumes LLM content is from user and performs any requested actions without authorization.

### Prevention and Mitigation Strategies

1. Enforce parameterized inputs with validation and sanitization. Inspect unstructured inputs for unsafe methods.

2. Apply OWASP input validation and sanitization guidelines.

3. Thoroughly test plugins for validation issues using SAST, DAST, IAST scans. 

4. Minimize exploit impact through least privilege access control per OWASP.

5. Use proper authentication like OAuth2 and API keys for authorization decisions. 

6. Require manual user approval before allowing sensitive actions.

7. Apply OWASP API security guidance to plugins.

### Example Attack Scenarios

1. Attacker exploits plugin URL parameter injection to inject malicious content.

2. Unvalidated plugin input enables reconnaissance and exploitation.

3. Attacker overrides plugin configuration to access unauthorized data sources. 

4. SQL injection through unchecked plugin input.

5. Prompt injection exploits code management plugin to lock out user.



### Common Weakness Enumeration (CWE)

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

  Description: The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

  Justification: Highly applicable to insecure plugin design as user inputs that are not properly sanitized can lead to cross-site scripting attacks. Plugins, especially those handling text fields or other forms of user input, are often susceptible to such vulnerabilities.

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): SQL Injection

  Description: Software allows an attacker to send hostile data as part of a command or query that can take unauthorized actions.

  Justification: Since plugins may accept raw SQL statements without parameterization, there's a significant risk of SQL Injection.

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication

  Description: When an actor claims to have a given identity, the software does not prove, or insufficiently proves, that the claim is correct.

  Justification: Directly relevant to insecure plugin design where lack of proper authentication checks can lead to unauthorized access. A plugin that doesn't validate the identity of the interacting users or systems effectively opens a doorway for attackers.

- [CWE-451](https://cwe.mitre.org/data/definitions/451.html): User Interface (UI) Misrepresentation of Critical Information

  Description: Incorrect or misleading user interface presentation that masks or misrepresents critical information.

  Justification: Critically relevant because plugins often interface with users, and UI misrepresentation could directly lead to misleading or harmful user actions.



### Techniques

### MITRE ATT&CK® Techniques

- [T1548](https://attack.mitre.org/techniques/T1068/): Exploitation for Privilege Escalation

  Description: Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

  Justification: Insecure plugin design often results in insufficient access control, making it easier for attackers to escalate privileges.

- [T1190](https://attack.mitre.org/techniques/T1190/): Exploit Public-Facing Application

  Description: Attacker exploits vulnerabilities in public-facing applications like APIs and plugins.

  Justification: Directly relevant as plugins are public interfaces that may contain flaws.

### MITRE ATLAS™ Techniques

- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006/): Active Scanning

  Description: Adversaries actively probe and scan LLM plugin interfaces to identify vulnerabilities in input validation, sanitization, access controls or other weaknesses that could enable exploitation through crafted malicious inputs. Thorough scanning reveals flaws adversaries can later exploit.

  Justification: Active scanning of LLM plugin systems is a key technique adversaries use to identify vulnerabilities to exploit through malicious plugin inputs.

- [AML.T0011](https://atlas.mitre.org/techniques/AML.T0011/): User Execution  

  Description: Adversaries manipulate users into executing unsafe plugin outputs generated due to insufficient input validation. Lack of sanitization enables adversaries to exploit plugins by crafting inputs that trigger malicious logic when executed by users.

  Justification: User execution of unsafe plugin outputs generated from insufficient input validation enables adversaries to exploit plugins through crafted malicious inputs.

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data

  Description: Adversaries exploit validation flaws in LLM plugins by carefully crafting malicious plugin inputs containing payloads designed to trigger unintended behaviors. Crafted inputs take advantage of insufficient validation to compromise plugin logic.

  Justification: Insecure LLM plugins enable adversaries to easily exploit systems by crafting malicious plugin inputs that exploit insufficient input validation.

- [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044/): Full ML Model Access

  Description: Full white-box access to LLM plugins enables adversaries to thoroughly analyze them to optimally craft malicious inputs tailored to reliably exploit any vulnerability discovered through extensive probing of logic flaws.

  Justification: Complete LLM plugin access allows adversaries to deeply probe vulnerabilities to optimize malicious inputs for exploitation. 

### Additional Techniques

- Plugin Enumeration

  Description: Adversaries scan the system to list all available plugins and target the ones with known vulnerabilities.

  Justification: Understanding which plugins are available provides adversaries a roadmap for attacks.



### Mitigations

### MITRE ATT&CK® Mitigations

N.A.


### MITRE ATLAS™ Mitigations

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004/): Restrict Number of ML Model Queries

  Description: Limit the total number and rate of queries a user can perform.

  Justification: Restricting the number of queries helps prevent malicious probing and exploitation of plugins.

- [AML.M0005](https://atlas.mitre.org/mitigations/AML.M0005/): Control Access to ML Models and Data at Rest

  Description: Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users.

  Justification: Controlling access prevents unauthorized access that could lead to plugin exploitation.

- [AML.M0011](https://atlas.mitre.org/mitigations/AML.M0011/): Restrict Library Loading

  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software.

  Justification: Restricting library loading mitigates the risk of malicious code execution through plugins.

- [AML.M0012](https://atlas.mitre.org/mitigations/AML.M0012/): Encrypt Sensitive Information

  Description: Encrypt sensitive data such as ML models to protect against adversaries attempting to access sensitive data.

  Justification: Encryption helps prevent exposure of sensitive data through compromised plugins.
  
- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection

  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

  Justification: Detecting and blocking adversarial inputs helps prevent plugin exploitation.

- [AML.M0017](https://atlas.mitre.org/mitigations/AML.M0017/): Model Distribution Methods

  Description: Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model.

  Justification: Careful model distribution reduces exposure of plugins to attackers.

- [AML.M0018](https://atlas.mitre.org/mitigations/AML.M0018/): User Training  

  Description: Educate ML model developers on secure coding practices and ML vulnerabilities.

  Justification: Developer training helps avoid coding mistakes that lead to plugin vulnerabilities.

### Additional Mitigations 

- [AML.M0020](https://atlas.mitre.org/mitigations/AML.M0020/): Periodic Code Reviews

  Description: Periodically review plugin code for vulnerabilities and adhere to secure coding guidelines.

  Justification: Regular code reviews help identify and fix plugin vulnerabilities early.



### STRIDE Analysis (generated by clause.ai)

Insecure plugin design can impact multiple components of the STRIDE threat model:

**Spoofing**

- Attackers can spoof user identities through unauthorized access enabled by inadequate plugin authentication.
- Malicious plugins could also spoof other trusted system components to extract data.

**Tampering**

- Adversaries can tamper with data, predictions, and model behaviors by injecting malicious plugin inputs. 
- Carefully crafted plugin inputs precisely control model actions through malicious instructions.

**Repudiation** 

- Lack of logging around plugin inputs can complicate attack attribution.
- Plugin exploits could also tamper with or disable logging to hide their actions.

**Information Disclosure**

- Malicious plugins can trick models into revealing sensitive user, system, or training data.
- Indirect injection through web inputs could enable plugins to extract sensitive data via malicious text processing.

**Denial of Service**

- Specially crafted plugin inputs could trigger crashes, resource exhaustion, or make models unusable.
- Recursive plugin requests could cause infinite inference loops.

**Elevation of Privilege**

- Injected plugin inputs could escalate privileges or disable backend access controls.
- Compromised credentials enable bypassing access controls when invoking plugins.
