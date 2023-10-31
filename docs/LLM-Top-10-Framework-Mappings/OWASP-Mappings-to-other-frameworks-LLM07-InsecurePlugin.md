By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM07: Insecure Plugin Design 

### Summary
LLM plugins processing untrusted inputs without validation can enable severe exploits like remote code execution.

### Description
LLM plugins implement free-text model inputs without validation due to context limitations. This allows malformed inputs leading to undesired behaviors like remote code execution.

Inadequate access control exacerbates this by enabling malicious inputs to cause data theft, code execution, and privilege escalation.

Proper input validation, access controls, isolation, logging, testing, and zero trust design are essential. Validate and authorize all inputs and actions.

Not to be confused with:

- LLM02: Insecure Output Handling - Failing to validate LLM-generated outputs before sending them to downstream services can allow insecure code or attack strings to reach vulnerable systems. 

- LLM08: Excessive Agency - Excessive LLM permissions or autonomy to perform actions


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



### MITRE ATLAS™ 

#### Techniques
- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006/): Active Scanning - If the plugin endpoint is public, adversaries can probe to identify flaws in input validation. Then the adversary could craft prompt injections that will exploit the discovered flaw. 

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data - Adversaries can exploit flaws in LLM plugin input validation and sanitization by carefully crafting malicious inputs containing adversarial payloads. Insufficient validation enables adversaries to inject payloads that compromise plugin logic when interpreted. The payloads trigger unintended behaviors in the plugins which the adversary can leverage to achieve their objectives.

- [AML.T0049](https://atlas.mitre.org/techniques/AML.T0049/): Exploit Public-Facing Application - Any unintended public interface to LLM plugins can be exploited by adversaries sending crafted inputs. Similar to AML.T0006 above. 

#### Mitigations

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.

- [AML.M0016](https://atlas.mitre.org/mitigations/AML.M0016/): Vulnerability Scanning. Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for arbitrary code execution. Scan ML artifacts for vulnerabilities before execution.


#### Possible Additions

**New Technique Proposals**

- AML.TXXXX: Plugin Enumeration - Adversaries may scan a system and enumerate available plugins and extensions to identify ones that are vulnerable or useful for exploitation. Knowing the specific plugins in use provides a roadmap to target plugins with insecure design or known vulnerabilities.

**New Mitigation Proposals**

- AML.MXXXX: Enforce Least Privilege Access Control - Implement granular access controls that restrict plugins to only the permissions necessary for their intended functionality. Prevent plugins from accessing resources or performing actions beyond their specified scope. Regularly audit and review access. Likely best practice anyway, so not sure this is truly needed here.

- AML.MXXXX: Require Manual Approval for Sensitive Actions - For sensitive or high-risk actions like payments, PII exposure, or data deletion, require manual approval from the end user even if the plugin requests the action. Do not allow plugins to automatically perform sensitive actions without additional authorization. Log all requests.


### STRIDE Analysis (generated by claude.ai)

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



### Common Weakness Enumeration (CWE)

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Summary: Failure to validate input from untrusted sources.

  Exploit: An LLM plugin processes outputs from the LLM as inputs without properly validating or sanitizing them. This allows an attacker to craft malicious inputs by taking advantage of the lack of validation, which could exploit the plugin's logic in unintended ways including arbitrary code execution.

- [CWE-74](https://cwe.mitre.org/data/definitions/74.html): Improper Neutralization of Special Elements in Output Used by a Downstream Component

  Summary: Failure to sanitize outputs enables downstream injection attacks.

  Exploit: An LLM plugin interprets LLM outputs containing un-neutralized special elements. This allows an attacker to inject malicious snippets into downstream operations by taking advantage of the lack of output sanitization in the plugin.

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Neutralization of Special Elements used in an SQL Command

  Summary: Failure to neutralize special elements in SQL statements enables SQL injection.

  Exploit: An LLM plugin executes LLM outputs as SQL queries without neutralizing special elements. This allows an attacker to perform SQL injection by crafting LLM outputs containing malicious SQL, taking advantage of the lack of output sanitization.

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Summary: Failure to restrict access from unauthorized actors.

  Exploit: An LLM plugin processes outputs from the LLM without proper authorization checks. This allows an attacker to escalate privileges and access sensitive resources by manipulating the plugin through crafted LLM outputs.
  
- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error

  Summary: Failure to validate source of input.

  Exploit: An LLM plugin processes outputs from the LLM without properly verifying their source. This allows an attacker to inject malicious data by spoofing the origin of the outputs.


---

# IGNORE FOR NOW - NEED RE-REVIEW



### MITRE ATT&CK® Techniques

- [T1548](https://attack.mitre.org/techniques/T1068/): Exploitation for Privilege Escalation

  Description: Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

  Justification: Insecure plugin design often results in insufficient access control, making it easier for attackers to escalate privileges.

- [T1190](https://attack.mitre.org/techniques/T1190/): Exploit Public-Facing Application

  Description: Attacker exploits vulnerabilities in public-facing applications like APIs and plugins.

  Justification: Directly relevant as plugins are public interfaces that may contain flaws.


### MITRE ATT&CK® Mitigations

N.A.

