By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM06: Sensitive Information Disclosure

### Summary

Insufficient safeguards risk exposing sensitive information through LLM outputs, causing legal issues or competitive harm.

### Description

Securing large language models against unintended sensitive data exposure is critical, yet challenging. Insufficient safeguards can enable adversaries to extract confidential or private information through malicious prompts or direct model access. Accidental disclosure is also a risk due to unanticipated prompt interactions. LLM outputs may expose trade secrets, personal data, or other sensitive information leading to illegal activity.

Technical controls are needed to mitigate risks, including differential privacy, federated learning, data sanitization, input filtering, and output validation. However, the unpredictable nature of LLMs makes fully preventing unauthorized data exposure difficult. Comprehensive access policies, monitoring systems, and layered defenses should be implemented to reduce the attack surface.


### Common Examples of Risk

1. Improper filtering of sensitive data in LLM responses.

2. Overfitting on confidential data during training. 

3. Unintended disclosure through model errors or misinterpretations.

### Prevention and Mitigation Strategies

1. Scrub sensitive data from training sets.

2. Implement robust input validation and sanitization.

3. Apply strict data access controls and least privilege when enriching models.

4. Limit model access to external data sources.

5. Maintain secure supply chain for external data.

### Example Attack Scenarios

1. Legitimate user exposed to other user's sensitive data through LLM.

2. Attacker bypasses filters to elicit sensitive data through crafted prompts.

3. Sensitive training data leaked into model enables exposure risks.


### MITRE ATLAS™ 

#### Techniques
- [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024): Exfiltration via ML Inference API - Adversaries could craft prompts designed to elicit private information from the LLM and exfiltrate it via the inference API. This could expose proprietary data or personally identifiable information.

- [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025): Exfiltration via Cyber Means - Adversaries may exfiltrate sensitive information extracted from an ML model via traditional cyber techniques that do not rely on the model's inference API. This allows adversaries to steal confidential data gathered through the model after insufficient safeguards have allowed access to that information.

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043): Craft Adversarial Data - Adversaries could iteratively craft prompts to extract sensitive information from the LLM. Carefully tuned prompts can reveal confidential data even if the model was not explicitly trained on it. This allows adversaries to exploit insufficient safeguards around model outputs.

- [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044): Full ML Model Access - With complete white-box access to the model, adversaries can thoroughly analyze model parameters and data relationships to optimally extract maximum sensitive information. This level of access enables adversaries to fully exploit insufficient safeguards.

#### Mitigations

- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002/): Passive ML Output Obfuscation. Decreasing the fidelity of model outputs provided to the end user can reduce an adversaries ability to extract information about the model and optimize attacks for the model. Suggested approaches: - Restrict the number of results shown - Limit specificity of output class ontology - Use randomized smoothing techniques - Reduce the precision of numerical outputs](https://atlas.mitre.org/mitigations/AML.M0002/): Passive ML Output Obfuscation. Decrease fidelity of model outputs to users to reduce adversarial knowledge for attacks.


- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004/): Restrict Number of ML Model Queries. Limit the total number and rate of queries a user can perform. Suggested approaches: - Limit the number of queries users can perform in a given interval to hinder an attacker's ability to send computationally expensive inputs - Limit the amount of information an attacker can learn about a model's ontology through API queries. - Limit the volume of API queries in a given period of time to regulate the amount and fidelity of potentially sensitive information an attacker can learn. - Limit the number of queries users can perform in a given interval to shrink the attack surface for black-box attacks. - Limit the number of queries users can perform in a given interval to prevent a denial of service.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.


### STRIDE Analysis (generated by claude.ai)


**Spoofing**

- Attackers can spoof user identities with stolen credentials to access sensitive data.
- Forged input data could trick models into revealing confidential information. 

**Tampering**

- Adversaries can tamper with inputs to manipulate model behavior for sensitive data exposure.
- Training data poisoning modifies model behavior to inadvertently leak sensitive information.

**Repudiation** 

- Lack of logging around access and data flows complicates attack attribution.
- Disablement of monitoring systems also undermines attack attribution.

**Information Disclosure**

- Improper data handling exposes sensitive information through models. 
- Unauthorized data access grants visibility into confidential artifacts and training data.

**Denial of Service**

- Unexpected crashes from adversarial inputs disrupt model availability.
- Resource exhaustion attacks on backend systems create denial of service effects.

**Elevation of Privilege**

- Compromised credentials enable escalated data access privileges.
- Exploiting vulnerabilities in access controls allows unauthorized data access.
- Circumventing authentication opens access to restricted data.


### Common Weakness Enumeration (CWE)

- [CWE-200](https://cwe.mitre.org/data/definitions/200.html): Exposure of Sensitive Information

  Summary: Sensitive information exposed to unauthorized actors.

  Exploit: Due to insufficient data filtering or access controls, an attacker can use carefully crafted prompts to extract proprietary algorithms, training data, model parameters or other confidential information from the LLM, which they can then exfiltrate and exploit.

- [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Exposure Through Error Messages

  Summary: Sensitive information revealed through error messages.

  Exploit: When the LLM encounters unexpected inputs or conditions, the resulting error messages can unintentionally expose details about the model architecture, training data schemas, hyperparameters or other sensitive implementation information an attacker can leverage to refine their prompts and extraction techniques.

- [CWE-215](https://cwe.mitre.org/data/definitions/215.html): Exposure Through Debug Logs

  Summary: Sensitive information in debug logs.

  Exploit: The LLM's debugging information can reveal details about the training data distribution, structure and sources as well as inference metadata. Attackers can analyze these logs to identify weaknesses and optimize prompts for extracting sensitive information.

- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of Broken Cryptography

  Summary: Weak crypto enables data exposure.

  Exploit: The use of flawed or outdated cryptographic algorithms to protect sensitive training data, model parameters, and artifacts can allow an attacker to easily decrypt and access this proprietary information.

- [CWE-541](https://cwe.mitre.org/data/definitions/541.html): Exposure Through Source Code

  Summary: Source code revealing sensitive details.

  Exploit: Hardcoded sensitive information like API keys, credentials or server addresses in the LLM's source code can enable an attacker to directly access its environment and training data sources to extract additional confidential information.

- [CWE-922](https://cwe.mitre.org/data/definitions/922.html): Insecure Data Storage

  Summary: Unencrypted sensitive artifacts enable data theft.

  Exploit: Storing model parameters, training datasets, or other proprietary artifacts without encryption or access controls allows attackers to easily obtain this sensitive information.



---

# IGNORE FOR NOW - NEED RE-REVIEW


### MITRE ATT&CK® Techniques

- [T1078](https://attack.mitre.org/techniques/T1078/): Valid Accounts

  Description: Adversaries may steal or guess valid credentials to gain authorized access.

  Justification: Valid credentials can be used to bypass security controls, potentially leading to sensitive information disclosure via LLM.

- [T1530](https://attack.mitre.org/techniques/T1530/): Data from Cloud Storage Object

  Description: Adversaries may get access to sensitive data from cloud storage including credentials and keys.

  Justification: Unauthorized access to cloud storage can directly expose both training data and model parameters, leading to substantial risks of information disclosure.

- [T1552](https://attack.mitre.org/techniques/T1552/): Unsecured Credentials

  Description: Adversaries may steal and abuse valid account credentials and keys to access cloud services, like AWS.

  Justification: Compromised credentials could enable unauthorized access to sensitive information.



### MITRE ATT&CK® Mitigations

- [M1027](https://attack.mitre.org/mitigations/M1027/): Password Policies

  Description: Set and enforce secure password policies for accounts.

  Justification: Strong password policies prevent compromised credentials that could enable unauthorized data access.

- [M1041](https://attack.mitre.org/mitigations/M1041/): Encrypt Sensitive Information

  Description: Protect sensitive information with strong encryption.

  Justification: Encrypting sensitive training data and artifacts prevents exposure if improperly accessed.

- [M1042](https://attack.mitre.org/mitigations/M1042/): Disable or Remove Feature or Program

  Description: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

  Justification: Minimizing the attack surface by disabling or removing unnecessary features can substantially lower the risks of sensitive information disclosure.
