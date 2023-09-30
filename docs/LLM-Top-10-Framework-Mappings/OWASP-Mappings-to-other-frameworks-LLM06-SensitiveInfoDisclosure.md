By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM06: Sensitive Information Disclosure

### Summary
Failure to protect against disclosure of sensitive information in LLM outputs can result in legal consequences or a loss of competitive advantage.

### Description

Failure to protect against unauthorized exposure of confidential data in LLM outputs can enable adversaries to steal intellectual property and sensitive information. 

Inadequate data handling, weak access controls, and insufficient input/output validation allow attackers to insert malicious prompts or directly access sensitive data. Successful attacks can lead to privacy violations, intellectual property theft, reputational damage, and regulatory noncompliance.

Prevention involves robust data sanitization, input filtering, and output validation. Strict access controls should be implemented, limiting data access to only authorized purposes. LLM training data must be carefully filtered to exclude sensitive information. Comprehensive data governance and privacy policies can help mitigate risks. Monitoring systems for anomalous behavior can also help detect potential unauthorized access attempts. Securing LLMs against sensitive data exposure is critical for maintaining trust and competitive advantage.

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


### Common Weakness Enumeration (CWE) 

- [CWE-202](https://cwe.mitre.org/data/definitions/202.html): Exposure of Sensitive Information to an Unauthorized Actor

  Description: The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

  Justification: Inadequate access controls could enable exposure of sensitive data through model outputs.

- [CWE-208](https://cwe.mitre.org/data/definitions/208.html): Observable Discrepancy

  Description: Behavioral differences between the product's expected behavior and its actual behavior allow detection of the product's sensitive information.

  Justification: Model outputs could reveal sensitive training data through observable discrepancies.

- [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Information Exposure Through an Error Message

  Description: The product generates error messages that expose sensitive information about the environment, users, or associated data.

  Justification: Model error messages could reveal sensitive configuration, training data or internal details. 

- [CWE-215](https://cwe.mitre.org/data/definitions/215.html): Information Exposure Through Debug Information

  Description: Debugging output can contain sensitive information like credentials or cryptographic keys.

  Justification: Model debug logs could expose private training data metadata and inferences.

- [CWE-538](https://cwe.mitre.org/data/definitions/538.html): File and Directory Information Exposure

  Description: The product reveals sensitive filesystem information that aids attackers in adversary techniques.

  Justification: Filesystem permissions could enable unauthorized access to sensitive model artifacts.

- [CWE-541](https://cwe.mitre.org/data/definitions/541.html): Information Exposure Through Include Source Code

  Description: Source code exposes sensitive details like credentials, SQL, or cryptographic material.

  Justification: Model source code could expose sensitive configuration details or training data. 

- [CWE-649](https://cwe.mitre.org/data/definitions/649.html): Reliance on Obfuscation or Protection Mechanism

  Description: Relying solely on obfuscation or data protection mechanisms provides ineffective protection.

  Justification: Proper access controls still needed despite obfuscation of sensitive data.

- [CWE-922](https://cwe.mitre.org/data/definitions/922.html): Insecure Storage of Sensitive Information

  Description: Sensitive information stored without encryption or with a weak algorithm can enable adversaries to easily gain access.

  Justification: Unencrypted model artifacts could expose training data or parameters.

### MITRE ATT&CK Techniques

- [T1530](https://attack.mitre.org/techniques/T1530/) - Data from Cloud Storage Object

  Description: Adversaries may get access to sensitive data from cloud storage including credentials and keys.

  Justification: Could access stored artifacts exposing sensitive model information. 

- [T1552](https://attack.mitre.org/techniques/T1552/) - Unsecured Credentials

  Description: Adversaries may steal and abuse valid account credentials and keys to access cloud services, like AWS.

  Justification: Compromised credentials could enable unauthorized access to sensitive information.


### MITRE ATLAS Techniques

- AML.T0024: Exfiltration via ML Inference API. The inference API could reveal private details about training data or model behavior enabling exposure of sensitive information.

- AML.T0021: Establish Accounts. May access compromised victim accounts to collect sensitive documents, artifacts or data. Gains access to private information.

- AML.T0036: Data from Information Repositories. Could steal sensitive documents, artifacts or data from repositories. Exfiltrates sensitive information. 

- AML.T0037: Data from Local System. Local systems like model servers contain private artifacts, data and documents that could be collected. Gathers sensitive information.

- AML.T0040: ML Model Inference API Access. Carefully crafted inference queries could reveal private details about training data or model behavior. API access enables exposing sensitive information.

- AML.T0016: Obtain Capabilities. May obtain tools to exfiltrate sensitive data or automate collection of private artifacts. Aids stealing sensitive information. 

- AML.T0012: Valid Accounts. Compromised credentials provide access to systems and sensitive artifacts, data and documents. Allows access to private information.

- AML.T0044: Full ML Model Access. Full whitebox control enables retrieving maximum sensitive information from model internals. Maximizes data access.

- AML.T0047: ML-Enabled Product or Service. Services with weak data protection could be exploited to access sensitive information. Identifies services with data exposure risks. 

- AML.T0019: Publish Poisoned Data. Training models on sensitive data could enable later inference of that private information. Leaks sensitive data via training set composition.
  
### MITRE ATT&CK Mitigations

- [M1041](https://attack.mitre.org/mitigations/M1041/): Restrict Web-Based Content

  Description: Limiting web content execution can reduce attack surface and prevent malicious web activity.

  Justification: Could block web vectors used to collect sensitive data. 

- [M1043](https://attack.mitre.org/mitigations/M1043/): Isolate System or Network

  Description: Isolating systems provides network segmentation, limiting an attacker's ability to access systems and sensitive data.

  Justification: Segmentation limits exposure of sensitive systems and data.

- [M1048](https://attack.mitre.org/mitigations/M1048/): Perform Software and File Integrity Checking

  Description: Checking integrity of systems and files enables detection of unauthorized modifications or access attempts.

  Justification: Could identify unauthorized access attempts and modifications.


### MITRE ATLAS Mitigations

- AML.M0002: Passive ML Output Obfuscation. Decrease output fidelity which limits the amount of sensitive information leaked through model outputs.

- AML.M0004: Restrict Number of ML Model Queries. Limit total queries and rate which reduces attack surface for malicious queries attempting to extract sensitive data.

- AML.M0015: Adversarial Input Detection. Detect and block potentially malicious queries designed to expose sensitive data. Identifies data stealing attempts.

- AML.M0003: Model Hardening. Make models more robust to inputs attempting to extract sensitive training data. Hardens model against data exposure.

- AML.M0001: Limit Model Artifact Release. Reduce public information that could help adversaries design inputs to extract sensitive data. Limits available information. 

- AML.M0005: Control Access to ML Models and Data at Rest. Limit access to sensitive training data and models. Reduces attack surface for data exposure.

- AML.M0012: Encrypt Sensitive Information. Encrypt training data, models and artifacts containing sensitive information. Protects against data exposure. 

- AML.M0014: Verify ML Artifacts. Detect artifacts that may have been tampered with to introduce data exposure vulnerabilities. Identifies risks.

- AML.M0007: Sanitize Training Data. Remove sensitive data from training sets and models. Addresses data exposure risks introduced via training data.