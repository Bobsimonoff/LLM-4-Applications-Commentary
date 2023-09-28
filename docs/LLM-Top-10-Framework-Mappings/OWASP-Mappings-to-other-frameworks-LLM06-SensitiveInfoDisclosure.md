By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM06: Sensitive Information Disclosure

## Summary
Failure to protect against disclosure of sensitive information in LLM outputs can result in legal consequences or a loss of competitive advantage.

## Description

Failure to protect against unauthorized exposure of confidential data in LLM outputs can enable adversaries to steal intellectual property and sensitive information. 

Inadequate data handling, weak access controls, and insufficient input/output validation allow attackers to insert malicious prompts or directly access sensitive data. Successful attacks can lead to privacy violations, intellectual property theft, reputational damage, and regulatory noncompliance.

Prevention involves robust data sanitization, input filtering, and output validation. Strict access controls should be implemented, limiting data access to only authorized purposes. LLM training data must be carefully filtered to exclude sensitive information. Comprehensive data governance and privacy policies can help mitigate risks. Monitoring systems for anomalous behavior can also help detect potential unauthorized access attempts. Securing LLMs against sensitive data exposure is critical for maintaining trust and competitive advantage.


## Common Weakness Enumeration (CWE)

- [CWE-202](https://cwe.mitre.org/data/definitions/202.html): Exposure of Sensitive Information to an Unauthorized Actor - Applicable when sensitive data like API keys or PII is exposed in model outputs to unauthorized users due to inadequate access controls.

- [CWE-208](https://cwe.mitre.org/data/definitions/208.html): Observable Discrepancy - Applicable when differences between a model's expected and actual outputs allow inference of sensitive information used in training data. 

- [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Information Exposure Through an Error Message - Applicable if error messages generated during model inference reveal details about training data or internal model information.

- [CWE-215](https://cwe.mitre.org/data/definitions/215.html): Information Exposure Through Debug Information - Applicable if debug logs from models contain sensitive metadata or inferences about private training data.

- [CWE-538](https://cwe.mitre.org/data/definitions/538.html): File and Directory Information Exposure - Applicable if filesystem permissions allow unauthorized access to view model artifacts containing sensitive data.

- [CWE-541](https://cwe.mitre.org/data/definitions/541.html): Information Exposure Through Include Source Code - Applicable if source code for models exposes sensitive configuration details or training data.

- [CWE-649](https://cwe.mitre.org/data/definitions/649.html): Reliance on Obfuscation or Protection Mechanism - Applicable if relying solely on input/output obfuscation without proper access controls to protect sensitive data.

- [CWE-922](https://cwe.mitre.org/data/definitions/922.html): Insecure Storage of Sensitive Information - Applicable if artifacts containing sensitive data like model parameters or training texts are stored without encryption.

## ATT&CK Techniques

- [T1530](https://attack.mitre.org/techniques/T1530/) - Data from Cloud Storage Object. Accesses cloud storage containing model training data or artifacts. Could access stored sensitive information.

- [T1552](https://attack.mitre.org/techniques/T1552/) - Unsecured Credentials. Uses compromised identities and keys to access systems and data. Could enable unauthorized access to sensitive information.


## MITRE ATLAS Techniques

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
  

## ATT&CK Mitigations

- [M1041](https://attack.mitre.org/mitigations/M1041/) - Restrict Web-Based Content. Limits web content execution which could be used to collect sensitive data or access controlled systems. Reduces attack surface.

- [M1043](https://attack.mitre.org/mitigations/M1043/) - Isolate System or Network. Isolates systems containing sensitive data and models. Limits access to sensitive information. 

- [M1048](https://attack.mitre.org/mitigations/M1048/) - Perform Software and File Integrity Checking. Checks integrity of assets like data and models. Could detect unauthorized modifications or access attempts.

## MITRE ATLAS Mitigations

- AML.M0002: Passive ML Output Obfuscation. Decrease output fidelity which limits the amount of sensitive information leaked through model outputs.

- AML.M0004: Restrict Number of ML Model Queries. Limit total queries and rate which reduces attack surface for malicious queries attempting to extract sensitive data.

- AML.M0015: Adversarial Input Detection. Detect and block potentially malicious queries designed to expose sensitive data. Identifies data stealing attempts.

- AML.M0003: Model Hardening. Make models more robust to inputs attempting to extract sensitive training data. Hardens model against data exposure.

- AML.M0001: Limit Model Artifact Release. Reduce public information that could help adversaries design inputs to extract sensitive data. Limits available information. 

- AML.M0005: Control Access to ML Models and Data at Rest. Limit access to sensitive training data and models. Reduces attack surface for data exposure.

- AML.M0012: Encrypt Sensitive Information. Encrypt training data, models and artifacts containing sensitive information. Protects against data exposure. 

- AML.M0014: Verify ML Artifacts. Detect artifacts that may have been tampered with to introduce data exposure vulnerabilities. Identifies risks.

- AML.M0007: Sanitize Training Data. Remove sensitive data from training sets and models. Addresses data exposure risks introduced via training data.