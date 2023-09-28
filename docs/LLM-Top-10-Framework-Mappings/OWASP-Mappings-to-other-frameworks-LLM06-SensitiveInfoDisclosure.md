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

[CWE-202](https://cwe.mitre.org/data/definitions/202.html): Exposure of Sensitive Information to an Unauthorized Actor - Applicable when sensitive data is exposed to unauthorized users.

[CWE-208](https://cwe.mitre.org/data/definitions/208.html): Observable Discrepancy - Applicable when differences between expected and actual LLM behavior allow inference of sensitive information.

[CWE-209](https://cwe.mitre.org/data/definitions/209.html): Information Exposure Through an Error Message - Applicable if error messages reveal sensitive information. 

[CWE-215](https://cwe.mitre.org/data/definitions/215.html): Information Exposure Through Debug Information - Applicable if debug logs contain sensitive data.

[CWE-538](https://cwe.mitre.org/data/definitions/538.html): File and Directory Information Exposure - Applicable if filesystem information is exposed.

[CWE-541](https://cwe.mitre.org/data/definitions/541.html): Information Exposure Through Include Source Code - Applicable if source code containing sensitive data is exposed.

[CWE-649](https://cwe.mitre.org/data/definitions/649.html): Reliance on Obfuscation or Protection Mechanism - Applicable if relying solely on obfuscation without proper access controls.

[CWE-922](https://cwe.mitre.org/data/definitions/922.html): Insecure Storage of Sensitive Information - Applicable if sensitive data is stored insecurely.

## ATT&CK Techniques

- [T1530](https://attack.mitre.org/techniques/T1530/) - Data from Cloud Storage Object. Accesses cloud storage data. Could access stored sensitive data.

- [T1552](https://attack.mitre.org/techniques/T1552/) - Unsecured Credentials. Uses compromised identities and keys. Could enable unauthorized data access.

## ATT&CK Mitigations

- [M1041](https://attack.mitre.org/mitigations/M1041/) - Restrict Web-Based Content. Limits web content execution. Could block web access to sensitive data. 

- [M1043](https://attack.mitre.org/mitigations/M1043/) - Isolate System or Network. Isolates systems and networks. Could prevent sensitive data access.

- [M1048](https://attack.mitre.org/mitigations/M1048/) - Perform Software and File Integrity Checking. Checks integrity of assets. Could detect unauthorized data modifications.


## MITRE ATLAS Techniques

- AML.T0024: Exfiltration via ML Inference API. The API could reveal private training data or inferences. Directly leaks sensitive data.

- AML.T0021: Establish Accounts. May access victim accounts to collect sensitive data. Gains access to private data. 

- AML.T0036: Data from Information Repositories. Could steal sensitive documents and data. Exfiltrates sensitive data.

- AML.T0037: Data from Local System. Local systems contain private data that could be collected. Gathers sensitive data. 

- AML.T0040: ML Model Inference API Access. Carefully crafted queries could reveal private details. API access to exploit.

- AML.T0016: Obtain Capabilities. May obtain tools to exfiltrate or automate data collection. Aids stealing data.

- AML.T0012: Valid Accounts. Compromised credentials provide access to sensitive data. Allows access to private data.

- AML.T0044: Full ML Model Access. Full control enables retrieving maximum data. Maximizes data access. 

- AML.T0047: ML-Enabled Product or Service. Services with data exposure could be exploited. Identify services with weaknesses.

- AML.T0019: Publish Poisoned Data. Training on sensitive data could enable later exposure. Leaks data via training.

## MITRE ATLAS Mitigations

- AML.M0002: Passive ML Output Obfuscation. Decrease output fidelity. Limits information leaked through outputs.

- AML.M0004: Restrict Number of ML Model Queries. Limit total queries and rate. Reduces attack surface. 

- AML.M0015: Adversarial Input Detection. Detect and block malicious queries. Identifies data stealing attempts.

- AML.M0003: Model Hardening. Make models more robust to extracting sensitive data. Hardens model. 

- AML.M0001: Limit Model Artifact Release. Reduce public info that could help extract data. Limits available information.

- AML.M0005: Control Access to ML Models and Data at Rest. Limit access to sensitive data and models. Reduces attack surface.

- AML.M0012: Encrypt Sensitive Information. Encrypt data and models. Protects sensitive artifacts. 

- AML.M0014: Verify ML Artifacts. Detect artifacts tampered with to enable data theft. Identifies data exposure efforts.

- AML.M0007: Sanitize Training Data. Remove sensitive data from training sets. Addresses data exposure via training. 


