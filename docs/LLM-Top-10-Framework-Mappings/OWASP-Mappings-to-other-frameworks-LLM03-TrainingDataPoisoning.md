By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM03: Training Data Poisoning

## Summary

Tampered training data can impair LLM models leading to responses that may compromise security, accuracy, or ethical behavior.

## Description

Training Data Poisoning involves manipulating the data used to train LLMs to impair model capabilities and outputs. 

Poisoned training data like falsified, biased, or malicious content can lead to compromised security, accuracy, or ethical model behavior. Attackers may target pre-training data or data used for fine-tuning and embeddings. Impacts include unreliable outputs, biases, information leakage, reputation damage, and flawed decisions.

Prevention involves verifying supply chain integrity, validating legitimacy of data sources, isolating training environments, sanitizing inputs, and incorporating adversarial robustness techniques. Monitoring model behavior and using human review loops can help detect poisoning attacks.


## CWE

[CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Applicable as lack of validation enables poisoning of training data.

[CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function - Applicable as lack of authentication of data sources can allow poisoning.

[CWE-502](https://cwe.mitre.org/data/definitions/502.html): Deserialization of Untrusted Data - Applicable as deserializing untrusted training data poses risks.

[CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure - Added as failure of protections can enable poisoning.

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as poisoned data introduces unintended functionality.

[CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities - Added as vulnerable components could enable poisoning.


## MITRE ATT&CK Techniques

- AML.T0019: Publish Poisoned Data. Adversaries could directly publish poisoned datasets used for training.

- AML.T0020: Poison Training Data. Allows adversaries to manipulate training data to introduce vulnerabilities.

- AML.T0010: ML Supply Chain Compromise. Compromising data sources could allow poisoning of artifacts used for training. 

- AML.T0016: Obtain Capabilities. Adversaries may obtain tools to aid in crafting poisoned data.

- AML.T0043: Craft Adversarial Data. Could allow carefully crafted data designed to influence model behavior.

- AML.T0012: Valid Accounts. Compromised credentials could allow direct data poisoning.

- AML.T0044: Full ML Model Access. Full access enables direct manipulation of training data.

- AML.T0040: ML Model Inference API Access. May enable inferring details of training data to craft attacks.

- AML.T0024: Exfiltration via ML Inference API. Could expose private training data. 

- AML.T0047: ML-Enabled Product or Service. Existing services using poisoned data could be exploited.


## MITRE ATT&CK Mitigations

- AML.M0007: Sanitize Training Data. Remove or remediate poisoned data. Directly addresses data poisoning. 

- AML.M0014: Verify ML Artifacts. Detect tampering of training data. Identifies poisoning attempts.

- AML.M0004: Restrict Number of ML Model Queries. Limit inference queries that could aid poisoning. Reduces attack surface.

- AML.M0013: Code Signing. Prevent execution of poisoned artifacts. Blocks malicious code execution. 

- AML.M0015: Adversarial Input Detection. Detect and block poisoning input attempts. Identifies poisoning tries. 

- AML.M0012: Encrypt Sensitive Information. Encrypt training data. Limits exposure for poisoning. 

- AML.M0005: Control Access to ML Models and Data at Rest. Limit access to training data. Reduces poisoning surface.

- AML.M0016: Vulnerability Scanning. Scan for flaws that could enable poisoning. Finds weaknesses to address.

- AML.M0018: User Training. Educate users on poisoning risks. Reduces unknowing poisoning.
