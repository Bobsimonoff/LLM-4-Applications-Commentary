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


## Common Weakness Enumeration (CWE) 

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Failure to properly validate input data. Applicable as lack of validation enables poisoning of training data by allowing malicious data to be ingested without inspection.

- [CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function - Not authenticating entities before performing sensitive functions. Applicable as lack of authentication of data sources can allow poisoning by permitting unauthorized access to manipulate training data. 

- [CWE-502](https://cwe.mitre.org/data/definitions/502.html): Deserialization of Untrusted Data - Deserializing data from untrusted sources. Applicable as deserializing untrusted training data poses risks of executing adversary code in poisoned serialized models or datasets.

- [CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure - A security protection failing unexpectedly. Added as failure of protections can enable poisoning by allowing defenses to be circumvented.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Use of untrusted code or inputs. Applicable as poisoned data introduces unintended functionality by including malicious content.

- [CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities - Failure to patch known weaknesses. Added as vulnerable components could enable poisoning by providing a vector for malicious data to enter workflow.

## ATT&CK Techniques

- [T1565](https://attack.mitre.org/techniques/T1565/): Data Manipulation - Altering data prior to storage or transmission. Could directly poison training data by manipulating datasets before they are consumed.

- [T1566](https://attack.mitre.org/techniques/T1566/): Phishing - Use of fraudulent messages to deliver payloads. Could direct users to poisoned data sources through phishing lures.

## MITRE ATLAS Techniques

- [AML.T0019](/techniques/AML.T0019): Publish Poisoned Data - Distribution of contaminated datasets. Adversaries could directly publish poisoned datasets used for training. Directly provides poisoned data.

- [AML.T0020](/techniques/AML.T0020): Poison Training Data - Manipulation of training data to introduce vulnerabilities. Allows adversaries to manipulate training data to introduce vulnerabilities. Directly poisons data. 

- [AML.T0010](/techniques/AML.T0010): ML Supply Chain Compromise - Compromise of ML components and services. Compromising data sources could allow poisoning of artifacts used for training. Introduces poisoned data through third parties.

- [AML.T0016](/techniques/AML.T0016): Obtain Capabilities - Obtaining tools and exploits. Adversaries may obtain tools to aid in crafting poisoned data. Provides capabilities to optimize poisoning. 

- [AML.T0043](/techniques/AML.T0043): Craft Adversarial Data - Careful input crafting to manipulate models. Could allow carefully crafted data designed to influence model behavior. Allows optimizing poisoned data.

- [AML.T0012](/techniques/AML.T0012): Valid Accounts - Abuse of compromised credentials. Compromised credentials could allow direct data poisoning. Provides access to manipulate training data. 

- [AML.T0044](/techniques/AML.T0044): Full ML Model Access - Complete control over the model. Full access enables direct manipulation of training data. Provides maximal control over data.

- [AML.T0040](/techniques/AML.T0040): ML Model Inference API Access - Use of the model API to manipulate behavior. May enable inferring details of training data to craft attacks. Allows reconnaissance for optimizing attacks.

- [AML.T0024](/techniques/AML.T0024): Exfiltration via ML Inference API - Stealing data through the model API. Could expose private training data. Reveals insider information about training data.

- [AML.T0047](/techniques/AML.T0047): ML-Enabled Product or Service - Exploiting ML services. Existing services using poisoned data could be exploited. Propagates impacts through supply chain.


## ATT&CK Mitigations

- [M1041](https://attack.mitre.org/mitigations/M1041/): Restrict Web-Based Content - Limiting web content execution. Limits web content execution. Could block web access to poisoned data by restricting web content loading. 

- [M1043](https://attack.mitre.org/mitigations/M1043/): Isolate System or Network - Isolating systems from untrusted networks. Isolates systems and networks. Could prevent poisoned data from spreading by isolating compromised systems.

- [M1050](https://attack.mitre.org/mitigations/M1050/): Network Segmentation - Segmenting networks into enclaves. Segregates networks. Could prevent poisoned data accessing production systems by enforcing network boundaries. 

## MITRE ATLAS Mitigations

- AML.M0007: Sanitize Training Data - Detecting and removing malicious training data. Remove or remediate poisoned data. Directly addresses data poisoning by cleansing datasets.

- AML.M0014: Verify ML Artifacts - Checking artifacts for signs of tampering. Detect tampering of training data. Identifies poisoning attempts by validating data integrity. 

- AML.M0004: Restrict Number of ML Model Queries - Limiting queries to reduce attack surface. Limit inference queries that could aid poisoning. Reduces attack surface by restricting overall model access. 

- AML.M0013: Code Signing - Enforcing integrity checks on software and binaries. Prevent execution of poisoned artifacts. Blocks malicious code execution by requiring valid signatures.

- AML.M0015: Adversarial Input Detection - Detecting and blocking malicious input data. Detect and block poisoning input attempts. Identifies poisoning tries by analyzing inputs.

- AML.M0012: Encrypt Sensitive Information - Protecting confidentiality through cryptography. Encrypt training data. Limits exposure for poisoning by encoding data.

- AML.M0005: Control Access to ML Models and Data at Rest - Implementing access controls on assets. Limit access to training data. Reduces poisoning surface by restricting data access. 

- AML.M0016: Vulnerability Scanning - Discovering flaws and weaknesses. Scan for flaws that could enable poisoning. Finds weaknesses to address through active scanning. 

- AML.M0018: User Training - Educating users about adversary TTPs. Educate users on poisoning risks. Reduces unknowing poisoning by improving awareness.

