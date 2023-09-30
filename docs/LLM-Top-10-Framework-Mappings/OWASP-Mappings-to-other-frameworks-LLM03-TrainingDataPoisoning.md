By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM03: Training Data Poisoning

### Summary

Tampered training data can impair LLM models leading to responses that may compromise security, accuracy, or ethical behavior.

### Description

Training Data Poisoning involves manipulating the data used to train LLMs to impair model capabilities and outputs. 

Poisoned training data like falsified, biased, or malicious content can lead to compromised security, accuracy, or ethical model behavior. Attackers may target pre-training data or data used for fine-tuning and embeddings. Impacts include unreliable outputs, biases, information leakage, reputation damage, and flawed decisions.

Prevention involves verifying supply chain integrity, validating legitimacy of data sources, isolating training environments, sanitizing inputs, and incorporating adversarial robustness techniques. Monitoring model behavior and using human review loops can help detect poisoning attacks.


### Common Examples of Risk

1. Malicious actor poisons model training data with falsified information that impacts model outputs.

2. Attacker directly injects harmful content into model training which is reflected in outputs. 

3. User unintentionally leaks sensitive data that appears in model outputs.

4. Model trains on unverified data leading to inaccurate outputs.

5. Model ingests unsafe data due to lack of access controls, generating harmful outputs.

### Prevention and Mitigation Strategies

1. Verify training data supply chain, sources, and contents.

2. Confirm legitimacy of all data used in training stages.

3. Craft separate models for different use cases with tailored training data.

4. Sandbox models to restrict ingestion of unintended data sources. 

5. Filter and sanitize training data inputs.

6. Use robustness techniques like federated learning to minimize outlier impact.

7. Test models and monitor outputs to detect poisoning signs.

### Example Attack Scenarios

1. Attacker poisons training data to bias model outputs and mislead users. 

2. Malicious user injects toxic data into training, adapting model to generate biased output.

3. Attacker creates fake documents that manipulate model training, impacting outputs.

4. Attacker exploits prompt injection to insert malicious data into model training.

### Common Weakness Enumeration (CWE) 

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Description: Missing or inadequate input validation leads to unchecked tainted input used directly or indirectly resulting in dangerous downstream behaviors.

  Justification: Lack of validation enables poisoning of training data by allowing malicious data to be ingested without inspection.

- [CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function

  Description: The software does not perform or incorrectly performs an authentication check when an actor attempts to access a critical function or resource.

  Justification: Lack of authentication of data sources can allow poisoning by permitting unauthorized access to manipulate training data.

- [CWE-502](https://cwe.mitre.org/data/definitions/502.html): Deserialization of Untrusted Data

  Description: The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.

  Justification: Deserializing untrusted training data poses risks of executing adversary code in poisoned serialized models or datasets.

- [CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure

  Description: A protection mechanism unexpectedly fails to be enforced or performs an unexpected negative action. This may lead to unintended adverse consequences that were supposed to be prevented by the mechanism.

  Justification: Failure of protections can enable poisoning by allowing defenses to be circumvented.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: The software imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

  Justification: Poisoned data introduces unintended functionality by including malicious content.

- [CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities

  Description: The software is out-of-date, lacking patches, or uses components with publicly known vulnerabilities.

  Justification: Vulnerable components could enable poisoning by providing a vector for malicious data to enter workflow.


### MITRE ATT&CK Techniques

- [T1565](https://attack.mitre.org/techniques/T1565/): Data Manipulation

  Description: Adversaries may manipulate and forge file contents and metadata to confuse and mislead forensic investigators or file analysis tools. File attributes like timestamps can be modified to mimic legitimate files. Adversaries may tamper with data at rest or in transit to manipulate external outcomes.

  Justification: Could directly poison training data by manipulating datasets before they are consumed.

### MITRE ATLAS Techniques

- AML.T0019: Publish Poisoned Datasets

  Description: Adversaries may poison datasets and publish them to a public location. The poisoned data may be introduced via supply chain compromise.

  Justification: Publishing poisoned training data enables poisoning attacks by making malicious data available.

- AML.T0020: Poison Training Data

  Description: Adversaries may modify training data or labels to embed vulnerabilities in models trained on the data. Poisoned data can be introduced through supply chain attacks or after gaining initial access.

  Justification: Poisoning training data is a direct way to manipulate model behavior by embedding flaws.

- AML.T0035: ML Artifact Collection

  Description: Adversaries may collect ML artifacts like models and datasets for exfiltration or use in attack staging.

  Justification: Collecting training data could enable poisoning by providing access to manipulate the data.

- AML.T0036: Data from Information Repositories

  Description: Adversaries may mine information repositories to find valuable data aiding their objectives. Repositories facilitate collaboration and information sharing.

  Justification: Mining data repositories could reveal training data sources to target for poisoning attacks.

- AML.T0037: Data from Local System

  Description: Adversaries may search local system sources like file systems and databases to find sensitive data prior to exfiltration.

  Justification: Accessing local training data stores enables poisoning attacks by providing ability to directly manipulate the data.

- AML.T0043: Craft Adversarial Data

  Description: Adversaries carefully craft inputs to manipulate model behavior and outputs. Modifications are designed to achieve the adversary's goals.

  Justification: Crafting poisoned training data manipulates the model's learned behavior.

- AML.T0044: Full ML Model Access

  Description: Adversaries gain complete white-box access to a model, enabling them to meticulously craft malicious inputs.

  Justification: Full access facilitates crafting poisoned training data to precisely manipulate model capabilities.

- AML.T0010: ML Supply Chain Compromise

  Description: Adversaries compromise parts of the ML supply chain like data, software, and models to gain initial access.

  Justification: Compromising training data supply chain is a vector for introducing poisoned data.


### MITRE ATT&CK Mitigations

- [M1041](https://attack.mitre.org/mitigations/M1041/): Restrict Web-Based Content

  Description: Allowlisting, blocking, or sandboxing web content will reduce the attack surface against web-based attacks, resulting in safer web browsing and reduced phishing effectiveness.

  Justification: Could block web access to poisoned data by restricting web content loading.

- [M1043](https://attack.mitre.org/mitigations/M1043/): Isolate System or Network

  Description: Isolate systems from the Internet or untrusted networks, and isolate sensitive systems from vulnerable systems to reduce a threat's ability to access and compromise systems. Network segregation also adds a layer of defense, since an exploitation would have to traverse the boundary to reach other systems.

  Justification: Could prevent poisoned data from spreading by isolating compromised systems.

- [M1050](https://attack.mitre.org/mitigations/M1050/): Network Segmentation

  Description: Segment networks to enforce a degree of separation between systems that reduces the ability for lateral movement and limits traffic to other enclaves and zones. Network segmentation can be achieved through the use of emerging network virtualization techniques, VLANs, and physically separated network segments joined by guarded network gateways.

  Justification: Could prevent poisoned data accessing production systems by enforcing network boundaries.

- [M1015](https://attack.mitre.org/mitigations/M1015/): Secure Authentication

  Description: Adversaries commonly steal credentials or reuse existing compromised credentials as a means of gaining Initial Access; limiting accessibility and applying multi-factor authentication makes credential theft more difficult. Enable MFA/2FA and use centralized management to enforce secure authentication across all systems, services, and infrastructure.

  Justification: Secure authentication prevents unauthorized data poisoning.


### MITRE ATLAS Mitigations

- AML.M0007: Sanitize Training Data - Detecting and removing malicious training data. Remove or remediate poisoned data. Directly addresses data poisoning by cleansing datasets.

- AML.M0014: Verify ML Artifacts - Checking artifacts for signs of tampering. Detect tampering of training data. Identifies poisoning attempts by validating data integrity. 

- AML.M0004: Restrict Number of ML Model Queries - Limiting queries to reduce attack surface. Limit inference queries that could aid poisoning. Reduces attack surface by restricting overall model access. 

- AML.M0013: Code Signing - Enforcing integrity checks on software and binaries. Prevent execution of poisoned artifacts. Blocks malicious code execution by requiring valid signatures.

- AML.M0015: Adversarial Input Detection - Detecting and blocking malicious input data. Detect and block poisoning input attempts. Identifies poisoning tries by analyzing inputs.

- AML.M0012: Encrypt Sensitive Information - Protecting confidentiality through cryptography. Encrypt training data. Limits exposure for poisoning by encoding data.

- AML.M0005: Control Access to ML Models and Data at Rest - Implementing access controls on assets. Limit access to training data. Reduces poisoning surface by restricting data access. 

- AML.M0016: Vulnerability Scanning - Discovering flaws and weaknesses. Scan for flaws that could enable poisoning. Finds weaknesses to address through active scanning. 

- AML.M0018: User Training - Educating users about adversary TTPs. Educate users on poisoning risks. Reduces unknowing poisoning by improving awareness.

