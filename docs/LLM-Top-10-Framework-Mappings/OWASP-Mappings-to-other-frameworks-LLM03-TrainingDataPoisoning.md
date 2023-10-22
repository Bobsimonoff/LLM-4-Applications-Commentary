By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main



# LLM03: Training Data Poisoning

### Summary

Tampered training data can impair LLMs, leading to compromised security, accuracy, or ethical behavior.

### Description

Training data poisoning involves manipulating training data to intentionally impair model capabilities and outputs. Poisoned data leads to compromised security, inaccurate outputs, biases, information leakage, and flawed decisions.

Poisoning attacks target pre-training or fine-tuning data. Impacts include unreliable outputs, biases, reputation damage, and unethical behavior.

Prevention involves supply chain integrity checks, input sanitization, isolation, and adversarial robustness techniques. Monitoring and human review help detect poisoning attacks.


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

  Justification: Deserializing untrusted training data not only poses risks of code execution but also allows the injection of malicious training examples directly into the training dataset, making it more susceptible to data poisoning.

- [CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure

  Description: A protection mechanism unexpectedly fails to be enforced or performs an unexpected negative action. This may lead to unintended adverse consequences that were supposed to be prevented by the mechanism.

  Justification: Failure of protections can enable poisoning by allowing defenses to be circumvented.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: The software imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

  Justification: Poisoned data introduces unintended functionality by including malicious content.

- [CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities

  Description: The software is out-of-date, lacking patches, or uses components with publicly known vulnerabilities.

  Justification: Vulnerable components could enable poisoning by providing a vector for malicious data to enter workflow.

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html): OS Command Injection

  Description: The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.

  Justification: OS command injection can potentially allow an attacker to tamper with the data or the system where training data is stored, thereby facilitating poisoning.



### Techniques

### MITRE ATT&CK® Techniques

- [T1565](https://attack.mitre.org/techniques/T1565/): Data Manipulation

  Description: Adversaries may manipulate and forge file contents and metadata to confuse and mislead forensic investigators or file analysis tools. File attributes like timestamps can be modified to mimic legitimate files. Adversaries may tamper with data at rest or in transit to manipulate external outcomes.
   
  Justification: Could directly poison training data by manipulating datasets before they are consumed. 

- [T1190](https://attack.mitre.org/techniques/T1190): Exploit Public-Facing Application

  Description: Adversaries may attack public-facing applications in an attempt to manipulate, exfiltrate, or modify data, including the risk of tampering with training data.
   
  Justification: Vulnerable public-facing applications can be an entry point for attackers to manipulate training data.

### MITRE ATLAS™ Techniques

- [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020): Poison Training Data - An attacker could poison the training data used to train the victim LLM. This allows the attacker to embed vulnerabilities that can be triggered later with crafted inputs.

- [AML.T0018](https://atlas.mitre.org/techniques/AML.T0018): Backdoor ML Model - An attacker could backdoor the LLM by training it on poisoned data that associates a trigger with a malicious output. This backdoor could later be used to force unethical or flawed behavior.

- [AML.T0019](https://atlas.mitre.org/techniques/AML.T0019): Publish Poisoned Datasets - An attacker could publish a poisoned dataset that the victim organization then unintentionally uses to train their LLM, poisoning it.


### Additional Techniques

- Model Parameter Tampering

  Description: Adversaries may tamper with the hyperparameters of the model, affecting how the model learns from the training data, thereby inducing flawed behavior.
   
  Justification: Tampering with model parameters directly targets the learning process and can introduce vulnerabilities.



### Mitigations

### MITRE ATT&CK® Mitigations

- [M1013](https://attack.mitre.org/mitigations/M1013): Application Developer Guidance

  Description: This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of.
   
  Justification: Guidance on secure coding practices helps prevent vulnerabilities that could enable data tampering.

- [M1041](https://attack.mitre.org/mitigations/M1041): Encrypt Sensitive Information

  Description: Protect sensitive information with strong encryption.
   
  Justification: Encrypting training data and models protects their integrity and validity.

- [M1053](https://attack.mitre.org/mitigations/M1053): Data Backup

  Description: Regular backups of critical data can serve as a safeguard against data tampering, including training data poisoning.
   
  Justification: Frequent backups can serve as a mitigation strategy for rolling back to a clean state in case of training data poisoning.


### MITRE ATLAS™ Mitigations

- [AML.M0007](https://atlas.mitre.org/mitigations/AML.M0007): Sanitize Training Data - Detect and remove poisoned data before model training.

- [AML.M0014](https://atlas.mitre.org/mitigations/AML.M0014): Verify ML Artifacts - Catch poisoned datasets by verifying checksums. 


### Additional Mitigations 

- Use Case Specific Model Training and Deployment

  Description: Create separate machine learning models for each specific intended use case or application. Carefully curate and isolate the training data used for each individual model based on the data required for that particular use case. Do not commingle data across different use case models.

  Justification: Training models on data narrowly tailored to one specific application limits the attack surface. If an attacker poisons a subset of the data, it will only affect the model trained on that related data, not propagate across models for other use cases. Segmenting data by use case contained any poisoning impact.

- Employ Robust Training Techniques  

  Description: Incorporate robust machine learning training techniques designed to reduce the influence of outlier data points, such as those from a poisoning attack. Examples include federated learning, which trains models on decentralized data located on user devices. Differential privacy introduces noise to mask individual data points.

  Justification: Robust training techniques make the model more resilient against poisoning attacks by minimizing the impact of any manipulated training data. Outlier points have reduced influence on the overall model behavior. This prevents attackers from significantly altering model performance by poisoning small portions of data.

- Continuous Data Integrity Checks

  Description: Continuously verify the integrity of training data by employing cryptographic hashing and integrity checking mechanisms.
   
  Justification: Integrity checks directly validate data has not been manipulated.


### STRIDE Analysis (generated by clause.ai)

Training data poisoning attacks can impact multiple components of the STRIDE threat model:

**Spoofing**

- Attackers can spoof the source of poisoned data to disguise its malicious origins.
- Manipulated training data could also spoof legitimate source domains, authors, timestamps, etc. 

**Tampering**

- Poisoning directly tampers with and manipulates model training data.
- Crafted malicious data precisely controls how models behave by embedding specific vulnerabilities.

**Repudiation** 

- Lack of data provenance around poisoned sources can complicate attack attribution.
- Poisoning attacks could also disable or tamper with data logging to undermine attribution.

**Information Disclosure**

- Models trained on poisoned data may reveal sensitive information about training data, model parameters, or backend systems.
- Poisoned web scraped data could expose sensitive user info during training.

**Denial of Service**

- Maliciously corrupted training data could trigger crashes, resource exhaustion, or model degradation.
- Targeted data poisoning could severely impair model accuracy or usability.

**Elevation of Privilege**

- Poisoned data may enable privilege escalation or disable access controls on backend systems.
- Compromised data source credentials enable greater access when poisoning data.

In summary, training data poisoning can impact confidentiality, integrity, and availability across multiple STRIDE categories through direct data manipulation and embedding of model flaws.