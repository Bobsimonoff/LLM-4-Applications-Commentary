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


### MITRE ATT&CK® Techniques

- [T1565](https://attack.mitre.org/techniques/T1565/): Data Manipulation

  Description: Adversaries may manipulate and forge file contents and metadata to confuse and mislead forensic investigators or file analysis tools. File attributes like timestamps can be modified to mimic legitimate files. Adversaries may tamper with data at rest or in transit to manipulate external outcomes.

  Justification: Could directly poison training data by manipulating datasets before they are consumed.


### MITRE ATLAS™ Techniques

- AML.T0019: Publish Poisoned Datasets

  Description: Adversaries may publish poisoned datasets designed to manipulate and impair models that consume the data. Publishing provides a vector to introduce malicious data into victim training pipelines.

  Justification: Publishing poisoned data enables poisoning by making malicious datasets available to unsuspecting consumers.

- AML.T0020: Poison Training Data

  Description: Adversaries may directly poison training data to embed flaws activated later. Poisoned data introduced via supply chain attacks or after gaining access persistently compromises integrity of models trained on the data.

  Justification: Poisoning training data is a direct way to manipulate model capabilities by embedding vulnerabilities.

- AML.T0035: ML Artifact Collection

  Description: Adversaries may collect artifacts like training data for exfiltration or use in attack staging. Access to training data provides the ability to directly manipulate and poison it.

  Justification: Access to training data enables poisoning by permitting direct data manipulation.

- AML.T0036: Data from Information Repositories

  Description: By mining repositories, adversaries can discover details of training data sources, enabling them to target sources directly for poisoning attacks.

  Justification: Discovering data repository details reveals training data sources to target.
  
- AML.T0043: Craft Adversarial Data

  Description: Adversaries may carefully craft malicious training data designed to manipulate model capabilities. The tailored data embeds specific flaws during training.

  Justification: Crafting poisoned data precisely manipulates models by embedding flaws.


### MITRE ATT&CK® Mitigations

- [M1013](https://attack.mitre.org/mitigations/M1013): Application Developer Guidance

  Description: This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of.

  Justification: Guidance on secure coding practices helps prevent vulnerabilities that could enable data tampering.

- [M1027](https://attack.mitre.org/mitigations/M1027): Password Policies

  Description: Set and enforce secure password policies for accounts.

  Justification: Strong authentication makes it harder to gain access needed to directly manipulate training data.  

- [M1041](https://attack.mitre.org/mitigations/M1041): Encrypt Sensitive Information

  Description: Protect sensitive information with strong encryption.

  Justification: Encrypting training data and models protects their integrity and validity.


### MITRE ATLAS™ Mitigations

- AML.M0005: Control Access to ML Models and Data at Rest
  Description: Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users.

- AML.M0007: Sanitize Training Data
  Description: Detect and remove or remediate poisoned training data. Training data should be sanitized prior to model training and recurrently for an active learning model. Implement a filter to limit ingested training data. Establish a content policy that would remove unwanted content such as certain explicit or offensive language from being used.

- AML.M0012: Encrypt Sensitive Information
  Description: Encrypt sensitive data such as ML models to protect against adversaries attempting to access sensitive data.

- AML.M0015: Adversarial Input Detection
  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

---


## Common Weakness Enumeration (CWE)

### Remove
- No items to remove. All listed CWEs are relevant to the risk of Training Data Poisoning in Large Language Models.

### Add

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html): OS Command Injection

  Description: The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.

  Justification: OS command injection can potentially allow an attacker to tamper with the data or the system where training data is stored, thereby facilitating poisoning.

### Update
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html): Deserialization of Untrusted Data

  Old Justification: Deserializing untrusted training data poses risks of executing adversary code in poisoned serialized models or datasets.

  New Justification: Deserializing untrusted training data not only poses risks of code execution but also allows the injection of malicious training examples directly into the training dataset, making it more susceptible to data poisoning.


## MITRE ATT&CK® Techniques

### Remove
- No items to remove. All listed techniques target the risk of Training Data Poisoning effectively.

### Add
- [T1190](https://attack.mitre.org/techniques/T1190): Exploit Public-Facing Application
  
  Description: Adversaries may attack public-facing applications in an attempt to manipulate, exfiltrate, or modify data, including the risk of tampering with training data.

  Justification: Vulnerable public-facing applications can be an entry point for attackers to manipulate training data.

### Update
- No updates needed. All justifications are strong and related to the risk.


## MITRE ATLAS™ Techniques

### Remove
- No items to remove. All listed ATLAS Techniques are relevant to the risk in discussion.

### Add
- AML.T0044: Model Parameter Tampering
  
  Description: Adversaries may tamper with the hyperparameters of the model, affecting how the model learns from the training data, thereby inducing flawed behavior.

  Justification: Tampering with model parameters directly targets the learning process and can introduce vulnerabilities.

### Update
- No updates needed. All justifications are strong and clearly highlight the risks involved.


## MITRE ATT&CK® Mitigations

### Remove
- [M1027](https://attack.mitre.org/mitigations/M1027): Password Policies
  
  Reason for removal: While password policies are essential for general security, they may not be specifically effective in preventing training data poisoning. Password policies are better suited for preventing unauthorized access but might not be adequate for mitigating risks associated with data integrity.

### Add
- [M1032](https://attack.mitre.org/mitigations/M1032): Data Backup
  
  Description: Regular backups of critical data can serve as a safeguard against data tampering, including training data poisoning.

  Justification: Frequent backups can serve as a mitigation strategy for rolling back to a clean state in case of training data poisoning.

### Update
- No updates needed. All other mitigations listed are adequate for the risk.


## MITRE ATLAS™ Mitigations

### Remove
- No items to remove. All listed ATLAS Mitigations are pertinent to the risk involved.

### Add
- AML.M0018: Continuous Data Integrity Checks
  
  Description: Continuously verify the integrity of training data by employing cryptographic hashing and integrity checking mechanisms.

  Justification: Ensures that the data hasn't been tampered with, offering a direct way to prevent poisoning attacks.

### Update
- No updates needed. All listed ATLAS Mitigations have strong justifications and are pertinent to the risk of training data poisoning.

  ---

  # Consolidated
  ---

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

#### Rejected CWE Review Comments
- No rejected review comments


### Techniques

#### MITRE ATT&CK® Techniques

- [T1565](https://attack.mitre.org/techniques/T1565/): Data Manipulation

  Description: Adversaries may manipulate and forge file contents and metadata to confuse and mislead forensic investigators or file analysis tools. File attributes like timestamps can be modified to mimic legitimate files. Adversaries may tamper with data at rest or in transit to manipulate external outcomes.
   
  Justification: Could directly poison training data by manipulating datasets before they are consumed.

- [T1190](https://attack.mitre.org/techniques/T1190): Exploit Public-Facing Application

  Description: Adversaries may attack public-facing applications in an attempt to manipulate, exfiltrate, or modify data, including the risk of tampering with training data.
   
  Justification: Vulnerable public-facing applications can be an entry point for attackers to manipulate training data.

#### MITRE ATLASTM Techniques

- AML.T0019: Publish Poisoned Datasets

  Description: Adversaries may publish poisoned datasets designed to manipulate and impair models that consume the data. Publishing provides a vector to introduce malicious data into victim training pipelines.
   
  Justification: Publishing poisoned data enables poisoning by making malicious datasets available to unsuspecting consumers.

- AML.T0020: Poison Training Data

  Description: Adversaries may directly poison training data to embed flaws activated later. Poisoned data introduced via supply chain attacks or after gaining access persistently compromises integrity of models trained on the data.
   
  Justification: Poisoning training data is a direct way to manipulate model capabilities by embedding vulnerabilities. 

- AML.T0035: ML Artifact Collection

  Description: Adversaries may collect artifacts like training data for exfiltration or use in attack staging. Access to training data provides the ability to directly manipulate and poison it.
   
  Justification: Access to training data enables poisoning by permitting direct data manipulation.
  
- AML.T0036: Data from Information Repositories

  Description: By mining repositories, adversaries can discover details of training data sources, enabling them to target sources directly for poisoning attacks.
   
  Justification: Discovering data repository details reveals training data sources to target.

- AML.T0043: Craft Adversarial Data

  Description: Adversaries may carefully craft malicious training data designed to manipulate model capabilities. The tailored data embeds specific flaws during training.
   
  Justification: Crafting poisoned data precisely manipulates models by embedding flaws.

- AML.T0044: Model Parameter Tampering

  Description: Adversaries may tamper with the hyperparameters of the model, affecting how the model learns from the training data, thereby inducing flawed behavior.
   
  Justification: Tampering with model parameters directly targets the learning process and can introduce vulnerabilities.

#### Rejected Technique Review Comments
- No rejected review comments

### Mitigations

#### MITRE ATT&CK® Mitigations

- [M1013](https://attack.mitre.org/mitigations/M1013): Application Developer Guidance

  Description: This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of.
   
  Justification: Guidance on secure coding practices helps prevent vulnerabilities that could enable data tampering.

- [M1041](https://attack.mitre.org/mitigations/M1041): Encrypt Sensitive Information

  Description: Protect sensitive information with strong encryption.
   
  Justification: Encrypting training data and models protects their integrity and validity.

- [M1032](https://attack.mitre.org/mitigations/M1032): Data Backup

  Description: Regular backups of critical data can serve as a safeguard against data tampering, including training data poisoning.
   
  Justification: Frequent backups can serve as a mitigation strategy for rolling back to a clean state in case of training data poisoning.

#### MITRE ATLASTM Mitigations

- AML.M0005: Control Access to ML Models and Data at Rest

  Description: Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users.
   
  Justification: Access controls prevent unauthorized access needed for poisoning.

- AML.M0007: Sanitize Training Data

  Description: Detect and remove or remediate poisoned training data. Training data should be sanitized prior to model training and recurrently for an active learning model. Implement a filter to limit ingested training data. Establish a content policy that would remove unwanted content such as certain explicit or offensive language from being used.
   
  Justification: Sanitizing training data directly counters poisoning by removing malicious inputs.

- AML.M0012: Encrypt Sensitive Information

  Description: Encrypt sensitive data such as ML models to protect against adversaries attempting to access sensitive data.
   
  Justification: Encryption protects integrity of data and models.  

- AML.M0015: Adversarial Input Detection

  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.
   
  Justification: Detecting anomalies counters poisoning by identifying malicious inputs.

- AML.M0018: Continuous Data Integrity Checks

  Description: Continuously verify the integrity of training data by employing cryptographic hashing and integrity checking mechanisms.
   
  Justification: Integrity checks directly validate data has not been manipulated.

#### Rejected Mitigation Review Comments
- No rejected review comments.


#### Additional mitigations created

1. Craft separate models for different use cases with tailored training data.

   - AML.M0021: Use Case Specific Model Training
    
      Description: Train distinct ML models for each intended use case using data closely tailored to that particular application. Segregate training data by use case.

      Justification: Training models on data specific to each use case limits exposure if parts of the data are poisoned.

2. Use robustness techniques like federated learning to minimize outlier impact.

   - AML.M0022: Employ Robust Training Techniques
    
      Description: Incorporate robust training techniques like federated learning and differential privacy to minimize the influence of poisoned outlier data.

     Justification: Robust techniques make model training more resilient to poisoned data points.

