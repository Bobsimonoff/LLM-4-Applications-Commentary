By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM10: Model Theft

### Summary
LLM theft can lead to financial losses, competitive disadvantage, and unauthorized data access.

### Description

Unauthorized access and theft of proprietary large language models can undermine competitive advantage and lead to data breaches. 

Attackers can exploit weak access controls, insufficient monitoring, vulnerable components, and insider threats to infiltrate systems and steal valuable LLMs. Successful attacks enable adversaries to acquire sensitive data, launch advanced prompt engineering attacks, and financially damage organizations.

Prevention requires strong access controls, network security, authentication, and monitoring. LLMs should have restricted network access and regular auditing of related logs and activities. Robust MLOps governance, input filtering, and output encoding can help prevent extraction attacks. Physical security and watermarking also help mitigate risks. Proactively securing LLMs against theft is crucial for maintaining confidentiality of intellectual property.


### Common Examples of Risk

1. Attacker exploits infrastructure vulnerabilities, gaining unauthorized access to LLM repositories due to misconfigurations.
2. Centralized ML Model Inventory enforces access controls, authentication, and monitoring for production ML models.
3. Insider threats involve employees leaking LLM-related artifacts.
4. Attacker queries the model API to create a shadow model through crafted inputs.
5. Malicious actors bypass input filtering, performing side-channel attacks to harvest model data.
6. Attackers fine-tune models by querying LLMs with numerous prompts.
7. **_Functional model replication_** creates functional equivalents using LLMs through prompts.

Stolen models can facilitate adversarial attacks, including unauthorized data access.

### Prevention and Mitigation Strategies

1. Implement strong access controls and authentication to restrict unauthorized LLM access.
2. Limit LLM's network access and monitor access logs.
3. Regularly audit access logs.
4. Automate MLOps deployment with governance.
5. Mitigate prompt injection risks.
6. Apply rate limiting or filters for data exfiltration prevention.
7. Deploy adversarial robustness training and enhance physical security.
8. Use watermarking in LLMs.

### Example Attack Scenarios

1. Attacker exploits infrastructure vulnerabilities to steal LLMs, using them to compete or extract sensitive data.
2. Disgruntled employees leak LLMs, increasing the risk of attacks.
3. Attacker crafts precise inputs to create shadow models.
4. Supply chain security failure leads to proprietary model leaks.
5. Malicious actors bypass input filtering, performing side-channel attacks to retrieve model data.


### MITRE ATLAS™ 

#### Techniques
- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006): Active Scanning - Active scanning enables adversaries to identify vulnerabilities in systems housing private language models, which can then be exploited to gain unauthorized access for stealing intellectual property or sensitive training data.

- [AML.T0012](https://atlas.mitre.org/techniques/AML.T0012): Valid Accounts - Compromised valid credentials allow adversaries to bypass access controls and gain unauthorized access to private language models and related systems, enabling theft of intellectual property and sensitive training data.  

- [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024): Exfiltration via ML Inference API - The inference API provides an avenue for adversaries to extract unauthorized functional copies of private language models, enabling intellectual property theft.

- [AML.T0035](https://atlas.mitre.org/techniques/AML.T0035): ML Artifact Collection - Collecting language model artifacts and related data, while preparatory, could provide assets enabling direct model theft. 

- [AML.T0037](https://atlas.mitre.org/techniques/AML.T0037): Data from Local System - Accessing local systems housing models, while requiring existing access, could enable theft of artifacts and data to steal intellectual property.

- [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040): ML Model Inference API Access - Inference API access provides a duplicative pathway like T0024 that could enable model theft through extraction.

#### Mitigations
- [AML.M0005](https://atlas.mitre.org/mitigations/AML.M0005): Control Access to ML Models and Data at Rest - Prevent theft by restricting access.

- [AML.M0012](https://atlas.mitre.org/mitigations/AML.M0012): Encrypt Sensitive Information - Protect models and data via encryption.


#### Possible Additions

**Possible New Techniques**

- Insider Model Leak - An insider with authorized access exfiltrates proprietary language models or related artifacts like training data, enabling theft of intellectual property. This could involve transferring files to unauthorized systems, cloud storage, or removable media.  

- Model Data Exfiltration - An adversary exploits vulnerabilities or misconfigurations to bypass protections and exfiltrate private model data through side channels. This could involve carefully crafted prompts to extract data or exploiting side channels like timing or cache access patterns.

Yes, that would be a distinct and valuable mitigation to add. Here is how I would incorporate it:

**Possible New Mitigations**

- Model Access Monitoring - Continuously monitor and log access to language models and related systems like training data repositories to detect potential unauthorized access or exfiltration attempts. Anomalies in access patterns can indicate malicious activity.

- Development Process Governance - Embed comprehensive security practices into the MLOps software development lifecycle including access control, anomaly detection, testing, monitoring, and incident response. This provides protections against theft throughout the model development process. 

- Prompt Filtering - Implement filtering of prompts and limit the complexity of allowed model queries to prevent extraction of private data like training samples. This mitigates the risk of model theft through prompting.

- Model Watermarking - Embed unique watermarks directly into language models to enable identification of theft and unauthorized distribution. Watermarks act as persistent forensic evidence if models are exfiltrated.

- User Behavior Analytics - Monitor user activities like queries, data access, and commands to detect anomalous actions that may indicate unauthorized access attempts to LLM repositories. This can help in early detection of insider threats or compromised credentials, thereby preventing potential model theft.


### STRIDE Analysis (generated by claude.ai)

**Spoofing**

- Adversaries can spoof or impersonate authorized users and system components to bypass authentication and access controls.

**Tampering**

- Stolen models may be tampered with through adversarial techniques like poisoning, parameter modification, or backdoors.

**Repudiation**

- Lack of access controls and monitoring around models enables denial of theft attribution. 

**Information Disclosure**

- Theft inherently discloses proprietary model IP and potentially sensitive training data.

**Denial of Service**

- Organizations lose exclusive availability and control over access to stolen proprietary models.

**Elevation of Privilege**

- Exploitation enables adversaries to gain privileged access to restricted models.


### Common Weakness Enumeration (CWE)

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Summary: Flawed authorization enables unauthorized access.

  Exploit: Weak authorization controls grant improper access to model storage, allowing attackers to access and steal proprietary LLM intellectual property.

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication

  Summary: Weak authentication allows unauthorized access.

  Exploit: Poor authentication mechanisms enable attackers to bypass identity checks and gain access to LLM artifacts to steal IP.

- [CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function

  Summary: Lack of authentication allows unauthorized access.

  Exploit: Absent authentication checks for LLM access endpoints provide an unguarded pathway for attackers to access and misuse stolen models.

- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm

  Summary: Weak cryptography enables unauthorized data access.

  Exploit: Flawed encryption allows attackers to intercept LLM artifacts in transit and exfiltrate stolen IP.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error

  Summary: Lack of source validation enables unauthorized access.

  Exploit: Failing to validate the source of access requests allows attackers to spoof identities and gain access to steal LLMs.

- [CWE-384](https://cwe.mitre.org/data/definitions/384.html): Session Fixation

  Summary: Session hijacking provides unauthorized access.

  Exploit: Attackers can fix sessions to impersonate valid users and gain access to steal proprietary LLM IP.

- [CWE-522](https://cwe.mitre.org/data/definitions/522.html): Insufficiently Protected Credentials

  Summary: Poorly protected credentials enable unauthorized access.

  Exploit: Weak protections over credentials allow attackers to easily compromise them and access LLM environments to steal IP.

- [CWE-639](https://cwe.mitre.org/data/definitions/639.html): Authorization Bypass Through User-Controlled Key

  Summary: User keys enable authorization bypass.

  Exploit: Compromised API keys or tokens allow attackers to bypass access controls and steal LLMs.

- [CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure

  Summary: Security control failures enable unauthorized access.

  Exploit: Compromised or absent protections pave the way for attackers to access and steal proprietary LLM IP.

- [CWE-732](https://cwe.mitre.org/data/definitions/732.html): Incorrect Permission Assignment for Critical Resource

  Summary: Overly permissive critical resource access.

  Exploit: Broad model access permissions increase ability for attackers to steal IP.


---

# IGNORE FOR NOW - NEED RE-REVIEW



### MITRE ATT&CK® Techniques

- [T1530](https://attack.mitre.org/techniques/T1530/): Data from Cloud Storage Object

  Description: T1530 involves accessing cloud storage containing data, including language models or artifacts, which could be used to access proprietary data or steal sensitive information.

  Justification: T1530 is relevant to the risk as it highlights the scenario where cloud storage containing language models or artifacts is accessed, potentially leading to the theft of proprietary language models and data.

- [T1552](https://attack.mitre.org/techniques/T1552/): Unsecured Credentials

  Description: Adversaries may search for unsecured credentials that are used in applications or scripts. These can be leveraged to gain unauthorized access to resources like LLM repositories.

  Justification: Given that one of the primary vectors of attack would be through exploiting weak access controls, having a technique focused on unsecured credentials would enhance the risk model.

### MITRE ATT&CK® Mitigations

- [M1027](https://attack.mitre.org/mitigations/M1027/): Password Policies

  Description: Set and enforce secure password policies for accounts.

  Justification: Strong password policies prevent compromised credentials that could enable unauthorized model access.

- [M1032](https://attack.mitre.org/mitigations/M1032/): Multi-factor Authentication

  Description: Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.

  Justification: Multi-factor authentication raises the bar for gaining authenticated access needed for model theft.

- [M1030](https://attack.mitre.org/mitigations/M1030/): Network Segmentation

  Description: Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information.

  Justification: Network segmentation can help isolate and protect critical model storage and access systems.  

- [M1041](https://attack.mitre.org/mitigations/M1041/): Encrypt Sensitive Information

  Description: Protect sensitive information with strong encryption.

  Justification: Encrypting model files and artifacts helps prevent exposure if improperly accessed.


  ### Additional Mitigations

- User Behavior Analytics

  Description: Monitor user activities to detect anomalous actions that may indicate unauthorized access attempts to LLM repositories.

  Justification: User behavior analytics can help in early detection of insider threats or compromised credentials, thereby preventing potential model theft.

- Regular Model Checksum Verification

  Description: Frequently verify the checksums of models in storage to ensure their integrity hasn't been compromised.

  Justification: Regular checksum verification detects unauthorized modifications to the model, preventing potential intellectual property corruption.

