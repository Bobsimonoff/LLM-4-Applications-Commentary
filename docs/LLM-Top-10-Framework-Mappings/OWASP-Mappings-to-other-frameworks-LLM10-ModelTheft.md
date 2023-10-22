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


### Common Weakness Enumeration (CWE)

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Description: Flawed authorization controls may grant unauthorized access to resources, including language models, which can lead to unauthorized access and potential data theft.

  Justification: This CWE is directly related to the risk because it addresses the issue of improper authorization controls, which, if not adequately implemented, can result in unauthorized access to language models, posing a risk of data theft and unauthorized use.

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication

  Description: Weak authentication mechanisms can allow unauthorized users to bypass authentication and gain access to sensitive resources, such as language models.

  Justification: Weak authentication mechanisms are directly related to the risk because they can lead to unauthorized access to language models, potentially enabling data theft and misuse.

- [CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function

  Description: Lack of authentication checks for critical functions can result in unauthorized access to resources, in this case, language models.

  Justification: Missing authentication for critical functions is highly relevant to the risk as it directly addresses the scenario where authentication checks are lacking, leading to unauthorized access to language models and potential data theft.

- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm

  Description: Weak or broken cryptographic algorithms can expose data to interception, potentially leading to unauthorized access.

  Justification: This CWE is directly related to the risk because it highlights the importance of strong cryptographic measures to protect language model data from interception and unauthorized access during transmission.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error

  Description: Failing to validate the source of inputs to language model interfaces can allow unauthorized API access enabling data theft.

  Justification: Origin validation errors are not just related, but pivotal to the risk of unauthorized access to language models. Failure to validate input sources could not only enable unauthorized API access but also pave the way for more sophisticated attacks, such as data exfiltration or launching additional internal attacks, all leading to data theft.

- [CWE-384](https://cwe.mitre.org/data/definitions/384.html): Session Fixation

  Description: Session fixation attacks can allow an attacker to hijack a user's session and gain unauthorized access to sensitive resources, such as language models.

  Justification: Session fixation can directly result in unauthorized access to language models by exploiting weaknesses in session management. Given that this risk targets unauthorized access, this CWE should be added as it is a potential cause of such a risk.

- [CWE-522](https://cwe.mitre.org/data/definitions/522.html): Insufficiently Protected Credentials

  Description: Poorly protected credentials, such as API keys or passwords, can be easily compromised, providing unauthorized access to language models.

  Justification: Insufficiently protected credentials can directly lead to unauthorized access to language models, which is central to the risk at hand. Strengthening credential protection is a necessary step in mitigating this risk.

- [CWE-639](https://cwe.mitre.org/data/definitions/639.html): Authorization Bypass Through User-Controlled Key

  Description: Authorization bypass through user-controlled keys can lead to unauthorized access to resources and data theft.

  Justification: This CWE is directly related to the risk as it addresses the specific scenario where user-controlled API keys can be exploited to bypass authorization and gain unauthorized access to language models, potentially resulting in data theft.

- [CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data

  Description: Inadequate output encoding can expose sensitive data, including training data, to potential theft.

  Justification: Inadequate encoding of output data is directly related to the risk as it highlights the importance of proper encoding to prevent the exposure of sensitive training data, which could be targeted for theft.  

- [CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials

  Description: The use of hard-coded credentials poses an acute risk to language model security. It's not just related, but a critical vulnerability that could serve as a single point of failure, giving unauthorized users an easy pathway for access and theft of sensitive language models.

  Justification: The use of hard-coded credentials is directly related to the risk as it points out the risk associated with such credentials, which can result in unauthorized access to language models and potential data theft.

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF)

  Description: SSRF vulnerabilities could enable unauthorized access to internal language model storage servers to steal data.

  Justification: SSRF vulnerabilities are directly related to the risk as they highlight the potential for unauthorized access to internal language model storage servers, which could result in data theft.  

- [CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure

  Description: Failure of built-in security measures can provide an avenue for unauthorized access to language models, undermining other security controls in place.

  Justification: When protection mechanisms fail, this could directly lead to unauthorized access and potential theft of language models, thus strongly associated with this risk.



### Techniques

### MITRE ATT&CK® Techniques

- [T1530](https://attack.mitre.org/techniques/T1530/): Data from Cloud Storage Object

  Description: T1530 involves accessing cloud storage containing data, including language models or artifacts, which could be used to access proprietary data or steal sensitive information.

  Justification: T1530 is relevant to the risk as it highlights the scenario where cloud storage containing language models or artifacts is accessed, potentially leading to the theft of proprietary language models and data.

- [T1552](https://attack.mitre.org/techniques/T1552/): Unsecured Credentials

  Description: Adversaries may search for unsecured credentials that are used in applications or scripts. These can be leveraged to gain unauthorized access to resources like LLM repositories.

  Justification: Given that one of the primary vectors of attack would be through exploiting weak access controls, having a technique focused on unsecured credentials would enhance the risk model.

### MITRE ATLAS™ Techniques

- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006): Active Scanning - Active scanning enables adversaries to identify vulnerabilities in systems housing private language models, which can then be exploited to gain unauthorized access for stealing intellectual property or sensitive training data.

- [AML.T0012](https://atlas.mitre.org/techniques/AML.T0012): Valid Accounts - Compromised valid credentials allow adversaries to bypass access controls and gain unauthorized access to private language models and related systems, enabling theft of intellectual property and sensitive training data.  

- [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024): Exfiltration via ML Inference API - The inference API provides an avenue for adversaries to extract unauthorized functional copies of private language models, enabling intellectual property theft.

- [AML.T0035](https://atlas.mitre.org/techniques/AML.T0035): ML Artifact Collection - Collecting language model artifacts and related data, while preparatory, could provide assets enabling direct model theft. 

- [AML.T0037](https://atlas.mitre.org/techniques/AML.T0037): Data from Local System - Accessing local systems housing models, while requiring existing access, could enable theft of artifacts and data to steal intellectual property.

- [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040): ML Model Inference API Access - Inference API access provides a duplicative pathway like T0024 that could enable model theft through extraction.



### Additional Techniques
- Model Tampering

  Description: Adversaries may alter the internal parameters or structures of a deployed model to produce malicious outcomes.

  Justification: While not directly resulting in model "theft," tampering with a model could result in intellectual property corruption and the generation of malicious outcomes that mirror those of stolen models.


### Mitigations

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


### MITRE ATLAS™ Mitigations

- [AML.M0005](https://atlas.mitre.org/mitigations/AML.M0005): Control Access to ML Models and Data at Rest - Prevent theft by restricting access.

- [AML.M0012](https://atlas.mitre.org/mitigations/AML.M0012): Encrypt Sensitive Information - Protect models and data via encryption.


  ### Additional Mitigations

- User Behavior Analytics

  Description: Monitor user activities to detect anomalous actions that may indicate unauthorized access attempts to LLM repositories.

  Justification: User behavior analytics can help in early detection of insider threats or compromised credentials, thereby preventing potential model theft.

- Regular Model Checksum Verification

  Description: Frequently verify the checksums of models in storage to ensure their integrity hasn't been compromised.

  Justification: Regular checksum verification detects unauthorized modifications to the model, preventing potential intellectual property corruption.


### STRIDE Analysis (generated by clause.ai)

Model theft can impact multiple components of the STRIDE threat model:

**Spoofing**

- Attackers can spoof identities to bypass authentication controls and gain unauthorized access to proprietary models.
- Spoofed access credentials enable adversaries to impersonate authorized users.

**Tampering**

- Adversaries may tamper with proprietary models by altering parameters or structures.
- Tampering can corrupt intellectual property or produce malicious outcomes.

**Repudiation** 

- Lack of monitoring around model access can complicate attribution of theft.
- Disabling logging mechanisms can prevent forensic analysis.

**Information Disclosure**

- Theft of proprietary models discloses intellectual property to unauthorized parties.
- Model training data may also be exposed during attacks.

**Denial of Service**

- Model theft deprives the rightful owners of availability and competitive advantage.
- Owners lose exclusive control over access and usage of stolen models.

**Elevation of Privilege**

- Compromised credentials grant adversaries elevated privileges to access restricted proprietary models.
- Exploiting vulnerabilities elevates adversary access from unauthorized to authorized.