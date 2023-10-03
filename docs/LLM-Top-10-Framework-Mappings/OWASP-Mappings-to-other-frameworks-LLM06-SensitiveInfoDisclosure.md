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

- [CWE-200](https://cwe.mitre.org/data/definitions/200.html): Information Exposure

  Description: The exposure of sensitive information to an actor that is not explicitly authorized to have access to that information.

  Justification: While CWE-202 covers unauthorized actors, CWE-200 broadens the scope to include unintentional exposures, which are a significant risk in LLMs.

- [CWE-202](https://cwe.mitre.org/data/definitions/202.html): Exposure of Sensitive Information to an Unauthorized Actor

  Description: The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

  Justification: Lacking stringent access controls and multi-factor authentication can result in the unauthorized disclosure of sensitive data via LLM outputs.
  
- [CWE-208](https://cwe.mitre.org/data/definitions/208.html): Observable Discrepancy

  Description: Behavioral differences between the product's expected behavior and its actual behavior allow detection of the product's sensitive information.

  Justification: Model outputs could reveal sensitive training data through observable discrepancies.
  
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Information Exposure Through an Error Message

  Description: The product generates error messages that expose sensitive information about the environment, users, or associated data.

  Justification: Model error messages could reveal sensitive configuration, training data or internal details.

- [CWE-215](https://cwe.mitre.org/data/definitions/215.html): Information Exposure Through Debug Information

  Description: Debugging output can contain sensitive information like credentials or cryptographic keys.

  Justification: Model debug logs could expose private training data metadata and inferences.
  
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm

  Description: The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.
  
  Justification: Weak encryption can be a significant vulnerability in LLMs where sensitive data and model parameters are stored.

- [CWE-538](https://cwe.mitre.org/data/definitions/538.html): File and Directory Information Exposure

  Description: The product reveals sensitive filesystem information that aids attackers in adversary techniques.

  Justification: Filesystem permissions could enable unauthorized access to sensitive model artifacts.

- [CWE-541](https://cwe.mitre.org/data/definitions/541.html): Information Exposure Through Include Source Code

  Description: Source code exposes sensitive details like credentials, SQL, or cryptographic material.

  Justification: Model source code could expose sensitive configuration details or training data.

- [CWE-649](https://cwe.mitre.org/data/definitions/649.html): Reliance on Obfuscation or Protection Mechanism

  Description: Relying solely on obfuscation or data protection mechanisms provides ineffective protection.

  Justification: While obfuscation techniques may deter casual adversaries, they're insufficient for ensuring data protection in LLMs. Proper encryption, access controls, and other security layers are essential to ensure data is secure.

- [CWE-922](https://cwe.mitre.org/data/definitions/922.html): Insecure Storage of Sensitive Information

  Description: Sensitive information stored without encryption or with a weak algorithm can enable adversaries to easily gain access.

  Justification: Unencrypted model artifacts could expose training data or parameters.


### Techniques

#### MITRE ATT&CK® Techniques

- [T1078](https://attack.mitre.org/techniques/T1078/): Valid Accounts

  Description: Adversaries may steal or guess valid credentials to gain authorized access.

  Justification: Valid credentials can be used to bypass security controls, potentially leading to sensitive information disclosure via LLM.

- [T1530](https://attack.mitre.org/techniques/T1530/): Data from Cloud Storage Object

  Description: Adversaries may get access to sensitive data from cloud storage including credentials and keys.

  Justification: Unauthorized access to cloud storage can directly expose both training data and model parameters, leading to substantial risks of information disclosure.

- [T1552](https://attack.mitre.org/techniques/T1552/): Unsecured Credentials

  Description: Adversaries may steal and abuse valid account credentials and keys to access cloud services, like AWS.

  Justification: Compromised credentials could enable unauthorized access to sensitive information.

#### MITRE ATLAS™ Techniques

- [T0024](https://attack.mitre.org/techniques/T0024/): Exfiltration via ML Inference API

  Description: Adversaries leverage inference API access to reconstruct and exfiltrate sensitive information used in training models, through techniques like membership inference and model inversion that exploit vulnerabilities in how models learn relationships between data.

  Justification: The inference API provides adversaries a pathway to extract sensitive training data from models.

- [T0035](https://attack.mitre.org/techniques/T0035/): ML Artifact Collection

  Description: By gathering proprietary model artifacts and related data, adversaries obtain assets containing sensitive information that can be exfiltrated and exposed. Collecting artifacts provides direct access to confidential data.

  Justification: Acquisition of proprietary model artifacts poses a severe risk as it grants adversaries deep insights into the model, including sensitive information that the model may have learned.

- [T0036](https://attack.mitre.org/techniques/T0036/): Data from Information Repositories

  Description: Adversaries mine internal data repositories containing details like proprietary training data metadata, data source configurations, model training parameters, and inferences to gather sensitive information for exposure and theft.

  Justification: Mining data repositories reveals sensitive model information adversaries can exfiltrate.

- [T0037](https://attack.mitre.org/techniques/T0037/): Data from Local System

  Description: Adversaries search local data stores like file systems, databases, and storage for model training data, parameters, inferences, and other sensitive artifacts containing proprietary information to improperly access and exfiltrate.

  Justification: Accessing local systems provides adversaries access to directly gather confidential model information.

- [T0040](https://attack.mitre.org/techniques/T0040/): ML Model Inference API Access

  Description: Adversaries exploit the inference API to extract sensitive training data indirectly through model outputs. The API enables data reconstruction through model vulnerabilities.

  Justification: Inference API access provides adversaries a pathway to extract sensitive information from models.

- [T0043](https://attack.mitre.org/techniques/T0043/): Craft Adversarial Data

  Description: Through carefully engineered prompts and queries, adversaries can manipulate model behavior to expose sensitive information learned during training that can be extracted and exfiltrated.

  Justification: Crafting adversarial model inputs can elicit exposure of private training data.  

- [T0044](https://attack.mitre.org/techniques/T0044/): Full ML Model Access

  Description: Full white-box access to models allows adversaries to optimally craft queries to reliably extract maximum sensitive information by precisely analyzing model mechanics and data relationships.

  Justification: Complete model access maximizes adversaries' ability to expose sensitive training data through tailored prompts.

- [T0045](https://attack.mitre.org/techniques/T0045/): ML Intellectual Property Theft

  Description: Adversaries may exfiltrate ML artifacts to steal intellectual property and cause economic harm to the victim organization.

  Justification: If the trained model has sensitive data contained within the exfiltration will make that data available to attackers. 


### Mitigations

#### MITRE ATT&CK® Mitigations

- [M1027](https://attack.mitre.org/mitigations/M1027/): Password Policies

  Description: Set and enforce secure password policies for accounts.

  Justification: Strong password policies prevent compromised credentials that could enable unauthorized data access.

- [M1041](https://attack.mitre.org/mitigations/M1041/): Encrypt Sensitive Information

  Description: Protect sensitive information with strong encryption.

  Justification: Encrypting sensitive training data and artifacts prevents exposure if improperly accessed.

- [M1042](https://attack.mitre.org/mitigations/M1042/): Disable or Remove Feature or Program

  Description: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

  Justification: Minimizing the attack surface by disabling or removing unnecessary features can substantially lower the risks of sensitive information disclosure.

#### MITRE ATLAS™ Mitigations

- [M0002](https://attack.mitre.org/mitigations/M0002/): Passive ML Output Obfuscation

  Description: Decreasing the fidelity of model outputs provided to the end user can reduce an adversaries ability to extract information about the model and optimize attacks for the model.

  Justification: Limiting the detail in model outputs hampers adversaries' ability to reverse-engineer the model for sensitive data exposure.

- [M0004](https://attack.mitre.org/mitigations/M0004/): Restrict Number of ML Model Queries

  Description: Limit the total number and rate of queries a user can perform.

  Justification: Restricting queries limits the data adversaries can gather to reconstruct training data.

- [M0005](https://attack.mitre.org/mitigations/M0005/): Control Access to ML Models and Data at Rest

  Description: Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users.

  Justification: Access controls prevent unauthorized access that could lead to data exposure.  


- [M0012](https://attack.mitre.org/mitigations/M0012/): Encrypt Sensitive Information

  Description: Encrypt sensitive data such as ML models to protect against adversaries attempting to access sensitive data.

  Justification: Encryption protects training data and model parameters from exposure if improperly accessed.

- [M0015](https://attack.mitre.org/mitigations/M0015/): Adversarial Input Detection

  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

  Justification: Detecting and blocking adversarial inputs prevents crafted data exposure attempts.

- [M0017](https://attack.mitre.org/mitigations/M0017/): Model Distribution Methods

  Description: Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model.

  Justification: Limiting model access reduces potential attack vectors for data exposure.  

#### Additional Mitigations
- Differential Privacy

  Description: Introduce statistical noise into model outputs to anonymize individual data entries.

  Justification: Differential privacy techniques minimize the risk of individual data points being identified, protecting against exposure.



### STRIDE Analysis (generated by clause.ai)

Sensitive information disclosure vulnerabilities can enable various types of threats within the STRIDE model:

**Spoofing**

- Attackers can spoof user identities with stolen credentials to access sensitive data.
- Forged input data could trick models into revealing confidential information. 

**Tampering**

- Adversaries can tamper with inputs to manipulate model behavior for sensitive data exposure.
- Training data poisoning modifies model behavior to inadvertently leak sensitive information.

**Repudiation** 

- Lack of logging around access and data flows complicates attack attribution.
- Disablement of monitoring systems also undermines attack attribution.

**Information Disclosure**

- Improper data handling exposes sensitive information through models. 
- Unauthorized data access grants visibility into confidential artifacts and training data.

**Denial of Service**

- Unexpected crashes from adversarial inputs disrupt model availability.
- Resource exhaustion attacks on backend systems create denial of service effects.

**Elevation of Privilege**

- Compromised credentials enable escalated data access privileges.
- Exploiting vulnerabilities in access controls allows unauthorized data access.
- Circumventing authentication opens access to restricted data.

In summary, sensitive information disclosure provides pathways for a broad range of threats against confidentiality and availability. Mitigating this risk requires protecting the full spectrum of STRIDE threat categories.