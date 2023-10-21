By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM05: Supply Chain Vulnerabilities

### Summary 
Depending upon compromised third-party components, services or datasets undermine system integrity, causing data breaches and system failures.


### Description

Supply chain vulnerabilities arise when compromised third-party components undermine system integrity. Attackers can exploit these to cause data breaches, biased outputs, and system failures.

Vulnerable components like unpatched libraries, contaminated datasets, and compromised model artifacts enable attackers to infiltrate systems. They may manipulate training data to insert biases, backdoors, or errors that degrade model integrity. Successful attacks can lead to IP theft, privacy violations, security breaches, and non-compliance with regulations.

Prevention involves extensive supplier vetting, integrity checks, and monitoring. Only use trusted suppliers and ensure alignment of security policies. Scrutinize third-party plugins before integration. Maintain updated inventories of components, and implement code signing for models. Audit supplier security regularly.

### Common Examples of Risk

1. Outdated or insecure third-party libraries and components.

2. Use of vulnerable pre-trained models.

3. Training with poisoned crowd-sourced data. 

4. Using unmaintained deprecated models.

5. Unclear supplier terms enabling data misuse.

### Prevention and Mitigation Strategies

1. Vet suppliers and ensure security policies align.

2. Scrutinize and test third-party plugins before use.

3. Apply mitigations from OWASP Top Ten vulnerable components guidance. 

4. Maintain updated component inventories with SBOMs.

5. Use model signing and reputable model repositories. 

6. Scan models and data for poisoning.

7. Monitor for unauthorized components and vulnerabilities.

8. Patch vulnerable components.

9. Regularly audit supplier security and access.

### Example Attack Scenarios 

1. Vulnerable library exploits system used in model development.

2. Attacker provides plugin generating scam links.

3. Compromised PyPi package exfiltrates data from model environment.

4. Attacker poisons economic analysis model on public hub to generate misinformation.

5. Attacker poisons public datasets to introduce market bias when models fine-tune.

6. Compromised supplier employee steals confidential data.

7. Supplier changes terms enabling sensitive data exposure.



### Common Weakness Enumeration (CWE)

- [CWE-200](https://cwe.mitre.org/data/definitions/200.html): Information Exposure

  Description: Software does not adequately prevent the read or write of data, which leads to an unintended direct or indirect disclosure of sensitive information.

  Justification: When third-party components in the supply chain are compromised, there's a risk of exposing sensitive data unintentionally.

- [CWE-494](https://cwe.mitre.org/data/definitions/494.html): Download of Code Without Integrity Check

  Description: Software downloads code from an untrusted source without verifying its integrity, authenticity, or origin before execution.

  Justification: Lack of integrity checks during the downloading of code significantly heightens the risk of including compromised or malicious third-party components in the supply chain, thus breaching system integrity.

- [CWE-664](https://cwe.mitre.org/data/definitions/664.html): Improper Control of a Resource Through its Lifetime

  Description: The software does not properly manage the resource's scope, duration, or timing, which can lead to unintended behaviors.

  Justification: In a compromised supply chain, not properly controlling resource lifetimes can introduce multiple vulnerabilities, including unauthorized data access and resource leaks.  

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: The software imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

  Justification: Integration of third-party code introduces risks of untrusted functionality if the supplier is compromised.

- [CWE-915](https://cwe.mitre.org/data/definitions/915.html): Improperly Controlled Modification of Dynamically-Determined Object Attributes

  Description: Modifications of object attributes without appropriate constraints can often lead to exploitable vulnerabilities.

  Justification: Lack of control over third-party code attributes poses risks if the supplier is compromised.  

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF)

  Description: An SSRF attack occurs when a web server is tricked into making arbitrary requests on behalf of the attacker and can be used to interact with internal systems.

  Justification: Third-party requests may not be validated after integration, enabling SSRF through compromised suppliers.

- [CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities

  Description: The software is out-of-date, lacking patches, or makes use of third-party components with publicly known vulnerabilities.

  Justification: Misconfigured third-party components integrated from a compromised supplier pose risks per OWASP.


### Techniques

### MITRE ATT&CK® Techniques

- [T1195](https://attack.mitre.org/techniques/T1195/): Supply Chain Compromise

  Description: Manipulates products or services from third-party suppliers.

  Justification: Directly relevant to compromising the supply chain.

- [T1588](https://attack.mitre.org/techniques/T1588/): Obtain Capabilities

  Description: Adversaries may search for and obtain software capabilities like adversarial ML tools to exploit vulnerable supply chain components. Obtaining capabilities aids adversaries in developing attacks targeting weaknesses in integrated third-party code, models, and data.

  Justification: Obtaining attack tools can enable adversaries to exploit vulnerable supply chain components.


### MITRE ATLAS™ Techniques

- [AML.T0016](https://atlas.mitre.org/techniques/AML.T0016/): Obtain Capabilities

  Description: Adversaries may search for and obtain software capabilities like adversarial ML tools to exploit vulnerable supply chain components. Obtaining capabilities aids adversaries in developing attacks targeting weaknesses in integrated third-party code, models, and data.

  Justification: Obtaining attack tools can enable adversaries to exploit vulnerable supply chain components.

- [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024/): Exfiltration via ML Inference API

  Description: Adversaries may extract data, models, and other artifacts containing proprietary information or intellectual property via inference APIs of compromised third-party components. This technique exploits vulnerable access controls in integrated suppliers.

  Justification: Inference API access to compromised third-party components enables data and IP exfiltration.

- [AML.T0031](https://atlas.mitre.org/techniques/AML.T0031/): Erode ML Model Integrity

  Description: Adversaries can degrade model performance over time by exploiting vulnerabilities in integrated components to craft malicious inputs. Continually supplying adversarial data via compromised suppliers erodes integrity and causes system failures.

  Justification: Introducing adversarial data through compromised third parties erodes model integrity.  



### Mitigations

### MITRE ATT&CK® Mitigations

N/A

### MITRE ATLAS™ Mitigations

- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002/): Passive ML Output Obfuscation

  Description: Decreasing the fidelity of model outputs provided to the end user can reduce an adversaries ability to extract information about the model and optimize attacks for the model.

  Justification: Obfuscating outputs can prevent adversaries from gaining insights to exploit compromised components.

- [AML.M0003](https://atlas.mitre.org/mitigations/AML.M0003/): Model Hardening
  
  Description: Use techniques to make machine learning models robust to adversarial inputs such as adversarial training or network distillation.

  Justification: Hardened models are more resilient to exploits of compromised supply chain components.  

- [AML.M0012](https://atlas.mitre.org/mitigations/AML.M0012/): Encrypt Sensitive Information

  Description: Encrypt sensitive data such as ML models to protect against adversaries attempting to access sensitive data.

  Justification: Encryption prevents exposure of data through compromised supply chain.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection

  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

  Justification: Detecting adversarial inputs from compromised components mitigates risks.
  
### Additional Mitigations

- Component Validation

  Description: Validate third-party components, libraries, and modules for vulnerabilities before integrating them into the environment.

  Justification: Validation reduces risks from compromised third-party supply chain elements.



### STRIDE Analysis (generated by clause.ai)

Supply chain vulnerabilities can impact multiple components of the STRIDE threat model:

**Spoofing**

- Attackers can spoof compromised suppliers to hide their origin and insert vulnerabilities.
- Vulnerable third-party components enable spoofing other systems after infiltration.

**Tampering** 

- Compromised dependencies allow tampering with system integrity via malicious code insertion.
- Attackers can tamper with data at rest via compromised supply chain components. 

**Repudiation**

- Lack of integrity checks on third-party code undermines attack attribution.
- Compromised suppliers confound audit trails masking the source of attacks.

**Information Disclosure**

- Third-party components with data access enable unauthorized exposure of sensitive assets.
- Compromised suppliers can exfiltrate confidential data and intellectual property.

**Denial of Service**

- Vulnerable dependencies open avenues for crashing critical systems.
- Manipulation of third-party data and models can degrade system functionality.

**Elevation of Privilege** 

- Exploits in third-party code can be used to escalate privileges in downstream systems.
- Access permissions granted to suppliers for integration enable privilege escalation.