By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM05: Supply Chain Vulnerabilities

## Summary 
Depending upon compromised components, services or datasets undermine system integrity, causing data breaches and system failures.


## Description

Supply chain vulnerabilities arise when compromised third-party components undermine system integrity. Attackers can exploit these to cause data breaches, biased outputs, and system failures.

Vulnerable components like unpatched libraries, contaminated datasets, and compromised model artifacts enable attackers to infiltrate systems. They may manipulate training data to insert biases, backdoors, or errors that degrade model integrity. Successful attacks can lead to IP theft, privacy violations, security breaches, and non-compliance with regulations.

Prevention involves extensive supplier vetting, integrity checks, and monitoring. Only use trusted suppliers and ensure alignment of security policies. Scrutinize third-party plugins before integration. Maintain updated inventories of components, and implement code signing for models. Audit supplier security regularly.


## Common Weakness Enumeration (CWE)

- [CWE-494](https://cwe.mitre.org/data/definitions/494.html): Download of Code Without Integrity Check - Applicable as unauthorized third-party code from a compromised supplier may be integrated without integrity checks, introducing vulnerabilities.

- [CWE-733](https://cwe.mitre.org/data/definitions/733.html): Compiler Optimization Removal or Modification of Security-critical Code - Applicable as optimizations during compilation of third-party code could remove security controls, increasing vulnerabilities.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as integration of third-party code introduces risks of untrusted functionality from compromised suppliers.

- [CWE-915](https://cwe.mitre.org/data/definitions/915.html): Improperly Controlled Modification of Dynamically-Determined Object Attributes - Applicable as lack of control over dynamic attributes in integrated third-party code poses risks if the supplier is compromised.

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) - Applicable as third-party requests to external services may not be properly validated after integration, enabling SSRF if the supplier is compromised.

- [CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A5 - Security Misconfiguration - Applicable as misconfigured third-party components integrated from a compromised supplier pose risks per OWASP guidelines.

- [CWE-916](https://cwe.mitre.org/data/definitions/916.html): Use of Password Hash With Insufficient Computational Effort - Applicable if third-party code from a compromised supplier uses weak hashing, enabling password cracking.

## ATT&CK Techniques

- [T1195](https://attack.mitre.org/techniques/T1195/) - Supply Chain Compromise. Manipulates products or services from third-party suppliers. Directly relevant to compromising the supply chain.

## MITRE ATLAS Techniques

- AML.T0010: ML Supply Chain Compromise. Compromising any supplier provides a vector to introduce vulnerabilities through legitimate third-party dependencies.  

- AML.T0019: Publish Poisoned Data. The adversary can insert carefully crafted poisoning examples into datasets obtained from third-party suppliers. When used to train models, these poisoned datasets manipulate the model's behavior to create hidden vulnerabilities or degrade performance.

- AML.T0020: Poison Training Data. A compromised data supplier could tamper with training data or labels before delivery to the organization. The data poisoning injects vulnerabilities into models trained on the data.

- AML.T0043: Craft Adversarial Data. Carefully crafted data or models from a compromised supplier could contain vulnerabilities designed to exploit systems.

- AML.T0016: Obtain Capabilities. The adversary can leverage a compromised supplier to gain access to tools, code, or information that aids in targeting other elements of the supply chain. This can lead to a chain compromise.

- AML.T0044: Full ML Model Access. Full control of third-party model artifacts enables thorough poisoning if the supplier is compromised.

- AML.T0012: Valid Accounts. Compromised supplier credentials could allow direct access to artifacts to poison them.

- AML.T0011: User Execution. Code delivered through third-party dependencies may contain hidden exploits or vulnerabilities that get executed unknowingly when users run or integrate the code into their systems.

- AML.T0047: ML-Enabled Product or Service. Services relying on compromised third-party components could be exploited.

- AML.T0040: ML Model Inference API Access. May enable attacks via access to APIs of compromised third-party models.


## ATT&CK Mitigations

- [M1048](https://attack.mitre.org/mitigations/M1048/) - Perform Software and File Integrity Checking. Checks integrity of third-party assets obtained through the supply chain. Could detect compromised or tampered components.

- [M1053](https://attack.mitre.org/mitigations/M1053/) - Disable or Restrict Resource Consumption Settings. Limits resource use by third-party components. Could prevent compromised artifacts from overloading systems.


## MITRE ATLAS Mitigations

- AML.M0014: Verify ML Artifacts. Detect tampered or compromised third-party artifacts by verifying checksums. Identifies issues introduced through the supply chain.

- AML.M0013: Code Signing. Ensure proper signing of third-party artifacts before integration. Validates authenticity from the source. 

- AML.M0015: Adversarial Input Detection. Detect attempts to exploit vulnerabilities in integrated third-party components. Identifies attacks enabled by compromised supply chain.

- AML.M0016: Vulnerability Scanning. Scan for flaws in integrated third-party components obtained through the supply chain. Finds weaknesses to address.

- AML.M0005: Control Access to ML Models and Data at Rest. Limit access to supply chain components to reduce the attack surface for compromises. 

- AML.M0018: User Training. Educate users on supply chain compromise risks to reduce unknowing participation in attacks involving compromised components.