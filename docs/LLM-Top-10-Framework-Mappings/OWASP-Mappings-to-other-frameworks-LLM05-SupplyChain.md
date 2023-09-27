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


## CWE

[CWE-494](https://cwe.mitre.org/data/definitions/494.html): Download of Code Without Integrity Check - Applicable as unauthorized third-party code may be downloaded without integrity checks.

[CWE-733](https://cwe.mitre.org/data/definitions/733.html): Compiler Optimization Removal or Modification of Security-critical Code - Applicable as optimizations could remove security controls in third-party code. 

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as third-party code introduces risks of untrusted functionality.

[CWE-915](https://cwe.mitre.org/data/definitions/915.html): Improperly Controlled Modification of Dynamically-Determined Object Attributes - Applicable as lack of control over dynamic attributes in third-party code poses risks.

[CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) - Applicable as third-party requests may not be properly validated, enabling SSRF.

[CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A5 - Security Misconfiguration - Applicable as misconfigured third-party components pose risks per OWASP guidelines. 

[CWE-916](https://cwe.mitre.org/data/definitions/916.html): Use of Password Hash With Insufficient Computational Effort - Applicable if third-party code uses weak hashing.


## MITRE ATT&CK Techniques

- AML.T0010: ML Supply Chain Compromise. Compromising any part of the supply chain provides a vector for attacks. Directly exploits supply chain.

- AML.T0019: Publish Poisoned Data. Adversaries could distribute poisoned datasets through compromised sources. Poisons data sources.

- AML.T0020: Poison Training Data. Allows poisoning of artifacts used in training models. Manipulates training data.

- AML.T0043: Craft Adversarial Data. Could allow carefully crafted data or models designed to exploit systems. Introduces vulnerabilities.

- AML.T0016: Obtain Capabilities. May obtain tools to compromise supply chain components. Aids targeting supply chain. 

- AML.T0044: Full ML Model Access. Full control of components enables thorough poisoning. Maximizes control over supply chain.

- AML.T0012: Valid Accounts. Compromised credentials could allow direct access to poison. Allows access to compromise.

- AML.T0011: User Execution. Users may unknowingly execute code from compromised sources. Executes malicious code.

- AML.T0047: ML-Enabled Product or Service. Services relying on compromised components could be exploited. Finds and exploits vulnerabilities.

- AML.T0040: ML Model Inference API Access. May enable attacks via compromised model APIs. API access to poisoned models.
