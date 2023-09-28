By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM08: Excessive Agency

## Summary
Granting LLMs unchecked autonomy to take action can lead to unintended consequences, jeopardizing reliability, privacy, and trust.

## Description

Granting LLMs unchecked autonomy to take actions through excessive permissions, functionality, and lack of oversight can lead to harmful unintended consequences. 

Attackers can exploit ambiguous or malicious prompts, along with insecure plugins and components, to manipulate the LLM into taking unauthorized and potentially damaging actions. Successful attacks can result in data breaches, financial fraud, regulatory violations, reputational damage, and other impacts.

Prevention requires limiting LLM functionality, permissions, and autonomy to only what is essential. Strict input validation and robust access controls should be implemented in plugins. User context must be maintained and human approval required for impactful actions. Monitoring systems and rate limiting can help detect and limit unauthorized behaviors. Following security best practices around authorization, mediation, and privilege minimization is key to securing LLM agency.

## Common Weakness Enumeration (CWE)

[CWE-272](https://cwe.mitre.org/data/definitions/272.html): Least Privilege Violation - Applicable when excessive permissions are granted beyond functional needs.

[CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control - Applicable if plugins lack access controls, enabling unauthorized actions.

[CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Applicable when improper authorization leads to unauthorized actions. 

[CWE-347](https://cwe.mitre.org/data/definitions/347.html): Improper Verification of Cryptographic Signature - Applicable if failure to verify signatures poses authorization risks.

[CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data - Applicable if plugin output lacks encoding, leading to unintended actions.

[CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials - Applicable as hard-coded credentials with excessive permissions pose unauthorized action risks.

[CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency - Applicable as lack of frequency control poses risks of excessive unauthorized actions.  

[CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization - Applicable when authorization is not checked before actions.


## ATT&CK Techniques

- [T1548](https://attack.mitre.org/techniques/T1548/) - Abuse Elevation Control Mechanism. Exploits weak access controls. Could leverage excessive permissions. 

- [T1555](https://attack.mitre.org/techniques/T1555/) - Credentials from Password Stores. Steals stored credentials. Could access unchecked functions.

## ATT&CK Mitigations

- [M1032](https://attack.mitre.org/mitigations/M1032/) - Limit Access to Resource Over Network. Limits network resource access. Could prevent lateral movement from excessive permissions.

- [M1040](https://attack.mitre.org/mitigations/M1040/) - Network Segmentation. Segregates networks. Could limit connectivity of unchecked functions.


## MITRE ATLAS Techniques 

- AML.T0047: ML-Enabled Product or Service. Services granting excessive permissions introduce vulnerability. Provides unchecked capabilities.

- AML.T0040: ML Model Inference API Access. Carefully crafted queries could trigger unintended actions via the API. API access to downstream systems.

- AML.T0043: Craft Adversarial Data. Allows tailoring prompts to exploit excessive permissions. Optimizes malicious prompts. 

- AML.T0016: Obtain Capabilities. May obtain tools to identify or exploit excessive permissions. Aids targeting vulnerabilities.

- AML.T0010: ML Supply Chain Compromise. Compromised components could introduce excessive capabilities. Introduces vulnerabilities.

- AML.T0044: Full ML Model Access. Full control allows optimal exploitation of excessive permissions. Maximizes impact.

- AML.T0019: Publish Poisoned Data. Data could trigger unintended behaviors enabled by excessive permissions. Manipulates downstream actions.


## MITRE ATLAS Mitigations

- AML.M0015: Adversarial Input Detection. Detect and block malicious queries that could trigger unintended actions. Identifies and blocks malicious queries.

- AML.M0004: Restrict Number of ML Model Queries. Limit total queries and rate to downstream systems. Reduces attack surface.

- AML.M0014: Verify ML Artifacts. Detect tampered plugins or components enabling excessive actions. Identifies compromised artifacts.

- AML.M0005: Control Access to ML Models and Data at Rest. Limit plugin and component access to sensitive systems. Reduces capabilities.

- AML.M0003: Model Hardening. Make models robust to manipulation attempts that could enable unintended actions. Hardens model. 

- AML.M0016: Vulnerability Scanning. Scan plugins and components for flaws enabling unintended actions. Finds weaknesses.

- AML.M0018: User Training. Educate users on potential excessive agency risks. Reduces unknowing participation.

- AML.M0012: Encrypt Sensitive Information. Encrypt data to prevent unintended actions resulting in data exposure. Protects data confidentiality.

