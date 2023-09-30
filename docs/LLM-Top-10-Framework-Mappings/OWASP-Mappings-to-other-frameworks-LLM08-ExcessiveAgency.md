By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM08: Excessive Agency

### Summary
Granting LLMs unchecked autonomy to take action can lead to unintended consequences, jeopardizing reliability, privacy, and trust.

### Description

Granting LLMs unchecked autonomy to take actions through excessive permissions, functionality, and lack of oversight can lead to harmful unintended consequences. 

Attackers can exploit ambiguous or malicious prompts, along with insecure plugins and components, to manipulate the LLM into taking unauthorized and potentially damaging actions. Successful attacks can result in data breaches, financial fraud, regulatory violations, reputational damage, and other impacts.

Prevention requires limiting LLM functionality, permissions, and autonomy to only what is essential. Strict input validation and robust access controls should be implemented in plugins. User context must be maintained and human approval required for impactful actions. Monitoring systems and rate limiting can help detect and limit unauthorized behaviors. Following security best practices around authorization, mediation, and privilege minimization is key to securing LLM agency.

### Common Examples of Risk

1. Plugins have unnecessary functions beyond what's needed. 

2. Plugins fail to filter inputs properly.

3. Plugins get more access permissions than required.  

4. Plugins use high-privilege identities unnecessarily. 

5. Plugins take actions without approval.

### Prevention and Mitigation Strategies

1. Only allow necessary plugin functions.

2. Restrict plugin functions to the minimum needed. 

3. Avoid open-ended plugin functions when possible.

4. Give plugins least privilege access to other systems.

5. Check user authorization for all plugin actions. 

6. Require human approval for impactful actions.

7. Validate all plugin requests against security policies.

### Example Attack Scenarios

1. A mail plugin can send messages when it should only read mail. The LLM is tricked into sending spam.

2. A plugin has unnecessary database access. The LLM deletes records it shouldn't. 

3. A plugin uses an admin account unnecessarily. The LLM makes changes as admin without approval.

4. A social media plugin can post without approval. The LLM posts inappropriate content.


### Common Weakness Enumeration (CWE)

- [CWE-272](https://cwe.mitre.org/data/definitions/272.html): Least Privilege Violation

  Description: Granting excessive permissions beyond functional needs enables unauthorized actions.

  Justification: Highly relevant as plugins often get unnecessary privileges. 

- [CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control

  Description: Lacking controls between software components permits privilege escalation.

  Justification: Applicable as poor plugin access controls pose risks.

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Description: Missing or improper authorization enables unauthorized actions.

  Justification: Directly relevant as plugins may lack authorization checks.

- [CWE-347](https://cwe.mitre.org/data/definitions/347.html): Improper Verification of Cryptographic Signature

  Description: Failing to verify signatures on actions poses authorization risks.

  Justification: Relevant as lack of signature verification enables unauthorized actions.

- [CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data

  Description: Lack of output encoding may lead to unintended execution of actions.

  Justification: Applicable as poor encoding could result in unauthorized behaviors.

- [CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials

  Description: Hard-coded credentials with excessive privileges pose unauthorized action risks.

  Justification: Relevant as hard-coded credentials enable unintended behaviors.

- [CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency

  Description: Lack of frequency control poses risks of excessive unauthorized actions.

  Justification: Applicable as excessive actions could occur without frequency checks.

- [CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization

  Description: Not checking authorization before actions poses risks of unauthorized behavior.

  Justification: Highly applicable as plugins act without authorization.


### MITRE ATT&CK Techniques

- [T1548](https://attack.mitre.org/techniques/T1548/): Abuse Elevation Control Mechanism

  Description: Exploiting weak access controls to leverage excessive privileges.

  Justification: Relevant technique to exploit plugin privileges.

- [T1555](https://attack.mitre.org/techniques/T1555/): Credentials from Password Stores
  
  Description: Stealing stored credentials granting excessive privileges.
  
  Justification: Enables unauthorized actions through stolen credentials.


### MITRE ATLAS Techniques

- AML.T0047: ML-Enabled Product or Service. Services granting plugins or components excessive permissions introduce vulnerabilities enabling unintended actions.

- AML.T0040: ML Model Inference API Access. Carefully crafted queries could trigger unintended actions via the API by exploiting poor access controls.

- AML.T0043: Craft Adversarial Data. Allows tailoring prompts to exploit poor access controls and perform unintended actions.

- AML.T0016: Obtain Capabilities. May obtain tools to identify or exploit excessive permissions granted to plugins.

- AML.T0010: ML Supply Chain Compromise. Compromised components could be granted excessive capabilities leading to unintended actions.

- AML.T0044: Full ML Model Access. Full control allows optimal exploitation of poor access controls to manipulate downstream behaviors. 

- AML.T0019: Publish Poisoned Data. Data obtained from compromised sources could trigger unintended behaviors enabled by excessive permissions.


### MITRE ATT&CK Mitigations 

- [M1032](https://attack.mitre.org/mitigations/M1032/): Limit Access to Resource Over Network

  Description: Limit network access to downstream systems.

  Justification: Could prevent lateral movement from plugins.

- [M1040](https://attack.mitre.org/mitigations/M1040/): Network Segmentation

  Description: Segregate networks to limit connectivity.

  Justification: Limits impact of unchecked plugin actions.


### MITRE ATLAS Mitigations

- AML.M0015: Adversarial Input Detection. Detect and filter malicious queries that could trigger unintended actions before reaching vulnerable systems. Identifies and blocks potentially malicious queries.

- AML.M0004: Restrict Number of ML Model Queries. Limit total queries and rate to downstream systems which reduces attack surface for sending action-triggering inputs.

- AML.M0014: Verify ML Artifacts. Detect compromised or tampered plugins and components through integrity verification to identify artifacts enabling excessive actions.

- AML.M0005: Control Access to ML Models and Data at Rest. Limit plugin and component access through permissions to sensitive systems and data stores. Reduces capabilities that could enable unintended actions.

- AML.M0003: Model Hardening. Make models robust to manipulation attempts that could enable uncontrolled downstream actions. Hardens model against enabling unintended behaviors.

- AML.M0016: Vulnerability Scanning. Scan plugins and components for flaws that could lead to unintended actions. Finds weaknesses to address proactively.

- AML.M0018: User Training. Educate users on potential excessive agency risks so they avoid unknowingly triggering unintended behaviors. 

- AML.M0012: Encrypt Sensitive Information. Encrypt sensitive data to prevent unintended actions resulting in unauthorized data exposure. Protects data confidentiality.

 