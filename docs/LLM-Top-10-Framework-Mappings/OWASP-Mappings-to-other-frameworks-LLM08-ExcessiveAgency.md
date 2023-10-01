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

- AML.T0011: User Execution

  Description: Adversaries may manipulate users into executing unintended and potentially unsafe actions suggested by an LLM that has been granted excessive, unchecked autonomy. Users may unknowingly execute unsafe code or actions that take advantage of the LLM's broad permissions.

  Justification: User execution of unintended actions enabled by an LLM with excessive autonomy allows adversaries to more easily exploit the LLM's broad capabilities through manipulated user behavior.

- AML.T0043: Craft Adversarial Data

  Description: By crafting adversarial data inputs, an adversary can manipulate the behaviors of an LLM that has excessive autonomy, causing it to take unintended actions that take advantage of its broad permissions and capabilities.

  Justification: Carefully engineered data samples enable adversaries to control and exploit the excessive autonomy granted to the LLM to achieve unintended behaviors.

- AML.T0044: Full ML Model Access

  Description: Full white-box access to an LLM with excessive autonomy provides an adversary with maximum control over manipulating its behaviors by crafting inputs optimized to exploit its unchecked capabilities.

  Justification: Complete access maximizes an adversary's ability to control and exploit the unchecked autonomy granted to the LLM.

- AML.T0047: ML-Enabled Product or Service

  Description: By accessing a product that interacts with an LLM backend granted excessive autonomy, adversaries can manipulate the product to control the LLM's behaviors in unintended ways that exploit its broad permissions.
  
  Justification: ML-enabled products provide adversaries a pathway to exploit excessive LLM autonomy by manipulating the product's interactions with the LLM.


### MITRE ATT&CK Mitigations 

- [M1032](https://attack.mitre.org/mitigations/M1032/): Limit Access to Resource Over Network

  Description: Limit network access to downstream systems.

  Justification: Could prevent lateral movement from plugins.

- [M1040](https://attack.mitre.org/mitigations/M1040/): Network Segmentation

  Description: Segregate networks to limit connectivity.

  Justification: Limits impact of unchecked plugin actions.


### MITRE ATLAS Mitigations

- AML.M0011: Restrict Library Loading
  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for loading of malicious libraries.

- AML.M0015: Adversarial Input Detection
  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

- AML.M0017: Model Distribution Methods
  Description: Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model. 

- AML.M0018: User Training
  Description: Educate ML model developers on secure coding practices and ML vulnerabilities.
