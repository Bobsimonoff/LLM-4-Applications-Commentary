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

This item focuses on the fact that LLMs may be able to take action on their own, but do not have perfect training, can make mistakes, and do hallucinate. 

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


### MITRE ATT&CK® Techniques

- [T1548](https://attack.mitre.org/techniques/T1548/): Abuse Elevation Control Mechanism

  Description: Exploiting weak access controls to leverage excessive privileges.

  Justification: Relevant technique to exploit plugin privileges.


### MITRE ATLAS™ Techniques

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


### MITRE ATT&CK® Mitigations 

- [M1027](https://attack.mitre.org/mitigations/M1027): Password Policies

  Description: Set and enforce secure password policies for accounts.

  Justification: Strong authentication makes unauthorized access more difficult.

- [M1042](https://attack.mitre.org/mitigations/M1042): Disable or Remove Feature or Program

  Description: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

  Justification: Reducing available services limits potential vectors to manipulate behaviors.

- [M1030](https://attack.mitre.org/mitigations/M1030): Network Segmentation

  Description: Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information.

  Justification: Network segmentation can isolate critical systems from manipulation.

- [M1032](https://attack.mitre.org/mitigations/M1032): Multi-factor Authentication

  Description: Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.

  Justification: Raises the bar for gaining access needed to manipulate behaviors.



### MITRE ATLAS™ Mitigations

- AML.M0011: Restrict Library Loading
  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for loading of malicious libraries.

- AML.M0015: Adversarial Input Detection
  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

- AML.M0017: Model Distribution Methods
  Description: Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model. 

- AML.M0018: User Training
  Description: Educate ML model developers on secure coding practices and ML vulnerabilities.


---

# REVIEW COMMENTS

## Common Weakness Enumeration (CWE)

### Remove
- **CWE-732**: Inadequate Encoding of Output Data

  **Reason for removal**: The focus of this risk item is on excessive permissions and agency given to LLMs, and not directly related to output encoding issues. Therefore, CWE-732 may not be strongly associated with the risk of 'Excessive Agency.'

- **CWE-799**: Improper Control of Interaction Frequency

  **Reason for removal**: This CWE talks about frequency control, which is not directly associated with the agency and permissions granted to LLMs. It's more about throttling or rate-limiting actions, not the agency to make those actions.

### Add
- **[CWE-269](https://cwe.mitre.org/data/definitions/269.html)**: Improper Privilege Management

  **Description**: Improper management of privileges can allow unauthorized access and activity.

  **Justification**: In an environment where LLMs have excessive agency, improper privilege management can exacerbate risks significantly, enabling unauthorized actions.

### Update
- **[CWE-272](https://cwe.mitre.org/data/definitions/272.html)**: Least Privilege Violation

  **Old Justification**: Highly relevant as plugins often get unnecessary privileges.
  
  **New Justification**: Core to the issue of excessive agency is the violation of the principle of least privilege. By providing more permissions than necessary, LLMs are given a wider range of potential actions, thereby increasing the risk of unauthorized or unintended actions.


## MITRE ATT&CK® Techniques

### Remove
- No items to remove

### Add
- **[T1078](https://attack.mitre.org/techniques/T1078/)**: Valid Accounts

  **Description**: Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

  **Justification**: In environments where LLMs have excessive permissions, the risk of adversaries using valid accounts to abuse these permissions increases.

### Update
- No items to update

## MITRE ATLAS™ Techniques

### Remove
- **AML.T0047**: ML-Enabled Product or Service

  **Reason for removal**: While ML-Enabled products can be vulnerable, this technique is too broad to be directly associated with the risk of excessive agency in LLMs.

### Add
- **AML.T0012**: Role-Based Access Control

  **Description**: Implementing role-based access controls in LLM systems can prevent unauthorized actions.

  **Justification**: Role-Based Access Control directly targets the issue of excessive agency by ensuring that only authorized roles have access to certain functionalities.

### Update
- No items to update

## MITRE ATT&CK® Mitigations

### Remove
- No items to remove

### Add
- **[M1050](https://attack.mitre.org/mitigations/M1050)**: Audit

  **Description**: Audit the activities and permissions of LLMs to ensure they are acting within the designated limits.

  **Justification**: Continuous auditing can immediately flag and potentially halt any unauthorized or unexpected behavior, which is crucial in preventing risks arising from excessive agency.

### Update
- No items to update

## MITRE ATLAS™ Mitigations

### Remove
- No items to remove

### Add
- **AML.M0019**: Limit Model Functionality

  **Description**: Limit the operations that the machine learning model can perform to only what is essential for its intended purpose.

  **Justification**: By restricting the functionalities to only what is essential, the risks associated with excessive agency are directly mitigated.

### Update
- No items to update

  
---
# Consolidated
---

### Common Weakness Enumeration (CWE)

- [CWE-272](https://cwe.mitre.org/data/definitions/272.html): Least Privilege Violation

  Description: The software performs an operation at a privilege level higher than the minimum level required, which can cause unintended information disclosures or access control bypasses.

  Justification: Core to the issue of excessive agency is the violation of the principle of least privilege. By providing more permissions than necessary, LLMs are given a wider range of potential actions, thereby increasing the risk of unauthorized or unintended actions.

- [CWE-269](https://cwe.mitre.org/data/definitions/269.html): Improper Privilege Management

  Description: The software does not properly manage privileges to restrict access to only authorized users or processes. This may allow an actor to access or perform unauthorized functions.

  Justification: In an environment where LLMs have excessive agency, improper privilege management can exacerbate risks significantly, enabling unauthorized actions.

- [CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control

  Description: The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

  Justification: Applicable as poor access controls in components interacting with the LLM pose risks of unauthorized actions.

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Description: The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.

  Justification: Directly relevant as components interacting with the LLM may lack proper authorization checks.

#### Rejected CWE Review Comments

- Remove CWE-732 Inadequate Encoding of Output Data

  - This CWE is not directly related to excessive agency and permissions granted to the LLM. Output encoding issues are a separate concern.

- Remove CWE-799 Improper Control of Interaction Frequency

  - This CWE focuses on throttling/rate-limiting actions, not on the agency or permissions to make those actions, so it is not directly relevant.


### Techniques

#### MITRE ATT&CK® Techniques

- [T1078](https://attack.mitre.org/techniques/T1078/): Valid Accounts

  Description: Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.
  
  Justification: In environments where LLMs have excessive permissions, the risk of adversaries using valid accounts to abuse these permissions increases.

- [T1548](https://attack.mitre.org/techniques/T1548/): Abuse Elevation Control Mechanism

  Description: Exploiting weak access controls to leverage excessive privileges.

  Justification: Relevant technique to exploit excessive plugin privileges granted to the LLM.

#### MITRE ATLASTM Techniques

- [AML.T0011](https://collaborate.mitre.org/attackics/index.php/Technique/AML/T0011): User Execution

  Description: Adversaries may manipulate users into executing unintended and potentially unsafe actions suggested by an LLM that has been granted excessive, unchecked autonomy. Users may unknowingly execute unsafe code or actions that take advantage of the LLM's broad permissions.

  Justification: User execution of unintended actions enabled by an LLM with excessive autonomy allows adversaries to more easily exploit the LLM's broad capabilities through manipulated user behavior.  

- [AML.T0043](https://collaborate.mitre.org/attackics/index.php/Technique/AML/T0043): Craft Adversarial Data

  Description: By crafting adversarial data inputs, an adversary can manipulate the behaviors of an LLM that has excessive autonomy, causing it to take unintended actions that take advantage of its broad permissions and capabilities.

  Justification: Carefully engineered data samples enable adversaries to control and exploit the excessive autonomy granted to the LLM to achieve unintended behaviors.

- [AML.T0044](https://collaborate.mitre.org/attackics/index.php/Technique/AML/T0044): Full ML Model Access

  Description: Full white-box access to an LLM with excessive autonomy provides an adversary with maximum control over manipulating its behaviors by crafting inputs optimized to exploit its unchecked capabilities.

  Justification: Complete access maximizes an adversary's ability to control and exploit the unchecked autonomy granted to the LLM.


#### Rejected Technique Review Comments

- Remove AML.T0047 ML-Enabled Product or Service
  
  - This technique is too broad and not directly related to risks arising from excessive LLM agency specifically.


### Mitigations

#### MITRE ATT&CK® Mitigations

- [M1027](https://attack.mitre.org/mitigations/M1027/): Password Policies

  Description: Set and enforce secure password policies for accounts.

  Justification: Strong authentication makes unauthorized access more difficult. 

- [M1042](https://attack.mitre.org/mitigations/M1042/): Disable or Remove Feature or Program

  Description: Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries.

  Justification: Reducing available services limits potential vectors to manipulate behaviors.

- [M1030](https://attack.mitre.org/mitigations/M1030/): Network Segmentation

  Description: Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation to prevent access to potentially sensitive systems and information.

  Justification: Network segmentation can isolate critical systems from manipulation.  

- [M1032](https://attack.mitre.org/mitigations/M1032/): Multi-factor Authentication

  Description: Use two or more pieces of evidence to authenticate to a system; such as username and password in addition to a token from a physical smart card or token generator.

  Justification: Raises the bar for gaining access needed to manipulate behaviors.

- [M1050](https://attack.mitre.org/mitigations/M1050/): Audit

  Description: Audit the activities and permissions of LLMs to ensure they are acting within the designated limits.

  Justification: Continuous auditing can immediately flag and potentially halt any unauthorized or unexpected behavior, which is crucial in preventing risks arising from excessive agency.


#### MITRE ATLASTM Mitigations

- [AML.M0011](https://collaborate.mitre.org/attackics/index.php/Mitigation/AML/M0011): Restrict Library Loading

  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for loading of malicious libraries.

  Justification: Restricting library loading prevents adversaries from injecting malicious code to manipulate model behaviors.

- [AML.M0015](https://collaborate.mitre.org/attackics/index.php/Mitigation/AML/M0015): Adversarial Input Detection

  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

  Justification: Detecting and blocking adversarial inputs prevents manipulation of the model's behaviors.

- [AML.M0017](https://collaborate.mitre.org/attackics/index.php/Mitigation/AML/M0017): Model Distribution Methods

  Description: Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model.

  Justification: Restricting model access by using cloud deployment reduces potential attack surface area.

- [AML.M0018](https://collaborate.mitre.org/attackics/index.php/Mitigation/AML/M0018): User Training

  Description: Educate ML model developers on secure coding practices and ML vulnerabilities.

  Justification: Proper training of developers helps ensure they implement appropriate access controls and limitations.

- [AML.M0019](https://collaborate.mitre.org/attackics/index.php/Mitigation/AML/M0019): Limit Model Functionality

  Description: Limit the operations that the machine learning model can perform to only what is essential for its intended purpose.

  Justification: By restricting the functionalities to only what is essential, the risks associated with excessive agency are directly mitigated.

#### Rejected Mitigation Review Comments

- No rejected review comments

