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


### Techniques

#### MITRE ATT&CK® Techniques

- [T1078](https://attack.mitre.org/techniques/T1078/): Valid Accounts

  Description: Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

  Justification: In environments where LLMs have excessive permissions, the risk of adversaries using valid accounts to abuse these permissions increases.

- [T1548](https://attack.mitre.org/techniques/T1548/): Abuse Elevation Control Mechanism

  Description: Exploiting weak access controls to leverage excessive privileges.

  Justification: Relevant technique to exploit excessive plugin privileges granted to the LLM.

#### MITRE ATLAS™ Techniques

- [T0011](https://attack.mitre.org/techniques/T0011/): User Execution

  Description: Adversaries may manipulate users into executing unintended and potentially unsafe actions suggested by an LLM that has been granted excessive, unchecked autonomy. Users may unknowingly execute unsafe code or actions that take advantage of the LLM's broad permissions.

  Justification: User execution of unintended actions enabled by an LLM with excessive autonomy allows adversaries to more easily exploit the LLM's broad capabilities through manipulated user behavior.

- [T0043](https://attack.mitre.org/techniques/T0043/): Craft Adversarial Data

  Description: By crafting adversarial data inputs, an adversary can manipulate the behaviors of an LLM that has excessive autonomy, causing it to take unintended actions that take advantage of its broad permissions and capabilities.

  Justification: Carefully engineered data samples enable adversaries to control and exploit the excessive autonomy granted to the LLM to achieve unintended behaviors.  

- [T0044](https://attack.mitre.org/techniques/T0044/): Full ML Model Access

  Description: Full white-box access to an LLM with excessive autonomy provides an adversary with maximum control over manipulating its behaviors by crafting inputs optimized to exploit its unchecked capabilities.

  Justification: Complete access maximizes an adversary's ability to control and exploit the unchecked autonomy granted to the LLM.

- [T0012](https://attack.mitre.org/techniques/T0012/): Role-Based Access Control

  Description: Implementing role-based access controls in LLM systems can prevent unauthorized actions.

  Justification: Role-Based Access Control directly targets the issue of excessive agency by ensuring that only authorized roles have access to certain functionalities.  


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

#### MITRE ATLAS™ Mitigations

- [M0011](https://attack.mitre.org/mitigations/M0011/): Restrict Library Loading

  Description: Prevent abuse of library loading mechanisms in the operating system and software to load untrusted code by configuring appropriate library loading mechanisms and investigating potential vulnerable software. 

  Justification: Restricting library loading prevents adversaries from injecting malicious code to manipulate model behaviors.

- [M0015](https://attack.mitre.org/mitigations/M0015/): Adversarial Input Detection

  Description: Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model.

  Justification: Detecting and blocking adversarial inputs prevents manipulation of the model's behaviors.

- [M0017](https://attack.mitre.org/mitigations/M0017/): Model Distribution Methods  

  Description: Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model.

  Justification: Restricting model access by using cloud deployment reduces potential attack surface area.

- [M0018](https://attack.mitre.org/mitigations/M0018/): User Training

  Description: Educate ML model developers on secure coding practices and ML vulnerabilities.

  Justification: Proper training of developers helps ensure they implement appropriate access controls and limitations. 

- [M0019](https://attack.mitre.org/mitigations/M0019/): Limit Model Functionality

  Description: Limit the operations that the machine learning model can perform to only what is essential for its intended purpose.

  Justification: By restricting the functionalities to only what is essential, the risks associated with excessive agency are directly mitigated.