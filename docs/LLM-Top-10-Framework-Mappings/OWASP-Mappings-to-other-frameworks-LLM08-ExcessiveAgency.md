e a new and better By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM08: Excessive Agency

### Summary

Excessive LLM permissions or autonomy enables unintended harmful actions based on faulty LLM outputs.

### Description 

Excessive Agency stems from providing an LLM with more permissions than are necessary for its intended functionality. Specifically, granting excessive:

- Functionality: Access to plugins, tools or capabilities beyond necessity. 

- Permissions: Overly broad access to systems, APIs and data.

- Autonomy: Ability to take impactful actions without human oversight.

Not to be confused with:
- LLM02: Insecure Output Handling - Failing to validate LLM-generated outputs before sending them to downstream services can allow insecure code or attack strings to reach vulnerable systems. 

- LLM07: Insecure Plugin Design - Lack of validation by downstream components 

- LLM09: Overreliance - Placing too much trust in the accuracy of LLM outputs 

Excessive Agency outside an LLM's intended scope enables unintended harmful actions based on faulty model outputs. Potential impacts include data loss, fraud, reputational damage, and more.

Prevention requires narrowly limiting LLM capabilities to least functionality, permissions and autonomy needed for core operations.


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


### MITRE ATLAS™ 

#### Techniques
- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006/): Active Scanning - The adversary could actively probe the LLM to find prompts that seem to enable elevated permissions

- [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025/): Exfiltration via Cyber Means - Exfiltrating data like logs could help the adversary understand how to manipulate the LLM 

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data - Crafting adversarial prompts could then exploit elevated permissions to take unintended actions

#### Mitigations
- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004/): Restrict Number of ML Model Queries. Limit the total number and rate of queries a user can perform. Suggested approaches: - Limit the number of queries users can perform in a given interval to hinder an attacker's ability to send computationally expensive inputs - Limit the amount of information an attacker can learn about a model's ontology through API queries. - Limit the volume of API queries in a given period of time to regulate the amount and fidelity of potentially sensitive information an attacker can learn. - Limit the number of queries users can perform in a given interval to shrink the attack surface for black-box attacks. - Limit the number of queries users can perform in a given interval to prevent a denial of service.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.

#### Possible Additions

**Possible Additional Mitigations** 

- AML.MXXXX: Audit LLM Activities - Continuously monitor and audit LLM behaviors, permissions, and access to detect anomalies or actions outside expected boundaries that could signal unintended consequences.

- AML.MXXXX: Limit LLM Capabilities - Carefully restrict the specific functions and capabilities the LLM can perform to only those necessary for its core intended purpose, reducing potential for unintended actions.


### STRIDE Analysis (generated by claude.ai)

**Spoofing**

- Adversaries can spoof user identities through valid credentials to bypass authorization controls when manipulating model behaviors.

- Excessive privileges granted to plugins and components can be abused to spoof trusted identities.

**Tampering**

- Unchecked model behaviors mean malicious inputs can precisely control and tamper with model actions and outputs.

- Excessive permissions enable tampering with downstream data and systems.

**Repudiation** 

- Lack of permissions auditing around manipulated behaviors can complicate attack attribution.

- Tampering with logs can undermine forensic analysis of exploited autonomous behaviors.


**Information Disclosure**

- Uncontrolled model outputs increase the risk of exposing sensitive information.

- Access to backend systems means private data can be extracted through manipulated behaviors.


**Denial of Service**

- Unchecked recursive model invocations could trigger resource exhaustion.

- Malicious adversarial samples could crash models or render them unusable.


**Elevation of Privilege**

- Excessive permissions granted to plugins can enable privilege escalation on backend systems.

- Valid accounts and poor access controls enable bypassing privilege restrictions.



### Common Weakness Enumeration (CWE)

- [CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure

  Summary: Failure to use protections against directed attacks.

  Exploit: Lack of safeguards restricting an LLM's permissions and capabilities enables attackers to manipulate it into taking harmful actions through crafted inputs.

- [CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization  

  Summary: Failure to perform authorization checks for actions.

  Exploit: An LLM plugin takes impactful actions without approval based on its excessive autonomy, allowing attackers to induce unintended harmful activity through the unrestricted LLM.

- [CWE-250](https://cwe.mitre.org/data/definitions/250.html): Execution with Unnecessary Privileges

  Summary: Performing actions with unnecessary privileges.

  Exploit: Excessive privileges granted to an LLM or its plugins exceed what is needed for its core functions, enabling unintended privileged actions induced by an attacker's manipulated inputs.

- [CWE-269](https://cwe.mitre.org/data/definitions/269.html): Improper Privilege Management

  Summary: Failing to properly restrict privileges to authorized users.

  Exploit: An LLM or its plugins are granted excessive privileges without proper management of the privileges. This enables attackers to induce unintended privileged actions by manipulating the unrestricted LLM through crafted inputs designed to exploit its unnecessary privileges.

- [CWE-732](https://cwe.mitre.org/data/definitions/732.html): Incorrect Permission Assignment for Critical Resource

  Summary: Incorrect critical resource permissions allow abuse.

  Exploit: Overly broad permissions beyond necessity provided to an LLM or its plugins enable unintended actions on critical resources triggered by an attacker.

- [CWE-668](https://cwe.mitre.org/data/definitions/668.html): Exposure of Resource to Wrong Sphere

  Summary: Exposing resources to unintended actors enables abuse.

  Exploit: Excessive functionality or access to resources beyond an LLM's core needs allows attackers to induce unintended actions through crafted inputs.


---

# IGNORE FOR NOW - NEED RE-REVIEW




### MITRE ATT&CK® Techniques

- [T1078](https://attack.mitre.org/techniques/T1078/): Valid Accounts

  Description: Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

  Justification: In environments where LLMs have excessive permissions, the risk of adversaries using valid accounts to abuse these permissions increases.

- [T1548](https://attack.mitre.org/techniques/T1548/): Abuse Elevation Control Mechanism

  Description: Exploiting weak access controls to leverage excessive privileges.

  Justification: Relevant technique to exploit excessive plugin privileges granted to the LLM.

### MITRE ATT&CK® Mitigations

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



