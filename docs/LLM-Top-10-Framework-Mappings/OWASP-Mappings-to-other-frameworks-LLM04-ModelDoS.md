By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM04: Denial of Service

### Summary
Overloading LLMs with resource-intensive operations can cause service disruptions, degraded performance, and increased costs.

### Description
Denial of service attacks overload LLMs through input flooding, recursive context expansion, and other techniques that consume excessive resources. This causes service disruptions, performance degradation, and increased costs.

Preventive measures include input sanitization, resource capping, rate limiting, monitoring, and secure architecture guidelines.


### Common Examples of Risk

1. Sending queries that recursively generate excessive tasks. 

2. Submitting inputs with unusual formatting that require extensive processing.

3. Flooding systems with continuous input exceeding context limits. 

4. Repeatedly sending long inputs that strain context window capacity. 

5. Crafting inputs that recursively expand context causing repeated processing.

6. Flooding systems with variable length inputs approaching context limits.

### Prevention and Mitigation Strategies

1. Validate and sanitize input data to defined limits.

2. Cap resource usage per request to slow complex inputs. 

3. Enforce API rate limiting to restrict requests.

4. Limit queued actions and total actions after LLM responses.

5. Monitor for spikes in resource utilization indicating attacks.

6. Set strict input size limits based on context window. 

7. Educate developers on potential denial of service risks.

### Example Attack Scenarios

1. Attacker overwhelms systems with repeated expensive requests, degrading performance.

2. Benign web query triggers excessive resource consumption through model interactions.

3. Attacker floods LLM with input exceeding context window, crashing system. 

4. Attacker sends sequential inputs approaching context limit, exhausting resources.

5. Attacker crafted input causes repeated context expansion, straining systems.

6. Attacker floods systems with varied length inputs targeting context limits.



### MITRE ATLAS™ 

#### Techniques

- [AML.T0016](https://atlas.mitre.org/techniques/AML.T0016): Obtain Capabilities - An adversary acquires tools and software that generate adversarial inputs to language models. These tools allow the adversary to craft prompts and other inputs designed to trigger excessive processing, memory usage, and other behaviors that can overwhelm systems. 

- [AML.T0029](https://atlas.mitre.org/techniques/AML.T0029): Denial of ML Service - This technique could potentially be used to exploit a denial of service vulnerability in an LLM system. An adversary could intentionally craft inputs that are resource intensive for the LLM to process, with the goal of overloading the system.

- [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040): ML Model Inference API Access - An adversary utilizes a language model's public inference API to probe the model, identify weaknesses, and craft inputs that consume excessive resources. API access enables information gathering and input optimization prior to launching a denial of service attack.

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043): Craft Adversarial Data - An adversary could craft prompts or other inputs that are designed to trigger very long, repetitive responses from the LLM. Flooding the system with many such carefully crafted inputs could overwhelm the LLM's processing capacity and memory usage, resulting in a denial of service effect. 

#### Mitigations

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004/): Restrict Number of ML Model Queries. Limit the total number and rate of queries a user can perform. Suggested approaches: - Limit the number of queries users can perform in a given interval to hinder an attacker's ability to send computationally expensive inputs - Limit the amount of information an attacker can learn about a model's ontology through API queries. - Limit the volume of API queries in a given period of time to regulate the amount and fidelity of potentially sensitive information an attacker can learn. - Limit the number of queries users can perform in a given interval to shrink the attack surface for black-box attacks. - Limit the number of queries users can perform in a given interval to prevent a denial of service.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.

- [AML.M0016](https://atlas.mitre.org/mitigations/AML.M0016/): Vulnerability Scanning. Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for arbitrary code execution. Scan ML artifacts for vulnerabilities before execution.

- [AML.M0017](https://atlas.mitre.org/mitigations/AML.M0017/): Model Distribution Methods. Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model. Not distributing the model in software to edge devices, can limit an adversary's ability to gain full access to the model. With full access to the model, an adversary could perform white-box attacks. An adversary could repackage the application with a malicious version of the model.

#### Possible Additions

**New Technique Proposals**

- AML.TXXXX: Recursive Context Expansion - An adversary crafts inputs containing text triggers that cause the language model to continuously expand the context window and reprocess the input in a recursive loop. Each iteration consumes additional memory and compute resources. Sending many such inputs can rapidly exhaust available resources, resulting in denial of service. Note this could be a subtechnique of craft adversarial data.

- AML.TXXXX: Benign Query Resource Exhaustion - An adversary identifies benign input text which does not appear obviously malicious but leads to unpredictable resource consumption due to the language model's processing. Queries submitted through public interfaces get processed by downstream models in a way that consumes substantial resources due to lengthy text generation or repeated context expansion. The adversary can send many such queries to degrade performance and availability. 

**New Mitigation Proposals**  

- AML.MXXXX: Limit Context Expansions - The language model is configured to limit the number of recursive context expansions that can occur per request. This prevents adversaries from causing excessive processing through inputs that continuously trigger context re-generation. Hard thresholds prevent unlimited recursive expansion scenarios.

- AML.MXXXX: Resource Consumption Monitoring - Continuously monitor CPU, memory, and other resource consumption metrics to identify abnormal behavior indicative of a DoS attack.



### STRIDE Analysis (generated by claude.ai)

**Spoofing**

- Attackers can spoof the origin of requests to disguise their source and make attribution more difficult.

**Tampering**

- Malicious requests can tamper with model behaviors by overloading systems and disrupting availability.

**Repudiation** 

- Lack of logging around malicious requests complicates attack attribution and allows repudiation.
- DoS attacks could also tamper with or disable logging to undermine attribution.
- Flooding attacks against a language model can overwhelm any logging or monitoring capabilities on that system, making it difficult to record and analyze the high volumes of malicious traffic. This complicates root cause analysis and attribution after the attack.

**Information Disclosure**

- Flooding attacks do not directly cause information disclosure but service disruption enables easier access to compromised systems.

**Denial of Service**

- Specially crafted inputs trigger resource exhaustion, system crashes, and service disruption.
- Flooding systems with requests disrupts availability and prevents legitimate use.

**Elevation of Privilege**

- While DoS does not directly enable privilege escalation, service disruption provides opportunities for unauthorized access.
- Compromised credentials allow attackers to more easily trigger DoS conditions.  


### Common Weakness Enumeration (CWE)

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Summary: Failure to validate inputs allows malicious inputs to exploit systems.

  Exploit: By not properly validating inputs, an attacker can craft specially formatted data that consumes excessive resources when processed by the system, leading to resource exhaustion and denial of service.

- [CWE-352](https://cwe.mitre.org/data/definitions/352.html): Cross-Site Request Forgery (CSRF)

  Summary: Forces unintended external requests facilitating denial of service.

  Exploit: Malicious input tricks LLM into making harmful requests to external systems contributing to resource exhaustion.

- [CWE-400](https://cwe.mitre.org/data/definitions/400.html): Uncontrolled Resource Consumption

  Summary: Allows attackers to consume excessive resources (CPU, memory, disk, network) via malicious input.

  Exploit: The lack of restrictions on resource usage enables an attacker to overwhelm systems with carefully crafted inputs that demand extensive processing cycles, memory, storage, or network capacity far beyond normal operations.

- [CWE-601](https://cwe.mitre.org/data/definitions/601.html): URL Redirection to Untrusted Site

  Summary: Redirects to malicious external sites enabling denial of service.

  Exploit: Attacker manipulates LLM to interact with harmful external sites that trigger excessive resource consumption leading to denial of service.

- [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling

  Summary: No limits on resource allocation allows exhaustion via excessive requests.

  Exploit: With no throttling or caps on resource allocation, an attacker can exploit the system by flooding it with excessive requests that rapidly drain available resources leading to denial of service.
  
- [CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency

  Summary: Failure to limit the frequency of interactions enabling repeated operations that strain resources.

  Exploit: Lack of frequency throttling enables an attacker to overwhelm systems by bombarding them with rapid, repeated requests that cumulatively create a denial of service effect.

- [CWE-834](https://cwe.mitre.org/data/definitions/834.html): Excessive Iteration

  Summary: Uncontrolled looping allows arbitrary computation, resource exhaustion.

  Exploit: Inputs designed to trigger extensive recursive processing induce excessive iteration cycles that continually drain and overwhelm system resources.

- [CWE-835](https://cwe.mitre.org/data/definitions/835.html): Loop with Unreachable Exit Condition ('Infinite Loop')

  Summary: Infinite loops cause programs to hang, consume resources indefinitely.

  Exploit: Crafted inputs that recursively expand context force infinite processing loops that continuously consume resources leading to denial of service.

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF)

  Summary: Failure to block server-side execution of malicious external requests leading to resource exhaustion.

  Exploit: An attacker can submit crafted inputs that induce the system to make unintended external requests to APIs and other endpoints, amplifying compute and network resource consumption.


---

# IGNORE FOR NOW - NEED RE-REVIEW


### MITRE ATT&CK® 

#### Techniques

- [T1496](https://attack.mitre.org/techniques/T1496/): Resource Hijacking

  Description: An adversary may use the LLM resources for unintended purposes like cryptocurrency mining.

  Justification: While not a typical DoS, this technique disrupts normal functioning by reallocating system resources for unauthorized uses, effectively causing service degradation.


- [T1499](https://attack.mitre.org/techniques/T1499/): Endpoint Denial of Service

  Description: Techniques used to make systems or services unavailable to legitimate users.

  Justification: Directly causes denial of service on endpoints.

#### Mitigations

- None

