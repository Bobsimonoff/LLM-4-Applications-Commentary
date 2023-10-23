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

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004): Restrict Number of ML Model Queries - Query rate limiting prevents flooding attacks by restricting the number of inputs an adversary can submit over a period of time. Requests exceeding the defined rate are dropped/blocked. Rate limits can be applied per user account and potentially increased for legitimate high-volume usages.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015): Adversarial Input Detection - Runtime monitoring mechanisms analyze inputs to the language model and characterize the expected resource consumption. Inputs projected to consume excessive resources based on analysis of text, prompt length, expandability and other factors are blocked prior to processing.

- [AML.M0016](https://github.com/mitre-atlas/atlas/blob/master/data/mitigations/mitigations-yaml/AML.M0016.yml): Limit Model Queries Per User - Rate limiting and quotas prevent adversaries from overwhelming systems by restricting the number of queries an individual can make over a given time window. This mitigates denial of service from query flooding.

- [AML.M0017](https://github.com/mitre-atlas/atlas/blob/master/data/mitigations/mitigations-yaml/AML.M0017.yml): Resource Isolation - Language model resources like memory, compute, and storage are isolated from other components through mechanisms like containers. This prevents denial of service impacts from spreading beyond the language model to other critical services.

#### Possible Additions

**Possible New Techniques**

- Recursive Context Expansion - An adversary crafts inputs containing text triggers that cause the language model to continuously expand the context window and reprocess the input in a recursive loop. Each iteration consumes additional memory and compute resources. Sending many such inputs can rapidly exhaust available resources, resulting in denial of service. Note this could be a subtechnique of craft adversarial data.

- Benign Query Resource Exhaustion - An adversary identifies benign input text which does not appear obviously malicious but leads to unpredictable resource consumption due to the language model's processing. Queries submitted through public interfaces get processed by downstream models in a way that consumes substantial resources due to lengthy text generation or repeated context expansion. The adversary can send many such queries to degrade performance and availability. 

**Possible New Mitigations**  

- Limit Concurrent Requests - The number of requests that can be processed concurrently by the language model is restricted through configuration. Limiting concurrency makes it more difficult for an adversary to overwhelm systems with high volumes of queries. The limit could be applied across all users or per individual user account.

- Limit Context Expansions - The language model is configured to limit the number of recursive context expansions that can occur per request. This prevents adversaries from causing excessive processing through inputs that continuously trigger context re-generation. Hard thresholds prevent unlimited recursive expansion scenarios.

- Resource Consumption Monitoring - Continuously monitor CPU, memory, and other resource consumption metrics to identify abnormal behavior indicative of a DoS attack.



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

---

# IGNORE FOR NOW - NEED RE-REVIEW


### Common Weakness Enumeration (CWE)

- [CWE-16](https://cwe.mitre.org/data/definitions/16.html): Configuration

  Description: Weaknesses related to security configurations wherein the default configurations are misconfigured or unsafe.

  Justification: Misconfigurations could trigger resource exhaustion by enabling unchecked resource consumption.

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Description: Missing or inadequate input validation leading to dangerous behaviors from unchecked tainted input.

  Justification: Lack of input validation enables sending resource-heavy requests. 

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Description: Failure to restrict access to authorized entities leading to privilege escalation.

  Justification: Unauthorized requests could abuse resources since they are unrestricted.

- [CWE-400](https://cwe.mitre.org/data/definitions/400.html): Uncontrolled Resource Consumption

  Description: Failure to control resource consumption enabling exhaustion of resources like CPU, memory, disk space, database connections, etc.

  Justification: Directly targets the risk by facilitating both direct and indirect resource exhaustion through unchecked resource usage, making it a cornerstone vulnerability in Denial of Service attacks on LLMs.

- [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling

  Description: Failure to throttle or limit allocation of resources enabling unchecked consumption.

  Justification: Lack of throttling allows unchecked resource usage enabling exhaustion.

- [CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency

  Description: Failure to limit the frequency of interactions enabling repeated operations that strain resources.

  Justification: Lack of frequency control allows flooding requests overwhelming resources.

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF)

  Description: Failure to block server-side execution of maliciously crafted external URIs, leading to data exposure or resource exhaustion.

  Justification: In a LLM context, SSRF can be exploited to create tasks that indirectly exhaust resources by causing the LLM to make additional unintended external requests, further amplifying the DoS effect.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: Use of untrusted code or inputs leading to unintended functionality.

  Justification: Extensions/plugins could trigger resource issues by including uncontrolled functionality.


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

