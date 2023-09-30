By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM04: Denial of Service

### Summary

Overloading LLMs with resource-heavy operations can cause service disruptions and increased costs.

### Description

Model Denial of Service involves overloading LLMs with resource-heavy operations that can disrupt services and incur costs. 

Attackers can send unusual or malformed inputs that consume excessive resources, overload context windows, or trigger recursive processing. This strains systems, causes slowdowns and unavailability. Impacts include service disruptions, increased infrastructure costs, and revenue losses.

Prevention involves input sanitization, enforcing limits on resource usage and context windows, implementing rate limiting, monitoring for spikes in resource utilization, and promoting awareness among developers.

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

  Justification: Malicious interactions directly exhaust LLM resources through uncontrolled consumption.

- [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling

  Description: Failure to throttle or limit allocation of resources enabling unchecked consumption.

  Justification: Lack of throttling allows unchecked resource usage enabling exhaustion.

- [CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency

  Description: Failure to limit the frequency of interactions enabling repeated operations that strain resources.

  Justification: Lack of frequency control allows flooding requests overwhelming resources.

- [CWE-404](https://cwe.mitre.org/data/definitions/404.html): Improper Resource Shutdown or Release

  Description: Failure to properly free resources after use leading to resource exhaustion.

  Justification: Improper resource release leads to depletion of available resources.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: Use of untrusted code or inputs leading to unintended functionality.

  Justification: Extensions/plugins could trigger resource issues by including uncontrolled functionality.

## ATT&CK Technique

- [T1499](https://attack.mitre.org/techniques/T1499/): Endpoint Denial of Service

  Description: Techniques used to make systems or services unavailable to legitimate users.

  Justification: Directly causes denial of service on endpoints.


### MITRE ATLAS Techniques

- AML.T0016: Obtain Capabilities  

  Description: Adversaries may obtain or develop capabilities like adversarial machine learning tools to craft inputs precisely engineered to consume excessive resources. These tools enable adversaries to optimize resource exhaustion attacks on LLMs by precisely measuring resource usage.

  Justification: Obtaining capabilities to craft resource-heavy inputs enables optimized denial of service attacks by profiling resource consumption.

- AML.T0029: Denial of ML Service

  Description: Adversaries may directly overwhelm ML systems with excessive requests designed to degrade performance and deny service availability. Flooding systems strains resources and causes unavailability.

  Justification: Sending excessive requests directly triggers resource exhaustion and denial of service.

- AML.T0034: Cost Harvesting

  Description: Adversaries may specifically craft adversarial inputs designed to incur maximum costs through wasted computation and infrastructure usage in order to financially damage the victim organization.

  Justification: Inputs can be tailored to maximize costs by wasting cloud compute resources.

- AML.T0040: ML Model Inference API Access

  Description: Adversaries may use inference API access to profile model behaviors and identify triggers that require extensive processing in order to craft optimized resource exhaustion attacks.

  Justification: Inference API access enables adversaries to analyze behaviors to craft optimized resource exhaustion inputs.

- AML.T0043: Craft Adversarial Data

  Description: Adversaries may carefully craft inputs designed to consume excessive resources and manipulate model behavior. This aids in developing denial of service attacks.

  Justification: Crafting complex inputs strains LLM systems, enabling denial of service.


### MITRE ATT&CK Mitigations

N/A

### MITRE ATLAS Mitigations

- AML.M0004: Restrict Number of ML Model Queries

  Description: Limiting total queries and rate.

  Justification: Directly prevents flooding systems.

- AML.M0015: Adversarial Input Detection

  Description: Detecting and blocking heavy inputs.

  Justification: Identifies malicious requests.

- AML.M0003: Model Hardening

  Description: Making models robust to complex inputs.

  Justification: Reduces strain from inputs. 

- AML.M0014: Verify ML Artifacts

  Description: Detecting tampered artifacts.

  Justification: Identifies artifacts designed to cause exhaustion.

- AML.M0013: Code Signing

  Description: Preventing execution of unsigned artifacts.

  Justification: Checks integrity to prevent modified exhaustion code.

- AML.M0012: Encrypt Sensitive Information

  Description: Encrypting models and data.

  Justification: Prevents crafting resource-heavy inputs.

- AML.M0005: Control Access to ML Models and Data at Rest

  Description: Limiting model access.

  Justification: Reduces attack surface.

- AML.M0016: Vulnerability Scanning

  Description: Scanning for flaws.

  Justification: Finds weaknesses that could enable exhaustion attacks.

- AML.M0018: User Training

  Description: Educating users on risks.

  Justification: Reduces unknowing participation.
