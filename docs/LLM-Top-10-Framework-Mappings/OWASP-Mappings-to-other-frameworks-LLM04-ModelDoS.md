By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM04: Denial of Service

## Summary

Overloading LLMs with resource-heavy operations can cause service disruptions and increased costs.

## Description

Model Denial of Service involves overloading LLMs with resource-heavy operations that can disrupt services and incur costs. 

Attackers can send unusual or malformed inputs that consume excessive resources, overload context windows, or trigger recursive processing. This strains systems, causes slowdowns and unavailability. Impacts include service disruptions, increased infrastructure costs, and revenue losses.

Prevention involves input sanitization, enforcing limits on resource usage and context windows, implementing rate limiting, monitoring for spikes in resource utilization, and promoting awareness among developers.


## Common Weakness Enumeration (CWE)

- [CWE-16](https://cwe.mitre.org/data/definitions/16.html): Configuration - Weaknesses related to security configurations. Applicable as misconfigurations could trigger resource issues by enabling resource exhaustion. 

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Failure to properly validate input data. Applicable as validation failures enable malicious requests that consume excessive resources. 

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Failure to restrict access to authorized users. Applicable as unauthorized requests could abuse resources since they are not limited.

- [CWE-400](https://cwe.mitre.org/data/definitions/400.html): Uncontrolled Resource Consumption - Failure to limit resource consumption. Applicable as malicious interactions can exhaust LLM resources directly via uncontrolled consumption.

- [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling - Failure to throttle or limit allocation of resources. Applicable as lack of throttling enables resource exhaustion by allowing unchecked usage. 

- [CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency - Failure to limit frequency of interactions. Applicable as lack of frequency control allows flooding requests that overwhelm resources.

- [CWE-404](https://cwe.mitre.org/data/definitions/404.html): Improper Resource Shutdown or Release - Failure to properly free resources after use. Applicable if resources are not properly released after use, leading to exhaustion by depleting available resources.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Use of untrusted code or inputs. Applicable if plugins/extensions can trigger resource issues by including uncontrolled functionality. 

## ATT&CK Technique

- [T1499](https://attack.mitre.org/techniques/T1499/): Endpoint Denial of Service - Techniques to disrupt service availability. Disrupts service availability. Directly causes denial of service.

## MITRE ATLAS Techniques 

- [AML.T0029](/techniques/AML.T0029): Denial of ML Service - Overloading systems with resource-heavy operations. Designed to overload systems with resource-heavy inputs. Directly causes denial of service.

- [AML.T0043](/techniques/AML.T0043): Craft Adversarial Data - Careful input crafting to manipulate models. Crafting prompts that require extensive processing could strain systems. Carefully crafted inputs that consume excessive resources. 

- [AML.T0040](/techniques/AML.T0040): ML Model Inference API Access - Use of the model API to manipulate behavior. Flooding the API with requests could overwhelm systems. API access enables attacks.

- [AML.T0016](/techniques/AML.T0016): Obtain Capabilities - Obtaining tools and exploits. May obtain tools to automate sending malicious requests. Aids automation of resource exhaustion. 

- [AML.T0012](/techniques/AML.T0012): Valid Accounts - Abuse of compromised credentials. Compromised credentials could bypass rate limiting. Allows increased access to send more requests. 

- [AML.T0010](/techniques/AML.T0010): ML Supply Chain Compromise - Compromise of ML components and services. Could introduce inefficiencies via compromised artifacts that are resource-intensive. Introduces weaknesses that strain resources.

- [AML.T0044](/techniques/AML.T0044): Full ML Model Access - Complete control over the model. Full control enables sending optimized resource-heavy inputs. Maximizes impact through total control. 

- [AML.T0047](/techniques/AML.T0047): ML-Enabled Product or Service - Exploiting ML services. Existing services with inadequate protections could be exploited. Finds vulnerable services to target.

- [AML.T0019](/techniques/AML.T0019): Publish Poisoned Data - Distribution of contaminated datasets. Training on data designed to increase compute could degrade performance. Influences model to require more resources. 

- [AML.T0011](/techniques/AML.T0011): User Execution - Tricking users into executing payloads. Users may unknowingly execute code that overloads systems. Executes malicious code causing resource exhaustion.


## ATT&CK Mitigations

N.A.


## MITRE ATLAS Mitigations 

- AML.M0004: Restrict Number of ML Model Queries. Limit total queries and rate. Directly prevents flooding systems.

- AML.M0015: Adversarial Input Detection. Detect and block heavy inputs before reaching model. Identifies malicious requests. 

- AML.M0003: Model Hardening. Make models robust to complex inputs. Reduces strain from inputs.

- AML.M0014: Verify ML Artifacts. Detect tampered artifacts designed to overload systems. Identifies tampering. 

- AML.M0013: Code Signing. Prevent execution of artifacts modified to cause denial of service. Checks integrity.

- AML.M0012: Encrypt Sensitive Information. Encrypt models and data. Prevents access to craft resource-heavy inputs.   

- AML.M0005: Control Access to ML Models and Data at Rest. Limit access to models. Reduces attack surface.

- AML.M0016: Vulnerability Scanning. Scan for flaws enabling denial of service. Finds weaknesses to address.

- AML.M0018: User Training. Educate users on denial of service risks. Reduces unknowing participation.