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

[CWE-16](https://cwe.mitre.org/data/definitions/16.html): Configuration - Applicable as misconfigurations could trigger resource issues.

[CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Applicable as validation failures enable malicious requests.  

[CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Applicable as unauthorized requests could abuse resources.

[CWE-400](https://cwe.mitre.org/data/definitions/400.html): Uncontrolled Resource Consumption - Applicable as malicious interactions can exhaust LLM resources.  

[CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling - Applicable as lack of throttling enables resource exhaustion.

[CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency - Applicable as lack of frequency control allows flooding.

[CWE-404](https://cwe.mitre.org/data/definitions/404.html): Improper Resource Shutdown or Release - Applicable if resources are not properly released after use, leading to exhaustion.

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable if plugins/extensions can trigger resource issues.

## ATT&CK Techniques 

- [T1499](https://attack.mitre.org/techniques/T1499/) - Endpoint Denial of Service. Disrupts service availability. Directly causes denial of service.

## ATT&CK Mitigations

- [M1042](https://attack.mitre.org/mitigations/M1042/) - Disable or Remove Feature or Program. Removes features. Could eliminate functions producing heavy resource load.

- [M1049](https://attack.mitre.org/mitigations/M1049/) - Disable or Remove Feature or Program. Removes features. Could eliminate functions producing heavy resource load. 

- [M1050](https://attack.mitre.org/mitigations/M1050/) - Network Segmentation. Segregates networks. Could prevent resource-heavy requests reaching models.


## MITRE ATLAS Techniques

- AML.T0029: Denial of ML Service. Designed to overload systems with resource-heavy inputs. Directly causes denial of service.

- AML.T0043: Craft Adversarial Data. Crafting prompts that require extensive processing could strain systems. Carefully crafted inputs.

- AML.T0040: ML Model Inference API Access. Flooding the API with requests could overwhelm systems. API access enables attacks. 

- AML.T0016: Obtain Capabilities. May obtain tools to automate sending malicious requests. Aids automation.

- AML.T0012: Valid Accounts. Compromised credentials could bypass rate limiting. Allows increased access.

- AML.T0010: ML Supply Chain Compromise. Could introduce inefficiencies via compromised artifacts that are resource-intensive. Introduces weaknesses. 

- AML.T0044: Full ML Model Access. Full control enables sending optimized resource-heavy inputs. Maximizes impact.

- AML.T0047: ML-Enabled Product or Service. Existing services with inadequate protections could be exploited. Finds vulnerable services.

- AML.T0019: Publish Poisoned Data. Training on data designed to increase compute could degrade performance. Influences model.

- AML.T0011: User Execution. Users may unknowingly execute code that overloads systems. Executes malicious code.


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


