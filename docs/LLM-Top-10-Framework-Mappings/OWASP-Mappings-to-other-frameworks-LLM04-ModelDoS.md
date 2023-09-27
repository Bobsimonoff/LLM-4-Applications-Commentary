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


## CWE

[CWE-16](https://cwe.mitre.org/data/definitions/16.html): Configuration - Applicable as misconfigurations could trigger resource issues.

[CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Applicable as validation failures enable malicious requests.  

[CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Applicable as unauthorized requests could abuse resources.

[CWE-400](https://cwe.mitre.org/data/definitions/400.html): Uncontrolled Resource Consumption - Applicable as malicious interactions can exhaust LLM resources.  

[CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling - Applicable as lack of throttling enables resource exhaustion.

[CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency - Applicable as lack of frequency control allows flooding.

[CWE-404](https://cwe.mitre.org/data/definitions/404.html): Improper Resource Shutdown or Release - Applicable if resources are not properly released after use, leading to exhaustion.

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable if plugins/extensions can trigger resource issues.


## MITRE ATT&CK Techniques

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

