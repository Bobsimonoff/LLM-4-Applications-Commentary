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



---
---
# WIP: Ignore below this line for now
---
---




## NIST CSF

**Subcategories**

- PR.IP-1: A baseline configuration of information technology/industrial control systems is created and maintained
- PR.IP-3: Configuration change control processes are in place
- PR.IP-9: Response plans (Incident Response and Business Continuity) and recovery plans (Incident Recovery and Disaster Recovery) are in place and managed

**Detect Functions**

- DE.AE-5: Processes are established to receive, analyze and respond to vulnerabilities disclosed to the organization from internal and external sources.
- DE.CM-4: Malicious code is detected
- DE.CM-7: Monitoring for unauthorized personnel, connections, devices and software is performed

**Respond Functions** 

- RS.RP-1: Response plan is executed during or after an event
- RS.CO-2: Incidents are reported consistent with established criteria
- RS.CO-3: Information is shared consistent with response plans
- RS.CO-5: Voluntary information sharing occurs with external stakeholders to achieve broader cybersecurity situational awareness

**Recover Functions**

- RC.RP-1: Recovery plan is executed during or after a cybersecurity incident
- RC.IM-2: Recovery strategies are updated


## MITRE ATT&CK

**Tactics**

- Initial Access - Gain initial access to target networks/systems

- Execution - Execute adversarial payloads and commands on local systems

- Impact - Disrupt availability and integrity of systems and data

**Techniques**

- Drive-by Compromise - Gain initial access by exploiting web-facing apps 

- Exploitation for Client Execution - Exploit client-side apps like browsers to execute code

- Resource Exhaustion FLOOD - Overwhelm systems with high volumes of traffic/requests

- Service Stop - Disable or degrade critical system services


## CIS Controls 

**Safeguards**

- CIS Control 1 - Inventory and Control of Enterprise Assets: Inventory assets to support DoS defenses. Metrics - percentage of assets inventoried.

- CIS Control 10 - Data Recovery Capabilities: Ensure backup and recovery to restore after DoS incidents. Metrics - time to recover from attacks.

- CIS Control 16 - Account Monitoring and Control: Monitor accounts to detect DoS attacks. Metrics - accounts monitored, unauthorized access detected.



## FAIR

**Threat Communities**

- Hacktivists - Hacktivist groups performing ideologically motivated attacks.

- Organized Crime - Criminal groups attacking for financial gain. 

- Nation States - State-sponsored attackers pursuing strategic objectives.

**Loss Factors**

- Productivity Loss - Operational disruption decreasing productivity.

- Response Costs - Expenses for incident handling and recovery.

- Fines and Legal Costs - Regulatory and contractual penalties.

- Reputation Loss - Damage to brand credibility. 


## BSIMM

**Practices**

- Practice 1 - Architecture Analysis: Architect resiliency into system design.

- Practice 9 - Security Testing: Stress test system robustness against DoS.

- Practice 12 - Operational Enablement: Monitor systems for DoS indicators and impact.


## ENISA

**Threats**

- Data poisoning - Flood systems with maliciously crafted data to overwhelm resources.

- Model evasion - Craft inputs to force costly inference, draining resources.

- Logic corruption - Manipulate model logic to trigger unstable behavior.

**Controls**

- Anomaly detection - Detect abnormal spikes in resource usage indicating DoS.

- Rate limiting - Throttle traffic to mitigate resource exhaustion. 

- Input filtering - Filter excessive inputs to maintain operational capacity.


## OAIR

**Vulnerabilities**

- Resource exhaustion - Systems lack protections against resource exhaustion.

- Logic corruption - Models are susceptible to unstable logic.

**Threat Scenarios**

- Flooding attacks - Overwhelm systems with excessive requests. 

- Recursion attacks - Trigger repeated expensive processing.

**Harms**

- Denial of service - Systems become unresponsive to legitimate users.

- Financial loss - Downtime and recovery costs due to DoS incidents.


## ATLAS 

**Tactics**

- Initial Access - Gain initial foothold on systems.

- Execution - Execute malicious payloads and commands.

- Impact - Disrupt system availability and integrity.

**Techniques** 

- Drive-by Compromise - Gain initial access by exploiting web apps.

- Command and Scripting Interpreter - Execute payloads via languages like Python. 

- Process Injection - Inject code into running processes.

- Service Stop - Disable or degrade critical system services. 

**Procedures**

- Fingerprint service vulnerabilities - Identify potential denial of service vectors.

- Craft recursive queries - Engineer queries to cause repeated expensive processing. 

- Amplify network requests - Use techniques to magnify traffic volume.
