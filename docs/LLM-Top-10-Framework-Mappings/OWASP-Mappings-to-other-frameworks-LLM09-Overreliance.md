By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM09: Overreliance

## Summary
Failing to critically assess LLM outputs can lead to compromised decision making, security vulnerabilities, and legal liabilities.

## Description

Blindly trusting LLM outputs without proper validation can lead to the dissemination of misinformation, integration of vulnerabilities, and other issues.  

Failing to scrutinize outputs allows attackers to manipulate prompts or poison training data to trick the LLM into generating plausible but inaccurate or biased content. Overreliance on unchecked model responses can result in legal liabilities, financial losses, reputational damage, and security risks.

Prevention requires continuous monitoring, oversight, and multiple levels of verification. Outputs should be validated against trusted external sources and checked for consistency across models. Automated validation tools and vigilant human review are essential. Risks should be clearly communicated and UIs designed to promote responsible LLM use. Establishing secure coding practices is critical when relying on LLM-generated code. Reducing overreliance through defense-in-depth and critical evaluation is key to mitigating risks.


## Common Weakness Enumeration (CWE)

- [CWE-119](https://cwe.mitre.org/data/definitions/119.html): Improper Restriction of Operations within the Bounds of a Memory Buffer - Applicable as blindly using unchecked LLM-generated code risks buffer overflows.

- [CWE-347](https://cwe.mitre.org/data/definitions/347.html): Improper Verification of Cryptographic Signature - Applicable as reliance on unsigned LLM content could lead to use of manipulated outputs.

- [CWE-707](https://cwe.mitre.org/data/definitions/707.html): Improper Enforcement of Message Integrity During Transmission in a Communication Channel - Applicable as reliance on unvalidated LLM communications risks integrity issues in outputs. 

- [CWE-839](https://cwe.mitre.org/data/definitions/839.html): Numeric Range Comparison Without Minimum Check - Applicable as reliance on unvalidated LLM numerical outputs poses risks of accepting invalid values.

- [CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization - Applicable as blind reliance on LLM outputs could lead to missing authorization checks before taking impactful actions.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as reliance on LLM outputs without validating functionality risks inclusion of untrusted code or logic.

- [CWE-554](https://cwe.mitre.org/data/definitions/554.html): ASP.NET Misconfiguration: Not Understanding the Implications of Invoking Unvalidated Methods - Applicable as invoking unchecked LLM-generated methods risks misconfiguration issues. 

- [CWE-908](https://cwe.mitre.org/data/definitions/908.html): Use of Uninitialized Resource - Applicable as reliance on unvalidated, uninitialized LLM outputs poses risks.

- [CWE-1053](https://cwe.mitre.org/data/definitions/1053.html): Missing Documentation for Design - Applicable if design docs lack details on monitoring and verifying LLM outputs, enabling blind trust.

- [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html): Incomplete Documentation of Program Execution - Applicable if execution docs lack details on monitoring and verifying LLM outputs, enabling blind trust.

## ATT&CK Techniques

- [T1566](https://attack.mitre.org/techniques/T1566/) - Phishing. Deploys malicious messages to users which could distribute LLM-generated misinformation via phishing.

- [T1572](https://attack.mitre.org/techniques/T1572/) - Protocol Tunneling. Uses other protocols to bypass restrictions which could allow manipulated LLM outputs to bypass filters exploiting blind trust.

## MITRE ATLAS Techniques

- AML.T0019: Publish Poisoned Data. Training models on poisoned data from compromised sources could lead to unreliable outputs. Poisons model reliability.

## ATT&CK Mitigations

- [M1043](https://attack.mitre.org/mitigations/M1043/) - Isolate System or Network. Isolates systems containing LLMs to prevent lateral movement of unreliable data generated through poisoning.

- [M1034](https://attack.mitre.org/mitigations/M1034/) - Account Use Policies. Defines acceptable use policies around verifying LLM outputs which could discourage blind trust in systems.

## MITRE ATLAS Mitigations

- AML.M0002: Passive ML Output Obfuscation. Decrease output fidelity which reduces appearance of authority and reliability, discouraging blind trust.

- AML.M0015: Adversarial Input Detection. Detect and filter unreliable queries designed to manipulate outputs. Identifies poisoning attempts. 

- AML.M0003: Model Hardening. Make models more robust to generating unreliable outputs. Hardens model reliability. 

- AML.M0014: Verify ML Artifacts. Detect artifacts modified to produce unreliable outputs by verifying integrity. Checks for poisoning.

- AML.M0018: User Training. Train users to critically verify LLM outputs instead of blindly trusting them. Reduces overreliance.

- AML.M0007: Sanitize Training Data. Remove data leading to unreliable outputs. Addresses data poisoning impacting outputs.

- AML.M0016: Vulnerability Scanning. Scan for flaws enabling unreliable outputs. Finds issues introducing unreliability to address.

- AML.M0001: Limit Model Artifact Release. Reduce public information that could help craft unreliable outputs. Limits available knowledge to leverage.