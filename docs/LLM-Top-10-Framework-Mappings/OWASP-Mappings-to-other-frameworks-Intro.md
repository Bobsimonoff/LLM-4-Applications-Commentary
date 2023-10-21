By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# Introduction
The OWASP Top 10 provides the top 10 critical security risks for web applications. The OWASP Top 10 for Large Language Model Applications project aims to provide a similar standard set of risks specifically for applications integrated with language models. To augment these LLM risks, we will map the OWASP Top 10 for LLM applications to several complementary cybersecurity frameworks for a more holistic perspective:

- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) serves as a dictionary of software weaknesses. CWEs provide standardized concepts that classify the types of weaknesses related to the OWASP LLM risks. Mapping CWEs helps identify the core vulnerability types that could lead to or underlie the OWASP risks.

- [MITRE ATT&CK®](https://attack.mitre.org/) is a security framework that provides a structured approach to understanding and categorizing the tactics and techniques used by adversaries during cyberattacks and the mitigations that can help prevent them. 

  - **Tactics**: These represent high-level objectives or goals that adversaries aim to achieve during an attack. They help in understanding the strategic aspect of an attack, such as gaining initial access, maintaining persistence, or exfiltrating data.

  - **Techniques**: Under each tactic, MITRE ATT&CK® documents specific techniques employed by attackers. These techniques delve into the more detailed methods and procedures adversaries use to achieve their tactical goals. For example, under the "Execution" tactic, a technique might be "Spear Phishing."

  - **Mitigations**: Mitigations are countermeasures and best practices that organizations can implement to defend against or reduce the effectiveness of the documented techniques. These are crucial for improving security posture and mitigating the risk associated with each technique.


- [ATLAS™](https://atlas.mitre.org/) (Adversarial Threat Landscape for Artificial-Intelligence Systems) is a knowledge base that focuses on adversary tactics, techniques, and case studies for machine learning (ML) systems. It is structured similarly to MITRE ATT&CK® but tailored to the unique threats posed to ML systems.

  - **Tactics:** ATLAS™ outlines high-level objectives or tactics that adversaries aim to achieve when targeting ML systems, providing strategic insights into their goals.

  - **Techniques:** Under each tactic, ATLAS™ documents specific techniques employed by adversaries to exploit vulnerabilities in ML systems, detailing their methods and procedures.

  - **Mitigations:** ATLAS™ also includes mitigations, which are security concepts and technologies that can prevent or mitigate the successful execution of a technique or sub-technique. These countermeasures help defend ML systems against threats.

- The [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) delivers guidelines and best practices for managing organizational cybersecurity risk. Mapping NIST CSF helps relate the OWASP risks to recognized standards and controls, providing mature mitigation guidance.

- [CIS Controls](https://www.cisecurity.org/controls/) provides prescriptive cybersecurity safeguards and metrics. Mapping CIS Controls gives tangible, measurable security steps to prevent, detect, and respond to the OWASP LLM risks.

- [ENISA Threat Landscape](https://www.enisa.europa.eu/) examines emerging threats to AI systems. Mapping ENISA helps identify OWASP LLM risks unique to the AI domain that may not be highlighted in traditional frameworks.


This cross-framework mapping aims to connect the dots between OWASP risks and complementary frameworks. 

![alt text](./images/Security-Frameworks-Template.png)


The following areroughed in and ready for discussion.

1. **Weaknesses**
   - CWE weakness types

2. **Threats & Attack Vectors**
   - MITRE ATT&CK® tactics and techniques
   - ATLAS™ tactics and techniques

3. **Controls & Mitigations**
   - ATT&CK® Mitigations
   - ATLAS™ Mitigation


Sections:

- [LLM01: Prompt injection](./OWASP-Mappings-to-other-frameworks-LLM01-PromptInj.md)
- [LLM02: Insecure output handling](./OWASP-Mappings-to-other-frameworks-LLM02-InsecureOutput.md) 
- [LLM03: Training data poisoning](./OWASP-Mappings-to-other-frameworks-LLM03-TrainingDataPoisoning.md)
- [LLM04: Model denial of service](./OWASP-Mappings-to-other-frameworks-LLM04-ModelDoS.md)
- [LLM05: Supply chain vulnerabilities](./OWASP-Mappings-to-other-frameworks-LLM05-SupplyChain.md)
- [LLM06: Sensitive information disclosure](./OWASP-Mappings-to-other-frameworks-LLM06-SensitiveInfoDisclosure.md)
- [LLM07: Insecure plug-in design](./OWASP-Mappings-to-other-frameworks-LLM07-InsecurePlugin.md)
- [LLM08: Excessive agency](./OWASP-Mappings-to-other-frameworks-LLM08-ExcessiveAgency.md)
- [LLM09: Overreliance](./OWASP-Mappings-to-other-frameworks-LLM09-Overreliance.md)
- [LLM10: Model theft](./OWASP-Mappings-to-other-frameworks-LLM10-ModelTheft.md)
