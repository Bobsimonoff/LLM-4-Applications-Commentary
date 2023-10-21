Bob Simonoff, September 23, 2023

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# Introduction
The OWASP Top 10 provides the top 10 critical security risks for web applications. The OWASP Top 10 for Large Language Model Applications project aims to provide a similar standard set of risks specifically for applications integrated with language models. To augment these LLM risks, we will map the OWASP Top 10 for LLM applications to several complementary cybersecurity frameworks for a more holistic perspective:

- The [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) serves as a dictionary of software weaknesses. CWEs provide standardized concepts that classify the types of weaknesses related to the OWASP LLM risks. Mapping CWEs helps identify the core vulnerability types that could lead to or underlie the OWASP risks.

- [MITRE ATT&CK®](https://attack.mitre.org/) is a knowledge base of real-world adversary tactics and techniques. Mapping ATT&CK® techniques provides insights into how adversaries could actually exploit the OWASP LLM risks in practice. This intelligence can inform threat modeling and defenses.

- The [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) delivers guidelines and best practices for managing organizational cybersecurity risk. Mapping NIST CSF helps relate the OWASP risks to recognized standards and controls, providing mature mitigation guidance.

- [CIS Controls](https://www.cisecurity.org/controls/) provides prescriptive cybersecurity safeguards and metrics. Mapping CIS Controls gives tangible, measurable security steps to prevent, detect, and respond to the OWASP LLM risks.

- [FAIR](https://www.riskmanagementinsight.com/) supports quantitative cyber risk analysis. Mapping FAIR provides data-driven risk evaluation of the potential loss impacts related to the OWASP LLM risks.

- [BSIMM](https://www.bsimm.com/) documents real-world software security best practices. Mapping BSIMM helps relate the OWASP risks to proven security processes and maturity benchmarks.

- [ENISA Threat Landscape](https://www.enisa.europa.eu/) examines emerging threats to AI systems. Mapping ENISA helps identify OWASP LLM risks unique to the AI domain that may not be highlighted in traditional frameworks.

- [OAIR Framework](https://www.operationalizingai.org/) identifies risks across the AI system lifecycle. Mapping OAIR relates the OWASP risks to AI-specific vulnerabilities and harms providing visibility into AI relevance.

- [ATLAS™](https://ATLAS™.mitre.org/) documents observed real-world attacks against AI. Mapping ATLAS™ builds understanding of how the OWASP risks manifest in actual AI threat scenarios based on evidence.


![alt text](./LLM-Top-10-Framework-Mappings/images/Security-Frameworks-Template.png)



The following is a tentative classification of where part of the various frameworks could be places with respect to their security context.

1. **Vulnerabilities & Weaknesses**
   - CWE weakness types
   - OAIR vulnerabilities
   - Arc: exposes OWASP Risk

2. **Threats & Attack Vectors**
   - MITRE ATT&CK® tactics and techniques
   - ATLAS™ tactics, techniques, and procedures
   - ENISA threats
   - OAIR Threat Scenarios
   - Arc: targets OWASP Risk

3. **Threat Actors**
   - FAIR threat communities
   - Arc: exploit OWASP Risk

4. **Impacts & Harms**
   - OAIR harms
   - FAIR loss factors
   - Arc: result from OWASP Risk

5. **Controls & Mitigations**
   - CIS Controls Safeguards
   - ENISA controls
   - NIST CSF Subcategories
   - Arc: mitigates OWASP Risk

6. **Processes & Practices**
   - BSIMM software security practices
   - BSIMM metrics
   - CIS Controls metrics
   - Arc: manages OWASP Risk

7. **Detection Strategies**
   - NIST CSF detect function
   - MITRE ATT&CK® Detection
   - Arc: addresses OWASP Risk

8. **Response Strategies**
   - NIST CSF respond function
   - NIST CSF recover function
   - MITRE ATT&CK® Response
   - Arc: manages OWASP Risk


Sections:

- [LLM01: Prompt injection](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM01-PromptInj.md)
- [LLM02: Insecure output handling](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM02-InsecureOutput.md) 
- [LLM03: Training data poisoning](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM03-TrainingDataPoisoning.md)
- [LLM04: Model denial of service](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM04-ModelDoS.md)
- [LLM05: Supply chain vulnerabilities](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM05-SupplyChain.md)
- [LLM06: Sensitive information disclosure](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM06-SensitiveInfoDisclosure.md)
- [LLM07: Insecure plug-in design](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM07-InsecurePlugin.md)
- [LLM08: Excessive agency](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM08-ExcessiveAgency.md)
- [LLM09: Overreliance](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM09-Overreliance.md)
- [LLM10: Model theft](./LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-LLM10-ModelTheft.md)
