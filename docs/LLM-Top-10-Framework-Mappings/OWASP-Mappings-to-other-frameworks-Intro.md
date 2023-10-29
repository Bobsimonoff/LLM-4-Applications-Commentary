By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# Introduction

The OWASP Top 10 provides the top 10 critical security risks for web applications. The OWASP Top 10 for Large Language Model Applications project aims to provide a similar standard set of risks specifically for applications integrated with language models. 

To provide a more comprehensive perspective, we map the OWASP Top 10 LLM risks to several complementary cybersecurity frameworks:

- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) serves as a dictionary of software weaknesses. CWEs provide standardized concepts that classify the types of vulnerabilities that could lead to or underlie the OWASP LLM risks. 

  Mapping relevant CWEs identifies the core weakness classes enabling each OWASP risk.

- [MITRE ATLAS™ framework](https://atlas.mitre.org/) (Adversarial Threat Landscape for Artificial-Intelligence Systems) documents adversary tactics, techniques, and case studies tailored to threats against machine learning systems. 

  It is structured similarly to MITRE ATT&CK® but specific to risks posed to ML environments. Relevant ATT&CK techniques are referenced under each OWASP LLM risk. The following will be explicitly listed in the mnappings

  - **Techniques:** Detail the specific procedures and methods employed by adversaries when exploiting vulnerabilities in ML systems.

  - **Mitigations:** Countermeasures recommended by MITRE ATLAS that can prevent successful technique execution, helping defend ML systems.

- [STRIDE](https://learn.microsoft.com/en-us/previous-versions/commerce-server/ee823878(v=cs.20)?redirectedfrom=MSDN) Spoofing identity, Tampering with data, Repudiation, Information disclosure, Denial of service, Elevation of privilege 

  The STRIDE threat model categorizes risks based on the types of threat action - Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. 

  STRIDE models provide a lens for analyzing risks from the perspective of adversary goals. We will map STRIDE categories to each OWASP LLM risk.

  This multi-framework mapping provides a comprehensive view of risks from the lens of software weaknesses, adversary tactics, and threat actions. The standardized concepts enable structured analysis of risks within these complementary frameworks.


# The Mappings
Files containing Mappings only
- [CWE to OWASP Top 10 for LLM Applications Mapping for all Risks](./OWASP-CWE-mapping.md)
- [ATLAS to OWASP Top 10 for LLM Applications Mapping for all Risks](./OWASP-ATLAS.md) 
- [STRIDE to OWASP Top 10 for LLM Applications Mapping for all Risks](./OWASP-STRIDE.md)


Complete Sections containing OWASP Risk/Vulnerability Summary and all applicable mappings for the OWASP Top 10 item:

- [LLM01: Prompt injection summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM01-PromptInj.md)
- [LLM02: Insecure output handling summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM02-InsecureOutput.md) 
- [LLM03: Training data poisoning summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM03-TrainingDataPoisoning.md)
- [LLM04: Model denial of service summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM04-ModelDoS.md)
- [LLM05: Supply chain vulnerabilities summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM05-SupplyChain.md)
- [LLM06: Sensitive information disclosure summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM06-SensitiveInfoDisclosure.md)
- [LLM07: Insecure plug-in design summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM07-InsecurePlugin.md)
- [LLM08: Excessive agency summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM08-ExcessiveAgency.md)
- [LLM09: Overreliance summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM09-Overreliance.md)
- [LLM10: Model theft summary + all mappings](./OWASP-Mappings-to-other-frameworks-LLM10-ModelTheft.md)




# TBD ... Maybe

- The [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) delivers guidelines and best practices for managing organizational cybersecurity risk. Mapping NIST CSF helps relate the OWASP risks to recognized standards and controls, providing mature mitigation guidance.

- [CIS Controls](https://www.cisecurity.org/controls/) provides prescriptive cybersecurity safeguards and metrics. Mapping CIS Controls gives tangible, measurable security steps to prevent, detect, and respond to the OWASP LLM risks.

- [ENISA Threat Landscape](https://www.enisa.europa.eu/) examines emerging threats to AI systems. Mapping ENISA helps identify OWASP LLM risks unique to the AI domain that may not be highlighted in traditional frameworks.