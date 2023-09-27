# LLM-4-Applications-Commentary

## Who am I
I am a Senior Principal Software Engineer and a Fellow at my current company. I am also a core team and founding member of the OWASP Top 10 for Large Language Model applications project. 

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


## Why am I here
This repository contains thoughts, notes and observations on the [OWASP Top 10 for Large Language Model Applications Top 10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications) project and documents. Also note there is a website at [llmtop10.com](https://llmtop10.com/). 

I intend to use this repository as a way of incubating ideas and developing thoughts for proposed inclusion in the project documentation as well as blog articles that I have time to publish.  

## Current Content
**[LLM Monitors](./docs/LLM-Monitors.md)** - LLMs work very differently than most traditional software. They are nondeterministic and use natural language for their inputs, outputs, and actions taken. Furthermore, LLMs currently lack explainability to give confidence in the process used to produce answers to prompts. As a result new security monitoring concerns become important while foundational software security monitoring still remains crucial. The goal of this docuement is to highlight monitors implied by LLM security implications to help guide monitoring investments. Keeping these risk areas in mind can inform decisions around tools, metrics, and processes to implement.

**[Risks versus Vulnerabilities](./docs/risks-vs-vulnerabilities.md)** - Realizations when I understood that OWASP Top 10 focuses on risks not vulnerabilities.  this changed my thinking about what should and should not go in the LLM Applicatkns Top 10 list.

**[The Promise of Generative AI](./docs/The-promise-of-generative-ai.md)** - This is a high level article I wrote for my company's blog site. It speaks to executive management about the balance between the promise of Generative AI and the new security landscape that comes with it. 

**[Exploring ChatGPT Hallucinations and Confabulation through the 6 Degrees of Kevin Bacon Game](./docs/2023-09-08-exploring-chatgpt-hallucinations-and-confabulation.markdown)** - An article describing an experiment that I did to explore the idea of hallucinations using the game 6° of Kevin Bacon. 

**[Taking Text Embedding and Cosine Similarity for a Test Drive](./docs/2023-09-13-text-embedding-and-cosine-similarity.markdown)** - documentation of some experiments I did on OpenAIs embedding algorithm. The goal was to see whether the embedding algorithm was overly sensitive to upper versus lower case, synonyms, punctuation, etc.  


**[Mappings to/from OWASP Top 10 for LLM Applications to other Security Frameworks](./docs/LLM-Top-10-Framework-Mappings/OWASP-Mappings-to-other-frameworks-Intro.md)** - mapping between the OWASP Top 10 for Large Language Models and the following frameworks:
- The Common Weakness Enumeration (CWE) serves as a dictionary of software weaknesses. CWEs provide standardized concepts that classify the types of weaknesses related to the OWASP LLM risks. Mapping CWEs helps identify the core vulnerability types that could lead to or underlie the OWASP risks.

- MITRE ATT&CK is a knowledge base of real-world adversary tactics and techniques. Mapping ATT&CK techniques provides insights into how adversaries could actually exploit the OWASP LLM risks in practice. This intelligence can inform threat modeling and defenses.

- The NIST Cybersecurity Framework delivers guidelines and best practices for managing organizational cybersecurity risk. Mapping NIST CSF helps relate the OWASP risks to recognized standards and controls, providing mature mitigation guidance.

- CIS Controls provides prescriptive cybersecurity safeguards and metrics. Mapping CIS Controls gives tangible, measurable security steps to prevent, detect, and respond to the OWASP LLM risks.

- FAIR supports quantitative cyber risk analysis. Mapping FAIR provides data-driven risk evaluation of the potential loss impacts related to the OWASP LLM risks.

- BSIMM documents real-world software security best practices. Mapping BSIMM helps relate the OWASP risks to proven security processes and maturity benchmarks.

- ENISA Threat Landscape examines emerging threats to AI systems. Mapping ENISA helps identify OWASP LLM risks unique to the AI domain that may not be highlighted in traditional frameworks.

- OAIR Framework identifies risks across the AI system lifecycle. Mapping OAIR relates the OWASP risks to AI-specific vulnerabilities and harms providing visibility into AI relevance.

- ATLAS documents observed real-world attacks against AI. Mapping ATLAS builds understanding of how the OWASP risks manifest in actual AI threat scenarios based on evidence.
