# LLM-4-Applications-Commentary

## Who am I
I am a Senior Principal Software Engineer and a Fellow at my current company. I am also a core team and founding member of the OWASP Top 10 for Large Language Model applications project. 

I can be found at [Linked in](https://www.linkedin.com/in/bob-simonoff/).

## Why am I here
This repository contains thoughts, notes and observations on the [OWASP Top 10 for Large Language Model Applications Top 10](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications) project and documents. Also note there is a website at [llmtop10.com](https://llmtop10.com/). 

I intend to use this repository as a way of incubating ideas and developing thoughts for proposed inclusion in the project documentation as well as blog articles that I have time to publish.  

## Current Content
**[LLM Monitors](./docs/LLM-monitors.md)** - LLMs work very differently than most traditional software. They are nondeterministic and use natural language for their inputs, outputs, and actions taken. Furthermore, LLMs currently lack explainability to give confidence in the process used to produce answers to prompts. As a result new security monitoring concerns become important while foundational software security monitoring still remains crucial. The goal of this docuement is to highlight monitors implied by LLM security implications to help guide monitoring investments. Keeping these risk areas in mind can inform decisions around tools, metrics, and processes to implement.

**[Risks versus Vulnerabilities](./docs/risks-vs-vulnerabilities.md)** - Realizations when I understood that OWASP Top 10 focuses on risks not vulnerabilities.  this changed my thinking about what should and should not go in the LLM Applicatkns Top 10 list/ 
