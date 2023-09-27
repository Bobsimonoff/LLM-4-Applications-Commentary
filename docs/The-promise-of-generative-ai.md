# Unmasking the Risks of Generative AI

*Bob Simonoff, September 18, 2023*
- LinkedIn at https://www.linkedin.com/in/bob-simonoff
- medium/com at https://medium.com/@bob.simonoff
- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


This article was originally published at [The Promise of Generative AI] (https://blog.blueyonder.com/unmasking-the-risks-of-generative-ai/)

As we’ve explored in previous posts, generative AI holds tremendous promise across many industries and disciplines. However, as with any powerful new technology, it also brings new security risks. In this blog, we dive into the emerging generative AI threat landscape and the steps organizations can take to securely adopt these tools, focusing specifically on areas of data and system security.

## How is Generative AI Different?

To grasp how generative AI changes the threat landscape, we must first consider how these new systems differ from traditional systems that have served as the backbone of supply chain systems for the past 50 years. The Top 5 differences are:

- **Security tools and practices for generative AI are still maturing compared to technologies already available for databases.** Database security vulnerabilities like SQL injection are well understood given decades of focus. Developers are extensively trained on these, and robust auditing tools are integrated into CI/CD pipelines. However, the generative AI journey is just beginning, with threat modeling and tools still emerging.

- **Generative AI delivers novel insights rather than merely retrieving records.** Whereas databases return data that they have previously stored, possibly with transformations or calculations, generative AI synthesizes novel data based on its training. This is analogous to an analyst generating insights rather than a clerk fetching records.

- **Formal programming languages are predictable and unambiguous, unlike the nuances and ambiguity present in natural language used by generative AI.** Databases utilize formal languages, such as SQL, which have a formal understood syntax to access data. A given SQL statement, taken in the context of the already stored data will always produce the same result. However, generative AI utilizes natural “everyday” language – with all its nuance and ambiguity – for all input and output. Like two people negotiating a contract, misunderstandings can occur between humans and AIs. Furthermore, generative AI’s outputs are non-deterministic, meaning identical inputs can yield distinct results in phrasing, wording, or meaning.

- **Generative AI may lack traceability and auditing capabilities versus databases that have tighter controls.** With databases, authorized users can easily audit stored data and trace its origin. In contrast, generative AI models store knowledge in a neural network in a form that is incomprehensible to most people. Additionally, there are currently no robust techniques to audit the models’ acquired “knowledge” and the potential biases from its training data.

- **Generative AI currently has fewer built in data access controls compared to databases.** Databases have robust authorization controls governing data access. However, generative AI currently lacks such built-in controls – authenticated users may access any data.
Examining the differences between traditional systems and generative AI reveals new security vulnerabilities and necessary mitigations, which can be categorized into three key domains: securing sensitive data, securing from malicious use, and properly governing AI agents and plug-ins.

## Understanding Your Risk Factors and What It Takes to Secure Generative AI

When a company entrusts its software system with sensitive data there is an expectation that all such information will be fully protected from unauthorized access, modification, or exfiltration. While traditional vulnerabilities remain a concern, the unique nature of generative AI introduces additional risks that must be guarded against.

In addition to protecting sensitive data, it is also important that the generative AI meets its service level agreements (SLAs), including availability, scalability, performance, reliability, and disaster recovery. The AI must also not negatively affect the SLAs of downstream systems. Understanding these vulnerabilities and mitigating them from creating security exposures in generative AI-based systems will pave the way for the realization of the tremendous promise of generative AI.


Some key vulnerabilities to look out for include:

- Prompt Injection: Well-crafted inputs can trick the AI into revealing confidential data or executing harmful actions.
- Insecure Output Handling: Blindly using AI outputs without scrutiny opens the door for system exploits like unauthorized data access.
- Training Data Poisoning: Manipulated training data can corrupt the AI, introducing dangerous biases or backdoors.
- Model Denial of Service: Attackers can overwhelm generative AIs with complex requests, degrading or disabling service.
- Excessive Agency: Giving the AI uncontrolled autonomy may allow it to make damaging decisions based on faulty reasoning.
- Insecure Plugin Design: Third-party AI components can introduce severe vulnerabilities through unsafe data handling.
- Supply Chain Compromise: If any third-party tools or data sources get hacked, it can create risk within the generative AI application.
- Sensitive Data Leakage: The AI may reveal sensitive customer or business data it was exposed to during its training.

Luckily, some preventive measures mitigate multiple types of vulnerabilities. For example, securing against prompt injection and training data poisoning also helps reduce the chance of sensitive information disclosure. A robust identity and access framework with a well thought out access control implementation is prerequisite for protecting against excessive agency attacks. And the traditional security measures that we’ve been practicing since the dawn of computing provide the foundation upon which generative AI protections are built.

With a vigilant security posture and defense-in-depth measures in place, companies can realize the tremendous potential of generative AI while safeguarding systems and sensitive information. Securing generative AI necessitates a multi-layered approach encompassing data, model training and fine-tuning, infrastructure, identities, access control, and, importantly, diligence when evaluating vendors. Moreover, implementing comprehensive governance, rigorous access control, input and output controls, monitoring, sandboxing, and well thought out development and operations is imperative.

## Assessing Your Generative AI Security Position Before Diving In

When evaluating solutions, whether incorporating generative AI directly into in-house built solutions or acquiring them from vendors that have incorporated generative AI, asking the right questions is paramount for ensuring good security practices. The questions can help guide conversations to determine if adequate protections have been implemented. Consider the following topic areas:

- Supply Chain Security: Be sure to request third-party audits, penetration testing, and code reviews and understand how third-party providers are evaluated – both initially and on an ongoing basis.

- Data Security: Look to understand how data is classified and protected based on sensitivity, including personal and proprietary business data. How are user permissions managed and what safeguards are in place?

- Access Control: With a vigilant security posture, including least privilege access controls, and defense-in-depth measures in place, companies can realize the tremendous potential of generative AI while safeguarding systems and sensitive information.

- Training Pipeline Security: Be sure to look for rigorous control around training data governance, pipelines, models, and algorithms. What protections are in place to protect against data poisoning?

- Input and Output Security: Evaluate input validation methods, as well as how outputs are filtered, sanitized, and approved.

- Infrastructure Security: How often does the vendor perform resilience testing? What are their SLAs in terms of availability, scalability, and performance?

- Monitoring and Response: Discuss workflows, monitoring, and responses to better understand how they are automated, logged, and audited. Also, be sure that the audit records are secure, especially if they are likely to contain confidential or personal information.  

- Compliance: Confirm the vendor is in compliance with regulations like GDPR and CCPA and that certifications like SOC2, ISO 27001, etc., have been achieved. Understand where data will be collected, stored, and used to ensure country-specific or state-specific requirements are met.

## The Promise of Generative AI

Generative AI brings immense potential, with new applications being discovered almost daily. While current capabilities are already profound, even greater potential lies ahead. However, with this promise comes risks requiring prudent, ongoing governance. By collaborating across teams and evaluating vendors, organizations can balance these emerging risks and future innovation. Security establishes trust and enables progress, and the guidance above provides a starting point for organizations to assess and address these risks. With diligence, companies can adopt generative AI early – and securely – to get a head start on realizing generative AI’s benefits now and in the future. The key is balancing innovation and governance through continuous collaboration between security and AI teams.