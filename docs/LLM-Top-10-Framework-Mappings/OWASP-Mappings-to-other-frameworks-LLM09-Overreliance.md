By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM09: Overreliance

### Summary

Failing to critically assess LLM outputs can lead to compromised decision making, security vulnerabilities, and legal liabilities.

### Description

Overreliance can occur when an Large Language Model produces erroneous information and provides it in an authoritative manner. While LLMs can produce creative and informative content, they can also generate content that is factually incorrect, inappropriate or unsafe. This is referred to as hallucination or confabulation. When people or systems trust this information without oversight or confirmation it can result in a security breach, misinformation, miscommunication, legal issues, and reputational damage.


### Common Examples of Risk

1. LLM gives inaccurate information confidently, misleading users. 

2. LLM suggests insecure code, introducing vulnerabilities.


### Prevention and Mitigation Strategies

1. Continuously monitor and manually review LLM outputs.

2. Validate outputs by comparing to trusted external sources.

3. Use automated validations against known facts.

4. Fine-tune models to improve quality. 

5. Break complex tasks into smaller pieces across multiple agents.

6. Clearly communicate risks and limitations of LLMs.

7. Design interfaces that promote safe and responsible LLM use.

8. Establish secure coding practices when using LLM-generated code.

9. Implement human-in-the-loop approval for high risk or sensitive actions. 

10. Employ multiple levels of verification, not blindly trusting LLM outputs.

**Example High-Risk Scenarios:**

1. News org relies on LLM, spreading misinformation.

2. LLM plagiarizes, hurting trust.

3. Over-reliance on LLM coding suggestions introduces vulnerabilities. 

4. Developer adds malicious package, not verifying LLM suggestion.


### Common Weakness Enumeration (CWE)

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: This weakness relates to the inclusion of functionality from an untrusted control sphere, which can lead to security issues.

  Justification: Inclusion of functionality from untrusted sources, particularly when guided by LLM suggestions, can amplify the risks associated with overreliance, leading to security vulnerabilities or even breaches.

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation
  
  Description: Weakness in input validation can allow an attacker to exploit the system.
  
  Justification: Since LLMs often generate outputs based on inputs, failing to validate those inputs can contribute to overreliance on misleading or harmful outputs.


### Techniques

#### MITRE ATT&CK® Techniques

- No changes made due to no suggested additions

#### MITRE ATLAS™ Techniques

- [AML.T0045](https://attack.mitre.org/techniques/AML.T0045/): ML Intellectual Property Theft

  Description: Excessive trust in LLM outputs enables adversaries to more readily manipulate users into improperly disclosing or mishandling intellectual property and other confidential data assets by providing manipulated information that is incorrectly treated as authoritative without proper verification.

  Justification: Overreliance on LLM outputs not only exposes intellectual property to theft but also amplifies the risk of disclosing sensitive or classified information. Users may unknowingly act on manipulated or incorrect LLM suggestions.

- [AML.T0071](https://attack.mitre.org/techniques/AML.T0071/): Excessive Trust in Model Outputs

  Description: Users may trust LLM outputs for decision-making in security-critical scenarios without proper validation.

  Justification: Overreliance on LLM outputs can lead to compromised decision-making and security vulnerabilities, making it essential to address this in the ATLAS techniques.


### Mitigations

#### MITRE ATT&CK® Mitigations

- [M1051](https://attack.mitre.org/mitigations/M1051/): Regular Expression Limitations

  Description: Use regular expressions to limit and validate inputs and outputs to and from LLMs.

  Justification: Implementing regular expression checks can mitigate the risks associated with accepting or generating unsafe or incorrect data, thus countering overreliance on LLMs.

#### MITRE ATLAS™ Mitigations  

- [AML.M0021](https://attack.mitre.org/mitigations/AML.M0021/): Model Monitoring

  Description: Continuously monitor model outputs for anomalies or suspicious activities to alert users or administrators.

  Justification: Real-time monitoring can serve as an early warning system, thereby reducing the risk associated with overreliance on LLM outputs.

