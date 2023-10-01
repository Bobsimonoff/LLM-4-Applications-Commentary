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

- [CWE-119](https://cwe.mitre.org/data/definitions/119.html): Improper Restriction of Operations within the Bounds of a Memory Buffer

  Description: This weakness occurs when software does not properly restrict operations within the bounds of a memory buffer, potentially leading to buffer overflows.

  Justification: CWE-119 is relevant because blindly using unchecked LLM-generated code could result in buffer overflows or memory-related vulnerabilities, which can compromise security and stability.

- [CWE-347](https://cwe.mitre.org/data/definitions/347.html): Improper Verification of Cryptographic Signature

  Description: This weakness involves the improper verification of cryptographic signatures, which can lead to the use of manipulated or tampered data.

  Justification: CWE-347 is applicable as relying on unsigned LLM content without proper verification can result in the use of manipulated or tampered outputs, leading to security risks.

- [CWE-707](https://cwe.mitre.org/data/definitions/707.html): Improper Enforcement of Message Integrity During Transmission in a Communication Channel

  Description: This weakness relates to the improper enforcement of message integrity during transmission, potentially leading to integrity issues in communication.

  Justification: CWE-707 is relevant because relying on unvalidated LLM communications can introduce integrity issues in the outputs, which can lead to misinformation or security breaches.

- [CWE-839](https://cwe.mitre.org/data/definitions/839.html): Numeric Range Comparison Without Minimum Check

  Description: This weakness occurs when software performs a numeric range comparison without first checking the minimum value, potentially accepting invalid values.

  Justification: CWE-839 is applicable because relying on unvalidated LLM numerical outputs without checking the minimum values poses risks of accepting invalid or incorrect values.

- [CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization

  Description: This weakness involves missing authorization checks, allowing unauthorized access or actions.

  Justification: CWE-862 is relevant as blind reliance on LLM outputs without proper authorization checks could lead to unauthorized actions or access, compromising security.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere

  Description: This weakness relates to the inclusion of functionality from an untrusted control sphere, which can lead to security issues.

  Justification: CWE-829 is applicable because relying on LLM outputs without validating the functionality can risk including untrusted code or logic, potentially leading to security vulnerabilities.

- [CWE-554](https://cwe.mitre.org/data/definitions/554.html): ASP.NET Misconfiguration: Not Understanding the Implications of Invoking Unvalidated Methods

  Description: This weakness involves the misconfiguration of ASP.NET applications due to not understanding the implications of invoking unvalidated methods.

  Justification: CWE-554 is relevant because invoking unchecked LLM-generated methods can lead to misconfiguration issues in applications, potentially introducing security vulnerabilities.

- [CWE-908](https://cwe.mitre.org/data/definitions/908.html): Use of Uninitialized Resource

  Description: This weakness occurs when software uses an uninitialized resource, potentially leading to unpredictable behavior or vulnerabilities.

  Justification: CWE-908 is applicable as reliance on unvalidated, uninitialized LLM outputs can pose risks, including unpredictable behavior or vulnerabilities.

- [CWE-1053](https://cwe.mitre.org/data/definitions/1053.html): Missing Documentation for Design

  Description: This weakness involves missing documentation for the design, which can lead to misunderstandings and inadequate monitoring of software components.

  Justification: CWE-1053 is relevant if design documentation lacks details on monitoring and verifying LLM outputs, as this can enable blind trust and inadequate oversight.

- [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html): Incomplete Documentation of Program Execution

  Description: This weakness occurs when there is incomplete documentation of program execution, which can lead to misunderstandings and inadequate monitoring of software components.

  Justification: CWE-1059 is applicable if execution documentation lacks details on monitoring and verifying LLM outputs, as this can enable blind trust and inadequate oversight.


### MITRE ATT&CK® Techniques

- [T1566](https://attack.mitre.org/techniques/T1566/) - Phishing

  Description: Phishing is the practice of deploying malicious messages to users to deceive them into taking actions that may compromise security. It often involves sending deceptive emails or messages with links or attachments.

  Justification: T1566 is relevant because attackers could deploy phishing campaigns that distribute LLM-generated misinformation. If users blindly trust the information provided by LLMs, they may be more susceptible to phishing attacks that exploit this trust.

- [T1572](https://attack.mitre.org/techniques/T1572/) - Protocol Tunneling

  Description: Protocol tunneling involves using other protocols to bypass network restrictions or filters. Attackers use this technique to evade detection and exploit network vulnerabilities.

  Justification: T1572 is related to the risk because it could allow manipulated LLM outputs to bypass security filters and restrictions. If users blindly trust LLM-generated content without proper validation, attackers might leverage protocol tunneling to introduce malicious content or misinformation into the network, taking advantage of the blind trust.


### MITRE ATLAS™ Techniques

- AML.T0011: User Execution  

  Description: Adversaries may manipulate users into executing unsafe actions or accessing malicious content based on incorrect information generated by an LLM that is over-relied upon. If users trust LLM outputs without proper validation, they may unknowingly execute unsafe code or actions that have been socially engineered by the adversary to take advantage of that blind trust.

  Justification: User execution of unsafe actions guided by over-reliance on incorrect LLM outputs enables adversaries to more readily manipulate user behavior through social engineering tactics designed to exploit the excessive trust placed in the LLM.

- AML.T0045: ML Intellectual Property Theft

  Description: Excessive trust in LLM outputs enables adversaries to more readily manipulate users into improperly disclosing or mishandling intellectual property and other confidential data assets by providing manipulated information that is incorrectly treated as authoritative without proper verification.

  Justification: Over-reliance on LLM outputs allows adversaries to more easily exploit users' excessive trust to steal IP and data through user actions guided by misleading LLM information.

- AML.T0046: Spamming ML System with Chaff Data

  Description: By overwhelming an LLM with excessive useless input designed to increase inaccurate outputs, an adversary can degrade the model's reliability over time, increasing the occurrence of incorrect outputs that users may over-rely on without proper verification.

  Justification: Spamming the LLM with useless chaff inputs manipulates the model to produce more inaccurate outputs, which users may blindly trust due to over-reliance, enabling adversary exploitation through the increased unreliable outputs.


### MITRE ATT&CK® Mitigations

- [M1043](https://attack.mitre.org/mitigations/M1043/) - Isolate System or Network

  Description: This mitigation involves isolating systems or networks to prevent the lateral movement of unreliable data generated through poisoning or other malicious activities.

  Justification: M1043 is related to the risk because it suggests isolating systems that contain Large Language Models (LLMs) to prevent the spread of potentially compromised or unreliable LLM-generated data. Isolation can help contain the impact of misinformation or malicious content generated by LLMs, reducing the risk of it spreading throughout the network.

- [M1034](https://attack.mitre.org/mitigations/M1034/) - Account Use Policies

  Description: Account use policies define acceptable use policies around verifying LLM outputs, which could discourage blind trust in systems.

  Justification: M1034 is relevant because it emphasizes the importance of defining and enforcing account use policies. By implementing policies that require verification and validation of LLM outputs before trusting them, organizations can reduce the risk of overreliance on potentially incorrect or malicious information generated by LLMs. These policies encourage responsible and cautious use of LLM-generated content.


### MITRE ATLAS™ Mitigations

- AML.M0018: User Training
  Description: Educate ML model developers on secure coding practices and ML vulnerabilities.
