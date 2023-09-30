By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM10: Model Theft

### Summary
Unauthorized access to proprietary large language models risks theft, competitive advantage, and dissemination of sensitive information.

### Description

Unauthorized access and theft of proprietary large language models can undermine competitive advantage and lead to data breaches. 

Attackers can exploit weak access controls, insufficient monitoring, vulnerable components, and insider threats to infiltrate systems and steal valuable LLMs. Successful attacks enable adversaries to acquire sensitive data, launch advanced prompt engineering attacks, and financially damage organizations.

Prevention requires strong access controls, network security, authentication, and monitoring. LLMs should have restricted network access and regular auditing of related logs and activities. Robust MLOps governance, input filtering, and output encoding can help prevent extraction attacks. Physical security and watermarking also help mitigate risks. Proactively securing LLMs against theft is crucial for maintaining confidentiality of intellectual property.


### Common Examples of Risk

1. Attacker exploits infrastructure vulnerabilities, gaining unauthorized access to LLM repositories due to misconfigurations.
2. Centralized ML Model Inventory enforces access controls, authentication, and monitoring for production ML models.
3. Insider threats involve employees leaking LLM-related artifacts.
4. Attacker queries the model API to create a shadow model through crafted inputs.
5. Malicious actors bypass input filtering, performing side-channel attacks to harvest model data.
6. Attackers fine-tune models by querying LLMs with numerous prompts.
7. **_Functional model replication_** creates functional equivalents using LLMs through prompts.

Stolen models can facilitate adversarial attacks, including unauthorized data access.

### Prevention and Mitigation Strategies

1. Implement strong access controls and authentication to restrict unauthorized LLM access.
2. Limit LLM's network access and monitor access logs.
3. Regularly audit access logs.
4. Automate MLOps deployment with governance.
5. Mitigate prompt injection risks.
6. Apply rate limiting or filters for data exfiltration prevention.
7. Deploy adversarial robustness training and enhance physical security.
8. Use watermarking in LLMs.

### Example Attack Scenarios

1. Attacker exploits infrastructure vulnerabilities to steal LLMs, using them to compete or extract sensitive data.
2. Disgruntled employees leak LLMs, increasing the risk of attacks.
3. Attacker crafts precise inputs to create shadow models.
4. Supply chain security failure leads to proprietary model leaks.
5. Malicious actors bypass input filtering, performing side-channel attacks to retrieve model data.


### Common Weakness Enumeration (CWE)

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Flawed authorization controls allow unauthorized access to proprietary language models.

  Description: Flawed authorization controls may grant unauthorized access to resources, including language models, which can lead to unauthorized access and potential data theft.

  Justification: This CWE is directly related to the risk because it addresses the issue of improper authorization controls, which, if not adequately implemented, can result in unauthorized access to language models, posing a risk of data theft and unauthorized use.

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication - Weak authentication mechanisms enable unauthorized users to access private language models. 

  Description: Weak authentication mechanisms can allow unauthorized users to bypass authentication and gain access to sensitive resources, such as language models.

  Justification: Weak authentication mechanisms are directly related to the risk because they can lead to unauthorized access to language models, potentially enabling data theft and misuse.

- [CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function - Lack of authentication checks for access to language models allows unauthorized users access.

  Description: Lack of authentication checks for critical functions can result in unauthorized access to resources, in this case, language models.

  Justification: Missing authentication for critical functions is highly relevant to the risk as it directly addresses the scenario where authentication checks are lacking, leading to unauthorized access to language models and potential data theft.

- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm - Use of weak cryptography to protect language model data could enable interception and unauthorized access during transmission.

  Description: Weak or broken cryptographic algorithms can expose data to interception, potentially leading to unauthorized access.

  Justification: This CWE is directly related to the risk because it highlights the importance of strong cryptographic measures to protect language model data from interception and unauthorized access during transmission.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error - Failing to validate the source of inputs to language model interfaces can allow unauthorized API access enabling data theft.

  Description: Failing to validate the source of inputs can result in unauthorized API access, which can lead to data theft.

  Justification: Origin validation errors directly relate to the risk because they highlight the need to validate input sources, preventing unauthorized API access and potential data theft.

- [CWE-639](https://cwe.mitre.org/data/definitions/639.html): Authorization Bypass Through User-Controlled Key - User API keys could enable authorization bypass to access private language models and steal data.

  Description: Authorization bypass through user-controlled keys can lead to unauthorized access to resources and data theft.

  Justification: This CWE is directly related to the risk as it addresses the specific scenario where user-controlled API keys can be exploited to bypass authorization and gain unauthorized access to language models, potentially resulting in data theft.

- [CWE-703](https://cwe.mitre.org/data/definitions/703.html): Improper Check or Handling of Exceptional Conditions - May prevent detection of language model data extraction attacks by mishandling exceptions.

  Description: Mishandling exceptions can prevent the detection of data extraction attacks, potentially leading to unauthorized access and data theft.

  Justification: Improper handling of exceptional conditions is directly related to the risk because it can hinder the detection of data extraction attacks, allowing unauthorized access to language models and potential data theft to go unnoticed.

- [CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data - Insufficient output encoding from language models risks exposing sensitive training data enabling theft.

  Description: Inadequate output encoding can expose sensitive data, including training data, to potential theft.

  Justification: Inadequate encoding of output data is directly related to the risk as it highlights the importance of proper encoding to prevent the exposure of sensitive training data, which could be targeted for theft.

- [CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials - Hard-coded credentials with excessive permissions granted to interfaces risk unauthorized access to language models.

  Description: Hard-coded credentials with excessive permissions can lead to unauthorized access to resources, including language models.

  Justification: The use of hard-coded credentials is directly related to the risk as it points out the risk associated with such credentials, which can result in unauthorized access to language models and potential data theft.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Inclusion of untrusted third-party components poses risks of unauthorized access to language models.

  Description: Including untrusted third-party components can introduce risks of unauthorized access to resources, in this case, language models.

  Justification: This CWE is directly related to the risk as it addresses the potential risks associated with including untrusted third-party components, which can lead to unauthorized access to language models and potential data theft.

- [CWE-384](https://cwe.mitre.org/data/definitions/384.html): Session Fixation - Session fixation could allow an adversary to hijack authenticated sessions to language models to access or steal data.

  Description: Session fixation can allow attackers to hijack authenticated sessions, potentially leading to unauthorized access and data theft.

  Justification: Session fixation is directly related to the risk as it highlights the risk of attackers hijacking authenticated sessions to gain unauthorized access to language models and potentially steal data.

- [CWE-913](https://cwe.mitre.org/data/definitions/913.html): Improper Control of Dynamically-Managed Code Resources - Could allow unauthorized execution of code enabling access to steal language model data.

  Description: Improper control of dynamically-managed code resources can result in unauthorized code execution, potentially leading to data access and theft.

  Justification: Improper control of dynamically-managed code resources is directly related to the risk as it addresses the scenario where unauthorized code execution could enable access to language model data, leading to potential theft.

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) - SSRF vulnerabilities could enable unauthorized access to internal language model storage servers to steal data.

  Description: SSRF vulnerabilities can enable unauthorized access to internal resources, in this case, language model storage servers, potentially leading to data theft.

  Justification: SSRF vulnerabilities are directly related to the risk as they highlight the potential for unauthorized access to internal language model storage servers, which could result in data theft.
  

### MITRE ATT&CK Techniques

- [T1081](https://attack.mitre.org/techniques/T1081/) - Credentials in Files

  Description: This technique involves accessing credentials stored in files, which could provide unauthorized access to systems and resources.

  Justification: T1081 is related to the risk as it addresses the potential exposure of credentials in files, which, if accessed by attackers, could lead to unauthorized access to proprietary language models, posing a risk of data theft.

- [T1530](https://attack.mitre.org/techniques/T1530/) - Data from Cloud Storage Object

  Description: T1530 involves accessing cloud storage containing data, including language models or artifacts, which could be used to access proprietary data or steal sensitive information.

  Justification: T1530 is relevant to the risk as it highlights the scenario where cloud storage containing language models or artifacts is accessed, potentially leading to the theft of proprietary language models and data.


### MITRE ATLAS Techniques  

- AML.T0024: Exfiltration via ML Inference API. Carefully crafted queries to language model APIs could elicit proprietary details that are extracted and stolen.

- AML.T0043: Craft Adversarial Data. Tailored prompts and inputs to language models could infer proprietary model architecture and parameters for theft.

- AML.T0040: ML Model Inference API Access. Repeated queries to language model APIs could reconstruct model behavior for extraction and theft.

- AML.T0012: Valid Accounts. Compromised credentials provide unauthorized access to language models to steal proprietary artifacts.

- AML.T0044: Full ML Model Access. Full whitebox control makes stealing proprietary language model artifacts simpler.

- AML.T0010: ML Supply Chain Compromise. Compromising third-party suppliers provides a vector to steal proprietary language models.  

- AML.T0016: Obtain Capabilities. May obtain tools to automate extraction and theft of language models.

- AML.T0047: ML-Enabled Product or Service. Commercial services with weak protections could enable language model theft.

### MITRE ATT&CK Mitigations

- [M1015](https://attack.mitre.org/mitigations/M1015/) - Secure Authentication

  Description: This mitigation involves implementing secure authentication mechanisms to prevent unauthorized use of credentials.

  Justification: M1015 is directly related to the risk as it addresses the importance of secure authentication, which is crucial for preventing unauthorized access to language models and the potential theft of data.

- [M1043](https://attack.mitre.org/mitigations/M1043/) - Isolate System or Network

  Description: This mitigation recommends isolating systems containing proprietary language models to prevent unauthorized access.

  Justification: M1043 is highly relevant to the risk as it emphasizes the isolation of systems containing language models, which can effectively prevent model extraction and theft by unauthorized users.

- [M1051](https://attack.mitre.org/mitigations/M1051/) - Network Intrusion Prevention

  Description: This mitigation involves using network Intrusion Prevention Systems (IPS) to block unauthorized connections attempting to extract language models.

  Justification: M1051 is directly related to the risk as it focuses on using network IPS to block unauthorized attempts to extract language models, thus preventing data theft and unauthorized access.

### MITRE ATLAS Mitigations

- AML.M0005: Control Access to ML Models and Data at Rest. Limit access to language models through permissions. Reduces attack surface for theft.

- AML.M0012: Encrypt Sensitive Information. Encrypt language models and related artifacts containing IP. Protects confidentiality against data theft.

- AML.M0013: Code Signing. Ensure proper cryptographic signing of language models and artifacts. Validates integrity to identify theft.

- AML.M0014: Verify ML Artifacts. Detect tampered, modified or stolen language model artifacts. Identifies potential model extraction attempts.

- AML.M0015: Adversarial Input Detection. Detect and filter queries attempting to extract language models. Identifies extraction tries. 

- AML.M0004: Restrict Number of ML Model Queries. Limit total queries to language models that could aid extraction. Reduces attack surface.

- AML.M0001: Limit Model Artifact Release. Reduce public details of language models. Limits available information to aid theft attacks.

- AML.M0016: Vulnerability Scanning. Scan for flaws that could enable language model theft. Finds issues to address proactively.

- AML.M0018: User Training. Educate users on language model theft risks to reduce unknowing participation in attacks.