By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM10: Model Theft

## Summary
Unauthorized access to proprietary large language models risks theft, competitive advantage, and dissemination of sensitive information.

## Description

Unauthorized access and theft of proprietary large language models can undermine competitive advantage and lead to data breaches. 

Attackers can exploit weak access controls, insufficient monitoring, vulnerable components, and insider threats to infiltrate systems and steal valuable LLMs. Successful attacks enable adversaries to acquire sensitive data, launch advanced prompt engineering attacks, and financially damage organizations.

Prevention requires strong access controls, network security, authentication, and monitoring. LLMs should have restricted network access and regular auditing of related logs and activities. Robust MLOps governance, input filtering, and output encoding can help prevent extraction attacks. Physical security and watermarking also help mitigate risks. Proactively securing LLMs against theft is crucial for maintaining confidentiality of intellectual property.

## Common Weakness Enumeration (CWE)

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Flawed authorization controls allow unauthorized access to proprietary language models.

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication - Weak authentication mechanisms enable unauthorized users to access private language models. 

- [CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function - Lack of authentication checks for access to language models allows unauthorized users access.

- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm - Use of weak cryptography to protect language model data could enable interception and unauthorized access during transmission.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error - Failing to validate the source of inputs to language model interfaces can allow unauthorized API access enabling data theft.

- [CWE-639](https://cwe.mitre.org/data/definitions/639.html): Authorization Bypass Through User-Controlled Key - User API keys could enable authorization bypass to access private language models and steal data.

- [CWE-703](https://cwe.mitre.org/data/definitions/703.html): Improper Check or Handling of Exceptional Conditions - May prevent detection of language model data extraction attacks by mishandling exceptions.

- [CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data - Insufficient output encoding from language models risks exposing sensitive training data enabling theft.

- [CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials - Hard-coded credentials with excessive permissions granted to interfaces risk unauthorized access to language models.

- [CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Inclusion of untrusted third-party components poses risks of unauthorized access to language models.

- [CWE-384](https://cwe.mitre.org/data/definitions/384.html): Session Fixation - Session fixation could allow an adversary to hijack authenticated sessions to language models to access or steal data.

- [CWE-913](https://cwe.mitre.org/data/definitions/913.html): Improper Control of Dynamically-Managed Code Resources - Could allow unauthorized execution of code enabling access to steal language model data.

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) - SSRF vulnerabilities could enable unauthorized access to internal language model storage servers to steal data.
  

## ATT&CK Techniques

- [T1081](https://attack.mitre.org/techniques/T1081/) - Credentials in Files. Accesses credentials stored in files which could enable unauthorized access to proprietary language models.

- [T1530](https://attack.mitre.org/techniques/T1530/) - Data from Cloud Storage Object. Accesses cloud storage containing language models or artifacts. Could access proprietary data to steal.

## MITRE ATLAS Techniques  

- AML.T0024: Exfiltration via ML Inference API. Carefully crafted queries to language model APIs could elicit proprietary details that are extracted and stolen.

- AML.T0043: Craft Adversarial Data. Tailored prompts and inputs to language models could infer proprietary model architecture and parameters for theft.

- AML.T0040: ML Model Inference API Access. Repeated queries to language model APIs could reconstruct model behavior for extraction and theft.

- AML.T0012: Valid Accounts. Compromised credentials provide unauthorized access to language models to steal proprietary artifacts.

- AML.T0044: Full ML Model Access. Full whitebox control makes stealing proprietary language model artifacts simpler.

- AML.T0010: ML Supply Chain Compromise. Compromising third-party suppliers provides a vector to steal proprietary language models.  

- AML.T0016: Obtain Capabilities. May obtain tools to automate extraction and theft of language models.

- AML.T0047: ML-Enabled Product or Service. Commercial services with weak protections could enable language model theft.

## ATT&CK Mitigations

- [M1015](https://attack.mitre.org/mitigations/M1015/) - Secure Authentication. Implements secure authentication mechanisms. Prevents unauthorized use of credentials to access language models.

- [M1043](https://attack.mitre.org/mitigations/M1043/) - Isolate System or Network. Isolates systems containing proprietary language models. Could prevent model extraction and theft.

- [M1051](https://attack.mitre.org/mitigations/M1051/) - Network Intrusion Prevention. Uses network IPS to block unauthorized connections attempting model extraction.

## MITRE ATLAS Mitigations

- AML.M0005: Control Access to ML Models and Data at Rest. Limit access to language models through permissions. Reduces attack surface for theft.

- AML.M0012: Encrypt Sensitive Information. Encrypt language models and related artifacts containing IP. Protects confidentiality against data theft.

- AML.M0013: Code Signing. Ensure proper cryptographic signing of language models and artifacts. Validates integrity to identify theft.

- AML.M0014: Verify ML Artifacts. Detect tampered, modified or stolen language model artifacts. Identifies potential model extraction attempts.

- AML.M0015: Adversarial Input Detection. Detect and filter queries attempting to extract language models. Identifies extraction tries. 

- AML.M0004: Restrict Number of ML Model Queries. Limit total queries to language models that could aid extraction. Reduces attack surface.

- AML.M0001: Limit Model Artifact Release. Reduce public details of language models. Limits available information to aid theft attacks.

- AML.M0016: Vulnerability Scanning. Scan for flaws that could enable language model theft. Finds issues to address proactively.

- AML.M0018: User Training. Educate users on language model theft risks to reduce unknowing participation in attacks.