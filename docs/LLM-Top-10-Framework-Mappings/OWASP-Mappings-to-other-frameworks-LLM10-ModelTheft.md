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

## CWE

[CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Flawed authorization allows unauthorized model access.

[CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication - Weak authentication enables unauthorized access.

[CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function - Lack of authentication could allow unauthorized access.

[CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm - Weak cryptography could enable interception of model data.

[CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error - Failing to validate input source can allow unauthorized access.

[CWE-639](https://cwe.mitre.org/data/definitions/639.html): Authorization Bypass Through User-Controlled Key - User keys could enable authorization bypass. 

[CWE-703](https://cwe.mitre.org/data/definitions/703.html): Improper Check or Handling of Exceptional Conditions - May prevent detection of extraction attacks.

[CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data - Insufficient output encoding risks data exfiltration.

[CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials - Hard-coded credentials with excessive permissions risk unauthorized access.

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Inclusion of untrusted components poses unauthorized access risks.

[CWE-384](https://cwe.mitre.org/data/definitions/384.html): Session Fixation - Session fixation could allow adversary to steal authenticated sessions to access models.

[CWE-913](https://cwe.mitre.org/data/definitions/913.html): Improper Control of Dynamically-Managed Code Resources - Could allow execution of unauthorized code enabling model access/theft.

[CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) - SSRF could enable unauthorized access to internal model storage.


## MITRE ATT&CK Techniques

- AML.T0024: Exfiltration via ML Inference API. Carefully crafted queries could elicit model details that are extracted. Extracts model details.

- AML.T0043: Craft Adversarial Data. Tailored prompts could infer model architecture and parameters. Infers model details.

- AML.T0040: ML Model Inference API Access. Repeated queries could reconstruct model behavior for theft. Reconstructs model.

- AML.T0012: Valid Accounts. Compromised credentials provide access to steal artifacts. Enables unauthorized access.

- AML.T0044: Full ML Model Access. Full control makes stealing artifacts simpler. Provides direct access for theft. 

- AML.T0010: ML Supply Chain Compromise. Compromising suppliers provides a vector to steal models. Attacks supply chain.

- AML.T0016: Obtain Capabilities. May obtain tools to automate model extraction. Aids model theft.

- AML.T0047: ML-Enabled Product or Service. Commercial services with weak protections could enable theft. Finds vulnerable services.
