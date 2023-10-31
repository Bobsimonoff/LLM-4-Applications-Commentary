By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM05: Supply Chain Vulnerabilities

### Summary 

Depending on compromised third-party components can undermine system integrity, causing data breaches and failures.

### Description

Supply chain vulnerabilities arise when compromised third-party components undermine system integrity. Attackers can exploit these to cause data breaches, biased outputs, and system failures.

Vulnerable components like unpatched libraries, contaminated datasets, and compromised model artifacts enable attackers to infiltrate systems. They may manipulate training data to insert biases, backdoors, or errors that degrade model integrity. Successful attacks can lead to IP theft, privacy violations, security breaches, and non-compliance with regulations.

Prevention involves extensive supplier vetting, integrity checks, and monitoring. Only use trusted suppliers and ensure alignment of security policies. Scrutinize third-party plugins before integration. Maintain updated inventories of components, and implement code signing for models. Audit supplier security regularly.


### Common Examples of Risk

1. Outdated or insecure third-party libraries and components.

2. Use of vulnerable pre-trained models.

3. Training with poisoned crowd-sourced data. 

4. Using unmaintained deprecated models.

5. Unclear supplier terms enabling data misuse.

### Prevention and Mitigation Strategies

1. Vet suppliers and ensure security policies align.

2. Scrutinize and test third-party plugins before use.

3. Apply mitigations from OWASP Top Ten vulnerable components guidance. 

4. Maintain updated component inventories with SBOMs.

5. Use model signing and reputable model repositories. 

6. Scan models and data for poisoning.

7. Monitor for unauthorized components and vulnerabilities.

8. Patch vulnerable components.

9. Regularly audit supplier security and access.

### Example Attack Scenarios 

1. Vulnerable library exploits system used in model development.

2. Attacker provides plugin generating scam links.

3. Compromised PyPi package exfiltrates data from model environment.

4. Attacker poisons economic analysis model on public hub to generate misinformation.

5. Attacker poisons public datasets to introduce market bias when models fine-tune.

6. Compromised supplier employee steals confidential data.

7. Supplier changes terms enabling sensitive data exposure.



### MITRE ATLAS™ 

#### Techniques

- [AML.T0010](https://atlas.mitre.org/techniques/AML.T0010): ML Supply Chain Compromise - An attacker could introduce poisoned training data or compromise software dependencies like libraries or frameworks used during model development. This undermines the integrity of the downstream model, allowing the attacker to degrade performance, evade detection, or steal IP.

- [AML.T0019](https://atlas.mitre.org/techniques/AML.T0019): Publish Poisoned Datasets - An attacker can strategically modify a public dataset to inject biases, errors, or backdoors. If the victim's model trains on this poisoned data, it will inherit the vulnerabilities the attacker introduced.

- [AML.T0018](https://atlas.mitre.org/techniques/AML.T0018): Backdoor ML Model - An attacker who has compromised part of the supply chain can inject malicious code into the victim's model files. This backdoor activates when the attacker provides a special input, allowing them to manipulate the model's behavior.


#### Mitigations

- [AML.M0005](https://atlas.mitre.org/mitigations/AML.M0005/): Control Access to ML Models and Data at Rest. Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users. Access controls can prevent tampering with ML artifacts and prevent unauthorized copying.

- [AML.M0013](https://atlas.mitre.org/mitigations/AML.M0013/): Code Signing. Enforce binary and application integrity with digital signature verification to prevent untrusted code from executing. Adversaries can embed malicious code in ML software or models. Enforcement of code signing can prevent the compromise of the machine learning supply chain and prevent execution of malicious code. Prevent execution of ML artifacts that are not properly signed. Enforce properly signed drivers and ML software frameworks. Enforce properly signed model files.

- [AML.M0014](https://atlas.mitre.org/mitigations/AML.M0014/): Verify ML Artifacts. Verify the cryptographic checksum of all machine learning artifacts to verify that the file was not modified by an attacker. Determine validity of published data in order to avoid using poisoned data that introduces vulnerabilities. Introduce proper checking of signatures to ensure that unsafe ML artifacts will not be executed in the system. These artifacts may have a detrimental effect on the system. Introduce proper checking of signatures to ensure that unsafe ML artifacts will not be introduced to the system.


#### Possible Additions

**New Mitigation Proposals** 

- AML.TXXXX: Review Supplier Terms and Conditions - Require legal and security teams to thoroughly review supplier terms and conditions for changes that could expose sensitive data or undermine security. Changes should be evaluated for risk and approved before accepting.

- AML.TXXXX: Maintain Software Bill of Materials - Maintain inventories of third-party software components used in ML systems, including libraries, frameworks, and pre-trained models. Regularly audit for vulnerabilities.

- AML.TXXXX: Review Supplier Terms and Conditions - Require cross-functional legal and security review of supplier terms and conditions changes that could undermine security or enable data exposure. Regularly review Terms and Conditions for changes.


### STRIDE Analysis (generated by claude.ai)

**Spoofing**

- Attackers can spoof compromised suppliers to hide their origin and insert vulnerabilities.
- Vulnerable third-party components enable spoofing other systems after infiltration.

**Tampering** 

- Compromised dependencies allow tampering with system integrity via malicious code insertion.
- Attackers can tamper with data at rest via compromised supply chain components. 

**Repudiation**

- Lack of integrity checks on third-party code undermines attack attribution.
- Compromised suppliers confound audit trails masking the source of attacks.

**Information Disclosure**

- Third-party components with data access enable unauthorized exposure of sensitive assets.
- Compromised suppliers can exfiltrate confidential data and intellectual property.

**Denial of Service**

- Vulnerable dependencies open avenues for crashing critical systems.
- Manipulation of third-party data and models can degrade system functionality.

**Elevation of Privilege** 

- Exploits in third-party code can be used to escalate privileges in downstream systems.
- Access permissions granted to suppliers for integration enable privilege escalation.


### Common Weakness Enumeration (CWE)

- [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html): Reliance on Insufficiently Trustworthy Component

  Summary: Use of unverified third-party components enables backdoors.
   
  Exploit: An attacker can inject malicious code, modified files, or tainted data into a third-party library, dataset, or pre-trained model. By relying on the insufficiently trustworthy component without proper verification, the compromised artifact gets integrated into the victim system, enabling the attacker to manipulate the system and degrade its integrity.

- [CWE-494](https://cwe.mitre.org/data/definitions/494.html): Download of Code Without Integrity Check

  Summary: Importing unvalidated code risks backdoors.

  Exploit: An attacker can modify or inject malicious code into a third-party library or pre-trained model file during transit. By subsequently downloading and integrating these files without sufficient integrity checking, the compromised component executes within the system, enabling the attacker to access and manipulate the system.

- [CWE-506](https://cwe.mitre.org/data/definitions/506.html): Embedded Malicious Code

  Summary: Malicious code injection in components facilitates exploits.

  Exploit: An attacker compromises a third-party supplier and embeds malicious code, like a backdoor or logic bomb, into a library or model artifact produced by that supplier. Integration of the component without detecting this embedded malicious code allows the attacker to remotely access and control the system.

- [CWE-937](https://cwe.mitre.org/data/definitions/937.html): Using Components with Known Vulnerabilities

  Summary: Known vulnerable components enable attacks.
   
  Exploit: An attacker learns that a third-party library or pre-trained model integrated into the victim system contains known vulnerabilities. By exploiting these vulnerabilities present in the integrated component, the attacker can manipulate the system's behavior and impair its integrity.

- [CWE-636](https://cwe.mitre.org/data/definitions/636.html): Not Failing Securely ('Failing Open')

  Summary: Default allow on failure enables compromised components.
  
  Exploit: A failure occurs while validating the integrity of a downloaded third-party component. By defaulting to using the component even after this failure, a compromised or malicious component gets integrated, enabling the attacker to infiltrate the system.

- [CWE-602](https://cwe.mitre.org/data/definitions/602.html): Client-Side Enforcement of Server-Side Security

  Summary: Client-side verification bypassed enables backdoors.

  Exploit: The system relies on client-side checks to validate third-party components. An attacker bypasses these checks by directly uploading malicious components server-side, compromising the system's integrity.

- [CWE-295](https://cwe.mitre.org/data/definitions/295.html): Improper Certificate Validation

  Summary: Certificate validation failure enables tampering.

  Exploit: Weak certificate validation allows an attacker to perform a MITM attack against a connection to a third-party supplier and replace legitimate components with compromised ones containing backdoors, which get integrated into the victim system.


---

# IGNORE FOR NOW - NEED RE-REVIEW



### MITRE ATT&CK® 

#### Techniques

- [T1195](https://attack.mitre.org/techniques/T1195/): Supply Chain Compromise

  Description: Manipulates products or services from third-party suppliers.

  Justification: Directly relevant to compromising the supply chain.

- [T1588](https://attack.mitre.org/techniques/T1588/): Obtain Capabilities

  Description: Adversaries may search for and obtain software capabilities like adversarial ML tools to exploit vulnerable supply chain components. Obtaining capabilities aids adversaries in developing attacks targeting weaknesses in integrated third-party code, models, and data.

  Justification: Obtaining attack tools can enable adversaries to exploit vulnerable supply chain components.


#### Mitigations

N/A

