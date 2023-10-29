By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM01: Prompt Injection

### Summary

Crafted prompts can manipulate LLMs to cause unauthorized access, data breaches, and compromised decision-making.


### Common Weakness Enumeration (CWE)

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Summary: Not validating or incorrectly validating input allows attackers to craft inputs that can exploit the system in unexpected ways.

  Exploit: Without proper validation of user prompts, an attacker could inject additional instructions, special characters, or malicious code sequences that when processed by the LLM could lead to unintended behavior, such as executing unwanted commands, accessing unauthorized data, or bypassing restrictions. Lack of prompt input validation provides the opening for attackers to craft carefully designed prompts that manipulate model behavior.

- [CWE-77](https://cwe.mitre.org/data/definitions/77.html): Improper Neutralization of Special Elements used in a Command ('Command Injection')

  Summary: Improper neutralization of special elements in user prompts could allow injected instructions to modify and extend the intended command.

  Exploit: When processing prompts, the LLM may construct system commands to perform required queries or data fetching operations. If prompts contain un-neutralized special elements like backticks, an attacker could terminate the intended command and inject new malicious commands that get executed on backend systems accessible through the LLM interface. This command injection can lead to unauthorized actions like data exfiltration, privilege escalation, and denial of service.

- [CWE-114](https://cwe.mitre.org/data/definitions/114.html): Process Control

  Summary: Lack of isolation between user prompts and external data sources could enable unintended processing behavior.

  Exploit: Often LLMs incorporate external data from websites, databases, etc. into prompts to provide contextual grounding. If prompts and external data are not properly isolated, an attacker could inject malicious instructions into the external data source. When the compromised data source text gets incorporated into a prompt, the injected instructions could manipulate the LLM into executing unintended and potentially harmful actions.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error

  Summary: Not validating the source of input enables spoofing and injection from untrusted sources.

  Exploit: When processing user prompts, failing to validate the origin of the input could allow an attacker to impersonate a legitimate user and inject malicious prompts. Without checking the source, spoofed input from unauthorized external systems can manipulate LLM behavior in unintended ways. Proper origin validation restricts ability to inject prompts from untrusted origins.



# LLM02: Insecure Output Handling

### Summary 

Failing to validate, sanitize and filter LLM outputs enables attackers to indirectly access systems or trigger exploits via crafted prompts.


### Common Weakness Enumeration (CWE)


- [CWE-74](https://cwe.mitre.org/data/definitions/74.html): Improper Neutralization of Special Elements in Output Used by a Downstream Component

  Summary: Failure to sanitize special elements in outputs enables injection attacks on downstream components.

  Exploit: An attacker could craft prompts that induce the LLM to generate malicious outputs containing unneutralized special elements like shell metacharacters. When passed unchecked to a downstream OS command execution module, these adversarial outputs could allow arbitrary command injection on backend servers.

- [CWE-78](https://cwe.mitre.org/data/definitions/78.html): Improper Neutralization of Special Elements used in an OS Command

  Summary: Failure to sanitize outputs allows OS command injection.

  Exploit: By injecting crafted prompts, an attacker tricks the LLM into producing malicious output payloads containing unneutralized OS command separators and metacharacters. An unsanitized downstream execution of these outputs risks arbitrary command injection on backend OS shells.

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Improper Neutralization of Input During Web Page Generation

  Summary: Failure to sanitize web outputs enables injection of malicious scripts.

  Exploit: An attacker spoofs prompts to induce generation of unencoded LLM outputs containing malicious scripts. Downstream use of these unchecked outputs in web pages allows cross-site scripting attacks when the pages are rendered in users' browsers.  

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Neutralization of Special Elements used in an SQL Command

  Summary: Failure to sanitize outputs enables SQL injection.

  Exploit: By injecting carefully crafted prompts, an attacker causes the LLM to generate malicious SQL query outputs containing unneutralized separators and conditionals. Direct unchecked execution of these outputs by downstream SQL engines risks SQL injection attacks.

- [CWE-94](https://cwe.mitre.org/data/definitions/94.html): Improper Control of Generation of Code

  Summary: Failure to sanitize outputs allows arbitrary code execution.

  Deailed Exploit: An attacker uses adversarial prompts to induce the LLM to generate unrestrained outputs containing exploits, scripts or arbitrary code payloads. Direct unchecked execution of these outputs risks arbitrary remote code execution.

- [CWE-116](https://cwe.mitre.org/data/definitions/116.html): Improper Encoding or Escaping of Output

  Summary: Failure to properly encode/escape output leads to issues when read downstream.

  Exploit: Absence of proper output encoding or escaping allows an attacker to craft prompts inducing generation of malicious exploit payloads and injection attack vectors in LLM outputs. These adversarial outputs can compromise downstream components when consumed without validation.

- [CWE-838](https://cwe.mitre.org/data/definitions/838.html): Inappropriate Encoding for Output Context

  Summary: Using wrong encoding for outputs leads to misinterpretation.

  Exploit: An attacker tricks the LLM into generating malicious payload outputs using encodings inappropriate for the downstream context. This allows the payloads to bypass protection mechanisms and successfully exploit vulnerabilities when improperly handled by downstream components.



# LLM03: Training Data Poisoning

### Summary

Tampered training data can impair LLMs, leading to compromised security, accuracy, or ethical behavior.

### Common Weakness Enumeration (CWE)

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Summary: Failure to validate inputs allows malicious inputs to exploit systems.

  Exploit: Lack of proper validation of training data enables an attacker to directly insert manipulated, poisoned examples into the training set which distorts the model's learning and leads to unintended behaviors.

- [CWE-300](https://cwe.mitre.org/data/definitions/300.html): Channel Accessible by Non-Endpoint

  Summary: Accessible channels allow unauthorized data access/manipulation.

  Exploit: Unprotected training data channels allow an attacker to access the data and directly inject malicious examples that poison the integrity of the training process and impair the model's capabilities.

- [CWE-345](https://cwe.mitre.org/data/definitions/345.html): Insufficient Verification of Data Authenticity

  Summary: Lack of data authentication allows fraudulent data insertion.

  Exploit: Without sufficiently verifying the authenticity of training data, an attacker can tamper with the data by adding crafted malicious examples that undermine the model's accuracy and security.

- [CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function

  Summary: Lack of authentication enables unauthorized data access.

  Exploit: Missing authentication requirements for accessing and modifying training data enables an attacker to inject poisoned examples without authorization that impair the model's functionality.


# LLM04: Denial of Service

### Summary
Overloading LLMs with resource-intensive operations can cause service disruptions, degraded performance, and increased costs.


### Common Weakness Enumeration (CWE)

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Summary: Failure to validate inputs allows malicious inputs to exploit systems.

  Exploit: By not properly validating inputs, an attacker can craft specially formatted data that consumes excessive resources when processed by the system, leading to resource exhaustion and denial of service.

- [CWE-352](https://cwe.mitre.org/data/definitions/352.html): Cross-Site Request Forgery (CSRF)

  Summary: Forces unintended external requests facilitating denial of service.

  Exploit: Malicious input tricks LLM into making harmful requests to external systems contributing to resource exhaustion.

- [CWE-400](https://cwe.mitre.org/data/definitions/400.html): Uncontrolled Resource Consumption

  Summary: Allows attackers to consume excessive resources (CPU, memory, disk, network) via malicious input.

  Exploit: The lack of restrictions on resource usage enables an attacker to overwhelm systems with carefully crafted inputs that demand extensive processing cycles, memory, storage, or network capacity far beyond normal operations.

- [CWE-601](https://cwe.mitre.org/data/definitions/601.html): URL Redirection to Untrusted Site

  Summary: Redirects to malicious external sites enabling denial of service.

  Exploit: Attacker manipulates LLM to interact with harmful external sites that trigger excessive resource consumption leading to denial of service.

- [CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling

  Summary: No limits on resource allocation allows exhaustion via excessive requests.

  Exploit: With no throttling or caps on resource allocation, an attacker can exploit the system by flooding it with excessive requests that rapidly drain available resources leading to denial of service.
  
- [CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency

  Summary: Failure to limit the frequency of interactions enabling repeated operations that strain resources.

  Exploit: Lack of frequency throttling enables an attacker to overwhelm systems by bombarding them with rapid, repeated requests that cumulatively create a denial of service effect.

- [CWE-834](https://cwe.mitre.org/data/definitions/834.html): Excessive Iteration

  Summary: Uncontrolled looping allows arbitrary computation, resource exhaustion.

  Exploit: Inputs designed to trigger extensive recursive processing induce excessive iteration cycles that continually drain and overwhelm system resources.

- [CWE-835](https://cwe.mitre.org/data/definitions/835.html): Loop with Unreachable Exit Condition ('Infinite Loop')

  Summary: Infinite loops cause programs to hang, consume resources indefinitely.

  Exploit: Crafted inputs that recursively expand context force infinite processing loops that continuously consume resources leading to denial of service.

- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF)

  Summary: Failure to block server-side execution of malicious external requests leading to resource exhaustion.

  Exploit: An attacker can submit crafted inputs that induce the system to make unintended external requests to APIs and other endpoints, amplifying compute and network resource consumption.



# LLM05: Supply Chain Vulnerabilities

### Summary 

Depending on compromised third-party components can undermine system integrity, causing data breaches and failures.


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


# LLM06: Sensitive Information Disclosure

### Summary

Insufficient safeguards risk exposing sensitive information through LLM outputs, causing legal issues or competitive harm.


### Common Weakness Enumeration (CWE)

- [CWE-200](https://cwe.mitre.org/data/definitions/200.html): Exposure of Sensitive Information

  Summary: Sensitive information exposed to unauthorized actors.

  Exploit: Due to insufficient data filtering or access controls, an attacker can use carefully crafted prompts to extract proprietary algorithms, training data, model parameters or other confidential information from the LLM, which they can then exfiltrate and exploit.

- [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Exposure Through Error Messages

  Summary: Sensitive information revealed through error messages.

  Exploit: When the LLM encounters unexpected inputs or conditions, the resulting error messages can unintentionally expose details about the model architecture, training data schemas, hyperparameters or other sensitive implementation information an attacker can leverage to refine their prompts and extraction techniques.

- [CWE-215](https://cwe.mitre.org/data/definitions/215.html): Exposure Through Debug Logs

  Summary: Sensitive information in debug logs.

  Exploit: The LLM's debugging information can reveal details about the training data distribution, structure and sources as well as inference metadata. Attackers can analyze these logs to identify weaknesses and optimize prompts for extracting sensitive information.

- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of Broken Cryptography

  Summary: Weak crypto enables data exposure.

  Exploit: The use of flawed or outdated cryptographic algorithms to protect sensitive training data, model parameters, and artifacts can allow an attacker to easily decrypt and access this proprietary information.

- [CWE-541](https://cwe.mitre.org/data/definitions/541.html): Exposure Through Source Code

  Summary: Source code revealing sensitive details.

  Exploit: Hardcoded sensitive information like API keys, credentials or server addresses in the LLM's source code can enable an attacker to directly access its environment and training data sources to extract additional confidential information.

- [CWE-922](https://cwe.mitre.org/data/definitions/922.html): Insecure Data Storage

  Summary: Unencrypted sensitive artifacts enable data theft.

  Exploit: Storing model parameters, training datasets, or other proprietary artifacts without encryption or access controls allows attackers to easily obtain this sensitive information.



# LLM07: Insecure Plugin Design 

### Summary
LLM plugins processing untrusted inputs without validation can enable severe exploits like remote code execution.



### Common Weakness Enumeration (CWE)

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation

  Summary: Failure to validate input from untrusted sources.

  Exploit: An LLM plugin processes outputs from the LLM as inputs without properly validating or sanitizing them. This allows an attacker to craft malicious inputs by taking advantage of the lack of validation, which could exploit the plugin's logic in unintended ways including arbitrary code execution.

- [CWE-74](https://cwe.mitre.org/data/definitions/74.html): Improper Neutralization of Special Elements in Output Used by a Downstream Component

  Summary: Failure to sanitize outputs enables downstream injection attacks.

  Exploit: An LLM plugin interprets LLM outputs containing un-neutralized special elements. This allows an attacker to inject malicious snippets into downstream operations by taking advantage of the lack of output sanitization in the plugin.

- [CWE-89](https://cwe.mitre.org/data/definitions/89.html): Improper Neutralization of Special Elements used in an SQL Command

  Summary: Failure to neutralize special elements in SQL statements enables SQL injection.

  Exploit: An LLM plugin executes LLM outputs as SQL queries without neutralizing special elements. This allows an attacker to perform SQL injection by crafting LLM outputs containing malicious SQL, taking advantage of the lack of output sanitization.

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Summary: Failure to restrict access from unauthorized actors.

  Exploit: An LLM plugin processes outputs from the LLM without proper authorization checks. This allows an attacker to escalate privileges and access sensitive resources by manipulating the plugin through crafted LLM outputs.
  
- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error

  Summary: Failure to validate source of input.

  Exploit: An LLM plugin processes outputs from the LLM without properly verifying their source. This allows an attacker to inject malicious data by spoofing the origin of the outputs.



# LLM08: Excessive Agency

### Summary

Excessive LLM permissions or autonomy enables unintended harmful actions based on faulty LLM outputs.


### Common Weakness Enumeration (CWE)

- [CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure

  Summary: Failure to use protections against directed attacks.

  Exploit: Lack of safeguards restricting an LLM's permissions and capabilities enables attackers to manipulate it into taking harmful actions through crafted inputs.

- [CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization  

  Summary: Failure to perform authorization checks for actions.

  Exploit: An LLM plugin takes impactful actions without approval based on its excessive autonomy, allowing attackers to induce unintended harmful activity through the unrestricted LLM.

- [CWE-250](https://cwe.mitre.org/data/definitions/250.html): Execution with Unnecessary Privileges

  Summary: Performing actions with unnecessary privileges.

  Exploit: Excessive privileges granted to an LLM or its plugins exceed what is needed for its core functions, enabling unintended privileged actions induced by an attacker's manipulated inputs.

- [CWE-269](https://cwe.mitre.org/data/definitions/269.html): Improper Privilege Management

  Summary: Failing to properly restrict privileges to authorized users.

  Exploit: An LLM or its plugins are granted excessive privileges without proper management of the privileges. This enables attackers to induce unintended privileged actions by manipulating the unrestricted LLM through crafted inputs designed to exploit its unnecessary privileges.

- [CWE-732](https://cwe.mitre.org/data/definitions/732.html): Incorrect Permission Assignment for Critical Resource

  Summary: Incorrect critical resource permissions allow abuse.

  Exploit: Overly broad permissions beyond necessity provided to an LLM or its plugins enable unintended actions on critical resources triggered by an attacker.

- [CWE-668](https://cwe.mitre.org/data/definitions/668.html): Exposure of Resource to Wrong Sphere

  Summary: Exposing resources to unintended actors enables abuse.

  Exploit: Excessive functionality or access to resources beyond an LLM's core needs allows attackers to induce unintended actions through crafted inputs.



# LLM09: Overreliance

### Summary

Blindly trusting LLM outputs can lead to issues like misinformation, legal problems, and reputational damage without verification.


### Common Weakness Enumeration (CWE)
n.A.




# LLM10: Model Theft

### Summary
LLM theft can lead to financial losses, competitive disadvantage, and unauthorized data access.


### Common Weakness Enumeration (CWE)

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization

  Summary: Flawed authorization enables unauthorized access.

  Exploit: Weak authorization controls grant improper access to model storage, allowing attackers to access and steal proprietary LLM intellectual property.

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication

  Summary: Weak authentication allows unauthorized access.

  Exploit: Poor authentication mechanisms enable attackers to bypass identity checks and gain access to LLM artifacts to steal IP.

- [CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function

  Summary: Lack of authentication allows unauthorized access.

  Exploit: Absent authentication checks for LLM access endpoints provide an unguarded pathway for attackers to access and misuse stolen models.

- [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm

  Summary: Weak cryptography enables unauthorized data access.

  Exploit: Flawed encryption allows attackers to intercept LLM artifacts in transit and exfiltrate stolen IP.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error

  Summary: Lack of source validation enables unauthorized access.

  Exploit: Failing to validate the source of access requests allows attackers to spoof identities and gain access to steal LLMs.

- [CWE-384](https://cwe.mitre.org/data/definitions/384.html): Session Fixation

  Summary: Session hijacking provides unauthorized access.

  Exploit: Attackers can fix sessions to impersonate valid users and gain access to steal proprietary LLM IP.

- [CWE-522](https://cwe.mitre.org/data/definitions/522.html): Insufficiently Protected Credentials

  Summary: Poorly protected credentials enable unauthorized access.

  Exploit: Weak protections over credentials allow attackers to easily compromise them and access LLM environments to steal IP.

- [CWE-639](https://cwe.mitre.org/data/definitions/639.html): Authorization Bypass Through User-Controlled Key

  Summary: User keys enable authorization bypass.

  Exploit: Compromised API keys or tokens allow attackers to bypass access controls and steal LLMs.

- [CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure

  Summary: Security control failures enable unauthorized access.

  Exploit: Compromised or absent protections pave the way for attackers to access and steal proprietary LLM IP.

- [CWE-732](https://cwe.mitre.org/data/definitions/732.html): Incorrect Permission Assignment for Critical Resource

  Summary: Overly permissive critical resource access.

  Exploit: Broad model access permissions increase ability for attackers to steal IP.







