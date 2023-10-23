By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium.com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM01: Prompt Injection

### Summary

Crafted prompts can manipulate LLMs to cause unauthorized access, data breaches, and compromised decision-making.

### MITRE ATLAS™ 

#### Techniques
- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043): Craft Adversarial Data - Prompt injection attacks involve carefully crafting prompts (adversarial data) that manipulate the LLM to produce unintended and potentially harmful outputs. The crafted prompts exploit vulnerabilities in the LLM's training and design to achieve objectives like unauthorized access, financial fraud, etc.

#### Mitigations

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004): Restrict Number of ML Model Queries - Limiting API queries restricts reconnaissance and attack optimization. 

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015): Adversarial Input Detection - Detect and block potentially malicious prompts before they reach the model.

#### Possible Additions

**Possible New Techniques**

- AML.TXXXX: Insert Malicious Prompt via User Upload - Adding a malicious prompt to user-provided content like resumes, support tickets, etc. that then compromises the LLM when processed.

- AML.TXXXX: Embed Malicious Prompt in External Data Source - Embedding a malicious prompt in any external data sources like files, databases, websites, etc. that compromises the LLM when processed. 

- AML.TXXXX: Exploit LLM Plugin - Exploiting vulnerabilities in LLM plugins to manipulate behavior with a malicious prompt.

**Possible New Mitigations**

- AML.MXXXX: Sanitize User Uploads - Remove or neutralize potentially malicious prompts from user-provided content before processing to prevent compromise.

- AML.MXXXX: Isolate External Data - Run any external data sources like files, databases, websites in an isolated environment to prevent malicious prompts from impacting the LLM.

- AML.MXXXX: LLM Plugin Security Review - Rigorously review LLM plugins for potential injection flaws before deployment to prevent compromise.

- AML.MXXXX: Prompt Request/Response Auditing - Log and audit prompt requests and responses to identify anomalies indicating potential attacks.

- AML.MXXXX: Prompt Input Validation & Sanitization - Validate and sanitize prompt inputs to neutralize potentially malicious prompts before processing.



# LLM02: Insecure Output Handling

### Summary 

Failing to validate, sanitize and filter LLM outputs enables attackers to indirectly access systems or trigger exploits via crafted prompts.


### MITRE ATLAS™ 

#### Techniques
- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043): Craft Adversarial Data - An adversary could exploit insecure output handling by crafting prompts containing adversarial text or code that gets embedded in the LLM's output. When these adversarial outputs are passed unchecked to downstream systems, they could trigger exploits.

- [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044): Full ML Model Access - With full white-box access to the model, an adversary could perform prompt injections to trigger the model to generate insecure outputs. The downstream client's failure to sanitize these adversarial outputs enables exploit.

- [AML.T0047](https://atlas.mitre.org/techniques/AML.T0047): ML-Enabled Product or Service - An adversary could use a public API or product service powered by an LLM backend model to generate malicious outputs that exploit insecure handling by the client application. The adversary crafts inputs that induce the model to generate harmful outputs. The downstream client application fails to properly sanitize these outputs before passing them to vulnerable components. 

- [AML.T0050](https://atlas.mitre.org/techniques/AML.T0050): Command and Scripting Interpreter - Executing unchecked commands from an LLM could enable code injection or remote code execution. 


#### Mitigations
- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002): Passive ML Output Obfuscation - Reducing output fidelity restricts adversary's ability to optimize attacks.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015): Adversarial Input Detection - Detect and block prompts likely to generate malicious outputs.


#### Possible Additions

**New Technique Proposals**

- Downstream System Spoofing - An adversary could manipulate LLM output formats, identifiers, and credentials to impersonate trusted downstream services and bypass authentication checks. This causes improper access and misleading log data.

- Control Flow Tampering - By injecting malicious logic bombs, loops, recursion, and other control flow altering payloads into LLM outputs, an adversary can disrupt downstream system operations. This could cause crashes, instability, or unauthorized changes. 

- Log Tampering - An adversary may tamper with logging configurations or directly modify log data related to LLM outputs to remove evidence of their attack. This complicates investigation and attribution by auditors.

- Information Leakage Amplification - Carefully crafted LLM outputs can trigger verbose error messages and logging from downstream systems. An adversary can extract sensitive details and troubleshooting data.

- Privilege Escalation - If LLM outputs allow code execution on downstream systems, an adversary can perform vertical privilege escalation by compromising process/service accounts and executing commands. Lateral movement with stolen credentials expands access.

**New Mitigation Proposals** 

- Input Validation - Thoroughly validating data inputs and command structures before they are passed to an LLM will prevent injection of malicious prompts that could generate harmful outputs.

- Output Encoding - Properly encoding LLM outputs based on the downstream execution context (e.g. browsers, OS shells, DBs) prevents exploits like XSS, command injection, and SQLi.

- LLM Output Sandboxing - Running LLM outputs in an isolated sandbox environment limits the damage and systemic impact of any malicious payloads generated. However, this may reduce functionality.

- LLM Output Logging - Securely logging all LLM outputs to an immutable audit log enables attack investigation, forensics, and attribution after incidents. Proper access controls on logs are critical.




# LLM03: Training Data Poisoning

### Summary

Tampered training data can impair LLMs, leading to compromised security, accuracy, or ethical behavior.

### MITRE ATLAS™ 

#### Techniques
- [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020): Poison Training Data - An attacker could poison the training data used to train the victim LLM. This allows the attacker to embed vulnerabilities that can be triggered later with crafted inputs.

- [AML.T0018](https://atlas.mitre.org/techniques/AML.T0018): Backdoor ML Model - An attacker could backdoor the LLM by training it on poisoned data that associates a trigger with a malicious output. This backdoor could later be used to force unethical or flawed behavior.

- [AML.T0019](https://atlas.mitre.org/techniques/AML.T0019): Publish Poisoned Datasets - An attacker could publish a poisoned dataset that the victim organization then unintentionally uses to train their LLM, poisoning it.


#### Mitigations

- [AML.M0007](https://atlas.mitre.org/mitigations/AML.M0007): Sanitize Training Data - Detect and remove poisoned data before model training.

- [AML.M0014](https://atlas.mitre.org/mitigations/AML.M0014): Verify ML Artifacts - Catch poisoned datasets by verifying checksums. 


#### Possible Additions

**Possible New Techniques**

- Unintended Data Exposure in Training: An authorized user may accidentally expose private or sensitive data (e.g. PII, financial data, confidential documents) that then gets incorporated into the model's training data. This can lead to information leakage if the model memorizes and regurgitates that private data during inference. Attackers could exploit this to extract sensitive data.

- Insufficient Access Controls on Training Data: If proper access controls are not enforced on what data can be used for model training, an attacker may be able to introduce arbitrary external training data from unsafe sources. Without sufficient validation, this poisoned data could be used to train the model, embedding vulnerabilities that attackers can later exploit. 

**Possible New Mitigations** 

- Isolate Models and Data: By proactively separating models and their associated training datasets into different environments based on sensitivity levels, the blast radius of a poisoning attack can be limited. Critical models can be isolated from general purpose models and their respective data sources. This makes it harder for an attacker to impact business-critical models.

- Detect Poisoned Outputs: Monitoring the model's outputs during inference can help detect anomalous behaviors that may indicate training data poisoning. For example, sudden drops in accuracy, spikes in certain predictions, or outputting unintended data could signal that the model was trained on manipulated data. Early detection of these signals can prevent harm.

- Adversarial Training: Intentionally injecting adversarial examples during model training makes the model more robust to poisoned data points an attacker may introduce. The model learns to be less sensitive to small perturbations. This minimizes the impact of poisoning attacks.


# LLM04: Denial of Service

### Summary
Overloading LLMs with resource-intensive operations can cause service disruptions, degraded performance, and increased costs.


### MITRE ATLAS™ 

#### Techniques

- [AML.T0016](https://atlas.mitre.org/techniques/AML.T0016): Obtain Capabilities - An adversary acquires tools and software that generate adversarial inputs to language models. These tools allow the adversary to craft prompts and other inputs designed to trigger excessive processing, memory usage, and other behaviors that can overwhelm systems. 

- [AML.T0029](https://atlas.mitre.org/techniques/AML.T0029): Denial of ML Service - This technique could potentially be used to exploit a denial of service vulnerability in an LLM system. An adversary could intentionally craft inputs that are resource intensive for the LLM to process, with the goal of overloading the system.

- [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040): ML Model Inference API Access - An adversary utilizes a language model's public inference API to probe the model, identify weaknesses, and craft inputs that consume excessive resources. API access enables information gathering and input optimization prior to launching a denial of service attack.

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043): Craft Adversarial Data - An adversary could craft prompts or other inputs that are designed to trigger very long, repetitive responses from the LLM. Flooding the system with many such carefully crafted inputs could overwhelm the LLM's processing capacity and memory usage, resulting in a denial of service effect. 

#### Mitigations

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004): Restrict Number of ML Model Queries - Query rate limiting prevents flooding attacks by restricting the number of inputs an adversary can submit over a period of time. Requests exceeding the defined rate are dropped/blocked. Rate limits can be applied per user account and potentially increased for legitimate high-volume usages.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015): Adversarial Input Detection - Runtime monitoring mechanisms analyze inputs to the language model and characterize the expected resource consumption. Inputs projected to consume excessive resources based on analysis of text, prompt length, expandability and other factors are blocked prior to processing.

- [AML.M0016](https://github.com/mitre-atlas/atlas/blob/master/data/mitigations/mitigations-yaml/AML.M0016.yml): Limit Model Queries Per User - Rate limiting and quotas prevent adversaries from overwhelming systems by restricting the number of queries an individual can make over a given time window. This mitigates denial of service from query flooding.

- [AML.M0017](https://github.com/mitre-atlas/atlas/blob/master/data/mitigations/mitigations-yaml/AML.M0017.yml): Resource Isolation - Language model resources like memory, compute, and storage are isolated from other components through mechanisms like containers. This prevents denial of service impacts from spreading beyond the language model to other critical services.

#### Possible Additions

**Possible New Techniques**

- Recursive Context Expansion - An adversary crafts inputs containing text triggers that cause the language model to continuously expand the context window and reprocess the input in a recursive loop. Each iteration consumes additional memory and compute resources. Sending many such inputs can rapidly exhaust available resources, resulting in denial of service. Note this could be a subtechnique of craft adversarial data.

- Benign Query Resource Exhaustion - An adversary identifies benign input text which does not appear obviously malicious but leads to unpredictable resource consumption due to the language model's processing. Queries submitted through public interfaces get processed by downstream models in a way that consumes substantial resources due to lengthy text generation or repeated context expansion. The adversary can send many such queries to degrade performance and availability. 

**Possible New Mitigations**  

- Limit Concurrent Requests - The number of requests that can be processed concurrently by the language model is restricted through configuration. Limiting concurrency makes it more difficult for an adversary to overwhelm systems with high volumes of queries. The limit could be applied across all users or per individual user account.

- Limit Context Expansions - The language model is configured to limit the number of recursive context expansions that can occur per request. This prevents adversaries from causing excessive processing through inputs that continuously trigger context re-generation. Hard thresholds prevent unlimited recursive expansion scenarios.

- Resource Consumption Monitoring - Continuously monitor CPU, memory, and other resource consumption metrics to identify abnormal behavior indicative of a DoS attack.



# LLM05: Supply Chain Vulnerabilities

### Summary 

Depending on compromised third-party components can undermine system integrity, causing data breaches and failures.


### MITRE ATLAS™ 

#### Techniques

- [AML.T0010](https://atlas.mitre.org/techniques/AML.T0010): ML Supply Chain Compromise - An attacker could introduce poisoned training data or compromise software dependencies like libraries or frameworks used during model development. This undermines the integrity of the downstream model, allowing the attacker to degrade performance, evade detection, or steal IP.

- [AML.T0019](https://atlas.mitre.org/techniques/AML.T0019): Publish Poisoned Datasets - An attacker can strategically modify a public dataset to inject biases, errors, or backdoors. If the victim's model trains on this poisoned data, it will inherit the vulnerabilities the attacker introduced.

- [AML.T0018](https://atlas.mitre.org/techniques/AML.T0018): Backdoor ML Model - An attacker who has compromised part of the supply chain can inject malicious code into the victim's model files. This backdoor activates when the attacker provides a special input, allowing them to manipulate the model's behavior.


#### Mitigations

- [AML.M0005](https://atlas.mitre.org/mitigations/AML.M0005): Control Access to ML Models and Data at Rest - Strict access controls prevent unauthorized modification of artifacts at rest. This protects against supply chain poisoning attacks.

- [AML.M0013](https://atlas.mitre.org/mitigations/AML.M0013): Code Signing - Enforcing cryptographic signing of software and models verifies they have not been tampered with or replaced in the supply chain. This prevents execution of unauthorized code.

- [AML.M0014](https://atlas.mitre.org/mitigations/AML.M0014): Verify ML Artifacts - Hashing artifacts and checking against known good hashes ensures they have not been corrupted or poisoned in the supply chain.


#### Possible Additions

**Possible New Mitigations** 

- Review Supplier Terms and Conditions - Require legal and security teams to thoroughly review supplier terms and conditions for changes that could expose sensitive data or undermine security. Changes should be evaluated for risk and approved before accepting.

- Maintain Software Bill of Materials - Maintain inventories of third-party software components used in ML systems, including libraries, frameworks, and pre-trained models. Regularly audit for vulnerabilities.

- Review Supplier Terms and Conditions - Require cross-functional legal and security review of supplier terms and conditions changes that could undermine security or enable data exposure. Regularly review Terms and Conditions for changes.



# LLM06: Sensitive Information Disclosure

### Summary

Insufficient safeguards risk exposing sensitive information through LLM outputs, causing legal issues or competitive harm.


### MITRE ATLAS™ 

#### Techniques
- [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024): Exfiltration via ML Inference API - Adversaries could craft prompts designed to elicit private information from the LLM and exfiltrate it via the inference API. This could expose proprietary data or personally identifiable information.

- [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025): Exfiltration via Cyber Means - Adversaries may exfiltrate sensitive information extracted from an ML model via traditional cyber techniques that do not rely on the model's inference API. This allows adversaries to steal confidential data gathered through the model after insufficient safeguards have allowed access to that information.

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043): Craft Adversarial Data - Adversaries could iteratively craft prompts to extract sensitive information from the LLM. Carefully tuned prompts can reveal confidential data even if the model was not explicitly trained on it. This allows adversaries to exploit insufficient safeguards around model outputs.

- [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044): Full ML Model Access - With complete white-box access to the model, adversaries can thoroughly analyze model parameters and data relationships to optimally extract maximum sensitive information. This level of access enables adversaries to fully exploit insufficient safeguards.

#### Mitigations

- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002): Passive ML Output Obfuscation - Limits exposure through outputs.

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004): Restrict Number of ML Model Queries - Limits API-based exfiltration. 

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015): Adversarial Input Detection - Catch prompts aimed at leaking info.



# LLM07: Insecure Plugin Design 

### Summary
LLM plugins processing untrusted inputs without validation can enable severe exploits like remote code execution.



### MITRE ATLAS™ 

#### Techniques
- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006/): Active Scanning - If the plugin endpoint is public, adversaries can probe to identify flaws in input validation. Then the adversary could craft prompt injections that will exploit the discovered flaw. 

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data - Adversaries can exploit flaws in LLM plugin input validation and sanitization by carefully crafting malicious inputs containing adversarial payloads. Insufficient validation enables adversaries to inject payloads that compromise plugin logic when interpreted. The payloads trigger unintended behaviors in the plugins which the adversary can leverage to achieve their objectives.

- [AML.T0049](https://atlas.mitre.org/techniques/AML.T0049/): Exploit Public-Facing Application - Any unintended public interface to LLM plugins can be exploited by adversaries sending crafted inputs. Similar to AML.T0006 above. 

#### Mitigations

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015): Adversarial Input Detection - Catch exploit attempts on plugins.

- [AML.M0016](https://atlas.mitre.org/mitigations/AML.M0016): Vulnerability Scanning - Find flaws to fix.


#### Possible Additions

**Possible New Techniques**

- Plugin Enumeration - Adversaries may scan a system and enumerate available plugins and extensions to identify ones that are vulnerable or useful for exploitation. Knowing the specific plugins in use provides a roadmap to target plugins with insecure design or known vulnerabilities.

**Possible New Mitigations**

- Enforce Least Privilege Access Control - Implement granular access controls that restrict plugins to only the permissions necessary for their intended functionality. Prevent plugins from accessing resources or performing actions beyond their specified scope. Regularly audit and review access. Likely best practice anyway, so not sure this is truly needed here.

- Require Manual Approval for Sensitive Actions - For sensitive or high-risk actions like payments, PII exposure, or data deletion, require manual approval from the end user even if the plugin requests the action. Do not allow plugins to automatically perform sensitive actions without additional authorization. Log all requests.




# LLM08: Excessive Agency

### Summary

Excessive LLM permissions or autonomy enables unintended harmful actions based on faulty LLM outputs.


### MITRE ATLAS™ 

#### Techniques
- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006/): Active Scanning - The adversary could actively probe the LLM to find prompts that seem to enable elevated permissions

- [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025/): Exfiltration via Cyber Means - Exfiltrating data like logs could help the adversary understand how to manipulate the LLM 

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data - Crafting adversarial prompts could then exploit elevated permissions to take unintended actions

#### Mitigations
- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004): Restrict Number of ML Model Queries - Limit ability to probe model. 

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015): Adversarial Input Detection - Catch abnormal permission elevation attempts.

#### Possible Additions

**Possible Additional Mitigations** 

- Audit LLM Activities - Continuously monitor and audit LLM behaviors, permissions, and access to detect anomalies or actions outside expected boundaries that could signal unintended consequences.

- Limit LLM Capabilities - Carefully restrict the specific functions and capabilities the LLM can perform to only those necessary for its core intended purpose, reducing potential for unintended actions.



# LLM09: Overreliance

### Summary

Blindly trusting LLM outputs can lead to issues like misinformation, legal problems, and reputational damage without verification.


### MITRE ATLAS™ 

#### Techniques

N.A. Since Overreliance is not truly an attack vector.

#### Mitigations

- [AML.M0015: Adversarial Input Detection](/mitigations/AML.M0015) - Detect and block inputs that deviate from known benign behavior through techniques like anomaly detection on queries and user input. This can prevent malicious or erroneous inputs from reaching downstream systems and users.

- [AML.M0018: User Training](/mitigations/AML.M0018) - Train users on adversarial machine learning risks so they understand the potential for issues with LLMs and do not blindly trust outputs. Set clear expectations on when manual review is required.

#### Possible Additions

**Possible Additional Mitigations** 

- Modularize Complex Tasks - Break down complex prompts requiring reasoning into smaller subtasks across multiple agents to reduce reliance on any single system. This limits the blast radius from any single erroneous output.

- Responsible Interface Design - Design interfaces to promote safe and responsible use through visibility into model limitations, controls like confidence thresholds, and appropriate framing of LLM capabilities. This prevents users from blindly trusting outputs.

- Oversight for Risky Actions - Require human approval before allowing high-risk actions suggested by LLMs like publishing content or executing code. This acts as a check against blindly trusting potentially unsafe actions.

- Monitor and Log Interactions - Continuously monitor and log user interactions and queries to the LLM. Logs can be analyzed to identify potentially malicious or erroneous inputs as well as find patterns of overreliance for additional user training.

- Independent Oversight - Establish independent oversight teams responsible for auditing logs, reviewing outlier cases, and assessing risks. This provides an unbiased perspective to identify potential issues.



# LLM10: Model Theft

### Summary
LLM theft can lead to financial losses, competitive disadvantage, and unauthorized data access.


### MITRE ATLAS™ 

#### Techniques
- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006): Active Scanning - Active scanning enables adversaries to identify vulnerabilities in systems housing private language models, which can then be exploited to gain unauthorized access for stealing intellectual property or sensitive training data.

- [AML.T0012](https://atlas.mitre.org/techniques/AML.T0012): Valid Accounts - Compromised valid credentials allow adversaries to bypass access controls and gain unauthorized access to private language models and related systems, enabling theft of intellectual property and sensitive training data.  

- [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024): Exfiltration via ML Inference API - The inference API provides an avenue for adversaries to extract unauthorized functional copies of private language models, enabling intellectual property theft.

- [AML.T0035](https://atlas.mitre.org/techniques/AML.T0035): ML Artifact Collection - Collecting language model artifacts and related data, while preparatory, could provide assets enabling direct model theft. 

- [AML.T0037](https://atlas.mitre.org/techniques/AML.T0037): Data from Local System - Accessing local systems housing models, while requiring existing access, could enable theft of artifacts and data to steal intellectual property.

- [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040): ML Model Inference API Access - Inference API access provides a duplicative pathway like T0024 that could enable model theft through extraction.

#### Mitigations
- [AML.M0005](https://atlas.mitre.org/mitigations/AML.M0005): Control Access to ML Models and Data at Rest - Prevent theft by restricting access.

- [AML.M0012](https://atlas.mitre.org/mitigations/AML.M0012): Encrypt Sensitive Information - Protect models and data via encryption.


#### Possible Additions

**Possible New Techniques**

- Insider Model Leak - An insider with authorized access exfiltrates proprietary language models or related artifacts like training data, enabling theft of intellectual property. This could involve transferring files to unauthorized systems, cloud storage, or removable media.  

- Model Data Exfiltration - An adversary exploits vulnerabilities or misconfigurations to bypass protections and exfiltrate private model data through side channels. This could involve carefully crafted prompts to extract data or exploiting side channels like timing or cache access patterns.

Yes, that would be a distinct and valuable mitigation to add. Here is how I would incorporate it:

**Possible New Mitigations**

- Model Access Monitoring - Continuously monitor and log access to language models and related systems like training data repositories to detect potential unauthorized access or exfiltration attempts. Anomalies in access patterns can indicate malicious activity.

- Development Process Governance - Embed comprehensive security practices into the MLOps software development lifecycle including access control, anomaly detection, testing, monitoring, and incident response. This provides protections against theft throughout the model development process. 

- Prompt Filtering - Implement filtering of prompts and limit the complexity of allowed model queries to prevent extraction of private data like training samples. This mitigates the risk of model theft through prompting.

- Model Watermarking - Embed unique watermarks directly into language models to enable identification of theft and unauthorized distribution. Watermarks act as persistent forensic evidence if models are exfiltrated.

- User Behavior Analytics - Monitor user activities like queries, data access, and commands to detect anomalous actions that may indicate unauthorized access attempts to LLM repositories. This can help in early detection of insider threats or compromised credentials, thereby preventing potential model theft.

