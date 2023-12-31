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

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004/): Restrict Number of ML Model Queries. Limit the total number and rate of queries a user can perform. Suggested approaches: - Limit the number of queries users can perform in a given interval to hinder an attacker's ability to send computationally expensive inputs - Limit the amount of information an attacker can learn about a model's ontology through API queries. - Limit the volume of API queries in a given period of time to regulate the amount and fidelity of potentially sensitive information an attacker can learn. - Limit the number of queries users can perform in a given interval to shrink the attack surface for black-box attacks. - Limit the number of queries users can perform in a given interval to prevent a denial of service.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.

#### Possible Additions

**New Technique Proposals**

- AML.TXXXX: Insert Malicious Prompt via User Upload - Adding a malicious prompt to user-provided content like resumes, support tickets, etc. that then compromises the LLM when processed.

- AML.TXXXX: Embed Malicious Prompt in External Data Source - Embedding a malicious prompt in any external data sources like files, databases, websites, etc. that compromises the LLM when processed. 

- AML.TXXXX: Exploit LLM Plugin - Exploiting vulnerabilities in LLM plugins to manipulate behavior with a malicious prompt.

**New Mitigation Proposals**

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
- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002/): Passive ML Output Obfuscation. Decreasing the fidelity of model outputs provided to the end user can reduce an adversaries ability to extract information about the model and optimize attacks for the model. Suggested approaches: - Restrict the number of results shown - Limit specificity of output class ontology - Use randomized smoothing techniques - Reduce the precision of numerical outputs](https://atlas.mitre.org/mitigations/AML.M0002/): Passive ML Output Obfuscation. Decrease fidelity of model outputs to users to reduce adversarial knowledge for attacks.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.


#### Possible Additions

**New Technique Proposals**

- AML.TXXXX: Downstream System Spoofing - An adversary could manipulate LLM output formats, identifiers, and credentials to impersonate trusted downstream services and bypass authentication checks. This causes improper access and misleading log data.

- AML.TXXXX: Control Flow Tampering - By injecting malicious logic bombs, loops, recursion, and other control flow altering payloads into LLM outputs, an adversary can disrupt downstream system operations. This could cause crashes, instability, or unauthorized changes. 

- AML.TXXXX: Log Tampering - An adversary may tamper with logging configurations or directly modify log data related to LLM outputs to remove evidence of their attack. This complicates investigation and attribution by auditors.

- AML.TXXXX: Information Leakage Amplification - Carefully crafted LLM outputs can trigger verbose error messages and logging from downstream systems. An adversary can extract sensitive details and troubleshooting data.

- AML.TXXXX: Privilege Escalation - If LLM outputs allow code execution on downstream systems, an adversary can perform vertical privilege escalation by compromising process/service accounts and executing commands. Lateral movement with stolen credentials expands access.

**New Mitigation Proposals** 

- AML.MXXXX: Output Encoding - Properly encoding LLM outputs based on the downstream execution context (e.g. browsers, OS shells, DBs) prevents exploits like XSS, command injection, and SQLi.

- AML.MXXXX: LLM Output Sandboxing - Running LLM outputs in an isolated sandbox environment limits the damage and systemic impact of any malicious payloads generated. However, this may reduce functionality.

- AML.MXXXX: LLM Output Logging - Securely logging all LLM outputs to an immutable audit log enables attack investigation, forensics, and attribution after incidents. Proper access controls on logs are critical.




# LLM03: Training Data Poisoning

### Summary

Tampered training data can impair LLMs, leading to compromised security, accuracy, or ethical behavior.

### MITRE ATLAS™ 

#### Techniques
- [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020): Poison Training Data - An attacker could poison the training data used to train the victim LLM. This allows the attacker to embed vulnerabilities that can be triggered later with crafted inputs.

- [AML.T0018](https://atlas.mitre.org/techniques/AML.T0018): Backdoor ML Model - An attacker could backdoor the LLM by training it on poisoned data that associates a trigger with a malicious output. This backdoor could later be used to force unethical or flawed behavior.

- [AML.T0019](https://atlas.mitre.org/techniques/AML.T0019): Publish Poisoned Datasets - An attacker could publish a poisoned dataset that the victim organization then unintentionally uses to train their LLM, poisoning it.


#### Mitigations

- [AML.M0007](https://atlas.mitre.org/mitigations/AML.M0007/): Sanitize Training Data. Detect and remove or remediate poisoned training data prior to model training and recurrently for an active learning model. Implement a filter to limit ingested training data. Establish a content policy that would remove unwanted content such as certain explicit or offensive language from being used. Detect and remove or remediate poisoned data to avoid adversarial model drift or backdoor attacks. Detect modification of data and labels which may cause adversarial model drift or backdoor attacks. Prevent attackers from leveraging poisoned datasets to launch backdoor attacks against a model.

- [AML.M0014](https://atlas.mitre.org/mitigations/AML.M0014/): Verify ML Artifacts. Verify the cryptographic checksum of all machine learning artifacts to verify that the file was not modified by an attacker. Determine validity of published data in order to avoid using poisoned data that introduces vulnerabilities. Introduce proper checking of signatures to ensure that unsafe ML artifacts will not be executed in the system. These artifacts may have a detrimental effect on the system. Introduce proper checking of signatures to ensure that unsafe ML artifacts will not be introduced to the system.


#### Possible Additions

**New Technique Proposals**

- AML.TXXXX: Unintended Data Exposure in Training: An authorized user may accidentally expose private or sensitive data (e.g. PII, financial data, confidential documents) that then gets incorporated into the model's training data. This can lead to information leakage if the model memorizes and regurgitates that private data during inference. Attackers could exploit this to extract sensitive data.

- AML.TXXXX: Insufficient Access Controls on Training Data: If proper access controls are not enforced on what data can be used for model training, an attacker may be able to introduce arbitrary external training data from unsafe sources. Without sufficient validation, this poisoned data could be used to train the model, embedding vulnerabilities that attackers can later exploit. 

**New Mitigation Proposals** 

- AML.MXXXX: Isolate Models and Data: By proactively separating models and their associated training datasets into different environments based on sensitivity levels, the blast radius of a poisoning attack can be limited. Critical models can be isolated from general purpose models and their respective data sources. This makes it harder for an attacker to impact business-critical models.

- AML.MXXXX: Detect Poisoned Outputs: Monitoring the model's outputs during inference can help detect anomalous behaviors that may indicate training data poisoning. For example, sudden drops in accuracy, spikes in certain predictions, or outputting unintended data could signal that the model was trained on manipulated data. Early detection of these signals can prevent harm.

- AML.MXXXX: Adversarial Training: Intentionally injecting adversarial examples during model training makes the model more robust to poisoned data points an attacker may introduce. The model learns to be less sensitive to small perturbations. This minimizes the impact of poisoning attacks.


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

- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004/): Restrict Number of ML Model Queries. Limit the total number and rate of queries a user can perform. Suggested approaches: - Limit the number of queries users can perform in a given interval to hinder an attacker's ability to send computationally expensive inputs - Limit the amount of information an attacker can learn about a model's ontology through API queries. - Limit the volume of API queries in a given period of time to regulate the amount and fidelity of potentially sensitive information an attacker can learn. - Limit the number of queries users can perform in a given interval to shrink the attack surface for black-box attacks. - Limit the number of queries users can perform in a given interval to prevent a denial of service.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.

- [AML.M0016](https://atlas.mitre.org/mitigations/AML.M0016/): Vulnerability Scanning. Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for arbitrary code execution. Scan ML artifacts for vulnerabilities before execution.

- [AML.M0017](https://atlas.mitre.org/mitigations/AML.M0017/): Model Distribution Methods. Deploying ML models to edge devices can increase the attack surface of the system. Consider serving models in the cloud to reduce the level of access the adversary has to the model. Not distributing the model in software to edge devices, can limit an adversary's ability to gain full access to the model. With full access to the model, an adversary could perform white-box attacks. An adversary could repackage the application with a malicious version of the model.

#### Possible Additions

**New Technique Proposals**

- AML.TXXXX: Recursive Context Expansion - An adversary crafts inputs containing text triggers that cause the language model to continuously expand the context window and reprocess the input in a recursive loop. Each iteration consumes additional memory and compute resources. Sending many such inputs can rapidly exhaust available resources, resulting in denial of service. Note this could be a subtechnique of craft adversarial data.

- AML.TXXXX: Benign Query Resource Exhaustion - An adversary identifies benign input text which does not appear obviously malicious but leads to unpredictable resource consumption due to the language model's processing. Queries submitted through public interfaces get processed by downstream models in a way that consumes substantial resources due to lengthy text generation or repeated context expansion. The adversary can send many such queries to degrade performance and availability. 

**New Mitigation Proposals**  

- AML.MXXXX: Limit Context Expansions - The language model is configured to limit the number of recursive context expansions that can occur per request. This prevents adversaries from causing excessive processing through inputs that continuously trigger context re-generation. Hard thresholds prevent unlimited recursive expansion scenarios.

- AML.MXXXX: Resource Consumption Monitoring - Continuously monitor CPU, memory, and other resource consumption metrics to identify abnormal behavior indicative of a DoS attack.



# LLM05: Supply Chain Vulnerabilities

### Summary 

Depending on compromised third-party components can undermine system integrity, causing data breaches and failures.


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

- [AML.M0002](https://atlas.mitre.org/mitigations/AML.M0002/): Passive ML Output Obfuscation. Decreasing the fidelity of model outputs provided to the end user can reduce an adversaries ability to extract information about the model and optimize attacks for the model. Suggested approaches: - Restrict the number of results shown - Limit specificity of output class ontology - Use randomized smoothing techniques - Reduce the precision of numerical outputs](https://atlas.mitre.org/mitigations/AML.M0002/): Passive ML Output Obfuscation. Decrease fidelity of model outputs to users to reduce adversarial knowledge for attacks.


- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004/): Restrict Number of ML Model Queries. Limit the total number and rate of queries a user can perform. Suggested approaches: - Limit the number of queries users can perform in a given interval to hinder an attacker's ability to send computationally expensive inputs - Limit the amount of information an attacker can learn about a model's ontology through API queries. - Limit the volume of API queries in a given period of time to regulate the amount and fidelity of potentially sensitive information an attacker can learn. - Limit the number of queries users can perform in a given interval to shrink the attack surface for black-box attacks. - Limit the number of queries users can perform in a given interval to prevent a denial of service.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.



# LLM07: Insecure Plugin Design 

### Summary
LLM plugins processing untrusted inputs without validation can enable severe exploits like remote code execution.



### MITRE ATLAS™ 

#### Techniques
- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006/): Active Scanning - If the plugin endpoint is public, adversaries can probe to identify flaws in input validation. Then the adversary could craft prompt injections that will exploit the discovered flaw. 

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data - Adversaries can exploit flaws in LLM plugin input validation and sanitization by carefully crafting malicious inputs containing adversarial payloads. Insufficient validation enables adversaries to inject payloads that compromise plugin logic when interpreted. The payloads trigger unintended behaviors in the plugins which the adversary can leverage to achieve their objectives.

- [AML.T0049](https://atlas.mitre.org/techniques/AML.T0049/): Exploit Public-Facing Application - Any unintended public interface to LLM plugins can be exploited by adversaries sending crafted inputs. Similar to AML.T0006 above. 

#### Mitigations

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.

- [AML.M0016](https://atlas.mitre.org/mitigations/AML.M0016/): Vulnerability Scanning. Vulnerability scanning is used to find potentially exploitable software vulnerabilities to remediate them. File formats such as pickle files that are commonly used to store machine learning models can contain exploits that allow for arbitrary code execution. Scan ML artifacts for vulnerabilities before execution.


#### Possible Additions

**New Technique Proposals**

- AML.TXXXX: Plugin Enumeration - Adversaries may scan a system and enumerate available plugins and extensions to identify ones that are vulnerable or useful for exploitation. Knowing the specific plugins in use provides a roadmap to target plugins with insecure design or known vulnerabilities.

**New Mitigation Proposals**

- AML.MXXXX: Enforce Least Privilege Access Control - Implement granular access controls that restrict plugins to only the permissions necessary for their intended functionality. Prevent plugins from accessing resources or performing actions beyond their specified scope. Regularly audit and review access. Likely best practice anyway, so not sure this is truly needed here.

- AML.MXXXX: Require Manual Approval for Sensitive Actions - For sensitive or high-risk actions like payments, PII exposure, or data deletion, require manual approval from the end user even if the plugin requests the action. Do not allow plugins to automatically perform sensitive actions without additional authorization. Log all requests.




# LLM08: Excessive Agency

### Summary

Excessive LLM permissions or autonomy enables unintended harmful actions based on faulty LLM outputs.


### MITRE ATLAS™ 

#### Techniques
- [AML.T0006](https://atlas.mitre.org/techniques/AML.T0006/): Active Scanning - The adversary could actively probe the LLM to find prompts that seem to enable elevated permissions

- [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025/): Exfiltration via Cyber Means - Exfiltrating data like logs could help the adversary understand how to manipulate the LLM 

- [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043/): Craft Adversarial Data - Crafting adversarial prompts could then exploit elevated permissions to take unintended actions

#### Mitigations
- [AML.M0004](https://atlas.mitre.org/mitigations/AML.M0004/): Restrict Number of ML Model Queries. Limit the total number and rate of queries a user can perform. Suggested approaches: - Limit the number of queries users can perform in a given interval to hinder an attacker's ability to send computationally expensive inputs - Limit the amount of information an attacker can learn about a model's ontology through API queries. - Limit the volume of API queries in a given period of time to regulate the amount and fidelity of potentially sensitive information an attacker can learn. - Limit the number of queries users can perform in a given interval to shrink the attack surface for black-box attacks. - Limit the number of queries users can perform in a given interval to prevent a denial of service.

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.

#### Possible Additions

**Possible Additional Mitigations** 

- AML.MXXXX: Audit LLM Activities - Continuously monitor and audit LLM behaviors, permissions, and access to detect anomalies or actions outside expected boundaries that could signal unintended consequences.

- AML.MXXXX: Limit LLM Capabilities - Carefully restrict the specific functions and capabilities the LLM can perform to only those necessary for its core intended purpose, reducing potential for unintended actions.



# LLM09: Overreliance

### Summary

Blindly trusting LLM outputs can lead to issues like misinformation, legal problems, and reputational damage without verification.


### MITRE ATLAS™ 

#### Techniques

N.A. Since Overreliance is not truly an attack vector.

#### Mitigations

- [AML.M0015](https://atlas.mitre.org/mitigations/AML.M0015/): Adversarial Input Detection. Detect and block adversarial inputs or atypical queries that deviate from known benign behavior, exhibit behavior patterns observed in previous attacks or that come from potentially malicious IPs. Incorporate adversarial detection algorithms into the ML system prior to the ML model. Prevent an attacker from introducing adversarial data into the system. Monitor queries and query patterns to the target model, block access if suspicious queries are detected. Assess queries before inference call or enforce timeout policy for queries which consume excessive resources. Incorporate adversarial input detection into the pipeline before inputs reach the model.

- [AML.M0018](https://atlas.mitre.org/mitigations/AML.M0018/): User Training. Educate ML model developers on secure coding practices and ML vulnerabilities. Training users to be able to identify attempts at manipulation will make them less susceptible to performing techniques that cause the execution of malicious code. Train users to identify attempts of manipulation to prevent them from running unsafe code which when executed could develop unsafe artifacts. These artifacts may have a detrimental effect on the system.

#### Possible Additions

**Possible Additional Mitigations** 

- AML.MXXXX: Responsible Interface Design - Design interfaces to promote safe and responsible use through visibility into model limitations, controls like confidence thresholds, and appropriate framing of LLM capabilities. This prevents users from blindly trusting outputs.

- AML.MXXXX: Oversight for Risky Actions - Require human approval before allowing high-risk actions suggested by LLMs like publishing content or executing code. This acts as a check against blindly trusting potentially unsafe actions.

- AML.MXXXX: Monitor and Log Interactions - Continuously monitor and log user interactions and queries to the LLM. Logs can be analyzed to identify potentially malicious or erroneous inputs as well as find patterns of overreliance for additional user training.

- AML.MXXXX: Independent Oversight - Establish independent oversight teams responsible for auditing logs, reviewing outlier cases, and assessing risks. This provides an unbiased perspective to identify potential issues.



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
- [AML.M0005](https://atlas.mitre.org/mitigations/AML.M0005/): Control Access to ML Models and Data at Rest. Establish access controls on internal model registries and limit internal access to production models. Limit access to training data only to approved users. Access controls can prevent tampering with ML artifacts and prevent unauthorized copying.

- [AML.M0012](https://atlas.mitre.org/mitigations/AML.M0012/): Encrypt Sensitive Information. Encrypt sensitive data such as ML models to protect against adversaries attempting to access sensitive data. Protect machine learning artifacts with encryption. Protect machine learning artifacts with encryption.


#### Possible Additions

**New Technique Proposals**

- AML.TXXXX: Insider Model Leak - An insider with authorized access exfiltrates proprietary language models or related artifacts like training data, enabling theft of intellectual property. This could involve transferring files to unauthorized systems, cloud storage, or removable media.  

- AML.TXXXX: Model Data Exfiltration - An adversary exploits vulnerabilities or misconfigurations to bypass protections and exfiltrate private model data through side channels. This could involve carefully crafted prompts to extract data or exploiting side channels like timing or cache access patterns.

**New Mitigation Proposals**

- AML.MXXXX: Model Access Monitoring - Continuously monitor and log access to language models and related systems like training data repositories to detect potential unauthorized access or exfiltration attempts. Anomalies in access patterns can indicate malicious activity.

- AML.MXXXX: Development Process Governance - Embed comprehensive security practices into the MLOps software development lifecycle including access control, anomaly detection, testing, monitoring, and incident response. This provides protections against theft throughout the model development process. 

- AML.MXXXX: Model Watermarking - Embed unique watermarks directly into language models to enable identification of theft and unauthorized distribution. Watermarks act as persistent forensic evidence if models are exfiltrated.

- AML.MXXXX: User Behavior Analytics - Monitor user activities like queries, data access, and commands to detect anomalous actions that may indicate unauthorized access attempts to LLM repositories. This can help in early detection of insider threats or compromised credentials, thereby preventing potential model theft.

