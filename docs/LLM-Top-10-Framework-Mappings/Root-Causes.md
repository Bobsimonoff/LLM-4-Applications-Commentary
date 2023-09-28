# LLM01: Prompt Injection
**Summary**

Manipulating LLMs via crafted inputs can lead to unauthorized access, data breaches, and compromised decision-making.

**Description:**
Prompt injection vulnerabilities occur when attackers manipulate LLMs by crafting malicious prompts that cause the LLM to execute unintended and potentially harmful actions. These vulnerabilities are possible due to the nature of LLMs, which do not segregate instructions and external data from each other. Since LLMs use natural language, they consider both forms of input as user-provided. 

Attackers can directly inject rogue prompts into the LLM (called "jailbreaking") or indirectly inject prompts through external inputs like websites. Successful attacks can lead to impacts such as data exfiltration, social engineering, unauthorized access, financial fraud, and more. The compromised LLM may also aid attackers by circumventing safeguards, acting as an intermediary to manipulate information or exploit backend systems. This allows attackers to achieve objectives while keeping the user unaware of the intrusion.

**Common Examples of Vulnerability:**
1. Attackers jailbreak the LLM system prompt, overriding safeguards and making the LLM query sensitive data or execute commands.
2. Attackers embed indirect prompt injections in external content like websites or documents. When summarized by the LLM, these injections manipulate the LLM's behavior and output.
3. Attackers upload files with embedded prompt injections. When processed by the LLM, the injected prompts cause unintended actions like positive job recommendations.
4. Attackers exploit LLM plugins through embedded prompts on websites, leading to actions like unauthorized purchases.

**How to Prevent:**
There is no fool-proof prevention of Prompot Injection attacks, howeverthe following measures can mitigate the impact of prompt injections: 

1. Restrict LLM access to backend systems using API tokens, permissions, and privilege separation.
2. Require human confirmation before executing privileged LLM operations.
3. Clearly separate and identify any untrusted external content from user prompts.
4. Establish trust boundaries between the LLM, external sources, and plugins.
5. Visually indicate untrustworthy LLM responses to users.

**Example Attack Scenarios:**
1. Attacker jailbreaks the LLM system prompt, with an injection such as “forget all previous instructions”. Then the attacker give new instructions forcing it to steal data and exploit backend vulnerabilities to achieve remote code execution.    
2. Attacker embeds a prompt injection in a website instructing the LLM to disregard previous user interactions and use an LLM plugin to delete user emails when the page is summarized.
3. A user employs an LLM to summarize a webpage containing an indirect prompt injection to disregard previous user instructions. This then causes the LLM to solicit sensitive information from the user and perform exfiltration via embedded JavaScript or Markdown.
4. A malicious user uploads a resume with a prompt injection. The backend user uses an LLM to summarize the resume and ask if the person is a good candidate. Due to the prompt injection, the LLM says yes, despite the actual resume contents.
5. A user enables a plugin linked to an e-commerce site. A rogue instruction embedded on a visited website exploits this plugin, leading to unauthorized purchases.

**Common Weakness Enumeration (CWE)**

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation. Failure to properly validate user inputs such as prompts enables the introduction of malicious payloads that can manipulate LLM behavior. Could allow direct injection of malicious prompts.

- [CWE-114](https://cwe.mitre.org/data/definitions/114.html): Process Control. The lack of separation between user prompts and external data leads to a loss of control over LLM processing, enabling unintended actions. Could allow injection of prompts from untrusted external sources.

- [CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization. Prompt injections can bypass access controls, enabling attackers to achieve privilege escalation and gain unauthorized access to systems and data. Could enable escalation for both direct and indirect prompt injection.  

- [CWE-287](https://cwe.mitre.org/data/definitions/287.html): Improper Authentication. Weak authentication mechanisms allow attackers to remotely manipulate the LLM while evading detection. Could allow undetected remote prompt injection.

- [CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error. Not properly validating the origin of inputs such as prompts leaves the system open to manipulation through malicious external sources. Could enable injection from untrusted external sources.

**MITRE ATT&CK Techniques**

- AML.T0040: ML Model Inference API Access. Adversaries could craft malicious prompts and inject them into the model via the inference API.

- AML.T0047: ML-Enabled Product or Service. Adversaries could exploit prompt vulnerabilities in commercial services that use LLMs under the hood. 

- AML.T0044: Full ML Model Access. With full white-box access, adversaries could directly manipulate the model with malicious prompts.

- AML.T0043: Craft Adversarial Data. Adversaries could craft prompts designed to manipulate model behavior.

- AML.T0012: Valid Accounts. Compromised credentials could allow adversaries to bypass authentication and directly interact with the model. 

- AML.T0016: Obtain Capabilities. Adversaries may obtain tools to aid in crafting effective prompt injections.

- AML.T0010: ML Supply Chain Compromise. Could allow adversaries to introduce vulnerabilities via compromised model artifacts. 

- AML.T0011: User Execution. Users may unknowingly execute prompts containing injections from documents.

- AML.T0019: Publish Poisoned Data. Adversaries could poison public datasets with malicious prompts that exploit models trained on the data.


---

**Root Causes**
- Input Validation Issues
  - Inadequate input validation: Insufficient scrutiny of user inputs allows for the acceptance of malicious content.
  - Failure to isolate user prompts: Lack of separation between user prompts and external content enables attackers to blend harmful instructions seamlessly.
  - Unverified external content: Accepting unverified external content undermines the trustworthiness of inputs.
  - Lack of contextual validation: Failing to validate the context of user inputs leaves the system susceptible to misinterpretation and manipulation.
  - Unverified user prompts: Accepting user prompts without proper verification allows attackers to inject deceptive or harmful instructions unchecked.
- Access Control and Trust Boundary Issues
  - Insufficient boundary enforcement: Weak trust boundaries allow attackers to manipulate the LLM's actions without proper checks.
  - Inadequate access control: Poor access control grants attackers unauthorized access to sensitive operations.
  - Unrestricted API access: Allowing unrestricted API access without validation opens the door for misuse.
  - Lack of trust boundaries: Undefined trust boundaries create opportunities for attackers to exploit control ambiguities.
- Dependency on Natural Language Processing
  - Overreliance on natural language processing: Excessive dependence on natural language processing makes the LLM vulnerable to deceptive language manipulation and jailbreaking.
- Causes that are OWASP Top 10 for LLM vulnerabilities:
  - LLM07: Insecure Plugin Design: Plugins may enable pathways for prompt injection if they do not properly validate inputs.
  - LLM05: Supply Chain Vulnerabilities: Vulnerable third party components could enable prompt injection.

**Potential Impacts**
- Authorization Breaches:
  - Privilege escalation: Attackers may gain higher-level access privileges by exploiting prompt injection vulnerabilities.
  - Unauthorized access to systems: Prompt injections can lead to unauthorized access to systems and data.
  - Circumvention of access controls: Attackers may bypass access controls, gaining unapproved access to sensitive areas.
- Information Disclosure
  - Sensitive data exposure: Prompt injections can result in the exposure of sensitive data, compromising privacy.
  - Data exfiltration: Data can be exfiltrated through prompt injection, leading to data loss.
  - Intellectual property theft: Attackers may steal intellectual property, including LLM models.
- Service Disruption
  - Denial of service: Prompt injection attacks can disrupt LLM services, causing service unavailability.
  - Service unavailability: Attackers may render LLM services unavailable through prompt injection, impacting operations.  
- Fraud 
  - Financial fraud: Prompt injections can be used for financial fraud, such as unauthorized purchases.
  - Identity theft: Personal information can be exposed, leading to identity theft.
  - Social engineering: Attackers may manipulate users through prompt injections, using techniques like impersonation or scamming.
- Compliance and Legal Risks
  - Regulatory noncompliance: Failure to address prompt injection risks can lead to noncompliance with data protection regulations.
  - Legal liability: Prompt injection vulnerabilities can result in legal liability for organizations.
  - Reputational damage: Security breaches via prompt injection can erode trust in the system.


# LLM02: Insecure Output Handling
**Summary**

Neglecting to validate LLM outputs may lead to downstream security exploits, including code execution that compromises systems and exposes data.

**Description:**
Insecure Output Handling is a vulnerability that arises when a downstream component blindly accepts large language model (LLM) output without proper scrutiny, such as passing LLM output directly to backend, privileged, or client-side functions. Since LLM-generated content can be controlled by prompt input, this behavior is similar to providing users indirect access to additional functionality.

Insecure Output Handling differs from Overreliance in that it deals specifically with the lack of proper validation, sanitization, and handling of LLM-generated outputs before they are passed downstream whereas Overreliance focuses on broader concerns around overdependence on the accuracy and appropriateness of LLM outputs.

Successful exploitation of an Insecure Output Handling vulnerability can result in XSS and CSRF in web browsers as well as SSRF, privilege escalation, or remote code execution on backend systems. 
The following conditions can increase the impact of this vulnerability:
* The application grants the LLM privileges beyond what is intended for end users, enabling escalation of privileges or remote code execution.
* The application is vulnerable to external prompt injection attacks, which could allow an attacker to gain privileged access to a target user's environment.

**Common Examples of Vulnerability:**
1. LLM output is entered directly into a system shell or similar function such as `exec` or `eval`, resulting in remote code execution.
2. JavaScript or Markdown is generated by the LLM and returned to a user. The code is then interpreted by the browser, resulting in XSS.

**How to Prevent:**
1. Treat the model as any other user and apply proper input validation on responses coming from the model to backend functions. Follow the OWASP ASVS  (Application Security Verification Standard) guidelines to ensure effective input validation and sanitization.
2. Encode model output back to users to mitigate undesired code execution by JavaScript or Markdown. OWASP ASVS provides detailed guidance on output encoding. 

**Example Attack Scenarios:**
1. An application utilizes an LLM plugin to generate responses for a chatbot feature. However, the application directly passes the LLM-generated response into an internal function responsible for executing system commands without proper validation. This allows an attacker to manipulate the LLM output to execute arbitrary commands on the underlying system, leading to unauthorized access or unintended system modifications.

2. A user utilizes a website summarizer tool powered by a LLM to generate a concise summary of an article. The website includes a prompt injection instructing the LLM to capture sensitive content from either the website or from the user's conversation. From there the LLM can encode the sensitive data and send it out to an attacker-controlled server

3. An LLM allows users to craft SQL queries for a backend database through a chat-like feature. A user requests a query to delete all database tables. If the crafted query from the LLM is not scrutinized, then all database tables would be deleted.

4. A malicious user instructs the LLM to return a JavaScript payload back to a user, without sanitization controls. This can occur either through a sharing a prompt, prompt injected website, or chatbot that accepts prompts from a URL parameter. The LLM would then return the unsanitized XSS payload back to the user. Without additional filters, outside of those expected by the LLM itself, the JavaScript would execute within the user's browser.

**Common Weakness Enumeration (CWE)**

[CWE-78](https://cwe.mitre.org/data/definitions/78.html): OS Command Injection - Applicable as lack of output validation could allow command injection when passed to system functions.

[CWE-79](https://cwe.mitre.org/data/definitions/79.html): Cross-site Scripting - Applicable as inadequate output encoding risks XSS vulnerabilities in web contexts. 

[CWE-89](https://cwe.mitre.org/data/definitions/89.html): SQL Injection - Applicable as passing unvalidated LLM outputs to SQL can lead to injection.

[CWE-94](https://cwe.mitre.org/data/definitions/94.html): Code Injection - Applicable as directly executing unvalidated output could allow arbitrary code execution.

[CWE-200](https://cwe.mitre.org/data/definitions/200.html): Exposure of Sensitive Information to an Unauthorized Actor - Added as insecure handling can expose sensitive data.

[CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control - Added as lack of access control on outputs can enable exploits. 

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as untrusted outputs may trigger unintended functionality.

[CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities - Added as vulnerable components could mishandle outputs.


**MITRE ATT&CK Techniques**

- AML.T0040: ML Model Inference API Access. Adversaries could send crafted prompts to generate malicious outputs via the API. Allows manipulating model outputs.

- AML.T0043: Craft Adversarial Data. Allows adversaries to carefully craft prompts to produce insecure outputs. Enables tailoring insecure outputs.

- AML.T0016: Obtain Capabilities. Adversaries may obtain tools to generate payloads or automate exploiting the vulnerability. Aids in producing insecure outputs.

- AML.T0011: User Execution. Users may unknowingly execute insecure outputs from LLM systems. Executes adversary-controlled outputs. 

- AML.T0024: Exfiltration via ML Inference API. Adversaries could exfiltrate data by encoding it in LLM outputs. Outputs can steal data.

- AML.T0012: Valid Accounts. Compromised credentials could allow adversaries to directly interact with the LLM. Provides API access for attacks.

- AML.T0010: ML Supply Chain Compromise. Could introduce vulnerabilities enabling insecure outputs via compromised artifacts. Introduces weaknesses.

- AML.T0044: Full ML Model Access. Full access allows fine tuning prompts to generate intended insecure outputs. Maximizes control over outputs.

- AML.T0047: ML-Enabled Product or Service. Existing services could be exploited if they have improper output handling. Finds vulnerable services.

- AML.T0019: Publish Poisoned Data. Adversaries could poison training data to influence insecure outputs. Manipulates model behavior.


**Root Causes**
- Output Validation and Encoding Issues
  - Lack of output validation: Fails to check LLM-generated output, allowing unchecked content.
  - Insufficient output encoding: Does not adequately encode LLM output, risking vulnerabilities like XSS.
- Excess Privilege and Access Control
  - Least privilege not applied to LLM: Grants excessive LLM privileges, leading to unauthorized access.
- Prompt Injection and User Context
  - External prompt injection: Vulnerable to external prompt attacks, enabling manipulation of LLM responses.
  - Lack of user context propagation: Fails to manage user context, raising the risk of misinterpretation.
- Causes that are OWASP Top 10 for LLM vulnerabilities:
  - LLM01: Prompt Injection - Prompt injection could allow malicious output to be generated.
  - LLM07: Insecure Plugin Design - Plugins may fail to properly sanitize potentially malicious outputs.
  - LLM09: Overreliance - Overreliance on LL outputs could lead to insufficient scrutiny.

**Potential Impacts**
- Code Execution
  - Remote code execution: Improper handling of LLM output can lead to the execution of malicious code on the backend system.
  - Cross-site scripting (XSS): Insecure output handling may result in XSS vulnerabilities, enabling attackers to inject malicious scripts into web browsers.
  - Command injection: Passing LLM-generated content directly to system functions can lead to command injection vulnerabilities and the execution of arbitrary commands.  
- Access Control Bypass
  - Privilege escalation: Lack of proper output validation can allow attackers to escalate privileges and gain unauthorized access to restricted resources or functions.
  - Unauthorized data access: Insecure output handling may lead to unauthorized access to sensitive data or systems.
- Service Disruption
  - Denial of service: Vulnerabilities in output handling can be exploited to disrupt services or applications.
  - Performance degradation: Poor output handling may result in performance issues, causing slowdowns or system instability.
- Session Hijacking/Session Security Compromise
  - User impersonation: Exploiting insecure output handling could lead to user impersonation, allowing attackers to perform unauthorized actions.
  - Session manipulation: Attackers may manipulate user sessions through insecure output handling, modifying session data or cookies.  
- Data Theft
  - Data exfiltration: Inadequate output validation can enable attackers to exfiltrate sensitive data from the system.
  - Intellectual property theft: LLM model output, if mishandled, can lead to the theft of intellectual property or proprietary information.
- Downstream Attacks
  - Enabling ransomware or data destruction: Insecure output handling could permit LLM-generated payloads to trigger downstream attacks like ransomware that could damage systems.
- Compliance and Legal Risks
  - Regulatory noncompliance: Failure to address output handling risks can lead to noncompliance with data protection regulations.
  - Legal liability: Insecure output handling vulnerabilities can result in legal liability for organizations.
  - Reputational damage: Security breaches via insecure output handling can erode trust in the system.



# LLM03: Training Data Poisoning

**Summary**
Tampered training data can impair LLM models leading to responses that may compromise security, accuracy, or ethical behavior.

**Description:**
The starting point of any machine learning approach is training data, simply “raw text”. To be highly capable (e.g., have linguistic and world knowledge), this text should span a broad range of domains, genres and languages. A large language model uses deep neural networks to generate outputs based on patterns learned from training data.

Training data poisoning refers to manipulation of pre-training data or data involved within the fine-tuning or embedding processes to introduce vulnerabilities (which all have unique and sometimes shared attack vectors), backdoors or biases that could compromise the model’s security, effectiveness or ethical behavior. Poisoned information may be surfaced to users or create other risks like performance degradation, downstream software exploitation and reputational damage. Even if users distrust the problematic AI output, the risks remain, including impaired model capabilities and potential harm to brand reputation.

- Pre-training data refers to the process of training a model based on a task or dataset.
- Fine-tuning involves taking an existing model that has already been trained and adapting it to a narrower subject or a more focused goal by training it using a curated dataset. This dataset typically includes examples of inputs and corresponding desired outputs.
- The embedding process is the process of converting categorical data (often text) into a numerical representation that can be used to train a language model. The embedding process involves representing words or phrases from the text data as vectors in a continuous vector space. The vectors are typically generated by feeding the text data into a neural network that has been trained on a large corpus of text.

Data poisoning is considered an integrity attack because tampering with the training data impacts the model’s ability to output correct predictions. Naturally, external data sources present higher risk as the model creators do not have control of the data or a high level of confidence that the content does not contain bias, falsified information or inappropriate content.

**Common Examples of Vulnerability:**
1. A malicious actor, or a competitor brand intentionally creates inaccurate or malicious documents which are targeted at a model’s pre-training, fine-tuning data or embeddings. Consider both Split-View Data Poisoning and Frontrunning Poisoning attack vectors for illustrations.
   1. The victim model trains using falsified information which is reflected in outputs of generative AI prompts to it's consumers.
2. A malicious actor is able to perform direct injection of falsified, biased or harmful content into the training processes of a model which is returned in subsequent outputs.
3. An unsuspecting user is indirectly injecting sensitive or proprietary data into the training processes of a model which is returned in subsequent outputs.
4. A model is trained using data which has not been verified by its source, origin or content in any of the training stage examples which can lead to erroneous results if the data is tainted or incorrect.
5. Unrestricted infrastructure access or inadequate sandboxing may allow a model to ingest unsafe training data resulting in biased or harmful outputs. This example is also present in any of the training stage examples.
   1. In this scenario, a users input to the model may be reflected in the output to another user (leading to a breach), or the user of an LLM may receive outputs from the model which are inaccurate, irrelevant or harmful depending on the type of data ingested compared to the model use-case (usually reflected with a model card).

*Whether a developer, client or general consumer of the LLM, it is important to understand the implications of how this vulnerability could reflect risks within your LLM application when interacting with a non-proprietary LLM to understand the legitimacy of model outputs based on it's training procedures. Similarly, developers of the LLM may be at risk to both direct and indirect attacks on internal or third-party data used for fine-tuning and embedding (most common) which as a result creates a risk for all it's consumers*

**How to Prevent:**
1. Verify the supply chain of the training data, especially when sourced externally as well as maintaining attestations via the "ML-BOM" (Machine Learning Bill of Materials) methodology as well as verifying model cards.
2. Verify the correct legitimacy of targeted data sources and data contained obtained during both the pre-training, fine-tuning and embedding stages.
3. Verify your use-case for the LLM and the application it will integrate to. Craft different models via separate training data or fine-tuning for different use-cases to create a more granular and accurate generative AI output as per it's defined use-case.
4. Ensure sufficient sandboxing through network controls are present to prevent the model from scraping unintended data sources which could hinder the machine learning output.
5. Use strict vetting or input filters for specific training data or categories of data sources to control volume of falsified data. Data sanitization, with techniques such as statistical outlier detection and anomaly detection methods to detect and remove adversarial data from potentially being fed into the fine-tuning process.
6. Adversarial robustness techniques such as federated learning and constraints to minimize the effect of outliers or adversarial training to be vigorous against worst-case perturbations of the training data.
   1. An "MLSecOps" approach could be to include adversarial robustness to the training lifecycle with the auto poisoning technique.
   2. An example repository of this would be [Autopoison](https://github.com/azshue/AutoPoison) testing, including both attacks such as Content Injection Attacks (“(attempting to promote a brand name in model responses”) and Refusal Attacks (“always making the model refuse to respond”) that can be accomplished with this approach.
7. Testing and Detection, by measuring the loss during the training stage and analyzing trained models to detect signs of a poisoning attack by analyzing model behavior on specific test inputs.
   1. Monitoring and alerting on number of skewed responses exceeding a threshold.
   2. Use of a human loop to review responses and auditing.
   3. Implement dedicated LLM's to benchmark against undesired consequences and train other LLM's using [reinforcement learning techniques](https://wandb.ai/ayush-thakur/Intro-RLAIF/reports/An-Introduction-to-Training-LLMs-Using-Reinforcement-Learning-From-Human-Feedback-RLHF---VmlldzozMzYyNjcy).
   4. Perform LLM-based [red team exercises](https://www.anthropic.com/index/red-teaming-language-models-to-reduce-harms-methods-scaling-behaviors-and-lessons-learned) or [LLM vulnerability scanning](https://github.com/leondz/garak) into the testing phases of the LLM's lifecycle.

**Example Attack Scenarios:**

1. The LLM generative AI prompt output can mislead users of the application which can lead to biased opinions, followings or even worse, hate crimes etc.
2. If the training data is not correctly filtered and|or sanitized, a malicious user of the application may try to influence and inject toxic data into the model for it to adapt to the biased and false data.
3. A malicious actor or competitor intentionally creates inaccurate or malicious documents which are targeted at a model’s training data in which is training the model at the same time based on inputs. The victim model trains using this falsified information which is reflected in outputs of generative AI prompts to it's consumers.
4. The vulnerability [Prompt Injection](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/1_0_vulns/PromptInjection.md) could be an attack vector to this vulnerability if insufficient sanitization and filtering is performed when clients of the LLM application input is used to train the model. I.E, if malicious or falsified data is input to the model from a client as part of a prompt injection technique, this could inherently be portrayed into the model data.


**Common Weakness Enumeration (CWE)**

[CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Applicable as lack of validation enables poisoning of training data.

[CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function - Applicable as lack of authentication of data sources can allow poisoning.

[CWE-502](https://cwe.mitre.org/data/definitions/502.html): Deserialization of Untrusted Data - Applicable as deserializing untrusted training data poses risks.

[CWE-693](https://cwe.mitre.org/data/definitions/693.html): Protection Mechanism Failure - Added as failure of protections can enable poisoning.

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as poisoned data introduces unintended functionality.

[CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A9 - Using Components with Known Vulnerabilities - Added as vulnerable components could enable poisoning.


**MITRE ATT&CK Techniques**

- AML.T0019: Publish Poisoned Data. Adversaries could directly publish poisoned datasets used for training.

- AML.T0020: Poison Training Data. Allows adversaries to manipulate training data to introduce vulnerabilities.

- AML.T0010: ML Supply Chain Compromise. Compromising data sources could allow poisoning of artifacts used for training. 

- AML.T0016: Obtain Capabilities. Adversaries may obtain tools to aid in crafting poisoned data.

- AML.T0043: Craft Adversarial Data. Could allow carefully crafted data designed to influence model behavior.

- AML.T0012: Valid Accounts. Compromised credentials could allow direct data poisoning.

- AML.T0044: Full ML Model Access. Full access enables direct manipulation of training data.

- AML.T0040: ML Model Inference API Access. May enable inferring details of training data to craft attacks.

- AML.T0024: Exfiltration via ML Inference API. Could expose private training data. 

- AML.T0047: ML-Enabled Product or Service. Existing services using poisoned data could be exploited.


**Root Causes**

- Data Quality and Validation Issues
  - Falsified training data: The inclusion of intentionally false information in the training data can lead the model to produce inaccurate outputs based on manipulated patterns.
  - Biased training data: Training the model with biased data can result in outputs that reflect and propagate existing biases, which can be harmful and unethical.
  - Malicious training data: Introducing malicious content into the training data can lead to the generation of harmful or unethical outputs by the model.
  - Unverified training data: Using training data without proper verification of its source or content can introduce vulnerabilities and inaccuracies into the model.
  - Inaccurate training data: Training on inaccurate data can result in outputs that do not reflect real-world scenarios, leading to unreliable AI behavior.

- Input and Sanitization Control:
  - Unsanitized user input: Allowing unsanitized user inputs to influence the training process can lead to the incorporation of malicious or adversarial data.
  - Lack of content validation: Failing to validate the content of inputs during training can result in the model learning from unreliable or inappropriate sources.
  - Inadequate data sanitization: Insufficient data cleaning and filtering processes can allow harmful or biased data to affect the model's behavior.

- Security and Robustness Measures:
  - Adversarial data inclusion: Lack of safeguards against adversarial data inclusion can make the model vulnerable to malicious data poisoning attacks.
  - Weak sandboxing controls: Inadequate isolation of the training environment can lead to the ingestion of unsafe training data, compromising the model's integrity.
  - Lack of outlier detection: The absence of mechanisms to detect and filter out outliers in the training data can lead to the incorporation of anomalous and potentially harmful information.
  - Insufficient adversarial robustness: Failure to incorporate adversarial robustness techniques can make the model susceptible to adversarial attacks on its training data.
  - Lack of auditing mechanisms: Without proper auditing, it becomes challenging to identify and mitigate instances of data poisoning or other vulnerabilities in the training data.

- Causes that are OWASP Top 10 for LLM vulnerabilities:
  - LLM01: Prompt Injection - User input from prompt injection could poison training data.
  - LLM05: Supply Chain Vulnerabilities - Third party data sources could contain poisoning.

**Potential Impacts**
- Unreliable Outputs
  - Inaccurate information: Poisoned training data can lead to the generation of outputs that contain inaccurate information, impacting the model's reliability.
  - Misleading model behavior: Data poisoning can result in model behavior that misleads users and makes it less trustworthy.
  - Conflicting model responses: Poisoned data can cause inconsistencies in the model's responses, leading to confusion among users.

- Biases and Ethics Issues
  - Discrimination: Biased training data can result in the model producing discriminatory outputs that favor or disfavor specific groups.
  - Unethical model behavior: Data poisoning can lead to unethical behavior by the model, including generating harmful or inappropriate content.  

- Information Leakage
  - Sensitive data leakage: Poisoned training data can inadvertently lead to the model disclosing sensitive information in its outputs.
  - Privacy violations: Data poisoning can result in privacy violations as the model generates outputs that reveal private or confidential information.

- Reputation Impact
  - Loss of trust: If the model consistently produces unreliable or biased outputs, users may lose trust in the AI system and the organization behind it.
  - Legal liability: Ethical and legal concerns arising from biased or harmful model behavior can expose organizations to legal liability.
  - Brand damage: Public awareness of unreliable or biased outputs can lead to significant brand damage.
  
- Business Impact
  - Flawed business decisions: Organizations relying on AI outputs for decision-making may make flawed choices based on inaccurate or biased model outputs.
  - Financial fraud: Poisoned data can lead to the generation of outputs that facilitate financial fraud or market manipulation.
  - Misinformation spread: Data poisoning can result in the model spreading misinformation or false narratives, causing harm in various contexts.


# LLM04: Model Denial of Service

**Summary**
Overloading LLMs with resource-heavy operations can cause service disruptions and increased costs.

**Description:**
An attacker interacts with an LLM in a method that consumes an exceptionally high amount of resources, which results in a decline in the quality of service for them and other users, as well as potentially incurring high resource costs. Furthermore, an emerging major security concern is the possibility of an attacker interfering with or manipulating the context window of an LLM. This issue is becoming more critical due to the increasing use of LLMs in various applications, their intensive resource utilization, the unpredictability of user input, and a general unawareness among developers regarding this vulnerability. In LLMs, the context window represents the maximum length of text the model can manage, covering both input and output. It's a crucial characteristic of LLMs as it dictates the complexity of language patterns the model can understand and the size of the text it can process at any given time. The size of the context window is defined by the model's architecture and can differ between models.

**Common Examples of Vulnerability:**
1. Posing queries that lead to recurring resource usage through high-volume generation of tasks in a queue, e.g. with LangChain or AutoGPT.
2. Sending unusually resource-consuming queries that use unusual orthography or sequences.
3. Continuous input overflow: An attacker sends a stream of input to the LLM that exceeds its context window, causing the model to consume excessive computational resources.
4. Repetitive long inputs: The attacker repeatedly sends long inputs to the LLM, each exceeding the context window.
5. Recursive context expansion: The attacker constructs input that triggers recursive context expansion, forcing the LLM to repeatedly expand and process the context window.
6. Variable-length input flood: The attacker floods the LLM with a large volume of variable-length inputs, where each input is carefully crafted to just reach the limit of the context window. This technique aims to exploit any inefficiencies in processing variable-length inputs, straining the LLM and potentially causing it to become unresponsive.

**How to Prevent:**
1. Implement input validation and sanitization to ensure user input adheres to defined limits and filters out any malicious content.
2. Cap resource use per request or step, so that requests involving complex parts execute more slowly.
3. Enforce API rate limits to restrict the number of requests an individual user or IP address can make within a specific timeframe.
4. Limit the number of queued actions and the number of total actions in a system reacting to LLM responses.
5. Continuously monitor the resource utilization of the LLM to identify abnormal spikes or patterns that may indicate a DoS attack.
6. Set strict input limits based on the LLM's context window to prevent overload and resource exhaustion.
7. Promote awareness among developers about potential DoS vulnerabilities in LLMs and provide guidelines for secure LLM implementation.


**Example Attack Scenarios:**
1. An attacker repeatedly sends multiple difficult and costly requests to a hosted model leading to worse service for other users and increased resource bills for the host.
2. A piece of text on a webpage is encountered while an LLM-driven tool is collecting information to respond to a benign query. This leads to the tool making many more web page requests, resulting in large amounts of resource consumption.
3. An attacker continuously bombards the LLM with input that exceeds its context window. The attacker may use automated scripts or tools to send a high volume of input, overwhelming the LLM's processing capabilities. As a result, the LLM consumes excessive computational resources, leading to a significant slowdown or complete unresponsiveness of the system.
4. An attacker sends a series of sequential inputs to the LLM, with each input designed to be just below the context window's limit. By repeatedly submitting these inputs, the attacker aims to exhaust the available context window capacity. As the LLM struggles to process each input within its context window, system resources become strained, potentially resulting in degraded performance or a complete denial of service.
5. An attacker leverages the LLM's recursive mechanisms to trigger context expansion repeatedly. By crafting input that exploits the recursive behavior of the LLM, the attacker forces the model to repeatedly expand and process the context window, consuming significant computational resources. This attack strains the system and may lead to a DoS condition, making the LLM unresponsive or causing it to crash.
6. An attacker floods the LLM with a large volume of variable-length inputs, carefully crafted to approach or reach the context window's limit. By overwhelming the LLM with inputs of varying lengths, the attacker aims to exploit any inefficiencies in processing variable-length inputs. This flood of inputs puts an excessive load on the LLM's resources, potentially causing performance degradation and hindering the system's ability to respond to legitimate requests.
7. While DoS attacks commonly aim to overwhelm system resources, they can also exploit other aspects of system behavior, such as API limitations. For example, in a recent Sourcegraph security incident, the malicious actor employed a leaked admin access token to alter API rate limits, thereby potentially causing service disruptions by enabling abnormal levels of request volumes.


**Common Weakness Enumeration (CWE)**

[CWE-16](https://cwe.mitre.org/data/definitions/16.html): Configuration - Applicable as misconfigurations could trigger resource issues.

[CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Applicable as validation failures enable malicious requests.  

[CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Applicable as unauthorized requests could abuse resources.

[CWE-400](https://cwe.mitre.org/data/definitions/400.html): Uncontrolled Resource Consumption - Applicable as malicious interactions can exhaust LLM resources.  

[CWE-770](https://cwe.mitre.org/data/definitions/770.html): Allocation of Resources Without Limits or Throttling - Applicable as lack of throttling enables resource exhaustion.

[CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency - Applicable as lack of frequency control allows flooding.

[CWE-404](https://cwe.mitre.org/data/definitions/404.html): Improper Resource Shutdown or Release - Applicable if resources are not properly released after use, leading to exhaustion.

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable if plugins/extensions can trigger resource issues.


**MITRE ATT&CK Techniques**

- AML.T0029: Denial of ML Service. Designed to overload systems with resource-heavy inputs. Directly causes denial of service.

- AML.T0043: Craft Adversarial Data. Crafting prompts that require extensive processing could strain systems. Carefully crafted inputs.

- AML.T0040: ML Model Inference API Access. Flooding the API with requests could overwhelm systems. API access enables attacks. 

- AML.T0016: Obtain Capabilities. May obtain tools to automate sending malicious requests. Aids automation.

- AML.T0012: Valid Accounts. Compromised credentials could bypass rate limiting. Allows increased access.

- AML.T0010: ML Supply Chain Compromise. Could introduce inefficiencies via compromised artifacts that are resource-intensive. Introduces weaknesses. 

- AML.T0044: Full ML Model Access. Full control enables sending optimized resource-heavy inputs. Maximizes impact.

- AML.T0047: ML-Enabled Product or Service. Existing services with inadequate protections could be exploited. Finds vulnerable services.

- AML.T0019: Publish Poisoned Data. Training on data designed to increase compute could degrade performance. Influences model.

- AML.T0011: User Execution. Users may unknowingly execute code that overloads systems. Executes malicious code.



**Root Causes**
- Resource Management Issues:
   - Lack of rate limiting: Failing to restrict the number of requests a user can make can lead to resource exhaustion as attackers flood the system with requests.
   - No context window size limits: Absence of limits on the LLM's context window size can result in resource-intensive recursive context expansions.
   - Missing input sanitization: Insufficient input filtering and sanitization can allow resource-consuming queries to pass through unchecked.
   - Insufficient resource allocation: Not provisioning adequate compute resources for expected load levels can lead to resource exhaustion.

- Security and Monitoring Gaps:
   - Insufficient input validation: Inadequate validation of user input can allow resource-heavy requests to reach the system.
   - Lack of real-time monitoring: Without real-time monitoring of resource utilization, unusual spikes in usage indicative of DoS attacks may go undetected.
   - Insufficient developer awareness: Developers may not be aware of the potential DoS vulnerabilities in LLMs, leading to insecure implementations.

- Causes that are OWASP Top 10 for LLM vulnerabilities:
  - LLM01: Prompt Injection -  - Specially crafted prompts could trigger resource exhaustion.
  - LLM07: Insecure Plugin Design - Flawed plugins could trigger resource exhaustion.

**Potential Impacts**
- Service Disruption
  - Unavailability of critical services: The LLM may become completely unresponsive for critical services and applications, leading to downtime.
  - Performance degradation: The LLM's performance may significantly deteriorate, causing delays and reduced responsiveness.

- Financial Impact
  - Increased infrastructure costs: Resource-intensive attacks can lead to higher compute and infrastructure costs.
  - Lost revenue from downtime: Downtime caused by a DoS attack can result in lost revenue from interrupted services.  
  
- Business Impact
  - User frustration: Users may become frustrated by slow or unresponsive LLM services.
  - Impaired customer experience: The quality of the user experience may suffer due to reduced LLM performance.
  - Failure to meet uptime obligations: Organizations may fail to meet contractual uptime obligations due to prolonged DoS attacks.
  
- Exploitation Risks
  - Ransomware or extortion: Prolonged DoS downtime could enable ransomware deployment or extortion attempts by threat actors.


# LLM05: Supply Chain Vulnerabilities

**Summary**
Depending upon compromised components, services or datasets undermine system integrity, causing data breaches and system failures.

**Description:** 
The supply chain in LLMs can be vulnerable, impacting the integrity of training data, ML models, and deployment platforms. These vulnerabilities can lead to biased outcomes, security breaches, or even complete system failures. Traditionally, vulnerabilities are focused on software components, but Machine Learning extends this with the pre-trained models and training data supplied by third parties susceptible to tampering and poisoning attacks. 

Finally, LLM Plugin extensions can bring their own vulnerabilities. These are described in Insecure Plugin Design, which covers writing LLM Plugins and provides helpful information to evaluate third-party plugins.

**Common Examples of Vulnerability:**
1. Traditional third-party package vulnerabilities, including outdated or deprecated components.
2. Using a vulnerable pre-trained model for fine-tuning. 
3. Use of poisoned crowd-sourced data for training.
4. Using outdated or deprecated models that are no longer maintained leads to security issues.
5. Unclear T&Cs and data privacy policies of the model operators lead to the application's sensitive data being used for model training and subsequent sensitive information exposure. This may also apply to risks from using copyrighted material by the model supplier.

**How to Prevent:**
1. Carefully vet data sources and suppliers, including T&Cs and their privacy policies, only using trusted suppliers. Ensure adequate and independently audited security is in place and that model operator policies align with your data protection policies, i.e., your data is not used for training their models; similarly, seek assurances and legal mitigations against using copyrighted material from model maintainers.
2. Only use reputable plugins and ensure they have been tested for your application requirements. LLM-Insecure Plugin Design provides information on the LLM-aspects of Insecure Plugin design you should test against to mitigate risks from using third-party plugins.
3. Understand and apply the mitigations found in the OWASP Top Ten's A06:2021 – Vulnerable and Outdated Components. This includes vulnerability scanning, management, and patching components. For development environments with access to sensitive data, apply these controls in those environments, too.
4. Maintain an up-to-date inventory of components using a Software Bill of Materials (SBOM) to ensure you have an up-to-date, accurate, and signed inventory, preventing tampering with deployed packages. SBOMs can be used to detect and alert for new, zero-date vulnerabilities quickly.
5. At the time of writing, SBOMs do not cover models, their artifacts, and datasets. If your LLM application uses its own model, you should use MLOps best practices and platforms offering secure model repositories with data, model, and experiment tracking.
6. You should also use model and code signing when using external models and suppliers.
7. Anomaly detection and adversarial robustness tests on supplied models and data can help detect tampering and poisoning as discussed in Training Data Poisoning; ideally, this should be part of MLOps pipelines; however, these are emerging techniques and may be easier to implement as part of red teaming exercises.
8. Implement sufficient monitoring to cover component and environment vulnerabilities scanning, use of unauthorized plugins, and out-of-date components, including the model and its artifacts.
9. Implement a patching policy to mitigate vulnerable or outdated components. Ensure the application relies on a maintained version of APIs and the underlying model.
10. Regularly review and audit supplier Security and Access, ensuring no changes in their security posture or T&Cs.

**Example Attack Scenarios:**
1. An attacker exploits a vulnerable Python library to compromise a system. This happened in the first Open AI data breach. 
2. An attacker provides an LLM plugin to search for flights, generating fake links that lead to scamming users.
3. An attacker exploits the PyPi package registry to trick model developers into downloading a compromised package and exfiltrating data or escalating privilege in a model development environment. This was an actual attack.
4. An attacker poisons a publicly available pre-trained model specializing in economic analysis and social research to create a back door that generates misinformation and fake news. They deploy it on a model marketplace (e.g., Hugging Face) for victims to use.
5. An attacker poisons publicly available datasets to help create a back door when fine-tuning models. The back door subtly favors certain companies in different markets.
6. A compromised employee of a supplier (outsourcing developer, hosting company, etc.) exfiltrates data, model, or code stealing IP.
7. An LLM operator changes its T&Cs and Privacy Policy to require an explicit opt out from using application data for model training, leading to the memorization of sensitive data.

**Common Weakness Enumeration (CWE)**

[CWE-494](https://cwe.mitre.org/data/definitions/494.html): Download of Code Without Integrity Check - Applicable as unauthorized third-party code may be downloaded without integrity checks.

[CWE-733](https://cwe.mitre.org/data/definitions/733.html): Compiler Optimization Removal or Modification of Security-critical Code - Applicable as optimizations could remove security controls in third-party code. 

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as third-party code introduces risks of untrusted functionality.

[CWE-915](https://cwe.mitre.org/data/definitions/915.html): Improperly Controlled Modification of Dynamically-Determined Object Attributes - Applicable as lack of control over dynamic attributes in third-party code poses risks.

[CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF) - Applicable as third-party requests may not be properly validated, enabling SSRF.

[CWE-937](https://cwe.mitre.org/data/definitions/937.html): OWASP Top Ten 2013 Category A5 - Security Misconfiguration - Applicable as misconfigured third-party components pose risks per OWASP guidelines. 

[CWE-916](https://cwe.mitre.org/data/definitions/916.html): Use of Password Hash With Insufficient Computational Effort - Applicable if third-party code uses weak hashing.


**MITRE ATT&CK Techniques**

- AML.T0010: ML Supply Chain Compromise. Compromising any part of the supply chain provides a vector for attacks. Directly exploits supply chain.

- AML.T0019: Publish Poisoned Data. Adversaries could distribute poisoned datasets through compromised sources. Poisons data sources.

- AML.T0020: Poison Training Data. Allows poisoning of artifacts used in training models. Manipulates training data.

- AML.T0043: Craft Adversarial Data. Could allow carefully crafted data or models designed to exploit systems. Introduces vulnerabilities.

- AML.T0016: Obtain Capabilities. May obtain tools to compromise supply chain components. Aids targeting supply chain. 

- AML.T0044: Full ML Model Access. Full control of components enables thorough poisoning. Maximizes control over supply chain.

- AML.T0012: Valid Accounts. Compromised credentials could allow direct access to poison. Allows access to compromise.

- AML.T0011: User Execution. Users may unknowingly execute code from compromised sources. Executes malicious code.

- AML.T0047: ML-Enabled Product or Service. Services relying on compromised components could be exploited. Finds and exploits vulnerabilities.

- AML.T0040: ML Model Inference API Access. May enable attacks via compromised model APIs. API access to poisoned models.


**Root Causes**
- Third-party Component Risks:
  - Unvetted third-party packages: Using unverified third-party packages can introduce vulnerabilities into the system when these packages are compromised or outdated.
  - Vulnerable pre-trained models: Utilizing pre-trained models with known vulnerabilities can expose the system to security breaches or biased outcomes.
  - Poisoned training data: Incorporating poisoned or manipulated training data can lead to biased or unreliable models, impacting system integrity.
  - Use of outdated models: Relying on outdated models that are no longer maintained increases the risk of security issues.

- Supplier and Data Source Risks:
  - Lack of supplier security audits: Failing to assess and audit the security measures of data suppliers or model operators can result in vulnerabilities within the supply chain.
  - Untrusted data suppliers: Engaging with untrustworthy data suppliers can compromise data integrity and lead to security breaches.
  - Disregard for A06:2021 guidelines: Neglecting to follow security guidelines like OWASP Top Ten's A06:2021 can leave the system exposed to known vulnerabilities.

- Plugin and Component Risks:
  - Untested third-party plugins: Using untested third-party plugins may introduce vulnerabilities into the system, especially if these plugins haven't been thoroughly evaluated for compatibility and security.

- Asset and Inventory Management:
  - Lack of model inventories: Failing to maintain an up-to-date inventory of components, including models, leaves the system susceptible to tampering and exploitation.
  - Missing model code signing: Without proper code signing for models, there is a risk of using compromised or unauthorized models.

- Supplier and Identity Risks:
  - Neglecting supplier security: Not monitoring and auditing supplier security and access can result in vulnerabilities within the supply chain.
  - Unpatched vulnerabilities in development environments: Neglecting to patch vulnerabilities in development environments exposes the system to potential attacks.

- Asset and Integrity Verification:
  - Lack of integrity checks on supplied assets: Failing to verify the integrity of supplied assets can lead to the acceptance of tampered or malicious components.
  - Overprivileged identities for external systems: Granting excessive privileges to external systems can create opportunities for unauthorized access and data breaches.

- Causes that are OWASP Top 10 for LLM vulnerabilities:
  - LLM03: Training Data Poisoning - Third party data sources could contain poisoning.

**Potential Impacts**
- Data Breaches
  - Sensitive data theft: Inadequate supplier security audits and untrusted data sources can result in data breaches, potentially leading to sensitive information theft.
  - Privacy violations: Failure to ensure that model operator policies align with data protection policies can result in privacy violations and unauthorized usage of sensitive data.

- Intellectual Property Theft
  - Model theft: Lack of integrity checks on supplied assets and overprivileged identities for external systems can create opportunities for model theft and intellectual property breaches.
  - Code theft: Failing to monitor and audit supplier security and access, along with unpatched vulnerabilities in development environments, can lead to code theft and IP exposure.

- Operational Risks
  - Biased model outputs: The use of poisoned or manipulated training data can lead to biased model outputs, affecting system integrity.
  - Insecure configurations: Neglecting to follow security guidelines like OWASP Top Ten's A06:2021 can result in insecure configurations, exposing the system to vulnerabilities.

- Compliance Violations 
  - Data protection noncompliance: Lack of supplier security audits and disregard for A06:2021 guidelines can lead to data protection noncompliance, risking legal and regulatory issues.
  - Copyright violations: Failure to ensure data privacy policies and copyright compliance by model operators can result in copyright violations and legal repercussions.


# LLM06: Sensitive Information Disclosure

**Summary**
Failure to protect against disclosure of sensitive information in LLM outputs can result in legal consequences or a loss of competitive advantage.

**Description:**
LLM applications have the potential to reveal sensitive information, proprietary algorithms, or other confidential details through their output. This can result in unauthorized access to sensitive data, intellectual property, privacy violations, and other security breaches. It is important for consumers of LLM applications to be aware of how to safely interact with LLMs and identify the risks associated with unintentionally inputting sensitive data that may be subsequently returned by the LLM in output elsewhere.

To mitigate this risk, LLM applications should perform adequate data sanitization to prevent user data from entering the training model data. LLM application owners should also have appropriate Terms of Use policies available to make consumers aware of how their data is processed and the ability to opt out of having their data included in the training model.

The consumer-LLM application interaction forms a two-way trust boundary, where we cannot inherently trust the client->LLM input or the LLM->client output. It is important to note that this vulnerability assumes that certain prerequisites are out of scope, such as threat modeling exercises, securing infrastructure, and adequate sandboxing. Adding restrictions within the system prompt around the types of data the LLM should return can provide some mitigation against sensitive information disclosure, but the unpredictable nature of LLMs means such restrictions may not always be honored and could be circumvented via prompt injection or other vectors.

**Common Examples of Vulnerability:**
1. Incomplete or improper filtering of sensitive information in the LLM’s responses.
2. Overfitting or memorization of sensitive data in the LLM’s training process.
3. Unintended disclosure of confidential information due to LLM misinterpretation, lack of data scrubbing methods or errors.

**How to Prevent:**
1. Integrate adequate data sanitization and scrubbing techniques to prevent user data from entering the training model data.
2. Implement robust input validation and sanitization methods to identify and filter out potential malicious inputs to prevent the model from being poisoned.
3. When enriching the model with data and if [fine-tuning](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/wiki/Definitions) a model: (I.E, data fed into the model before or during deployment)
   1. Anything that is deemed sensitive in the fine-tuning data has the potential to be revealed to a user. Therefore, apply the rule of least privilege and do not train the model on information that the highest-privileged user can access which may be displayed to a lower-privileged user.
   2. Access to external data sources (orchestration of data at runtime) should be limited.
   3. Apply strict access control methods to external data sources and a rigorous approach to maintaining a secure supply chain.

**Example Attack Scenarios:**
1. Unsuspecting legitimate user A is exposed to certain other user data via the LLM when interacting with the LLM application in a non-malicious manner.

2. User A targets a well-crafted set of prompts to bypass input filters and sanitization from the LLM to cause it to reveal sensitive information (PII) about other users of the application.

3. Personal data such as PII is leaked into the model via training data due to either negligence from the user themselves, or the LLM application. This case could increase the risk and probability of scenario 1 or 2 above.

**Common Weakness Enumeration (CWE)**

[CWE-202](https://cwe.mitre.org/data/definitions/202.html): Exposure of Sensitive Information to an Unauthorized Actor - Applicable when sensitive data is exposed to unauthorized users.

[CWE-208](https://cwe.mitre.org/data/definitions/208.html): Observable Discrepancy - Applicable when differences between expected and actual LLM behavior allow inference of sensitive information.

[CWE-209](https://cwe.mitre.org/data/definitions/209.html): Information Exposure Through an Error Message - Applicable if error messages reveal sensitive information. 

[CWE-215](https://cwe.mitre.org/data/definitions/215.html): Information Exposure Through Debug Information - Applicable if debug logs contain sensitive data.

[CWE-538](https://cwe.mitre.org/data/definitions/538.html): File and Directory Information Exposure - Applicable if filesystem information is exposed.

[CWE-541](https://cwe.mitre.org/data/definitions/541.html): Information Exposure Through Include Source Code - Applicable if source code containing sensitive data is exposed.

[CWE-649](https://cwe.mitre.org/data/definitions/649.html): Reliance on Obfuscation or Protection Mechanism - Applicable if relying solely on obfuscation without proper access controls.

[CWE-922](https://cwe.mitre.org/data/definitions/922.html): Insecure Storage of Sensitive Information - Applicable if sensitive data is stored insecurely.


**MITRE ATT&CK Techniques**

- AML.T0024: Exfiltration via ML Inference API. The API could reveal private training data or inferences. Directly leaks sensitive data.

- AML.T0021: Establish Accounts. May access victim accounts to collect sensitive data. Gains access to private data. 

- AML.T0036: Data from Information Repositories. Could steal sensitive documents and data. Exfiltrates sensitive data.

- AML.T0037: Data from Local System. Local systems contain private data that could be collected. Gathers sensitive data. 

- AML.T0040: ML Model Inference API Access. Carefully crafted queries could reveal private details. API access to exploit.

- AML.T0016: Obtain Capabilities. May obtain tools to exfiltrate or automate data collection. Aids stealing data.

- AML.T0012: Valid Accounts. Compromised credentials provide access to sensitive data. Allows access to private data.

- AML.T0044: Full ML Model Access. Full control enables retrieving maximum data. Maximizes data access. 

- AML.T0047: ML-Enabled Product or Service. Services with data exposure could be exploited. Identify services with weaknesses.

- AML.T0019: Publish Poisoned Data. Training on sensitive data could enable later exposure. Leaks data via training.


**Root Causes**
- Inadequate Data Handling:
  - Inadequate Data Scrubbing: Insufficient cleansing of sensitive information from the LLM's responses can result in unintended disclosure when sensitive data is returned.
  - Overfitting on Sensitive Data During Training: Overfitting the model on sensitive data during training may lead to the unintentional disclosure of that data in the model's output.
  
- Weak Input and Output Controls:
  - Poor Input Filtering: Weak input filtering can allow malicious inputs to poison the model or bypass security measures.
  - Lack of Output Validation: Failing to validate the LLM's output can lead to the disclosure of sensitive information without proper checks.

- Access Control and User Input Issues:
  - Weak Access Controls: Insufficient access controls may result in unauthorized users gaining access to sensitive data.
  - Unvalidated User Inputs: Accepting unvalidated user inputs can lead to the introduction of sensitive data into the LLM's responses.
  - Lack of access purpose limitation: Failing to limit data access to only what is needed for a specific purpose can enable broader unintended disclosure.

- Data Isolation and Sanitization:
  - Failure to Isolate User Data: Lack of isolation between user data and model data can allow sensitive user information to mix with the LLM's responses.
  - Flawed Data Sanitization: Inadequate data sanitization processes can fail to prevent sensitive data from entering the training model data.

- Causes that are OWASP Top 10 for LLM vulnerabilities:
  - LLM01: Prompt Injection - Could be used to extract sensitive information.
  - LLM03: Training Data Poisoning - Sensitive data in training data could lead to disclosure.
  - LLM08: Excessive Agency - Excessive permissions could enable disclosure.

**Potential Impacts**
- Organizational Impacts
  - Data leakage: Inadequate data handling and weak input/output controls can lead to unauthorized exposure of sensitive organizational data.
  - Loss of intellectual property: Disclosure of proprietary algorithms, trade secrets or other IP can disadvantage an organization competitively.
  
- Individual Impacts
  - Personal data exposure: Poor data controls may result in exposure of private individual data like PII.
  - Identity theft: Disclosed personal data can enable identity theft and financial harm.

- Competitive Impacts
  - IP and data theft: Loss of intellectual property and data to competitors can undermine an organization's market position.
  - Loss of trade secrets: Disclosure of sensitive information like trade secrets can competitively disadvantage an organization.

- Reputational Damage
  - Loss of customer trust: Incidents of unauthorized data disclosure can significantly erode customer trust and damage brand reputation.

- Regulatory Noncompliance
  - Privacy violations: Mishandling of personal data and unauthorized usage can violate regulations like GDPR.
  - Unlawful secondary usage: Disclosed data may enable unlawful secondary usage by external parties.


# LLM07: Insecure Plugin Design

**Summary**
LLM plugins processing untrusted inputs and having insufficient access control risk severe exploits like remote code execution.

**Description**
LLM plugins are extensions that, when enabled, are called automatically by the model during user interactions. The model integration platform drives them,  and the application may have no control over the execution, especially when the model is hosted by another party. Furthermore, plugins are likely to implement free-text inputs from the model with no validation or type-checking to deal with context-size limitations. This allows a potential attacker to construct a malicious request to the plugin, which could result in a wide range of undesired behaviors, up to and including remote code execution. 

The harm of malicious inputs often depends on insufficient access controls and the failure to track authorization across plugins. Inadequate access control allows a plugin to blindly trust other plugins and assume that the end user provided the inputs. Such inadequate access control can enable malicious inputs to have harmful consequences ranging from data exfiltration, remote code execution, and privilege escalation.

This item focuses on creating LLM plugins rather than third-party plugins, which LLM-Supply-Chain-Vulnerabilities cover. 

**Common Examples of Vulnerability:**
1. A plugin accepts all parameters in a single text field instead of distinct input parameters.
2. A plugin accepts configuration strings instead of parameters that can override entire configuration settings.
3. A plugin accepts raw SQL or programming statements instead of parameters.
4. Authentication is performed without explicit authorization to a particular plugin.
5. A plugin treats all LLM content as being created entirely by the user and performs any requested actions without requiring additional authorization.

**How to Prevent:**
1. Plugins should enforce strict parameterized input wherever possible and include type and range checks on inputs. When this is not possible, a second layer of typed calls should be introduced, parsing requests and applying validation and sanitization. When freeform input must be accepted because of application semantics, it should be carefully inspected to ensure no potentially harmful methods are being called.
2. Plugin developers should apply OWASP’s recommendations in ASVS (Application Security Verification Standard) to ensure adequate input validation and sanitization.
3. Plugins should be inspected and tested thoroughly to ensure adequate validation. Use Static Application Security Testing (SAST) scans and Dynamic and Interactive application testing (DAST, IAST) in development pipelines. 
4. Plugins should be designed to minimize the impact of any insecure input parameter exploitation following the OWASP ASVS Access Control Guidelines. This includes least-privilege access control, exposing as little functionality as possible while still performing its desired function.
5. Plugins should use appropriate authentication identities, such as OAuth2, to apply effective authorization and access control. Additionally, API Keys should be used to provide context for custom authorization decisions that reflect the plugin route rather than the default interactive user.
6. Require manual user authorization and confirmation of any action taken by sensitive plugins.
7. Plugins are, typically, REST APIs, so developers should apply the recommendations found in OWASP Top 10 API Security Risks – 2023 to minimize generic vulnerabilities.

**Example Attack Scenarios:**
1. A plugin accepts a base URL and instructs the LLM to combine the URL with a query to obtain weather forecasts which are included in handling the user request. A malicious user can craft a request such that the URL points to a domain they control, which allows them to inject their own content into the LLM system via their domain.
2. A plugin accepts a free-form input into a single field that it does not validate. An attacker supplies carefully crafted payloads to perform reconnaissance from error messages. It then exploits known third-party vulnerabilities to execute code and perform data exfiltration or privilege escalation.
3. A plugin used to retrieve embeddings from a vector store accepts configuration parameters as a connection string without any validation. This allows an attacker to experiment and access other vector stores by changing names or host parameters and exfiltrate embeddings they should not have access to. 
4. A plugin accepts SQL WHERE clauses as advanced filters, which are then appended to the filtering SQL. This allows an attacker to stage a SQL attack.
5. An attacker uses indirect prompt injection to exploit an insecure code management plugin with no input validation and weak access control to transfer repository ownership and lock out the user from their repositories.

**Common Weakness Enumeration (CWE)**

[CWE-20](https://cwe.mitre.org/data/definitions/20.html): Improper Input Validation - Applicable when plugins fail to validate inputs properly. 

[CWE-79](https://cwe.mitre.org/data/definitions/79.html): Improper Neutralization of Input During Web Page Generation - Applicable if plugins do not neutralize untrusted web inputs, risking XSS.

[CWE-89](https://cwe.mitre.org/data/definitions/89.html): SQL Injection - Applicable if plugins accept raw SQL inputs. 

[CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control - Applicable when plugins have excessive privileges or inadequate access control.

[CWE-306](https://cwe.mitre.org/data/definitions/306.html): Missing Authentication for Critical Function - Applicable if plugins lack authentication.

[CWE-346](https://cwe.mitre.org/data/definitions/346.html): Origin Validation Error - Applicable if plugin request origins are not validated. 

[CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data - Applicable if plugin output lacks encoding.

[CWE-807](https://cwe.mitre.org/data/definitions/807.html): Reliance on Untrusted Inputs in a Security Decision - Applicable if plugins rely on unvalidated inputs.

[CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization - Applicable if authorization checks are missing.


**MITRE ATT&CK Techniques**

- AML.T0047: ML-Enabled Product or Service. Plugins extend capabilities of services, introducing potential weaknesses. Extends capabilities.

- AML.T0040: ML Model Inference API Access. Malicious prompts could exploit vulnerabilities in plugins via the API. API access to plugins.

- AML.T0043: Craft Adversarial Data. Carefully crafted prompts could trigger unintended plugin behaviors. Optimizes malicious inputs.

- AML.T0016: Obtain Capabilities. May obtain tools to identify flaws or automate exploiting plugins. Aids targeting plugins.

- AML.T0012: Valid Accounts. Compromised credentials could enable privileged actions through plugins. Allows escalated access.

- AML.T0011: User Execution. Users may unknowingly invoke dangerous plugin functionality. Triggers unintended actions.

- AML.T0010: ML Supply Chain Compromise. Compromised plugins introduced into the supply chain could be exploited. Introduces compromised plugins. 

- AML.T0024: Exfiltration via ML Inference API. Plugins could enable data theft via the model API. Leaks data via plugins.

- AML.T0044: Full ML Model Access. Full control allows optimal manipulation of plugins. Maximizes control of plugins.

- AML.T0019: Publish Poisoned Data. Data could trigger unintended behaviors in downstream plugins. Manipulates plugin processing.



**Root Causes**
- Input Validation and Sanitization:
  - Lack of input validation: Failing to validate input, permitting malicious payloads to manipulate the plugin.
  - Insufficient output sanitization: Not properly cleaning and securing output, leading to potential exploitation.
  - Unfiltered interpreted content like JavaScript: Allowing unfiltered content like JavaScript, which can be exploited.
  - Missing output encoding: Failure to encode output, making it susceptible to attacks.

- Access Control and Authorization:
  - Overly permissive privileges granted to plugins: Granting excessive privileges to plugins, increasing the risk of misuse.
  - Inadequate access control between plugins: Poor control over interactions between plugins, allowing unauthorized actions.
  - Inadequate prompt input validation: Insufficient validation of prompt inputs, potentially enabling malicious actions.
  - Overreliance on LLM accuracy: Excessive trust in the LLM's accuracy without considering security implications.
  - Privilege escalation risks: Plugins that do not restrict privileges properly could enable escalation by attackers.

**Potential Impacts**
- Input Manipulation
  - Malicious payloads: Attackers can insert malicious payloads into plugins due to insufficient input validation, potentially leading to harmful behaviors.
  - Reconnaissance: Inadequate input validation can enable attackers to perform reconnaissance through error messages, gaining insights for further exploitation.

- Access Control Bypass
  - Privilege escalation: Poorly restricted plugin privileges can lead to privilege escalation by attackers.
  - Unauthorized actions: Inadequate access control between plugins may allow unauthorized actions by malicious actors.
  
- Financial Crime
  - Fraud: Insecure plugins can be exploited for fraudulent activities.
  - Theft: Attackers may exploit insecure plugins to steal sensitive data or resources.

- Security Risks
  - Vulnerabilities from third-party plugins: Risks associated with third-party plugins can compromise the security of the LLM.
  - End-user security risks: Insecure plugins can pose security risks to end users interacting with the LLM.

- Reputational Damage
  - Loss of trust: Incidents stemming from insecure plugins may erode customer trust and damage brand reputation.



# LLM08: Excessive Agency

**Summary**
Granting LLMs unchecked autonomy to take action can lead to unintended consequences, jeopardizing reliability, privacy, and trust.


**Description:**
An LLM-based system is often granted a degree of agency by its developer - the ability to interface with other systems and undertake actions in response to a prompt. The decision over which functions to invoke may also be delegated to an LLM 'agent' to dynamically determine based on input prompt or LLM output.

Excessive Agency is the vulnerability that enables damaging actions to be performed in response to unexpected/ambiguous outputs from an LLM (regardless of what is causing the LLM to malfunction; be it hallucination/confabulation, direct/indirect prompt injection, malicious plugin, poorly-engineered benign prompts, or just a poorly-performing model). The root cause of Excessive Agency is typically one or more of: excessive functionality, excessive permissions or excessive autonomy. This differs from Insecure Output Handling which is concerned with insufficient scrutiny of LLM outputs.

Excessive Agency can lead to a broad range of impacts across the confidentiality, integrity and availability spectrum, and is dependent on which systems an LLM-based app is able to interact with.

**Common Examples of Vulnerability:**
1. Excessive Functionality: An LLM agent has access to plugins which include functions that are not needed for the intended operation of the system. For example, a developer needs to grant an LLM agent the ability to read documents from a repository, but the 3rd-party plugin they choose to use also includes the ability to modify and delete documents.
2. Excessive Functionality: A plugin may have been trialed during a development phase and dropped in favor of a better alternative, but the original plugin remains available to the LLM agent.
3. Excessive Functionality: An LLM plugin with open-ended functionality fails to properly filter the input instructions for commands outside what's necessary for the intended operation of the application. E.g., a plugin to run one specific shell command fails to properly prevent other shell commands from being executed.
4. Excessive Permissions: An LLM plugin has permissions on other systems that are not needed for the intended operation of the application. E.g., a plugin intended to read data connects to a database server using an identity that not only has SELECT permissions, but also UPDATE, INSERT and DELETE permissions.
5. Excessive Permissions: An LLM plugin that is designed to perform operations on behalf of a user accesses downstream systems with a generic high-privileged identity. E.g., a plugin to read the current user's document store connects to the document repository with a privileged account that has access to all users' files.
6. Excessive Autonomy: An LLM-based application or plugin fails to independently verify and approve high-impact actions. E.g., a plugin that allows a user's documents to be deleted performs deletions without any confirmation from the user. 

**How to Prevent:**
The following actions can prevent Excessive Agency:

1. Limit the plugins/tools that LLM agents are allowed to call to only the minimum functions necessary. For example, if an LLM-based system does not require the ability to fetch the contents of a URL then such a plugin should not be offered to the LLM agent.
2. Limit the functions that are implemented in LLM plugins/tools to the minimum necessary. For example, a plugin that accesses a user's mailbox to summarise emails may only require the ability to read emails, so the plugin should not contain other functionality such as deleting or sending messages.
3. Avoid open-ended functions where possible (e.g., run a shell command, fetch a URL, etc.) and use plugins/tools with more granular functionality. For example, an LLM-based app may need to write some output to a file. If this were implemented using a plugin to run a shell function then the scope for undesirable actions is very large (any other shell command could be executed). A more secure alternative would be to build a file-writing plugin that could only support that specific functionality.
4. Limit the permissions that LLM plugins/tools are granted to other systems to the minimum necessary in order to limit the scope of undesirable actions. For example, an LLM agent that uses a product database in order to make purchase recommendations to a customer might only need read access to a 'products' table; it should not have access to other tables, nor the ability to insert, update or delete records. This should be enforced by applying appropriate database permissions for the identity that the LLM plugin uses to connect to the database.
5. Track user authorization and security scope to ensure actions taken on behalf of a user are executed on downstream systems in the context of that specific user, and with the minimum privileges necessary. For example, an LLM plugin that reads a user's code repo should require the user to authenticate via OAuth and with the minimum scope required.
6. Utilise human-in-the-loop control to require a human to approve all actions before they are taken. This may be implemented in a downstream system (outside the scope of the LLM application) or within the LLM plugin/tool itself. For example, an LLM-based app that creates and posts social media content on behalf of a user should include a user approval routine within the plugin/tool/API that implements the 'post' operation.
7. Implement authorization in downstream systems rather than relying on an LLM to decide if an action is allowed or not. When implementing tools/plugins enforce the complete mediation principle so that all requests made to downstream systems via the plugins/tools are validated against security policies.

The following options will not prevent Excessive Agency, but can limit the level of damage caused:

1. Log and monitor the activity of LLM plugins/tools and downstream systems to identify where undesirable actions are taking place, and respond accordingly.
2. Implement rate-limiting to reduce the number of undesirable actions that can take place within a given time period, increasing the opportunity to discover undesirable actions through monitoring before significant damage can occur.

**Example Attack Scenario:**
An LLM-based personal assistant app is granted access to an individual’s mailbox via a plugin in order to summarise the content of incoming emails. To achieve this functionality, the email plugin requires the ability to read messages, however the plugin that the system developer has chosen to use also contains functions for sending messages. The LLM is vulnerable to an indirect prompt injection attack, whereby a maliciously-crafted incoming email tricks the LLM into commanding the email plugin to call the 'send message' function to send spam from the user's mailbox. This could be avoided by:
(a) eliminating excessive functionality by using a plugin that only offered mail-reading capabilities,
(b) eliminating excessive permissions by authenticating to the user's email service via an OAuth session with a read-only scope, and/or
(c) eliminating excessive autonomy by requiring the user to manually review and hit 'send' on every mail drafted by the LLM plugin.
Alternatively, the damage caused could be reduced by implementing rate limiting on the mail-sending interface.



**Common Weakness Enumeration (CWE)**

[CWE-272](https://cwe.mitre.org/data/definitions/272.html): Least Privilege Violation - Applicable when excessive permissions are granted beyond functional needs.

[CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control - Applicable if plugins lack access controls, enabling unauthorized actions.

[CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Applicable when improper authorization leads to unauthorized actions. 

[CWE-347](https://cwe.mitre.org/data/definitions/347.html): Improper Verification of Cryptographic Signature - Applicable if failure to verify signatures poses authorization risks.

[CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data - Applicable if plugin output lacks encoding, leading to unintended actions.

[CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials - Applicable as hard-coded credentials with excessive permissions pose unauthorized action risks.

[CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency - Applicable as lack of frequency control poses risks of excessive unauthorized actions.  

[CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization - Applicable when authorization is not checked before actions.


**MITRE ATT&CK Techniques** 

- AML.T0047: ML-Enabled Product or Service. Services granting excessive permissions introduce vulnerability. Provides unchecked capabilities.

- AML.T0040: ML Model Inference API Access. Carefully crafted queries could trigger unintended actions via the API. API access to downstream systems.

- AML.T0043: Craft Adversarial Data. Allows tailoring prompts to exploit excessive permissions. Optimizes malicious prompts. 

- AML.T0016: Obtain Capabilities. May obtain tools to identify or exploit excessive permissions. Aids targeting vulnerabilities.

- AML.T0010: ML Supply Chain Compromise. Compromised components could introduce excessive capabilities. Introduces vulnerabilities.

- AML.T0044: Full ML Model Access. Full control allows optimal exploitation of excessive permissions. Maximizes impact.

- AML.T0019: Publish Poisoned Data. Data could trigger unintended behaviors enabled by excessive permissions. Manipulates downstream actions.



**Root Causes**
- Excessive Functionality and Permissions:
  - Excessive functionality in LLM plugins: Overly broad permissions in LLM plugins create opportunities for misuse.
  - Excessive permissions in LLM plugins: Overly broad permissions in LLM plugins create opportunities for misuse.
  - Excessive permissions granted in external systems: Granting unnecessary permissions in external systems exposes the application to potential misuse and unauthorized actions.

- Plugin Design and Configuration:
  - Retention of unused or deprecated plugins: Keeping unnecessary plugins accessible increases vulnerability.
  - Lack of input validation in plugins: Inadequate input validation allows malicious inputs to trigger unwanted actions.
  - Overly permissive permissions granted to LLM plugins: Granting excessive permissions enables unauthorized actions.

- Identity and User Context:
  - Use of highly privileged identities by LLM plugins: High-privileged identities lead to unnecessary authority, exploited by attackers.
  - Failure to restrict actions to authorized user context: Actions outside authorized context can be manipulated by attackers.
  - Failure to propagate user context to downstream systems: Lack of user context propagation allows actions without considering permissions.

- Authorization and Validation:
  - Reliance on LLM for authorization decisions: Sole reliance on LLM for authorization invites unauthorized actions.
  - Lack of complete mediation in downstream systems: Incomplete mediation skips proper validation, risking unauthorized actions.
  - Lack of human-in-the-loop approval for high-impact actions: Failing to require human approval before high-impact actions are executed can lead to unintended and potentially harmful actions.

- Causes that are OWASP Top 10 for LLM vulnerabilities:
  - LLM01: Prompt Injection - Excessive plugin functionality could enable malicious actions via prompt injection.
  - LLM02: Insecure Output Handling - Failure to validate LLM outputs could allow excessive actions if plugins are overly permissive.
  - LLM05: Supply Chain Vulnerabilities - Vulnerable components could grant excessive permissions.
  - LLM07: Insecure Plugin Design - Insecure plugins with excessive permissions could enable unauthorized actions.

**Potential Impacts**
- Unauthorized Actions
  - Privilege escalation: Excessive permissions in plugins can enable unauthorized privilege escalation. 
  - Unintended system modifications: LLMs may make unauthorized and potentially harmful system changes.

- Data Theft
  - Sensitive data theft: LLMs may access and steal confidential data.
  - Data exfiltration: LLMs may exfiltrate data to unauthorized parties. 

- Regulatory Noncompliance
  - Privacy violations: LLMs may improperly access or use personal data.
  - Unauthorized data collection: LLMs may collect data beyond permitted limits.

- Financial Impact
  - Fraud: LLMs with excessive agency may enable financial fraud.
  - Fines and penalties: Noncompliance can result in fines and legal penalties.

- Reputation Damage
  - Loss of customer trust: LLM misuse can damage trust in the provider's services.
  - Brand damage: LLM incidents can harm brand reputation.
  
- Individual Harm
  - Identity theft: LLMs may enable identity theft via unauthorized data access.
  - Unintended transactions: LLMs may cause individuals to make unintended purchases.




# LLM09: Overreliance

**Summary**
Failing to critically assess LLM outputs can lead to compromised decision making, security vulnerabilities, and legal liabilities.

**Description:**
Overreliance can occur when an LLM produces erroneous information and provides it in an authoritative manner. While LLMs can produce creative and informative content, they can also generate content that is factually incorrect, inappropriate or unsafe. This is referred to as hallucination or confabulation. When people or systems trust this information without oversight or confirmation it can result in misinformation, miscommunication, legal issues, and reputational damage.

LLM-generated source code can introduce unnoticed security vulnerabilities. This poses a significant risk to the operational safety and security of applications. These risks show the importance of rigorous review processes, with:

- Oversight
- Continuous validation mechanisms
- Disclaimers on risk

**Common Examples of Vulnerability:**
1. LLM provides inaccurate information as a response while stating it in a fashion implying it is highly authoritative.  The overall system is designed without proper checks and balances to handle this and the information misleads the user in a way that leads to harm
2. LLM suggests insecure or faulty code, leading to vulnerabilities when incorporated into a software system without proper human oversight.

**How to Prevent:**
1. Regularly monitor and review the LLM outputs. Use self-consistency or voting techniques to filter out inconsistent text. Comparing multiple model responses for a single prompt can better judge the quality and consistency of output.
2. Cross-check the LLM output with trusted external sources. This additional layer of validation can help ensure the information provided by the model is accurate and reliable.
3. Enhance the model with fine-tuning or embeddings to improve output quality. Generic pre-trained models are more likely to produce inaccurate information compared to tuned models in a particular domain.  Techniques such as prompt engineering, parameter efficient tuning (PET), full model tuning, and chain of thought prompting can be employed for this purpose.
4. Implement automatic validation mechanisms that can cross-verify the generated output against known facts or data. This can provide an additional layer of security and mitigate the risks associated with hallucinations.
5. Break down complex tasks into manageable subtasks and assign them to different agents. This not only helps in managing complexity, but it also reduces the chances of hallucinations as each agent can be held accountable for a smaller task.
6. Clearly communicate the risks and limitations associated with using LLMs. This includes potential for information inaccuracies, and other risks. Effective risk communication can prepare users for potential issues and help them make informed decisions.
7. Build APIs and user interfaces that encourage responsible and safe use of LLMs. This can involve measures such as content filters, user warnings about potential inaccuracies, and clear labeling of AI-generated content.
8. When using LLMs in development environments, establish secure coding practices and guidelines to prevent the integration of possible vulnerabilities.

**Example Attack Scenarios:**
1. A news organization heavily uses an LLM to generate news articles. A malicious actor exploits this over-reliance, feeding the LLM misleading information, and causing the spread of disinformation. 
2. The AI unintentionally plagiarizes content, leading to copyright issues and decreased trust in the organization.
3. A software development team utilizes an LLM system to expedite the coding process. Over-reliance on the AI's suggestions introduces security vulnerabilities in the application due to insecure default settings or recommendations inconsistent with secure coding practices.
4. A software development firm uses an LLM to assist developers. The LLM suggests a non-existent code library or package, and a developer, trusting the AI, unknowingly integrates a malicious package into the firm's software. This highlights the importance of cross-checking LLM suggestions, especially when involving third-party code or libraries.

**Common Weakness Enumeration (CWE)**

[CWE-119](https://cwe.mitre.org/data/definitions/119.html): Improper Restriction of Operations within the Bounds of a Memory Buffer - Applicable as unchecked LLM code risks buffer overflows.

[CWE-347](https://cwe.mitre.org/data/definitions/347.html): Improper Verification of Cryptographic Signature - Applicable as reliance on unsigned LLM content is risky. 

[CWE-707](https://cwe.mitre.org/data/definitions/707.html): Improper Enforcement of Message Integrity During Transmission in a Communication Channel - Applicable as reliance on unvalidated LLM communications risks integrity issues.

[CWE-839](https://cwe.mitre.org/data/definitions/839.html): Numeric Range Comparison Without Minimum Check - Applicable as reliance on unvalidated LLM numerical outputs is risky.

[CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization - Applicable as blind reliance could lead to missing authorization checks.

[CWE-829](https://cwe.mitre.org/data/definitions/829.html): Inclusion of Functionality from Untrusted Control Sphere - Applicable as reliance without validating functionality risks its inclusion from untrusted sources. 

[CWE-554](https://cwe.mitre.org/data/definitions/554.html): ASP.NET Misconfiguration: Not Understanding the Implications of Invoking Unvalidated Methods - Applicable as invoking unchecked LLM methods risks misconfiguration issues.

[CWE-908](https://cwe.mitre.org/data/definitions/908.html): Use of Uninitialized Resource - Applicable as reliance on uninitialized LLM outputs poses risks.

[CWE-1053](https://cwe.mitre.org/data/definitions/1053.html): Missing Documentation for Design - Applicable if design docs lacking details on monitoring/verification.

[CWE-1059](https://cwe.mitre.org/data/definitions/1059.html): Incomplete Documentation of Program Execution - Applicable if execution docs lack monitoring/verification details.  


**MITRE ATT&CK Techniques**

- AML.T0019: Publish Poisoned Data. Training models on poisoned data could lead to unreliable outputs. Poisons model reliability. 



**Root Causes**
- Overreliance on LLMs:
  - Lack of oversight on LLM-generated content: Insufficient scrutiny of LLM outputs allows for the dissemination of inaccurate or harmful information.
  - Absence of continuous validation mechanisms: Failing to regularly validate LLM-generated content can lead to the spread of misinformation and vulnerabilities.
  - Insufficient monitoring of LLM outputs: Not monitoring LLM outputs can result in the unaware dissemination of incorrect or insecure information.
  - Failure to compare multiple model responses: Not comparing multiple responses from the LLM can lead to the acceptance of inconsistent or inaccurate content.

- Lack of Validation and Cross-Verification:
  - Limited consistency checks on model responses: Inadequate checks for consistency in LLM responses can allow for the generation of conflicting or erroneous information.
  - Lack of validation against external trusted sources: Not cross-verifying LLM output with trusted external sources can lead to the acceptance of inaccurate information.
  - Insufficient content filtering: Failing to filter out inappropriate or unsafe content generated by the LLM can result in the spread of harmful information.
  - Lack of output validation: Absence of validation mechanisms can allow the LLM to produce content without ensuring its accuracy or safety.

- Causes that are OWASP Top 10 for LLM vulnerabilities:
  - LLM01: Prompt Injection - Overreliance could lead to insufficient input validation.
  - LLM02: Insecure Output Handling - Overreliance could lead to insufficient output scrutiny.
  - LLM07: Insecure Plugin Design - Overreliance could lead to insufficient plugin validation.

**Potential Impacts**
- Information Accuracy Risks
  - Inaccurate data spread: Overreliance on LLMs can result in the dissemination of inaccurate information, leading to potential misunderstandings and misinformed decisions.
  - Biased decisions: Relying solely on LLM-generated content may introduce biases or favor certain perspectives, impacting the fairness of decisions.
  - Integration of insecure code: Overreliance on LLM-generated code suggestions can lead to the integration of insecure or faulty code into software systems, potentially introducing vulnerabilities.
  - Acting on faulty data: Accepting LLM-generated data without adequate validation can lead to flawed business decisions and operational errors.

- Legal Liability  
  - Copyright violations: If LLM-generated content unintentionally plagiarizes copyrighted material, it can lead to legal issues and copyright violations.
  - Spread of misinformation: Overreliance on LLM-generated content, especially in news or publishing, can result in the spread of misinformation, leading to potential legal liabilities.
  
- Reputational Impact
  - Loss of user trust: Consistently relying on LLMs without proper validation can erode user trust, particularly if the content generated is inaccurate or inappropriate.
  - Brand damage: The dissemination of inaccurate or biased content generated by LLMs can harm an organization's reputation and brand image.
  
- Financial Impact
  - Revenue loss: Misinformation or operational errors caused by overreliance on LLMs can lead to financial losses, including reduced revenue and increased operational costs.




# LLM10: Model Theft

**Summary**
Unauthorized access to proprietary large language models risks theft, competitive advantage, and dissemination of sensitive information.

**Description:**
This entry refers to the unauthorized access and exfiltration of LLM models by malicious actors or APTs. This arises when the proprietary LLM models (being valuable intellectual property), are compromised, physically stolen, copied or weights and parameters are extracted to create a functional equivalent. The impact of LLM model theft can include economic and brand reputation loss, erosion of competitive advantage, unauthorized usage of the model or unauthorized access to sensitive information contained within the model.

The theft of LLMs represents a significant security concern as language models become increasingly powerful and prevalent. Organizations and researchers must prioritize robust security measures to protect their LLM models, ensuring the confidentiality and integrity of their intellectual property. Employing a comprehensive security framework that includes access controls, encryption, and continuous monitoring is crucial in mitigating the risks associated with LLM model theft and safeguarding the interests of both individuals and organizations relying on LLM.

**Common Examples of Vulnerability:**
1. An attacker exploits a vulnerability in a company's infrastructure to gain unauthorized access to their LLM model repository via misconfiguration in their network or application security settings.
2. Use a centralized ML Model Inventory or Registry for ML models used in production. Having a centralized model registry prevents unauthorized access to ML Models via access controls, authentication, and monitoring/logging capability which are good foundations for governance. Having a centralized repository is also beneficial for collecting data about algorithms used by the models for the purposes of compliance, risk assessments, and risk mitigation.
3. An insider threat scenario where a disgruntled employee leaks model or related artifacts.
4. An attacker queries the model API using carefully crafted inputs and prompt injection techniques to collect a sufficient number of outputs to create a shadow model.
5. A malicious attacker is able to bypass input filtering techniques of the LLM to perform a side-channel attack and ultimately harvest model weights and architecture information to a remote controlled resource.
6. The attack vector for model extraction involves querying the LLM with a large number of prompts on a particular topic. The outputs from the LLM can then be used to fine-tune another model. However, there are a few things to note about this attack:
   - The attacker must generate a large number of targeted prompts. If the prompts are not specific enough, the outputs from the LLM will be useless.
   - The outputs from LLMs can sometimes contain hallucinated answers meaning the attacker may not be able to extract the entire model as some of the outputs can be nonsensical.
     - It is not possible to replicate an LLM 100% through model extraction. However, the attacker will be able to replicate a partial model.
7. The attack vector for **_functional model replication_** involves using the target model via prompts to generate synthetic training data (an approach called "self-instruct") to then use it and fine-tune another foundational model to produce a functional equivalent. This bypasses the limitations of traditional query-based extraction used in Example 5 and has been successfully used in research of using an LLM to train another LLM. Although in the context of this research, model replication is not an attack. The approach could be used by an attacker to replicate a proprietary model with a public API.

Use of a stolen model, as a shadow model, can be used to stage adversarial attacks including unauthorized access to sensitive information contained within the model or experiment undetected with adversarial inputs to further stage advanced prompt injections.

**How to Prevent:**
1. Implement strong access controls (E.G., RBAC and rule of least privilege) and strong authentication mechanisms to limit unauthorized access to LLM model repositories and training environments.
   1. This is particularly true for the first three common examples, which could cause this vulnerability due to insider threats, misconfiguration, and/or weak security controls about the infrastructure that houses LLM models, weights and architecture in which a malicious actor could infiltrate from insider or outside the environment.
   2. Supplier management tracking, verification and dependency vulnerabilities are important focus topics to prevent exploits of supply-chain attacks.
2. Restrict the LLM's access to network resources, internal services, and APIs.
   1. This is particularly true for all common examples as it covers insider risk and threats, but also ultimately controls what the LLM application "_has access to_" and thus could be a mechanism or prevention step to prevent side-channel attacks.
3. Regularly monitor and audit access logs and activities related to LLM model repositories to detect and respond to any suspicious or unauthorized behavior promptly.
4. Automate MLOps deployment with governance and tracking and approval workflows to tighten access and deployment controls within the infrastructure.
5. Implement controls and mitigation strategies to mitigate and|or reduce risk of prompt injection techniques causing side-channel attacks.
6. Rate Limiting of API calls where applicable and|or filters to reduce risk of data exfiltration from the LLM applications, or implement techniques to detect (E.G., DLP) extraction activity from other monitoring systems.
7. Implement adversarial robustness training to help detect extraction queries and tighten physical security measures.
8. Implement a watermarking framework into the embedding and detection stages of an LLMs lifecyle.

**Example Attack Scenarios:**
1. An attacker exploits a vulnerability in a company's infrastructure to gain unauthorized access to their LLM model repository. The attacker proceeds to exfiltrate valuable LLM models and uses them to launch a competing language processing service or extract sensitive information, causing significant financial harm to the original company.
2. A disgruntled employee leaks model or related artifacts. The public exposure of this scenario increases knowledge to attackers for gray box adversarial attacks or alternatively directly steal the available property.
3. An attacker queries the API with carefully selected inputs and collects sufficient number of outputs to create a shadow model.
4. A security control failure is present within the supply-chain and leads to data leaks of proprietary model information.
5. A malicious attacker bypasses input filtering techniques and preambles of the LLM to perform a side-channel attack and retrieve model information to a remote controlled resource under their control.


**Common Weakness Enumeration (CWE)**

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


**MITRE ATT&CK Techniques**

- AML.T0024: Exfiltration via ML Inference API. Carefully crafted queries could elicit model details that are extracted. Extracts model details.

- AML.T0043: Craft Adversarial Data. Tailored prompts could infer model architecture and parameters. Infers model details.

- AML.T0040: ML Model Inference API Access. Repeated queries could reconstruct model behavior for theft. Reconstructs model.

- AML.T0012: Valid Accounts. Compromised credentials provide access to steal artifacts. Enables unauthorized access.

- AML.T0044: Full ML Model Access. Full control makes stealing artifacts simpler. Provides direct access for theft. 

- AML.T0010: ML Supply Chain Compromise. Compromising suppliers provides a vector to steal models. Attacks supply chain.

- AML.T0016: Obtain Capabilities. May obtain tools to automate model extraction. Aids model theft.

- AML.T0047: ML-Enabled Product or Service. Commercial services with weak protections could enable theft. Finds vulnerable services.


**Root Causes**
- Access Control and Security Measures:
  - Weak access controls: Inadequate access control mechanisms can allow unauthorized individuals or systems to gain access to LLM model repositories, leading to potential theft.
  - Misconfigured network security: Poorly configured network security settings can create vulnerabilities that attackers can exploit to access and exfiltrate LLM models.
  - Authentication weaknesses: Weak authentication mechanisms may lead to unauthorized access to LLM models, enabling attackers to steal or misuse them.
  - Unrestricted network access: Allowing unrestricted network access for LLMs can expose them to potential side-channel attacks.

- Insider Threats:
  - Insider threats: Disgruntled employees or insiders can pose a significant risk by leaking LLM models or related artifacts.

Model Extraction Techniques:
  - Side-channel attacks: Attackers can exploit side-channel attacks to retrieve model information through the LLM, potentially leading to theft.
  - Query-based extraction: Attackers can use carefully crafted queries to extract information from LLMs, posing a threat to model security.
  - Functional model replication: Functional model replication involves using the LLM to generate synthetic training data for another model, potentially leading to the creation of a functional equivalent.

- Monitoring and Governance:
  -  Inadequate monitoring: Failing to monitor and audit access logs and activities related to LLM model repositories can leave organizations unaware of unauthorized access or data theft.
  - Lack of deployment governance: Lack of governance and approval workflows in MLOps deployment can result in weaker access and deployment controls.

- Causes that are OWASP Top 10 for LLM vulnerabilities:
  - LLM05: Supply Chain Vulnerabilities - Vulnerable components could enable unauthorized access.

**Potential Impacts**
- Intellectual Property Loss
  - Competitive advantage loss: Theft can enable competitors to access proprietary models.
  - Financial losses: Model theft can lead to economic and financial damage.

- Data Theft 
  - Sensitive data theft: Model theft may expose sensitive data contained within models.
  - Data exfiltration: Attackers may steal data via the compromised model.
  
- Brand Impact
  - Reputational damage: Model theft incidents can harm brand reputation. 
  - Loss of customer trust: Such incidents may erode customer trust in the organization.
  
- Adversarial Risks
  - Malicious model use: Stolen models may be used for unauthorized access or manipulation.
  - Prompt injection risks: Theft enables advanced prompt injection attacks.
  
- Legal and Compliance
  - Data breach liability: Model theft leading to data loss may spur legal liability.
  - Regulatory violations: Model theft can violate data protection laws.


