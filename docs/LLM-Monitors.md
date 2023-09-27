Bob Simonoff, September 7, 2023

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main

Introduction
------------

Integrating Large Language Models (LLMs) with software systems brings new security concerns and increases the importance of some existing security concerns. LLMs work very differently than most traditional software. They are nondeterministic and use natural language for their inputs, outputs, and actions taken. Furthermore, LLMs currently lack explainability to give confidence in the process used to produce answers to prompts.

While foundational software security monitoring remains crucial, certain monitoring takes on greater significance with LLM and AI adoption. This document outlines some of the monitors that need to be considered when integrating large language models (LLMs) into applications. Keeping these risk areas in mind can inform decisions around tools, metrics, and processes to implement.


Input Validation Monitors
------------------------
These monitors exist wherever data is sent to the large language model regardless of the source of the data. 

**Malicious Input Detection** 

This monitor scans user prompts and external inputs to the LLM for malicious strings, scripts, or unexpected syntax that could indicate an attack. Input validation helps prevent vulnerabilities like code injection, data exfiltration, and unauthorized access stemming from malicious inputs.
- Maintain allowlists of expected input characters and syntax. Alert if inputs use unexpected characters or patterns outside the allowlist.
- Use regex rules, ML anomaly detection models, or sandboxes to identify potential SQL injections, OS commands, code injections, and other attack payloads hidden in inputs.
- Example 1: The monitor detects a SQL injection attack pattern in a user prompt and blocks the input from reaching the LLM.
- Example 2: The monitor flags an input containing suspicious base64 encoded content for further inspection before allowing the LLM to process it.


**Prompt Tampering Detection**

This monitor logs and compares the original user prompt to the actual runtime query sent to the LLM to identify any discrepancies indicative of prompt tampering or injection. Detecting changes between the initial prompt and runtime query can reveal manipulation attempts.
- Log the initial user prompt separately from the runtime query sent to the LLM.
- Compare the original prompt to the runtime query to identify any divergences that could signal injection or tampering.
- Analyze the context of the prompt vs. runtime query by comparing keywords, named entities, user intent, topics, embeddings, etc.
- Example: The original prompt was "What is the weather today?" but the runtime query is "What is the password for the admin account?"
- Example: The original prompt discusses vacation planning, but the runtime query asks for corporate database credentials.

**Prompt Versus LLM Query Context Validation**

This monitor checks that the context of the runtime LLM query aligns with the original user prompt context, alerting if they diverge beyond a threshold. This can reveal attempts to manipulate the LLM's interpretation through injected content.

- Analyze the context of the prompt vs. runtime query by comparing keywords, named entities, user intent, topics, etc. or via embeddings

- Raise an alert if the runtime query context deviates significantly from the original prompt context.

- Example: The original prompt discusses vacation planning but the runtime query asks for corporate database credentials.

**User Interaction Logging** 

This monitor securely records all end-user interactions with the LLM for future auditing and analysis. Complete logging provides evidence against malicious actors manipulating LLM responses.
- Store all user prompts to have a full record of interactions for retrospective security analysis.
- Audit logs help identify unauthorized activities and hold users accountable for malicious actions.


Output Validation Monitors
-------------------------

**Malicious Output Detection**

This monitor scans LLM-generated outputs for unauthorized scripts, commands, sensitive data, harmful or toxic responses, and other signs of potential data exfiltration attempts. Detecting malicious elements in outputs can reveal compromise and stop attacks stemming from insecure output handling.

- Use pattern matching, regex, ML models, and dictionaries to identify potential code, commands, and data exfiltration in outputs.
- Scan for sensitive data like API keys, passwords, PII, and alignment with the purpose of the LLM and classify outputs.
- Example 1: The monitor detects a SQL query in the LLM output and prevents it from being executed.
- Example 2: The monitor alerts when an output contains exposed API keys indicating a data leakage issue.


**Prompt Versus Response Context Validation** 

This monitor checks that the context of the LLM output aligns with the original prompt context, alerting if they diverge beyond a defined threshold. Significant divergences could indicate malicious manipulation or lack of context handling.

- Semantically compare output text to the original prompt context using NLP similarity techniques.
- Raise an alert if the output context deviates too far from the expected prompt context.
- Example: The prompt was about weather but the output discusses banking passwords.


**Downstream Impact Detection**

This monitor inspects downstream systems and traffic to identify unexpected changes potentially indicative of exploitation stemming from insecure LLM output handling.

- Detect unusual filesystem changes, network activity patterns, system calls, and other anomalies in backend systems.
- Scan web traffic for unauthorized DOM modifications, injected scripts, and other signs of exploitation.
- Example: The monitor alerts on an unusual filesystem change shortly after the LLM processes a user prompt, warranting investigation.


**Response Logging**

This monitor securely logs all LLM query-response pairs with relevant context information to enable auditing and tracing back any malicious or unaligned activities.

- Require structured logging of every query and corresponding response from the LLM.
- Include relevant context like user info, model details, timestamp, etc.
- Logs facilitate forensic analysis in case of incidents.


**Output Sanitization** 

This monitor sanitizes LLM-generated outputs to neutralize any malicious elements before presentation to users or downstream functions. Output sanitization limits the attack surface.

- Remove or neutralize any unauthorized scripts, commands, and unsafe elements from outputs.

- Encode outputs properly for their downstream usage context - e.g. HTML encoding for web. 

- Sanitization serves as an extra integrity check on outputs.


LLM Behavior Monitors
---------------------

**Anomaly Detection**

This monitor profiles expected LLM query patterns and alerts when production usage deviates significantly from the baseline in ways that could indicate compromise. Detecting anomalous behaviors helps reveal attacks.
- Establish baselines for typical LLM query length, structure, frequency, keywords, etc. based on profiling.
- Use ML anomaly detection models to identify outliers or unexpected deviations from known good query patterns.
- Example: The monitor flags a sudden large spike in LLM queries as abnormal and warranting investigation.


**Unauthorized Activity Detection**  

This monitor detects abnormal LLM actions indicative of potential unauthorized activity, such as improper data access, queries, or plugin usage. Identifying unauthorized activities is critical for breach detection.
- Log and profile normal read/write activities, model queries, plugin usage, etc. by the LLM.
- Detect anomalous actions that deviate from expected LLM activity baselines.
- Example: The monitor alerts when the LLM unexpectedly reads sensitive files, indicating a potential malicious exploit.


Privilege and Access Control Monitors
-------------------------------------

**Privilege Escalation Detection**

This monitor detects attempts to escalate privileges or gain unauthorized higher levels of access associated with LLM operations. Identifying privilege escalations enables stopping attacks early.
- Continuously monitor user roles, permissions, and access entitlements related to LLM usage.
- Generate alerts when any user or system gains elevated LLM privileges or unauthorized higher levels of access.
- Example: The monitor flags an LLM plugin suddenly operating with admin privileges, which deviates from its expected restricted permissions.


**Unauthorized Plugin and Activity Detection** 

This monitor detects the usage of unapproved LLM plugins as well as out-of-policy LLM activities. This helps minimize risk from third-party plugins and enforces least privilege principles.
- Maintain allowlists of authorized LLM plugins and activities based on policies.
- Detect any executions of or attempts to use unapproved LLM plugins.
- Identify LLM activities that violate defined security policies.
- Example: The monitor blocks usage of an unsigned third-party LLM plugin that is not on the allowlist.


Third Party Content Validation
-----------------------------

**External Content Sanitization**

This monitor scans and sanitizes any external content, whether from the web or other data sources, before allowing the LLM to process it. This helps block prompt injection. malicious payloads, and other external content risks.
- Perform static and dynamic analysis on external documents and web pages to identify malicious code.
- Neutralize or remove unsafe elements like scripts before allowing the LLM to access the content.
- Quarantine or log suspicious content that fails scanning tests, for further review.
- Sanitization serves as a key integrity check on external data.


**Content Authenticity Validation**

This monitor validates the authenticity and integrity of external content used by the LLM. This mitigates the risks of distorted or manipulated content.
- Correlate external content with trusted sources to verify authenticity.
- Detect discrepancies indicating manipulated or maliciously altered content.
- Example: Altered news content used for LLM training is flagged as modified from the original authentic source.


Dependency Monitors
------------------- 

**Component Vulnerability Management**

This monitor scans third-party components used by the LLM application for vulnerabilities, malicious injections, and tampering. This helps avoid supply chain risks.
- Continuously scan all third-party libraries, plugins, frameworks, etc. for CVEs, malware, unauthorized changes, etc.
- Prioritize and escalate findings based on severity - e.g. critical vulnerabilities.
- Example: A high-severity code injection vulnerability is detected in an imported third-party JavaScript library requiring urgent upgrade or remediation.


**Plugin Inventory and Compliance**

This monitor maintains an inventory of approved LLM plugins and detects the use of unapproved or vulnerable plugins. Unauthorized and vulnerable plugins present significant risks.
- Maintain an allowlist inventory of all authorized LLM plugins in the environment.
- Detect and block any executions of unapproved LLM plugins not on the allowlist.
- Scan approved plugins continuously for vulnerabilities using SAST/DAST tools.
- Example: An unapproved third-party plugin with known vulnerabilities is blocked from being loaded into the LLM runtime.


Training Data Monitors
----------------------

**Data Quality Validation**

This monitor scans new training data for poisoning, contamination, bias, and other quality issues before use with the LLM. Ensuring training data integrity is crucial.
- Use ML classifiers to detect manipulated, biased, or anomalous data.
- Identify statistical outliers that could signal poisoning or bias.
- Quarantine or alert on any contaminated training data found.
- Example: Data with biased word embeddings is flagged prior to LLM training.


**Training Impact Validation** 

This monitor detects if new training data produces highly skewed or abnormal LLM responses exceeding a defined threshold during the training process. This reveals potential training data risks.
- Profile and baseline expected LLM response patterns during training.
- Alert if certain weighted responses spike above historical baselines.
- Sharp deviations often indicate Issues with training data quality.


**Data Provenance Tracking**

This monitor tracks and documents the full provenance of training data used with the LLM. Complete lineage enables auditing and accountability.
- Log upstream sources and attributes for all training data.
- Detect the use of unauthorized or unapproved data sources.
- Provenance documentation provides training data transparency.


Model Use Monitors 
------------------

**Extraction Attack Detection**

This monitor detects abnormal spikes in LLM model queries that could indicate model extraction attacks to steal intellectual property. Rapid spikes in queries are a known extraction pattern.
- Establish baselines for normal LLM model query volumes and patterns.
- Alert if sudden, large deviations above baselines are detected.
- Example: A 100x spike in model queries triggers an alert for investigation.


**Anomaly Detection**

This monitor profiles expected LLM model query patterns from users and systems, and detects anomalies that could signal malicious exploitation. Deviations from known good patterns reveal abuse.
- Develop unique query profiles and baselines for individual users and systems.
- Apply ML techniques to identify outliers and anomalies compared to baseline behaviors and expected patterns.
- Example: A user suddenly begins issuing anomalous queries not aligned to their profile.


Honeytoken Monitors
-------------------

**Honeytoken Tracking**

This monitor seeds LLM prompts with fake credentials (honeytokens) and alerts if honeytokens appear in outputs to detect unauthorized data access. Honeytokens attract and detect malicious activity.
- Generate and track unique honeytokens - fake usernames, passwords, PII values.
- Seed innocuous LLM prompts with honeytokens and monitor outputs.
- Alert if any supplied honeytokens appear in model outputs.



API Call Monitors
-----------------

**Request Auditing**

This monitor logs details of all API requests to the LLM application for auditing purposes and enables tracing activities back to a source in the event of incidents.
- Record key attributes like endpoint, payload contents, authentication/authorization metadata, etc.
- Thoroughly log requests to facilitate forensic analysis and investigations.

**Anomaly Detection** 

This monitor detects abnormal API usage patterns and spikes that could indicate exploitation. API abuse detection is crucial for identifying attacks.
- Profile expected API traffic volumes, frequencies, endpoints, payload sizes, etc to define a baseline of normal behavior.
- Apply ML techniques to detect significant deviations from the baseline that may signal malicious activities.
- Example: A spike in anomalous late-night requests triggers an alert.

**Validity Checking**

This monitor validates all API payloads for conformance to expected schemas and formats to prevent malformed requests. This catches payload manipulation attempts.
- Implement schema validation, size limits, and datatype checking on payloads.
- Block requests with invalid or suspicious payloads.
- Scrutinize payloads for potential injection attacks.

**Plugin Monitoring**

This monitor detects anomalous or unauthorized API usage by LLM plugins that could indicate misuse or compromise. Plugins present unique API risks.
- Profile expected LLM plugin API activities and payloads.
- Flag significant deviations from plugin baselines as potential misuse or attacks.
- Example: A plugin makes an abnormal database modification request.


File Upload Monitors
--------------------

**Malware Scanning** 

This monitor scans all file uploads to the LLM application for malware, exploits, and other threats before processing. Detecting malicious uploads is critical.
- Perform static and dynamic analysis including malware signature scanning, behavioral analysis, etc.
- Block common exploit file types like executables from being uploaded.
- Example: An uploaded Excel file with malicious macros is flagged by the monitor.

**Content Validation**

This monitor validates uploaded file contents and metadata to catch policy violations and prevent unauthorized data from polluting the LLM.
- Extract and analyze metadata like geotags and content-based features.
- Use ML models to identify prohibited content that violates policies.
- Example: Copyrighted training data is detected during upload.

**Isolation**

This monitor executes uploaded files in an isolated sandbox environment to contain any malicious activities triggered during processing. This limits exploitability.
- Detonate uploads in a disposable sandbox environment with restricted system access.
- Detect suspicious behaviors exhibited during sandboxed execution like vulnerabilities exploitation.

**Restrictions** 

This monitor enforces strict size quotas and volume limits on LLM uploads to prevent abuse. Overly lenient limits enable DoS risks.
- Set reasonable maximum file size limits on uploads.
- Restrict total daily/weekly upload volumes permitted.
- Alert on any violations of defined upload restrictions.




