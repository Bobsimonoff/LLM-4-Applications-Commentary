# LLM08: Excessive Agency

## Summary
Granting LLMs unchecked autonomy to take action can lead to unintended consequences, jeopardizing reliability, privacy, and trust.

## Description

Granting LLMs unchecked autonomy to take actions through excessive permissions, functionality, and lack of oversight can lead to harmful unintended consequences. 

Attackers can exploit ambiguous or malicious prompts, along with insecure plugins and components, to manipulate the LLM into taking unauthorized and potentially damaging actions. Successful attacks can result in data breaches, financial fraud, regulatory violations, reputational damage, and other impacts.

Prevention requires limiting LLM functionality, permissions, and autonomy to only what is essential. Strict input validation and robust access controls should be implemented in plugins. User context must be maintained and human approval required for impactful actions. Monitoring systems and rate limiting can help detect and limit unauthorized behaviors. Following security best practices around authorization, mediation, and privilege minimization is key to securing LLM agency.

## CWE

[CWE-272](https://cwe.mitre.org/data/definitions/272.html): Least Privilege Violation - Applicable when excessive permissions are granted beyond functional needs.

[CWE-284](https://cwe.mitre.org/data/definitions/284.html): Improper Access Control - Applicable if plugins lack access controls, enabling unauthorized actions.

[CWE-285](https://cwe.mitre.org/data/definitions/285.html): Improper Authorization - Applicable when improper authorization leads to unauthorized actions. 

[CWE-347](https://cwe.mitre.org/data/definitions/347.html): Improper Verification of Cryptographic Signature - Applicable if failure to verify signatures poses authorization risks.

[CWE-732](https://cwe.mitre.org/data/definitions/732.html): Inadequate Encoding of Output Data - Applicable if plugin output lacks encoding, leading to unintended actions.

[CWE-798](https://cwe.mitre.org/data/definitions/798.html): Use of Hard-coded Credentials - Applicable as hard-coded credentials with excessive permissions pose unauthorized action risks.

[CWE-799](https://cwe.mitre.org/data/definitions/799.html): Improper Control of Interaction Frequency - Applicable as lack of frequency control poses risks of excessive unauthorized actions.  

[CWE-862](https://cwe.mitre.org/data/definitions/862.html): Missing Authorization - Applicable when authorization is not checked before actions.



---
---
# WIP: Ignore below this line for now
---
---




## NIST CSF

### Identify Function

**ID.AM-3: Organizational communication and data flows are mapped**

Mapping how data flows between systems and applications to understand what actions and access LLMs may have. This enables identifying excessive permissions and functionality.

**ID.BE-5: Dependencies and critical functions for delivery of critical services are established** 

Identifying critical services and dependencies allows evaluating potential impacts of excessive LLM agency.

**ID.GV-1: Organizational information security policy is established**

Establishing security policies provides standards to assess whether LLM functionality and agency align with policy. 

**ID.RA-1: Asset vulnerabilities are identified and documented**

Documenting asset vulnerabilities helps identify where excessive LLM agency could be exploited.

### Protect Function


**PR.PT-1: Audit/log records are determined, documented, implemented, and reviewed in accordance with policy**

Auditing LLM actions provides tracing for excessive agency incidents.

**PR.AC-1: Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes**

Proper identity and credential management prevents the use of excessive privileges by LLM plugins.

**PR.AC-3: Remote access is managed**

Managing remote access prevents unauthorized remote actions by LLMs.

**PR.AC-4: Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties** 

Least privilege limits the impact of excessive agency.

**PR.AC-5: Network integrity is protected (e.g., network segregation, network segmentation)**

Network controls protect unauthorized LLM network activity.


**PR.DS-5: Protections against data leaks are implemented** 

Protecting against data leaks limits exfiltration enabled by excessive LLM agency.

**PR.IP-1: A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles (e.g. concept of least functionality)**

Least functionality baseline configurations prevent unnecessary LLM functionality.


**PR.PT-3: The principle of least functionality is incorporated by configuring systems to provide only essential capabilities**

Least functionality limits potential impact of excessive LLM agency.

**ID.RA-2: Cyber threat intelligence is received from information sharing forums and sources**

Threat intel can provide insights into emerging excessive agency vulnerabilities to address in third-party components.

### Detect Function

**DE.DP-2: Detection activities comply with all applicable requirements**

Ensures excessive agency detection aligns with legal/regulatory policies.

**DE.AE-1: A baseline of network operations and expected data flows for users and systems is established and managed**

Baselines help detect anomalous actions from excessive LLM agency.

**DE.AE-2: Detected events are analyzed to understand attack targets and methods** 

Analyzing events helps determine root causes like excessive permissions. 

**DE.CM-1: The network is monitored to detect potential cybersecurity events**

Monitoring can detect malicious activity from excessive agency.

**DE.CM-3: Personnel activity is monitored to detect potential cybersecurity events**

Monitoring user activity helps detect unauthorized actions.

**DE.CM-4: Malicious code is detected**

Malicious code detection can identify malware enabling excessive agency.

**DE.CM-7: Monitoring for unauthorized personnel, connections, devices, and software is performed** 

Monitoring helps detect malicious unauthorized actions.

### Respond Function 

**RS.MI-2: Incidents are mitigated**

Mitigating incidents stemming from excessive agency limits damage.

**RS.CO-2: Events are reported consistent with established criteria**

Reporting excessive agency events facilitates response. 

**RS.CO-3: Information is shared consistent with response plans** 

Sharing information on excessive agency incidents enables better response.

**RS.AN-1: Notifications from detection systems are investigated**

Investigating alerts can identify unauthorized actions.

**RS.IM-1: Response plans incorporate lessons learned**

Incorporating lessons around excessive agency strengthens response.

**RS.IM-2: Response strategies are updated**

Updating response strategies improves capability to address excessive agency incidents.

**RS.RP-1: Response plan is executed during or after an event**

Executing response plans helps recover from excessive agency events.


### Recover Function

**RC.RP-1: Recovery plan is executed during or after a cybersecurity incident**

Recovery planning helps restore capabilities impaired by excessive agency incidents.


## MITRE ATT&CK

### Initial Access

**T1190 - Exploit Public-Facing Application**

Exploiting vulnerabilities in public apps accessed by LLMs can enable initial access for unauthorized actions. 

**T1133 - External Remote Services**

LLMs may connect to external services, which if excessive permissions exist, can enable initial unauthorized access.

**T1189 - Drive-by Compromise** 

LLMs may connect to external facing components vulnerable to drive-by attacks, providing initial access.

### Execution

**T1106 - Execution through API** 

APIs exposed to LLMs with excessive permissions allow execution of unintended functions.

**T1203 - Exploitation for Client Execution** 

Exploiting client apps accessed by LLMs can lead to unintended code execution.

**T1059 - Command and Scripting Interpreter**

Excessive permissions may allow LLMs to access interpreters and execute unintended commands.

**T1064 - Scripting**

LLMs may be able to access and abuse script interpreters.

### Persistence

**T1136 - Create Account**

Excessive permissions could enable LLMs to create unauthorized accounts. 

**T1197 - BITS Jobs** 

LLMs could use BITS jobs for persistence of unauthorized access.


### Privilege Escalation  

**T1078 - Valid Accounts**

Excessive permissions granted to accounts used by LLMs may enable privilege escalation.

**T1548 - Abuse Elevation Control Mechanism**

LLMs could exploit elevation control mechanisms to gain privilege escalation.

**T1088 - Bypass User Account Control**

Excessive LLM agency could enable UAC bypass on endpoints.

### Defense Evasion

**T1562 - Impair Defenses**

Excessive permissions may enable LLMs to impair defenses like disabling security tools.

**T1554 - Compromise Client Software Binary**

LLMs could tamper with client software they access to evade defenses.  

### Credential Access

**T1555 - Credentials from Password Stores** 

LLMs may access credentials in stores like password managers. 

**T1081 - Credentials in Files**

LLMs could access credential files they have permissions to.

**T1528 - Steal Application Access Token**

LLMs may be able to steal tokens.

### Discovery

**T1083 - File and Directory Discovery**

Excessive permissions may enable LLMs to discover unauthorized files and directories. 

**T1010 - Application Window Discovery** 

LLMs could discover applications to identify targets.

### Lateral Movement 

**T1563 - Remote Service Session Hijacking**

LLMs with excessive privileges could hijack other user remote sessions.

**T1105 - Remote File Copy**

LLMs may copy remote files they shouldn't have access to.

### Collection

**T1005 - Data from Local System**

LLMs could collect and exfiltrate local data they have excessive access to.  

**T1119 - Automated Collection**

Excessive permissions may enable automated collection of unauthorized data.

### Exfiltration

**T1022 - Data Encrypted**

LLMs may encrypt data prior to exfiltration to avoid detection.

**T1567 - Exfiltration Over Web Service**

LLMs with excessive permissions could exfiltrate data over web services.

### Impact

**T1499 - Endpoint Denial of Service** 

LLMs could trigger denial of service on endpoints they have access to.

**T1485 - Data Destruction**

Excessive permissions may allow LLMs to destroy or corrupt data.


## CIS CONTROLS

Here are the CIS Controls mapped with metrics:

**3.4 Use VLANs to segment networks**

Segmenting networks limits potential impact of excessive LLM network access.

Metrics: Percentage of systems using VLANs or other network segmentation

**4.5 Use multifactor authentication**

MFA protects access to systems LLMs interface with. 

Metrics: Percentage of systems using MFA

**5.1 Establish secure configurations**

Establishing secure system configurations limits unnecessary functionality accessible to LLMs.

Metrics: Percentage of systems with secure configurations applied

**5.7 Employ application isolation and sandboxing** 

Isolating/sandboxing applications limits what LLMs can impact.

Metrics: Percentage of applications isolated or sandboxed

**6.2 Ensure software is still supported**

Unsupported software is more likely to have excessive agency vulnerabilities.

Metrics: Percentage of EOL systems 

**8.4 Conduct regular pen testing of externally facing apps**

Pen testing helps find excessive access/functionality issues in external apps.

Metrics: Frequency of external pen testing

**9.1 Limit access to authorized users and processes**

Limiting access to authorized users/processes prevents LLMs from taking unauthorized actions.

Metrics: Percentage of systems properly restricting access

**10.1 Use application whitelisting** 

Whitelisting limits applications LLMs can execute code in.

Metrics: Percentage of systems using application whitelisting

**11.4 Deploy intrusion detection and prevention systems**

IDS/IPS can detect malicious activity resulting from excessive LLM agency.

Metrics: Percentage of systems covered by IDS/IPS

**16.8 Conduct penetration testing and red team exercises**

Pen testing helps identify excessive permissions issues. 

Metrics: Frequency of penetration testing and red teams

**16.12 Conduct crisis management exercises**

Exercises prep response to excessive agency crises.

Metrics: Frequency of crisis management exercises


## FAIR

**Malicious User Threat Community** 

Attackers could exploit excessive LLM agency to achieve malicious goals.

**Unintentional Actor Threat Community**

Excessive agency may enable unintentional harmful actions by authorized LLM users. 

**Partners Threat Community**

Business partners could exploit excessive access granted through integrations.

**Service Providers Threat Community** 

Vendors servicing systems could misuse excessive privileges.

**Loss Event Frequency Factor**

Frequency that loss events resulting from excessive agency may occur. 

**Loss Magnitude Factor** 

Impact/severity of losses from incidents enabled by excessive LLM agency.

**Secondary Loss Events Factor**

Follow-on damages like outages during recovery from excessive agency incidents.

**Loss Event Duration Factor**

Length of time losses are incurred during excessive agency events.


## BSIMM

**Practice 2: Architecture Analysis**

Analyzing architecture identifies high-risk components prone to excessive agency.  


**Practice 9: Standards and Requirements**

Establishing security standards ensures excessive agency risks are addressed.


**Practice 10: Strategy and Metrics** 

Developing metrics to track excessive agency risks helps inform security strategy. 


**Practice 12: Compliance and Policy**

Compliance policies can mandate controls limiting excessive agency.


## ENISA

**Threat T16: Manipulation of the training data**

Manipulated training data could lead models prone to generating outputs that trigger excessive unauthorized actions when automated.


**Threat T10: Unexpected malicious input triggers undesired behavior**

Malicious inputs could exploit excessive agency by triggering damaging actions. 


**Control C10: Software security**

Applying security practices like least privilege limits potential impact of excessive agency.


**Control C21: Formally verify, validate and test** 

Formal verification, validation and testing helps identify excessive agency risks.


## OAIR

**Misuse vulnerability**

LLMs with excessive permissions and inadequate constraints on functionality are vulnerable to misuse, enabling adversaries to achieve malicious objectives.

**Unintended functionality vulnerability**

Excessive LLM functionality increases the potential for unintended consequences when commands are incorrectly interpreted.

**Unanticipated misuse threat scenario**

Adversaries could craft inputs to exploit excessive LLM permissions to carry out harmful unintended actions.

**Quantity harm** 

Excessive automation paired with excessive agency risks quantitatively more frequent or severe harms.

## ATLAS

**Reconnaissance TTPs**

Adversaries may probe systems interfaced by LLMs to identify excessive permissions to exploit.

**Development TTPs**

Adversaries may develop customized payloads tailored to abuse excessive LLM functionality. 

**Insertion TTPs**

Threat actors could insert malicious inputs or code to hijack excessive LLM permissions.

**Execution TTPs** 

Adversaries may use command execution tactics to leverage excessive LLM capabilities.

**Exfiltration TTPs**

Threat actors could leverage excessive LLM permissions to steal data.

**Command and Control TTPs**

Adversaries may exploit excessive permissions to establish C2 channels.