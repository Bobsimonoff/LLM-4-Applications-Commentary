By Bob Simonoff

- LinkedIn at https://www.linkedin.com/in/bob-simonoff

- medium/com at https://medium.com/@bob.simonoff

- github at https://github.com/Bobsimonoff/LLM-4-Applications-Commentary/tree/main


# LLM09: Overreliance

## Summary
Failing to critically assess LLM outputs can lead to compromised decision making, security vulnerabilities, and legal liabilities.

## Description

Blindly trusting LLM outputs without proper validation can lead to the dissemination of misinformation, integration of vulnerabilities, and other issues.  

Failing to scrutinize outputs allows attackers to manipulate prompts or poison training data to trick the LLM into generating plausible but inaccurate or biased content. Overreliance on unchecked model responses can result in legal liabilities, financial losses, reputational damage, and security risks.

Prevention requires continuous monitoring, oversight, and multiple levels of verification. Outputs should be validated against trusted external sources and checked for consistency across models. Automated validation tools and vigilant human review are essential. Risks should be clearly communicated and UIs designed to promote responsible LLM use. Establishing secure coding practices is critical when relying on LLM-generated code. Reducing overreliance through defense-in-depth and critical evaluation is key to mitigating risks.

## CWE

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



---
---
# WIP: Ignore below this line for now
---
---





## NIST CSF 

N/A


## MITRE ATT&CK

**Tactics**

N/A

**Techniques**

N/A


## CIS Controls

N/A 

## FAIR 

**Threat Communities:**
- Competitors (TC.CP): Could exploit overreliance to damage reputation with inaccurate outputs.
- Hacktivists (TC.ACT): Could leverage overreliance to spread disinformation.

**Loss Factors:**

- Productivity Loss (LF.P): Overreliance issues degrade productivity through inaccurate responses to prompts.

- Fines & Judgements (LF.FJ): Overreliance could lead to lawsuits, fines, and legal judgements.

- Reputation Loss (LF.R): Inaccurate outputs damage brand reputation.


## BSIMM

N/A


## ENISA

**Threats**

N/A

**Controls** 

N/A

## OAIR

**Vulnerabilities**

N/A

**Threat Scenarios**

N/A

**Harms**

N/A

## ATLAS

**Tactics**
N/A

**Techniques**
N/A

**Procedures**
N/A
