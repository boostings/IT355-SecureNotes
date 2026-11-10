# Member 1 – Abstract & Conclusion

> Draft — reword in your own terms. Abstract must stay ≤ 200 words (this one is about 180).

---

## Abstract

Software vulnerabilities rarely come from exotic attacks. Most come from a small set of well-known mistakes that developers repeat across projects and languages. This report studies the Common Weakness Enumeration (CWE), the community-built catalog of software and hardware weakness types maintained by MITRE, and shows how developers can use it to write safer code. We first explain what CWE is, who maintains it, and how a single CWE entry is organized, from its description and relationships to its consequences and mitigations. We then examine thirty weaknesses from the CWE-699 Software Development view, covering credentials, authentication, sessions, file handling, resource management, concurrency, cryptography, and information exposure. For each one we explain what it is and why it matters. To put these ideas into practice, the team built SecureNotes, a Java terminal application that avoids all thirty weaknesses, with each defense labeled in the code. Finally, we explain how CWE connects to CVE, NVD, and CAPEC to form the wider vulnerability ecosystem. Readers will come away able to recognize common weaknesses, read a CWE entry, and apply proven mitigations in their own Java programs.

**GitHub repository:** https://github.com/boostings/IT355-SecureNotes

---

## Conclusion

The Common Weakness Enumeration turns decades of security failures into a shared vocabulary. Instead of treating each vulnerability as a one-off surprise, CWE groups them into types with known causes, consequences, and fixes. Working on this project showed us that most of the thirty weaknesses we studied are not hard to prevent. Using a `PreparedStatement`-style safe API, `SecureRandom` instead of `Random`, try-with-resources, PBKDF2 for passwords, AES-GCM for encryption, and an authorization check inside every sensitive method each took only a few lines of Java. The hard part is knowing the weakness exists in the first place, and that is exactly the gap CWE fills.

We also learned how CWE fits into a larger system. A CWE describes the kind of mistake, a CVE records a real instance of it in a specific product, NVD scores and tracks those CVEs, and CAPEC describes how attackers exploit the weakness. Together they connect a developer's coding decision to real-world impact.

Engineers can use CWE in their daily work in several ways:
- as a checklist during design and code review
- to prioritize fixes using the CWE Top 25 Most Dangerous Software Weaknesses
- to interpret findings from static analysis tools, which report results by CWE ID
- to write security requirements and test cases
- to train new developers using the real examples in each entry

As a team, we found that splitting the work by weakness category let each member become the expert on one area, while building a single shared program forced us to understand how the pieces fit together. Building SecureNotes showed us that secure coding is mostly a matter of awareness and habit, and CWE is a practical tool for building both.
