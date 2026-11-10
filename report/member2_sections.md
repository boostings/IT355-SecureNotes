# Member 2 – Introduction to CWE

> Draft — reword in your own terms before submitting. Facts checked on cwe.mitre.org (About page and entry pages) in November 2026.

---

## Introduction to CWE

The **Common Weakness Enumeration (CWE)** is a free, public list of the kinds of mistakes that lead to security vulnerabilities in software and hardware. It does not describe bugs in one specific product. Each entry instead describes a *type* of weakness, such as SQL injection, a hard-coded password, or a missing login check, that can appear in any program. Every weakness gets a permanent ID like **CWE-79** or **CWE-306**, so developers, testers, tools, and security teams can all refer to the same problem by the same name.

**Who maintains it.** CWE is managed by **The MITRE Corporation**, a U.S. not-for-profit organization, through the Homeland Security Systems Engineering and Development Institute (HSSEDI). It is sponsored by the **U.S. Department of Homeland Security's Cybersecurity and Infrastructure Security Agency (CISA)**. MITRE also runs the related CVE (Common Vulnerabilities and Exposures) and CAPEC (Common Attack Pattern Enumeration and Classification) programs. The CWE program has been running for about 20 years.

**How it is maintained.** CWE is community-developed. Researchers, tool vendors, universities, and companies suggest new weaknesses or improvements to existing ones. New content is drafted in a public content-development repository on GitHub and discussed in working groups and special interest groups. A CWE Board guides the program. MITRE reviews the submissions and publishes new versions of the list several times a year. Old entries are never reused. When an entry is unclear it is marked **deprecated** and points to better entries, so an ID always keeps its meaning. While researching our own CWEs we ran into this: CWE-613 (Insufficient Session Expiration) is now deprecated and replaced by newer, more specific session entries such as CWE-1463.

**How it is organized.** CWE entries come at different levels of detail:
- **Pillars and Classes:** very broad, like "Improper Access Control".
- **Bases:** specific enough to fix directly.
- **Variants:** tied to a particular language or technology.

The same entries can be browsed through different **views**. The **Software Development view (CWE-699)**, which this project uses, groups weaknesses into categories developers recognize, like *Authentication Errors*, *Random Number Issues*, or *User Session Errors*. Other views target hardware design or research.

**How it is used.** Developers use CWE as a checklist during design and code review. Static-analysis tools report their findings by CWE ID. Organizations use the yearly **CWE Top 25 Most Dangerous Software Weaknesses** to decide what to fix first. Because the list is free to use in research, education, and tools, CWE has become the common language that connects a coding mistake to the vulnerabilities, attacks, and fixes discussed later in this report.
