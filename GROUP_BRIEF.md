# IT 355 – Research on CWE: Group Brief & Plan

## What we have to turn in
1. **Report** (.docx or PDF, using the "Research on CWEV2" template) – ONE person submits it. It must include our **GitHub link**.
2. **Java program** on GitHub – one program that shows how to avoid all our CWEs.
3. **Presentation** (50 pts) with a live demo.
4. **Peer evaluation** – EVERY one of us submits our own. Peer scores decide how much of the grade you keep (average 10–12 = 100%, below 6 = 0%). So: do your part early and post updates.

## Points (report = 150)
| Section | Pts |
|---|---|
| Introduction to CWE (what it is, MITRE maintains it, how) | 5 |
| Structure of a CWE (walk through one entry, e.g. CWE-416) | 15 |
| Explain our CWEs (6 each = 30 total) | 20 |
| **Java program** | **80** |
| Consistent formatting / proofread | 10 |
| Vulnerability ecosystem (CWE ↔ CVE ↔ NVD ↔ CAPEC) | 20 |
| Conclusion | – |

Each CWE is written as:
**CWE-XXX: Name** → *Description* (in our own words) → *Why is this important*

## The program: SecureNotes (already built)
A simple terminal (TUI) app. You register, log in, and write/read private notes that are encrypted on disk. The admin can view an audit log. One file: `src/Main.java`. Every defense is commented with its CWE (search for "CWE-").

Run it:
```
javac -d out src/Main.java
java -cp out Main
```
(Java 17+. Run in a real terminal so the password is hidden.)

Test all the demo scenarios automatically: `./test/smoke.sh`

## Who owns what (6 CWEs each)
| Member | Area | CWEs |
|---|---|---|
| **1** | Passwords & credentials | 798 Hard-coded Credentials · 256 Plaintext Password Storage · 549 Missing Password Masking · 916 Weak Password Hash · 521 Weak Password Requirements · 307 Brute Force |
| **2** | Login & sessions | 306 Missing Authentication · 208 Timing Discrepancy · 338 Weak PRNG · 1463 Session Timeout · 1465 Session Invalidation after Logout · 842 User in Incorrect Group *(287/330/384/862 aren't in CWE-699 and 613 is deprecated; see `report/member2_CWEs.md`)* |
| **3** | Files | 22 Path Traversal · 59 Link Following · 367 TOCTOU Race · 276 Bad Default Permissions · 639 User-Controlled Key (IDOR) · 404 Resource Not Closed |
| **4** | Resources & concurrency | 400 Uncontrolled Resource Use · 770 Allocation Without Limits · 362 Race Condition · 667 Improper Locking · 226 Sensitive Data Not Cleared · 532 Secrets in Logs |
| **5** | Crypto & errors | 327 Broken Crypto · 326 Weak Key Strength · 321 Hard-coded Crypto Key · 312 Cleartext Storage · 209 Info in Error Messages · 117 Log Injection |

**First thing everyone does:** open your 6 CWEs on cwe.mitre.org and check they're in the CWE-699 view and NOT in the banned categories (Type Errors, Bad Coding Practices, Numeric, Behavioral, UI Security, Communication Channel, Error Conditions, Expression, Data Validation, Documentation). If one is banned, post in chat and swap it.

## Each member's tasks
- Write your 6 CWE entries (own words – Description + Why it's important).
- Find where your CWEs are handled in `Main.java` and be able to explain the code.
- Make 2–3 slides for your area + one demo moment.

Shared sections (one owner each):
| Section | Owner |
|---|---|
| Abstract (≤200 words) + Conclusion | Member 1 |
| Introduction to CWE | Member 2 |
| Structure of CWE (CWE-416 walkthrough) | Member 3 |
| Vulnerability Ecosystem (CVE/NVD/CAPEC) | Member 4 |
| GitHub repo + final formatting + submit | Member 5 |

## Timeline
| When | Task |
|---|---|
| Day 1 | Confirm CWEs (no banned categories). Everyone runs the app. |
| Day 3 | CWE write-ups + shared sections drafted in the shared doc. |
| Day 4 | Everyone reviews someone else's section. Slides drafted. |
| Day 5 | Final formatting, remove template's highlighted text, rehearse presentation. |
| Due date | Submit report + everyone submits peer eval. |

## Presentation plan (50 pts)
1. Intro: team, agenda, goal, why CWE matters (Member 1)
2. What CWE is + structure (Members 2 & 3)
3. Ecosystem: CWE/CVE/NVD/CAPEC (Member 4)
4. **Live demo** (Member 5 drives, each member explains their part):
   - Wrong password 3× → account locked (CWE-307)
   - Read note `../secret` → blocked (CWE-22)
   - Paste a 1000+ char note → rejected (CWE-400)
   - Open the note file on disk → it's encrypted gibberish (CWE-312/327)
   - Normal user types the hidden option 5 → "Access denied" (CWE-842)
   - Leave the "Text" prompt open for 2+ minutes → session expired, note not saved (CWE-1463)
   - Show audit log has no passwords (CWE-532)
5. Conclusion + what we learned working together (Member 1)

Stay inside the time limit and keep the handoffs between speakers smooth.

## Report formatting rules
- One font and size everywhere, same heading styles.
- Delete ALL the template's highlighted and italic instructions.
- Put the GitHub link near the top.
- Proofread before submitting.
