# Member 5 – Crypto & Information Exposure

> Draft — reword in your own terms before submitting.
>
> Categories checked on cwe.mitre.org (CWE-699 view), none banned:
> 312 → Information Management Errors (199) · 117 → Data Neutralization Issues (137), Audit / Logging Errors (1210) · 1240, 1204 → Cryptographic Issues (310) · 323 → Key Management Errors (320) · 497 → Information Management Errors (199).
> CWE-327, 326 and 321 (originally assigned) are not in the CWE-699 view, and CWE-209 is also a member of the banned Error Conditions category (389), so those four were replaced.

---

## CWE-312: Cleartext Storage of Sensitive Information

**Description:**
This weakness happens when a program saves private data, such as notes, personal details, or tokens, to a file or database exactly as it is, without encrypting it. Anyone who gets a copy of the file can read everything.

**Why is this important:**
Files get copied, backed up, synced, and stolen. If the data is stored in cleartext, any one of those leaks exposes it completely. Encryption at rest means a stolen file is useless without the key.

**In SecureNotes:** Every note is encrypted with AES-GCM before it touches the disk. Opening a `.note` file shows only random-looking bytes (`encrypt()`, `writeNote()`). This is part of the live demo.

---

## CWE-117: Improper Output Neutralization for Logs

**Description:**
This weakness happens when a program writes user input into a log file without cleaning it. If the input contains a newline, the attacker can start a new, fake line in the log, for example a username of `bob\nLOGIN ok user=admin`.

**Why is this important:**
Logs are what investigators trust after an incident. If attackers can forge or hide entries, they can cover their tracks or frame someone else. Injected content can also attack the tools used to view the logs.

**In SecureNotes:** Before anything is logged, carriage returns, newlines, and tabs are replaced with `_`, so each event is always exactly one line (`log()`).

---

## CWE-1240: Use of a Cryptographic Primitive with a Risky Implementation

**Description:**
This weakness happens when a program uses home-made encryption, an outdated algorithm like DES, or an unsafe mode like AES/ECB, instead of a well-tested library and a modern algorithm. Cryptography is very easy to get subtly wrong, and mistakes are invisible until someone breaks it.

**Why is this important:**
A weak or homemade cipher can look like it works while being trivial to crack. Many real breaches came from "custom" encryption or old algorithms left in place. Using standard, vetted primitives is the most important crypto rule.

**In SecureNotes:** The app uses only the JDK's built-in, well-tested algorithms: `AES/GCM/NoPadding` with a 256-bit key for notes, and `PBKDF2WithHmacSHA256` for keys and password hashes. There is no custom crypto code (`encrypt()`, `decrypt()`, `pbkdf2()`).

---

## CWE-1204: Generation of Weak Initialization Vector (IV)

**Description:**
An initialization vector (IV) is a random starting value mixed into encryption so that encrypting the same text twice gives different results. This weakness happens when the IV is fixed, predictable, or all zeros, which leaks patterns and in some modes lets attackers recover data.

**Why is this important:**
With a weak IV, an attacker can tell when two notes are identical, or even decrypt or forge messages. The WEP Wi-Fi protocol famously broke this way. A good IV costs nothing to generate.

**In SecureNotes:** Each time a note is encrypted, a new 12-byte IV is generated with `SecureRandom` and stored next to the ciphertext (`encrypt()`).

---

## CWE-323: Reusing a Nonce, Key Pair in Encryption

**Description:**
A nonce is a "number used once". Some encryption modes, including AES-GCM, require that the same nonce is never used twice with the same key. This weakness happens when a program reuses one, for example by hard-coding it or restarting a counter.

**Why is this important:**
With AES-GCM, reusing a nonce even once can let an attacker recover the plaintext of both messages and forge new ones that look valid. It is a catastrophic failure that comes from a tiny coding shortcut.

**In SecureNotes:** The GCM nonce (the IV above) is freshly random for every single encryption, so a nonce/key pair is never repeated (`encrypt()`).

---

## CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere

**Description:**
This weakness happens when a program shows users internal details about the system, such as stack traces, file paths, Java versions, or database names, usually in error messages. These details are meant for developers, not for the people using (or attacking) the program.

**Why is this important:**
System details give attackers a map: which software and versions to target, where files live, and how the code is structured. A friendly generic error gives them nothing, while the full details can still go to a private log for developers.

**In SecureNotes:** When anything goes wrong, the user sees only "Something went wrong. Please try again." The exception type is written to the admin-only audit log, and stack traces are never printed (`fail()`).
