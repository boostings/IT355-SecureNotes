# Member 2 – Login & Sessions

> Draft — reword in your own terms before submitting.
>
> **CWE swaps (checked on cwe.mitre.org, CWE-699 view, CWE 5.0):** five of the six assigned IDs are not usable, so they were replaced with the closest entry that *is* in CWE-699 and in no banned category:
>
> | Assigned | Problem | Replaced with | CWE-699 category |
> |---|---|---|---|
> | 287 Improper Authentication | Class-level entry, not in CWE-699 | **306** Missing Authentication for Critical Functionality | Authentication Errors (1211) |
> | 208 Observable Timing Discrepancy | OK, kept | **208** | Information Management Errors (199) |
> | 330 Use of Insufficiently Random Values | Not in CWE-699 | **338** Use of Cryptographically Weak PRNG | Random Number Issues (1213), Cryptographic Issues (310) |
> | 613 Insufficient Session Expiration | **Deprecated** by MITRE ("insufficiently clear") | **1463** Insufficient Session Timeout Value | User Session Errors (1217) |
> | 384 Session Fixation | Not in CWE-699 | **1465** Improper Session Invalidation after User Logout | User Session Errors (1217) |
> | 862 Missing Authorization | Not in CWE-699 (the obvious alternative, 425 Direct Request, is also under the banned Communication Channel Errors) | **842** Placement of User into Incorrect Group | Authorization Errors (1212) |

---

## CWE-306: Missing Authentication for Critical Functionality

**Description:**
This weakness happens when a program lets someone use an important feature without first proving who they are. Examples are an admin page anyone can open, a "delete account" action that never asks for a login, or an API endpoint that trusts every caller. The feature works fine. The problem is that nothing checks who is using it.

**Why is this important:**
Critical functions are exactly what attackers want: reading private data, changing settings, or acting as an admin. If one of them skips authentication, the attacker doesn't need to crack a password or find a bug. They just call the function directly. Many real breaches come from a forgotten "internal" endpoint that was never put behind a login.

**In SecureNotes:** Every note and admin function (`writeNote`, `readNote`, `listNotes`, `viewLog`) needs a `Session`. Its constructor is private, and only `login()` creates one, after the password hash matches. There is no way to reach the notes menu without logging in.

---

## CWE-208: Observable Timing Discrepancy

**Description:**
This weakness happens when a program takes a noticeably different amount of time depending on a secret. A common example is a login that returns instantly for an unknown username but takes longer for a real one, because it only hashes the password when the user exists. Another is comparing passwords or hashes byte by byte and stopping at the first difference. An attacker who measures response times can learn secrets the program never actually prints.

**Why is this important:**
Timing leaks turn a "yes/no" login into a source of extra information. An attacker can first find out which usernames exist and then focus a password-guessing attack on just those accounts. With enough measurements, early-exit comparisons can even leak a secret value piece by piece. These attacks are quiet: no error is shown and nothing looks wrong in the logs.

**In SecureNotes:** `login()` always runs the slow PBKDF2 hash, using a dummy salt when the username doesn't exist, so real and fake usernames take the same time. The hashes are compared with `MessageDigest.isEqual`, which takes the same time no matter where the bytes differ. Both cases show the same message: "Invalid username or password."

---

## CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

**Description:**
This weakness happens when a program uses an ordinary random number generator, such as Java's `java.util.Random` or `Math.random()`, for something that must be unpredictable, like session IDs, salts, encryption IVs, reset tokens, or keys. These generators are built for speed and statistics, not secrecy. Their output follows a formula, so after seeing a few values an attacker can predict the next ones.

**Why is this important:**
If a session ID or reset token can be predicted, an attacker can simply calculate a valid one and take over an account without knowing any password. Weak salts and IVs also weaken the encryption and hashing built on top of them. Switching to a cryptographically secure generator is a one-line fix, but if the weak one is used, everything that depends on it is weak too.

**In SecureNotes:** All randomness comes from one `SecureRandom` (`RNG`): the 32-byte session ID, each user's password salt, and the fresh AES-GCM IV for every note. `java.util.Random` is never used.

---

## CWE-1463: Insufficient Session Timeout Value

**Description:**
This weakness happens when a logged-in session lasts too long or never expires at all. MITRE describes two kinds of timeouts. An *inactivity* timeout ends the session after a period with no activity. An *absolute* timeout ends it after a fixed total time, even if the user stays active. A program that has neither, or sets them far too long, leaves sessions open indefinitely.

**Why is this important:**
Every extra minute a session stays valid is another minute for someone to misuse it. That someone might walk up to an unlocked computer in a lab, or might be an attacker who stole a session ID and keeps replaying it. Short timeouts limit the damage from both. MITRE suggests inactivity timeouts of about 2–5 minutes for high-value applications.

**In SecureNotes:** A session ends after 2 minutes of inactivity (`IDLE_TTL`) or 5 minutes in total (`SESSION_TTL`), whichever comes first. The check (`requireActive()`) runs after *every* prompt, not just at the menu. So if you start writing a note, walk away, and press Enter later, the note is not saved and you have to log in again.

---

## CWE-1465: Improper Session Invalidation after User Logout

**Description:**
This weakness happens when a program has a logout button, but logging out doesn't actually end the session on the server side. It may just hide the menu or delete the client's copy of the session ID, while the session itself stays valid. Anyone who still holds that session, or a copy of its ID, can keep using it.

**Why is this important:**
People log out precisely because they want their account closed, for example on a shared computer or when they're finished for the day. If the session lives on after logout, that sense of safety is false. An attacker who captured the session ID earlier can keep using it as if the user never left. MITRE's mitigation is to invalidate the session on the server and never rely on the client to throw it away.

**In SecureNotes:** Choosing **Logout**, or hitting a timeout, calls `Session.invalidate()`. That marks the session inactive and drops its note-encryption key, so the same session object can never be used again, even for admin checks (`isAdmin()` requires an active session). Each login creates a brand-new session with a new random ID.

---

## CWE-842: Placement of User into Incorrect Group

**Description:**
This weakness happens when a user is put into the wrong group or role, usually one with more privileges than they should have. It can come from a bug in sign-up logic, a role taken from user input, a default role that is too powerful, or a group name that the program doesn't recognize but trusts anyway. The user then gets whatever powers that group has.

**Why is this important:**
Most authorization checks are really group checks: "is this user an admin?" If the group is wrong, every later check gives the wrong answer, and a normal user quietly becomes an administrator. Correct group placement is the foundation that the rest of access control is built on.

**In SecureNotes:** Users never choose their own group. Only two groups exist (`ROLE_ADMIN`, `ROLE_USER`). The first account becomes admin and everyone after that becomes a normal user. The "is this the first account?" check and the write to `users.txt` happen under the same lock, so two sign-ups at once can't both become admin. A line in `users.txt` with any other group, such as one edited to `superuser`, is ignored. `viewLog()` checks the admin group *inside* the function, so a normal user who types the hidden option **5** is still refused and the attempt is logged.
