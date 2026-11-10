# Member 1 – Passwords & Credentials

> Draft — reword in your own terms before submitting.
>
> Categories verified on cwe.mitre.org (CWE-699 view), none banned:
> 798 → Credentials Management Errors (255), Key Management Errors (320) · 256, 521, 549 → Credentials Management Errors (255) · 916 → Credentials Management Errors (255), Cryptographic Issues (310) · 307 → Authentication Errors (1211)

---

## CWE-798: Use of Hard-coded Credentials

**Description:**
This weakness happens when a program has a username, password, or key typed directly into its source code, for example `if (password.equals("admin123"))`. Every copy of the program then shares the same secret, and anyone who can read the code or decompile the `.class`/`.jar` file can find it. Java bytecode is easy to decompile, so the secret is never truly hidden. The password also can't be changed without rebuilding and redistributing the whole program.

**Why is this important:**
A hard-coded password works like a master key that can never be changed. Once one person finds it, every installation is open to them. Attackers regularly scan public GitHub repos and firmware images for exactly these strings, and many real breaches of routers and IoT devices began with a hard-coded admin account.

**In SecureNotes:** The source contains no usernames or passwords. Accounts are created at runtime through **Register**, and the first account becomes the admin (`register()`).

---

## CWE-256: Plaintext Storage of a Password

**Description:**
This weakness happens when a program saves users' passwords exactly as they were typed, in a file, database, or config file. Anyone who gets read access to that storage (a hacker, a backup tape, a curious employee) can see every password immediately.

**Why is this important:**
Stolen password databases are among the most common results of a breach. Because people reuse passwords, one plaintext leak hands attackers the keys to victims' email, banking, and work accounts too. Storing passwords in plaintext turns a small breach into a disaster that reaches far beyond your own system.

**In SecureNotes:** `users.txt` stores only a salt and a PBKDF2 hash, never the password itself (`register()`, `pbkdf2()`).

---

## CWE-549: Missing Password Field Masking

**Description:**
This weakness happens when a program shows the password on screen as the user types it, instead of hiding it with dots, asterisks, or nothing at all. Anyone looking at the screen, sitting behind the user, or watching a screen share or recording can read it.

**Why is this important:**
"Shoulder surfing" needs no hacking skill at all, so it's one of the easiest ways to steal a password. It is a real risk in labs, offices, coffee shops, and during presentations. Hiding the typed characters is a small, cheap step that closes this hole.

**In SecureNotes:** Passwords are read with `System.console().readPassword()`, which hides the characters as they're typed (`readPassword()`). The password is returned as a `char[]` that gets wiped after use, rather than a `String`.

---

## CWE-916: Use of Password Hash With Insufficient Computational Effort

**Description:**
This weakness happens when passwords are hashed with a fast algorithm such as MD5 or plain SHA-256. These were designed to be fast, so a modern graphics card can try billions of guesses per second. Password hashing should be deliberately slow, using algorithms like PBKDF2, bcrypt, scrypt, or Argon2 that repeat the work many thousands of times.

**Why is this important:**
If the password file is ever stolen, the hashing algorithm is the only thing standing between the attacker and the real passwords. A slow hash turns days of cracking into centuries. It costs the real user only a fraction of a second at login.

**In SecureNotes:** Passwords are hashed with `PBKDF2WithHmacSHA256` at 210,000 iterations (`pbkdf2()`, `PBKDF2_ITERATIONS`).

---

## CWE-521: Weak Password Requirements

**Description:**
This weakness happens when a system lets users choose passwords that are too short or too simple, such as "1234" or "password". Without minimum rules, many users will pick something easy to guess.

**Why is this important:**
Even perfect hashing and lockouts can't protect a password that sits at the top of every attacker's guess list. Weak password rules make account takeover through guessing, credential stuffing, or offline cracking easy. Basic requirements raise the bar for every account in the system.

**In SecureNotes:** Registration requires at least 10 characters with an uppercase letter, a lowercase letter, and a digit (`isStrong()`).

---

## CWE-307: Improper Restriction of Excessive Authentication Attempts

**Description:**
This weakness happens when a login screen lets someone try passwords forever with no limit or delay. An attacker, or an automated script, can then keep guessing until one works. This is called a brute-force attack.

**Why is this important:**
Without a limit, any password can eventually be guessed, and automated tools can try thousands per minute. Limiting attempts, adding delays, or locking accounts turns an attack that is sure to succeed eventually into one that is impractical.

**In SecureNotes:** After 3 wrong passwords the account is locked for 60 seconds (`login()`, `MAX_TRIES`, `LOCKOUT`). This is the first step of the live demo.
