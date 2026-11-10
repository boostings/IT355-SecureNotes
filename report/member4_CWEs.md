# Member 4 – Resources & Concurrency

> Draft — reword in your own terms before submitting.
>
> Categories checked on cwe.mitre.org (CWE-699 view), none banned:
> 770, 1188 → Resource Management Errors (399) · 366, 820, 821 → Concurrency Issues (557) · 778 → Audit / Logging Errors (1210).
> Five originally assigned IDs (400, 362, 667, 226, 532) are not in the CWE-699 view, so they were replaced with the closest entries that are.

---

## CWE-770: Allocation of Resources Without Limits or Throttling

**Description:**
This weakness happens when a program lets a user consume memory, disk space, files, or other resources without any upper limit. If there's no cap on how big an upload can be or how many items one user can create, a single user can fill the disk or exhaust memory.

**Why is this important:**
Without limits, one careless or malicious user can make the system slow or unusable for everyone else. This is a denial-of-service attack, and it often needs no special skill, just a very large input or a loop. Limits are cheap to add and protect the whole system.

**In SecureNotes:** Notes are capped at 1,000 characters, each user can have at most 20 notes, and note files are read with a bounded `readNBytes(8192)` (`MAX_NOTE_CHARS`, `MAX_NOTES_PER_USER`, `writeNote()`, `readNote()`). Live demo: pasting a 1,001-character note shows "Note too long."

---

## CWE-366: Race Condition within a Thread

**Description:**
This weakness happens when two threads use the same variable at the same time without coordination. Even a simple statement like `count++` is really three steps (read, add, write), so two threads can both read the same old value and one update gets lost.

**Why is this important:**
Race conditions cause wrong totals, corrupted data, and security checks that pass when they shouldn't. They are hard to reproduce because they depend on timing, so they often slip through testing and show up only under real load.

**In SecureNotes:** The "notes saved" counter is an `AtomicInteger`, so `incrementAndGet()` happens as one indivisible step and no update can be lost (`notesSaved`).

---

## CWE-820: Missing Synchronization

**Description:**
This weakness happens when a resource shared between threads is used with no synchronization at all: no `synchronized`, no lock, no thread-safe class. Each thread assumes it has the resource to itself.

**Why is this important:**
Unsynchronized access can corrupt files and data structures, mix up records, or crash the program. In security code it can let one thread see half-finished data from another, for example a partly written log line or a partly updated user record.

**In SecureNotes:** The `log()` method is `synchronized`, so two threads can't interleave half-written lines in the audit log. Shared login state uses thread-safe `ConcurrentHashMap`s (`failures`, `lockedUntil`).

---

## CWE-821: Incorrect Synchronization

**Description:**
This weakness happens when a program does use synchronization but uses it wrongly: locking the wrong object, locking too little of the operation, or forgetting to unlock. A common Java mistake is calling `lock()` and then `unlock()` at the end of the method, so an exception in between leaves the lock held forever.

**Why is this important:**
Wrong synchronization gives a false sense of safety. Races still happen, or threads get stuck waiting for a lock that will never be released, which freezes the program (a deadlock or hang). These bugs are hard to diagnose after the fact.

**In SecureNotes:** The shared file lock covers the whole "is this the first user? then write the account" step, so two sign-ups can't both become admin. `unlock()` is always called in a `finally` block, so an error can never leave the lock held (`register()`, `writeNote()`).

---

## CWE-1188: Initialization of a Resource with an Insecure Default

**Description:**
This weakness happens when a program sets something up with a default that is convenient but unsafe, such as a default admin password, a debug mode left on, or files that anyone can read, and relies on the user to change it later. Most users never do.

**Why is this important:**
Insecure defaults are behind many large-scale attacks, from routers shipped with `admin/admin` to cloud storage buckets left public. Secure-by-default design means the system is safe even if nobody touches the settings.

**In SecureNotes:** On first run the app creates the vault folder, user file, and audit log with owner-only permissions immediately. There are no default accounts or passwords: the first person to register becomes the admin (`setup()`, `register()`).

---

## CWE-778: Insufficient Logging

**Description:**
This weakness happens when a program doesn't record security-relevant events, such as failed logins, permission denials, or errors, or records them without enough detail to understand what happened. When something goes wrong, there is no trail to follow.

**Why is this important:**
Without logs, attacks go unnoticed and can't be investigated afterwards. Many breaches are discovered months late, or never, because nobody recorded the warning signs. Good logs also help prove what did *not* happen. They must never contain secrets, though, or the log itself becomes a target.

**In SecureNotes:** Every security event is written to `vault/audit.log` with a timestamp: registrations, successful and failed logins, denied admin access, session expiry, logouts, and errors. Passwords and note contents are never logged, and only the admin can view the log (`log()`, `viewLog()`).
