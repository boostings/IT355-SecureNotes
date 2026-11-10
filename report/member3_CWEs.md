# Member 3 – Files

> Draft — reword in your own terms before submitting.
>
> Categories checked on cwe.mitre.org (CWE-699 view), none banned:
> 22, 59 → File Handling Issues (1219) · 367 → Concurrency Issues (557) · 276 → Permission Issues (275) · 639 → Authorization Errors (1212), Business Logic Errors (840) · 772 → Resource Management Errors (399).
> CWE-404 (originally assigned) is not in the CWE-699 view, so it was replaced with its close relative CWE-772.

---

## CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Description:**
This weakness happens when a program builds a file path from user input without making sure the result stays inside the folder it's meant to use. Special sequences like `../` mean "go up one folder", so an attacker who types `../../etc/passwd` as a file name can climb out of the intended folder and read or overwrite any file the program has access to.

**Why is this important:**
Path traversal can expose passwords, configuration files, source code, and other users' data. If the program also writes files, it can let an attacker overwrite critical files. It is one of the most common and most exploited web and file-handling bugs, and it regularly appears in the CWE Top 25.

**In SecureNotes:** Note titles may only contain letters, digits, `-` and `_`, so `../` is rejected outright. As a second check, the final normalized path must still start with the user's own notes folder (`notePath()`). Live demo: reading `../secret` shows "Invalid title."

---

## CWE-59: Improper Link Resolution Before File Access ('Link Following')

**Description:**
A symbolic link (symlink) is a file that points to another file. This weakness happens when a program opens a file by name without checking whether that name is really a symlink. An attacker who can create a link in the right spot can trick the program into reading or writing a completely different file, such as a system file or another user's data.

**Why is this important:**
Symlink attacks let an attacker borrow the program's permissions to touch files they could never reach themselves. They are especially dangerous in programs that run with higher privileges or write to shared folders. They have caused real privilege-escalation bugs in installers, backup tools, and system services.

**In SecureNotes:** Notes are read and written with `LinkOption.NOFOLLOW_LINKS`, so if a note file has been replaced by a symlink, the program refuses to follow it (`writeNote()`, `readNote()`).

---

## CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition

**Description:**
This weakness happens when a program checks something about a resource ("does this file exist?", "am I allowed to open it?") and then uses it a moment later, assuming nothing changed in between. In that tiny gap another process or thread can swap, create, or delete the file, so the program ends up acting on something it never checked.

**Why is this important:**
TOCTOU bugs are hard to spot in testing because they depend on timing, but attackers can trigger them reliably by retrying many times. They can lead to files being overwritten, permissions bypassed, or data from one user ending up in another's file.

**In SecureNotes:** Instead of "check if the note exists, then write it", the app uses `Files.createFile()`, which creates the file atomically and fails if it already exists. There is no gap between the check and the use (`writeNote()`).

---

## CWE-276: Incorrect Default Permissions

**Description:**
This weakness happens when a program creates files or folders with permissions that are too open, for example readable or writable by every user on the computer, instead of only by the owner. The program may work perfectly, but its data sits exposed to anyone who logs in to the same machine.

**Why is this important:**
Even if the data is protected inside the program, loose file permissions let other users or malware read or tamper with it directly on disk. Password files, logs, and private data are common targets. Fixing permissions after a breach is too late.

**In SecureNotes:** The vault folder, user file, audit log, and every note are set to owner-only permissions (`rwx------` for folders, `rw-------` for files) as soon as they are created (`restrict()`, `setup()`, `writeNote()`).

---

## CWE-639: Authorization Bypass Through User-Controlled Key

**Description:**
This weakness happens when a program decides which record to show based on an ID or name the user supplies, without checking that the record actually belongs to that user. Changing `?note=5` to `?note=6`, or typing another user's name, then shows someone else's data. This is often called an IDOR (Insecure Direct Object Reference).

**Why is this important:**
IDOR is one of the simplest ways attackers steal data: no special tools, just changing a number or a name. It has exposed medical records, bank statements, and private messages in real systems, and it falls under OWASP's top risk, Broken Access Control.

**In SecureNotes:** The user never tells the program whose notes to open. The owner's folder always comes from the logged-in session (`s.user.name()`), so there is no way to request another user's note (`notePath()`, `listNotes()`).

---

## CWE-772: Missing Release of Resource after Effective Lifetime

**Description:**
This weakness happens when a program opens a resource, such as a file, network connection, or database handle, and never closes it when it's finished, often because an error skipped the `close()` call. Each leaked resource stays open until the program ends.

**Why is this important:**
Operating systems only allow a limited number of open files and connections. A program that leaks them slowly runs out and starts failing, which an attacker can exploit to crash it on purpose (denial of service). Leaked file handles can also keep files locked or keep sensitive data reachable longer than needed.

**In SecureNotes:** Every file stream is opened with Java's try-with-resources (`try (InputStream is = ...)`), which guarantees the file is closed even if an exception is thrown (`readNote()`, `listNotes()`, `writeNote()`, `log()`).
