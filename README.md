# SecureNotes

A small Java terminal app built for the **IT 355 "Research on CWE"** group project. You register, log in, and keep private notes that are encrypted on disk. An admin can view an audit log.

The app exists to show how to **avoid 30 weaknesses from MITRE's CWE list** (CWE-699 Software Development view). Every defense in the code has a comment naming the CWE it prevents, so you can search `src/Main.java` for `CWE-` to find them.

## Requirements

- **Java 17 or newer** (`java -version` to check)
- A real terminal (Terminal, iTerm, PowerShell, cmd), so your password is hidden while you type. IDE consoles work, but they show the password.

## How to run

From the repo root:

```bash
javac -d out src/Main.java
java -cp out Main
```

On first run the app creates a `vault/` folder next to where you ran it. Both `vault/` and `out/` are git-ignored.

## Using the app

1. **Register:** username of 3–16 letters, digits or `_`; password of 10+ characters with an uppercase letter, a lowercase letter and a digit. **The first account you create is the admin.**
2. **Log in:** after 3 wrong passwords the account is locked for 60 seconds.
3. **Notes menu:**
   - **Write note:** title of letters, digits, `-` or `_` (max 32); text up to 1000 characters; max 20 notes per user.
   - **Read note / List notes:** you can only see your own notes.
   - **Logout:** ends the session completely.
   - **View audit log:** admin only.

Sessions end after **2 minutes of inactivity** or **5 minutes in total**, and you'll be asked to log in again.

### Where data is stored

| File | Contents |
|---|---|
| `vault/users.txt` | `username:role:salt:hash`, never the password itself (PBKDF2-SHA256, 210,000 iterations) |
| `vault/notes/<user>/<title>.note` | the note encrypted with AES-256-GCM, using a key derived from that user's password |
| `vault/audit.log` | logins, logouts, saved notes, denied access; never passwords or note text |

On macOS/Linux these files are readable only by your user. To start over, delete the `vault/` folder.

## Demo script

These are the moments from the live presentation:

| Try this | You should see | CWE |
|---|---|---|
| Wrong password 3× | Account locked for a minute | 307 |
| Read a note titled `../secret` | "Invalid title." | 22 |
| Paste a 1000+ character note | "Note too long." | 400 |
| Open a `.note` file in `vault/notes/` | Encrypted gibberish | 312 / 327 |
| Log in as a normal user and type `5` | "Access denied." | 842 |
| Leave the "Text" prompt open for 2+ minutes | Session expired, note not saved | 1463 |
| Open `vault/audit.log` | No passwords or note contents | 532 |

## The 30 CWEs

| Member | Area | CWEs |
|---|---|---|
| 1 | Passwords & credentials | 798, 256, 549, 916, 521, 307 |
| 2 | Login & sessions | 306, 208, 338, 1463, 1465, 842 |
| 3 | Files | 22, 59, 367, 276, 639, 404 |
| 4 | Resources & concurrency | 400, 770, 362, 667, 226, 532 |
| 5 | Crypto & errors | 327, 326, 321, 312, 209, 117 |

## Repo layout

```
src/Main.java      the whole app (one file)
report/            each member's CWE write-ups and report sections (drafts)
GROUP_BRIEF.md     assignment requirements, who owns what, timeline, presentation plan
```

## Notes

- This is a teaching project, not a production password manager. If you forget your password, your notes can't be recovered, because the encryption key comes from the password.
- Data is stored in plain files in the folder you run it from, so run it from the same folder each time.
