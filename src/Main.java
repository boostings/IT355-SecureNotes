import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * SecureNotes - a tiny terminal (TUI) notes app for IT 355.
 * Users register, log in, and write/read private encrypted notes.
 * Every defensive line is tagged with the CWE it avoids: search for "CWE-".
 */
public class Main {

    static final Path VAULT = Paths.get("vault");
    static final Path USERS = VAULT.resolve("users.txt");
    static final Path NOTES = VAULT.resolve("notes");
    static final Path LOG   = VAULT.resolve("audit.log");

    static final int MAX_NOTE_CHARS = 1000;          // CWE-400: cap input size
    static final int MAX_NOTES_PER_USER = 20;        // CWE-770: cap allocations per user
    static final int MAX_TRIES = 3;                  // CWE-307: brute-force limit
    static final int PBKDF2_ITERATIONS = 210_000;    // CWE-916: slow, strong hash
    static final Duration LOCKOUT = Duration.ofSeconds(60);
    static final Duration SESSION_TTL = Duration.ofMinutes(5);  // CWE-1463: absolute session lifetime
    static final Duration IDLE_TTL = Duration.ofMinutes(2);     // CWE-1463: inactivity timeout

    static final String ROLE_ADMIN = "admin";                    // CWE-842: the only two groups that exist
    static final String ROLE_USER = "user";

    static final SecureRandom RNG = new SecureRandom();          // CWE-338: cryptographically strong PRNG, not java.util.Random
    static final Map<String, Integer> failures = new ConcurrentHashMap<>();
    static final Map<String, Instant> lockedUntil = new ConcurrentHashMap<>();
    static final AtomicInteger notesSaved = new AtomicInteger(); // CWE-362: atomic counter
    static final ReentrantLock fileLock = new ReentrantLock();
    static final Scanner in = new Scanner(System.in);

    record User(String name, String role, byte[] salt, byte[] hash) {}

    /**
     * A logged-in session. CWE-306: only login() creates one, after the password is verified, and every
     * note/audit function requires one, so no critical function can run without authentication.
     */
    static class Session {
        final String id;
        final User user;
        SecretKey key;
        final Instant started = Instant.now();
        Instant lastActive = started;
        boolean active = true;

        private Session(User user, SecretKey key) {
            byte[] raw = new byte[32];
            RNG.nextBytes(raw);                    // CWE-338: unpredictable session ID from SecureRandom, new on every login
            this.id = HexFormat.of().formatHex(raw);
            this.user = user;
            this.key = key;
        }
        // CWE-1463: the session ends after SESSION_TTL in total OR after IDLE_TTL with no activity
        boolean expired() {
            Instant now = Instant.now();
            return now.isAfter(started.plus(SESSION_TTL)) || now.isAfter(lastActive.plus(IDLE_TTL));
        }
        void touch() { lastActive = Instant.now(); }
        // CWE-1465: logout/expiry really ends the session: it can't be reused and the note key is dropped
        void invalidate() { active = false; key = null; }
        boolean isAdmin() { return active && ROLE_ADMIN.equals(user.role()); }
    }

    /**
     * CWE-1463/1465: checked after every prompt, not just at the menu, so an action started before the
     * timeout can't finish after it (e.g. sitting at the "Text" prompt for an hour, then saving).
     */
    static boolean requireActive(Session s) {
        if (s.active && !s.expired()) { s.touch(); return true; }
        if (s.active) log("SESSION expired user=" + s.user.name() + " id=" + s.id.substring(0, 8));
        s.invalidate();
        pause("Session expired. Please log in again.");
        return false;
    }

    // ───────────────────────────── main loop ─────────────────────────────

    public static void main(String[] args) {
        try {
            setup();
            while (true) {
                screen("SECURE NOTES", "1) Login", "2) Register", "3) Quit");
                switch (prompt("Choose")) {
                    case "1" -> { Session s = login(); if (s != null) menu(s); }
                    case "2" -> register();
                    case "3" -> { System.out.println("  Goodbye!"); return; }
                    default  -> pause("Invalid choice.");
                }
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    static void menu(Session s) {
        while (true) {
            List<String> opts = new ArrayList<>(List.of(
                    "1) Write note", "2) Read note", "3) List notes", "4) Logout"));
            if (s.isAdmin()) opts.add("5) View audit log (admin)");
            opts.add("");
            opts.add("Notes saved this run: " + notesSaved.get());
            screen("NOTES - " + s.user.name(), opts.toArray(String[]::new));
            String choice = prompt("Choose");

            if (!requireActive(s)) return;                          // CWE-1463
            try {
                switch (choice) {
                    case "1" -> writeNote(s);
                    case "2" -> readNote(s);
                    case "3" -> listNotes(s);
                    case "4" -> {
                        log("LOGOUT user=" + s.user.name());
                        s.invalidate();                             // CWE-1465: end the session on logout
                        return;
                    }
                    case "5" -> viewLog(s);
                    default  -> pause("Invalid choice.");
                }
            } catch (Exception e) {
                fail(e);
            }
            if (!s.active) return;                                  // expired during the action
        }
    }

    // ───────────────────────────── accounts ─────────────────────────────

    // CWE-798: there are NO hard-coded usernames/passwords. The first account registered becomes admin.
    static void register() throws Exception {
        screen("REGISTER",
                "Username: 3-16 letters, digits or _",
                "Password: 10+ chars, upper, lower and digit");
        String name = prompt("Username");
        if (!name.matches("[A-Za-z0-9_]{3,16}")) { pause("Invalid username."); return; }
        if (findUser(name) != null) { pause("That username is taken."); return; }

        char[] pw = readPassword("Password");
        try {
            if (!isStrong(pw)) { pause("Password too weak."); return; }   // CWE-521

            byte[] salt = new byte[16];
            RNG.nextBytes(salt);                                          // CWE-916: unique random salt per user (defeats rainbow tables)
            byte[] hash = pbkdf2(pw, salt);                               // CWE-256/916: store only a strong hash
            String role = null;

            fileLock.lock();                                              // CWE-667: lock ...
            try {
                // CWE-842: the group is decided by the program, never typed by the user. Checking "is this
                // the first account?" and writing it happen under one lock, so two sign-ups can't both
                // be placed in the admin group; everyone after the first goes into "user".
                if (findUser(name) == null) {
                    role = readUsers().isEmpty() ? ROLE_ADMIN : ROLE_USER;
                    String line = name + ":" + role + ":" + b64(salt) + ":" + b64(hash) + System.lineSeparator();
                    Files.writeString(USERS, line, StandardOpenOption.APPEND);
                }
            } finally {
                fileLock.unlock();                                        // ... always released in finally
            }
            if (role == null) { pause("That username is taken."); return; }
            secureDir(NOTES.resolve(name));
            log("REGISTER user=" + name + " role=" + role);               // CWE-532: never log the password
            pause("Account created" + (role.equals(ROLE_ADMIN) ? " (you are the admin)." : "."));
        } finally {
            Arrays.fill(pw, '\0');                                        // CWE-226: wipe password from memory
        }
    }

    static Session login() throws Exception {
        screen("LOGIN");
        String name = prompt("Username");

        Instant until = lockedUntil.get(name);
        if (until != null && Instant.now().isBefore(until)) {            // CWE-307
            pause("Too many failed attempts. Try again in a minute.");
            return null;
        }

        char[] pw = readPassword("Password");
        try {
            User u = findUser(name);
            // CWE-208: always run the hash, even for unknown users, so timing doesn't reveal which names exist
            byte[] salt = (u != null) ? u.salt() : new byte[16];
            byte[] attempt = pbkdf2(pw, salt);

            // CWE-306: a Session (needed for every note/admin function) is only created after this check passes.
            // MessageDigest.isEqual compares in constant time, so timing doesn't leak how close a guess was (CWE-208)
            if (u != null && MessageDigest.isEqual(attempt, u.hash())) {
                failures.remove(name);
                lockedUntil.remove(name);
                log("LOGIN ok user=" + name);
                return new Session(u, deriveNoteKey(pw, u.salt()));
            }

            int n = failures.merge(name, 1, Integer::sum);
            if (n >= MAX_TRIES) {
                lockedUntil.put(name, Instant.now().plus(LOCKOUT));
                failures.remove(name);
            }
            log("LOGIN failed user=" + name);
            pause("Invalid username or password.");   // same message either way: no username hints
            return null;
        } finally {
            Arrays.fill(pw, '\0');                     // CWE-226
        }
    }

    static boolean isStrong(char[] pw) {
        boolean up = false, low = false, dig = false;
        for (char c : pw) {
            if (Character.isUpperCase(c)) up = true;
            else if (Character.isLowerCase(c)) low = true;
            else if (Character.isDigit(c)) dig = true;
        }
        return pw.length >= 10 && up && low && dig;
    }

    // ───────────────────────────── notes ─────────────────────────────

    static void writeNote(Session s) throws Exception {
        screen("WRITE NOTE", "Title: letters, digits, - or _ (max 32)", "Text: max " + MAX_NOTE_CHARS + " characters");
        Path p = notePath(s, prompt("Title"));
        if (p == null) { pause("Invalid title."); return; }

        String body = prompt("Text");
        if (!requireActive(s)) return;                                             // CWE-1463: still logged in?
        if (body.length() > MAX_NOTE_CHARS) { pause("Note too long."); return; }   // CWE-400

        long count;
        try (var files = Files.list(p.getParent())) { count = files.count(); }     // CWE-404: stream closed
        if (count >= MAX_NOTES_PER_USER) { pause("Note limit reached."); return; } // CWE-770

        byte[] data = encrypt(s.key, body);                                        // CWE-312: never stored as plaintext

        fileLock.lock();                                                           // CWE-667
        try {
            // CWE-367: createFile is atomic, no "check if exists, then write" gap
            Files.createFile(p);
            restrict(p, false);                                                    // CWE-276: owner-only permissions
            Files.write(p, data, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS); // CWE-59
        } catch (FileAlreadyExistsException e) {
            pause("A note with that title already exists.");
            return;
        } finally {
            fileLock.unlock();
        }
        notesSaved.incrementAndGet();                                              // CWE-362
        log("NOTE saved user=" + s.user.name() + " title=" + p.getFileName());     // CWE-532: no note contents
        pause("Note saved and encrypted.");
    }

    static void readNote(Session s) throws Exception {
        screen("READ NOTE");
        Path p = notePath(s, prompt("Title"));
        if (!requireActive(s)) return;                                             // CWE-1463
        if (p == null) { pause("Invalid title."); return; }

        byte[] data;
        // CWE-404: try-with-resources closes the file; CWE-59: refuse to follow symlinks
        try (InputStream is = Files.newInputStream(p, LinkOption.NOFOLLOW_LINKS)) {
            data = is.readNBytes(8192);                                            // CWE-400: bounded read
        } catch (NoSuchFileException e) {
            pause("No note with that title.");
            return;
        }
        String text = decrypt(s.key, data);
        screen("NOTE: " + p.getFileName().toString().replace(".note", ""), wrap(text, 46));
        pause("");
    }

    static void listNotes(Session s) throws IOException {
        List<String> names = new ArrayList<>();
        try (var files = Files.list(NOTES.resolve(s.user.name()))) {              // CWE-404
            files.forEach(f -> names.add(" - " + f.getFileName().toString().replace(".note", "")));
        }
        if (names.isEmpty()) names.add("(no notes yet)");
        screen("YOUR NOTES", names.toArray(String[]::new));
        pause("");
    }

    /**
     * Builds the path for a note. The owner always comes from the logged-in session, never from
     * user input (CWE-639), and the title can't escape the user's folder (CWE-22).
     */
    static Path notePath(Session s, String title) {
        if (!title.matches("[A-Za-z0-9_-]{1,32}")) return null;                    // CWE-22: no "../" or "/"
        Path dir = NOTES.resolve(s.user.name()).toAbsolutePath().normalize();      // CWE-639
        Path p = dir.resolve(title + ".note").normalize();
        return p.startsWith(dir) ? p : null;                                       // CWE-22: belt and braces
    }

    static void viewLog(Session s) throws IOException {
        // CWE-842: the admin group is checked here, inside the function, not just by hiding the menu option,
        // so a "user" who types 5 anyway is still refused.
        if (!s.isAdmin()) {
            log("DENIED audit-log user=" + s.user.name());
            pause("Access denied.");
            return;
        }
        List<String> lines = Files.readAllLines(LOG);
        List<String> last = lines.subList(Math.max(0, lines.size() - 15), lines.size());
        screen("AUDIT LOG (last 15)", last.stream().map(l -> l.length() > 46 ? l.substring(20) : l).toArray(String[]::new));
        pause("");
    }

    // ───────────────────────────── crypto ─────────────────────────────

    static byte[] pbkdf2(char[] pw, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(pw, salt, PBKDF2_ITERATIONS, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();                                                  // CWE-226
        }
    }

    // CWE-321: the encryption key is derived from the user's password, never hard-coded in the source.
    // CWE-326: 256-bit AES key.
    static SecretKey deriveNoteKey(char[] pw, byte[] salt) throws GeneralSecurityException {
        byte[] keySalt = Arrays.copyOf(salt, salt.length + 4);
        System.arraycopy("note".getBytes(StandardCharsets.UTF_8), 0, keySalt, salt.length, 4);
        return new SecretKeySpec(pbkdf2(pw, keySalt), "AES");
    }

    // CWE-327: AES-GCM (modern, authenticated) instead of DES or AES/ECB.
    static byte[] encrypt(SecretKey key, String text) throws GeneralSecurityException {
        byte[] iv = new byte[12];
        RNG.nextBytes(iv);                                                         // CWE-338: fresh IV from SecureRandom
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(text.getBytes(StandardCharsets.UTF_8));
        byte[] out = Arrays.copyOf(iv, iv.length + ct.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return out;
    }

    static String decrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, data, 0, 12));
        return new String(c.doFinal(data, 12, data.length - 12), StandardCharsets.UTF_8);
    }

    // ───────────────────────────── storage & logging ─────────────────────────────

    static void setup() throws IOException {
        secureDir(VAULT);
        secureDir(NOTES);
        for (Path f : List.of(USERS, LOG)) {
            if (!Files.exists(f)) { Files.createFile(f); restrict(f, false); }     // CWE-276
        }
    }

    static List<User> readUsers() throws IOException {
        List<User> users = new ArrayList<>();
        for (String line : Files.readAllLines(USERS)) {
            String[] p = line.split(":");
            // CWE-842: a line with an unknown group (e.g. edited to "superuser") is ignored, not trusted
            if (p.length == 4 && (p[1].equals(ROLE_ADMIN) || p[1].equals(ROLE_USER)))
                users.add(new User(p[0], p[1], Base64.getDecoder().decode(p[2]), Base64.getDecoder().decode(p[3])));
        }
        return users;
    }

    static User findUser(String name) throws IOException {
        for (User u : readUsers()) if (u.name().equals(name)) return u;
        return null;
    }

    static void secureDir(Path p) throws IOException {
        Files.createDirectories(p);
        restrict(p, true);
    }

    // CWE-276: only the owner can read/write the vault (on macOS/Linux).
    static void restrict(Path p, boolean dir) {
        try {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(dir ? "rwx------" : "rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows has no POSIX permissions; the folder inherits the user's profile ACLs.
        }
    }

    // CWE-117: strip newlines so a username like "bob\nLOGIN ok user=admin" can't forge log lines.
    // CWE-532: callers only ever pass usernames/titles, never passwords, keys or note text.
    static synchronized void log(String msg) {
        String clean = msg.replaceAll("[\\r\\n\\t]", "_");
        try (BufferedWriter w = Files.newBufferedWriter(LOG, StandardOpenOption.CREATE, StandardOpenOption.APPEND)) { // CWE-404
            w.write(Instant.now() + " " + clean);
            w.newLine();
        } catch (IOException ignored) {
        }
    }

    // CWE-209: the user sees a generic message; only the exception type goes in the private log.
    static void fail(Exception e) {
        log("ERROR " + e.getClass().getSimpleName());
        pause("Something went wrong. Please try again.");
    }

    // ───────────────────────────── TUI helpers ─────────────────────────────

    static final int WIDTH = 48;

    static void screen(String title, String... lines) {
        System.out.print("\033[H\033[2J");
        System.out.flush();
        String bar = "═".repeat(WIDTH);
        System.out.println("╔" + bar + "╗");
        System.out.println("║ " + pad(title, WIDTH - 1) + "║");
        System.out.println("╠" + bar + "╣");
        for (String l : lines) System.out.println("║ " + pad(l, WIDTH - 1) + "║");
        System.out.println("╚" + bar + "╝");
    }

    static String pad(String s, int n) {
        if (s.length() > n) s = s.substring(0, n);
        return s + " ".repeat(n - s.length());
    }

    static String[] wrap(String text, int n) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < text.length(); i += n) out.add(text.substring(i, Math.min(text.length(), i + n)));
        if (out.isEmpty()) out.add("(empty)");
        return out.toArray(String[]::new);
    }

    static String prompt(String label) {
        System.out.print("  > " + label + ": ");
        if (!in.hasNextLine()) System.exit(0);
        return in.nextLine().trim();
    }

    static char[] readPassword(String label) {
        Console c = System.console();
        if (c != null) return c.readPassword("  > %s: ", label);   // CWE-549: password is masked while typing
        System.out.print("  > " + label + ": ");                   // fallback for IDE consoles
        if (!in.hasNextLine()) System.exit(0);
        return in.nextLine().toCharArray();
    }

    static void pause(String msg) {
        if (!msg.isEmpty()) System.out.println("  " + msg);
        System.out.print("  (press Enter)");
        if (in.hasNextLine()) in.nextLine();
    }

    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
}
