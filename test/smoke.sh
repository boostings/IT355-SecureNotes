#!/usr/bin/env bash
# Smoke test for SecureNotes: replays the live-demo scenarios through stdin
# and checks each defense. Run from repo root: ./test/smoke.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
javac -d "$ROOT/out" "$ROOT/src/Main.java"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cd "$WORK"   # vault/ is created relative to the working directory

run() { printf '%s\n' "$@" | java -cp "$ROOT/out" Main 2>&1; }
pass=0; failn=0
check() { # name, haystack, needle, [expect-absent]
  if [[ "${4:-}" == "absent" ]]; then
    if grep -qF -- "$3" <<<"$2"; then echo "FAIL  $1"; failn=$((failn+1)); else echo "PASS  $1"; pass=$((pass+1)); fi
  else
    if grep -qF -- "$3" <<<"$2"; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; failn=$((failn+1)); fi
  fi
}

ADMIN_PW='AdminPass123'; USER_PW='BobPassword9'
LONG=$(printf 'x%.0s' {1..1001})

out=$(run 2 alice "$ADMIN_PW" "" 2 bob "$USER_PW" "" 2 carol weak "" 3)
check "first account becomes admin (CWE-798)"      "$out" "you are the admin"
check "weak password rejected (CWE-521)"           "$out" "Password too weak."

out=$(run 1 bob "$USER_PW" 1 secret1 "my hidden text" "" 2 secret1 "" 1 ../secret "" 1 big "$LONG" "" 5 "" 4 3)
check "note saved encrypted"                       "$out" "Note saved and encrypted."
check "note decrypts for owner"                    "$out" "my hidden text"
check "path traversal blocked (CWE-22)"            "$out" "Invalid title."
check "oversized note rejected (CWE-400)"          "$out" "Note too long."
check "non-admin denied audit log (CWE-862)"       "$out" "Access denied."
check "audit log option hidden for user"           "$out" "View audit log" absent

disk=$(cat vault/notes/bob/secret1.note)
check "note file is ciphertext (CWE-312/327)"      "$disk" "my hidden text" absent
check "users file has no plaintext pw (CWE-256)"   "$(cat vault/users.txt)" "$USER_PW" absent

out=$(run 1 bob x "" 1 bob x "" 1 bob x "" 1 bob "" 3)
check "lockout after 3 failures (CWE-307)"         "$out" "Too many failed attempts"

out=$(run 1 alice "$ADMIN_PW" 5 "" 4 3)
check "admin can view audit log"                   "$out" "AUDIT LOG"

log=$(cat vault/audit.log)
check "audit log has no passwords (CWE-532)"       "$log" "$USER_PW" absent
check "audit log has no note text (CWE-532)"       "$log" "my hidden text" absent
check "audit log records denial"                   "$log" "DENIED audit-log user=bob"

perm=$(stat -f '%Lp' vault/notes/bob/secret1.note 2>/dev/null || stat -c '%a' vault/notes/bob/secret1.note)
check "note file is owner-only 600 (CWE-276)"      "$perm" "600"

echo "---- $pass passed, $failn failed"
[[ $failn -eq 0 ]]
