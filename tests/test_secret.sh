#!/usr/bin/env bash
#
# tests/test_secret.sh — runs against a throwaway keychain; the login keychain is never
# touched, and no --ask item is ever read (that would raise a dialog).
#
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHELL_BIN="${BASH:-bash}"; [[ ${1:-} == --bash32 ]] && SHELL_BIN=/bin/bash
PASS=0 FAIL=0
ok()    { printf '  ✓ %s\n' "$1"; PASS=$((PASS+1)); }
no()    { printf '  ✗ %s\n' "$1"; [[ -n ${2:-} ]] && printf '      %s\n' "$2"; FAIL=$((FAIL+1)); }
check() { if [[ $2 == "$3" ]]; then ok "$1"; else no "$1" "expected [$3], got [$2]"; fi; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/secret-test.XXXXXX")"
export SECRET_KEYCHAIN="$WORK/test.keychain-db" SECRET_STATE="$WORK/state"
security create-keychain -p test "$SECRET_KEYCHAIN" || exit 2
security unlock-keychain -p test "$SECRET_KEYCHAIN"
security set-keychain-settings "$SECRET_KEYCHAIN"          # no auto-lock mid-test
trap 'security delete-keychain "$SECRET_KEYCHAIN" 2>/dev/null; rm -rf "$WORK"' EXIT
sec() { "$SHELL_BIN" "$ROOT/secret" "$@"; }

printf 'secret test suite — %s\n\n' "$("$SHELL_BIN" --version | head -1)"

printf 'tok-123' | sec set API_TOKEN --stdin --desc "an api token" 2>/dev/null
check "set --stdin stores a value" "$(sec get API_TOKEN 2>/dev/null)" "tok-123"
weird='he said "hi" \ and $HOME & `x` '"'"'q'"'"''
printf '%s' "$weird" | sec set WEIRD --stdin 2>/dev/null
check "quotes, backslashes and \$ survive" "$(sec get WEIRD 2>/dev/null)" "$weird"
printf 'v2' | sec set API_TOKEN --stdin --desc "rotated" 2>/dev/null
check "set replaces an existing value" "$(sec get API_TOKEN 2>/dev/null)" "v2"

out="$(sec list 2>&1)"
grep -q 'API_TOKEN' <<<"$out" && ok "list shows names" || no "list shows names" "$out"
grep -q 'rotated' <<<"$out" && ok "list shows descriptions" || no "list shows descriptions" "$out"
grep -q 'v2' <<<"$out" && no "list never shows values" || ok "list never shows values"
check "list --json" "$(sec list --json | jq -r '.[] | select(.name=="API_TOKEN") | .desc')" "rotated"
changed="$(sec list --json | jq -r '.[] | select(.name=="API_TOKEN") | .changed')"
[[ $changed =~ ^[0-9]{14}Z$ ]] && ok "list --json says when each changed" || no "list --json says when each changed" "$changed"
sleep 1; printf 'v3' | sec set API_TOKEN --stdin --desc "rotated" 2>/dev/null
[[ "$(sec list --json | jq -r '.[] | select(.name=="API_TOKEN") | .changed')" != "$changed" ]] \
    && ok "and a new value moves it" || no "and a new value moves it"
printf 'v2' | sec set API_TOKEN --stdin --desc "rotated" 2>/dev/null

sec set ACCOUNT_ID --plain acct-123 --desc "an account id" 2>/dev/null
check "--plain stores a value that is not a secret" "$(sec get ACCOUNT_ID 2>/dev/null)" "acct-123"
check "list --json shows a plain value" "$(sec list --json | jq -r '.[] | select(.name=="ACCOUNT_ID") | .value')" "acct-123"
check "and marks it plain" "$(sec list --json | jq -r '.[] | select(.name=="ACCOUNT_ID") | .plain')" "true"
check "but never a secret's value" "$(sec list --json | jq -r '.[] | select(.name=="API_TOKEN") | has("value")')" "false"
grep -q 'acct-123' <<<"$(sec list)" && ok "list shows it too" || no "list shows it too"
sec set BOTH --plain x --ask >/dev/null 2>&1 && no "--plain and --ask are refused together" || ok "--plain and --ask are refused together"
sec set EMPTY --plain >/dev/null 2>&1 && no "--plain wants a value" || ok "--plain wants a value"
sec rm ACCOUNT_ID >/dev/null 2>&1

check "run puts the secret in the command's environment" \
    "$(sec run API_TOKEN -- sh -c 'printf %s "$API_TOKEN"')" "v2"
check "run VAR=NAME renames it" "$(sec run TOKEN=API_TOKEN -- sh -c 'printf %s "$TOKEN"')" "v2"
check "run takes several" "$(sec run API_TOKEN WEIRD -- sh -c 'printf %s "${#API_TOKEN}"')" "2"
check "run passes the exit status through" "$(sec run API_TOKEN -- sh -c 'exit 4'; echo $?)" "4"
out="$(sec run NOPE -- sh -c 'echo ran' 2>&1)"; rc=$?
[[ $rc != 0 ]] && ! grep -q ran <<<"$out" && ok "a missing secret stops the command from running" \
    || no "a missing secret stops the command from running" "$out"
sec run 'bad-name' -- true >/dev/null 2>&1 && no "invalid names are refused" || ok "invalid names are refused"
[[ -z ${API_TOKEN:-} ]] && ok "the caller's environment is untouched" || no "the caller's environment is untouched"
grep -q 'run API_TOKEN cmd=sh' "$SECRET_STATE/audit.log" && ok "runs are logged, names only" || no "runs are logged, names only"
grep -q 'v2' "$SECRET_STATE/audit.log" && no "the log never holds values" || ok "the log never holds values"

printf 'guarded' | sec set GUARDED --stdin --ask 2>/dev/null
check "--ask is marked in list" "$(sec list --json | jq -r '.[] | select(.name=="GUARDED") | .ask')" "true"
acl="$(security dump-keychain -a "$SECRET_KEYCHAIN" 2>/dev/null | awk '/"acct"<blob>="GUARDED"/ {f=1} f && /applications \(/ {print; exit}')"
grep -q 'applications (0)' <<<"$acl" && ok "--ask trusts no application, so every read prompts" || no "--ask trusts no application, so every read prompts" "$acl"
acl="$(security dump-keychain -a "$SECRET_KEYCHAIN" 2>/dev/null | awk '/"acct"<blob>="API_TOKEN"/ {f=1} f && /applications \(/ {print; exit}')"
grep -q 'applications (1)' <<<"$acl" && ok "a default item trusts only security" || no "a default item trusts only security" "$acl"

# `security -i` exits 0 even when its command fails. A stand-in that silently drops one
# chosen write proves every write is checked, and that a failed replacement loses nothing.
mkdir -p "$WORK/shim"
cat > "$WORK/shim/security" <<'SHIM'
#!/bin/bash
if [[ ${1:-} == -i ]]; then
    in="$(cat)"
    [[ -n ${SHIM_DROP:-} && $in == *"$SHIM_DROP"* ]] && exit 0
    printf '%s\n' "$in" | /usr/bin/security -i; exit
fi
exec /usr/bin/security "$@"
SHIM
chmod +x "$WORK/shim/security"
shim() { PATH="$WORK/shim:$PATH" SHIM_DROP="$1" "$SHELL_BIN" "$ROOT/secret" "${@:2}"; }

out="$(printf 'x' | shim "-a FRESH " set FRESH --stdin 2>&1)"; rc=$?
[[ $rc != 0 ]] && ! grep -q stored <<<"$out" && ok "a write that silently fails is reported as a failure" \
    || no "a write that silently fails is reported as a failure" "$out"
printf 'old' | sec set KEEP --stdin 2>/dev/null
printf 'new' | shim "-s secret-run.pending -a KEEP " set KEEP --stdin >/dev/null 2>&1 \
    && no "a replacement whose new value cannot be written fails" || ok "a replacement whose new value cannot be written fails"
check "and the old value is untouched" "$(sec get KEEP 2>/dev/null)" "old"
printf 'new' | shim "-s secret-run -a KEEP " set KEEP --stdin >/dev/null 2>&1 \
    && no "a replacement that cannot be moved into place fails" || ok "a replacement that cannot be moved into place fails"
check "and the new value is parked, not lost" \
    "$(security find-generic-password -s secret-run.pending -a KEEP -w "$SECRET_KEYCHAIN" 2>/dev/null)" "new"
printf 'v3' | sec set KEEP --stdin 2>/dev/null
check "the next set recovers cleanly" "$(sec get KEEP 2>/dev/null)" "v3"
security find-generic-password -s secret-run.pending -a KEEP "$SECRET_KEYCHAIN" >/dev/null 2>&1 \
    && no "and clears the parked copy" || ok "and clears the parked copy"
sec list | grep -q pending && no "parked copies never show in list" || ok "parked copies never show in list"

printf 'x' | sec set SWITCH --stdin 2>/dev/null
printf 'y' | sec set SWITCH --stdin --ask 2>/dev/null
acl="$(security dump-keychain -a "$SECRET_KEYCHAIN" 2>/dev/null | awk '/"acct"<blob>="SWITCH"/ {f=1} f && /applications \(/ {print; exit}')"
grep -q 'applications (0)' <<<"$acl" && ok "an existing item can be switched to --ask" || no "an existing item can be switched to --ask" "$acl"
printf 'z' | sec set SWITCH --stdin 2>/dev/null
check "and back again" "$(sec get SWITCH 2>/dev/null)" "z"

sec rm API_TOKEN 2>/dev/null
sec get API_TOKEN >/dev/null 2>&1 && no "rm deletes" || ok "rm deletes"
sec rm API_TOKEN >/dev/null 2>&1 && no "rm of a missing name fails" || ok "rm of a missing name fails"

printf '\n'; if (( FAIL == 0 )); then printf '%d passed\n' "$PASS"; exit 0
else printf '%d passed, %d failed\n' "$PASS" "$FAIL"; exit 1; fi
