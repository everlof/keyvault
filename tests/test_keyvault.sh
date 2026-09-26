#!/usr/bin/env bash
#
# tests/test_keyvault.sh — exercises the whole lifecycle without touching the real
# keychain, the real config, the real keys or the real vault.
#
# Plain age keys stand in for the Secure Enclave (KEYVAULT_SE_IDENTITY) and for the
# passphrase (KEYVAULT_PASSPHRASE_IDENTITY), so most of the suite runs without prompts.
# Everything that needs a human — setup, approvals, a real scrypt passphrase — runs
# through a pty (tests/onpty.py).
#
# Run with:   tests/test_keyvault.sh            (whatever bash is first on PATH)
#             tests/test_keyvault.sh --bash32   (force stock /bin/bash 3.2)
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KV="$ROOT/keyvault"
SHELL_BIN="${BASH:-bash}"
[[ ${1:-} == --bash32 ]] && SHELL_BIN=/bin/bash

PASS=0 FAIL=0
if [[ -t 1 ]]; then G=$'\033[32m'; R=$'\033[31m'; D=$'\033[2m'; Z=$'\033[0m'
else G=; R=; D=; Z=; fi

ok()   { printf '  %s✓%s %s\n' "$G" "$Z" "$1"; PASS=$((PASS+1)); }
no()   { printf '  %s✗%s %s\n' "$R" "$Z" "$1"; [[ -n ${2:-} ]] && printf '      %s%s%s\n' "$D" "$2" "$Z"; FAIL=$((FAIL+1)); }
group(){ printf '\n%s\n' "$1"; }

check()      { if [[ $2 == "$3" ]]; then ok "$1"; else no "$1" "expected [$3], got [$2]"; fi; }
check_true() { if "$@"; then ok "$1"; else no "$1"; fi; } # unused guard, kept explicit below

# ---------------------------------------------------------------------------- fixture

WORK="$(mktemp -d "${TMPDIR:-/tmp}/keyvault-test.XXXXXX")"
trap 'rm -rf "$WORK"; [[ -n ${MOUNT:-} ]] && rm -rf "$MOUNT" 2>/dev/null; true' EXIT

mkdir -p "$WORK/src" "$WORK/globdir" "$WORK/dest" "$WORK/state"

printf 'PRIVATE-KEY-ALPHA\n'   > "$WORK/src/alpha.key"
printf 'PRIVATE-KEY-BETA\n'    > "$WORK/src/beta.key"
printf 'AuthKey_TEST1.p8 body\n' > "$WORK/globdir/AuthKey_TEST1.p8"
printf 'not a key\n'             > "$WORK/globdir/notes.txt"
# The real ~/.appstoreconnect/private_keys entry is a symlink into ~/Documents, and an
# earlier version of this tool silently skipped it. Keep a symlinked key in the fixture.
mkdir -p "$WORK/elsewhere"
printf 'AuthKey_TEST2.p8 body\n' > "$WORK/elsewhere/AuthKey_TEST2.p8"
ln -s "$WORK/elsewhere/AuthKey_TEST2.p8" "$WORK/globdir/AuthKey_TEST2.p8"
chmod 600 "$WORK/src"/*.key "$WORK/globdir/AuthKey_TEST1.p8" "$WORK/elsewhere"/*.p8

# Real key bundles carry filenames with spaces (Certificate 0001 2026-01-01 10-00-00Z.pfx).
printf 'SPACED CERT BODY\n' > "$WORK/globdir/Certificate 0001 2026-01-01 10-00-00Z.pfx"
chmod 600 "$WORK/globdir/Certificate 0001 2026-01-01 10-00-00Z.pfx"

# Every level is exercised: alpha needs both factors, the .p8s Touch ID, the .pfx the passphrase.
cat > "$WORK/keyvault.conf" <<EOF
file "$WORK/src/alpha.key" --id alpha --desc "the alpha key" --level both
file "$WORK/src/beta.key"  --id beta  --desc "the beta key"
glob "$WORK/globdir" '*.p8' --desc "test p8 keys"
level passphrase
glob "$WORK/globdir" '*.pfx' --desc "a certificate whose name has spaces"
EOF

command -v age-keygen >/dev/null || { echo "age-keygen missing; install age"; exit 2; }
for k in se pass recovery wrong; do age-keygen -o "$WORK/$k.id" >/dev/null 2>&1; done
chmod 600 "$WORK"/*.id
RECOVERY_SECRET="$(grep '^AGE-SECRET-KEY-' "$WORK/recovery.id")"
LAST6="${RECOVERY_SECRET: -6}"

export KEYVAULT_CONF="$WORK/keyvault.conf"
export KEYVAULT_DEST="$WORK/dest"
export KEYVAULT_STATE="$WORK/state"
export KEYVAULT_KEYS="$WORK/keys"
export KEYVAULT_SE_IDENTITY="$WORK/se.id"               # stands in for the Secure Enclave
export KEYVAULT_PASSPHRASE_IDENTITY="$WORK/pass.id"     # stands in for scrypt
export KEYVAULT_RECOVERY_IDENTITY="$WORK/recovery.id"   # only used with --recovery
export KEYVAULT_MOUNT="$WORK/mount"
export KEYVAULT_NO_RAMDISK=1     # the fallback workspace; the ramdisk path is checked separately
export NO_COLOR=1

# Detached from any controlling terminal, the way an agent's shell is. Without this the
# suite would behave differently in a developer's terminal than in CI: age would find
# /dev/tty and sit waiting for a passphrase.
NOTTY=(python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])')
notty() { "${NOTTY[@]}" "$@"; }     # the array form also works where a function cannot (env, exec)
kv()    { notty "$SHELL_BIN" "$KV" "$@"; }
# No factor available at all: what a command can do when nobody can unlock anything.
bare()  { notty env -u KEYVAULT_SE_IDENTITY -u KEYVAULT_PASSPHRASE_IDENTITY -u KEYVAULT_RECOVERY_IDENTITY "$SHELL_BIN" "$KV" "$@"; }
onpty() { local input="$1"; shift; python3 "$ROOT/tests/onpty.py" "$input" "$@"; }

STORE="$WORK/dest/keyvault"
store_hash() { find "$STORE" -type f -name '*.age' -exec shasum -a 256 {} + 2>/dev/null | sort | shasum -a 256; }
# The factors, unwrapped by hand: what a test needs to peel a layer on its own.
unwrap() { age -d -i "$WORK/se.id" "$KEYVAULT_KEYS/biometric.mac.age" > "$WORK/kbio"
           age -d -i "$WORK/pass.id" "$KEYVAULT_KEYS/passphrase.key.age" > "$WORK/kpass"; }

printf '%skeyvault test suite — %s%s\n' "$D" "$("$SHELL_BIN" --version | head -1)" "$Z"

# ---------------------------------------------------------------------------- units

group "Unit: path portability"
out="$(KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; tildify '$HOME/a/b'")"
check "tildify collapses \$HOME" "$out" "~/a/b"
out="$(KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; untildify '~/a/b'")"
check "untildify expands ~" "$out" "$HOME/a/b"
out="$(KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; tildify /etc/hosts")"
check "tildify leaves other paths alone" "$out" "/etc/hosts"

group "Unit: keyvault's own output is never collected"
mkdir -p "$WORK/dest/keyvault/added" "$WORK/dest/archive/1"
for f in catalog.json README.txt keyvault/biometric.age keyvault/added/x.both.age archive/1/both.age; do
    : > "$WORK/dest/$f"
    KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; is_own_output \"\$(resolve_path '$WORK/dest/$f')\"" \
        && ok "$f is own output" || no "$f is own output"
done
KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; is_own_output \"\$(resolve_path '$WORK/dest/AuthKey_X.p8')\"" \
    && no "a key beside it is not" || ok "a key beside it is not"
rm -rf "$WORK/dest"/*

group "Config: init and dest"
X="$WORK/xdg"
out="$(env -u KEYVAULT_CONF XDG_CONFIG_HOME="$X" "$SHELL_BIN" "$KV" init 2>&1)"
[[ -f $X/keyvault/keyvault.conf ]] && ok "init writes ~/.config/keyvault/keyvault.conf" || no "init writes ~/.config/keyvault/keyvault.conf" "$out"
check "the config is private" "$(stat -f %Lp "$X/keyvault/keyvault.conf" 2>/dev/null)" "600"
env -u KEYVAULT_CONF XDG_CONFIG_HOME="$X" "$SHELL_BIN" "$KV" init >/dev/null 2>&1 \
    && no "init never overwrites an existing config" || ok "init never overwrites an existing config"
printf 'dest "%s"\nfile "%s" --id d\n' "$WORK/from-conf" "$WORK/src/alpha.key" > "$WORK/dest.conf"
out="$(env -u KEYVAULT_DEST KEYVAULT_CONF="$WORK/dest.conf" "$SHELL_BIN" "$KV" doctor 2>&1)"
grep -q "destination  .*from-conf" <<<"$out" && ok "dest in the config sets the destination" || no "dest in the config sets the destination" "$out"
out="$(KEYVAULT_DEST="$WORK/from-env" KEYVAULT_CONF="$WORK/dest.conf" "$SHELL_BIN" "$KV" doctor 2>&1)"
grep -q 'from-env' <<<"$out" && ok "KEYVAULT_DEST overrides it" || no "KEYVAULT_DEST overrides it" "$out"
printf 'file "%s" --level sometimes\n' "$WORK/src/alpha.key" > "$WORK/badlevel.conf"
out="$(KEYVAULT_CONF="$WORK/badlevel.conf" "$SHELL_BIN" "$KV" doctor 2>&1)"
grep -q 'level must be one of' <<<"$out" && ok "an unknown level is rejected" || no "an unknown level is rejected" "$out"

group "Unit: symlink resolution"
mkdir -p "$WORK/link"
printf 'x\n' > "$WORK/link/real.txt"
ln -s "$WORK/link/real.txt" "$WORK/link/one.txt"
ln -s "$WORK/link/one.txt"  "$WORK/link/two.txt"
out="$(KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; resolve_path '$WORK/link/two.txt'")"
check "a symlink chain resolves to the real file" "$out" "$(cd "$WORK/link" && pwd -P)/real.txt"
out="$(KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; resolve_path '$WORK/link/real.txt'")"
check "a plain file resolves to itself" "$out" "$(cd "$WORK/link" && pwd -P)/real.txt"
ln -s "$WORK/link/loop_a" "$WORK/link/loop_b"; ln -s "$WORK/link/loop_b" "$WORK/link/loop_a"
timeout 5 "$SHELL_BIN" -c "KEYVAULT_LIB=1; source '$KV'; resolve_path '$WORK/link/loop_a'" >/dev/null 2>&1
[[ $? -ne 124 ]] && ok "a symlink loop terminates instead of hanging" || no "a symlink loop terminates instead of hanging"

group "Unit: ed25519 derivation (both export shapes Sparkle produces)"
python3 - "$WORK" <<'PY2'
import base64, sys, pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
w = pathlib.Path(sys.argv[1])
k = Ed25519PrivateKey.generate()
seed = k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
pub = k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
(w / "seed32.txt").write_bytes(base64.b64encode(seed))
(w / "seed64.txt").write_bytes(base64.b64encode(seed + pub))
(w / "seed64bad.txt").write_bytes(base64.b64encode(seed + bytes(32)))
(w / "seedshort.txt").write_bytes(base64.b64encode(seed[:16]))
(w / "expected.txt").write_text(base64.b64encode(pub).decode())
PY2
expected="$(cat "$WORK/expected.txt")"
for form in seed32 seed64; do
    out="$(KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; ed25519_public_from_seed_file '$WORK/$form.txt'")"
    check "$form derives the right public key" "$out" "$expected"
done
KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; ed25519_public_from_seed_file '$WORK/seed64bad.txt'" >/dev/null 2>&1
check "a 64-byte export with a mismatched public half is rejected" "$?" "4"
KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; ed25519_public_from_seed_file '$WORK/seedshort.txt'" >/dev/null 2>&1
check "a truncated key is rejected" "$?" "3"

# ---------------------------------------------------------------------------- setup

group "setup"
kv pack >/dev/null 2>&1 && no "pack refuses before setup" || ok "pack refuses before setup"
out="$(kv setup 2>&1)"; rc=$?
[[ $rc != 0 ]] && grep -q 'human at a terminal' <<<"$out" && ok "setup refuses without a terminal" || no "setup refuses without a terminal" "$out"
out="$(onpty $'WRONG1\n'"$LAST6"$'\n' "$SHELL_BIN" "$KV" setup 2>&1)"; rc=$?
check "setup succeeds through a terminal" "$rc" "0"
grep -q "${RECOVERY_SECRET:0:16}" <<<"$out" && ok "it shows the recovery key once, to write down" || no "it shows the recovery key once, to write down" "$out"
grep -q 'does not match' <<<"$out" && ok "a wrong confirmation is caught" || no "a wrong confirmation is caught" "$out"
check "three public keys are recorded" "$(grep -c '^[a-z]* age1' "$KEYVAULT_KEYS/recipients")" "3"
for f in biometric.mac.age passphrase.key.age; do
    [[ -f $KEYVAULT_KEYS/$f ]] && ok "keys/$f exists" || no "keys/$f exists"
done
grep -rq 'AGE-SECRET-KEY' "$KEYVAULT_KEYS" && no "no key is stored unwrapped" || ok "no key is stored unwrapped"
check "the recovery key's public half is the one recorded" \
    "$(awk '$1=="recovery"{print $2}' "$KEYVAULT_KEYS/recipients")" "$(age-keygen -y "$WORK/recovery.id")"
onpty "$LAST6"$'\n' "$SHELL_BIN" "$KV" setup >/dev/null 2>&1 && no "setup never replaces existing keys" || ok "setup never replaces existing keys"

group "recovery-check"
kv recovery-check >/dev/null 2>&1
check "the right recovery key checks out" "$?" "0"
KEYVAULT_RECOVERY_IDENTITY="$WORK/wrong.id" kv recovery-check >/dev/null 2>&1 \
    && no "a wrong recovery key is refused" || ok "a wrong recovery key is refused"

# ---------------------------------------------------------------------------- lifecycle

group "pack"
out="$(bare pack 2>&1)"; rc=$?
check "pack asks for nothing: it needs only public keys" "$rc" "0"
for l in biometric passphrase both; do
    [[ -f $STORE/$l.age ]] && ok "$l.age written" || no "$l.age written" "$out"
done
head -1 "$STORE/both.age" | grep -q 'BEGIN AGE ENCRYPTED FILE' && ok "files are armored age" || no "files are armored age"
grep -rq 'PRIVATE-KEY-ALPHA' "$STORE" && no "the vault leaks plaintext" || ok "the vault contains no plaintext"
[[ -f $WORK/dest/README.txt ]] && ok "destination README written" || no "destination README written"
[[ -e $WORK/mount ]] && no "workspace torn down after pack" || ok "workspace torn down after pack"

group "levels are real layers"
unwrap
age -d -i "$WORK/kpass" -o "$WORK/inner" "$STORE/both.age" 2>/dev/null \
    && head -1 "$WORK/inner" | grep -q 'BEGIN AGE' && ok "both: the passphrase opens the outer layer, to another layer" \
    || no "both: the passphrase opens the outer layer, to another layer"
age -d -i "$WORK/kbio" "$STORE/both.age" >/dev/null 2>&1 && no "both: Touch ID alone cannot" || ok "both: Touch ID alone cannot"
age -d -i "$WORK/kbio" "$WORK/inner" 2>/dev/null | tar -tzf - 2>/dev/null | grep -q 'items/alpha' \
    && ok "both: Touch ID opens the inner layer, to alpha" || no "both: Touch ID opens the inner layer, to alpha"
age -d -i "$WORK/kpass" "$STORE/biometric.age" >/dev/null 2>&1 && no "biometric: the passphrase cannot open it" || ok "biometric: the passphrase cannot open it"
age -d -i "$WORK/recovery.id" "$STORE/both.age" 2>/dev/null | age -d -i "$WORK/recovery.id" 2>/dev/null | tar -tzf - >/dev/null 2>&1 \
    && ok "the recovery key opens every layer" || no "the recovery key opens every layer"
rm -f "$WORK/inner"

group "list"
out="$(bare list 2>&1)"
for id in alpha beta AuthKey_TEST1.p8 AuthKey_TEST2.p8; do
    grep -q "$id" <<<"$out" && ok "list shows $id" || no "list shows $id" "$out"
done
grep -qE '^alpha +both ' <<<"$out" && ok "list shows each item's level" || no "list shows each item's level" "$out"
grep -q 'notes.txt' <<<"$out" && no "glob excluded notes.txt" || ok "glob excluded notes.txt"

group "verify"
kv verify >/dev/null 2>&1
check "verify passes on a fresh vault" "$?" "0"
bare verify --recovery >/dev/null 2>&1 && no "--recovery with no recovery key fails" || ok "--recovery with no recovery key fails"
kv verify --recovery >/dev/null 2>&1
check "verify passes with the recovery key alone" "$?" "0"

group "each command asks only for what it needs"
notty env -u KEYVAULT_PASSPHRASE_IDENTITY "$SHELL_BIN" "$KV" show beta --out "$WORK/beta.out" >/dev/null 2>&1
check "a biometric item opens without the passphrase" "$?" "0"
out="$(notty env -u KEYVAULT_PASSPHRASE_IDENTITY "$SHELL_BIN" "$KV" show alpha --out "$WORK/alpha.out" 2>&1)"
[[ ! -f $WORK/alpha.out ]] && grep -q 'passphrase needs a human' <<<"$out" \
    && ok "a both item does not open without it" || no "a both item does not open without it" "$out"
KEYVAULT_SE_IDENTITY="$WORK/wrong.id" notty "$SHELL_BIN" "$KV" verify >/dev/null 2>&1 \
    && no "a wrong biometric key cannot open the vault" || ok "a wrong biometric key cannot open the vault"
[[ -e $WORK/mount ]] && no "a failed unlock leaves no workspace" || ok "a failed unlock leaves no workspace"

group "reading needs a vault that exists"
for c in verify list validate; do
    KEYVAULT_DEST="$WORK/nowhere" kv $c >/dev/null 2>&1 && no "$c fails when there is no vault" || ok "$c fails when there is no vault"
done
KEYVAULT_DEST="$WORK/nowhere" kv restore >/dev/null 2>&1 && no "restore fails when there is no vault" || ok "restore fails when there is no vault"
[[ -e $WORK/nowhere/keyvault ]] && no "and none is created by asking" || ok "and none is created by asking"

group "add"
bare add licence --file "$WORK/src/beta.key" --restore-to "$WORK/dest/licence.key" --desc "a licence" >/dev/null 2>&1
check "add --file asks for nothing" "$?" "0"
printf 'hunter2-and-then-some' | bare add apppw --stdin --level both --desc "an app-specific password" >/dev/null 2>&1
check "add --stdin --level both" "$?" "0"
[[ -f $STORE/added/licence.biometric.age && -f $STORE/added/apppw.both.age ]] \
    && ok "each added item is its own file, named by level" || no "each added item is its own file, named by level" "$(ls "$STORE/added")"
out="$(bare list 2>/dev/null)"
grep -qE '^apppw +both +secret +yes' <<<"$out" && ok "list shows the added secret, its level, marked added" || no "list shows the added secret, its level, marked added" "$out"
grep -q 'licence' <<<"$out" && ok "list shows the added file" || no "list shows the added file"
kv add alpha --file "$WORK/src/beta.key" >/dev/null 2>&1 && no "an added item cannot shadow a declared one" || ok "an added item cannot shadow a declared one"
kv verify >/dev/null 2>&1
check "verify still passes after add" "$?" "0"

group "a failed add changes nothing"
before="$(store_hash)"
printf '' | kv add apppw --stdin >/dev/null 2>&1 && no "replacing with empty stdin fails" || ok "replacing with empty stdin fails"
check "the vault is untouched" "$(store_hash)" "$before"
kv add licence --file "$WORK/no-such-file" >/dev/null 2>&1 && no "adding a missing file fails" || ok "adding a missing file fails"
check "and still untouched" "$(store_hash)" "$before"
kv add bad --stdin --level sometimes </dev/null >/dev/null 2>&1 && no "an unknown level is refused" || ok "an unknown level is refused"

group "added items survive a repack"
kv pack >/dev/null 2>&1
out="$(kv list 2>/dev/null)"
grep -q 'apppw' <<<"$out" && ok "the typed-in secret is still listed after pack" || no "the typed-in secret is still listed after pack"
out="$(kv show apppw --out "$WORK/roundtrip.txt" 2>&1; cat "$WORK/roundtrip.txt")"
grep -q 'hunter2-and-then-some' <<<"$out" && ok "secret survives byte-for-byte" || no "secret survives byte-for-byte" "$out"
printf 'rotated' | kv add apppw --stdin --level biometric >/dev/null 2>&1
[[ -f $STORE/added/apppw.biometric.age && ! -f $STORE/added/apppw.both.age ]] \
    && ok "re-adding at another level replaces the old file" || no "re-adding at another level replaces the old file" "$(ls "$STORE/added")"

group "remove"
bare remove apppw >/dev/null 2>&1
check "remove asks for nothing" "$?" "0"
[[ -f $STORE/added/apppw.biometric.age ]] && no "its file is gone" || ok "its file is gone"
kv list 2>/dev/null | grep -q '^apppw ' && no "and it is no longer listed" || ok "and it is no longer listed"
out="$(kv remove alpha 2>&1)"
[[ $? -ne 0 ]] && grep -q 'keyvault.conf' <<<"$out" && ok "a declared item is removed in the config, not here" || no "a declared item is removed in the config, not here" "$out"
kv remove nosuchthing >/dev/null 2>&1 && no "removing an unknown id fails" || ok "removing an unknown id fails"

group "restore"
kv pack >/dev/null 2>&1
rm -f "$WORK/src/beta.key" "$WORK/globdir/AuthKey_TEST1.p8"
out="$(kv restore 2>&1)"
grep -q 'would' <<<"$out" && ok "dry run says 'would'" || no "dry run says 'would'" "$out"
[[ -f $WORK/src/beta.key ]] && no "dry run changed nothing" || ok "dry run changed nothing"
bare restore --recovery --apply >/dev/null 2>&1 && no "restore --recovery needs the recovery key" || ok "restore --recovery needs the recovery key"
kv restore --recovery --apply >/dev/null 2>&1
check "restore --recovery --apply exits 0 (a new Mac: no Touch ID, no passphrase key)" "$?" "0"
[[ -f $WORK/src/beta.key ]] && ok "beta.key restored" || no "beta.key restored"
grep -q 'PRIVATE-KEY-BETA' "$WORK/src/beta.key" && ok "restored content is correct" || no "restored content is correct"
check "restored mode is 600" "$(stat -f '%Lp' "$WORK/src/beta.key")" "600"
[[ -f $WORK/globdir/AuthKey_TEST1.p8 ]] && ok "globbed p8 restored" || no "globbed p8 restored"

group "restore refuses to clobber"
printf 'SOMETHING ELSE\n' > "$WORK/src/beta.key"
kv restore --apply --only beta >/dev/null 2>&1
[[ $? -ne 0 ]] && ok "differing file is not overwritten without --force" || no "differing file is not overwritten without --force"
grep -q 'SOMETHING ELSE' "$WORK/src/beta.key" && ok "the differing file is untouched" || no "the differing file is untouched"
kv restore --apply --only beta --force >/dev/null 2>&1
grep -q 'PRIVATE-KEY-BETA' "$WORK/src/beta.key" && ok "--force overwrites" || no "--force overwrites"

group "filenames with spaces survive the whole round trip"
out="$(kv list 2>/dev/null)"
grep -q 'Certificate_0001' <<<"$out" && ok "a spaced filename becomes a usable id" || no "a spaced filename becomes a usable id" "$out"
kv verify >/dev/null 2>&1
check "verify passes with a spaced filename in the vault" "$?" "0"
rm -f "$WORK/globdir/Certificate 0001 2026-01-01 10-00-00Z.pfx"
kv restore --apply >/dev/null 2>&1
[[ -f "$WORK/globdir/Certificate 0001 2026-01-01 10-00-00Z.pfx" ]] \
    && ok "it restores to its original spaced path" || no "it restores to its original spaced path"
grep -q 'SPACED CERT BODY' "$WORK/globdir/Certificate 0001 2026-01-01 10-00-00Z.pfx" 2>/dev/null \
    && ok "its contents are intact" || no "its contents are intact"

group "two files cannot silently claim one id"
# Key bundles are full of generic cert.pem / key.pem; collapsing two onto one id would
# store one twice and the other not at all.
mkdir -p "$WORK/bundleA" "$WORK/bundleB"
printf 'FROM BUNDLE A\n' > "$WORK/bundleA/key.pem"
printf 'FROM BUNDLE B\n' > "$WORK/bundleB/key.pem"
cat > "$WORK/collide.conf" <<EOF
glob "$WORK/bundleA" '*.pem' --desc "bundle A"
glob "$WORK/bundleB" '*.pem' --desc "bundle B"
EOF
before="$(store_hash)"
out="$(KEYVAULT_CONF="$WORK/collide.conf" KEYVAULT_DEST="$WORK/collide-dest" KEYVAULT_MOUNT="$WORK/collide-mount" kv pack 2>&1)"
rc=$?
[[ $rc -ne 0 ]] && ok "a colliding id fails the pack" || no "a colliding id fails the pack" "$out"
grep -q 'claimed by two files' <<<"$out" && ok "the error names both files" || no "the error names both files" "$out"
grep -q 'give one an --id' <<<"$out" && ok "the error says how to fix it" || no "the error says how to fix it"
[[ -e $WORK/collide-dest/keyvault ]] && no "a failed pack writes nothing" || ok "a failed pack writes nothing"
check "the real vault was untouched" "$(store_hash)" "$before"

group "the vault never swallows its own output"
# The real config globs the same folder the vault is written to.
cat > "$WORK/selfeat.conf" <<EOF
glob "$WORK/dest" '*'
glob "$STORE" '*.age'
file "$WORK/src/alpha.key" --id alpha
EOF
out="$(KEYVAULT_CONF="$WORK/selfeat.conf" kv pack 2>&1)"
check "a glob over the destination still packs" "$?" "0"
grep -q "keyvault's own output" <<<"$out" && ok "it says what it skipped" || no "it says what it skipped" "$out"
out="$(KEYVAULT_CONF="$WORK/selfeat.conf" kv list 2>/dev/null)"
grep -qE '^(catalog.json|README.txt|biometric.age) ' <<<"$out" && no "none of it is inside the vault" "$out" || ok "none of it is inside the vault"
kv pack >/dev/null 2>&1   # restore the real fixture vault

group "symlinked keys are followed, not skipped"
out="$(kv list 2>/dev/null)"
grep -q 'AuthKey_TEST2.p8' <<<"$out" && ok "a symlinked key is collected" || no "a symlinked key is collected" "$out"
real_elsewhere="$(cd "$WORK/elsewhere" && pwd -P)"
grep -q "$real_elsewhere/AuthKey_TEST2.p8" <<<"$out" \
    && ok "it is recorded under its real path" || no "it is recorded under its real path" "$out"
rm -f "$WORK/elsewhere/AuthKey_TEST2.p8" "$WORK/globdir/AuthKey_TEST2.p8"
kv restore --apply >/dev/null 2>&1
[[ -f $WORK/elsewhere/AuthKey_TEST2.p8 ]] && ok "the real file is restored" || no "the real file is restored"
grep -q 'AuthKey_TEST2.p8 body' "$WORK/elsewhere/AuthKey_TEST2.p8" 2>/dev/null \
    && ok "its contents are the target's, not the link's" || no "its contents are the target's, not the link's"
[[ -L $WORK/globdir/AuthKey_TEST2.p8 ]] && ok "the symlink is recreated" || no "the symlink is recreated"

group "validate"
kv validate >/dev/null 2>&1
check "validate passes when the machine matches" "$?" "0"
printf 'NEW KEY\n' > "$WORK/globdir/AuthKey_TEST3.p8"
out="$(kv validate 2>&1)"; rc=$?
grep -q 'AuthKey_TEST3.p8  matches keyvault.conf but is not in the vault' <<<"$out" \
    && ok "validate notices a new file in a globbed folder" || no "validate notices a new file in a globbed folder" "$out"
check "and exits 2 (out of date)" "$rc" "2"
rm -f "$WORK/globdir/AuthKey_TEST3.p8"
printf 'DRIFTED\n' > "$WORK/src/beta.key"
out="$(kv validate 2>&1)"; rc=$?
grep -qi 'differs' <<<"$out" && ok "validate notices on-disk drift" || no "validate notices on-disk drift" "$out"
check "drift exits 2, not 0" "$rc" "2"
rm -f "$WORK/src/alpha.key"
out="$(kv validate 2>&1)"
grep -qi 'gone from disk\|only copy' <<<"$out" && ok "validate notices a deleted source" || no "validate notices a deleted source"

group "a failed pack writes nothing"
# alpha.key is declared in the config but was deleted during the validate block.
before="$(store_hash)"
kv pack >/dev/null 2>&1 && no "pack fails when a declared source is missing" || ok "pack fails when a declared source is missing"
check "the vault on disk is unchanged" "$(store_hash)" "$before"
[[ -e $WORK/mount ]] && no "and no workspace is left behind" || ok "and no workspace is left behind"
printf 'PRIVATE-KEY-ALPHA\n' > "$WORK/src/alpha.key"   # put the fixture back
printf 'PRIVATE-KEY-BETA\n'  > "$WORK/src/beta.key"
chmod 600 "$WORK/src"/*.key
kv pack >/dev/null 2>&1 || no "pack succeeds with the fixture restored"

group "verify detects tampering"
unwrap
mkdir -p "$WORK/tamper" && age -d -i "$WORK/kbio" "$STORE/biometric.age" | tar -xzf - -C "$WORK/tamper"
printf 'TAMPERED\n' > "$(find "$WORK/tamper/vault/items" -name 'beta.key' | head -1)"
cp "$STORE/biometric.age" "$WORK/biometric.good"
tar -czf - -C "$WORK/tamper" vault | age -a -r "$(awk '$1=="biometric"{print $2}' "$KEYVAULT_KEYS/recipients")" > "$STORE/biometric.age"
out="$(kv verify 2>&1)"; rc=$?
[[ $rc -ne 0 ]] && grep -qi 'checksum mismatch' <<<"$out" && ok "verify fails on a modified item, and names it" || no "verify fails on a modified item, and names it" "$out"
cp "$WORK/biometric.good" "$STORE/biometric.age"
LC_ALL=C sed -i '' '3s/./X/' "$STORE/biometric.age"
kv verify >/dev/null 2>&1 && no "verify fails on damaged ciphertext" || ok "verify fails on damaged ciphertext"
cp "$WORK/biometric.good" "$STORE/biometric.age"
kv verify >/dev/null 2>&1 || no "the fixture vault verifies again"

group "archive retention"
rm -rf "$WORK/dest/archive"
kv pack >/dev/null 2>&1
n="$(ls -1d "$WORK/dest/archive"/[0-9]*/ 2>/dev/null | wc -l | tr -d ' ')"
check "pack archives the previous vault" "$n" "1"
kv pack >/dev/null 2>&1; kv pack >/dev/null 2>&1; kv pack >/dev/null 2>&1
n="$(ls -1d "$WORK/dest/archive"/[0-9]*/ 2>/dev/null | wc -l | tr -d ' ')"
check "same-second packs do not overwrite each other" "$n" "4"
( export KEYVAULT_ARCHIVE_KEEP=2; kv pack >/dev/null 2>&1 )
n="$(ls -1d "$WORK/dest/archive"/[0-9]*/ 2>/dev/null | wc -l | tr -d ' ')"
[[ $n -le 2 ]] && ok "old archives are pruned to the limit" || no "old archives are pruned to the limit" "found $n"

group "card, help, status"
out="$(bare card 2>/dev/null)"
grep -q 'RECOVERY SHEET' <<<"$out" && ok "card renders without opening anything" || no "card renders without opening anything"
grep -q "$(age-keygen -y "$WORK/recovery.id")" <<<"$out" && ok "card carries the recovery key's public half" || no "card carries the recovery key's public half"
grep -q "${RECOVERY_SECRET:16:20}" <<<"$out" && no "card never carries the recovery key itself" || ok "card never carries the recovery key itself"
out="$(kv help 2>/dev/null)"
grep -q 'restore' <<<"$out" && grep -q 'setup' <<<"$out" && ok "help renders" || no "help renders"
out="$(kv status 2>/dev/null)"
grep -q 'both.age' <<<"$out" && ok "status lists the vault files" || no "status lists the vault files" "$out"
out="$(kv open 2>&1)"
[[ $? -ne 0 ]] && grep -q '2.0' <<<"$out" && ok "the old session commands explain themselves" || no "the old session commands explain themselves" "$out"

group "the vault opens with nothing but age, tar and the recovery key"
# Exactly the recipe on the card and in the README, run by hand.
mkdir -p "$WORK/manual" && cp -R "$STORE" "$WORK/manual/" && (
    cd "$WORK/manual/keyvault" && cp "$WORK/recovery.id" ../r.txt
    for f in *.age added/*.age; do
        [[ -f $f ]] || continue
        cp "$f" x; while grep -q 'BEGIN AGE' x; do age -d -i ../r.txt x > y && mv y x; done
        tar -xzf x; mv vault "vault-$(basename "$f" .age)"
    done
    rm -f x ../r.txt
)
check "every file opened" "$(ls -d "$WORK/manual/keyvault"/vault-*/ 2>/dev/null | wc -l | tr -d ' ')" "$(ls "$STORE"/*.age "$STORE"/added/*.age 2>/dev/null | wc -l | tr -d ' ')"
grep -rq 'PRIVATE-KEY-ALPHA' "$WORK/manual/keyvault"/vault-both/items 2>/dev/null \
    && ok "the both level, two layers deep, is readable" || no "the both level, two layers deep, is readable"
jq -e '[.items[] | select(.type=="file")] | length > 0' "$WORK/manual/keyvault/vault-biometric/manifest.json" >/dev/null 2>&1 \
    && ok "manifests say where every file belongs" || no "manifests say where every file belongs"

group "a real passphrase, end to end (scrypt, through a terminal)"
# Everything above uses a stand-in for the passphrase. This is the real thing.
P="$WORK/real"; mkdir -p "$P"
realkv() { KEYVAULT_KEYS="$P/keys" KEYVAULT_DEST="$P/dest" KEYVAULT_MOUNT="$P/mount" \
           env -u KEYVAULT_PASSPHRASE_IDENTITY "$@"; }
out="$(realkv python3 "$ROOT/tests/onpty.py" $'correct horse battery staple\ncorrect horse battery staple\n'"$LAST6"$'\n' "$SHELL_BIN" "$KV" setup 2>&1)"
check "setup with a real passphrase" "$?" "0"
grep -q 'AGE-SECRET-KEY' "$P/keys/passphrase.key.age" && no "the passphrase key is wrapped" || ok "the passphrase key is wrapped"
realkv "${NOTTY[@]}" "$SHELL_BIN" "$KV" pack >/dev/null 2>&1
check "pack still asks for nothing" "$?" "0"
realkv "${NOTTY[@]}" "$SHELL_BIN" "$KV" verify >/dev/null 2>&1 && no "without a terminal the passphrase cannot be typed" || ok "without a terminal the passphrase cannot be typed"
out="$(realkv python3 "$ROOT/tests/onpty.py" $'correct horse battery staple\n' "$SHELL_BIN" "$KV" verify 2>&1)"
grep -q 'internally sound' <<<"$out" && ok "typing it opens every level" || no "typing it opens every level" "$out"
out="$(realkv python3 "$ROOT/tests/onpty.py" $'wrong horse\n' "$SHELL_BIN" "$KV" verify 2>&1)"
grep -q 'wrong passphrase' <<<"$out" && ok "a wrong passphrase is refused" || no "a wrong passphrase is refused" "$out"
[[ -e $P/mount ]] && no "and leaves no workspace" || ok "and leaves no workspace"

# ---------------------------------------------------------------------------- agent access
#
# A second, independent vault so the counts above stay untouched: a real EC .p8, a
# self-signed certificate and an age identity, which is what metadata derivation reads.

A="$WORK/acc"
mkdir -p "$A/keys" "$A/dest" "$A/state"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$A/keys/AuthKey_ABCDE12345.p8" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$A/keys/cert-key.pem" -out "$A/keys/client.pem" \
    -days 30 -subj "/CN=keyvault-test/O=Acme" 2>/dev/null
age-keygen -o "$A/keys/sops-age.txt" >/dev/null 2>&1
chmod 600 "$A/keys"/*
cat > "$A/keyvault.conf" <<EOF
glob "$A/keys" '*.p8' --desc "ASC key"
file "$A/keys/client.pem" --id client-cert --desc "a client certificate"
file "$A/keys/sops-age.txt" --id sops-age --desc "SOPS master key" --level both
meta AuthKey_ABCDE12345.p8 issuer_id=11111111-2222-3333-4444-555555555555 used_by=myapp
meta no-such-item x=y
EOF

akv() { KEYVAULT_CONF="$A/keyvault.conf" KEYVAULT_DEST="$A/dest" KEYVAULT_STATE="$A/state" \
        KEYVAULT_MOUNT="$A/mount" KEYVAULT_NO_NOTIFY=1 notty "$SHELL_BIN" "$KV" "$@"; }
# As an agent sees it: no factor it could unlock, so nothing can be decrypted.
agent() { notty env -u KEYVAULT_SE_IDENTITY -u KEYVAULT_PASSPHRASE_IDENTITY -u KEYVAULT_RECOVERY_IDENTITY KEYVAULT_CONF="$A/keyvault.conf" KEYVAULT_DEST="$A/dest" \
          KEYVAULT_STATE="$A/state" KEYVAULT_MOUNT="$A/mount" KEYVAULT_NO_NOTIFY=1 "$SHELL_BIN" "$KV" "$@"; }
human() { local input="$1"; shift
          KEYVAULT_CONF="$A/keyvault.conf" KEYVAULT_DEST="$A/dest" KEYVAULT_STATE="$A/state" \
          KEYVAULT_MOUNT="$A/mount" KEYVAULT_NO_NOTIFY=1 python3 "$ROOT/tests/onpty.py" "$input" "$SHELL_BIN" "$KV" "$@"; }
CAT="$A/dest/catalog.json"

group "Catalog: what an agent may know"
out="$(akv pack 2>&1)"; rc=$?
check "pack exits 0" "$rc" "0"
[[ -f $CAT ]] && ok "sealing writes catalog.json next to the artifact" || no "sealing writes catalog.json next to the artifact"
grep -q 'no such item' <<<"$out" && ok "a meta line for an unknown id warns" || no "a meta line for an unknown id warns" "$out"
check "the catalog records each item's level" "$(jq -r '.items[] | select(.id=="sops-age") | .level' "$CAT")" "both"
check "a .p8 is recognised as an ASC key" "$(jq -r '.items[] | select(.id=="AuthKey_ABCDE12345.p8") | .kind' "$CAT")" "asc-api-key"
check "its key id comes from the filename" "$(jq -r '.items[] | select(.id=="AuthKey_ABCDE12345.p8") | .meta.asc_key_id' "$CAT")" "ABCDE12345"
check "conf meta lands in the catalog" "$(jq -r '.items[] | select(.id=="AuthKey_ABCDE12345.p8") | .meta.issuer_id' "$CAT")" "11111111-2222-3333-4444-555555555555"
want="$(openssl pkey -in "$A/keys/AuthKey_ABCDE12345.p8" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -binary | base64)"
check "the public-key fingerprint is published" "$(jq -r '.items[] | select(.id=="AuthKey_ABCDE12345.p8") | .meta.public_key_sha256' "$CAT")" "$want"
check "a PEM certificate is recognised" "$(jq -r '.items[] | select(.id=="client-cert") | .kind' "$CAT")" "x509-certificate"
jq -r '.items[] | select(.id=="client-cert") | .meta.subject' "$CAT" | grep -q 'CN=keyvault-test' \
    && ok "its subject is published" || no "its subject is published"
[[ -n $(jq -r '.items[] | select(.id=="client-cert") | .meta.not_after // empty' "$CAT") ]] \
    && ok "its expiry is published" || no "its expiry is published"
check "an age identity is recognised" "$(jq -r '.items[] | select(.id=="sops-age") | .kind' "$CAT")" "age-identity"
check "its recipient (public key) is published" "$(jq -r '.items[] | select(.id=="sops-age") | .meta.age_recipient' "$CAT")" \
    "$(age-keygen -y "$A/keys/sops-age.txt")"
if grep -qE 'PRIVATE KEY|AGE-SECRET-KEY' "$CAT" \
   || jq -e '[.. | objects | keys[]] | any(. == "sha256" or . == "file" or . == "p12_password")' "$CAT" >/dev/null; then
    no "the catalog carries no secret material, hashes or vault paths"
else
    ok "the catalog carries no secret material, hashes or vault paths"
fi

group "Catalog: read without the passphrase"
out="$(agent catalog 2>&1)"; rc=$?
check "catalog works with no identity" "$rc" "0"
grep -q 'ABCDE12345' <<<"$out" && ok "the table shows the key id" || no "the table shows the key id" "$out"
out="$(agent find myapp 2>&1)"
grep -q 'AuthKey_ABCDE12345.p8' <<<"$out" && ok "find searches meta values" || no "find searches meta values" "$out"
agent find nothing-like-this >/dev/null 2>&1 && no "find with no hits exits non-zero" || ok "find with no hits exits non-zero"
out="$(agent describe AuthKey_ABCDE12345.p8 2>&1)"
grep -q 'KV_AUTHKEY_ABCDE12345_P8' <<<"$out" && ok "describe names the variable a grant will set" || no "describe names the variable a grant will set" "$out"
grep -q 'notarytool' <<<"$out" && ok "describe shows how an ASC key is used" || no "describe shows how an ASC key is used"
agent describe nope >/dev/null 2>&1 && no "describe rejects an unknown id" || ok "describe rejects an unknown id"

group "Grants: request, deny, approve, use, revoke"
agent request nope --reason x >/dev/null 2>&1 && no "a request for an unknown id is refused" || ok "a request for an unknown id is refused"
agent request sops-age >/dev/null 2>&1 && no "a request without --reason is refused" || ok "a request without --reason is refused"
agent request sops-age --reason x --ttl 13h >/dev/null 2>&1 && no "a TTL over 12h is refused" || ok "a TTL over 12h is refused"

out="$(agent request AuthKey_ABCDE12345.p8 --reason "release MyApp 1.2.3" --ttl 10m 2>&1)"
gid="$(grep -oE 'kv-[a-f0-9]{8}' <<<"$out" | head -1)"
[[ -n $gid ]] && ok "request returns a grant id" || no "request returns a grant id" "$out"
grep -q "keyvault approve $gid" <<<"$out" && ok "request tells the agent what to ask the human" || no "request tells the agent what to ask the human"
out="$(agent exec "$gid" -- true 2>&1)"; rc=$?
[[ $rc != 0 ]] && grep -q 'waiting for approval' <<<"$out" && ok "a pending grant cannot be used" || no "a pending grant cannot be used" "$out"
out="$(agent approve "$gid" 2>&1)"; rc=$?
[[ $rc != 0 ]] && grep -q 'human at a terminal' <<<"$out" && ok "approve refuses without a terminal (every agent shell)" || no "approve refuses without a terminal (every agent shell)" "$out"

out="$(human $'n\n' approve "$gid" 2>&1)"
grep -q 'denied' <<<"$out" && ok "answering no denies" || no "answering no denies" "$out"
[[ -f $A/state/grants/$gid.json ]] && no "a denied request is forgotten" || ok "a denied request is forgotten"

gid="$(agent request AuthKey_ABCDE12345.p8 --reason "release MyApp 1.2.3" --ttl 10m 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
out="$(human $'y\n' approve "$gid" 2>&1)"
grep -q 'release MyApp 1.2.3' <<<"$out" && ok "the human sees the agent's reason" || no "the human sees the agent's reason" "$out"
check "answering yes activates the grant" "$(jq -r .status "$A/state/grants/$gid.json" 2>/dev/null)" "active"
gmount="$(jq -r .mount "$A/state/grants/$gid.json")"
check "the grant workspace holds only the granted item" "$(find "$gmount" -type f | wc -l | tr -d ' ')" "1"
[[ -d $A/mount ]] && no "the full vault is closed again after approval" || ok "the full vault is closed again after approval"
got="$(agent exec "$gid" -- sh -c 'shasum -a 256 < "$KV_AUTHKEY_ABCDE12345_P8"' | awk '{print $1}')"
check "exec hands the command the real key by path" "$got" "$(shasum -a 256 < "$A/keys/AuthKey_ABCDE12345.p8" | awk '{print $1}')"
out="$(agent exec "$gid" -- sh -c 'exit 7' 2>&1)"; rc=$?
check "exec passes the command's exit status through" "$rc" "7"
out="$(agent env "$gid" 2>&1)"
grep -q "^export KV_AUTHKEY_ABCDE12345_P8=" <<<"$out" && ok "env prints the paths for a shell" || no "env prints the paths for a shell"
out="$(agent grants 2>&1)"
grep -q "$gid  active" <<<"$out" && ok "grants lists the loan" || no "grants lists the loan"
for ev in "request $gid" "approve $gid" "exec $gid"; do
    grep -q "$ev" "$A/state/audit.log" && ok "audit log records: ${ev%% *}" || no "audit log records: ${ev%% *}"
done
out="$(agent revoke "$gid" 2>&1)"
[[ -d $gmount ]] && no "revoke removes the workspace" || ok "revoke removes the workspace"
agent exec "$gid" -- true >/dev/null 2>&1 && no "a revoked grant cannot be used" || ok "a revoked grant cannot be used"
grep -q "revoked $gid" "$A/state/audit.log" && ok "audit log records: revoked" || no "audit log records: revoked"

group "Grants: they end on their own"
gid="$(agent request sops-age --reason "short" --ttl 2s 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
out="$(human $'y\n' approve "$gid" 2>&1)"
grep -q 'sops-age  \[both\]' <<<"$out" && ok "approval shows each item's level" || no "approval shows each item's level" "$out"
grep -q 'unlock  Touch ID and your passphrase' <<<"$out" && ok "and what it will ask for" || no "and what it will ask for" "$out"
gmount="$(jq -r .mount "$A/state/grants/$gid.json" 2>/dev/null)"
for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -f $A/state/grants/$gid.json ]] || break; sleep 1; done
[[ -f $A/state/grants/$gid.json ]] && no "the watcher expires a grant on time" || ok "the watcher expires a grant on time"
[[ -n $gmount && ! -d $gmount ]] && ok "and its workspace is gone" || no "and its workspace is gone"
grep -q "expired $gid" "$A/state/audit.log" && ok "audit log records: expired" || no "audit log records: expired"

# The grant record is writable by the grantee; pushing the deadline out must not work.
gid="$(agent request sops-age --reason "tamper" --ttl 2s 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
human $'y\n' approve "$gid" >/dev/null 2>&1
f="$A/state/grants/$gid.json"; jq '.expires_epoch = 4102444800' "$f" > "$f.t" && mv "$f.t" "$f"
for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -f $f ]] || break; sleep 1; done
[[ -f $f ]] && no "editing the record does not extend a grant" || ok "editing the record does not extend a grant"

# The backstop: a grant whose watcher died (crash, sleep) is still swept.
gid="$(agent request client-cert --reason "sweep" --ttl 10m 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
human $'y\n' approve "$gid" >/dev/null 2>&1
pkill -f "_expire $gid" 2>/dev/null
f="$A/state/grants/$gid.json"; jq '.expires_epoch = 1' "$f" > "$f.t" && mv "$f.t" "$f"
agent grants >/dev/null 2>&1
[[ -f $f ]] && no "an overdue grant is swept by the next command" || ok "an overdue grant is swept by the next command"

group "One-shot: the human approves a command, not a key"
agent request sops-age --reason x --run >/dev/null 2>&1 && no "--run without a command is refused" || ok "--run without a command is refused"
out="$(cd "$A" && agent request AuthKey_ABCDE12345.p8 --reason "sign it" --run -- sh -c 'shasum -a 256 < "$KV_AUTHKEY_ABCDE12345_P8"; printf "%s|" "$@"' argv0 "a b" c 2>&1)"
gid="$(grep -oE 'kv-[a-f0-9]{8}' <<<"$out" | head -1)"
grep -q "keyvault result $gid" <<<"$out" && ok "a one-shot request points at 'result'" || no "a one-shot request points at 'result'" "$out"
agent result "$gid" >/dev/null 2>&1 && no "no result before approval" || ok "no result before approval"
out="$(human $'y\n' approve "$gid" 2>&1)"
grep -q 'runs    sh -c' <<<"$out" && ok "the human is shown the exact command" || no "the human is shown the exact command" "$out"
grep -qF "in      $(cd "$A" && pwd)" <<<"$out" && ok "and where it will run" || no "and where it will run" "$out"
check "the one-shot is done" "$(jq -r .status "$A/state/grants/$gid.json" 2>/dev/null)" "done"
check "nothing is left mounted" "$(ls -d "$A"/mount-grant-* 2>/dev/null | wc -l | tr -d ' ')" "0"
got="$(agent result "$gid" 2>/dev/null)"; rc=$?
check "result exits with the command's status" "$rc" "0"
check "the command saw the key" "$(head -1 <<<"$got" | awk '{print $1}')" "$(shasum -a 256 < "$A/keys/AuthKey_ABCDE12345.p8" | awk '{print $1}')"
check "arguments survive intact, spaces and all" "$(tail -1 <<<"$got")" "a b|c|"
agent exec "$gid" -- true >/dev/null 2>&1 && no "a finished one-shot cannot be exec'd" || ok "a finished one-shot cannot be exec'd"
grep -q "run $gid rc=0" "$A/state/audit.log" && ok "audit log records: run" || no "audit log records: run"
# No shell is involved, so keyvault expands $KV_X itself — and only granted names.
gid="$(agent request AuthKey_ABCDE12345.p8 --reason "direct" --run -- shasum -a 256 '$KV_AUTHKEY_ABCDE12345_P8' '${KV_AUTHKEY_ABCDE12345_P8}' 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
human $'y\n' approve "$gid" >/dev/null 2>&1
got="$(agent result "$gid" 2>/dev/null | awk '{print $1}' | sort -u)"
check "\$KV_X and \${KV_X} are expanded without a shell" "$got" "$(shasum -a 256 < "$A/keys/AuthKey_ABCDE12345.p8" | awk '{print $1}')"
gid="$(agent request AuthKey_ABCDE12345.p8 --reason "literal" --run -- printf '%s|' '$KV_NOT_GRANTED' '$HOME' '$KV_AUTHKEY_ABCDE12345_P8X' 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
human $'y\n' approve "$gid" >/dev/null 2>&1
check "anything not granted stays literal" "$(agent result "$gid" 2>/dev/null)" '$KV_NOT_GRANTED|$HOME|$KV_AUTHKEY_ABCDE12345_P8X|'
gid="$(agent request sops-age --reason "fail" --run -- sh -c 'echo nope >&2; exit 3' 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
human $'y\n' approve "$gid" >/dev/null 2>&1
err="$(agent result "$gid" 2>&1 >/dev/null)"; rc=$?
check "a failing one-shot reports its status" "$rc" "3"
check "and its stderr" "$err" "nope"
agent revoke "$gid" >/dev/null 2>&1
[[ -d $A/state/results/$gid ]] && no "revoke deletes a one-shot's output" || ok "revoke deletes a one-shot's output"

group "Hardening: the record is writable by the requester"
agent revoke ../../etc >/dev/null 2>&1 && no "grant ids are validated" || ok "grant ids are validated"
agent exec 'kv-../x' -- true >/dev/null 2>&1 && no "exec validates the id too" || ok "exec validates the id too"
# A forged mount must not steer the teardown at a folder of the attacker's choosing.
mkdir -p "$A/precious"; printf keep > "$A/precious/file"
gid="$(agent request client-cert --reason "forge" --ttl 10m 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
human $'y\n' approve "$gid" >/dev/null 2>&1
realmount="$(jq -r .mount "$A/state/grants/$gid.json")"
f="$A/state/grants/$gid.json"; jq --arg m "$A/precious" '.mount = $m' "$f" > "$f.t" && mv "$f.t" "$f"
agent revoke "$gid" >/dev/null 2>&1
[[ -f $A/precious/file ]] && ok "a forged mount path is never deleted" || no "a forged mount path is never deleted"
rm -rf "$realmount"
# Approval acts on the snapshot it showed, never on a re-read of the (writable) record.
gid="$(agent request client-cert --reason "swap" --run -- sh -c 'echo "$KV_CLIENT_CERT"' 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
out="$(human $'y\n' approve "$gid" 2>&1)"
grep -q 'client-cert' <<<"$out" && [[ $(agent result "$gid" 2>/dev/null) == */client-cert/* ]] \
    && ok "the approved snapshot is what runs" || no "the approved snapshot is what runs" "$out"
grep -q '^  binary  /bin/sh' <<<"$out" && ok "a system binary raises no warning" || no "a system binary raises no warning" "$out"
agent revoke "$gid" >/dev/null 2>&1
printf '#!/bin/sh\necho hi\n' > "$A/tool.sh"; chmod +x "$A/tool.sh"
gid="$(cd "$A" && agent request client-cert --reason "local tool" --run -- "$A/tool.sh" 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
out="$(human $'n\n' approve "$gid" 2>&1)"
grep -q 'agent can write' <<<"$out" && ok "a binary outside system paths is flagged" || no "a binary outside system paths is flagged" "$out"

group "Hardening: expiry does not depend on the record"
for how in blanked deleted; do
    gid="$(agent request client-cert --reason "$how" --ttl 3s 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
    human $'y\n' approve "$gid" >/dev/null 2>&1
    gmount="$(jq -r .mount "$A/state/grants/$gid.json")"
    f="$A/state/grants/$gid.json"
    if [[ $how == blanked ]]; then jq '.mount = "" | .device = ""' "$f" > "$f.t" && mv "$f.t" "$f"; else rm -f "$f"; fi
    for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -d $gmount ]] || break; sleep 1; done
    [[ -d $gmount ]] && no "a ${how} record does not keep keys mounted past expiry" \
                     || ok "a ${how} record does not keep keys mounted past expiry"
done
gid="$(agent request client-cert --reason "orphan" --ttl 10m 2>&1 | grep -oE 'kv-[a-f0-9]{8}' | head -1)"
human $'y\n' approve "$gid" >/dev/null 2>&1
gmount="$(jq -r .mount "$A/state/grants/$gid.json")"
pkill -f "_expire $gid" 2>/dev/null; rm -f "$A/state/grants/$gid.json"
agent grants >/dev/null 2>&1
[[ -d $gmount ]] && no "a workspace with no record is swept" || ok "a workspace with no record is swept"
grep -q "orphaned $gid" "$A/state/audit.log" && ok "audit log records: orphaned" || no "audit log records: orphaned"

group "Grants: the human shortcut"
out="$(human $'y\n' grant client-cert --reason "manual" --ttl 5m 2>&1)"
gid="$(grep -oE 'kv-[a-f0-9]{8}' <<<"$out" | head -1)"
check "grant creates an active loan in one step" "$(jq -r .status "$A/state/grants/$gid.json" 2>/dev/null)" "active"
agent revoke --all >/dev/null 2>&1
check "revoke --all leaves nothing on loan" "$(ls "$A/state/grants" | wc -l | tr -d ' ')" "0"

# ---------------------------------------------------------------------------- ramdisk

group "RAM-disk workspace (the real path, not the fallback)"
if [[ $(uname) == Darwin ]]; then
    out="$(KEYVAULT_NO_RAMDISK=0 KEYVAULT_MOUNT=/Volumes/keyvault-selftest \
           KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; workspace_create")"
    mount_path="${out%%$'\t'*}"; dev="${out##*$'\t'}"
    if [[ -n $dev && -d $mount_path ]]; then
        ok "a RAM disk mounts without sudo"
        mounts="$(mount)"
        grep -q "$mount_path" <<<"$mounts" && ok "the workspace is a real mount" || no "the workspace is a real mount"
        KEYVAULT_LIB=1 "$SHELL_BIN" -c "source '$KV'; workspace_destroy '$mount_path' '$dev'"
        [[ -d $mount_path ]] && no "the RAM disk detaches" || ok "the RAM disk detaches"
    else
        no "a RAM disk mounts without sudo" "got mount=[$mount_path] dev=[$dev]"
    fi
else
    printf '  %s· skipped (not macOS)%s\n' "$D" "$Z"
fi

# ---------------------------------------------------------------------------- report

printf '\n'
if (( FAIL == 0 )); then
    printf '%s%d passed%s\n' "$G" "$PASS" "$Z"
    exit 0
else
    printf '%s%d passed, %d failed%s\n' "$R" "$PASS" "$FAIL" "$Z"
    exit 1
fi
