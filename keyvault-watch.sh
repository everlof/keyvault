# keyvault-watch.sh — sourced by keyvault. Watches the machine rather than the vault, so
# that what needs doing reaches you without anyone remembering to look.
#
#   scan [PATH…]                 keys and tokens left in files (gitleaks' rules), never a value
#   checkup [--notify]           what needs doing: dates due, certificates the vault lacks,
#                                Reminders behind, keys that turned up in files since last time
#   schedule on | off | status   the checkup, weekly, as a launchd agent that notifies you
#
# Recovery never needs any of it, which is why it is not in keyvault itself.

readonly KV_SCAN_IGNORE="$(dirname "$KV_CONF")/scan-ignore"
readonly KV_CHECKUP_STATE="$KV_STATE/checkup.json"
readonly KV_SCHEDULE_LABEL="keyvault.checkup"
readonly KV_LAUNCH_AGENTS="${KEYVAULT_LAUNCH_AGENTS:-$HOME/Library/LaunchAgents}"
readonly KV_SCHEDULE_PLIST="$KV_LAUNCH_AGENTS/$KV_SCHEDULE_LABEL.plist"
readonly KV_SCHEDULE_LOG="$KV_STATE/checkup.log"

watch_main() {
    have jq || die "jq is not installed"
    local cmd="$1"; shift
    case "$cmd" in
        scan)     cmd_scan "$@" ;;
        checkup)  cmd_checkup "$@" ;;
        schedule) cmd_schedule "$@" ;;
    esac
}

# ---------------------------------------------------------------------------- scan
#
# Keys and tokens left in files: a .env in Downloads, a token in a note, a key committed to
# a repo. gitleaks finds them; keyvault-scan.py chooses the files (no caches, nothing only
# in the cloud) and says what each finding means. A value is never printed, never stored.

cmd_scan() {
    [[ ${1:-} == ignore ]] && { shift; scan_ignore "$@"; return; }
    local json=0 transcripts=0 roots=() out
    while (($#)); do
        case "$1" in
            --json)        json=1; shift ;;
            --transcripts) transcripts=1; shift ;;
            -*)            die "scan: unknown option '$1'" ;;
            *)             [[ -e $1 ]] || die "scan: no such file or folder: $1"; roots+=("$1"); shift ;;
        esac
    done
    scan_ready || exit 1
    (( ${#roots[@]} )) || roots=("$HOME")
    (( json )) || info "Looking for keys and tokens in $(printf '%s ' "${roots[@]}" | sed "s|$HOME|~|g")— up to ten minutes for a whole home folder…"
    out="$(scan_run "$transcripts" "${roots[@]}")" || exit 1
    (( json )) && { jq . <<<"$out"; scan_status "$out"; return; }
    scan_report "$out"
    scan_status "$out"
}

scan_ready() {
    have gitleaks || { info "keyvault: keyvault scan uses gitleaks to recognise keys: brew install gitleaks"; return 1; }
    have python3 || { info "keyvault: keyvault scan needs python3"; return 1; }
}

scan_run() {   # scan_run <transcripts 0|1> <root>… -> the result as JSON; 1, said on stderr, if it failed
    local transcripts="$1"; shift
    local vp p out rc
    # A finding in a file keyvault already holds is a key where it belongs.
    vp="$(mktemp "${TMPDIR:-/tmp}/keyvault-scan-paths.XXXXXX")" || { info "keyvault: scan: no temporary file"; return 1; }
    { catalog_items | jq -r '.[] | .path // empty'
      catalog_items | jq -r '.[] | .path // empty' | while IFS= read -r p; do resolve_path "$(untildify "$p")"; done
    } > "$vp" 2>/dev/null
    out="$(python3 "$KV_ROOT/keyvault-scan.py" --vault-paths "$vp" --ignore "$KV_SCAN_IGNORE" \
             --own "$KV_KEYS" --own "$KV_STATE" --own "$KV_STORE" --own "$KV_ARCHIVE" \
             --own "$KV_CATALOG" --own "$KV_DEST/README.txt" \
             $( ((transcripts)) && echo --transcripts) -- "$@")"; rc=$?
    rm -f "$vp"
    (( rc == 0 )) || { info "keyvault: scan failed: $(jq -r '.error // empty' <<<"$out" 2>/dev/null)"; return 1; }
    printf '%s\n' "$out"
}

# 2: something to act on. A tool's own config and a file the vault holds are where they
# belong, and on any real machine there are some: counting them would make it always 2.
scan_status() { jq -e 'any(.findings[]; .category | IN("committed", "shell", "loose", "agent"))' <<<"$1" >/dev/null && return 2; return 0; }

scan_report() {   # scan_report <result-json>
    local r="$1" s
    s="$(jq -r '.stats | "\(.files) files (\((.bytes / 1048576) | floor) MB) in \(.walk_seconds + (.scan_seconds // 0) | floor) s"' <<<"$r")"
    say ""
    say "${C_BOLD}Searched $s.${C_RESET} $(dim "Values are never shown.")"
    jq -r '.stats | [ (if .cloud_only > 0 then "\(.cloud_only) only in the cloud (never downloaded to be read)" else empty end),
                      (if .too_big > 0 then "\(.too_big) over 5 MB" else empty end),
                      (if (.ignored // 0) > 0 then "\(.ignored) findings you ignored" else empty end) ]
           | select(length > 0) | "Skipped: " + join(", ")' <<<"$r" | while IFS= read -r l; do dim "$l"; done
    jq -e '.stats.agent_logs_skipped' <<<"$r" >/dev/null && dim "AI agents' conversation logs were skipped: keyvault scan --transcripts"
    scan_unreadable "$r"

    if jq -e '.findings | length == 0' <<<"$r" >/dev/null; then
        say ""; ok "no keys or tokens found"; return 0
    fi

    scan_section committed "${C_RED}COMMITTED TO GIT${C_RESET}" \
        "The value is in the repository's history, and deleting the file does not take it out." \
        "Rotate it (issue a new one, revoke this one), store the new one in keyvault, and read it from there."
    scan_section shell "${C_YELLOW}IN YOUR SHELL SETUP OR HISTORY${C_RESET}" \
        "A profile's export reaches every program you start, agents included; history keeps what was pasted." \
        "Move it into keyvault (keyvault secret set NAME), use it as keyvault secret run NAME -- <cmd>, and delete the line."
    scan_section loose "${C_YELLOW}LYING AROUND${C_RESET}" \
        "A copy in a document, a download, a .env: anything that reads the folder can read it." \
        "Move it into keyvault, then delete it here: keyvault secret set NAME (a token) or keyvault add ID --file PATH (a key file)."
    scan_section agent "${C_YELLOW}SEEN BY AN AI AGENT${C_RESET}" \
        "It was pasted into, or printed into, a conversation, and the agent's log still holds it." \
        "If it still works, rotate it. From now on: keyvault secret request NAME, so no agent sees the value."
    scan_section tool "WHERE A TOOL READS IT" \
        "A config file a command-line tool reads its credentials from: usually fine where it is." \
        "Keep it if it has to be there; if it cannot be re-issued, back it up: keyvault add ID --file PATH."
    local n; n="$(jq '[.findings[] | select(.category == "vault") | .file] | unique | length' <<<"$r")"
    (( n )) && { say ""; ok "$n file$( ((n == 1)) || echo s) keyvault already holds — nothing to do"; }
    say ""
    dim "A false alarm, or fine where it is? keyvault scan ignore <a file or folder, as listed>"
    dim "(one finding alone: its fingerprint, from keyvault scan --json)"
}

scan_section() {   # scan_section <category> <title> <what it means> <what to do>  (reads $r)
    local rows files places
    rows="$(jq -c --arg c "$1" '[.findings[] | select(.category == $c)]' <<<"$r")"
    [[ $rows == "[]" ]] && return 0
    files="$(jq '[.[].file] | unique | length' <<<"$rows")"
    places="$(jq '[.[].place] | unique | length' <<<"$rows")"
    say ""
    say "${C_BOLD}$2${C_RESET} — $(jq length <<<"$rows") in $files file$( ((files == 1)) || echo s)$( ((places < files)) && printf ', %s places' "$places")"
    dim "  $3"
    dim "  $4"
    # One line per place, those holding a recognisable key first: a folder of captures or a
    # source tree is one line, and one 'scan ignore'. Fields split on \x1f, which, unlike a
    # tab, read does not merge when a field is empty.
    jq -r 'def generic: .rule == "generic-api-key";
           group_by(.place) | map({place: .[0].place, n: length, files: ([.[].file] | unique),
               s: (map(select(generic | not)) | length),
               rules: ((map(select(generic | not) | .rule) | unique) + (if any(.[]; generic) then ["generic-api-key"] else [] end)),
               first: (sort_by(.file, .line) | .[0]), wt: (map(.worktrees // 1) | max)})
           | sort_by(-.s, -.n, .place)[]
           | [ (if (.files | length) > 1 then "\(.place)/  (\(.files | length) files)"
                elif .first.line > 0 then "\(.first.file):\(.first.line)" else .first.file end),   # a whole-file rule has no line
               ((.rules[0:6] | join(", ")) + (if (.rules | length) > 6 then ", …" else "" end)),
               (if .n > 1 then "\(.n) findings" else "" end),
               (if .wt > 1 then "the same in \(.wt) worktrees" else "" end) ] | join("\u001f")' <<<"$rows" \
    | head -25 \
    | while IFS=$'\x1f' read -r at rules n wt; do
        printf '  %s\n      %s%s%s\n' "$at" "$rules" "${n:+  · $n}" "${wt:+  · $wt}"
      done
    (( places > 25 )) && note "…and $(( places - 25 )) more places: keyvault scan --json"
    return 0
}

scan_ignore() {   # scan_ignore <FILE:RULE:LINE | path>
    (($#)) || die "usage: keyvault scan ignore <FILE:RULE:LINE as scan printed it, or a file or folder>"
    local x="$1"
    [[ -e $x ]] && x="$(cd "$(dirname "$x")" && pwd)/$(basename "$x")"   # as the walk sees it: links not resolved
    # Written the way scan prints it, with ~ for the home folder: the shell expanded a leading ~,
    # and cd spells $HOME without the // or trailing / it may have been given with.
    local home; home="$(cd "$HOME" 2>/dev/null && pwd)" || home="$HOME"
    x="$(tildify "${x%/}")"
    [[ $x == "$home"/* ]] && x="~${x#"$home"}"
    mkdir -p "$(dirname "$KV_SCAN_IGNORE")"
    awk -v x="$x" '{ sub(/[[:space:]]*#.*/, "") } $0 == x { f = 1 } END { exit !f }' "$KV_SCAN_IGNORE" 2>/dev/null \
        && { ok "already ignored: $x"; return 0; }
    printf '%s    # %s\n' "$x" "$(date +%F)" >> "$KV_SCAN_IGNORE"
    ok "ignored from now on: $x  ($(tildify "$KV_SCAN_IGNORE"))"
}

# Folders the scan was not let into. Run by launchd, the checkup is /bin/bash on its own, and
# macOS keeps Documents, Desktop, Downloads and iCloud Drive from it until it is allowed in.
scan_unreadable() {   # scan_unreadable <result-json>
    local n; n="$(jq '.stats.unreadable // [] | length' <<<"$1")"
    (( n )) || return 0
    warn "$n folder$( ((n == 1)) || echo s) could not be read: $(jq -r '.stats.unreadable[0:3] | join(", ")' <<<"$1")$( ((n > 3)) && echo ", …")"
    note "macOS privacy settings keep them out: System Settings ▸ Privacy & Security ▸ Files and Folders"
}

# ---------------------------------------------------------------------------- checkup
#
# One look at what needs doing. `schedule on` runs it weekly with --notify. It only reads:
# it never unlocks the vault, never exports from the keychain, and never writes to
# Reminders, because a job nobody is watching must not put a prompt on the screen.

cmd_checkup() {
    local notify=0 scan=1
    while (($#)); do
        case "$1" in
            --notify)  notify=1; shift ;;
            --no-scan) scan=0; shift ;;
            *) die "usage: keyvault checkup [--notify] [--no-scan]" ;;
        esac
    done
    local todo=() items due n lacks l
    say "${C_BOLD}keyvault checkup${C_RESET}  $(dim "$(date '+%Y-%m-%d %H:%M')")"

    if items="$(expiry_items)"; then
        due="$(expiry_due "$KV_EXPIRY_WARN_DAYS" <<<"$items")"; n="$(jq length <<<"$due")"
        if (( n )); then
            warn "$n expired, due within $KV_EXPIRY_WARN_DAYS days, or with an unreadable date — keyvault expiring"
            jq -r '.[0:8][] | "      \(.expires // "unreadable")  \(.name)"' <<<"$due"
            todo+=("$n expiring")
        else
            ok "nothing expires within $KV_EXPIRY_WARN_DAYS days"
        fi
    else
        bad "cannot read $(tildify "$KV_CATALOG")"; todo+=("catalog unreadable")
    fi

    if reminders_on; then
        if reminders_behind; then warn "Reminders ▸ $KV_REMIND_LIST is behind the vault — keyvault remind"; todo+=("Reminders behind")
        else ok "Reminders ▸ $KV_REMIND_LIST is up to date"; fi
    fi

    lacks="$(identities_unpacked)"
    if [[ -n $lacks ]]; then
        warn "the keychain has certificates the vault lacks (renewed?) — keyvault pack"
        while IFS= read -r l; do note "    $l"; done <<<"$lacks"
        todo+=("keyvault pack")
    fi

    (( scan )) && checkup_scan

    say ""
    if (( ${#todo[@]} )); then
        local msg; msg="$(printf '%s, ' "${todo[@]}")"; msg="${msg%, }"
        (( notify )) && checkup_notify "$msg"
        warn "to do: $msg"
        return 2
    fi
    ok "nothing needs doing"
}

# Keys in files, compared with the last checkup: only what is new is news. A finding is its
# file and rule, not its line, so an edit above it does not make it new again. The first
# checkup records what is there (keyvault scan shows all of it) and reports nothing as new.
checkup_scan() {   # adds to the caller's todo
    local out known prev new n since
    scan_ready 2>/dev/null || { warn "no scan: gitleaks is not installed (brew install gitleaks)"; return 0; }
    if ! out="$(scan_run 0 "$HOME" 2>&1)"; then
        bad "the scan failed: ${out#keyvault: }"; todo+=("scan failed"); return 0
    fi
    known="$(jq -c '[.findings[] | select(.category | IN("committed", "shell", "loose", "agent")) | "\(.file)\t\(.rule)"] | unique' <<<"$out")"
    if [[ -f $KV_CHECKUP_STATE ]]; then
        prev="$(jq -c '.known // []' "$KV_CHECKUP_STATE" 2>/dev/null)"; [[ -n $prev ]] || prev='[]'
        since="$(jq -r '.at // "the last checkup"' "$KV_CHECKUP_STATE" 2>/dev/null)"
        new="$(jq -c --argjson p "$prev" '. - $p' <<<"$known")"; n="$(jq length <<<"$new")"
        if (( n )); then
            warn "$n new key$( ((n == 1)) || echo s) in files since $since — keyvault scan"
            jq -r '.[0:8][] | split("\t") | "      \(.[0])  \(.[1])"' <<<"$new"
            todo+=("$n new in files")
        else
            ok "no new keys in files since $since"
        fi
    else
        ok "scan: $(jq length <<<"$known") findings recorded — from now on only new ones are reported (keyvault scan shows all)"
    fi
    scan_unreadable "$out"
    mkdir -p "$KV_STATE"
    ( umask 077; jq -n --argjson k "$known" --arg t "$(date '+%Y-%m-%d %H:%M')" '{at: $t, known: $k}' > "$KV_CHECKUP_STATE.new" ) \
        && mv -f "$KV_CHECKUP_STATE.new" "$KV_CHECKUP_STATE"
}

# Keychain identities the vault's copy lacks: a certificate renewed since the last pack.
# find-identity lists them without touching a private key, so this never raises a prompt.
identities_unpacked() {
    conf_load soft 2>/dev/null || return 0
    local spec kc have_sha
    for spec in ${KV_SOURCES[@]+"${KV_SOURCES[@]}"}; do
        [[ $(jq -r '.type' <<<"$spec") == identities ]] || continue
        kc="$(jq -r '.keychain' <<<"$spec")"
        have_sha="$(catalog_items | jq -r --arg id "$(identities_id "$spec")" '.[] | select(.id == $id) | .certs[]?.sha1')"
        security find-identity -v "$kc" 2>/dev/null \
            | sed -n 's/^[[:space:]]*[0-9]*)[[:space:]]*\([0-9A-F]\{40\}\) "\(.*\)"$/\1 \2/p' \
            | while read -r sha name; do grep -qx "$sha" <<<"$have_sha" || printf '%s\n' "$name"; done
    done
}

checkup_notify() {   # checkup_notify <what to do>
    if [[ -n ${KEYVAULT_NOTIFY_BIN:-} ]]; then "$KEYVAULT_NOTIFY_BIN" "$1"; return; fi   # tests
    [[ ${KEYVAULT_NO_NOTIFY:-0} == 1 ]] && return 0
    osascript - "$1" <<'AS' >/dev/null 2>&1
on run argv
    display notification (item 1 of argv) with title "keyvault" subtitle "In a terminal: keyvault checkup"
end run
AS
}

# ---------------------------------------------------------------------------- schedule
#
# The checkup as a launchd agent: Mondays at 10:00, or at the next wake if the Mac was
# asleep. It runs this checkout's keyvault (git pull updates it) under stock /bin/bash, with
# the PATH it was scheduled from, so gitleaks, jq and age are found where they were then.
# Niced, with low-priority disk access, but not ProcessType Background: that throttles the
# scan to a few percent of one core, and ten minutes of work took hours.

launchctl_() { if [[ -n ${KEYVAULT_LAUNCHCTL:-} ]]; then "$KEYVAULT_LAUNCHCTL" "$@"; else launchctl "$@"; fi; }   # tests fake it

cmd_schedule() {
    case "${1:-status}" in
        on)     schedule_on ;;
        off)    schedule_off ;;
        status) schedule_status ;;
        *) die "usage: keyvault schedule on | off | status" ;;
    esac
}

schedule_on() {
    have python3 || die "schedule needs python3, to write the launchd plist"
    local domain env='{}' v
    domain="gui/$(id -u)"
    for v in KEYVAULT_CONF KEYVAULT_DEST KEYVAULT_KEYS KEYVAULT_STATE; do
        [[ -n ${!v:-} ]] && env="$(jq -c --arg k "$v" --arg v "${!v}" '. + {($k): $v}' <<<"$env")"
    done
    env="$(jq -c --arg p "$PATH" '. + {PATH: $p}' <<<"$env")"
    mkdir -p "$KV_LAUNCH_AGENTS" "$KV_STATE"
    # plistlib writes the XML: paths hold &, spaces and quotes that XML written by hand would not survive.
    python3 -c '
import json, plistlib, sys
path, label, keyvault, log, env = sys.argv[1:6]
plist = {
    "Label": label,
    "ProgramArguments": ["/bin/bash", keyvault, "checkup", "--notify"],
    "StartCalendarInterval": {"Weekday": 1, "Hour": 10, "Minute": 0},
    "EnvironmentVariables": json.loads(env),
    "StandardOutPath": log, "StandardErrorPath": log,
    "ProcessType": "Standard", "LowPriorityIO": True, "Nice": 10,
}
with open(path, "wb") as f:
    plistlib.dump(plist, f)
' "$KV_SCHEDULE_PLIST" "$KV_SCHEDULE_LABEL" "$KV_ROOT/keyvault" "$KV_SCHEDULE_LOG" "$env" \
        || die "could not write $(tildify "$KV_SCHEDULE_PLIST")"
    launchctl_ bootout "$domain/$KV_SCHEDULE_LABEL" >/dev/null 2>&1      # an older one, if any
    launchctl_ bootstrap "$domain" "$KV_SCHEDULE_PLIST" || die "launchctl would not load $(tildify "$KV_SCHEDULE_PLIST")"
    ok "weekly checkup on: Mondays at 10:00, or when the Mac next wakes — a notification when something needs doing"
    note "log: $(tildify "$KV_SCHEDULE_LOG")    now, by hand: keyvault checkup    stop: keyvault schedule off"
}

schedule_off() {
    launchctl_ bootout "gui/$(id -u)/$KV_SCHEDULE_LABEL" >/dev/null 2>&1
    rm -f "$KV_SCHEDULE_PLIST"
    ok "weekly checkup off"
}

schedule_status() {
    if [[ ! -f $KV_SCHEDULE_PLIST ]]; then note "off — turn on with: keyvault schedule on"; return 0; fi
    if launchctl_ print "gui/$(id -u)/$KV_SCHEDULE_LABEL" >/dev/null 2>&1; then ok "on — Mondays at 10:00 ($(tildify "$KV_SCHEDULE_PLIST"))"
    else warn "written, but not loaded: keyvault schedule on"; fi
    [[ -f $KV_CHECKUP_STATE ]] && note "last checkup scan: $(jq -r '.at' "$KV_CHECKUP_STATE")"
    [[ -f $KV_SCHEDULE_LOG ]] && note "log: $(tildify "$KV_SCHEDULE_LOG")"
    return 0
}
