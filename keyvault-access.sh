# keyvault-access.sh — sourced by keyvault. Lets an agent see what the vault holds and
# borrow specific items for a bounded time, with a human approving each loan.
#
#   anyone, no passphrase:   catalog · find · describe · request · grants · revoke
#                            (catalog, find and describe cover the `keyvault secret` tokens too)
#   human at a terminal:     approve · grant             (Touch ID and/or passphrase, per level)
#   holder of a live grant:  exec · env
#   after a one-shot run:    result
#
# Two shapes of loan. A *grant* puts the items on a RAM disk for a TTL. A *one-shot*
# (`request … --run -- <cmd>`) shows the human the exact command, runs it once inside
# the approval, wipes everything, and leaves only its output — the key never exists
# outside a command the human read and accepted.
#
# The human is the boundary. An agent has no /dev/tty, so it can neither answer the
# approval prompt nor type the passphrase; Touch ID is a dialog it can raise but not
# answer — which is why `both` exists for the keys that matter most; everything it can do alone is read public
# metadata and file a request. What an approved grant hands over is a RAM disk holding
# only the granted items, which unmounts itself when the grant expires or is revoked.
#
# What this is not: a sandbox. A process running as you can read a granted file while
# the grant lives. The guarantees are scope (only those items), time (the TTL), a human
# decision per loan, and an audit trail — not isolation from a hostile process.

readonly KV_GRANTS="$KV_STATE/grants"
readonly KV_RESULTS="$KV_STATE/results"
readonly KV_AUDIT="$KV_STATE/audit.log"
readonly KV_TTL_DEFAULT="${KEYVAULT_TTL_DEFAULT:-30m}"
readonly KV_TTL_MAX=43200                                              # 12 h
readonly KV_GRANT_SECTORS="${KEYVAULT_GRANT_SECTORS:-20480}"           # 10 MB

# ---------------------------------------------------------------------------- helpers

epoch() { date -u +%s; }

ttl_seconds() {   # 90 · 90s · 30m · 2h
    [[ $1 =~ ^([0-9]+)([smh]?)$ ]] || return 1
    local n="${BASH_REMATCH[1]}"
    case "${BASH_REMATCH[2]}" in
        h) n=$((n * 3600)) ;;
        m) n=$((n * 60)) ;;
    esac
    (( n > 0 && n <= KV_TTL_MAX )) || return 1
    printf '%s\n' "$n"
}

human_duration() {
    local s="$1"
    if (( s >= 3600 )); then printf '%dh%02dm' $((s / 3600)) $((s % 3600 / 60))
    elif (( s >= 60 )); then printf '%dm' $((s / 60))
    else printf '%ds' "$s"; fi
}

env_name() {   # env_name <item-id>  ->  KV_<ID>, shell-safe
    printf 'KV_%s\n' "$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9\n' '_')"
}

audit() {
    mkdir -p "$KV_STATE"
    printf '%s %s\n' "$(now_utc)" "$*" >> "$KV_AUDIT"
    chmod 600 "$KV_AUDIT" 2>/dev/null
}

catalog_require() {
    [[ -f $KV_CATALOG ]] && return 0
    die "no catalog at $(tildify "$KV_CATALOG") — the vault has not been packed (ask the user to run 'keyvault pack')"
}

# One place to look: the vault's items and the tokens `secret` keeps. Tokens are listed
# live and never read; `backup` says whether the vault holds a current copy (current),
# an older one (stale) or none. A token's copy is shown as the token, not twice.
tokens_items() {
    local copies
    copies="$(jq -c '[.items[]? | select(.meta.token) | {t: .meta.token, c: (.meta.changed // "")}]' "$KV_CATALOG" 2>/dev/null)"
    [[ -n $copies ]] || copies='[]'
    tokens_list | jq -c --argjson b "$copies" 'map(. as $k | {id: .name, type: "token", kind: "token",
        level: (if .ask then "ask" else "run" end), desc,
        backup: (if any($b[]; .t == $k.name and .c == ($k.changed // "")) then "current"
                 elif any($b[]; .t == $k.name) then "stale" else "none" end)})'
}
all_items() {   # every item an agent may know about, vault first
    local vault='[]'
    [[ -f $KV_CATALOG ]] && vault="$(jq -c '[.items // [] | .[] | select(.meta.token | not)]' "$KV_CATALOG")"
    jq -nc --argjson v "$vault" --argjson t "$(tokens_items)" '$v + $t'
}
something_require() {
    [[ -f $KV_CATALOG ]] && return 0
    [[ $(tokens_items) != "[]" ]] && return 0
    catalog_require
}

grant_file()  { printf '%s/%s.json\n' "$KV_GRANTS" "$1"; }
grant_get()   { jq -r --arg k "$2" '.[$k] // ""' "$(grant_file "$1")" 2>/dev/null; }
grant_set()   {   # grant_set <gid> <jq program> [jq args…]
    local f; f="$(grant_file "$1")"; shift
    jq "$@" "$f" > "$f.new" && mv -f "$f.new" "$f" && chmod 600 "$f"
}
grant_exists() { [[ -f $(grant_file "$1") ]]; }
gid_ok()       { [[ $1 =~ ^kv-[a-f0-9]{8}$ ]]; }
gid_require()  { gid_ok "$1" || die "not a grant id: '$1' (they look like kv-1a2b3c4d)"; }
grant_mount_for() {
    if [[ -n ${KEYVAULT_MOUNT:-} ]]; then printf '%s-grant-%s\n' "$KV_MOUNT" "$1"
    else printf '/Volumes/keyvault-grant-%s\n' "$1"; fi
}

# Where a grant's keys are is derived from its id alone, never read from its record: the
# record is writable by whoever holds the grant, and a record that lies about (or simply
# omits) its mount must not be able to keep keys mounted, or point the teardown at another
# folder (rm -rf) or disk (hdiutil detach).
grant_locate() {   # grant_locate <gid> -> "<mount>\t<device>" of its live workspace, if any
    local gid="$1" m d
    for m in "$(grant_mount_for "$gid")" "${TMPDIR:-/tmp}"/keyvault-grant-"$gid".*; do
        m="${m%/}"
        [[ -d $m ]] || continue
        d="$(mount | awk -v m="$m" '$2 == "on" && $3 == m { print $1; exit }')"
        printf '%s\t%s\n' "$m" "$d"
        return 0
    done
    return 1
}

grant_teardown() {   # grant_teardown <gid>
    local ws
    while ws="$(grant_locate "$1")"; do
        workspace_destroy "${ws%%$'\t'*}" "${ws##*$'\t'}"
        [[ -d ${ws%%$'\t'*} ]] && { warn "$1: could not remove ${ws%%$'\t'*}"; return 1; }
    done
    return 0
}

grant_drop() {   # grant_drop <gid> <why>  — unmount, forget, log
    local gid="$1" why="$2"
    gid_ok "$gid" || return 0
    grant_teardown "$gid"
    grant_exists "$gid" || { rm -rf "$KV_RESULTS/$gid"; audit "$why $gid (no record)"; return 0; }
    audit "$why $gid items=$(jq -r '.items | join(",")' "$(grant_file "$gid")" 2>/dev/null)"
    rm -rf "$KV_RESULTS/$gid"
    rm -f "$(grant_file "$gid")"
}

# Expired grants are torn down by their watcher; this catches the ones a crash, sleep or
# reboot left behind. A pending request nobody answered in a day is stale.
grants_sweep() {
    [[ -d $KV_GRANTS ]] || return 0
    local f gid status now; now="$(epoch)"
    for f in "$KV_GRANTS"/*.json; do
        [[ -f $f ]] || continue
        gid="$(basename "$f" .json)"; gid_ok "$gid" || continue
        status="$(grant_get "$gid" status)"
        if [[ $status == active ]]; then
            if (( now >= $(grant_get "$gid" expires_epoch) )); then
                grant_drop "$gid" expired
            elif ! grant_locate "$gid" >/dev/null; then
                grant_drop "$gid" vanished        # rebooted, or ejected by hand
            fi
        elif (( now - $(grant_get "$gid" requested_epoch) > 86400 )); then
            grant_drop "$gid" stale       # unanswered, or a one-shot result nobody collected
        fi
    done
    # A workspace whose record is gone — deleted by hand, or by whoever held the grant —
    # is still keys on disk. Nothing should be mounted that no record accounts for.
    local m
    for m in "$(dirname "$(grant_mount_for kv-00000000)")"/*-grant-kv-* "${TMPDIR:-/tmp}"/keyvault-grant-kv-*; do
        [[ -d $m ]] || continue
        gid="$(basename "$m" | sed -n 's/.*-grant-\(kv-[a-f0-9]\{8\}\).*/\1/p')"
        gid_ok "$gid" && ! grant_exists "$gid" && grant_drop "$gid" orphaned
    done
    return 0
}

item_line() {   # one catalog item -> one line of the table
    jq -r '
        def facts:
            if .kind == "asc-api-key" then "key \(.meta.asc_key_id)" + (if .meta.issuer_id then "  issuer \(.meta.issuer_id)" else "" end)
            elif .type == "sparkle" then "ed25519 \(.public_key)"
            elif .type == "identities" then "\(.certs | length) certs: " + ([.certs[].team_id // empty] | unique | join(","))
            elif .type == "token" then (.desc // "") + ({current: "", stale: "  (backup out of date)", none: "  (no backup)"}[.backup] // "")
            elif .meta.subject then .meta.subject
            elif .meta.age_recipient then .meta.age_recipient
            elif .path then .path
            else "" end;
        [.id, (.level // "?"), .kind, facts] | @tsv' <<<"$1" \
    | awk -F'\t' '{ printf "%-38s %-11s %-20s %s\n", $1, $2, $3, (length($4) > 50 ? substr($4, 1, 47) "..." : $4) }'
}

# ---------------------------------------------------------------------------- read-only

cmd_catalog() {
    something_require
    if [[ ${1:-} == --json ]]; then
        if [[ -f $KV_CATALOG ]]; then jq --argjson t "$(tokens_items)" '. + {tokens: $t}' "$KV_CATALOG"
        else jq -n --argjson t "$(tokens_items)" '{items: [], tokens: $t}'; fi
        return 0
    fi
    if [[ -f $KV_CATALOG ]]; then
        say "$(dim "$(tildify "$KV_CATALOG") — packed $(jq -r '.packed_at // "?"' "$KV_CATALOG"), no secrets in here")"
    fi
    printf '%-38s %-11s %-20s %s\n' ID LEVEL KIND FACTS
    local it
    while IFS= read -r it; do item_line "$it"; done < <(all_items | jq -c '.[]')
    say ""
    say "$(dim "LEVEL: biometric/passphrase/both — a vault item, borrowed with 'keyvault request'.")"
    say "$(dim "       run/ask — a token, used with 'keyvault secret run'; ask: every use asks the user.")"
    say "$(dim "keyvault describe <id> for everything known about one item; keyvault find <text> to search.")"
}

cmd_find() {
    (($#)) || die "usage: keyvault find <text> [--json]"
    something_require
    local q="$1" json=0; [[ ${2:-} == --json ]] && json=1
    local hits
    hits="$(all_items | jq -c --arg q "$q" '.[] | select(tostring | ascii_downcase | contains($q | ascii_downcase))')"
    [[ -n $hits ]] || { info "nothing in the catalog matches '$q'"; return 1; }
    if (( json )); then jq -s . <<<"$hits"; return 0; fi
    local it; while IFS= read -r it; do item_line "$it"; done <<<"$hits"
}

cmd_describe() {
    (($#)) || die "usage: keyvault describe <id>"
    something_require
    local it; it="$(all_items | jq -c --arg id "$1" 'first(.[] | select(.id == $id)) // empty')"
    [[ -n $it ]] || die "no item '$1' in the catalog (keyvault find <text>)"
    jq . <<<"$it"
    if [[ $(jq -r '.type' <<<"$it") == token ]]; then
        say ""
        say "A token. Use it for one command, never print or copy it:"
        say "  keyvault secret run $1 -- <command…>     (\$$1 is set for that command only)"
        say "  keyvault secret run OTHER_NAME=$1 -- …   (under the name the tool expects)"
        [[ $(jq -r '.level' <<<"$it") == ask ]] \
            && say "Every use raises a keychain dialog the user must click: tell them before you run it."
        return 0
    fi
    local var; var="$(env_name "$1")"
    say ""
    say "Once granted, \$$var is the path to it inside 'keyvault exec'."
    case "$(jq -r '.kind' <<<"$it")" in
        asc-api-key)      say "  e.g. xcrun notarytool submit … --key \"\$$var\" --key-id $(jq -r '.meta.asc_key_id' <<<"$it") --issuer $(jq -r '.meta.issuer_id // "<issuer>"' <<<"$it")" ;;
        sparkle-ed25519)  say "  e.g. sign_update --ed-key-file \"\$$var\" MyApp.zip" ;;
        codesign-identities) say "  a .p12; its password is in the file \$${var}_PASSWORD_FILE."
                             say "  (For signing on this Mac you rarely need this: codesign uses the login keychain.)" ;;
    esac
    say "To borrow it:  keyvault request $1 --reason \"what for\" [--ttl 30m]"
}

# ---------------------------------------------------------------------------- request

grant_new_id() { printf 'kv-%s\n' "$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"; }   # bounded read: no SIGPIPE games

# Who is asking: the process chain above us, e.g. "bash<claude<zsh", so the human can tell
# an agent's request from their own.
requester() {
    local by="" pid="$PPID" n=0 c
    while (( n++ < 4 )) && [[ -n $pid && $pid != 1 && $pid != 0 ]]; do
        c="$(ps -o comm= -p "$pid" 2>/dev/null)"; c="$(basename "${c:-?}")"
        by="${by:+$by<}$c"
        pid="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')"
    done
    printf '%s\n' "${by:-?}"
}

grant_record() {   # grant_record <reason> <ttl-seconds> <id>…  -> prints gid
    local reason="$1" ttl="$2"; shift 2
    local id toks; toks="$(tokens_items)"
    for id in "$@"; do
        jq -e --arg id "$id" 'any(.items[]; .id == $id)' "$KV_CATALOG" >/dev/null 2>&1 && continue
        jq -e --arg id "$id" 'any(.[]; .id == $id)' <<<"$toks" >/dev/null \
            && die "'$id' is a token, not a vault item: use it with 'keyvault secret run $id -- <command…>'"
    done
    catalog_require
    for id in "$@"; do
        jq -e --arg id "$id" 'any(.items[]; .id == $id)' "$KV_CATALOG" >/dev/null \
            || die "no item '$id' in the catalog (keyvault find <text>)"
    done
    mkdir -p "$KV_GRANTS"; chmod 700 "$KV_STATE" "$KV_GRANTS" 2>/dev/null
    local gid; gid="$(grant_new_id)"
    local by; by="$(requester)"
    local run='[]'
    (( ${#LOAN_RUN[@]} )) && run="$(jq -nc '$ARGS.positional' --args -- "${LOAN_RUN[@]}")"   # -- or jq eats a -c
    jq -n --arg id "$gid" --arg r "$reason" --argjson ttl "$ttl" --arg t "$(now_utc)" \
        --argjson te "$(epoch)" --arg by "${by:-?}" --argjson run "$run" --arg cwd "$PWD" --args \
        '{id:$id, status:"pending", items:$ARGS.positional, reason:$r, ttl:$ttl,
          requested_at:$t, requested_epoch:$te, requested_by:$by}
         + (if ($run | length) > 0 then {run:$run, cwd:$cwd} else {} end)' "$@" > "$(grant_file "$gid")"
    chmod 600 "$(grant_file "$gid")"
    audit "request $gid items=$(IFS=,; echo "$*") ttl=$ttl by=${by:-?} reason=$(printf '%q' "$reason")"
    printf '%s\n' "$gid"
}

parse_loan_args() {   # sets LOAN_IDS[], LOAN_REASON, LOAN_TTL, LOAN_RUN[]
    LOAN_IDS=(); LOAN_REASON=""; LOAN_TTL="$KV_TTL_DEFAULT"; LOAN_RUN=()
    while (($#)); do
        case "$1" in
            --reason) LOAN_REASON="$2"; shift 2 ;;
            --ttl)    LOAN_TTL="$2"; shift 2 ;;
            --run)    shift; [[ ${1:-} == -- ]] && shift
                      (($#)) || die "--run wants a command: --run -- <command…>"
                      LOAN_RUN=("$@"); break ;;
            -*)       die "unknown option '$1'" ;;
            *)        LOAN_IDS+=("$1"); shift ;;
        esac
    done
    (( ${#LOAN_IDS[@]} )) || die "name at least one item id (keyvault catalog)"
    [[ -n $LOAN_REASON ]] || die "--reason is required: the human approving this reads it"
    LOAN_TTL="$(ttl_seconds "$LOAN_TTL")" || die "--ttl wants e.g. 20m or 2h, at most 12h"
}

cmd_request() {
    have jq || die "jq is not installed"
    parse_loan_args "$@"
    local gid; gid="$(grant_record "$LOAN_REASON" "$LOAN_TTL" "${LOAN_IDS[@]}")" || exit 1

    if [[ ${KEYVAULT_NO_NOTIFY:-0} != 1 ]] && have osascript; then
        osascript -e "display notification \"$(printf '%s' "$LOAN_REASON" | tr -d '"\\')\" with title \"keyvault: $gid wants ${#LOAN_IDS[@]} key(s)\"" >/dev/null 2>&1 &
    fi
    if (( ${#LOAN_RUN[@]} )); then
        say "Request $gid is pending: run once with ${LOAN_IDS[*]}."
    else
        say "Request $gid is pending: ${LOAN_IDS[*]} for $(human_duration "$LOAN_TTL")."
    fi
    say ""
    say "Ask the user to run this in their own terminal (it needs the vault passphrase):"
    say ""
    say "    keyvault approve $gid"
    say ""
    if (( ${#LOAN_RUN[@]} )); then
        say "Then collect the output:      keyvault result $gid"
    else
        say "Then run your commands with:  keyvault exec $gid -- <command…>"
        say "And give it back when done:   keyvault revoke $gid"
    fi
}

# ---------------------------------------------------------------------------- tokens from the user
#
# `keyvault secret request NAME --desc TEXT`: an agent needs a token it must never see. A macOS
# dialog asks the user to paste it, and the value goes from the dialog straight into the
# keychain and the vault's copy; the agent is told only that it was stored. The user also
# decides whether agents may use it freely or whether every use asks them (the default).

token_dialog() {   # token_dialog <name> <desc> <requester> <replaces?> -> "<button>\n<value>"
    if [[ -n ${KEYVAULT_DIALOG:-} ]]; then "$KEYVAULT_DIALOG" "$@"; return; fi   # tests
    # The agent's text reaches AppleScript as arguments, never as code.
    osascript - "$@" <<'AS' 2>/dev/null
on run argv
    set {nm, ds, who, ex} to {item 1 of argv, item 2 of argv, item 3 of argv, item 4 of argv}
    set msg to "An agent (" & who & ") asks you to store a token:" & return & return & nm & " — " & ds & return & return & "Paste or type its value. It goes straight into your keychain, with a copy in keyvault. The agent never sees it."
    if ex is not "" then set msg to msg & return & return & "This REPLACES the current " & nm & "."
    set r to display dialog msg with title "keyvault" default answer "" with hidden answer buttons {"Cancel", "Agents may use it", "Ask me every use"} default button 3 cancel button 1 with icon caution giving up after 300
    if gave up of r then return ""
    return (button returned of r) & linefeed & (text returned of r)
end run
AS
}

secret_request() {
    local sb="$1"; shift
    (($#)) || die "usage: keyvault secret request NAME --desc \"what it is, what it is for\""
    local name="$1"; shift
    local desc="" by out button v ask replaces=""
    while (($#)); do
        case "$1" in
            --desc) desc="$2"; shift 2 ;;
            *) die "secret request: unknown option '$1'" ;;
        esac
    done
    [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "'$name' is not a valid name (letters, digits, _)"
    [[ -n $desc ]] || die "--desc is required: the user reads it in the dialog"
    [[ -n ${KEYVAULT_DIALOG:-} ]] || have osascript || die "no macOS dialog to ask the user with"
    tokens_list | jq -e --arg n "$name" 'any(.[]; .name == $n)' >/dev/null && replaces=1
    by="$(requester)"
    info "Asking the user for $name in a dialog on their screen…"
    out="$(token_dialog "$name" "$desc" "$by" "$replaces")" || { audit "token-request $name by=$by cancelled"; die "the user cancelled"; }
    [[ -n $out ]] || { audit "token-request $name by=$by unanswered"; die "no answer within 5 minutes"; }
    # "<button>\n<value>"; an empty value loses its newline to the command substitution.
    button="${out%%$'\n'*}"; v=""; [[ $out == *$'\n'* ]] && v="${out#*$'\n'}"; out=""
    [[ -n $v ]] || { audit "token-request $name by=$by empty"; die "nothing was entered"; }
    [[ $button == "Agents may use it" ]] && ask=0 || ask=1
    token_store "$sb" "$name" "$ask" "$desc" "$v"; local rc=$?
    v=""
    (( rc )) && { audit "token-request $name by=$by failed"; return 1; }
    audit "token-request $name by=$by stored$( ((ask)) && echo ' ask')"
    if (( ask )); then say "$name is stored. Every use asks the user: keyvault secret run $name -- <command…>"
    else say "$name is stored. Use it with: keyvault secret run $name -- <command…>"; fi
}

# ---------------------------------------------------------------------------- approve

require_human() {
    # No controlling terminal means no human to ask. That is every agent shell.
    { exec 3</dev/tty; } 2>/dev/null || die "$1 needs a human at a terminal — run it yourself, not through an agent"
}

confirm_tty() {
    local a
    printf '%s [y/N] ' "$1" >/dev/tty
    IFS= read -r a <&3 || return 1
    [[ $a == y || $a == Y || $a == yes ]]
}

# Approval works from one snapshot of the request, REC, read once and shown to the human.
# The file on disk is writable by the requester; re-reading it after "y" would let the
# items or command change between what was shown and what runs.

grant_stage() {   # decrypt, copy just REC's items onto their own RAM disk
    # Sets STAGE_MOUNT, STAGE_DEV, STAGE_ENV (json {VAR: path}).
    local gid="$1"
    # Decrypts only the files holding these items, so a loan asks only for the factors
    # its items' levels need: one Touch ID for a biometric .p8, both for a Sparkle key.
    # shellcheck disable=SC2046
    vault_load $(jq -r '.items[]' <<<"$REC")
    local ws mount dev
    ws="$(workspace_create "$(grant_mount_for "$gid")" "$KV_GRANT_SECTORS")" || return 1
    mount="${ws%%$'\t'*}"; dev="${ws##*$'\t'}"

    local env='{}' id it src dst var
    for id in $(jq -r '.items[]' <<<"$REC"); do
        it="$(mf_item "$id")"
        if [[ -z $it ]]; then
            workspace_destroy "$mount" "$dev"; ws_close
            die "'$id' is in the catalog but not in the vault — the catalog is stale; run 'keyvault pack'"
        fi
        src="$(session_dir)/$(jq -r '.file' <<<"$it")"
        mkdir -p "$mount/$id"
        dst="$mount/$id/$(basename "$src")"
        cp "$src" "$dst" && chmod 600 "$dst" || { workspace_destroy "$mount" "$dev"; ws_close; die "copy of $id failed"; }
        var="$(env_name "$id")"
        env="$(jq -c --arg k "$var" --arg v "$dst" '. + {($k): $v}' <<<"$env")"
        if [[ $(jq -r '.type' <<<"$it") == identities ]]; then
            ( umask 077; jq -r '.p12_password' <<<"$it" > "$mount/$id/password" )
            env="$(jq -c --arg k "${var}_PASSWORD_FILE" --arg v "$mount/$id/password" '. + {($k): $v}' <<<"$env")"
        fi
    done
    ws_close        # the decrypted vault is gone before anything is handed out
    STAGE_MOUNT="$mount"; STAGE_DEV="$dev"; STAGE_ENV="$env"
}

grant_materialize() {   # stage, then leave it mounted for the TTL
    local gid="$1" ttl="$2"
    grant_stage "$gid" || return 1
    local mount="$STAGE_MOUNT" dev="$STAGE_DEV" env="$STAGE_ENV"
    local now; now="$(epoch)"
    grant_set "$gid" --arg m "$mount" --arg d "$dev" --argjson env "$env" \
        --arg t "$(now_utc)" --argjson exp $((now + ttl)) --argjson ttl "$ttl" \
        --arg expt "$(date -u -r $((now + ttl)) +%Y-%m-%dT%H:%M:%SZ)" \
        '.status = "active" | .mount = $m | .device = $d | .env = $env | .ttl = $ttl
         | .approved_at = $t | .expires_epoch = $exp | .expires_at = $expt'

    # The watcher is what makes the TTL real: it unmounts on time even if nobody ever
    # runs keyvault again. grants_sweep is only the backstop.
    # Fully detached: holding the approver's terminal open would keep it from closing.
    # The deadline is passed in, not re-read: the record is writable by the grantee.
    nohup "${BASH:-bash}" "$KV_ROOT/keyvault" _expire "$gid" $((now + ttl)) </dev/null >/dev/null 2>&1 3<&- &
    disown 2>/dev/null || true
}

grant_argv() {   # fills RUN_ARGV[] from REC, NUL-safe
    RUN_ARGV=()
    local a
    while IFS= read -r -d '' a; do RUN_ARGV+=("$a"); done \
        < <(jq -j '.run[]? | (., "\u0000")' <<<"$REC")
}
rec() { jq -r --arg k "$1" '.[$k] // ""' <<<"$REC"; }

grant_run_once() {   # stage, run the approved command, wipe, keep only its output
    local gid="$1"
    grant_argv
    local cwd; cwd="$(rec cwd)"
    [[ -d $cwd ]] || die "the request's directory $cwd no longer exists"
    grant_stage "$gid" || return 1

    local res="$KV_RESULTS/$gid" rc k
    mkdir -p "$res"; chmod 700 "$KV_RESULTS" "$res"
    step "Running once"
    (
        cd "$cwd" || exit 97
        for k in $(jq -r 'keys[]' <<<"$STAGE_ENV"); do
            export "$k=$(jq -r --arg k "$k" '.[$k]' <<<"$STAGE_ENV")"
        done
        export KEYVAULT_GRANT="$gid"
        # No shell runs the command, so expand $KV_X / ${KV_X} here — granted names only;
        # anything else is left exactly as the human read it.
        local argv=() a
        for a in "${RUN_ARGV[@]}"; do
            argv+=("$(perl -e '$_ = shift; s/\$\{(KV_\w+)\}|\$(KV_\w+)/my $n = $1 \/\/ $2; exists $ENV{$n} ? $ENV{$n} : $&/ge; print' -- "$a")")
        done
        exec "${argv[@]}" </dev/null 3<&-
    ) > "$res/stdout" 2> "$res/stderr"
    rc=$?
    workspace_destroy "$STAGE_MOUNT" "$STAGE_DEV"
    chmod 600 "$res"/*

    grant_set "$gid" --argjson rc "$rc" --arg t "$(now_utc)" \
        '.status = "done" | .exit = $rc | .approved_at = $t | .finished_at = $t'
    audit "run $gid rc=$rc cmd=$(basename "${RUN_ARGV[0]}")"

    [[ $rc == 0 ]] && ok "exit 0" || bad "exit $rc"
    local f
    for f in stdout stderr; do
        [[ -s $res/$f ]] || continue
        say "$(dim "── $f (last 10 lines) ──")"
        tail -n 10 "$res/$f"
    done
    note "keys wiped; the agent can collect this with: keyvault result $gid"
}

approve_one() {   # approve_one <gid> [ttl-override]
    local gid="$1" ttl="${2:-}"
    gid_require "$gid"
    grant_exists "$gid" || die "no request '$gid' (keyvault grants)"
    REC="$(jq -c . "$(grant_file "$gid")" 2>/dev/null)" || die "$gid: unreadable record"
    [[ $(rec status) == pending ]] || die "$gid is not pending"
    [[ -n $ttl ]] || ttl="$(rec ttl)"
    [[ $(rec id) == "$gid" ]] || die "$gid: record does not match its name"

    local oneshot=0; jq -e '.run' <<<"$REC" >/dev/null 2>&1 && oneshot=1

    say "${C_BOLD}$gid${C_RESET}  requested $(rec requested_at) by $(rec requested_by)"
    say "  reason  $(rec reason)"
    if (( oneshot )); then
        grant_argv
        local bin; bin="$(cd "$(rec cwd)" 2>/dev/null && type -P "${RUN_ARGV[0]}")"
        say "  runs    ${C_BOLD}$(printf '%q ' "${RUN_ARGV[@]}")${C_RESET}"
        say "  binary  ${bin:-${RUN_ARGV[0]} (not found on PATH)}"
        say "  in      $(rec cwd)"
        say "  once    keys exist only while this command runs, then are wiped"
        case "$bin" in
            /usr/*|/bin/*|/sbin/*|/System/*|/Applications/*|/Library/*|/opt/homebrew/*) ;;
            *) say "  ${C_YELLOW}!${C_RESET}       that binary lives where an agent can write — check it before saying yes" ;;
        esac
    else
        say "  for     $(human_duration "$ttl")"
    fi
    local id
    local lv levels=""
    for id in $(jq -r '.items[]' <<<"$REC"); do
        lv="$(jq -r --arg id "$id" '.items[] | select(.id == $id) | .level // "?"' "$KV_CATALOG")"
        levels="$levels $lv"
        say "  item    $id  [$lv]  $(dim "$(jq -r --arg id "$id" '.items[] | select(.id == $id) | .desc // ""' "$KV_CATALOG")")"
    done
    local asks=""
    case "$levels" in *both*|*biometric*) asks="Touch ID" ;; esac
    case "$levels" in *both*|*passphrase*) asks="${asks:+$asks and }your passphrase" ;; esac
    [[ -n $asks ]] && say "  unlock  $asks"
    if ! confirm_tty "Grant this?"; then
        grant_drop "$gid" denied
        say "denied"
        return 1
    fi
    printf '%s\n' "$REC" > "$(grant_file "$gid")"     # the record is now what was approved
    if (( oneshot )); then
        audit "approve $gid once"
        grant_run_once "$gid" || { grant_drop "$gid" failed; die "run failed"; }
        return 0
    fi
    grant_materialize "$gid" "$ttl" || { grant_drop "$gid" failed; die "grant failed"; }
    audit "approve $gid ttl=$ttl"
    ok "$gid active until $(grant_get "$gid" expires_at) — tell the agent it can proceed"
}

cmd_approve() {
    local gid="" ttl=""
    while (($#)); do
        case "$1" in
            --ttl) ttl="$(ttl_seconds "$2")" || die "--ttl wants e.g. 20m or 2h, at most 12h"; shift 2 ;;
            --via) KV_VIA="$2"; shift 2 ;;
            -*)    die "approve: unknown option '$1'" ;;
            *)     gid="$1"; shift ;;
        esac
    done
    require_human approve
    grants_sweep
    if [[ -z $gid ]]; then
        # No id: walk every pending request, oldest first.
        local f n=0
        for f in $(ls -tr "$KV_GRANTS"/*.json 2>/dev/null); do
            gid="$(basename "$f" .json)"
            [[ $(grant_get "$gid" status) == pending ]] || continue
            n=$((n + 1)); approve_one "$gid" "$ttl"; say ""
        done
        (( n )) || say "nothing pending"
        return 0
    fi
    approve_one "$gid" "$ttl"
}

cmd_grant() {   # human shortcut: request + approve in one step
    have jq || die "jq is not installed"
    require_human grant
    parse_loan_args "$@"
    local gid; gid="$(grant_record "$LOAN_REASON" "$LOAN_TTL" "${LOAN_IDS[@]}")" || exit 1
    approve_one "$gid" "$LOAN_TTL"
}

# ---------------------------------------------------------------------------- use

grant_active_or_die() {
    local gid="$1"
    gid_require "$gid"
    grants_sweep
    grant_exists "$gid" || die "no grant '$gid' — it expired, was revoked, or never existed (keyvault grants)"
    case "$(grant_get "$gid" status)" in
        active)  return 0 ;;
        pending) die "$gid is still waiting for approval — ask the user to run: keyvault approve $gid" ;;
        done)    die "$gid was a one-shot run and is finished — keyvault result $gid" ;;
        *)       die "$gid is not usable" ;;
    esac
}

cmd_exec() {
    local gid="${1:-}"; shift || true
    [[ -n $gid && ${1:-} == -- ]] || die "usage: keyvault exec <grant> -- <command…>"
    shift
    (($#)) || die "exec: no command given"
    grant_active_or_die "$gid"
    local k
    for k in $(jq -r '.env | keys[]' "$(grant_file "$gid")"); do
        export "$k=$(jq -r --arg k "$k" '.env[$k]' "$(grant_file "$gid")")"
    done
    export KEYVAULT_GRANT="$gid"
    audit "exec $gid cmd=$(basename "$1")"
    "$@"
}

cmd_env() {
    local gid="${1:-}"
    [[ -n $gid ]] || die "usage: keyvault env <grant>"
    grant_active_or_die "$gid"
    jq -r '.env | to_entries[] | "export \(.key)=\(.value | @sh)"' "$(grant_file "$gid")"
}

cmd_result() {   # result <gid> — the one-shot's stdout/stderr, and its exit status
    local gid="${1:-}"
    [[ -n $gid ]] || die "usage: keyvault result <grant>"
    gid_require "$gid"
    grants_sweep
    grant_exists "$gid" || die "no request '$gid'"
    case "$(grant_get "$gid" status)" in
        done)    ;;
        pending) die "$gid is still waiting for approval — ask the user to run: keyvault approve $gid" ;;
        *)       die "$gid is not a one-shot run" ;;
    esac
    cat "$KV_RESULTS/$gid/stdout" 2>/dev/null
    cat "$KV_RESULTS/$gid/stderr" >&2 2>/dev/null
    audit "result $gid"
    return "$(grant_get "$gid" exit)"
}

cmd_grants() {
    grants_sweep
    local f gid n=0 now; now="$(epoch)"
    for f in "$KV_GRANTS"/*.json; do
        [[ -f $f ]] || continue
        gid="$(basename "$f" .json)"; gid_ok "$gid" || continue; n=$((n + 1))
        if [[ $(grant_get "$gid" status) == done ]]; then
            say "$gid  done      exit $(grant_get "$gid" exit)  $(jq -r '.items | join(" ")' "$f")"
            say "  $(dim "$(grant_get "$gid" reason)  →  keyvault result $gid")"
        elif [[ $(grant_get "$gid" status) == active ]]; then
            say "${C_YELLOW}$gid  active${C_RESET}  $(human_duration $(( $(grant_get "$gid" expires_epoch) - now ))) left  $(jq -r '.items | join(" ")' "$f")"
            say "  $(dim "$(grant_get "$gid" reason)")"
            jq -r '.env | keys[] | "  $" + .' "$f"
        else
            say "$gid  pending   $(jq -r '.items | join(" ")' "$f")"
            say "  $(dim "$(grant_get "$gid" reason)  →  keyvault approve $gid")"
        fi
    done
    (( n )) || say "no grants or requests — nothing is on loan"
}

cmd_revoke() {
    [[ ${1:-} ]] || die "usage: keyvault revoke <grant> | --all"
    if [[ $1 == --all ]]; then
        local f
        for f in "$KV_GRANTS"/*.json; do [[ -f $f ]] && grant_drop "$(basename "$f" .json)" revoked; done
        ok "everything revoked"
        return 0
    fi
    gid_require "$1"
    grant_exists "$1" || die "no grant '$1'"
    grant_drop "$1" revoked
    ok "$1 revoked — its RAM disk is gone"
}

cmd__expire() {   # _expire <gid> <deadline-epoch> — sleep until due, then tear it down
    # Everything this needs is in its arguments and in the grant id. Deleting or editing
    # the record changes nothing: the watcher stops early only once the keys are gone.
    local gid="$1" deadline="$2" left
    gid_ok "$gid" && [[ $deadline =~ ^[0-9]+$ ]] || return 1
    while grant_locate "$gid" >/dev/null; do
        left=$(( deadline - $(epoch) ))
        (( left <= 0 )) && { grant_drop "$gid" expired; return 0; }
        sleep $(( left < 30 ? left : 30 ))
    done
    grant_exists "$gid" && [[ $(grant_get "$gid" status) == active ]] && grant_drop "$gid" expired
    return 0
}

# ---------------------------------------------------------------------------- dispatch

access_main() {
    have jq || die "jq is not installed"
    local cmd="$1"; shift
    case "$cmd" in
        catalog)  cmd_catalog "$@" ;;
        find)     cmd_find "$@" ;;
        describe) cmd_describe "$@" ;;
        request)  cmd_request "$@" ;;
        approve)  cmd_approve "$@" ;;
        grant)    cmd_grant "$@" ;;
        grants)   cmd_grants "$@" ;;
        exec)     cmd_exec "$@" ;;
        env)      cmd_env "$@" ;;
        revoke)   cmd_revoke "$@" ;;
        result)   cmd_result "$@" ;;
        _expire)  cmd__expire "$@" ;;
    esac
}
