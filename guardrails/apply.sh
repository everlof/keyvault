#!/usr/bin/env bash
#
# guardrails/apply.sh — merge the guardrail fragments into every Claude Code profile.
#
#   guardrails/apply.sh                       show what would change (permissions layer)
#   guardrails/apply.sh --layer sandbox       same, for the sandbox layer
#   guardrails/apply.sh --apply               write it (backs up each file first)
#   guardrails/apply.sh --only ~/.claude      one profile instead of all
#
# Arrays are unioned, never replaced, so existing rules survive. Restore a profile with
# the backup path this prints: settings.json.bak-guardrails-<timestamp>.
#
# The fragments here cover what every Mac has (~/.ssh, ~/.aws, sops, App Store Connect).
# Your own paths go in ~/.config/keyvault/guardrails/claude-<layer>.json, same shape;
# it is merged on top when present.
#
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
layer=permissions apply=0 only=""
while (($#)); do
    case "$1" in
        --layer) layer="$2"; shift 2 ;;
        --apply) apply=1; shift ;;
        --only)  only="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 1 ;;
    esac
done
frag="$HERE/claude-$layer.json"
[[ -f $frag ]] || { echo "no layer '$layer' (permissions | sandbox)" >&2; exit 1; }
local_frag="${XDG_CONFIG_HOME:-$HOME/.config}/keyvault/guardrails/claude-$layer.json"
fragjson="$(cat "$frag")"
if [[ -f $local_frag ]]; then
    echo "+ merging your local rules from ${local_frag/#$HOME/~}"
    fragjson="$(jq -n --argjson a "$fragjson" --argjson b "$(cat "$local_frag")" '
        def m($b): . as $a | reduce ($b | keys[]) as $k ($a;
            .[$k] = (($a[$k]) as $x | ($b[$k]) as $y
                     | if ($x|type) == "array" and ($y|type) == "array" then ($x + $y | unique)
                       elif ($x|type) == "object" and ($y|type) == "object" then ($x | m($y))
                       else $y end));
        $a | m($b)')" || { echo "invalid JSON in $local_frag" >&2; exit 1; }
fi

# A profile is a config dir Claude Code has actually used: it has projects/ or settings.json.
profiles=()
if [[ -n $only ]]; then profiles=("${only%/}")
else
    for d in "$HOME/.claude" "$HOME"/.claude-*; do
        [[ -d $d ]] && { [[ -d $d/projects || -f $d/settings.json ]]; } && profiles+=("$d")
    done
fi

MERGE='def m($b): . as $a | reduce ($b | keys[]) as $k ($a;
          .[$k] = (($a[$k]) as $x | ($b[$k]) as $y
                   | if ($x|type) == "array" and ($y|type) == "array" then ($x + $y | unique)
                     elif ($x|type) == "object" and ($y|type) == "object" then ($x | m($y))
                     else $y end));
       m($frag)'

stamp="$(date +%Y%m%d-%H%M%S)"
for p in "${profiles[@]}"; do
    f="$p/settings.json"
    cur='{}'; [[ -s $f ]] && cur="$(cat "$f")"
    new="$(jq --argjson frag "$fragjson" "$MERGE" <<<"$cur")" || { echo "✗ $f: invalid JSON, skipped" >&2; continue; }
    if [[ "$(jq -S . <<<"$cur")" == "$(jq -S . <<<"$new")" ]]; then
        echo "= ${f/#$HOME/~}  already has the $layer layer"; continue
    fi
    echo "~ ${f/#$HOME/~}"
    diff <(jq -S . <<<"$cur") <(jq -S . <<<"$new") | grep '^[<>]' | sed 's/^/    /'
    if (( apply )); then
        [[ -f $f ]] && cp -p "$f" "$f.bak-guardrails-$stamp" && echo "    backup: ${f/#$HOME/~}.bak-guardrails-$stamp"
        printf '%s\n' "$new" > "$f.new" && mv -f "$f.new" "$f" && echo "    written"
    fi
done
(( apply )) || echo; (( apply )) || echo "dry run — nothing written. Add --apply to write."
