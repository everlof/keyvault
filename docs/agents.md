# Using keyvault as an agent

`keyvault catalog` is the one place to look for anything auth- or key-related on this
machine: the vault's keys and the everyday tokens `secret` keeps. It shows what exists,
what it is for and how to use it. It never shows a value, and looking costs nothing.
`keyvault help agents` is the short version of this page.

This machine keeps its irreplaceable keys in keyvault: Sparkle update keys, code-signing
identities, App Store Connect `.p8` keys, GitHub App keys, the SOPS master key, recovery
codes. You cannot open it, and you should not try. Every item has a level (`biometric`,
`passphrase` or `both`) and only the user can unlock it: with Touch ID, with a passphrase
typed at a terminal, or both.

**Never run `age`, `age-plugin-se` or anything else against `~/.config/keyvault/keys/`.** It
would put a Touch ID dialog on the user's screen that does not say who is asking. That is
the one way to trick them, so don't.

## Find what you need (no permission required)

    keyvault catalog            # every key and token: id, level, kind, key ids, public keys, expiry
    keyvault find <text>        # e.g. an ASC key id, an app name, a team id, "loopia"
    keyvault describe <id>      # details, and exactly how to use it

Add `--json` to `catalog`/`find` for machine-readable output.

The LEVEL column says how an item is used:

| Level | What it is | How you use it |
|---|---|---|
| `biometric`, `passphrase`, `both` | a key in the vault | borrow it: `keyvault request` (below) |
| `run` | a token | `keyvault secret run NAME -- <command>` |
| `ask` | a token that asks the user every time | the same, after telling the user |

## First: does it need the vault at all?

For releases on this Mac, usually not. Keychain already does the job without exposing a key:
`codesign` signs with the login keychain, Sparkle's `sign_update` reads its key from the
keychain, and `xcrun notarytool --keychain-profile <name>` notarizes. Use those first.

## One command? Ask for the command, not the key

    keyvault request <id> --reason "…" --run -- <command…>

The user approves that exact command, it runs once, the keys are wiped, and you collect
the output with `keyvault result <grant>`. Write `$KV_<ID>` in single quotes so your shell
leaves it alone; keyvault fills in the path. No shell runs the command, so wrap pipelines
in `sh -c '…'`.

## Everyday tokens: `keyvault secret`

API keys and deploy tokens live in the keychain, not in env files or shell profiles:

    keyvault secret run SENTRY_AUTH_TOKEN -- sentry-cli …  # in that command's environment only
    keyvault secret run TOKEN=SENTRY_AUTH_TOKEN -- …       # under the name the tool expects

(`secret run` is the same thing.) Never `set` or `rm` a token unless the user asked you to.

**Need a token that isn't there?** Don't ask the user to paste it into the chat. Ask for it:

    keyvault secret request LOOPIA_API_PASSWORD --desc "Loopia API password, for the DNS script"

A dialog on the user's screen asks them for the value. It goes from there into the keychain,
with a backup in the vault, and you never see it. They also choose whether you may use it
freely or whether every use asks them first. Then use it with `keyvault secret run`.
Name it the way the tool expects (`UPPER_SNAKE`), and say in `--desc` what it is for.

**Asked to back up a key file?** Seal it as it is, without opening it:

    keyvault add <id> --file ~/Downloads/AuthKey_ABCDE12345.p8 --level both --desc "ASC key for my-app"

Only when the user asks you to. It asks for nothing, and `keyvault catalog` shows it next time.

Items marked `ask` raise a macOS dialog the user must click. If one appears, tell them what
you are running and why. Never use `secret get` in scripts, or print a value.

## Borrow it, for this job only

1. `keyvault request <id>… --reason "<what, specifically>" --ttl <30m>`. Ask for the
   fewest items and the shortest time that will do. The user reads your reason.
2. Tell the user to run `keyvault approve <grant>` in their terminal, then **stop and wait**.
   You cannot approve it yourself, so don't try.
3. `keyvault exec <grant> -- <command>`. Each granted file is available as `$KV_<ID>`:
   uppercase id, non-alphanumerics become `_`. Pass the path to the tool; **never print,
   copy, cat or echo key contents**, and never write them anywhere outside the grant.
4. `keyvault revoke <grant>` as soon as the job is done. Don't leave it to expire.

If the grant expired mid-job, file a new request. Don't ask for a longer TTL up front "just
in case".

## Never

- Set `KEYVAULT_SE_IDENTITY`, `KEYVAULT_PASSPHRASE_IDENTITY`, `KEYVAULT_RECOVERY_IDENTITY`
  or `KEYVAULT_DIALOG`, or run `setup`, `show`, `restore`, `verify`, `validate`, `pack`,
  `remove`, `approve` or `grant`. Those are the user's commands, and several put a Touch ID
  or passphrase prompt on their screen.
- Use `secret get`, or `add --stdin` / `secret set --stdin` with a value you were given.
  A value that passed through you is exposed; use `keyvault secret request`.
- Read `/Volumes/keyvault-*` directly, or copy granted files elsewhere.
- Copy a key into a repo, a `.env`, a log, a chat message or a CI secret without being asked
  to, in so many words.
