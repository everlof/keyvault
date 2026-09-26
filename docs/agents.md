# Using keyvault as an agent

This machine keeps its irreplaceable keys in keyvault: Sparkle update keys, code-signing
identities, App Store Connect `.p8` keys, GitHub App keys, the SOPS master key, recovery
codes. You cannot open it, and you should not try. Every item has a level (`biometric`,
`passphrase` or `both`) and only the user can unlock it: with Touch ID, with a passphrase
typed at a terminal, or both.

**Never run `age`, `age-plugin-se` or anything else against `~/.config/keyvault/keys/`.** It
would put a Touch ID dialog on the user's screen that does not say who is asking. That is
the one way to trick them, so don't.

## Find what you need (no permission required)

    keyvault catalog            # every item: id, level, kind, key ids, public keys, expiry
    keyvault find <text>        # e.g. an ASC key id, an app name, a team id
    keyvault describe <id>      # details, the $KV_ variable a grant sets, a usage example

Add `--json` to `catalog`/`find` for machine-readable output.

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

## Everyday tokens: `secret`

API keys and deploy tokens live in the keychain, not in env files or shell profiles:

    secret list                                  # names and descriptions, never values
    secret run SENTRY_AUTH_TOKEN -- sentry-cli …  # in that command's environment only

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

- Set `KEYVAULT_SE_IDENTITY`, `KEYVAULT_PASSPHRASE_IDENTITY` or `KEYVAULT_RECOVERY_IDENTITY`,
  or run `setup`, `show`, `restore`, `verify`, `pack`, `add` or `remove`. Those are the
  user's commands.
- Read `/Volumes/keyvault-*` directly, or copy granted files elsewhere.
- Copy a key into a repo, a `.env`, a log, a chat message or a CI secret without being asked
  to, in so many words.
