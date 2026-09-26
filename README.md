# keyvault

**Back up the keys you can never get back, and let AI agents use them without handing them
over.**

Some keys have no reset button. Lose a Sparkle update-signing key and no installed copy of
your app will ever accept an update again. App Store Connect API keys can be downloaded once.
GitHub App keys are shown once. A SOPS master key decrypts everything its project ever
encrypted. These usually live in exactly one place: a keychain, or a loose file in a cloud
folder.

keyvault collects them into one `age`-encrypted file you can copy anywhere. Separately, it lets
coding agents (Claude Code, Codex, …) find out which keys exist, and borrow one for a single
job, with a human approving each loan.

```
keyvault pack        →  ~/Library/Mobile Documents/com~apple~CloudDocs/Keyvault/keyvault.age
```

It is three small tools, bash and `age` only, for macOS:

| | For | Where secrets live |
|---|---|---|
| **`keyvault`** | keys that cannot be re-issued | one encrypted artifact, passphrase-protected |
| **`secret`** | everyday tokens (API keys, deploy tokens) | the macOS login keychain |
| **`guardrails/`** | stopping agents from simply reading key files | Claude Code / Codex settings |

## Why an encrypted file, and not just…

- **…plaintext in iCloud Drive?** Every process on every synced machine can read it, and so
  can anyone who gets into your Apple ID.
- **…only the keychain?** One dead SSD or stolen laptop and it is gone. Login-keychain items
  such as signing identities do not sync through iCloud Keychain.

Encrypt once, then copy freely. When the bytes are useless without the passphrase, "where do I
keep it" stops being a security question and becomes a durability question. The answer to
that is always *more copies*.

## Install

```bash
brew install age jq
git clone https://github.com/everlof/keyvault && cd keyvault
./install.sh                 # links keyvault and secret into ~/.local/bin
keyvault init                # writes ~/.config/keyvault/keyvault.conf from the example
keyvault edit                # say what to collect
keyvault doctor              # check every source is where the config says
keyvault pack                # collect, encrypt, write the artifact (asks for a passphrase)
```

The passphrase is stored nowhere. Put it in a password manager **and** on paper, in
different places. `keyvault card` prints a recovery sheet to keep with it.

## The config

`~/.config/keyvault/keyvault.conf` is plain bash. It names your keys and where they live, so
it stays out of any repository. See [`keyvault.conf.example`](keyvault.conf.example).

```bash
dest "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Keyvault"

sparkle my-app --plist "$HOME/src/my-app/Resources/Info.plist"   # from the login keychain
identities login.keychain-db                                     # every signing identity, as one .p12
glob "$HOME/.appstoreconnect/private_keys" '*.p8'                # a folder that grows
file "$HOME/.config/sops/age/keys.txt" --id sops-age             # one file

meta AuthKey_ABCDE12345.p8 issuer_id=… used_by=my-app            # facts for agents (below)
```

For anything one-off: `keyvault add NAME --file PATH`, or `keyvault add NAME --secret` to
type a value in. Added items carry across every future `pack`.

## Is the backup any good?

Two different questions, two commands:

**`keyvault verify`: is the artifact itself sound?** Fully offline: no keychain, no
network. It re-derives every Sparkle public key from its stored private key, opens the `.p12`
with its stored password, and checksums every file. Run it on a *different* machine: "my
backup is fine" is a claim worth testing somewhere other than where it was made.

**`keyvault validate`: does it still describe this machine?** It answers the questions
that go stale. Is there a certificate in the keychain the vault has never seen? A new key in a
folder you glob? A file that changed on disk? And the important one: does the backed-up
Sparkle key still match the `SUPublicEDKey` your shipped app carries? If those disagree, the
key you are guarding is not the one your users' installs accept, and you would find out on
release day. Exit status 0 means it matches, 2 means out of date (run `pack`), and 1 means
something is wrong.

## Restoring onto a dead machine

You do not need this tool:

```bash
brew install age
age --decrypt keyvault.age | tar -xzv
cat vault/manifest.json          # what every file is, and where it belongs
```

With the tool, `keyvault restore` puts everything back. Sparkle keys go into the keychain,
identities are imported, and files are written to their recorded paths and modes. It is a
**dry run** unless you pass `--apply`, and it refuses to overwrite anything that differs
unless you pass `--force`.

## How it handles plaintext

Decrypted keys are only ever written to a **RAM disk** (`hdiutil attach ram://`, no sudo),
which is unmounted when the work is done and cannot survive a reboot. A temp directory can't
make that promise, because deleting a file on APFS does not overwrite it. If a RAM disk cannot
be created, keyvault falls back to a `700` temp directory and says so loudly.

A command that fails never reseals the vault, so a broken write cannot replace a good
artifact. The previous ten artifacts are kept in `archive/`.

## Agents: knowing what exists, borrowing what they need

The vault answers two questions for an agent, and neither one hands over the passphrase.

**What is in there?** Sealing the vault also writes `catalog.json` next to it. It lists
every item's id, kind and public facts, and no secrets. The facts are derived from the keys
themselves:

- an App Store Connect key's id
- a certificate's subject and expiry
- the SHA-256 of each private key's *public* half (the fingerprint GitHub and Apple display)
- an age identity's recipient
- each signing identity's team id

The catalog is built from an allowlist, so no hashes of secrets and no `.p12` passwords leave
the vault.

```bash
keyvault catalog                          # the table; --json for machines
keyvault find my-app                      # search ids, descriptions, metadata
keyvault describe AuthKey_ABCDE12345.p8   # one item, plus how it would be used
```

**Run one command with a key: a one-shot.** You approve the exact command, not the key:

```bash
keyvault request sparkle-my-app --reason "sign the 1.4 update" \
    --run -- sign_update --ed-key-file '$KV_SPARKLE_MY_APP' MyApp-1.4.zip
keyvault approve kv-5e6f7a8b      # you: shows the command, the binary it resolves to, the directory
keyvault result kv-5e6f7a8b       # the agent: stdout, stderr, exit status
```

The key exists only while that command runs, then it is wiped. keyvault substitutes
`$KV_…` itself for granted items only, because no shell runs the approved command. The
approval also warns when the binary lives somewhere an agent could have written it.

**Keep a key for a while: a grant.**

```bash
keyvault request AuthKey_ABCDE12345.p8 --reason "notarize 1.4" --ttl 45m
keyvault approve kv-1a2b3c4d
keyvault exec kv-1a2b3c4d -- xcrun notarytool submit MyApp.zip --key "$KV_AUTHKEY_ABCDE12345_P8" …
keyvault revoke kv-1a2b3c4d       # or let it expire
```

Only the granted items are copied, onto a RAM disk of their own, and the full vault is
closed again before anything is handed out. A detached watcher unmounts it when the TTL runs
out (30 minutes by default, 12 hours at most). The watcher takes its deadline and location
from its own arguments, never from the grant record, so the grantee cannot extend its loan.
Every request, approval, denial, use, revocation and expiry is logged to
`~/.local/state/keyvault/audit.log`.

### What that does and does not protect

**What stops an agent approving its own request is the passphrase.** An agent's shell has
no controlling terminal, so it can neither answer `approve`'s prompt nor type the passphrase
`age` asks for. That means an identity file (`KEYVAULT_IDENTITY`, which makes age
non-interactive) must never be visible to an agent.

A grant is **scope, time, a human decision and a record**. It is not a sandbox: while a grant
is live, any process running as you can read the granted files. It protects against an agent
helping itself, keys lingering after the job, and not knowing afterwards what was used. It
does not protect against a hostile process already running as you. For that, see
[guardrails](#guardrails).

[`docs/agents.md`](docs/agents.md) is the page to point agents at.

## `secret`: everyday tokens

API keys and deploy tokens can be re-issued, and they want the opposite trade-off: easy to
use many times a day, but never sitting in a shell profile that every process inherits.

```bash
secret set SENTRY_AUTH_TOKEN --desc "Sentry CLI"       # typed, not echoed (or --stdin)
secret run SENTRY_AUTH_TOKEN -- sentry-cli releases list
secret run TOKEN=OPENAI_API_KEY -- ./script.sh         # under another variable name
secret list                                            # names and descriptions, never values
secret set PROD_DATABASE_URL --ask                     # every read raises the keychain dialog
```

A default item trusts `/usr/bin/security`, so any process running as you can read it without
a prompt. That keeps tokens out of the places they leak from by accident, but it does not
stop someone reading on purpose. An `--ask` item trusts no application, so every read is a
macOS dialog you answer. **Allow** is one-time; **Always Allow** would undo the point.

Values reach `security` hex-encoded on stdin, never in argv, so they never show up in `ps`.
`security -i` exits 0 even when its command fails, so every write is verified afterwards. A
replacement parks the new value before it removes the old one, so a failure never loses
both.

## Guardrails

Permission rules and a sandbox, so that "agents can't just read the key files" is enforced
rather than hoped for. Nothing is applied until you pass `--apply`.

```bash
guardrails/apply.sh                         # dry run: every Claude Code profile, permission rules
guardrails/apply.sh --apply                 # write, backing up each settings.json first
guardrails/apply.sh --layer sandbox --only ~/.claude   # try the sandbox in one profile
```

| Layer | Enforces | Cost |
|---|---|---|
| `claude-permissions.json` | Claude's file tools, and `cat`/`head`/redirects in Bash, cannot read key files; `.env` files, keychain reads, `sops -d`, `secret get` ask first | nothing noticeable |
| `claude-sandbox.json` | the OS blocks every Bash subprocess from key files and strips token env vars | writes are confined to the project and new network domains prompt, so try it before rolling it out |
| `codex.toml` | Codex asks before leaving the workspace | Codex can still *read* everything, so for Codex the protection is that plaintext keys stop existing |

The fragments cover what every Mac has. Your own paths go in
`~/.config/keyvault/guardrails/claude-<layer>.json`, which is merged on top.

Permission rules match command strings, so `python -c 'open(…)'` walks past them. Only the
sandbox holds against that. Rules still stop the accidental read, which is the common case.

## Commands

```
keyvault init | edit | doctor | status
keyvault pack [--fresh] | list | verify | validate | card
keyvault add <id> --file PATH | --secret | --stdin  [--desc T] [--meta k=v] [--restore-to P]
keyvault remove <id> | show <id> --out PATH
keyvault restore [--only ID] [--force] [--apply]
keyvault open | close | abort                     several edits on one passphrase entry

keyvault catalog | find <text> | describe <id>    no passphrase, no secrets
keyvault request <id>… --reason T [--ttl 30m] [--run -- <cmd…>]
keyvault approve [ID] | grant <id>… --reason T    a human at a terminal
keyvault exec <grant> -- <cmd…> | env <grant> | result <grant>
keyvault grants | revoke <grant> | --all
```

| Variable | |
|---|---|
| `KEYVAULT_CONF` | config file (default `~/.config/keyvault/keyvault.conf`) |
| `KEYVAULT_DEST` | overrides `dest` from the config |
| `KEYVAULT_IDENTITY` | an age identity file instead of a passphrase: for automation and tests only, never where an agent can see it |
| `KEYVAULT_SPARKLE_BIN` | directory holding Sparkle's `generate_keys` and `sign_update` (found in DerivedData otherwise) |
| `KEYVAULT_ARCHIVE_KEEP` | previous artifacts to keep (default 10) |
| `SECRET_KEYCHAIN` | keychain for `secret` (default: login) |

## Design notes

- **Bash 3.2.** That is what stock macOS ships, and the machine you are restoring onto will
  not have Homebrew yet. `keyvault` is one file for the same reason; the agent features live
  in `keyvault-access.sh`, which recovery never needs.
- **A passphrase, not an identity file.** An identity file is a second secret that needs its
  own backup, which is the problem this tool exists to solve.
- **Say what you left out.** A config that records, in comments, what was considered and
  rejected is worth as much as the inclusions: it separates "not backed up" from "decided not
  to".

## Tests

```bash
tests/test_keyvault.sh            # the whole lifecycle, on synthetic keys, in identity mode
tests/test_keyvault.sh --bash32   # the same under /bin/bash 3.2
tests/test_secret.sh              # against a throwaway keychain; your login keychain is never touched
```

They never touch your keychain, config or artifact. Several cases exist because a real key
broke the tool once: a symlinked key, a filename with spaces, two files claiming one id, a
glob over the destination folder, a glob whose single failure used to be swallowed.

## License

MIT, see [LICENSE](LICENSE).
