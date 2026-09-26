# keyvault

**Back up the keys you can never get back, unlock them with Touch ID, and let AI agents
use them without handing them over.**

Some keys have no reset button. Lose a Sparkle update-signing key and no installed copy of
your app will ever accept an update again. App Store Connect API keys can be downloaded once.
GitHub App keys are shown once. A SOPS master key decrypts everything its project ever
encrypted. 2FA recovery codes are, by definition, the thing you need when everything else is
gone. These usually live in exactly one place: a keychain, or a loose file in a cloud folder.

keyvault collects them into an `age`-encrypted vault you can copy anywhere. Every item has a
**level**: Touch ID, your passphrase, or both. A **recovery key** on paper opens everything on
a new machine. Coding agents (Claude Code, Codex, …) can find out which keys exist and borrow
one for a single job, with you approving each loan.

It is three small tools, bash and `age` only, for macOS:

| | For | Where secrets live |
|---|---|---|
| **`keyvault`** | keys that cannot be re-issued, recovery codes | an age-encrypted vault; per item Touch ID, passphrase, or both |
| **`secret`** | everyday tokens (API keys, deploy tokens) | the macOS login keychain |
| **`guardrails/`** | stopping agents from simply reading key files | Claude Code / Codex settings |

## Why an encrypted vault, and not just…

- **…plaintext in iCloud Drive?** Every process on every synced machine can read it, and so
  can anyone who gets into your Apple ID.
- **…only the keychain?** One dead SSD or stolen laptop and it is gone. Login-keychain items
  such as signing identities do not sync through iCloud Keychain.

Encrypt once, then copy freely. When the bytes are useless without a key, "where do I keep
it" stops being a security question and becomes a durability question. The answer to that
is always *more copies*.

## Install

```bash
brew install everlof/tap/keyvault      # keyvault and secret, with age, jq and age-plugin-se
keyvault init                # writes ~/.config/keyvault/keyvault.conf from the example
keyvault setup               # creates the keys: Touch ID, passphrase, recovery (on paper)
keyvault edit                # say what to collect, and at which level
keyvault doctor              # check every source is where the config says
keyvault pack                # collect and encrypt; asks for nothing but macOS's Keychain prompts
keyvault verify              # open every level and check every item
```

Working on keyvault itself? `./install.sh` in a checkout links `keyvault` and `secret` into
`~/.local/bin` instead, so edits take effect immediately. Don't mix the two installs: use
one or the other.

## Keys and levels

`keyvault setup` creates three keys, each protecting against something different:

| Key | Unlocked by | Lives | Stops |
|---|---|---|---|
| **biometric** | Touch ID | wrapped by this Mac's Secure Enclave ([age-plugin-se](https://github.com/remko/age-plugin-se)) | someone who learned your passphrase |
| **passphrase** | your passphrase | wrapped with scrypt | an agent on your Mac, which cannot type it |
| **recovery** | you, reading it off paper | **nowhere on any computer** | losing the Mac |

Every item in the vault gets a level:

| Level | Opens everyday with | On a new Mac |
|---|---|---|
| `biometric` | Touch ID | the recovery key |
| `passphrase` | the passphrase | the recovery key |
| `both` | Touch ID **and** the passphrase | the recovery key |

`both` is real layered encryption: an inner layer to the biometric key, an outer layer to
the passphrase key. Every layer is also encrypted to the recovery key.

- **Writing needs only public keys.** `pack`, `add` and `remove` never ask for anything.
- **Reading asks for what the items need, once per command.** A `.p8` costs one touch; a
  Sparkle key at `both` costs a touch and the passphrase.
- **The recovery key is what makes `both` mean something.** Anyone who steals your passphrase
  still needs Touch ID on this Mac, or the paper.

`setup` shows the recovery key once and asks you to confirm its last characters; it is never
written to disk. `keyvault card` prints a sheet to write it on, and `keyvault
recovery-check` tells you later whether the paper copy is right.

## The config

`~/.config/keyvault/keyvault.conf` is plain bash. It names your keys and where they live, so
it stays out of any repository. See [`keyvault.conf.example`](keyvault.conf.example).

```bash
dest "$HOME/Library/Mobile Documents/com~apple~CloudDocs/Keyvault"

sparkle my-app --plist "$HOME/src/my-app/Resources/Info.plist" --level both
identities login.keychain-db --level both                        # every signing identity, as one .p12
glob "$HOME/.appstoreconnect/private_keys" '*.p8'                # biometric, the default
level passphrase                                                 # the default from here on
file "$HOME/.config/sops/age/keys.txt" --id sops-age

meta AuthKey_ABCDE12345.p8 issuer_id=… used_by=my-app            # facts for agents (below)
```

Anything one-off, like recovery codes, goes in with `keyvault add`:

```bash
keyvault add github-recovery-codes --file ~/Downloads/github-recovery-codes.txt --level both
pbpaste | keyvault add apple-id-recovery-key --stdin --level both
keyvault add some-totp-seed --secret --level passphrase        # one line, typed without echo
```

Added items get a file of their own, carry across every future `pack`, and default to
`biometric` unless you say otherwise.

## Is the backup any good?

Two different questions, two commands:

**`keyvault verify`: is the vault itself sound?** It opens every level and checks every item:
Sparkle private keys derive to their recorded public keys, the `.p12` opens with its stored
password, and every file matches its checksum. `verify --recovery` does the same with only the
recovery key, which is the check that matters: can you get in without this Mac?

**`keyvault validate`: does it still describe this machine?** It answers the questions that go
stale. Is there a certificate in the keychain the vault has never seen? A new key in a folder
you glob? A file that changed on disk? And the important one: does the backed-up Sparkle key
still match the `SUPublicEDKey` your shipped app carries? If those disagree, the key you are
guarding is not the one your users' installs accept, and you would find out on release day.
Exit status 0 means it matches, 2 means out of date (run `pack`), and 1 means something is
wrong.

## Restoring onto a new machine

You need the recovery key, and nothing but `age`:

```bash
brew install age
printf '%s\n' 'AGE-SECRET-KEY-1…' > r.txt
cd Keyvault/keyvault
for f in *.age keychain/*.age added/*.age; do
    [ -f "$f" ] || continue
    cp "$f" x; while grep -q 'BEGIN AGE' x; do age -d -i ../r.txt x > y && mv y x; done
    tar -xzf x; mv vault "vault-$(basename "$f" .age)"
done
rm x ../r.txt                 # each vault-*/manifest.json says what is where
```

With the tool, `keyvault restore --recovery` puts everything back. Sparkle keys go into the
keychain, identities are imported, and files are written to their recorded paths and modes. It
is a **dry run** unless you pass `--apply`, and it refuses to overwrite anything that differs
unless you pass `--force`. Then run `keyvault setup` on the new Mac and `pack` again.

## How it handles plaintext

Decrypted keys, and the unwrapped Touch ID and passphrase keys, are only ever written to a
**RAM disk** (`hdiutil attach ram://`, no sudo), which is unmounted when the command exits,
however it exits, and cannot survive a reboot. A temp directory can't make that promise,
because deleting a file on APFS does not overwrite it. If a RAM disk cannot be created,
keyvault falls back to a `700` temp directory and says so loudly.

A pack is all or nothing: if any source fails, nothing on disk changes. Every change first
copies the vault to `archive/`, which keeps the last ten.

Exporting signing identities costs one macOS prompt per private key, every time; "Always
Allow" does not stick for exports. So each `identities` line is sealed in a file of its own
(`keychain/`), and `pack` exports again only when the keychain's identities differ from the
ones in the vault. `pack --refresh` exports anyway. Only valid identities are exported:
expired, revoked and untrusted ones stay behind, and cost no prompt. (That takes python3;
without it, `security export` takes every identity in the keychain.)

## Agents: knowing what exists, borrowing what they need

**What is in there?** Every pack, add and remove updates `catalog.json` next to the vault. It
lists every item's id, level, kind and public facts, and no secrets. `catalog`, `find` and
`describe` also list your tokens (name, description, whether it asks, whether it is backed
up), so an agent has one place to look for anything auth-related. Tokens are listed from keychain
attributes, which never decrypts anything and never raises a dialog. The facts are derived
from the keys themselves:

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
keyvault approve kv-5e6f7a8b      # you: the command, the binary, each item's level; then Touch ID / passphrase
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

Approval decrypts only the files that hold the requested items, so it asks only for what
their levels need. Only the granted items are copied, onto a RAM disk of their own. A detached
watcher unmounts it when the TTL runs out (30 minutes by default, 12 hours at most). The
watcher takes its deadline and location from its own arguments, never from the grant record,
so the grantee cannot extend its loan. Every request, approval, denial, use, revocation and
expiry is logged to `~/.local/state/keyvault/audit.log`.

### What that does and does not protect

**An agent cannot approve its own request.** Its shell has no terminal: it can neither answer
`approve`'s prompt nor type the passphrase.

**Touch ID is the weaker gate against agents.** An agent can run `age` against the biometric
key itself, and a Touch ID dialog appears on your screen that says little about who is asking
or why. Touch the sensor only when *you* just started something. Anything an agent must never
reach on its own belongs at `passphrase` or `both`.

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

**Backed up by keyvault.** `keyvault secret` is `secret` with a backup built in:

```bash
keyvault secret set LOOPIA_API_PASSWORD --ask   # stored in the keychain, and a copy sealed in the vault
keyvault secret rm LOOPIA_API_PASSWORD          # both gone (the vault's archive keeps a copy)
keyvault secret run LOOPIA_API_PASSWORD -- …    # list, run, get: exactly as `secret`
keyvault secret backup                          # once, for tokens stored with plain `secret`
keyvault secret request NAME --desc "…"         # for agents: a dialog asks you for the value
```

`request` is how an agent gets a token it must never see: a macOS dialog asks you to paste
it, and the value goes from the dialog into the keychain and the vault. The dialog shows the
name, the agent's description and which process is asking, and you choose whether agents may
use the token freely or whether every use asks you (the default).

`set` reads the value once and hands it to both, so the backup never reads it back from the
keychain and never raises a dialog, not even for an `--ask` token. The copy sits in
`added/secret-<NAME>.both.age`. `validate` reports a token with no copy, or one changed
behind keyvault's back (every `secret set` renews the item's modification time, which
listing sees without decrypting). `keyvault restore` puts tokens back with `secret set`,
`--ask` and all; one already in the keychain is left alone unless you pass `--force`.

Values reach `security` hex-encoded on stdin, never in argv, so they never show up in `ps`.
`security -i` exits 0 even when its command fails, so every write is verified afterwards. A
replacement parks the new value before it removes the old one, so a failure never loses
both.

## Guardrails

Permission rules and a sandbox, so that "agents can't just read the key files" is enforced
rather than hoped for. Nothing is applied until you pass `--apply`.

```bash
G="$(brew --prefix keyvault)/libexec/guardrails"   # or ./guardrails in a checkout
$G/apply.sh                                 # dry run: every Claude Code profile, permission rules
$G/apply.sh --apply                         # write, backing up each settings.json first
$G/apply.sh --layer sandbox --only ~/.claude           # try the sandbox in one profile
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
keyvault init | setup | edit | doctor | status | card | recovery-check
keyvault pack [--refresh] | list | verify | validate
keyvault secret set NAME [--ask] | rm NAME | backup | run NAME -- <cmd…> | list
keyvault add <id> --file PATH | --secret | --stdin  [--level L] [--desc T] [--meta k=v] [--restore-to P]
keyvault remove <id> | show <id> --out PATH
keyvault restore [--only ID] [--force] [--apply]
    reading commands also take --recovery (the paper key) and --via DEVICE

keyvault catalog | find <text> | describe <id>    asks for nothing, shows no secrets
keyvault request <id>… --reason T [--ttl 30m] [--run -- <cmd…>]
keyvault approve [ID] | grant <id>… --reason T    a human at a terminal
keyvault exec <grant> -- <cmd…> | env <grant> | result <grant>
keyvault grants | revoke <grant> | --all
```

| Variable | |
|---|---|
| `KEYVAULT_CONF` | config file (default `~/.config/keyvault/keyvault.conf`) |
| `KEYVAULT_KEYS` | key directory (default `keys/` next to the config) |
| `KEYVAULT_DEST` | overrides `dest` from the config |
| `KEYVAULT_UNLOCK_VIA` | default for `--via` (default `mac`) |
| `KEYVAULT_SPARKLE_BIN` | directory holding Sparkle's `generate_keys` and `sign_update` (found in DerivedData otherwise) |
| `KEYVAULT_ARCHIVE_KEEP` | earlier versions to keep (default 10) |
| `SECRET_KEYCHAIN` | keychain for `secret` (default: login) |

The test suite also uses `KEYVAULT_SE_IDENTITY`, `KEYVAULT_PASSPHRASE_IDENTITY` and
`KEYVAULT_RECOVERY_IDENTITY` to stand plain age keys in for the Secure Enclave, the passphrase
and the paper. Anyone who can set them does not need keyvault's permission: never set them in
an environment an agent can see.

## Coming next

**Face ID on your iPhone, via Threading.** The biometric key is
one key, wrapped once per device (`keys/biometric.<device>.age`). A paired iPhone becomes one
more wrap. Approving a loan with `--via iphone` sends the request to the phone, you approve it
with Face ID, and the phone unwraps the key for that one command. Nothing is re-encrypted, and
the Mac never waits on a Touch ID sensor you are nowhere near.

## Design notes

- **Bash 3.2.** That is what stock macOS ships, and the machine you are restoring onto will
  not have Homebrew yet. `keyvault` is one file for the same reason; the agent features live
  in `keyvault-access.sh`, which recovery never needs.
- **Three factors, one of them on paper.** The recovery key never touches a computer, so
  stealing your passphrase or your Mac is not enough on its own.
- **Say what you left out.** A config that records, in comments, what was considered and
  rejected is worth as much as the inclusions: it separates "not backed up" from "decided not
  to".

## Tests

```bash
tests/test_keyvault.sh            # the whole lifecycle, on synthetic keys
tests/test_keyvault.sh --bash32   # the same under /bin/bash 3.2
tests/test_secret.sh              # against a throwaway keychain; your login keychain is never touched
```

They never touch your keychain, config, keys or vault, and they behave the same in a
terminal and in CI. Setup, approvals and a real scrypt passphrase run through a pty. Several
cases exist because a real key broke the tool once: a symlinked key, a filename with spaces,
two files claiming one id, a glob over the destination folder, a glob whose single failure
used to be swallowed.

## License

MIT, see [LICENSE](LICENSE).
