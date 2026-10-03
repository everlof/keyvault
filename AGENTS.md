# AGENTS.md: working on this repository

This is the source of keyvault. To *use* keyvault as an agent (find a key, ask for one), read
[docs/agents.md](docs/agents.md) instead.

## Ground rules

- **Nothing secret, nothing personal, ever.** No keys, no real key ids, no real paths or
  account names, not even in tests or examples. Use `my-app`, `AuthKey_ABCDE12345`,
  `$HOME/src/…`. `.gitignore` blocks key file types and `keyvault.conf`; don't work around it.
- **Bash 3.2.** No associative arrays, `mapfile`, `${x^^}` or `|&`. The machine being
  restored onto has only stock macOS. Run both test modes.
- **`keyvault` stays one file** and must restore a dead machine on its own. Agent features go
  in `keyvault-access.sh`, watching the machine (scan, checkup, schedule) in
  `keyvault-watch.sh`, the recovery key's QR code (show, print, camera, clipboard) in
  `keyvault-qr.sh` with its camera app in `tools/qr-reader.swift`; recovery must never need
  them, and typing the key must always work without them.
- **Plaintext only on the RAM disk.** Never write a decrypted key anywhere else, including a
  temp file "just for a moment".
- **Every bug fix gets a regression test,** named for what it protects.

## Checks before handing off

```bash
tests/test_keyvault.sh && tests/test_keyvault.sh --bash32
tests/test_secret.sh && tests/test_secret.sh --bash32
gitleaks dir . && gitleaks git .        # if installed
```

The suites never touch the real keychain, config, keys or vault. `test_secret.sh` must never
read an `--ask` item: that raises a dialog on the developer's screen.
