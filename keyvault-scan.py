#!/usr/bin/env python3
"""keyvault scan — find keys and tokens left lying around in files, without reading one out.

gitleaks does the finding (its rules know ghp_, sk-ant-, AKIA, xoxb-, PEM blocks and a
few hundred more). This decides what it looks at, and what a finding means:

  * which files: walked here, not by gitleaks, so caches, build output and toolchains are
    pruned before anything is read, and so is anything iCloud, Google Drive or OneDrive has
    not downloaded (SF_DATALESS): reading those would fetch every file in the cloud.
    gitleaks then scans a folder of symlinks to just the chosen files.
  * never a value: gitleaks runs with --redact, and only file, line and rule ever leave
    this script. The report it writes is deleted before the script returns.
  * what it means: committed to git, lying around, where a tool reads it, seen by an AI
    agent, or already a keyvault item.

Called by `keyvault scan`, which prints the result; JSON on stdout.
"""
import argparse, json, os, shutil, stat, subprocess, sys, tempfile, time

SF_DATALESS = 0x40000000          # sys/stat.h: the contents live in the cloud, not on disk
HOME = os.path.normpath(os.path.expanduser("~"))   # $HOME may be spelled with a // or a trailing /

# Folders never worth reading: rebuilt from elsewhere, and huge.
PRUNE_NAMES = {
    ".git", ".hg", ".svn", "node_modules", "DerivedData", ".build", "Pods", "Carthage",
    ".gradle", ".m2", ".npm", ".pnpm-store", ".yarn", ".cache", ".cargo", ".rustup",
    "venv", ".venv", "site-packages", "__pycache__", ".Trash", ".next", ".nuxt",
    ".terraform", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "xcuserdata",
    ".swiftpm", "SourcePackages", "Caches", "Logs", ".konan", ".elan", ".rubies", ".gem",
    ".pyenv", ".nvm", ".android", ".tizen", "emsdk", ".ollama", ".lima", "conda", ".conda",
    "miniconda3", "anaconda3", ".gk", ".swiftly", "build", "Build", "dist", ".derived-data",
    ".generated", "vendor_imports",
}
PRUNE_SUFFIXES = (".xcarchive", ".app", ".framework", ".xcframework", ".photoslibrary",
                  ".musiclibrary", ".tvlibrary", ".bundle", ".dSYM", ".xcassets", ".lproj",
                  ".noindex", ".xcresult")
# Scanning the whole home folder: trees that are an application's own store, media, or
# downloaded code. ~/Library is left out except for the cloud drives inside it. A folder
# named on the command line is scanned as asked, whatever it is.
PRUNE_HOME = {".Trash", "Applications", "Movies", "Music", "Pictures",
              ".vscode/extensions", ".cursor/extensions", ".antigravity/extensions",
              ".windsurf/extensions", ".vscode-server", ".local/lib", ".local/pipx",
              ".local/share/cursor-agent", "go/pkg"}
INCLUDE_LIBRARY = ("Library/Mobile Documents", "Library/CloudStorage")
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".heic", ".webp", ".ico", ".icns", ".tiff", ".bmp",
    ".mp3", ".m4a", ".wav", ".aiff", ".flac", ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm",
    ".pdf", ".zip", ".gz", ".tgz", ".xz", ".bz2", ".zst", ".7z", ".rar", ".dmg", ".pkg", ".ipa",
    ".apk", ".aab", ".jar", ".o", ".a", ".dylib", ".so", ".dll", ".exe", ".class", ".pyc",
    ".wasm", ".bin", ".dat", ".ttf", ".otf", ".woff", ".woff2", ".sqlite", ".sqlite-shm",
    ".sqlite-wal", ".db", ".db-shm", ".db-wal", ".car", ".nib", ".psd", ".sketch", ".key",
    ".numbers", ".pages", ".xcf", ".blend", ".fbx", ".glb", ".profraw", ".tflite", ".onnx",
    ".pt", ".safetensors", ".gguf", ".npy", ".parquet", ".map", ".rmeta", ".rlib", ".pcm",
    ".d", ".swiftdeps", ".swiftmodule", ".swiftdoc", ".swiftsourceinfo", ".dawg", ".lock",
}
# Where AI agents keep their conversations. A key found there was pasted into, or printed
# into, a chat: the copy on disk matters less than the fact that the agent saw it.
AGENT_HOMES = (".claude", ".codex", ".gemini", ".copilot", ".cursor", ".grok", ".pi", ".antigravity")
AGENT_LOGS = {"projects", "sessions", "archived_sessions", "file-history", "history.jsonl",
              "todos", "shell-snapshots", "shell_snapshots", "paste-cache", "attachments",
              "conversations", "chats", "logs", "tmp", "debug", "jobs"}
AGENT_CODE = {"plugins", "extensions", "conda", "runtime", "statsig", "cache", "worktrees"}
# Every program started from the shell inherits what the profile exports; history keeps
# whatever was pasted into a command. Backups of either (".bash_profile.bak") count too.
SHELL_FILES = (".bash_profile", ".bashrc", ".bash_login", ".profile", ".zshrc", ".zprofile",
               ".zshenv", ".zlogin", ".bash_history", ".zsh_history", ".python_history",
               ".sqlite_history", ".node_repl_history", ".psql_history", ".mysql_history",
               ".bash_sessions", ".zsh_sessions", ".config/fish")


def rel_home(p):
    return os.path.relpath(p, HOME) if p == HOME or p.startswith(HOME + os.sep) else None


def pruned_dir(path, name, home_rules, transcripts):
    if name in PRUNE_NAMES or name.endswith(PRUNE_SUFFIXES) or name.startswith(".tmp"):
        return True
    if name == "worktrees" and os.path.basename(os.path.dirname(path)).startswith(AGENT_HOMES):
        return True                       # an agent's checkouts of a repo that is walked anyway
    r = rel_home(path)
    if not home_rules or r is None:
        return False
    if r in PRUNE_HOME:
        return True
    if r.startswith("Library/") and not any(r == i or r.startswith(i + "/") for i in INCLUDE_LIBRARY):
        return True
    parts = r.split(os.sep)
    if len(parts) == 2 and parts[0].startswith(AGENT_HOMES) and parts[1] in AGENT_CODE:
        return True                       # an agent's downloaded plugins and runtimes: code
    return not transcripts and agent_log(path)


def agent_log(path):
    r = rel_home(path)
    if r is None:
        return False
    parts = r.split(os.sep)
    return (len(parts) >= 2 and parts[0].startswith(AGENT_HOMES) and parts[1] in AGENT_LOGS)


def cache_dir(path):
    """The Cache Directory Tagging Standard: cargo's target/, among others, says so itself."""
    return os.path.exists(os.path.join(path, "CACHEDIR.TAG"))


def walk(roots, farm, max_bytes, transcripts):
    s = {"files": 0, "bytes": 0, "cloud_only": 0, "too_big": 0, "binary": 0, "agent_logs_skipped": False}
    seen = set()
    # A folder macOS privacy settings keep us out of is said, not silently skipped: the
    # scheduled checkup runs as /bin/bash, which Documents and iCloud Drive may refuse.
    unreadable = []

    def refused(err):
        if isinstance(err, PermissionError) and err.filename:
            unreadable.append(tilde(err.filename))
    for root in roots:
        root = os.path.abspath(os.path.expanduser(root))
        home_rules = root == HOME
        s["agent_logs_skipped"] |= home_rules and not transcripts
        if os.path.isfile(root):
            tree = [(os.path.dirname(root), [], [os.path.basename(root)])]
        else:
            tree = os.walk(root, followlinks=False, onerror=refused)
        for dirpath, dirnames, filenames in tree:
            dirnames[:] = [d for d in dirnames if not pruned_dir(os.path.join(dirpath, d), d, home_rules, transcripts)
                           and not cache_dir(os.path.join(dirpath, d))]
            for name in filenames:
                path = os.path.join(dirpath, name)
                if path in seen:
                    continue
                seen.add(path)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
                    continue
                if st.st_flags & SF_DATALESS:
                    s["cloud_only"] += 1
                    continue
                if st.st_size > max_bytes:
                    s["too_big"] += 1
                    continue
                if os.path.splitext(name)[1].lower() in SKIP_EXT:
                    s["binary"] += 1
                    continue
                link = farm + path
                try:
                    os.makedirs(os.path.dirname(link), exist_ok=True)
                    os.symlink(path, link)
                except OSError:
                    continue
                s["files"] += 1
                s["bytes"] += st.st_size
    s["unreadable"] = sorted(set(unreadable))
    return s


# git runs inside whatever repositories the walk turns up, downloaded ones included, and a
# repository's own .git/config can name a program for git to run: core.fsmonitor, on
# ls-files. Command-line -c outranks that config, so switch it off; and take no locks.
GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"]
GIT_ENV = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")


def git(*args, **kw):
    return subprocess.run(GIT + list(args), capture_output=True, env=GIT_ENV, **kw)


class Git:
    """Is a file committed? One `git ls-files` per repository, however many findings it has."""
    def __init__(self):
        self.top = {}
        self.tracked = {}
        self.origins = {}

    def origin(self, top):
        """The repository a worktree belongs to: its worktrees share one history, so one finding."""
        if top not in self.origins:
            try:
                out = git("-C", top, "rev-parse", "--git-common-dir", text=True, timeout=20)
                common = os.path.realpath(os.path.join(top, out.stdout.strip())) if out.returncode == 0 else top
            except (OSError, subprocess.TimeoutExpired):
                common = top
            self.origins[top] = os.path.dirname(common) if os.path.basename(common) == ".git" else common
        return self.origins[top]

    def toplevel(self, d):
        if d not in self.top:
            try:
                out = git("-C", d, "rev-parse", "--show-toplevel", text=True, timeout=20)
                self.top[d] = out.stdout.strip() if out.returncode == 0 else None
            except (OSError, subprocess.TimeoutExpired):
                self.top[d] = None
        return self.top[d]

    def committed(self, path):
        top = self.toplevel(os.path.dirname(path))
        if not top:
            return None
        if top not in self.tracked:
            try:
                out = git("-C", top, "ls-files", "-z", timeout=60)
                self.tracked[top] = {os.path.join(top, f) for f in out.stdout.decode("utf-8", "replace").split("\0") if f}
            except (OSError, subprocess.TimeoutExpired):
                self.tracked[top] = set()
        real_top = os.path.realpath(top)
        p = os.path.join(top, os.path.relpath(os.path.realpath(path), real_top))
        return top if p in self.tracked[top] else None


def category(path, vault_paths, own, git):
    if os.path.realpath(path) in vault_paths or path in vault_paths:
        return "vault", None
    if any(p == o or p.startswith(o + os.sep) for o in own for p in (path, os.path.realpath(path))):
        return "vault", None              # keyvault's own files: sealed items, catalog, keys, state
    repo = git.committed(path)
    if repo:
        return "committed", repo
    if agent_log(path):
        return "agent", None
    r = rel_home(path)
    if r is not None and r.startswith(SHELL_FILES):
        return "shell", None
    if r is not None and r.startswith("."):
        return "tool", None
    return "loose", None


def tilde(p):
    r = rel_home(p)
    return "~/" + r if r not in (None, ".") else p


def place(path, repo):
    """Where a finding is, coarsely enough that one line (and one `scan ignore`) covers a
    whole capture folder or source tree: its repository, else a folder three deep in home
    (five inside ~/Library, where the cloud drives sit)."""
    if repo:
        return tilde(repo)
    r = rel_home(path)
    if r is None:
        return os.path.dirname(path)
    parts = r.split(os.sep)
    depth = 4 if parts[0] == "Library" else 2
    return "~/" + "/".join(parts[:depth]) if len(parts) > depth else "~/" + r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="+")
    ap.add_argument("--gitleaks", default="gitleaks")
    ap.add_argument("--config")
    ap.add_argument("--max-mb", type=int, default=5)
    ap.add_argument("--transcripts", action="store_true")
    ap.add_argument("--vault-paths", default="", help="file: one path per line of keyvault's items")
    ap.add_argument("--ignore", default="", help="file: fingerprints and paths not to report")
    ap.add_argument("--own", action="append", default=[], help="a folder of keyvault's own (keys, state)")
    a = ap.parse_args()

    vault_paths = set()
    if a.vault_paths and os.path.exists(a.vault_paths):
        for line in open(a.vault_paths, encoding="utf-8"):
            p = os.path.expanduser(line.rstrip("\n"))
            if p:
                vault_paths.add(p)
                vault_paths.add(os.path.realpath(p))
    ignored = set()
    if a.ignore and os.path.exists(a.ignore):
        for line in open(a.ignore, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
                ignored.add(line)

    work = tempfile.mkdtemp(prefix="keyvault-scan.")
    os.chmod(work, 0o700)
    try:
        farm = os.path.join(work, "farm")
        report = os.path.join(work, "report.json")
        t0 = time.time()
        stats = walk(a.roots, farm, a.max_mb * 1024 * 1024, a.transcripts)
        stats["walk_seconds"] = round(time.time() - t0, 1)
        raw = []
        if stats["files"]:
            cmd = [a.gitleaks, "dir", farm, "--follow-symlinks", "--redact", "--no-banner",
                   "--log-level", "fatal", "--max-target-megabytes", str(a.max_mb),
                   "--report-format", "json", "--report-path", report, "--exit-code", "0"]
            if a.config:
                cmd += ["--config", a.config]
            t1 = time.time()
            done = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            stats["scan_seconds"] = round(time.time() - t1, 1)
            if done.returncode != 0 or not os.path.exists(report):
                print(json.dumps({"error": "gitleaks failed: " + done.stderr.strip()[-500:]}))
                return 1
            raw = json.load(open(report, encoding="utf-8")) or []

        def is_ignored(shown, fp):
            return fp in ignored or any(shown == i or shown.startswith(i.rstrip("/") + "/") for i in ignored)

        repos = Git()
        own = [o.rstrip("/") for o in a.own]
        entries, groups = [], {}
        for f in raw:
            link = f.get("SymlinkFile") or f.get("File") or ""
            path = link[len(farm):] if link.startswith(farm) else link
            rule = f.get("RuleID", "")
            line = f.get("StartLine", 0)
            shown = tilde(path)
            fp = "%s:%s:%s" % (shown, rule, line)
            cat, repo = category(path, vault_paths, own, repos)
            item = {"file": shown, "line": line, "rule": rule,
                    "description": f.get("Description", ""), "category": cat, "fingerprint": fp,
                    "place": place(path, repo)}
            if not repo:
                entries.append({"item": item, "copies": [(shown, fp)]})
                continue
            item["repo"] = tilde(repo)
            # The same committed line in every worktree of one repository is one finding, named
            # by the main checkout; ignoring any copy of it ignores it.
            origin = repos.origin(repo)
            key = (origin, os.path.relpath(os.path.realpath(path), os.path.realpath(repo)), rule, line)
            if key in groups:
                g = groups[key]
                g["copies"].append((shown, fp))
                if os.path.realpath(repo) == origin:
                    g["item"] = item
                continue
            groups[key] = {"item": item, "copies": [(shown, fp)]}
            entries.append(groups[key])

        findings = []
        for e in entries:
            if any(is_ignored(shown, fp) for shown, fp in e["copies"]):
                stats["ignored"] = stats.get("ignored", 0) + 1
                continue
            if len(e["copies"]) > 1:
                e["item"]["worktrees"] = len(e["copies"])
            findings.append(e["item"])
        findings.sort(key=lambda x: (x["file"], x["line"], x["rule"]))
        print(json.dumps({"roots": [tilde(os.path.abspath(os.path.expanduser(r))) for r in a.roots],
                          "stats": stats, "findings": findings}))
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
