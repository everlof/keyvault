import os, pty, signal, sys
# tests only: approve/grant read their confirmation from /dev/tty, which a script has not got.
# usage: pty.py "<input>" cmd args...  — runs cmd on a pty, feeds input, relays output
inp = sys.argv[1].encode(); cmd = sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)   # python ignores it; children would inherit that
    os.execvp(cmd[0], cmd)
os.write(fd, inp)
out = b""
while True:
    try: b = os.read(fd, 4096)
    except OSError: break
    if not b: break
    out += b
_, st = os.waitpid(pid, 0)
sys.stdout.write(out.decode(errors="replace").replace("\r", ""))
sys.exit(os.waitstatus_to_exitcode(st))
