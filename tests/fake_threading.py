#!/usr/bin/env python3
# tests only: a stand-in for Threading's Face ID approval socket (see `--via iphone`).
#
#   fake_threading.py <socket> <state-dir>
#
# The phone is this file, told what to do per request by <state>/phone: approve (open the
# envelope — hand back what `wrap` sealed), deny, or wrong (hand back some other key). What the
# phone would have shown for each request is written to <state>/asked.json.
import base64
import json
import os
import socket
import sys

path, state = sys.argv[1], sys.argv[2]


def b64(data):
    return base64.b64encode(data).decode()


def read(name, default=b""):
    try:
        with open(os.path.join(state, name), "rb") as f:
            return f.read()
    except OSError:
        return default


def answer(request):
    op = request.get("op")
    if op == "status":
        return {"ok": True, "enabled": True, "enrolled": True, "fingerprint": "TEST 0000 1111 2222"}
    if op == "wrap":
        # Stands in for the phone's Secure Enclave: only this process can "open" it.
        with open(os.path.join(state, "enclave"), "wb") as f:
            f.write(base64.b64decode(request["secret"]))
        return {"ok": True, "envelope": {"version": 1, "recipient": b64(b"phone-key"),
                                         "ephemeral": b64(b"ephemeral"), "sealed": b64(b"sealed-for-the-phone")}}
    if op == "unwrap":
        with open(os.path.join(state, "asked.json"), "w") as f:
            json.dump({k: request.get(k) for k in ("client", "title", "lines")}, f)
        phone = read("phone", b"approve").decode().strip()
        if phone == "deny":
            return {"ok": False, "error": "denied"}
        if phone == "wrong":
            return {"ok": True, "secret": b64(read("wrong.id"))}
        return {"ok": True, "secret": b64(read("enclave"))}
    return {"ok": False, "error": "malformed"}


server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(4)
while True:
    client, _ = server.accept()
    data = b""
    while not data.endswith(b"\n"):
        chunk = client.recv(65536)
        if not chunk:
            break
        data += chunk
    try:
        reply = answer(json.loads(data))
    except (ValueError, KeyError):
        reply = {"ok": False, "error": "malformed"}
    client.sendall((json.dumps(reply) + "\n").encode())
    client.close()
