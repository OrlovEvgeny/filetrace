#!/usr/bin/env python3
"""usage: script_peer.py PORT --listen|--connect --script ACTION[,ACTION...] [--rcvbuf N] [--sndbuf N] [--wait-file PATH]

A peer for one TCP connection that follows a script.
  --listen         wait for the connection (the default is to connect to 127.0.0.1:PORT)
  --wait-file P    with --connect: create the socket now and connect once P exists
Actions:
  recv:N     read until N more bytes arrived     recvany   one read           drain  read until the other side closes
  send:N     send N random bytes                 sleep:S   wait S seconds
  close      close                               rst       close with a reset
The peer ends when the other side closes during a recv."""
import argparse
import os
import socket
import struct
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("port", type=int)
ap.add_argument("--listen", action="store_true")
ap.add_argument("--connect", action="store_true")
ap.add_argument("--script", default="drain")
ap.add_argument("--rcvbuf", type=int, default=0)
ap.add_argument("--sndbuf", type=int, default=0)
ap.add_argument("--wait-file", default="")
a = ap.parse_args()

if a.listen:
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if a.rcvbuf:
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, a.rcvbuf)
    if a.sndbuf:
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, a.sndbuf)
    lsock.bind(("127.0.0.1", a.port))
    lsock.listen(4)
    c, _ = lsock.accept()
else:
    c = socket.socket()
    if a.rcvbuf:
        c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, a.rcvbuf)
    if a.sndbuf:
        c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, a.sndbuf)
    while a.wait_file and not os.path.exists(a.wait_file):
        time.sleep(0.002)
    for _ in range(200):
        try:
            c.connect(("127.0.0.1", a.port))
            break
        except OSError:
            time.sleep(0.05)
    else:
        sys.exit("connect")

for act in a.script.split(","):
    if not act:
        continue
    name, _, arg = act.partition(":")
    try:
        if name == "recv":
            need = int(arg)
            while need > 0:
                d = c.recv(min(need, 65536))
                if not d:
                    sys.exit(0)
                need -= len(d)
        elif name == "recvany":
            if not c.recv(65536):
                sys.exit(0)
        elif name == "send":
            c.sendall(os.urandom(int(arg)))
        elif name == "sleep":
            time.sleep(float(arg))
        elif name == "drain":
            while c.recv(65536):
                pass
        elif name == "rst":
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            c.close()
        elif name == "close":
            c.close()
    except OSError:
        sys.exit(0)
