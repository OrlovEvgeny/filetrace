#!/usr/bin/env python3
"""usage: peer.py PORT [--heard] [--rcvbuf N] [--rate BYTES_PER_S] [--echo10] [--notify-at N]

A peer for one TCP connection.
  --heard       read a request head and answer it with an empty 200 first
  --rcvbuf N    receive buffer of the listening socket
  --rate R      read no faster than R bytes a second
  --echo10      send 10 B after every chunk received
  --notify-at N send 10 B once, after N bytes were received
"""
import argparse
import socket
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("port", type=int)
ap.add_argument("--heard", action="store_true")
ap.add_argument("--rcvbuf", type=int, default=0)
ap.add_argument("--rate", type=int, default=0)
ap.add_argument("--echo10", action="store_true")
ap.add_argument("--notify-at", type=int, default=0)
a = ap.parse_args()

lsock = socket.socket()
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if a.rcvbuf:
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, a.rcvbuf)
lsock.bind(("127.0.0.1", a.port))
lsock.listen(2)
c, _ = lsock.accept()
if a.heard:
    b = b""
    while b"\r\n\r\n" not in b:
        d = c.recv(4096)
        if not d:
            sys.exit(0)
        b += d
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
total = 0
notified = False
step = 4096 if a.rate else 65536
while True:
    d = c.recv(step)
    if not d:
        break
    total += len(d)
    if a.echo10:
        c.sendall(b"0123456789")
    if a.notify_at and not notified and total >= a.notify_at:
        notified = True
        c.sendall(b"0123456789")
    if a.rate:
        time.sleep(len(d) / a.rate)
