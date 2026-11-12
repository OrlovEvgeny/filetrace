#!/usr/bin/env python3
"""A peer that takes what arrives and answers little.

usage: sink.py PORT [--tls none|1.2|1.3|any] [--clientcert] [--mode http|raw|echo]
               [--banner N] [--echo-bytes N] [--reply-at S]
  http: after each complete request (head and Content-Length body) answer 200 with 64 bytes
  raw:  never answer
  echo: answer every read with --echo-bytes bytes
  --banner N sends N bytes as soon as a connection is accepted; --reply-at S sends 4 bytes
  S seconds after the first bytes of a connection arrived.
"""
import argparse
import socket
import ssl
import struct
import threading

TLS = "/opt/ft-acceptance/tls/"

ap = argparse.ArgumentParser()
ap.add_argument("port", type=int)
ap.add_argument("--tls", default="none")
ap.add_argument("--clientcert", action="store_true")
ap.add_argument("--mode", default="http")
ap.add_argument("--banner", type=int, default=0)
ap.add_argument("--echo-bytes", type=int, default=1)
ap.add_argument("--reply-at", type=float, default=0.0)
a = ap.parse_args()

ctx = None
if a.tls != "none":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(TLS + "server.pem", TLS + "server.key")
    if a.tls == "1.2":
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif a.tls == "1.3":
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if a.clientcert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(TLS + "ca.pem")


def handle(c):
    total = 0
    try:
        if a.banner:
            c.sendall(b"x" * a.banner)
        if ctx:
            c = ctx.wrap_socket(c, server_side=True)
        buf = b""
        sent100 = False
        while True:
            d = c.recv(65536)
            if not d:
                break
            total += len(d)
            if a.mode == "echo":
                c.sendall(b"k" * a.echo_bytes)
                continue
            if a.reply_at and total == len(d):
                threading.Timer(a.reply_at, lambda: c.sendall(b"hint")).start()
            if a.mode != "http":
                continue
            buf += d
            while True:
                i = buf.find(b"\r\n\r\n")
                if i < 0:
                    break
                head = buf[:i].lower()
                cl = 0
                for ln in head.split(b"\r\n"):
                    if ln.startswith(b"content-length:"):
                        cl = int(ln.split(b":")[1])
                if b"expect: 100-continue" in head and len(buf) < i + 4 + cl and not sent100:
                    sent100 = True
                    c.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                if len(buf) < i + 4 + cl:
                    break
                buf = buf[i + 4 + cl:]
                sent100 = False
                body = b"x" * 64
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
                if b"connection: close" in head:
                    return
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", a.port))
s.listen(256)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
