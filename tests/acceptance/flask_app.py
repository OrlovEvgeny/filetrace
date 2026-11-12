#!/usr/bin/env python3
"""A Flask app on 127.0.0.1:18301 whose /file?f=<path> answers with send_file; with &hdr=1
the reply carries the headers of a typical production app."""
from flask import Flask, request, send_file

HEADERS = [
    ("Set-Cookie", "sessionid=abc123def456ghi789jkl; Path=/; HttpOnly; Secure; SameSite=Lax"),
    ("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.example.com; img-src 'self' data:"),
    ("Cache-Control", "public, max-age=3600"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
]

app = Flask(__name__)


@app.after_request
def extra(r):
    if request.args.get("hdr"):
        for k, v in HEADERS:
            r.headers[k] = v
    return r


@app.route("/file")
def file():
    return send_file(request.args["f"])


app.run(host="127.0.0.1", port=18301, threaded=True)
