#!/usr/bin/env python3
"""Minimal WebLogic admin-console login mock used for local smoke testing.

Oracle publishes no anonymously pullable WebLogic image (the official
`container-registry.oracle.com/middleware/weblogic` repository requires an
Oracle SSO login), so this file reproduces just enough of the console login
contract to exercise the `brute weblogic` module end to end:

- ``GET  /console/login/LoginForm.jsp``   -> 200 (target probe)
- ``POST /console/j_security_check``      -> 302 to ``/console/console.portal``
  when ``j_username``/``j_password`` match, otherwise 302 back to
  ``/console/login/LoginForm.jsp``
- ``GET  /console/console.portal``        -> 200 console HTML when the session
  cookie from a successful login is present, otherwise 302 to the login form
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

USER = "weblogic"
PASSWORD = "Webl0gic-Pass1"
SESSION_COOKIE = "ADMINCONSOLESESSION"

LOGIN_FORM = b"<html><body>WebLogic login</body></html>"
CONSOLE_PAGE = b"<html><body>WebLogic console</body></html>"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body=b"", headers=None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/console/console.portal"):
            cookie = self.headers.get("Cookie", "")
            if SESSION_COOKIE in cookie:
                self._send(200, CONSOLE_PAGE, {"Content-Type": "text/html"})
            else:
                self._send(302, b"", {"Location": "/console/login/LoginForm.jsp"})
            return
        if self.path.startswith("/console/login/LoginForm.jsp"):
            self._send(200, LOGIN_FORM, {"Content-Type": "text/html"})
            return
        self._send(404)

    def do_POST(self):
        if not self.path.startswith("/console/j_security_check"):
            self._send(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        username = form.get("j_username", [""])[0]
        password = form.get("j_password", [""])[0]
        if username == USER and password == PASSWORD:
            self._send(
                302,
                b"",
                {
                    "Location": "/console/console.portal",
                    "Set-Cookie": f"{SESSION_COOKIE}=ok; Path=/",
                },
            )
        else:
            self._send(302, b"", {"Location": "/console/login/LoginForm.jsp"})

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 7001), Handler).serve_forever()
