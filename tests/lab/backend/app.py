"""Tiny WSGI back-end for the discrepant-pair integration lab.

Served by the pinned gunicorn 20.0.4 behind the pinned HAProxy 1.7.9. Responses
are distinct per path so doppelganger's differential-confirmation stage can
observe a smuggled prefix poisoning a following request:

  * ``/``           -> 200 ``path=/``
  * anything else   -> 404 ``path=<path>``

R5: this app never evaluates request content; it only echoes the path.
"""

from __future__ import annotations


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/") or "/"
    if path == "/":
        status = "200 OK"
    else:
        status = "404 Not Found"
    body = ("path=" + path).encode("latin-1", "replace")
    start_response(
        status,
        [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))],
    )
    return [body]
