/**
 * php2shell-alert — Cloudflare Worker
 * Passive + benign fingerprinting for CVE-2026-109618 / CVE-2026-109619.
 *
 * Ethics: we NEVER send exploit-shaped traffic (no OOM pressure, no "|"
 * injection, no serialized payloads, no memory-corruption probes) to targets.
 * Probes are limited to: 1) a normal GET /, 2) a tiny, well-formed multipart
 * POST (browser-equivalent file-upload attempt) that exercises the
 * session.upload_progress code path without abusing it.
 */

const FIXED = { 2: '8.2.35', 3: '8.3.36', 4: '8.4.27', 5: '8.5.12' };
const EOL_BRANCHES = ['7.4', '8.0', '8.1']; // official source backports exist
const CVE = 'CVE-2026-109618 / CVE-2026-109619';

// ---------- rate limiting (best-effort, per isolate) ----------
const BUCKET_MS = 60_000;
const buckets = new Map(); // key -> [windowStart, count, ...targetHostTimestamps]

function rateLimited(clientIP, target) {
  const now = Date.now();
  let b = buckets.get(clientIP);
  if (!b || now - b[0] > BUCKET_MS) { b = [now, 0]; buckets.set(clientIP, b); }
  b[1]++;
  // per-target cooldown: same host at most 3x per minute per IP
  const stampKey = clientIP + '|' + target;
  let stamps = buckets.get(stampKey);
  if (!stamps) { stamps = []; buckets.set(stampKey, stamps); }
  stamps.push(now);
  while (stamps.length && now - stamps[0] > BUCKET_MS) stamps.shift();
  if (buckets.size > 5000) buckets.clear(); // crude memory guard
  return b[1] > 20 || stamps.length > 3;
}

// ---------- URL validation / SSRF guard ----------
const PRIVATE_V4 = [
  /^127\./, /^0\./, /^10\./, /^192\.168\./, /^169\.254\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, /^198\.1[89]\./,
];

function isPrivateHost(hostname) {
  if (typeof process !== 'undefined' && process.env && process.env.P2S_ALLOW_PRIVATE === '1') return false; // local tests only
  const h = hostname.toLowerCase().replace(/\.$/, '');
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.home.arpa')) return true;
  if (h.includes('@') || h === '') return true;
  if (/^\[?::1\]?$/.test(h) || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;
  const bare = h.replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) {
    for (const re of PRIVATE_V4) if (re.test(bare)) return true;
  }
  return false;
}

function normalizeTarget(raw) {
  if (!raw) return { error: 'missing_url' };
  let s = raw.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && !/^https?:\/\//i.test(s)) return { error: 'bad_scheme' };
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch { return { error: 'invalid_url' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { error: 'bad_scheme' };
  if (isPrivateHost(u.hostname)) return { error: 'private_host' };
  if (u.username || u.password) return { error: 'userinfo_not_allowed' };
  u.hash = '';
  u.search = '';
  return { url: u };
}

// ---------- PHP version logic ----------
function parsePhpVer(str) {
  if (!str) return null;
  const m = /PHP[\/\- ]{0,3}v?(\d+)\.(\d+)\.(\d+)/i.exec(String(str));
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], text: `${m[1]}.${m[2]}.${m[3]}` };
}

function assessVersion(v) {
  if (!v) return null;
  const { major, minor, patch } = v;
  if (major < 5 || (major === 5 && minor < 4)) {
    return { status: 'ancient', branch: `${major}.${minor}`, fixedIn: null, eol: true };
  }
  if (major === 8 && FIXED[minor] !== undefined) {
    const fixed = FIXED[minor];
    const vulnerable = patch < parseInt(fixed.split('.')[2], 10);
    return { status: vulnerable ? 'vulnerable' : 'patched', branch: `${major}.${minor}`, fixedIn: fixed, eol: minor <= 2 };
  }
  if (major > 8 || (major === 8 && minor > 5)) {
    return { status: 'patched', branch: `${major}.${minor}`, fixedIn: null, eol: false };
  }
  // 5.4 .. 8.1 — EOL, unpatched by upstream
  return { status: 'vulnerable_eol', branch: `${major}.${minor}`, fixedIn: null, eol: true };
}


// ---------- probes ----------
async function timedFetch(url, init, ms = 9000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try { return await fetch(url, { ...init, signal: ctl.signal, redirect: 'follow' }); }
  finally { clearTimeout(t); }
}

function collectSignals(headers, bodySnippet) {
  const sig = [];
  const h = (n) => headers.get(n) || '';
  const xpb = h('x-powered-by');
  let phpVer = parsePhpVer(xpb) || parsePhpVer(h('x-php-version')) || null;
  if (xpb) sig.push({ kind: 'header', name: 'X-Powered-By', value: xpb.slice(0, 120) });
  if (/PHPSESSID/i.test(h('set-cookie'))) sig.push({ kind: 'cookie', name: 'PHPSESSID session cookie', value: 'present' });
  if (!phpVer && bodySnippet) {
    const bodyVer = parsePhpVer(bodySnippet);
    if (bodyVer) { phpVer = bodyVer; sig.push({ kind: 'body', name: 'PHP version string in page body', value: bodyVer.text }); }
  }
  const appFP = [
    [/wp-content|wp-includes|wp-json/i, 'WordPress'],
    [/\/sites\/default\/files|Drupal\.js|drupal-settings-json/i, 'Drupal'],
    [/Joomla!|\/media\/system\/js\//i, 'Joomla'],
    [/MediaWiki|\/w\/index\.php\?title=/i, 'MediaWiki'],
    [/phpMyAdmin|pma_password/i, 'phpMyAdmin'],
    [/nextcloud|\/index\.php\/login\?v=/i, 'Nextcloud'],
    [/laravel_session|XSRF-TOKEN/i, 'Laravel'],
    [/Magento|\/static\/version\d+\//i, 'Magento'],
  ];
  for (const [re, name] of appFP) {
    if (re.test(bodySnippet)) { sig.push({ kind: 'app', name, value: 'detected' }); break; }
  }
  return { sig, phpVer };
}

// Tiny, well-formed multipart POST — indistinguishable from a normal small
// browser file upload. No injection characters, no size, no OOM pressure.
const BOUND = '----p2scheck7Y3k';
function benignMultipart(sid) {
  const part = (n, v) => `--${BOUND}\r\nContent-Disposition: form-data; name="${n}"\r\n\r\n${v}\r\n`;
  const file = `--${BOUND}\r\nContent-Disposition: form-data; name="f"; filename="probe.txt"\r\nContent-Type: text/plain\r\n\r\np2s\r\n`;
  return (part('PHPSESSID', sid) + part('PHP_SESSION_UPLOAD_PROGRESS', 'p2sprobe') + file + `--${BOUND}--\r\n`);
}

function looksLikeCloudflare(headers, body) {
  if (headers.get('cf-ray') || headers.get('cf-cache-status')) return true;
  if (/cloudflare/i.test(headers.get('server') || '')) return true;
  if (headers.get('cf-mitigated')) return true;
  if (body && /Attention Required!\s*\|\s*Cloudflare|cloudflare.*ray ID/i.test(body.slice(0, 4000))) return true;
  return false;
}

async function handleCheck(request, env) {
  const target = normalizeTarget(new URL(request.url).searchParams.get('url'));
  if (target.error) return json({ error: target.error }, 400);
  const clientIP = request.headers.get('cf-connecting-ip') || 'unknown';
  if (rateLimited(clientIP, target.url.hostname)) return json({ error: 'rate_limited' }, 429);

  const out = {
    cve: CVE, input: target.url.hostname, checkedAt: new Date().toISOString(),
    signals: [], phpVersion: null, verdict: null, waf: {}, probes: {}, disclaimer: null,
  };

  // Probe 1: plain GET / (https first; fall back to http when TLS is unavailable)
  let get = null;
  let getErr = null;
  const getOpts = { method: 'GET', headers: { 'user-agent': 'php2shell-alert/1.0 (+https://php.muran.ai; passive+benign checks only)' } };
  for (const candidate of (target.url.protocol === 'https:' ? ['https:', 'http:'] : ['http:'])) {
    try {
      target.url.protocol = candidate;
      get = await timedFetch(target.url.toString(), getOpts);
      break;
    } catch (e) {
      getErr = e;
      get = null;
    }
  }
  if (!get) {
    out.probes.get = { status: 0, error: getErr && getErr.name === 'AbortError' ? 'timeout' : 'fetch_failed' };
    return json({ ...out, verdict: { status: 'unreachable', reason: out.probes.get.error } }, 200);
  }
  let bodySnippet = '';
  try {
    const body = await get.text();
    bodySnippet = body.slice(0, 65536);
    out.probes.get = { status: get.status, finalUrl: get.url.slice(0, 300) };
    const { sig, phpVer } = collectSignals(get.headers, bodySnippet);
    out.signals.push(...sig);
    out.phpVersion = phpVer;
    out.server = (get.headers.get('server') || '').slice(0, 80);
    out.waf.cloudflare = looksLikeCloudflare(get.headers, body);
  } catch (e) {
    out.probes.get = { status: get.status || 0, error: 'read_failed' };
  }

  // Probe 2: benign multipart POST (session.upload_progress path touch).
  // Prefer a real PHP endpoint found in the page over the raw root URL.
  let postUrl = target.url.toString();
  const phpLink = /(?:href|action)=["']([^"'\s]+\.php[^"'\s]*)["']/i.exec(bodySnippet);
  if (phpLink) {
    try { postUrl = new URL(phpLink[1], get.url).toString().slice(0, 300); } catch { /* keep root */ }
  }
  const sid = 'p2s' + Math.random().toString(16).slice(2, 10).padEnd(8, '0') + Math.random().toString(16).slice(2, 10).padEnd(24, '0');
  try {
    const body = benignMultipart(sid);
    const post = await timedFetch(postUrl, {
      method: 'POST',
      headers: {
        'content-type': `multipart/form-data; boundary=${BOUND}`,
        'user-agent': 'php2shell-alert/1.0 (+https://php.muran.ai; passive+benign checks only)',
        'x-requested-with': 'p2s-benign-probe',
      },
      body,
    });
    const postBody = await post.text();
    const setc = post.headers.get('set-cookie') || '';
    const reflected = new RegExp('PHPSESSID=' + sid, 'i').test(setc);
    const regenerated = /PHPSESSID=[a-z0-9,\-]{26,}/i.test(setc) && !reflected;
    out.probes.multipart = { status: post.status };
    out.waf.cloudflareBlockedMultipart = post.status === 403 && looksLikeCloudflare(post.headers, postBody);
    out.waf.multipartBlockedAtOrigin = post.status === 403 && !out.waf.cloudflare;
    if (reflected || regenerated) {
      out.signals.push({
        kind: 'session',
        name: 'session.upload_progress',
        value: reflected ? 'enabled — attacker-controlled session id accepted (use_strict_mode=0)' : 'responds with fresh PHP session on upload',
      });
    }
  } catch (e) {
    out.probes.multipart = { status: 0, error: e.name === 'AbortError' ? 'timeout' : 'fetch_failed' };
  }

  // ---------- verdict ----------
  const assessed = out.phpVersion ? assessVersion(out.phpVersion) : null;
  const phpDetected = !!out.phpVersion || out.signals.some(s => s.kind === 'cookie' || s.kind === 'session' || s.kind === 'app');
  if (assessed) {
    out.verdict = { status: assessed.status, branch: assessed.branch, fixedIn: assessed.fixedIn, eol: assessed.eol, version: out.phpVersion.text };
  } else if (phpDetected) {
    out.verdict = { status: 'php_version_hidden', branch: null, fixedIn: null, note: 'php-detected-no-version' };
  } else {
    out.verdict = { status: 'no_php_signals', branch: null, fixedIn: null, note: 'absence of signals is not proof of safety' };
  }
  out.disclaimer = 'Passive + benign probing only. No exploit payload was sent. A hidden banner does not mean you are safe — verify with `php -v` on the server.';
  return json(out, 200);
}

function json(obj, status) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api/check' && request.method === 'GET') {
      return handleCheck(request, env);
    }
    if (url.pathname === '/api/health') return json({ ok: true, ts: Date.now() });
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Not found', { status: 404 });
  },
};
