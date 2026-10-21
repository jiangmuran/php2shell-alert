// Local preview: static public/ + real worker /api/*.  P2S_ALLOW_PRIVATE=1 lets
// you test the checker against the local lab. Usage: node preview.mjs
process.env.P2S_ALLOW_PRIVATE = '1';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const worker = (await import('./src/worker.js')).default;
const root = fileURLToPath(new URL('./public', import.meta.url));
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

const srv = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (url.pathname.startsWith('/api/')) {
    const r = await worker.fetch(new Request('http://127.0.0.1:4173' + req.url, req));
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(await r.text());
    return;
  }
  let p = join(root, url.pathname === '/' ? 'index.html' : url.pathname);
  try {
    const buf = await readFile(p);
    res.writeHead(200, { 'content-type': MIME[extname(p)] || 'application/octet-stream' });
    res.end(buf);
  } catch {
    res.writeHead(404); res.end('not found');
  }
});
srv.listen(4173, '127.0.0.1', () => console.log('preview: http://127.0.0.1:4173'));
