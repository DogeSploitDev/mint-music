// server.js
// Two-mode server: runs on Node.js (>=18) and Cloudflare Workers.
// Features:
// - Login with Amazon (OAuth 2.0) to keep the flow in your app.
// - Serves the mint player index.html (reads file on Node, falls back inline on Workers).
// - Validates session and proxies metadata fetch for Amazon Music URLs.
//
// ENV required:
// - AMAZON_CLIENT_ID
// - AMAZON_CLIENT_SECRET
// - BASE_URL (e.g., http://localhost:3000 or https://your-worker.workers.dev)
// - COOKIE_SECURE (optional: 'auto' | 'true' | 'false')

const OAUTH_AUTH = 'https://www.amazon.com/ap/oa';
const OAUTH_TOKEN = 'https://api.amazon.com/auth/o2/token';
const PROFILE_API = 'https://api.amazon.com/user/profile';

const AMAZON_MUSIC_HOSTS = new Set([
  'music.amazon.com','music.amazon.co.uk','music.amazon.de','music.amazon.co.jp','music.amazon.in',
  'music.amazon.ca','music.amazon.com.au','music.amazon.fr','music.amazon.it','music.amazon.es',
  'music.amazon.com.mx','music.amazon.com.br'
]);

// Inline fallback for Workers (Node reads index.html from disk)
const HTML_FALLBACK = `<!doctype html><meta charset="utf-8"><title>Mint Player</title><body>Missing index.html</body>`;

function textResponse(text, status = 200, headers = {}) {
  return new Response(text, { status, headers: { 'content-type': 'text/html; charset=utf-8', ...headers }});
}
function jsonResponse(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', ...headers }});
}
function redirect(location, status=302, headers = {}) {
  return new Response(null, { status, headers: { location, ...headers }});
}

function getEnv(env) {
  const E = typeof env === 'object' && env ? env : {};
  return {
    CLIENT_ID: E.AMAZON_CLIENT_ID || (typeof process !== 'undefined' ? process.env.AMAZON_CLIENT_ID : undefined),
    CLIENT_SECRET: E.AMAZON_CLIENT_SECRET || (typeof process !== 'undefined' ? process.env.AMAZON_CLIENT_SECRET : undefined),
    BASE_URL: E.BASE_URL || (typeof process !== 'undefined' ? (process.env.BASE_URL || 'http://localhost:3000') : 'http://localhost:3000'),
    COOKIE_SECURE: (E.COOKIE_SECURE || (typeof process !== 'undefined' ? process.env.COOKIE_SECURE : 'auto') || 'auto')
  };
}

function cookieParams(reqUrl, securePref='auto') {
  const isHttps = reqUrl.startsWith('https://');
  const secure = securePref === 'auto' ? isHttps : securePref === 'true';
  const base = `Path=/; SameSite=Lax; ${secure ? 'Secure; ' : ''}HttpOnly`;
  return base;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}

// Base64url for JSON strings in both runtimes
function b64url(str) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'utf8').toString('base64url');
  }
  return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function ub64url(str) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'base64url').toString('utf8');
  }
  return atob(str.replace(/-/g,'+').replace(/_/g,'/'));
}

function randomState() {
  const a = new Uint8Array(16);
  (globalThis.crypto || {}).getRandomValues?.(a);
  return Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function exchangeCodeForTokens(code, redirectUri, env) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: env.CLIENT_ID,
    client_secret: env.CLIENT_SECRET
  });
  const r = await fetch(OAUTH_TOKEN, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  });
  if (!r.ok) throw new Error('token_exchange_failed');
  return r.json();
}

async function fetchProfile(accessToken) {
  const r = await fetch(PROFILE_API, { headers: { authorization: 'Bearer ' + accessToken }});
  if (!r.ok) throw new Error('profile_failed');
  return r.json();
}

function isAmazonMusicUrl(u) {
  try {
    const url = new URL(u);
    return AMAZON_MUSIC_HOSTS.has(url.hostname.toLowerCase());
  } catch { return false; }
}

function sanitizeTarget(u) {
  // Allow only Amazon Music links for metadata. No auth, no cookies forwarded.
  if (!isAmazonMusicUrl(u)) return null;
  try {
    const url = new URL(u);
    url.protocol = 'https:'; // enforce https
    return url.toString();
  } catch { return null; }
}

async function readIndexHtmlNode() {
  try {
    const fs = await import('node:fs/promises');
    return await fs.readFile('index.html', 'utf8');
  } catch {
    return HTML_FALLBACK;
  }
}

async function handle(request, env, ctx) {
  const url = new URL(request.url);
  const { pathname, searchParams, origin } = url;
  const E = getEnv(env);
  const cookies = parseCookies(request.headers.get('cookie') || '');
  const session = cookies.session ? JSON.parse(ub64url(cookies.session) || '{}') : null;
  const cookieBase = cookieParams(origin, String(E.COOKIE_SECURE));

  // Serve index
  if (pathname === '/') {
    // On Node, read index.html; on Workers, fall back inline
    if (typeof process !== 'undefined' && process.release && process.release.name === 'node') {
      const html = await readIndexHtmlNode();
      return textResponse(html);
    }
    return textResponse(HTML_FALLBACK);
  }

  if (pathname === '/me') {
    if (session && session.name && session.exp && Date.now() < session.exp) {
      return jsonResponse({ loggedIn: true, name: session.name });
    }
    return jsonResponse({ loggedIn: false });
  }

  if (pathname === '/login') {
    if (!E.CLIENT_ID) return textResponse('Missing AMAZON_CLIENT_ID env', 500);
    const redirectUri = E.BASE_URL.replace(/\/+$/,'') + '/callback';
    const state = randomState();
    const authUrl = new URL(OAUTH_AUTH);
    authUrl.searchParams.set('client_id', E.CLIENT_ID);
    authUrl.searchParams.set('scope', 'profile');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('state', state);
    const headers = { 'Set-Cookie': `oauth_state=${state}; ${cookieBase}; Max-Age=600` };
    return redirect(authUrl.toString(), 302, headers);
  }

  if (pathname === '/callback') {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const stateCookie = cookies.oauth_state;
    const redirectUri = E.BASE_URL.replace(/\/+$/,'') + '/callback';

    if (!code || !state || !stateCookie || stateCookie !== state) {
      return textResponse('Invalid OAuth response.', 400);
    }
    try {
      const tokens = await exchangeCodeForTokens(code, redirectUri, E);
      const prof = await fetchProfile(tokens.access_token);
      const expiresInMs = (Number(tokens.expires_in) || 3600) * 1000;
      const sessionObj = {
        name: prof.name || prof.email || 'Amazon user',
        exp: Date.now() + Math.min(expiresInMs, 6 * 3600 * 1000)
      };
      const setCookies = [
        `session=${b64url(JSON.stringify(sessionObj))}; ${cookieBase}; Max-Age=${Math.floor((sessionObj.exp - Date.now())/1000)}`,
        `oauth_state=; ${cookieBase}; Max-Age=0`
      ];
      return redirect('/', 302, { 'Set-Cookie': setCookies });
    } catch {
      return textResponse('Login failed. Please try again.', 500);
    }
  }

  if (pathname === '/logout' && request.method === 'POST') {
    const setCookies = [
      `session=; ${cookieBase}; Max-Age=0`,
      `oauth_state=; ${cookieBase}; Max-Age=0`
    ];
    return jsonResponse({ ok: true }, 200, { 'Set-Cookie': setCookies });
  }

  // Metadata proxy for Amazon Music pages (scrapes Open Graph tags)
  if (pathname === '/metadata') {
    const target = sanitizeTarget(searchParams.get('url') || '');
    if (!target) return jsonResponse({ ok:false, error:'invalid_url' }, 400);
    try {
      const r = await fetch(target, {
        headers: {
          'user-agent': 'Mozilla/5.0 MintPlayer/1.0',
          'accept': 'text/html,application/xhtml+xml'
        }
      });
      const html = await r.text();
      const meta = {};
      const grab = (prop) => {
        const re = new RegExp(`<meta[^>]+property=["']${prop}["'][^>]*content=["']([^"']+)["']`, 'i');
        const m = html.match(re);
        return m ? m[1] : '';
      };
      meta.title = grab('og:title') || '';
      meta.image = grab('og:image') || '';
      meta.site = grab('og:site_name') || '';
      meta.url = target;
      return jsonResponse({ ok:true, meta });
    } catch {
      return jsonResponse({ ok:false, error:'fetch_failed' }, 500);
    }
  }

  return textResponse('Not found', 404);
}

export default { fetch: handle };

// Node.js bootstrap
if (typeof process !== 'undefined' && process.release && process.release.name === 'node') {
  const isMain = import.meta && import.meta.url ? (import.meta.url === `file://${process.argv[1]}`) : true;
  if (isMain) {
    const http = await import('node:http');
    const PORT = Number(process.env.PORT || 3000);
    const server = http.createServer((req, res) => {
      const reqUrl = `http://localhost:${PORT}${req.url}`;
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) headers.set(k, Array.isArray(v) ? v.join(', ') : (v || ''));
      const request = new Request(reqUrl, { method: req.method, headers, body: req.method === 'GET' || req.method === 'HEAD' ? undefined : req });
      handle(request, {}, {}).then(r => {
        res.statusCode = r.status;
        r.headers.forEach((v, k) => res.setHeader(k, v));
        if (r.body) r.arrayBuffer().then(buf => res.end(Buffer.from(buf))).catch(() => res.end());
        else res.end();
      }).catch(() => { res.statusCode = 500; res.end('Internal error'); });
    });
    server.listen(PORT, () => {
      console.log('Listening on http://localhost:' + PORT);
    });
  }
}
