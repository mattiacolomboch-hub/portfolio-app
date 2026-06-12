/**
 * Cloudflare Worker — CORS proxy with Stooq proof-of-work bypass.
 *
 * Usage (unchanged): https://<worker>/?url=<ENCODED_TARGET_URL>
 *   - Yahoo Finance JSON, Stooq CSV, etc. all go through ?url=.
 *
 * Stooq now gates its CSV endpoint behind a SHA-256 proof-of-work challenge.
 * When the proxied response is that challenge page, this Worker solves the PoW
 * server-side, POSTs /__verify, caches the resulting cookie in memory, and
 * re-fetches the real content. The solved cookie is reused across requests
 * (same isolate) so the expensive PoW runs rarely, not on every call.
 *
 * NOTE: solving the PoW (difficulty 4 hex zeros ≈ 65k SHA-256) needs more CPU
 * than the Free plan's 10ms allows. Use the Workers Paid plan (or raise the
 * CPU limit). Cached requests are cheap; only a cold cookie pays the cost.
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': '*',
};

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
  'Accept': 'text/html,application/json,text/csv,*/*',
  'Accept-Language': 'en-US,en;q=0.9',
};

// in-memory cookie cache (per isolate)
let COOKIE_JAR = {};       // { origin: "name=value; name2=value2" }
let COOKIE_TS = {};        // { origin: epochMs }
const COOKIE_TTL = 1000 * 60 * 30; // 30 minutes

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
    const target = new URL(request.url).searchParams.get('url');
    if (!target) return new Response('missing ?url=', { status: 400, headers: CORS });

    try {
      const { body, status, contentType } = await fetchMaybeChallenge(target);
      const headers = new Headers(CORS);
      headers.set('content-type', contentType || 'text/plain; charset=utf-8');
      return new Response(body, { status, headers });
    } catch (e) {
      return new Response('proxy error: ' + e.message, { status: 502, headers: CORS });
    }
  },
};

async function fetchMaybeChallenge(target) {
  const origin = new URL(target).origin;

  // 1) try a cached cookie first
  const cached = COOKIE_JAR[origin];
  if (cached && Date.now() - (COOKIE_TS[origin] || 0) < COOKIE_TTL) {
    const r = await fetch(target, { headers: { ...BROWSER_HEADERS, Cookie: cached } });
    const text = await r.text();
    if (!isChallenge(text)) return { body: text, status: r.status, contentType: r.headers.get('content-type') };
    // cookie went stale → fall through and re-solve
  }

  // 2) fetch fresh; if not a challenge, done
  let jar = parseCookies(cached);
  let r = await fetch(target, { headers: BROWSER_HEADERS });
  let text = await r.text();
  mergeSetCookies(jar, r);
  if (!isChallenge(text)) {
    return { body: text, status: r.status, contentType: r.headers.get('content-type') };
  }

  // 3) parse + solve the proof-of-work
  const m = text.match(/const c="([^"]+)"\s*,\s*d=(\d+)/);
  if (!m) return { body: text, status: r.status, contentType: r.headers.get('content-type') };
  const c = m[1], d = parseInt(m[2], 10);
  const n = solvePow(c, d);

  // 4) POST /__verify with the solution (carry challenge cookies)
  const vr = await fetch(origin + '/__verify', {
    method: 'POST',
    headers: { ...BROWSER_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookieString(jar) },
    body: 'c=' + encodeURIComponent(c) + '&n=' + n,
  });
  mergeSetCookies(jar, vr);

  // 5) cache + re-fetch the real content
  const cookie = cookieString(jar);
  COOKIE_JAR[origin] = cookie;
  COOKIE_TS[origin] = Date.now();
  r = await fetch(target, { headers: { ...BROWSER_HEADERS, Cookie: cookie } });
  text = await r.text();
  return { body: text, status: r.status, contentType: r.headers.get('content-type') };
}

function isChallenge(text) {
  return /__verify/.test(text) && /requires JavaScript|crypto\.subtle/.test(text);
}

// ── cookie helpers ───────────────────────────────────────────
function parseCookies(str) {
  const jar = {};
  if (!str) return jar;
  str.split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) jar[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return jar;
}
function mergeSetCookies(jar, res) {
  const list = typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie()
    : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
  list.forEach(sc => {
    const first = sc.split(';')[0];
    const i = first.indexOf('=');
    if (i > 0) jar[first.slice(0, i).trim()] = first.slice(i + 1).trim();
  });
}
function cookieString(jar) {
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
}

// ── proof-of-work: find n where sha256(c+n) starts with d hex zeros ──
function solvePow(c, d) {
  const target = '0'.repeat(d);
  for (let n = 0; n < 50_000_000; n++) {
    if (sha256(c + n).startsWith(target)) return n;
  }
  throw new Error('PoW not found');
}

// Compact synchronous SHA-256 (ASCII input) → hex string.
function sha256(ascii) {
  function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
  const mathPow = Math.pow, maxWord = mathPow(2, 32);
  let result = '';
  const words = [];
  const asciiBitLength = ascii.length * 8;
  let hash = sha256.h, k = sha256.k;
  if (!hash) {
    hash = sha256.h = []; k = sha256.k = [];
    let primeCounter = 0; const isComposite = {};
    for (let candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
  }
  hash = hash.slice(0, 8);
  ascii += '\x80';
  while (ascii.length % 64 - 56) ascii += '\x00';
  for (let i = 0; i < ascii.length; i++) {
    const j = ascii.charCodeAt(i);
    if (j >> 8) return '';
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }
  words[words.length] = (asciiBitLength / maxWord) | 0;
  words[words.length] = asciiBitLength;
  for (let j = 0; j < words.length;) {
    const w = words.slice(j, j += 16);
    const oldHash = hash;
    hash = hash.slice(0, 8);
    for (let i = 0; i < 64; i++) {
      const w15 = w[i - 15], w2 = w[i - 2];
      const a = hash[0], e = hash[4];
      const temp1 = hash[7]
        + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
        + ((e & hash[5]) ^ (~e & hash[6]))
        + k[i]
        + (w[i] = (i < 16) ? w[i] : (
            w[i - 16]
            + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
            + w[i - 7]
            + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
          ) | 0);
      const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
  }
  for (let i = 0; i < 8; i++) {
    for (let j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += ((b < 16) ? 0 : '') + b.toString(16);
    }
  }
  return result;
}
