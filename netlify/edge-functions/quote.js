// Netlify Edge Function — proxy Yahoo Finance v7 quotes.
//   GET /v1/quote?symbols=TSLA,AAPL,...
// Returns the Yahoo quotes array (JSON) with CORS, cached 60s.
//
// NOTE: Yahoo's v7 /finance/quote endpoint is gated behind a "crumb" + cookie
// (a bare proxy returns {"error":"Unauthorized"}). So this function performs the
// cookie→crumb handshake and caches it per edge isolate, refreshing on rejection.

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

const FIELDS = [
  'regularMarketPrice', 'regularMarketChange', 'regularMarketChangePercent',
  'regularMarketPreviousClose', 'shortName', 'longName', 'currency', 'exchange',
  'marketCap', 'trailingPE', 'forwardPE', 'dividendYield',
  'fiftyTwoWeekHigh', 'fiftyTwoWeekLow', 'regularMarketVolume',
].join(',');

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': '*',
};

// crumb + cookie cached across invocations on the same isolate
let CRUMB = '', COOKIE = '', CRUMB_TS = 0;
const CRUMB_TTL = 30 * 60 * 1000; // 30 min

function setCookies(res) {
  const list = typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie()
    : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
  return list.map((c) => c.split(';')[0]).filter(Boolean);
}

async function refreshCrumb() {
  let cookie = '';
  for (const u of ['https://fc.yahoo.com/', 'https://finance.yahoo.com/', 'https://login.yahoo.com/']) {
    try {
      const r = await fetch(u, { headers: { 'User-Agent': UA, Accept: 'text/html' }, redirect: 'manual' });
      const jar = setCookies(r);
      if (jar.length) { cookie = jar.join('; '); break; }
    } catch { /* try next */ }
  }
  if (!cookie) return false;
  const r = await fetch('https://query1.finance.yahoo.com/v1/test/getcrumb', {
    headers: { 'User-Agent': UA, Cookie: cookie, Accept: 'text/plain' },
  });
  const crumb = (await r.text()).trim();
  if (!crumb || crumb.length > 40 || /[<>{}\s]/.test(crumb)) return false; // got an error page, not a crumb
  COOKIE = cookie; CRUMB = crumb; CRUMB_TS = Date.now();
  return true;
}

async function fetchQuotes(symbols) {
  const url = 'https://query1.finance.yahoo.com/v7/finance/quote'
    + `?symbols=${encodeURIComponent(symbols)}&fields=${FIELDS}&crumb=${encodeURIComponent(CRUMB)}`;
  const r = await fetch(url, { headers: { 'User-Agent': UA, Cookie: COOKIE, Accept: 'application/json' } });
  if (!r.ok) return { ok: false };
  try { return { ok: true, data: await r.json() }; } catch { return { ok: false }; }
}

export default async (request) => {
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const symbols = (new URL(request.url).searchParams.get('symbols') || '').trim();
  if (!symbols) {
    return new Response(JSON.stringify({ error: 'missing symbols param' }), {
      status: 400, headers: { ...CORS, 'content-type': 'application/json' },
    });
  }

  try {
    if (!CRUMB || !COOKIE || Date.now() - CRUMB_TS > CRUMB_TTL) await refreshCrumb();

    let res = await fetchQuotes(symbols);
    if (!res.ok || res.data?.finance?.error || res.data?.quoteResponse?.error || !res.data?.quoteResponse) {
      await refreshCrumb();                 // crumb stale/rejected → refresh once, retry
      res = await fetchQuotes(symbols);
    }

    const quotes = res.data?.quoteResponse?.result || [];
    return new Response(JSON.stringify(quotes), {
      status: 200,
      headers: {
        ...CORS,
        'content-type': 'application/json',
        'Cache-Control': 'public, max-age=60',
        'Netlify-CDN-Cache-Control': 'public, s-maxage=60',
      },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: String(e) }), {
      status: 502, headers: { ...CORS, 'content-type': 'application/json' },
    });
  }
};
