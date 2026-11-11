// Stagehand: the backstage code every Worker on mutaafaziz.com used to copy. One operator check, one token
// check, one log shape. Phase 5 of github.com/mutaaf/cue/blob/main/docs/ARCHITECTURE.md.
//
//   import { operator, session, bearer, log } from 'stagehand';
//
// Operator auth, strongest first:
//   1. Cloudflare Access. When ACCESS_TEAM and ACCESS_AUD are set, the Cf-Access-Jwt-Assertion header is
//      verified with jose against the team's published keys (RS256, audience, issuer, expiry). An email in
//      OPERATOR_EMAILS (comma-separated) is the operator.
//   2. A signed session cookie (HMAC-SHA256 over an expiry), set after the console's one password. Same
//      format the services already used, so nobody is signed out by the move.
import { createRemoteJWKSet, jwtVerify } from 'jose';

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

export async function sha256(text) {
  const h = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function timingSafeEqual(a, b) {
  const x = enc.encode(String(a)), y = enc.encode(String(b));
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}

// ---- Signed session cookies -------------------------------------------------------------------------------
export function session({ cookie, path, days = 30 }) {
  const key = (secret) => crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sign = async (secret, payload) => `${payload}.${b64u(await crypto.subtle.sign('HMAC', await key(secret), enc.encode(payload)))}`;
  const verify = async (secret, token, now = Date.now()) => {
    if (!secret || !token) return false;
    const i = token.lastIndexOf('.');
    if (i < 0) return false;
    const payload = token.slice(0, i);
    if (!timingSafeEqual(await sign(secret, payload), token)) return false;
    return Number(payload.split(':')[1]) > now;
  };
  const read = (req) => (req.headers.get('cookie') || '').match(new RegExp(`(?:^|;\\s*)${cookie}=([^;]+)`))?.[1] ?? null;
  return {
    sign, verify, read,
    issue: async (secret, now = Date.now()) => `${cookie}=${await sign(secret, `op:${now + days * 864e5}`)}; Path=${path}; HttpOnly; Secure; SameSite=Strict; Max-Age=${days * 86400}`,
    clear: `${cookie}=; Path=${path}; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
    valid: async (req, secret) => verify(secret, read(req)),
  };
}

// ---- Cloudflare Access ------------------------------------------------------------------------------------
const jwks = new Map();
export async function accessIdentity(req, env, { getKeys = null } = {}) {
  const token = req.headers.get('cf-access-jwt-assertion');
  if (!token || !env.ACCESS_TEAM || !env.ACCESS_AUD) return null;
  const issuer = `https://${env.ACCESS_TEAM}.cloudflareaccess.com`;
  if (!getKeys && !jwks.has(issuer)) jwks.set(issuer, createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`)));
  try {
    const { payload } = await jwtVerify(token, getKeys ?? jwks.get(issuer), { issuer, audience: env.ACCESS_AUD, algorithms: ['RS256'] });
    return { email: payload.email ?? null, sub: payload.sub, service: !payload.email };
  } catch { return null; }
}

// ---- Who is asking ----------------------------------------------------------------------------------------
// 'operator' (Access, or the console cookie), 'agent' (Bearer AGENT_TOKEN), or null.
export async function operator(req, env, { session: s = null, secret = env.ADMIN_PASSWORD, getKeys = null } = {}) {
  const id = await accessIdentity(req, env, { getKeys });
  if (id?.email && String(env.OPERATOR_EMAILS || '').split(',').map((e) => e.trim().toLowerCase()).includes(id.email.toLowerCase())) return 'operator';
  const b = /^Bearer (.+)$/.exec(req.headers.get('authorization') || '')?.[1];
  if (b && env.AGENT_TOKEN && timingSafeEqual(b, env.AGENT_TOKEN)) return 'agent';
  if (s && (await s.valid(req, secret))) return 'operator';
  return null;
}

// Tokens stored only as sha-256 hashes: { "<hash>": "<name>" } JSON, or one hash string for a single caller.
export async function bearer(req, hashes) {
  const m = /^Bearer (.+)$/.exec(req.headers.get('authorization') || '');
  if (!m || !hashes) return null;
  const h = await sha256(m[1]);
  if (typeof hashes === 'string' && !hashes.trim().startsWith('{')) return timingSafeEqual(h, hashes.trim()) ? 'token' : null;
  let map; try { map = typeof hashes === 'string' ? JSON.parse(hashes) : hashes; } catch { return null; }
  return Object.hasOwn(map, h) ? map[h] : null;
}

// ---- One log shape ----------------------------------------------------------------------------------------
// Workers Logs indexes JSON fields, and the account's OpenTelemetry export carries the same lines, so every
// service can be queried the same way: service, event, ms, ok. Fields that look personal are dropped.
const PERSONAL = /(^|_|-)(ip|email|e-?mail|phone|user|username|name|password|secret|token|address|location)($|_|-)/i;
export function log(service, event, fields = {}) {
  const clean = Object.fromEntries(Object.entries(fields).filter(([k]) => !PERSONAL.test(k)));
  const line = { service, event, ...clean, at: new Date().toISOString() };
  (fields.ok === false ? console.error : console.log)(JSON.stringify(line));
  return line;
}

// Time a piece of work and log it in the same shape.
export async function timed(service, event, fn, fields = {}) {
  const t = Date.now();
  try { const r = await fn(); log(service, event, { ...fields, ms: Date.now() - t, ok: true }); return r; }
  catch (e) { log(service, event, { ...fields, ms: Date.now() - t, ok: false, error: String(e?.message ?? e).slice(0, 200) }); throw e; }
}
