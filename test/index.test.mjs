import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, generateKeyPair, createLocalJWKSet, exportJWK } from 'jose';
import { session, operator, accessIdentity, bearer, sha256, log, timingSafeEqual } from '../src/index.mjs';

const req = (h = {}) => new Request('https://mutaafaziz.com/ads/api', { headers: h });
const s = session({ cookie: 'x_session', path: '/x' });

test('a cookie it issued is valid, a forged one is not', async () => {
  const c = (await s.issue('pw')).split(';')[0];
  assert.equal(await s.valid(req({ cookie: c }), 'pw'), true);
  assert.equal(await s.valid(req({ cookie: c }), 'other'), false);
  assert.equal(await s.valid(req({ cookie: c.slice(0, -3) + 'abc' }), 'pw'), false);
});
test('an expired cookie is not valid', async () => { const c = (await s.issue('pw', Date.now() - 40 * 864e5)).split(';')[0]; assert.equal(await s.valid(req({ cookie: c }), 'pw'), false); });
test('cookies issued by the old per-service code still verify', async () => {
  // The format every service used: op:<expiry>.<base64url HMAC>, so nobody is signed out by the move.
  const payload = `op:${Date.now() + 864e5}`, key = await crypto.subtle.importKey('raw', new TextEncoder().encode('pw'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))))).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  assert.equal(await s.verify('pw', `${payload}.${sig}`), true);
});
test('the cookie is scoped and locked down', async () => assert.match(await s.issue('pw'), /Path=\/x; HttpOnly; Secure; SameSite=Strict/));

async function access(claims, aud = 'aud1') {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256' };
  const token = await new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer('https://team.cloudflareaccess.com').setAudience(aud).setIssuedAt().setExpirationTime('1h').sign(privateKey);
  return { token, getKeys: createLocalJWKSet({ keys: [jwk] }) };
}
const env = { ACCESS_TEAM: 'team', ACCESS_AUD: 'aud1', OPERATOR_EMAILS: 'Owner@Example.com', AGENT_TOKEN: 'agent-t', ADMIN_PASSWORD: 'pw' };

test('a valid Access token for a listed email is the operator', async () => { const { token, getKeys } = await access({ email: 'owner@example.com' }); assert.equal(await operator(req({ 'cf-access-jwt-assertion': token }), env, { getKeys }), 'operator'); });
test('an Access token for anyone else is not', async () => { const { token, getKeys } = await access({ email: 'someone@example.com' }); assert.equal(await operator(req({ 'cf-access-jwt-assertion': token }), env, { getKeys }), null); });
test('an Access token for another application is refused', async () => { const { token, getKeys } = await access({ email: 'owner@example.com' }, 'other-app'); assert.equal(await accessIdentity(req({ 'cf-access-jwt-assertion': token }), env, { getKeys }), null); });
test('Access is ignored until it is configured', async () => { const { token, getKeys } = await access({ email: 'owner@example.com' }); assert.equal(await accessIdentity(req({ 'cf-access-jwt-assertion': token }), {}, { getKeys }), null); });
test('the agent token and the console cookie still work', async () => {
  assert.equal(await operator(req({ authorization: 'Bearer agent-t' }), env), 'agent');
  assert.equal(await operator(req({ cookie: (await s.issue('pw')).split(';')[0] }), env, { session: s }), 'operator');
  assert.equal(await operator(req({ authorization: 'Bearer nope' }), env, { session: s }), null);
});

test('hashed tokens name their caller', async () => {
  const map = JSON.stringify({ [await sha256('abc')]: 'lobby' });
  assert.equal(await bearer(req({ authorization: 'Bearer abc' }), map), 'lobby');
  assert.equal(await bearer(req({ authorization: 'Bearer constructor' }), '{}'), null);
  assert.equal(await bearer(req({ authorization: 'Bearer abc' }), await sha256('abc')), 'token');
  assert.equal(await bearer(req({ authorization: 'Bearer x' }), await sha256('abc')), null);
});
test('timingSafeEqual compares whole strings', () => { assert.equal(timingSafeEqual('a', 'a'), true); assert.equal(timingSafeEqual('a', 'ab'), false); });
test('log lines share one shape and drop personal fields', () => { const l = log('svc', 'thing', { ms: 3, email: 'x@y', user_id: 1, ok: true }); assert.deepEqual(Object.keys(l).sort(), ['at', 'event', 'ms', 'ok', 'service']); });
