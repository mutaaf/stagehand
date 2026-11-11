# Stagehand

The backstage code every Worker on mutaafaziz.com used to copy: operator auth, token checks and one log shape. MIT.

```js
import { operator, session, bearer, log, timed } from 'stagehand';
const console_ = session({ cookie: 'marquee_session', path: '/ads' });
const who = await operator(req, env, { session: console_ });   // 'operator' | 'agent' | null
```

- **Operator auth.** Cloudflare Access first: when `ACCESS_TEAM` and `ACCESS_AUD` are set, the `Cf-Access-Jwt-Assertion` header is verified with [jose](https://github.com/panva/jose) (RS256, issuer, audience, expiry) and an email in `OPERATOR_EMAILS` is the operator. Until then, the signed console cookie (HMAC-SHA256, same format the services already used, so nobody is signed out) and the `AGENT_TOKEN` bearer.
- **Hashed tokens.** `bearer(req, hashes)`: tokens are stored only as sha-256.
- **One log shape.** `log(service, event, fields)` writes one JSON line (`service`, `event`, `ms`, `ok`, `at`) that Workers Logs indexes and the OpenTelemetry export carries. Fields that look personal are dropped.

Install from GitHub: `"stagehand": "github:mutaaf/stagehand#v1.0.0"`.
