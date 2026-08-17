---
icon: lucide/settings
---

# Configuration

JWT Ninja validates its security profile at startup. The following three values are mandatory and there is **no** fallback to Django's `SECRET_KEY`:

```python title="settings.py"
JWT_SECRET_KEY = "a-dedicated-random-key-of-at-least-32-bytes"
JWT_ISSUER = "https://auth.example.com"
JWT_AUDIENCE = "example-api"
JWT_ALGORITHM = "HS256"
```

For asymmetric algorithms, `JWT_SECRET_KEY` is the private signing key and `JWT_VERIFYING_KEY` is the separate public key. HMAC must omit `JWT_VERIFYING_KEY` or set it to the exact signing key. Startup fails for `none`/unsupported algorithms, undersized HMAC keys, malformed or incompatible keys, public-only signing keys, mismatched pairs, and RSA/PS keys below 2048 bits.

Tokens include and validate `iss`, `aud`, `iat`, `nbf`, and `exp`, enforce `JWT_LEEWAY_SECONDS`, enforce the configured lifetime for each token type, and require exact JOSE `typ` headers (`at+jwt` and `rt+jwt`).

## Settings

| Setting | Default | Notes |
| --- | --- | --- |
| `JWT_SECRET_KEY` | required | Dedicated signing key; never Django `SECRET_KEY`. |
| `JWT_VERIFYING_KEY` | `None` | Required separate public key for asymmetric algorithms. |
| `JWT_ALGORITHM` | `HS256` | Supported signed JOSE algorithm; `none` is rejected. |
| `JWT_ISSUER` / `JWT_AUDIENCE` | required | Non-empty exact validation values. |
| `JWT_LEEWAY_SECONDS` | `0` | Clock leeway, 0–300 seconds. |
| `JWT_ACCESS_TOKEN_EXPIRE_SECONDS` | `300` | Access lifetime and maximum accepted access lifetime. |
| `JWT_REFRESH_TOKEN_EXPIRE_SECONDS` | `365 * 3600` | Refresh lifetime and maximum accepted refresh lifetime. |
| `JWT_SESSION_EXPIRE_SECONDS` | `365 * 3600` | Session max age; `0` disables age-out. Cannot exceed refresh lifetime. |
| `JWT_REFRESH_TOKEN_REUSE_GRACE_SECONDS` | `0` | Must remain `0`; positive values fail startup. |
| `JWT_REFRESH_TOKEN_TRANSPORT` | `body` | `body`, `cookie`, or `both`. Cookie/both enable CSRF checks. |
| `JWT_REFRESH_COOKIE_*` | secure defaults | `SameSite=None` requires both Secure and HttpOnly. |
| `JWT_LOGIN_THROTTLE_RATE` | `5/min` | Cache-backed pre-auth limit. `None` or `"0"` explicitly disables. |
| `JWT_REFRESH_THROTTLE_RATE` | `30/min` | Runs before token decode. `None` or `"0"` explicitly disables. |
| `JWT_THROTTLE_CACHE_ALIAS` | `default` | Django cache alias used for counters. Use a shared atomic cache in multi-worker production. |
| `JWT_MAX_ACTIVE_SESSIONS` | `20` | Per-user cap; oldest active sessions are atomically revoked and all active rows are listed. |
| `JWT_MAX_TOKEN_LENGTH` | `8192` | Bound for generated and received tokens. |
| `JWT_MAX_USERNAME_LENGTH` | `254` | Login credential bound. |
| `JWT_MAX_PASSWORD_LENGTH` | `1024` | Login credential bound. |
| `JWT_TRUSTED_PROXY_CIDRS` | `[]` | Proxy networks allowed to supply `X-Forwarded-For`. |
| `JWT_MAX_FORWARDED_HEADER_LENGTH` | `2048` | Forwarded header byte/character bound. |
| `JWT_MAX_FORWARDED_HOPS` | `10` | Entire chain must validate within this limit. |
| `JWT_PERSIST_CLIENT_IP` | `True` | Set false to avoid storing the resolved IP. |
| `JWT_GEOLOCATION_PROVIDER` | `None` | Geolocation is off by default. |
| `JWT_GEOLOCATION_THIRD_PARTY_CONSENT` | `False` | Must be true for the built-in ipapi.co network provider. |
| `JWT_GEOLOCATION_TIMEOUT_SECONDS` | `2.0` | Bounded network timeout. |
| `JWT_GEOLOCATION_MAX_RESPONSE_BYTES` | `32768` | Maximum provider response size. Redirects are rejected. |
| `JWT_USER_LOGIN_AUTHENTICATOR` | Django authenticator | Dotted login callback. |
| `JWT_PAYLOAD_CLASS` | `jwt_ninja.types.JWTPayload` | Subclasses retain custom claims. |

All numeric limits and CIDRs are validated at startup. Throttle cache failures deny authentication rather than silently disabling protection. Django's LocMemCache is isolated per process; select a shared atomic cache with `JWT_THROTTLE_CACHE_ALIAS` and/or enforce an edge limit when a deployment-wide guarantee is required.

## Proxy and privacy model

Forwarded headers are ignored unless the direct peer (`REMOTE_ADDR`) is in a configured trusted CIDR. JWT Ninja validates the whole bounded chain, scans right-to-left past trusted proxies, and safely falls back to the direct peer on malformed or excessive input. Only list proxy networks you operate.

Geolocation output is validated and field/coordinate bounded. Failures remain non-fatal and logs omit the client IP. The built-in provider rejects redirects and oversized responses. Prefer an offline provider; enabling a third-party provider discloses login IP addresses under that provider's privacy terms.
