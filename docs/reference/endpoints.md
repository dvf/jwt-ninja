---
icon: lucide/route
---

# Endpoints

All responses use `Cache-Control: no-store` and `Pragma: no-cache`. Login and refresh require a JSON media type. In cookie or both mode, call `GET /auth/csrf/`, retain its CSRF cookie, and send the returned `csrf_token` in `X-CSRFToken` on login and refresh.

| Method   | Path                   | Purpose                                         | Success | Errors              |
| -------- | ---------------------- | ----------------------------------------------- | ------- | ------------------- |
| `GET`    | `/auth/csrf/`          | Set CSRF cookie and return a masked token       | `200`   | —                   |
| `POST`   | `/auth/login/`         | Issue an access token and a refresh token       | `200`   | `401`, `403`, `415`, `429` |
| `POST`   | `/auth/refresh/`       | Strictly consume and rotate a refresh token     | `200`   | `400`, `401`, `403`, `415`, `429` |
| `GET`    | `/auth/sessions/`      | List the caller's active sessions               | `200`   | `401`               |
| `DELETE` | `/auth/sessions/{id}/` | Revoke a single session                         | `200`   | `401`, `404`        |
| `POST`   | `/auth/logout/`        | Expire the caller's current session             | `200`   | `401`               |
| `POST`   | `/auth/logout/all/`    | Expire **all** of the caller's active sessions  | `200`   | `401`               |

## `POST /auth/login/`

**Request**

```json
{ "username": "alice", "password": "hunter2" }
```

**Response (`200`)**

=== "`body` mode"

    ```json
    { "access_token": "eyJhbGci…", "refresh_token": "eyJhbGci…" }
    ```

=== "`cookie` mode"

    ```json
    { "access_token": "eyJhbGci…" }
    ```

    The server sets the refresh token as an HttpOnly cookie and does not return it in JSON.

In `both` mode, the server returns the refresh token in JSON **and** sets the cookie.

## `POST /auth/refresh/`

**Request**

=== "`body` mode"

    ```json
    { "refresh_token": "eyJhbGci…" }
    ```

=== "`cookie` mode"

    Send `{}` as JSON with the refresh token cookie that `/auth/login/` set and a valid `X-CSRFToken` header.

**Response (`200`)**

=== "`body` mode"

    ```json
    { "access_token": "eyJhbGci…", "refresh_token": "eyJhbGci…" }
    ```

=== "`cookie` mode"

    ```json
    { "access_token": "eyJhbGci…" }
    ```

!!! warning "Refresh tokens are rotated"

    Every call atomically consumes the current token. Store the replacement immediately. Concurrent/replayed use revokes the session. If a response is lost, do not retry the uncertain old token; require reauthentication. See [Strict atomic rotation](../guide/refresh-tokens.md#strict-atomic-rotation).

## `GET /auth/sessions/`

Returns every active session for the authenticated user — one per logged-in device. Render it as a "where you're signed in" screen.

**Response (`200`)**

```json
[
  {
    "id": "8dKt2…",
    "created_at": "2026-08-16T09:12:03Z",
    "last_activity_at": "2026-08-16T11:47:20Z",
    "ip_address": "203.0.113.42",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) … Chrome/126.0.0.0 Safari/537.36",
    "browser": "Chrome on macOS",
    "location": {
      "city": "Amsterdam",
      "region": "North Holland",
      "country": "Netherlands",
      "country_code": "NL",
      "latitude": 52.37,
      "longitude": 4.89
    },
    "is_current": true
  }
]
```

| Field | Meaning |
| ----- | ------- |
| `ip_address` | Client IP recorded at login. `null` when it could not be determined. Treat as a hint — see [the IP caveat](../guide/sessions.md#the-session-list). |
| `user_agent` | Raw `User-Agent` header sent at login. `null` if the client sent none. |
| `browser` | Best-effort "Chrome on macOS" summary parsed from `user_agent` in-process — no dependency, no lookup. `null` when unrecognized. |
| `location` | Where the login IP appeared to be. `null` unless a [geolocation provider](../guide/sessions.md#session-geolocation) is configured. |
| `is_current` | `true` on the session this request authenticated with, so the client can label it "this device" and warn before revoking it. |

## `DELETE /auth/sessions/{id}/`

Revokes a single session — the "sign out that device" button next to each row of the session list.

**Response (`200`)** — empty. The session no longer authenticates requests or refreshes tokens.

**Response (`404 session_not_found`)** — the id is not one of the caller's own active sessions: it belongs to another user, is already expired, or never existed. The three cases are deliberately indistinguishable.

!!! note "Revoking the current session"

    Revoking the session the request authenticated with is equivalent to `POST /auth/logout/`, including clearing the refresh cookie under cookie transport.
