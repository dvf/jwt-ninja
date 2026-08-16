---
icon: lucide/route
---

# Endpoints

| Method | Path                | Purpose                                         | Success | Errors              |
| ------ | ------------------- | ----------------------------------------------- | ------- | ------------------- |
| `POST` | `/auth/login/`      | Issue an access token and a refresh token       | `200`   | `401`               |
| `POST` | `/auth/refresh/`    | Refresh an access token                         | `200`   | `400`, `401`        |
| `GET`  | `/auth/sessions/`   | List the caller's active sessions               | `200`   | `401`               |
| `POST` | `/auth/logout/`     | Expire the caller's current session             | `200`   | `401`               |
| `POST` | `/auth/logout/all/` | Expire **all** of the caller's active sessions  | `200`   | `401`               |

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

    Send the refresh token cookie that `/auth/login/` set.

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

    Every call to `/auth/refresh/` returns a new refresh token and retires the one you sent. Store the new token and use it for the next refresh. See [Rotation](../guide/refresh-tokens.md#rotation).
