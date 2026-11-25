# Changes made by 076one to the Predator VPN core (GPL-3.0-or-later)

Upstream: erfan-tahvilian/PredatorVPN v2.0.7. The rest of this directory is unchanged.

- 2026-11-25, 076one v1.8.7: `mobile/control.go` — Firefox "Client Challenge" (captcha) context raised from 180 s to 15 minutes, so a user has time to read and answer the image.
- 2026-11-26, 076one v1.8.8: `mobile/control.go` — when the Firefox Accounts API returns an error with `retryAfter`, the value is appended to the error message as `[retryAfter=N]` so the app can show when sign-in unlocks.

The 076one front end `fpn/main.go` (also GPL-3.0-or-later) raised its captcha answer wait from 170 s to 10 minutes in v1.8.7.
