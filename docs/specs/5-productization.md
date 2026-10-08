# Auth Platform — Iteration 5: Productization (Phase D)

**Goal:** Elevate from "our login service" to the central auth *product*: operable by a human, extensible per app.

**Status:** Not started
**Depends on:** 4-prod-hardening.md

---

## 1. Scope

### Admin dashboard
| # | Item | Detail |
|---|------|--------|
| 5.1 | Admin auth + roles | Admin role on users; admin session; all admin routes gated (extends 2.5). |
| 5.2 | Users admin | List/search users, verify email manually, disable account, force password reset. |
| 5.3 | Clients admin | List/create/disable OAuth clients (AC-CLIENT-3: disable invalidates tokens). |
| 5.4 | Sessions admin | List active sessions per user, remote logout (`delete-all-for-user` exists, `session.go:89`). |
| 5.5 | Audit log | Record: login, signup, reset, client create/disable, admin actions → `audit_log` table (Kafka deferred; DB first). |

### Identity features
| # | Item | Detail |
|---|------|--------|
| 5.6 | MFA (TOTP) | Enroll/verify TOTP; login step-up when enabled; recovery codes. |
| 5.7 | Session/device management (self-service) | Profile page: active devices, revoke individually. |
| 5.8 | RP-initiated logout | `id_token_hint` + `post_logout_redirect_uri` per OIDC; federated logout propagation. |
| 5.9 | Profile/settings page | View email/name, change password (sessions revoked per AC-RESET-3), link/unlink social identities (completes 2.7). |

### OAuth extensibility
| # | Item | Detail |
|---|------|--------|
| 5.10 | Consent screen + scopes | Per `1-mvp.md` §8: scope definitions per product, approval screen for third-party-ish clients. |
| 5.11 | `client_credentials` grant | Service-to-service tokens via fosite (compose factory currently skips it). |
| ✅ 5.12 | Token introspection | ~~Expose advertised `/introspect`~~ Done in spec 2 (2.6): `POST /introspect` registered, client auth via Basic, discovery accurate. |
| 5.13 | Event webhooks | Notify products: user.created, user.disabled, session.revoked (HMAC-signed). |
| 5.14 | Developer self-service portal | `1-mvp.md` §8: developers register/manage their own clients (names, redirect URIs, secrets rotate), usage view. Supersedes raw `POST /admin/clients` for day-to-day use. |
| 5.15 | Dynamic Client Registration | RFC 7591 `POST /register` for approved third-party developers (opt-in; own products keep seeded clients from spec 3). |
| 5.16 | RBAC / fine-grained scopes | Role claims in tokens, per-role scope grants beyond 5.10's consent scopes (e.g. `admin`, `billing:read`). |
| — | Multi-tenancy | **Backlog beyond iteration 5** — no home yet; revisit after productization ships. |

## 2. Acceptance Criteria

- **AC-5-1** Non-admin hits any `/admin/*` → 403; admin sees dashboard.
- **AC-5-2** Admin disables client → subsequent `/authorize` + `/token` rejected; existing tokens invalidated.
- **AC-5-3** Admin revokes user sessions → next product request re-authenticates.
- **AC-5-4** TOTP enabled → login requires second factor; recovery code works; replayed TOTP rejected.
- **AC-5-5** User sees own sessions, revokes one → that session cookie dead immediately.
- **AC-5-6** RP-initiated logout clears session and returns to product's registered post-logout URI only (exact match).
- **AC-5-7** Audit trail complete for §1 admin/auth actions (queryable by actor + time).
- **AC-5-8** Consent screen appears only for clients lacking pre-granted scopes; remembered grant skips it.
- **AC-5-9** Webhook receiver gets signed `user.created` within seconds of signup.
- **AC-5-10** Developer registers a client via portal UI (not raw admin API), secret shown once, usable at `/authorize` immediately.
- **AC-5-11** `POST /register` with valid software statement → client created; rejected for unknown developers when allowlist enforced.
- **AC-5-12** Token carrying `admin` role passes a role-gated check; same token without the role is denied.
