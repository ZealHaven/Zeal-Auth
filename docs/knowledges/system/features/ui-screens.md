---
feature: ui-screens
status: delivered
specs: [docs/specs/1-mvp.md]
plans: [docs/plans/1-8-ui-screens.md]
commits: (see git log)
---

# UI Screens (Server-Rendered)

## What Was Built
10 server-rendered HTML templates with dark theme, served alongside JSON API endpoints. Content negotiation via Accept header / User-Agent detection. HTML form handlers for browser users, JSON handlers for API clients.

## Position in Auth Platform
Presentation layer — all auth flows (signup, login, verify, reset, authorize, link-account) now have browser-facing UI. API clients continue to get JSON.

## Screens

| Template | Route | Purpose |
|----------|-------|---------|
| signup.html | GET /signup | Registration form |
| login.html | GET /login | Login form + social buttons |
| check-email.html | GET /check-email | "Check your inbox" after signup |
| verify-success.html | GET /verify?token=X | Email verified confirmation |
| verify-expired.html | GET /verify?token=X | Expired verification link |
| forgot-password.html | GET /forgot-password | Password reset request |
| reset-password.html | GET /reset-password?token=X | New password form |
| authorize.html | GET /authorize | OAuth consent + login |
| link-account.html | GET /link-account | Social login account linking |
| redirect.html | (internal) | Post-auth redirect with JS fallback |

## Architecture

| Layer | File | Pattern |
|-------|------|---------|
| Template engine | internal/handler/templates.go | sync.Once, runtime.Caller for path resolution |
| HTML handlers | internal/handler/html_handler.go | Content negotiation (Accept/User-Agent) |
| Styles | templates/styles.html | Shared CSS partial (dark theme) |
| Templates | templates/*.html | Self-contained HTML (each includes styles partial) |
| Router | internal/handler/handler.go | Separate GET page routes + POST form routes |
| Tests | internal/handler/templates_test.go, html_flow_test.go | Template rendering + form submission flows |

## Key Patterns

- **Self-contained templates**: Each template includes full HTML + styles partial (no Go template inheritance conflicts)
- **Path resolution**: `runtime.Caller(0)` to find templates relative to source file (works in tests and prod)
- **Form routes**: Separate `/signup-form`, `/login-form`, etc. POST routes for HTML forms (JSON routes unchanged)
- **Content negotiation**: `isHTMLRequest()` checks Accept header, User-Agent, Referer for browser detection
- **Verify handler**: Content-negotiates — returns HTML for browsers, JSON for API clients

## Design Tokens

| Token | Value |
|-------|-------|
| Background | #0F1319 |
| Card | #171D26 |
| Border | #2A3341 |
| Primary | #5FD9C0 |
| Text | #E7ECF2 |
| Muted | #8493A6 |
| Error | #EF4444 |
| Font | Inter (Google Fonts) |

## Known Issues / Deferred Work
- No client-side form validation beyond HTML5 attributes
- No "resend verification email" button on check-email page
- Root `/` route added separately (redirects to /login)
