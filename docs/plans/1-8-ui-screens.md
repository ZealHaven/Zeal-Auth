# Plan 1-8: UI Screens (Server-Rendered)

**Spec:** `docs/specs/1-mvp.md §5`, mockups in `docs/references/auth-platform-mvp-mockups.html`
**Depends on:** 1-3, 1-4, 1-5, 1-6, 1-7
**Estimated scope:** ~8 HTML templates, 1 Go file, ~400 lines total

---

## Context

All auth screens as server-rendered Go templates. Based on the mockups in the references folder. Dark theme, Inter font, consistent with the mockup design.

## Task

### 1. Template engine setup

Create `internal/handler/templates.go`:
```go
var tmpl = template.Must(template.ParseGlob("templates/*.html"))

func renderTemplate(w http.ResponseWriter, name string, data any) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    tmpl.ExecuteTemplate(w, name, data)
}
```

### 2. Base layout (`templates/layout.html`)

Shared HTML skeleton:
- Dark background (`#0F1319`), Inter font from Google Fonts
- Centered card layout, max-width 360px
- Brand placeholder (30x30 colored square)
- Consistent styling matching mockups

### 3. Screens

Create a file per screen or group. Each template receives minimal data (error messages, return URLs, client names).

**templates/signup.html**
- Email + password form → POST /signup
- Social buttons (Google, GitHub) → /oauth/google, /oauth/github
- Link: "Already have an account? Log in"
- Error state: show validation errors inline

**templates/login.html**
- Email + password form → POST /login
- "Forgot password?" link → /forgot-password
- Social buttons
- Link: "New here? Create an account"
- Error state: wrong credentials, email not verified

**templates/check-email.html**
- Email icon
- "Check your inbox" + email address
- "Resend email" button (optional for MVP)

**templates/verify-success.html**
- Checkmark icon
- "Email verified"
- "Continue to log in" button

**templates/verify-expired.html**
- Clock icon
- "This link expired"
- "Send new link" button → POST /forgot-password

**templates/forgot-password.html**
- Email input → POST /forgot-password
- "Back to log in" link

**templates/reset-password.html**
- New password + confirm password → POST /reset-password?token=xxx
- "At least 8 characters" helper text

**templates/authorize.html**
- App banner: "Continue to [ClientName]" (from client registry)
- Login form (if no session)
- Social buttons
- Auto-submit/redirect if session valid (handled in handler, not template)

### 4. Link-account template (for social login account linking)

**templates/link-account.html**
- "An account already exists with this email"
- "Log in to link your [Provider] account"
- Login form → POST /login?link_provider=google

### 5. Handler integration

In auth handlers, replace JSON responses with `renderTemplate` calls for HTML requests. Check `Accept: text/html` header or use URL patterns:
- `/signup` → renders `signup.html`
- `/login` → renders `login.html`
- etc.

Keep JSON responses for API clients (check `Accept` header or `/api/` prefix).

### 6. Static assets (minimal)

For MVP, inline CSS in templates or a single `static/style.css`. No build step. Match mockup design:
- Background: `#0F1319`
- Panel: `#171D26`
- Border: `#2A3341`
- Primary: `#5FD9C0`
- Text: `#E7ECF2`
- Muted: `#8493A6`

## Automatic Testing

### Test file: `internal/handler/templates_test.go`
```go
func TestRenderTemplate_Signup(t *testing.T)           // renders without error, contains form
func TestRenderTemplate_Login(t *testing.T)
func TestRenderTemplate_CheckEmail(t *testing.T)
func TestRenderTemplate_VerifySuccess(t *testing.T)
func TestRenderTemplate_VerifyExpired(t *testing.T)
func TestRenderTemplate_ForgotPassword(t *testing.T)
func TestRenderTemplate_ResetPassword(t *testing.T)
func TestRenderTemplate_Authorize(t *testing.T)
func TestRenderTemplate_LinkAccount(t *testing.T)
func TestRenderTemplate_WithError(t *testing.T)        // error message displayed
func TestRenderTemplate_WithClientName(t *testing.T)   // "Continue to [App]" shown
```

### Test file: `internal/handler/html_flow_test.go`
```go
func TestSignupFlow_HTML_RedirectsToCheckEmail(t *testing.T) // POST /signup → 302 to check-email
func TestVerifyFlow_HTML_ShowsSuccess(t *testing.T)          // GET /verify?token=X → 200 HTML
func TestLoginFlow_HTML_WithSession_CookieSet(t *testing.T)  // POST /login → Set-Cookie header
func TestAuthorizeFlow_HTML_NoSession_ShowsLogin(t *testing.T) // GET /authorize → HTML login form
func TestAuthorizeFlow_HTML_WithSession_ShowsRedirect(t *testing.T) // auto-approve → redirect page
```

**Note:** Tests use `httptest` + `text/html` Accept header. Templates are tested with `template.Execute` to verify rendering. Flow tests make HTTP requests and assert response status + content-type + presence of expected HTML strings.

### Verification command
```bash
go test ./internal/handler/ -run "TestRenderTemplate|TestSignupFlow|TestVerifyFlow|TestLoginFlow|TestAuthorizeFlow" -v -count=1
```

## Acceptance Criteria

- [ ] All 8 screens from mockups rendered as server templates
- [ ] Signup → Check email → Verify flow works end-to-end in browser
- [ ] Login → authorize → redirect flow works
- [ ] Social login buttons redirect to correct OAuth providers
- [ ] Error states display inline (not JSON)
- [ ] Dark theme matches mockup design
- [ ] Forms submit to correct endpoints
- [ ] Link-account screen appears when social login hits existing email
- [ ] `go test ./internal/handler/ -run "TestRenderTemplate|TestSignupFlow|TestVerifyFlow|TestLoginFlow|TestAuthorizeFlow" -v` passes

## Files touched

- `internal/handler/templates.go`
- `internal/handler/templates_test.go`
- `internal/handler/html_flow_test.go`
- `templates/layout.html`
- `templates/signup.html`
- `templates/login.html`
- `templates/check-email.html`
- `templates/verify-success.html`
- `templates/verify-expired.html`
- `templates/forgot-password.html`
- `templates/reset-password.html`
- `templates/authorize.html`
- `templates/link-account.html`
- `templates/redirect.html`
- `static/style.css` (optional, inline in templates)
