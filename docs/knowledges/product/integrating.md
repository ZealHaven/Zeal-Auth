# Integrating a product with Zeal Auth

Recipe for any product — no SDK required. Works against any Zeal Auth instance;
for local dev run `just up && just migrate-up && just seed && just dev` first
(dev seed creates `dev@example.com` / `password123` and two demo clients).

## 1. Register your client

```bash
just seed-client <name> <redirect-uri>
# prints client_id + client_secret ONCE — store the secret; it cannot be re-shown
```

Redirect URIs are matched **exactly** (no prefix matching). Dev allows
`http://localhost:*`; production requires https.

## 2. Authorization Code + PKCE flow

1. **Redirect user** to:

   ```
   {ISSUER}/authorize?response_type=code&client_id=YOUR_CLIENT_ID
     &redirect_uri=YOUR_REDIRECT_URI&scope=openid+profile+email
     &state=RANDOM&code_challenge=BASE64URL(SHA256(verifier))
     &code_challenge_method=S256
   ```

   No session → login screen. Existing session → silent redirect back with `code`.

2. **Exchange code** at `{ISSUER}/token`:

   ```
   POST grant_type=authorization_code&code=...&redirect_uri=...&client_id=...
        &client_secret=...&code_verifier=...
   → { access_token, id_token, refresh_token, expires_in }
   ```

3. **Verify `id_token` locally** against `{ISSUER}/jwks.json` — never call the
   auth service to validate a token:

   ```go
   import (
       "crypto/rsa"
       "encoding/base64"
       "math/big"

       "github.com/golang-jwt/jwt/v5"
   )

   // Fetch JWKS once, cache by kid (refetch on unknown kid)
   resp, _ := http.Get(issuer + "/jwks.json")
   var jwks struct {
       Keys []struct{ Kty, Kid, N, E string } `json:"keys"`
   }
   _ = json.NewDecoder(resp.Body).Decode(&jwks)

   pubKeys := map[string]*rsa.PublicKey{}
   for _, k := range jwks.Keys {
       nb, _ := base64.RawURLEncoding.DecodeString(k.N)
       eb, _ := base64.RawURLEncoding.DecodeString(k.E)
       var e int
       for _, b := range eb {
           e = e<<8 | int(b)
       }
       pubKeys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
   }

   token, err := jwt.Parse(idToken, func(t *jwt.Token) (any, error) {
       if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
           return nil, fmt.Errorf("unexpected alg %s", t.Method.Alg())
       }
       kid, _ := t.Header["kid"].(string)
       pub, ok := pubKeys[kid]
       if !ok {
           return nil, fmt.Errorf("kid %q not in JWKS", kid)
       }
       return pub, nil
   })
   if err != nil || !token.Valid {
       return err // reject — token forged, expired, or key rotated out
   }
   ```

4. **Refresh** when `expires_in` passes:

   ```
   POST grant_type=refresh_token&refresh_token=...&client_id=...&client_secret=...
   → { access_token, id_token, refresh_token }   // old refresh_token is now dead
   ```

   Refresh tokens are **single-use and revocable**: password reset and logout
   revoke every token issued to that user. Treat `invalid_grant` as "send the
   user back to login".

## 3. Logout

Redirect to `{ISSUER}/logout?post_logout_redirect_uri=YOUR_APP_URL` — clears the
SSO session and revokes the user's refresh tokens.

## API reference

| Step | Endpoint | Notes |
|------|----------|-------|
| Authorize | `GET /authorize` | PKCE S256 mandatory, `state` required |
| Token | `POST /token` | code exchange + refresh |
| Verify | `GET /jwks.json` | RS256 keys, cache with kid fallback |
| Discovery | `GET /.well-known/openid-configuration` | all URLs above |
| User info | `GET /userinfo` | Bearer access_token |
| Logout | `GET /logout` | revokes session + refresh tokens |

Scopes: `openid` (issues ID token), `profile`, `email`.
