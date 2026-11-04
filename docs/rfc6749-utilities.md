# RFC 6749 utility functions

Issue: [#3](https://github.com/andimon/oat/issues/3)

This note lists the helper functions an OAuth 2.0 authorization server needs to
follow [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749). The helpers are pure
functions under `Oat.OAuth2.*`: no Plug, Ecto or Phoenix types. The endpoints,
storage and consent screens are built on top of them later.

## Modules

| Module | Purpose | RFC sections |
| --- | --- | --- |
| `Oat.OAuth2.Syntax` | Validate each protocol element against the Appendix A ABNF | App. A |
| `Oat.OAuth2.Params` | Decode form/query strings, drop empty values, reject repeated parameters, check required ones, parse `response_type` | 3.1, 3.1.1, 3.2 |
| `Oat.OAuth2.Scope` | Parse, format, resolve and compare scopes | 3.3, 5.1 |
| `Oat.OAuth2.RedirectURI` | Validate and match redirection URIs, add response parameters to the query or fragment | 3.1.2, 4.1.2, 4.2.2 |
| `Oat.OAuth2.ClientAuth` | Encode and decode HTTP Basic client credentials, find which method a client used, compare secrets in constant time | 2.3, 2.3.1, 3.2.1, 5.2 |
| `Oat.OAuth2.Token` | Generate and hash codes and tokens, compute expiry and `expires_in` | 4.1.2, 10.3, 10.4, 10.10 |
| `Oat.OAuth2.TokenResponse` | Token response body and no-cache headers | 4.2.2, 5.1 |
| `Oat.OAuth2.Error` | Error codes, error parameters and token endpoint status | 4.1.2.1, 4.2.2.1, 5.2 |

## Functions and the rule each one covers

### `Syntax`

One predicate per element in Appendix A: `client_id?/1`, `client_secret?/1`,
`response_type?/1`, `scope?/1`, `scope_token?/1`, `state?/1`,
`uri_reference?/1`, `error?/1`, `error_description?/1`, `grant_type?/1`,
`code?/1`, `access_token?/1`, `token_type?/1`, `expires_in?/1`, `username?/1`,
`password?/1`, `refresh_token?/1`, `name?/1` (extension parameter names).

### `Params`

- `decode/1`: parameters without a value count as omitted, and a parameter
  must not appear more than once (§3.1, §3.2). Plug keeps only the last value of
  a repeated parameter, so this runs on the raw query string or body.
- `require/2`: fetch required parameters, report the first missing one
  (`invalid_request`).
- `response_type/1`: space-delimited names, order does not matter (§3.1.1).

### `Scope`

- `parse/1`, `format/1`: space-delimited, case-sensitive tokens (§3.3).
- `resolve/3`: use a default when the client asks for none, or fail with
  `invalid_scope`; reject scopes the client may not have.
- `changed?/2`: when the granted scope differs from the requested one, the
  token response must include `scope` (§3.3, §5.1).

### `RedirectURI`

- `valid?/1`: absolute URI, no fragment (§3.1.2).
- `resolve/2`: exact string match against registered URIs; if the request
  leaves the parameter out, the client must have exactly one registered URI
  (§3.1.2.3). On failure the server must not redirect (§4.1.2.1).
- `append/3`: authorization code responses go in the query, keeping any
  existing query (§3.1.2, §4.1.2); implicit grant responses go in the fragment
  (§4.2.2).

### `ClientAuth`

- `encode_basic/1`, `decode_basic/1`: id and secret are form-encoded before
  Base64 (§2.3.1, Appendix B).
- `extract/2`: returns which method the client used (header, body, public
  client with `client_id` only, or none). Using both the header and body
  credentials is `invalid_request` (§2.3).
- `secret_matches?/2`: constant-time comparison.
- `www_authenticate/1`: header for a 401 `invalid_client` response (§5.2).

### `Token`

- `generate/1`: 256 random bits by default, at least 128 (§10.10). URL-safe
  Base64, so it fits `1*VSCHAR`.
- `hash/1`: store a hash, not the credential itself (§10.3, §10.4).
- `expires_at/2`, `expired?/2`, `expires_in/2`: lifetimes; authorization codes
  should live 10 minutes at most (§4.1.2).

### `TokenResponse`

- `headers/0`: `Cache-Control: no-store` and `Pragma: no-cache` on every token
  response (§5.1, §5.2).
- `build/1`: `access_token`, `token_type`, optional `expires_in`,
  `refresh_token`, `scope`, plus extension parameters that cannot override the
  standard ones.

### `Error`

- `authorization_codes/0`, `token_codes/0`: the error codes each endpoint
  defines.
- `new/2`: refuses descriptions and URIs outside the allowed characters
  (§4.1.2.1, A.8, A.9).
- `to_params/1`: error parameters, including `state` at the authorization
  endpoint.
- `status/2`: 400, or 401 for `invalid_client` when the client used the
  `Authorization` header (§5.2).

## Not in this change

These belong to the endpoints or to storage and come in later issues:

- One-time use of authorization codes, and revoking tokens issued from a reused
  code (§4.1.2, §10.5).
- Checking at the token endpoint that `redirect_uri` and `client_id` match the
  ones used to get the code (§4.1.3).
- Refresh token rotation and scope narrowing on refresh (§6).
- TLS enforcement (§3.1, §3.2, §10.9) and brute-force protection for the
  password grant (§4.3.2, §10.7).
- Related specs that most servers also need: Bearer tokens (RFC 6750) and PKCE
  (RFC 7636).
