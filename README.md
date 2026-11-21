# pure-tcl-oauth2-core

Shared OAuth2/OIDC primitives for Tcl 9.1. Protocol code is Tcl; cryptography is
provided by native packages. Install this package independently, or through the
client/server packages. JSON is parsed and generated with `tjson`.

Dependencies: `tjson >=1.0.30`, `thashlib >=0.1.1`, `tink >=20240704.0.3`
(the distribution is named `tink-tcl`). The optional SQL backend needs
`tpersist >=0.1.5` and its SQLite or PostgreSQL driver. No JOSE extension is needed.

```tcl
package require pure-tcl-oauth2-core 0.1.1
set pair [::oauth2::core::pkce]
# dict: code_verifier, code_challenge, code_challenge_method (S256)
set bytes [::oauth2::core::b64decode [::oauth2::core::b64encode abc]]
```

## JSON and protocol helpers

`json text` / `json_bytes utf8Bytes` return the field dictionary of a **typed**
JSON object. `encode_json typedFields` serializes it. Values use tjson notation:
`{S text}`, `{N 42}`, `{BOOL 1}`, `{N null}`, `{L typedValues}`, `{M typedFields}`.
`claim_string fields name ?default?` and `value fields name type ?default?`
enforce types. Duplicate members, malformed UTF-8, NUL, non-finite numbers and
documents exceeding 32 levels of nesting or 1 MiB are rejected. Boolean `true` is never accepted as a string.

Other commands in `::oauth2::core`:

| Command | Purpose |
| --- | --- |
| `random ?bytes=32?` | CSPRNG bytes encoded as unpadded base64url |
| `digest text` / `equal text text` | SHA-256 UTF-8 digest / constant-time equal-length comparison |
| `pkce` / `pkce_challenge verifier` | RFC 7636 S256; 43–128 character verifiers |
| `form_encode fields` / `form_decode body` | UTF-8 URL encoding; reject duplicate parameters and malformed input |
| `query_url url fields` | Append encoded query parameters |
| `url value ?allowHttpLoopback=false?` | HTTPS endpoint validation; explicit loopback HTTP exception |
| `scopes text` / `scope_subset requested allowed` | Validate and constrain scopes |
| `bearer authorizationHeader` | Extract a bearer credential |
| `response typedFields ?status=200?` / `error_response code ?status=400?` | `{statusCode headers body}` with JSON and no-store headers |

`jwt_parts compact algorithms` is **unverified** preflight data, only for key
selection. `jwks_key typedJwks kid algorithm` returns an owned Tink public handle;
always unregister it. It rejects ambiguous matches and private key material.
JWT-provided URLs are never followed.

`jwt_verify key compact -issuer issuerList -audience clientId` returns typed
claims only after signature/MAC and claim validation. Options are `-algorithms
{RS256}`, `-nonce {}`, `-type {}`, `-now seconds`, `-skew 60` (maximum 300),
`-access_token {}` (checks `at_hash` when supplied), and `-mac false`.
Expiration, issue time, subject and audience are required. Multiple audiences
require `azp`; issuer, nonce, authorized party, time bounds and algorithm policy
are checked. Symmetric JWTs require explicit MAC mode and an HS algorithm policy.

## Storage

```tcl
package require tpersist
set db [::tpersist::db_connect -database oauth.sqlite -autobegin 0]
::oauth2::store::initdb $db  ;# explicit provisioning, not a request-time action
set store [::oauth2::store::sql $db my-tenant]
# For tests or a single-process demonstration only:
set temporary [::oauth2::store::memory]
```

Each worker owns a store object and borrows a connection. Use the same tenant,
database and persistent encryption keys in every worker serving a client.
Destroy objects with `$store destroy`; the caller closes the borrowed connection.
Schedule `$store prune [clock seconds]` to remove expired records. Memory storage
is neither durable nor shared across workers. SQL uses bound values, transactions
and revision-based compare-and-swap on SQLite and PostgreSQL.

The backend interface is `durable`, `atomic commandPrefix`, `get kind id now`,
`put kind id data expires ?group?`, `replace kind id oldRecord data`,
`delete kind id oldRecord`, and `prune now`. `get` returns `{data expires revision
group}` or empty. Replace/delete return the number of changed rows. Atomic scripts
must either commit entirely or roll back on error. Storage objects are trusted
application internals, not request-facing APIs. Client transactions are AEAD
encrypted when durable; server bearer credentials are stored only as hashes.
SQL server profile data is not automatically encrypted: protect the database.

## Build and test

After installing native dependencies in a prefix visible to Tcl:

```sh
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/your/prefix
cmake --install build
tclsh9.1 tests/all.tcl
```

Use the same steps for the client, server and examples packages. Add the prefix's
`lib` directory to `TCLLIBPATH`. These are source packages with CMake installation
and `ttrek.json` manifests; registry publication is a separate release action.
Errors use `-errorcode {OAUTH2 code}`. Do not log request bodies, tokens, callbacks,
private configuration or full Tcl error stacks containing those values.
