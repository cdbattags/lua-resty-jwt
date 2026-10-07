# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, minor releases may
contain breaking changes. Changes before 0.4.0 are only recorded in the git
history and the [GitHub releases](https://github.com/cdbattags/lua-resty-jwt/releases).

## [0.4.0] - UNRELEASED

0.4.0 is a security release. It fixes several vulnerabilities and hardens
every verification and decryption path. Some of the changes are **breaking**:
read [Upgrading from 0.3.x](#upgrading-from-03x) before upgrading.

### Security

<!-- Fill in the GHSA/CVE IDs when the advisories are published, not before. -->

- **Critical: forged JWE accepted when a public key is used as the PBES2 password** (0.3.0–0.3.2).
  Applications calling `jwt:verify(public_key_pem, token)` without an algorithm whitelist
  accepted attacker-made PBES2 JWEs. JWE key management algorithms are now bound to
  compatible key types. GHSA-TBD.
- **Algorithm confusion: an RSA/EC public key was accepted as the HMAC secret** with no
  whitelist set (all versions). GHSA-TBD.
- **JWE AES-GCM tag length was not enforced**, allowing forgery with truncated tags
  (0.2.3–0.3.2). Tags must now be exactly 16 bytes. GHSA-TBD.
- **Remote nginx worker crash** when an ES*-signed token was verified with an RSA key
  (0.2.3–0.3.2), or when an `x5c` token was verified with an unloadable trusted-certs file
  (all versions). GHSA-TBD.
- **AES-CBC-HMAC JWE was decrypted before its tag was checked**, and claims were validated
  before authentication (a padding/decryption oracle; all versions). GHSA-TBD.
- **Unbounded PBES2 iteration count, and the alg whitelist was not applied to JWE**
  (CPU exhaustion; PBES2 in 0.3.0–0.3.2, the whitelist was ignored for JWE in all
  versions). GHSA-TBD.
- **Token malleability**: non-canonical compact serializations (extra dots, padding, the
  standard base64 alphabet, non-zero trailing bits) verified as the original token
  (all versions). GHSA-TBD.
- `sign` could echo the whole secret into the error reason when an RSA-OAEP JWE was signed
  with a key that was neither a certificate nor a public key. If you hit that error in
  production, rotate the key.
- HS256/384/512 signatures are compared in constant time, and only their canonical
  encoding is accepted.
- `evp.lua`: about ten NULL-dereference, buffer-overflow and leak fixes in the OpenSSL FFI
  layer, and every constructor now returns its own instance (before, each `new()` replaced
  the key of every object made earlier).

### Breaking changes

Verification and keys:
- HS* secrets that contain PEM (`-----BEGIN`) or DER key material, empty secrets, and
  asymmetric JWKs or key objects are rejected for HMAC, when signing and when verifying.
- Algorithms are bound to key types: RS*/PS* require RSA, ES256/384/512 require
  P-256/P-384/P-521, Ed25519/Ed448 require the matching OKP key and EdDSA either one.
  Mismatches fail with `key type mismatch: …`. Signing with ES256/384/512, Ed25519, Ed448
  or EdDSA also requires the matching key, so the library no longer produces mislabeled
  tokens (0.3.x, for example, signed an `Ed448` token with an Ed25519 key).
- Signing with Ed25519, Ed448 or EdDSA accepts only a PEM or DER private key string. `nil`,
  a table (such as a JWK) or a key object fails with `failed to load EdDSA private key:
  expected a PEM or DER string`, and a public key with `failed to load EdDSA private key: a
  public key cannot sign` (see Fixed).
- Signatures (and JWE authentication) are verified **before** claims are validated. A
  signature failure always wins. Validators receive `jwt_json` with `verified=true` and
  no JWE internals.
- `lifetime_grace_period` (legacy options) applies to that call only and no longer changes
  the global leeway.
- A non-string `kid` is rejected when the key is looked up by `kid` (a secret function or a
  JWK Set). Malformed headers (non-object JSON, non-string alg/kid, malformed x5c/x5u)
  give clean reasons instead of Lua errors.
- HS verification no longer applies the sign-side `typ` check, so `typ: at+jwt` tokens verify.

Parsing:
- Compact serializations are parsed strictly: exactly 3 (JWS) or 5 (JWE) parts, every part
  canonical unpadded base64url. The 4-part JWE form is gone. Empty parts are allowed only
  for the JWE encrypted key of `dir`/`ECDH-ES` and an AES-GCM ciphertext. `dir` and
  `ECDH-ES` require an empty encrypted key, and the other algs a non-empty one.
- Tokens with a `crit` header are rejected unless every listed extension is declared with
  `jwt:set_crit_whitelist`.
- `__header` is now a reserved claim-spec key.

JWE:
- `jwt:set_alg_whitelist` now also applies to JWE `alg` **and** `enc`, checked before any key work.
- Every JWE tag/MAC check, key unwrap, content decryption and decompression failure returns
  the single reason `failed to decrypt JWE`. Malformed IV or tag lengths and invalid header
  parameters (`p2c`, `p2s`, `iv`/`tag` of AES-GCM key wrap, ...) are rejected earlier, with
  their own reasons.
- AES-GCM JWE always uses 16-byte tags, for content encryption and for AES-GCM key wrap.
  0.3.x emitted 8-byte tags for A128GCM/A128GCMKW and 12-byte tags for A192GCM/A192GCMKW;
  those tokens no longer decrypt.
- PBES2 `p2c` must be an integer in [1000, 10000] by default (`jwt:set_pbes2_max_count`), and
  `p2s` must be at least 8 octets.
- AES key wrap algorithms (A*KW, A*GCMKW) require keys of exactly their size (16, 24 or 32
  bytes), when encrypting and decrypting. Before, the key's length picked the AES variant.
- `dir`, A*KW, A*GCMKW and PBES2 refuse PEM or DER key material and empty secrets as the
  shared key or password, when encrypting and decrypting. Encrypting also requires the key
  to be a string.
- ECDH-ES+A*KW now follows RFC 7518's Concat KDF. Tokens from 0.3.x need the deprecated,
  decrypt-only `jwt:set_legacy_ecdh_kw_kdf(true)`, which will be removed in 1.0. Invalid
  `apu`/`apv` are rejected; `epk` is validated (EC P-256/384/521 only; secp256k1 refused).
- `zip` (which 0.3.x ignored) is rejected on a JWS. A JWE with a `zip` header is rejected
  (`unsupported zip: DEF`) before key work unless a handler for that value is registered,
  and none is by default. 0.3.x ignored `zip` and passed the still-compressed bytes to the
  payload decoder (with the default JSON decoder, the payload was `nil`). `sign` with a
  `zip` header raises the same reason. Enable `DEF` with `jwt:register_zlib_compression()`.
  JWEs that 0.3.x signed with a `zip` header were never actually compressed, so they don't
  decrypt in 0.4.0 even with compression enabled; reissue them without `zip`.

Token output:
- `sign` serializes the header with a stable parameter order (`typ`, `alg`, `enc`, `zip`,
  `kid`, then the rest sorted by name), so the same input always gives the same token. The
  token bytes can differ from what 0.3.x produced for the same input; both verify.
- A payload encoder set with `set_payload_encoder` (on the module or an instance) is now
  also used when signing a JWS, not only a JWE, so an application that set one for JWE
  gets it applied to its JWS payloads too (see Fixed).
- A JWE keeps its `typ` header (RFC 7516 4.1.11); 0.3.x silently dropped it. A JWE signed
  with `typ` now carries it in the protected header, so `verify_with`'s `typ` option and
  `validators.typ_is` can check it. `sign` no longer adds `epk`, `iv`, `tag`, `p2s` or `p2c`
  to the caller's header table, nor removes `typ` from it.

Validators:
- Validators receive the verified payload as a 4th argument (`chain` forwards it).
- `jwt_json` is only built for validators that can read it: it is `nil` for the validators of
  `resty.jwt-validators` and for functions declaring fewer than three parameters, which
  could never observe it.

Packaging:
- `lua-resty-openssl` >= 1.1.0 is required (OPM: >= 1.2.0, as OPM has no 1.1.x build).
  0.8.0 and older don't load against OpenSSL 3, and 1.0.x lacks APIs this release uses.
- The OPM package no longer depends on `jkeys089/lua-resty-hmac`. Code that requires
  `resty.hmac` itself must depend on it directly.
- `resty.evp` and `resty.jwt-validators` no longer have a `_VERSION` (it was a stale
  "0.2.4"). `resty.jwt`'s `_VERSION` is the release version.

Reason strings:
- Some `reason` strings changed. Match on `verified`, not on `reason` text:
  - a non-canonical signature encoding gives `invalid jwt string: non-canonical base64url
    in signature` (0.3.x: `Wrongly encoded signature`, or `Verification failed` from
    `resty.evp`);
  - `invalid secret type (must be string or function)` is now `invalid secret type (must
    be string, function, JWK or key object)`;
  - a key of the wrong type or curve for the alg gives `key type mismatch: …` (0.3.x: for
    example `signature length != 2 * order length`, or a crash);
  - signing Ed25519/Ed448/EdDSA with a public key gives `failed to load EdDSA private key:
    a public key cannot sign` (0.3.x: `EdDSA sign error: …`);
  - JWE authentication and decryption failures give `failed to decrypt JWE` (see JWE).

Other:
- A JSON-string secret with a `kty` or `keys` member is parsed as a JWK, not used as raw
  HMAC bytes.
- A secret function must return a string. Any other non-nil value fails with
  `function returned a non-string secret for kid: …`.
- `sign` raises `invalid typ: must be a string` for a non-string `typ` (0.3.x raised a Lua
  error for a table).

### Added

- `jwt:verify_with(secret, token, options)`: per-call allowed `algorithms` (required; for a
  JWE both `alg` and `enc`), checked before any decryption, plus `claim_specs` and the
  options `issuer`, `audience`, `max_age`, `required_claims`, `typ` and `jti`. Each option
  makes its claim (or header) required. The `jti` hook runs after every other check.
- Claim validators in `resty.jwt-validators`: `audience` (RFC 7519 `aud`, a string or an
  array), `issued_at` (`iat` not in the future, optional `max_age`), `jti_hook` (replay
  detection) and `required_claims`. `is_not_before`, `is_not_expired` and `is_at` take an
  optional per-validator `{ leeway = n }`.
- `jwt:validate_claims(jwt_obj, ...)` runs claim specs against an object that was already
  verified, and refuses objects whose `verified` isn't `true`. The idea comes from the
  HalleyAssist fork.
- JWK and JWK Set keys (table or JSON), `resty.openssl.pkey`/`x509` objects, and reusable
  key objects via `jwt:load_key`. JWKS keys are selected by `kid`/`kty`/`crv`/`use`/`key_ops`/`alg`.
  New module `resty.jwt.jwk` with RFC 7638 thumbprints.
- Opt-in JWE compression (`zip: "DEF"`), off by default: `jwt:register_zlib_compression()`
  enables a built-in raw-DEFLATE provider over the system zlib (new module `resty.jwt-zlib`,
  no new dependency; raises at registration if zlib cannot be loaded),
  `jwt:register_zlib_compression(require "zlib")` uses lua-zlib instead, and
  `register_compression_alg` registers any handler. Registrations apply to the module or a
  single instance. Inflate is bounded (`jwt:set_zip_max_size`) and runs only after the
  content is authenticated. Based on PR #71.
- Configurable sign-side `typ` whitelist (`jwt:set_typ_whitelist`; case-insensitive,
  `application/` prefix ignored). Based on PR #72.
- `crit` handling (`jwt:set_crit_whitelist`) and header validators (`__header`,
  `validators.typ_is`, `validators.normalize_typ`).
- `jwt:set_pbes2_max_count`, `jwt:set_legacy_ecdh_kw_kdf` (deprecated).
- EdDSA verification accepts a PEM certificate.
- RFC 7520 and RFC 7518 Appendix C known-answer tests, plus interop checks with jwcrypto.
- LuaLS (`---@class`/`---@param`) annotations for `resty.jwt`, `resty.jwt-validators` and
  `resty.jwt.jwk`.
- [RELEASING.md](RELEASING.md), and `./ci-release-dry-run X.Y.Z`, which builds and checks both
  release packages locally without uploading.

### Changed

- `sign`'s default `typ` check is wider: besides `JWT` and `JWE` it accepts the registered
  `+jwt` types (`at+jwt`, `dpop+jwt`, `token-introspection+jwt`,
  `client-authentication+jwt`, `secevent+jwt`, `logout+jwt`), compared case-insensitively
  and ignoring an `application/` prefix. 0.3.x accepted only the exact strings `JWT` and
  `JWE`. Use `jwt:set_typ_whitelist` to narrow it.
- The trusted-certs store is cached per worker and path: edits to the file under the same
  path are not picked up until nginx reloads, or until the same object sets another path
  and then this one again (see the README).
- Internal HMAC uses `resty.openssl.hmac`. The vendored `resty.hmac` is still shipped in the
  LuaRocks package but unused, and will be removed in 1.0.
- base64url encoding and decoding use lua-resty-core's `ngx.base64` (with the old code as a
  fallback), and `resty.jwt.jwk` shares the same strict decoder as token parsing.
- `validate_claims` no longer JSON-encodes the whole token on every verification.
- The publish workflow refuses a tag that doesn't match `_VERSION` before building or
  uploading anything, runs the suite through `./ci` first, and only runs for published,
  non-pre-release GitHub releases.
- The examples log `reason` instead of returning it, return a bare 401, and pin their
  algorithms with `verify_with`.

### Fixed

- `set_payload_decoder` on a `jwt.new()` instance is used when parsing a JWS, and
  `set_payload_encoder` (on the module or an instance) is used when signing one. Both were
  ignored for JWS.
- A JWE whose plaintext isn't JSON returns the raw string as its payload, like a JWS,
  instead of `payload = nil`.
- Claims of non-object payloads are treated as absent: a string payload no longer
  satisfied `validators.required()` for claims such as `sub`, and number or boolean
  payloads no longer raise a Lua error.
- `sign` with Ed25519, Ed448 or EdDSA and a `nil`, table or key-object key raises an error.
  0.3.x passed the key to `pkey.new`, which generated a random RSA key for it, so `sign`
  returned a token labeled EdDSA that carried an RSA signature, which no key the caller
  held could verify.
- JWE encryption with RSA-OAEP, RSA-OAEP-256/384/512, ECDH-ES or ECDH-ES+A*KW and a key that
  isn't a string (`nil`, a table such as a JWK, or a key object) raises `invalid key for
  <alg>: expected a PEM string`. 0.3.x raised a raw Lua error for RSA-OAEP, and for ECDH-ES
  generated a random RSA key before failing with `unsupported EC curve NID: nil`.
- RS/PS/ES signing failures raise a clean `{ reason = ... }` instead of failing later in
  `jwt_encode(nil)`, and so does a failed RSA-OAEP encryptor in JWE signing.
- A JWE header with a missing or non-string `alg`/`enc` gives a clean reason.
- `resty.evp` accepts DER public keys (`d2i_PUBKEY_bio` was never declared).

### Deprecated

- `jwt:set_legacy_ecdh_kw_kdf`, to be removed in 1.0.
- The vendored `resty.hmac` module (third-party/lua-resty-hmac), to be removed in 1.0.

### Upgrading from 0.3.x

The changes you are most likely to hit, and what to do about them:

1. **A JWE no longer decrypts with your alg whitelist** (`whitelist unsupported alg/enc`).
   `set_alg_whitelist` and `verify_with`'s `algorithms` now apply to JWE, and both the key
   management `alg` and the content `enc` must be listed, e.g.
   `{ RS256 = 1, ["RSA-OAEP-256"] = 1, A256GCM = 1 }`.
2. **Your HMAC secret is refused** (`invalid secret for HS256: …`). Empty secrets, secrets
   containing `-----BEGIN` or a DER key/certificate, and asymmetric JWKs can't be HMAC keys
   any more. A JSON string with `kty` or `keys` is now read as a JWK. Use a random secret
   (at least as long as the hash, e.g. 32 bytes for HS256) or an `oct` JWK. If your secret
   was public key material, every token MACed with it could have been forged: rotate it.
3. **Tokens you accepted before now fail to parse** (`invalid jwt string: …`). Every part
   must be canonical, unpadded base64url, a JWS has exactly 3 parts and a JWE exactly 5
   (`header..iv.ciphertext.tag` for `dir`/`ECDH-ES`), and no other part may be empty. Fix the
   issuer: tokens with padding, `+`/`/`, extra dots or the old 4-part JWE form were never
   valid.
4. **Tokens with a `crit` header are rejected** (`unsupported critical header parameter: …`).
   Declare the extensions you understand with `jwt:set_crit_whitelist({ "ext" })` and
   enforce them with `__header` validators.
5. **A128GCM/A192GCM tokens from 0.3.x fail** (`invalid JWE authentication tag length`), as
   do A128GCMKW/A192GCMKW ones (`invalid iv/tag length in header for AES-GCM key wrap`).
   0.3.x emitted truncated tags that no other library accepts, and there is no
   compatibility switch: re-issue them with 0.4.0.
6. **ECDH-ES+A128KW/A192KW/A256KW tokens from 0.3.x fail** (`failed to decrypt JWE`). Call
   `jwt:set_legacy_ecdh_kw_kdf(true)` while they are still in circulation, then turn it off;
   it will be removed in 1.0. Direct `ECDH-ES` tokens whose `apu`/`apv` contain `-`, `_`,
   `+`, `/` or `=` (0.3.x decoded them as standard base64) have no fallback and must be
   re-issued.
7. **Claims are checked after the signature.** For a token with a bad signature and a
   failing claim, `reason` is now the signature failure, validators only ever see
   authenticated tokens (`jwt_json` has `verified = true`, and no JWE key material), and
   `lifetime_grace_period` no longer changes the leeway of later verifications: use
   `validators.set_system_leeway(n)` if you relied on that.
8. **Dependencies.** Install `lua-resty-openssl` >= 1.1.0 (OPM >= 1.2.0). On OPM, code
   that requires `resty.hmac` directly must now depend on `jkeys089/lua-resty-hmac`
   itself. Also check `set_pbes2_max_count` if you accept PBES2 tokens with more than
   10000 iterations, and AES key wrap keys, which must now have exactly the alg's size.
9. **JWEs with `zip: "DEF"` are rejected** (`unsupported zip: DEF`). Compression is opt-in:
   call `jwt:register_zlib_compression()` (built-in, system zlib) or pass a lua-zlib module,
   and drop any custom payload decoder that inflated the payload itself. Tokens that 0.3.x
   signed with a `zip` header were never compressed and must be reissued without it.

### Credits

Thanks to everyone whose work shaped this release (GitHub accounts verified):
- @spacewander: evp NULL-check fixes (PR #73), and the original strict-split fix (api7 PR #1)
- @jattsson: JWE compression (PR #71) and the configurable typ whitelist (PR #72)
- @tzssangglass: the secret-in-error fix (api7 PR #2)
- @splitice: per-instance evp objects and the `d2i_PUBKEY_bio` declaration (HalleyAssist fork)
- Earlier co-authors whose work this release builds on: @adanegit (PS256/PS512, PR #57),
  @yciabaud (RSA-OAEP, PR #58), @ObeydKhan (ECDH-ES, PR #66)

[0.4.0]: https://github.com/cdbattags/lua-resty-jwt/compare/v0.3.2...v0.4.0
