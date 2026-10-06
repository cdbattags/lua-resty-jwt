**DISCLAIMER:**
 
As discussed in https://github.com/SkyLothar/lua-resty-jwt/issues/85, this project is a fork of https://github.com/SkyLothar/lua-resty-jwt by @SkyLothar that has now been adopted by all interested parties including:
- [zmartzone/lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc)
  - OpenID Connect Relying Party and OAuth 2.0 Resource Server implementation in Lua for NGINX / OpenResty

---

# Name

lua-resty-jwt - [JWT](http://self-issued.info/docs/draft-jones-json-web-token-01.html) for ngx_lua and LuaJIT

[![test](https://github.com/cdbattags/lua-resty-jwt/actions/workflows/test.yml/badge.svg)](https://github.com/cdbattags/lua-resty-jwt/actions/workflows/test.yml)


**Attention :exclamation: the hmac lib used here is [lua-resty-hmac](https://github.com/jkeys089/lua-resty-hmac), not the one in luarocks.**

# Installation

- luarocks: `luarocks install lua-resty-jwt`
- ~~opm: `opm get cdbattags/lua-resty-jwt`~~ (deprecated for 0.2+)
- Head to [release page](https://github.com/cdbattags/lua-resty-jwt/releases) and download `tar.gz`


# Table of Contents

* [Name](#name)
* [Status](#status)
* [Description](#description)
* [Synopsis](#synopsis)
* [Methods](#methods)
    * [sign](#sign)
    * [verify](#verify)
    * [verify_with](#verify_with)
    * [Keys: PEM, JWK, JWK Set and key objects](#keys-pem-jwk-jwk-set-and-key-objects)
    * [load and verify](#load--verify)
    * [set_alg_whitelist](#set_alg_whitelist)
    * [set_typ_whitelist](#set_typ_whitelist)
    * [set_crit_whitelist](#set_crit_whitelist)
    * [set_trusted_certs_file](#set_trusted_certs_file)
    * [set_pbes2_max_count](#set_pbes2_max_count)
    * [sign JWE](#sign-jwe)
    * [set_zip_max_size](#set_zip_max_size)
    * [register_zlib_compression](#register_zlib_compression)
    * [register_compression_alg](#register_compression_alg)
    * [set_legacy_ecdh_kw_kdf](#set_legacy_ecdh_kw_kdf)
* [Verification](#verification)
    * [JWT Validators](#jwt-validators)
    * [Legacy/Timeframe options](#legacy-timeframe-options)
* [Breaking changes in 0.4.0](#breaking-changes-in-040)
* [Example](#examples)
* [Installation](#installation)
* [Testing With Docker](#testing-with-docker)
* [Authors](AUTHORS.md)
* [See Also](#see-also)

# Status

This library is under active development but is considered production ready.

# Description

This library requires an nginx build with OpenSSL,
the [ngx_lua module](http://wiki.nginx.org/HttpLuaModule),
the [LuaJIT 2.0](http://luajit.org/luajit.html),
the [lua-resty-hmac](https://github.com/jkeys089/lua-resty-hmac),
and the [lua-resty-string](https://github.com/openresty/lua-resty-string),

# Synopsis

```lua
    # nginx.conf:

    lua_package_path "/path/to/lua-resty-jwt/lib/?.lua;;";

    server {
        default_type text/plain;
        location = /verify {
            content_by_lua '
                local cjson = require "cjson"
                local jwt = require "resty.jwt"

                local jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                    ".eyJmb28iOiJiYXIifQ" ..
                    ".VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY"
                local jwt_obj = jwt:verify("lua-resty-jwt", jwt_token)
                ngx.say(cjson.encode(jwt_obj))
            ';
        }
        location = /sign {
            content_by_lua '
                local cjson = require "cjson"
                local jwt = require "resty.jwt"

                local jwt_token = jwt:sign(
                    "lua-resty-jwt",
                    {
                        header={typ="JWT", alg="HS256"},
                        payload={foo="bar"}
                    }
                )
                ngx.say(jwt_token)
            ';
        }
    }
```

[Back to TOC](#table-of-contents)

# Methods

To load this library,

1. you need to specify this library's path in ngx_lua's [lua_package_path](https://github.com/openresty/lua-nginx-module#lua_package_path) directive. For example, `lua_package_path "/path/to/lua-resty-jwt/lib/?.lua;;";`.
2. you use `require` to load the library into a local Lua variable:

```lua
    local jwt = require "resty.jwt"
```

[Back to TOC](#table-of-contents)

## sign


`syntax: local jwt_token = jwt:sign(key, table_of_jwt)`

sign a table_of_jwt to a jwt_token.

The `alg` argument specifies which signing algorithm to use (`HS256`, `HS512`, `RS256`, `RS512`, `PS256`, `PS512`, `ES256`, `ES512`).

### sample of table_of_jwt ###

```
{
    "header": {"typ": "JWT", "alg": "HS512"},
    "payload": {"foo": "bar"}
}
```

## verify

`syntax: local jwt_obj = jwt:verify(key, jwt_token [, claim_spec [, ...]])`

verify a jwt_token and returns a jwt_obj table.  `key` can be a pre-shared key (as a string), a PEM key or certificate, a JWK or JWK Set, a key object (see [Keys](#keys-pem-jwk-jwk-set-and-key-objects)), *or* a function which takes a single parameter (the value of `kid` from the header) and returns either the pre-shared key (as a string) for the `kid` or `nil` if the `kid` lookup failed.  This call will fail if you try to specify a function for `key` and there is no `kid` existing in the header.

See [Verification](#verification) for details on the format of `claim_spec` parameters.

The signature is always checked before any `claim_spec` is evaluated, so validators only ever see authenticated claims, and a bad signature is reported in preference to a failing claim.

The key must fit the token's `alg`:

* `HS256`/`HS384`/`HS512`: a shared secret, or an `oct` JWK. Empty secrets and asymmetric key material are rejected: PEM (`-----BEGIN`), DER keys and certificates, asymmetric JWKs, `pkey`/`x509` objects. This prevents the RS/HS key-confusion attack where a token is MACed with a server's *public* key.
* `RS*`/`PS*`: an RSA public key or certificate (PEM), or an `RSA` JWK.
* `ES256`/`ES384`/`ES512`: an EC public key or certificate on P-256/P-384/P-521 respectively, or an `EC` JWK with that `crv`.
* `Ed25519`/`Ed448`/`EdDSA`: the matching OKP public key or certificate, or an `OKP` JWK (`EdDSA` accepts either curve).

Otherwise verification fails with `key type mismatch: ...`. Even so, prefer pinning the algorithms you expect with [verify_with](#verify_with) or [set_alg_whitelist](#set_alg_whitelist).

## verify_with

`syntax: local jwt_obj = jwt:verify_with(key, jwt_token, options)`

Like `verify`, but takes an options table that pins the algorithms accepted for this call:

* `algorithms` (required): list of allowed `alg` header values, e.g. `{ "RS256", "ES256" }` (the `set_alg_whitelist` style `{ RS256 = 1 }` is accepted too). As with `set_alg_whitelist`, a JWE's `enc` must be listed as well, e.g. `{ "RSA-OAEP-256", "A256GCM" }`.
* `claim_specs` (optional): list of `claim_spec` tables, the same as the trailing arguments of `verify`.

The `alg` (and a JWE's `enc`) is checked before the token is parsed, so a JWE using a disallowed algorithm is never decrypted. A global [set_alg_whitelist](#set_alg_whitelist) still applies as well. Invalid options raise an error.

```lua
local jwt_obj = jwt:verify_with(public_key, jwt_token, {
    algorithms = { "RS256" },
    claim_specs = { { iss = validators.equals("https://issuer.example") } },
})
-- an HS256 (or any non-RS256) token fails with "whitelist unsupported alg: HS256"
```


## Keys: PEM, JWK, JWK Set and key objects

Wherever a verification or decryption key is expected (`verify`, `verify_with`, `verify_jwt_obj`, `load_jwt`), you can pass:

* a PEM (or, for EdDSA, DER) public key or certificate string, as before; for JWE, a PEM private key or the shared secret string;
* a **JWK** ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)) as a Lua table or JSON string. Supported `kty`: `RSA`, `EC` (`P-256`, `P-384`, `P-521`), `OKP` (`Ed25519`, `Ed448`, and `X25519`/`X448` for `ECDH-ES*` decryption), and `oct` for `HS*` and the symmetric JWE algorithms (`dir`, `A*KW`, `A*GCMKW`, `PBES2-*`);
* a **JWK Set** `{ keys = { ... } }` as a Lua table or JSON string;
* a `resty.openssl.pkey` or `resty.openssl.x509` object;
* a key object returned by `jwt:load_key(...)` / `require("resty.jwt.jwk").load(...)`.

HS signing (`jwt:sign`) also accepts an `oct` JWK. Asymmetric signing and JWE encryption still take PEM strings.

The key always has to fit the token's `alg`. An `oct` key never verifies `RS*`/`PS*`/`ES*`/`EdDSA`, and an asymmetric key is never usable for `HS*` or a symmetric JWE algorithm (`key type mismatch: ...`). A JWK is checked further:

* `alg`, if present, must equal the token's `alg` (RFC 7517 4.4);
* `use`, if present, must be `sig` for JWS and `enc` for JWE;
* `key_ops`, if present, must allow the operation: `verify` (or `sign` when signing); for JWE, `decrypt` for `dir`, `unwrapKey` for `A*KW`, `unwrapKey`/`decrypt` for `A*GCMKW` and `RSA-OAEP*`, and `deriveKey`/`deriveBits` for `ECDH-ES*` and `PBES2-*`;
* a JWK used to *verify* a signature must be public. A JWK with private members (`d`, `p`, ...) is refused, because private key material in a verifier's key set (often a published JWKS) is a leak waiting to happen. JWE decryption needs the private JWK (`RSA-OAEP*`, `ECDH-ES*`). This check covers JWKs only: PEM strings, `pkey` objects and key objects loaded from PEM are used as given.

Key selection in a **JWK Set**:

1. If the token header has a `kid`, only keys with that `kid` are candidates.
2. Candidates whose `kty`/`crv`, `use`, `key_ops` or `alg` don't fit the token are dropped.
3. Exactly one remaining key is used. With none left, verification fails (`no key in the JWK Set matches ...`, or the reason the `kid`'s key was refused). With several left, it fails with `ambiguous key: ...`. Keys are never tried one after another.

Members of a set with an unknown `kty` or malformed values are ignored (RFC 7517 5).

```lua
local jwt = require "resty.jwt"

-- JWKS, e.g. read from a file or fetched by your own code (resty.jwt does not
-- fetch keys over the network)
local jwks = [[{"keys":[{"kty":"RSA","kid":"2024-01","use":"sig","n":"...","e":"AQAB"}]}]]
local jwt_obj = jwt:verify_with(jwks, token, { algorithms = { "RS256" } })
```

### Reusable key objects

Passing a PEM string, JWK or JWKS parses it on every call. On hot paths, parse it once per worker with `jwt:load_key(key)` (same as `require("resty.jwt.jwk").load(key)`) and reuse the returned key object. It accepts everything listed above and returns `nil, err` for keys it can't use; malformed members of a JWK Set are skipped with a `warn` log.

```lua
-- module level: runs once per worker
local jwt = require "resty.jwt"
local signing_keys = assert(jwt:load_key(io.open("/etc/nginx/jwks.json"):read("*a")))

local _M = {}
function _M.access()
    local jwt_obj = jwt:verify_with(signing_keys, token, { algorithms = { "RS256", "ES256" } })
    ...
end
return _M
```

For keys that change at runtime, cache the key objects in a [lua-resty-lrucache](https://github.com/openresty/lua-resty-lrucache) keyed by key id or source, and refresh them on your own schedule.

### JWK thumbprint

`syntax: local thumbprint, err = require("resty.jwt.jwk").thumbprint(jwk [, hash])`

Computes the [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint of a JWK (table or JSON string; `RSA`, `EC`, `OKP` or `oct`), base64url encoded. `hash` is a digest name and defaults to `"SHA256"`.

## load & verify

```
syntax: local jwt_obj = jwt:load_jwt(jwt_token)
syntax: local verified = jwt:verify_jwt_obj(key, jwt_obj [, claim_spec [, ...]])
```

```
verify = load_jwt +  verify_jwt_obj
```

load jwt, check for kid, then verify it with the correct key

`load_jwt` parses strictly: a JWS must have exactly 3 dot-separated parts and a JWE exactly 5, and no part may be empty (`invalid jwt string: empty <part>`), with one exception: a JWE's encrypted key, which must be empty for `dir` and `ECDH-ES` and non-empty for every other `alg`. An empty JWS signature is never accepted (`alg: none` is not supported). Tokens whose `crit` header isn't understood are rejected here too, see [set_crit_whitelist](#set_crit_whitelist).

### sample of jwt_obj ###

```
{
    "raw_header": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
    "raw_payload: "eyJmb28iOiJiYXIifQ",
    "signature": "wrong-signature",
    "header": {"typ": "JWT", "alg": "HS256"},
    "payload": {"foo": "bar"},
    "verified": false,
    "valid": true,
    "reason": "signature mismatched: wrong-signature"
}
```

## set_alg_whitelist

`syntax: jwt:set_alg_whitelist(algorithms)`

Restrict which algorithms are accepted during verification. Pass a table whose keys are the allowed algorithm names. If set, any token using an algorithm not in the whitelist will be rejected.

```lua
local jwt = require "resty.jwt"

-- Only allow RS256 and ES256
jwt:set_alg_whitelist({ RS256 = 1, ES256 = 1 })

local jwt_obj = jwt:verify(public_key, jwt_token)
-- Tokens signed with HS256, RS512, etc. will fail with:
--   "whitelist unsupported alg: HS256"
```

For JWE tokens the whitelist is checked when the token is loaded, before any key is unwrapped or derived, and **both** the key management `alg` and the content encryption `enc` must be present:

```lua
-- Only accept RSA-OAEP-256 + A256GCM encrypted tokens (plus RS256 JWS)
jwt:set_alg_whitelist({ RS256 = 1, ["RSA-OAEP-256"] = 1, A256GCM = 1 })
-- A JWE with a disallowed enc fails with:
--   "whitelist unsupported enc: A128CBC-HS256"
```

Pass `nil` to clear the whitelist and allow all algorithms again.

## set_typ_whitelist

`syntax: jwt:set_typ_whitelist(typs)`

`sign` validates the `typ` header value you supply against this whitelist *before* performing any signing or encryption. If the value isn't whitelisted, `sign` raises `invalid typ: <value>` and produces no token (a non-string `typ` raises `invalid typ: must be a string`). Pass a table whose keys are the allowed typ values, or a list of them. Tokens that don't set a `typ` header are unaffected.

Values are compared case-insensitively, and an `application/` prefix is ignored as RFC 7515 §4.1.9 describes, so `application/at+jwt`, `AT+JWT` and `at+jwt` are the same value. The table is copied, so changing it afterwards has no effect; call `set_typ_whitelist` again instead.

The default whitelist accepts `JWT` (RFC 7519), `JWE` (RFC 7516), and the RFC-registered `+jwt` structured-syntax values:

- `at+jwt` — RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens)
- `dpop+jwt` — RFC 9449 (Demonstrating Proof of Possession)
- `token-introspection+jwt` — RFC 9701 (JWT Response for OAuth Token Introspection)
- `client-authentication+jwt` — draft-ietf-oauth-rfc7523bis
- `secevent+jwt` — RFC 8417 (Security Event Token)
- `logout+jwt` — OpenID Connect Back-Channel Logout 1.0

```lua
local jwt = require "resty.jwt"

-- Allow only JWT and a custom value
jwt:set_typ_whitelist({ JWT = 1, ["my-custom+jwt"] = 1 })
```

Pass `nil` to disable typ validation entirely — any value (or no value) is then accepted. Pass `{}` (an empty table) to reject every typ value, including `JWT`/`JWE`. Like the other settings, calling it on an instance from `jwt.new()` only affects that instance.

Note: this whitelist is consulted only during `sign`. The `verify`/`load` path does not validate `header.typ`. To enforce a specific typ on incoming tokens (e.g. `at+jwt` per RFC 9068), use the [`validators.typ_is`](#validatorstyp_isexpected-opt) header validator, which compares the same way:

```lua
local validators = require "resty.jwt-validators"
local jwt_obj = jwt:verify(key, token, { __header = { typ = validators.typ_is("at+jwt") } })
```

## set_crit_whitelist

`syntax: jwt:set_crit_whitelist(extensions)`

Tokens may list extension header parameters in `crit` (RFC 7515 §4.1.11, RFC 7516 §4.1.13) that a recipient must understand to accept them. Both JWS and JWE tokens are rejected, before any signature check or decryption, when `crit`:

* is not a non-empty array of distinct strings (`invalid crit header: must be a non-empty array of strings`),
* lists a registered header parameter such as `alg`, `enc`, `kid` or `typ`,
* lists a header parameter that isn't in the header, or
* lists an extension that wasn't declared with `set_crit_whitelist` (`unsupported critical header parameter: <name>`).

By default no extension is understood, so any token carrying `crit` is rejected. Declare the extensions your application handles, as a list or as table keys; the table is copied. Pass `nil` to understand none again.

```lua
local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"

jwt:set_crit_whitelist({ "my-ext" })

-- the library does not interpret "my-ext": enforce it with a header validator,
-- which runs only after the signature has been verified
local jwt_obj = jwt:verify(key, token, { __header = { ["my-ext"] = validators.equals("v1") } })
```

Registered header names and `b64` (RFC 7797 unencoded payloads are not supported) can't be declared.

## set_trusted_certs_file

`syntax: jwt:set_trusted_certs_file(filename)`

Set a PEM file containing trusted CA certificates for `x5c`/`x5u` based verification of RS256/ES256 tokens.

The file is read once per worker and the resulting certificate store is cached by path. Setting a different path drops the cache, so the next verification reads the file again. To pick up a changed file under the same path, reload nginx, or set another path and then the original one again.

## set_pbes2_max_count

`syntax: jwt:set_pbes2_max_count(max_count)`

Set the highest PBES2 iteration count (`p2c` header) accepted when decrypting `PBES2-HS*+A*KW` tokens. The count is chosen by whoever built the token and PBKDF2 runs inside the nginx worker, so tokens above the cap are rejected before any key derivation. Defaults to `10000` (the panva/jose default); raise it only if a token producer you trust uses a larger count; counts below `1000` are always rejected, and `p2s` must decode to at least 8 octets. Pass `nil` to restore the default.

[Back to TOC](#table-of-contents)

## sign-jwe

`syntax: local jwt_token = jwt:sign(key, table_of_jwt)`

sign a table_of_jwt to a jwt_token.

The `alg` argument specifies which key management algorithm to use (`dir`, `RSA-OAEP`, `RSA-OAEP-256`, `ECDH-ES`).
The `enc` argument specifies which content encryption algorithm to use (`A128CBC-HS256`, `A256CBC-HS512`, `A128GCM`, `A256GCM`).

The optional `zip` header parameter (RFC 7516 §4.1.3) compresses the payload
before it is encrypted. The only registered value is `DEF` (raw DEFLATE,
RFC 1951). It is built in: `resty.jwt-zlib` binds the system zlib through the
LuaJIT FFI (OpenResty's nginx already links zlib), so nothing extra has to be
installed. If zlib cannot be loaded, `DEF` is unsupported until a handler is
registered with [register_zlib_compression](#register_zlib_compression) or
[register_compression_alg](#register_compression_alg).

**Only set `zip` when you have considered the leak.** Compress-then-encrypt
reveals information about the plaintext through the ciphertext length (the
CRIME / BREACH family of attacks). Do not compress payloads where
attacker-influenced data sits next to secrets. A JWE is only ever compressed
when its header asks for it.

When verifying a `zip` JWE:

* An unknown or non-string `zip` value is rejected (`unsupported zip: …` /
  `invalid zip in JWE header`) before any key is unwrapped or derived.
* Content is decompressed only after the authentication tag or MAC has been
  verified and the content decrypted.
* The decompressed size is capped at max(250 KiB, 10 × the compressed size),
  as in go-jose (cf. CVE-2024-28180). Use
  [set_zip_max_size](#set_zip_max_size) for an explicit cap. Decompression
  stops as soon as the cap is passed, so a "zip bomb" never allocates more.
* Oversized, truncated or invalid DEFLATE data and trailing bytes after the
  stream are rejected with the generic `failed to decrypt JWE` reason.
* `zip` is a JWE-only parameter, so a JWS carrying it is rejected (`zip is not
  allowed in a JWS header`), and so is signing one.

### sample of table_of_jwt ###

```
{
    "header": {"typ": "JWE", "alg": "dir", "enc":"A128CBC-HS256"},
    "payload": {"foo": "bar"}
}
```

When a JWE fails authentication or decryption (bad tag or MAC, wrong key, tampered ciphertext or encrypted key) the result's `reason` is always `failed to decrypt JWE`, so it cannot be used as an oracle. Details are logged at `ngx.DEBUG`.

### sample with DEFLATE compression ###

```
{
    "header": {"typ": "JWE", "alg": "dir", "enc":"A128CBC-HS256", "zip": "DEF"},
    "payload": {"foo": "bar"}
}
```

## set_zip_max_size

`syntax: jwt:set_zip_max_size(max_size)`

Set the largest decompressed payload, in bytes, accepted from a `zip` JWE. The
default is max(250 KiB, 10 × the compressed size). An explicit value replaces
both, so a larger value admits bigger payloads and a smaller one a tighter
cap. Larger payloads fail with `failed to decrypt JWE`. Pass `nil` to restore
the default.

## register_zlib_compression

`syntax: jwt:register_zlib_compression(zlib_module)`

Bind `DEF` to a caller-supplied
[lua-zlib](https://github.com/brimworks/lua-zlib)-compatible module instead of
the built-in FFI binding, e.g. where the FFI is not available. The module stays
a caller-owned dependency. Input is fed to lua-zlib in small pieces so the
size cap still applies, and lua-zlib's end-of-stream flag and input count are
checked to reject truncated streams and trailing data.

```lua
jwt:register_zlib_compression(require "zlib")
```

## register_compression_alg

`syntax: jwt:register_compression_alg(name, { deflate = fn, inflate = fn })`

Register or override the handler used for a given JWE `zip` header value. Use
this to swap in an alternate DEFLATE implementation or to support a
non-standard `zip` value.

`deflate(data)` takes a byte string. `inflate(data, max_size)` also receives
the size cap and must not produce more than `max_size` bytes; it should stop
as soon as the output would pass it. Both return a byte string on success,
or `nil, err` on failure. Results larger than `max_size`, errors and raised
errors all fail verification with `failed to decrypt JWE` (`err` is logged
at `ngx.DEBUG`).

```lua
jwt:register_compression_alg("DEF", {
    deflate = function(data) return my_compress(data) end,
    inflate = function(data, max_size) return my_bounded_decompress(data, max_size) end,
})
```

Registrations apply to the object they are made on. Called on the module
(`jwt:register_compression_alg`), they are inherited by `jwt:new()` instances
that have not registered their own. Called on an instance, they affect only
that instance. The built-in `DEF` handler itself is never modified.

For reference implementations, see `lib/resty/jwt-zlib.lua` (bounded streaming
inflate over the FFI) and `register_zlib_compression` in `lib/resty/jwt.lua`.

[Back to TOC](#table-of-contents)

## set_legacy_ecdh_kw_kdf

`syntax: jwt:set_legacy_ecdh_kw_kdf(true)`

**Deprecated, will be removed in 1.0.** Versions 0.3.0 - 0.3.2 derived the `ECDH-ES+A128KW`/`ECDH-ES+A192KW`/`ECDH-ES+A256KW`
key wrapping key with a non-standard Concat KDF (AlgorithmID `A128KW` instead of `ECDH-ES+A128KW`, and `apu`/`apv`
decoded as standard base64), so those tokens did not interoperate with other JOSE libraries. Tokens are now produced
and decrypted as specified in RFC 7518 Section 4.6. Enabling this flag (it is off by default) lets decryption fall back
to the old derivation, so tokens issued by 0.3.x can still be read while they expire. Signing always uses RFC 7518.

`apu`/`apv` header values must be base64url; a JWE with a value that is not is rejected.

[Back to TOC](#table-of-contents)


# Breaking changes in 0.4.0

Key handling:

* `HS*` secrets must not be empty, and must not be DER-encoded keys or certificates (in addition to PEM). This applies to signing and verifying.
* `HS*` and the symmetric JWE algorithms (`dir`, `A*KW`, `A*GCMKW`, `PBES2-*`) refuse asymmetric keys given as a JWK, JWK Set, `pkey` or `x509` object. The JWE algorithms also refuse empty, PEM and DER secrets. Previously a public key could be used as a `PBES2` password, so anyone holding the verifier's RSA public key could forge a JWE that `jwt:verify` accepted.
* A string secret that is a JSON object with a `kty` or `keys` member is now treated as a JWK/JWK Set rather than as raw HMAC secret bytes.

[Back to TOC](#table-of-contents)

# Verification

Both the `jwt:load` and `jwt:verify_jwt_obj` functions take, as additional parameters, any number of optional `claim_spec` parameters.  A `claim_spec` is simply a lua table of claims and validators.  Each key in the `claim_spec` table corresponds to a matching key in the payload, and the `validator` is a function that will be called to determine if the claims are met.

The signature of a `validator` function is:

```
function(val, claim, jwt_json)
```

Where `val` is the value of the claim from the `jwt_obj` being tested (or nil if it doesn't exist in the object's payload), `claim` is the name of the claim that is being verified, and `jwt_json` is a json-serialized representation of the object that is being verified.  If the function has no need of the `claim` or `jwt_json`, parameters, they may be left off.

A `validator` function returns either `true` or `false`.  Any `validator` *MAY* raise an error, and the validation will be treated as a failure, and the error that was raised will be put into the reason field of the resulting object.  If a `validator` returns nothing (i.e. `nil`), then the function is treated to have succeeded - under the assumption that it would have raised an error if it would have failed.

A special claim named `__jwt` can be used such that if a `validator` function exists for it, then the `validator` will be called with a deep clone of the entire parsed jwt object as the value of `val`.  This is so that you can write verifications for an entire object that may depend on one or more claims.

A special claim named `__header` validates header parameters instead of payload claims. Its value is a table mapping header parameter names to `validator` functions, each called with the header parameter's value as `val` and its name as `claim`, e.g. `{ __header = { typ = validators.typ_is("at+jwt"), kid = validators.required() } }`. Like all validators, they only run after the signature (or a JWE's authentication tag) has been verified.

Multiple `claim_spec` tables can be specified to the `jwt:load` and `jwt:verify_jwt_obj` - and they will be executed in order.  There is no guarantee of the execution order of individual `validators` within a single `claim_spec`.  If a `claim_spec` fails, then any following `claim_specs` will *NOT* be executed.


### sample `claim_spec` ###

```
{
    sub = function(val) return string.match("^[a-z]+$", val) end,
    iss = function(val)
        for _, value in pairs({ "first", "second" }) do
            if value == val then return true end
        end
        return false
    end,
    __jwt = function(val, claim, jwt_json)
        if val.payload.foo == nil or val.payload.bar == nil then
            error("Need to specify either 'foo' or 'bar'")
        end
    end,
    __header = {
        kid = function(val) return val == "my-key" end
    }
}
```

## JWT Validators

A library of helpful `validator` functions exists at `resty.jwt-validators`.  You can use this library by including:
```
local validators = require "resty.jwt-validators"
```

The following functions are currently defined in the validator library.  Those marked with "(opt)" means that the same function exists named `opt_<name>` which takes the same parameters.  The "opt" version of the function will return `true` if the key does not exist in the payload of the jwt_object being verified, while the "non-opt" version of the function will return false if the key does not exist in the payload of the jwt_object being verified.

#### `validators.chain(...)` ####

Returns a validator that chains the given functions together, one after another - as long as they keep passing their checks.

#### `validators.required(chain_function)` ####

Returns a validator that returns `false` if a value doesn't exist.  If the value exists and a `chain_function` is specified, then the value of `chain_function(val, claim, jwt_json)` will be returned, otherwise, `true` will be returned.  This allows for specifying that a value is both required *and* it must match some additional check.

#### `validators.require_one_of(claim_keys)` ####

Returns a validator which errors with a message if *NONE* of the given claim keys exist.  It is expected that this function is used against a full jwt object.  The claim_keys must be a non-empty table of strings.

#### `validators.check(check_val, check_function, name, check_type)` (opt)  ####

Returns a validator that checks if the result of calling the given `check_function` for the tested value and `check_val` returns true.  The value of `check_val` and `check_function` cannot be nil.  The optional `name` is used for error messages and defaults to "check_value".  The optional `check_type` is used to make sure that the check type matches and defaults to `type(check_val)`.  The first parameter passed to check_function will *never* be nil.  If the `check_function` raises an error, that will be appended to the error message.

#### `validators.equals(check_val)` (opt) ####

Returns a validator that checks if a value exactly equals (using `==`) the given check_value. The value of `check_val` cannot be nil.

#### `validators.matches(pattern)` (opt) ####

Returns a validator that checks if a value matches the given pattern (using `string.match`).  The value of `pattern` must be a string.

#### `validators.any_of(check_values, check_function, name, check_type, table_type)` (opt) ####

Returns a validator which calls the given `check_function` for each of the given `check_values` and the tested value.  If any of these calls return `true`, then this function returns `true`.  The value of `check_values` must be a non-empty table with all the same types, and the value of `check_function` must not be `nil`.  The optional `name` is used for error messages and defaults to "check_values".  The optional `check_type` is used to make sure that the check type matches and defaults to `type(check_values[1])` - the table type.

#### `validators.equals_any_of(check_values)` (opt) ####

Returns a validator that checks if a value exactly equals any of the given `check_values`.

#### `validators.matches_any_of(patterns)` (opt) ####

Returns a validator that checks if a value matches any of the given `patterns`.

#### `validators.contains_any_of(check_values,name)` (opt) ####

Returns a validator that checks if a value of expected type `string` exists in any of the given `check_values`.  The value of `check_values`must be a non-empty table with all the same types.  The optional name is used for error messages and defaults to `check_values`.

#### `validators.greater_than(check_val)` (opt) ####

Returns a validator that checks how a value compares (numerically, using `>`) to a given `check_value`.  The value of `check_val` cannot be `nil` and must be a number.

#### `validators.greater_than_or_equal(check_val)` (opt) ####

Returns a validator that checks how a value compares (numerically, using `>=`) to a given `check_value`.  The value of `check_val` cannot be `nil` and must be a number.

#### `validators.less_than(check_val)` (opt) ####

Returns a validator that checks how a value compares (numerically, using `<`) to a given `check_value`.  The value of `check_val` cannot be `nil` and must be a number.

#### `validators.less_than_or_equal(check_val)` (opt) ####

Returns a validator that checks how a value compares (numerically, using `<=`) to a given `check_value`.  The value of `check_val` cannot be `nil` and must be a number.

#### `validators.is_not_before(options)` (opt) ####

Returns a validator that checks if the current time is not before the tested value within the leeway.  This means that:
```
val <= (system_clock() + leeway).
```
The optional `options` table may set `{ leeway = seconds }` for this validator only; otherwise the system leeway is used.

#### `validators.is_not_expired(options)` (opt) ####

Returns a validator that checks if the current time is not equal to or after the tested value within the leeway.  This means that:
```
val > (system_clock() - leeway).
```
The optional `options` table may set `{ leeway = seconds }` for this validator only; otherwise the system leeway is used.

#### `validators.is_at(options)` (opt) ####

Returns a validator that checks if the current time is the same as the tested value within the leeway.  This means that:
```
val >= (system_clock() - leeway) and val <= (system_clock() + leeway).
```
The optional `options` table may set `{ leeway = seconds }` for this validator only; otherwise the system leeway is used.

#### `validators.typ_is(expected)` (opt) ####

Returns a validator for the `typ` *header*, to be used in a `__header` table: it checks that `typ` is the `expected` string, or one of a list of strings. Values are compared case-insensitively and with an `application/` prefix ignored (RFC 7515 §4.1.9), the same way as [set_typ_whitelist](#set_typ_whitelist). The required version fails with `'typ' header is required.` when the header has no `typ`. `validators.normalize_typ(typ)` exposes the normalization.

#### `validators.set_system_leeway(leeway)` ####

A function to set the default leeway (in seconds) used for `is_not_before`, `is_not_expired` and `is_at` when they are not given their own `leeway`.  The default is to use `0` seconds.  This is module-wide state for the whole worker.

#### `validators.set_system_clock(clock)` ####

A function to set the system clock used for `is_not_before` and `is_not_expired`.  The default is to use `ngx.now`

### sample `claim_spec` using validators ###

```
local validators = require "resty.jwt-validators"
local claim_spec = {
    sub = validators.opt_matches("^[a-z]+$),
    iss = validators.equals_any_of({ "first", "second" }),
    __jwt = validators.require_one_of({ "foo", "bar" }),
    __header = { typ = validators.typ_is("at+jwt") }
}
```

## Legacy/Timeframe options

In order to support code which used previous versions of this library, as well as to simplify specifying timeframe-based `claim_specs`, you may use in place of any single `claim_spec` parameter a table of `validation_options`.  The parameter should be expressed as a key/value table. Each key of the table should be picked from the following list.

When using legacy `validation_options`, you *MUST ONLY* specify these options.  That is, you cannot mix legacy `validation_options` with other `claim_spec` validators.  In order to achieve that, you must specify multiple options to the `jwt:load`/`jwt:verify_jwt_obj` functions.

* `lifetime_grace_period`: Define the leeway in seconds to account for clock skew between the server that generated the jwt and the server validating it. Value should be zero (`0`) or a positive integer.

    * When this validation option is specified, the process will ensure that the jwt contains at least one of the two `nbf` or `exp` claim and compare the current clock time against those boundaries. Would the jwt be deemed as expired or not valid yet, verification will fail.

    * When none of the `nbf` and `exp` claims can be found, verification will fail.

    * `nbf` and `exp` claims are expected to be expressed in the jwt as numerical values. Wouldn't that be the case, verification will fail.

    * The leeway applies to this verification only; it does not change the system leeway.

    * Specifying this option is equivalent to specifying as a `claim_spec`:
      ```
      {
        __jwt = validators.require_one_of({ "nbf", "exp" }),
        nbf = validators.opt_is_not_before({ leeway = leeway }),
        exp = validators.opt_is_not_expired({ leeway = leeway })
      }
      ```

* `require_nbf_claim`: Express if the `nbf` claim is optional or not. Value should be a boolean.

    * When this validation option is set to `true` and no `lifetime_grace_period` has been specified, the system leeway (`0` unless changed with `validators.set_system_leeway`) is used.

    * Specifying this option is equivalent to specifying as a `claim_spec`:
      ```
      {
        nbf = validators.is_not_before(),
      }
      ```

* `require_exp_claim`: Express if the `exp` claim is optional or not. Value should be a boolean.

    * When this validation option is set to `true` and no `lifetime_grace_period` has been specified, the system leeway (`0` unless changed with `validators.set_system_leeway`) is used.

    * Specifying this option is equivalent to specifying as a `claim_spec`:
      ```
      {
        exp = validators.is_not_expired(),
      }
      ```

* `valid_issuers`: Whitelist the vetted issuers of the jwt. Value should be a array of strings.

    * When this validation option is specified, the process will compare the jwt `iss` claim against the list of valid issuers. Comparison is done in a case sensitive manner. Would the jwt issuer not be found in the whitelist, verification will fail.

    * `iss` claim is expected to be expressed in the jwt as a string. Wouldn't that be the case, verification will fail.

    * Specifying this option is equivalent to specifying as a `claim_spec`:
      ```
      {
        iss = validators.equals_any_of(valid_issuers),
      }
      ```


### sample of validation_options usage ###

```
local jwt_obj = jwt:verify(key, jwt_token,
    {
        lifetime_grace_period = 120,
        require_exp_claim = true,
        valid_issuers = { "my-trusted-issuer", "my-other-trusteed-issuer" }
    }
)
```

# Examples

* [JWT Auth With Query and Cookie](examples/README.md#jwt-auth-using-query-and-cookie)
* [JWT Auth With KID and Store Your Key in Redis](examples/README.md#jwt-auth-with-kid-and-store-keys-in-redis)

[Back to TOC](#table-of-contents)

# Installation

Using Luarocks
```bash
luarocks install lua-resty-jwt
```

It is recommended to use the latest [ngx_openresty bundle](http://openresty.org) directly.

Also, You need to configure
the [lua_package_path](https://github.com/openresty/lua-nginx-module#lua_package_path) directive to
add the path of your lua-resty-jwt source tree to ngx_lua's Lua module search path, as in

```nginx
    # nginx.conf
    http {
        lua_package_path "/path/to/lua-resty-jwt/lib/?.lua;;";
        ...
    }
```

and then load the library in Lua:

```lua
    local jwt = require "resty.jwt"
```

[Back to TOC](#table-of-contents)

# Testing With Docker

```
./ci
```

[Back to TOC](#table-of-contents)

# See Also

* the ngx_lua module: http://wiki.nginx.org/HttpLuaModule

[Back to TOC](#table-of-contents)
