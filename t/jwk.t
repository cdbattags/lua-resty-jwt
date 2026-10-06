BEGIN { use Cwd; $ENV{TEST_NGINX_SERVROOT} = Cwd::cwd() . "/t/servroot_$$"; $ENV{TEST_NGINX_SERVER_PORT} = 10000 + ($$ % 50000) }
use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (3 * blocks() + 1);

my $coverage = $ENV{COVERAGE} ? "require('luacov')" : "";

# Shared helpers (globals): read test keys, export them as JWKs and sign
# tokens with them.
our $HttpConfig = <<"_EOC_";
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        $coverage
        local cjson = require "cjson"
        local jwt = require "resty.jwt"
        local pkey = require "resty.openssl.pkey"

        function read_file(name)
            local f = assert(io.open("/lua-resty-jwt/testcerts/" .. name, "rb"))
            local s = f:read("*all")
            f:close()
            return s
        end

        -- JWK (table) of a PEM test key, with extra members merged in
        function jwk_of(name, private, extra)
            local pk = assert(pkey.new(read_file(name)))
            local t = cjson.decode(assert(pk:tostring(private and "private" or "public", "JWK")))
            for k, v in pairs(extra or {}) do
                t[k] = v
            end
            return t
        end

        function b64url(s)
            return jwt:jwt_encode(s)
        end

        function oct_jwk(k, extra)
            local t = { kty = "oct", k = b64url(k) }
            for name, v in pairs(extra or {}) do
                t[name] = v
            end
            return t
        end

        function sign(keyfile, header, payload)
            return jwt:sign(read_file(keyfile), { header = header, payload = payload or { foo = "bar" } })
        end

        function show(obj)
            ngx.say(obj.verified, " ", obj.reason)
        end
    }
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: RSA, EC and OKP public JWKs verify (table and JSON string)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local rsa = jwk_of("cert-pubkey.pem")
            show(jwt:verify(rsa, sign("cert-key.pem", { alg = "RS256" })))
            show(jwt:verify(cjson.encode(rsa), sign("cert-key.pem", { alg = "RS512" })))
            show(jwt:verify(rsa, sign("cert-key.pem", { alg = "PS256" })))
            show(jwt:verify(jwk_of("ec_cert_pubkey.pem"), sign("ec_cert-key.pem", { alg = "ES256" })))
            show(jwt:verify(cjson.encode(jwk_of("ec_cert_p384_pubkey.pem")), sign("ec_cert_p384-key.pem", { alg = "ES384" })))
            show(jwt:verify(jwk_of("ec_cert_p521_pubkey.pem"), sign("ec_cert_p521-key.pem", { alg = "ES512" })))
            show(jwt:verify(jwk_of("ed25519-pubkey.pem"), sign("ed25519-key.pem", { alg = "EdDSA" })))
            show(jwt:verify(jwk_of("ed448-pubkey.pem"), sign("ed448-key.pem", { alg = "Ed448" })))
            -- wrong key of the right type
            show(jwt:verify(jwk_of("pubkey.pem"), sign("cert-key.pem", { alg = "RS256" })))
            -- right kty, wrong curve
            show(jwt:verify(jwk_of("ec_cert_p384_pubkey.pem"), sign("ec_cert-key.pem", { alg = "ES256" })))
            show(jwt:verify(jwk_of("ed448-pubkey.pem"), sign("ed25519-key.pem", { alg = "Ed25519" })))
            -- verify_with accepts JWKs too
            show(jwt:verify_with(rsa, sign("cert-key.pem", { alg = "RS256" }), { algorithms = { "RS256" } }))
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
false Verification failed
false key type mismatch: alg ES256 requires an EC P-256 key
false key type mismatch: alg Ed25519 requires an Ed25519 key
true everything is awesome~ :p
--- no_error_log
[error]


=== TEST 2: oct JWK as an HS256 key (verify and sign)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local secret = "a-very-long-and-secret-hmac-key!"
            local token = jwt:sign(secret, { header = { alg = "HS256" }, payload = { foo = "bar" } })
            show(jwt:verify(oct_jwk(secret), token))
            show(jwt:verify(cjson.encode(oct_jwk(secret)), token))
            local obj = jwt:verify(oct_jwk("wrong"), token)
            ngx.say(obj.verified, " ", obj.reason:match("^signature mismatch") ~= nil)
            -- signing with an oct JWK gives the same token as the raw secret
            ngx.say(jwt:sign(oct_jwk(secret), { header = { alg = "HS256" }, payload = { foo = "bar" } }) == token)
            -- a JSON string that isn't a JWK is still a plain secret
            local json_secret = '{"not":"a jwk"}'
            token = jwt:sign(json_secret, { header = { alg = "HS512" }, payload = { foo = "bar" } })
            show(jwt:verify(json_secret, token))
            -- oct JWK with a matching alg, and one with use=enc
            show(jwt:verify(oct_jwk(json_secret, { alg = "HS512", use = "sig" }), token))
            show(jwt:verify(oct_jwk(json_secret, { use = "enc" }), token))
            -- malformed oct JWKs
            show(jwt:verify({ kty = "oct" }, token))
            show(jwt:verify({ kty = "oct", k = "" }, token))
            show(jwt:verify({ kty = "oct", k = "not+base64url/" }, token))
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p
true everything is awesome~ :p
false true
true
true everything is awesome~ :p
true everything is awesome~ :p
false JWK use "enc" does not permit alg HS512
false invalid oct JWK: "k" must be a base64url string
false invalid oct JWK: "k" must not be empty
false invalid oct JWK: "k" must be a base64url string
--- no_error_log
[error]


=== TEST 3: JWK Set: kid selection
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local jwks = { keys = {
                jwk_of("pubkey.pem", false, { kid = "other" }),
                jwk_of("cert-pubkey.pem", false, { kid = "main" }),
                jwk_of("ec_cert_pubkey.pem", false, { kid = "ec" }),
                oct_jwk("a-very-long-and-secret-hmac-key!", { kid = "hmac" }),
            } }
            show(jwt:verify(jwks, sign("cert-key.pem", { alg = "RS256", kid = "main" })))
            show(jwt:verify(cjson.encode(jwks), sign("cert-key.pem", { alg = "RS256", kid = "main" })))
            -- the kid picks the key, so the wrong key fails the signature
            show(jwt:verify(jwks, sign("cert-key.pem", { alg = "RS256", kid = "other" })))
            show(jwt:verify(jwks, sign("ec_cert-key.pem", { alg = "ES256", kid = "ec" })))
            show(jwt:verify(jwks, jwt:sign("a-very-long-and-secret-hmac-key!",
                { header = { alg = "HS256", kid = "hmac" }, payload = { foo = "bar" } })))
            -- unknown kid
            show(jwt:verify(jwks, sign("cert-key.pem", { alg = "RS256", kid = "nope" })))
            -- kid of a key that doesn't fit alg: never falls back to another key
            show(jwt:verify(jwks, sign("cert-key.pem", { alg = "RS256", kid = "ec" })))
            show(jwt:verify(jwks, jwt:sign("x", { header = { alg = "HS256", kid = "main" }, payload = {} })))
            -- non-string kid
            local h = jwt:jwt_encode(cjson.encode({ alg = "RS256", kid = 5 }))
            show(jwt:verify(jwks, h .. "." .. jwt:jwt_encode("{}") .. ".AAAA"))
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p
true everything is awesome~ :p
false Verification failed
true everything is awesome~ :p
true everything is awesome~ :p
false no key in the JWK Set matches kid nope
false key type mismatch: alg RS256 requires an RSA key
false key type mismatch: alg HS256 requires a symmetric (oct) key
false invalid kid in header: must be a string
--- no_error_log
[error]


=== TEST 4: JWK Set without kid: single match, ambiguous match, no match
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local mixed = { keys = {
                jwk_of("cert-pubkey.pem"),
                jwk_of("ec_cert_pubkey.pem"),
                jwk_of("ec_cert_p384_pubkey.pem"),
                jwk_of("ed25519-pubkey.pem"),
            } }
            -- exactly one key fits each alg (crv is part of the match)
            show(jwt:verify(mixed, sign("cert-key.pem", { alg = "RS256" })))
            show(jwt:verify(mixed, sign("ec_cert-key.pem", { alg = "ES256" })))
            show(jwt:verify(mixed, sign("ec_cert_p384-key.pem", { alg = "ES384" })))
            show(jwt:verify(mixed, sign("ed25519-key.pem", { alg = "EdDSA" })))
            -- nothing fits
            show(jwt:verify(mixed, sign("ec_cert_p521-key.pem", { alg = "ES512" })))
            show(jwt:verify(mixed, jwt:sign("secret", { header = { alg = "HS256" }, payload = {} })))
            -- two RSA keys and no kid: ambiguous, no key is tried
            local two = { keys = { jwk_of("pubkey.pem"), jwk_of("cert-pubkey.pem") } }
            show(jwt:verify(two, sign("cert-key.pem", { alg = "RS256" })))
            -- the same kid twice is ambiguous as well
            local dup = { keys = { jwk_of("pubkey.pem", false, { kid = "k" }), jwk_of("cert-pubkey.pem", false, { kid = "k" }) } }
            show(jwt:verify(dup, sign("cert-key.pem", { alg = "RS256", kid = "k" })))
            -- keys without a kid don't match a token kid
            show(jwt:verify(two, sign("cert-key.pem", { alg = "RS256", kid = "k" })))
            -- unusable members are ignored (RFC 7517 5)
            local junk = { keys = { { kty = "XYZ" }, "nope", { kty = "RSA", n = 5 }, jwk_of("cert-pubkey.pem") } }
            show(jwt:verify(junk, sign("cert-key.pem", { alg = "RS256" })))
            show(jwt:verify({ keys = {} }, sign("cert-key.pem", { alg = "RS256" })))
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
false no key in the JWK Set matches alg ES512
false no key in the JWK Set matches alg HS256
false ambiguous key: 2 keys in the JWK Set match alg RS256; the token needs a kid
false ambiguous key: 2 keys in the JWK Set match kid k and alg RS256
false no key in the JWK Set matches kid k
true everything is awesome~ :p
false no key in the JWK Set matches alg RS256
--- no_error_log
[error]


=== TEST 5: JWK alg, use and key_ops
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = sign("cert-key.pem", { alg = "RS256" })
            -- JWK alg must equal the token alg (RFC 7517 4.4)
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { alg = "RS256" }), token))
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { alg = "RS384" }), token))
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { alg = "PS256" }), token))
            -- in a set, the alg narrows the candidates
            show(jwt:verify({ keys = {
                jwk_of("pubkey.pem", false, { alg = "RS384" }),
                jwk_of("cert-pubkey.pem", false, { alg = "RS256" }),
            } }, token))
            -- use
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { use = "sig" }), token))
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { use = "enc" }), token))
            show(jwt:verify({ keys = {
                jwk_of("pubkey.pem", false, { use = "enc" }),
                jwk_of("cert-pubkey.pem", false, { use = "sig" }),
            } }, token))
            -- key_ops
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { key_ops = { "verify" } }), token))
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { key_ops = { "sign", "encrypt" } }), token))
            show(jwt:verify({ keys = {
                jwk_of("pubkey.pem", false, { key_ops = { "encrypt" } }),
                jwk_of("cert-pubkey.pem", false, { key_ops = { "verify" } }),
            } }, token))
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { key_ops = "verify" }), token))
            -- a private JWK is refused for verification
            show(jwt:verify(jwk_of("cert-key.pem", true), token))
            show(jwt:verify(jwk_of("ed25519-key.pem", true), sign("ed25519-key.pem", { alg = "EdDSA" })))
            -- bad member types
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { kid = 1 }), token))
            show(jwt:verify(jwk_of("cert-pubkey.pem", false, { n = "%%" }), token))
            show(jwt:verify(jwk_of("ec_cert_pubkey.pem", false, { crv = "P-192" }), sign("ec_cert-key.pem", { alg = "ES256" })))
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p
false JWK alg RS384 does not match token alg RS256
false JWK alg PS256 does not match token alg RS256
true everything is awesome~ :p
true everything is awesome~ :p
false JWK use "enc" does not permit alg RS256
true everything is awesome~ :p
true everything is awesome~ :p
false JWK key_ops do not permit alg RS256
true everything is awesome~ :p
false invalid JWK: key_ops must be an array of strings
false JWK for signature verification must not contain private key members
false JWK for signature verification must not contain private key members
false invalid JWK: kid must be a string
false invalid RSA JWK: "n" must be a base64url string
false unsupported JWK crv for kty EC: P-192
--- no_error_log
[error]


=== TEST 6: private JWKs decrypt RSA-OAEP and ECDH-ES JWEs
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local rsa_priv = jwk_of("cert-key.pem", true)
            local ec_priv = jwk_of("ec_cert-key.pem", true)
            for _, case in ipairs({
                { "cert-pubkey.pem", "RSA-OAEP", "A128GCM", rsa_priv },
                { "cert-pubkey.pem", "RSA-OAEP-256", "A256CBC-HS512", cjson.encode(rsa_priv) },
                { "cert-pubkey.pem", "RSA-OAEP-512", "A256GCM", rsa_priv },
                { "ec_cert_pubkey.pem", "ECDH-ES", "A128GCM", ec_priv },
                { "ec_cert_pubkey.pem", "ECDH-ES", "A256CBC-HS512", cjson.encode(ec_priv) },
                { "ec_cert_pubkey.pem", "ECDH-ES+A128KW", "A256GCM", ec_priv },
            }) do
                local token = sign(case[1], { alg = case[2], enc = case[3] }, { foo = case[2] })
                local obj = jwt:verify(case[4], token)
                ngx.say(case[2], " ", case[3], ": ", obj.verified, " ", obj.reason, " ", obj.payload and obj.payload.foo)
            end

            -- a JWK Set picks the use=enc key by kid or by elimination
            local jwks = { keys = {
                jwk_of("cert-pubkey.pem", false, { use = "sig", kid = "s" }),
                jwk_of("cert-key.pem", true, { use = "enc", kid = "e", key_ops = { "unwrapKey" } }),
                jwk_of("ec_cert-key.pem", true, { use = "enc", kid = "ec" }),
            } }
            local token = sign("cert-pubkey.pem", { alg = "RSA-OAEP-256", enc = "A128GCM" })
            show(jwt:verify(jwks, token))
            token = sign("ec_cert_pubkey.pem", { alg = "ECDH-ES", enc = "A128GCM", kid = "ec" })
            show(jwt:verify(jwks, token))
            show(jwt:verify(jwk_of("cert-key.pem", true, { use = "sig" }),
                sign("cert-pubkey.pem", { alg = "RSA-OAEP", enc = "A128GCM" })))
            show(jwt:verify(jwk_of("cert-key.pem", true, { key_ops = { "verify" } }),
                sign("cert-pubkey.pem", { alg = "RSA-OAEP", enc = "A128GCM" })))

            -- decryption needs the private key, and a key of the right type
            show(jwt:verify(jwk_of("cert-pubkey.pem"), sign("cert-pubkey.pem", { alg = "RSA-OAEP", enc = "A128GCM" })))
            show(jwt:verify(jwk_of("ec_cert_pubkey.pem"), sign("ec_cert_pubkey.pem", { alg = "ECDH-ES", enc = "A128GCM" })))
            show(jwt:verify(ec_priv, sign("cert-pubkey.pem", { alg = "RSA-OAEP", enc = "A128GCM" })))
            show(jwt:verify(rsa_priv, sign("ec_cert_pubkey.pem", { alg = "ECDH-ES", enc = "A128GCM" })))
            show(jwt:verify(jwk_of("ed25519-key.pem", true), sign("ec_cert_pubkey.pem", { alg = "ECDH-ES", enc = "A128GCM" })))
            -- the wrong private key gives the generic decryption failure
            show(jwt:verify(jwk_of("privatekey.pem", true), sign("cert-pubkey.pem", { alg = "RSA-OAEP", enc = "A128GCM" })))
        }
    }
--- request
GET /t
--- response_body
RSA-OAEP A128GCM: true everything is awesome~ :p RSA-OAEP
RSA-OAEP-256 A256CBC-HS512: true everything is awesome~ :p RSA-OAEP-256
RSA-OAEP-512 A256GCM: true everything is awesome~ :p RSA-OAEP-512
ECDH-ES A128GCM: true everything is awesome~ :p ECDH-ES
ECDH-ES A256CBC-HS512: true everything is awesome~ :p ECDH-ES
ECDH-ES+A128KW A256GCM: true everything is awesome~ :p ECDH-ES+A128KW
true everything is awesome~ :p
true everything is awesome~ :p
false JWK use "sig" does not permit alg RSA-OAEP
false JWK key_ops do not permit alg RSA-OAEP
false alg RSA-OAEP requires a private key
false alg ECDH-ES requires a private key
false key type mismatch: alg RSA-OAEP requires an RSA key
false key type mismatch: alg ECDH-ES requires an EC key
false key type mismatch: alg ECDH-ES requires an EC key
false failed to decrypt JWE
--- no_error_log
[error]


=== TEST 7: X25519/X448 keys are refused for ECDH-ES (EC epk only) and for signatures
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local pkey = require "resty.openssl.pkey"
            local token = sign("ec_cert_pubkey.pem", { alg = "ECDH-ES", enc = "A128GCM" })
            local x25519 = assert(pkey.new({ type = "X25519" }))
            show(jwt:verify(cjson.decode(x25519:tostring("private", "JWK")), token))
            show(jwt:verify(x25519, token))
            show(jwt:verify(assert(jwt:load_key(x25519:tostring("private", "PEM"))), token))
            local x448 = assert(pkey.new({ type = "X448" }))
            show(jwt:verify(cjson.decode(x448:tostring("private", "JWK")), token))
            show(jwt:verify(cjson.decode(x25519:tostring("public", "JWK")), sign("ed25519-key.pem", { alg = "EdDSA" })))
        }
    }
--- request
GET /t
--- response_body
false key type mismatch: alg ECDH-ES requires an EC key
false key type mismatch: alg ECDH-ES requires an EC key
false key type mismatch: alg ECDH-ES requires an EC key
false key type mismatch: alg ECDH-ES requires an EC key
false key type mismatch: alg EdDSA requires an Ed25519 or Ed448 key
--- no_error_log
[error]


=== TEST 8: oct JWK with A128KW, dir, A128GCMKW and PBES2
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local kw = "0123456789abcdef"
            local cek = string.rep("k", 32)
            for _, case in ipairs({
                { kw, "A128KW", "A128CBC-HS256", oct_jwk(kw) },
                { kw, "A128KW", "A256GCM", cjson.encode(oct_jwk(kw, { alg = "A128KW", use = "enc", key_ops = { "unwrapKey" } })) },
                { kw, "A128GCMKW", "A128GCM", oct_jwk(kw) },
                { cek, "dir", "A128CBC-HS256", oct_jwk(cek) },
                { "correct horse battery", "PBES2-HS256+A128KW", "A128GCM", oct_jwk("correct horse battery") },
            }) do
                local token = jwt:sign(case[1], { header = { alg = case[2], enc = case[3] }, payload = { foo = case[2] } })
                local obj = jwt:verify(case[4], token)
                ngx.say(case[2], " ", case[3], ": ", obj.verified, " ", obj.reason, " ", obj.payload and obj.payload.foo)
            end
            local token = jwt:sign(kw, { header = { alg = "A128KW", enc = "A128GCM" }, payload = { foo = "bar" } })
            show(jwt:verify(oct_jwk("fedcba9876543210"), token))
            show(jwt:verify(oct_jwk(kw, { alg = "A256KW" }), token))
            show(jwt:verify(oct_jwk(kw, { use = "sig" }), token))
            show(jwt:verify(oct_jwk(kw, { key_ops = { "decrypt" } }), token))
            -- a JWK Set with kid
            token = jwt:sign(kw, { header = { alg = "A128KW", enc = "A128GCM", kid = "kw" }, payload = { foo = "bar" } })
            show(jwt:verify({ keys = { oct_jwk("fedcba9876543210", { kid = "x" }), oct_jwk(kw, { kid = "kw" }) } }, token))
        }
    }
--- request
GET /t
--- response_body
A128KW A128CBC-HS256: true everything is awesome~ :p A128KW
A128KW A256GCM: true everything is awesome~ :p A128KW
A128GCMKW A128GCM: true everything is awesome~ :p A128GCMKW
dir A128CBC-HS256: true everything is awesome~ :p dir
PBES2-HS256+A128KW A128GCM: true everything is awesome~ :p PBES2-HS256+A128KW
false failed to decrypt JWE
false JWK alg A256KW does not match token alg A128KW
false JWK use "sig" does not permit alg A128KW
false JWK key_ops do not permit alg A128KW
true everything is awesome~ :p
--- no_error_log
[error]


=== TEST 9: HS key confusion: empty, PEM, DER and asymmetric key secrets are refused
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local pkey = require "resty.openssl.pkey"
            local x509 = require "resty.openssl.x509"
            local hmac = require "resty.hmac"

            -- an attacker MACs a token with whatever the verifier was given
            local function forge(secret, alg)
                local h = jwt:jwt_encode(cjson.encode({ alg = alg or "HS256" }))
                local p = jwt:jwt_encode(cjson.encode({ foo = "bar" }))
                local algo = ({ HS256 = hmac.ALGOS.SHA256, HS384 = hmac.ALGOS.SHA384, HS512 = hmac.ALGOS.SHA512 })[alg or "HS256"]
                return h .. "." .. p .. "." .. jwt:jwt_encode(hmac:new(secret, algo):final(h .. "." .. p))
            end

            show(jwt:verify("", forge("")))
            local ok, err = pcall(jwt.sign, jwt, "", { header = { alg = "HS256" }, payload = {} })
            ngx.say("sign empty: ", ok, " ", type(err) == "table" and err.reason or err)

            local rsa_der = assert(pkey.new(read_file("cert-pubkey.pem"))):tostring("public", "DER")
            local ec_der = assert(pkey.new(read_file("ec_cert_pubkey.pem"))):tostring("public", "DER")
            local ed_der = assert(pkey.new(read_file("ed25519-pubkey.pem"))):tostring("public", "DER")
            local cert_der = assert(x509.new(read_file("cert.pem"))):tostring("DER")
            show(jwt:verify(rsa_der, forge(rsa_der)))
            show(jwt:verify(ec_der, forge(ec_der, "HS384")))
            show(jwt:verify(ed_der, forge(ed_der, "HS512")))
            show(jwt:verify(cert_der, forge(cert_der)))
            ok, err = pcall(jwt.sign, jwt, cert_der, { header = { alg = "HS256" }, payload = {} })
            ngx.say("sign DER: ", ok, " ", type(err) == "table" and err.reason or err)
            -- binary secrets that merely start with 0x30 are fine
            local bin = "\48\30" .. string.rep("\1", 30)
            show(jwt:verify(bin, forge(bin)))
            local bin2 = "0123456789"
            show(jwt:verify(bin2, forge(bin2)))

            -- asymmetric JWKs (table or JSON), JWK Sets, pkey and x509 objects
            local rsa_jwk = jwk_of("cert-pubkey.pem")
            show(jwt:verify(rsa_jwk, forge(cjson.encode(rsa_jwk))))
            show(jwt:verify(cjson.encode(rsa_jwk), forge(cjson.encode(rsa_jwk))))
            show(jwt:verify(cjson.encode(jwk_of("ec_cert_pubkey.pem")), forge("x")))
            show(jwt:verify({ keys = { rsa_jwk } }, forge("x")))
            show(jwt:verify(cjson.encode({ keys = { rsa_jwk } }), forge("x")))
            show(jwt:verify(assert(pkey.new(read_file("cert-pubkey.pem"))), forge("x")))
            show(jwt:verify(assert(x509.new(read_file("cert.pem"))), forge("x")))
            show(jwt:verify(assert(jwt:load_key(read_file("cert.pem"))), forge("x")))

            -- and the other way round: an oct key never verifies RS/ES/PS/EdDSA
            local oct = oct_jwk("a-very-long-and-secret-hmac-key!")
            show(jwt:verify(oct, sign("cert-key.pem", { alg = "RS256" })))
            show(jwt:verify(oct, sign("cert-key.pem", { alg = "PS256" })))
            show(jwt:verify(cjson.encode(oct), sign("ec_cert-key.pem", { alg = "ES256" })))
            show(jwt:verify(oct, sign("ed25519-key.pem", { alg = "EdDSA" })))
        }
    }
--- request
GET /t
--- response_body
false invalid secret for HS256: empty secret
sign empty: false invalid secret for HS256: empty secret
false invalid secret for HS256: DER key material cannot be used as an HMAC secret
false invalid secret for HS384: DER key material cannot be used as an HMAC secret
false invalid secret for HS512: DER key material cannot be used as an HMAC secret
false invalid secret for HS256: DER key material cannot be used as an HMAC secret
sign DER: false invalid secret for HS256: DER key material cannot be used as an HMAC secret
true everything is awesome~ :p
true everything is awesome~ :p
false key type mismatch: alg HS256 requires a symmetric (oct) key
false key type mismatch: alg HS256 requires a symmetric (oct) key
false key type mismatch: alg HS256 requires a symmetric (oct) key
false no key in the JWK Set matches alg HS256
false no key in the JWK Set matches alg HS256
false key type mismatch: alg HS256 requires a symmetric (oct) key
false key type mismatch: alg HS256 requires a symmetric (oct) key
false key type mismatch: alg HS256 requires a symmetric (oct) key
false key type mismatch: alg RS256 requires an RSA key
false key type mismatch: alg PS256 requires an RSA key
false key type mismatch: alg ES256 requires an EC P-256 key
false key type mismatch: alg EdDSA requires an Ed25519 or Ed448 key
--- no_error_log
[error]


=== TEST 10: symmetric JWE algs refuse public key material (PBES2/AES-KW key confusion)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local pkey = require "resty.openssl.pkey"
            -- an app verifying RS256 tokens with a public key must not accept
            -- a PBES2 JWE "encrypted" with that public key as the password
            local pub = read_file("cert-pubkey.pem")
            local token = jwt:sign(pub, { header = { alg = "PBES2-HS256+A128KW", enc = "A128GCM" }, payload = { admin = true } })
            show(jwt:verify(pub, token))
            local der = assert(pkey.new(pub)):tostring("public", "DER")
            token = jwt:sign(der, { header = { alg = "PBES2-HS256+A128KW", enc = "A128GCM" }, payload = { admin = true } })
            show(jwt:verify(der, token))
            token = jwt:sign("pw-is-long-enough", { header = { alg = "PBES2-HS256+A128KW", enc = "A128GCM" }, payload = {} })
            show(jwt:verify("", token))
            show(jwt:verify(jwk_of("cert-pubkey.pem"), token))
            show(jwt:verify(assert(pkey.new(pub)), token))
            token = jwt:sign("0123456789abcdef", { header = { alg = "A128KW", enc = "A128GCM" }, payload = {} })
            show(jwt:verify(cjson.encode(jwk_of("ec_cert-key.pem", true)), token))
            token = jwt:sign(string.rep("k", 32), { header = { alg = "dir", enc = "A128CBC-HS256" }, payload = {} })
            show(jwt:verify({ keys = { jwk_of("cert-key.pem", true) } }, token))
        }
    }
--- request
GET /t
--- response_body
false invalid key for PBES2-HS256+A128KW: PEM key material cannot be used as a symmetric key
false invalid key for PBES2-HS256+A128KW: DER key material cannot be used as a symmetric key
false invalid key for PBES2-HS256+A128KW: empty secret
false key type mismatch: alg PBES2-HS256+A128KW requires a symmetric (oct) key
false key type mismatch: alg PBES2-HS256+A128KW requires a symmetric (oct) key
false key type mismatch: alg A128KW requires a symmetric (oct) key
false no key in the JWK Set matches alg dir
--- no_error_log
[error]


=== TEST 11: resty.openssl pkey and x509 objects as keys
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local pkey = require "resty.openssl.pkey"
            local x509 = require "resty.openssl.x509"
            show(jwt:verify(assert(pkey.new(read_file("cert-pubkey.pem"))), sign("cert-key.pem", { alg = "RS256" })))
            show(jwt:verify(assert(x509.new(read_file("cert.pem"))), sign("cert-key.pem", { alg = "PS384" })))
            show(jwt:verify(assert(x509.new(read_file("ec_cert.pem"))), sign("ec_cert-key.pem", { alg = "ES256" })))
            show(jwt:verify(assert(pkey.new(read_file("ed448-pubkey.pem"))), sign("ed448-key.pem", { alg = "EdDSA" })))
            -- private pkey objects decrypt
            local obj = jwt:verify(assert(pkey.new(read_file("cert-key.pem"))),
                sign("cert-pubkey.pem", { alg = "RSA-OAEP-256", enc = "A128GCM" }))
            show(obj)
            obj = jwt:verify(assert(pkey.new(read_file("ec_cert-key.pem"))),
                sign("ec_cert_pubkey.pem", { alg = "ECDH-ES+A256KW", enc = "A128GCM" }))
            show(obj)
            -- type binding still applies
            show(jwt:verify(assert(pkey.new(read_file("ec_cert_pubkey.pem"))), sign("cert-key.pem", { alg = "RS256" })))
            show(jwt:verify(assert(x509.new(read_file("cert.pem"))), sign("ec_cert-key.pem", { alg = "ES256" })))
            show(jwt:verify(assert(pkey.new(read_file("cert-pubkey.pem"))),
                sign("cert-pubkey.pem", { alg = "RSA-OAEP", enc = "A128GCM" })))
            show(jwt:verify(assert(x509.new(read_file("cert.pem"))),
                sign("cert-pubkey.pem", { alg = "RSA-OAEP", enc = "A128GCM" })))
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
false key type mismatch: alg RS256 requires an RSA key
false key type mismatch: alg ES256 requires an EC P-256 key
false alg RSA-OAEP requires a private key
false alg RSA-OAEP requires a private key
--- no_error_log
[error]


=== TEST 12: reusable key objects from jwk.load / jwt:load_key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local jwk = require "resty.jwt.jwk"
            local pkey = require "resty.openssl.pkey"

            local rsa = assert(jwk.load(read_file("cert-pubkey.pem")))
            local cert = assert(jwt:load_key(read_file("cert.pem")))
            local ec = assert(jwk.load(cjson.encode(jwk_of("ec_cert_pubkey.pem"))))
            local ed = assert(jwk.load(read_file("ed25519-pubkey.pem")))
            local set = assert(jwk.load({ keys = {
                jwk_of("cert-pubkey.pem", false, { kid = "a" }),
                jwk_of("ec_cert_pubkey.pem", false, { kid = "b" }),
                { kty = "RSA", kid = "broken", n = "AQAB" },
            } }))
            local dec = assert(jwk.load(jwk_of("cert-key.pem", true)))
            ngx.say(jwk.is_key(rsa), " ", jwk.is_key({}), " ", tostring(rsa), " ", #set.keys)
            ngx.say(jwk.load(rsa) == rsa)

            for i = 1, 2 do
                show(jwt:verify(rsa, sign("cert-key.pem", { alg = "RS256" })))
                show(jwt:verify(cert, sign("cert-key.pem", { alg = "RS256" })))
                show(jwt:verify(ec, sign("ec_cert-key.pem", { alg = "ES256" })))
                show(jwt:verify(ed, sign("ed25519-key.pem", { alg = "EdDSA" })))
                show(jwt:verify(set, sign("ec_cert-key.pem", { alg = "ES256", kid = "b" })))
            end
            local obj = jwt:verify(dec, sign("cert-pubkey.pem", { alg = "RSA-OAEP", enc = "A256GCM" }))
            ngx.say(obj.verified, " ", obj.payload and obj.payload.foo)
            -- a loaded PEM private key is a key object, not a JWK: usable for verifying
            show(jwt:verify(assert(jwk.load(read_file("ed25519-key.pem"))), sign("ed25519-key.pem", { alg = "EdDSA" })))
            -- the key object is checked against alg like any other key
            show(jwt:verify(rsa, sign("ec_cert-key.pem", { alg = "ES256" })))
            show(jwt:verify(rsa, jwt:sign("x", { header = { alg = "HS256" }, payload = {} })))

            -- load errors
            for _, bad in ipairs({ "not a key", {}, 5, { kty = "RSA", n = "AQAB" }, { kty = "EC", crv = "P-256", x = "AA", y = "AA" },
                    { keys = { { kty = "XYZ" } } }, '{"kty":"oct"}', { kty = "RSA", n = "AQAB", e = "AQAB", d = "!!" } }) do
                local k, err = jwk.load(bad)
                ngx.say(tostring(k), " ", err)
            end
        }
    }
--- request
GET /t
--- response_body
true false resty.jwt.jwk key set 2
true
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
true bar
true everything is awesome~ :p
false key type mismatch: alg ES256 requires an EC P-256 key
false key type mismatch: alg HS256 requires a symmetric (oct) key
nil unable to parse key: expected a PEM/DER key or certificate, a JWK or a JWK Set
nil invalid key: expected a JWK, a JWK Set, a PEM/DER string, a pkey or an x509 object
nil invalid key: expected a JWK, a JWK Set, a PEM/DER string, a pkey or an x509 object
nil invalid RSA JWK: "e" must be a base64url string
nil failed to load EC JWK
nil JWK Set has no usable keys
nil invalid oct JWK: "k" must be a base64url string
nil invalid RSA JWK: "d" must be a base64url string
--- error_log
ignoring JWK Set member #3 (kid broken)
--- no_error_log
[error]


=== TEST 13: JWK thumbprint (RFC 7638)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwk = require "resty.jwt.jwk"
            -- RFC 7638 3.1
            local key = {
                kty = "RSA",
                n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                e = "AQAB",
                alg = "RS256",
                kid = "2011-04-29",
            }
            ngx.say(jwk.thumbprint(key))
            ngx.say(jwk.thumbprint(cjson.encode(key), "SHA256"))
            ngx.say(#jwk.thumbprint(key, "SHA512"))
            -- private members don't change the thumbprint
            local pub = jwk_of("ec_cert_pubkey.pem")
            ngx.say(jwk.thumbprint(pub) == jwk.thumbprint(jwk_of("ec_cert-key.pem", true)))
            ngx.say(jwk.thumbprint({ kty = "oct", k = "AQAB" }) ~= nil)
            ngx.say(jwk.thumbprint({ kty = "OKP", crv = "Ed25519", x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }))
            ngx.say(select(2, jwk.thumbprint({ kty = "RSA", e = "AQAB" })))
            ngx.say(select(2, jwk.thumbprint({ kty = "XYZ" })))
            ngx.say(select(2, jwk.thumbprint(key, "NOPE")) ~= nil)
        }
    }
--- request
GET /t
--- response_body
NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
86
true
true
kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
invalid JWK: "n" is missing or malformed
unsupported JWK kty: XYZ
true
--- no_error_log
[error]


=== TEST 14: the trusted certs store is read once per path
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local evp = require "resty.evp"
            local x509 = require "resty.openssl.x509"

            local der = assert(x509.new(read_file("cert.pem"))):tostring("DER")
            local token = sign("cert-key.pem", { alg = "RS256", x5c = { ngx.encode_base64(der) } })

            local j = jwt:new()
            local before = evp.trust_store_loads
            j:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            for i = 1, 3 do
                show(j:verify(nil, token))
            end
            ngx.say("loads: ", evp.trust_store_loads - before)
            -- same path again: still cached
            j:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            show(j:verify(nil, token))
            ngx.say("loads: ", evp.trust_store_loads - before)
            -- a different path drops the cache
            j:set_trusted_certs_file("/lua-resty-jwt/testcerts/ec_cert.pem")
            show(j:verify(nil, token))
            j:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            show(j:verify(nil, token))
            show(j:verify(nil, token))
            ngx.say("loads: ", evp.trust_store_loads - before)
            -- a missing file isn't cached
            j:set_trusted_certs_file("/lua-resty-jwt/testcerts/missing.pem")
            local obj = j:verify(nil, token)
            ngx.say(obj.verified)
            obj = j:verify(nil, token)
            ngx.say(obj.verified)
            ngx.say("loads: ", evp.trust_store_loads - before)
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p
true everything is awesome~ :p
true everything is awesome~ :p
loads: 1
true everything is awesome~ :p
loads: 1
false Cert used to sign the JWT isn't trusted: unable to get local issuer certificate
true everything is awesome~ :p
true everything is awesome~ :p
loads: 3
false
false
loads: 5
--- no_error_log
[error]


=== TEST 15: evp constructors return distinct instances (no shared class state)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local function v(...) return tostring((...)) end
            local msg = "hello"

            local a = assert(evp.PublicKey:new(read_file("cert-pubkey.pem")))
            local b = assert(evp.PublicKey:new(read_file("ec_cert_pubkey.pem")))
            ngx.say("distinct: ", a ~= b, " ", a.public_key ~= b.public_key, " ", rawget(evp.PublicKey, "public_key") == nil)

            -- objects made earlier keep their own key after later new() calls
            local rs = assert(evp.RSASigner:new(read_file("cert-key.pem")))
            local es = assert(evp.ECSigner:new(read_file("ec_cert-key.pem")))
            local rs2 = assert(evp.RSASigner:new(read_file("privatekey.pem")))
            local rv = assert(evp.RSAVerifier:new(a))
            local ev = assert(evp.ECVerifier:new(b))
            local c = assert(evp.Cert:new(read_file("cert.pem")))
            local ec_cert = assert(evp.Cert:new(read_file("ec_cert.pem")))
            local cv = assert(evp.RSAVerifier:new(c))
            local pv = assert(evp.RSAVerifier:new(a, evp.CONST.RSA_PKCS1_PSS_PADDING))

            local rsig = assert(rs:sign(msg, "SHA256"))
            local esig = assert(es:get_raw_sig(assert(es:sign(msg, "SHA256"))))
            ngx.say("rsa: ", v(rv:verify(msg, rsig, "SHA256")))
            ngx.say("ec: ", v(ev:verify(msg, esig, "SHA256")))
            ngx.say("cert: ", v(cv:verify(msg, rsig, "SHA256")))
            ngx.say("other rsa key: ", v(rv:verify(msg, assert(rs2:sign(msg, "SHA256")), "SHA256")))
            ngx.say("pss verifier is separate: ", v(pv:verify(msg, rsig, "SHA256")), " ", v(rv:verify(msg, rsig, "SHA256")))
            ngx.say("certs: ", c:get_fingerprint("SHA256") ~= ec_cert:get_fingerprint("SHA256"))
            ngx.say("classes: ", getmetatable(ev).__index == evp.ECVerifier, " ", getmetatable(es).__index == evp.ECSigner,
                " ", getmetatable(rs).__index == evp.RSASigner)

            local enc = assert(evp.RSAEncryptor:new(a))
            local dec1 = assert(evp.RSADecryptor:new(read_file("cert-key.pem")))
            local dec2 = assert(evp.RSADecryptor:new(read_file("privatekey.pem")))
            ngx.say("decrypt: ", v(dec1:decrypt(assert(enc:encrypt("cek")))), " ", dec2:decrypt(assert(enc:encrypt("cek"))) == nil)
        }
    }
--- request
GET /t
--- response_body
distinct: true true true
rsa: true
ec: true
cert: true
other rsa key: false
pss verifier is separate: false true
certs: true
classes: true true true
decrypt: cek true
--- no_error_log
[error]
