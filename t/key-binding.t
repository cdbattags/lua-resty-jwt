BEGIN { use Cwd; $ENV{TEST_NGINX_SERVROOT} = Cwd::cwd() . "/t/servroot_$$"; $ENV{TEST_NGINX_SERVER_PORT} = 10000 + ($$ % 50000) }
use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

if ($ENV{COVERAGE}) {
    $HttpConfig .= "    init_by_lua_block { require('luacov') }\n";
}

no_long_string();

run_tests();

__DATA__

=== TEST 1: AES key wrap algs round-trip only with keys of the alg's size
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local sizes = { A128KW = 16, A192KW = 24, A256KW = 32, A128GCMKW = 16, A192GCMKW = 24, A256GCMKW = 32 }
            for _, alg in ipairs({ "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW" }) do
                local key = string.rep("k", sizes[alg])
                local token = jwt:sign(key, { header = { alg = alg, enc = "A128GCM" }, payload = { foo = "bar" } })
                ngx.say(alg, " ", tostring(jwt:verify(key, token).verified))
            end
        }
    }
--- request
GET /t
--- response_body
A128KW true
A192KW true
A256KW true
A128GCMKW true
A192GCMKW true
A256GCMKW true
--- no_error_log
[error]



=== TEST 2: signing with a key of the wrong size for the alg is refused
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            for _, c in ipairs({ { "A128KW", 32 }, { "A256KW", 16 }, { "A192GCMKW", 32 }, { "A128GCMKW", 24 } }) do
                local ok, err = pcall(jwt.sign, jwt, string.rep("k", c[2]),
                    { header = { alg = c[1], enc = "A128GCM" }, payload = { foo = "bar" } })
                ngx.say(c[1], " with ", c[2], " bytes: ", tostring(ok), " ", ok and "" or err.reason)
            end
        }
    }
--- request
GET /t
--- response_body
A128KW with 32 bytes: false invalid key for A128KW: expected a 16-byte key
A256KW with 16 bytes: false invalid key for A256KW: expected a 32-byte key
A192GCMKW with 32 bytes: false invalid key for A192GCMKW: expected a 24-byte key
A128GCMKW with 24 bytes: false invalid key for A128GCMKW: expected a 16-byte key
--- no_error_log
[error]



=== TEST 3: decrypting with a key of the wrong size for the alg is refused before unwrapping
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = jwt:sign(string.rep("k", 16), { header = { alg = "A128KW", enc = "A128GCM" }, payload = { foo = "bar" } })
            local obj = jwt:verify(string.rep("k", 32), token)
            ngx.say(tostring(obj.verified), " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
false invalid key for A128KW: expected a 16-byte key
--- no_error_log
[error]



=== TEST 4: a per-instance payload decoder is used when loading a JWS
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = jwt:sign("instance-decoder-secret", { header = { typ = "JWT", alg = "HS256" }, payload = { foo = "bar" } })
            local j = jwt.new()
            j:set_payload_decoder(function(s) return { decoded_by = "instance", raw = s } end)
            local obj = j:verify("instance-decoder-secret", token)
            ngx.say(tostring(obj.verified), " ", obj.payload.decoded_by)
            -- the module-level decoder is unaffected
            ngx.say(jwt:verify("instance-decoder-secret", token).payload.foo)
        }
    }
--- request
GET /t
--- response_body
true instance
bar
--- no_error_log
[error]



=== TEST 5: ES* signing refuses a key on the wrong curve
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function read(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local c = f:read("*a"); f:close(); return c
            end
            local p256 = read("ec_cert-key.pem")
            local p384 = read("ec_cert_p384-key.pem")
            local ok, err = pcall(jwt.sign, jwt, p384, { header = { typ = "JWT", alg = "ES256" }, payload = { foo = "bar" } })
            ngx.say("ES256 with P-384: ", tostring(ok), " ", ok and "" or err.reason)
            local token = jwt:sign(p256, { header = { typ = "JWT", alg = "ES256" }, payload = { foo = "bar" } })
            ngx.say("ES256 with P-256: ", tostring(jwt:verify(read("ec_cert_pubkey.pem"), token).verified))
            local t384 = jwt:sign(p384, { header = { typ = "JWT", alg = "ES384" }, payload = { foo = "bar" } })
            ngx.say("ES384 with P-384: ", tostring(jwt:verify(read("ec_cert_p384_pubkey.pem"), t384).verified))
        }
    }
--- request
GET /t
--- response_body
ES256 with P-384: false key type mismatch: alg ES256 requires an EC P-256 key
ES256 with P-256: true
ES384 with P-384: true
--- no_error_log
[error]



=== TEST 6: EdDSA signing takes only a PEM or DER private key of the alg's curve
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function read(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local c = f:read("*a"); f:close(); return c
            end
            local function try(label, key, alg)
                local ok, err = pcall(jwt.sign, jwt, key, { header = { typ = "JWT", alg = alg }, payload = { foo = "bar" } })
                ngx.say(label, ": ", tostring(ok), " ", ok and "" or tostring(err.reason))
            end
            try("Ed25519 nil", nil, "Ed25519")
            try("EdDSA nil", nil, "EdDSA")
            try("Ed25519 table", {}, "Ed25519")
            try("Ed25519 key object", jwt:load_key(read("ed25519-key.pem")), "Ed25519")
            -- OpenSSL's own error text follows the prefix; only the prefix is ours
            local ok, err = pcall(jwt.sign, jwt, "", { header = { typ = "JWT", alg = "Ed25519" }, payload = { foo = "bar" } })
            ngx.say("Ed25519 empty: ", tostring(ok), " ", tostring(err.reason:find("failed to load EdDSA private key: ", 1, true) == 1))
            try("Ed25519 with Ed448 key", read("ed448-key.pem"), "Ed25519")
            try("Ed448 with Ed25519 key", read("ed25519-key.pem"), "Ed448")
            try("Ed25519 with P-256 key", read("ec_cert-key.pem"), "Ed25519")
            try("Ed25519 with public key", read("ed25519-pubkey.pem"), "Ed25519")
            -- the matching keys still sign, and the tokens verify
            for _, c in ipairs({ { "Ed25519", "ed25519" }, { "Ed448", "ed448" }, { "EdDSA", "ed25519" }, { "EdDSA", "ed448" } }) do
                local token = jwt:sign(read(c[2] .. "-key.pem"), { header = { typ = "JWT", alg = c[1] }, payload = { foo = "bar" } })
                ngx.say(c[1], " with ", c[2], ": ", tostring(jwt:verify(read(c[2] .. "-pubkey.pem"), token).verified))
            end
            -- a DER private key string signs too
            local der = require("resty.openssl.pkey").new(read("ed448-key.pem")):tostring("private", "DER")
            local token = jwt:sign(der, { header = { typ = "JWT", alg = "Ed448" }, payload = { foo = "bar" } })
            ngx.say("Ed448 with DER ed448: ", tostring(jwt:verify(read("ed448-pubkey.pem"), token).verified))
        }
    }
--- request
GET /t
--- response_body
Ed25519 nil: false failed to load EdDSA private key: expected a PEM or DER string
EdDSA nil: false failed to load EdDSA private key: expected a PEM or DER string
Ed25519 table: false failed to load EdDSA private key: expected a PEM or DER string
Ed25519 key object: false failed to load EdDSA private key: expected a PEM or DER string
Ed25519 empty: false true
Ed25519 with Ed448 key: false key type mismatch: alg Ed25519 requires an Ed25519 key
Ed448 with Ed25519 key: false key type mismatch: alg Ed448 requires an Ed448 key
Ed25519 with P-256 key: false key type mismatch: alg Ed25519 requires an Ed25519 key
Ed25519 with public key: false failed to load EdDSA private key: a public key cannot sign
Ed25519 with ed25519: true
Ed448 with ed448: true
EdDSA with ed25519: true
EdDSA with ed448: true
Ed448 with DER ed448: true
--- no_error_log
[error]



=== TEST 7: symmetric JWE encryption refuses key material that decryption would refuse
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local pkey = require "resty.openssl.pkey"
            local function read(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local c = f:read("*a"); f:close(); return c
            end
            local pem = read("cert-pubkey.pem")
            local der = assert(pkey.new(pem)):tostring("public", "DER")
            local function try(label, key, alg, enc)
                local ok, err = pcall(jwt.sign, jwt, key, { header = { alg = alg, enc = enc or "A128GCM" }, payload = { foo = "bar" } })
                ngx.say(label, ": ", tostring(ok), " ", ok and "" or tostring(err.reason))
            end
            try("PBES2 PEM", pem, "PBES2-HS256+A128KW")
            try("PBES2 DER", der, "PBES2-HS256+A128KW")
            try("PBES2 empty", "", "PBES2-HS256+A128KW")
            try("PBES2 table", { kty = "oct", k = "cGFzc3dvcmQ" }, "PBES2-HS256+A128KW")
            try("dir empty", "", "dir", "A128CBC-HS256")
            try("dir nil", nil, "dir", "A128CBC-HS256")
            try("A128KW PEM", pem, "A128KW")
            try("A128GCMKW nil", nil, "A128GCMKW")
            -- a plain password still round-trips
            local token = jwt:sign("password", { header = { alg = "PBES2-HS256+A128KW", enc = "A128GCM" }, payload = { foo = "bar" } })
            ngx.say("PBES2 password: ", tostring(jwt:verify("password", token).verified))
        }
    }
--- request
GET /t
--- response_body
PBES2 PEM: false invalid key for PBES2-HS256+A128KW: PEM key material cannot be used as a symmetric key
PBES2 DER: false invalid key for PBES2-HS256+A128KW: DER key material cannot be used as a symmetric key
PBES2 empty: false invalid key for PBES2-HS256+A128KW: empty secret
PBES2 table: false invalid key for PBES2-HS256+A128KW: expected a string
dir empty: false invalid key for dir: empty secret
dir nil: false invalid key for dir: expected a string
A128KW PEM: false invalid key for A128KW: PEM key material cannot be used as a symmetric key
A128GCMKW nil: false invalid key for A128GCMKW: expected a string
PBES2 password: true
--- no_error_log
[error]



=== TEST 8: an ES* signature that isn't exactly twice the curve order size is refused
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local evp = require "resty.evp"
            local function read(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local c = f:read("*a"); f:close(); return c
            end
            local pub = read("ec_cert_p521_pubkey.pem")
            local token = jwt:sign(read("ec_cert_p521-key.pem"), { header = { typ = "JWT", alg = "ES512" }, payload = { foo = "bar" } })
            local signing_input, encoded_sig = token:match("^(.+)%.([^.]+)$")
            local sig = jwt:jwt_decode(encoded_sig)
            ngx.say("raw length: ", #sig, " verifies: ", tostring(jwt:verify(pub, token).verified))
            for _, c in ipairs({ { "131 bytes", sig:sub(1, -2) }, { "133 bytes", sig .. "\0" }, { "empty", "" } }) do
                -- through the library, and straight into the FFI verifier
                local obj = jwt:verify(pub, signing_input .. "." .. jwt:jwt_encode(c[2]))
                local verifier = assert(evp.ECVerifier:new(assert(evp.PublicKey:new(pub))))
                local ok, err = verifier:verify(signing_input, c[2], evp.CONST.SHA512_DIGEST)
                ngx.say(c[1], ": ", tostring(obj.verified), " ", obj.reason, " | evp: ", tostring(ok), " ", err)
            end
        }
    }
--- request
GET /t
--- response_body
raw length: 132 verifies: true
131 bytes: false signature length != 2 * order length | evp: nil signature length != 2 * order length
133 bytes: false signature length != 2 * order length | evp: nil signature length != 2 * order length
empty: false invalid jwt string: empty signature | evp: nil signature length != 2 * order length
--- no_error_log
[error]



=== TEST 9: a PBES2 JWE made with the RSA public key as the password does not verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local f = io.open("/lua-resty-jwt/testcerts/cert-pubkey.pem")
            local pub = f:read("*a"); f:close()
            -- made by v0.3.2 with jwt:sign(<cert-pubkey.pem>, { header = { alg =
            -- "PBES2-HS256+A128KW", enc = "A128GCM" }, payload = { sub = "admin" } });
            -- v0.3.2's jwt:verify(<cert-pubkey.pem>, token) returns verified = true
            local token = "eyJlbmMiOiJBMTI4R0NNIiwicDJzIjoiXzRNOTEwb2FYSGlKbG54SXlPQ2VSdyIsImFsZyI6IlBCRVMyLUhTMjU2K0ExMjhLVyIsInAyYyI6NDA5Nn0"
                .. ".SiSxkGW1ROFQaYJNwui7sRBrbqVB3GjH.1H6m4yDhuCS-vbN_.5Ms0zP0M3sNt7q__y3z0.zD-N2Is5qeo"
            local obj = jwt:verify(pub, token)
            ngx.say("verify: ", tostring(obj.verified), " ", obj.reason)
            obj = jwt:verify_with(pub, token, { algorithms = { "RS256" } })
            ngx.say("verify_with RS256: ", tostring(obj.verified), " ", obj.reason)

            -- the same token asking for 10^9 PBKDF2 iterations: the key is refused
            -- before any key derivation, even where the p2c cap would allow it
            local encoded_header, rest = token:match("^([^.]+)(%..+)$")
            local header = cjson.decode(jwt:jwt_decode(encoded_header))
            header.p2c = 1000000000
            local slow = jwt:jwt_encode(cjson.encode(header)) .. rest
            ngx.say("p2c: ", cjson.decode(jwt:jwt_decode(slow:match("^[^.]+"))).p2c)
            local uncapped = jwt:new()
            uncapped:set_pbes2_max_count(1000000000)
            for _, c in ipairs({ { "default", jwt }, { "uncapped", uncapped } }) do
                ngx.update_time()
                local start = ngx.now()
                obj = c[2]:verify(pub, slow)
                ngx.update_time()
                ngx.say(c[1], ": ", tostring(obj.verified), " ", obj.reason, " fast: ", tostring(ngx.now() - start < 0.5))
            end
        }
    }
--- request
GET /t
--- response_body
verify: false invalid key for PBES2-HS256+A128KW: PEM key material cannot be used as a symmetric key
verify_with RS256: false whitelist unsupported alg: PBES2-HS256+A128KW
p2c: 1000000000
default: false invalid key for PBES2-HS256+A128KW: PEM key material cannot be used as a symmetric key fast: true
uncapped: false invalid key for PBES2-HS256+A128KW: PEM key material cannot be used as a symmetric key fast: true
--- no_error_log
[error]



=== TEST 10: asymmetric JWE encryption takes only a PEM string
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function read(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local c = f:read("*a"); f:close(); return c
            end
            local keys = {
                { "nil", nil },
                { "table", {} },
                { "RSA key object", jwt:load_key(read("cert-pubkey.pem")) },
                { "EC key object", jwt:load_key(read("ec_cert_pubkey.pem")) },
            }
            for _, alg in ipairs({ "RSA-OAEP", "RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW" }) do
                for _, k in ipairs(keys) do
                    local ok, err = pcall(jwt.sign, jwt, k[2], { header = { alg = alg, enc = "A128GCM" }, payload = { foo = "bar" } })
                    ngx.say(alg, " ", k[1], ": ", tostring(ok), " ", ok and "" or tostring(err.reason))
                end
            end
            -- PEM strings still encrypt, and the tokens decrypt
            for _, c in ipairs({ { "RSA-OAEP-256", "cert.pem", "cert-key.pem" }, { "RSA-OAEP-256", "cert-pubkey.pem", "cert-key.pem" },
                                 { "ECDH-ES", "ec_cert_pubkey.pem", "ec_cert-key.pem" }, { "ECDH-ES+A128KW", "ec_cert_pubkey.pem", "ec_cert-key.pem" } }) do
                local token = jwt:sign(read(c[2]), { header = { alg = c[1], enc = "A128GCM" }, payload = { foo = "bar" } })
                ngx.say(c[1], " with ", c[2], ": ", tostring(jwt:verify(read(c[3]), token).verified))
            end
        }
    }
--- request
GET /t
--- response_body
RSA-OAEP nil: false invalid key for RSA-OAEP: expected a PEM string
RSA-OAEP table: false invalid key for RSA-OAEP: expected a PEM string
RSA-OAEP RSA key object: false invalid key for RSA-OAEP: expected a PEM string
RSA-OAEP EC key object: false invalid key for RSA-OAEP: expected a PEM string
RSA-OAEP-256 nil: false invalid key for RSA-OAEP-256: expected a PEM string
RSA-OAEP-256 table: false invalid key for RSA-OAEP-256: expected a PEM string
RSA-OAEP-256 RSA key object: false invalid key for RSA-OAEP-256: expected a PEM string
RSA-OAEP-256 EC key object: false invalid key for RSA-OAEP-256: expected a PEM string
ECDH-ES nil: false invalid key for ECDH-ES: expected a PEM string
ECDH-ES table: false invalid key for ECDH-ES: expected a PEM string
ECDH-ES RSA key object: false invalid key for ECDH-ES: expected a PEM string
ECDH-ES EC key object: false invalid key for ECDH-ES: expected a PEM string
ECDH-ES+A128KW nil: false invalid key for ECDH-ES+A128KW: expected a PEM string
ECDH-ES+A128KW table: false invalid key for ECDH-ES+A128KW: expected a PEM string
ECDH-ES+A128KW RSA key object: false invalid key for ECDH-ES+A128KW: expected a PEM string
ECDH-ES+A128KW EC key object: false invalid key for ECDH-ES+A128KW: expected a PEM string
RSA-OAEP-256 with cert.pem: true
RSA-OAEP-256 with cert-pubkey.pem: true
ECDH-ES with ec_cert_pubkey.pem: true
ECDH-ES+A128KW with ec_cert_pubkey.pem: true
--- no_error_log
[error]
