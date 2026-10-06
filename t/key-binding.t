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



=== TEST 6: EdDSA signing refuses a missing key, a table, a public key and the wrong curve
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
--- no_error_log
[error]
