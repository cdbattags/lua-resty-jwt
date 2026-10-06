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

=== TEST 1: a per-instance payload encoder is used when signing a JWS
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local j = jwt.new()
            j:set_payload_encoder(function(t) return '{"encoded_by":"instance"}' end)
            local token = j:sign("instance-encoder-secret", { header = { typ = "JWT", alg = "HS256" }, payload = { foo = "bar" } })
            local obj = jwt:verify("instance-encoder-secret", token)
            ngx.say(tostring(obj.verified), " ", obj.payload.encoded_by, " ", tostring(obj.payload.foo))
            -- the module (and other instances) keep the default encoder
            token = jwt:sign("instance-encoder-secret", { header = { typ = "JWT", alg = "HS256" }, payload = { foo = "bar" } })
            obj = jwt:verify("instance-encoder-secret", token)
            ngx.say(tostring(obj.verified), " ", tostring(obj.payload.encoded_by), " ", obj.payload.foo)
        }
    }
--- request
GET /t
--- response_body
true instance nil
true nil bar
--- no_error_log
[error]



=== TEST 2: the instance encoder applies to asymmetric JWS too, and to verifying a hand-built object
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function read(name)
                local f = assert(io.open("/lua-resty-jwt/testcerts/" .. name))
                local s = f:read("*a")
                f:close()
                return s
            end
            local j = jwt.new()
            j:set_payload_encoder(function(t) return '{"sub":"from-encoder"}' end)
            local token = j:sign(read("cert-key.pem"), { header = { typ = "JWT", alg = "RS256" }, payload = { sub = "ignored" } })
            local obj = jwt:verify(read("cert.pem"), token)
            ngx.say(tostring(obj.verified), " ", obj.payload.sub)

            -- a hand-built object (no raw_* parts) is encoded the same way on verify
            local hs = j:sign("hand-built-secret", { header = { typ = "JWT", alg = "HS256" }, payload = { sub = "ignored" } })
            local sig = hs:match("[^.]+$")
            local built = { valid = true, header = { typ = "JWT", alg = "HS256" }, payload = { sub = "ignored" }, signature = sig }
            ngx.say("instance: ", tostring(j:verify_jwt_obj("hand-built-secret", built).verified))
            built = { valid = true, header = { typ = "JWT", alg = "HS256" }, payload = { sub = "ignored" }, signature = sig }
            ngx.say("module: ", tostring(jwt:verify_jwt_obj("hand-built-secret", built).verified))
        }
    }
--- request
GET /t
--- response_body
true from-encoder
instance: true
module: false
--- no_error_log
[error]



=== TEST 3: JWK members must be canonical base64url
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwk = require "resty.jwt.jwk"
            -- "AQ" is the canonical encoding of "\1"; "AR" decodes to the same
            -- byte with non-zero trailing bits
            for _, k in ipairs({ "AQ", "AR", "AQ==", "A+8", "A/8", "A-8", "A" }) do
                local key, err = jwk.load({ kty = "oct", k = k })
                ngx.say(k, ": ", key and "ok" or err)
            end
        }
    }
--- request
GET /t
--- response_body
AQ: ok
AR: invalid oct JWK: "k" must be a base64url string
AQ==: invalid oct JWK: "k" must be a base64url string
A+8: invalid oct JWK: "k" must be a base64url string
A/8: invalid oct JWK: "k" must be a base64url string
A-8: ok
A: invalid oct JWK: "k" must be a base64url string
--- no_error_log
[error]



=== TEST 4: utils base64url helpers round-trip and reject every non-canonical spelling
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local utils = require "resty.utils"
            local ok = true
            for len = 0, 64 do
                local bytes = {}
                for i = 1, len do bytes[i] = string.char((i * 37 + len) % 256) end
                local s = table.concat(bytes)
                local e = utils.base64url_encode(s)
                if e:find("[=+/]") or utils.base64url_decode_strict(e) ~= s then
                    ok = false
                    ngx.say("round-trip failed at length ", len)
                end
            end
            ngx.say("round-trip: ", tostring(ok))
            for _, v in ipairs({ "", "Zm9v", "Zm9", "Zm8", "Zm9=", "Zm9vYg==", "Zm9vYh", "Zm9vYg", "Z", "Zm9v YQ", 42 }) do
                local d = utils.base64url_decode_strict(v)
                ngx.say(tostring(v), ": ", d and ("[" .. d .. "]") or "nil")
            end
        }
    }
--- request
GET /t
--- response_body
round-trip: true
: []
Zm9v: [foo]
Zm9: nil
Zm8: [fo]
Zm9=: nil
Zm9vYg==: nil
Zm9vYh: nil
Zm9vYg: [foob]
Z: nil
Zm9v YQ: nil
42: nil
--- no_error_log
[error]



=== TEST 5: JWK thumbprints are unchanged (RFC 7638 3.1 example)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwk = require "resty.jwt.jwk"
            ngx.say(jwk.thumbprint({
                kty = "RSA",
                n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                e = "AQAB",
                alg = "RS256",
                kid = "2011-04-29",
            }))
        }
    }
--- request
GET /t
--- response_body
NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
--- no_error_log
[error]
