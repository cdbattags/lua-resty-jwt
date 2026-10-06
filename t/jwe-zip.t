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

=== TEST 1: zip=DEF round-trips with the built-in provider for every enc
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            ngx.say("built-in: ", require("resty.jwt-zlib").available)
            local keys = {
                ["A128CBC-HS256"] = string.rep("k", 32),
                ["A192CBC-HS384"] = string.rep("k", 48),
                ["A256CBC-HS512"] = string.rep("k", 64),
                A128GCM = string.rep("k", 16),
                A192GCM = string.rep("k", 24),
                A256GCM = string.rep("k", 32),
            }
            local payload = { text = string.rep("abc", 50) }
            for _, enc in ipairs({ "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
                                   "A128GCM", "A192GCM", "A256GCM" }) do
                local token = jwt:sign(keys[enc], {
                    header = { typ = "JWE", alg = "dir", enc = enc, zip = "DEF" },
                    payload = payload,
                })
                local obj = jwt:verify(keys[enc], token)
                ngx.say(enc, ": ", obj.verified, " ", obj.header.zip, " ",
                        cjson.encode(obj.payload) == cjson.encode(payload))
            end
        }
    }
--- request
GET /t
--- response_body
built-in: true
A128CBC-HS256: true DEF true
A192CBC-HS384: true DEF true
A256CBC-HS512: true DEF true
A128GCM: true DEF true
A192GCM: true DEF true
A256GCM: true DEF true
--- no_error_log
[error]



=== TEST 2: zip=DEF round-trips with RSA-OAEP-256, ECDH-ES, A128KW and PBES2
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local cases = {
                { alg = "RSA-OAEP-256", enc = "A256GCM",
                  sign = get_testcert("cert-pubkey.pem"), verify = get_testcert("cert-key.pem") },
                { alg = "ECDH-ES", enc = "A128CBC-HS256",
                  sign = get_testcert("ec_cert_pubkey.pem"), verify = get_testcert("ec_cert-key.pem") },
                { alg = "A128KW", enc = "A128GCM",
                  sign = string.rep("w", 16), verify = string.rep("w", 16) },
                { alg = "PBES2-HS256+A128KW", enc = "A128CBC-HS256",
                  sign = "correct horse", verify = "correct horse" },
            }
            for _, c in ipairs(cases) do
                local payload = { foo = "bar", alg = c.alg }
                local token = jwt:sign(c.sign, {
                    header = { typ = "JWE", alg = c.alg, enc = c.enc, zip = "DEF" },
                    payload = payload,
                })
                local obj = jwt:verify(c.verify, token)
                ngx.say(c.alg, ": ", obj.verified, " ", obj.header.zip, " ",
                        obj.payload.foo == "bar" and obj.payload.alg == c.alg)
            end
        }
    }
--- request
GET /t
--- response_body
RSA-OAEP-256: true DEF true
ECDH-ES: true DEF true
A128KW: true DEF true
PBES2-HS256+A128KW: true DEF true
--- no_error_log
[error]



=== TEST 3: zip=DEF meaningfully shrinks a compressible payload
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local shared_key = "12341234123412341234123412341234"
            local big = string.rep("compressible-payload-chunk-", 200)
            local plain = jwt:sign(shared_key, {
              header = { typ = "JWE", alg = "dir", enc = "A128CBC-HS256" },
              payload = { data = big }
            })
            local zipped = jwt:sign(shared_key, {
              header = { typ = "JWE", alg = "dir", enc = "A128CBC-HS256", zip = "DEF" },
              payload = { data = big }
            })
            ngx.say("shrunk: ", #zipped < #plain / 2)
            local jwt_obj = jwt:verify(shared_key, zipped)
            ngx.say("verified: ", jwt_obj.verified)
            ngx.say("payload_ok: ", jwt_obj.payload.data == big)
        }
    }
--- request
GET /t
--- response_body
shrunk: true
verified: true
payload_ok: true
--- no_error_log
[error]



=== TEST 4: RFC 7520 section 5.9 (compressed content, A128KW + A128GCM) decrypts
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- Figure 151 (JWK "k")
            local key = jwt:jwt_decode("GZy6sIZ6wl9NJOKB-jnmVQ")
            -- Figure 170
            local token = table.concat({
                "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC" ..
                "04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0",
                "5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi",
                "p9pUq6XHY0jfEZIl",
                "HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyez" ..
                "SPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0" ..
                "m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBK" ..
                "hpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw",
                "VILuUwuIxaLVmh5X-T7kmA",
            }, ".")
            -- Figure 72
            local expected = "You can trust us to stick with you through thick and "
                .. "thin\xe2\x80\x93to the bitter end. And you can trust us to "
                .. "keep any secret of yours\xe2\x80\x93closer than you keep it "
                .. "yourself. But you cannot trust us to let you face trouble "
                .. "alone, and go off without a word. We are your friends, Frodo."
            -- the plaintext is not JSON, so decode it as a raw string
            local j = jwt:new()
            j:set_payload_decoder(function(s) return s end)
            local obj = j:verify(key, token)
            ngx.say("verified: ", obj.verified, " ", obj.reason)
            ngx.say("zip: ", obj.header.zip)
            ngx.say("plaintext matches: ", obj.payload == expected)
        }
    }
--- request
GET /t
--- response_body
verified: true everything is awesome~ :p
zip: DEF
plaintext matches: true
--- no_error_log
[error]



=== TEST 5: a decompression bomb is rejected by the size cap, quickly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local zlib = require "resty.jwt-zlib"
            local key = string.rep("k", 32)
            -- 10 MiB of zeros deflates to ~10 KiB
            local bomb = assert(zlib.deflate(string.rep("\0", 10 * 1024 * 1024)))
            ngx.say("bomb is small: ", #bomb < 20 * 1024)
            -- a signer whose DEF provider emits the pre-built stream
            local signer = jwt:new()
            signer:register_compression_alg("DEF", {
                deflate = function() return bomb end,
                inflate = function() return nil, "unused" end,
            })
            for _, enc in ipairs({ "A256GCM", "A128CBC-HS256" }) do
                local token = signer:sign(key, {
                    header = { alg = "dir", enc = enc, zip = "DEF" },
                    payload = { foo = "bar" },
                })
                ngx.update_time()
                local t0 = ngx.now()
                local obj = jwt:verify(key, token)
                ngx.update_time()
                ngx.say(enc, ": ", obj.verified, " ", obj.reason, " fast: ", ngx.now() - t0 < 0.5)
            end
        }
    }
--- request
GET /t
--- response_body
bomb is small: true
A256GCM: false failed to decrypt JWE fast: true
A128CBC-HS256: false failed to decrypt JWE fast: true
--- no_error_log
[error]



=== TEST 6: set_zip_max_size sets an explicit cap and validates its argument
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            -- ~300 KiB of JSON that compresses far better than 10:1
            local payload = { data = string.rep("a", 300 * 1024) }
            local token = jwt:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                payload = payload,
            })
            local obj = jwt:verify(key, token)
            ngx.say("default cap: ", obj.verified, " ", obj.reason)

            local big = jwt:new()
            big:set_zip_max_size(1024 * 1024)
            obj = big:verify(key, token)
            ngx.say("1 MiB cap: ", obj.verified, " ", obj.payload.data == payload.data)

            local small = jwt:new()
            small:set_zip_max_size(10)
            local tiny = jwt:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                payload = { foo = "bar" },
            })
            obj = small:verify(key, tiny)
            ngx.say("10 byte cap: ", obj.verified, " ", obj.reason)
            small:set_zip_max_size(nil)
            ngx.say("reset: ", small:verify(key, tiny).verified)

            for _, bad in ipairs({ 0, -1, 1.5, "100" }) do
                local ok, err = pcall(jwt.set_zip_max_size, jwt:new(), bad)
                ngx.say(tostring(bad), ": ", ok, " ", err)
            end
        }
    }
--- request
GET /t
--- response_body
default cap: false failed to decrypt JWE
1 MiB cap: true true
10 byte cap: false failed to decrypt JWE
reset: true
0: false 'max_size' is expected to be an integer >= 1
-1: false 'max_size' is expected to be an integer >= 1
1.5: false 'max_size' is expected to be an integer >= 1
100: false 'max_size' is expected to be an integer >= 1
--- no_error_log
[error]



=== TEST 7: truncated and trailing-garbage DEFLATE streams fail generically
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local zlib = require "resty.jwt-zlib"
            local key = string.rep("k", 32)
            local good = assert(zlib.deflate('{"foo":"bar","pad":"' .. string.rep("x", 200) .. '"}'))
            local streams = {
                { "valid", good },
                { "truncated", good:sub(1, #good - 4) },
                { "trailing garbage", good .. "garbage" },
                { "not deflate", "\255\255\255\255" },
                -- under GCM an empty ciphertext segment would not reach
                -- parse_jwe at all; CBC padding keeps it non-empty
                { "empty", "", "A128CBC-HS256" },
            }
            for _, s in ipairs(streams) do
                local signer = jwt:new()
                signer:register_compression_alg("DEF", {
                    deflate = function() return s[2] end,
                    inflate = function() return nil, "unused" end,
                })
                local token = signer:sign(key, {
                    header = { alg = "dir", enc = s[3] or "A256GCM", zip = "DEF" },
                    payload = { foo = "bar" },
                })
                local obj = jwt:verify(key, token)
                ngx.say(s[1], ": ", obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
valid: true everything is awesome~ :p
truncated: false failed to decrypt JWE
trailing garbage: false failed to decrypt JWE
not deflate: false failed to decrypt JWE
empty: false failed to decrypt JWE
--- no_error_log
[error]



=== TEST 8: unknown or malformed zip values are rejected before any key work
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            -- sign
            local ok, err = pcall(jwt.sign, jwt, string.rep("k", 32), {
                header = { typ = "JWE", alg = "dir", enc = "A128CBC-HS256", zip = "FOO" },
                payload = { foo = "bar" }
            })
            ngx.say("sign FOO: ", ok, " ", err.reason)
            ok, err = pcall(jwt.sign, jwt, string.rep("k", 32), {
                header = { typ = "JWE", alg = "dir", enc = "A128CBC-HS256", zip = 1 },
                payload = { foo = "bar" }
            })
            ngx.say("sign 1: ", ok, " ", err.reason)

            -- verify: the FOO token is made by an instance that knows FOO; the
            -- verifier passes no RSA key at all, so reaching key work would
            -- report "rsa private key must not be null" instead
            local signer = jwt:new()
            signer:register_compression_alg("FOO", {
                deflate = function(d) return d end,
                inflate = function(d) return d end,
            })
            local token = signer:sign(get_testcert("cert-pubkey.pem"), {
                header = { alg = "RSA-OAEP-256", enc = "A256GCM", zip = "FOO" },
                payload = { foo = "bar" },
            })
            ngx.say("signer verifies: ", signer:verify(get_testcert("cert-key.pem"), token).verified)
            local obj = jwt:verify(nil, token)
            ngx.say("verify FOO: ", obj.verified, " ", obj.reason)

            local parts = {}
            for p in token:gmatch("[^.]+") do parts[#parts + 1] = p end
            parts[1] = jwt:jwt_encode('{"alg":"RSA-OAEP-256","enc":"A256GCM","zip":["DEF"]}')
            obj = jwt:verify(nil, table.concat(parts, "."))
            ngx.say("verify table: ", obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
sign FOO: false unsupported zip: FOO
sign 1: false invalid zip in JWE header
signer verifies: true
verify FOO: false unsupported zip: FOO
verify table: false invalid zip in JWE header
--- no_error_log
[error]



=== TEST 9: zip is rejected on a JWS, when loading and when signing
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local hmac = require "resty.hmac"
            local secret = "lua-resty-jwt"
            local signing_input = jwt:jwt_encode('{"alg":"HS256","typ":"JWT","zip":"DEF"}')
                .. "." .. jwt:jwt_encode('{"foo":"bar"}')
            local mac = hmac:new(secret, hmac.ALGOS.SHA256):final(signing_input)
            local token = signing_input .. "." .. jwt:jwt_encode(mac)

            local obj = jwt:load_jwt(token)
            ngx.say("load: ", obj.valid, " ", obj.reason)
            obj = jwt:verify(secret, token)
            ngx.say("verify: ", obj.verified, " ", obj.reason)

            local ok, err = pcall(jwt.sign, jwt, secret, {
                header = { typ = "JWT", alg = "HS256", zip = "DEF" },
                payload = { foo = "bar" },
            })
            ngx.say("sign: ", ok, " ", err.reason)
        }
    }
--- request
GET /t
--- response_body
load: false zip is not allowed in a JWS header
verify: false zip is not allowed in a JWS header
sign: false zip is not allowed in a JWS header
--- no_error_log
[error]



=== TEST 10: tampered ciphertext or tag fails generically without inflating
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local zlib = require "resty.jwt-zlib"
            local inflate_calls = 0
            local verifier = jwt:new()
            verifier:register_compression_alg("DEF", {
                deflate = zlib.deflate,
                inflate = function(d, max_size)
                    inflate_calls = inflate_calls + 1
                    return zlib.inflate(d, max_size)
                end,
            })
            local function flip(token, index)
                local parts = {}
                for p in token:gmatch("[^.]+") do parts[#parts + 1] = p end
                local raw = jwt:jwt_decode(parts[index])
                raw = string.char(bit.bxor(raw:byte(1), 1)) .. raw:sub(2)
                parts[index] = jwt:jwt_encode(raw)
                return table.concat(parts, ".")
            end
            local keys = { A256GCM = string.rep("k", 32), ["A128CBC-HS256"] = string.rep("k", 32) }
            for _, enc in ipairs({ "A256GCM", "A128CBC-HS256" }) do
                local token = jwt:sign(keys[enc], {
                    header = { alg = "dir", enc = enc, zip = "DEF" },
                    payload = { foo = "bar" },
                })
                -- dir has an empty encrypted key: parts are header, iv, ciphertext, tag
                for _, case in ipairs({ { "ciphertext", 3 }, { "tag", 4 }, { "iv", 2 } }) do
                    local obj = verifier:verify(keys[enc], flip(token, case[2]))
                    ngx.say(enc, " ", case[1], ": ", obj.verified, " ", obj.reason)
                end
                ngx.say(enc, " inflate calls: ", inflate_calls)
                ngx.say(enc, " untampered: ", verifier:verify(keys[enc], token).verified)
                inflate_calls = 0
            end
        }
    }
--- request
GET /t
--- response_body
A256GCM ciphertext: false failed to decrypt JWE
A256GCM tag: false failed to decrypt JWE
A256GCM iv: false failed to decrypt JWE
A256GCM inflate calls: 0
A256GCM untampered: true
A128CBC-HS256 ciphertext: false failed to decrypt JWE
A128CBC-HS256 tag: false failed to decrypt JWE
A128CBC-HS256 iv: false failed to decrypt JWE
A128CBC-HS256 inflate calls: 0
A128CBC-HS256 untampered: true
--- no_error_log
[error]



=== TEST 11: a custom provider registered on an instance stays on that instance
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"
            local deflate_calls, inflate_calls = 0, 0
            local function xor_bytes(d)
                local out = {}
                for i = 1, #d do
                    out[i] = string.char(bit.bxor(string.byte(d, i), 0x55))
                end
                return table.concat(out)
            end
            local a = jwt:new()
            a:register_compression_alg("XOR", {
                deflate = function(d)
                    deflate_calls = deflate_calls + 1
                    return xor_bytes(d)
                end,
                inflate = function(d)
                    inflate_calls = inflate_calls + 1
                    return xor_bytes(d)
                end,
            })
            -- overriding DEF on the instance must not touch the built-in
            a:register_compression_alg("DEF", {
                deflate = function() return nil, "disabled" end,
                inflate = function() return nil, "disabled" end,
            })
            local token = a:sign(shared_key, {
                header = { typ = "JWE", alg = "dir", enc = "A128CBC-HS256", zip = "XOR" },
                payload = { foo = "bar" }
            })
            local obj = a:verify(shared_key, token)
            ngx.say("deflate_calls: ", deflate_calls)
            ngx.say("inflate_calls: ", inflate_calls)
            ngx.say("payload: ", cjson.encode(obj.payload))
            ngx.say("instance: ", obj.verified)

            ngx.say("module: ", jwt:verify(shared_key, token).reason)
            ngx.say("other instance: ", jwt:new():verify(shared_key, token).reason)

            local def_token = jwt:sign(shared_key, {
                header = { alg = "dir", enc = "A128CBC-HS256", zip = "DEF" },
                payload = { foo = "bar" }
            })
            ngx.say("module DEF: ", jwt:verify(shared_key, def_token).verified)
            ngx.say("instance DEF: ", a:verify(shared_key, def_token).reason)
            local ok, err = pcall(a.sign, a, shared_key, {
                header = { alg = "dir", enc = "A128CBC-HS256", zip = "DEF" },
                payload = { foo = "bar" }
            })
            ngx.say("instance DEF sign: ", ok, " ", err.reason)
        }
    }
--- request
GET /t
--- response_body
deflate_calls: 1
inflate_calls: 1
payload: {"foo":"bar"}
instance: true
module: unsupported zip: XOR
other instance: unsupported zip: XOR
module DEF: true
instance DEF: failed to decrypt JWE
instance DEF sign: false failed to compress payload: disabled
--- no_error_log
[error]



=== TEST 12: module-level registrations are inherited by instances, copy on write
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            local id = { deflate = function(d) return d end, inflate = function(d) return d end }
            jwt:register_compression_alg("ID", id)
            local inst = jwt:new()
            local token = inst:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "ID" },
                payload = { foo = "bar" },
            })
            ngx.say("inherited: ", inst:verify(key, token).verified)
            inst:register_compression_alg("OTHER", id)
            ngx.say("instance keeps ID: ", inst:verify(key, token).verified)
            ngx.say("module has no OTHER: ", jwt.compression_algs.OTHER == nil)
        }
    }
--- request
GET /t
--- response_body
inherited: true
instance keeps ID: true
module has no OTHER: true
--- no_error_log
[error]



=== TEST 13: provider errors, raises and oversized results fail generically
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            local signer = jwt:new()
            signer:register_compression_alg("T", {
                deflate = function(d) return d end,
                inflate = function(d) return d end,
            })
            local token = signer:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "T" },
                payload = { foo = "bar" },
            })
            local inflates = {
                ["returns error"] = function() return nil, "broken" end,
                ["raises"] = function() error("boom") end,
                ["ignores max_size"] = function(d, max_size) return string.rep(" ", max_size + 1) end,
                ["returns non-string"] = function() return {} end,
            }
            for _, name in ipairs({ "returns error", "raises", "ignores max_size", "returns non-string" }) do
                local verifier = jwt:new()
                verifier:register_compression_alg("T", {
                    deflate = function(d) return d end,
                    inflate = inflates[name],
                })
                local obj = verifier:verify(key, token)
                ngx.say(name, ": ", obj.verified, " ", obj.reason)
            end
            local bad = { "x", {}, { deflate = 1, inflate = function() end } }
            for i = 1, #bad do
                local ok, err = pcall(jwt.register_compression_alg, jwt:new(), "Y", bad[i])
                ngx.say("bad handler ", i, ": ", ok, " ", err.reason)
            end
            local ok, err = pcall(jwt.register_compression_alg, jwt:new(), "", bad[3])
            ngx.say("bad name: ", ok, " ", err.reason)
        }
    }
--- request
GET /t
--- response_body
returns error: false failed to decrypt JWE
raises: false failed to decrypt JWE
ignores max_size: false failed to decrypt JWE
returns non-string: false failed to decrypt JWE
bad handler 1: false compression handler must be a table with deflate and inflate functions
bad handler 2: false compression handler must be a table with deflate and inflate functions
bad handler 3: false compression handler must be a table with deflate and inflate functions
bad name: false compression alg name must be a non-empty string
--- no_error_log
[error]



=== TEST 14: register_zlib_compression adapts a lua-zlib-style module, bounded
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            -- A stand-in for lua-zlib's streaming API: an identity "codec"
            -- whose stream ends at a "$" byte. inflate streams return
            -- (output, eof, total bytes in, total bytes out).
            local function fake_zlib(opts)
                opts = opts or {}
                return {
                    BEST_COMPRESSION = 9,
                    deflate = function()
                        return function(data) return data .. "$" end
                    end,
                    inflate = function()
                        local total_in, total_out, done = 0, 0, false
                        return function(piece)
                            local stop = piece:find("$", 1, true)
                            if stop and not opts.never_eof then
                                done = true
                                piece = piece:sub(1, stop - 1)
                                total_in = total_in + stop
                            else
                                total_in = total_in + #piece
                            end
                            total_out = total_out + #piece
                            return piece, done, total_in, total_out
                        end
                    end,
                }
            end
            local function verify_with(zlib, token)
                local j = jwt:new()
                j:register_zlib_compression(zlib)
                return j:verify(key, token)
            end

            local signer = jwt:new()
            signer:register_zlib_compression(fake_zlib())
            local token = signer:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                payload = { foo = "bar" },
            })
            ngx.say("round trip: ", verify_with(fake_zlib(), token).verified)
            ngx.say("no eof: ", verify_with(fake_zlib({ never_eof = true }), token).reason)

            local trailing = jwt:new()
            trailing:register_compression_alg("DEF", {
                deflate = function(d) return d .. "$junk" end,
                inflate = function() return nil, "unused" end,
            })
            token = trailing:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                payload = { foo = "bar" },
            })
            ngx.say("trailing: ", verify_with(fake_zlib(), token).reason)

            -- 1 MiB of payload: the 10x rule allows ~10 MiB here, so cap it
            local capped = jwt:new()
            capped:register_zlib_compression(fake_zlib())
            capped:set_zip_max_size(4096)
            token = signer:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                payload = { data = string.rep("a", 1024 * 1024) },
            })
            ngx.say("over cap: ", capped:verify(key, token).reason)

            local ok, err = pcall(jwt.register_zlib_compression, jwt:new(), {})
            ngx.say("bad module: ", ok, " ", err.reason)
        }
    }
--- request
GET /t
--- response_body
round trip: true
no eof: failed to decrypt JWE
trailing: failed to decrypt JWE
over cap: failed to decrypt JWE
bad module: false zlib module must expose deflate and inflate functions (pass `require "zlib"`)
--- no_error_log
[error]
