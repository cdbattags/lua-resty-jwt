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

=== TEST 1: truncated GCM content tag (1, 8, 15 bytes) is rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local keys = {
                A128GCM = string.rep("k", 16),
                A192GCM = string.rep("k", 24),
                A256GCM = string.rep("k", 32),
            }
            local function with_tag_len(token, n)
                local head, tag = token:match("^(.*)%.([^.]+)$")
                return head .. "." .. jwt:jwt_encode(jwt:jwt_decode(tag):sub(1, n))
            end
            for _, enc in ipairs({ "A128GCM", "A192GCM", "A256GCM" }) do
                local key = keys[enc]
                local token = jwt:sign(key, {
                    header = { alg = "dir", enc = enc },
                    payload = { foo = "bar" },
                })
                ngx.say(enc, " 16: ", jwt:verify(key, token).verified)
                for _, n in ipairs({ 1, 8, 15 }) do
                    local obj = jwt:verify(key, with_tag_len(token, n))
                    ngx.say(enc, " ", n, ": ", obj.verified, " ", obj.reason)
                end
            end
        }
    }
--- request
GET /t
--- response_body
A128GCM 16: true
A128GCM 1: false invalid JWE authentication tag length
A128GCM 8: false invalid JWE authentication tag length
A128GCM 15: false invalid JWE authentication tag length
A192GCM 16: true
A192GCM 1: false invalid JWE authentication tag length
A192GCM 8: false invalid JWE authentication tag length
A192GCM 15: false invalid JWE authentication tag length
A256GCM 16: true
A256GCM 1: false invalid JWE authentication tag length
A256GCM 8: false invalid JWE authentication tag length
A256GCM 15: false invalid JWE authentication tag length
--- no_error_log
[error]



=== TEST 2: truncated A*GCMKW header tag (1, 8, 15 bytes) is rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local cipher = require "resty.openssl.cipher"
            local kek = string.rep("K", 32)
            local cek = string.rep("c", 32)
            local b64 = function(s) return jwt:jwt_encode(s) end

            -- Build an A256GCMKW + A256GCM token by hand so the content is
            -- validly encrypted under the header that carries the (possibly
            -- truncated) key wrap tag; only the key wrap tag check can fail.
            local function build(kw_tag_len)
                local kw_iv = string.rep("\1", 12)
                local kw = cipher.new("aes-256-gcm")
                local wrapped = assert(kw:encrypt(kek, kw_iv, cek, false))
                local kw_tag = assert(kw:get_aead_tag())
                local encoded_header = b64('{"alg":"A256GCMKW","enc":"A256GCM","iv":"'
                    .. b64(kw_iv) .. '","tag":"' .. b64(kw_tag:sub(1, kw_tag_len)) .. '"}')
                local iv = string.rep("\2", 12)
                local c = cipher.new("aes-256-gcm")
                local ct = assert(c:encrypt(cek, iv, '{"foo":"bar"}', false, encoded_header))
                local tag = assert(c:get_aead_tag())
                return table.concat({ encoded_header, b64(wrapped), b64(iv), b64(ct), b64(tag) }, ".")
            end

            for _, n in ipairs({ 16, 1, 8, 15 }) do
                local obj = jwt:verify(kek, build(n))
                ngx.say(n, ": ", obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
16: true everything is awesome~ :p
1: false invalid iv/tag length in header for AES-GCM key wrap
8: false invalid iv/tag length in header for AES-GCM key wrap
15: false invalid iv/tag length in header for AES-GCM key wrap
--- no_error_log
[error]



=== TEST 3: wrong IV length is rejected for GCM and CBC, wrong tag length for CBC-HS
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function replace_part(token, idx, value)
                local parts = {}
                for p in (token .. "."):gmatch("([^.]*)%.") do
                    parts[#parts + 1] = p
                end
                parts[idx] = jwt:jwt_encode(value)
                return table.concat(parts, ".")
            end
            local cases = {
                { enc = "A256GCM", key = string.rep("k", 32), iv = 16, tag = 16 },
                { enc = "A128CBC-HS256", key = string.rep("k", 32), iv = 12, tag = 8 },
                { enc = "A192CBC-HS384", key = string.rep("k", 48), iv = 12, tag = 16 },
                { enc = "A256CBC-HS512", key = string.rep("k", 64), iv = 12, tag = 16 },
            }
            for _, c in ipairs(cases) do
                local token = jwt:sign(c.key, {
                    header = { alg = "dir", enc = c.enc },
                    payload = { foo = "bar" },
                })
                local bad_iv = jwt:verify(c.key, replace_part(token, 3, string.rep("\0", c.iv)))
                ngx.say(c.enc, " iv: ", bad_iv.verified, " ", bad_iv.reason)
                if c.enc ~= "A256GCM" then
                    local raw_tag = jwt:jwt_decode(token:match("([^.]+)$"))
                    local bad_tag = jwt:verify(c.key, replace_part(token, 5, raw_tag:sub(1, c.tag)))
                    ngx.say(c.enc, " tag: ", bad_tag.verified, " ", bad_tag.reason)
                end
            end
        }
    }
--- request
GET /t
--- response_body
A256GCM iv: false invalid JWE initialization vector length
A128CBC-HS256 iv: false invalid JWE initialization vector length
A128CBC-HS256 tag: false invalid JWE authentication tag length
A192CBC-HS384 iv: false invalid JWE initialization vector length
A192CBC-HS384 tag: false invalid JWE authentication tag length
A256CBC-HS512 iv: false invalid JWE initialization vector length
A256CBC-HS512 tag: false invalid JWE authentication tag length
--- no_error_log
[error]



=== TEST 4: sign emits 16-byte GCM tags for every key size (content and GCMKW header)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            for _, c in ipairs({
                { alg = "dir", enc = "A128GCM", key = string.rep("k", 16) },
                { alg = "dir", enc = "A192GCM", key = string.rep("k", 24) },
                { alg = "A128GCMKW", enc = "A128GCM", key = string.rep("k", 16) },
                { alg = "A192GCMKW", enc = "A192GCM", key = string.rep("k", 24) },
            }) do
                local token = jwt:sign(c.key, {
                    header = { alg = c.alg, enc = c.enc },
                    payload = { foo = "bar" },
                })
                local header = cjson.decode(jwt:jwt_decode(token:match("^([^.]+)")))
                local tag = jwt:jwt_decode(token:match("([^.]+)$"))
                local kw_tag = header.tag and #jwt:jwt_decode(header.tag) or "-"
                ngx.say(c.alg, " ", c.enc, ": ", #tag, " ", kw_tag, " ",
                        jwt:verify(c.key, token).verified)
            end
        }
    }
--- request
GET /t
--- response_body
dir A128GCM: 16 - true
dir A192GCM: 16 - true
A128GCMKW A128GCM: 16 16 true
A192GCMKW A192GCM: 16 16 true
--- no_error_log
[error]



=== TEST 5: CBC-HS MAC is checked before decryption: tampered ciphertext and tampered tag fail identically
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function flip_last_byte(token, idx)
                local parts = {}
                for p in (token .. "."):gmatch("([^.]*)%.") do
                    parts[#parts + 1] = p
                end
                local raw = jwt:jwt_decode(parts[idx])
                raw = raw:sub(1, -2) .. string.char(bit.bxor(raw:byte(-1), 1))
                parts[idx] = jwt:jwt_encode(raw)
                return table.concat(parts, ".")
            end
            for _, c in ipairs({
                { enc = "A128CBC-HS256", key = string.rep("k", 32) },
                { enc = "A192CBC-HS384", key = string.rep("k", 48) },
                { enc = "A256CBC-HS512", key = string.rep("k", 64) },
            }) do
                local token = jwt:sign(c.key, {
                    header = { alg = "dir", enc = c.enc },
                    payload = { foo = "bar" },
                })
                local ok = jwt:verify(c.key, token)
                -- flipping the last ciphertext byte corrupts the CBC padding;
                -- it must be caught by the MAC, not reported as a padding error
                local bad_ct = jwt:verify(c.key, flip_last_byte(token, 4))
                local bad_tag = jwt:verify(c.key, flip_last_byte(token, 5))
                local bad_iv = jwt:verify(c.key, flip_last_byte(token, 3))
                ngx.say(c.enc, ": ", ok.verified, " ", ok.reason)
                ngx.say(c.enc, " ct: ", bad_ct.verified, " ", bad_ct.reason)
                ngx.say(c.enc, " same reason: ", bad_ct.reason == bad_tag.reason
                        and bad_ct.reason == bad_iv.reason)
            end
        }
    }
--- request
GET /t
--- response_body
A128CBC-HS256: true everything is awesome~ :p
A128CBC-HS256 ct: false failed to decrypt JWE
A128CBC-HS256 same reason: true
A192CBC-HS384: true everything is awesome~ :p
A192CBC-HS384 ct: false failed to decrypt JWE
A192CBC-HS384 same reason: true
A256CBC-HS512: true everything is awesome~ :p
A256CBC-HS512 ct: false failed to decrypt JWE
A256CBC-HS512 same reason: true
--- no_error_log
[error]



=== TEST 6: hand-built JWE objects are not reported as verified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local obj = jwt:verify_jwt_obj("k", {
                typ = "JWE",
                valid = true,
                verified = false,
                header = { alg = "dir", enc = "A256GCM" },
                payload = { foo = "bar" },
                internal = { authenticated = {} },
            })
            ngx.say(obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
false JWE was not authenticated
--- no_error_log
[error]



=== TEST 7: missing or invalid enc / alg in a JWE header is rejected cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            local rest = "." .. jwt:jwt_encode(string.rep("\0", 12))
                      .. "." .. jwt:jwt_encode("ciphertext")
                      .. "." .. jwt:jwt_encode(string.rep("\0", 16))
            for _, h in ipairs({
                '{"alg":"dir"}',
                '{"alg":"dir","enc":null}',
                '{"alg":"dir","enc":123}',
                '{"alg":"dir","enc":["A256GCM"]}',
                '{"alg":"dir","enc":"A1GCM"}',
                '{"alg":"A256KW","enc":"A256KW"}',
                '{"enc":"A256GCM"}',
                '{"alg":1,"enc":"A256GCM"}',
                '"just a string"',
            }) do
                local obj = jwt:verify(key, jwt:jwt_encode(h) .. "." .. rest)
                ngx.say(obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
false missing or invalid enc in JWE header
false missing or invalid enc in JWE header
false missing or invalid enc in JWE header
false missing or invalid enc in JWE header
false unsupported enc: A1GCM
false unsupported enc: A256KW
false missing or invalid alg in JWE header
false missing or invalid alg in JWE header
false invalid header: Imp1c3QgYSBzdHJpbmci
--- no_error_log
[error]



=== TEST 8: every JWE authentication/decryption failure yields the same generic reason
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function read(name)
                local f = assert(io.open("/lua-resty-jwt/testcerts/" .. name))
                local c = f:read("*all")
                f:close()
                return c
            end
            local function tamper(token, idx)
                local parts = {}
                for p in (token .. "."):gmatch("([^.]*)%.") do
                    parts[#parts + 1] = p
                end
                local raw = jwt:jwt_decode(parts[idx])
                raw = raw:sub(1, -2) .. string.char(bit.bxor(raw:byte(-1), 1))
                parts[idx] = jwt:jwt_encode(raw)
                return table.concat(parts, ".")
            end
            local function sign(alg, enc, key)
                return jwt:sign(key, { header = { alg = alg, enc = enc }, payload = { foo = "bar" } })
            end
            local k32, k32b = string.rep("k", 32), string.rep("w", 32)
            local cases = {
                { "dir GCM tampered tag", k32, tamper(sign("dir", "A256GCM", k32), 5) },
                { "dir GCM tampered ct", k32, tamper(sign("dir", "A256GCM", k32), 4) },
                { "dir GCM wrong key", k32b, sign("dir", "A256GCM", k32) },
                { "dir CBC tampered tag", k32, tamper(sign("dir", "A128CBC-HS256", k32), 5) },
                { "dir CBC tampered ct", k32, tamper(sign("dir", "A128CBC-HS256", k32), 4) },
                { "dir CBC wrong key", k32b, sign("dir", "A128CBC-HS256", k32) },
                { "A256KW wrong key", k32b, sign("A256KW", "A256GCM", k32) },
                { "A256KW tampered key", k32, tamper(sign("A256KW", "A256GCM", k32), 2) },
                { "A256GCMKW wrong key", k32b, sign("A256GCMKW", "A256GCM", k32) },
                { "PBES2 wrong password", "wrong", sign("PBES2-HS256+A128KW", "A128GCM", "secret") },
                { "RSA-OAEP wrong key", read("privatekey.pem"),
                  sign("RSA-OAEP-256", "A256GCM", read("cert-pubkey.pem")) },
                { "RSA-OAEP tampered key", read("cert-key.pem"),
                  tamper(sign("RSA-OAEP", "A128CBC-HS256", read("cert-pubkey.pem")), 2) },
                { "RSA-OAEP tampered tag", read("cert-key.pem"),
                  tamper(sign("RSA-OAEP", "A128CBC-HS256", read("cert-pubkey.pem")), 5) },
            }
            for _, c in ipairs(cases) do
                local obj = jwt:verify(c[2], c[3])
                ngx.say(c[1], ": ", obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
dir GCM tampered tag: false failed to decrypt JWE
dir GCM tampered ct: false failed to decrypt JWE
dir GCM wrong key: false failed to decrypt JWE
dir CBC tampered tag: false failed to decrypt JWE
dir CBC tampered ct: false failed to decrypt JWE
dir CBC wrong key: false failed to decrypt JWE
A256KW wrong key: false failed to decrypt JWE
A256KW tampered key: false failed to decrypt JWE
A256GCMKW wrong key: false failed to decrypt JWE
PBES2 wrong password: false failed to decrypt JWE
RSA-OAEP wrong key: false failed to decrypt JWE
RSA-OAEP tampered key: false failed to decrypt JWE
RSA-OAEP tampered tag: false failed to decrypt JWE
--- no_error_log
[error]



=== TEST 9: alg whitelist is enforced for JWE alg and enc before any key work
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local k32 = string.rep("k", 32)
            local rest = "." .. jwt:jwt_encode(string.rep("\0", 40))
                      .. "." .. jwt:jwt_encode(string.rep("\0", 12))
                      .. "." .. jwt:jwt_encode("ciphertext")
                      .. "." .. jwt:jwt_encode(string.rep("\0", 16))
            -- p2c = 10^9 would block the worker for minutes if PBKDF2 ran
            local pbes2 = jwt:jwt_encode('{"alg":"PBES2-HS512+A256KW","enc":"A256GCM",'
                .. '"p2s":"' .. jwt:jwt_encode(string.rep("s", 16)) .. '","p2c":1000000000}') .. rest

            jwt:set_alg_whitelist({ dir = 1, A256GCM = 1 })
            ngx.update_time()
            local start = ngx.now()
            local obj = jwt:verify("password", pbes2)
            ngx.update_time()
            ngx.say("pbes2: ", obj.verified, " ", obj.reason)
            ngx.say("fast: ", ngx.now() - start < 1)

            -- no key at all: the whitelist fires before the key is touched
            local rsa = jwt:jwt_encode('{"alg":"RSA-OAEP","enc":"A256GCM"}') .. rest
            ngx.say("rsa: ", jwt:verify(nil, rsa).reason)

            local kw = jwt:sign(k32, { header = { alg = "A256KW", enc = "A256GCM" }, payload = { foo = "bar" } })
            local cbc = jwt:sign(k32 .. k32, { header = { alg = "dir", enc = "A256CBC-HS512" }, payload = { foo = "bar" } })
            local gcm = jwt:sign(k32, { header = { alg = "dir", enc = "A256GCM" }, payload = { foo = "bar" } })

            ngx.say("dir+A256GCM: ", jwt:verify(k32, gcm).verified)
            ngx.say("dir+A256CBC-HS512: ", jwt:verify(k32 .. k32, cbc).reason)

            -- JWS-only whitelist blocks JWE entirely
            jwt:set_alg_whitelist({ RS256 = 1, HS256 = 1 })
            ngx.say("jws-only: ", jwt:verify(k32, gcm).reason)

            -- alg listed but not enc
            jwt:set_alg_whitelist({ A256KW = 1 })
            ngx.say("alg only: ", jwt:verify(k32, kw).reason)

            jwt:set_alg_whitelist({ A256KW = 1, A256GCM = 1 })
            ngx.say("alg+enc: ", jwt:verify(k32, kw).verified)

            -- load_jwt is also gated
            ngx.say("load_jwt: ", jwt:load_jwt(gcm, k32).reason)

            jwt:set_alg_whitelist(nil)
            ngx.say("no whitelist: ", jwt:verify(k32 .. k32, cbc).verified)
        }
    }
--- request
GET /t
--- response_body
pbes2: false whitelist unsupported alg: PBES2-HS512+A256KW
fast: true
rsa: whitelist unsupported alg: RSA-OAEP
dir+A256GCM: true
dir+A256CBC-HS512: whitelist unsupported enc: A256CBC-HS512
jws-only: whitelist unsupported alg: dir
alg only: whitelist unsupported enc: A256GCM
alg+enc: true
load_jwt: whitelist unsupported alg: dir
no whitelist: true
--- no_error_log
[error]



=== TEST 10: PBES2 p2c outside [1000, max] and short p2s are rejected before PBKDF2
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local rest = "." .. jwt:jwt_encode(string.rep("\0", 24))
                      .. "." .. jwt:jwt_encode(string.rep("\0", 12))
                      .. "." .. jwt:jwt_encode("ciphertext")
                      .. "." .. jwt:jwt_encode(string.rep("\0", 16))
            local salt16 = '"' .. jwt:jwt_encode(string.rep("s", 16)) .. '"'
            local function token(p2c, p2s)
                local h = '{"alg":"PBES2-HS256+A128KW","enc":"A128GCM"'
                if p2c then h = h .. ',"p2c":' .. p2c end
                if p2s then h = h .. ',"p2s":' .. p2s end
                return jwt:jwt_encode(h .. "}") .. rest
            end
            local cases = {
                { "p2c=10^9", token("1000000000", salt16) },
                { "p2c=10001", token("10001", salt16) },
                { "p2c=999", token("999", salt16) },
                { "p2c=0", token("0", salt16) },
                { "p2c=-5000", token("-5000", salt16) },
                { "p2c=4096.5", token("4096.5", salt16) },
                { "p2c=\"4096\"", token('"4096"', salt16) },
                { "p2c=1e999", token("1e999", salt16) },
                { "p2c missing", token(nil, salt16) },
                { "p2s missing", token("4096", nil) },
                { "p2s 7 bytes", token("4096", '"' .. jwt:jwt_encode("1234567") .. '"') },
                { "p2s empty", token("4096", '""') },
                { "p2s number", token("4096", "12345678") },
                -- within bounds: reaches PBKDF2 and fails only at key unwrap
                { "p2c=1000 p2s 8 bytes", token("1000", '"' .. jwt:jwt_encode("12345678") .. '"') },
                { "p2c=10000", token("10000", salt16) },
            }
            for _, c in ipairs(cases) do
                local obj = jwt:verify("password", c[2])
                ngx.say(c[1], ": ", obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
p2c=10^9: false p2c out of acceptable bounds in header for PBES2
p2c=10001: false p2c out of acceptable bounds in header for PBES2
p2c=999: false p2c out of acceptable bounds in header for PBES2
p2c=0: false p2c out of acceptable bounds in header for PBES2
p2c=-5000: false p2c out of acceptable bounds in header for PBES2
p2c=4096.5: false invalid p2c in header for PBES2
p2c="4096": false invalid p2c in header for PBES2
p2c=1e999: false p2c out of acceptable bounds in header for PBES2
p2c missing: false missing p2s/p2c in header for PBES2
p2s missing: false missing p2s/p2c in header for PBES2
p2s 7 bytes: false invalid p2s in header for PBES2
p2s empty: false invalid p2s in header for PBES2
p2s number: false invalid p2s in header for PBES2
p2c=1000 p2s 8 bytes: false failed to decrypt JWE
p2c=10000: false failed to decrypt JWE
--- no_error_log
[error]



=== TEST 11: jwt:set_pbes2_max_count adjusts the cap and validates its argument
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = jwt:sign("secret", {
                header = { alg = "PBES2-HS512+A256KW", enc = "A256GCM" },
                payload = { foo = "bar" },
            })
            ngx.say("default: ", jwt:verify("secret", token).verified)
            jwt:set_pbes2_max_count(2000)
            ngx.say("cap 2000: ", jwt:verify("secret", token).reason)
            jwt:set_pbes2_max_count(4096)
            ngx.say("cap 4096: ", jwt:verify("secret", token).verified)
            for _, bad in ipairs({ 999, 1500.5, "5000", true }) do
                local ok, err = pcall(jwt.set_pbes2_max_count, jwt, bad)
                ngx.say("set ", tostring(bad), ": ", ok, " ", err)
            end
            jwt:set_pbes2_max_count(nil)
            ngx.say("reset: ", jwt:verify("secret", token).verified)
        }
    }
--- request
GET /t
--- response_body
default: true
cap 2000: p2c out of acceptable bounds in header for PBES2
cap 4096: true
set 999: false 'max_count' is expected to be an integer >= 1000
set 1500.5: false 'max_count' is expected to be an integer >= 1000
set 5000: false 'max_count' is expected to be an integer >= 1000
set true: false 'max_count' is expected to be an integer >= 1000
reset: true
--- no_error_log
[error]
