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
A128CBC-HS256 ct: false signature mismatch
A128CBC-HS256 same reason: true
A192CBC-HS384: true everything is awesome~ :p
A192CBC-HS384 ct: false signature mismatch
A192CBC-HS384 same reason: true
A256CBC-HS512: true everything is awesome~ :p
A256CBC-HS512 ct: false signature mismatch
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
