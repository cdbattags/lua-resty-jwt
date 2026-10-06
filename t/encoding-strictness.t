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

=== TEST 1: JWS parts must be canonical base64url
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            local secret = "lua-resty-jwt-encoding-strictness"
            -- kid "??>>" makes the encoded header contain '-' and '_'
            local token = jwt:sign(secret, {
                header = { typ = "JWT", alg = "HS256", kid = "??>>" },
                payload = { foo = "bar" },
            })
            local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")

            -- same signature bytes, but the unused low bits of the last
            -- character are set (32 bytes -> 43 chars, 2 unused bits)
            local last = s:sub(-1)
            local idx = alphabet:find(last, 1, true) - 1
            local alt_sig = s:sub(1, -2) .. alphabet:sub(idx + 2, idx + 2)

            local cases = {
                { "canonical", token },
                { "sig trailing bits", h .. "." .. p .. "." .. alt_sig },
                { "sig padded", h .. "." .. p .. "." .. s .. "=" },
                { "header std alphabet", h:gsub("%-", "+"):gsub("_", "/") .. "." .. p .. "." .. s },
                { "payload padded", h .. "." .. p .. "=." .. s },
            }
            for _, c in ipairs(cases) do
                local obj = jwt:verify(secret, c[2])
                ngx.say(c[1], ": ", tostring(obj.verified), " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
canonical: true everything is awesome~ :p
sig trailing bits: false invalid jwt string: non-canonical base64url in signature
sig padded: false invalid jwt string: non-canonical base64url in signature
header std alphabet: false invalid jwt string: non-canonical base64url in header
payload padded: false invalid jwt string: non-canonical base64url in payload
--- no_error_log
[error]



=== TEST 2: JWE parts must be canonical base64url
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            local key = string.rep("k", 32)
            local token = jwt:sign(key, {
                header = { alg = "dir", enc = "A256GCM" },
                payload = { foo = "bar" },
            })
            local parts = {}
            for part in (token .. "."):gmatch("([^.]*)%.") do parts[#parts + 1] = part end

            -- 16-byte tag -> 22 chars, the last char carries 4 unused bits
            local tag = parts[5]
            local idx = alphabet:find(tag:sub(-1), 1, true) - 1
            local alt = { parts[1], parts[2], parts[3], parts[4], tag:sub(1, -2) .. alphabet:sub(idx + 2, idx + 2) }

            local ok = jwt:verify(key, token)
            local bad = jwt:verify(key, table.concat(alt, "."))
            ngx.say("canonical: ", tostring(ok.verified))
            ngx.say("tag trailing bits: ", tostring(bad.verified), " ", bad.reason)
        }
    }
--- request
GET /t
--- response_body
canonical: true
tag trailing bits: false invalid jwt string: non-canonical base64url in authentication tag
--- no_error_log
[error]



=== TEST 3: AES-GCM JWE with an empty plaintext round-trips; empty CBC ciphertext is rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            local j = jwt.new()
            j:set_payload_encoder(function() return "" end)
            j:set_payload_decoder(function(s) return { plaintext = s } end)
            local token = j:sign(key, {
                header = { alg = "dir", enc = "A256GCM" },
                payload = {},
            })
            local parts = {}
            for part in (token .. "."):gmatch("([^.]*)%.") do parts[#parts + 1] = part end
            ngx.say("parts: ", #parts, " ciphertext empty: ", tostring(parts[4] == ""))
            local obj = j:verify(key, token)
            ngx.say("gcm empty: ", tostring(obj.verified), " [", obj.payload and obj.payload.plaintext, "]")

            local cbc_key = string.rep("k", 64)
            local cbc = jwt:sign(cbc_key, {
                header = { alg = "dir", enc = "A256CBC-HS512" },
                payload = { foo = "bar" },
            })
            local cp = {}
            for part in (cbc .. "."):gmatch("([^.]*)%.") do cp[#cp + 1] = part end
            cp[4] = ""
            local bad = jwt:verify(cbc_key, table.concat(cp, "."))
            ngx.say("cbc empty: ", tostring(bad.verified), " ", bad.reason)
        }
    }
--- request
GET /t
--- response_body
parts: 5 ciphertext empty: true
gcm empty: true []
cbc empty: false invalid JWE ciphertext
--- no_error_log
[error]
