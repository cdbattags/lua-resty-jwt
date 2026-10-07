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

=== TEST 1: by default a zip=DEF JWE is rejected before any key is unwrapped or derived
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
            -- tokens come from an instance that opted in
            local zlib = require "resty.jwt-zlib"
            local signer = jwt:new()
            signer:register_compression_alg("DEF", { deflate = zlib.deflate, inflate = zlib.inflate })
            local cases = {
                { alg = "dir", enc = "A256GCM", key = string.rep("k", 32),
                  wrong = string.rep("x", 32) },
                { alg = "RSA-OAEP-256", enc = "A256GCM", key = get_testcert("cert-pubkey.pem"),
                  right = get_testcert("cert-key.pem"), wrong = get_testcert("ec_cert-key.pem") },
                { alg = "A128KW", enc = "A128GCM", key = string.rep("w", 16),
                  wrong = string.rep("x", 16) },
                { alg = "PBES2-HS256+A128KW", enc = "A128CBC-HS256", key = "correct horse",
                  wrong = "wrong horse" },
            }
            for _, c in ipairs(cases) do
                local token = signer:sign(c.key, {
                    header = { alg = c.alg, enc = c.enc, zip = "DEF" },
                    payload = { foo = "bar" },
                })
                local right = c.right or c.key
                ngx.say(c.alg, " signer: ", signer:verify(right, token).verified)
                ngx.say(c.alg, " module: ", jwt:verify(right, token).reason)
                ngx.say(c.alg, " instance: ", jwt:new():verify(right, token).reason)
                -- a wrong key (or none) would fail key work with another reason
                ngx.say(c.alg, " wrong key: ", jwt:verify(c.wrong, token).reason)
                ngx.say(c.alg, " no key: ", jwt:verify(nil, token).reason)
            end
        }
    }
--- request
GET /t
--- response_body
dir signer: true
dir module: unsupported zip: DEF
dir instance: unsupported zip: DEF
dir wrong key: unsupported zip: DEF
dir no key: unsupported zip: DEF
RSA-OAEP-256 signer: true
RSA-OAEP-256 module: unsupported zip: DEF
RSA-OAEP-256 instance: unsupported zip: DEF
RSA-OAEP-256 wrong key: unsupported zip: DEF
RSA-OAEP-256 no key: unsupported zip: DEF
A128KW signer: true
A128KW module: unsupported zip: DEF
A128KW instance: unsupported zip: DEF
A128KW wrong key: unsupported zip: DEF
A128KW no key: unsupported zip: DEF
PBES2-HS256+A128KW signer: true
PBES2-HS256+A128KW module: unsupported zip: DEF
PBES2-HS256+A128KW instance: unsupported zip: DEF
PBES2-HS256+A128KW wrong key: unsupported zip: DEF
PBES2-HS256+A128KW no key: unsupported zip: DEF
--- no_error_log
[error]



=== TEST 2: by default the RFC 7520 section 5.9 compressed JWE is rejected, and decrypts once enabled
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = jwt:jwt_decode("GZy6sIZ6wl9NJOKB-jnmVQ")
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
            local obj = jwt:verify(key, token)
            ngx.say("default: ", obj.verified, " ", obj.reason)
            local j = jwt:new()
            j:register_zlib_compression()
            obj = j:verify(key, token)
            ngx.say("enabled: ", obj.verified, " ", obj.payload:sub(1, 22))
        }
    }
--- request
GET /t
--- response_body
default: false unsupported zip: DEF
enabled: true You can trust us to st
--- no_error_log
[error]



=== TEST 3: by default sign with a zip header raises, for the module and an instance
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            for _, obj in ipairs({ { "module", jwt }, { "instance", jwt:new() } }) do
                local ok, err = pcall(obj[2].sign, obj[2], key, {
                    header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                    payload = { foo = "bar" },
                })
                ngx.say(obj[1], ": ", ok, " ", type(err), " ", type(err) == "table" and err.reason)
            end
        }
    }
--- request
GET /t
--- response_body
module: false table unsupported zip: DEF
instance: false table unsupported zip: DEF
--- no_error_log
[error]



=== TEST 4: register_zlib_compression() on an instance enables DEF for that instance only
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            local j = jwt:new()
            local before = jwt:new()
            j:register_zlib_compression()
            local token = j:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                payload = { data = string.rep("abc", 100) },
            })
            local obj = j:verify(key, token)
            ngx.say("instance: ", obj.verified, " ", obj.payload.data == string.rep("abc", 100))
            ngx.say("module: ", jwt:verify(key, token).reason)
            ngx.say("module registry: ", jwt.compression_algs == nil)
            ngx.say("instance made before: ", before:verify(key, token).reason)
            ngx.say("instance made after: ", jwt:new():verify(key, token).reason)
            local ok, err = pcall(jwt.sign, jwt, key, {
                header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                payload = { foo = "bar" },
            })
            ngx.say("module sign: ", ok, " ", err.reason)
        }
    }
--- request
GET /t
--- response_body
instance: true true
module: unsupported zip: DEF
module registry: true
instance made before: unsupported zip: DEF
instance made after: unsupported zip: DEF
module sign: false unsupported zip: DEF
--- no_error_log
[error]



=== TEST 5: register_zlib_compression() on the module enables DEF for instances without their own registry
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local key = string.rep("k", 32)
            local id = { deflate = function(d) return d end, inflate = function(d) return d end }
            local plain = jwt:new()
            local own = jwt:new()
            own:register_compression_alg("ID", id)

            local signer = jwt:new()
            signer:register_zlib_compression()
            local token = signer:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                payload = { foo = "bar" },
            })
            ngx.say("plain before: ", plain:verify(key, token).reason)

            jwt:register_zlib_compression()
            ngx.say("module: ", jwt:verify(key, token).verified)
            ngx.say("module sign: ", jwt:verify(key, jwt:sign(key, {
                header = { alg = "dir", enc = "A256GCM", zip = "DEF" },
                payload = { foo = "bar" },
            })).verified)
            ngx.say("plain after: ", plain:verify(key, token).verified)
            ngx.say("new instance: ", jwt:new():verify(key, token).verified)
            -- an instance's own registry is a copy taken when it registered
            ngx.say("own registry: ", own:verify(key, token).reason)
        }
    }
--- request
GET /t
--- response_body
plain before: unsupported zip: DEF
module: true
module sign: true
plain after: true
new instance: true
own registry: unsupported zip: DEF
--- no_error_log
[error]



=== TEST 6: register_zlib_compression() raises at registration when zlib cannot be loaded
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local real = package.loaded["resty.jwt-zlib"]
            package.loaded["resty.jwt-zlib"] = { available = false, err = "zlib shared library not found" }
            local j = jwt:new()
            local ok, err = pcall(j.register_zlib_compression, j)
            ngx.say("instance: ", ok, " ", err.reason)
            ok, err = pcall(jwt.register_zlib_compression, jwt)
            ngx.say("module: ", ok, " ", err.reason)
            ngx.say("nothing registered: ", rawget(j, "compression_algs") == nil
                and jwt.compression_algs == nil)
            package.loaded["resty.jwt-zlib"] = real
            j:register_zlib_compression()
            ngx.say("restored: ", j.compression_algs.DEF ~= nil)
        }
    }
--- request
GET /t
--- response_body
instance: false the built-in zlib provider is not available: zlib shared library not found
module: false the built-in zlib provider is not available: zlib shared library not found
nothing registered: true
restored: true
--- no_error_log
[error]
