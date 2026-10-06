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
