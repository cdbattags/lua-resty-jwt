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
