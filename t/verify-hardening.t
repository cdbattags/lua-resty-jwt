BEGIN { use Cwd; $ENV{TEST_NGINX_SERVROOT} = Cwd::cwd() . "/t/servroot_$$"; $ENV{TEST_NGINX_SERVER_PORT} = 10000 + ($$ % 50000) }
use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (3 * blocks());

my $coverage = $ENV{COVERAGE} ? "require('luacov')" : "";

# Shared helpers (globals): read test certs and hand-craft tokens with
# arbitrary headers, which jwt:sign would refuse to produce.
our $HttpConfig = <<"_EOC_";
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        $coverage
        local cjson = require "cjson"
        local hmac = require "resty.hmac"
        local jwt = require "resty.jwt"

        function read_file(name)
            local f = assert(io.open("/lua-resty-jwt/testcerts/" .. name, "rb"))
            local s = f:read("*all")
            f:close()
            return s
        end

        -- header/payload may be tables (json encoded) or already-raw json strings
        function make_token(header, payload, sig)
            local h = type(header) == "string" and header or cjson.encode(header)
            local p = type(payload) == "string" and payload or cjson.encode(payload)
            return jwt:jwt_encode(h) .. "." .. jwt:jwt_encode(p) .. "." .. (sig or "AAAA")
        end

        function hs_token(secret, header, payload, algo)
            local h = jwt:jwt_encode(type(header) == "string" and header or cjson.encode(header))
            local p = jwt:jwt_encode(type(payload) == "string" and payload or cjson.encode(payload))
            local mac = hmac:new(secret, hmac.ALGOS[algo or "SHA256"]):final(h .. "." .. p)
            return h .. "." .. p .. "." .. jwt:jwt_encode(mac)
        end

        function rs256_token(header, payload)
            local evp = require "resty.evp"
            local h = jwt:jwt_encode(cjson.encode(header))
            local p = jwt:jwt_encode(cjson.encode(payload))
            local signer = assert(evp.RSASigner:new(read_file("cert-key.pem")))
            local sig = assert(signer:sign(h .. "." .. p, evp.CONST.SHA256_DIGEST))
            return h .. "." .. p .. "." .. jwt:jwt_encode(sig)
        end
    }
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: HS256 token with typ "at+jwt" verifies (verify does not apply sign-time typ check)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = hs_token("secret", {typ="at+jwt", alg="HS256"}, {foo="bar"})
            local obj = jwt:verify("secret", token)
            ngx.say(obj.verified, " ", obj.reason)
            obj = jwt:verify("other", token)
            ngx.say(obj.verified)
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p
false
--- no_error_log
[error]


=== TEST 2: HS384/HS512 still sign and verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            for _, alg in ipairs({"HS256", "HS384", "HS512"}) do
                local token = jwt:sign("secret", {header={typ="JWT", alg=alg}, payload={foo="bar"}})
                local obj = jwt:verify("secret", token)
                ngx.say(alg, " ", obj.verified, " ", obj.payload.foo)
            end
        }
    }
--- request
GET /t
--- response_body
HS256 true bar
HS384 true bar
HS512 true bar
--- no_error_log
[error]


=== TEST 3: HS256 rejects truncated, wrong-length and non-canonical signatures
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = hs_token("secret", {typ="JWT", alg="HS256"}, {foo="bar"})
            local hp, sig = token:match("^(.+)%.([^.]+)$")
            ngx.say(jwt:verify("secret", token).verified)

            -- truncated by one byte
            local raw = jwt:jwt_decode(sig)
            ngx.say(jwt:verify("secret", hp .. "." .. jwt:jwt_encode(raw:sub(1, 31))).verified)
            -- extended by one byte
            ngx.say(jwt:verify("secret", hp .. "." .. jwt:jwt_encode(raw .. "x")).verified)
            -- HS512-length signature on an HS256 token
            ngx.say(jwt:verify("secret", hp .. "." .. jwt:jwt_encode(raw .. raw)).verified)
            -- 32 bytes encode to 43 chars; the last char carries 2 unused bits.
            -- Flipping them decodes to the same bytes but must not verify.
            local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            local last = sig:sub(-1)
            local idx = alphabet:find(last, 1, true) - 1
            local alt = alphabet:sub(bit.bxor(idx, 1) + 1, bit.bxor(idx, 1) + 1)
            local malleated = sig:sub(1, -2) .. alt
            ngx.say(jwt:jwt_decode(malleated) == raw)
            local obj = jwt:verify("secret", hp .. "." .. malleated)
            ngx.say(obj.verified, " ", obj.reason == "signature mismatch: " .. malleated)
        }
    }
--- request
GET /t
--- response_body
true
false
false
false
true
false true
--- no_error_log
[error]
