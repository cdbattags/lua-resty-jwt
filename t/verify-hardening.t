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


=== TEST 4: untrusted x5c cert yields a clean reason (no nil concat)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local pem = read_file("cert.pem")
            local der_b64 = pem:gsub("%-%-%-%-%-[^-]+%-%-%-%-%-", ""):gsub("%s", "")
            -- trust an unrelated CA so the chain cannot be built
            jwt:set_trusted_certs_file("/lua-resty-jwt/testcerts/ec_cert.pem")
            local token = rs256_token({typ="JWT", alg="RS256", x5c={der_b64}}, {foo="bar"})
            local obj = jwt:verify(nil, token)
            ngx.say(obj.verified)
            ngx.say(obj.reason:find("^Cert used to sign the JWT isn't trusted: .+") ~= nil)

            -- and the same token is accepted with the right CA
            jwt:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            obj = jwt:verify(nil, token)
            ngx.say(obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
false
true
true everything is awesome~ :p
--- no_error_log
[error]


=== TEST 5: non-string alg in header gives a clean reason
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local pub = read_file("cert-pubkey.pem")
            for _, alg in ipairs({123, {"HS256"}, true, {HS256=1}}) do
                local token = make_token({typ="JWT", alg=alg}, {foo="bar"})
                local obj = jwt:verify(pub, token)
                ngx.say(obj.verified, " ", obj.reason)
            end
            jwt:set_alg_whitelist({HS256=1})
            local obj = jwt:verify("secret", make_token({alg=7}, {foo="bar"}))
            ngx.say(obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
false invalid alg: must be a string
false invalid alg: must be a string
false invalid alg: must be a string
false invalid alg: must be a string
false invalid alg: must be a string
--- no_error_log
[error]


=== TEST 6: non-object JSON headers are rejected at load time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            for _, h in ipairs({"123", "null", "\"HS256\"", "true", "[1,2]"}) do
                local obj = jwt:verify("secret", make_token(h, {foo="bar"}))
                ngx.say(obj.verified, " ", obj.reason)
            end
            -- a hand-built object with a broken header must not crash verify_jwt_obj
            local obj = jwt:verify_jwt_obj("secret", {valid=true, header=5, payload={}})
            ngx.say(obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
false invalid header: MTIz
false invalid header: bnVsbA
false invalid header: IkhTMjU2Ig
false invalid header: dHJ1ZQ
false No algorithm supplied
nil invalid header
--- no_error_log
[error]


=== TEST 7: non-string typ/kid/x5c/x5u header fields don't crash verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- typ is not checked on verify
            local obj = jwt:verify("secret", hs_token("secret", {typ={1}, alg="HS256"}, {foo="bar"}))
            ngx.say("typ table: ", obj.verified)

            local function secret_fn(kid) return "secret" end
            for _, kid in ipairs({5, {"a"}, false}) do
                obj = jwt:verify(secret_fn, hs_token("secret", {alg="HS256", kid=kid}, {foo="bar"}))
                ngx.say("kid ", type(kid), ": ", obj.verified, " ", obj.reason)
            end
            obj = jwt:verify(function() return {} end, hs_token("secret", {alg="HS256", kid="k"}, {foo="bar"}))
            ngx.say(obj.verified, " ", obj.reason)

            -- function secret with an RSA alg
            obj = jwt:verify(secret_fn, make_token({alg="RS256"}, {foo="bar"}))
            ngx.say(obj.verified, " ", obj.reason)
            -- table secret with RS/EdDSA algs
            obj = jwt:verify({}, make_token({alg="RS256"}, {foo="bar"}))
            ngx.say(obj.verified, " ", obj.reason)
            obj = jwt:verify({type="ED25519"}, make_token({alg="EdDSA"}, {foo="bar"}))
            ngx.say(obj.verified, " ", obj.reason)

            jwt:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            for _, x5c in ipairs({5, "abc", {5}, {{}}, true}) do
                obj = jwt:verify(nil, make_token({alg="RS256", x5c=x5c}, {foo="bar"}))
                ngx.say("x5c ", type(x5c), ": ", obj.verified, " ", obj.reason)
            end
            obj = jwt:verify(nil, make_token({alg="RS256", x5u={1}}, {foo="bar"}))
            ngx.say("x5u table: ", obj.verified, " ", obj.reason)
            jwt:set_x5u_content_retriever(function() return nil end)
            obj = jwt:verify(nil, make_token({alg="RS256", x5u="https://x"}, {foo="bar"}))
            ngx.say("x5u nil cert: ", obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
typ table: true
kid number: false secret function specified with non-string kid in header
kid table: false secret function specified with non-string kid in header
kid boolean: false secret function specified with non-string kid in header
false function returned a non-string secret for kid: k
false Decode secret is not a valid cert/public key
false Decode secret is not a valid cert/public key
false Failed to load EdDSA public key: no key provided
x5c number: false Malformed x5c header
x5c string: false Malformed x5c header
x5c table: false Malformed x5c header
x5c table: false Malformed x5c header
x5c boolean: false Malformed x5c header
x5u table: false Malformed x5u header
x5u nil cert: false The x5u_content_retriever function did not return a certificate.
--- no_error_log
[error]


=== TEST 8: sign with a non-string typ or alg returns a clean error
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local ok, err = pcall(jwt.sign, jwt, "secret", {header={typ={}, alg="HS256"}, payload={}})
            ngx.say(ok, " ", err.reason:find("^invalid typ: ") ~= nil)
            ok, err = pcall(jwt.sign, jwt, "secret", {header={typ="JWT", alg={}}, payload={}})
            ngx.say(ok, " ", err.reason:find("^unsupported alg: ") ~= nil)
        }
    }
--- request
GET /t
--- response_body
false true
false true
--- no_error_log
[error]


=== TEST 9: claims of a non-JSON (string) payload are nil
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local token = jwt:sign("secret", {header={typ="JWT", alg="HS256"}, payload="hello world"})
            local obj = jwt:verify("secret", token)
            ngx.say(obj.verified, " ", obj.payload)

            for _, claim in ipairs({"sub", "len", "format", "rep"}) do
                obj = jwt:verify("secret", token, {[claim]=validators.required()})
                ngx.say(claim, ": ", obj.verified, " ", obj.reason)
            end
            local seen = "unset"
            obj = jwt:verify("secret", token, {sub=function(val) seen = type(val) end})
            ngx.say(obj.verified, " ", seen)
        }
    }
--- request
GET /t
--- response_body
true hello world
sub: false 'sub' claim is required.
len: false 'len' claim is required.
format: false 'format' claim is required.
rep: false 'rep' claim is required.
true nil
--- no_error_log
[error]


=== TEST 10: number/boolean JSON payloads don't crash claim validation
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            for _, p in ipairs({"123", "true", "[1,2]"}) do
                local token = hs_token("secret", {alg="HS256"}, p)
                local obj = jwt:verify("secret", token)
                ngx.say(p, ": ", obj.verified, " ", obj.reason)
                obj = jwt:verify("secret", token, {exp=validators.is_not_expired()})
                ngx.say(p, ": ", obj.verified, " ", obj.reason)
            end
            -- x5u retriever receives a nil iss for a non-object payload
            jwt:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            local got_iss = "unset"
            jwt:set_x5u_content_retriever(function(url, iss) got_iss = iss return nil end)
            local obj = jwt:verify(nil, make_token({alg="RS256", x5u="https://x"}, "123"))
            ngx.say(obj.verified, " ", got_iss)
        }
    }
--- request
GET /t
--- response_body
123: true everything is awesome~ :p
123: false 'exp' claim is required.
true: true everything is awesome~ :p
true: false 'exp' claim is required.
[1,2]: true everything is awesome~ :p
[1,2]: false 'exp' claim is required.
false nil
--- no_error_log
[error]


=== TEST 11: validator raising a non-string error gives a clean reason
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = jwt:sign("secret", {header={typ="JWT", alg="HS256"}, payload={foo={1,2}}})
            local obj = jwt:verify("secret", token, {foo=function() error({}) end})
            ngx.say(obj.verified, " ", obj.reason)
            obj = jwt:verify("secret", token, {foo=function() return false end})
            ngx.say(obj.verified, " ", obj.reason:find("^Claim 'foo' %('table: ") ~= nil)
        }
    }
--- request
GET /t
--- response_body
false Claim 'foo' validation failed
false true
--- no_error_log
[error]
