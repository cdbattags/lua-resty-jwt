BEGIN { use Cwd; $ENV{TEST_NGINX_SERVROOT} = Cwd::cwd() . "/t/servroot_$$"; $ENV{TEST_NGINX_SERVER_PORT} = 10000 + ($$ % 50000) }
use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (3 * blocks());

my $coverage = $ENV{COVERAGE} ? "require('luacov')" : "";

# Shared helpers (globals). The validators' clock is pinned to 1000 so the
# date checks are deterministic.
our $HttpConfig = <<"_EOC_";
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        $coverage
        local jwt = require "resty.jwt"
        local validators = require "resty.jwt-validators"
        validators.set_system_clock(function() return 1000 end)

        function hs_token(payload, header)
            return jwt:sign("secret", {
                header = header or {typ="JWT", alg="HS256"},
                payload = payload,
            })
        end

        -- flips the last signature character, keeping the token well-formed
        function tamper(token)
            local last = token:sub(-1)
            return token:sub(1, -2) .. (last == "A" and "Q" or "A")
        end

        -- verifies an HS256 token for payload against the claim specs and
        -- prints the outcome
        function check(label, payload, ...)
            local obj = jwt:verify("secret", hs_token(payload), ...)
            ngx.say(label, ": ", obj.verified, " ", obj.reason)
        end

        -- prints the error raised when building a validator
        function build_error(label, fx, ...)
            local ok, err = pcall(fx, ...)
            ngx.say(label, ": ", ok and "built" or err)
        end
    }
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: audience accepts a string or array aud containing an allowed audience
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            check("string", {aud="api"}, {aud=validators.audience("api")})
            check("string in list", {aud="web"}, {aud=validators.audience({"api", "web"})})
            check("array, any", {aud={"other", "web"}}, {aud=validators.audience({"api", "web"})})
            check("string mismatch", {aud="evil"}, {aud=validators.audience({"api", "web"})})
            check("array mismatch", {aud={"evil", "other"}}, {aud=validators.audience("api")})
            check("empty array", {aud={}}, {aud=validators.audience("api")})
            check("missing", {sub="x"}, {aud=validators.audience("api")})
            check("opt missing", {sub="x"}, {aud=validators.opt_audience("api")})
            check("opt mismatch", {aud="evil"}, {aud=validators.opt_audience("api")})
        }
    }
--- request
GET /t
--- response_body
string: true everything is awesome~ :p
string in list: true everything is awesome~ :p
array, any: true everything is awesome~ :p
string mismatch: false 'aud' claim does not contain an allowed audience.
array mismatch: false 'aud' claim does not contain an allowed audience.
empty array: false 'aud' claim does not contain an allowed audience.
missing: false 'aud' claim is required.
opt missing: true everything is awesome~ :p
opt mismatch: false 'aud' claim does not contain an allowed audience.
--- no_error_log
[error]


=== TEST 2: audience rejects an aud that is not a string or an array of strings
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            local spec = {aud=validators.audience("api")}
            check("number", {aud=1}, spec)
            check("boolean", {aud=true}, spec)
            check("object", {aud={["1"]="api"}}, spec)
            check("array with number", {aud={"api", 1}}, spec)
            check("array with object", {aud={"api", {x="api"}}}, spec)
            check("null", {aud=require("cjson").null}, spec)
            -- a substring or pattern of an allowed audience is not a match
            check("substring", {aud="ap"}, spec)
            check("pattern", {aud="a.i"}, {aud=validators.audience("a.i")})
            check("pattern mismatch", {aud="api"}, {aud=validators.audience("a.i")})
        }
    }
--- request
GET /t
--- response_body
number: false 'aud' is malformed.  Expected to be a string or array of strings.
boolean: false 'aud' is malformed.  Expected to be a string or array of strings.
object: false 'aud' is malformed.  Expected to be a string or array of strings.
array with number: false 'aud' is malformed.  Expected to be a string or array of strings.
array with object: false 'aud' is malformed.  Expected to be a string or array of strings.
null: false 'aud' is malformed.  Expected to be a string or array of strings.
substring: false 'aud' claim does not contain an allowed audience.
pattern: true everything is awesome~ :p
pattern mismatch: false 'aud' claim does not contain an allowed audience.
--- no_error_log
[error]


=== TEST 3: audience validator construction errors
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            build_error("nil", validators.audience, nil)
            build_error("number", validators.opt_audience, 42)
            build_error("empty", validators.audience, {})
            build_error("non-string entry", validators.audience, {"api", 1})
            build_error("ok", validators.audience, {"api"})
        }
    }
--- request
GET /t
--- response_body
nil: Cannot create validator for nil audiences.
number: Cannot create validator for non-string or table audiences.
empty: Cannot create validator for empty table audiences.
non-string entry: Cannot create validator for non-string table audiences.
ok: built
--- no_error_log
[error]


=== TEST 4: issued_at rejects an iat in the future, within the leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            check("now", {iat=1000}, {iat=validators.issued_at()})
            check("past", {iat=1}, {iat=validators.issued_at()})
            check("float", {iat=999.5}, {iat=validators.issued_at()})
            check("future", {iat=1001}, {iat=validators.issued_at()})
            check("in leeway", {iat=1005}, {iat=validators.issued_at({leeway=5})})
            check("past leeway", {iat=1006}, {iat=validators.issued_at({leeway=5})})
            check("missing", {sub="x"}, {iat=validators.issued_at()})
            check("opt missing", {sub="x"}, {iat=validators.opt_issued_at()})
            check("opt future", {iat=2000}, {iat=validators.opt_issued_at()})
        }
    }
--- request
GET /t
--- response_body
now: true everything is awesome~ :p
past: true everything is awesome~ :p
float: true everything is awesome~ :p
future: false 'iat' claim is in the future: issued at Thu, 01 Jan 1970 00:16:41 GMT
in leeway: true everything is awesome~ :p
past leeway: false 'iat' claim is in the future: issued at Thu, 01 Jan 1970 00:16:46 GMT
missing: false 'iat' claim is required.
opt missing: true everything is awesome~ :p
opt future: false 'iat' claim is in the future: issued at Thu, 01 Jan 1970 00:33:20 GMT
--- no_error_log
[error]


=== TEST 5: issued_at max_age rejects tokens issued too long ago
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            check("at max age", {iat=940}, {iat=validators.issued_at({max_age=60})})
            check("too old", {iat=939}, {iat=validators.issued_at({max_age=60})})
            check("zero max age", {iat=1000}, {iat=validators.issued_at({max_age=0})})
            check("zero max age, old", {iat=999}, {iat=validators.issued_at({max_age=0})})
            -- the leeway applies to the maximum age too
            check("leeway", {iat=935}, {iat=validators.issued_at({max_age=60, leeway=5})})
            check("leeway, too old", {iat=934}, {iat=validators.issued_at({max_age=60, leeway=5})})
            check("future still checked", {iat=1001}, {iat=validators.issued_at({max_age=60})})
        }
    }
--- request
GET /t
--- response_body
at max age: true everything is awesome~ :p
too old: false 'iat' claim is older than the maximum age: issued at Thu, 01 Jan 1970 00:15:39 GMT
zero max age: true everything is awesome~ :p
zero max age, old: false 'iat' claim is older than the maximum age: issued at Thu, 01 Jan 1970 00:16:39 GMT
leeway: true everything is awesome~ :p
leeway, too old: false 'iat' claim is older than the maximum age: issued at Thu, 01 Jan 1970 00:15:34 GMT
future still checked: false 'iat' claim is in the future: issued at Thu, 01 Jan 1970 00:16:41 GMT
--- no_error_log
[error]


=== TEST 6: issued_at rejects a non-numeric or negative iat
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            local spec = {iat=validators.issued_at({max_age=60})}
            check("string", {iat="1000"}, spec)
            check("negative", {iat=-1}, spec)
            check("table", {iat={1000}}, spec)
            check("boolean", {iat=true}, spec)
        }
    }
--- request
GET /t
--- response_body
string: false 'iat' is malformed.  Expected to be a positive numeric value.
negative: false 'iat' is malformed.  Expected to be a positive numeric value.
table: false 'iat' is malformed.  Expected to be a positive numeric value.
boolean: false 'iat' is malformed.  Expected to be a positive numeric value.
--- no_error_log
[error]


=== TEST 7: issued_at uses the system leeway unless given its own, without changing it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            check("own leeway", {iat=1100}, {iat=validators.issued_at({leeway=100})})
            -- a per-validator leeway does not leak into later validators
            check("default after own", {iat=1100}, {iat=validators.issued_at()})
            validators.set_system_leeway(100)
            check("system leeway", {iat=1100}, {iat=validators.issued_at()})
            check("own leeway wins", {iat=1100}, {iat=validators.issued_at({leeway=0})})
            validators.set_system_leeway(0)
            check("reset", {iat=1100}, {iat=validators.issued_at()})
            build_error("bad max_age", validators.issued_at, {max_age=-1})
            build_error("string max_age", validators.issued_at, {max_age="60"})
            build_error("bad leeway", validators.issued_at, {leeway=-1})
            build_error("not a table", validators.issued_at, 60)
        }
    }
--- request
GET /t
--- response_body
own leeway: true everything is awesome~ :p
default after own: false 'iat' claim is in the future: issued at Thu, 01 Jan 1970 00:18:20 GMT
system leeway: true everything is awesome~ :p
own leeway wins: false 'iat' claim is in the future: issued at Thu, 01 Jan 1970 00:18:20 GMT
reset: false 'iat' claim is in the future: issued at Thu, 01 Jan 1970 00:18:20 GMT
bad max_age: max_age must be a non-negative number
string max_age: max_age must be a non-negative number
bad leeway: leeway must be a non-negative number
not a table: Cannot create validator for non-table options.
--- no_error_log
[error]


=== TEST 8: jti_hook calls the hook with the jti and the verified payload
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            local seen = {}
            local hook = function(jti, payload)
                seen[#seen + 1] = jti .. "/" .. tostring(payload.sub)
                if jti == "replayed" then return nil, "already used" end
                if jti == "refused" then return false end
                if jti == "raises" then error("cache unavailable", 0) end
                if jti == "nothing" then return end
                return true
            end
            check("accepted", {jti="abc", sub="alice"}, {jti=validators.jti_hook(hook)})
            check("with reason", {jti="replayed", sub="bob"}, {jti=validators.jti_hook(hook)})
            check("false", {jti="refused", sub="carol"}, {jti=validators.jti_hook(hook)})
            check("raises", {jti="raises", sub="dave"}, {jti=validators.jti_hook(hook)})
            -- the hook must return true: a hook that returns nothing rejects
            check("no return", {jti="nothing", sub="erin"}, {jti=validators.jti_hook(hook)})
            ngx.say(table.concat(seen, ","))
        }
    }
--- request
GET /t
--- response_body
accepted: true everything is awesome~ :p
with reason: false 'jti' claim was rejected: already used
false: false 'jti' claim was rejected.
raises: false cache unavailable
no return: false 'jti' claim was rejected.
abc/alice,replayed/bob,refused/carol,raises/dave,nothing/erin
--- no_error_log
[error]


=== TEST 9: jti_hook rejects a missing or non-string jti without calling the hook
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            local calls = 0
            local hook = function() calls = calls + 1 return true end
            check("number", {jti=1}, {jti=validators.jti_hook(hook)})
            check("table", {jti={"a"}}, {jti=validators.jti_hook(hook)})
            check("opt number", {jti=1}, {jti=validators.opt_jti_hook(hook)})
            check("missing", {sub="x"}, {jti=validators.jti_hook(hook)})
            check("opt missing", {sub="x"}, {jti=validators.opt_jti_hook(hook)})
            ngx.say("calls: ", calls)
            build_error("nil hook", validators.jti_hook, nil)
            build_error("string hook", validators.opt_jti_hook, "fn")
        }
    }
--- request
GET /t
--- response_body
number: false 'jti' is malformed.  Expected to be a string.
table: false 'jti' is malformed.  Expected to be a string.
opt number: false 'jti' is malformed.  Expected to be a string.
missing: false 'jti' claim is required.
opt missing: true everything is awesome~ :p
calls: 0
nil hook: Cannot create validator for nil hook.
string hook: Cannot create validator for non-function hook.
--- no_error_log
[error]


=== TEST 10: jti_hook never runs for a token whose signature does not verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local calls = 0
            local spec = {jti=validators.jti_hook(function() calls = calls + 1 return true end)}
            local token = hs_token({jti="abc"})

            local obj = jwt:verify("secret", tamper(token), spec)
            ngx.say("tampered: ", obj.verified, " calls=", calls)
            obj = jwt:verify("wrong secret", token, spec)
            ngx.say("wrong key: ", obj.verified, " calls=", calls)
            -- an alg the whitelist refuses is never verified either
            jwt:set_alg_whitelist({RS256=1})
            obj = jwt:verify("secret", token, spec)
            jwt:set_alg_whitelist(nil)
            ngx.say("whitelist: ", obj.verified, " calls=", calls)
            -- a loaded but unverified object passed to verify_jwt_obj with a
            -- bad key is never validated
            obj = jwt:load_jwt(token)
            obj = jwt:verify_jwt_obj("wrong secret", obj, spec)
            ngx.say("verify_jwt_obj: ", obj.verified, " calls=", calls)

            obj = jwt:verify("secret", token, spec)
            ngx.say("valid: ", obj.verified, " calls=", calls)
        }
    }
--- request
GET /t
--- response_body
tampered: false calls=0
wrong key: false calls=0
whitelist: false calls=0
verify_jwt_obj: false calls=0
valid: true calls=1
--- no_error_log
[error]


=== TEST 11: jti_hook never runs for a JWE that fails authentication
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local key = string.rep("k", 32)
            local calls = 0
            local spec = {jti=validators.jti_hook(function() calls = calls + 1 return true end)}
            local token = jwt:sign(key, {
                header = {alg="dir", enc="A256GCM"},
                payload = {jti="abc"},
            })
            -- swap the authentication tag for a different, well-formed one
            local prefix, tag = token:match("^(.*%.)([^.]+)$")
            local bad = prefix .. jwt:jwt_encode(string.rep("x", #jwt:jwt_decode(tag)))

            local obj = jwt:verify(key, bad, spec)
            ngx.say("bad tag: ", obj.verified, " calls=", calls)
            obj = jwt:verify(string.rep("z", 32), token, spec)
            ngx.say("wrong key: ", obj.verified, " calls=", calls)
            obj = jwt:verify(key, token, spec)
            ngx.say("valid: ", obj.verified, " calls=", calls)
        }
    }
--- request
GET /t
--- response_body
bad tag: false calls=0
wrong key: false calls=0
valid: true calls=1
--- no_error_log
[error]


=== TEST 12: jti_hook runs after the other claims of the same token pass
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local calls = 0
            local hook = validators.jti_hook(function() calls = calls + 1 return true end)
            -- claim specs run in order and stop at the first failing one, so a
            -- hook in the last spec only sees tokens that passed the others
            local obj = jwt:verify("secret", hs_token({jti="abc", exp=999}),
                {exp=validators.is_not_expired()}, {jti=hook})
            ngx.say("expired: ", obj.verified, " ", obj.reason, " calls=", calls)
            obj = jwt:verify("secret", hs_token({jti="abc", exp=1001}),
                {exp=validators.is_not_expired()}, {jti=hook})
            ngx.say("valid: ", obj.verified, " calls=", calls)
        }
    }
--- request
GET /t
--- response_body
expired: false 'exp' claim expired at Thu, 01 Jan 1970 00:16:39 GMT calls=0
valid: true calls=1
--- no_error_log
[error]


=== TEST 13: required_claims requires every listed claim
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local validators = require "resty.jwt-validators"
            local spec = {__jwt=validators.required_claims({"sub", "iss"})}
            check("all", {sub="x", iss="y", other=1}, spec)
            check("missing iss", {sub="x"}, spec)
            check("missing both", {other=1}, spec)
            check("false is present", {sub=false, iss=0}, spec)
            -- usable on any claim key: it checks the whole payload
            check("other key", {sub="x"}, {sub=validators.required_claims({"sub", "aud"})})
            build_error("nil", validators.required_claims, nil)
            build_error("empty", validators.required_claims, {})
            build_error("non-string", validators.required_claims, {"sub", 1})
            build_error("string", validators.required_claims, "sub")
        }
    }
--- request
GET /t
--- response_body
all: true everything is awesome~ :p
missing iss: false 'iss' claim is required.
missing both: false 'sub' claim is required.
false is present: true everything is awesome~ :p
other key: false 'aud' claim is required.
nil: Cannot create validator for nil claim_keys.
empty: Cannot create validator for empty table claim_keys.
non-string: Cannot create validator for non-string table claim_keys.
string: Cannot create validator for non-table claim_keys.
--- no_error_log
[error]


=== TEST 14: required_claims fails on a non-object payload and works when called directly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local fx = validators.required_claims({"sub"})
            local token = jwt:sign("secret", {header={typ="JWT", alg="HS256"}, payload="just a string"})
            local obj = jwt:verify("secret", token, {__jwt=fx})
            ngx.say("string payload: ", obj.verified, " ", obj.reason)
            -- called directly as a "__jwt" validator, without the payload argument
            ngx.say("direct: ", fx({payload={sub="x"}}, "__jwt"))
            ngx.say("direct missing: ", pcall(fx, {payload={}}, "__jwt"))
        }
    }
--- request
GET /t
--- response_body
string payload: false 'payload' is malformed.  Expected to be a table.
direct: true
direct missing: false'sub' claim is required.
--- no_error_log
[error]


=== TEST 15: verify_with issuer and audience options
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function vw(label, payload, opts)
                opts.algorithms = {"HS256"}
                local obj = jwt:verify_with("secret", hs_token(payload), opts)
                ngx.say(label, ": ", obj.verified, " ", obj.reason)
            end
            vw("iss", {iss="a"}, {issuer="a"})
            vw("iss list", {iss="b"}, {issuer={"a", "b"}})
            vw("iss mismatch", {iss="evil"}, {issuer={"a", "b"}})
            vw("iss missing", {sub="x"}, {issuer="a"})
            vw("aud", {aud="api"}, {audience="api"})
            vw("aud array", {aud={"x", "web"}}, {audience={"api", "web"}})
            vw("aud mismatch", {aud={"x"}}, {audience="api"})
            vw("aud malformed", {aud=7}, {audience="api"})
            vw("aud missing", {sub="x"}, {audience="api"})
            vw("both", {iss="a", aud="api"}, {issuer="a", audience="api"})
        }
    }
--- request
GET /t
--- response_body
iss: true everything is awesome~ :p
iss list: true everything is awesome~ :p
iss mismatch: false Claim 'iss' ('evil') returned failure
iss missing: false 'iss' claim is required.
aud: true everything is awesome~ :p
aud array: true everything is awesome~ :p
aud mismatch: false 'aud' claim does not contain an allowed audience.
aud malformed: false 'aud' is malformed.  Expected to be a string or array of strings.
aud missing: false 'aud' claim is required.
both: true everything is awesome~ :p
--- no_error_log
[error]


=== TEST 16: verify_with max_age, required_claims and typ options
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function vw(label, payload, opts, header)
                opts.algorithms = {"HS256"}
                local obj = jwt:verify_with("secret", hs_token(payload, header), opts)
                ngx.say(label, ": ", obj.verified, " ", obj.reason)
            end
            vw("max_age", {iat=950}, {max_age=60})
            vw("too old", {iat=900}, {max_age=60})
            vw("future", {iat=1001}, {max_age=60})
            vw("iat missing", {sub="x"}, {max_age=60})
            vw("required", {sub="x", iss="y"}, {required_claims={"sub", "iss"}})
            vw("required missing", {sub="x"}, {required_claims={"sub", "iss"}})
            vw("typ", {sub="x"}, {typ="at+jwt"}, {typ="at+jwt", alg="HS256"})
            vw("typ normalized", {sub="x"}, {typ="application/at+jwt"}, {typ="AT+JWT", alg="HS256"})
            vw("typ list", {sub="x"}, {typ={"JWT", "at+jwt"}}, {typ="at+jwt", alg="HS256"})
            vw("typ mismatch", {sub="x"}, {typ="at+jwt"}, {typ="JWT", alg="HS256"})
            vw("typ missing", {sub="x"}, {typ="at+jwt"}, {alg="HS256"})
        }
    }
--- request
GET /t
--- response_body
max_age: true everything is awesome~ :p
too old: false 'iat' claim is older than the maximum age: issued at Thu, 01 Jan 1970 00:15:00 GMT
future: false 'iat' claim is in the future: issued at Thu, 01 Jan 1970 00:16:41 GMT
iat missing: false 'iat' claim is required.
required: true everything is awesome~ :p
required missing: false 'iss' claim is required.
typ: true everything is awesome~ :p
typ normalized: true everything is awesome~ :p
typ list: true everything is awesome~ :p
typ mismatch: false Header 'typ' ('JWT') returned failure
typ missing: false 'typ' header is required.
--- no_error_log
[error]


=== TEST 17: verify_with jti option runs the hook last and only for verified tokens
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local seen = {}
            local opts = {
                algorithms = {"HS256"},
                audience = "api",
                claim_specs = {{exp = validators.is_not_expired()}},
                jti = function(jti, payload)
                    if seen[jti] then return nil, "replayed" end
                    seen[jti] = payload.sub
                    return true
                end,
            }
            local function vw(label, token)
                local obj = jwt:verify_with("secret", token, opts)
                ngx.say(label, ": ", obj.verified, " ", (obj.reason:gsub("mismatch: .*", "mismatch")))
            end
            local good = hs_token({jti="a", sub="alice", aud="api", exp=2000})
            vw("bad signature", tamper(good))
            vw("expired", hs_token({jti="a", sub="alice", aud="api", exp=999}))
            vw("wrong audience", hs_token({jti="a", sub="alice", aud="web", exp=2000}))
            ngx.say("seen before: ", tostring(seen.a))
            vw("first use", good)
            vw("replay", good)
            vw("no jti", hs_token({sub="alice", aud="api", exp=2000}))
            ngx.say("seen after: ", tostring(seen.a))
        }
    }
--- request
GET /t
--- response_body
bad signature: false signature mismatch
expired: false 'exp' claim expired at Thu, 01 Jan 1970 00:16:39 GMT
wrong audience: false 'aud' claim does not contain an allowed audience.
seen before: nil
first use: true everything is awesome~ :p
replay: false 'jti' claim was rejected: replayed
no jti: false 'jti' claim is required.
seen after: alice
--- no_error_log
[error]


=== TEST 18: verify_with claim options keep the default exp/nbf checks
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local function vw(label, payload, opts)
                opts.algorithms = {"HS256"}
                local obj = jwt:verify_with("secret", hs_token(payload), opts)
                ngx.say(label, ": ", obj.verified, " ", obj.reason)
            end
            vw("expired", {aud="api", exp=999}, {audience="api"})
            vw("not yet valid", {aud="api", nbf=1001}, {audience="api"})
            vw("valid", {aud="api", exp=1001, nbf=1000}, {audience="api"})
            -- like verify(), explicit claim specs replace the defaults
            vw("specs replace defaults", {aud="api", exp=999},
                {audience="api", claim_specs={{sub=validators.opt_equals("x")}}})
            vw("specs and options", {aud="web", sub="y"},
                {audience="api", claim_specs={{sub=validators.opt_equals("x")}}})
            vw("legacy spec", {aud="api", exp=995},
                {audience="api", claim_specs={{lifetime_grace_period=10}}})
        }
    }
--- request
GET /t
--- response_body
expired: false 'exp' claim expired at Thu, 01 Jan 1970 00:16:39 GMT
not yet valid: false 'nbf' claim not valid until Thu, 01 Jan 1970 00:16:41 GMT
valid: true everything is awesome~ :p
specs replace defaults: true everything is awesome~ :p
specs and options: false 'aud' claim does not contain an allowed audience.
legacy spec: true everything is awesome~ :p
--- no_error_log
[error]


=== TEST 19: verify_with rejects invalid claim options
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = hs_token({sub="x"})
            local bad = {
                {issuer=1}, {issuer={}}, {issuer={"a", 2}},
                {audience=true}, {audience={}},
                {max_age=-1}, {max_age="60"},
                {required_claims="sub"}, {required_claims={}}, {required_claims={"sub", 1}},
                {typ=5}, {jti="hook"},
            }
            for _, opts in ipairs(bad) do
                opts.algorithms = {"HS256"}
                local ok, err = pcall(jwt.verify_with, jwt, "secret", token, opts)
                ngx.say(ok, " ", err)
            end
        }
    }
--- request
GET /t
--- response_body
false verify_with: options.issuer must be a string or a non-empty list of strings
false verify_with: options.issuer must be a string or a non-empty list of strings
false verify_with: options.issuer must be a string or a non-empty list of strings
false verify_with: options.audience must be a string or a non-empty list of strings
false verify_with: options.audience must be a string or a non-empty list of strings
false verify_with: options.max_age must be a non-negative number of seconds
false verify_with: options.max_age must be a non-negative number of seconds
false verify_with: options.required_claims must be a non-empty list of claim names
false verify_with: options.required_claims must be a non-empty list of claim names
false verify_with: options.required_claims must be a non-empty list of claim names
false verify_with: options.typ must be a string or a non-empty list of strings
false verify_with: options.jti must be a function
--- no_error_log
[error]


=== TEST 20: verify_with checks algorithms before the claim options
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local calls = 0
            local opts = {
                algorithms = {"RS256"},
                audience = "api",
                jti = function() calls = calls + 1 return true end,
            }
            local obj = jwt:verify_with("secret", hs_token({aud="api", jti="a"}), opts)
            ngx.say(obj.verified, " ", obj.reason, " calls=", calls)
            obj = jwt:verify_with("secret", "not a token", opts)
            ngx.say(obj.verified, " ", obj.reason, " calls=", calls)
        }
    }
--- request
GET /t
--- response_body
false whitelist unsupported alg: HS256 calls=0
false invalid jwt string calls=0
--- no_error_log
[error]


=== TEST 21: validate_claims checks claim specs on a verified object
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local obj = jwt:verify("secret", hs_token({sub="alice", aud={"api"}, iat=990}))
            ngx.say("verified: ", obj.verified)
            ngx.say("pass: ", jwt:validate_claims(obj,
                {aud=validators.audience("api")},
                {iat=validators.issued_at({max_age=60})}))
            ngx.say("still verified: ", obj.verified, " ", obj.reason)
            ngx.say("fail: ", jwt:validate_claims(obj,
                {sub=validators.equals("alice")}, {aud=validators.audience("web")}))
            ngx.say("after failure: ", obj.verified, " ", obj.reason)
            -- the object is no longer verified, so it is refused from now on
            ngx.say("again: ", jwt:validate_claims(obj, {sub=validators.equals("alice")}))
        }
    }
--- request
GET /t
--- response_body
verified: true
pass: true
still verified: true everything is awesome~ :p
fail: false'aud' claim does not contain an allowed audience.
after failure: false 'aud' claim does not contain an allowed audience.
again: falseclaims can only be validated on a verified token
--- no_error_log
[error]


=== TEST 22: validate_claims refuses objects that were not verified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local calls = 0
            local spec = {jti=validators.jti_hook(function() calls = calls + 1 return true end)}
            local token = hs_token({jti="a"})

            local loaded = jwt:load_jwt(token)
            ngx.say("loaded: ", jwt:validate_claims(loaded, spec))
            ngx.say("loaded untouched: ", loaded.verified, " ", loaded.valid, " ", tostring(loaded.reason))
            local bad = jwt:verify("secret", tamper(token))
            ngx.say("bad signature: ", jwt:validate_claims(bad, spec))
            local invalid = jwt:verify("secret", "garbage")
            ngx.say("invalid: ", jwt:validate_claims(invalid, spec))
            ngx.say("truthy flag: ", jwt:validate_claims({verified="true", payload={jti="a"}}, spec))
            ngx.say("nil: ", jwt:validate_claims(nil, spec))
            ngx.say("string: ", jwt:validate_claims(token, spec))
            ngx.say("calls: ", calls)
            local obj = jwt:verify("secret", token)
            ngx.say("verified: ", jwt:validate_claims(obj, spec), " calls=", calls)
        }
    }
--- request
GET /t
--- response_body
loaded: falseclaims can only be validated on a verified token
loaded untouched: false true nil
bad signature: falseclaims can only be validated on a verified token
invalid: falseclaims can only be validated on a verified token
truthy flag: falseclaims can only be validated on a verified token
nil: falseclaims can only be validated on a verified token
string: falseclaims can only be validated on a verified token
calls: 0
verified: true calls=1
--- no_error_log
[error]


=== TEST 23: validate_claims applies the default checks and rejects malformed specs
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            -- verified with a spec that skips the default exp check
            local obj = jwt:verify("secret", hs_token({sub="x", exp=999}), {sub=validators.equals("x")})
            ngx.say("verified: ", obj.verified)
            ngx.say("defaults: ", jwt:validate_claims(obj))

            obj = jwt:verify("secret", hs_token({sub="x", exp=999}), {sub=validators.equals("x")})
            ngx.say("legacy: ", jwt:validate_claims(obj, {lifetime_grace_period=5}))
            ngx.say("malformed: ", pcall(jwt.validate_claims, jwt, obj, {sub="x"}))
            ngx.say("unchanged: ", obj.verified)
        }
    }
--- request
GET /t
--- response_body
verified: true
defaults: false'exp' claim expired at Thu, 01 Jan 1970 00:16:39 GMT
legacy: true
malformed: falseClaim spec value must be a function - see jwt-validators.lua for helper functions
unchanged: true
--- no_error_log
[error]


=== TEST 24: validate_claims works on a verified JWE
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local key = string.rep("k", 32)
            local token = jwt:sign(key, {
                header = {alg="dir", enc="A256GCM"},
                payload = {sub="alice", aud="api"},
            })
            local obj = jwt:verify(key, token)
            ngx.say("verified: ", obj.verified)
            ngx.say("aud: ", jwt:validate_claims(obj, {aud=validators.audience("api")}))
            ngx.say("required: ", jwt:validate_claims(obj, {__jwt=validators.required_claims({"sub", "iss"})}))
        }
    }
--- request
GET /t
--- response_body
verified: true
aud: true
required: false'iss' claim is required.
--- no_error_log
[error]
