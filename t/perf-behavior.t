BEGIN { use Cwd; $ENV{TEST_NGINX_SERVROOT} = Cwd::cwd() . "/t/servroot_$$"; $ENV{TEST_NGINX_SERVER_PORT} = 10000 + ($$ % 50000) }
use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (3 * blocks());

my $coverage = $ENV{COVERAGE} ? "require('luacov')" : "";

# Performance changes must not change behavior. The legacy_* helpers are the
# gsub based base64url implementation jwt_encode/jwt_decode used to have.
our $HttpConfig = <<"_EOC_";
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        $coverage
        require "resty.jwt"

        function legacy_encode(s)
            return (ngx.encode_base64(s):gsub("%+", "-"):gsub("/", "_"):gsub("=", ""))
        end

        function legacy_decode(s)
            s = s:gsub("%-", "+"):gsub("_", "/")
            local rem = #s % 4
            if rem > 0 then
                s = s .. string.rep("=", 4 - rem)
            end
            return ngx.decode_base64(s)
        end

        -- byte strings of every length up to 70, plus every byte value
        function binary_corpus()
            math.randomseed(1234)
            local corpus = {}
            for len = 0, 70 do
                local t = {}
                for i = 1, len do t[i] = string.char(math.random(0, 255)) end
                corpus[#corpus + 1] = table.concat(t)
            end
            local all = {}
            for b = 0, 255 do all[#all + 1] = string.char(b) end
            corpus[#corpus + 1] = table.concat(all)
            return corpus
        end

        -- strings over the base64 and base64url alphabets plus padding,
        -- valid or not
        function text_corpus()
            math.randomseed(5678)
            local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_="
            local corpus = { "", "YQ", "YQ==", "YWI=", "YWI", "+/+/", "-_-_", "a", "ab=c", "@@@@", "YQ=", "Y Q" }
            for _ = 1, 500 do
                local t = {}
                for i = 1, math.random(1, 24) do
                    local n = math.random(1, #alphabet)
                    t[i] = alphabet:sub(n, n)
                end
                corpus[#corpus + 1] = table.concat(t)
            end
            return corpus
        end

        -- loads a fresh copy of resty.jwt for which ngx.base64 is unavailable
        function load_jwt_without_ngx_base64()
            local saved = package.loaded["ngx.base64"]
            local saved_jwt = package.loaded["resty.jwt"]
            package.loaded["ngx.base64"] = nil
            package.preload["ngx.base64"] = function() error("ngx.base64 unavailable") end
            package.loaded["resty.jwt"] = nil
            local jwt = require "resty.jwt"
            package.preload["ngx.base64"] = nil
            package.loaded["ngx.base64"] = saved
            package.loaded["resty.jwt"] = saved_jwt
            return jwt
        end

        -- whether jwt_encode uses ngx.base64 (an upvalue of the function)
        function uses_ngx_base64(jwt)
            local i = 1
            while true do
                local name, value = debug.getupvalue(jwt.jwt_encode, i)
                if name == nil then return false end
                if name == "encode_base64url" then return value ~= nil end
                i = i + 1
            end
        end
    }
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: jwt_encode output is unchanged and round-trips through jwt_decode
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            ngx.say("ngx.base64: ", uses_ngx_base64(jwt))
            local mismatches, roundtrip = 0, 0
            local corpus = binary_corpus()
            for _, s in ipairs(corpus) do
                local encoded = jwt:jwt_encode(s)
                if encoded ~= legacy_encode(s) then mismatches = mismatches + 1 end
                if jwt:jwt_decode(encoded) ~= s then roundtrip = roundtrip + 1 end
            end
            ngx.say(#corpus, " strings, ", mismatches, " encode mismatches, ", roundtrip, " round-trip failures")
            -- tables are still JSON encoded first
            ngx.say(jwt:jwt_encode({a="b"}), " ", jwt:jwt_decode(jwt:jwt_encode({a="b"}), true).a)
            -- non-string, non-table values keep their old behavior
            ngx.say("number: ", jwt:jwt_encode(12), " ", legacy_encode("12"))
        }
    }
--- request
GET /t
--- response_body
ngx.base64: true
72 strings, 0 encode mismatches, 0 round-trip failures
eyJhIjoiYiJ9 b
number: MTI MTI
--- no_error_log
[error]


=== TEST 2: jwt_decode accepts and rejects exactly what it used to
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local mismatches, accepted, rejected = 0, 0, 0
            local corpus = text_corpus()
            for _, s in ipairs(corpus) do
                local got, want = jwt:jwt_decode(s), legacy_decode(s)
                if got ~= want then
                    mismatches = mismatches + 1
                    ngx.say("mismatch for ", s)
                end
                if want then accepted = accepted + 1 else rejected = rejected + 1 end
            end
            ngx.say(#corpus, " strings, ", mismatches, " mismatches")
            ngx.say("both accepted and rejected inputs: ", accepted > 50 and rejected > 50)
            -- padding and the standard alphabet still decode (lenient helper)
            ngx.say(jwt:jwt_decode("YQ=="), jwt:jwt_decode("YWI="), " ", jwt:jwt_decode("-_-_") == jwt:jwt_decode("+/+/"))
            ngx.say(tostring(jwt:jwt_decode("a")), " ", tostring(jwt:jwt_decode("@@@@")))
            ngx.say(jwt:jwt_decode(jwt:jwt_encode('{"x":1}'), true).x)
        }
    }
--- request
GET /t
--- response_body
512 strings, 0 mismatches
both accepted and rejected inputs: true
aab true
nil nil
1
--- no_error_log
[error]


=== TEST 3: without ngx.base64, jwt_encode/jwt_decode fall back to the same results
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local fast = require "resty.jwt"
            local slow = load_jwt_without_ngx_base64()
            ngx.say("fast uses ngx.base64: ", uses_ngx_base64(fast))
            ngx.say("fallback uses ngx.base64: ", uses_ngx_base64(slow))
            local mismatches = 0
            for _, s in ipairs(binary_corpus()) do
                if slow:jwt_encode(s) ~= fast:jwt_encode(s) then mismatches = mismatches + 1 end
            end
            for _, s in ipairs(text_corpus()) do
                if slow:jwt_decode(s) ~= fast:jwt_decode(s) then mismatches = mismatches + 1 end
            end
            ngx.say("mismatches: ", mismatches)

            local token = fast:sign("secret", {header={typ="JWT", alg="HS256"}, payload={foo="bar"}})
            ngx.say("same token: ", slow:sign("secret", {header={typ="JWT", alg="HS256"}, payload={foo="bar"}}) == token)
            local obj = slow:verify("secret", token)
            ngx.say("fallback verifies: ", obj.verified, " ", obj.payload.foo)
        }
    }
--- request
GET /t
--- response_body
fast uses ngx.base64: true
fallback uses ngx.base64: false
mismatches: 0
same token: true
fallback verifies: true bar
--- no_error_log
[error]


=== TEST 4: token parsing still requires canonical base64url, with or without ngx.base64
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local fast = require "resty.jwt"
            local slow = load_jwt_without_ngx_base64()
            local token = fast:sign("secret", {header={typ="JWT", alg="HS256"}, payload={foo="bar"}})
            local h, p, s = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
            -- the HS256 signature is 32 bytes: 43 characters with 2 spare bits
            -- (the last character of a canonical one encodes 4 data bits)
            local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            local idx = alphabet:find(s:sub(-1), 1, true)
            local trailing = s:sub(1, -2) .. alphabet:sub(idx + 1, idx + 1)
            local variants = {
                {"canonical", token},
                {"padded payload", h .. "." .. p .. "=." .. s},
                {"standard alphabet", h .. "." .. p .. ".+" .. s:sub(2)},
                {"trailing bits", h .. "." .. p .. "." .. trailing},
            }
            for _, impl in ipairs({{"fast", fast}, {"fallback", slow}}) do
                for _, v in ipairs(variants) do
                    local obj = impl[2]:verify("secret", v[2])
                    ngx.say(impl[1], " ", v[1], ": ", obj.verified, " ", obj.reason)
                end
            end
        }
    }
--- request
GET /t
--- response_body
fast canonical: true everything is awesome~ :p
fast padded payload: false invalid jwt string: non-canonical base64url in payload
fast standard alphabet: false invalid jwt string: non-canonical base64url in signature
fast trailing bits: false invalid jwt string: non-canonical base64url in signature
fallback canonical: true everything is awesome~ :p
fallback padded payload: false invalid jwt string: non-canonical base64url in payload
fallback standard alphabet: false invalid jwt string: non-canonical base64url in signature
fallback trailing bits: false invalid jwt string: non-canonical base64url in signature
--- no_error_log
[error]


=== TEST 5: validators that can read jwt_json still get a decodable copy of the object
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local cjson = require "cjson"
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local token = jwt:sign("secret", {header={typ="JWT", alg="HS256"}, payload={sub="alice", n=1}})
            local function show(label)
                return function(val, claim, jwt_json)
                    local obj = cjson.decode(jwt_json)
                    ngx.say(label, ": ", claim, "=", tostring(val), " ", obj.payload.sub, " ", obj.header.alg, " ", obj.verified)
                    return true
                end
            end
            local obj = jwt:verify("secret", token,
                {sub=show("three params")},
                {sub=function(val, claim, jwt_json, payload)
                    ngx.say("four params: ", type(jwt_json), " ", payload.n)
                end},
                {sub=function(...)
                    ngx.say("varargs: ", type(select(3, ...)), " ", select("#", ...))
                end},
                {sub=validators.chain(validators.required(), show("chained"))},
                {__header={alg=show("header")}},
                {__jwt=function(val, claim, jwt_json)
                    val.payload.sub = "mallory"
                    ngx.say("__jwt: ", type(jwt_json), " ", cjson.decode(jwt_json).payload.sub)
                end},
                {sub=function(val) ngx.say("one param: ", val) end})
            ngx.say(obj.verified, " ", obj.payload.sub)
        }
    }
--- request
GET /t
--- response_body
three params: sub=alice alice HS256 true
four params: string 1
varargs: string 4
chained: sub=alice alice HS256 true
header: alg=HS256 alice HS256 true
__jwt: string alice
one param: alice
true alice
--- no_error_log
[error]


=== TEST 6: the jwt object is JSON encoded at most once, and only when a validator can read it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            -- a fresh resty.jwt whose cjson.safe counts encodes of jwt objects
            local real = require "cjson.safe"
            local encodes = 0
            local counting = setmetatable({
                encode = function(v)
                    if type(v) == "table" and v.verified ~= nil then encodes = encodes + 1 end
                    return real.encode(v)
                end,
            }, {__index = real})
            local saved_cjson, saved_jwt = package.loaded["cjson.safe"], package.loaded["resty.jwt"]
            package.loaded["cjson.safe"] = counting
            package.loaded["resty.jwt"] = nil
            local jwt = require "resty.jwt"
            package.loaded["cjson.safe"] = saved_cjson
            package.loaded["resty.jwt"] = saved_jwt

            local validators = require "resty.jwt-validators"
            local token = jwt:sign("secret", {header={typ="JWT", alg="HS256"},
                payload={sub="alice", iss="me", aud="api", iat=ngx.time(), exp=ngx.time() + 60}})
            local function count(label, ...)
                encodes = 0
                local obj = jwt:verify("secret", token, ...)
                ngx.say(label, ": ", obj.verified, " encodes=", encodes)
            end
            count("defaults")
            count("builtin validators", {
                sub=validators.required(),
                iss=validators.equals_any_of({"me", "you"}),
                aud=validators.audience("api"),
                iat=validators.issued_at({max_age=60}),
                exp=validators.is_not_expired(),
                __header={typ=validators.typ_is("JWT")},
            }, {__jwt=validators.required_claims({"sub"})})
            count("legacy options", {lifetime_grace_period=5, valid_issuers={"me"}})
            count("short custom functions", {sub=function(val) return val == "alice" end,
                iss=function(val, claim) return true end})
            count("custom jwt_json reader", {sub=function(val, claim, jwt_json) return true end})
            count("two readers", {sub=function(val, claim, jwt_json) return true end},
                {iss=function(val, claim, jwt_json) return true end})
            count("varargs", {sub=function(...) return true end})
            count("chain with custom", {sub=validators.chain(validators.required(),
                function(val, claim, jwt_json) return true end)})
            count("payload-only __jwt", {__jwt=validators.require_one_of({"sub"})})
            count("__jwt copy", {__jwt=function(val) return val.payload.sub == "alice" end})
            encodes = 0
            local obj = jwt:verify("secret", token, {sub=validators.required()})
            jwt:validate_claims(obj, {aud=validators.audience("api")})
            ngx.say("validate_claims: encodes=", encodes)
        }
    }
--- request
GET /t
--- response_body
defaults: true encodes=0
builtin validators: true encodes=0
legacy options: true encodes=0
short custom functions: true encodes=0
custom jwt_json reader: true encodes=1
two readers: true encodes=1
varargs: true encodes=1
chain with custom: true encodes=1
payload-only __jwt: true encodes=0
__jwt copy: true encodes=1
validate_claims: encodes=0
--- no_error_log
[error]


=== TEST 7: needs_jwt_json/needs_jwt_copy are false only where the argument is never read
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local v = require "resty.jwt-validators"
            local custom = function(val, claim, jwt_json) return true end
            local cases = {
                {"required", v.required()},
                {"required(builtin)", v.required(v.equals("x"))},
                {"opt_equals", v.opt_equals("x")},
                {"matches_any_of", v.matches_any_of({"^a"})},
                {"contains_any_of", v.contains_any_of({"a"})},
                {"greater_than", v.greater_than(1)},
                {"check", v.check(1, function(a, b) return a == b end)},
                {"is_not_expired", v.is_not_expired({leeway=1})},
                {"opt_is_at", v.opt_is_at()},
                {"require_one_of", v.require_one_of({"a"})},
                {"typ_is", v.typ_is("JWT")},
                {"opt_typ_is", v.opt_typ_is("JWT")},
                {"audience", v.audience("a")},
                {"issued_at", v.opt_issued_at()},
                {"jti_hook", v.jti_hook(function() return true end)},
                {"required_claims", v.required_claims({"a"})},
                {"chain of builtins", v.chain(v.required(), v.equals("x"))},
                {"chain with custom", v.chain(v.required(), custom)},
                {"required(custom)", v.required(custom)},
                {"custom", custom},
                {"one param", function(val) end},
                {"two params", function(val, claim) end},
                {"varargs", function(val, ...) end},
                {"C function", print},
            }
            for _, c in ipairs(cases) do
                ngx.say(c[1], ": ", v.needs_jwt_json(c[2]))
            end
            -- only these two "__jwt" validators can do without the object copy
            ngx.say("copy: ", v.needs_jwt_copy(v.require_one_of({"a"})), " ",
                v.needs_jwt_copy(v.required_claims({"a"})), " ",
                v.needs_jwt_copy(v.required()), " ", v.needs_jwt_copy(custom))
        }
    }
--- request
GET /t
--- response_body
required: false
required(builtin): false
opt_equals: false
matches_any_of: false
contains_any_of: false
greater_than: false
check: false
is_not_expired: false
opt_is_at: false
require_one_of: false
typ_is: false
opt_typ_is: false
audience: false
issued_at: false
jti_hook: false
required_claims: false
chain of builtins: false
chain with custom: true
required(custom): true
custom: true
one param: false
two params: false
varargs: true
C function: true
copy: false false true true
--- no_error_log
[error]
