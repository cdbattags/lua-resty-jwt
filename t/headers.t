BEGIN { use Cwd; $ENV{TEST_NGINX_SERVROOT} = Cwd::cwd() . "/t/servroot_$$"; $ENV{TEST_NGINX_SERVER_PORT} = 10000 + ($$ % 50000) }
use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (3 * blocks());

my $coverage = $ENV{COVERAGE} ? "require('luacov')" : "";

# Shared helpers (globals): read test certs, hand-craft tokens with arbitrary
# headers and split/join compact serializations keeping empty parts.
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
        function hs_token(secret, header, payload)
            local h = jwt:jwt_encode(type(header) == "string" and header or cjson.encode(header))
            local p = jwt:jwt_encode(type(payload) == "string" and payload or cjson.encode(payload or {foo="bar"}))
            local mac = hmac:new(secret, hmac.ALGOS.SHA256):final(h .. "." .. p)
            return h .. "." .. p .. "." .. jwt:jwt_encode(mac)
        end

        function split(token)
            local parts = {}
            for part in (token .. "."):gmatch("([^.]*)%.") do
                parts[#parts + 1] = part
            end
            return parts
        end

        function join(parts)
            return table.concat(parts, ".")
        end

        DIR_KEY = "12341234123412341234123412341234"

        function dir_token(header)
            header.alg = header.alg or "dir"
            header.enc = header.enc or "A128CBC-HS256"
            return jwt:sign(DIR_KEY, { header = header, payload = { foo = "bar" } })
        end
    }
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: sign typ whitelist is case-insensitive and ignores an "application/" prefix
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            for _, typ in ipairs({ "jwt", "AT+JWT", "application/at+jwt", "Application/DPoP+JWT",
                                   "application/foo/at+jwt", "text/at+jwt", "at+jwt+x" }) do
                local ok, err = pcall(jwt.sign, jwt, "secret",
                    { header = { typ = typ, alg = "HS256" }, payload = { foo = "bar" } })
                ngx.say(typ, ": ", ok and "signed" or err.reason)
            end
        }
    }
--- request
GET /t
--- response_body
jwt: signed
AT+JWT: signed
application/at+jwt: signed
Application/DPoP+JWT: signed
application/foo/at+jwt: invalid typ: application/foo/at+jwt
text/at+jwt: invalid typ: text/at+jwt
at+jwt+x: invalid typ: at+jwt+x
--- no_error_log
[error]



=== TEST 2: set_typ_whitelist normalizes its entries and accepts list form
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            jwt:set_typ_whitelist({ "Application/My+JWT", ["other+jwt"] = 1, ["off+jwt"] = false })
            for _, typ in ipairs({ "my+jwt", "application/MY+jwt", "other+jwt", "off+jwt", "JWT" }) do
                local ok, err = pcall(jwt.sign, jwt, "secret",
                    { header = { typ = typ, alg = "HS256" }, payload = { foo = "bar" } })
                ngx.say(typ, ": ", ok and "signed" or err.reason)
            end
        }
    }
--- request
GET /t
--- response_body
my+jwt: signed
application/MY+jwt: signed
other+jwt: signed
off+jwt: invalid typ: off+jwt
JWT: invalid typ: JWT
--- no_error_log
[error]



=== TEST 3: set_typ_whitelist copies its table; the default whitelist is not a shared module table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local function try(obj, typ)
                local ok, err = pcall(obj.sign, obj, "secret",
                    { header = { typ = typ, alg = "HS256" }, payload = { foo = "bar" } })
                return ok and "signed" or err.reason
            end

            ngx.say("module default exposed: ", tostring(jwt.typ_whitelist))

            local mine = { ["a+jwt"] = 1 }
            jwt:set_typ_whitelist(mine)
            mine["b+jwt"] = 1
            ngx.say("b+jwt after caller mutation: ", try(jwt, "b+jwt"))

            -- an instance's whitelist doesn't leak into the module and vice versa
            local inst = jwt.new()
            ngx.say("instance inherits module: ", try(inst, "a+jwt"))
            inst:set_typ_whitelist(nil)
            ngx.say("instance disabled: ", try(inst, "anything"))
            ngx.say("module still enforced: ", try(jwt, "anything"))

            local fresh = jwt.new()
            jwt.typ_whitelist = nil
            ngx.say("fresh instance back on defaults: ", try(fresh, "dpop+jwt"), " / ", try(fresh, "anything"))
        }
    }
--- request
GET /t
--- response_body
module default exposed: nil
b+jwt after caller mutation: invalid typ: b+jwt
instance inherits module: signed
instance disabled: signed
module still enforced: invalid typ: anything
fresh instance back on defaults: signed / invalid typ: anything
--- no_error_log
[error]



=== TEST 4: a non-string typ gives a clean reason; bad set_typ_whitelist input errors
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            for _, typ in ipairs({ 123, true, { "JWT" } }) do
                local ok, err = pcall(jwt.sign, jwt, "secret",
                    { header = { typ = typ, alg = "HS256" }, payload = { foo = "bar" } })
                ngx.say(type(typ), ": ", ok and "signed" or err.reason)
            end
            for _, bad in ipairs({ "JWT", { 1 }, { [{}] = 1 } }) do
                local ok, err = pcall(jwt.set_typ_whitelist, jwt, bad)
                ngx.say(ok and "accepted" or err)
            end
        }
    }
--- request
GET /t
--- response_body
number: invalid typ: must be a string
boolean: invalid typ: must be a string
table: invalid typ: must be a string
'typs' is expected to be a table of typ values, or nil
'typs' is expected to be a table of typ values, or nil
'typs' is expected to be a table of typ values, or nil
--- no_error_log
[error]



=== TEST 5: the typ whitelist is sign-side only: HS256, RS256 and ES256 verify ignore it
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            jwt:set_typ_whitelist(nil)
            local cases = {
                { "HS256", "secret", "secret" },
                { "RS256", read_file("cert-key.pem"), read_file("cert-pubkey.pem") },
                { "ES256", read_file("ec_cert-key.pem"), read_file("ec_cert_pubkey.pem") },
            }
            local tokens = {}
            for i, c in ipairs(cases) do
                tokens[i] = jwt:sign(c[2], { header = { typ = "custom", alg = c[1] }, payload = { foo = "bar" } })
            end
            -- now reject every typ on sign
            jwt:set_typ_whitelist({})
            for i, c in ipairs(cases) do
                local obj = jwt:verify(c[3], tokens[i])
                ngx.say(c[1], ": ", obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
HS256: true everything is awesome~ :p
RS256: true everything is awesome~ :p
ES256: true everything is awesome~ :p
--- no_error_log
[error]



=== TEST 6: crit must be a non-empty array of distinct strings
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            jwt:set_crit_whitelist({ "ext" })
            for _, crit in ipairs({ '"ext"', '[]', '{"ext":1}', '[1]', 'null', '["ext",2]',
                                    '["ext","ext"]', 'true' }) do
                local token = hs_token("secret", '{"alg":"HS256","ext":1,"crit":' .. crit .. '}')
                local obj = jwt:verify("secret", token)
                ngx.say(crit, ": ", obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
"ext": false invalid crit header: must be a non-empty array of strings
[]: false invalid crit header: must be a non-empty array of strings
{"ext":1}: false invalid crit header: must be a non-empty array of strings
[1]: false invalid crit header: must be a non-empty array of strings
null: false invalid crit header: must be a non-empty array of strings
["ext",2]: false invalid crit header: must be a non-empty array of strings
["ext","ext"]: false invalid crit header: duplicate name ext
true: false invalid crit header: must be a non-empty array of strings
--- no_error_log
[error]



=== TEST 7: crit must not list registered header parameters or absent ones
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local cases = {
                '{"alg":"HS256","crit":["alg"]}',
                '{"alg":"HS256","kid":"k","crit":["kid"]}',
                '{"alg":"HS256","typ":"JWT","crit":["typ"]}',
                '{"alg":"HS256","crit":["crit"]}',
                '{"alg":"HS256","x5t#S256":"x","crit":["x5t#S256"]}',
                '{"alg":"HS256","crit":["ext"]}',
            }
            jwt:set_crit_whitelist({ "ext" })
            for _, header in ipairs(cases) do
                local obj = jwt:verify("secret", hs_token("secret", header))
                ngx.say(obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
false invalid crit header: lists registered header parameter alg
false invalid crit header: lists registered header parameter kid
false invalid crit header: lists registered header parameter typ
false invalid crit header: lists registered header parameter crit
false invalid crit header: lists registered header parameter x5t#S256
false invalid crit header: lists absent header parameter ext
--- no_error_log
[error]



=== TEST 8: JWS crit fails closed until the extension is declared understood
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = hs_token("secret", '{"alg":"HS256","ext":1,"crit":["ext"]}')

            local obj = jwt:verify("secret", token)
            ngx.say("default: ", obj.verified, " ", obj.reason)
            obj = jwt:load_jwt(token)
            ngx.say("load_jwt: ", obj.valid, " ", obj.reason)

            local inst = jwt.new()
            inst:set_crit_whitelist({ ext = true })
            obj = inst:verify("secret", token)
            ngx.say("instance: ", obj.verified, " ", obj.reason)
            obj = jwt:verify("secret", token)
            ngx.say("module unaffected: ", obj.verified, " ", obj.reason)

            -- an object loaded by an instance that understands "ext" is still
            -- rejected when verified by one that doesn't
            obj = inst:load_jwt(token)
            obj = jwt:verify_jwt_obj("secret", obj)
            ngx.say("verify_jwt_obj: ", obj.verified, " ", obj.reason)

            -- every listed name must be understood
            local token2 = hs_token("secret", '{"alg":"HS256","ext":1,"other":2,"crit":["ext","other"]}')
            obj = inst:verify("secret", token2)
            ngx.say("partly understood: ", obj.verified, " ", obj.reason)

            inst:set_crit_whitelist(nil)
            obj = inst:verify("secret", token)
            ngx.say("reset: ", obj.verified, " ", obj.reason)

            -- tokens without crit are unaffected
            obj = jwt:verify("secret", hs_token("secret", '{"alg":"HS256","ext":1}'))
            ngx.say("no crit: ", obj.verified)
        }
    }
--- request
GET /t
--- response_body
default: false unsupported critical header parameter: ext
load_jwt: false unsupported critical header parameter: ext
instance: true everything is awesome~ :p
module unaffected: false unsupported critical header parameter: ext
verify_jwt_obj: false unsupported critical header parameter: ext
partly understood: false unsupported critical header parameter: other
reset: false unsupported critical header parameter: ext
no crit: true
--- no_error_log
[error]



=== TEST 9: JWE crit fails closed and is checked before any decryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local token = dir_token({ ext = "v", crit = { "ext" } })

            local obj = jwt:verify(DIR_KEY, token)
            ngx.say("default: ", obj.verified, " ", obj.reason)
            -- the wrong key would fail decryption: crit is rejected first
            obj = jwt:verify(string.rep("x", 32), token)
            ngx.say("wrong key: ", obj.verified, " ", obj.reason)

            jwt:set_crit_whitelist({ "ext" })
            obj = jwt:verify(DIR_KEY, token)
            ngx.say("declared: ", obj.verified, " ", obj.reason, " ", obj.payload.foo)

            obj = jwt:verify(DIR_KEY, dir_token({ crit = { "ext" } }))
            ngx.say("absent: ", obj.verified, " ", obj.reason)
            obj = jwt:verify(DIR_KEY, dir_token({ crit = { "enc" } }))
            ngx.say("registered: ", obj.verified, " ", obj.reason)
            obj = jwt:verify(DIR_KEY, dir_token({ crit = "ext", ext = 1 }))
            ngx.say("malformed: ", obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
default: false unsupported critical header parameter: ext
wrong key: false unsupported critical header parameter: ext
declared: true everything is awesome~ :p bar
absent: false invalid crit header: lists absent header parameter ext
registered: false invalid crit header: lists registered header parameter enc
malformed: false invalid crit header: must be a non-empty array of strings
--- no_error_log
[error]



=== TEST 10: set_crit_whitelist rejects registered names, b64 and non-strings
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            for _, bad in ipairs({ "ext", { "alg" }, { enc = true }, { "b64" }, { 1 }, { "" } }) do
                local ok, err = pcall(jwt.set_crit_whitelist, jwt, bad)
                ngx.say(ok and "accepted" or err)
            end
            local ok = pcall(jwt.set_crit_whitelist, jwt, { "ext", other = true, off = false })
            ngx.say(ok and "accepted" or "rejected")
        }
    }
--- request
GET /t
--- response_body
'extensions' is expected to be a table of header parameter names, or nil
'alg' can't be declared as an understood crit extension
'enc' can't be declared as an understood crit extension
'b64' can't be declared as an understood crit extension
'extensions' is expected to be a table of header parameter names, or nil
'extensions' is expected to be a table of header parameter names, or nil
accepted
--- no_error_log
[error]



=== TEST 11: __header validators with typ_is (same normalization as sign)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local function check(typ_header, spec)
                local header = { alg = "HS256", typ = typ_header }
                local obj = jwt:verify("secret", hs_token("secret", header), spec)
                return tostring(obj.verified) .. " " .. obj.reason
            end
            local at = { __header = { typ = validators.typ_is("at+jwt") } }
            ngx.say("at+jwt: ", check("at+jwt", at))
            ngx.say("application/AT+JWT: ", check("application/AT+JWT", at))
            ngx.say("JWT: ", check("JWT", at))
            ngx.say("missing: ", check(nil, at))
            ngx.say("number: ", check(123, at))
            ngx.say("spec prefix: ", check("at+jwt", { __header = { typ = validators.typ_is("Application/At+Jwt") } }))
            local any = { __header = { typ = validators.typ_is({ "JWT", "dpop+jwt" }) } }
            ngx.say("list: ", check("jwt", any), " / ", check("at+jwt", any))
            local opt = { __header = { typ = validators.opt_typ_is("at+jwt") } }
            ngx.say("opt missing: ", check(nil, opt), " / opt wrong: ", check("JWT", opt))
            for _, bad in ipairs({ {}, 1, { 1 } }) do
                local ok, err = pcall(validators.typ_is, bad)
                ngx.say(ok and "accepted" or err)
            end
        }
    }
--- request
GET /t
--- response_body
at+jwt: true everything is awesome~ :p
application/AT+JWT: true everything is awesome~ :p
JWT: false Header 'typ' ('JWT') returned failure
missing: false 'typ' header is required.
number: false 'typ' is malformed.  Expected to be a string.
spec prefix: true everything is awesome~ :p
list: true everything is awesome~ :p / false Header 'typ' ('at+jwt') returned failure
opt missing: true everything is awesome~ :p / opt wrong: false Header 'typ' ('JWT') returned failure
Cannot create validator for non-string table expected.
Cannot create validator for non-string or table expected.
Cannot create validator for non-string table expected.
--- no_error_log
[error]



=== TEST 12: __header validators combine with claim validators; malformed __header specs raise
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local token = hs_token("secret", { alg = "HS256", kid = "k1" }, { iss = "me" })
            local spec = { iss = validators.equals("me"), __header = { kid = validators.equals("k1") } }
            local obj = jwt:verify("secret", token, spec)
            ngx.say("both pass: ", obj.verified, " ", obj.reason)

            obj = jwt:verify("secret", token, { __header = { kid = validators.equals("k2") } })
            ngx.say("kid mismatch: ", obj.verified, " ", obj.reason)
            obj = jwt:verify("secret", token, { __header = { kid = function() error({ reason = "custom" }) end } })
            ngx.say("raising: ", obj.verified, " ", obj.reason)
            obj = jwt:verify("secret", token, { __header = { kid = function() error(nil) end } })
            ngx.say("raising nil: ", obj.verified, " ", obj.reason)

            -- header values aren't looked up in the payload and vice versa
            obj = jwt:verify("secret", token, { kid = validators.required() })
            ngx.say("payload kid: ", obj.verified, " ", obj.reason)

            for _, bad in ipairs({ { __header = "x" }, { __header = { kid = "x" } }, { __header = { "x" } } }) do
                local ok, err = pcall(jwt.verify, jwt, "secret", token, bad)
                ngx.say(ok and "accepted" or err)
            end
        }
    }
--- request
GET /t
--- response_body
both pass: true everything is awesome~ :p
kid mismatch: false Header 'kid' ('k1') returned failure
raising: false custom
raising nil: false Header 'kid' validation failed
payload kid: false 'kid' claim is required.
Claim spec '__header' must be a table mapping header names to validator functions
Header spec value must be a function - see jwt-validators.lua for helper functions
Header spec value must be a function - see jwt-validators.lua for helper functions
--- no_error_log
[error]



=== TEST 13: __header validators run only after the signature is verified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local called = 0
            local spec = { __header = { typ = function() called = called + 1; return false end } }
            local token = hs_token("other-secret", { alg = "HS256", typ = "JWT" })
            local obj = jwt:verify("secret", token, spec)
            ngx.say(obj.verified, " ", obj.reason:match("^signature mismatch") or obj.reason, " called=", called)
            obj = jwt:verify("other-secret", token, spec)
            ngx.say(obj.verified, " ", obj.reason, " called=", called)
        }
    }
--- request
GET /t
--- response_body
false signature mismatch called=0
false Header 'typ' ('JWT') returned failure called=1
--- no_error_log
[error]



=== TEST 14: __header validators on a JWE see the protected header
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local token = dir_token({ kid = "k1" })
            local obj = jwt:verify(DIR_KEY, token, { __header = { kid = validators.equals("k1"), enc = validators.equals("A128CBC-HS256") } })
            ngx.say(obj.verified, " ", obj.reason)
            obj = jwt:verify(DIR_KEY, token, { __header = { kid = validators.equals("k2") } })
            ngx.say(obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p
false Header 'kid' ('k1') returned failure
--- no_error_log
[error]
