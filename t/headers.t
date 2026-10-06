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
