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
