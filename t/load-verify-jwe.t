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

=== TEST 1: Verify A256CBC-HS512 Direct Encryption with a Shared Symmetric Key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234" ..
                               "12341234123412341234123412341234"

            local jwt_obj = jwt:verify(
              shared_key,
              "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0." ..
              ".M927Z_hNTmumFQE0rtRQCQ.nnd7AoE_2dgvws2-iay8qA.d" ..
              "kyZuuks4Qm9Cd7VfEVSs07pi_Kyt0INVHTTesUC2BM"
            )

            ngx.say(
                "alg: ", jwt_obj.header.alg, "\\n",
                "enc: ", jwt_obj.header.enc, "\\n",
                "payload: ", cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
alg: dir
enc: A256CBC-HS512
payload: {"foo":"bar"}
valid: true
verified: true
--- no_error_log
[error]



=== TEST 2: Verify A128CBC-HS256 Direct Encryption with a Shared Symmetric Key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"

            local jwt_obj = jwt:verify(
                shared_key,
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." ..
                ".U6emIwy_yVkagUwQ4EjdFA.FrapgQVvG3uictQz9NPPMw.n" ..
                "MoW0ShdgCN0JHw472SJjQ"
            )

            ngx.say(
                "alg: ", jwt_obj.header.alg, "\\n",
                "enc: ", jwt_obj.header.enc, "\\n",
                "payload: ", cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
alg: dir
enc: A128CBC-HS256
payload: {"foo":"bar"}
valid: true
verified: true
--- no_error_log
[error]



=== TEST 3: Dont fail if extra chars added
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"

            local jwt_obj = jwt:verify(
                shared_key,
                "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." ..
                ".U6emIwy_yVkagUwQ4EjdFA.FrapgQVvG3uictQz9NPPMw.n" ..
                "MoW0ShdgCN0JHw472SJjQ" ..
                "xxx"

            )
            ngx.say(
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
valid: true
verified: false
--- no_error_log
[error]



=== TEST 4: Encode A128CBC-HS256 Direct Encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"

            local table_of_jwt = {
              header = { alg = "dir", enc = "A128CBC-HS256" },
              payload = { foo = "bar" },
            }

            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token)

            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]



=== TEST 5: Encode A256CBC-HS512 Direct Encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234" ..
                               "12341234123412341234123412341234"

            local table_of_jwt = {
              header = { alg = "dir", enc = "A256CBC-HS512" },
              payload = { foo = "bar" },
            }

            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token)

            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]



=== TEST 6: Use rsa oeap 256 for encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]



=== TEST 7: Use rsa oeap 256 for encryption invalid typ
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC-HS512",
                  typ = "INVALID",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
            }

            local success, err = pcall(function () jwt:sign(
                        get_testcert("cert-pubkey.pem"),
                        table_of_jwt
                )
            end)
            ngx.say(err.reason)
        ';
    }
--- request
GET /t
--- response_body
invalid typ: INVALID
--- no_error_log
[error]



=== TEST 8: Use rsa oeap 256 for encryption invalid key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
            }

            local success, err = pcall(function () jwt:sign(
                        "invalid RSA",
                        table_of_jwt
                    )
            end)
            ngx.say(err.reason)
        ';
    }
--- request
GET /t
--- response_body
Decode secret is not a valid cert/public key: invalid RSA
--- no_error_log
[error]



=== TEST 9: Use rsa oeap 256 for encryption invalid enc algo
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local success, err = pcall(function () jwt:sign(
                        get_testcert("cert-pubkey.pem"),
                        table_of_jwt
                    )
            end)
            ngx.say(err.reason)
        ';
    }
--- request
GET /t
--- response_body
unsupported payload encryption algorithm :A256CBC
--- no_error_log
[error]



=== TEST 10: Use rsa oeap 256 for encryption with custom payload encoder/decoder
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt_module = require "resty.jwt"
            local cjson = require "cjson"

            local function split_string(str, delim)
                local result = {}
                local sep = string.format("([^%s]+)", delim)
                for m in str:gmatch(sep) do
                    result[#result+1]=m
                end
                return result
            end

            local jwt = jwt_module.new()

            jwt:set_payload_encoder(function(tab)
                                        local str = ""
                                        for i, v in ipairs(tab) do
                                            if (i ~= 1) then
                                                str = str .. ":"
                                            end
                                            str = str .. ":" .. v
                                         end
                                         return str
                                     end
                                    )

            jwt:set_payload_decoder(function(str)
                                         return split_string(str, ":")
                                     end
                                    )

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  "foo" , "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]

=== TEST 11: Use rsa oeap 256 with aes-256-gcm for encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256GCM",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]

=== TEST 12: verify jwe create with rsa-oaep256 and aes-256-gcm with invalid tag
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256GCM",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = "eyJlbmMiOiJBMjU2R0NNIiwia2lkIjoibXlLZXkiLCJhbGciOiJSU0EtT0FFUC0yNTYifQ" .. "." ..
                              "HcMWB6Gh03hYZjsrH08L69aDe8FKv6bZ8e-M8_FggGFyyRdmq1zbHchdbUKMxup1rW9HaIKlNgYpaHiWh7f_BRWAmH4oMzqop4_SmA1LN4nkz3d-P2_MBO2Rm9yVA-4Y4ju0F9QqQ7QbvPLiBknKOmKwEHzL371jN52OK5gByLEA8sSE75rIbfHVoTGtPkz_aIrDp40gcPyojMtMEy4Edm3og2yC8FZl80YRIlVeo9y5qfuwRG5IIFYv60vCdfPXzNN_OBGXUuHPr4szVAu3FV3bwXbM_EyuYPMc1crH42cXFz9zTei8eONU1xmA1H3Z2Jplgj0zUOJtLsgOSeZCwQ" .. "." ..
                              "mROZHYnNXD2Db6vl" .. "." ..
                              "iO8YLN0EiL3QfmP40Q" .. "." ..
                              "vlvUs6U8P6coJk1wyjwxFw"
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            local err = "false"
            if string.find(jwt_obj.reason, "failed to decrypt payload") then
                err = "true"
            end
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "verified: ", jwt_obj.verified, "\\n",
                "error: ", err
            )
        ';
    }
--- request
GET /t
--- response_body
false
verified: false
error: true
--- no_error_log
[error]


=== TEST 13: Use rsa-oaep (SHA1) with aes-256-cbc-hs512 for encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 14: Use rsa-oaep (SHA1) with aes-256-gcm for encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP",
                  enc = "A256GCM",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 15: Use rsa-oaep-256 with aes-128-gcm for encryption
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A128GCM",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 16: Use ecdh-es with aes-256-gcm, EC P-521 key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES",
                  enc = "A256GCM",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("ec_cert_p521_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert_p521-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 17: Use ecdh-es with aes-128-gcm, EC P-521 key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES",
                  enc = "A128GCM",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("ec_cert_p521_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert_p521-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 18: RSA-OAEP-256 with A192CBC-HS384
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A192CBC-HS384",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 19: RSA-OAEP-256 with A192GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A192GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 20: RSA-OAEP-384 with A256GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-384",
                  enc = "A256GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 21: RSA-OAEP-512 with A256GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-512",
                  enc = "A256GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("cert-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 22: A128KW with A128CBC-HS256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            -- 16-byte AES key for A128KW
            local kek = "0123456789abcdef"
            local table_of_jwt = {
              header = {
                  alg = "A128KW",
                  enc = "A128CBC-HS256",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(kek, table_of_jwt)
            local jwt_obj = jwt:verify(kek, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 23: A256KW with A256GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            -- 32-byte AES key for A256KW
            local kek = "0123456789abcdef0123456789abcdef"
            local table_of_jwt = {
              header = {
                  alg = "A256KW",
                  enc = "A256GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(kek, table_of_jwt)
            local jwt_obj = jwt:verify(kek, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 24: ECDH-ES+A128KW with A128GCM, EC P-256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES+A128KW",
                  enc = "A128GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("ec_cert_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 25: ECDH-ES+A256KW with A256GCM, EC P-521
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES+A256KW",
                  enc = "A256GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("ec_cert_p521_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert_p521-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 26: A192KW with A192GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            -- 24-byte AES key for A192KW
            local kek = "0123456789abcdef01234567"
            local table_of_jwt = {
              header = {
                  alg = "A192KW",
                  enc = "A192GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(kek, table_of_jwt)
            local jwt_obj = jwt:verify(kek, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 27: ECDH-ES+A192KW with A192CBC-HS384, EC P-256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES+A192KW",
                  enc = "A192CBC-HS384",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }

            local jwt_token = jwt:sign(get_testcert("ec_cert_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 28: A128GCMKW with A128GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local kek = "0123456789abcdef"
            local table_of_jwt = {
              header = {
                  alg = "A128GCMKW",
                  enc = "A128GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(kek, table_of_jwt)
            local jwt_obj = jwt:verify(kek, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 29: A192GCMKW with A192CBC-HS384
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local kek = "0123456789abcdef01234567"
            local table_of_jwt = {
              header = {
                  alg = "A192GCMKW",
                  enc = "A192CBC-HS384",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(kek, table_of_jwt)
            local jwt_obj = jwt:verify(kek, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 30: A256GCMKW with A256CBC-HS512
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local kek = "0123456789abcdef0123456789abcdef"
            local table_of_jwt = {
              header = {
                  alg = "A256GCMKW",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(kek, table_of_jwt)
            local jwt_obj = jwt:verify(kek, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 31: PBES2-HS256+A128KW with A128GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local password = "my-super-secret-password"
            local table_of_jwt = {
              header = {
                  alg = "PBES2-HS256+A128KW",
                  enc = "A128GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(password, table_of_jwt)
            local jwt_obj = jwt:verify(password, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 32: PBES2-HS384+A192KW with A192CBC-HS384
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local password = "another-password-here"
            local table_of_jwt = {
              header = {
                  alg = "PBES2-HS384+A192KW",
                  enc = "A192CBC-HS384",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(password, table_of_jwt)
            local jwt_obj = jwt:verify(password, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 33: PBES2-HS512+A256KW with A256CBC-HS512
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local password = "yet-another-password"
            local table_of_jwt = {
              header = {
                  alg = "PBES2-HS512+A256KW",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(password, table_of_jwt)
            local jwt_obj = jwt:verify(password, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 34: Use ecdh-es with aes-256-gcm, EC P-256 key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES",
                  enc = "A256GCM",
                  typ = "JWE",
                  kid = "myKey"
              },
              payload = {
                  foo = "bar"
              }
             }

            local jwt_token = jwt:sign(get_testcert("ec_cert_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert-key.pem"), jwt_token)
            print(cjson.encode(jwt_obj))
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 35: dir with A128GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "1234567890abcdef"
            local table_of_jwt = {
              header = { alg = "dir", enc = "A128GCM" },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 36: dir with A192GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "1234567890abcdef12345678"
            local table_of_jwt = {
              header = { alg = "dir", enc = "A192GCM" },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 37: dir with A256GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"
            local table_of_jwt = {
              header = { alg = "dir", enc = "A256GCM" },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 38: dir with A192CBC-HS384
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            -- 48-byte key for A192CBC-HS384 (24 MAC + 24 enc)
            local shared_key = "123456789012345678901234" ..
                               "123456789012345678901234"
            local table_of_jwt = {
              header = { alg = "dir", enc = "A192CBC-HS384" },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 39: ECDH-ES with A128CBC-HS256, EC P-256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES",
                  enc = "A128CBC-HS256",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("ec_cert_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 40: ECDH-ES with A192CBC-HS384, EC P-521
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES",
                  enc = "A192CBC-HS384",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("ec_cert_p521_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert_p521-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 41: ECDH-ES with A256CBC-HS512, EC P-256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("ec_cert_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 42: ECDH-ES with A192GCM, EC P-384
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES",
                  enc = "A192GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("ec_cert_p384_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert_p384-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 43: ECDH-ES+A256KW with A256CBC-HS512, EC P-384
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES+A256KW",
                  enc = "A256CBC-HS512",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("ec_cert_p384_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert_p384-key.pem"), jwt_token)
            ngx.say(
                cjson.encode(table_of_jwt.payload) == cjson.encode(jwt_obj.payload), "\\n",
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
true
valid: true
verified: true
--- no_error_log
[error]


=== TEST 44: dir wrong key returns verified false
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local sign_key = "12341234123412341234123412341234"
            local wrong_key = "abcdabcdabcdabcdabcdabcdabcdabcd"
            local table_of_jwt = {
              header = { alg = "dir", enc = "A128CBC-HS256" },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(sign_key, table_of_jwt)
            local jwt_obj = jwt:verify(wrong_key, jwt_token)
            ngx.say(
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
verified: false
--- no_error_log
[error]


=== TEST 45: A256KW wrong key fails to decrypt
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local sign_key = "0123456789abcdef0123456789abcdef"
            local wrong_key = "abcdefghijklmnopabcdefghijklmnop"
            local table_of_jwt = {
              header = {
                  alg = "A256KW",
                  enc = "A256GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(sign_key, table_of_jwt)
            local jwt_obj = jwt:verify(wrong_key, jwt_token)
            ngx.say(
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
verified: false
--- no_error_log
[error]


=== TEST 46: RSA-OAEP-256 wrong private key fails
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "RSA-OAEP-256",
                  enc = "A256GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(get_testcert("cert-pubkey.pem"), table_of_jwt)
            -- use a different RSA private key to decrypt
            local jwt_obj = jwt:verify(get_testcert("root-key.pem"), jwt_token)
            ngx.say(
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
verified: false
--- no_error_log
[error]


=== TEST 47: PBES2 wrong password fails to decrypt
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local table_of_jwt = {
              header = {
                  alg = "PBES2-HS256+A128KW",
                  enc = "A128GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign("correct-password", table_of_jwt)
            local jwt_obj = jwt:verify("wrong-password", jwt_token)
            ngx.say(
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
verified: false
--- no_error_log
[error]


=== TEST 48: ECDH-ES wrong EC private key fails
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local table_of_jwt = {
              header = {
                  alg = "ECDH-ES",
                  enc = "A256GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            -- sign with P-256 public key, try to decrypt with P-521 private key
            local jwt_token = jwt:sign(get_testcert("ec_cert_pubkey.pem"), table_of_jwt)
            local jwt_obj = jwt:verify(get_testcert("ec_cert_p521-key.pem"), jwt_token)
            ngx.say(
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
verified: false
--- no_error_log
[error]


=== TEST 49: JWE with claim validation (exp/nbf)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"
            local table_of_jwt = {
              header = { alg = "dir", enc = "A128CBC-HS256" },
              payload = {
                  foo = "bar",
                  exp = ngx.time() + 3600,
                  nbf = ngx.time() - 60,
              }
            }
            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token, {
                exp = validators.is_not_expired(),
                nbf = validators.is_not_before(),
            })
            ngx.say(
                "valid: ", jwt_obj.valid, "\\n",
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
valid: true
verified: true
--- no_error_log
[error]


=== TEST 50: JWE with expired claim rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"
            local table_of_jwt = {
              header = { alg = "dir", enc = "A128CBC-HS256" },
              payload = {
                  foo = "bar",
                  exp = ngx.time() - 3600,
              }
            }
            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token, {
                exp = validators.is_not_expired(),
            })
            ngx.say(
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
verified: false
--- no_error_log
[error]


=== TEST 51: JWE with nbf in the future rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local cjson = require "cjson"
            local shared_key = "12341234123412341234123412341234"
            local table_of_jwt = {
              header = { alg = "dir", enc = "A128CBC-HS256" },
              payload = {
                  foo = "bar",
                  nbf = ngx.time() + 3600,
              }
            }
            local jwt_token = jwt:sign(shared_key, table_of_jwt)
            local jwt_obj = jwt:verify(shared_key, jwt_token, {
                nbf = validators.is_not_before(),
            })
            ngx.say(
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
verified: false
--- no_error_log
[error]


=== TEST 52: dir with A256GCM wrong key returns verified false
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local sign_key = "12341234123412341234123412341234"
            local wrong_key = "abcdabcdabcdabcdabcdabcdabcdabcd"
            local table_of_jwt = {
              header = { alg = "dir", enc = "A256GCM" },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(sign_key, table_of_jwt)
            local jwt_obj = jwt:verify(wrong_key, jwt_token)
            ngx.say(
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
verified: false
--- no_error_log
[error]


=== TEST 53: dir with wrong key length rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            -- A128CBC-HS256 requires 32-byte key, try with 16-byte key
            local table_of_jwt = {
              header = { alg = "dir", enc = "A128CBC-HS256" },
              payload = { foo = "bar" }
            }
            local success, err = pcall(function ()
                jwt:sign("short-key-16byte", table_of_jwt)
            end)
            ngx.say("success: ", success)
            if not success then
                ngx.say("reason: ", err.reason)
            end
        ';
    }
--- request
GET /t
--- response_body
success: false
reason: invalid pre-shared key
--- no_error_log
[error]


=== TEST 54: A128GCMKW wrong key fails to decrypt
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local sign_key = "0123456789abcdef"
            local wrong_key = "abcdefghijklmnop"
            local table_of_jwt = {
              header = {
                  alg = "A128GCMKW",
                  enc = "A128GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local jwt_token = jwt:sign(sign_key, table_of_jwt)
            local jwt_obj = jwt:verify(wrong_key, jwt_token)
            ngx.say(
                "verified: ", jwt_obj.verified
            )
        ';
    }
--- request
GET /t
--- response_body
verified: false
--- no_error_log
[error]


=== TEST 55: Invalid alg in JWE header rejected
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local cjson = require "cjson"
            local table_of_jwt = {
              header = {
                  alg = "UNSUPPORTED",
                  enc = "A256GCM",
                  typ = "JWE",
              },
              payload = { foo = "bar" }
            }
            local success, err = pcall(function ()
                jwt:sign("12341234123412341234123412341234", table_of_jwt)
            end)
            ngx.say("success: ", success)
            if not success then
                ngx.say("has_reason: ", err.reason ~= nil)
            end
        ';
    }
--- request
GET /t
--- response_body
success: false
has_reason: true
--- no_error_log
[error]
