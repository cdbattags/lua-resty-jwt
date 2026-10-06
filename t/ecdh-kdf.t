BEGIN { use Cwd; $ENV{TEST_NGINX_SERVROOT} = Cwd::cwd() . "/t/servroot_$$"; $ENV{TEST_NGINX_SERVER_PORT} = 10000 + ($$ % 50000) }
use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        local cjson = require "cjson"
        local pkey = require "resty.openssl.pkey"

        function get_testcert(name)
            local f = io.open("/lua-resty-jwt/testcerts/" .. name)
            local contents = f:read("*all")
            f:close()
            return contents
        end

        function b64url_encode(s)
            return (ngx.encode_base64(s):gsub("+", "-"):gsub("/", "_"):gsub("=", ""))
        end

        function b64url_decode(s)
            s = s:gsub("-", "+"):gsub("_", "/")
            return ngx.decode_base64(s .. string.rep("=", (4 - #s % 4) % 4))
        end

        function jwk_to_pem(jwk, which)
            local key = assert(pkey.new(cjson.encode(jwk), { format = "JWK" }))
            return assert(key:tostring(which, "PEM"))
        end

        -- a JWE whose header is the given table; the other parts are dummies,
        -- for tests that must fail before the content is decrypted
        function jwe_with_header(header, encrypted_key)
            return b64url_encode(cjson.encode(header)) .. "." .. (encrypted_key or "") ..
                ".AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA"
        end

        -- a valid P-256 ephemeral public key (RFC 7518 Appendix C, Alice)
        rfc7518_alice_epk = {
            kty = "EC",
            crv = "P-256",
            x = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            y = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
        }

        -- tokens produced by lua-resty-jwt v0.3.2 (non-standard Concat KDF),
        -- encrypted to testcerts/ec_cert_pubkey.pem
        legacy_tokens = {
            {
                foo = "legacy",
                token = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsi" ..
                    "Onsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIybGNERWg1LVprMTJj" ..
                    "QzNxY3NoaTltZ1NyNlktZDdORUtuZ2VCUnQ3NWhBIiwia2lkIjoiaWprYkN3" ..
                    "dV9WNmhZQkZYNUJOTkNqWjVMTXNVcmpqU1gyYjRpazgxcTBkTSIsInkiOiJ5" ..
                    "dWp5bWdjRDU2M0dLaWtBZGxnV1BmNlk5YlpZcXl2d3lCOEl1Q0ZxZHVzIn19" ..
                    ".f58Jmk3q8REIUvJ8qg08Dl5D4OeLOquKxG3BcYspopDticCbe7CCSA.A4-a" ..
                    "4hZfqYp1e44J.s4FQrjJUAs62NhTmlkVjHw.XONMwtAXJna5t0S0kcqTUw",
            },
            {
                foo = "legacy",
                token = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYi" ..
                    "LCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJYeXlYMVlr" ..
                    "ZjAxS3Rxa0ZLc1pOdUJrSTdaeUpjdTl0QlpiU0VqWURZSU1rIiwia2lkIjoi" ..
                    "VTgxc3h3a2YxTUd2TFpLNjZZU2pQb2h6azdnOVVkV3czampSMVBZdmZQayIs" ..
                    "InkiOiJublBXY2I5djV4RjFhYmJteC1PdDROaXRaT01sX0w5ZU5yQWlOY09M" ..
                    "TnNFIn19.kAtYGsdijwAQ634oxzhNck5BQ4g1EtmPqZaD2sU6vONjbx4SamL" ..
                    "X8A.ZMMRw2HyO71j2VKWYbda3A.VcN6vml5_iAu2BEzONoUX4SXwMBXVJClq" ..
                    "CdEEES0tNU.Hf0cpVt2oCSjvysHo9U6Og",
            },
            {
                -- apu "Zm9v-_A" is base64url; v0.3.2 failed to decode it as base64 and ignored it
                foo = "legacy-apu",
                token = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkEyNTZHQ00iLCJhcHUi" ..
                    "OiJabTl2LV9BIiwiYXB2IjoiWW1GeSIsImVwayI6eyJrdHkiOiJFQyIsImNy" ..
                    "diI6IlAtMjU2IiwieCI6IjRpdk9wcnNMcFUzZWtxUVhiSnlVOVFLWENhVGlC" ..
                    "cDNEWGNxUmVBZWhuRk0iLCJraWQiOiJ4N2hjNHlPM2R2Q1RDdUJLU2lLa1FE" ..
                    "NjlEc0lsNjlpX1B1bmFUd3pPdl9rIiwieSI6IjUza3g5dWZxT2ZVUnlfeUNj" ..
                    "Wldsb2V5bUZPR1ltZ2tjWEhkUkZpZjJzY3MifX0.dphq08zZMxT908QUNaBz" ..
                    "1eRjewuY2cghiLAXSLK6pWOJdd1_g18Gfw.q0Ji-k032x9GVXsU.OSX1dOE7" ..
                    "L5GkAik2dEA5ChRwpLE.BId9pxGpk1Y5TRHmXnrWWw",
            },
        }
    }
_EOC_

if ($ENV{COVERAGE}) {
    $HttpConfig =~ s/init_by_lua_block \{/init_by_lua_block {\n        require('luacov')/;
}

no_long_string();

run_tests();

__DATA__

=== TEST 1: RFC 7518 Appendix C Concat KDF derivation output
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local utils = require "resty.utils"
            local pkey = require "resty.openssl.pkey"
            local cjson = require "cjson"

            -- RFC 7518 Appendix C: Z, apu "Alice", apv "Bob", enc "A128GCM"
            local Z = string.char(158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
                38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
                140, 254, 144, 196)
            local derived = utils.concat_kdf(Z, "A128GCM", 128, b64url_decode("QWxpY2U"), b64url_decode("Qm9i"))
            ngx.say("derived key: ", b64url_encode(derived))

            -- and Z itself, from Bob's private key and Alice's ephemeral public key
            local bob = jwk_to_pem({
                kty = "EC",
                crv = "P-256",
                x = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
                y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
                d = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
            }, "private")
            local alice = assert(pkey.new(cjson.encode(rfc7518_alice_epk), { format = "JWK" }))
            ngx.say("Z matches: ", assert(pkey.new(bob):derive(alice)) == Z)
        }
    }
--- request
GET /t
--- response_body
derived key: VqqN6vgjbSBcIijNcacQGg
Z matches: true
--- no_error_log
[error]



=== TEST 2: RFC 7518 Appendix C key agreement decrypts content encrypted with the RFC's CEK
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            local cipher = require "resty.openssl.cipher"
            local cjson = require "cjson"

            local bob = jwk_to_pem({
                kty = "EC",
                crv = "P-256",
                x = "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
                y = "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
                d = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
            }, "private")
            local encoded_header = b64url_encode(cjson.encode({
                alg = "ECDH-ES", enc = "A128GCM", apu = "QWxpY2U", apv = "Qm9i", epk = rfc7518_alice_epk,
            }))
            local iv = string.rep("\1", 12)
            local c = cipher.new("aes-128-gcm")
            local plaintext = "Appendix C"
            local cipher_text = assert(c:encrypt(b64url_decode("VqqN6vgjbSBcIijNcacQGg"), iv, plaintext, false, encoded_header))
            local tag = assert(c:get_aead_tag(16))
            local token = table.concat({ encoded_header, "", b64url_encode(iv), b64url_encode(cipher_text), b64url_encode(tag) }, ".")

            jwt:set_payload_decoder(function(s) return s end)
            local obj = jwt:verify(bob, token)
            ngx.say("verified: ", obj.verified, " reason: ", obj.reason)
            ngx.say("payload matches: ", obj.payload == plaintext)
        }
    }
--- request
GET /t
--- response_body
verified: true reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]



=== TEST 3: decrypt tokens encrypted by jwcrypto (independent implementation), base64url apu/apv
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            jwt:set_payload_decoder(function(s) return s end)
            -- generated with python jwcrypto 1.6.1; apu/apv contain "-" and "_"
            local kats = {
                {
                    key = "ec_cert-key.pem",
                    plaintext = "jwcrypto ECDH-ES+A128KW A128GCM",
                    token = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImFwdSI6Ii0tLS1fMEZzYVdObCIs" ..
                            "ImFwdiI6IlFtOWktXzgiLCJlbmMiOiJBMTI4R0NNIiwiZXBrIjp7ImNydiI6" ..
                            "IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiLVBMNG5YekpFSVdmb19xaHpDR202" ..
                            "QzNaUlpKbE5xdEFXc1RDYm9DdTVJWSIsInkiOiJrU05DZ1pzQmVVUUwwYmls" ..
                            "TXp6WkxncFBqMzRUeDVnLWg3WnZUX09xOWZNIn19.oGSmbmhIMScF6Rseb2S" ..
                            "l5SQZ9q-ZcE-3.xCIduf_ahZihUXX8.KUOOctSINtRHlkIXcusxlVW6TavXP" ..
                            "F1TaKJ-8CVbPQ.ZidQC5HpkyE1gt5i6HFEMQ",
                },
                {
                    key = "ec_cert-key.pem",
                    plaintext = "jwcrypto ECDH-ES A256GCM",
                    token = "eyJhbGciOiJFQ0RILUVTIiwiYXB1IjoiLS0tLV8wRnNhV05sIiwiYXB2Ijoi" ..
                            "UW05aS1fOCIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsiY3J2IjoiUC0yNTYi" ..
                            "LCJrdHkiOiJFQyIsIngiOiJwTHJXZkVmbGFpVnU3M1JhZnRuRmNOb0dhRXV3" ..
                            "NWtLZnc1REtrZVNxN2UwIiwieSI6InBVSjhfMVVTUTRkMUNaZ0FONDh3Tm5h" ..
                            "dmtFT3JiY0lYMVA5QmRYQm5MbGMifX0..0bIqIYriPsvfCGog.Qj8myzPB6o" ..
                            "9fVi1evJSATURRq7lZLh-m.QcxYGRwXBNQEsE0gUhGwag",
                },
                {
                    key = "ec_cert_p521-key.pem",
                    plaintext = "jwcrypto ECDH-ES A256CBC-HS512",
                    token = "eyJhbGciOiJFQ0RILUVTIiwiYXB1IjoiLS0tLV8wRnNhV05sIiwiZW5jIjoi" ..
                            "QTI1NkNCQy1IUzUxMiIsImVwayI6eyJjcnYiOiJQLTUyMSIsImt0eSI6IkVD" ..
                            "IiwieCI6IkFYOHdmUEMtQmMxZGNUQUNjTVd4VVlzZFhDY081QTctVHAxLThh" ..
                            "NkFTaEVRaDMxQUZwYzVwTW5lWFVaOWhYY3dBY09XNUxVX2R1QUVtRWdhTjhE" ..
                            "eHM4Q24iLCJ5IjoiQUJnWG0xdXFJNExNMjA0b2VnTUdJNFhaZkc2YWxuMFBD" ..
                            "Q2ZVeXNKOEpqWDVlSmxRYlNYZU1vSHc4OFcyWE9UcXdmWmNLMjR3M3NsaTRG" ..
                            "azdTNlhZTnI3bCJ9fQ..uvsgleymDwJmRCE7qpPkIA._R5lNieQXno1TtWr-" ..
                            "JXfOk6og585yIt3TIqMNTH-NlU.ymlZIPt5XZ9R1oHDNJsXYHgiKGRHpxhFY" ..
                            "U7wbf6vfTE",
                },
                {
                    key = "ec_cert_p521-key.pem",
                    plaintext = "jwcrypto ECDH-ES+A256KW A256CBC-HS512",
                    token = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImFwdiI6IlFtOWktXzgiLCJlbmMi" ..
                            "OiJBMjU2Q0JDLUhTNTEyIiwiZXBrIjp7ImNydiI6IlAtNTIxIiwia3R5Ijoi" ..
                            "RUMiLCJ4IjoiQUxESlpacWpES0p6b3A5N05UUlEtWERZSWtZdDcwTGpEX3JE" ..
                            "eG1ValgwT21CZXpodks1WVM0S1JxMWtDU2dpVkxaWGhoeW43dVhoc3pzcmFZ" ..
                            "TE84NnAyciIsInkiOiJBQXNjVjdPNk0zODhrOGdSLVN3WE91SlJLa3RnT3RF" ..
                            "dUxsa0NWMXBEQjFUdVgzNXVZQVpQN2dxNF8wV0ZxbUgzemU3UEpjTGI2T0c1" ..
                            "RjVnR1ZQbTRyUWgxIn19.zpsqDBcUQ21arBduRDyHHsmihEccSMmaRpgV3Fn" ..
                            "lHprIIzyrkO6rqbTWRNkqic0cuWQ-h2jOsfQJEdjl5Ne_RRXQLazWByEG.eV" ..
                            "zE8C1gP9ogv4XvEMi7mw.3VfUtFaGtBK3CBWZ73s9fnaQilbRdPJ0yBSYVqQ" ..
                            "QfobmPOXcH5PCyvCJqH-tzqnn.q9wuMXvmUbNS8lSMzPFUQ2yRQvCGMpywv5" ..
                            "eEmdnv8Fc",
                },
            }
            for _, kat in ipairs(kats) do
                local obj = jwt:verify(get_testcert(kat.key), kat.token)
                ngx.say(obj.header and obj.header.alg, " ", obj.header and obj.header.enc, ": ",
                    obj.verified, " ", obj.reason, " ", obj.payload == kat.plaintext)
            end
        }
    }
--- request
GET /t
--- response_body
ECDH-ES+A128KW A128GCM: true everything is awesome~ :p true
ECDH-ES A256GCM: true everything is awesome~ :p true
ECDH-ES A256CBC-HS512: true everything is awesome~ :p true
ECDH-ES+A256KW A256CBC-HS512: true everything is awesome~ :p true
--- no_error_log
[error]



=== TEST 4: v0.3.2 ECDH-ES+A*KW tokens are rejected by default
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            for _, legacy in ipairs(legacy_tokens) do
                local obj = jwt:verify(get_testcert("ec_cert-key.pem"), legacy.token)
                ngx.say(obj.verified, " ", obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
false failed to decrypt JWE
false failed to decrypt JWE
false failed to decrypt JWE
--- no_error_log
[error]



=== TEST 5: v0.3.2 ECDH-ES+A*KW tokens decrypt with set_legacy_ecdh_kw_kdf(true)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            jwt:set_legacy_ecdh_kw_kdf(true)
            for _, legacy in ipairs(legacy_tokens) do
                local obj = jwt:verify(get_testcert("ec_cert-key.pem"), legacy.token)
                ngx.say(obj.verified, " ", obj.reason, " ", obj.payload and obj.payload.foo == legacy.foo)
            end
            -- and wrong keys still fail, with the generic reason once both derivations fail
            local obj = jwt:verify(get_testcert("ec_cert_p384-key.pem"), legacy_tokens[1].token)
            ngx.say(obj.verified)
            local other = jwt:sign(get_testcert("ec_cert_p521_pubkey.pem"), {
                header = { alg = "ECDH-ES+A128KW", enc = "A256GCM" }, payload = { foo = "bar" } })
            obj = jwt:verify(get_testcert("ec_cert_p521-key.pem"), (other:gsub("^[^.]+%.[^.]+", function(prefix)
                -- swap in the encrypted key of a token for a different recipient key
                return prefix:match("^[^.]+") .. "." .. legacy_tokens[1].token:match("^[^.]+%.([^.]+)")
            end)))
            ngx.say(obj.verified, " ", obj.reason)
            jwt:set_legacy_ecdh_kw_kdf(false)
            obj = jwt:verify(get_testcert("ec_cert-key.pem"), legacy_tokens[1].token)
            ngx.say(obj.verified)
        }
    }
--- request
GET /t
--- response_body
true everything is awesome~ :p true
true everything is awesome~ :p true
true everything is awesome~ :p true
false
false failed to decrypt JWE
false
--- no_error_log
[error]



=== TEST 6: set_legacy_ecdh_kw_kdf(true) still signs RFC 7518 tokens and decrypts them
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            local cjson = require "cjson"
            jwt:set_legacy_ecdh_kw_kdf(true)
            local results = {}
            for _, alg in ipairs({ "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW" }) do
                local token = jwt:sign(get_testcert("ec_cert_pubkey.pem"), {
                    header = { alg = alg, enc = "A256GCM", apu = "-_-_", apv = "Qm9i" },
                    payload = { foo = alg },
                })
                local with_flag = jwt:verify(get_testcert("ec_cert-key.pem"), token)
                local strict = require("resty.jwt").new()
                local without_flag = strict:verify(get_testcert("ec_cert-key.pem"), token)
                ngx.say(alg, " ", with_flag.verified, " ", without_flag.verified, " ",
                    without_flag.payload and without_flag.payload.foo)
            end
        }
    }
--- request
GET /t
--- response_body
ECDH-ES+A128KW true true ECDH-ES+A128KW
ECDH-ES+A192KW true true ECDH-ES+A192KW
ECDH-ES+A256KW true true ECDH-ES+A256KW
--- no_error_log
[error]



=== TEST 7: apu/apv must be base64url
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            local key = get_testcert("ec_cert-key.pem")
            for _, h in ipairs({
                { alg = "ECDH-ES", enc = "A128GCM", apu = "a+b/", epk = rfc7518_alice_epk },
                { alg = "ECDH-ES", enc = "A128GCM", apv = "QWxpY2U=", epk = rfc7518_alice_epk },
                { alg = "ECDH-ES", enc = "A128GCM", apu = "QWxpY", epk = rfc7518_alice_epk },
                { alg = "ECDH-ES", enc = "A128GCM", apv = 42, epk = rfc7518_alice_epk },
            }) do
                ngx.say(jwt:verify(key, jwe_with_header(h)).reason)
            end
            local h = { alg = "ECDH-ES+A128KW", enc = "A128GCM", apu = "a+b/", epk = rfc7518_alice_epk }
            ngx.say(jwt:verify(key, jwe_with_header(h, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).reason)

            local ok, err = pcall(jwt.sign, jwt, get_testcert("ec_cert_pubkey.pem"), {
                header = { alg = "ECDH-ES+A128KW", enc = "A128GCM", apv = "Qm9i==" },
                payload = { foo = "bar" },
            })
            ngx.say(ok, " ", err.reason)
        }
    }
--- request
GET /t
--- response_body
invalid apu in JWE header
invalid apv in JWE header
invalid apu in JWE header
invalid apv in JWE header
invalid apu in JWE header
false invalid apv in JWE header
--- no_error_log
[error]



=== TEST 8: epk validation
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            local key = get_testcert("ec_cert-key.pem")
            local function with_epk(epk, alg)
                return jwt:verify(key, jwe_with_header({ alg = alg or "ECDH-ES", enc = "A128GCM", epk = epk },
                    alg and "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).reason
            end
            local epk_with_d = {}
            for k, v in pairs(rfc7518_alice_epk) do epk_with_d[k] = v end
            epk_with_d.d = "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
            local off_curve = {}
            for k, v in pairs(rfc7518_alice_epk) do off_curve[k] = v end
            off_curve.y = "TLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"

            ngx.say(with_epk(nil))
            ngx.say(with_epk("not an object"))
            ngx.say(with_epk({ kty = "OKP", crv = "X25519", x = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo" }))
            ngx.say(with_epk({ kty = "EC", crv = "secp256k1", x = rfc7518_alice_epk.x, y = rfc7518_alice_epk.y }))
            ngx.say(with_epk({ kty = "EC", crv = "P-256", x = rfc7518_alice_epk.x }))
            ngx.say(with_epk(epk_with_d))
            ngx.say(with_epk(epk_with_d, "ECDH-ES+A128KW"))
            -- invalid curve attack: OpenSSL must refuse the point
            ngx.say(with_epk(off_curve):match("^failed to load ephemeral public key: .*point is not on curve") ~= nil)
            ngx.say(with_epk(off_curve, "ECDH-ES+A128KW"):match("^failed to load ephemeral public key: .*point is not on curve") ~= nil)
            -- x = p, which is congruent to 0 but not a valid field element
            ngx.say(with_epk({ kty = "EC", crv = "P-256", y = rfc7518_alice_epk.y,
                x = "_____wAAAAEAAAAAAAAAAAAAAAD___________________8" }):match("^failed to load ephemeral public key") ~= nil)
            -- RFC 7520 Figure 111 (P-384) against a P-256 private key
            ngx.say(with_epk({
                kty = "EC",
                crv = "P-384",
                x = "uBo4kHPw6kbjx5l0xowrd_oYzBmaz-GKFZu4xAFFkbYiWgutEK6iuEDsQ6wNdNg3",
                y = "sp3p5SGhZVC2faXumI-e9JU2Mo8KpoYrFDr5yPNVtW4PgEwZOyQTA-JdaY8tb7E0",
            }))
        }
    }
--- request
GET /t
--- response_body
missing epk in JWE header
missing epk in JWE header
unsupported epk key type
unsupported epk curve
invalid epk in JWE header
epk must not contain a private key
epk must not contain a private key
true
true
true
epk curve does not match the EC private key
--- no_error_log
[error]



=== TEST 9: ECDH-ES key and token shape checks
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            local key = get_testcert("ec_cert-key.pem")
            local direct = { alg = "ECDH-ES", enc = "A128GCM", epk = rfc7518_alice_epk }
            local kw = { alg = "ECDH-ES+A128KW", enc = "A128GCM", epk = rfc7518_alice_epk }
            ngx.say(jwt:verify(key, jwe_with_header(direct, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).reason)
            ngx.say(jwt:verify(key, jwe_with_header(kw)).reason)
            ngx.say(jwt:verify(nil, jwe_with_header(direct)).reason)
            ngx.say(jwt:verify(get_testcert("cert-key.pem"), jwe_with_header(direct)).reason)
            ngx.say(jwt:verify(get_testcert("ec_cert_pubkey.pem"), jwe_with_header(direct)).reason)

            local ok, err = pcall(jwt.sign, jwt, get_testcert("cert-pubkey.pem"), {
                header = { alg = "ECDH-ES", enc = "A128GCM" },
                payload = { foo = "bar" },
            })
            ngx.say(ok, " ", err.reason)
        }
    }
--- request
GET /t
--- response_body
JWE encrypted key must be empty for ECDH-ES
missing JWE encrypted key
EC private key must not be null
ECDH-ES requires an EC private key
ECDH-ES requires an EC private key
false unsupported EC curve NID: nil
--- no_error_log
[error]



=== TEST 10: ECDH-ES+A*KW rejects an unwrapped CEK of the wrong length with the generic reason
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            local utils = require "resty.utils"
            local pkey = require "resty.openssl.pkey"
            local cipher = require "resty.openssl.cipher"
            local cjson = require "cjson"

            -- encrypt to ec_cert_pubkey.pem by hand so the CEK length can be wrong
            local recipient = assert(pkey.new(get_testcert("ec_cert_pubkey.pem")))
            local ephemeral = assert(pkey.new({ type = "EC", curve = "prime256v1" }))
            local epk = cjson.decode(ephemeral:tostring("public", "JWK"))
            local Z = assert(ephemeral:derive(recipient))
            local kek = utils.concat_kdf(Z, "ECDH-ES+A128KW", 128, "", "")
            local header = { alg = "ECDH-ES+A128KW", enc = "A256GCM",
                epk = { kty = "EC", crv = epk.crv, x = epk.x, y = epk.y } }
            local cek = string.rep("k", 16) -- A256GCM needs 32 octets
            local wrapped = assert(cipher.new("aes-128-wrap"):encrypt(kek, string.rep("\166", 8), cek, false))
            local token = jwe_with_header(header, b64url_encode(wrapped))

            local obj = jwt:verify(get_testcert("ec_cert-key.pem"), token)
            ngx.say(obj.verified, " ", obj.reason)
        }
    }
--- request
GET /t
--- response_body
false failed to decrypt JWE
--- no_error_log
[error]



=== TEST 11: signed epk carries only public coordinates on an RFC 7518 curve
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require("resty.jwt").new()
            for _, c in ipairs({ { "ec_cert_pubkey.pem", "ec_cert-key.pem" },
                                 { "ec_cert_p384_pubkey.pem", "ec_cert_p384-key.pem" },
                                 { "ec_cert_p521_pubkey.pem", "ec_cert_p521-key.pem" } }) do
                local token = jwt:sign(get_testcert(c[1]), {
                    header = { alg = "ECDH-ES", enc = "A256CBC-HS512" },
                    payload = { foo = "bar" },
                })
                local obj = jwt:verify(get_testcert(c[2]), token)
                local epk = obj.header.epk
                local keys = {}
                for k in pairs(epk) do keys[#keys + 1] = k end
                table.sort(keys)
                ngx.say(epk.crv, " ", table.concat(keys, ","), " ", obj.verified)
            end
        }
    }
--- request
GET /t
--- response_body
P-256 crv,kty,x,y true
P-384 crv,kty,x,y true
P-521 crv,kty,x,y true
--- no_error_log
[error]
