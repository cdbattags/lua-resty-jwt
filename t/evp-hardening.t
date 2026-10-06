BEGIN { use Cwd; $ENV{TEST_NGINX_SERVROOT} = Cwd::cwd() . "/t/servroot_$$"; $ENV{TEST_NGINX_SERVER_PORT} = 10000 + ($$ % 50000) }
use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_worker_by_lua_block {
        local h = {}
        function h.cert(name)
            local f = assert(io.open("/lua-resty-jwt/testcerts/" .. name))
            local contents = f:read("*all")
            f:close()
            return contents
        end
        function h.b64url(s)
            return (ngx.encode_base64(s):gsub('+', '-'):gsub('/', '_'):gsub('=', ''))
        end
        -- A token whose signature bytes do not matter: the key type is
        -- checked before the signature is.
        function h.token(alg, sig_len)
            return h.b64url('{"typ":"JWT","alg":"' .. alg .. '"}') ..
                "." .. h.b64url('{"sub":"test"}') ..
                "." .. h.b64url(string.rep("A", sig_len or 64))
        end
        function h.pem_to_der(pem)
            local body = pem:gsub("%-%-%-%-%-[^\n]*%-%-%-%-%-", ""):gsub("%s", "")
            return ngx.decode_base64(body)
        end
        package.loaded["evp_hardening_helpers"] = h
    }
_EOC_

if ($ENV{COVERAGE}) {
    $HttpConfig .= "    init_by_lua_block { require('luacov') }\n";
}

no_long_string();

run_tests();

__DATA__


=== TEST 1: ES256 token verified with an RSA public key fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            local jwt_obj = jwt:verify(h.cert("pubkey.pem"), h.token("ES256", 64))
            ngx.say(jwt_obj.verified)
            ngx.say(jwt_obj.reason)
        }
    }
--- request
GET /t
--- response_body
false
key type mismatch: alg ES256 requires an EC P-256 key
--- no_error_log
[error]


=== TEST 2: ES384 token verified with an RSA certificate fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            local jwt_obj = jwt:verify(h.cert("cert.pem"), h.token("ES384", 96))
            ngx.say(jwt_obj.verified)
            ngx.say(jwt_obj.reason)
        }
    }
--- request
GET /t
--- response_body
false
key type mismatch: alg ES384 requires an EC P-384 key
--- no_error_log
[error]


=== TEST 3: ES512 token verified with RSA public key and certificate fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            for _, name in ipairs({ "pubkey.pem", "cert.pem" }) do
                local jwt_obj = jwt:verify(h.cert(name), h.token("ES512", 132))
                ngx.say(jwt_obj.verified, " ", jwt_obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
false key type mismatch: alg ES512 requires an EC P-521 key
false key type mismatch: alg ES512 requires an EC P-521 key
--- no_error_log
[error]


=== TEST 4: ES256 token verified with an Ed25519 public key fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            local jwt_obj = jwt:verify(h.cert("ed25519-pubkey.pem"), h.token("ES256", 64))
            ngx.say(jwt_obj.verified)
            ngx.say(jwt_obj.reason)
        }
    }
--- request
GET /t
--- response_body
false
key type mismatch: alg ES256 requires an EC P-256 key
--- no_error_log
[error]


=== TEST 5: RS256 token verified with an EC public key and certificate is rejected by key type
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            for _, name in ipairs({ "ec_cert_pubkey.pem", "ec_cert.pem" }) do
                local jwt_obj = jwt:verify(h.cert(name), h.token("RS256", 256))
                ngx.say(jwt_obj.verified, " ", jwt_obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
false key type mismatch: alg RS256 requires an RSA key
false key type mismatch: alg RS256 requires an RSA key
--- no_error_log
[error]


=== TEST 6: PS256 token verified with an EC public key and certificate is rejected by key type
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            for _, name in ipairs({ "ec_cert_pubkey.pem", "ec_cert.pem" }) do
                local jwt_obj = jwt:verify(h.cert(name), h.token("PS256", 256))
                ngx.say(jwt_obj.verified, " ", jwt_obj.reason)
            end
        }
    }
--- request
GET /t
--- response_body
false key type mismatch: alg PS256 requires an RSA key
false key type mismatch: alg PS256 requires an RSA key
--- no_error_log
[error]


=== TEST 7: RS256/PS256 signing with an EC private key returns a signer error
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            for _, alg in ipairs({ "RS256", "PS256" }) do
                local ok, err = pcall(jwt.sign, jwt, h.cert("ec_cert-key.pem"),
                    { header = { typ = "JWT", alg = alg }, payload = { foo = "bar" } })
                ngx.say(alg, " ", ok, " ", type(err) == "table"
                    and err.reason:match("^signer error: ") ~= nil)
            end
        }
    }
--- request
GET /t
--- response_body
RS256 false true
PS256 false true
--- no_error_log
[error]


=== TEST 8: ES256 signing with an RSA private key returns a signer error
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            local h = require "evp_hardening_helpers"
            for _, name in ipairs({ "privatekey.pem", "cert-key.pem" }) do
                local ok, err = pcall(jwt.sign, jwt, h.cert(name),
                    { header = { typ = "JWT", alg = "ES256" }, payload = { foo = "bar" } })
                ngx.say(ok, " ", type(err) == "table"
                    and err.reason:match("^signer error: ") ~= nil)
            end
        }
    }
--- request
GET /t
--- response_body
false true
false true
--- no_error_log
[error]


=== TEST 9: Signers and RSADecryptor reject a missing or mismatched private key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local s, err = evp.RSASigner:new(nil)
            ngx.say("RSASigner nil: ", s, " ", err)
            s, err = evp.ECSigner:new(nil)
            ngx.say("ECSigner nil: ", s, " ", err)
            s, err = evp.RSADecryptor:new(h.cert("ec_cert-key.pem"))
            ngx.say("RSADecryptor EC key: ", s, " ", err ~= nil)
        }
    }
--- request
GET /t
--- response_body
RSASigner nil: nil Must pass a PEM private key
ECSigner nil: nil Must pass a PEM private key
RSADecryptor EC key: nil true
--- no_error_log
[error]


=== TEST 10: ECSigner.get_raw_sig rejects malformed and short DER
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local signer = assert(evp.ECSigner:new(h.cert("ec_cert-key.pem")))
            local cases = {
                { "empty", "" },
                { "garbage", "not a DER signature" },
                { "truncated", "\48\6\2\1\1\2\1" },
                { "wrong tag", "\4\6\2\1\1\2\1\1" },
            }
            for _, c in ipairs(cases) do
                local raw, err = signer:get_raw_sig(c[2])
                ngx.say(c[1], ": ", raw, " ", err)
            end
        }
    }
--- request
GET /t
--- response_body
empty: nil Must pass a signature to convert
garbage: nil Invalid DER signature
truncated: nil Invalid DER signature
wrong tag: nil Invalid DER signature
--- no_error_log
[error]


=== TEST 11: ECSigner.get_raw_sig rejects r/s larger than the curve order and trailing data
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local signer = assert(evp.ECSigner:new(h.cert("ec_cert-key.pem")))
            -- SEQUENCE { INTEGER r (200 bytes), INTEGER 1 }: writing r
            -- unchecked lands 168 bytes before the 64 byte output buffer
            local r = "\0" .. string.rep("\255", 199)
            local body = "\2\129\200" .. r .. "\2\1\1"
            local raw, err = signer:get_raw_sig("\48\129" .. string.char(#body) .. body)
            ngx.say("oversized r: ", raw, " ", err)

            local der = assert(signer:sign("hello", evp.CONST.SHA256_DIGEST))
            raw, err = signer:get_raw_sig(der .. "\0")
            ngx.say("trailing data: ", raw, " ", err)

            raw, err = signer:get_raw_sig(der)
            ngx.say("valid: ", #raw, " ", err)
            local verifier = assert(evp.ECVerifier:new(
                assert(evp.PublicKey:new(h.cert("ec_cert_pubkey.pem")))))
            ngx.say("verifies: ", (verifier:verify("hello", raw, evp.CONST.SHA256_DIGEST)))
        }
    }
--- request
GET /t
--- response_body
oversized r: nil Invalid DER signature: r or s larger than curve order
trailing data: nil Invalid DER signature: trailing data
valid: 64 nil
verifies: true
--- no_error_log
[error]


=== TEST 12: ECSigner.get_raw_sig with a non-EC key fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local ec_signer = assert(evp.ECSigner:new(h.cert("ec_cert-key.pem")))
            local der = assert(ec_signer:sign("hello", evp.CONST.SHA256_DIGEST))
            local rsa_signer = assert(evp.RSASigner:new(h.cert("privatekey.pem")))
            local raw, err = evp.ECSigner.get_raw_sig(rsa_signer, der)
            ngx.say(raw, " ", err)
        }
    }
--- request
GET /t
--- response_body
nil key is not an EC key
--- no_error_log
[error]


=== TEST 13: Verifiers and encryptor reject a key source without a public key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            ngx.say("RSAVerifier: ", evp.RSAVerifier:new({}))
            ngx.say("ECVerifier: ", evp.ECVerifier:new({}))
            ngx.say("RSAEncryptor: ", evp.RSAEncryptor:new({}))
        }
    }
--- request
GET /t
--- response_body
RSAVerifier: nilYou must pass in an key_source for a public key
ECVerifier: nilYou must pass in an key_source for a public key
RSAEncryptor: nilYou must pass in an key_source for a public key
--- no_error_log
[error]


=== TEST 14: RSAEncryptor with an EC public key is rejected by key type
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local pub = assert(evp.PublicKey:new(h.cert("ec_cert_pubkey.pem")))
            local enc = assert(evp.RSAEncryptor:new(pub))
            ngx.say(enc:encrypt("secret"))
        }
    }
--- request
GET /t
--- response_body
nilkey is not an RSA key
--- no_error_log
[error]


=== TEST 15: Cert.verify_trust with an invalid trusted certs path fails cleanly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local cert = assert(evp.Cert:new(h.cert("cert.pem")))
            local ok, err = cert:verify_trust("/nonexistent/trusted.pem")
            ngx.say("missing file: ", ok, " ", err ~= nil)
            ok, err = cert:verify_trust("/lua-resty-jwt/testcerts")
            ngx.say("directory: ", ok, " ", err ~= nil)
            ok, err = cert:verify_trust(nil)
            ngx.say("nil: ", ok, " ", err)
            local pok, ok2, err2 = pcall(cert.verify_trust, cert, 42)
            ngx.say("number: ", pok, " ", ok2, " ", err2)
            ok, err = cert:verify_trust("/lua-resty-jwt/testcerts/root.pem")
            ngx.say("trusted: ", ok, " ", err)
        }
    }
--- request
GET /t
--- response_body
missing file: false true
directory: false true
nil: false Must pass a trusted certs file path
number: true false Must pass a trusted certs file path
trusted: true nil
--- no_error_log
[error]


=== TEST 16: PublicKey accepts a DER encoded public key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            for _, name in ipairs({ "pubkey.pem", "ec_cert_pubkey.pem" }) do
                local ok, pub, err = pcall(evp.PublicKey.new, evp.PublicKey,
                    h.pem_to_der(h.cert(name)))
                ngx.say(name, ": ", ok, " ", pub ~= nil, " ", err)
            end
            local ok, pub, err = pcall(evp.PublicKey.new, evp.PublicKey, "\48\3\2\1\1")
            ngx.say("garbage: ", ok, " ", pub, " ", err ~= nil)
        }
    }
--- request
GET /t
--- response_body
pubkey.pem: true true nil
ec_cert_pubkey.pem: true true nil
garbage: true nil true
--- no_error_log
[error]


=== TEST 17: Cert fingerprints for digests longer than 32 bytes
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local cert = assert(evp.Cert:new(h.cert("cert.pem")))
            ngx.say((cert:get_fingerprint("SHA256")))
            ngx.say((cert:get_fingerprint("SHA512")))
            ngx.say(cert:get_fingerprint("NOPE"))
        }
    }
--- request
GET /t
--- response_body
58:01:1C:35:34:CA:A9:F7:B4:76:D4:62:CD:C6:32:51:41:09:8D:CB:02:DE:0C:6F:22:C3:2B:66:FC:8C:8A:4E
76:25:7E:72:F2:6C:2E:24:7A:79:F0:C5:CA:B3:99:B9:2F:16:D6:60:BC:3E:27:CE:F3:5E:28:99:92:CA:48:1C:17:7D:45:23:DB:D4:7D:B0:D0:85:01:CF:39:4C:B1:22:B2:C6:E4:F1:CC:CB:1D:59:F0:8C:41:11:07:59:9E:F3
nilUnknown message digest
--- no_error_log
[error]


=== TEST 18: Cert.get_der round-trips through Cert.new
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local evp = require "resty.evp"
            local h = require "evp_hardening_helpers"
            local pem = h.cert("cert.pem")
            local der = assert(evp.Cert:new(pem):get_der())
            ngx.say(der == h.pem_to_der(pem))
            local cert = assert(evp.Cert:new(der))
            ngx.say((cert:get_fingerprint("SHA256")))
        }
    }
--- request
GET /t
--- response_body
true
58:01:1C:35:34:CA:A9:F7:B4:76:D4:62:CD:C6:32:51:41:09:8D:CB:02:DE:0C:6F:22:C3:2B:66:FC:8C:8A:4E
--- no_error_log
[error]
