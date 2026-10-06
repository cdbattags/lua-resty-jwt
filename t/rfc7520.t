BEGIN { use Cwd; $ENV{TEST_NGINX_SERVROOT} = Cwd::cwd() . "/t/servroot_$$"; $ENV{TEST_NGINX_SERVER_PORT} = 10000 + ($$ % 50000) }
use Test::Nginx::Socket::Lua;

repeat_each(1);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua_block {
        local cjson = require "cjson"
        local pkey = require "resty.openssl.pkey"

        -- RFC 7520 Figure 7 (JWS payload) and Figure 72 (JWE plaintext);
        -- neither is JSON.
        rfc7520_jws_payload =
            "It\xe2\x80\x99s a dangerous business, Frodo, going out your " ..
            "door. You step onto the road, and if you don't keep your feet, " ..
            "there\xe2\x80\x99s no knowing where you might be swept off " ..
            "to."
        rfc7520_jwe_plaintext =
            "You can trust us to stick with you through thick and " ..
            "thin\xe2\x80\x93to the bitter end. And you can trust us to " ..
            "keep any secret of yours\xe2\x80\x93closer than you keep it " ..
            "yourself. But you cannot trust us to let you face trouble " ..
            "alone, and go off without a word. We are your friends, Frodo."

        function rfc7520_jwk_to_pem(jwk, which)
            local key = assert(pkey.new(cjson.encode(jwk), { format = "JWK" }))
            return assert(key:tostring(which, "PEM"))
        end

        function rfc7520_b64url_decode(s)
            s = s:gsub("-", "+"):gsub("_", "/")
            return ngx.decode_base64(s .. string.rep("=", (4 - #s % 4) % 4))
        end

        -- verify and print the outcome; the payload is compared byte for byte
        function rfc7520_check(jwt, key, token, expected)
            jwt:set_payload_decoder(function(s) return s end)
            local obj = jwt:verify(key, token)
            ngx.say("alg: ", obj.header and obj.header.alg)
            ngx.say("enc: ", obj.header and obj.header.enc)
            ngx.say("verified: ", obj.verified)
            ngx.say("reason: ", obj.reason)
            ngx.say("payload matches: ", obj.payload == expected)
        end
    }
_EOC_

if ($ENV{COVERAGE}) {
    $HttpConfig =~ s/init_by_lua_block \{/init_by_lua_block {\n        require('luacov')/;
}

no_long_string();

run_tests();

__DATA__

=== TEST 1: RFC 7520 4.1 RS256 (RSA v1.5 signature)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 3
            local jwk = {
                kty = "RSA",
                kid = "bilbo.baggins@hobbiton.example",
                use = "sig",
                n = "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2" ..
                     "jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL" ..
                     "-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tp" ..
                     "e-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzw" ..
                     "OHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_" ..
                     "qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
                e = "AQAB",
            }
            -- RFC 7520 Figure 13
            local token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24u" ..
                "ZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbyw" ..
                "gZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCw" ..
                "gYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5" ..
                "vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRj" ..
                "dkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZ" ..
                "opdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4" ..
                "JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6" ..
                "x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLG" ..
                "djluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ" ..
                "41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg"
            rfc7520_check(jwt, rfc7520_jwk_to_pem(jwk, "public"), token, rfc7520_jws_payload)
        }
    }
--- request
GET /t
--- response_body
alg: RS256
enc: nil
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]


=== TEST 2: RFC 7520 4.3 ES512 (ECDSA P-521 signature)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 2
            local jwk = {
                kty = "EC",
                kid = "bilbo.baggins@hobbiton.example",
                use = "sig",
                crv = "P-521",
                x = "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTK" ..
                     "qjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                y = "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQ" ..
                     "kAgDPrwQrJmbnX9cwlGfP-HqHZR1",
                d = "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrC" ..
                     "W9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
            }
            -- RFC 7520 Figure 27
            local token = "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24u" ..
                "ZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbyw" ..
                "gZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCw" ..
                "gYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5" ..
                "vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.AE_" ..
                "R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu" ..
                "9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-k" ..
                "vAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"
            rfc7520_check(jwt, rfc7520_jwk_to_pem(jwk, "public"), token, rfc7520_jws_payload)
        }
    }
--- request
GET /t
--- response_body
alg: ES512
enc: nil
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]


=== TEST 3: RFC 7520 4.4 HS256 (HMAC-SHA2 integrity protection)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 5
            local jwk = {
                kty = "oct",
                kid = "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
                use = "sig",
                alg = "HS256",
                k = "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
            }
            -- RFC 7520 Figure 34
            local token = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2" ..
                "LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCB" ..
                "Gcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGU" ..
                "gcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmX" ..
                "igJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB" ..
                "0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
            rfc7520_check(jwt, rfc7520_b64url_decode(jwk.k), token, rfc7520_jws_payload)
        }
    }
--- request
GET /t
--- response_body
alg: HS256
enc: nil
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]


=== TEST 4: RFC 7520 5.2 RSA-OAEP with A256GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 84
            local jwk = {
                kty = "RSA",
                kid = "samwise.gamgee@hobbiton.example",
                use = "enc",
                n = "wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRrI4pP1A" ..
                     "hoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-FyXJGcTy0HdK" ..
                     "QWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnkNrg71S2CuNZSQB" ..
                     "IPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeStsqo571utNfoUTU8E4q" ..
                     "dzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M5qnZtdw-7v4WuR4779ubDu" ..
                     "J5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIUe7Tzizjg1nms0Xq_yPub_UOlWn" ..
                     "0ec85FCft1hACpWG8schrOBeNqHBODFskYpUc2LC5JA2TaPF2dA67dg1TTsC" ..
                     "_FupfQ2kNGcE1LgprxKHcVWYQb86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJf" ..
                     "NcFLlH3b8mb-H_ox35FjqBSAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_" ..
                     "TOljMVfFTWXUxlnfhOOnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5q" ..
                     "FDxDQKis99gcDaiCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfas" ..
                     "vKn0aZRsnTyC0xhWBlsolZE",
                e = "AQAB",
                alg = "RSA-OAEP",
                d = "n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bxcc0xQn" ..
                     "5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq-B3qhfF3iz" ..
                     "lbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT2LYQRxUOCf5TtJ" ..
                     "XvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9EA-KMgAjTiISXxqIXQh" ..
                     "WUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876DhkO8v4UOZLwA1OlUX98mk" ..
                     "oqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIjh1fL0gdNfihLxnclWtW7pCztLn" ..
                     "ImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r-MSH9sqbuziHN2grGjD_jfRluMHa0l" ..
                     "84fFKl6bcqN1JWxPVhzNZo01yDF-1LiQnqUYSepPf6X3a2SOdkqBRiquE6Ev" ..
                     "LuSYIDpJq3jDIsgoL8Mo1LoomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1u" ..
                     "hSR8aJAQWAiFImWH5W_IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6" ..
                     "z-tY_KuBG00-28S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_" ..
                     "mnhsPbGs0c9WsWgRzI-K8gE",
                p = "7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKghvM4hRk" ..
                     "Ovbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsYa_QZWpXB_I" ..
                     "rtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3mY46J961Y2LRnre" ..
                     "VwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-RFNhO1AoiJhYZj69hj" ..
                     "mMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9sfbZRqL94bbtE4_e0Zrpo8R" ..
                     "No8vxRLqQNwIy85fc6BRgBJomt8QdQvIgPgWCv5HoQ",
                q = "zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6ZyKQCO-O" ..
                     "6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDcqssd_uMbP-" ..
                     "DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYGRuUwfQTus0w1Nf" ..
                     "jFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJaPJN5cxjySPZPD3Vp0" ..
                     "1a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EXe2kSwVgOzvt-gsmM29QQ8v" ..
                     "eHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJJlXXnH8Q",
                dp = "19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xnx5kA7-1" ..
                      "erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQJ_ia5mxjxNj" ..
                      "S6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72FZQ5gTjXoTXC2-xt" ..
                      "CDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3iXjxqzbEanflwPvj6V9i" ..
                      "DSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGmpKdSO08kLBx8VUjkbv_3Pn2" ..
                      "0Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9LcnwwT0jvoQ",
                dq = "S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1VBEqeD-" ..
                      "1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM1ip0CCNmkms" ..
                      "mDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fgdyEwYa08pESKwwW" ..
                      "isy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrIChZlkiOdFCtxDqdmCqN" ..
                      "acnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2AycH6Ci5yjbxt4Ppox_5pjm" ..
                      "6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iznBNCeOUIQ",
                qi = "FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCciRrokxg" ..
                      "lZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80oPEf6-jJ5Iy" ..
                      "6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMwQqWFeV31XtZ8l5c" ..
                      "VI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl27DuEES0aK0WE97jnsy" ..
                      "O27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4UZxw9zsXww46wy0P6f9grnY" ..
                      "p7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq8EzqZEKIA",
            }
            local key = rfc7520_jwk_to_pem(jwk, "private")
            -- RFC 7520 Figure 92
            local token = "eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJp" ..
                "dG9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0.rT99rwrBTbTI7IJM8fU3" ..
                "Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQibeYOl5S_PJsAXZwSXt" ..
                "DePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyucvI6hvALeZ6OGnhN" ..
                "V4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58-Aad3FzMuo3Fn9" ..
                "buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8BpxKdUV9ScfJQTc" ..
                "Ym6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pKIIfux5BC6h" ..
                "uIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7pZfPYDSX" ..
                "ZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQfOTs_l" ..
                "ycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe38UjQ" ..
                "b0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU06" ..
                "MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5" ..
                "Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2oz" ..
                "DRs.-nBoKLH0YkLZPSI9.o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqB" ..
                "dpACm6UJuJowOHC5ytjqYgRL-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lT" ..
                "YxrXfVzIIaRdhYtEMRBvBWbEwP7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhN" ..
                "cizPersuhw5f-pGYzseva-TUaL8iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovE" ..
                "gj64X1I5s7E6GLp5fnbYGLa1QUiML7Cc2GxgvI7zqWo0YIEc7aCflLG1-8Bb" ..
                "oVWFdZKLK9vNoycrYHumwzKluLWEbSVmaPpOslY2n525DxDfWaVFUfKQxMF5" ..
                "6vn4B9QMpWAbnypNimbM8zVOw.UCGiqJxhBI3IFVdPalHHvA"
            rfc7520_check(jwt, key, token, rfc7520_jwe_plaintext)
        }
    }
--- request
GET /t
--- response_body
alg: RSA-OAEP
enc: A256GCM
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]


=== TEST 5: RFC 7520 5.3 PBES2-HS512+A256KW with A128CBC-HS256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 96
            local key = "entrap_o\xe2\x80\x93peter_long\xe2\x80\x93credit_tun"
            -- RFC 7520 Figure 95, without the whitespace added for readability
            local rfc7520_pbes2_plaintext = [[{"keys":[{"kty":"oct","kid":"77c7e2b8-6e13-45cf-8672-617b5b4]] ..
                [[5243a","use":"enc","alg":"A128GCM","k":"XctOhJAkA-pD9Lh7ZgW_]] ..
                [[2A"},{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac]] ..
                [[8","use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"},]] ..
                [[{"kty":"oct","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d","u]] ..
                [[se":"enc","alg":"A256GCMKW","k":"qC57l_uxcm7Nm3K-ct4GFjx8tM1]] ..
                [[U8CZ0NLBvdQstiS8"}]}]]
            -- RFC 7520 Figure 105
            local token = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNS" ..
                "M3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24i" ..
                "LCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.d3qNhUWfqheyPp4H8sjOWsDYajoe" ..
                "j4c5Je6rlUtFPWdgtURtmeDV1g.VBiCzVHNoLiR3F4V82uoTQ.23i-Tb1AV4" ..
                "n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFz" ..
                "LxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4" ..
                "q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asm" ..
                "as_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_S" ..
                "EGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKd" ..
                "PQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtr" ..
                "okAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmd" ..
                "n_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oM" ..
                "KdTw8V3kobXZ77ulMwDs4p.0HlwodAhOCILG5SQ2LQ9dg"
            rfc7520_check(jwt, key, token, rfc7520_pbes2_plaintext)
        }
    }
--- request
GET /t
--- response_body
alg: PBES2-HS512+A256KW
enc: A128CBC-HS256
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]


=== TEST 6: RFC 7520 5.4 ECDH-ES+A128KW with A128GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 108
            local jwk = {
                kty = "EC",
                kid = "peregrin.took@tuckborough.example",
                use = "enc",
                crv = "P-384",
                x = "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2Fpx" ..
                     "Bmu2",
                y = "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL" ..
                     "1ETP",
                d = "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDl" ..
                     "Zh-j",
            }
            local key = rfc7520_jwk_to_pem(jwk, "private")
            -- RFC 7520 Figure 117
            local token = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tA" ..
                "dHVja2Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6" ..
                "IlAtMzg0IiwieCI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdL" ..
                "Rlp1NHhBRkZrYllpV2d1dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVT" ..
                "R2haVkMyZmFYdW1JLWU5SlUyTW84S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lR" ..
                "VEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBMTI4R0NNIn0.0DJjBXri_kBcC46I" ..
                "kU5_Jk9BqaQeHdv2.mH-G2zVqgztUtnW_.tkZuOO9h95OgHJmkkrfLBisku8" ..
                "rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRCjSpAaUZ5dOR3Spy7QuEk" ..
                "mKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo1hIi-uEkUpOZ8" ..
                "aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3ORXaM0J" ..
                "aHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-" ..
                "nkUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVnt" ..
                "RJ6K53NgPQ5p99l3Z408OUqj4ioYezbS6vTPlQ.WuGzxmcreYjpHGJoa17EB" ..
                "g"
            rfc7520_check(jwt, key, token, rfc7520_jwe_plaintext)
        }
    }
--- request
GET /t
--- response_body
alg: ECDH-ES+A128KW
enc: A128GCM
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]


=== TEST 7: RFC 7520 5.5 ECDH-ES with A128CBC-HS256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 120
            local jwk = {
                kty = "EC",
                kid = "meriadoc.brandybuck@buckland.example",
                use = "enc",
                crv = "P-256",
                x = "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
                y = "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
                d = "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8",
            }
            local key = rfc7520_jwk_to_pem(jwk, "private")
            -- RFC 7520 Figure 128
            local token = "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0Bi" ..
                "dWNrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0y" ..
                "NTYiLCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hI" ..
                "dE5rZFlvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBG" ..
                "dzJTUzM0RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ..yc9N8v5s" ..
                "Yyv3iGQT926IUg.BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4O" ..
                "PKbWE1zSTEFjDfhU9IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqA" ..
                "YtskTTmzmzNa-_q4F_evAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNN" ..
                "kpOMQKF1Cl8i8wjzRli7-IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1" ..
                "r7URUhArM79BY8soZU0lzwI-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni" ..
                "5UZL4mYpvKDiwmyzGd65KqVw7MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5" ..
                "LmyX_yJ-3AROq8p1WZBfG-ZyJ6195_JGG2m9Csg.WCCkNa-x4BeB9hIDIfFu" ..
                "hg"
            rfc7520_check(jwt, key, token, rfc7520_jwe_plaintext)
        }
    }
--- request
GET /t
--- response_body
alg: ECDH-ES
enc: A128CBC-HS256
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]


=== TEST 8: RFC 7520 5.6 dir with A128GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 130
            local jwk = {
                kty = "oct",
                kid = "77c7e2b8-6e13-45cf-8672-617b5b45243a",
                use = "enc",
                alg = "A128GCM",
                k = "XctOhJAkA-pD9Lh7ZgW_2A",
            }
            local key = rfc7520_b64url_decode(jwk.k)
            -- RFC 7520 Figure 136
            local token = "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02" ..
                "MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0..refa467QzzKx6QAB.JW" ..
                "_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y" ..
                "hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9" ..
                "zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtB" ..
                "P-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZ" ..
                "Axscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9" ..
                "aKZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TT" ..
                "np.vbb32Xvllea2OtmHAdccRQ"
            rfc7520_check(jwt, key, token, rfc7520_jwe_plaintext)
        }
    }
--- request
GET /t
--- response_body
alg: dir
enc: A128GCM
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]


=== TEST 9: RFC 7520 5.7 A256GCMKW with A128CBC-HS256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 138
            local jwk = {
                kty = "oct",
                kid = "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
                use = "enc",
                alg = "A256GCMKW",
                k = "qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8",
            }
            local key = rfc7520_b64url_decode(jwk.k)
            -- RFC 7520 Figure 148
            local token = "eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUt" ..
                "YjIwNS0yYjRkZDFkNDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0t" ..
                "a3N3IiwiaXYiOiJLa1lUMEdYXzJqSGxmcU5fIiwiZW5jIjoiQTEyOENCQy1I" ..
                "UzI1NiJ9.lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok.gz6NjyE" ..
                "FNm_vm8Gj6FwoFQ.Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8" ..
                "EqoDZHyFKFBupS8iaEeVIgMqWmsuJKuoVgzR3YfzoMd3GxEm3VxNhzWyWtZK" ..
                "X0gxKdy6HgLvqoGNbZCzLjqcpDiF8q2_62EVAbr2uSc2oaxFmFuIQHLcqAHx" ..
                "y51449xkjZ7ewzZaGV3eFqhpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLq" ..
                "aeNQaJtvJmSMFuEOSAzw9Hdeb6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1" ..
                "_4yDJFcqb5CiDSmA-psB2k0JtjxAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG" ..
                "7h8wGjV98QhrKEnR7xKZ3KCr0_qR1B-gxpNk3xWU.DKW7jrb4WaRSNfbXVPl" ..
                "T5g"
            rfc7520_check(jwt, key, token, rfc7520_jwe_plaintext)
        }
    }
--- request
GET /t
--- response_body
alg: A256GCMKW
enc: A128CBC-HS256
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]


=== TEST 10: RFC 7520 5.8 A128KW with A128GCM
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local jwt = require "resty.jwt"
            -- RFC 7520 Figure 151
            local jwk = {
                kty = "oct",
                kid = "81b20965-8332-43d9-a468-82160ad91ac8",
                use = "enc",
                alg = "A128KW",
                k = "GZy6sIZ6wl9NJOKB-jnmVQ",
            }
            local key = rfc7520_b64url_decode(jwk.k)
            -- RFC 7520 Figure 159
            local token = "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2" ..
                "OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0.CBI6oDw8MydIx1IB" ..
                "ntf_lQcw2MmJKIQx.Qx0pmsDa8KnJc9Jo.AwliP-KmWgsZ37BvzCefNen6VT" ..
                "bRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9ADsnWgL56" ..
                "NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp" ..
                "1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53" ..
                "TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqq" ..
                "FvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRaa8Z7MOZ7UGxGIMvE" ..
                "mxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF.ER7MWJZ1FBI_NKvn7Zb1L" ..
                "w"
            rfc7520_check(jwt, key, token, rfc7520_jwe_plaintext)
        }
    }
--- request
GET /t
--- response_body
alg: A128KW
enc: A128GCM
verified: true
reason: everything is awesome~ :p
payload matches: true
--- no_error_log
[error]
