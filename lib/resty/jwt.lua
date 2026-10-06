local cjson = require "cjson.safe"

local evp = require "resty.evp"
local hmac = require "resty.hmac"
local resty_random = require "resty.random"
local cipher = require "resty.openssl.cipher"
local pkey = require "resty.openssl.pkey"
local x509 = require "resty.openssl.x509"
local digest = require "resty.openssl.digest"
local openssl_rand = require "resty.openssl.rand"
local kdf = require "resty.openssl.kdf"
local utils = require "resty.utils"
local jwt_validators = require "resty.jwt-validators"
local jwt_zlib = require "resty.jwt-zlib"
local jwk = require "resty.jwt.jwk"
local bit = require "bit"

local _M = { _VERSION = "0.3.2" }

local mt = {
    __index = _M
}

local string_rep = string.rep
local string_format = string.format
local string_sub = string.sub
local string_find = string.find
local string_char = string.char
local string_byte = string.byte
local math_floor = math.floor
local table_concat = table.concat
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64
local ngx_log = ngx.log
local ngx_DEBUG = ngx.DEBUG
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local tostring = tostring
local error = error
local ipairs = ipairs
local type = type
local pcall = pcall
local assert = assert
local setmetatable = setmetatable
local bxor = bit.bxor
local bor = bit.bor
local pairs = pairs

-- define string constants to avoid string garbage collection
local str_const = {
  invalid_jwt= "invalid jwt string",
  regex_join_msg = "%s.%s",
  regex_jwt_join_str = "%s.%s.%s",
  raw_underscore  = "raw_",
  dash = "-",
  empty = "",
  dotdot = "..",
  table  = "table",
  plus = "+",
  equal = "=",
  underscore = "_",
  slash = "/",
  header = "header",
  typ = "typ",
  JWT = "JWT",
  JWE = "JWE",
  payload = "payload",
  signature = "signature",
  encrypted_key = "encrypted_key",
  alg = "alg",
  enc = "enc",
  kid = "kid",
  exp = "exp",
  nbf = "nbf",
  iss = "iss",
  full_obj = "__jwt",
  header_specs = "__header",
  crit = "crit",
  x5c = "x5c",
  x5u = 'x5u',
  HS256 = "HS256",
  HS384 = "HS384",
  HS512 = "HS512",
  RS256 = "RS256",
  RS384 = "RS384",
  RS512 = "RS512",
  PS256 = "PS256",
  PS384 = "PS384",
  PS512 = "PS512",
  ES256 = "ES256",
  ES384 = "ES384",
  ES512 = "ES512",
  Ed25519 = "Ed25519",
  Ed448 = "Ed448",
  EdDSA = "EdDSA",
  A128CBC_HS256 = "A128CBC-HS256",
  A128CBC_HS256_CIPHER_MODE = "aes-128-cbc",
  A256CBC_HS512 = "A256CBC-HS512",
  A256CBC_HS512_CIPHER_MODE = "aes-256-cbc",
  A256GCM = "A256GCM",
  A256GCM_CIPHER_MODE = "aes-256-gcm",
  A192CBC_HS384 = "A192CBC-HS384",
  A192CBC_HS384_CIPHER_MODE = "aes-192-cbc",
  A128GCM = "A128GCM",
  A128GCM_CIPHER_MODE = "aes-128-gcm",
  A192GCM = "A192GCM",
  A192GCM_CIPHER_MODE = "aes-192-gcm",
  RSA_OAEP = "RSA-OAEP",
  RSA_OAEP_256 = "RSA-OAEP-256",
  RSA_OAEP_384 = "RSA-OAEP-384",
  RSA_OAEP_512 = "RSA-OAEP-512",
  ECDH_ES = "ECDH-ES",
  ECDH_ES_A128KW = "ECDH-ES+A128KW",
  ECDH_ES_A192KW = "ECDH-ES+A192KW",
  ECDH_ES_A256KW = "ECDH-ES+A256KW",
  A128KW = "A128KW",
  A192KW = "A192KW",
  A256KW = "A256KW",
  A128GCMKW = "A128GCMKW",
  A192GCMKW = "A192GCMKW",
  A256GCMKW = "A256GCMKW",
  PBES2_HS256_A128KW = "PBES2-HS256+A128KW",
  PBES2_HS384_A192KW = "PBES2-HS384+A192KW",
  PBES2_HS512_A256KW = "PBES2-HS512+A256KW",
  DIR = "dir",
  zip = "zip",
  DEF = "DEF",
  reason = "reason",
  verified = "verified",
  number = "number",
  string = "string",
  funct = "function",
  boolean = "boolean",
  valid = "valid",
  valid_issuers = "valid_issuers",
  lifetime_grace_period = "lifetime_grace_period",
  require_nbf_claim = "require_nbf_claim",
  require_exp_claim = "require_exp_claim",
  pem_begin = "-----BEGIN",
  internal_error = "internal error",
  jwe_decrypt_failed = "failed to decrypt JWE",
  everything_awesome = "everything is awesome~ :p"
}

-- @function split a compact serialization on ".", keeping empty parts
-- (a JWE using "dir" or "ECDH-ES" has an empty encrypted key). Stops after 6
-- parts: anything beyond 5 is invalid anyway.
local function split_token(str)
  local parts = {}
  local start = 1
  while #parts < 6 do
    local dot = string_find(str, ".", start, true)
    if not dot then
      parts[#parts + 1] = string_sub(str, start)
      break
    end
    parts[#parts + 1] = string_sub(str, start, dot - 1)
    start = dot + 1
  end
  return parts
end

-- @function is nil or boolean
-- @return true if param is nil or true or false; false otherwise
local function is_nil_or_boolean(arg_value)
    if arg_value == nil then
        return true
    end

    if type(arg_value) ~= str_const.boolean then
        return false
    end

    return true
end

--@function get the raw part
--@param part_name
--@param jwt_obj
local function get_raw_part(part_name, jwt_obj)
  local raw_part = jwt_obj[str_const.raw_underscore .. part_name]
  if raw_part == nil then
    local part = jwt_obj[part_name]
    if part == nil then
      error({reason="missing part " .. part_name})
    end
    raw_part = _M:jwt_encode(part)
  end
  return raw_part
end


-- CEK length in bits per "enc". Also the RFC 7518 Section 4.6.2 Concat KDF
-- keydatalen for ECDH-ES direct key agreement, which derives the CEK itself
local keydatalen_map = {
  [str_const.A128GCM] = 128,
  [str_const.A192GCM] = 192,
  [str_const.A256GCM] = 256,
  [str_const.A128CBC_HS256] = 256,
  [str_const.A192CBC_HS384] = 384,
  [str_const.A256CBC_HS512] = 512,
}

-- ECDH-ES+A*KW derives the key wrapping key, so keydatalen is the AES-KW key size
local ecdh_es_kw_keydatalen = {
  [str_const.ECDH_ES_A128KW] = 128,
  [str_const.ECDH_ES_A192KW] = 192,
  [str_const.ECDH_ES_A256KW] = 256,
}

-- Curves allowed for ECDH-ES (RFC 7518 Section 6.2.1.1): OpenSSL NID -> curve names
local ecdh_curves_by_nid = {
  [415] = { openssl = "prime256v1", jwk = "P-256" },
  [715] = { openssl = "secp384r1", jwk = "P-384" },
  [716] = { openssl = "secp521r1", jwk = "P-521" },
}

local ecdh_nid_by_crv = {}
for nid, curve in pairs(ecdh_curves_by_nid) do
  ecdh_nid_by_crv[curve.jwk] = nid
end

-- strict base64url (RFC 7515 Section 2): URL-safe alphabet, no padding
local function decode_base64url_strict(value)
  if type(value) ~= str_const.string or value:find("[^%w%-_]") or #value % 4 == 1 then
    return nil
  end
  return _M:jwt_decode(value)
end

-- "apu"/"apv" carry the base64url encoded PartyUInfo/PartyVInfo; absent means empty
local function decode_party_info(header, name)
  local value = header[name]
  if value == nil then
    return str_const.empty
  end
  local decoded = decode_base64url_strict(value)
  if not decoded then
    error({reason="invalid " .. name .. " in JWE header"})
  end
  return decoded
end

-- RFC 7518 Section 4.6.2: AlgorithmID is the "enc" value for ECDH-ES direct key
-- agreement and the "alg" value (e.g. "ECDH-ES+A128KW") when the derived key is
-- used to wrap the CEK.
local function derive_shared_key(header, shared_secret_Z)
    local alg = header.alg
    local algorithm_id, keydatalen
    if alg == str_const.ECDH_ES then
        algorithm_id = header.enc
        keydatalen = keydatalen_map[algorithm_id]
    else
        algorithm_id = alg
        keydatalen = ecdh_es_kw_keydatalen[alg]
    end
    if not keydatalen then
        error({reason="unsupported algorithm for ECDH-ES key derivation: " .. tostring(algorithm_id)})
    end

    return utils.concat_kdf(shared_secret_Z, algorithm_id, keydatalen,
        decode_party_info(header, "apu"), decode_party_info(header, "apv"))
end

-- DEPRECATED, to be removed in 1.0 together with set_legacy_ecdh_kw_kdf.
-- v0.3.0 - v0.3.2 derived the ECDH-ES+A*KW key wrapping key with AlgorithmID
-- "A128KW"/"A192KW"/"A256KW" and decoded apu/apv as standard base64, silently
-- ignoring values that failed to decode. Only ever used to decrypt.
local legacy_ecdh_kw_algorithm_id = {
  [str_const.ECDH_ES_A128KW] = str_const.A128KW,
  [str_const.ECDH_ES_A192KW] = str_const.A192KW,
  [str_const.ECDH_ES_A256KW] = str_const.A256KW,
}

local function derive_legacy_ecdh_kw_key(header, shared_secret_Z)
    local alg = header.alg
    local apu = type(header.apu) == str_const.string and ngx_decode_base64(header.apu) or str_const.empty
    local apv = type(header.apv) == str_const.string and ngx_decode_base64(header.apv) or str_const.empty
    return utils.concat_kdf(shared_secret_Z, legacy_ecdh_kw_algorithm_id[alg],
        ecdh_es_kw_keydatalen[alg], apu, apv)
end

--- DEPRECATED, to be removed in 1.0.
-- Also accept ECDH-ES+A128KW/A192KW/A256KW tokens produced by lua-resty-jwt
-- v0.3.0 - v0.3.2, which used a non-standard Concat KDF (see
-- derive_legacy_ecdh_kw_key). When enabled, decryption tries the RFC 7518
-- derivation first and falls back to the legacy one. Signing always produces
-- RFC 7518 tokens. Disabled by default.
function _M.set_legacy_ecdh_kw_kdf(self, enabled)
  self.legacy_ecdh_kw_kdf = enabled and true or false
end

_M.legacy_ecdh_kw_kdf = false

-- RFC 7518 Section 4.6: validate the ephemeral public key ("epk") against the
-- recipient's EC private key and compute the ECDH shared secret Z
--@param private_key_pem the EC private key: a PEM string or a
-- resty.openssl.pkey (from a JWK or key object); the same checks apply to both
local function ecdh_es_shared_secret(header, private_key_pem)
    if not private_key_pem then
        error({reason="EC private key must not be null"})
    end
    local epk_jwk = header.epk
    if type(epk_jwk) ~= str_const.table then
        error({reason="missing epk in JWE header"})
    end
    if epk_jwk.kty ~= "EC" then
        error({reason="unsupported epk key type"})
    end
    local epk_nid = ecdh_nid_by_crv[epk_jwk.crv]
    if not epk_nid then
        error({reason="unsupported epk curve"})
    end
    if epk_jwk.d ~= nil then
        error({reason="epk must not contain a private key"})
    end
    if type(epk_jwk.x) ~= str_const.string or type(epk_jwk.y) ~= str_const.string then
        error({reason="invalid epk in JWE header"})
    end

    local private_key, priv_err = private_key_pem, nil
    if not pkey.istype(private_key) then
        private_key, priv_err = pkey.new(private_key_pem)
    end
    if not private_key then
        error({reason="failed to load EC private key: " .. (priv_err or "")})
    end
    local params = private_key:is_private() and private_key:get_parameters()
    if not params or not params.group then
        error({reason="ECDH-ES requires an EC private key"})
    end
    if params.group ~= epk_nid then
        error({reason="epk curve does not match the EC private key"})
    end

    -- only the public coordinates are passed on. The import rejects points that are
    -- not on the curve, which ECDH with a static key relies on (invalid curve attack)
    local epk, epk_err = pkey.new(cjson_encode({
        kty = epk_jwk.kty, crv = epk_jwk.crv, x = epk_jwk.x, y = epk_jwk.y,
    }), { format = "JWK" })
    if not epk then
        error({reason="failed to load ephemeral public key: " .. (epk_err or "")})
    end
    local Z, derive_err = private_key:derive(epk)
    if not Z then
        error({reason="ECDH key derivation failed: " .. (derive_err or "")})
    end
    return Z
end

-- generate the sender's ephemeral key on the recipient's curve and compute Z
local function ecdh_es_ephemeral_agreement(header, public_key_pem)
    local public_key, pub_err = pkey.new(public_key_pem)
    if not public_key then
        error({reason="failed to load EC public key: " .. (pub_err or "")})
    end
    local params, param_err = public_key:get_parameters()
    if not params then
        error({reason="failed to get EC key parameters: " .. (param_err or "")})
    end
    local curve = ecdh_curves_by_nid[params.group]
    if not curve then
        error({reason="unsupported EC curve NID: " .. tostring(params.group)})
    end
    local ephemeral, eph_err = pkey.new({ type = "EC", curve = curve.openssl })
    if not ephemeral then
        error({reason="failed to generate ephemeral EC key: " .. (eph_err or "")})
    end
    local epk = cjson_decode(ephemeral:tostring("public", "JWK"))
    header.epk = { kty = epk.kty, crv = epk.crv, x = epk.x, y = epk.y }
    local Z, derive_err = ephemeral:derive(public_key)
    if not Z then
        error({reason="ECDH key derivation failed: " .. (derive_err or "")})
    end
    return Z
end

--@function raise the single, generic JWE decryption failure.
-- Every authentication/decryption failure (bad tag or MAC, bad padding, key
-- unwrap failure, wrong key) must look the same to the caller so the reason
-- cannot be used as an oracle. Details go to the debug log only; never pass
-- key material or plaintext in `detail`.
local function jwe_decrypt_error(detail)
  ngx_log(ngx_DEBUG, "JWE decryption failed: ", detail)
  error({reason=str_const.jwe_decrypt_failed})
end

--@function check that an unwrapped/decrypted CEK has the size required by enc
local function check_cek_len(enc, cek)
  if #cek * 8 ~= keydatalen_map[enc] then
    jwe_decrypt_error("unexpected CEK length for " .. enc)
  end
  return cek
end

-- AES Key Wrap (RFC 3394) default IV
local AES_KW_DEFAULT_IV = string_char(0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6)

local function aes_kw_mode(kek)
    local len = #kek
    if len == 16 then return "aes-128-wrap"
    elseif len == 24 then return "aes-192-wrap"
    else return "aes-256-wrap" end
end

local function aes_key_wrap(kek, plaintext_key)
    local mode = aes_kw_mode(kek)
    local c = assert(cipher.new(mode))
    local wrapped, err = c:encrypt(kek, AES_KW_DEFAULT_IV, plaintext_key, false)
    if not wrapped then
        error({reason="AES key wrap failed: " .. (err or "")})
    end
    return wrapped
end

local function aes_key_unwrap(kek, wrapped_key)
    local mode = aes_kw_mode(kek)
    local c = assert(cipher.new(mode))
    local unwrapped, err = c:decrypt(kek, AES_KW_DEFAULT_IV, wrapped_key, false)
    if not unwrapped then
        jwe_decrypt_error("AES key unwrap failed: " .. (err or ""))
    end
    return unwrapped
end

local function gcm_kw_mode(kek)
    local len = #kek
    if len == 16 then return "aes-128-gcm"
    elseif len == 24 then return "aes-192-gcm"
    else return "aes-256-gcm" end
end

local function aes_gcm_key_wrap(kek, plaintext_key)
    local mode = gcm_kw_mode(kek)
    local c = assert(cipher.new(mode))
    local iv = openssl_rand.bytes(12)
    local encrypted, err = c:encrypt(kek, iv, plaintext_key, false, nil, 16)
    if not encrypted then
        error({reason="AES-GCM key wrap failed: " .. (err or "")})
    end
    local tag = c:get_aead_tag(16)
    return encrypted, iv, tag
end

local function aes_gcm_key_unwrap(kek, wrapped_key, iv, tag)
    -- RFC 7518 4.7.1: 96-bit IV and 128-bit tag. OpenSSL would otherwise accept
    -- a truncated tag (1-16 bytes) and only compare that many bytes.
    if #iv ~= 12 or #tag ~= 16 then
        error({reason="invalid iv/tag length in header for AES-GCM key wrap"})
    end
    local mode = gcm_kw_mode(kek)
    local c = assert(cipher.new(mode))
    local decrypted, err = c:decrypt(kek, iv, wrapped_key, false, nil, tag)
    if not decrypted then
        jwe_decrypt_error("AES-GCM key unwrap failed: " .. (err or ""))
    end
    return decrypted
end

local kdf_derive = kdf.derive or kdf.derive_legacy

local pbes2_config = {
    ["PBES2-HS256+A128KW"] = { md = "sha256", keylen = 16 },
    ["PBES2-HS384+A192KW"] = { md = "sha384", keylen = 24 },
    ["PBES2-HS512+A256KW"] = { md = "sha512", keylen = 32 },
}

-- PBES2 "p2c" bounds. RFC 7518 4.8.1.2 recommends a minimum of 1000. The
-- count is attacker controlled and PBKDF2 runs synchronously in the nginx
-- worker, so the upper bound caps the CPU one token can burn; adjustable with
-- jwt:set_pbes2_max_count(). The default matches panva/jose (10000) and is
-- well above what this library signs with (4096); raise it only if you must
-- accept tokens from producers using larger counts (go-jose hard-caps 1000000).
local PBES2_MIN_COUNT = 1000
local PBES2_DEFAULT_MAX_COUNT = 10000
-- RFC 7518 4.8.1.1: the salt input must be at least 8 octets
local PBES2_MIN_SALT_LEN = 8

local function pbes2_derive_kek(alg, password, p2s_raw, p2c)
    local cfg = pbes2_config[alg]
    if not cfg then
        error({reason="unsupported PBES2 algorithm: " .. alg})
    end
    local salt = alg .. string_char(0) .. p2s_raw
    local kek, err = kdf_derive({
        type = kdf.PBKDF2,
        outlen = cfg.keylen,
        pass = password,
        salt = salt,
        pbkdf2_iter = p2c,
        md = cfg.md,
    })
    if not kek then
        error({reason="PBES2 key derivation failed: " .. (err or "")})
    end
    return kek
end

-- Required IV and authentication tag lengths (octets) per JWE "enc"
-- (RFC 7518 5.2.3-5.2.5 and 5.3). Tags of any other length must be rejected:
-- OpenSSL accepts truncated GCM tags, which would make forgery trivial.
local jwe_enc_lengths = {
  [str_const.A128CBC_HS256] = { iv = 16, tag = 16 },
  [str_const.A192CBC_HS384] = { iv = 16, tag = 24 },
  [str_const.A256CBC_HS512] = { iv = 16, tag = 32 },
  [str_const.A128GCM] = { iv = 12, tag = 16 },
  [str_const.A192GCM] = { iv = 12, tag = 16 },
  [str_const.A256GCM] = { iv = 12, tag = 16 },
}

--@function decrypt payload
--@param secret_key to decrypt the payload
--@param encrypted payload
--@param encryption algorithm
--@param iv which was generated while encrypting the payload
--@param aad additional authenticated data (used when gcm mode is used)
--@param auth_tag authenticated tag (used when gcm mode is used)
--@return decrypted payloaf
local function decrypt_payload(secret_key, encrypted_payload, enc, iv_in, aad, auth_tag )
  local decrypted_payload, err
  if enc == str_const.A128CBC_HS256 then
    local aes_128_cbs_cipher = assert(cipher.new(str_const.A128CBC_HS256_CIPHER_MODE))
    decrypted_payload, err=  aes_128_cbs_cipher:decrypt(secret_key, iv_in, encrypted_payload)
  elseif enc == str_const.A192CBC_HS384 then
    local aes_192_cbs_cipher = assert(cipher.new(str_const.A192CBC_HS384_CIPHER_MODE))
    decrypted_payload, err =  aes_192_cbs_cipher:decrypt(secret_key, iv_in, encrypted_payload)
  elseif enc == str_const.A256CBC_HS512 then
    local aes_256_cbs_cipher = assert(cipher.new(str_const.A256CBC_HS512_CIPHER_MODE))
    decrypted_payload, err =  aes_256_cbs_cipher:decrypt(secret_key, iv_in, encrypted_payload)
  elseif enc == str_const.A256GCM then
    local aes_256_gcm_cipher = assert(cipher.new(str_const.A256GCM_CIPHER_MODE))
    decrypted_payload, err =  aes_256_gcm_cipher:decrypt(secret_key, iv_in, encrypted_payload, false, aad, auth_tag)
  elseif enc == str_const.A192GCM then
    local aes_192_gcm_cipher = assert(cipher.new(str_const.A192GCM_CIPHER_MODE))
    decrypted_payload, err =  aes_192_gcm_cipher:decrypt(secret_key, iv_in, encrypted_payload, false, aad, auth_tag)
  elseif enc == str_const.A128GCM then
    local aes_128_gcm_cipher = assert(cipher.new(str_const.A128GCM_CIPHER_MODE))
    decrypted_payload, err =  aes_128_gcm_cipher:decrypt(secret_key, iv_in, encrypted_payload, false, aad, auth_tag)
  else
    return nil, "unsupported enc: " .. enc
  end
  if not  decrypted_payload or err then
    return nil, err
  end
  return decrypted_payload
end

-- @function  encrypt payload using given secret
-- @param secret_key secret key to encrypt
-- @param message  data to be encrypted. It could be lua table or string
-- @param enc algorithm to use for encryption
-- @param aad additional authenticated data (used when gcm mode is used)
local function encrypt_payload(secret_key, message, enc, aad )

  if enc == str_const.A128CBC_HS256 then
    local iv_rand =  resty_random.bytes(16,true)
    local aes_128_cbs_cipher = assert(cipher.new(str_const.A128CBC_HS256_CIPHER_MODE))
    local encrypted = aes_128_cbs_cipher:encrypt(secret_key, iv_rand, message)
    return encrypted, iv_rand

  elseif enc == str_const.A192CBC_HS384 then
    local iv_rand =  resty_random.bytes(16,true)
    local aes_192_cbs_cipher = assert(cipher.new(str_const.A192CBC_HS384_CIPHER_MODE))
    local encrypted = aes_192_cbs_cipher:encrypt(secret_key, iv_rand, message)
    return encrypted, iv_rand

  elseif enc == str_const.A256CBC_HS512 then
    local iv_rand =  resty_random.bytes(16,true)
    local aes_256_cbs_cipher = assert(cipher.new(str_const.A256CBC_HS512_CIPHER_MODE))
    local encrypted = aes_256_cbs_cipher:encrypt(secret_key, iv_rand, message)
    return encrypted, iv_rand

  elseif enc == str_const.A256GCM then
    local iv_rand =  resty_random.bytes(12,true) -- 96 bit IV is recommended for efficiency
    local aes_256_gcm_cipher = assert(cipher.new(str_const.A256GCM_CIPHER_MODE))
    local encrypted = aes_256_gcm_cipher:encrypt(secret_key, iv_rand, message, false, aad)
    local auth_tag = assert(aes_256_gcm_cipher:get_aead_tag(16))
    return encrypted, iv_rand, auth_tag

  elseif enc == str_const.A192GCM then
    local iv_rand =  resty_random.bytes(12,true)
    local aes_192_gcm_cipher = assert(cipher.new(str_const.A192GCM_CIPHER_MODE))
    local encrypted = aes_192_gcm_cipher:encrypt(secret_key, iv_rand, message, false, aad)
    local auth_tag = assert(aes_192_gcm_cipher:get_aead_tag(16))
    return encrypted, iv_rand, auth_tag

  elseif enc == str_const.A128GCM then
    local iv_rand =  resty_random.bytes(12,true)
    local aes_128_gcm_cipher = assert(cipher.new(str_const.A128GCM_CIPHER_MODE))
    local encrypted = aes_128_gcm_cipher:encrypt(secret_key, iv_rand, message, false, aad)
    local auth_tag = assert(aes_128_gcm_cipher:get_aead_tag(16))
    return encrypted, iv_rand, auth_tag

  else
    return nil, nil , nil, "unsupported enc: " .. enc
  end
end

--@function hmac_digest : generate hmac digest based on key for input message
--@param mac_key
--@param input message
--@return hmac digest
local function hmac_digest(enc, mac_key, message)
  if enc == str_const.A128CBC_HS256 then
    return hmac:new(mac_key, hmac.ALGOS.SHA256):final(message)
  elseif enc == str_const.A192CBC_HS384 then
    return hmac:new(mac_key, hmac.ALGOS.SHA384):final(message)
  elseif enc == str_const.A256CBC_HS512 then
    return hmac:new(mac_key, hmac.ALGOS.SHA512):final(message)
  else
    error({reason="unsupported enc: " .. enc})
  end
end

-- AL: 64-bit big-endian bit length of the AAD (RFC 7518 5.2.2.1)
-- https://tools.ietf.org/html/rfc7516#appendix-B.3
local function binlen(s)
  if type(s) ~= 'string' then return end

  local len = 8 * #s

  return string_char(len / 0x0100000000000000 % 0x100)
      .. string_char(len / 0x0001000000000000 % 0x100)
      .. string_char(len / 0x0000010000000000 % 0x100)
      .. string_char(len / 0x0000000100000000 % 0x100)
      .. string_char(len / 0x0000000001000000 % 0x100)
      .. string_char(len / 0x0000000000010000 % 0x100)
      .. string_char(len / 0x0000000000000100 % 0x100)
      .. string_char(len / 0x0000000000000001 % 0x100)
end

--@function constant time string comparison (length mismatch returns false)
local function constant_time_equals(a, b)
  if type(a) ~= str_const.string or type(b) ~= str_const.string or #a ~= #b then
    return false
  end
  local acc = 0
  for i = 1, #a do
    acc = bor(acc, bxor(string_byte(a, i), string_byte(b, i)))
  end
  return acc == 0
end

--@function compute the A*CBC-HS* authentication tag (RFC 7518 5.2.2.1)
--@return first half of HMAC(mac_key, AAD || IV || ciphertext || AL)
local function cbc_hs_auth_tag(enc, mac_key, aad, iv, cipher_text)
  local mac_input = table_concat({aad, iv, cipher_text, binlen(aad)})
  local mac = hmac_digest(enc, mac_key, mac_input)
  return string_sub(mac, 1, #mac / 2)
end

--@function dervice keys: it generates key if null based on encryption algorithm
--@param encryption type
--@param secret key
--@return secret key, mac key and encryption key
local function derive_keys(enc, secret_key)
  local mac_key_len, enc_key_len = 16, 16

  if enc == str_const.A256GCM then
    mac_key_len, enc_key_len = 0, 32
  elseif enc == str_const.A192GCM then
    mac_key_len, enc_key_len = 0, 24
  elseif enc == str_const.A128GCM then
    mac_key_len, enc_key_len = 0, 16
  elseif enc == str_const.A128CBC_HS256 then
    mac_key_len, enc_key_len = 16, 16
  elseif enc == str_const.A192CBC_HS384 then
    mac_key_len, enc_key_len = 24, 24
  elseif enc == str_const.A256CBC_HS512 then
    mac_key_len, enc_key_len = 32, 32
  else
    error({reason="unsupported payload encryption algorithm :" .. enc})
  end

  local secret_key_len = mac_key_len + enc_key_len

  if not secret_key then
    secret_key =  resty_random.bytes(secret_key_len, true)
  end

  if #secret_key ~= secret_key_len then
    error({reason="invalid pre-shared key"})
  end

  local mac_key = string_sub(secret_key, 1, mac_key_len)
  local enc_key = string_sub(secret_key, mac_key_len + 1)
  return secret_key, mac_key, enc_key
end

-- marks a JWE object whose tag/MAC was verified by parse_jwe; not forgeable
-- by callers building jwt objects by hand
local JWE_AUTHENTICATED = {}

local function get_payload_encoder(self)
    return self.payload_encoder or cjson_encode
end

local function get_payload_decoder(self)
    return self.payload_decoder or cjson_decode
end

-- Header Parameters registered by RFC 7515 (JWS), RFC 7516 (JWE) and RFC 7518
-- (JWA). "crit" must never list them (RFC 7515 4.1.11, RFC 7516 4.1.13).
local registered_header_params = {
  alg = true, jku = true, jwk = true, kid = true, x5u = true, x5c = true,
  x5t = true, ["x5t#S256"] = true, typ = true, cty = true, crit = true,
  enc = true, zip = true, epk = true, apu = true, apv = true, iv = true,
  tag = true, p2s = true, p2c = true,
}

local crit_malformed = "invalid crit header: must be a non-empty array of strings"

--@function check the "crit" header parameter (RFC 7515 4.1.11). Fails closed:
-- every listed name must be an extension declared via set_crit_whitelist.
--@return nil if the header is acceptable, failure reason otherwise
local function crit_error(self, header)
  local crit = header[str_const.crit]
  if crit == nil then
    return nil
  end
  local n = type(crit) == str_const.table and #crit or 0
  if n == 0 then
    return crit_malformed
  end
  local count = 0
  for _ in pairs(crit) do
    count = count + 1
  end
  if count ~= n then
    return crit_malformed
  end

  local understood = self and self.crit_whitelist
  local seen = {}
  for i = 1, n do
    local name = crit[i]
    if type(name) ~= str_const.string then
      return crit_malformed
    end
    if seen[name] then
      return "invalid crit header: duplicate name " .. name
    end
    seen[name] = true
    if registered_header_params[name] then
      return "invalid crit header: lists registered header parameter " .. name
    end
    if header[name] == nil then
      return "invalid crit header: lists absent header parameter " .. name
    end
    if not (understood and understood[name]) then
      return "unsupported critical header parameter: " .. name
    end
  end
  return nil
end

-- JWE "zip" header parameter handlers (RFC 7516 4.1.3), keyed by zip value.
-- Each handler is a table { deflate = fn(bytes)->bytes,err
--                           inflate = fn(bytes, max_size)->bytes,err }.
-- These built-ins are never mutated: jwt:register_compression_alg stores a
-- fresh table on the object it is called on (see get_compression_alg).
-- "DEF" is built in when the system zlib can be loaded through the FFI; it is
-- only used to compress when the caller's JWE header asks for zip=DEF.
local builtin_compression_algs = {}
if jwt_zlib.available then
  builtin_compression_algs[str_const.DEF] = {
    deflate = jwt_zlib.deflate,
    inflate = jwt_zlib.inflate,
  }
end

-- An inflated JWE payload may be at most max(250 KiB, 10x the compressed
-- size) unless jwt:set_zip_max_size sets an explicit cap (cf. go-jose,
-- CVE-2024-28180).
local ZIP_DEFAULT_MAX_SIZE = 250 * 1024
local ZIP_DEFAULT_MAX_RATIO = 10

local function get_compression_alg(self, zip)
  local algs = self and self.compression_algs
  local handler = algs and algs[zip]
  if handler == nil then
    handler = builtin_compression_algs[zip]
  end
  return handler
end

--@function look up the handler for a JWE "zip" header value, raising on an
-- unknown or malformed value
local function require_compression_alg(self, zip)
  if type(zip) ~= str_const.string then
    error({reason="invalid zip in JWE header"})
  end
  local handler = get_compression_alg(self, zip)
  if not handler then
    error({reason="unsupported zip: " .. zip})
  end
  return handler
end

local function get_zip_max_size(self, compressed_len)
  local max_size = self and self.zip_max_size
  if max_size then
    return max_size
  end
  max_size = compressed_len * ZIP_DEFAULT_MAX_RATIO
  if max_size < ZIP_DEFAULT_MAX_SIZE then
    max_size = ZIP_DEFAULT_MAX_SIZE
  end
  return max_size
end

--@function true if s is exactly one DER SEQUENCE (its outer length matches
-- the string length): the cheap test before parsing s as a key or certificate
local function is_der_sequence(s)
  local n = #s
  if n < 2 or string_byte(s, 1) ~= 0x30 then
    return false
  end
  local b = string_byte(s, 2)
  if b < 0x80 then
    return n == 2 + b
  end
  local nb = b - 0x80
  if nb < 1 or nb > 3 or n < 2 + nb then
    return false
  end
  local len = 0
  for i = 3, 2 + nb do
    len = len * 256 + string_byte(s, i)
  end
  return n == 2 + nb + len
end

--@function why a string can't be used as a symmetric secret (HMAC key, AES
-- key wrap key, PBES2 password). Asymmetric key material is typically public,
-- so accepting it as a shared secret lets anyone forge tokens (RS/HS key
-- confusion, CVE-2015-9235).
--@param secret string
--@param what "an HMAC secret" or "a symmetric key", for the reason
--@return nil if acceptable, failure reason otherwise
local function symmetric_secret_rejection(secret, what)
  if secret == str_const.empty then
    return "empty secret"
  end
  if secret:find(str_const.pem_begin, 1, true) then
    return "PEM key material cannot be used as " .. what
  end
  if is_der_sequence(secret)
      and (pkey.new(secret, { format = "DER" }) or x509.new(secret, "DER")) then
    return "DER key material cannot be used as " .. what
  end
  return nil
end

-- AES key wrap algorithms -> required key size in octets (RFC 7518 4.4,
-- 4.7). The wrap mode must follow the alg, never the length of the key.
local kw_key_lengths = {
  [str_const.A128KW] = 16, [str_const.A192KW] = 24, [str_const.A256KW] = 32,
  [str_const.A128GCMKW] = 16, [str_const.A192GCMKW] = 24, [str_const.A256GCMKW] = 32,
}

--@function raise unless `key` has the size required by the AES key wrap alg
local function check_kw_key_len(alg, key)
  local expected = kw_key_lengths[alg]
  if expected and #key ~= expected then
    error({reason="invalid key for " .. alg .. ": expected a " .. expected .. "-byte key"})
  end
end

-- symmetric JWE key management algorithms: the key is a shared secret
local symmetric_jwe_algs = {
  [str_const.DIR] = true,
  [str_const.A128KW] = true, [str_const.A192KW] = true, [str_const.A256KW] = true,
  [str_const.A128GCMKW] = true, [str_const.A192GCMKW] = true, [str_const.A256GCMKW] = true,
  [str_const.PBES2_HS256_A128KW] = true, [str_const.PBES2_HS384_A192KW] = true,
  [str_const.PBES2_HS512_A256KW] = true,
}

--@function select the key for a token from a key object, JWK, JWK Set, pkey
-- or x509 secret (see resty.jwt.jwk)
--@param purpose "verify", "sign" or "decrypt"
--@return key set entry; nil if `secret` is a plain (string/function) secret;
-- nil, reason if no usable key
local function select_key(secret, alg, header, purpose)
  local keyset, err = jwk.to_keyset(secret)
  if not keyset then
    return nil, err
  end
  return jwk.select(keyset, alg, header[str_const.kid], purpose)
end

--@function check that a JWE decryption key fits the key management alg
--@return nil if it does, failure reason otherwise
local function check_jwe_key_type(alg, pk)
  local ok, key_type = pcall(pk.get_key_type, pk)
  local sn = ok and type(key_type) == str_const.table and key_type.sn or nil
  if alg == str_const.RSA_OAEP or alg == str_const.RSA_OAEP_256
      or alg == str_const.RSA_OAEP_384 or alg == str_const.RSA_OAEP_512 then
    if sn == "rsaEncryption" then
      return nil
    end
    return "key type mismatch: alg " .. alg .. " requires an RSA key"
  end
  -- ECDH-ES*: the epk validation in ecdh_es_shared_secret is EC only
  if sn == "id-ecPublicKey" then
    return nil
  end
  return "key type mismatch: alg " .. alg .. " requires an EC key"
end

--@function resolve the key a JWE is decrypted with
--@return for symmetric algs the raw secret; for RSA-OAEP/ECDH-ES a
-- resty.openssl.pkey, or the PEM string as given (legacy path); nil if no key
local function get_jwe_key(secret, alg, header)
  if secret == nil then
    return nil
  end
  local entry, reason = select_key(secret, alg, header, "decrypt")
  if reason then
    error({reason=reason})
  end

  if symmetric_jwe_algs[alg] then
    local key = entry and entry.k or secret
    if type(key) ~= str_const.string then
      error({reason="invalid key for " .. alg .. ": expected a string or an oct JWK"})
    end
    local rejection = symmetric_secret_rejection(key, "a symmetric key")
    if rejection then
      error({reason="invalid key for " .. alg .. ": " .. rejection})
    end
    check_kw_key_len(alg, key)
    return key
  end

  if not entry then
    -- PEM strings are loaded in the alg branches, as before
    if type(secret) ~= str_const.string then
      error({reason="invalid key for " .. alg .. ": expected a PEM string, a JWK or a key object"})
    end
    return secret
  end
  local pk, err = jwk.get_pkey(entry)
  if not pk then
    error({reason=err})
  end
  local key_err = check_jwe_key_type(alg, pk)
  if key_err then
    error({reason=key_err})
  end
  return pk
end

--@function parse_jwe
--@param pre-shared key
--@encoded-header
local function parse_jwe(self, preshared_key, encoded_header, encoded_encrypted_key, encoded_iv, encoded_cipher_text, encoded_auth_tag)


  local header = _M:jwt_decode(encoded_header, true)
  if type(header) ~= str_const.table then
    error({reason="invalid header: " .. encoded_header})
  end
  local crit_err = crit_error(self, header)
  if crit_err then
    error({reason=crit_err})
  end

  local alg = header.alg
  if type(alg) ~= str_const.string then
    error({reason="missing or invalid alg in JWE header"})
  end
  if alg ~= str_const.DIR and alg ~= str_const.RSA_OAEP
      and alg ~= str_const.RSA_OAEP_256 and alg ~= str_const.RSA_OAEP_384
      and alg ~= str_const.RSA_OAEP_512 and alg ~= str_const.ECDH_ES
      and alg ~= str_const.ECDH_ES_A128KW and alg ~= str_const.ECDH_ES_A192KW and alg ~= str_const.ECDH_ES_A256KW
      and alg ~= str_const.A128KW and alg ~= str_const.A192KW and alg ~= str_const.A256KW
      and alg ~= str_const.A128GCMKW and alg ~= str_const.A192GCMKW and alg ~= str_const.A256GCMKW
      and alg ~= str_const.PBES2_HS256_A128KW and alg ~= str_const.PBES2_HS384_A192KW and alg ~= str_const.PBES2_HS512_A256KW then
    error({reason="invalid algorithm: " .. alg})
  end

  local enc = header.enc
  if type(enc) ~= str_const.string then
    error({reason="missing or invalid enc in JWE header"})
  end
  if not jwe_enc_lengths[enc] then
    error({reason="unsupported enc: " .. enc})
  end

  -- jwt:set_alg_whitelist applies to JWE as well: both the key management
  -- "alg" and the content encryption "enc" must be listed. Checked before any
  -- key unwrap/derivation so a disallowed algorithm costs nothing (e.g. PBES2).
  local alg_whitelist = self and self.alg_whitelist
  if alg_whitelist ~= nil then
    if alg_whitelist[alg] == nil then
      error({reason="whitelist unsupported alg: " .. alg})
    end
    if alg_whitelist[enc] == nil then
      error({reason="whitelist unsupported enc: " .. enc})
    end
  end

  -- RFC 7516 5.2 step 11: direct encryption uses an empty JWE Encrypted Key
  -- (as does ECDH-ES, checked in its branch below), every other alg a
  -- non-empty one
  if alg == str_const.DIR then
    if encoded_encrypted_key ~= str_const.empty then
      error({reason="JWE encrypted key must be empty for dir"})
    end
  elseif alg ~= str_const.ECDH_ES and (encoded_encrypted_key == nil or encoded_encrypted_key == str_const.empty) then
    error({reason="missing JWE encrypted key"})
  end

  -- Fail fast on unsupported compression before doing any expensive crypto work.
  local zip_handler
  if header.zip ~= nil then
    zip_handler = require_compression_alg(self, header.zip)
  end

  -- resolves JWK/JWKS/key object secrets and rejects keys that don't fit alg
  -- (e.g. public key material as a PBES2 password); before any key work
  local jwe_key = get_jwe_key(preshared_key, alg, header)

  local key, enc_key, _
  if alg == str_const.DIR then
    if not preshared_key  then
        error({reason="preshared key must not be null"})
    end
    key, _, enc_key = derive_keys(header.enc, jwe_key)
  elseif alg == str_const.ECDH_ES then
    -- RFC 7516 Section 5.2 step 10: direct key agreement has an empty encrypted key
    if encoded_encrypted_key ~= str_const.empty then
        error({reason="JWE encrypted key must be empty for ECDH-ES"})
    end
    local Z = ecdh_es_shared_secret(header, jwe_key)
    local derived_key = derive_shared_key(header, Z)
    key, _, enc_key = derive_keys(header.enc, derived_key)
  elseif alg == str_const.ECDH_ES_A128KW or alg == str_const.ECDH_ES_A192KW or alg == str_const.ECDH_ES_A256KW then
    local Z = ecdh_es_shared_secret(header, jwe_key)
    local wrapped_key = encoded_encrypted_key and _M:jwt_decode(encoded_encrypted_key)
    if not wrapped_key then
        error({reason="missing JWE encrypted key"})
    end
    local ok, secret_key = pcall(function()
        return aes_key_unwrap(derive_shared_key(header, Z), wrapped_key)
    end)
    if not ok then
        -- DEPRECATED, to be removed in 1.0: see set_legacy_ecdh_kw_kdf
        if not self.legacy_ecdh_kw_kdf then
            error(secret_key, 0)
        end
        secret_key = aes_key_unwrap(derive_legacy_ecdh_kw_key(header, Z), wrapped_key)
    end
    key, _, enc_key = derive_keys(header.enc, check_cek_len(enc, secret_key))
  elseif alg == str_const.A128KW or alg == str_const.A192KW or alg == str_const.A256KW then
    if not preshared_key then
        error({reason="AES key wrap key must not be null"})
    end
    local wrapped_key = _M:jwt_decode(encoded_encrypted_key)
    local secret_key = check_cek_len(enc, aes_key_unwrap(jwe_key, wrapped_key))
    key, _, enc_key = derive_keys(header.enc, secret_key)
  elseif alg == str_const.A128GCMKW or alg == str_const.A192GCMKW or alg == str_const.A256GCMKW then
    if not preshared_key then
        error({reason="AES-GCM key wrap key must not be null"})
    end
    local kw_iv = header.iv and _M:jwt_decode(header.iv)
    local kw_tag = header.tag and _M:jwt_decode(header.tag)
    if not kw_iv or not kw_tag then
        error({reason="missing iv/tag in header for AES-GCM key wrap"})
    end
    local wrapped_key = _M:jwt_decode(encoded_encrypted_key)
    local secret_key = check_cek_len(enc, aes_gcm_key_unwrap(jwe_key, wrapped_key, kw_iv, kw_tag))
    key, _, enc_key = derive_keys(header.enc, secret_key)
  elseif alg == str_const.PBES2_HS256_A128KW or alg == str_const.PBES2_HS384_A192KW or alg == str_const.PBES2_HS512_A256KW then
    if not preshared_key then
        error({reason="password must not be null"})
    end
    local p2c = header.p2c
    if header.p2s == nil or p2c == nil then
        error({reason="missing p2s/p2c in header for PBES2"})
    end
    if type(p2c) ~= str_const.number or p2c ~= math_floor(p2c) then
        error({reason="invalid p2c in header for PBES2"})
    end
    local max_count = self and self.pbes2_max_count or PBES2_DEFAULT_MAX_COUNT
    if p2c < PBES2_MIN_COUNT or p2c > max_count then
        error({reason="p2c out of acceptable bounds in header for PBES2"})
    end
    local p2s = type(header.p2s) == str_const.string and _M:jwt_decode(header.p2s)
    if not p2s or #p2s < PBES2_MIN_SALT_LEN then
        error({reason="invalid p2s in header for PBES2"})
    end
    local kek = pbes2_derive_kek(alg, jwe_key, p2s, p2c)
    local wrapped_key = _M:jwt_decode(encoded_encrypted_key)
    local secret_key = check_cek_len(enc, aes_key_unwrap(kek, wrapped_key))
    key, _, enc_key = derive_keys(header.enc, secret_key)
  elseif alg == str_const.RSA_OAEP or alg == str_const.RSA_OAEP_256
      or alg == str_const.RSA_OAEP_384 or alg == str_const.RSA_OAEP_512 then
    if not preshared_key  then
        error({reason="rsa private key must not be null"})
    end
    local oaep_digest = {
      [str_const.RSA_OAEP] = evp.CONST.SHA1_DIGEST,
      [str_const.RSA_OAEP_256] = evp.CONST.SHA256_DIGEST,
      [str_const.RSA_OAEP_384] = evp.CONST.SHA384_DIGEST,
      [str_const.RSA_OAEP_512] = evp.CONST.SHA512_DIGEST,
    }
    local digest_alg = oaep_digest[alg]
    local encrypted_key = _M:jwt_decode(encoded_encrypted_key) or ""
    local secret_key, err
    if type(jwe_key) == str_const.string then
      local rsa_decryptor, rsa_err = evp.RSADecryptor:new(jwe_key, nil, evp.CONST.RSA_PKCS1_OAEP_PADDING, digest_alg)
      if rsa_err then
          error({reason="failed to create rsa object: ".. rsa_err})
      end
      secret_key, err = rsa_decryptor:decrypt(encrypted_key)
    else
      secret_key, err = jwe_key:decrypt(encrypted_key, pkey.PADDINGS.RSA_PKCS1_OAEP_PADDING,
        { oaep_md = digest_alg })
    end
    local cek_len = keydatalen_map[enc] / 8
    if err or not secret_key or #secret_key ~= cek_len then
      -- RFC 7516 11.5: on a CEK decryption error continue with a random CEK so
      -- the failure is indistinguishable from a bad tag (reason and timing)
      ngx_log(ngx_DEBUG, "JWE RSA-OAEP CEK decryption failed: ", err or "unexpected CEK length")
      secret_key = resty_random.bytes(cek_len, true)
    end
    key, _, enc_key = derive_keys(header.enc, secret_key)
  end

  local cipher_text = _M:jwt_decode(encoded_cipher_text)
  local iv =  _M:jwt_decode(encoded_iv)
  local signature_or_tag = _M:jwt_decode(encoded_auth_tag)
  local lengths = jwe_enc_lengths[header.enc]
  if not iv or #iv ~= lengths.iv then
    error({reason="invalid JWE initialization vector length"})
  end
  if not signature_or_tag or #signature_or_tag ~= lengths.tag then
    error({reason="invalid JWE authentication tag length"})
  end
  -- AES-GCM allows an empty plaintext (and so an empty ciphertext); AES-CBC
  -- ciphertext is always a non-empty multiple of the block size
  if not cipher_text or (lengths.iv == 16 and (#cipher_text == 0 or #cipher_text % 16 ~= 0)) then
    error({reason="invalid JWE ciphertext"})
  end

  local mac_key
  key, mac_key, enc_key = derive_keys(header.enc, key)

  -- A*CBC-HS*: verify the MAC before touching the ciphertext so that padding
  -- errors can never be observed (no padding oracle). GCM authenticates the
  -- tag inside decrypt_payload.
  if mac_key ~= str_const.empty then
    local expected_tag = cbc_hs_auth_tag(header.enc, mac_key, encoded_header, iv, cipher_text)
    if not constant_time_equals(expected_tag, signature_or_tag) then
      jwe_decrypt_error("authentication tag mismatch")
    end
  end

  local payload, err = decrypt_payload(enc_key, cipher_text, header.enc, iv, encoded_header, signature_or_tag)
  if err or not payload then
    jwe_decrypt_error("content decryption failed: " .. (err or ""))
  end

  -- Only authenticated, decrypted content is ever decompressed. A failure
  -- here takes the generic JWE failure path so it cannot act as an oracle.
  if zip_handler then
    local max_size = get_zip_max_size(self, #payload)
    local ok, inflated, zerr = pcall(zip_handler.inflate, payload, max_size)
    if not ok then
      jwe_decrypt_error("payload decompression raised an error")
    end
    if zerr ~= nil or type(inflated) ~= str_const.string or #inflated > max_size then
      jwe_decrypt_error("payload decompression failed: "
        .. (type(zerr) == str_const.string and zerr or "invalid result"))
    end
    payload = inflated
  end

  -- A custom payload decoder's result is used as is. With the default one
  -- the plaintext is JSON when it parses as JSON and otherwise the raw
  -- string, as for a JWS payload (RFC 7516 allows any octet sequence).
  local decoded
  if self.payload_decoder then
    decoded = self.payload_decoder(payload)
  else
    decoded = cjson_decode(payload)
    if decoded == nil then
      decoded = payload
    end
  end

  return {
    typ = str_const.JWE,
    internal = {
      authenticated = JWE_AUTHENTICATED,
      json_payload = payload
    },
    header = header,
    signature = signature_or_tag,
    payload = decoded
  }
end

-- @function parse_jwt
-- @param encoded header
-- @param encoded
-- @param signature
-- @return jwt table
local function parse_jwt(self, encoded_header, encoded_payload, signature)
  local header = _M:jwt_decode(encoded_header, true)
  if type(header) ~= str_const.table then
    error({reason="invalid header: " .. encoded_header})
  end
  local crit_err = crit_error(self, header)
  if crit_err then
    error({reason=crit_err})
  end

  -- "zip" is a JWE-only header parameter (RFC 7516 4.1.3)
  if header.zip ~= nil then
    error({reason="zip is not allowed in a JWS header"})
  end

  -- Try JSON decoding first; fall back to raw string for non-JSON payloads (RFC 7515)
  local payload = _M.jwt_decode(self, encoded_payload, true, true)
  if not payload then
    payload = _M.jwt_decode(self, encoded_payload, false)
    if not payload then
      error({reason="invalid payload: " .. encoded_payload})
    end
  end

  local basic_jwt = {
    typ = str_const.JWT,
    raw_header=encoded_header,
    raw_payload=encoded_payload,
    header=header,
    payload=payload,
    signature=signature
  }
  return basic_jwt

end

-- @function parse token - this can be JWE or JWT token
-- @param token string
-- @return jwt/jwe tables
local jws_part_names = { "header", "payload", "signature" }
-- part 2 (encrypted key) is checked against the alg in parse_jwe; part 4
-- (ciphertext) may be empty for AES-GCM and is checked against enc there
local jwe_part_names = { "header", "encrypted key", "initialization vector", "ciphertext", "authentication tag" }
local jwe_part_may_be_empty = { [2] = true, [4] = true }

--@function check that a token part uses the one canonical base64url form:
-- URL-safe alphabet only, no padding and no non-zero trailing bits (RFC 7515
-- section 2). Without this, one token has many accepted spellings, which
-- defeats denylists and replay caches keyed on the token string.
local function is_canonical_b64url(s)
  if s:find("[^A-Za-z0-9_%-]") or #s % 4 == 1 then
    return false
  end
  local decoded = _M:jwt_decode(s)
  return decoded ~= nil and _M:jwt_encode(decoded) == s
end

local function parse(self, secret, token_str)
  if type(token_str) ~= str_const.string then
    error({reason=str_const.invalid_jwt})
  end
  local parts = split_token(token_str)
  local num_parts = #parts
  local part_names
  if num_parts == 3 then
    -- an empty signature is invalid as well: alg "none" is not supported
    part_names = jws_part_names
  elseif num_parts == 5 then
    part_names = jwe_part_names
  else
    error({reason=str_const.invalid_jwt})
  end
  local is_jwe = num_parts == 5
  for i = 1, num_parts do
    local part = parts[i]
    if part == str_const.empty then
      if not (is_jwe and jwe_part_may_be_empty[i]) then
        error({reason=str_const.invalid_jwt .. ": empty " .. part_names[i]})
      end
    elseif not is_canonical_b64url(part) then
      error({reason=str_const.invalid_jwt .. ": non-canonical base64url in " .. part_names[i]})
    end
  end

  if num_parts == 3 then
    return parse_jwt(self, parts[1], parts[2], parts[3])
  end
  return parse_jwe(self, secret, parts[1], parts[2], parts[3], parts[4], parts[5])
end

--@function jwt encode : it converts into base64 encoded string. if input is a table, it convets into
-- json before converting to base64 string
--@param payloaf
--@return base64 encoded payloaf
function _M.jwt_encode(self, ori, is_payload)
  if type(ori) == str_const.table then
    ori = is_payload and get_payload_encoder(self)(ori) or cjson_encode(ori)
  end
  local res = ngx_encode_base64(ori):gsub(str_const.plus, str_const.dash):gsub(str_const.slash, str_const.underscore):gsub(str_const.equal, str_const.empty)
  return res
end



--@function jwt decode : decode bas64 encoded string
function _M.jwt_decode(self, b64_str, json_decode, is_payload)
  b64_str = b64_str:gsub(str_const.dash, str_const.plus):gsub(str_const.underscore, str_const.slash)

  local reminder = #b64_str % 4
  if reminder > 0 then
    b64_str = b64_str .. string_rep(str_const.equal, 4 - reminder)
  end
  local data = ngx_decode_base64(b64_str)
  if not data then
    return nil
  end
  if json_decode then
    data = is_payload and get_payload_decoder(self)(data) or cjson_decode(data)
  end
  return data
end

--- Initialize the trusted certs
-- During RS256 verify, we'll make sure the
-- cert was signed by one of these
-- The file is read once per worker and cached; setting a different path
-- drops the cache, so the next verification re-reads the file.
function _M.set_trusted_certs_file(self, filename)
  if filename ~= self.trusted_certs_file then
    evp.clear_trust_store_cache()
  end
  self.trusted_certs_file = filename
end
_M.trusted_certs_file = nil

--- Set a whitelist of allowed algorithms
-- E.g., jwt:set_alg_whitelist({RS256=1,HS256=1})
--
-- @param algorithms - A table with keys for the supported algorithms
--                     If the table is non-nil, during
--                     verify, the alg must be in the table.
--                     For JWE tokens both the header "alg" (key management,
--                     e.g. "RSA-OAEP-256", "dir") and "enc" (content
--                     encryption, e.g. "A256GCM") must be in the table; this
--                     is checked on load, before any key is unwrapped or
--                     derived. E.g. {["RSA-OAEP-256"]=1, A256GCM=1}
function _M.set_alg_whitelist(self, algorithms)
  self.alg_whitelist = algorithms
end

_M.alg_whitelist = nil

--- Set the maximum PBES2 iteration count ("p2c") accepted when decrypting
-- PBES2-HS*+A*KW tokens. The count comes from the (unauthenticated) token
-- header and every iteration costs worker CPU, so tokens above the cap are
-- rejected before PBKDF2 runs. Counts below 1000 are always rejected.
--
-- @param max_count - integer >= 1000, or nil to restore the default (10000)
function _M.set_pbes2_max_count(self, max_count)
  if max_count ~= nil and (type(max_count) ~= str_const.number
      or max_count ~= math_floor(max_count) or max_count < PBES2_MIN_COUNT) then
    error("'max_count' is expected to be an integer >= " .. PBES2_MIN_COUNT, 0)
  end
  self.pbes2_max_count = max_count
end

_M.pbes2_max_count = nil


local normalize_typ = jwt_validators.normalize_typ

-- Default "typ" whitelist for sign: JWT (RFC 7519), JWE (RFC 7516), and the
-- RFC-registered "+jwt" structured-syntax values:
--   at+jwt                     RFC 9068
--   dpop+jwt                   RFC 9449
--   token-introspection+jwt    RFC 9701
--   client-authentication+jwt  draft-ietf-oauth-rfc7523bis
--   secevent+jwt               RFC 8417
--   logout+jwt                 OpenID Connect Back-Channel Logout 1.0
-- Keys are normalized (see jwt-validators normalize_typ). Kept private so it
-- can't be mutated through the module; set_typ_whitelist stores a copy.
local DEFAULT_TYP_WHITELIST = {
  [normalize_typ(str_const.JWT)] = true,
  [normalize_typ(str_const.JWE)] = true,
  ["at+jwt"] = true,
  ["dpop+jwt"] = true,
  ["token-introspection+jwt"] = true,
  ["client-authentication+jwt"] = true,
  ["secevent+jwt"] = true,
  ["logout+jwt"] = true,
}

local typ_whitelist_error = "'typs' is expected to be a table of typ values, or nil"

--- Set a whitelist of allowed "typ" header values
-- E.g., jwt:set_typ_whitelist({JWT=1, ["at+jwt"]=1}) or {"JWT", "at+jwt"}
--
-- @param typs - A table with keys (or list entries) for the supported typ
--              values. During sign the "typ" header (when present) must
--              match one of them, case-insensitively and ignoring an
--              "application/" prefix (RFC 7515 4.1.9). The table is copied.
--              Pass nil to disable typ validation entirely.
--              Only sign uses this list; verify never checks typ unless a
--              claim spec asks for it (see jwt-validators typ_is).
function _M.set_typ_whitelist(self, typs)
  if typs == nil then
    -- false (not nil) so an instance's choice isn't replaced by the module's
    self.typ_whitelist = false
    return
  end
  if type(typs) ~= str_const.table then
    error(typ_whitelist_error, 0)
  end
  local whitelist = {}
  for k, v in pairs(typs) do
    local typ
    if type(k) == str_const.number then
      typ = v
    elseif v then
      typ = k
    end
    if typ ~= nil then
      if type(typ) ~= str_const.string then
        error(typ_whitelist_error, 0)
      end
      whitelist[normalize_typ(typ)] = true
    end
  end
  self.typ_whitelist = whitelist
end

-- nil means DEFAULT_TYP_WHITELIST, false means typ validation is disabled
_M.typ_whitelist = nil

local crit_whitelist_error = "'extensions' is expected to be a table of header parameter names, or nil"

--- Declare the extension Header Parameters this application understands, so
-- tokens listing them in "crit" are accepted (RFC 7515 4.1.11). A token whose
-- "crit" lists anything else is rejected. The library does not interpret the
-- extensions itself: enforce their semantics with "__header" claim spec
-- validators, which run after the signature has been verified.
-- E.g., jwt:set_crit_whitelist({"exp-ext"}) or {["exp-ext"]=true}
--
-- @param extensions - A table with keys (or list entries) naming the
--                     extensions. Registered header names (alg, enc, kid...)
--                     can't be listed, nor "b64" (RFC 7797 is unsupported).
--                     Pass nil to understand none (the default).
function _M.set_crit_whitelist(self, extensions)
  local whitelist = {}
  if extensions ~= nil then
    if type(extensions) ~= str_const.table then
      error(crit_whitelist_error, 0)
    end
    for k, v in pairs(extensions) do
      local name
      if type(k) == str_const.number then
        name = v
      elseif v then
        name = k
      end
      if name ~= nil then
        if type(name) ~= str_const.string or name == str_const.empty then
          error(crit_whitelist_error, 0)
        end
        if registered_header_params[name] or name == "b64" then
          error("'" .. name .. "' can't be declared as an understood crit extension", 0)
        end
        whitelist[name] = true
      end
    end
  end
  self.crit_whitelist = whitelist
end

_M.crit_whitelist = nil


--- Returns the list of default validations that will be
--- applied upon the verification of a jwt.
function _M.get_default_validation_options(self, jwt_obj)
  local p = jwt_obj[str_const.payload]
  local p_is_table = type(p) == str_const.table
  return {
    [str_const.require_exp_claim]=p_is_table and p.exp ~= nil or false,
    [str_const.require_nbf_claim]=p_is_table and p.nbf ~= nil or false
  }
end

--- Set a function used to retrieve the content of x5u urls
--
-- @param retriever_function - A pointer to a function. This function should be
--                             defined to accept three string parameters. First one
--                             will be the value of the 'x5u' attribute. Second
--                             one will be the value of the 'iss' attribute, would
--                             it be defined in the jwt. Third one will be the value
--                             of the 'iss' attribute, would it be defined in the jwt.
--                             This function should return the matching certificate.
function _M.set_x5u_content_retriever(self, retriever_function)
  if type(retriever_function) ~= str_const.funct then
    error("'retriever_function' is expected to be a function", 0)
  end
  self.x5u_content_retriever = retriever_function
end

_M.x5u_content_retriever = nil

--@function sign jwe payload
--@param secret key : if used pre-shared or RSA key
--@param  jwe payload
--@return jwe token
local function sign_jwe(self, secret_key, jwt_obj)
  local header = jwt_obj.header
  local enc = header.enc
  local alg = header.alg

  -- remove type
  if header.typ then
    header.typ = nil
  end

  -- TODO: implement logic for creating enc key and mac key and then encrypt key
  local key, encrypted_key, mac_key, enc_key, _
  local encoded_header = _M:jwt_encode(header)
  local payload_to_encrypt = get_payload_encoder(self)(jwt_obj.payload)
  -- RFC 7516 5.1 step 6: compress the plaintext before encrypting it
  if header.zip ~= nil then
    local handler = require_compression_alg(self, header.zip)
    local compressed, zerr = handler.deflate(payload_to_encrypt)
    if zerr or not compressed then
      error({reason="failed to compress payload: " .. (zerr or "unknown error")})
    end
    payload_to_encrypt = compressed
  end
  if alg ==  str_const.DIR then
    _, mac_key, enc_key = derive_keys(enc, secret_key)
    encrypted_key = ""
  elseif alg == str_const.ECDH_ES then
    local Z = ecdh_es_ephemeral_agreement(header, secret_key)
    encoded_header = _M:jwt_encode(header)
    local derived_key = derive_shared_key(header, Z)
    _, mac_key, enc_key = derive_keys(enc, derived_key)
    encrypted_key = ""
  elseif alg == str_const.ECDH_ES_A128KW or alg == str_const.ECDH_ES_A192KW or alg == str_const.ECDH_ES_A256KW then
    local Z = ecdh_es_ephemeral_agreement(header, secret_key)
    encoded_header = _M:jwt_encode(header)
    local kek = derive_shared_key(header, Z)
    key, mac_key, enc_key = derive_keys(enc)
    encrypted_key = aes_key_wrap(kek, key)
  elseif alg == str_const.A128KW or alg == str_const.A192KW or alg == str_const.A256KW then
    check_kw_key_len(alg, secret_key)
    key, mac_key, enc_key = derive_keys(enc)
    encrypted_key = aes_key_wrap(secret_key, key)
  elseif alg == str_const.A128GCMKW or alg == str_const.A192GCMKW or alg == str_const.A256GCMKW then
    check_kw_key_len(alg, secret_key)
    key, mac_key, enc_key = derive_keys(enc)
    local wrapped, kw_iv, kw_tag = aes_gcm_key_wrap(secret_key, key)
    encrypted_key = wrapped
    header.iv = _M:jwt_encode(kw_iv)
    header.tag = _M:jwt_encode(kw_tag)
    encoded_header = _M:jwt_encode(header)
  elseif alg == str_const.PBES2_HS256_A128KW or alg == str_const.PBES2_HS384_A192KW or alg == str_const.PBES2_HS512_A256KW then
    local p2s = openssl_rand.bytes(16)
    local p2c = 4096
    header.p2s = _M:jwt_encode(p2s)
    header.p2c = p2c
    encoded_header = _M:jwt_encode(header)
    local kek = pbes2_derive_kek(alg, secret_key, p2s, p2c)
    key, mac_key, enc_key = derive_keys(enc)
    encrypted_key = aes_key_wrap(kek, key)
  elseif alg == str_const.RSA_OAEP or alg == str_const.RSA_OAEP_256
      or alg == str_const.RSA_OAEP_384 or alg == str_const.RSA_OAEP_512 then
    local cert, err
    if secret_key:find("CERTIFICATE") then
        cert, err = evp.Cert:new(secret_key)
    elseif secret_key:find("PUBLIC KEY") then
        cert, err = evp.PublicKey:new(secret_key)
    end
    if not cert then
        error({reason="Decode secret is not a valid cert/public key: " .. (err or "unsupported key format")})
    end
    local oaep_digest = {
      [str_const.RSA_OAEP] = evp.CONST.SHA1_DIGEST,
      [str_const.RSA_OAEP_256] = evp.CONST.SHA256_DIGEST,
      [str_const.RSA_OAEP_384] = evp.CONST.SHA384_DIGEST,
      [str_const.RSA_OAEP_512] = evp.CONST.SHA512_DIGEST,
    }
    local digest_alg = oaep_digest[alg]
    local rsa_encryptor, enc_err = evp.RSAEncryptor:new(cert, evp.CONST.RSA_PKCS1_OAEP_PADDING, digest_alg)
    if not rsa_encryptor then
        error({reason="failed to create rsa object for encryption: " .. (enc_err or "")})
    end
    key, mac_key, enc_key = derive_keys(enc)
    encrypted_key, err = rsa_encryptor:encrypt(key)
    if err or not encrypted_key then
        error({reason="failed to encrypt key " .. (err or "")})
    end
  else
    error({reason="unsupported alg: " .. alg})
  end

  local cipher_text, iv, auth_tag, err = encrypt_payload(enc_key, payload_to_encrypt, enc, encoded_header)
  if err then
    error({reason="error while encrypting payload. Error: " .. err})
  end

  if not auth_tag then
    auth_tag = cbc_hs_auth_tag(enc, mac_key, encoded_header, iv, cipher_text)
  end

  local jwe_table = {encoded_header, _M:jwt_encode(encrypted_key), _M:jwt_encode(iv),
    _M:jwt_encode(cipher_text),   _M:jwt_encode(auth_tag)}
  return table_concat(jwe_table, ".", 1, 5)
end

--@function get_secret_str  : returns the HMAC secret: the secret if it is a string, the result of a
-- function, or the "k" of the oct JWK selected from a JWK, JWK Set or key object
--@param either the string secret, a function that takes a string parameter and returns a string or nil,
-- or a JWK/JWK Set (table or JSON string) or a key object from resty.jwt.jwk
--@param  jwt payload
--@param purpose "sign" or "verify"
--@return the secret as a string
local function get_secret_str(secret_or_function, jwt_obj, purpose)
  if type(secret_or_function) == str_const.funct then
    -- Only use with hmac algorithms
    local alg = jwt_obj[str_const.header][str_const.alg]
    if alg ~= str_const.HS256 and alg ~= str_const.HS384 and alg ~= str_const.HS512 then
      error({reason="secret function can only be used with hmac alg: " .. tostring(alg)})
    end

    -- Pull out the kid value from the header
    local kid_val = jwt_obj[str_const.header][str_const.kid]
    if kid_val == nil then
      error({reason="secret function specified without kid in header"})
    end
    if type(kid_val) ~= str_const.string then
      error({reason="secret function specified with non-string kid in header"})
    end

    -- Call the function
    local secret_str = secret_or_function(kid_val)
    if secret_str == nil then
      error({reason="function returned nil for kid: " .. kid_val})
    end
    if type(secret_str) ~= str_const.string then
      error({reason="function returned a non-string secret for kid: " .. kid_val})
    end
    return secret_str
  end

  local header = jwt_obj[str_const.header]
  local entry, reason = select_key(secret_or_function, header[str_const.alg], header, purpose)
  if entry then
    -- an oct key: selection rejects every other kty for HS*
    return entry.k
  elseif reason then
    error({reason=reason})
  elseif type(secret_or_function) == str_const.string then
    -- Just return the string
    return secret_or_function
  else
    -- Throw an error
    error({reason="invalid secret type (must be string, function, JWK or key object)"})
  end
end

-- HMAC JWS algorithms -> hmac digest and raw signature length in bytes
local hmac_algs = {
  [str_const.HS256] = { algo = hmac.ALGOS.SHA256, len = 32 },
  [str_const.HS384] = { algo = hmac.ALGOS.SHA384, len = 48 },
  [str_const.HS512] = { algo = hmac.ALGOS.SHA512, len = 64 },
}

--@function hmac_sign : compute the raw HMAC signature of a JWS signing input
--@param alg HS256, HS384 or HS512
--@param secret the HMAC secret (string)
--@param message the JWS signing input (header.payload)
--@return raw signature bytes
local function hmac_sign(alg, secret, message)
  local spec = hmac_algs[alg]
  if not spec then
    error({reason="unsupported alg: " .. tostring(alg)})
  end
  -- An asymmetric key is public, so using one as an HMAC secret lets anyone
  -- forge tokens (RS/HS key confusion, CVE-2015-9235)
  local rejection = symmetric_secret_rejection(secret, "an HMAC secret")
  if rejection then
    error({reason="invalid secret for " .. alg .. ": " .. rejection})
  end
  return hmac:new(secret, spec.algo):final(message)
end

-- ECDSA alg -> required curve (OpenSSL NID and JOSE name), RFC 7518 3.4
local ecdsa_alg_curves = {
  [str_const.ES256] = { nid = 415, name = "P-256" },
  [str_const.ES384] = { nid = 715, name = "P-384" },
  [str_const.ES512] = { nid = 716, name = "P-521" },
}

local rsa_algs = {
  [str_const.RS256] = true, [str_const.RS384] = true, [str_const.RS512] = true,
  [str_const.PS256] = true, [str_const.PS384] = true, [str_const.PS512] = true,
}

local eddsa_alg_key_types = {
  [str_const.Ed25519] = { ED25519 = true },
  [str_const.Ed448] = { ED448 = true },
  [str_const.EdDSA] = { ED25519 = true, ED448 = true },
}

--@function load the public key of a PEM/DER certificate, or a PEM key
--@return resty.openssl.pkey or nil
local function load_verify_pkey(key_str)
  if not key_str:find(str_const.pem_begin, 1, true) or key_str:find("CERTIFICATE", 1, true) then
    local cert = x509.new(key_str)
    if cert then
      return cert:get_pubkey()
    end
  end
  return pkey.new(key_str)
end

--@function check that a verification key's type matches the JWS alg family,
-- so a key is never used with an algorithm it wasn't meant for
--@param alg the (string) alg from the JWS header
--@param pk resty.openssl.pkey
--@return nil if the key fits the alg, failure reason otherwise
local function check_key_type(alg, pk)
  local ok, key_type = pcall(pk.get_key_type, pk)
  local sn = ok and type(key_type) == str_const.table and key_type.sn or nil
  if rsa_algs[alg] then
    local is_pss = alg == str_const.PS256 or alg == str_const.PS384 or alg == str_const.PS512
    if sn == "rsaEncryption" or (is_pss and sn == "RSASSA-PSS") then
      return nil
    end
    return "key type mismatch: alg " .. alg .. " requires an RSA key"
  end
  local curve = ecdsa_alg_curves[alg]
  if curve then
    if sn == "id-ecPublicKey" then
      local params_ok, params = pcall(pk.get_parameters, pk)
      if params_ok and type(params) == str_const.table and params.group == curve.nid then
        return nil
      end
    end
    return "key type mismatch: alg " .. alg .. " requires an EC " .. curve.name .. " key"
  end
  local eddsa_types = eddsa_alg_key_types[alg]
  if eddsa_types then
    if sn and eddsa_types[sn] then
      return nil
    end
    return "key type mismatch: alg " .. alg .. " requires an " ..
      (alg == str_const.EdDSA and "Ed25519 or Ed448" or alg) .. " key"
  end
  return "key type mismatch: unsupported alg " .. alg
end

--@function verify the HMAC signature of a JWS object
--@return nil on success, failure reason otherwise
local function verify_hmac_signature(secret, jwt_obj, alg)
  local secret_str = get_secret_str(secret, jwt_obj, "verify")
  local raw_header = get_raw_part(str_const.header, jwt_obj)
  local raw_payload = get_raw_part(str_const.payload, jwt_obj)
  local message = string_format(str_const.regex_join_msg, raw_header, raw_payload)
  local expected = hmac_sign(alg, secret_str, message)

  local encoded_sig = jwt_obj[str_const.signature]
  local sig = type(encoded_sig) == str_const.string and _M:jwt_decode(encoded_sig, false)
  -- reject undecodable, wrong length and non-canonical (malleable) encodings
  if not sig or #sig ~= hmac_algs[alg].len or _M:jwt_encode(sig) ~= encoded_sig
      or not constant_time_equals(sig, expected) then
    return "signature mismatch: " .. tostring(encoded_sig)
  end
  return nil
end

--@function sign  : create a jwt/jwe signature from jwt_object
--@param secret key
--@param jwt/jwe payload
function _M.sign(self, secret_key, jwt_obj)
  -- header typ check
  local typ = jwt_obj[str_const.header][str_const.typ]
  -- Optional header typ check [See http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-5.1]
  local typ_whitelist = self.typ_whitelist
  if typ_whitelist == nil then
    typ_whitelist = DEFAULT_TYP_WHITELIST
  end
  if typ ~= nil and typ_whitelist then
    if type(typ) ~= str_const.string then
      error({reason="invalid typ: must be a string"})
    end
    if not typ_whitelist[normalize_typ(typ)] then
      error({reason="invalid typ: " .. typ})
    end
  end

  if jwt_obj.typ == str_const.JWE or (jwt_obj.typ == nil and (typ == str_const.JWE or jwt_obj.header.enc)) then
    return sign_jwe(self, secret_key, jwt_obj)
  end
  if jwt_obj[str_const.header].zip ~= nil then
    error({reason="zip is not allowed in a JWS header"})
  end
  -- header alg check
  local raw_header = get_raw_part(str_const.header, jwt_obj)
  local raw_payload = get_raw_part(str_const.payload, jwt_obj)
  local message = string_format(str_const.regex_join_msg, raw_header, raw_payload)
  local alg = jwt_obj[str_const.header][str_const.alg]
  local signature = ""
  if hmac_algs[alg] then
    local secret_str = get_secret_str(secret_key, jwt_obj, "sign")
    signature = hmac_sign(alg, secret_str, message)
  elseif alg == str_const.RS256 or alg == str_const.RS384 or alg == str_const.RS512
      or alg == str_const.PS256 or alg == str_const.PS384 or alg == str_const.PS512 then
    local signer, err
    if alg == str_const.PS256 or alg == str_const.PS384 or alg == str_const.PS512 then
      signer, err = evp.RSASigner:new(secret_key, nil, evp.CONST.RSA_PKCS1_PSS_PADDING)
    else
      signer, err = evp.RSASigner:new(secret_key)
    end
    if not signer then
      error({reason="signer error: " .. (err or "")})
    end
    if alg == str_const.RS256 or alg == str_const.PS256 then
      signature, err = signer:sign(message, evp.CONST.SHA256_DIGEST)
    elseif alg == str_const.RS384 or alg == str_const.PS384 then
      signature, err = signer:sign(message, evp.CONST.SHA384_DIGEST)
    elseif alg == str_const.RS512 or alg == str_const.PS512 then
      signature, err = signer:sign(message, evp.CONST.SHA512_DIGEST)
    end
    if not signature then
      error({reason="signature error: " .. (err or "")})
    end
  elseif alg == str_const.ES256 or alg == str_const.ES384 or alg == str_const.ES512 then
    local signer, err = evp.ECSigner:new(secret_key)
    if not signer then
      error({reason="signer error: " .. (err or "")})
    end
    -- OpenSSL will generate a DER encoded signature that needs to be converted
    local der_signature
    if alg == str_const.ES256 then
      der_signature, err = signer:sign(message, evp.CONST.SHA256_DIGEST)
    elseif alg == str_const.ES384 then
      der_signature, err = signer:sign(message, evp.CONST.SHA384_DIGEST)
    elseif alg == str_const.ES512 then
      der_signature, err = signer:sign(message, evp.CONST.SHA512_DIGEST)
    end
    if not der_signature then
      error({reason="signature error: " .. (err or "")})
    end
    -- Perform DER to RAW signature conversion
    signature, err = signer:get_raw_sig(der_signature)
    if not signature then
      error({reason="signature error: " .. (err or "")})
    end
  elseif alg == str_const.Ed25519 or alg == str_const.Ed448 or alg == str_const.EdDSA then
    local pk, err = pkey.new(secret_key)
    if not pk then
      error({reason="failed to load EdDSA private key: " .. (err or "")})
    end
    signature, err = pk:sign(message)
    if not signature then
      error({reason="EdDSA sign error: " .. (err or "")})
    end
  else
    error({reason="unsupported alg: " .. tostring(alg)})
  end
  -- return full jwt string
  return string_format(str_const.regex_join_msg, message , _M:jwt_encode(signature))

end

--@function load jwt
--@param jwt string token
--@param secret
function _M.load_jwt(self, jwt_str, secret)
  local success, ret = pcall(parse, self, secret, jwt_str)
  if not success then
    return {
      valid=false,
      verified=false,
      reason=ret[str_const.reason] or str_const.invalid_jwt
    }
  end

  local jwt_obj = ret
  jwt_obj[str_const.verified] = false
  jwt_obj[str_const.valid] = true
  return jwt_obj
end

--@function verify jwe object
--@param jwt object
--@return jwt object with reason whether verified or not
local function verify_jwe_obj(jwt_obj)
  -- the authentication tag (GCM) or MAC (CBC-HS) was already verified in
  -- parse_jwe, before decryption
  local internal = jwt_obj.internal
  if type(internal) ~= str_const.table or internal.authenticated ~= JWE_AUTHENTICATED then
    jwt_obj[str_const.reason] = "JWE was not authenticated"
  end

  jwt_obj.internal = nil
  jwt_obj.signature = nil

  if not jwt_obj[str_const.reason] then
    jwt_obj[str_const.verified] = true
    jwt_obj[str_const.reason] = str_const.everything_awesome
  end

  return jwt_obj
end

--@function extract certificate
--@param jwt object
--@return decoded certificate
local function extract_certificate(jwt_obj, x5u_content_retriever)
  local x5c = jwt_obj[str_const.header][str_const.x5c]
  if x5c ~= nil and (type(x5c) ~= str_const.table or (x5c[1] ~= nil and type(x5c[1]) ~= str_const.string)) then
    jwt_obj[str_const.reason] = "Malformed x5c header"
    return nil
  end
  if x5c ~= nil and x5c[1] ~= nil then
    -- TODO Might want to add support for intermediaries that we
    -- don't have in our trusted chain (items 2... if present)

    local cert_str = ngx_decode_base64(x5c[1])
    if not cert_str then
      jwt_obj[str_const.reason] = "Malformed x5c header"
    end

    return cert_str
  end

  local x5u = jwt_obj[str_const.header][str_const.x5u]
  if x5u ~= nil and type(x5u) ~= str_const.string then
    jwt_obj[str_const.reason] = "Malformed x5u header"
    return nil
  end
  if x5u ~= nil then
    -- TODO Ensure the url starts with https://
    -- cf. https://tools.ietf.org/html/rfc7517#section-4.6

    if x5u_content_retriever == nil then
      jwt_obj[str_const.reason] = "No function has been provided to retrieve the content pointed at by the 'x5u'."
      return nil
    end

    -- TODO Maybe validate the url against an optional list whitelisted url prefixes?
    -- cf. https://news.ycombinator.com/item?id=9302394

    local payload = jwt_obj[str_const.payload]
    local iss = type(payload) == str_const.table and payload[str_const.iss] or nil
    local kid = jwt_obj[str_const.header][str_const.kid]
    local success, ret = pcall(x5u_content_retriever, x5u, iss, kid)

    if not success then
      jwt_obj[str_const.reason] = "An error occured while invoking the x5u_content_retriever function."
      return nil
    end

    if type(ret) ~= str_const.string then
      jwt_obj[str_const.reason] = "The x5u_content_retriever function did not return a certificate."
      return nil
    end

    return ret
  end

  -- TODO When both x5c and x5u are defined, the implementation should
  -- ensure their content match
  -- cf. https://tools.ietf.org/html/rfc7517#section-4.6

  jwt_obj[str_const.reason] = "Unsupported RS256 key model"
  return nil
  -- TODO - Implement jwk and kid based models...
end

local function get_claim_spec_from_legacy_options(self, options)
  local claim_spec = { }
  local jwt_validators = require "resty.jwt-validators"

  if options[str_const.valid_issuers] ~= nil then
    claim_spec[str_const.iss] = jwt_validators.equals_any_of(options[str_const.valid_issuers])
  end

  -- the grace period applies to this call only (it used to mutate the
  -- module-wide system leeway); without one, the system leeway is used
  local grace_period = options[str_const.lifetime_grace_period]
  local date_options = { leeway = grace_period ~= nil and (grace_period or 0) or nil }

  if grace_period ~= nil then
    -- If we have a leeway set, then either an NBF or an EXP should also exist requireds are added below
    if options[str_const.require_nbf_claim] ~= true and options[str_const.require_exp_claim] ~= true then
      claim_spec[str_const.full_obj] = jwt_validators.require_one_of({ str_const.nbf, str_const.exp })
    end
  end

  if not is_nil_or_boolean(options[str_const.require_nbf_claim]) then
    error(string.format("'%s' validation option is expected to be a boolean.", str_const.require_nbf_claim), 0)
  end

  if not is_nil_or_boolean(options[str_const.require_exp_claim]) then
    error(string.format("'%s' validation option is expected to be a boolean.", str_const.require_exp_claim), 0)
  end

  if options[str_const.lifetime_grace_period] ~= nil or options[str_const.require_nbf_claim] ~= nil or options[str_const.require_exp_claim] ~= nil then
    if options[str_const.require_nbf_claim] == true then
      claim_spec[str_const.nbf] = jwt_validators.is_not_before(date_options)
    else
      claim_spec[str_const.nbf] = jwt_validators.opt_is_not_before(date_options)
    end

    if options[str_const.require_exp_claim] == true then
      claim_spec[str_const.exp] = jwt_validators.is_not_expired(date_options)
    else
      claim_spec[str_const.exp] = jwt_validators.opt_is_not_expired(date_options)
    end
  end

  return claim_spec
end

local function is_legacy_validation_options(options)

  -- Validation options MUST be a table
  if type(options) ~= str_const.table then
    return false
  end

  -- Validation options MUST have at least one of these, and must ONLY have these
  local legacy_options = { }
  legacy_options[str_const.valid_issuers]=1
  legacy_options[str_const.lifetime_grace_period]=1
  legacy_options[str_const.require_nbf_claim]=1
  legacy_options[str_const.require_exp_claim]=1

  local is_legacy = false
  for k in pairs(options) do
    if legacy_options[k] ~= nil then
      is_legacy = true
    else
      return false
    end
  end
  return is_legacy
end

-- Resolves the claim specs passed to verify: applies the default validation
-- options when none were given, converts legacy option tables and checks
-- that every spec maps claims to validator functions. Raises on malformed
-- specs (programming errors) regardless of the token being verified.
local function prepare_claim_specs(self, jwt_obj, ...)
  local claim_specs = {...}
  if #claim_specs == 0 then
    table.insert(claim_specs, _M:get_default_validation_options(jwt_obj))
  end

  for i, claim_spec in ipairs(claim_specs) do
    if type(claim_spec) ~= str_const.table then
      error("Claim spec must be a table - see jwt-validators.lua for helper functions", 0)
    end
    if is_legacy_validation_options(claim_spec) then
      claim_spec = get_claim_spec_from_legacy_options(self, claim_spec)
      claim_specs[i] = claim_spec
    end
    for claim, fx in pairs(claim_spec) do
      if claim == str_const.header_specs then
        -- "__header" maps header parameter names to validators
        if type(fx) ~= str_const.table then
          error("Claim spec '__header' must be a table mapping header names to validator functions", 0)
        end
        for name, header_fx in pairs(fx) do
          if type(name) ~= str_const.string or type(header_fx) ~= str_const.funct then
            error("Header spec value must be a function - see jwt-validators.lua for helper functions", 0)
          end
        end
      elseif type(fx) ~= str_const.funct then
        error("Claim spec value must be a function - see jwt-validators.lua for helper functions", 0)
      end
    end
  end
  return claim_specs
end

-- Validates the claims of an authenticated object against prepared claim specs.
-- Must only be called once the signature/authentication tag has been verified,
-- so validators never see (or leak, through failure reasons) forged claims.
-- Runs one validator, setting the failure reason on jwt_obj.
-- @param kind "Claim" or "Header", used in generic failure reasons
-- @return true if the validator passed
local function run_validator(jwt_obj, fx, val, name, jwt_json, kind)
  local success, ret = pcall(fx, val, name, jwt_json, jwt_obj[str_const.payload])
  if not success then
    if type(ret) == str_const.table and ret.reason ~= nil then
      jwt_obj[str_const.reason] = tostring(ret.reason)
    elseif type(ret) == str_const.string then
      jwt_obj[str_const.reason] = string.gsub(ret, "^.-:%d-: ", "")
    else
      jwt_obj[str_const.reason] = string.format("%s '%s' validation failed", kind, tostring(name))
    end
    return false
  elseif ret == false then
    jwt_obj[str_const.reason] = string.format("%s '%s' ('%s') returned failure", kind, tostring(name), tostring(val))
    return false
  end
  return true
end

local function validate_claims(jwt_obj, claim_specs)
  -- Encode the current jwt_obj and use it when calling the individual validation functions
  local jwt_json = cjson_encode(jwt_obj)
  -- Claims only exist in JSON object payloads. Indexing a string payload would
  -- otherwise hit the string library (e.g. "sub" -> string.sub).
  local payload = jwt_obj[str_const.payload]
  local header = jwt_obj[str_const.header]

  -- Validate all our specs
  for _, claim_spec in ipairs(claim_specs) do
    for claim, fx in pairs(claim_spec) do
      if claim == str_const.header_specs then
        for name, header_fx in pairs(fx) do
          if not run_validator(jwt_obj, header_fx, header[name], name, jwt_json, "Header") then
            return false
          end
        end
      else
        local val
        if claim == str_const.full_obj then
          val = cjson_decode(jwt_json)
        elseif type(payload) == str_const.table then
          val = payload[claim]
        end
        if not run_validator(jwt_obj, fx, val, claim, jwt_json, "Claim") then
          return false
        end
      end
    end
  end

  -- Everything was good
  return true
end

--@function verify the signature of a JWS object
--@param secret
--@param jwt_object
--@return jwt_obj with verified/reason set, or a new failure table
local function verify_jws_signature(self, secret, jwt_obj)
  local alg = jwt_obj[str_const.header][str_const.alg]

  if alg == nil then
    jwt_obj[str_const.reason] = "No algorithm supplied"
    return jwt_obj
  end

  if type(alg) ~= str_const.string then
    jwt_obj[str_const.reason] = "invalid alg: must be a string"
    return jwt_obj
  end

  if self.alg_whitelist ~= nil then
    if self.alg_whitelist[alg] == nil then
      return {verified=false, reason="whitelist unsupported alg: " .. alg}
    end
  end

  if hmac_algs[alg] then
    -- verify directly (not via _M.sign) so sign-time header checks such as typ
    -- don't apply, and compare signatures in constant time
    local success, ret = pcall(verify_hmac_signature, secret, jwt_obj, alg)
    if not success then
      jwt_obj[str_const.reason] = type(ret) == str_const.table and ret[str_const.reason] or str_const.internal_error
    elseif ret then
      jwt_obj[str_const.reason] = ret
    end
  elseif alg == str_const.RS256 or alg == str_const.RS384 or alg == str_const.RS512
      or alg == str_const.PS256 or alg == str_const.PS384 or alg == str_const.PS512
      or alg == str_const.ES256 or alg == str_const.ES384 or alg == str_const.ES512 then
    local cert, cert_str, err, pk
    if self.trusted_certs_file ~= nil then
      cert_str = extract_certificate(jwt_obj, self.x5u_content_retriever)
      if not cert_str then
        return jwt_obj
      end
      cert, err = evp.Cert:new(cert_str)
      if not cert then
        jwt_obj[str_const.reason] = "Unable to extract signing cert from JWT: " .. (err or "unknown error")
        return jwt_obj
      end
      -- Try validating against trusted CA's, then a cert passed as secret
      local trusted, trust_err = cert:verify_trust(self.trusted_certs_file)
      if not trusted then
        jwt_obj[str_const.reason] = "Cert used to sign the JWT isn't trusted: " .. (trust_err or "unknown error")
        return jwt_obj
      end
    elseif secret ~= nil then
      local entry, reason = select_key(secret, alg, jwt_obj[str_const.header], "verify")
      if reason then
        jwt_obj[str_const.reason] = reason
        return jwt_obj
      end
      if entry then
        pk, err = jwk.get_pkey(entry)
        if not pk then
          jwt_obj[str_const.reason] = err
          return jwt_obj
        end
        -- the evp verifiers only need the EVP_PKEY of a Cert/PublicKey
        cert = { public_key = pk.ctx }
      elseif type(secret) ~= str_const.string then
        cert = nil
      elseif secret:find("CERTIFICATE") then
        cert, err = evp.Cert:new(secret)
      elseif secret:find("PUBLIC KEY") then
        cert, err = evp.PublicKey:new(secret)
      end
      if not cert then
        jwt_obj[str_const.reason] = "Decode secret is not a valid cert/public key"
        return jwt_obj
      end
    else
      jwt_obj[str_const.reason] = "No trusted certs loaded"
      return jwt_obj
    end

    if not pk then
      local key_str = self.trusted_certs_file ~= nil and cert_str or secret
      local load_ok
      load_ok, pk = pcall(load_verify_pkey, key_str)
      if not load_ok or not pk then
        jwt_obj[str_const.reason] = "Unable to determine the verification key type"
        return jwt_obj
      end
    end
    local key_err = check_key_type(alg, pk)
    if key_err then
      jwt_obj[str_const.reason] = key_err
      return jwt_obj
    end

    local verifier
    if alg == str_const.RS256 or alg == str_const.RS384 or alg == str_const.RS512 then
      verifier, err = evp.RSAVerifier:new(cert)
    elseif alg == str_const.PS256 or alg == str_const.PS384 or alg == str_const.PS512 then
      verifier, err = evp.RSAVerifier:new(cert, evp.CONST.RSA_PKCS1_PSS_PADDING)
    elseif alg == str_const.ES256 or alg == str_const.ES384 or alg == str_const.ES512 then
      verifier, err = evp.ECVerifier:new(cert)
    end
    if not verifier then
      -- Internal error case, should not happen...
      jwt_obj[str_const.reason] = "Failed to build verifier " .. (err or "")
      return jwt_obj
    end

    -- assemble jwt parts
    local raw_header = get_raw_part(str_const.header, jwt_obj)
    local raw_payload = get_raw_part(str_const.payload, jwt_obj)

    local message =string_format(str_const.regex_join_msg, raw_header ,  raw_payload)
    local sig = _M:jwt_decode(jwt_obj[str_const.signature], false)

    if not sig then
      jwt_obj[str_const.reason] = "Wrongly encoded signature"
      return jwt_obj
    end

    local verified = false
    err = "verify error: reason unknown"

    if alg == str_const.RS256 or alg == str_const.ES256 or alg == str_const.PS256 then
      verified, err = verifier:verify(message, sig, evp.CONST.SHA256_DIGEST)
    elseif alg == str_const.RS384 or alg == str_const.ES384 or alg == str_const.PS384 then
      verified, err = verifier:verify(message, sig, evp.CONST.SHA384_DIGEST)
    elseif alg == str_const.RS512 or alg == str_const.ES512 or alg == str_const.PS512 then
      verified, err = verifier:verify(message, sig, evp.CONST.SHA512_DIGEST)
    end
    if not verified then
      jwt_obj[str_const.reason] = err or "signature verification failed"
    end
  elseif alg == str_const.Ed25519 or alg == str_const.Ed448 or alg == str_const.EdDSA then
    local entry, reason = select_key(secret, alg, jwt_obj[str_const.header], "verify")
    if reason then
      jwt_obj[str_const.reason] = reason
      return jwt_obj
    end
    local pk, pk_err
    if entry then
      pk, pk_err = jwk.get_pkey(entry)
    elseif type(secret) == str_const.string then
      local load_ok
      load_ok, pk, pk_err = pcall(load_verify_pkey, secret)
      if not load_ok then
        pk, pk_err = nil, "invalid key"
      end
    end
    if not pk then
      jwt_obj[str_const.reason] = "Failed to load EdDSA public key: " .. (pk_err or "no key provided")
      return jwt_obj
    end
    local key_err = check_key_type(alg, pk)
    if key_err then
      jwt_obj[str_const.reason] = key_err
      return jwt_obj
    end
    local raw_header = get_raw_part(str_const.header, jwt_obj)
    local raw_payload = get_raw_part(str_const.payload, jwt_obj)
    local message = string_format(str_const.regex_join_msg, raw_header, raw_payload)
    local sig = _M:jwt_decode(jwt_obj[str_const.signature], false)
    if not sig then
      jwt_obj[str_const.reason] = "Wrongly encoded signature"
      return jwt_obj
    end
    local ok, verify_err = pk:verify(sig, message)
    if not ok then
      jwt_obj[str_const.reason] = verify_err or "EdDSA signature verification failed"
    end
  else
    jwt_obj[str_const.reason] = "Unsupported algorithm " .. alg
  end

  if not jwt_obj[str_const.reason] then
    jwt_obj[str_const.verified] = true
    jwt_obj[str_const.reason] = str_const.everything_awesome
  end
  return jwt_obj

end

--@function verify jwt object
--@param secret
--@param jwt_object
--@param ... claim specs (see jwt-validators.lua) or legacy validation options
--@return verified jwt payload or jwt object with error code
function _M.verify_jwt_obj(self, secret, jwt_obj, ...)
  if not jwt_obj.valid then
    return jwt_obj
  end

  if type(jwt_obj[str_const.header]) ~= str_const.table then
    jwt_obj[str_const.reason] = "invalid header"
    return jwt_obj
  end

  local claim_specs = prepare_claim_specs(self, jwt_obj, ...)

  -- never trust a verdict left on the object by an earlier verification
  jwt_obj[str_const.verified] = false
  jwt_obj[str_const.reason] = nil

  -- load_jwt already checked "crit", but jwt_obj may not come from load_jwt
  local crit_err = crit_error(self, jwt_obj[str_const.header])
  if crit_err then
    jwt_obj[str_const.reason] = crit_err
    return jwt_obj
  end

  -- authenticate first: a signature failure takes precedence over claims
  if jwt_obj.typ == str_const.JWE or (jwt_obj.typ == nil and jwt_obj.internal ~= nil and jwt_obj[str_const.header][str_const.enc]) then
    verify_jwe_obj(jwt_obj)
  else
    local ret = verify_jws_signature(self, secret, jwt_obj)
    if ret ~= jwt_obj then
      return ret
    end
  end

  if not jwt_obj[str_const.verified] then
    return jwt_obj
  end

  -- only claims of an authenticated token get validated
  if not validate_claims(jwt_obj, claim_specs) then
    jwt_obj[str_const.verified] = false
  end
  return jwt_obj
end


function _M.verify(self, secret, jwt_str, ...)
  local jwt_obj = _M.load_jwt(self, jwt_str, secret)
  if not jwt_obj.valid then
    return {verified=false, reason=jwt_obj[str_const.reason]}
  end
  return  _M.verify_jwt_obj(self, secret, jwt_obj, ...)

end

local verify_with_algorithms_error =
  "verify_with: options.algorithms must be a non-empty list of algorithm names"

-- normalizes {"RS256", ...} (or the set_alg_whitelist style {RS256=1, ...})
-- into a set of algorithm names
local function get_allowed_algorithms(algorithms)
  if type(algorithms) ~= str_const.table then
    error(verify_with_algorithms_error, 0)
  end
  local allowed = {}
  for k, v in pairs(algorithms) do
    local name = type(k) == str_const.number and v or (v and k)
    if type(name) ~= str_const.string then
      error(verify_with_algorithms_error, 0)
    end
    allowed[name] = true
  end
  if next(allowed) == nil then
    error(verify_with_algorithms_error, 0)
  end
  return allowed
end

-- checks that a verify_with option is a string or a non-empty list of strings
local function check_string_list_option(options, name)
  local value = options[name]
  if type(value) == str_const.string then
    return
  end
  local msg = "verify_with: options." .. name .. " must be a string or a non-empty list of strings"
  if type(value) ~= str_const.table or value[1] == nil then
    error(msg, 0)
  end
  for _, v in ipairs(value) do
    if type(v) ~= str_const.string then
      error(msg, 0)
    end
  end
end

-- builds the claim specs for the verify_with claim options. Returns the specs
-- to run before the caller's claim specs and the one to run after them
local function get_option_claim_specs(options)
  local before = {}
  local spec = {}

  local required = options.required_claims
  if required ~= nil then
    if type(required) ~= str_const.table or required[1] == nil then
      error("verify_with: options.required_claims must be a non-empty list of claim names", 0)
    end
    local required_spec = {}
    for _, name in ipairs(required) do
      if type(name) ~= str_const.string then
        error("verify_with: options.required_claims must be a non-empty list of claim names", 0)
      end
      required_spec[name] = jwt_validators.required()
    end
    before[#before + 1] = required_spec
  end

  if options.issuer ~= nil then
    check_string_list_option(options, "issuer")
    local issuers = options.issuer
    spec[str_const.iss] = jwt_validators.equals_any_of(
      type(issuers) == str_const.string and { issuers } or issuers)
  end

  if options.audience ~= nil then
    check_string_list_option(options, "audience")
    spec.aud = jwt_validators.audience(options.audience)
  end

  if options.max_age ~= nil then
    local max_age = options.max_age
    if type(max_age) ~= str_const.number or max_age < 0 then
      error("verify_with: options.max_age must be a non-negative number of seconds", 0)
    end
    spec.iat = jwt_validators.issued_at({ max_age = max_age })
  end

  if options.typ ~= nil then
    check_string_list_option(options, str_const.typ)
    spec[str_const.header_specs] = { typ = jwt_validators.typ_is(options.typ) }
  end

  if next(spec) ~= nil then
    before[#before + 1] = spec
  end

  -- the jti hook runs last, so it only records tokens that passed every
  -- other check
  local after
  if options.jti ~= nil then
    if type(options.jti) ~= str_const.funct then
      error("verify_with: options.jti must be a function", 0)
    end
    after = { jti = jwt_validators.jti_hook(options.jti) }
  end

  return before, after
end

--- Verify a JWS/JWE string, pinning the accepted algorithms for this call.
--
-- jwt:verify_with(secret, jwt_str, {
--   algorithms = { "RS256", "ES256" },   -- required: allowed "alg" header values
--   claim_specs = { spec1, spec2 },      -- optional: same as verify()'s varargs
--   issuer = "https://issuer.example",   -- optional: required "iss", or a list
--   audience = "api",                    -- optional: required "aud", or a list
--   max_age = 3600,                      -- optional: required "iat", max age
--   required_claims = { "sub" },         -- optional: claims that must exist
--   typ = "at+jwt",                      -- optional: required "typ" header
--   jti = function(jti, payload) end,    -- optional: required "jti" hook
-- })
--
-- For a JWE both the key management "alg" and the content encryption "enc"
-- must be listed. They are checked before the token is parsed, so a JWE using
-- a disallowed algorithm is never decrypted. Applies in addition to
-- set_alg_whitelist().
--
-- The claim options add to claim_specs (or, without claim_specs, to the
-- default "exp"/"nbf" checks of verify()). The jti hook runs after every
-- other claim check has passed.
function _M.verify_with(self, secret, jwt_str, options)
  if type(options) ~= str_const.table then
    error("verify_with: options must be a table", 0)
  end
  local allowed = get_allowed_algorithms(options.algorithms)
  local claim_specs = options.claim_specs or {}
  if type(claim_specs) ~= str_const.table then
    error("verify_with: options.claim_specs must be a list of claim specs", 0)
  end
  local before_specs, after_spec = get_option_claim_specs(options)

  if type(jwt_str) ~= str_const.string then
    return {verified=false, reason=str_const.invalid_jwt}
  end
  local encoded_header = split_token(jwt_str)[1]
  local header = encoded_header and _M:jwt_decode(encoded_header, true)
  if type(header) == str_const.table then
    local alg = header[str_const.alg]
    if alg ~= nil and type(alg) ~= str_const.string then
      return {verified=false, reason="invalid alg: must be a string"}
    end
    if not allowed[alg] then
      return {verified=false, reason="whitelist unsupported alg: " .. tostring(alg)}
    end
    -- as with set_alg_whitelist, a JWE's content encryption must be listed too
    local enc = header[str_const.enc]
    if enc ~= nil and not allowed[enc] then
      return {verified=false, reason="whitelist unsupported enc: " .. tostring(enc)}
    end
  end
  -- otherwise load_jwt reports the malformed header

  if #before_specs == 0 and after_spec == nil then
    return _M.verify(self, secret, jwt_str, unpack(claim_specs))
  end

  local jwt_obj = _M.load_jwt(self, jwt_str, secret)
  if not jwt_obj.valid then
    return {verified=false, reason=jwt_obj[str_const.reason]}
  end
  local specs = before_specs
  if #claim_specs == 0 then
    -- what verify() would apply without claim specs
    specs[#specs + 1] = _M:get_default_validation_options(jwt_obj)
  else
    for _, claim_spec in ipairs(claim_specs) do
      specs[#specs + 1] = claim_spec
    end
  end
  specs[#specs + 1] = after_spec
  return _M.verify_jwt_obj(self, secret, jwt_obj, unpack(specs))
end

function _M.set_payload_encoder(self, encoder)
  if type(encoder) ~= "function" then
    error({reason="payload encoder must be function"})
  end
  self.payload_encoder = encoder
end


function _M.set_payload_decoder(self, decoder)
  if type(decoder) ~= "function" then
    error({reason="payload decoder must be function"})
  end
  self.payload_decoder= decoder
end


--@function register_compression_alg : register a handler for the given JWE "zip" header value
--@param name : the `zip` header value to bind (e.g. "DEF")
--@param handler : a table { deflate = fn(bytes)->bytes,err
--                           inflate = fn(bytes, max_size)->bytes,err }.
--                 inflate must not produce more than max_size bytes; results
--                 longer than that are rejected anyway.
-- The registration applies to the object it is called on: on the module
-- (jwt:register_compression_alg) it is inherited by instances from jwt:new()
-- that have not registered their own; on an instance it applies to that
-- instance only. Built-in handlers are never modified.
function _M.register_compression_alg(self, name, handler)
  if type(name) ~= "string" or name == "" then
    error({reason="compression alg name must be a non-empty string"})
  end
  if type(handler) ~= "table"
      or type(handler.deflate) ~= "function"
      or type(handler.inflate) ~= "function" then
    error({reason="compression handler must be a table with deflate and inflate functions"})
  end
  -- copy on write: never mutate a table another object may be reading
  local algs = {}
  for k, v in pairs(self.compression_algs or {}) do
    algs[k] = v
  end
  algs[name] = handler
  self.compression_algs = algs
end

_M.compression_algs = nil

-- lua-zlib streams are fed this many compressed bytes at a time, which bounds
-- how far one call can overshoot max_size (DEFLATE expands at most ~1032x).
local LUA_ZLIB_FEED_CHUNK = 256

--@function register_zlib_compression : bind the JWE "DEF" zip alg to a caller-supplied lua-zlib module
--@param zlib : a lua-zlib-compatible module (typically the result of `require "zlib"`).
--              Passing it in keeps the dependency caller-owned. "DEF" is
--              already built in when the system zlib can be loaded through
--              the FFI; use this to prefer lua-zlib or where the FFI is not
--              available. Like register_compression_alg it applies to the
--              object it is called on.
--              Compress-then-encrypt leaks information about the plaintext
--              through the ciphertext length (CRIME / BREACH family): only
--              sign with zip=DEF when attacker-chosen plaintext cannot be
--              mixed with secrets.
function _M.register_zlib_compression(self, zlib)
  if type(zlib) ~= "table"
      or type(zlib.deflate) ~= "function"
      or type(zlib.inflate) ~= "function" then
    error({reason="zlib module must expose deflate and inflate functions (pass `require \"zlib\"`)"})
  end
  _M.register_compression_alg(self, str_const.DEF, {
    deflate = function(data)
      local stream = zlib.deflate(zlib.BEST_COMPRESSION, -15)
      local ok, compressed = pcall(stream, data, "finish")
      if not ok then
        return nil, tostring(compressed)
      end
      return compressed
    end,
    -- feed the input in small pieces so the output can be checked against
    -- max_size as it grows, and use lua-zlib's eof flag and input count to
    -- reject truncated streams and trailing data
    inflate = function(data, max_size)
      local stream = zlib.inflate(-15)
      local out, n, total = {}, 0, 0
      local pos, len = 1, #data
      local eof, bytes_in = false, 0
      while pos <= len do
        local piece = string_sub(data, pos, pos + LUA_ZLIB_FEED_CHUNK - 1)
        pos = pos + #piece
        local ok, inflated, stream_eof, stream_in = pcall(stream, piece)
        if not ok then
          return nil, "invalid compressed stream"
        end
        if inflated and #inflated > 0 then
          total = total + #inflated
          if total > max_size then
            return nil, "decompressed size exceeds the maximum"
          end
          n = n + 1
          out[n] = inflated
        end
        if stream_eof then
          eof, bytes_in = true, stream_in
          break
        end
      end
      if not eof then
        return nil, "truncated compressed stream"
      end
      if bytes_in ~= len then
        return nil, "trailing data after compressed stream"
      end
      return table_concat(out, "", 1, n)
    end,
  })
end


--- Set the maximum size of a decompressed ("zip":"DEF") JWE payload.
-- By default the cap is max(250 KiB, 10 times the compressed size). Larger
-- payloads are rejected with the generic JWE failure reason.
--
-- @param max_size - integer >= 1 (bytes), or nil to restore the default
function _M.set_zip_max_size(self, max_size)
  if max_size ~= nil and (type(max_size) ~= str_const.number
      or max_size ~= math_floor(max_size) or max_size < 1) then
    error("'max_size' is expected to be an integer >= 1", 0)
  end
  self.zip_max_size = max_size
end

_M.zip_max_size = nil


--- Parse a key once for reuse as the key argument of verify, verify_with,
-- verify_jwt_obj and load_jwt (and of sign for HS* with an oct JWK).
-- See resty.jwt.jwk.load.
--
-- @param key a JWK or JWK Set (table or JSON string), a PEM/DER key or
--            certificate, a resty.openssl.pkey or a resty.openssl.x509
-- @return key object, or nil, error
function _M.load_key(self, key)
  return jwk.load(key)
end

function _M.new()
    return setmetatable({}, mt)
end

return _M
