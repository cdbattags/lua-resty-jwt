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
local bit = require "bit"

local _M = { _VERSION = "0.3.2" }

local mt = {
    __index = _M
}

local string_rep = string.rep
local string_format = string.format
local string_sub = string.sub
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
  regex_join_delim = "([^%s]+)",
  regex_split_dot = "%.",
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

-- @function split string
local function split_string(str, delim)
  local result = {}
  local sep = string_format(str_const.regex_join_delim, delim)
  for m in str:gmatch(sep) do
    result[#result+1]=m
  end
  return result
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


-- key length in bits for Concat KDF (GCM modes only for ECDH-ES direct agreement)
local keydatalen_map = {
  [str_const.A128GCM] = 128,
  [str_const.A192GCM] = 192,
  [str_const.A256GCM] = 256,
  [str_const.A128CBC_HS256] = 256,
  [str_const.A192CBC_HS384] = 384,
  [str_const.A256CBC_HS512] = 512,
  [str_const.A128KW] = 128,
  [str_const.A192KW] = 192,
  [str_const.A256KW] = 256,
}

-- OpenSSL NID -> curve name for EC key generation
local ec_nid_to_curve = {
  [415] = "prime256v1",
  [714] = "secp256k1",
  [715] = "secp384r1",
  [716] = "secp521r1",
}

-- RFC 7518 Section 4.6.2 - Concat KDF (multi-round SHA-256)
-- reps = ceil(keydatalen / hashlen); hashlen = 256 for SHA-256
local function derive_shared_key(header, shared_secret_Z)
    local enc = header.enc
    local keydatalen = keydatalen_map[enc]
    if not keydatalen then
        error({reason="unsupported enc for ECDH-ES key derivation: " .. enc})
    end

    local other_info = {}
    utils.append_array(other_info, utils.get_octet_sequence(enc))

    local empty_octet = utils.integer_to_32_bit_big_endian(0)
    local party_u = empty_octet
    if header.apu then
        local apu_decoded = ngx_decode_base64(header.apu)
        if apu_decoded then
            party_u = utils.get_octet_sequence(apu_decoded)
        end
    end
    utils.append_array(other_info, party_u)

    local party_v = empty_octet
    if header.apv then
        local apv_decoded = ngx_decode_base64(header.apv)
        if apv_decoded then
            party_v = utils.get_octet_sequence(apv_decoded)
        end
    end
    utils.append_array(other_info, party_v)

    utils.append_array(other_info, utils.integer_to_32_bit_big_endian(keydatalen))

    local hashlen = 256
    local reps = math.ceil(keydatalen / hashlen)
    local z_bytes = utils.string_to_byte_array(shared_secret_Z)
    local derived = {}

    for round = 1, reps do
        local counter = utils.integer_to_32_bit_big_endian(round)
        local round_concat = {}
        utils.append_array(round_concat, counter)
        utils.append_array(round_concat, z_bytes)
        utils.append_array(round_concat, other_info)

        local input = string_char(unpack(round_concat))
        local d, err = digest.new("SHA256")
        if not d then
            error({reason="failed to create SHA256 digest: " .. (err or "")})
        end
        local md, hash_err = d:final(input)
        if not md then
            error({reason="failed to compute KDF hash: " .. (hash_err or "")})
        end
        derived[round] = md
    end

    local full = table_concat(derived)
    return string_sub(full, 1, keydatalen / 8)
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

--@function parse_jwe
--@param pre-shared key
--@encoded-header
local function parse_jwe(self, preshared_key, encoded_header, encoded_encrypted_key, encoded_iv, encoded_cipher_text, encoded_auth_tag)


  local header = _M:jwt_decode(encoded_header, true)
  if type(header) ~= str_const.table then
    error({reason="invalid header: " .. encoded_header})
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

  local key, enc_key, _
  if alg == str_const.DIR then
    if not preshared_key  then
        error({reason="preshared key must not be null"})
    end
    key, _, enc_key = derive_keys(header.enc, preshared_key)
  elseif alg == str_const.ECDH_ES then
    if not preshared_key then
        error({reason="EC private key must not be null"})
    end
    local epk_jwk = header.epk
    if not epk_jwk then
        error({reason="missing epk in JWE header"})
    end
    local private_key, priv_err = pkey.new(preshared_key)
    if not private_key then
        error({reason="failed to load EC private key: " .. (priv_err or "")})
    end
    local epk, epk_err = pkey.new(cjson_encode(epk_jwk), { format = "JWK" })
    if not epk then
        error({reason="failed to load ephemeral public key: " .. (epk_err or "")})
    end
    local Z, derive_err = private_key:derive(epk)
    if not Z then
        error({reason="ECDH key derivation failed: " .. (derive_err or "")})
    end
    local derived_key = derive_shared_key(header, Z)
    key, _, enc_key = derive_keys(header.enc, derived_key)
  elseif alg == str_const.ECDH_ES_A128KW or alg == str_const.ECDH_ES_A192KW or alg == str_const.ECDH_ES_A256KW then
    if not preshared_key then
        error({reason="EC private key must not be null"})
    end
    local epk_jwk = header.epk
    if not epk_jwk then
        error({reason="missing epk in JWE header"})
    end
    local private_key, priv_err = pkey.new(preshared_key)
    if not private_key then
        error({reason="failed to load EC private key: " .. (priv_err or "")})
    end
    local epk, epk_err = pkey.new(cjson_encode(epk_jwk), { format = "JWK" })
    if not epk then
        error({reason="failed to load ephemeral public key: " .. (epk_err or "")})
    end
    local Z, derive_err = private_key:derive(epk)
    if not Z then
        error({reason="ECDH key derivation failed: " .. (derive_err or "")})
    end
    local kw_alg_map = {
        [str_const.ECDH_ES_A128KW] = str_const.A128KW,
        [str_const.ECDH_ES_A192KW] = str_const.A192KW,
        [str_const.ECDH_ES_A256KW] = str_const.A256KW,
    }
    local kw_alg = kw_alg_map[alg]
    local kek = derive_shared_key({ enc = kw_alg, apu = header.apu, apv = header.apv }, Z)
    local wrapped_key = _M:jwt_decode(encoded_encrypted_key)
    local secret_key = aes_key_unwrap(kek, wrapped_key)
    key, _, enc_key = derive_keys(header.enc, secret_key)
  elseif alg == str_const.A128KW or alg == str_const.A192KW or alg == str_const.A256KW then
    if not preshared_key then
        error({reason="AES key wrap key must not be null"})
    end
    local wrapped_key = _M:jwt_decode(encoded_encrypted_key)
    local secret_key = check_cek_len(enc, aes_key_unwrap(preshared_key, wrapped_key))
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
    local secret_key = check_cek_len(enc, aes_gcm_key_unwrap(preshared_key, wrapped_key, kw_iv, kw_tag))
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
    local kek = pbes2_derive_kek(alg, preshared_key, p2s, p2c)
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
    local rsa_decryptor, err = evp.RSADecryptor:new(preshared_key, nil, evp.CONST.RSA_PKCS1_OAEP_PADDING, digest_alg)
    if err then
        error({reason="failed to create rsa object: ".. err})
    end
    local secret_key, err = rsa_decryptor:decrypt(_M:jwt_decode(encoded_encrypted_key))
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
  if not cipher_text then
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

  return {
    typ = str_const.JWE,
    internal = {
      authenticated = JWE_AUTHENTICATED,
      json_payload = payload
    },
    header = header,
    signature = signature_or_tag,
    payload = get_payload_decoder(self)(payload)
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

  -- Try JSON decoding first; fall back to raw string for non-JSON payloads (RFC 7515)
  local payload = _M:jwt_decode(encoded_payload, true, true)
  if not payload then
    payload = _M:jwt_decode(encoded_payload, false)
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
local function parse(self, secret, token_str)
  local tokens = split_string(token_str, str_const.regex_split_dot)
  local num_tokens = #tokens
  if num_tokens == 3 then
    return  parse_jwt(self, tokens[1], tokens[2], tokens[3])
  elseif num_tokens == 4  then
    return parse_jwe(self, secret, tokens[1], nil, tokens[2], tokens[3],  tokens[4])
  elseif num_tokens == 5 then
    return parse_jwe(self, secret, tokens[1], tokens[2], tokens[3],  tokens[4], tokens[5])
  else
    error({reason=str_const.invalid_jwt})
  end
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
function _M.set_trusted_certs_file(self, filename)
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
  if alg ==  str_const.DIR then
    _, mac_key, enc_key = derive_keys(enc, secret_key)
    encrypted_key = ""
  elseif alg == str_const.ECDH_ES then
    local public_key, pub_err = pkey.new(secret_key)
    if not public_key then
        error({reason="failed to load EC public key: " .. (pub_err or "")})
    end
    local params, param_err = public_key:get_parameters()
    if not params then
        error({reason="failed to get EC key parameters: " .. (param_err or "")})
    end
    local curve = ec_nid_to_curve[params.group]
    if not curve then
        error({reason="unsupported EC curve NID: " .. tostring(params.group)})
    end
    local ephemeral, eph_err = pkey.new({ type = "EC", curve = curve })
    if not ephemeral then
        error({reason="failed to generate ephemeral EC key: " .. (eph_err or "")})
    end
    header.epk = cjson_decode(ephemeral:tostring("public", "JWK"))
    encoded_header = _M:jwt_encode(header)
    local Z, derive_err = ephemeral:derive(public_key)
    if not Z then
        error({reason="ECDH key derivation failed: " .. (derive_err or "")})
    end
    local derived_key = derive_shared_key(header, Z)
    _, mac_key, enc_key = derive_keys(enc, derived_key)
    encrypted_key = ""
  elseif alg == str_const.ECDH_ES_A128KW or alg == str_const.ECDH_ES_A192KW or alg == str_const.ECDH_ES_A256KW then
    local public_key, pub_err = pkey.new(secret_key)
    if not public_key then
        error({reason="failed to load EC public key: " .. (pub_err or "")})
    end
    local params, param_err = public_key:get_parameters()
    if not params then
        error({reason="failed to get EC key parameters: " .. (param_err or "")})
    end
    local curve = ec_nid_to_curve[params.group]
    if not curve then
        error({reason="unsupported EC curve NID: " .. tostring(params.group)})
    end
    local ephemeral, eph_err = pkey.new({ type = "EC", curve = curve })
    if not ephemeral then
        error({reason="failed to generate ephemeral EC key: " .. (eph_err or "")})
    end
    header.epk = cjson_decode(ephemeral:tostring("public", "JWK"))
    encoded_header = _M:jwt_encode(header)
    local Z, derive_err = ephemeral:derive(public_key)
    if not Z then
        error({reason="ECDH key derivation failed: " .. (derive_err or "")})
    end
    local kw_alg_map = {
        [str_const.ECDH_ES_A128KW] = str_const.A128KW,
        [str_const.ECDH_ES_A192KW] = str_const.A192KW,
        [str_const.ECDH_ES_A256KW] = str_const.A256KW,
    }
    local kw_alg = kw_alg_map[alg]
    local kek = derive_shared_key({ enc = kw_alg, apu = header.apu, apv = header.apv }, Z)
    key, mac_key, enc_key = derive_keys(enc)
    encrypted_key = aes_key_wrap(kek, key)
  elseif alg == str_const.A128KW or alg == str_const.A192KW or alg == str_const.A256KW then
    key, mac_key, enc_key = derive_keys(enc)
    encrypted_key = aes_key_wrap(secret_key, key)
  elseif alg == str_const.A128GCMKW or alg == str_const.A192GCMKW or alg == str_const.A256GCMKW then
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
        error({reason="Decode secret is not a valid cert/public key: " .. (err and err or secret_key)})
    end
    local oaep_digest = {
      [str_const.RSA_OAEP] = evp.CONST.SHA1_DIGEST,
      [str_const.RSA_OAEP_256] = evp.CONST.SHA256_DIGEST,
      [str_const.RSA_OAEP_384] = evp.CONST.SHA384_DIGEST,
      [str_const.RSA_OAEP_512] = evp.CONST.SHA512_DIGEST,
    }
    local digest_alg = oaep_digest[alg]
    local rsa_encryptor = evp.RSAEncryptor:new(cert, evp.CONST.RSA_PKCS1_OAEP_PADDING, digest_alg)
    if err then
        error("failed to create rsa object for encryption ".. err)
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

--@function get_secret_str  : returns the secret if it is a string, or the result of a function
--@param either the string secret or a function that takes a string parameter and returns a string or nil
--@param  jwt payload
--@return the secret as a string or as a function
local function get_secret_str(secret_or_function, jwt_obj)
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
  elseif type(secret_or_function) == str_const.string then
    -- Just return the string
    return secret_or_function
  else
    -- Throw an error
    error({reason="invalid secret type (must be string or function)"})
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
  if secret:find(str_const.pem_begin, 1, true) then
    error({reason="invalid secret for " .. alg .. ": PEM key material cannot be used as an HMAC secret"})
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
  local secret_str = get_secret_str(secret, jwt_obj)
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
  if typ ~= nil then
    if typ ~= str_const.JWT and typ ~= str_const.JWE then
      error({reason="invalid typ: " .. tostring(typ)})
    end
  end

  if jwt_obj.typ == str_const.JWE or (jwt_obj.typ == nil and (typ == str_const.JWE or jwt_obj.header.enc)) then
    return sign_jwe(self, secret_key, jwt_obj)
  end
  -- header alg check
  local raw_header = get_raw_part(str_const.header, jwt_obj)
  local raw_payload = get_raw_part(str_const.payload, jwt_obj)
  local message = string_format(str_const.regex_join_msg, raw_header, raw_payload)
  local alg = jwt_obj[str_const.header][str_const.alg]
  local signature = ""
  if hmac_algs[alg] then
    local secret_str = get_secret_str(secret_key, jwt_obj)
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
    for _, fx in pairs(claim_spec) do
      if type(fx) ~= str_const.funct then
        error("Claim spec value must be a function - see jwt-validators.lua for helper functions", 0)
      end
    end
  end
  return claim_specs
end

-- Validates the claims of an authenticated object against prepared claim specs.
-- Must only be called once the signature/authentication tag has been verified,
-- so validators never see (or leak, through failure reasons) forged claims.
local function validate_claims(jwt_obj, claim_specs)
  -- Encode the current jwt_obj and use it when calling the individual validation functions
  local jwt_json = cjson_encode(jwt_obj)
  -- Claims only exist in JSON object payloads. Indexing a string payload would
  -- otherwise hit the string library (e.g. "sub" -> string.sub).
  local payload = jwt_obj[str_const.payload]

  -- Validate all our specs
  for _, claim_spec in ipairs(claim_specs) do
    for claim, fx in pairs(claim_spec) do
      local val
      if claim == str_const.full_obj then
        val = cjson_decode(jwt_json)
      elseif type(payload) == str_const.table then
        val = payload[claim]
      end
      local success, ret = pcall(fx, val, claim, jwt_json)
      if not success then
        if type(ret) == str_const.table and ret.reason ~= nil then
          jwt_obj[str_const.reason] = tostring(ret.reason)
        elseif type(ret) == str_const.string then
          jwt_obj[str_const.reason] = string.gsub(ret, "^.-:%d-: ", "")
        else
          jwt_obj[str_const.reason] = string.format("Claim '%s' validation failed", tostring(claim))
        end
        return false
      elseif ret == false then
        jwt_obj[str_const.reason] = string.format("Claim '%s' ('%s') returned failure", tostring(claim), tostring(val))
        return false
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
    local cert, cert_str, err
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
      if type(secret) ~= str_const.string then
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

    local key_str = self.trusted_certs_file ~= nil and cert_str or secret
    local load_ok, pk = pcall(load_verify_pkey, key_str)
    if not load_ok or not pk then
      jwt_obj[str_const.reason] = "Unable to determine the verification key type"
      return jwt_obj
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
    local pk, pk_err
    if type(secret) == str_const.string then
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

--- Verify a JWS/JWE string, pinning the accepted algorithms for this call.
--
-- jwt:verify_with(secret, jwt_str, {
--   algorithms = { "RS256", "ES256" },   -- required: allowed "alg" header values
--   claim_specs = { spec1, spec2 },      -- optional: same as verify()'s varargs
-- })
--
-- The alg is checked before the token is parsed, so a JWE using a
-- disallowed key management algorithm is never decrypted. Applies in
-- addition to set_alg_whitelist().
function _M.verify_with(self, secret, jwt_str, options)
  if type(options) ~= str_const.table then
    error("verify_with: options must be a table", 0)
  end
  local allowed = get_allowed_algorithms(options.algorithms)
  local claim_specs = options.claim_specs or {}
  if type(claim_specs) ~= str_const.table then
    error("verify_with: options.claim_specs must be a list of claim specs", 0)
  end

  if type(jwt_str) ~= str_const.string then
    return {verified=false, reason=str_const.invalid_jwt}
  end
  local encoded_header = split_string(jwt_str, str_const.regex_split_dot)[1]
  local header = encoded_header and _M:jwt_decode(encoded_header, true)
  if type(header) == str_const.table then
    local alg = header[str_const.alg]
    if alg ~= nil and type(alg) ~= str_const.string then
      return {verified=false, reason="invalid alg: must be a string"}
    end
    if not allowed[alg] then
      return {verified=false, reason="whitelist unsupported alg: " .. tostring(alg)}
    end
  end
  -- otherwise load_jwt reports the malformed header

  return _M.verify(self, secret, jwt_str, unpack(claim_specs))
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


function _M.new()
    return setmetatable({}, mt)
end

return _M
