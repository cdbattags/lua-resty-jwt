-- JSON Web Keys (RFC 7517) for lua-resty-jwt: key objects, JWK Set key
-- selection and JWK thumbprints (RFC 7638).
--
-- A key set is what every key source is normalized into: a single JWK, a JWK
-- Set, a PEM/DER string, a resty.openssl.pkey or a resty.openssl.x509 object.
-- jwk.load() builds one eagerly (all keys parsed once, e.g. per worker);
-- resty.jwt builds one lazily per call when handed a raw JWK/JWKS.

local cjson = require "cjson.safe"
local pkey = require "resty.openssl.pkey"
local x509 = require "resty.openssl.x509"
local digest = require "resty.openssl.digest"
local utils = require "resty.utils"

--- A parsed key, or set of keys, from jwk.load; reusable across calls.
---@class resty.jwt.jwk.keyset
---@field keys resty.jwt.jwk.entry[]
---@field is_set boolean? built from a JWK Set

---@class resty.jwt.jwk.entry
---@field kty "RSA"|"EC"|"OKP"|"oct"
---@field crv string?
---@field kid string?
---@field use string?
---@field alg string?
---@field k string? the raw secret of an oct key
---@field public private boolean? holds private key material
---@field pkey table? (internal) the resty.openssl.pkey, once built
---@field jwk table? (internal) the JWK the pkey is built from

---@class resty.jwt.jwk
local _M = {}

local type = type
local pairs = pairs
local ipairs = ipairs
local tostring = tostring
local setmetatable = setmetatable
local getmetatable = getmetatable
local table_concat = table.concat
local ngx_log = ngx.log
local ngx_DEBUG = ngx.DEBUG
local ngx_WARN = ngx.WARN
local cjson_decode = cjson.decode
local cjson_encode = cjson.encode

local KEYSET_MT = {
  -- never print key material by accident
  __tostring = function() return "resty.jwt.jwk key set" end,
}

-- strict, canonical base64url (RFC 7515 2: no padding, URL alphabet, no
-- non-zero trailing bits), shared with resty.jwt's token parsing
local b64url_decode = utils.base64url_decode_strict
local b64url_encode = utils.base64url_encode

local ec_curves = { ["P-256"] = true, ["P-384"] = true, ["P-521"] = true }
local okp_curves = { Ed25519 = true, Ed448 = true, X25519 = true, X448 = true }

-- members holding key material per kty (RFC 7518 6, RFC 8037 2), all base64url
local kty_members = {
  RSA = { required = { "n", "e" }, optional = { "d", "p", "q", "dp", "dq", "qi" } },
  EC = { required = { "x", "y" }, optional = { "d" } },
  OKP = { required = { "x" }, optional = { "d" } },
  oct = { required = { "k" }, optional = {} },
}

-- any of these makes a JWK private (RFC 7518 6.2.2, 6.3.2, RFC 8037 2)
local private_members = { "d", "p", "q", "dp", "dq", "qi", "oth" }

--@function build a key set entry from a JWK table
-- Validates the members but does not build the OpenSSL key yet; error
-- messages never include member values (they may be private key material).
--@return entry or nil, error
local function entry_from_jwk(jwk)
  if type(jwk) ~= "table" then
    return nil, "invalid JWK: not a JSON object"
  end
  local kty = jwk.kty
  if type(kty) ~= "string" then
    return nil, "invalid JWK: missing kty"
  end
  local members = kty_members[kty]
  if not members then
    return nil, "unsupported JWK kty: " .. kty
  end

  local kid, use, alg, ops = jwk.kid, jwk.use, jwk.alg, jwk.key_ops
  if kid ~= nil and type(kid) ~= "string" then
    return nil, "invalid JWK: kid must be a string"
  end
  if use ~= nil and type(use) ~= "string" then
    return nil, "invalid JWK: use must be a string"
  end
  if alg ~= nil and type(alg) ~= "string" then
    return nil, "invalid JWK: alg must be a string"
  end
  local key_ops
  if ops ~= nil then
    if type(ops) ~= "table" then
      return nil, "invalid JWK: key_ops must be an array of strings"
    end
    key_ops = {}
    for _, op in ipairs(ops) do
      if type(op) ~= "string" then
        return nil, "invalid JWK: key_ops must be an array of strings"
      end
      key_ops[op] = true
    end
  end

  local crv = jwk.crv
  if kty == "EC" and not ec_curves[crv] then
    return nil, "unsupported JWK crv for kty EC: " .. tostring(crv)
  elseif kty == "OKP" and not okp_curves[crv] then
    return nil, "unsupported JWK crv for kty OKP: " .. tostring(crv)
  end

  for _, m in ipairs(members.required) do
    if not b64url_decode(jwk[m]) then
      return nil, "invalid " .. kty .. " JWK: \"" .. m .. "\" must be a base64url string"
    end
  end
  for _, m in ipairs(members.optional) do
    if jwk[m] ~= nil and not b64url_decode(jwk[m]) then
      return nil, "invalid " .. kty .. " JWK: \"" .. m .. "\" must be a base64url string"
    end
  end

  local entry = {
    kty = kty,
    crv = kty ~= "RSA" and kty ~= "oct" and crv or nil,
    kid = kid,
    use = use,
    alg = alg,
    key_ops = key_ops,
    from_jwk = true,
  }

  if kty == "oct" then
    local k = b64url_decode(jwk.k)
    if k == "" then
      return nil, "invalid oct JWK: \"k\" must not be empty"
    end
    entry.k = k
    return entry
  end

  local private = false
  for _, m in ipairs(private_members) do
    if jwk[m] ~= nil then
      private = true
      break
    end
  end
  entry.private = private
  entry.jwk = jwk
  return entry
end

-- OpenSSL short names -> JWK kty (and crv for OKP)
local sn_kty = {
  rsaEncryption = { kty = "RSA" },
  ["RSASSA-PSS"] = { kty = "RSA" },
  ["id-ecPublicKey"] = { kty = "EC" },
  ED25519 = { kty = "OKP", crv = "Ed25519" },
  ED448 = { kty = "OKP", crv = "Ed448" },
  X25519 = { kty = "OKP", crv = "X25519" },
  X448 = { kty = "OKP", crv = "X448" },
}

--@function build a key set entry from a resty.openssl.pkey
local function entry_from_pkey(pk, is_public)
  local ok, key_type = pcall(pk.get_key_type, pk)
  local info = ok and type(key_type) == "table" and sn_kty[key_type.sn]
  if not info then
    return nil, "unsupported key type"
  end
  local private = false
  if not is_public then
    local priv_ok, is_priv = pcall(pk.is_private, pk)
    private = priv_ok and is_priv == true
  end
  return {
    kty = info.kty,
    crv = info.crv,
    pkey = pk,
    private = private,
  }
end

--@function build a key set entry from a PEM or DER key or certificate
local function entry_from_pem_der(str)
  if not str:find("-----BEGIN", 1, true) or str:find("CERTIFICATE", 1, true) then
    local cert = x509.new(str)
    if cert then
      local pk = cert:get_pubkey()
      if pk then
        return entry_from_pkey(pk, true)
      end
    end
  end
  local pk = pkey.new(str)
  if not pk then
    return nil, "unable to parse key: expected a PEM/DER key or certificate, a JWK or a JWK Set"
  end
  return entry_from_pkey(pk)
end

--@function decode a string holding a JSON JWK or JWK Set
--@return the decoded table, or nil if the string is not one
local function decode_json_key(str)
  if not str:find("^%s*{") then
    return nil
  end
  local t = cjson_decode(str)
  if type(t) == "table" and (type(t.kty) == "string" or type(t.keys) == "table") then
    return t
  end
  return nil
end

--@function true if `str` is a JSON encoded JWK or JWK Set
---@param str any
---@return boolean
function _M.is_json_key(str)
  return type(str) == "string" and decode_json_key(str) ~= nil
end

--@function true if `obj` is a key set made by jwk.load
---@param obj any
---@return boolean
function _M.is_key(obj)
  return type(obj) == "table" and getmetatable(obj) == KEYSET_MT
end

--@function build a key set from a decoded JWK or JWK Set
--@param eager build every OpenSSL key now (skipping unusable set members)
local function keyset_from_table(t, eager)
  if t.keys ~= nil then
    if type(t.keys) ~= "table" then
      return nil, "invalid JWK Set: keys must be an array"
    end
    -- RFC 7517 5: ignore members that are not understood or are malformed
    local entries = {}
    for i, jwk in ipairs(t.keys) do
      local entry, err = entry_from_jwk(jwk)
      if entry and eager and entry.jwk then
        local pk, pk_err = _M.get_pkey(entry)
        if not pk then
          entry, err = nil, pk_err
        end
      end
      if entry then
        entries[#entries + 1] = entry
      else
        ngx_log(eager and ngx_WARN or ngx_DEBUG, "ignoring JWK Set member #", i,
          type(jwk) == "table" and type(jwk.kid) == "string" and (" (kid " .. jwk.kid .. ")") or "",
          ": ", err)
      end
    end
    if eager and #entries == 0 then
      return nil, "JWK Set has no usable keys"
    end
    return setmetatable({ keys = entries, is_set = true }, KEYSET_MT)
  end

  local entry, err = entry_from_jwk(t)
  if not entry then
    return nil, err
  end
  if eager and entry.jwk then
    local pk, pk_err = _M.get_pkey(entry)
    if not pk then
      return nil, pk_err
    end
  end
  return setmetatable({ keys = { entry } }, KEYSET_MT)
end

--@function normalize a key source into a key set without parsing keys it
-- may not need. Used by resty.jwt for raw JWK/JWKS/pkey/x509 secrets.
--@param input a key set, JWK/JWKS table or JSON string, pkey or x509 object
--@return key set; nil if `input` isn't such a key source; nil, err if malformed
---@param input any
---@return resty.jwt.jwk.keyset?
---@return string? err
function _M.to_keyset(input)
  if _M.is_key(input) then
    return input
  end
  if type(input) == "string" then
    local t = decode_json_key(input)
    if not t then
      return nil
    end
    return keyset_from_table(t, false)
  end
  if type(input) ~= "table" then
    return nil
  end
  if pkey.istype(input) then
    local entry, err = entry_from_pkey(input)
    if not entry then
      return nil, err
    end
    return setmetatable({ keys = { entry } }, KEYSET_MT)
  end
  if x509.istype(input) then
    local pk, err = input:get_pubkey()
    if not pk then
      return nil, "unable to get the certificate public key: " .. tostring(err)
    end
    local entry
    entry, err = entry_from_pkey(pk, true)
    if not entry then
      return nil, err
    end
    return setmetatable({ keys = { entry } }, KEYSET_MT)
  end
  if type(input.kty) == "string" or input.keys ~= nil then
    return keyset_from_table(input, false)
  end
  return nil
end

--- Parse a key once, for reuse as the `secret` of jwt:verify, verify_with,
-- verify_jwt_obj, load_jwt and (for HS* with an oct key) sign.
--
-- @param input a JWK or JWK Set (Lua table or JSON string), a PEM or DER
--              key or certificate string, a resty.openssl.pkey or a
--              resty.openssl.x509 object
-- @return key set object, or nil, error
---@param input any a JWK or JWK Set (table or JSON), a PEM/DER string, a pkey or an x509
---@return resty.jwt.jwk.keyset?
---@return string? err
function _M.load(input)
  if _M.is_key(input) then
    return input
  end
  if type(input) == "string" then
    local t = decode_json_key(input)
    if t then
      return keyset_from_table(t, true)
    end
    local entry, err = entry_from_pem_der(input)
    if not entry then
      return nil, err
    end
    return setmetatable({ keys = { entry } }, KEYSET_MT)
  end
  if type(input) == "table" and not pkey.istype(input) and not x509.istype(input) then
    if type(input.kty) ~= "string" and input.keys == nil then
      return nil, "invalid key: expected a JWK, a JWK Set, a PEM/DER string, a pkey or an x509 object"
    end
    return keyset_from_table(input, true)
  end
  local keyset, err = _M.to_keyset(input)
  if not keyset then
    return nil, err or "invalid key: expected a JWK, a JWK Set, a PEM/DER string, a pkey or an x509 object"
  end
  return keyset
end

--@function the resty.openssl.pkey of an asymmetric key set entry (built on
-- first use and kept on the entry)
--@return pkey or nil, error
---@param entry resty.jwt.jwk.entry
---@return table? pkey # resty.openssl.pkey
---@return string? err
function _M.get_pkey(entry)
  if entry.pkey then
    return entry.pkey
  end
  if not entry.jwk then
    return nil, "key type mismatch: not an asymmetric key"
  end
  local json = cjson_encode(entry.jwk)
  local pk = json and pkey.new(json, { format = "JWK" })
  if not pk then
    -- the OpenSSL/lua-resty-openssl error may quote member values
    return nil, "failed to load " .. entry.kty .. " JWK"
  end
  entry.pkey = pk
  entry.jwk = nil
  return pk
end

local function set(...)
  local s = {}
  for _, v in ipairs({...}) do
    s[v] = true
  end
  return s
end

local KTY_OCT = set("oct")
local KTY_RSA = set("RSA")
local KTY_EC = set("EC")
local KTY_OKP = set("OKP")

-- which keys an alg may use (RFC 7518 3.1 and 4.1, RFC 8037)
--   kty/crv: allowed key types and curves; desc: for failure reasons
--   use: the JWK "use" it requires; ops: key_ops that permit decrypting
--   private: needs a private key (decryption)
local function jws(kty, desc, crv)
  return { kty = kty, crv = crv, desc = desc, use = "sig" }
end
local function jwe(kty, desc, ops, private, crv)
  return { kty = kty, crv = crv, desc = desc, use = "enc", ops = ops, private = private }
end

local OPS_DECRYPT = set("decrypt")
local OPS_UNWRAP = set("unwrapKey")
local OPS_UNWRAP_DECRYPT = set("unwrapKey", "decrypt")
local OPS_DERIVE = set("deriveKey", "deriveBits")

local alg_requirements = {
  HS256 = jws(KTY_OCT, "a symmetric (oct)"),
  HS384 = jws(KTY_OCT, "a symmetric (oct)"),
  HS512 = jws(KTY_OCT, "a symmetric (oct)"),
  RS256 = jws(KTY_RSA, "an RSA"),
  RS384 = jws(KTY_RSA, "an RSA"),
  RS512 = jws(KTY_RSA, "an RSA"),
  PS256 = jws(KTY_RSA, "an RSA"),
  PS384 = jws(KTY_RSA, "an RSA"),
  PS512 = jws(KTY_RSA, "an RSA"),
  ES256 = jws(KTY_EC, "an EC P-256", set("P-256")),
  ES384 = jws(KTY_EC, "an EC P-384", set("P-384")),
  ES512 = jws(KTY_EC, "an EC P-521", set("P-521")),
  Ed25519 = jws(KTY_OKP, "an Ed25519", set("Ed25519")),
  Ed448 = jws(KTY_OKP, "an Ed448", set("Ed448")),
  EdDSA = jws(KTY_OKP, "an Ed25519 or Ed448", set("Ed25519", "Ed448")),

  dir = jwe(KTY_OCT, "a symmetric (oct)", OPS_DECRYPT),
  A128KW = jwe(KTY_OCT, "a symmetric (oct)", OPS_UNWRAP),
  A192KW = jwe(KTY_OCT, "a symmetric (oct)", OPS_UNWRAP),
  A256KW = jwe(KTY_OCT, "a symmetric (oct)", OPS_UNWRAP),
  A128GCMKW = jwe(KTY_OCT, "a symmetric (oct)", OPS_UNWRAP_DECRYPT),
  A192GCMKW = jwe(KTY_OCT, "a symmetric (oct)", OPS_UNWRAP_DECRYPT),
  A256GCMKW = jwe(KTY_OCT, "a symmetric (oct)", OPS_UNWRAP_DECRYPT),
  ["PBES2-HS256+A128KW"] = jwe(KTY_OCT, "a symmetric (oct)", OPS_DERIVE),
  ["PBES2-HS384+A192KW"] = jwe(KTY_OCT, "a symmetric (oct)", OPS_DERIVE),
  ["PBES2-HS512+A256KW"] = jwe(KTY_OCT, "a symmetric (oct)", OPS_DERIVE),
  ["RSA-OAEP"] = jwe(KTY_RSA, "an RSA", OPS_UNWRAP_DECRYPT, true),
  ["RSA-OAEP-256"] = jwe(KTY_RSA, "an RSA", OPS_UNWRAP_DECRYPT, true),
  ["RSA-OAEP-384"] = jwe(KTY_RSA, "an RSA", OPS_UNWRAP_DECRYPT, true),
  ["RSA-OAEP-512"] = jwe(KTY_RSA, "an RSA", OPS_UNWRAP_DECRYPT, true),
  -- ECDH-ES with X25519/X448 (RFC 8037) isn't supported: the epk validation
  -- in resty.jwt accepts EC keys only
  ["ECDH-ES"] = jwe(KTY_EC, "an EC", OPS_DERIVE, true),
  ["ECDH-ES+A128KW"] = jwe(KTY_EC, "an EC", OPS_DERIVE, true),
  ["ECDH-ES+A192KW"] = jwe(KTY_EC, "an EC", OPS_DERIVE, true),
  ["ECDH-ES+A256KW"] = jwe(KTY_EC, "an EC", OPS_DERIVE, true),
}

-- key_ops a JWS operation needs
local jws_ops = { verify = "verify", sign = "sign" }

--@function why a key set entry can't be used for `alg`
--@param purpose "verify", "sign" or "decrypt"
--@return nil if usable, failure reason otherwise
local function entry_rejection(entry, alg, req, purpose)
  if not req.kty[entry.kty] or (req.crv and entry.crv and not req.crv[entry.crv]) then
    return "key type mismatch: alg " .. alg .. " requires " .. req.desc .. " key"
  end
  if entry.use ~= nil and entry.use ~= req.use then
    return "JWK use \"" .. entry.use .. "\" does not permit alg " .. alg
  end
  if entry.key_ops ~= nil then
    local permitted = false
    if req.ops then
      for op in pairs(req.ops) do
        if entry.key_ops[op] then
          permitted = true
          break
        end
      end
    else
      permitted = entry.key_ops[jws_ops[purpose]] == true
    end
    if not permitted then
      return "JWK key_ops do not permit alg " .. alg
    end
  end
  if entry.alg ~= nil and entry.alg ~= alg then
    return "JWK alg " .. entry.alg .. " does not match token alg " .. alg
  end
  -- a verifier only needs the public key: private members in a verification
  -- JWK (e.g. a published JWKS) mean key material is in the wrong place
  if purpose == "verify" and entry.private and entry.from_jwk then
    return "JWK for signature verification must not contain private key members"
  end
  if req.private and entry.kty ~= "oct" and entry.private == false then
    return "alg " .. alg .. " requires a private key"
  end
  return nil
end

--- Select the key to use for a token from a key set.
--
-- With a JWK Set the header kid (if any) picks the candidates, which are then
-- filtered by kty/crv for alg, use (sig/enc), key_ops and the JWK alg. A
-- single match is used; several are an "ambiguous key" error. A key set
-- holding one key that isn't a JWK Set always uses that key (kid isn't
-- required to match) after the same checks.
--
-- @param keyset key set
-- @param alg the token alg
-- @param kid the token header kid (or nil)
-- @param purpose "verify", "sign" or "decrypt"
-- @return entry or nil, failure reason
---@param keyset resty.jwt.jwk.keyset
---@param alg string
---@param kid string?
---@param purpose "verify"|"sign"|"decrypt"
---@return resty.jwt.jwk.entry?
---@return string? reason
function _M.select(keyset, alg, kid, purpose)
  local req = alg_requirements[alg]
  if not req then
    return nil, "unsupported alg for key selection: " .. tostring(alg)
  end
  local keys = keyset.keys

  if not keyset.is_set then
    local entry = keys[1]
    local reason = entry_rejection(entry, alg, req, purpose)
    if reason then
      return nil, reason
    end
    return entry
  end

  if kid ~= nil and type(kid) ~= "string" then
    return nil, "invalid kid in header: must be a string"
  end

  local found, last_reason = nil, nil
  local count = 0
  for _, entry in ipairs(keys) do
    if kid == nil or entry.kid == kid then
      local reason = entry_rejection(entry, alg, req, purpose)
      if reason then
        last_reason = reason
      else
        count = count + 1
        found = entry
      end
    end
  end

  if count == 1 then
    return found
  end
  if count > 1 then
    if kid ~= nil then
      return nil, "ambiguous key: " .. count .. " keys in the JWK Set match kid " .. kid .. " and alg " .. alg
    end
    return nil, "ambiguous key: " .. count .. " keys in the JWK Set match alg " .. alg .. "; the token needs a kid"
  end
  if kid ~= nil then
    return nil, last_reason or ("no key in the JWK Set matches kid " .. kid)
  end
  return nil, "no key in the JWK Set matches alg " .. alg
end

-- RFC 7638 3.2: required members per kty, in lexicographic order
local thumbprint_members = {
  RSA = { "e", "kty", "n" },
  EC = { "crv", "kty", "x", "y" },
  OKP = { "crv", "kty", "x" },
  oct = { "k", "kty" },
}

--- Compute the JWK thumbprint (RFC 7638) of a public or private JWK.
--
-- @param jwk JWK as a Lua table or JSON string
-- @param hash digest name, default "SHA256"
-- @return base64url encoded thumbprint, or nil, error
---@param jwk string|table
---@param hash string? digest name, default "SHA256"
---@return string? thumbprint
---@return string? err
function _M.thumbprint(jwk, hash)
  if type(jwk) == "string" then
    jwk = cjson_decode(jwk)
  end
  if type(jwk) ~= "table" then
    return nil, "invalid JWK: not a JSON object"
  end
  local members = thumbprint_members[jwk.kty]
  if not members then
    return nil, "unsupported JWK kty: " .. tostring(jwk.kty)
  end
  local parts = {}
  for i, m in ipairs(members) do
    local v = jwk[m]
    -- the members are base64url strings or names (crv), so no JSON escaping
    -- is ever needed; anything else is rejected rather than mis-encoded
    if type(v) ~= "string" or v:find("[^%w_%-]") then
      return nil, "invalid JWK: \"" .. m .. "\" is missing or malformed"
    end
    parts[i] = '"' .. m .. '":"' .. v .. '"'
  end
  local d, err = digest.new(hash or "SHA256")
  if not d then
    return nil, "unsupported hash: " .. tostring(err)
  end
  local md
  md, err = d:final("{" .. table_concat(parts, ",") .. "}")
  if not md then
    return nil, err
  end
  return b64url_encode(md)
end

_M.base64url_decode = b64url_decode

return _M
