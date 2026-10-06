local digest = require "resty.openssl.digest"

local _M = {}

local type = type
local string_byte = string.byte
local string_char = string.char
local string_rep = string.rep
local string_sub = string.sub
local table_concat = table.concat
local table_insert = table.insert
local math_floor = math.floor
local math_ceil = math.ceil
local unpack = unpack
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64
-- lua-resty-core's ngx.base64 encodes/decodes base64url directly; without it
-- (e.g. outside OpenResty) standard base64 is translated
local has_ngx_base64, ngx_base64 = pcall(require, "ngx.base64")
local encode_base64url = has_ngx_base64 and ngx_base64.encode_base64url or nil
local decode_base64url = has_ngx_base64 and ngx_base64.decode_base64url or nil

--- base64url encode without padding (RFC 7515 Section 2)
---@param s string
function _M.base64url_encode(s)
    if encode_base64url then
        return (encode_base64url(s))
    end
    return (ngx_encode_base64(s):gsub("%+", "-"):gsub("/", "_"):gsub("=", ""))
end

--- Strict base64url decode (RFC 7515 Section 2): URL-safe alphabet only, no
-- padding, and the canonical encoding only (no non-zero trailing bits), so
-- every value has exactly one accepted spelling.
---@param s string
---@return string|nil decoded bytes, or nil if `s` isn't canonical base64url
function _M.base64url_decode_strict(s)
    if type(s) ~= "string" or s:find("[^A-Za-z0-9_%-]") or #s % 4 == 1 then
        return nil
    end
    local data
    if decode_base64url then
        data = decode_base64url(s)
    else
        local b64 = s:gsub("%-", "+"):gsub("_", "/")
        local rem = #b64 % 4
        if rem > 0 then
            b64 = b64 .. string_rep("=", 4 - rem)
        end
        data = ngx_decode_base64(b64)
    end
    if not data or _M.base64url_encode(data) ~= s then
        return nil
    end
    return data
end

function _M.append_array(dest, src)
    dest = dest or {}
    if src then
        for _, value in ipairs(src) do
            dest[#dest + 1] = value
        end
    end
    return dest
end

function _M.integer_to_32_bit_big_endian(int_val)
    return {
        math_floor(int_val / 0x1000000) % 0x100,
        math_floor(int_val / 0x10000) % 0x100,
        math_floor(int_val / 0x100) % 0x100,
        int_val % 0x100
    }
end

function _M.string_to_byte_array(str_val)
    local result = {}
    for i = 1, #str_val do
        result[i] = string_byte(str_val, i)
    end
    return result
end

-- RFC 7518 Section 4.6.2 - Concat KDF otherInfo field:
-- length-prefixed octet string
function _M.get_octet_sequence(str_val)
    local result = _M.integer_to_32_bit_big_endian(#str_val)
    _M.append_array(result, _M.string_to_byte_array(str_val))
    return result
end

local function uint32_be(int_val)
    return string_char(unpack(_M.integer_to_32_bit_big_endian(int_val)))
end

local function length_prefixed(str_val)
    return uint32_be(#str_val) .. str_val
end

-- RFC 7518 Section 4.6.2 - Concat KDF (NIST SP 800-56A, single-step KDF with SHA-256)
-- @param shared_secret_z  ECDH shared secret Z (binary string)
-- @param algorithm_id     AlgorithmID content: the "enc" value for direct key
--                         agreement, the "alg" value when the result is a key wrapping key
-- @param keydatalen       desired key length in bits
-- @param party_u_info     decoded "apu" (binary string, may be empty)
-- @param party_v_info     decoded "apv" (binary string, may be empty)
-- @return derived key (binary string of keydatalen / 8 octets)
function _M.concat_kdf(shared_secret_z, algorithm_id, keydatalen, party_u_info, party_v_info)
    local other_info = length_prefixed(algorithm_id)
        .. length_prefixed(party_u_info or "")
        .. length_prefixed(party_v_info or "")
        .. uint32_be(keydatalen)

    local hashlen = 256
    local reps = math_ceil(keydatalen / hashlen)
    local derived = {}
    for round = 1, reps do
        local d, err = digest.new("SHA256")
        if not d then
            error({reason="failed to create SHA256 digest: " .. (err or "")})
        end
        local md, hash_err = d:final(uint32_be(round) .. shared_secret_z .. other_info)
        if not md then
            error({reason="failed to compute KDF hash: " .. (hash_err or "")})
        end
        derived[round] = md
    end

    return string_sub(table_concat(derived), 1, keydatalen / 8)
end

return _M
