local digest = require "resty.openssl.digest"

local _M = {}

local string_byte = string.byte
local string_char = string.char
local string_sub = string.sub
local table_concat = table.concat
local table_insert = table.insert
local math_floor = math.floor
local math_ceil = math.ceil
local unpack = unpack

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
