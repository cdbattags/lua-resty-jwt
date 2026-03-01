local _M = {}

local string_byte = string.byte
local string_char = string.char
local table_insert = table.insert
local math_floor = math.floor

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

return _M
