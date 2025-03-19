local _M = {}

--- Appends all the values from source array to destination
-- @tparam table dest the destination array (array)
-- @tparam table src the source table (array)
-- @treturn reference to destination
function _M.append_array(dest, src)
    dest = dest or {}
    if src then
        for _, value in ipairs(src) do
            dest[#dest + 1] = value
        end
    end
    return dest
end

-- @function derives a 32 bit octet sequence from an integer value
-- @param int_val: integer value
-- @return 32 bit big endian value (example: 7 -> {0,0,0,7})
function _M.integer_to_32_bit_big_endian(int_val)
    return {
        math.floor(int_val / 2^24),
        math.floor((int_val % 2^24) / 2^16),
        math.floor((int_val % 2^16) / 2^8),
        math.floor(int_val % 2^8)
    }
end

-- @function converts a string into an ascii code array of its characters
-- @param str_val: input string
-- @return ascii array ( example: AGCM128 -> {65,49,50,56,71 67,77} )
function _M.string_to_ascii_array(str_val)
    local result = {}
    for i = 1, #str_val do
        local c = string.byte(str_val,i)
        result[i] = c
    end
    return result
end

-- @function derives an octet sequence (string length + ascii code of its characters) from a string value
-- @param str_val: input string
-- @return array ( example: AGCM128 -> {0,0,0,7,65,49,50,56,71 67,77} )
function _M.get_octet_sequence(str_val)
    local len = #str_val
    local result = _M.integer_to_32_bit_big_endian(len)
    _M.append_array(result, _M.string_to_ascii_array(str_val))
    return result
end

return _M
