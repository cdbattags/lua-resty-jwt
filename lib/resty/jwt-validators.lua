local _M = { _VERSION = "0.2.4" }

--[[
  This file defines "validators" to be used in validating a spec.  A "validator" is simply a function with
  a signature that matches:

    function(val, claim, jwt_json, payload)

  This function returns either true or false.  If a validator needs to give more information on why it failed,
  then it can also raise an error (which will be used in the "reason" part of the validated jwt_obj).  If a
  validator returns nil, then it is assumed to have passed (same as returning true) and that you just forgot
  to actually return a value.

  There is a special claim name of "__jwt" that can be used to validate the entire jwt_obj.

  There is a special claim name of "__header" whose value is not a validator but a table mapping
  header parameter names to validators, e.g. { __header = { typ = typ_is("at+jwt") } }.  Each one is
  called with the header parameter's value as "val" and its name as "claim".

  "val" is the value being tested.  It may be nil if the claim doesn't exist in the jwt_obj.  If the function
  is being called for the "__jwt" claim, then "val" will contain a deep clone of the full jwt object.

  "claim" is the claim that is being tested.  It is passed in just in case a validator needs to do additional
  checks.  It will be the string "__jwt" if the validator is being called for the entire jwt_object.

  "jwt_json" is a json-encoded representation of the full object that is being tested.  It will never be nil,
  and can always be decoded using cjson.decode(jwt_json).

  "payload" is the payload table of the (already verified) object being tested, for validators that check
  more than one claim.  It is the object's own table, so it must not be modified.
]]--


--[[
    A function which will define a validator.  It creates both "opt_" and required (non-"opt_")
    versions.  The function that is passed in is the *optional* version.
]]--
local function define_validator(name, fx)
  _M["opt_" .. name] = fx
  _M[name] = function(...) return _M.chain(_M.required(), fx(...)) end
end

-- Validation messages
local messages = {
  nil_validator = "Cannot create validator for nil %s.",
  wrong_type_validator = "Cannot create validator for non-%s %s.",
  empty_table_validator = "Cannot create validator for empty table %s.",
  wrong_table_type_validator = "Cannot create validator for non-%s table %s.",
  required_claim = "'%s' claim is required.",
  required_header = "'%s' header is required.",
  wrong_type_claim = "'%s' is malformed.  Expected to be a %s.",
  missing_claim = "Missing one of claims - [ %s ].",
  no_allowed_audience = "'%s' claim does not contain an allowed audience.",
  issued_in_future = "'%s' claim is in the future: issued at %s",
  issued_too_long_ago = "'%s' claim is older than the maximum age: issued at %s",
  hook_rejected = "'%s' claim was rejected.",
  hook_rejected_reason = "'%s' claim was rejected: %s"
}

-- Local function to make sure that a value is non-nil or raises an error
local function ensure_not_nil(v, e, ...)
  return v ~= nil and v or error(string.format(e, ...), 0)
end

-- Local function to make sure that a value is the given type
local function ensure_is_type(v, t, e, ...)
  return type(v) == t and v or error(string.format(e, ...), 0)
end

-- Local function to make sure that a value is a (non-empty) table
local function ensure_is_table(v, e, ...)
  ensure_is_type(v, "table", e, ...)
  return ensure_not_nil(next(v), e, ...)
end

-- Local function to make sure all entries in the table are the given type
local function ensure_is_table_type(v, t, e, ...)
  if v ~= nil then
    ensure_is_table(v, e, ...)
    for _,val in ipairs(v) do
      ensure_is_type(val, t, e, ...)
    end
  end
  return v
end

-- Local function to ensure that a number is non-negative (positive or 0)
local function ensure_is_non_negative(v, e, ...)
  if v ~= nil then
    ensure_is_type(v, "number", e, ...)
    if v >= 0 then
      return v
    else
      error(string.format(e, ...), 0)
    end
  end
end

-- A local function which returns simple equality
local function equality_function(val, check)
  return val == check
end

-- A local function which returns string match
local function string_match_function(val, pattern)
  return string.match(val, pattern) ~= nil
end

--[[
    A local function which returns truth on existence of check in vals.
    Adopted from auth0/nginx-jwt table_contains by @twistedstream
]]--
local function table_contains_function(vals, check)
    for _, val in pairs(vals) do
        if val == check then return true end
    end
    return false
end


-- A local function which returns numeric greater than comparison
local function greater_than_function(val, check)
  return val > check
end

-- A local function which returns numeric greater than or equal comparison
local function greater_than_or_equal_function(val, check)
  return val >= check
end

-- A local function which returns numeric less than comparison
local function less_than_function(val, check)
  return val < check
end

-- A local function which returns numeric less than or equal comparison
local function less_than_or_equal_function(val, check)
  return val <= check
end


--[[
    Returns a validator that chains the given functions together, one after
    another - as long as they keep passing their checks.
]]--
function _M.chain(...)
  local chain_functions = {...}
  for _, fx in ipairs(chain_functions) do
    ensure_is_type(fx, "function", messages.wrong_type_validator, "function", "chain_function")
  end

  return function(val, claim, jwt_json, payload)
    for _, fx in ipairs(chain_functions) do
      if fx(val, claim, jwt_json, payload) == false then
        return false
      end
    end
    return true
  end
end

--[[
    Returns a validator that returns false if a value doesn't exist.  If
    the value exists and a chain_function is specified, then the value of
        chain_function(val, claim, jwt_json)
    will be returned, otherwise, true will be returned.  This allows for
    specifying that a value is both required *and* it must match some
    additional check.  This function will be used in the "required_*" shortcut
    functions for simplification.
]]--
function _M.required(chain_function)
  if chain_function ~= nil then
    return _M.chain(_M.required(), chain_function)
  end

  return function(val, claim, jwt_json)
    ensure_not_nil(val, messages.required_claim, claim)
    return true
  end
end

--[[
    Returns a validator which errors with a message if *NONE* of the given claim
    keys exist.  It is expected that this function is used against a full jwt object.
    The claim_keys must be a non-empty table of strings.
]]--
function _M.require_one_of(claim_keys)
  ensure_not_nil(claim_keys, messages.nil_validator, "claim_keys")
  ensure_is_type(claim_keys, "table", messages.wrong_type_validator, "table", "claim_keys")
  ensure_is_table(claim_keys, messages.empty_table_validator, "claim_keys")
  ensure_is_table_type(claim_keys, "string", messages.wrong_table_type_validator, "string", "claim_keys")

  return function(val, claim, jwt_json)
    ensure_is_type(val, "table", messages.wrong_type_claim, claim, "table")
    ensure_is_type(val.payload, "table", messages.wrong_type_claim, claim .. ".payload", "table")

    for i, v in ipairs(claim_keys) do
      if val.payload[v] ~= nil then return true end
    end

    error(string.format(messages.missing_claim, table.concat(claim_keys, ", ")), 0)
  end
end

--[[
    Returns a validator that checks if the result of calling the given function for
    the tested value and the check value returns true.  The value of check_val and
    check_function cannot be nil.  The optional name is used for error messages and
    defaults to "check_value".  The optional check_type is used to make sure that
    the check type matches and defaults to type(check_val).  The first parameter
    passed to check_function will *never* be nil (check succeeds if value is nil).
    Use the required version to fail on nil.  If the check_function raises an
    error, that will be appended to the error message.
]]--
define_validator("check", function(check_val, check_function, name, check_type)
  name = name or "check_val"
  ensure_not_nil(check_val, messages.nil_validator, name)

  ensure_not_nil(check_function, messages.nil_validator, "check_function")
  ensure_is_type(check_function, "function", messages.wrong_type_validator, "function", "check_function")

  check_type = check_type or type(check_val)
  return function(val, claim, jwt_json)
    if val == nil then return true end

    ensure_is_type(val, check_type, messages.wrong_type_claim, claim, check_type)
    return check_function(val, check_val)
  end
end)


--[[
    Returns a validator that checks if a value exactly equals the given check_value.
    If the value is nil, then this check succeeds.  The value of check_val cannot be
    nil.
]]--
define_validator("equals", function(check_val)
  return _M.opt_check(check_val, equality_function, "check_val")
end)


--[[
    Returns a validator that checks if a value matches the given pattern.  The value
    of pattern must be a string.
]]--
define_validator("matches", function (pattern)
  ensure_is_type(pattern, "string", messages.wrong_type_validator, "string", "pattern")
  return _M.opt_check(pattern, string_match_function, "pattern", "string")
end)


--[[
    Returns a validator which calls the given function for each of the given values
    and the tested value.  If any of these calls return true, then this function
    returns true.  The value of check_values must be a non-empty table with all the
    same types, and the value of check_function must not be nil.  The optional name
    is used for error messages and defaults to "check_values".  The optional
    check_type is used to make sure that the check type matches and defaults to
    type(check_values[1]) - the table type.
]]--
define_validator("any_of", function(check_values, check_function, name, check_type, table_type)
  name = name or "check_values"
  ensure_not_nil(check_values, messages.nil_validator, name)
  ensure_is_type(check_values, "table", messages.wrong_type_validator, "table", name)
  ensure_is_table(check_values, messages.empty_table_validator, name)

  table_type = table_type or type(check_values[1])
  ensure_is_table_type(check_values, table_type, messages.wrong_table_type_validator, table_type, name)

  ensure_not_nil(check_function, messages.nil_validator, "check_function")
  ensure_is_type(check_function, "function", messages.wrong_type_validator, "function", "check_function")

  check_type = check_type or table_type
  return _M.opt_check(check_values, function(v1, v2)
    for i, v in ipairs(v2) do
      if check_function(v1, v) then return true end
    end
    return false
  end, name, check_type)
end)


--[[
    Returns a validator that checks if a value exactly equals any of the given values.
]]--
define_validator("equals_any_of", function(check_values)
  return _M.opt_any_of(check_values, equality_function, "check_values")
end)


--[[
    Returns a validator that checks if a value matches any of the given patterns.
]]--
define_validator("matches_any_of", function(patterns)
  return _M.opt_any_of(patterns, string_match_function, "patterns", "string", "string")
end)

--[[
    Returns a validator that checks if a value of expected type string exists in any of the given values.
    The value of check_values must be a non-empty table with all the same types.
    The optional name is used for error messages and defaults to "check_values".
]]--
define_validator("contains_any_of", function(check_values, name)
  return _M.opt_any_of(check_values, table_contains_function, name, "table", "string")
end)

--[[
    Returns a validator that checks how a value compares (numerically) to a given
    check_value.  The value of check_val cannot be nil and must be a number.
]]--
define_validator("greater_than", function(check_val)
  ensure_is_type(check_val, "number", messages.wrong_type_validator, "number", "check_val")
  return _M.opt_check(check_val, greater_than_function, "check_val", "number")
end)
define_validator("greater_than_or_equal", function(check_val)
  ensure_is_type(check_val, "number", messages.wrong_type_validator, "number", "check_val")
  return _M.opt_check(check_val, greater_than_or_equal_function, "check_val", "number")
end)
define_validator("less_than", function(check_val)
  ensure_is_type(check_val, "number", messages.wrong_type_validator, "number", "check_val")
  return _M.opt_check(check_val, less_than_function, "check_val", "number")
end)
define_validator("less_than_or_equal", function(check_val)
  ensure_is_type(check_val, "number", messages.wrong_type_validator, "number", "check_val")
  return _M.opt_check(check_val, less_than_or_equal_function, "check_val", "number")
end)


--[[
    A function to set the default leeway (in seconds) used for is_not_before, is_not_expired,
    is_at and issued_at when the validator isn't given its own leeway.  The default is to use 0 seconds
]]--
local system_leeway = 0
function _M.set_system_leeway(leeway)
  ensure_is_type(leeway, "number", "leeway must be a non-negative number")
  ensure_is_non_negative(leeway, "leeway must be a non-negative number")
  system_leeway = leeway
end

-- Local helper returning the leeway option of a date validator (a table such as
-- { leeway = 30 }).  nil means "use the system leeway at validation time".
local function get_leeway_option(options)
  if options == nil then
    return nil
  end
  ensure_is_type(options, "table", messages.wrong_type_validator, "table", "options")
  local leeway = options.leeway
  if leeway ~= nil then
    ensure_is_type(leeway, "number", "leeway must be a non-negative number")
    ensure_is_non_negative(leeway, "leeway must be a non-negative number")
  end
  return leeway
end


--[[
    A function to set the system clock used for is_not_before and is_not_expired.  The
    default is to use ngx.now
]]--
local system_clock = ngx.now
function _M.set_system_clock(clock)
  ensure_is_type(clock, "function", "clock must be a function")
  -- Check that clock returns the correct value
  local t = clock()
  ensure_is_type(t, "number", "clock function must return a non-negative number")
  ensure_is_non_negative(t, "clock function must return a non-negative number")
  system_clock = clock
end

-- Local helper function for date validation
local function validate_is_date(val, claim, jwt_json)
  ensure_is_non_negative(val, messages.wrong_type_claim, claim, "positive numeric value")
  return true
end

-- Local helper for date formatting
local function format_date_on_error(date_check_function, error_msg)
  ensure_is_type(date_check_function, "function", messages.wrong_type_validator, "function", "date_check_function")
  ensure_is_type(error_msg, "string", messages.wrong_type_validator, "string", error_msg)
  return function(val, claim, jwt_json)
    local ret = date_check_function(val, claim, jwt_json)
    if ret == false then
      error(string.format("'%s' claim %s %s", claim, error_msg, ngx.http_time(val)), 0)
    end
    return true
  end
end

--[[
    Returns a validator that checks if the current time is not before the tested value
    within the leeway.  This means that:
      val <= (system_clock() + leeway).
    The optional options table may set { leeway = seconds } for this validator only;
    otherwise the system leeway (see set_system_leeway) is used.
]]--
define_validator("is_not_before", function(options)
  local leeway = get_leeway_option(options)
  return format_date_on_error(
     _M.chain(validate_is_date,
        function(val)
           return val and less_than_or_equal_function(val, (system_clock() + (leeway or system_leeway)))
        end),
     "not valid until"
  )
end)


--[[
    Returns a validator that checks if the current time is not equal to or after the
    tested value within the leeway.  This means that:
      val > (system_clock() - leeway).
    The optional options table may set { leeway = seconds } for this validator only;
    otherwise the system leeway (see set_system_leeway) is used.
]]--
define_validator("is_not_expired", function(options)
  local leeway = get_leeway_option(options)
  return format_date_on_error(
     _M.chain(validate_is_date,
       function(val)
          return val and greater_than_function(val, (system_clock() - (leeway or system_leeway)))
       end),
     "expired at"
  )
end)

--[[
    Returns a validator that checks if the current time is the same as the tested value
    within the leeway.  This means that:
      val >= (system_clock() - leeway) and val <= (system_clock() + leeway).
    The optional options table may set { leeway = seconds } for this validator only;
    otherwise the system leeway (see set_system_leeway) is used.
]]--
define_validator("is_at", function(options)
  local leeway = get_leeway_option(options)
  return format_date_on_error(
    _M.chain(validate_is_date,
             function(val)
                local now = system_clock()
                local l = leeway or system_leeway
                return val and
                   greater_than_or_equal_function(val, now - l) and
                   less_than_or_equal_function(val, now + l)
             end),
    "is only valid at"
  )
end)


--[[
    Returns a validator for the "aud" claim (RFC 7519 section 4.1.3).  The
    claim may be a single string or an array of strings, and passes if *any* of
    its values is one of the allowed audiences.  The value of audiences must be
    a string or a non-empty table of strings.  An "aud" that is neither a
    string nor an array of strings fails.
]]--
define_validator("audience", function(audiences)
  if type(audiences) == "string" then
    audiences = { audiences }
  end
  ensure_not_nil(audiences, messages.nil_validator, "audiences")
  ensure_is_type(audiences, "table", messages.wrong_type_validator, "string or table", "audiences")
  ensure_is_table(audiences, messages.empty_table_validator, "audiences")
  ensure_is_table_type(audiences, "string", messages.wrong_table_type_validator, "string", "audiences")

  local allowed = {}
  for _, v in ipairs(audiences) do
    allowed[v] = true
  end
  return function(val, claim, jwt_json)
    if val == nil then return true end

    if type(val) == "string" then
      if allowed[val] then return true end
    elseif type(val) == "table" then
      -- every entry must be a string, and the table a plain array (an object
      -- such as {"1": "api"} is not an audience list)
      local count = 0
      for k, v in pairs(val) do
        if type(k) ~= "number" or type(v) ~= "string" then
          error(string.format(messages.wrong_type_claim, claim, "string or array of strings"), 0)
        end
        count = count + 1
      end
      if count ~= #val then
        error(string.format(messages.wrong_type_claim, claim, "string or array of strings"), 0)
      end
      for _, v in ipairs(val) do
        if allowed[v] then return true end
      end
    else
      error(string.format(messages.wrong_type_claim, claim, "string or array of strings"), 0)
    end
    error(string.format(messages.no_allowed_audience, claim), 0)
  end
end)


--[[
    Returns a validator for the "iat" claim (RFC 7519 section 4.1.6): it must
    be a non-negative number, and not in the future within the leeway:
      val <= (system_clock() + leeway).
    The optional options table may set { max_age = seconds } to also reject
    tokens issued too long ago:
      system_clock() - val <= max_age + leeway
    and { leeway = seconds } for this validator only; otherwise the system
    leeway (see set_system_leeway) is used.
]]--
define_validator("issued_at", function(options)
  local leeway = get_leeway_option(options)
  local max_age = options and options.max_age
  if max_age ~= nil then
    ensure_is_type(max_age, "number", "max_age must be a non-negative number")
    ensure_is_non_negative(max_age, "max_age must be a non-negative number")
  end
  return function(val, claim, jwt_json)
    if val == nil then return true end

    validate_is_date(val, claim, jwt_json)
    local now = system_clock()
    local l = leeway or system_leeway
    if val > now + l then
      error(string.format(messages.issued_in_future, claim, ngx.http_time(val)), 0)
    end
    if max_age ~= nil and now - val > max_age + l then
      error(string.format(messages.issued_too_long_ago, claim, ngx.http_time(val)), 0)
    end
    return true
  end
end)


--[[
    Returns a validator for the "jti" claim that calls hook(jti, payload), e.g.
    to detect replays.  The claim must be a string.  The hook must return true
    to accept the token; it may return false (or nil and an error message) or
    raise an error to reject it.  Claims are only validated once the token's
    signature (or a JWE's authentication tag) has been verified, so the hook
    never sees a forged token.  "payload" is the verified payload table and
    must not be modified.
]]--
define_validator("jti_hook", function(hook)
  ensure_not_nil(hook, messages.nil_validator, "hook")
  ensure_is_type(hook, "function", messages.wrong_type_validator, "function", "hook")

  return function(val, claim, jwt_json, payload)
    if val == nil then return true end

    ensure_is_type(val, "string", messages.wrong_type_claim, claim, "string")
    local ok, err = hook(val, payload)
    if not ok then
      if err ~= nil then
        error(string.format(messages.hook_rejected_reason, claim, tostring(err)), 0)
      end
      error(string.format(messages.hook_rejected, claim), 0)
    end
    return true
  end
end)


--[[
    Returns a validator which errors with a message if *ANY* of the given claim
    keys is missing from the payload.  It checks the whole payload, so attach
    it to the "__jwt" claim, e.g. { __jwt = required_claims({ "sub", "iss" }) }.
    The claim_keys must be a non-empty table of strings.
]]--
function _M.required_claims(claim_keys)
  ensure_not_nil(claim_keys, messages.nil_validator, "claim_keys")
  ensure_is_type(claim_keys, "table", messages.wrong_type_validator, "table", "claim_keys")
  ensure_is_table(claim_keys, messages.empty_table_validator, "claim_keys")
  ensure_is_table_type(claim_keys, "string", messages.wrong_table_type_validator, "string", "claim_keys")

  return function(val, claim, jwt_json, payload)
    -- called directly, without a payload: use the jwt object given for "__jwt"
    if payload == nil and type(val) == "table" then
      payload = val.payload
    end
    ensure_is_type(payload, "table", messages.wrong_type_claim, "payload", "table")

    for _, v in ipairs(claim_keys) do
      if payload[v] == nil then
        error(string.format(messages.required_claim, v), 0)
      end
    end
    return true
  end
end


--[[
    Normalizes a "typ" header value for comparison.  Media type names are case
    insensitive, and RFC 7515 section 4.1.9 says a value without a "/" is to be
    treated as if "application/" were prepended, so "application/at+jwt",
    "AT+JWT" and "at+jwt" all normalize to "at+jwt".  Returns nil for a
    non-string value.
]]--
function _M.normalize_typ(typ)
  if type(typ) ~= "string" then
    return nil
  end
  typ = string.lower(typ)
  local short = string.match(typ, "^application/([^/]*)$")
  return short or typ
end

--[[
    Returns a validator for the "typ" *header* that checks it is (one of) the
    given type(s), compared with normalize_typ (so "application/at+jwt" equals
    "at+jwt").  The value of expected must be a string or a non-empty table of
    strings.  Use it in a claim spec's "__header" table, e.g.
      { __header = { typ = validators.typ_is("at+jwt") } }
    The opt_ version passes when the header has no "typ".
]]--
function _M.opt_typ_is(expected)
  if type(expected) == "string" then
    expected = { expected }
  end
  ensure_not_nil(expected, messages.nil_validator, "expected")
  ensure_is_type(expected, "table", messages.wrong_type_validator, "string or table", "expected")
  ensure_is_table_type(expected, "string", messages.wrong_table_type_validator, "string", "expected")

  local accepted = {}
  for _, v in ipairs(expected) do
    accepted[_M.normalize_typ(v)] = true
  end
  return function(val, claim, jwt_json)
    if val == nil then return true end

    ensure_is_type(val, "string", messages.wrong_type_claim, claim, "string")
    return accepted[_M.normalize_typ(val)] == true
  end
end

function _M.typ_is(expected)
  return _M.chain(function(val, claim, jwt_json)
    ensure_not_nil(val, messages.required_header, claim)
    return true
  end, _M.opt_typ_is(expected))
end


return _M
