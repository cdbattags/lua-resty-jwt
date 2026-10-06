-- Micro-benchmark: sign and verify ops/sec for HS256, RS256 and ES256.
-- Not run in CI. From the repository root, in the testsuite container:
--
--   docker run -i --rm --entrypoint=/bin/sh -v "$(pwd)":/lua-resty-jwt \
--     -w /lua-resty-jwt cdbattags/openresty-testsuite:latest \
--     -c 'resty -I lib -I third-party/lua-resty-hmac/lib bench/jwt-bench.lua'
--
-- Optional arguments: seconds per measurement (default 1), the number of
-- rounds (default 3; the best round is reported) and a comma separated list
-- of algorithms to run (default all), e.g. `bench/jwt-bench.lua 2 5 HS256`.

local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"

local seconds = tonumber(arg and arg[1]) or 1
local rounds = tonumber(arg and arg[2]) or 3
local only = {}
for name in ((arg and arg[3]) or ""):gmatch("[^,]+") do only[name] = true end

local function read_file(name)
  local f = assert(io.open("testcerts/" .. name, "rb"))
  local s = f:read("*all")
  f:close()
  return s
end

local function now()
  ngx.update_time()
  return ngx.now()
end

-- runs fn repeatedly for `seconds`, `rounds` times; returns the best ops/sec
local function measure(fn)
  for _ = 1, 50 do fn() end -- warm up (and let the JIT compile)
  local best = 0
  for _ = 1, rounds do
    local n, start = 0, now()
    local deadline = start + seconds
    local t = start
    while t < deadline do
      for _ = 1, 20 do fn() end
      n = n + 20
      t = now()
    end
    local ops = n / (t - start)
    if ops > best then best = ops end
  end
  return best
end

local payload = {
  iss = "https://issuer.example",
  sub = "user-1234",
  aud = { "api", "web" },
  iat = math.floor(ngx.time()),
  exp = math.floor(ngx.time()) + 3600,
  scope = "read write",
}

local cases = {
  { alg = "HS256", sign_key = "a-very-secret-key-of-reasonable-size", verify_key = "a-very-secret-key-of-reasonable-size" },
  { alg = "RS256", sign_key = read_file("cert-key.pem"), verify_key = read_file("cert-pubkey.pem") },
  { alg = "ES256", sign_key = read_file("ec_cert-key.pem"), verify_key = read_file("ec_cert_pubkey.pem") },
}

local claim_spec = {
  iss = validators.equals("https://issuer.example"),
  sub = validators.required(),
  exp = validators.is_not_expired(),
}

print(string.format("%-6s %14s %14s %20s", "alg", "sign ops/s", "verify ops/s", "verify+claims ops/s"))
for _, c in ipairs(cases) do
  if next(only) and not only[c.alg] then goto continue end
  local obj = { header = { typ = "JWT", alg = c.alg, kid = "bench" }, payload = payload }
  local token = jwt:sign(c.sign_key, obj)
  local check = jwt:verify(c.verify_key, token)
  assert(check.verified, c.alg .. ": " .. tostring(check.reason))

  local sign_ops = measure(function()
    jwt:sign(c.sign_key, obj)
  end)
  local verify_ops = measure(function()
    jwt:verify(c.verify_key, token)
  end)
  local claims_ops = measure(function()
    jwt:verify(c.verify_key, token, claim_spec)
  end)
  print(string.format("%-6s %14.0f %14.0f %20.0f", c.alg, sign_ops, verify_ops, claims_ops))
  ::continue::
end
