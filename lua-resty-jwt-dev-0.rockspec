rockspec_format = '3.0'
package = 'lua-resty-jwt'
version = 'dev-0'
source = {
  url = 'file://.'
}
description = {
  summary = 'JWT for ngx_lua and LuaJIT.',
  detailed = [[
    JWS and JWE (JWT) signing, verification, encryption and decryption
    for OpenResty. Requires OpenResty (ngx_lua and LuaJIT) built with
    OpenSSL, and lua-resty-openssl.
  ]],
  homepage = 'https://github.com/cdbattags/lua-resty-jwt',
  license = 'Apache License Version 2'
}
dependencies = {
  'lua >= 5.1',
  'lua-resty-openssl >= 1.1.0'
}
build = {
  type = 'builtin',
  modules = {
    ['resty.jwt'] = 'lib/resty/jwt.lua',
    ['resty.jwt.jwk'] = 'lib/resty/jwt/jwk.lua',
    ['resty.evp'] = 'lib/resty/evp.lua',
    ['resty.jwt-validators'] = 'lib/resty/jwt-validators.lua',
    ['resty.jwt-zlib'] = 'lib/resty/jwt-zlib.lua',
    ['resty.utils'] = 'lib/resty/utils.lua',
    ['resty.hmac'] = 'third-party/lua-resty-hmac/lib/resty/hmac.lua'
  }
}
