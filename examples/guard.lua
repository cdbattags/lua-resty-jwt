local jwt = require "resty.jwt"

local jwt_token = ngx.var.arg_jwt or ngx.var.cookie_jwt
if not jwt_token then
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- always pin the algorithms you issue tokens with; tokens without "exp" are
-- refused, and "exp"/"nbf" are checked
local jwt_obj = jwt:verify_with(ngx.var.jwt_secret, jwt_token, {
    algorithms = { "HS256" },
    required_claims = { "exp" },
})

if not jwt_obj.verified then
    -- reason says why the token failed and can contain parts of it: log it,
    -- never send it to the client. A rejected token is a client error, so it
    -- is logged at info level like nginx's own client errors.
    ngx.log(ngx.INFO, "jwt rejected: ", jwt_obj.reason)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)

    -- or you can redirect to your website to get a new jwt token
    -- then redirect back
    -- return ngx.redirect("http://your-site-host/get_jwt")
end

-- remember a token that came in the query string, once it is known to be good
if ngx.var.arg_jwt then
    ngx.header['Set-Cookie'] = "jwt=" .. jwt_token .. "; Path=/; HttpOnly; Secure; SameSite=Lax"
end
