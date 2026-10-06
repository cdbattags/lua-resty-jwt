How You Can Use lua-resty-jwt
=============================

Both examples pin the accepted algorithms with `verify_with` and answer a
rejected token with a bare `401`. They never send `jwt_obj.reason` to the
client: it explains why a token failed and can contain parts of it. They log
it at `info` level instead (set `error_log ... info;` to see it).

### jwt auth using query and cookie

nginx config
```
location / {
    access_log off;
    default_type text/plain;

    set $jwt_secret "your-own-jwt-secret";
    access_by_lua_file /etc/nginx/lua/guard.lua;

    echo "i am protected by jwt guard";
}
```
[guard.lua](guard.lua) expects HS256 tokens with an `exp` claim, in the `jwt`
query argument or cookie, and sets the cookie once a token from the query
string has been verified.


### jwt auth with kid and store keys in redis
nginx config
```
location / {
    set $redhost "127.0.0.1";
    set $redport 6379;
    # set $reddb 1;
    # set $redauth "your-redis-pass";
    access_by_lua_file /etc/nginx/lua/redjwt.lua;

    echo "i am protected jwt guard";
}
```
[redjwt.lua](redjwt.lua) reads the HS256 key for the token's `kid` from
Redis, caching it in `lua_shared_dict jwt_key_dict`, and fails closed (`503`)
when Redis can't be reached.
