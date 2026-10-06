-- Raw DEFLATE (RFC 1951) for the JWE "zip":"DEF" header (RFC 7516 4.1.3),
-- bound through the LuaJIT FFI to the system zlib. OpenResty's nginx already
-- links zlib, so this adds no dependency there; when zlib (or the FFI) cannot
-- be found the module still loads with `available = false`.
--
-- inflate is bounded: output is produced in fixed-size chunks and the stream is
-- abandoned as soon as it would exceed the caller's maximum, so a decompression
-- bomb never allocates more than max_size plus one chunk.

local _M = { available = false }

local ok_ffi, ffi = pcall(require, "ffi")
if not ok_ffi then
  _M.err = "LuaJIT FFI is not available"
  return _M
end

local ffi_new = ffi.new
local ffi_string = ffi.string
local ffi_sizeof = ffi.sizeof
local ffi_cast = ffi.cast
local table_concat = table.concat
local ipairs = ipairs
local pcall = pcall
local type = type
local tonumber = tonumber

-- zlib symbols are declared under private names (asm redirection) so these
-- declarations can never clash with another module's cdef of zlib.
if not pcall(ffi.typeof, "resty_jwt_z_stream") then
  ffi.cdef[[
typedef struct resty_jwt_z_stream_s {
  const unsigned char *next_in;
  unsigned int avail_in;
  unsigned long total_in;
  unsigned char *next_out;
  unsigned int avail_out;
  unsigned long total_out;
  const char *msg;
  void *state;
  void *zalloc;
  void *zfree;
  void *opaque;
  int data_type;
  unsigned long adler;
  unsigned long reserved;
} resty_jwt_z_stream;

const char *resty_jwt_zlibVersion(void) __asm__("zlibVersion");
int resty_jwt_deflateInit2_(resty_jwt_z_stream *strm, int level, int method,
    int windowBits, int memLevel, int strategy, const char *version,
    int stream_size) __asm__("deflateInit2_");
int resty_jwt_deflate(resty_jwt_z_stream *strm, int flush) __asm__("deflate");
int resty_jwt_deflateEnd(resty_jwt_z_stream *strm) __asm__("deflateEnd");
unsigned long resty_jwt_deflateBound(resty_jwt_z_stream *strm,
    unsigned long sourceLen) __asm__("deflateBound");
int resty_jwt_inflateInit2_(resty_jwt_z_stream *strm, int windowBits,
    const char *version, int stream_size) __asm__("inflateInit2_");
int resty_jwt_inflate(resty_jwt_z_stream *strm, int flush) __asm__("inflate");
int resty_jwt_inflateEnd(resty_jwt_z_stream *strm) __asm__("inflateEnd");
]]
end

local Z_OK = 0
local Z_STREAM_END = 1
local Z_NO_FLUSH = 0
local Z_FINISH = 4
local Z_DEFLATED = 8
local Z_BEST_COMPRESSION = 9
local Z_DEFAULT_STRATEGY = 0
local RAW_WINDOW_BITS = -15  -- negative: raw DEFLATE, no zlib/gzip wrapper
local MEM_LEVEL = 8
local INFLATE_CHUNK = 16384

local symbols = {
  "resty_jwt_zlibVersion", "resty_jwt_deflateInit2_", "resty_jwt_deflate",
  "resty_jwt_deflateEnd", "resty_jwt_deflateBound", "resty_jwt_inflateInit2_",
  "resty_jwt_inflate", "resty_jwt_inflateEnd",
}

local function resolves(lib)
  for _, sym in ipairs(symbols) do
    if not pcall(function() return lib[sym] end) then
      return false
    end
  end
  return true
end

-- Prefer the zlib already loaded into the process (nginx links it), then the
-- usual shared library names.
local function load_zlib()
  if resolves(ffi.C) then
    return ffi.C
  end
  for _, name in ipairs({ "z", "libz.so.1", "libz.1.dylib", "zlib1" }) do
    local ok, lib = pcall(ffi.load, name)
    if ok and resolves(lib) then
      return lib
    end
  end
  return nil
end

local zlib = load_zlib()
if not zlib then
  _M.err = "zlib shared library not found"
  return _M
end

local zlib_version = zlib.resty_jwt_zlibVersion()
local stream_size = ffi_sizeof("resty_jwt_z_stream")

--- Compress with raw DEFLATE.
-- @param data string
-- @return compressed string, or nil and an error string
function _M.deflate(data)
  if type(data) ~= "string" then
    return nil, "data must be a string"
  end
  local strm = ffi_new("resty_jwt_z_stream")
  if zlib.resty_jwt_deflateInit2_(strm, Z_BEST_COMPRESSION, Z_DEFLATED, RAW_WINDOW_BITS,
      MEM_LEVEL, Z_DEFAULT_STRATEGY, zlib_version, stream_size) ~= Z_OK then
    return nil, "deflateInit2 failed"
  end

  local bound = tonumber(zlib.resty_jwt_deflateBound(strm, #data))
  local buf = ffi_new("unsigned char[?]", bound)
  strm.next_in = ffi_cast("const unsigned char *", data)
  strm.avail_in = #data
  strm.next_out = buf
  strm.avail_out = bound

  local rc = zlib.resty_jwt_deflate(strm, Z_FINISH)
  local produced = bound - strm.avail_out
  zlib.resty_jwt_deflateEnd(strm)
  if rc ~= Z_STREAM_END then
    return nil, "deflate failed"
  end
  return ffi_string(buf, produced)
end

--- Decompress raw DEFLATE, refusing to produce more than max_size bytes.
-- Rejects output over max_size, a truncated or unfinished stream, and any
-- trailing bytes after the end of the stream.
-- @param data string
-- @param max_size maximum decompressed size in bytes
-- @return decompressed string, or nil and an error string
function _M.inflate(data, max_size)
  if type(data) ~= "string" then
    return nil, "data must be a string"
  end
  if type(max_size) ~= "number" or max_size < 0 then
    return nil, "max_size must be a non-negative number"
  end
  local strm = ffi_new("resty_jwt_z_stream")
  if zlib.resty_jwt_inflateInit2_(strm, RAW_WINDOW_BITS, zlib_version, stream_size) ~= Z_OK then
    return nil, "inflateInit2 failed"
  end

  local buf = ffi_new("unsigned char[?]", INFLATE_CHUNK)
  strm.next_in = ffi_cast("const unsigned char *", data)
  strm.avail_in = #data

  local out, n, total = {}, 0, 0
  local err
  while true do
    strm.next_out = buf
    strm.avail_out = INFLATE_CHUNK
    local rc = zlib.resty_jwt_inflate(strm, Z_NO_FLUSH)
    local have = INFLATE_CHUNK - strm.avail_out
    if have > 0 then
      total = total + have
      if total > max_size then
        err = "decompressed size exceeds the maximum"
        break
      end
      n = n + 1
      out[n] = ffi_string(buf, have)
    end
    if rc == Z_STREAM_END then
      if strm.avail_in ~= 0 then
        err = "trailing data after compressed stream"
      end
      break
    end
    if rc ~= Z_OK then
      -- Z_BUF_ERROR: no progress possible, i.e. input ran out mid-stream
      err = rc == -5 and "truncated compressed stream" or "invalid compressed stream"
      break
    end
  end
  zlib.resty_jwt_inflateEnd(strm)

  if err then
    return nil, err
  end
  return table_concat(out, "", 1, n)
end

_M.available = true

return _M
