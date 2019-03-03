local ffi = require "ffi"
local C = ffi.C
local ffi_cast = ffi.cast
local ffi_new = ffi.new
local ffi_gc = ffi.gc
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local band = bit.band

local _M = { _VERSION = '0.01' }

local mt = { __index = _M }


ffi.cdef[[
typedef int size_t;
typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;
typedef struct ec_key_st EC_KEY;
typedef struct ec_group_st EC_GROUP;
typedef struct bignum_st BIGNUM;

BIO * BIO_new(BIO_METHOD *type);
BIO_METHOD *BIO_s_mem(void);
int BIO_puts(BIO *bp, const char *buf);
void BIO_vfree(BIO *a);
BIO_METHOD *BIO_s_file(void);

long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
int BIO_read(BIO *b, void *data, int len);

EC_KEY *EC_KEY_new(void);
void EC_KEY_free(EC_KEY *key);

int EC_KEY_generate_key(EC_KEY *key);
typedef struct { int nid; const char *comment;} EC_builtin_curve;
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_free(EC_GROUP *group);

typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
int PEM_write_bio_EC_PUBKEY(BIO *bp, EC_KEY *x);
EC_KEY * PEM_read_bio_ECPrivateKey(BIO *bp, EC_KEY **eckey, 
        pem_password_cb *cb, void *u);
EC_KEY * PEM_read_bio_EC_PUBKEY(BIO *bp, EC_KEY **eckey, 
        pem_password_cb *cb, void *u);

int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
int EC_KEY_generate_key(EC_KEY *key);
int ECDSA_size(const EC_KEY *eckey);

const char * ERR_reason_error_string(unsigned long e);
unsigned long ERR_get_error_line_data(const char **file, int *line,
        const char **data, int *flags);
unsigned long ERR_get_error(void);
unsigned long ERR_get_error_line(const char **file, int *line);

typedef struct evp_pkey_st EVP_PKEY;
typedef struct env_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;

typedef struct evp_cipher_st EVP_CIPHER;
int PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x);
int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
         unsigned char *kstr, int klen,
         pem_password_cb *cb, void *u);

/* EVP_MD_CTX methods for OpenSSL < 1.1.0 */
EVP_MD_CTX *EVP_MD_CTX_create(void);
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);

/* EVP_MD_CTX methods for OpenSSL >= 1.1.0 */
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

const EVP_MD *EVP_get_digestbyname(const char *name);
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, struct ec_key_st *key);
EVP_PKEY *EVP_PKEY_new(void);
const EVP_MD *EVP_sha256(void);
void EVP_PKEY_free(EVP_PKEY *pkey);
int EVP_PKEY_size(EVP_PKEY *pkey);
int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const unsigned char *in, int inl);
int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *sig,unsigned int *s, EVP_PKEY *pkey);
int EVP_VerifyFinal(EVP_MD_CTX *ctx,unsigned char *sigbuf, unsigned int siglen,EVP_PKEY *pkey);
]]

local ERR_TXT_STRING = 0x02

local evp_md_ctx_new
local evp_md_ctx_free
if not pcall(function () return C.EVP_MD_CTX_create end) then
    evp_md_ctx_new = C.EVP_MD_CTX_new
    evp_md_ctx_free = C.EVP_MD_CTX_free
else
    evp_md_ctx_new = C.EVP_MD_CTX_create
    evp_md_ctx_free = C.EVP_MD_CTX_destroy
end

local function ssl_err()
    local err_queue = {}
    local i = 1
    local data = ffi_new("const char*[1]")
    local flags = ffi_new("int[1]")

    while true do
        local code = C.ERR_get_error_line_data(nil, nil, data, flags)
        if code == 0 then
            break
        end

        local err = C.ERR_reason_error_string(code)

        err_queue[i] = ffi_str(err)

        i = i + 1

        if data[0] ~= nil and band(flags[0], ERR_TXT_STRING) > 0 then
            err_queue[i] = ffi_str(data[0])
            i = i + 1
        end
    end
    return table.concat(err_queue, ": ", 1, i - 1)
end

local function read_bio(bio)
    local BIO_CTRL_PENDING = 10
    local keylen = C.BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil);
    local key = ffi.new("char[?]", keylen)
    if C.BIO_read(bio, key, keylen) < 0 then
        return ssl_err()
    end
    return ffi_str(key, keylen)
end


function _M.get_curves_id(_)
    local len = ffi_new("uint64_t[1]")
    local len = C.EC_get_builtin_curves(nil, 0) -- get inside curves
    local curves = ffi.new("EC_builtin_curve[?]", len)

    C.EC_get_builtin_curves(curves, len)    

    local r = {}
    for i=1, tonumber(len)-1, 1 do
        if curves[i].nid ~= 0 then
            table.insert(r, {index=i, nid=curves[i].nid, comment=ffi_str(curves[i].comment)})
        end
    end

    return r
end

function _M.generate_ec_keys(_, nid)
    -- body
    local ec = C.EC_KEY_new()
    ffi_gc(ec, C.EC_KEY_free)

    if nid == nil then
        return nil, nil, "unknown curve method"
    end

    local group = C.EC_GROUP_new_by_curve_name(nid)
    ffi_gc(group, C.EC_GROUP_free)

    if group == nil then
        return nil, nil, ssl_err()
    end

    local ret = C.EC_KEY_set_group(ec, group)
    if ret == 0 then
        return nil, nil, ssl_err()
    end

    C.EC_KEY_generate_key(ec)

    local pkey = C.EVP_PKEY_new();
    ffi_gc(pkey, EVP_PKEY_free)
    C.EVP_PKEY_set1_EC_KEY(pkey, ec)

    local pubkey_bio = C.BIO_new(C.BIO_s_mem())
    ffi_gc(pubkey_bio, C.BIO_vfree)
    if C.PEM_write_bio_PUBKEY(pubkey_bio, pkey) ~= 1 then
        return nil, nil, ssl_err()
    end

    local public_key, err = read_bio(pubkey_bio)
    if not public_key then
        return nil, nil, err
    end

    local prikey_bio = C.BIO_new(C.BIO_s_mem())
    ffi_gc(prikey_bio, C.BIO_vfree)

    if C.PEM_write_bio_PrivateKey(prikey_bio, pkey, nil, nil, 0, nil, nil) ~= 1 then
        return nil, nil, ssl_err()
    end

    local private_key, err = read_bio(prikey_bio)
    if not public_key then
        return nil, nil, err
    end

    return public_key, private_key
end

function _M.new(_, opts)
    -- body
    local key, read_func, is_pub

    if opts.public_key then
        key = opts.public_key
        read_func = C.PEM_read_bio_EC_PUBKEY
        is_pub = true
    elseif opts.private_key then
        key = opts.private_key
        read_func = C.PEM_read_bio_ECPrivateKey
    else
        return nil, "public_key or private_key not found"
    end

    local bio = C.BIO_new(C.BIO_s_mem())
    ffi_gc(bio, C.BIO_vfree)

    local len = C.BIO_puts(bio, key)
    if len < 0 then
        return nil, ssl_err()
    end

    local ec_key = read_func(bio, nil, nil, nil)
    if ec_key == nil then
        return nil, ssl_err()
    end
    ffi_gc(ec_key, C.EC_KEY_free)

    local pkey = C.EVP_PKEY_new();
    ffi_gc(pkey, EVP_PKEY_free)
    C.EVP_PKEY_set1_EC_KEY(pkey, ec_key)

    local md = C.EVP_get_digestbyname("SHA256")
    if ffi_cast("void *", md) == nil then
        return nil, "Unknown message digest"
    end

    local size = C.EVP_PKEY_size(pkey)

    return setmetatable({
            pkey = pkey,
            size= size,
            is_pub = is_pub,
            md = md
        }, mt)
end


function _M.sign(self, str)
   if self.is_pub then
        return nil, "not inited for sign"
    end

    local md_ctx = evp_md_ctx_new()
    ffi_gc(md_ctx, evp_md_ctx_free)

    if C.EVP_DigestInit(md_ctx, self.md) <= 0 then
        return nil, ssl_err()
    end

    local strbuf = ffi_new("unsigned char[?]", #str)
    ffi_copy(strbuf, str, #str)
    if C.EVP_DigestUpdate(md_ctx, strbuf, #str) <= 0 then
        return nil, ssl_err()
    end
   
    local buf = ffi_new("unsigned char[?]", 1024)
    local len = ffi_new("unsigned int[1]")

    if C.EVP_SignFinal(md_ctx, buf, len, self.pkey) <= 0 then
        return nil, ssl_err()
    end

    return ffi_str(buf, len[0])
end

function _M.verify(self, str, sig)
    if not self.is_pub then
        return nil, "not inited for verify"
    end
    local md_ctx = evp_md_ctx_new()
    ffi_gc(md_ctx, evp_md_ctx_free)

    if C.EVP_DigestInit(md_ctx, self.md) <= 0 then
        return false, ssl_err()
    end

    local buf = ffi_new("unsigned char[?]", #str)
    ffi_copy(buf, str, #str)
    if C.EVP_DigestUpdate(md_ctx, buf, #str) <= 0 then
        return false, ssl_err()
    end
    local siglen = #sig

    local sigbuf = ffi_new("unsigned char[?]", siglen)

    ffi_copy(sigbuf, sig, siglen)

    if C.EVP_VerifyFinal(md_ctx, sigbuf, siglen, self.pkey) <= 0 then
        return false, ssl_err()
    end
    return true
end


return _M
