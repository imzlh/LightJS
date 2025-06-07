
#include "../engine/quickjs.h"
#include "core.h"
#include "polyfill.h"

#include <string.h>

#ifdef LJS_MBEDTLS
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/cipher.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

// 全局随机数上下文
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

// 初始化随机数生成器（模块加载时调用）
__attribute__((constructor)) static void init_rng() {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char* pers = "quickjs_crypto";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                         (const uint8_t*)pers, strlen(pers));
}

// 清理资源（模块卸载时调用）
__attribute__((destructor)) static void cleanup_rng() {
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

#define GET_BUF(ctx, val, ptr, len) ptr = JS_GetUint8Array(ctx, &len, val); \
    if (!ptr) return JS_EXCEPTION;

#define JS_IsUint8Array(ctx, val) (JS_IsObject(val) && JS_GetTypedArrayType(val) == JS_TYPED_ARRAY_UINT8)

static JSValue crypto_sha(JSContext *ctx, JSValueConst this_val,
                            int argc, JSValueConst *argv) {
    uint8_t *input, output[32];
    size_t len;

    if(argc == 0 || !JS_IsUint8Array(ctx, argv[0])){
        return LJS_Throw(ctx, "Missing argument", "crypto.sha(data: Uint8Array, shalevel?: number): Uint8Array");
    }
    
    GET_BUF(ctx, argv[0], input, len);
    int shalevel = 256;
    if(argc >= 2) JS_ToInt32(ctx, &shalevel, argv[1]);
    mbedtls_md_type_t md_shalevel;

    switch (shalevel){
        case 1: md_shalevel = MBEDTLS_MD_SHA1; break;
        case 224: md_shalevel = MBEDTLS_MD_SHA224; break;
        case 256: md_shalevel = MBEDTLS_MD_SHA256; break;
        case 384: md_shalevel = MBEDTLS_MD_SHA384; break;
        case 512: md_shalevel = MBEDTLS_MD_SHA512; break;
        case 3224: md_shalevel = MBEDTLS_MD_SHA3_224; break;
        case 3256: md_shalevel = MBEDTLS_MD_SHA3_256; break;
        case 3384: md_shalevel = MBEDTLS_MD_SHA3_384; break;
        case 3512: md_shalevel = MBEDTLS_MD_SHA3_512; break;
        default: return JS_ThrowRangeError(ctx, "Invalid SHA level");
    }
    
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_shalevel), 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, input, len);
    mbedtls_md_finish(&md_ctx, output);
    mbedtls_md_free(&md_ctx);
    
    return JS_NewUint8ArrayCopy(ctx, output, (shalevel & 0xff) /8);
}

static JSValue crypto_md5(JSContext *ctx, JSValueConst this_val,
                            int argc, JSValueConst *argv) {
    uint8_t *input, output[32];
    size_t len;

    if(argc == 0 || !JS_IsUint8Array(ctx, argv[0])){
        return LJS_Throw(ctx, "Missing argument", "crypto.md5(data: Uint8Array): Uint8Array");
    }
    
    GET_BUF(ctx, argv[0], input, len);
    
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, input, len);
    mbedtls_md_finish(&md_ctx, output);
    mbedtls_md_free(&md_ctx);
    
    return JS_NewUint8ArrayCopy(ctx, output, 32);
}

static JSValue crypto_aes(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    uint8_t *key, *iv, *input, *output;
    size_t key_len, iv_len, len;
    const mbedtls_cipher_info_t *cipher_info;
    
    if(argc <= 2 || !JS_IsUint8Array(ctx, argv[0]) || !JS_IsUint8Array(ctx, argv[1]) || !JS_IsUint8Array(ctx, argv[2]))
        return LJS_Throw(ctx, "Missing argument", "crypto.aes(key: Uint8Array, iv: Uint8Array, data: Uint8Array, bool encrypt = true): Uint8Array");

    GET_BUF(ctx, argv[0], key, key_len);
    GET_BUF(ctx, argv[1], iv, iv_len);
    GET_BUF(ctx, argv[2], input, len);

    bool encrypt = true;
    if(argc >= 4) encrypt = JS_ToBool(ctx, argv[3]);
    
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        JS_ThrowRangeError(ctx, "Invalid AES key size");
        goto fail;
    }
    
    cipher_info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES,
                                                 (int)key_len * 8,
                                                 MBEDTLS_MODE_CBC);
    if (!cipher_info) {
        JS_ThrowTypeError(ctx, "Unsupported AES mode");
        goto fail;
    }
    
    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_cipher_init(&cipher_ctx);
    mbedtls_cipher_setup(&cipher_ctx, cipher_info);
    mbedtls_cipher_set_padding_mode(&cipher_ctx, MBEDTLS_PADDING_PKCS7);
    mbedtls_cipher_setkey(&cipher_ctx, key, (int)key_len * 8,
                         encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);
    mbedtls_cipher_set_iv(&cipher_ctx, iv, iv_len);
    
    size_t output_len = len + 16;
    output = js_malloc(ctx, output_len);
    
    size_t final_len;
    mbedtls_cipher_update(&cipher_ctx, input, len, output, &output_len);
    mbedtls_cipher_finish(&cipher_ctx, output + output_len, &final_len);
    output_len += final_len;
    
    JSValue ret = JS_NewUint8ArrayCopy(ctx, output, output_len);
    js_free(ctx, output);
    
    mbedtls_cipher_free(&cipher_ctx);
fail:
    return ret;
}

static JSValue crypto_hmac(JSContext *ctx, JSValueConst this_val,
                          int argc, JSValueConst *argv) {
    uint8_t *key, *data, output[MBEDTLS_MD_MAX_SIZE];
    size_t key_len, data_len;
    mbedtls_md_type_t md_type;

    if(argc <= 2 || !JS_IsString(argv[0]) || !JS_IsUint8Array(ctx, argv[1]) || !JS_IsUint8Array(ctx, argv[2]))
        return LJS_Throw(ctx, "Missing argument", "crypto.hmac(algtype: string, key: Uint8Array, data: Uint8Array): Uint8Array");
    
    GET_BUF(ctx, argv[1], key, key_len);
    GET_BUF(ctx, argv[2], data, data_len);
    const char* type = JS_ToCString(ctx, argv[0]);
    if(!type) return JS_EXCEPTION;

    if(memcmp(type, "sha", 3)){
        bool sha3 = memcmp(type + 3, "3-", 2);
        long type2 = strtol(type + (sha3 ? 5 : 3), NULL, 10);
        switch(type2){
            case 1: md_type = sha3 ? MBEDTLS_MD_SHA3_256 : MBEDTLS_MD_SHA256; break;
            case 224: md_type = sha3 ? MBEDTLS_MD_SHA3_224 : MBEDTLS_MD_SHA224; break;
            case 256: md_type = sha3 ? MBEDTLS_MD_SHA3_256 : MBEDTLS_MD_SHA256; break;
            case 384: md_type = sha3 ? MBEDTLS_MD_SHA3_384 : MBEDTLS_MD_SHA384; break;
            case 512: md_type = sha3 ? MBEDTLS_MD_SHA3_512 : MBEDTLS_MD_SHA512; break;
            default: JS_ThrowRangeError(ctx, "Invalid SHA level"); goto fail;
        }
    }else if(memcmp(type, "md5", 4)){
        md_type = MBEDTLS_MD_MD5;
    }else if(memcmp(type, "ripemd160", 10)){
        md_type = MBEDTLS_MD_RIPEMD160;
    }else{
        JS_ThrowRangeError(ctx, "Invalid HMAC algorithm(sha, md5, ripemd160 are supported by mbedtls)");
        goto fail;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    mbedtls_md_hmac(md_info, key, key_len, data, data_len, output);
    
    JSValue ret = JS_NewUint8ArrayCopy(ctx, output, mbedtls_md_get_size(md_info));
fail:
    JS_FreeCString(ctx, type);
    return ret;
}


static JSValue crypto_random(JSContext *ctx, JSValueConst this_val,
                                  int argc, JSValueConst *argv) {
    if(argc == 0 || !JS_IsNumber(argv[0]))
        return LJS_Throw(ctx, "Missing argument", "crypto.random(size: number): Uint8Array");
                                    
    int32_t size;
    if (JS_ToInt32(ctx, &size, argv[0]) == -1 || size <= 0)
        return JS_ThrowRangeError(ctx, "Invalid size");
    
    uint8_t *buf = js_malloc(ctx, size);
    if (!buf) return JS_EXCEPTION;
    
    if (mbedtls_ctr_drbg_random(&ctr_drbg, buf, size) != 0) {
        js_free(ctx, buf);
        return LJS_Throw(ctx, "RNG failed", NULL);
    }
    
    JSValue ret = JS_NewUint8ArrayCopy(ctx, buf, size);
    js_free(ctx, buf);
    return ret;
}

const JSCFunctionListEntry crypto_funcs[] = {
    JS_CFUNC_DEF("sha", 1, crypto_sha),
    JS_CFUNC_DEF("md5", 1, crypto_md5),
    JS_CFUNC_DEF("aes", 3, crypto_aes),
    JS_CFUNC_DEF("hmac", 3, crypto_hmac),
    JS_CFUNC_DEF("random", 1, crypto_random),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Crypto", JS_PROP_CONFIGURABLE),
};
#else
const JSCFunctionListEntry crypto_funcs[] = {
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Crypto", JS_PROP_CONFIGURABLE),
};
#endif

static int js_crypto_init(JSContext *ctx, JSModuleDef *m) {
    JS_SetModuleExportList(ctx, m, crypto_funcs, countof(crypto_funcs));
    return 0;
}

bool LJS_init_crypto(JSContext *ctx) {
    JSModuleDef *m = JS_NewCModule(ctx, "crypto", js_crypto_init);
    if (!m) return false;
    JS_AddModuleExportList(ctx, m, crypto_funcs, countof(crypto_funcs));
    return true;
}