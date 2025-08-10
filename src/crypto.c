/**
 * LightJS Crypto Module
 *
 * Copyright (c) 2025 iz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "../engine/quickjs.h"
#include "core.h"
#include "polyfill.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/random.h>

#ifdef LJS_MBEDTLS
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/cipher.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/base64.h>
#include <mbedtls/error.h>

static mbedtls_ctr_drbg_context ctr_drbg;

// The function is thread-safe
int mb_random(void *data, unsigned char *output, size_t len) {
    static char noise[] = "LightJS " LJS_VERSION; 

    // system random
    int ret = getrandom(output, len, GRND_NONBLOCK);
    if(ret == -1){
        // use random to fill the buffer
        for(int i = 0; i < len; i++)
            output[i] = (rand() & noise[i % sizeof(noise)]) % 256;
    }
    return 0;
}

__attribute__((constructor)) static void init_rng() {
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char* pers = "quickjs_crypto";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mb_random, NULL,
                         (const uint8_t*)pers, strlen(pers));
}

__attribute__((destructor)) static void cleanup_rng() {
    mbedtls_ctr_drbg_free(&ctr_drbg);
}

#define GET_BUF(ctx, val, ptr, len) ptr = JS_GetUint8Array(ctx, &len, val); \
    if (!ptr) return JS_EXCEPTION;

#define JS_IsUint8Array(ctx, val) (JS_IsObject(val) && JS_GetTypedArrayType(val) == JS_TYPED_ARRAY_UINT8)

static JSValue crypto_sha(JSContext *ctx, JSValueConst this_val,
                            int argc, JSValueConst *argv) {
    uint8_t *input, output[32];
    size_t len;

    if(argc == 0 || !JS_IsUint8Array(ctx, argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Missing argument", "crypto.sha(data: Uint8Array, shalevel?: number): Uint8Array");
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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Missing argument", "crypto.md5(data: Uint8Array): Uint8Array");
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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Missing argument", "crypto.aes(key: Uint8Array, iv: Uint8Array, data: Uint8Array, bool encrypt = true): Uint8Array");

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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Missing argument", "crypto.hmac(algtype: string, key: Uint8Array, data: Uint8Array): Uint8Array");
    
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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Missing argument", "crypto.random(size: number): Uint8Array");
                                    
    int32_t size;
    if (JS_ToInt32(ctx, &size, argv[0]) == -1 || size <= 0)
        return JS_ThrowRangeError(ctx, "Invalid size");
    
    uint8_t *buf = js_malloc(ctx, size);
    if (!buf) return JS_EXCEPTION;
    
    if (mbedtls_ctr_drbg_random(&ctr_drbg, buf, size) != 0) {
        js_free(ctx, buf);
        return LJS_Throw(ctx, EXCEPTION_INTERNAL, "RNG failed", NULL);
    }
    
    JSValue ret = JS_NewUint8ArrayCopy(ctx, buf, size);
    js_free(ctx, buf);
    return ret;
}

static JSValue crypto_b64decenc(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic){
    if(argc == 0 || !JS_IsUint8Array(ctx, argv[0]))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Missing or invalid argument", 
            magic ? "crypto.b64encode(data: Uint8Array): string" : "crypto.b64decode(data: Uint8Array): Uint8Array"
        );

    uint8_t *input, *output;
    size_t len, output_len;
    GET_BUF(ctx, argv[0], input, len);

    output_len = magic ? (len * 4 / 3 + 4) : (len * 3 / 4 + 4);
realloc:
    output = js_malloc(ctx, output_len);
    if (!output) return JS_EXCEPTION;

    // mbedtls base64
    int ret;
    if(magic){
        ret = mbedtls_base64_encode(output, output_len, &output_len, input, len);
    }else{
        ret = mbedtls_base64_decode(output, output_len, &output_len, input, len);
    }
    if(ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL){
        js_free(ctx, output);
        output_len *= 1.5;
        goto realloc;
    }else if(ret != 0){
        js_free(ctx, output);
        return LJS_Throw(ctx, EXCEPTION_INTERNAL, "Base64 encoding/decoding failed", NULL);
    }
    return JS_NewUint8Array(ctx, output, output_len, free_js_malloc, NULL, true);
}

const JSCFunctionListEntry crypto_funcs[] = {
    JS_CFUNC_DEF("sha", 1, crypto_sha),
    JS_CFUNC_DEF("md5", 1, crypto_md5),
    JS_CFUNC_DEF("aes", 3, crypto_aes),
    JS_CFUNC_DEF("hmac", 3, crypto_hmac),
    JS_CFUNC_DEF("random", 1, crypto_random),
    JS_CFUNC_MAGIC_DEF("b64encode", 1, crypto_b64decenc, 1),
    JS_CFUNC_MAGIC_DEF("b64decode", 1, crypto_b64decenc, 0),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Crypto", JS_PROP_CONFIGURABLE),
};

// class CertDate
static JSClassID js_certdate_class_id;

struct CertDate {
    JSValue parent;
    mbedtls_x509_time time;
};

static JSValue js_certdate_ctor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv){
    return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "CertDate is not constructable", NULL);
}

#define CERTDATE_GENERATE(field) \
static JSValue js_certdate_get_ ##field(JSContext *ctx, JSValueConst this_val){ \
    struct CertDate *date = JS_GetOpaque2(ctx, this_val, js_certdate_class_id); \
    if(!date) return JS_EXCEPTION; \
    return JS_NewInt32(ctx, date -> time.field); \
}

CERTDATE_GENERATE(year)
CERTDATE_GENERATE(mon)
CERTDATE_GENERATE(day)
CERTDATE_GENERATE(hour)
CERTDATE_GENERATE(min)
CERTDATE_GENERATE(sec)

static void js_certdate_finalizer(JSRuntime *rt, JSValue val) {
    struct CertDate *date = JS_GetOpaque(val, js_certdate_class_id);
    if(date){
        JS_FreeValueRT(rt, date -> parent);
        js_free_rt(rt, date);
    }
}

static JSClassDef js_certdate_class = {
    "CertDate",
   .finalizer = js_certdate_finalizer,
};

const JSCFunctionListEntry js_certdate_proto_funcs[] = {
    JS_CGETSET_DEF("year", js_certdate_get_year, NULL),
    JS_CGETSET_DEF("mon", js_certdate_get_mon, NULL),
    JS_CGETSET_DEF("day", js_certdate_get_day, NULL),
    JS_CGETSET_DEF("hour", js_certdate_get_hour, NULL),
    JS_CGETSET_DEF("min", js_certdate_get_min, NULL),
    JS_CGETSET_DEF("sec", js_certdate_get_sec, NULL),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "CertDate", JS_PROP_CONFIGURABLE),
};

static JSValue new_CertDate(JSContext *ctx, const mbedtls_x509_time *time){
    JSValue obj = JS_NewObjectClass(ctx, js_certdate_class_id);
    struct CertDate *date = js_malloc(ctx, sizeof(struct CertDate));
    date -> parent = obj;
    date -> time = *time;
    JS_SetOpaque(obj, date);
    return obj;
}

// class Certificate
static JSClassID js_x509_class_id;
struct Certificate {
    const mbedtls_x509_crt* cert;
    
    // extensible properties
    JSValue parent;
    bool is_child;
};

static JSValue js_x509cert_ctor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv){
    // check arguments
    if(argc == 0 || (!JS_IsString(argv[0]) && !JS_IsTypedArray(ctx, argv[0])))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Missing argument", "Certificate(pem: string): Certificate");

    // get buffer
    uint8_t *buf;
    size_t len;
    bool binary = false;
    if(JS_IsString(argv[0])){
        buf = (void*)JS_ToCStringLen(ctx, &len, argv[0]);
    }else{
        buf = JS_GetUint8Array(ctx, &len, argv[0]);
        binary = true;
    }
    if(!buf || 0 == len) return JS_EXCEPTION;

    // allocate data
    struct Certificate *certObj = js_malloc(ctx, sizeof(struct Certificate));
    memset(certObj, 0, sizeof(struct Certificate));
    mbedtls_x509_crt *cert = js_malloc(ctx, sizeof(mbedtls_x509_crt));
    mbedtls_x509_crt_init(cert);
    certObj -> cert = cert;

    // parse certificate
    int ret = binary
        ? mbedtls_x509_crt_parse_der(cert, (void*)buf, len)
        : mbedtls_x509_crt_parse(cert, (void*)buf, len +1);
    if(ret != 0){
        js_free(ctx, cert);
        if(!binary) JS_FreeCString(ctx, (char*)buf);
        char buf[128];
        mbedtls_strerror(ret, buf, sizeof(buf));
        return LJS_Throw(ctx, EXCEPTION_INTERNAL, "parsing failed: %s", NULL, buf);
    }
    if(!binary) JS_FreeCString(ctx, (char*)buf);
    
    // return object
    JSValue obj = JS_NewObjectClass(ctx, js_x509_class_id);
    JS_SetOpaque(obj, certObj);
    return obj;
}

#define GX509OPAQUE \
    struct Certificate *certClass = JS_GetOpaque2(ctx, this_val, js_x509_class_id); \
    if(!certClass) return JS_EXCEPTION; \
    const mbedtls_x509_crt *cert = certClass -> cert;
#define HANDLE_RET(ret) \
    if(ret < 0){ \
        char buf[128]; \
        mbedtls_strerror(ret, buf, sizeof(buf)); \
        return LJS_Throw(ctx, EXCEPTION_INTERNAL, "failed: %s", NULL, buf); \
    }
static JSValue js_x509crt_toString(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    GX509OPAQUE;

    char buf[4096];
    int ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, " ", cert);
    HANDLE_RET(ret);

    // uint32_t offset = ret;
    // if(offset >= sizeof(buf) - 1 - 15) goto end;
    // strcat(buf, "\nVerify Info: \n");
    // offset += 15;
    // int ret2 = mbedtls_x509_crt_verify_info(buf + offset, sizeof(buf) - offset - 1, ": ", cert);
    // HANDLE_RET(ret2);
    // offset += ret2;

// end:
    return JS_NewStringLen(ctx, buf, ret);
}

static JSValue js_x509crt_get_version(JSContext *ctx, JSValueConst this_val){
    GX509OPAQUE;

    return JS_NewInt32(ctx, cert -> version);
}

static JSValue js_x509crt_get_issuer(JSContext *ctx, JSValueConst this_val){
    GX509OPAQUE;

    return JS_NewStringLen(ctx, (char*)cert -> issuer.val.p, cert -> issuer.val.len);
}

static JSValue js_x509crt_get_subject(JSContext *ctx, JSValueConst this_val){
    GX509OPAQUE;

    return JS_NewStringLen(ctx, (char*)cert -> subject.val.p, cert -> subject.val.len);
}

static JSValue js_x509crt_get_serial(JSContext *ctx, JSValueConst this_val){
    GX509OPAQUE;

    return JS_NewStringLen(ctx, (char*)cert -> serial.p, cert -> serial.len);
}

static JSValue js_x509crt_get_validRange(JSContext *ctx, JSValueConst this_val){
    GX509OPAQUE;

    return JS_NewArrayFrom(ctx, 2, (JSValueConst[]){
        new_CertDate(ctx, &cert -> valid_from),
        new_CertDate(ctx, &cert -> valid_to)
    });
}

static JSValue js_x509_get_status(JSContext *ctx, JSValueConst this_val){
    GX509OPAQUE;

    const char* status = "ok";
    if(mbedtls_x509_time_is_past(&cert -> valid_to)){
        status = "expired";
    }else if(mbedtls_x509_time_is_future(&cert -> valid_from)){
        status = "future";
    }

    return JS_NewString(ctx, status);
}

static JSValue js_x509crt_next(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    GX509OPAQUE;
    if(!cert -> next) return JS_NULL;

    struct Certificate* certClass2 = js_malloc(ctx, sizeof(struct Certificate));
    JSValue newone = JS_NewObjectClass(ctx, js_x509_class_id);
    JS_SetOpaque(newone, certClass2);
    certClass2 -> parent = JS_DupValue(ctx, this_val);
    certClass2 -> is_child = true;
    certClass2 -> cert = cert -> next;
    return newone;
}

static void x509_finalizer(JSRuntime *rt, JSValue val){
    struct Certificate *certClass = JS_GetOpaque(val, js_x509_class_id);
    if(!certClass) return;
    if(certClass -> is_child){
        JS_FreeValueRT(rt, certClass -> parent);
    }else{
        // writable, created by js_malloc
        mbedtls_x509_crt_free((void*)certClass -> cert);
        js_free_rt(rt, (void*)certClass -> cert);
    }
}

void free_mb_pk_ctx(JSRuntime *rt, void* ptr, void *opaque) {
    mbedtls_pk_context* pk = (mbedtls_pk_context*)ptr;
    mbedtls_pk_free(pk);
    js_free_rt(rt, pk);
}

static JSValue js_x509crt_static_parseKey(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || (!JS_IsString(argv[0]) && !JS_IsTypedArray(ctx, argv[0]))) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Missing or invalid argument", "Certificate.parseKey(pem: string, password?: string): Certificate");

    // get buffer
    uint8_t *buf;
    size_t len;
    bool binary = false;
    if(JS_IsString(argv[0])){
        buf = (void*)JS_ToCStringLen(ctx, &len, argv[0]);
    }else{
        buf = JS_GetUint8Array(ctx, &len, argv[0]);
        binary = true;
    }
    if(!buf || 0 == len) return JS_EXCEPTION;

    // get password
    const char *password = NULL;
    size_t pw_len = 0;
    if(argc > 1 && JS_IsString(argv[1])){
        password = JS_ToCStringLen(ctx, &pw_len, argv[1]);
        pw_len += 1;    // mbedtls requires null-terminated string
    }

    // allocate data
    struct mbedtls_pk_context* pk = js_malloc(ctx, sizeof(mbedtls_pk_context));
    mbedtls_pk_init(pk);

    // parse key
    int ret = mbedtls_pk_parse_key(pk, (void*)buf, binary ? len : len +1, (void*)password, pw_len, mb_random, NULL);
    if(!binary) JS_FreeCString(ctx, (char*)buf);

    // handle error
    if(ret < 0) js_free(ctx, pk);
    HANDLE_RET(ret);
    return JS_NewArrayBuffer(ctx, (void*)pk, sizeof(mbedtls_pk_context), free_mb_pk_ctx, NULL, false);
}

static const JSCFunctionListEntry js_x509crt_proto_funcs[] = {
    JS_CFUNC_DEF("toString", 0, js_x509crt_toString),
    JS_CGETSET_DEF("version", js_x509crt_get_version, NULL),
    JS_CGETSET_DEF("issuer", js_x509crt_get_issuer, NULL),
    JS_CGETSET_DEF("subject", js_x509crt_get_subject, NULL),
    JS_CGETSET_DEF("serial", js_x509crt_get_serial, NULL),
    JS_CGETSET_DEF("validRange", js_x509crt_get_validRange, NULL),
    JS_CGETSET_DEF("status", js_x509_get_status, NULL),
    JS_CFUNC_DEF("next", 0, js_x509crt_next),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Certificate", JS_PROP_CONFIGURABLE),
};

static const JSCFunctionListEntry js_x509_static_funcs[] = {
    JS_CFUNC_DEF("parseKey", 2, js_x509crt_static_parseKey),
};

static JSClassDef js_x509_class = {
    "Certificate",
   .finalizer = x509_finalizer,
};

const mbedtls_x509_crt* LJS_GetCertificate(JSContext *ctx, JSValueConst val){
    struct Certificate *certClass = JS_GetOpaque2(ctx, val, js_x509_class_id);
    if(!certClass) return NULL;
    return certClass -> cert;
}

JSValue LJS_NewCertificate(JSContext *ctx, const mbedtls_x509_crt *cert){
    JSValue obj = JS_NewObjectClass(ctx, js_x509_class_id);
    struct Certificate *certClass = js_malloc(ctx, sizeof(struct Certificate));
    certClass -> cert = cert;
    certClass -> parent = JS_UNDEFINED;
    certClass -> is_child = true;   // No Free!
    JS_SetOpaque(obj, certClass);
    return obj;
}

#else
const JSCFunctionListEntry crypto_funcs[] = {
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Crypto", JS_PROP_CONFIGURABLE),
};
#endif

static int js_crypto_init(JSContext *ctx, JSModuleDef *m) {
    JS_SetModuleExportList(ctx, m, crypto_funcs, countof(crypto_funcs));

#ifdef LJS_MBEDTLS
    // class Certificate
    JSValue xc_ctor = JS_NewCFunction2(ctx, js_x509cert_ctor, "Certificate", 1, JS_CFUNC_constructor, 0);
    JSValue xc_proto = JS_GetClassProto(ctx, js_x509_class_id);
    JS_SetConstructor(ctx, xc_ctor, xc_proto);
    JS_FreeValue(ctx, xc_proto);

    // Certificate.* static properties
    JS_SetPropertyFunctionList(ctx, xc_ctor, js_x509_static_funcs, countof(js_x509_static_funcs));
    
    // class CertDate
    JSValue cd_ctor = JS_NewCFunction2(ctx, js_certdate_ctor, "CertDate", 0, JS_CFUNC_constructor, 0);
    JSValue cd_proto = JS_GetClassProto(ctx, js_certdate_class_id);
    JS_SetConstructor(ctx, cd_ctor, cd_proto);
    JS_FreeValue(ctx, cd_proto);

    // export
    JS_SetModuleExport(ctx, m, "Certificate", xc_ctor);
    JS_SetModuleExport(ctx, m, "CertDate", cd_ctor);
#endif

    return 0;
}

bool LJS_init_crypto(JSContext *ctx) {
    JSModuleDef *m = JS_NewCModule(ctx, "crypto", js_crypto_init);
    if (!m) return false;
    JS_AddModuleExportList(ctx, m, crypto_funcs, countof(crypto_funcs));
    JS_AddModuleExport(ctx, m, "Certificate");
    JS_AddModuleExport(ctx, m, "CertDate");
    __maybe_unused JSRuntime *rt = JS_GetRuntime(ctx);

#ifdef LJS_MBEDTLS
    // class Certificate
    JS_NewClassID(rt, &js_x509_class_id);
    JS_NewClass(rt, js_x509_class_id, &js_x509_class);

    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_x509crt_proto_funcs, countof(js_x509crt_proto_funcs));
    JS_SetClassProto(ctx, js_x509_class_id, proto);

    // class CertDate
    JS_NewClassID(rt, &js_certdate_class_id);
    JS_NewClass(rt, js_certdate_class_id, &js_certdate_class);

    JSValue proto2 = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto2, js_certdate_proto_funcs, countof(js_certdate_proto_funcs));
    JS_SetClassProto(ctx, js_certdate_class_id, proto2);
#endif

    return true;
}