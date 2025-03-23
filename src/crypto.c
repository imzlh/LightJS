// #include <quickjs.h>
// #include <mbedtls/aes.h>
// #include <mbedtls/md.h>
// #include <mbedtls/cipher.h>
// #include <mbedtls/entropy.h>
// #include <mbedtls/ctr_drbg.h>
// #include <string.h>

// // 全局随机数上下文
// static mbedtls_ctr_drbg_context ctr_drbg;
// static mbedtls_entropy_context entropy;

// // 初始化随机数生成器（模块加载时调用）
// __attribute__((constructor)) static void init_rng() {
//     mbedtls_entropy_init(&entropy);
//     mbedtls_ctr_drbg_init(&ctr_drbg);
//     const char* pers = "quickjs_crypto";
//     mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
//                          (const uint8_t*)pers, strlen(pers));
// }

// // 清理资源（模块卸载时调用）
// __attribute__((destructor)) static void cleanup_rng() {
//     mbedtls_ctr_drbg_free(&ctr_drbg);
//     mbedtls_entropy_free(&entropy);
// }

// // 辅助函数：将二进制数据转为Hex字符串
// static JSValue bin_to_hex(JSContext *ctx, const uint8_t *buf, size_t len) {
//     char *hex = js_malloc(ctx, len * 2 + 1);
//     if (!hex) return JS_EXCEPTION;
    
//     for (size_t i = 0; i < len; i++) {
//         sprintf(hex + i * 2, "%02x", buf[i]);
//     }
//     hex[len * 2] = 0;
    
//     JSValue ret = JS_NewString(ctx, hex);
//     js_free(ctx, hex);
//     return ret;
// }

// // 辅助函数：获取二进制数据
// static int get_bin(JSContext *ctx, JSValueConst obj, uint8_t **buf, size_t *len) {
//     if (JS_IsArrayBuffer(ctx, obj)) {
//         *len = JS_GetArrayBuffer(ctx, NULL, (uint8_t **)buf, obj);
//         return 0;
//     }
    
//     const char *str = JS_ToCStringLen(ctx, len, obj);
//     if (!str) return -1;
    
//     *buf = js_malloc(ctx, *len);
//     if (!*buf) {
//         JS_FreeCString(ctx, str);
//         return -1;
//     }
//     memcpy(*buf, str, *len);
//     JS_FreeCString(ctx, str);
//     return 0;
// }

// // SHA256哈希函数
// static JSValue crypto_sha256(JSContext *ctx, JSValueConst this_val,
//                             int argc, JSValueConst *argv) {
//     uint8_t *input, output[32];
//     size_t len;
    
//     if (get_bin(ctx, argv[0], &input, &len) < 0)
//         return JS_EXCEPTION;
    
//     mbedtls_md_context_t md_ctx;
//     mbedtls_md_init(&md_ctx);
//     mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
//     mbedtls_md_starts(&md_ctx);
//     mbedtls_md_update(&md_ctx, input, len);
//     mbedtls_md_finish(&md_ctx, output);
//     mbedtls_md_free(&md_ctx);
    
//     js_free(ctx, input);
//     return bin_to_hex(ctx, output, 32);
// }

// // AES加密通用函数
// static JSValue crypto_aes(JSContext *ctx, int encrypt,
//                          JSValueConst this_val, int argc, JSValueConst *argv) {
//     uint8_t *key, *iv, *input, *output;
//     size_t key_len, iv_len, len;
//     const mbedtls_cipher_info_t *cipher_info;
    
//     if (get_bin(ctx, argv[0], &key, &key_len) < 0 ||
//         get_bin(ctx, argv[1], &iv, &iv_len) < 0 ||
//         get_bin(ctx, argv[2], &input, &len) < 0)
//         return JS_EXCEPTION;
    
//     if (key_len != 16 && key_len != 24 && key_len != 32) {
//         JS_ThrowRangeError(ctx, "Invalid AES key size");
//         goto fail;
//     }
    
//     cipher_info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES,
//                                                  (int)key_len * 8,
//                                                  MBEDTLS_MODE_CBC);
//     if (!cipher_info) {
//         JS_ThrowError(ctx, "Unsupported AES mode");
//         goto fail;
//     }
    
//     mbedtls_cipher_context_t cipher_ctx;
//     mbedtls_cipher_init(&cipher_ctx);
//     mbedtls_cipher_setup(&cipher_ctx, cipher_info);
//     mbedtls_cipher_set_padding_mode(&cipher_ctx, MBEDTLS_PADDING_PKCS7);
//     mbedtls_cipher_setkey(&cipher_ctx, key, (int)key_len * 8,
//                          encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);
//     mbedtls_cipher_set_iv(&cipher_ctx, iv, iv_len);
    
//     size_t output_len = len + 16; // 留出填充空间
//     output = js_malloc(ctx, output_len);
    
//     size_t final_len;
//     mbedtls_cipher_update(&cipher_ctx, input, len, output, &output_len);
//     mbedtls_cipher_finish(&cipher_ctx, output + output_len, &final_len);
//     output_len += final_len;
    
//     JSValue ret = JS_NewArrayBufferCopy(ctx, output, output_len);
//     js_free(ctx, output);
    
//     mbedtls_cipher_free(&cipher_ctx);
// fail:
//     js_free(ctx, key);
//     js_free(ctx, iv);
//     js_free(ctx, input);
//     return ret;
// }

// // HMAC函数
// static JSValue crypto_hmac(JSContext *ctx, JSValueConst this_val,
//                           int argc, JSValueConst *argv) {
//     const char *alg = JS_ToCString(ctx, argv[0]);
//     uint8_t *key, *data, output[MBEDTLS_MD_MAX_SIZE];
//     size_t key_len, data_len;
//     mbedtls_md_type_t md_type;
    
//     if (!alg || get_bin(ctx, argv[1], &key, &key_len) < 0 ||
//         get_bin(ctx, argv[2], &data, &data_len) < 0) {
//         JS_FreeCString(ctx, alg);
//         return JS_EXCEPTION;
//     }
    
//     if (strcmp(alg, "sha256") == 0) md_type = MBEDTLS_MD_SHA256;
//     else if (strcmp(alg, "sha1") == 0) md_type = MBEDTLS_MD_SHA1;
//     else {
//         JS_ThrowError(ctx, "Unsupported hash algorithm");
//         goto fail;
//     }
    
//     const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
//     mbedtls_md_hmac(md_info, key, key_len, data, data_len, output);
    
//     JSValue ret = bin_to_hex(ctx, output, mbedtls_md_get_size(md_info));
// fail:
//     JS_FreeCString(ctx, alg);
//     js_free(ctx, key);
//     js_free(ctx, data);
//     return ret;
// }

// // 模块初始化
// static int js_crypto_init(JSContext *ctx, JSModuleDef *m) {
//     JSValue crypto = JS_NewObject(ctx);
    
//     JS_SetPropertyStr(ctx, crypto, "sha256",
//                       JS_NewCFunction(ctx, crypto_sha256, "sha256", 1));
    
//     JS_SetPropertyStr(ctx, crypto, "aesEncrypt",
//                       JS_NewCFunction2(ctx, (JSCFunction *)crypto_aes, "aesEncrypt", 3,
//                                       JS_CFUNC_generic, (void *)1));
    
//     JS_SetPropertyStr(ctx, crypto, "aesDecrypt",
//                       JS_NewCFunction2(ctx, (JSCFunction *)crypto_aes, "aesDecrypt", 3,
//                                       JS_CFUNC_generic, (void *)0));
    
//     JS_SetPropertyStr(ctx, crypto, "hmac",
//                       JS_NewCFunction(ctx, crypto_hmac, "hmac", 3));
    
//     JS_SetModuleExport(ctx, m, "crypto", crypto);
//     return 0;
// }

// JSModuleDef *js_init_module_crypto(JSContext *ctx, const char *module_name) {
//     JSModuleDef *m = JS_NewCModule(ctx, module_name, js_crypto_init);
//     if (!m) return NULL;
//     JS_AddModuleExport(ctx, m, "crypto");
//     return m;
// }

// /* 通用哈希函数 */
// static JSValue crypto_hash(JSContext *ctx, mbedtls_md_type_t md_type,
//                           JSValueConst this_val, int argc, JSValueConst *argv) {
//     uint8_t *input, output[MBEDTLS_MD_MAX_SIZE];
//     size_t len;
    
//     if (get_bin(ctx, argv[0], &input, &len) < 0)
//         return JS_EXCEPTION;
    
//     const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
//     mbedtls_md(md_info, input, len, output);
    
//     js_free(ctx, input);
//     return bin_to_hex(ctx, output, mbedtls_md_get_size(md_info));
// }

// /* AES通用实现 */
// static JSValue crypto_aes(JSContext *ctx, int encrypt, mbedtls_cipher_mode_t mode,
//                          JSValueConst this_val, int argc, JSValueConst *argv) {
//     uint8_t *key, *iv, *input, *output;
//     size_t key_len, iv_len, len;
//     const mbedtls_cipher_info_t *cipher_info;
    
//     if (get_bin(ctx, argv[0], &key, &key_len) < 0 ||
//         get_bin(ctx, argv[1], &iv, &iv_len) < 0 ||
//         get_bin(ctx, argv[2], &input, &len) < 0)
//         return JS_EXCEPTION;
    
//     cipher_info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES,
//                                                  (int)key_len * 8, mode);
//     if (!cipher_info) {
//         JS_ThrowError(ctx, "Unsupported AES parameters");
//         goto fail;
//     }
    
//     mbedtls_cipher_context_t cipher_ctx;
//     mbedtls_cipher_init(&cipher_ctx);
    
//     if (mbedtls_cipher_setup(&cipher_ctx, cipher_info) != 0 ||
//         mbedtls_cipher_setkey(&cipher_ctx, key, (int)key_len * 8,
//                              encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT) != 0 ||
//         mbedtls_cipher_set_iv(&cipher_ctx, iv, iv_len) != 0) {
//         JS_ThrowError(ctx, "AES init failed");
//         goto cleanup;
//     }
    
//     size_t output_len = len + 16; // 最大填充空间
//     output = js_malloc(ctx, output_len);
    
//     if (mbedtls_cipher_update(&cipher_ctx, input, len, output, &output_len) != 0) {
//         js_free(ctx, output);
//         JS_ThrowError(ctx, "Encryption failed");
//         goto cleanup;
//     }
    
//     size_t final_len;
//     if (mbedtls_cipher_finish(&cipher_ctx, output + output_len, &final_len) != 0) {
//         js_free(ctx, output);
//         JS_ThrowError(ctx, "Finalization failed");
//         goto cleanup;
//     }
//     output_len += final_len;
    
//     JSValue ret = JS_NewArrayBufferCopy(ctx, output, output_len);
//     js_free(ctx, output);
    
// cleanup:
//     mbedtls_cipher_free(&cipher_ctx);
// fail:
//     js_free(ctx, key);
//     js_free(ctx, iv);
//     js_free(ctx, input);
//     return ret;
// }

// /* 随机字节生成 */
// static JSValue crypto_random_bytes(JSContext *ctx, JSValueConst this_val,
//                                   int argc, JSValueConst *argv) {
//     int32_t size;
//     if (JS_ToInt32(ctx, &size, argv[0]) < 0 || size <= 0)
//         return JS_ThrowRangeError(ctx, "Invalid size");
    
//     uint8_t *buf = js_malloc(ctx, size);
//     if (!buf) return JS_EXCEPTION;
    
//     if (mbedtls_ctr_drbg_random(&ctr_drbg, buf, size) != 0) {
//         js_free(ctx, buf);
//         return JS_ThrowError(ctx, "RNG failed");
//     }
    
//     JSValue ret = JS_NewArrayBufferCopy(ctx, buf, size);
//     js_free(ctx, buf);
//     return ret;
// }

// /* 模块初始化 */
// static int js_crypto_init(JSContext *ctx, JSModuleDef *m) {
//     // 哈希算法
//     JS_SetModuleExport(ctx, m, "sha256", 
//         JS_NewCFunction2(ctx, (JSCFunction*)crypto_hash, "sha256", 1,
//                         JS_CFUNC_generic, (void*)MBEDTLS_MD_SHA256));
    
//     JS_SetModuleExport(ctx, m, "sha512", 
//         JS_NewCFunction2(ctx, (JSCFunction*)crypto_hash, "sha512", 1,
//                         JS_CFUNC_generic, (void*)MBEDTLS_MD_SHA512));

//     // AES加密
//     JS_SetModuleExport(ctx, m, "aesEncryptCBC",
//         JS_NewCFunction2(ctx, (JSCFunction*)crypto_aes, "aesEncryptCBC", 3,
//                         JS_CFUNC_generic, (void*[]){1, MBEDTLS_MODE_CBC}));
    
//     JS_SetModuleExport(ctx, m, "aesDecryptCBC",
//         JS_NewCFunction2(ctx, (JSCFunction*)crypto_aes, "aesDecryptCBC", 3,
//                         JS_CFUNC_generic, (void*[]){0, MBEDTLS_MODE_CBC}));

//     // 在crypto_aes函数中增加模式判断
//     JS_SetModuleExport(ctx, m, "aesEncryptGCM",
//         JS_NewCFunction2(ctx, (JSCFunction*)crypto_aes, "aesEncryptGCM", 4,
//                     JS_CFUNC_generic, (void*[]){1, MBEDTLS_MODE_GCM}));

//     // 其他功能
//     JS_SetModuleExport(ctx, m, "randomBytes",
//         JS_NewCFunction(ctx, crypto_random_bytes, "randomBytes", 1));
    
//     return 0;
// }

// JSModuleDef *js_init_module_crypto(JSContext *ctx, const char *module_name) {
//     return JS_NewCModule(ctx, module_name, js_crypto_init);
// }