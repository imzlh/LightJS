#include "../engine/quickjs.h"
#include "core.h"

#include <stdarg.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

// ignore non-string values and return NULL
static inline const char* LJS_ToCString(JSContext *ctx, JSValueConst val, size_t* psize){
    if(!JS_IsString(val)) return NULL;  // different from JS_ToCString
    return JS_ToCStringLen(ctx, psize, val);
}

/**
 * 抛出一个错误，带有帮助信息
 * @param ctx 运行时上下文
 * @param msg 错误信息
 * @param help 帮助信息
 */
static inline JSValue LJS_Throw(JSContext *ctx, const char *msg, const char *help, ...) {
    va_list args;
    JSValue error_obj = JS_NewError(ctx);

    // Allocate the error message
    size_t msg_len = strlen(msg) * 3;
    char* msg2 = js_malloc(ctx, msg_len);   // guessed
    if (!msg2) {
        JS_FreeValue(ctx, error_obj);
        return JS_ThrowOutOfMemory(ctx);
    }

    va_start(args, help);
    vsnprintf(msg2, msg_len, msg, args);
    va_end(args);

    JS_DefinePropertyValueStr(ctx, error_obj, "message", JS_NewString(ctx, msg2), JS_PROP_C_W_E);
    js_free(ctx, msg2);

    if (help) {
        JS_DefinePropertyValueStr(ctx, error_obj, "help", JS_NewString(ctx, help), JS_PROP_C_W_E);
    }
    return JS_Throw(ctx, error_obj);
}

static inline JSValue LJS_ThrowWithError(JSContext *ctx, const char *msg, const char *help){
    char* error_str = js_malloc(ctx, 1024);
    if(!error_str) return JS_ThrowOutOfMemory(ctx);
    JSValue error = JS_GetException(ctx);
    JSValue message = JS_GetPropertyStr(ctx, error, "message");
    JSValue type = JS_GetPropertyStr(ctx, error, "name");
    char* message_str = "Unknown Error";
    char* type_str = "Error";
    if (JS_IsString(message)){
        message_str = (char*)JS_ToCString(ctx, message);
    }
    if (JS_IsString(type)){
        type_str = (char*)JS_ToCString(ctx, type);
    }
    snprintf(error_str, 1024, "%s: %s", type_str, message_str);
    JS_Throw(ctx, LJS_Throw(ctx, error_str, help));
    js_free(ctx, error_str);
    JS_FreeValue(ctx, error);
    JS_FreeValue(ctx, message);
    JS_FreeValue(ctx, type);
    return JS_EXCEPTION;
}

static inline void LJS_panic(const char *msg){
    printf("LightJS fatal error: %s\n", msg);
    js_exit(1);
}

struct promise{
    JSContext* ctx;
    JSValue resolve;
    JSValue reject;
    JSValue promise;
    void* user_data;
};

/**
 * 创建一个Promise Proxy，方便在C中操作
 * @param ctx 运行时上下文
 */
static inline struct promise* LJS_NewPromise(JSContext *ctx){
    struct promise* proxy = js_malloc(ctx, sizeof(struct promise));
    if(!proxy) return NULL;
    assert(ctx != NULL);
    JSValue resolving_funcs[2];
    proxy -> ctx = ctx;
    proxy -> promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    proxy -> resolve = resolving_funcs[0];
    proxy -> reject = resolving_funcs[1];
    return proxy;
}

static inline void LJS_FreePromise(struct promise* proxy){
    assert(NULL != proxy -> ctx);   // error: already free
    JS_FreeValue(proxy -> ctx, proxy -> resolve);
    JS_FreeValue(proxy -> ctx, proxy -> reject);
    // WARN: 此处应该由用户决策，所有权是否转移到JS层？
    // JS_FreeValue(proxy -> ctx, proxy -> promise);
    JSContext* ctx = proxy -> ctx;
    proxy -> ctx = NULL;
    js_free(ctx, proxy);
    
}

static inline void LJS_Promise_Resolve(struct promise* proxy, JSValue value){
    assert(NULL != proxy -> ctx);   // error: already free
    JSValue args[1] = {value};
    JS_Call(proxy -> ctx, proxy -> resolve, proxy -> promise, 1, args);
    LJS_FreePromise(proxy);
}

static inline void LJS_Promise_Reject(struct promise* proxy, const char* msg){
    assert(NULL != proxy -> ctx);   // error: already free
    JSValue error = JS_NewError(proxy -> ctx);
    JS_SetPropertyStr(proxy -> ctx, error, "message", JS_NewString(proxy -> ctx, msg));
    JS_Call(proxy -> ctx, proxy -> reject, proxy -> promise, 1, (JSValueConst[]){error});
    LJS_FreePromise(proxy);
}

static inline JSValue LJS_NewResolvedPromise(JSContext* ctx, JSValue value){
    JSValue cb[2];
    JSValue ret = JS_NewPromiseCapability(ctx, cb);
    JS_Call(ctx, cb[0], JS_UNDEFINED, 1, (JSValueConst[]){value});
    JS_FreeValue(ctx, cb[0]);
    JS_FreeValue(ctx, cb[1]);
    return ret;
}

static inline bool JS_CopyObject(JSContext *ctx, JSValueConst from, JSValue to, uint32_t max_items){
    JSValue val;

    JSPropertyEnum *props[max_items];
    int proplen = JS_GetOwnPropertyNames(ctx, props, &max_items, from, JS_GPN_ENUM_ONLY);
    if(proplen < 0) return false;
    for(int i = 0; i < proplen; i++){
        val = JS_GetProperty(ctx, from, props[i] -> atom);
        JS_SetProperty(ctx, to, props[i] -> atom, val);
    }
    return true;
}

struct JSValueProxy {
    JSValue val;
    JSContext* ctx;
};

static inline struct JSValueProxy* LJS_NewJSValueProxy(JSContext *ctx, JSValue val){
    struct JSValueProxy* proxy = js_malloc(ctx, sizeof(struct JSValueProxy));
    if(!proxy) return NULL;
    proxy -> val = JS_DupValue(ctx, val);
    proxy -> ctx = ctx;
    return proxy;
}

static inline void LJS_FreeJSValueProxy(struct JSValueProxy* proxy){
    JS_FreeValue(proxy -> ctx, proxy -> val);
    js_free(proxy -> ctx, proxy);
}

static inline void JS_PromiseCatch(JSContext* ctx, JSValueConst promise, JSValueConst onRejected){
    if(JS_IsPromise(promise))
        JS_SetProperty(ctx, promise, JS_ATOM_catch, onRejected);
}

static inline bool LJS_IsMainContext(JSContext* ctx){
    App* app = JS_GetContextOpaque(ctx);
    if(!app -> worker) return true;
    return false;
}

static inline bool JS_IsTypedArray(JSContext* ctx, JSValueConst val){
    // order QuickJS
    // size_t psize;
    // return NULL == JS_GetArrayBuffer(ctx, &psize, val);
    return JS_GetTypedArrayType(val) != -1;
}

// Note: should free after use
static inline JSValue JS_GetWeakRefValue(JSContext* ctx, JSValueConst ref){
    return JS_GetWeakRef(ctx, ref);
}

static inline int JS_GetEnumerableLength(JSContext* ctx, JSValueConst obj, int64_t* plen){
    JSValue jsobj;
    int ret = -1;
    if(JS_IsNumber(jsobj = JS_GetProperty(ctx, obj, JS_ATOM_length))){
        ret = JS_ToInt64(ctx, plen, jsobj);
        goto end;
    }
    JS_FreeValue(ctx, jsobj);
    
    if(JS_IsNumber(jsobj = JS_GetProperty(ctx, obj, JS_ATOM_size))){
        ret = JS_ToInt64(ctx, plen, jsobj);
        goto end;
    }

end:
    JS_FreeValue(ctx, jsobj);
    return ret;
}

static inline void JS_SetCtorProto(JSContext* ctx, JSValueConst ctor, JSClassID class_id){
    JSValue proto = JS_GetClassProto(ctx, class_id);
    JS_SetConstructor(ctx, ctor, proto);
    JS_FreeValue(ctx, proto);
}