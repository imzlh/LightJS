/**
 * This file is a part of the LightJS project.
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

#include <stdarg.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#pragma once

// ignore non-string values and return NULL
static inline const char* LJS_ToCString(JSContext *ctx, JSValueConst val, size_t* psize){
    if(!JS_IsString(val)) return NULL;  // different from JS_ToCString
    return JS_ToCStringLen(ctx, psize, val);
}

typedef enum {
    EXCEPTION_ERROR,
    EXCEPTION_TYPEERROR,
    EXCEPTION_IO,
    EXCEPTION_NOTFOUND,
    EXCEPTION_INPUT,
    EXCEPTION_INVAILDF,
    EXCEPTION_INTERNAL,
    EXCEPTION_NOTSUPPORT,

    __EXCEPTION_COUNT
} ExceptionType;

static const char* __exception_type_str[] = {
    "Error",
    "TypeError",
    "IOException",
    "NotFoundException",
    "InvaildFileException",
    "InputError",
    "InternalError",
    "NotSupportError"
};

/**
 * 抛出一个错误，带有帮助信息
 * @param ctx 运行时上下文
 * @param msg 错误信息
 * @param help 帮助信息
 */
static inline JSValue LJS_Throw(JSContext *ctx, ExceptionType type, const char *msg, const char *help, ...) {
    va_list args;
    JSValue error_obj = JS_NewError(ctx);

    // Allocate the error message
    char msg2[1024];

    va_start(args, help);
    vsnprintf(msg2, sizeof(msg2), msg, args);
    va_end(args);

    JS_DefinePropertyValue(ctx, error_obj, JS_ATOM_name, JS_NewString(ctx, __exception_type_str[type]), JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE);
    JS_DefinePropertyValue(ctx, error_obj, JS_ATOM_message, JS_NewString(ctx, msg2), JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE);

    if (help) {
        JS_DefinePropertyValueStr(ctx, error_obj, "help", JS_NewString(ctx, help), JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE);
    }
    return JS_Throw(ctx, error_obj);
}

#define LJS_ThrowInAsync(ctx, type, msg, help, ...) { \
    LJS_Throw(ctx, type, msg, help, ##__VA_ARGS__); \
    JSValue exception = JS_GetException(ctx), prom_cb[2], prom = JS_NewPromiseCapability(ctx, prom_cb); \
    JS_FreeValue(ctx, prom_cb[0]); \
    JS_Call(ctx, prom_cb[1], prom, 1, (JSValueConst[]){ exception }); \
    JS_FreeValue(ctx, prom_cb[1]); \
    JS_FreeValue(ctx, exception); \
    return prom; \
}

static inline JSValue LJS_ThrowWithError(JSContext *ctx, const char *msg, const char *help){
    JSValue error = JS_GetException(ctx);
    JSValue message = JS_GetPropertyStr(ctx, error, "message");
    const char* message_str = "Unknown Error";
    if (JS_IsString(message)){
        message_str = JS_ToCString(ctx, message);
        JS_FreeValue(ctx, message);
    }
    LJS_Throw(ctx, EXCEPTION_ERROR, "%s: %s", help, msg, message_str);
    JS_FreeValue(ctx, message);
    JS_FreeValue(ctx, error);
    return JS_EXCEPTION;
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

    JSPropertyEnum *props;
    int proplen = JS_GetOwnPropertyNames(ctx, &props, &max_items, from, JS_GPN_ENUM_ONLY);
    if(proplen < 0) return false;
    for(int i = 0; i < proplen; i++){
        val = JS_GetProperty(ctx, from, props[i].atom);
        JS_SetProperty(ctx, to, props[i].atom, val);
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
    if(app -> worker) return false; // worker
    if(JS_GetRuntimeOpaque(JS_GetRuntime(ctx)) != app) return false; // sandbox
    return true;
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

static inline bool JS_IsInternalError(JSContext* ctx, JSValueConst val){
    if(!JS_IsError(ctx, val)) return false;
    const char* name = LJS_ToCString(ctx, JS_GetProperty(ctx, val, JS_ATOM_name), NULL);
    if(!name || strcmp(name, "InternalError") != 0) return false;
    return true;
}

static inline void JS_Call2(JSContext* ctx, JSValueConst func, JSValueConst this_obj, int argc, JSValueConst* argv){
    JS_FreeValue(ctx, JS_Call(ctx, func, this_obj, argc, argv));
}

static inline JSValue JS_CopyValue(JSContext* source_ctx, JSContext* target_ctx, JSValue val){
    size_t len;
    JSValue ret;
    uint8_t* opcode = JS_WriteObject(source_ctx, &len, val, JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_SAB | JS_WRITE_OBJ_REFERENCE);
    ret = JS_ReadObject(target_ctx, opcode, len, JS_READ_OBJ_BYTECODE | JS_READ_OBJ_SAB);
    js_free(source_ctx, opcode);
    return ret;
}