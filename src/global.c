#include "../engine/quickjs.h"
#include "core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <sys/stat.h>

typedef struct {
    char *type;
    JSValue callback;
} Listener;

typedef struct {
    Listener *listeners;
    int listener_count;
    int listener_capacity;
    JSContext *ctx;
} EvTarget;

typedef struct {
    char *type;
    JSValue data;
    int default_prevented;
} Event;

static JSClassID evtarget_class_id;

// 初始化 EvTarget
static EvTarget *evtarget_new(JSContext* ctx){
    EvTarget *et = js_malloc(ctx, sizeof(EvTarget));
    et->listeners = NULL;
    et->listener_count = 0;
    et->listener_capacity = 0;
    return et;
}

// 释放 EvTarget
static void evtarget_free(EvTarget *et) {
    for (int i = 0; i < et->listener_count; i++) {
        JS_FreeValue(et -> ctx, et->listeners[i].callback);
        js_free(et -> ctx ,et->listeners[i].type);
    }
    js_free(et -> ctx, et->listeners);
    js_free(et -> ctx, et);
}

// 添加事件监听器
static void evtarget_on(EvTarget *et, const char *type, JSValue callback) {
    if (et->listener_count >= et->listener_capacity) {
        et->listener_capacity = et->listener_capacity ? et->listener_capacity * 2 : 8;
        et->listeners = js_realloc(et -> ctx, et->listeners, et->listener_capacity * sizeof(Listener));
    }
    et->listeners[et->listener_count].type = strdup(type);
    et->listeners[et->listener_count].callback = JS_DupValue(et -> ctx, callback);
    et->listener_count++;
}

// 移除事件监听器
static void evtarget_off(EvTarget *et, const char *type, JSValue callback) {
    for (int i = 0; i < et->listener_count; i++) {
        if (strcmp(et->listeners[i].type, type) == 0 && JS_VALUE_GET_PTR(et->listeners[i].callback) == JS_VALUE_GET_PTR(callback)) {
            JS_FreeValue(et -> ctx, et->listeners[i].callback);
            js_free(et -> ctx, et->listeners[i].type);
            memmove(&et->listeners[i], &et->listeners[i + 1], (et->listener_count - i - 1) * sizeof(Listener));
            et->listener_count--;
            break;
        }
    }
}

// 阻止默认行为
static void event_prevent_default(Event *event) {
    event->default_prevented = 1;
}

static JSValue js_ev_prevent_default(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    event_prevent_default(JS_GetOpaque(this_val, 0));
    return JS_UNDEFINED;
}

// 触发事件
static void evtarget_fire(EvTarget *et, Event *event) {
    for (int i = 0; i < et->listener_count; i++) {
        if (strcmp(et->listeners[i].type, event->type) == 0) {
            JSContext *ctx = et ->ctx;
            JSValue argv[1];
            argv[0] = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, argv[0], "type", JS_NewString(ctx, event->type));
            JS_SetPropertyStr(ctx, argv[0], "preventDefault", JS_NewCFunction(ctx, js_ev_prevent_default, "preventDefault", 0));
            JS_Call(ctx, et->listeners[i].callback, JS_UNDEFINED, 1, argv);
            JS_FreeValue(ctx, argv[0]);
        }
    }
}

// 创建 Event 对象
static Event *event_new(JSContext *ctx, const char *type, JSValue data) {
    Event *event = js_malloc(ctx, sizeof(Event));
    event->type = strdup(type);
    event->default_prevented = 0;
    event->data = data;
    return event;
}

// 释放 Event 对象
static void event_free(JSContext* ctx, Event *event) {
    JS_FreeValue(ctx, event->data);
    js_free(ctx, event->type);
    js_free(ctx, event);
}

// QuickJS 绑定部分
static JSValue js_evtarget_on(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    EvTarget *et = JS_GetOpaque(this_val, 0);
    if (!et || argc < 2)
        return JS_EXCEPTION;

    const char *type = JS_ToCString(ctx, argv[0]);
    JSValue callback = argv[1];
    evtarget_on(et, type, JS_DupValue(ctx, callback));
    JS_FreeCString(ctx, type);
    return JS_UNDEFINED;
}

static JSValue js_evtarget_off(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    EvTarget *et = JS_GetOpaque(this_val, 0);
    if (!et || argc < 2)
        return JS_EXCEPTION;

    const char *type = JS_ToCString(ctx, argv[0]);
    JSValue callback = argv[1];
    evtarget_off(et, type, callback);
    JS_FreeCString(ctx, type);
    return JS_UNDEFINED;
}

static JSValue js_evtarget_fire(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    EvTarget *et = JS_GetOpaque(this_val, 0);
    if (!et || argc < 1)
        return JS_EXCEPTION;

    JSValue data = JS_UNDEFINED;
    
    if(argc == 2){
        data = argv[1];
    }

    const char *type = JS_ToCString(ctx, argv[0]);
    Event *event = event_new(ctx, type, data);
    evtarget_fire(et, event);
    event_free(ctx, event);
    JS_FreeCString(ctx, type);
    return JS_UNDEFINED;
}

static void js_evtarget_finalizer(JSRuntime *rt, JSValue val) {
    EvTarget *et = JS_GetOpaque(val, 0);
    if (et)
        evtarget_free(et);
}

static JSClassDef evtarget_class = {
    "EvTarget",
    .finalizer = js_evtarget_finalizer,
};

static JSValue js_evtarget_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    EvTarget *et = evtarget_new(ctx);
    et -> ctx = ctx;
    JSValue obj = JS_NewObjectClass(ctx, 0);
    JS_SetOpaque(obj, et);
    return obj;
}

static const JSCFunctionListEntry evtarget_proto_funcs[] = {
    JS_CFUNC_DEF("on", 2, js_evtarget_on),
    JS_CFUNC_DEF("off", 2, js_evtarget_off),
    JS_CFUNC_DEF("fire", 1, js_evtarget_fire),
};

static thread_local JSValue global_ev;
static thread_local JSContext* global_ctx;

// ------- base64 ----

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const uint8_t *input, size_t len, char *output) {
    size_t i, j = 0;
    for (i = 0; i < len; i += 3) {
        uint32_t octet_a = i < len ? input[i] : 0;
        uint32_t octet_b = i + 1 < len ? input[i + 1] : 0;
        uint32_t octet_c = i + 2 < len ? input[i + 2] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = (i + 1 < len) ? base64_table[(triple >> 6) & 0x3F] : '=';
        output[j++] = (i + 2 < len) ? base64_table[triple & 0x3F] : '=';
    }
    output[j] = '\0';
}

void base64_decode(const char *input, size_t len, uint8_t *output, size_t *output_len) {
    size_t i, j = 0;
    uint8_t decoding_table[256] = {0};
    for (i = 0; i < 64; i++) {
        decoding_table[(unsigned char)base64_table[i]] = i;
    }

    for (i = 0; i < len; i += 4) {
        uint32_t sextet_a = i < len ? decoding_table[(unsigned char)input[i]] : 0;
        uint32_t sextet_b = i + 1 < len ? decoding_table[(unsigned char)input[i + 1]] : 0;
        uint32_t sextet_c = i + 2 < len ? decoding_table[(unsigned char)input[i + 2]] : 0;
        uint32_t sextet_d = i + 3 < len ? decoding_table[(unsigned char)input[i + 3]] : 0;

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < *output_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < *output_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < *output_len) output[j++] = triple & 0xFF;
    }
    *output_len = j; // 更新真实输出长度
}

static JSValue js_atob(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    
    if(argc != 1 || !JS_IsString(argv[0])){
        return JS_ThrowTypeError(ctx, "atob() requires a string argument");
    }

    const char *str = JS_ToCString(ctx, argv[0]);
    size_t len = strlen(str);
    size_t output_len = (len * 3) / 4;
    uint8_t *output = js_malloc(ctx, output_len);
    base64_decode(str, len, output, &output_len);
    JSValue ret = JS_NewStringLen(ctx, (char*)output, output_len);
    js_free(ctx, output);
    JS_FreeCString(ctx, str);
    return ret;
}

static JSValue js_btoa(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc != 1 || !JS_IsString(argv[0])){
        return JS_ThrowTypeError(ctx, "btoa() requires a string argument");
    }

    const char *str = JS_ToCString(ctx, argv[0]);
    size_t len = strlen(str);
    size_t output_len = (len * 4) / 3 + 4;
    char *output = js_malloc(ctx, output_len);
    base64_encode((const uint8_t*)str, len, output);
    JSValue ret = JS_NewString(ctx, output);
    js_free(ctx, output);
    JS_FreeCString(ctx, str);
    return ret;
}

// encode/decode utf8
static JSValue js_str_to_u8array(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc != 1 || !JS_IsString(argv[0])){
        return LJS_Throw(ctx, "encodeStr() requires a string argument",
            "encodeStr(str:string):Uint8Array"
        );
    }

    const char *str = JS_ToCString(ctx, argv[0]);
    size_t len = strlen(str);
    JSValue buf = JS_NewUint8ArrayCopy(ctx, (uint8_t*)str, len);
    JS_FreeCString(ctx, str);
    return buf;
}

bool LJS_init_global_helper(JSContext *ctx) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    JSValue global_obj = JS_GetGlobalObject(ctx);

    // 添加全局EvTarget类
    JS_NewClassID(rt, &evtarget_class_id);
    if(0 != JS_NewClass(rt, evtarget_class_id, &evtarget_class)) return false;

    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, evtarget_proto_funcs, countof(evtarget_proto_funcs));
    JS_SetClassProto(ctx, evtarget_class_id, proto);

    JSValue constructor = JS_NewCFunction2(ctx, js_evtarget_constructor, "EvTarget", 0, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, constructor, proto);

    JS_SetPropertyStr(ctx, global_obj, "EvTarget", constructor);

    // 为全局添加event对象实现C到JS的事件
    global_ev = JS_NewObjectClass(ctx, evtarget_class_id);
    global_ctx = ctx;
    JS_SetOpaque(global_ev, evtarget_new(ctx));

    // 添加全局atob和btoa函数
    JS_SetPropertyStr(ctx, global_obj, "atob", JS_NewCFunction(ctx, js_atob, "atob", 1));
    JS_SetPropertyStr(ctx, global_obj, "btoa", JS_NewCFunction(ctx, js_btoa, "btoa", 1));

    // encodeStr
    JS_SetPropertyStr(ctx, global_obj, "encodeStr", JS_NewCFunction(ctx, js_str_to_u8array, "encodeStr", 1));

    JS_SetPropertyStr(ctx, global_obj, "event", global_ev);
    return true;
}

void LJS_dispatch_ev(JSContext *ctx, const char * name, JSValue data){
    // new Event()
    Event *event = event_new(ctx, name, data);
    evtarget_fire(JS_GetOpaque(global_ev, evtarget_class_id), event);
}