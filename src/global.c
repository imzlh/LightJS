/**
 * JS Global Object & functions
 * & LightJS core utils
 */

#include "../engine/quickjs.h"
#include "core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <assert.h>
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

static thread_local JSClassID evtarget_class_id;

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

static bool is_utf16(const uint8_t* data, size_t len) {
    if (len < 2 || (len % 2 != 0)) return false;

    // BOM
    if (len >= 2) {
        if ((data[0] == 0xFF && data[1] == 0xFE) ||  // UTF-16LE BOM
            (data[0] == 0xFE && data[1] == 0xFF)) {    // UTF-16BE BOM
            return true;
        }
    }

    size_t valid_pairs = 0;
    for (size_t i = 0; i < len; i += 2) 
        if (data[i+1] == 0 && data[i] != 0) 
            valid_pairs++;

    bool ret = (valid_pairs * 2) >= len;
    return ret;
}

char* u16_to_u8(const uint16_t* utf16, size_t len) {
    char* utf8 = malloc(len * 4 + 1);
    char* p = utf8;
    for (size_t i = 0; i < len; i++) {
        uint32_t code = utf16[i];

        // 处理代理对（Surrogate pairs，4字节UTF-16）
        if (code >= 0xD800 && code <= 0xDBFF && i + 1 < len) {
            uint32_t low = utf16[i+1];
            if (low >= 0xDC00 && low <= 0xDFFF) {
                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                i++;
            }
        }

        // 转换为UTF-8
        if (code <= 0x7F) {
            *p++ = code;
        } else if (code <= 0x7FF) {
            *p++ = 0xC0 | (code >> 6);
            *p++ = 0x80 | (code & 0x3F);
        } else if (code <= 0xFFFF) {
            *p++ = 0xE0 | (code >> 12);
            *p++ = 0x80 | ((code >> 6) & 0x3F);
            *p++ = 0x80 | (code & 0x3F);
        } else {
            *p++ = 0xF0 | (code >> 18);
            *p++ = 0x80 | ((code >> 12) & 0x3F);
            *p++ = 0x80 | ((code >> 6) & 0x3F);
            *p++ = 0x80 | (code & 0x3F);
        }
    }

    *p = '\0';
    return utf8;
}

static JSValue js_u8array_to_str(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc != 1 || JS_GetTypedArrayType(argv[0]) == -1){
        return LJS_Throw(ctx, "decodeUint8Array() requires a TypedArray argument",
            "decodeStr(arr: TypedArray):string"
        );
    }

    size_t len = 0;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if(!data) return JS_EXCEPTION;

    while(*data == 0 && len != 0)
        data++, len--;

    if(data[len-1] == 0) len--; // 去掉结尾的\0
    if(len == 0) return JS_NewStringLen(ctx, "", 0);

    // U16判断
    if(is_utf16(data, len)){
        char* u8 = u16_to_u8((const uint16_t*)data, len/2);
        JSValue ret = JS_NewString(ctx, u8);
        free(u8);
        return ret;
    }
    
    JSValue ret = JS_NewStringLen(ctx, (char*)data, len);
    return ret;
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

    // encodeStr/decodeStr
    JS_SetPropertyStr(ctx, global_obj, "encodeStr", JS_NewCFunction(ctx, js_str_to_u8array, "encodeStr", 1));
    JS_SetPropertyStr(ctx, global_obj, "decodeStr", JS_NewCFunction(ctx, js_u8array_to_str, "decodeStr", 1));

    JS_SetPropertyStr(ctx, global_obj, "event", global_ev);
    return true;
}

void LJS_dispatch_ev(JSContext *ctx, const char * name, JSValue data){
    // new Event()
    Event *event = event_new(ctx, name, data);
    evtarget_fire(JS_GetOpaque(global_ev, evtarget_class_id), event);
}

JSValue js_extends_evtarget(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, evtarget_class_id);
    JS_SetOpaque(obj, evtarget_new(ctx));

    return obj;
}

//  ---------- VM features ----------
static JSValue js_vm_gc(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JS_RunGC(JS_GetRuntime(ctx));
    return JS_UNDEFINED;
}

static JSValue js_vm_dump(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc != 1){
        return LJS_Throw(ctx, "dump() requires at least one argument",
            "dump(obj: any, strip?: boolean): Uin8Array"
        );
    }

    int flag = JS_WRITE_OBJ_BYTECODE;
    if(!(argc >= 2 && JS_ToBool(ctx, argv[1]))) flag |= JS_WRITE_OBJ_STRIP_DEBUG | JS_WRITE_OBJ_STRIP_SOURCE;
    JSValue obj = argv[0];
    size_t len = 0;
    uint8_t *data = JS_WriteObject(ctx, &len, obj, flag);
    if(!data) return JS_EXCEPTION;
    return JS_NewUint8Array(ctx, data, len, free_js_malloc, NULL, false);
}

static JSValue js_vm_load(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc != 1 || JS_GetTypedArrayType(argv[0]) != JS_TYPED_ARRAY_UINT8){
        return LJS_Throw(ctx, "load() requires a Uint8Array argument",
            "load(arr: Uint8Array): any"
        );
    }

    size_t len = 0;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if(!data) return JS_EXCEPTION;

    JSValue obj = JS_ReadObject(ctx, data, len, JS_READ_OBJ_BYTECODE);
    return obj;
}

static JSValue js_vm_compile(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc == 0 || !JS_IsString(argv[0])){
        return LJS_Throw(ctx, "compile() requires a string argument",
            "compile(source: string, module_name?: string): Uint8Array"
        );
    }

    size_t len;
    int flag = JS_EVAL_FLAG_COMPILE_ONLY;
    const char *source = JS_ToCStringLen(ctx, &len, argv[0]);
    const char *module_name = argc >= 2 ? JS_ToCString(ctx, argv[1]) : NULL;
    if(!source) return JS_EXCEPTION;

    if(module_name) flag |= JS_EVAL_TYPE_MODULE;
    else flag |= JS_EVAL_TYPE_GLOBAL;

    JSValue compiled = JS_Eval(ctx, source, len, module_name ? module_name : "<eval>", flag);
    if(JS_IsException(compiled)) goto fail;

    size_t output_len;
    uint8_t* output = JS_WriteObject(ctx, &output_len, compiled, JS_WRITE_OBJ_BYTECODE);
    if(!output){ 
        JS_FreeValue(ctx, compiled); 
        goto fail; 
    }

    JS_FreeValue(ctx, compiled);
    JS_FreeCString(ctx, source);
    JS_FreeCString(ctx, module_name);
    return JS_NewUint8Array(ctx, (uint8_t*)output, output_len, free_js_malloc, NULL, false);
fail:
    JS_FreeCString(ctx, source);
    JS_FreeCString(ctx, module_name);
    return JS_EXCEPTION;
}

const JSCFunctionListEntry js_vm_funcs[] = {
    JS_CFUNC_DEF("gc", 0, js_vm_gc),
    JS_CFUNC_DEF("dump", 1, js_vm_dump),
    JS_CFUNC_DEF("load", 1, js_vm_load),
    JS_CFUNC_DEF("compile", 1, js_vm_compile),
};

// class Sandbox
// 使用线程内JSContext隔离执行JS代码
static thread_local JSClassID js_sandbox_class_id;

static JSValue js_sandbox_eval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    App* app = (App*)JS_GetOpaque(this_val, js_sandbox_class_id);
    if(!app) return LJS_Throw(ctx, "this value invalid", NULL);

    if(argc == 0){
        return LJS_Throw(ctx, "eval requires at least one argument",
            "Sandbox.eval(code: string, import_meta?: object): any | Promise<any>"
        );
    }

    const char* code = JS_ToCString(ctx, argv[0]);
    if(!code) return LJS_Throw(ctx, "code argument is not a string", NULL);
    JSValue func;
    JS_UpdateStackTop(JS_GetRuntime(ctx));
    if(argc == 2 && JS_IsObject(argv[1])){
        func = JS_Eval(ctx, code, strlen(code), "<eval>", JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        if(!JS_IsException(func) && JS_IsModule(func)){
            // set import.meta
            JSValue meta = JS_GetImportMeta(ctx, (JSModuleDef*)JS_VALUE_GET_PTR(func));
            JS_CopyObject(ctx, argv[1], meta, 32);
        }
    }else{
        func = JS_Eval(ctx, code, strlen(code), "<eval>", JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_COMPILE_ONLY);
    }

    if(JS_IsException(func)){
        return JS_EXCEPTION;
    }
    JS_UpdateStackTop(JS_GetRuntime(ctx));
    JSValue ret = JS_EvalFunction(ctx, func);
    return ret;
}

static JSValue js_sandbox_get_context(JSContext* ctx, JSValueConst this_val){
    App* app = (App*)JS_GetOpaque(this_val, js_sandbox_class_id);
    if(!app) return LJS_Throw(ctx, "this value invalid", NULL);
    return JS_GetGlobalObject(ctx);
}

static JSValue sandbox_func_proxy(JSContext* _ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic, JSValue* func_data){
    JSContext* ctx = JS_VALUE_GET_PTR(func_data[0]);
    JSValue real_func = func_data[magic];
    return JS_Call(ctx, real_func, this_val, argc, argv);
}

static JSValue js_sandbox_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    JSValue obj = JS_NewObjectClass(ctx, js_sandbox_class_id);

    App* app = LJS_create_app(JS_GetRuntime(ctx), 0, NULL, false, true, NULL, NULL);
    char* init_apps[32];
    uint8_t init_apps_len = 0;
    if(argc >= 1 && JS_IsObject(argv[0])){
        JSValue init_apps_obj = JS_GetPropertyStr(ctx, argv[0], "init");
        if(JS_IsArray(init_apps_obj)){
            int64_t len;
            if(JS_GetLength(ctx, init_apps_obj, &len)){
                for(uint32_t i = 0; i < len; i++){
                    JSValue val = JS_GetPropertyUint32(ctx, init_apps_obj, i);
                    if(JS_IsString(val)){
                        init_apps[init_apps_len++] = (char*)JS_ToCString(ctx, val);
                    }
                }
            }
            init_apps[init_apps_len] = '\0';
        }

        // module loader
        JSValue loader = JS_GetPropertyStr(ctx, argv[0], "loader");
        if(JS_IsFunction(ctx, loader)){
        //     size_t len;
        //     uint8_t* buf = JS_WriteObject(ctx, &len, loader, JS_WRITE_OBJ_BYTECODE);
        //     if(buf){
        //         app -> module_loader = JS_ReadObject(app -> ctx, buf, len, JS_READ_OBJ_BYTECODE);
        //         js_free(ctx, buf);
        //     }

            app -> module_loader = JS_NewCFunctionData(
                app -> ctx, sandbox_func_proxy, 1, 1,
                1, (JSValue[]){ JS_MKPTR(JS_TAG_OBJECT, app -> ctx), loader }
            );
        }
    }
    
    LJS_init_context(app, init_apps_len == 0 ? NULL : init_apps);
    JS_SetOpaque(obj, app);
    return obj;
}

static void js_sandbox_finalizer(JSRuntime* rt, JSValue val){
    App* app = (App*)JS_GetOpaque(val, js_sandbox_class_id);
    if(!app) return;
    LJS_destroy_app(app);
}

static JSCFunctionListEntry js_sandbox_funcs[] = {
    JS_CFUNC_DEF("eval", 1, js_sandbox_eval),
    JS_CGETSET_DEF("context", js_sandbox_get_context, NULL)
};

static JSClassDef js_sandbox_def = {
    "Sandbox",
    .finalizer = js_sandbox_finalizer,
};

static int vm_init(JSContext *ctx, JSModuleDef *m) {
    JS_SetModuleExportList(ctx, m, js_vm_funcs, countof(js_vm_funcs));

    JSValue sandbox_ctor = JS_NewCFunction2(ctx, js_sandbox_constructor, "Sandbox", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, sandbox_ctor, JS_GetClassProto(ctx, js_sandbox_class_id));
    JS_SetModuleExport(ctx, m, "Sandbox", sandbox_ctor);
    return 0;
}

bool LJS_init_vm(JSContext *ctx) {
    JSModuleDef* m = JS_NewCModule(ctx, "vm", vm_init);
    if (!m) return false;

    JS_NewClassID(JS_GetRuntime(ctx), &js_sandbox_class_id);
    if(-1 == JS_NewClass(JS_GetRuntime(ctx), js_sandbox_class_id, &js_sandbox_def)) return false;
    JSValue sandbox_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, sandbox_proto, js_sandbox_funcs, countof(js_sandbox_funcs));
    JS_SetClassProto(ctx, js_sandbox_class_id, sandbox_proto);
    JS_AddModuleExport(ctx, m, "Sandbox");

    return JS_AddModuleExportList(ctx, m, js_vm_funcs, countof(js_vm_funcs));
}

// ================ promise loop ==============
struct promise_data {
    struct list_head list;
    JSValue promise;
    JSContext* ctx;

    JSPromiseCallback callback;
    void* opaque;
};

static thread_local struct list_head promise_jobs = {NULL, NULL};

int js_run_promise_jobs(){
    if(promise_jobs.prev == NULL){
        init_list_head(&promise_jobs);
        return 0;
    }
    if(list_empty(&promise_jobs)) return 0;
    int count = 0;
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &promise_jobs){
        struct promise_data* data = list_entry(cur, struct promise_data, list);
        JSPromiseStateEnum res = JS_PromiseState(data -> ctx, data -> promise);
        if(res != JS_PROMISE_PENDING){
            const bool error = res == JS_PROMISE_REJECTED;
            if(error) JS_PromiseHandleError(data -> ctx, data -> promise);    // catch()
            data -> callback(
                data -> ctx, error, 
                JS_PromiseResult(data -> ctx, data -> promise),
                data -> opaque
            );
            list_del(cur);
            JS_FreeValue(data -> ctx, data -> promise);
            free(data);
            count ++;
        }
    }
    return count;
}

// return true if promise has been resolved or rejected
bool LJS_enqueue_promise_job(JSContext* ctx, JSValue promise, JSPromiseCallback callback, void* opaque){
    int state = JS_PromiseState(ctx, promise);
    if(state != JS_PROMISE_PENDING){
        const bool error = state == -1 ? JS_IsException(promise) : state == JS_PROMISE_REJECTED;
        if(error) JS_PromiseHandleError(ctx, promise);  // make the promise auto-catched
        callback(ctx, error, JS_PromiseResult(ctx, promise), opaque);
        JS_FreeValue(ctx, promise);
        return true;
    }

    struct promise_data* data = (struct promise_data*)malloc(sizeof(struct promise_data));
    data -> promise = JS_DupValue(ctx, promise);
    data -> ctx = ctx;
    data -> callback = callback;
    data -> opaque = opaque;
    list_add_tail(&data -> list, &promise_jobs);
    return false;
}

// static void handle_promise(JSContext *ctx, bool is_error, JSValue reason, void *opaque) {
//     assert(is_error);
//     JSValue promise = ((struct JSValueProxy*)opaque) -> val;
//     if(!JS_PromiseIsHandled(ctx, promise)){
//         fprintf(stderr, "Uncaught (in promise) ");
//         LJS_dump_error(ctx, reason);
//     }
// }

void js_handle_promise_reject(
    JSContext *ctx, JSValue promise,
    JSValue reason,
    bool is_handled, void *opaque
){
    if (!is_handled){
        // force next_tick
        // struct promise_data* data = (struct promise_data*)malloc(sizeof(struct promise_data));
        // data -> promise = JS_DupValue(ctx, promise);
        // data -> ctx = ctx;
        // data -> callback = handle_promise;
        // data -> opaque = LJS_NewJSValueProxy(ctx, promise);
        // list_add_tail(&data -> list, &promise_jobs);
        fprintf(stderr, "Uncaught (in promise) ");
        LJS_dump_error(ctx, reason);
    }
}