/**
 * JS Global Object & functions
 * & LightJS core utils
 */

#include "../engine/quickjs.h"
#include "core.h"
#include "polyfill.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <assert.h>
#include <signal.h>
#include <sys/stat.h>

// ------- event --------------
static thread_local JSValue event_notifier = JS_UNDEFINED;

static JSValue js_set_event_notifier(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc == 0 || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, "setEventNotifier() requires a function argument",
            "setEventNotifier(fn: (evname: string, data: any) => void):void"
        );
    }

    if(JS_GetContextOpaque(ctx) != JS_GetRuntimeOpaque(JS_GetRuntime(ctx)))
        return JS_ThrowTypeError(ctx, "setEventNotifier() cannot be used in a SandBox");

    if(!JS_IsUndefined(event_notifier))
        JS_FreeValue(ctx, event_notifier);
    event_notifier = JS_DupValue(ctx, argv[0]);
    return JS_UNDEFINED;
}

// ------- base64 --------

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

__maybe_unused static bool is_utf16(const uint8_t* data, size_t len) {
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

__maybe_unused static void u16_to_u8(char* utf8, const uint16_t* utf16, size_t len) {
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
}

static JSValue js_u8array_to_str(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc != 1 || JS_GetTypedArrayType(argv[0]) == -1){
        return LJS_Throw(ctx, "decodeUint8Array() requires a TypedArray argument",
            "decodeStr(arr: Uint8Array):string"
        );
    }

    size_t len = 0;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if(!data) return JS_EXCEPTION;

    // trim()
    while(*data == 0 && len != 0)
        data++, len--;
    if(len == 0) return JS_NewStringLen(ctx, "", 0);

    return JS_NewStringLen(ctx, (char*)data, len);

    // U16判断
    // if(len > 2 && is_utf16(data, len)){
    //     char* buf = malloc(len * 4 + 1);
    //     u16_to_u8(buf, (const uint16_t*)data, len/2);
    //     return JS_NewString(ctx, buf);
    // }else{
    //     return JS_NewStringLen(ctx, (char*)data, len);
    // }
}

bool LJS_init_global_helper(JSContext *ctx) {
    // JSRuntime *rt = JS_GetRuntime(ctx);
    JSValue global_obj = JS_GetGlobalObject(ctx);

    // 添加全局atob和btoa函数
    JS_SetPropertyStr(ctx, global_obj, "atob", JS_NewCFunction(ctx, js_atob, "atob", 1));
    JS_SetPropertyStr(ctx, global_obj, "btoa", JS_NewCFunction(ctx, js_btoa, "btoa", 1));

    // encodeStr/decodeStr
    JS_SetPropertyStr(ctx, global_obj, "encodeStr", JS_NewCFunction(ctx, js_str_to_u8array, "encodeStr", 1));
    JS_SetPropertyStr(ctx, global_obj, "decodeStr", JS_NewCFunction(ctx, js_u8array_to_str, "decodeStr", 1));

    JS_FreeValue(ctx, global_obj);
    return true;
}

void js_dispatch_global_event(JSContext *ctx, const char * name, JSValue data){
    JSValue evname = JS_NewString(ctx, name);
    JS_Call(ctx, event_notifier, JS_UNDEFINED, 2, (JSValueConst[]){
        evname, data
    });
    JS_FreeValue(ctx, evname);
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

    App* app = LJS_create_app(JS_GetRuntime(ctx), 0, NULL, false, true, "<inmemory>", NULL);
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
                    JS_FreeValue(ctx, val);
                }
            }
            init_apps[init_apps_len] = '\0';
        }
        JS_FreeValue(ctx, init_apps_obj);

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
                1, (JSValue[]){ JS_MKPTR(JS_TAG_INT, app -> ctx), loader }
            );
        }
    }
    
    LJS_init_context(app);
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

    JSValue sandbox = JS_GetClassProto(ctx, js_sandbox_class_id);
    JSValue sandbox_ctor = JS_NewCFunction2(ctx, js_sandbox_constructor, "Sandbox", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, sandbox_ctor, sandbox);
    JS_SetModuleExport(ctx, m, "Sandbox", sandbox_ctor);
    JS_FreeValue(ctx, sandbox);

    JSValue set_event_notifier = JS_NewCFunction(ctx, js_set_event_notifier, "setEventNotifier", 1);
    JS_SetModuleExport(ctx, m, "setEventNotifier", set_event_notifier);

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
    JS_AddModuleExport(ctx, m, "setEventNotifier");

    return JS_AddModuleExportList(ctx, m, js_vm_funcs, countof(js_vm_funcs));
}

// ================ promise loop ==============
struct Promise_data {
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
        struct Promise_data* data = list_entry(cur, struct Promise_data, list);
        JSPromiseStateEnum res = JS_PromiseState(data -> ctx, data -> promise);
        if(res != JS_PROMISE_PENDING){
#ifdef LJS_DEBUG
            printf("Promise job done: %p\n", data);
#endif
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

    struct Promise_data* data = (struct Promise_data*)malloc(sizeof(struct Promise_data));
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
//         js_dump(ctx, reason, stderr);
//     }
// }

void js_handle_promise_reject(
    JSContext *ctx, JSValue promise,
    JSValue reason,
    bool is_handled, void *opaque
){
    if (!is_handled){
        // force next_tick
        // struct Promise_data* data = (struct Promise_data*)malloc(sizeof(struct Promise_data));
        // data -> promise = JS_DupValue(ctx, promise);
        // data -> ctx = ctx;
        // data -> callback = handle_promise;
        // data -> opaque = LJS_NewJSValueProxy(ctx, promise);
        // list_add_tail(&data -> list, &promise_jobs);
        fprintf(stderr, "Uncaught (in promise) ");
        js_dump(ctx, reason, stderr);
        // JS_FreeValue(ctx, reason);
    }
}

void* js_malloc_proxy(size_t size, void* opaque){
    JSRuntime* rt = opaque;
    return js_malloc_rt(rt, size);
}

#ifdef LJS_DEBUG
static thread_local struct list_head promise_debug_jobs;

__attribute__((constructor)) void init_promise_debug_jobs(){
    init_list_head(&promise_debug_jobs);
}

void __js_dump_not_resolved_promises(){
    if(list_empty(&promise_debug_jobs)) return;
    printf("Unresolved promises:\n");
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &promise_debug_jobs){
        struct promise* proxy = list_entry(cur, struct promise, link);
        printf("  %p created at %s\n", proxy, proxy -> created);
    }
}

#else

void __js_dump_not_resolved_promises(){}

#endif

/**
 * 创建一个Promise Proxy，方便在C中操作
 * @param ctx 运行时上下文
 */
struct promise* __js_promise(JSContext *ctx, const char* __debug__){
    struct promise* proxy = js_malloc(ctx, sizeof(struct promise));
    assert(ctx != NULL && proxy != NULL);
    JSValue resolving_funcs[2];
    proxy -> ctx = ctx;
    proxy -> promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    proxy -> resolve = resolving_funcs[0];
    proxy -> reject = resolving_funcs[1];

#ifdef LJS_DEBUG
    assert(__debug__!= NULL);
    proxy -> created = __debug__;
    proxy -> resolved = NULL;
    list_add_tail(&proxy -> link, &promise_debug_jobs);
#endif

    return proxy;
}

static inline void free_promise(struct promise* proxy){
    assert(NULL != proxy -> ctx);   // error: already free
    JS_FreeValue(proxy -> ctx, proxy -> resolve);
    JS_FreeValue(proxy -> ctx, proxy -> reject);
    // WARN: 此处应该由用户决策，所有权是否转移到JS层？
    // JS_FreeValue(proxy -> ctx, proxy -> promise);

#ifdef LJS_DEBUG
    list_del(&proxy -> link);
#endif

    JSContext* ctx = proxy -> ctx;
    proxy -> ctx = NULL;
    js_free(ctx, proxy);
}

void __js_resolve(struct promise* proxy, JSValue value, const char* __debug__){
    assert(NULL != proxy -> ctx);   // error: already free
    JSValue args[1] = {value};
    JS_Call(proxy -> ctx, proxy -> resolve, proxy -> promise, 1, args);

#ifdef LJS_DEBUG
    proxy -> resolved = __debug__;
#endif

    free_promise(proxy);
}

void __js_reject(struct promise* proxy, const char* msg, const char* __debug__){
    assert(NULL != proxy -> ctx);   // error: already free
    JSValue error = JS_NewError(proxy -> ctx);
    JS_SetPropertyStr(proxy -> ctx, error, "message", JS_NewString(proxy -> ctx, msg));
    JS_Call(proxy -> ctx, proxy -> reject, proxy -> promise, 1, (JSValueConst[]){error});
    JS_FreeValue(proxy -> ctx, error);

#ifdef LJS_DEBUG
    proxy -> resolved = __debug__;
#endif

    free_promise(proxy);
}

void __js_reject2(struct promise* proxy, JSValue value, const char* __debug__){
    assert(NULL != proxy -> ctx);   // error: already free
    JS_Call(proxy -> ctx, proxy -> reject, proxy -> promise, 1, (JSValueConst[]){value});

#ifdef LJS_DEBUG
    proxy -> resolved = __debug__;
#endif

    free_promise(proxy);
}