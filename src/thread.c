#include "core.h"
#include "../engine/quickjs.h"

#include <pthread.h>
#include <threads.h>
#include <sys/eventfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/epoll.h>

#define BUFFER_SIZE 64 * 1024

static thread_local App* self_app;
static thread_local int worker_id;
static thread_local JSValue msg_callback;

// module

static inline void clear_if_not_equal(char** a, char** b){
    if(*a != *b){
        free(*a);
        *a = *b;
    }
}

uint8_t *LJS_tryGetJSFile(uint32_t *pbuf_len, char **_filename){
    FILE *f;
    uint8_t *buf;
    long lret;
    char* filename = *_filename;

main:
    f = fopen(filename, "rb");
    if (!f){
        // 尝试添加后缀
        char* str_addjs = malloc(strlen(filename) + 4);
        if (!str_addjs) {
            return NULL;
        }
        strcpy(str_addjs, filename);
        strcat(str_addjs, ".js");
        f = fopen(str_addjs, "rb");
        if (!f){
            free(str_addjs);
            return NULL;
        }
        filename = str_addjs;
    }
    if (fseek(f, 0, SEEK_END) < 0)  // 不是寻常文件
        goto fail;
    lret = ftell(f);
    if (lret < 0)
        goto fail;

    // 这是一个目录
    if (lret == LONG_MAX) {
        char* index_fname = malloc(strlen(filename) + 10);
        if (!index_fname) {
            goto fail;
        }
        strcpy(index_fname, filename);
        strcat(index_fname, "/index.js");
        // 尝试找到index.js
        clear_if_not_equal(&filename, _filename);
        filename = index_fname;
        goto main;
    }else if(lret > UINT32_MAX){
        goto fail;
    }
    *pbuf_len = lret;
    if (fseek(f, 0, SEEK_SET) < 0)
        goto fail;
    buf = malloc(*pbuf_len + 1);
    if (!buf)
        goto fail;
    if (fread(buf, 1, *pbuf_len, f) != *pbuf_len) {
        free(buf);
fail:
        fclose(f);
        clear_if_not_equal(&filename, _filename);
        return NULL;
    }
    buf[*pbuf_len] = '\0';
    fclose(f);
    clear_if_not_equal(_filename, &filename);
    return buf;
}

// static char* js_module_format(JSContext *ctx,
//     const char *module_base_name, const char *module_name, void *opaque)
// {
//     App* app = JS_GetContextOpaque(ctx);
//     if(JS_IsFunction(ctx, app -> module_format)){
//         JSValue argv[2] = {
//             JS_NewString(ctx, module_base_name),
//             JS_NewString(ctx, module_name),
//         };
//         JSValue ret = JS_Call(ctx, app -> module_format, JS_UNDEFINED, 2, argv);
//         if(JS_IsException(ret)){
//             LJS_ThrowWithError(ctx, "failed to resolve module format", NULL);
//             return NULL;
//         }
//         if(JS_IsString(ret)){
//             return (char*)JS_ToCString(ctx, ret);
//         }else{
//             LJS_Throw(ctx, "invaild return value of custom module format",
//                 "return value must be a string(module name or path) contains module format.");
//             return NULL;
//         }
//     }else{
//         if(JS_IsRegisteredClass())
//     }
// }

static JSModuleDef *js_module_loader(JSContext *_ctx,
                              const char *module_name, void *opaque)
{
    JSModuleDef *m;
    char* buf;
    uint32_t buf_len;
    App* app = JS_GetContextOpaque(_ctx);
    JSContext *ctx = app -> module_ctx ? app -> module_ctx : _ctx;
    bool use_loader = JS_IsFunction(ctx, app -> module_loader);

    if(use_loader){
        JSValue argv[1] = { JS_NewString(ctx, module_name) };
        JSValue ret = JS_Call(ctx, app -> module_loader, JS_UNDEFINED, 1, argv);
        if(JS_IsException(ret)){
            LJS_ThrowWithError(_ctx, "failed to load module", NULL);
            return NULL;
        }
        if(JS_IsString(ret)){
            size_t __len;
            buf = (char*)JS_ToCStringLen(ctx, &__len, ret);
            buf_len = __len;
            goto compile;
        }else{
            LJS_Throw(_ctx, "invaild return value of custom module loader",
                "return value must be a string contains module contents. Sync io is required.");
        }
    }

    // 默认加载器
    JSValue func_val;

    char* module_name_copied = strdup(module_name);
    buf = (char*)LJS_tryGetJSFile(&buf_len, &module_name_copied);
    if (!buf){
        JS_ThrowReferenceError(_ctx, "could not load module by name: %s",
                                   module_name);
        return NULL;
    }

    compile: {
        /* compile the module */
        func_val = JS_Eval(_ctx, buf, buf_len, module_name_copied,
                           JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        js_free(_ctx, buf);
        if (JS_IsException(func_val))
            return NULL;
            
        // import meta
        m = JS_VALUE_GET_PTR(func_val);
        JSValue meta_obj = JS_GetImportMeta(_ctx, m);
        JS_DefinePropertyValueStr(_ctx, meta_obj, "name",
            JS_NewString(_ctx, module_name_copied),
            JS_PROP_C_W_E);
        if(!use_loader){
            char* real_path = realpath(module_name_copied, NULL);
            JS_DefinePropertyValueStr(_ctx, meta_obj, "path",
                JS_NewString(_ctx, real_path),
                JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(_ctx, meta_obj, "filename",
                JS_NewString(_ctx, basename(real_path)),
                JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(_ctx, meta_obj, "dirname",
                JS_NewString(_ctx, dirname(real_path)),
                JS_PROP_C_W_E);
            free(real_path);
        }

        JS_FreeValue(_ctx, func_val);
    }

    return m;
}

static JSValue js_module_set_handler(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 1 || !JS_IsFunction(ctx, argv[0]))
        return LJS_Throw(ctx, "invalid arguments", "module.setHandler(handler: function): void");

    App* app = JS_GetContextOpaque(ctx);

    app -> module_loader = JS_DupValue(ctx, argv[0]);
    return JS_UNDEFINED;
}

// static inline char* resolve_module(JSContext *ctx, const char *module_name, const char *base_dir) {
//     if (module_name[0] == '/' || module_name[0] == '.') {
//         return LJS_resolve_path(module_name, base_dir);
//     } else {
//         return strdup(module_name);
//     }
// }

// require(sync dynamic import)
static JSValue js_require(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    // if(argc != 1 || !JS_IsString(argv[0])){
    //     return LJS_Throw(ctx, "require() requires a string argument",
    //         "require(path:string):any"
    //     );
    // }

    // const char *path = JS_ToCString(ctx, argv[0]);
    // const char *base = JS_AtomToCString(ctx, JS_GetScriptOrModuleName(ctx, 1));
    // char *resolved_path = resolve_module(ctx, path, NULL);
    // if(*base == '\0') base = NULL;
    
    // JSModuleDef *m = js_module_loader(ctx, resolved_path, NULL);
    // JSValue module = JS_DupValue(ctx, JS_MKPTR(JS_TAG_MODULE, m));  // EvalFunction will free it
    // JS_UpdateStackTop(JS_GetRuntime(ctx));
    // JSValue ret = JS_EvalFunction(ctx, module);

    // JS_FreeCString(ctx, path);
    // free(resolved_path);
    // if(base) JS_FreeCString(ctx, base);
    // return ret;
    return JS_EXCEPTION;
}

bool LJS_init_module(JSContext *ctx){
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JSValue proto_sethandler = JS_NewCFunction(ctx, js_module_set_handler, "setModuleResolver", 1);
    JSValue func_require = JS_NewCFunction(ctx, js_require, "require", 1);
    // require.prototype.setHandler = setModuleResolver;
    JSValue func_proto = JS_NewObjectProto(ctx, JS_GetPrototype(ctx, func_require));
    JS_DefinePropertyValueStr(ctx, func_proto, "setHandler", proto_sethandler, JS_PROP_C_W_E);
    JS_SetPrototype(ctx, func_require, func_proto);
    // globalThis.require = require;
    JS_SetPropertyStr(ctx, global_obj, "require", func_require);

    return true;
}

// predef
static void LJS_init_timer(JSContext* ctx);
static JSValue worker_close(JSContext* ctx, void* ptr, JSValue val);

static inline void worker_exit(int code, const char* message){
    Worker_Error* error = (Worker_Error*)malloc(sizeof(Worker_Error));
    error -> message = (char*)message;
    error -> code = code;
    pthread_exit((void*)error);
}

// queue
static inline void msgqueue_push(Worker_Message_Queue* queue, JSValue* arg, struct LJS_Promise_Proxy* promise){
    // leak memory
    JSValue* message = (JSValue*)malloc(sizeof(JSValue));
    *message = *arg;    // copy
    queue -> message[queue -> end] = message;  // 入队
    queue -> promise[queue -> end] = promise;
    if(queue -> end == MAX_MESSAGE_COUNT - 1) queue -> end = 0;
    else queue -> end++;
}

static inline uint64_t msgqueue_pop(Worker_Message_Queue* queue, struct LJS_Promise_Proxy** promise){
    if(queue -> start == queue -> end) return 0;  // 队列为空
    uint64_t value = (uint64_t)queue -> message[queue -> start];  // 出队
    *promise = queue -> promise[queue -> start];
    if(queue -> start == MAX_MESSAGE_COUNT - 1) queue -> start = 0;
    else queue -> start++;
    return value;
}

static inline void msgqueue_init(Worker_Message_Queue* queue){
    queue -> start = 0;
    queue -> end = 0;
}

static inline void msgqueue_destroy(Worker_Message_Queue* queue){
    uint8_t que_end = (queue -> start > queue -> end)? queue -> start : queue -> start + MAX_MESSAGE_COUNT;
    for(uint8_t i = queue -> start; i < que_end; i++){
        uint8_t j = (i + 1) % MAX_MESSAGE_COUNT;
        free(queue -> message[j]);
        LJS_FreePromise(queue -> promise[j]);
    }
}

App* LJS_create_app(
    JSRuntime* rt,
    uint32_t argc, char** argv,
    bool worker, bool module, char* script_path,
    App* parent
){
    JSContext* ctx = JS_NewContextRaw(rt);
    if(!ctx){
        return NULL;
    }
    App* app = (App*)malloc(sizeof(App));
    app->ctx = ctx;
    app->module = module;
    app->script_path = script_path;
    app->argv = argv;
    app->argc = argc;
    app->module_loader = JS_UNDEFINED;
    app->module_format = JS_UNDEFINED;

    if(parent && worker){
        // 分配worker专用资源
        app -> worker = malloc(sizeof(struct Worker_Props));
        app -> worker -> parent_ctx = parent -> ctx;
        app -> worker -> worker_id = worker_id;
        app -> worker -> message_callback = JS_UNDEFINED;
        app -> worker -> error = NULL;

        msgqueue_init(&app->worker->main_q);
        msgqueue_init(&app->worker->worker_q);

        worker_id = parent -> worker_count++;

        // 添加到父进程的worker数组中
        parent -> workers = (JSContext**)realloc(parent -> workers, sizeof(JSContext*) * parent -> worker_count);
        parent -> workers[worker_id] = ctx;

        // 添加.parent
        JSValue global_obj = JS_GetGlobalObject(ctx);
        JSValue parent_obj = JS_GetGlobalObject(parent -> ctx);
        JS_SetPropertyStr(ctx, global_obj, "parent", JS_DupValue(ctx, parent_obj));
        JS_FreeValue(ctx, parent_obj);
        JS_FreeValue(ctx, global_obj);

        // 在worker线程
        int fd1 = eventfd(0, EFD_NONBLOCK),
            fd2 = eventfd(0, EFD_NONBLOCK);
        if(fd1 < 0 || fd2 < 0){
            perror("eventfd");
            worker_exit(1, "eventfd failed");
        }

        app -> worker -> efd_worker2main = fd1;
        app -> worker -> efd_main2worker = fd2;
    }

    JS_SetContextOpaque(ctx, app);
    self_app = app;
    return app;
}

// for worker thread
static void worker_message_callback(EvFD* __, uint8_t* buffer, uint32_t read_size, void* user_data){
    App* app = (App*)user_data;
    uint64_t value;
    if(read(app -> worker -> efd_main2worker, &value, sizeof(uint64_t)) != sizeof(uint64_t)){
        worker_exit(1, "read from pipe failed");
    }
        
    // 转换数据指针
    JSValue* arg = (JSValue*)value;
    JS_Call(app -> ctx, msg_callback, JS_UNDEFINED, 1, arg);
    JS_FreeValue(app -> ctx, *arg);
    free(arg);
}

// for worker thread
static void worker_close_callback(int fd, void* user_data){
    close(((App*)user_data) -> worker -> efd_worker2main);
    worker_exit(0, "worker closed");
}

// for worker thread
static void worker_writeable_callback(EvFD* __, void* opaque){
    App* data = opaque;
    struct LJS_Promise_Proxy* promise = NULL;
    uint64_t value = msgqueue_pop(&data -> worker -> worker_q, &promise);

    if(value == 0 || promise == NULL) return;  // 队列为空

    // write to pipe
    if(write(data -> worker -> efd_worker2main, &value, sizeof(uint64_t)) == sizeof(uint64_t)){
        LJS_Promise_Resolve(promise, JS_UNDEFINED);
    }else{
        JS_Call(promise -> ctx, promise -> reject, JS_UNDEFINED, 0, NULL);
    }

    LJS_FreePromise(promise);
}

// for main thread
static void main_message_callback(EvFD* __, uint8_t* buffer, uint32_t read_size, void* opaque){
    App* app = (App*)opaque;
    uint64_t value;
    if(read(app -> worker -> efd_worker2main, &value, sizeof(uint64_t)) != sizeof(uint64_t)){
        worker_exit(1, "read from pipe failed");
    }
        
    // 转换数据指针
    JSValue* arg = (JSValue*)value;
    JS_Call(app -> ctx, app -> worker -> message_callback, JS_UNDEFINED, 1, arg);
    JS_FreeValue(app -> ctx, *arg);
    free(arg);
}

// for main thread
static void main_writeable_callback(EvFD* __, void* opaque){
    App* data = opaque;
    struct LJS_Promise_Proxy* promise = NULL;
    uint64_t value = msgqueue_pop(&data -> worker -> worker_q, &promise);
    if(value == 0 || promise == NULL) return;  // 队列为空
    if(write(data -> worker -> efd_main2worker, &value, sizeof(uint64_t)) == sizeof(uint64_t)){
        LJS_Promise_Resolve(promise, JS_UNDEFINED);
    }else{
        JSValue err = JS_NewError(self_app -> ctx);
        JS_DefinePropertyValueStr(self_app -> ctx, err, "message", JS_NewString(self_app -> ctx, "write to pipe failed"), JS_PROP_C_W_E);
        JSValue arr[] = { err };
        JS_Call(self_app -> ctx, promise -> reject, JS_UNDEFINED, 1, arr);
    }

    LJS_FreePromise(promise);
}

// for main thread
static void main_close_callback(int fd, void* user_data){
    App* app = (App*)user_data;

    // close
    worker_close(app -> ctx, app, JS_UNDEFINED);
}

static void LJS_worker_loop(App* app, JSValue func){
    JSContext* ctx = app -> ctx;

    // 初始化epoll
    LJS_evcore_init();

    // 调用
    JSValue ret = JS_Call(ctx, func, JS_UNDEFINED, 0, NULL);
    if(JS_IsException(ret)){
        JSValue error = JS_GetException(ctx);
        LJS_dump_error(ctx, error);
        worker_exit(1, "worker thread exception");
    }

    // 监听pipe
    LJS_evcore_attach(app -> worker -> efd_main2worker, false, worker_message_callback, NULL, worker_close_callback, app);
    LJS_evcore_attach(app -> worker -> efd_worker2main, false, NULL, worker_writeable_callback, NULL, app);

    // 启动事件循环
    LJS_evcore_run(NULL, NULL);
}

void LJS_init_runtime(JSRuntime* rt){
    // Promise追踪
    JS_SetHostPromiseRejectionTracker(rt, LJS_handle_promise_reject, NULL);

    // 初始化ES6模块
    JS_SetModuleLoaderFunc(rt, /* js_module_format */ NULL, js_module_loader, NULL);

    // atomic
    JS_SetCanBlock(rt, true);
}

static bool in(char** arr, const char* str){
    for(int i = 0; arr[i]; i++){
        if(strcmp(arr[i], str) == 0) return true;
    }
    return false;
}

void LJS_init_context(App* app, char** init_list){
    JSContext* ctx = app -> ctx;

    // 基础JS语法
    if(!init_list || in(init_list, "base")) JS_AddIntrinsicBaseObjects(ctx);
    if(!init_list || in(init_list, "date")) JS_AddIntrinsicDate(ctx);
    if(!init_list || in(init_list, "eval")) JS_AddIntrinsicEval(ctx);
    if(!init_list || in(init_list, "regexp")) JS_AddIntrinsicRegExp(ctx);
    if(!init_list || in(init_list, "json")) JS_AddIntrinsicJSON(ctx);
    if(!init_list || in(init_list, "proxy")) JS_AddIntrinsicProxy(ctx);
    if(!init_list || in(init_list, "mapset")) JS_AddIntrinsicMapSet(ctx);
    if(!init_list || in(init_list, "typedarray")) JS_AddIntrinsicTypedArrays(ctx);
    if(!init_list || in(init_list, "promise")) JS_AddIntrinsicPromise(ctx);
    if(!init_list || in(init_list, "bigint")) JS_AddIntrinsicBigInt(ctx);
    if(!init_list || in(init_list, "weakref")) JS_AddIntrinsicWeakRef(ctx);
    if(!init_list || in(init_list, "performance")) JS_AddPerformance(ctx);

    // 初始化所有模块
    if(!init_list || in(init_list, "pipe")){
        LJS_init_pipe(ctx);

        // 依赖项
        if(!init_list || in(init_list, "socket")){
            // socket: todo
            LJS_init_HTTP(ctx);
        }
        if(!init_list || in(init_list, "process")){
            LJS_init_process(ctx, app -> script_path, app -> argc, app -> argv);
            LJS_init_thread(ctx);
        }
        if(!init_list || in(init_list, "stdio"))
            LJS_init_stdio(ctx);
    }
    if(!init_list || in(init_list, "console")) LJS_init_console(ctx);
    if(!init_list || in(init_list, "event")) LJS_init_global_helper(ctx);
    if(!init_list || in(init_list, "module")) LJS_init_module(ctx);
    if(!init_list || in(init_list, "url")) LJS_init_global_url(ctx);
    if(!init_list || in(init_list, "timer")) LJS_init_timer(ctx);    // delay
}

static void* pthread_main(void* arg){
    App* app = (App*)arg;
    self_app = app;

    // 加载入口
    uint32_t buf_len;
    uint8_t* buf = LJS_tryGetJSFile(&buf_len, &app -> script_path);
    if(!buf){
        worker_exit(1, "load script failed");
    }
    uint8_t flag = JS_EVAL_FLAG_COMPILE_ONLY;
    if(app -> module) flag |= JS_EVAL_TYPE_MODULE;
    JS_UpdateStackTop(JS_GetRuntime(app -> ctx));
    JSValue func = JS_Eval(app -> ctx, (char*)buf, buf_len, app -> script_path, flag);

    LJS_worker_loop(self_app, func);

    return NULL;
}

/**
 * 在主线程中创建一个Worker线程
 * @param parent 父进程的App
 */
App* LJS_NewWorker(App* parent){
    pthread_t thread;

    App* app = LJS_create_app(
        JS_GetRuntime(parent -> ctx), 
        parent -> argc, (char**)parent -> argv, 
        false, false, NULL, parent
    );
    LJS_init_context(app, NULL);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if(0 != pthread_create(&thread, &attr, pthread_main, app)){
        return NULL;
    }

    return app;
}

static JSValue worker_poll(JSContext* ctx, void* ptr, JSValue __){
    App* app = (App*)ptr;
    struct LJS_Promise_Proxy* promise = LJS_NewPromise(app -> ctx);
    if(JS_IsFunction(app -> ctx, app -> worker -> message_callback)) 
        JS_FreeValue(app -> ctx, app -> worker -> message_callback);
    app -> worker -> message_callback = JS_DupValue(app -> ctx, promise -> resolve);
    return promise -> promise;
}

static JSValue worker_write(JSContext* ctx, void* ptr, JSValue data){
    App* app = (App*)ptr;

    struct LJS_Promise_Proxy* tmpdata = LJS_NewPromise(app -> ctx);
    msgqueue_push(&app -> worker -> main_q, &data, tmpdata);

    return tmpdata -> promise;
}

static JSValue worker_close(JSContext* ctx, void* ptr, JSValue val){
    App* app = (App*)ptr;

    if(app -> worker -> error){
        char* space = malloc(1024);
        snprintf(space, 1024, "Worker thread exited with code %d: %s\n", app -> worker -> error -> code, app -> worker -> error -> message);
        free(app -> worker -> error -> message);
        free(app -> worker -> error);
        LJS_Throw(app -> ctx, space, NULL);
        free(space);
    }

    LJS_evcore_detach(app -> worker -> efd_worker2main, EV_REMOVE_ALL);
    LJS_evcore_detach(app -> worker -> efd_main2worker, EV_REMOVE_ALL);
    close(app -> worker -> efd_worker2main);
    close(app -> worker -> efd_main2worker);
    msgqueue_destroy(&app -> worker -> main_q);
    msgqueue_destroy(&app -> worker -> worker_q);
    JS_FreeContext(app -> ctx);
    if(app -> worker -> error) {
        free(app -> worker -> error -> message);
        free(app -> worker -> error);
    }
    free(app -> worker);
    free(app);

    return JS_UNDEFINED;
}

static JSValue js_create_worker(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    char* script_path;
    bool module = false;
    
    if(argc == 1){
        script_path = (char*)JS_ToCString(ctx, argv[0]);
    }else if(argc == 2){
        script_path = (char*)JS_ToCString(ctx, argv[0]);
        module = JS_ToBool(ctx, argv[1]);
    }else{
        return LJS_Throw(ctx, "Worker constructor takes 1 or 2 arguments",
            "Worker(script_path: string, module: boolean = false)"
        );
    }

    App* app = LJS_NewWorker(self_app);

    // evloop
    LJS_evcore_attach(app -> worker -> efd_worker2main, false, main_message_callback, NULL, main_close_callback, app);
    LJS_evcore_attach(app -> worker -> efd_main2worker, false, NULL, main_writeable_callback, NULL, app);

    // Pipe
    return LJS_NewU8Pipe(app -> ctx, PIPE_READ | PIPE_WRITE, BUFFER_SIZE,
        worker_poll, worker_write, worker_close, app
    );
}


// class Sandbox
// 使用线程内JSContext隔离执行JS代码
static JSClassID js_sandbox_class_id;

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

static JSValue js_sandbox_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    JSValue proto = JS_GetPropertyStr(ctx, new_target, "prototype");
    JSValue obj = JS_NewObjectProtoClass(ctx, proto, js_sandbox_class_id);
    JS_FreeValue(ctx, proto);
    if(JS_IsException(obj)){
        return JS_NULL;
    }

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
            app -> module_loader = loader;
            app -> module_ctx = ctx;
        }
    }
    
    LJS_init_context(app, init_apps_len == 0 ? NULL : init_apps);
    JS_SetOpaque(obj, app);
    return obj;
}

static JSCFunctionListEntry js_sandbox_funcs[] = {
    JS_CFUNC_DEF("eval", 1, js_sandbox_eval),
    JS_CGETSET_DEF("context", js_sandbox_get_context, NULL)
};

bool LJS_init_thread(JSContext* ctx){
    JSValue global_obj = JS_GetGlobalObject(ctx);

    // worker
    JSValue worker_func = JS_NewCFunction(ctx, js_create_worker, "Worker", 1);
    JS_SetPropertyStr(ctx, global_obj, "Worker", worker_func);
    JS_FreeValue(ctx, worker_func);

    // sandbox
    JS_NewClassID(JS_GetRuntime(ctx), &js_sandbox_class_id);
    JSValue sandbox_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, sandbox_proto, js_sandbox_funcs, countof(js_sandbox_funcs));
    JS_SetPropertyStr(ctx, global_obj, "Sandbox", JS_NewCFunction2(ctx, js_sandbox_constructor, "Sandbox", 1, JS_CFUNC_constructor, 0));
    JS_FreeValue(ctx, sandbox_proto);
    return true;
}

// -- timer --
struct Timer_T {
    JSContext* ctx;
    JSValue resolve;
    bool once;
};

static void timer_callback(uint64_t count, void* ptr){
    struct Timer_T* timer = (struct Timer_T*)ptr;
    JS_Call(timer -> ctx, timer -> resolve, JS_UNDEFINED, 1, (JSValue[1]){ JS_NewInt64(timer -> ctx, count) });

    if(timer -> once){
        free(timer);
    }
}

static JSValue js_timer_delay(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 1 || !JS_IsNumber(argv[0])){
        return LJS_Throw(ctx, "Timer.delay takes 1 argument: delay_time", "Timer.delay(delay_time: number): Promise<void>");
    }

    struct LJS_Promise_Proxy* promise = LJS_NewPromise(ctx);
    struct Timer_T* timer = (struct Timer_T*)malloc(sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = JS_DupValue(ctx, promise -> resolve);
    timer -> once = true;

    uint32_t delay_time;
    if(delay_time == 0 || 0 != JS_ToUint32(ctx, &delay_time, argv[0])){
        return LJS_Throw(ctx, "Timer.delay takes a non-zero delay_time", NULL);
    }

    LJS_evcore_setTimeout(delay_time / 1000, timer_callback, timer);

    return promise -> promise;
}

static JSValue js_timer_set_timeout(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 2 || !JS_IsNumber(argv[1]) || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, "Timer.setTimeout takes 2 argument", "Timer.setTimeout(callback: () => void, delay_time: number): number");
    }

    JSValue callback = JS_DupValue(ctx, argv[0]);
    uint32_t delay_time;
    if(delay_time == 0 || !JS_ToUint32(ctx, &delay_time, argv[1])){
        return LJS_Throw(ctx, "Timer.setTimeout takes a non-zero delay_time", NULL);
    }

    struct Timer_T* timer = (struct Timer_T*)malloc(sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = callback;
    timer -> once = true;

    EvFD* fd = LJS_evcore_setTimeout(delay_time / 1000, timer_callback, timer);

    return JS_NewUint32(ctx, LJS_evfd_getfd(fd, NULL));
}

static JSValue js_timer_interval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 2 || !JS_IsNumber(argv[1]) || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, "Timer.interval takes 2 argument", "Timer.interval(callback: () => void, interval_time: number): number");
    }

    JSValue callback = JS_DupValue(ctx, argv[0]);
    uint32_t interval_time;
    if(interval_time == 0 || !JS_ToUint32(ctx, &interval_time, argv[1])){
        return LJS_Throw(ctx, "Timer.interval takes a non-zero interval_time", NULL);
    }

    struct Timer_T* timer = (struct Timer_T*)malloc(sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = callback;
    timer -> once = false;

    EvFD* fd = LJS_evcore_interval(interval_time / 1000, timer_callback, timer);

    return JS_NewUint32(ctx, LJS_evfd_getfd(fd, NULL));
}

static JSValue js_timer_clear(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 1 || !JS_IsNumber(argv[0])){
        return LJS_Throw(ctx, "Timer.clear takes 1 argument: timer", "Timer.clear(timer: number): boolean");
    }
    
    int id;
    JS_ToInt32(ctx, &id, argv[0]);
    return JS_NewBool(ctx, LJS_evcore_clearTimer(id));
}

static void LJS_init_timer(JSContext* ctx){
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global_obj, "setTimeout", 
        JS_NewCFunction(ctx, js_timer_set_timeout, "setTimeout", 2)
    );
    JS_SetPropertyStr(ctx, global_obj, "setInterval", 
        JS_NewCFunction(ctx, js_timer_interval, "setInterval", 2)
    );
    JS_SetPropertyStr(ctx, global_obj, "clearTimer", 
        JS_NewCFunction(ctx, js_timer_clear, "clearTimer", 1)
    );
    JS_SetPropertyStr(ctx, global_obj, "delay", 
        JS_NewCFunction(ctx, js_timer_delay, "delay", 1)
    );
    JS_FreeValue(ctx, global_obj);
}