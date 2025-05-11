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

static char* js_module_format(JSContext *ctx,
    const char *module_base_name, const char *module_name, void *opaque)
{
    App* app = JS_GetContextOpaque(ctx);
    if(JS_IsFunction(ctx, app -> module_format)){
        JSValue argv[2] = {
            JS_NewString(ctx, module_base_name),
            JS_NewString(ctx, module_name),
        };
        JSValue ret = JS_Call(ctx, app -> module_format, JS_UNDEFINED, 2, argv);
        if(JS_IsException(ret)){
            LJS_ThrowWithError(ctx, "failed to resolve module format", NULL);
            return NULL;
        }
        if(JS_IsString(ret)){
            const char* modpath = JS_ToCString(ctx, ret);
            char* modpath_dup = js_strdup(ctx, modpath);
            JS_FreeCString(ctx, modpath);
            return modpath_dup;
        }else{
            LJS_Throw(ctx, "invaild return value of custom module format",
                "return value must be a string(module name or path) contains module format.");
            return NULL;
        }
    }else if(module_name[0] == '.'){
        char* module_name_path = LJS_resolve_path(module_name, module_base_name);
        char* module_path = js_strdup(ctx, module_name_path);
        free(module_name_path);
        return module_path;
    }else{
        return js_strdup(ctx, module_name);
    }
}

static JSModuleDef *js_module_loader(JSContext *ctx,
                              const char *_modname, void *opaque)
{
    JSModuleDef *m;
    char* buf;
    uint32_t buf_len;
    App* app = JS_GetContextOpaque(ctx);
    bool use_loader = JS_IsFunction(ctx, app -> module_loader);

    char* module_name = strdup(_modname);  // avoid const cast error

    if(use_loader){
        JSValue argv[1] = { JS_NewString(ctx, module_name) };
        JSValue ret = JS_Call(ctx, app -> module_loader, JS_UNDEFINED, 1, argv);
        if(JS_IsException(ret)){
            LJS_ThrowWithError(ctx, "failed to load module", NULL);
            return NULL;
        }
        if(JS_IsString(ret)){
            size_t __len;
            buf = (char*)JS_ToCStringLen(ctx, &__len, ret);
            buf_len = __len;
            goto compile;
        }else{
            LJS_Throw(ctx, "invaild return value of custom module loader",
                "return value must be a string contains module contents. Sync io is required.");
        }
    }

    // 默认加载器
    JSValue func_val;

    buf = (char*)LJS_tryGetJSFile(&buf_len, (char**)&module_name);
    if (!buf){
        JS_ThrowReferenceError(ctx, "could not load module by name: %s",
                                   module_name);
        return NULL;
    }

    compile: {
        /* compile the module */
        func_val = JS_Eval(ctx, buf, buf_len, module_name,
                           JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        free(buf);
        if (JS_IsException(func_val))
            return NULL;
            
        // import meta
        m = JS_VALUE_GET_PTR(func_val);
        JSValue meta_obj = JS_GetImportMeta(ctx, m);
        JS_DefinePropertyValueStr(ctx, meta_obj, "name",
            JS_NewString(ctx, module_name),
            JS_PROP_C_W_E);
        if(!use_loader){
            char* real_path = realpath(module_name, NULL);
            JS_DefinePropertyValueStr(ctx, meta_obj, "path",
                JS_NewString(ctx, real_path),
                JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, meta_obj, "filename",
                JS_NewString(ctx, basename(real_path)),
                JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, meta_obj, "dirname",
                JS_NewString(ctx, dirname(real_path)),
                JS_PROP_C_W_E);
            free(real_path);
        }
    }

    free(module_name);
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
    JSValue func_proto = JS_GetPrototype(ctx, func_require);
    JS_DefinePropertyValueStr(ctx, func_proto, "setHandler", proto_sethandler, JS_PROP_C_W_E);
    // globalThis.require = require;
    JS_SetPropertyStr(ctx, global_obj, "require", func_require);

    return true;
}

// predef
static void LJS_init_timer(JSContext* ctx);

struct WorkerMessage {
    struct list_head list;
    JSValue arg;
};

typedef void (*WorkerCallback)(App* app, JSValueConst data);
struct Worker_Props{
    int efd_worker2main;
    int efd_main2worker;

    JSValue worker_msgcb;// for worker thread
    JSValue main_msgcb;  // for main thread
    JSValue destroy_cb;  // for main thread
    Worker_Error* error; // for main thread

    // write queue, in worker for main thread and worker thread
    struct list_head main_msg;
    struct list_head worker_msg;
    uint64_t msg_id;    // for eventfd
    pthread_mutex_t lock;

    App* parent;
};

static inline void worker_exit(int code, const char* message){
    Worker_Error* error = (Worker_Error*)malloc(sizeof(Worker_Error));
    error -> message = (char*)message;
    error -> code = code;
    pthread_exit((void*)error);
}

static inline void push_message(App* from, App* to, struct list_head* list, JSValue arg){
    // clone arg
    size_t size;
    void* data = JS_WriteObject(from -> ctx, &size, arg, 
        // all available options
        JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_REFERENCE | JS_WRITE_OBJ_SAB
    );

    // write to target App
    JSValue cloned_arg = JS_ReadObject(to -> ctx, data, size, 
        JS_READ_OBJ_BYTECODE | JS_READ_OBJ_REFERENCE | JS_READ_OBJ_SAB
    );

    // push to msgqueue
    pthread_mutex_lock(&to -> worker -> lock);
    struct WorkerMessage* msg = malloc(sizeof(struct WorkerMessage));
    msg -> arg = cloned_arg;
    list_add_tail(list, &msg -> list);
    pthread_mutex_unlock(&to -> worker -> lock);
} 

App* LJS_create_app(
    JSRuntime* rt,
    uint32_t argc, char** argv,
    bool worker, bool module, char* script_path,
    App* parent
){
    JSContext* ctx = JS_NewContextRaw(rt);
    if(!ctx) return NULL;
    App* app = (App*)malloc(sizeof(App));
    app -> ctx = ctx;
    app -> module = module;
    app -> script_path = script_path;
    app -> argv = argv;
    app -> argc = argc;
    app -> module_loader = JS_UNDEFINED;
    app -> module_format = JS_UNDEFINED;
    app -> worker = NULL;

    init_list_head(&app -> workers);

    if(parent && worker){
        // 分配worker专用资源
        struct Worker_Props* wel = app -> worker = malloc(sizeof(struct Worker_Props));
        wel -> worker_msgcb = JS_UNDEFINED;
        wel -> error = NULL;

        init_list_head(&wel -> main_msg);
        init_list_head(&wel -> worker_msg);
        pthread_mutex_init(&wel -> lock, NULL);

        // 添加到父进程的worker数组中
        list_add_tail(&parent -> workers, &app -> link);

        // TODO: 添加parent
        // JSValue global_obj = JS_GetGlobalObject(ctx);
        // JSValue parent_obj = JS_GetGlobalObject(parent -> ctx);
        // JS_SetPropertyStr(ctx, global_obj, "parent", JS_DupValue(ctx, parent_obj));
        // JS_FreeValue(ctx, parent_obj);
        // JS_FreeValue(ctx, global_obj);

        // 在worker线程
        int fd1 = eventfd(0, EFD_NONBLOCK),
            fd2 = eventfd(0, EFD_NONBLOCK);
        if(fd1 < 0 || fd2 < 0){
            perror("eventfd");
            worker_exit(1, "eventfd failed");
        }

        app -> worker -> efd_worker2main = fd1;
        app -> worker -> efd_main2worker = fd2;
        app -> worker -> parent = parent;
    }

    JS_SetContextOpaque(ctx, app);
    if(!parent) JS_SetRuntimeOpaque(rt, app);
    return app;
}

static inline void msglist_clear(JSContext* ctx, struct list_head* list){
    struct list_head* pos, *tmp;
    list_for_each_safe(pos, tmp, list){
        struct WorkerMessage* msg = list_entry(pos, struct WorkerMessage, list);
        JS_FreeValue(ctx, msg -> arg);
    }
}

void LJS_destroy_app(App* app) {
    if (!app) return;

    if (app -> worker) {
        // 关闭eventfd文件描述符
        if (app -> worker -> efd_worker2main >= 0) {
            close(app -> worker -> efd_worker2main);
        }
        if (app -> worker -> efd_main2worker >= 0) {
            close(app -> worker -> efd_main2worker);
        }
        
        // remove lock
        pthread_mutex_destroy(&app -> worker -> lock);

        // free msgcallback
        if(!JS_IsUndefined(app -> worker-> worker_msgcb))
            JS_FreeValue(app -> ctx, app -> worker-> worker_msgcb);
        if(!JS_IsUndefined(app -> worker -> main_msgcb))
            JS_FreeValue(app -> worker -> parent -> ctx, app -> worker -> main_msgcb);
        if(!JS_IsUndefined(app -> worker -> destroy_cb))
            JS_FreeValue(app -> worker -> parent -> ctx, app -> worker -> destroy_cb);

        // free queue
        msglist_clear(app -> ctx, &app -> worker -> main_msg);
        msglist_clear(app -> ctx, &app -> worker -> worker_msg);

        // free error
        if(app -> worker -> error){
            js_free(app -> ctx, app -> worker -> error -> message);
            js_free(app -> ctx, app -> worker -> error);
        }
        
        // 释放worker结构体
        js_free(app -> ctx, app -> worker);
    }

    // sandbox can be auto destroyed, however workers not.
    if(!list_empty(&app -> workers)){
        struct list_head* pos, *tmp;
        list_for_each_safe(pos, tmp, &app -> workers){
            App* child = list_entry(pos, App, link);
            LJS_destroy_app(child);
        }
    }

    if (!JS_IsUndefined(app -> module_loader)) {
        JS_FreeValue(app -> ctx, app -> module_loader);
    }
    if (!JS_IsUndefined(app -> module_format)) {
        JS_FreeValue(app -> ctx, app -> module_format);
    }
    if (app -> ctx) {
        JS_FreeContext(app -> ctx);
    }

    // free args
    if (app -> script_path) js_free(app -> ctx, app -> script_path);
    if (app -> argv) {
        for (uint32_t i = 0; i < app -> argc; i++) {
            js_free(app -> ctx, app -> argv[i]);
        }
        js_free(app -> ctx, app -> argv);
    }

    js_free(app -> ctx, app);
}


// for worker thread
static int worker_message_callback(EvFD* __, uint8_t* buffer, uint32_t read_size, void* user_data){
    App* app = (App*)user_data;
    uint64_t value;
    if(read(app -> worker -> efd_main2worker, &value, sizeof(uint64_t)) != sizeof(uint64_t)){
        worker_exit(1, "read from pipe failed");
    }
        
    // 读取队列
    if(JS_IsFunction(app -> ctx, app -> worker -> worker_msgcb)){
        pthread_mutex_lock(&app -> worker -> lock);
        // if(list_empty(&app -> worker -> main_msg)) abort();
        struct list_head* pos, *tmp;
        list_for_each_safe(pos, tmp, &app -> worker -> worker_msg){
            struct WorkerMessage* msg = list_entry(pos, struct WorkerMessage, list);
            list_del(&msg -> list);

            // call
            JS_Call(app -> ctx, app -> worker -> worker_msgcb, JS_UNDEFINED, 1, &msg -> arg);
            free(msg);
        }
        pthread_mutex_unlock(&app -> worker -> lock);
    }
    
    return EVCB_RET_DONE;
}

// for worker thread
static void worker_close_callback(EvFD* fd, void* user_data){
    close(((App*)user_data) -> worker -> efd_worker2main);
    worker_exit(0, "worker closed");
}

// for worker thread
static void worker_writeable_callback(EvFD* __, void* opaque){
    App* app = opaque;

    // message
    write(
        app -> worker -> efd_worker2main, 
        (uint8_t*)app -> worker -> msg_id,
        sizeof(uint64_t) 
    );
}

// for main thread
static int main_message_callback(EvFD* __, uint8_t* buffer, uint32_t read_size, void* opaque){
    App* app = (App*)opaque;    // worker APP, not main!
    uint64_t value;
    if(read(app -> worker -> efd_worker2main, &value, sizeof(uint64_t)) != sizeof(uint64_t))
        return EVCB_RET_DONE;
        
    // read queue
    JSContext *ctx = app -> worker -> parent -> ctx;
    if(JS_IsFunction(ctx, app -> worker -> main_msgcb)){
        pthread_mutex_lock(&app -> worker -> lock);
        // if(list_empty(&app -> worker -> main_msg)) abort();
        struct list_head* pos, *tmp;
        list_for_each_safe(pos, tmp, &app -> worker -> main_msg){
            struct WorkerMessage* msg = list_entry(pos, struct WorkerMessage, list);
            list_del(&msg -> list);

            // call
            JS_Call(ctx, app -> worker -> main_msgcb, JS_UNDEFINED, 1, &msg -> arg);
            free(msg);
        }
        pthread_mutex_unlock(&app -> worker -> lock);
    }

    return EVCB_RET_DONE;
}

// for main thread
static void main_writeable_callback(EvFD* __, void* opaque){
    App* data = opaque;
    // message
    write(
        data -> worker -> efd_main2worker, 
        (uint8_t*)data -> worker -> msg_id,
        sizeof(uint64_t) 
    );
}

// for main thread
static void main_close_callback(EvFD* fd, void* user_data){
    App* app = (App*)user_data; // worker APP, not main!
    JSContext* ctx = app -> worker -> parent -> ctx;

    // close
    if(app -> worker -> error){
        char* space = malloc(1024);
#ifdef LJS_DEBUG
        snprintf(space, 1024, "Worker thread exited with code %d: %s\n", app -> worker -> error -> code, app -> worker -> error -> message);
#endif
        if(JS_IsFunction(ctx, app -> worker -> destroy_cb)){
            JSValue obj = JS_NewObject(ctx);
            JS_SetPropertyStr(ctx, obj, "code", JS_NewInt32(ctx, app -> worker -> error -> code));
            JS_SetPropertyStr(ctx, obj, "message", JS_NewString(ctx, app -> worker -> error -> message));
            JS_Call(ctx, app -> worker -> destroy_cb, JS_UNDEFINED, 1, (JSValueConst[]){ obj });
            // obj will be freed by JS_Call
        }

        free(app -> worker -> error -> message);
        free(app -> worker -> error);
        free(space);
    }

    // close fd
    close(app -> worker -> efd_worker2main);
    close(app -> worker -> efd_main2worker);

    // destroy
    LJS_destroy_app(app);
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
    LJS_evcore_attach(app -> worker -> efd_main2worker, false, 
        worker_message_callback, app,
        NULL, NULL,
        worker_close_callback, app
    );
    LJS_evcore_attach(app -> worker -> efd_worker2main, false, 
        NULL, NULL,
        worker_writeable_callback, app,
        NULL, NULL
    );

    // 启动事件循环
    LJS_evcore_run(NULL, NULL);
}

void LJS_init_runtime(JSRuntime* rt){
    // Promise追踪
    JS_SetHostPromiseRejectionTracker(rt, js_handle_promise_reject, NULL);

    // 初始化ES6模块
    JS_SetModuleLoaderFunc(rt, js_module_format, js_module_loader, NULL);

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
    JS_AddIntrinsicBaseObjects(ctx);
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
            LJS_init_socket(ctx);
        }
        if(!init_list || in(init_list, "process")){
            LJS_init_process(ctx, app -> script_path, app -> argc, app -> argv);
            LJS_init_thread(ctx);
        }
        if(!init_list || in(init_list, "fs"))
            LJS_init_stdio(ctx);
        if(!init_list || in(init_list, "http"))
            LJS_init_http(ctx);

        if(!init_list || in(init_list, "compress"))
            LJS_init_compress(ctx);
    }
    if(!init_list || in(init_list, "console")) LJS_init_console(ctx);
    if(!init_list || in(init_list, "global")) LJS_init_global_helper(ctx);
    if(!init_list || in(init_list, "module")) LJS_init_module(ctx);
    if(!init_list || in(init_list, "timer")) LJS_init_timer(ctx);    // delay
    if(!init_list || in(init_list, "ffi")) LJS_init_ffi(ctx);
    if(!init_list || in(init_list, "vm")) LJS_init_vm(ctx);
    if(!init_list || in(init_list, "xml")) LJS_init_xml(ctx);
}

static void* pthread_main(void* arg){
    App* app = (App*)arg;

    // 加载入口
    uint32_t buf_len;
    uint8_t* buf = LJS_tryGetJSFile(&buf_len, &app -> script_path);
    if(!buf){
        worker_exit(1, "load script failed");
    }
    uint8_t flag = JS_EVAL_FLAG_COMPILE_ONLY;
    if(app -> module) flag |= JS_EVAL_TYPE_MODULE;
    JSValue func = JS_Eval(app -> ctx, (char*)buf, buf_len, app -> script_path, flag);

    // import.meta
    if(app -> module){
        JSValue meta = JS_GetImportMeta(app -> ctx, (JSModuleDef*)JS_VALUE_GET_PTR(func));
        JS_SetPropertyStr(app -> ctx, meta, "url", JS_NewString(app -> ctx, app -> script_path));
        JS_SetPropertyStr(app -> ctx, meta, "main", JS_TRUE);
    }

    LJS_worker_loop(app, func);

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

// class Worker
static thread_local JSClassID js_worker_class_id;
#define GET_APP(varname) App* varname = JS_GetOpaque(this_val, js_worker_class_id);\
    if(!varname) return LJS_Throw(ctx, "Worker is destroyed", NULL);

static JSValue js_worker_close(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    App* app = JS_GetOpaque(this_val, js_worker_class_id);  // worker APP, not main!
    if(!app) return JS_UNDEFINED;

    LJS_evcore_detach(app -> worker -> efd_worker2main, EV_REMOVE_ALL);
    LJS_evcore_detach(app -> worker -> efd_main2worker, EV_REMOVE_ALL);
    LJS_destroy_app(app);

    JS_SetOpaque(this_val, NULL);
    return JS_UNDEFINED;
}

static JSValue js_worker_send(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    GET_APP(app);

    if(argc == 0){
        return LJS_Throw(ctx, "postMessage requires at least one argument",
            "Worker.postMessage(message: any): void"
        );
    }

    // add to queue
    push_message((App*)JS_GetContextOpaque(ctx), app, &app -> worker -> worker_msg, argv[0]);
    return JS_UNDEFINED;
}

static JSValue js_worker_set_onmessage(JSContext* ctx, JSValueConst this_val, JSValueConst val){
    GET_APP(app);

    app -> worker -> worker_msgcb = JS_DupValue(ctx, val);
    return JS_UNDEFINED;
}

static JSValue js_worker_get_onmessage(JSContext* ctx, JSValueConst this_val){
    GET_APP(app);

    return JS_DupValue(ctx, app -> worker -> worker_msgcb);
}

static JSValue js_worker_set_ondestroy(JSContext* ctx, JSValueConst this_val, JSValueConst val){
    GET_APP(app);

    app -> worker -> destroy_cb = JS_DupValue(ctx, val);
    return JS_UNDEFINED;
}

static JSValue js_worker_get_ondestroy(JSContext* ctx, JSValueConst this_val){
    GET_APP(app);

    return JS_DupValue(ctx, app -> worker -> destroy_cb);
}


static JSCFunctionListEntry js_worker_props[] = {
    JS_CGETSET_DEF("onmessage", js_worker_get_onmessage, js_worker_set_onmessage),
    JS_CGETSET_DEF("ondestroy", js_worker_get_ondestroy, js_worker_set_ondestroy),
    JS_CFUNC_DEF("terminate", 0, js_worker_close),
    JS_CFUNC_DEF("postMessage", 1, js_worker_send),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Worker", JS_PROP_CONFIGURABLE),
};

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

    App* app = LJS_NewWorker((App*)JS_GetContextOpaque(ctx));

    // evloop
    LJS_evcore_attach(app -> worker -> efd_worker2main, false, 
        main_message_callback, app,
        NULL, NULL,
        main_close_callback, app
    );
    LJS_evcore_attach(app -> worker -> efd_main2worker, false,
        NULL, NULL,
        main_writeable_callback, app,
        NULL, NULL
    );

    // construct class
    JSValue obj = JS_NewObjectClass(ctx, js_worker_class_id);
    JS_SetOpaque(obj, app);
    return obj;
}

static JSClassDef js_worker_def = {
    "Worker",
    .finalizer = NULL,  // worker can run in background
};

bool LJS_init_thread(JSContext* ctx){
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JSRuntime* rt = JS_GetRuntime(ctx);

    // worker
    JS_NewClassID(rt, &js_worker_class_id);
    if(-1 == JS_NewClass(rt, js_worker_class_id, &js_worker_def)) return false;
    JSValue worker_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, worker_proto, js_worker_props, countof(js_worker_props));
    JS_SetClassProto(ctx, js_worker_class_id, worker_proto);

    JSValue worker_ctor = JS_NewCFunction2(ctx, js_create_worker, "Worker", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, worker_ctor, worker_proto);
    JS_SetPropertyStr(ctx, global_obj, "Worker", worker_ctor);
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

    struct promise* promise = LJS_NewPromise(ctx);
    struct Timer_T* timer = (struct Timer_T*)malloc(sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = JS_DupValue(ctx, promise -> resolve);
    timer -> once = true;

    uint32_t delay_time;
    if(-1 == JS_ToUint32(ctx, &delay_time, argv[0]) || delay_time == 0){
        return LJS_Throw(ctx, "Timer.delay takes a non-zero delay_time", NULL);
    }

    LJS_evcore_setTimeout(delay_time, timer_callback, timer);

    return promise -> promise;
}

static JSValue js_timer_set_timeout(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 2 || !JS_IsNumber(argv[1]) || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, "Timer.setTimeout takes 2 argument", "Timer.setTimeout(callback: () => void, delay_time: number): number");
    }

    JSValue callback = JS_DupValue(ctx, argv[0]);
    uint32_t delay_time;
    if(delay_time == 0 || -1 == JS_ToUint32(ctx, &delay_time, argv[1])){
        return LJS_Throw(ctx, "Timer.setTimeout takes a non-zero delay_time", NULL);
    }

    struct Timer_T* timer = (struct Timer_T*)malloc(sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = callback;
    timer -> once = true;

    EvFD* fd = LJS_evcore_setTimeout(delay_time, timer_callback, timer);

    return JS_NewUint32(ctx, LJS_evfd_getfd(fd, NULL));
}

static JSValue js_timer_interval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 2 || !JS_IsNumber(argv[1]) || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, "Timer.interval takes 2 argument", "Timer.interval(callback: () => void, interval_time: number): number");
    }

    JSValue callback = JS_DupValue(ctx, argv[0]);
    uint32_t interval_time;
    if(interval_time == 0 || -1 == JS_ToUint32(ctx, &interval_time, argv[1])){
        return LJS_Throw(ctx, "Timer.interval takes a non-zero interval_time", NULL);
    }

    struct Timer_T* timer = (struct Timer_T*)malloc(sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = callback;
    timer -> once = false;

    EvFD* fd = LJS_evcore_interval(interval_time, timer_callback, timer);

    return JS_NewUint32(ctx, LJS_evfd_getfd(fd, NULL));
}

static JSValue js_timer_clear(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 1 || !JS_IsNumber(argv[0])){
        return LJS_Throw(ctx, "Timer.clear takes 1 argument: timer", "Timer.clear(timer: number): boolean");
    }
    
    int id;
    if(-1 == JS_ToInt32(ctx, &id, argv[0])) return JS_EXCEPTION;
    return JS_NewBool(ctx, LJS_evcore_clearTimer(id));
}

const JSCFunctionListEntry js_timer_funcs[] = {
    JS_CFUNC_DEF("delay", 1, js_timer_delay),
    JS_CFUNC_DEF("setTimeout", 2, js_timer_set_timeout),
    JS_CFUNC_DEF("interval", 2, js_timer_interval),
    JS_CFUNC_DEF("clear", 1, js_timer_clear),
};

static void LJS_init_timer(JSContext* ctx){
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JS_SetPropertyFunctionList(ctx, global_obj, js_timer_funcs, countof(js_timer_funcs));
}