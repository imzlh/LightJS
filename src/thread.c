#include "core.h"
#include "polyfill.h"
#include "../engine/quickjs.h"

#include <pthread.h>
#include <signal.h>
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
#include <sys/stat.h>

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

static bool resolve_module_path(char **_filename){
    char* filename = *_filename;
    struct stat st;
    int tried = 0;

main:
    if(tried == 2) goto finalize;
    tried ++;
    if(0 == stat(filename, &st)){
        if(S_ISDIR(st.st_mode)){
            // add /index.js
            char* index_fname = malloc(strlen(filename) + 10);
            if (!index_fname) goto memerror;
            strcpy(index_fname, filename);
            strcat(index_fname, "/index.js");
            free(filename);
            filename = index_fname;
            goto main;
        }else if(S_ISREG(st.st_mode)){
            *_filename = filename;
            return true;
        }else{ 
            errno = EPROTONOSUPPORT;
            goto finalize;
        }
    }else{
        // add .js extension
        char* str_addjs = malloc(strlen(filename) + 4);
        if (!str_addjs) goto memerror;
        strcpy(str_addjs, filename);
        strcat(str_addjs, ".js");
        free(filename);
        filename = str_addjs;
        goto main;
    }
    
memerror:
    errno = ENOMEM;
finalize:
    *_filename = NULL;
    return false;
}

static uint8_t* read_file(const char* filename, uint32_t* pbuf_len){
    int fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0)  goto err1;
    size_t size = st.st_size;
    size_t readed = 0;
    uint8_t *buf = malloc(size + 1);
    if (!buf) goto err1;
    while(readed < size){
        ssize_t n = read(fd, buf + readed, size - readed);
        if (n < 0) {
            if(errno == EINTR) continue;
            free(buf);
err1:
            close(fd);
            return NULL;
        } else if (n == 0) {
            break;
        }
        readed += n;
    }
    buf[size] = '\0';
    close(fd);
    *pbuf_len = size;
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
        if(!resolve_module_path(&module_name_path)){
            LJS_Throw(ctx, "Read file failed: %s", NULL, strerror(errno));
            free(module_name_path);
            return NULL;
        }
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
    const char* module_name;
    bool free_url = false;

    if(use_loader){
        JSValue argv[1] = { JS_NewString(ctx, _modname) };
        JSValue ret = JS_Call(ctx, app -> module_loader, JS_UNDEFINED, 1, argv);
        JS_FreeValue(ctx, argv[0]);
        if(JS_IsException(ret)){
            return NULL;
        }
        module_name = _modname;
        if(JS_IsString(ret)){
            size_t __len;
            buf = (char*)JS_ToCStringLen(ctx, &__len, ret);
            buf_len = __len;
            JS_FreeValue(ctx, ret);
            goto compile;
        }else{
            JS_FreeValue(ctx, ret);
            return NULL;
        }
    }

    // 默认加载器
    JSValue func_val;
    URL_data url = {0};
    if(!LJS_parse_url(_modname, &url, NULL)){
        return NULL;
    }
    free_url = true;

    if(!url.protocol || memcmp(url.protocol, "file", 4)){
        buf = (char*)read_file(url.path, &buf_len);
        if (!buf){
            return NULL;
        }
    }else{
        return NULL;
    }
    module_name = url.path;

    compile: {
        /* compile the module */
        func_val = JS_Eval(ctx, buf, buf_len, _modname,
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
            JS_DefinePropertyValueStr(ctx, meta_obj, "url",
                JS_NewString(ctx, real_path),
                JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, meta_obj, "filename",
                JS_NewString(ctx, basename(real_path)),
                JS_PROP_C_W_E);
            JS_DefinePropertyValueStr(ctx, meta_obj, "dirname",
                JS_NewString(ctx, dirname(real_path)),
                JS_PROP_C_W_E);

            JS_DefinePropertyValueStr(ctx, meta_obj, "main",
                JS_FALSE,
                JS_PROP_C_W_E);
            free(real_path);
        }
        JS_FreeValue(ctx, meta_obj);
    }

    if(free_url) LJS_free_url(&url);
    return m;
}

char* js_resolve_module(JSContext* ctx, const char* module_name){
    if(ctx){
        return js_module_format(ctx, NULL, module_name, NULL);
    }else{
        char* rpath = strdup(module_name);
        if(resolve_module_path(&rpath)){
            return rpath;
        }else{
            free(rpath);
            return NULL;
        }
    }
}

static JSValue js_module_set_handler(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 1 || !JS_IsFunction(ctx, argv[0]))
        return LJS_Throw(ctx, "invalid arguments", "module.setHandler(handler: function): void");

    App* app = JS_GetContextOpaque(ctx);

    if(!JS_IsUndefined(app -> module_loader))
        JS_FreeValue(ctx, app -> module_loader);
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
    JS_DefinePropertyValueStr(ctx, func_require, "setHandler", proto_sethandler, JS_PROP_C_W_E);
    // globalThis.require = require;
    JS_SetPropertyStr(ctx, global_obj, "require", func_require);
    
    JS_FreeValue(ctx, global_obj);

    return true;
}

// predef
static inline void worker_free_app(App* app);

struct WorkerMessage {
    struct list_head list;
    JSValue arg;
};

typedef void (*WorkerCallback)(App* app, JSValueConst data);
struct WorkerPipe{
    EvFD* main;
    EvFD* worker;
    int fd;
};
struct Worker_Props{
    struct WorkerPipe efd_worker2main;
    struct WorkerPipe efd_main2worker;

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
    bool exiting;   // pthread_join is pending
};

// Note: in worker thread
static inline void worker_exit(App* app, int code, const char* message){
    Worker_Error* error = (Worker_Error*)malloc(sizeof(Worker_Error));
    error -> message = (char*)message;
    error -> code = code;

    JSRuntime* rt = JS_GetRuntime(app -> ctx);
    worker_free_app(app);
    evcore_destroy();
    JS_FreeRuntime(rt);

    // exit thread
    pthread_exit((void*)error);
}

static inline void push_message(App* from, App* to, struct list_head* list, JSValue arg){
    // clone arg
    size_t size;
    void* data = JS_WriteObject(from -> ctx, &size, arg, 
        JS_WRITE_OBJ_BYTECODE | JS_WRITE_OBJ_REFERENCE | JS_WRITE_OBJ_SAB
    );
    if (!data) return;

    JSValue obj = JS_ReadObject(to -> ctx, data, size, 
        JS_READ_OBJ_BYTECODE | JS_READ_OBJ_REFERENCE | JS_READ_OBJ_SAB
    );
    free(data);
    
    if (JS_IsException(obj)) {
        return;
    }

    struct WorkerMessage* msg = malloc(sizeof(struct WorkerMessage));
    msg -> arg = obj;
    
    pthread_mutex_lock(&to -> worker -> lock);
    init_list_head(&msg -> list);
    list_add_tail(list, &msg -> list);
    pthread_mutex_unlock(&to -> worker -> lock);
}


App* LJS_create_app(
    JSRuntime* rt,
    uint32_t argc, char** argv,
    bool worker, bool module, char* script_path,
    App* parent
){
    if(!script_path) return NULL;
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
    app -> thread = pthread_self();

    init_list_head(&app -> workers);

    if(parent && worker){
        // 分配worker专用资源
        struct Worker_Props* wel = app -> worker = malloc(sizeof(struct Worker_Props));
        wel -> worker_msgcb = JS_UNDEFINED;
        wel -> error = NULL;

        init_list_head(&wel -> main_msg);
        init_list_head(&wel -> worker_msg);
        pthread_mutex_init(&wel -> lock, NULL);

        // Add to parent's worker list
        init_list_head(&app -> link);
        list_add_tail(&parent -> workers, &app -> link);

        // Create eventfd for worker-main communication
        int fd1 = eventfd(0, EFD_NONBLOCK),
            fd2 = eventfd(0, EFD_NONBLOCK);
        if(fd1 < 0 || fd2 < 0){
            perror("eventfd");
            goto failed;
        }

        // Message List
        init_list_head(&wel -> main_msg);
        init_list_head(&wel -> worker_msg);

        app -> worker -> efd_worker2main.fd = fd1;
        app -> worker -> efd_main2worker.fd = fd2;
        app -> worker -> parent = parent;
    }

    JS_SetContextOpaque(ctx, app);
    if(!parent || worker) JS_SetRuntimeOpaque(rt, app);
    return app;

failed:
    LJS_destroy_app(app);
    return NULL;
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
        struct Worker_Props* wel = app -> worker;
        // 关闭eventfd文件描述符
        evfd_close2(wel -> efd_worker2main.worker);
        evfd_close(wel -> efd_main2worker.worker);
        
        // remove lock
        pthread_mutex_destroy(&wel -> lock);

        // free msgcallback
        if(!JS_IsUndefined(wel-> worker_msgcb))
            JS_FreeValue(app -> ctx, wel-> worker_msgcb);
        if(!JS_IsUndefined(wel -> main_msgcb))
            JS_FreeValue(wel -> parent -> ctx, wel -> main_msgcb);
        if(!JS_IsUndefined(wel -> destroy_cb))
            JS_FreeValue(wel -> parent -> ctx, wel -> destroy_cb);

        // free queue
        msglist_clear(app -> ctx, &wel -> main_msg);
        msglist_clear(app -> ctx, &wel -> worker_msg);

        // free error
        if(wel -> error){
            free(wel -> error -> message);
            free(wel -> error);
        }
        
        // 释放worker结构体
        free(wel);
    }

    // sandbox can be auto destroyed, however workers not.
    if(!list_empty(&app -> workers)){
        struct list_head* pos, *tmp;
        list_for_each_safe(pos, tmp, &app -> workers){
            App* child = list_entry(pos, App, link);
            JSRuntime* rt = JS_GetRuntime(child -> ctx);
            pthread_kill(child -> thread, SIGINT);
            pthread_join(child -> thread, NULL);
            worker_free_app(child);
            JS_FreeRuntime(rt);
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

    // XXX: free script_path and argv or by user?
    // free args
    // if (app -> script_path) free(app -> script_path);
    // if (app -> argv) {
    //     for (uint32_t i = 0; i < app -> argc; i++) {
    //         free(app -> argv[i]);
    //     }
    //     free(app -> argv);
    // }

    free(app);
}

static inline void worker_free_app(App* app){
    LJS_destroy_app(app);

    free(app -> script_path);
    if (app -> argv) {
        for (uint32_t i = 0; i < app -> argc; i++) {
            free(app -> argv[i]);
        }
        free(app -> argv);
    }
}

// for worker thread
static int worker_message_callback(EvFD* __, uint8_t* buffer, uint32_t read_size, void* user_data){
    App* app = (App*)user_data;
    __maybe_unused uint64_t value;
    // Alert: main2worker eventfs should be closed by worker thread
    assert(read(app -> worker -> efd_main2worker.fd, &value, sizeof(uint64_t)) == sizeof(uint64_t));
        
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
    struct Worker_Props* wel = ((App*)user_data) -> worker;
    evfd_close(wel -> efd_worker2main.worker);
    evfd_close2(wel -> efd_main2worker.worker);
    worker_exit((App*)user_data, 0, "worker closed");
}

// for worker thread
static void worker_writeable_callback(EvFD* __, bool __unused__, void* opaque){
    App* app = opaque;

    // message
    write(
        app -> worker -> efd_worker2main.fd, 
        (uint8_t*)app -> worker -> msg_id,
        sizeof(uint64_t) 
    );
}

// for main thread
static int main_message_callback(EvFD* __, uint8_t* buffer, uint32_t read_size, void* opaque){
    App* app = (App*)opaque;    // worker APP, not main!
    uint64_t value;
    if(read(app -> worker -> efd_worker2main.fd, &value, sizeof(uint64_t)) != sizeof(uint64_t))
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
static void main_writeable_callback(EvFD* __, bool __unused__, void* opaque){
    App* data = opaque;
    // message
    write(
        data -> worker -> efd_main2worker.fd, 
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
    evfd_close2(app -> worker -> efd_worker2main.main);
    evfd_close(app -> worker -> efd_main2worker.main);
}

static bool worker_check_abort(void* opaque){
    App* app = (App*)opaque;
    if(app -> worker -> exiting) return true;
    return false;
}

static void worker_main_loop(App* app, JSValue func){
    JSContext* ctx = app -> ctx;

    // 初始化epoll
    evcore_init();

    // prevent signal(only handled in main thread)
    sigset_t sigmask;
    sigfillset(&sigmask);
    sigdelset(&sigmask, SIGUSR1);
    sigdelset(&sigmask, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, NULL, &sigmask);

    // 监听pipe
    app -> worker -> efd_main2worker.worker = 
        evcore_attach(app -> worker -> efd_main2worker.fd, false, 
            worker_message_callback, app,
            NULL, NULL,
            worker_close_callback, app
        );
    app -> worker -> efd_worker2main.worker = 
        evcore_attach(app -> worker -> efd_worker2main.fd, false, 
            NULL, NULL,
            worker_writeable_callback, app,
            NULL, NULL
        );

#ifdef LJS_DEBUG
    printf("Worker thread started: %s\n", app -> script_path);
#endif

    // 调用
    JSValue ret = JS_Call(ctx, func, JS_UNDEFINED, 0, NULL);
    if(JS_IsException(ret)){
        JSValue error = JS_GetException(ctx);
        js_dump(ctx, error, stderr);

        const char* message = JS_ToCString(ctx, error);
        char* space = malloc(strlen(message) + 39);
        memcpy(space, "Worker thread exited with exception: ", 37);
        memcpy(space + 37, message, strlen(message));
        worker_exit((App*)JS_GetContextOpaque(ctx), 1, space);
    }

    // 启动事件循环
    evcore_run(worker_check_abort, app);

    // exit
    worker_exit(app, 0, "worker thread exited");
}

void LJS_init_runtime(JSRuntime* rt){
    // Promise追踪
    JS_SetHostPromiseRejectionTracker(rt, js_handle_promise_reject, NULL);

    // 初始化ES6模块
    JS_SetModuleLoaderFunc(rt, js_module_format, js_module_loader, NULL);

    // atomic
    JS_SetCanBlock(rt, true);
}

// static bool in(char** arr, const char* str){
//     for(int i = 0; arr[i]; i++){
//         if(strcmp(arr[i], str) == 0) return true;
//     }
//     return false;
// }

void LJS_init_context(App* app){
    JSContext* ctx = app -> ctx;

    // 基础JS语法
    JS_AddIntrinsicBaseObjects(ctx);
    JS_AddIntrinsicDate(ctx);
    JS_AddIntrinsicEval(ctx);
    JS_AddIntrinsicRegExp(ctx);
    JS_AddIntrinsicJSON(ctx);
    JS_AddIntrinsicProxy(ctx);
    JS_AddIntrinsicMapSet(ctx);
    JS_AddIntrinsicTypedArrays(ctx);
    JS_AddIntrinsicPromise(ctx);
    JS_AddIntrinsicBigInt(ctx);
    JS_AddIntrinsicWeakRef(ctx);
    JS_AddPerformance(ctx);
    LJS_init_thread(ctx);
    if(!app -> worker){
        LJS_init_pipe(ctx);
        LJS_init_socket(ctx);
        LJS_init_process(ctx, app -> argc, app -> argv);

        LJS_init_stdio(ctx);
        LJS_init_http(ctx);

        LJS_init_compress(ctx);
        LJS_init_console(ctx);
        LJS_init_global_helper(ctx);
        LJS_init_module(ctx);
        LJS_init_timer(ctx);    // delay
        LJS_init_ffi(ctx);
        LJS_init_vm(ctx);
        LJS_init_xml(ctx);
        LJS_init_crypto(ctx);
    }
}

void js_set_import_meta(JSContext* ctx, JSValue func, const char* modname, bool main){
    App* app = JS_GetContextOpaque(ctx);
    char* path = js_strdup(ctx, app -> script_path);
    JSValue meta = JS_GetImportMeta(app -> ctx, (JSModuleDef*)JS_VALUE_GET_PTR(func));
    JS_SetPropertyStr(app -> ctx, meta, "name", JS_NewString(app -> ctx, modname));
    JS_SetPropertyStr(app -> ctx, meta, "url", JS_NewString(app -> ctx, app -> script_path));
    JS_SetPropertyStr(app -> ctx, meta, "main", JS_NewBool(app -> ctx, main));
    JS_SetPropertyStr(app -> ctx, meta, "dirname", JS_NewString(app -> ctx, dirname(path))); // dirname will change source string
    JS_SetPropertyStr(app -> ctx, meta, "filename", JS_NewString(app -> ctx, basename(app -> script_path)));
    js_free(ctx, path);
    JS_FreeValue(app -> ctx, meta);
}

static void* worker_entry(void* arg){
    App* app = (App*)arg;

    // init
    evcore_init();
    app -> thread = pthread_self();

    // eval script
    uint32_t buf_len;
    char* raw_name = js_strdup(app -> ctx, app -> script_path);
    // Note: LJS_tryGetJSFile will change app -> script_path
    uint8_t* buf = LJS_tryGetJSFile(&buf_len, &app -> script_path);
    if(!buf){
        worker_exit(app, 1, "load script failed");
    }
    uint8_t flag = JS_EVAL_FLAG_COMPILE_ONLY;
    if(app -> module) flag |= JS_EVAL_TYPE_MODULE;
    else flag |= JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_ASYNC;
    JSValue func = JS_Eval(app -> ctx, (char*)buf, buf_len, app -> script_path, flag);
    free(buf);

    // import.meta
    if(app -> module){
        js_set_import_meta(app -> ctx, func, raw_name, true);
    }
    js_free(app -> ctx, raw_name);

    worker_main_loop(app, func);
    JS_FreeValue(app -> ctx, func);

    return NULL;
}

/**
 * Create a new worker thread.
 * Note: script_path will be freed by LJS_destroy_app.
 * @param parent 父进程的App
 */
App* LJS_NewWorker(App* parent, char* script_path){
    pthread_t thread;

    JSRuntime* rt = JS_NewRuntime();
    App* app = LJS_create_app(
        rt, 
        parent -> argc, parent -> argv,
        true, false, script_path, parent
    );
    LJS_init_runtime(rt);
    LJS_init_context(app);

// #ifdef LJS_DEBUG
//     JS_SetDumpFlags(rt, JS_DUMP_GC | JS_DUMP_LEAKS | JS_DUMP_PROMISE | JS_DUMP_OBJECTS);
// #endif

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if(0 != pthread_create(&thread, &attr, worker_entry, app)){
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

    // Note: close main-thread to worker pipe, but remain another to main-thread.
    evfd_close(app -> worker -> efd_main2worker.main);
    evfd_close2(app -> worker -> efd_worker2main.main);

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

    if(!JS_IsUndefined(app -> worker -> worker_msgcb))
        JS_FreeValue(ctx, app -> worker -> worker_msgcb);
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

static JSValue js_worker_ctor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
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

#ifdef LJS_DEBUG
    printf("Worker: %s, module: %d\n", script_path, module);
#endif

    App* app = LJS_NewWorker((App*)JS_GetContextOpaque(ctx), strdup(script_path));

    // evloop
    app -> worker -> efd_worker2main.main =
        evcore_attach(app -> worker -> efd_worker2main.fd, false, 
            main_message_callback, app,
            NULL, NULL,
            main_close_callback, app
        );
    app -> worker -> efd_main2worker.main =
        evcore_attach(app -> worker -> efd_main2worker.fd, false,
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

// Note: main-thread "worker" and Sandbox "worker" fields is always NULL.
static inline bool is_worker_ctx(JSContext* ctx){
    App* app = (App*)JS_GetContextOpaque(ctx);
    return app -> worker != NULL;
}

#define CHECK_WORKER_CTX(ctx) if(!is_worker_ctx(ctx)) return LJS_Throw(ctx, "Worker is not available in this context", NULL);

static JSValue js_worker_static_postMessage(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    CHECK_WORKER_CTX(ctx);

    if(argc < 1 || !JS_IsObject(argv[0])){
        return LJS_Throw(ctx, "Worker.postMessage takes 1 argument: message", "Worker.postMessage(message: any): void");
    }

    App* app = (App*)JS_GetContextOpaque(ctx);
    push_message(app, app, &app -> worker -> worker_msg, argv[0]);
    return JS_UNDEFINED;
}

static JSValue js_worker_static_exit(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    CHECK_WORKER_CTX(ctx);
    worker_exit((App*)JS_GetContextOpaque(ctx), 0, "worker thread exit");
    return JS_UNDEFINED;
}

static JSValue js_worker_static_set_onmessage(JSContext* ctx, JSValueConst this_val, JSValueConst val){
    CHECK_WORKER_CTX(ctx);
    App* app = (App*)JS_GetContextOpaque(ctx);
    if(!JS_IsUndefined(app -> worker -> main_msgcb))
        JS_FreeValue(ctx, app -> worker -> main_msgcb);
    app -> worker -> main_msgcb = JS_DupValue(ctx, val);
    return JS_UNDEFINED;
}

static JSValue js_worker_static_get_onmessage(JSContext* ctx, JSValueConst this_val){
    CHECK_WORKER_CTX(ctx);
    App* app = (App*)JS_GetContextOpaque(ctx);
    return JS_DupValue(ctx, app -> worker -> main_msgcb);
}

static JSCFunctionListEntry js_worker_static_funcs[] = {
    JS_CFUNC_DEF("postMessage", 1, js_worker_static_postMessage),
    JS_CFUNC_DEF("exit", 0, js_worker_static_exit),
    JS_CGETSET_DEF("onmessage", js_worker_static_get_onmessage, js_worker_static_set_onmessage),
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

    JSValue worker_ctor = JS_NewCFunction2(ctx, js_worker_ctor, "Worker", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, worker_ctor, worker_proto);
    JS_SetPropertyStr(ctx, global_obj, "Worker", worker_ctor);

    // worker props
    if(is_worker_ctx(ctx)){
        JS_SetPropertyFunctionList(ctx, worker_ctor, js_worker_static_funcs, countof(js_worker_static_funcs));
    }

    JS_FreeValue(ctx, global_obj);

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
    JS_FreeValue(timer -> ctx, timer -> resolve);

    if(timer -> once){
        js_free(timer -> ctx, timer);
    }
}

static void timer_free_callback(EvFD* fd, void* ptr){
    struct Timer_T* timer = (struct Timer_T*)ptr;
    js_free(timer -> ctx, timer);
}

static JSValue js_timer_delay(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 1 || !JS_IsNumber(argv[0])){
        return LJS_Throw(ctx, "delay takes 1 argument: delay_time", "delay(delay_time: number): Promise<void>");
    }

    JSValue promise_cb[2];
    JSValue promise = JS_NewPromiseCapability(ctx, promise_cb);
    struct Timer_T* timer = (struct Timer_T*)js_malloc(ctx, sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = promise_cb[0];
    timer -> once = true;

    uint32_t delay_time;
    if(-1 == JS_ToUint32(ctx, &delay_time, argv[0]) || delay_time == 0){
        return LJS_Throw(ctx, "delay takes a non-zero delay_time", NULL);
    }

    evcore_setTimeout(delay_time, timer_callback, timer);

    JS_FreeValue(ctx, promise_cb[1]);
    return promise;
}

static JSValue js_timer_timeout(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 2 || !JS_IsNumber(argv[1]) || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, "setTimeout takes 2 argument", "setTimeout(callback: () => void, delay_time: number): number");
    }

    JSValue callback = JS_DupValue(ctx, argv[0]);
    uint32_t delay_time;
    if(-1 == JS_ToUint32(ctx, &delay_time, argv[1]) || delay_time == 0){
        return LJS_Throw(ctx, "setTimeout takes a non-zero delay_time", NULL);
    }

    struct Timer_T* timer = (struct Timer_T*)js_malloc(ctx, sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = callback;
    timer -> once = true;

    EvFD* fd = evcore_setTimeout(delay_time, timer_callback, timer);

    return JS_NewUint32(ctx, evfd_getfd(fd, NULL));
}

static JSValue js_timer_interval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 2 || !JS_IsNumber(argv[1]) || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, "interval takes 2 argument", "interval(callback: () => void, interval_time: number): number");
    }

    JSValue callback = JS_DupValue(ctx, argv[0]);
    uint32_t interval_time;
    if(-1 == JS_ToUint32(ctx, &interval_time, argv[1]) || interval_time == 0){
        return LJS_Throw(ctx, "interval takes a non-zero interval_time", NULL);
    }

    struct Timer_T* timer = (struct Timer_T*)js_malloc(ctx, sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = callback;
    timer -> once = false;

    EvFD* fd = evcore_interval(interval_time, timer_callback, timer, timer_free_callback, timer);

    return JS_NewUint32(ctx, evfd_getfd(fd, NULL));
}

static JSValue js_timer_clear(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 1 || !JS_IsNumber(argv[0])){
        return LJS_Throw(ctx, "clearTimer takes 1 argument: timer", "clearTimer(timer: number): boolean");
    }
    
    int id;
    if(-1 == JS_ToInt32(ctx, &id, argv[0])) return JS_EXCEPTION;
    return JS_NewBool(ctx, evcore_clearTimer(id));
}

const JSCFunctionListEntry js_timer_funcs[] = {
    JS_CFUNC_DEF("delay", 1, js_timer_delay),
    JS_CFUNC_DEF("setTimeout", 2, js_timer_timeout),
    JS_CFUNC_DEF("setInterval", 2, js_timer_interval),
    JS_CFUNC_DEF("clearTimer", 1, js_timer_clear),
};

void LJS_init_timer(JSContext* ctx){
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JS_SetPropertyFunctionList(ctx, global_obj, js_timer_funcs, countof(js_timer_funcs));
    JS_FreeValue(ctx, global_obj);
}