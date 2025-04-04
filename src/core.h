#include "../engine/quickjs.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/inotify.h>

// once include
#pragma once

// GNU/POSIX compatibility
#define _POSIX_C_SOURCE 1
#ifndef __GNUC__
#warning "This code may not fit well on non-GNU compilers"
#endif

// version
#define LJS_VERSION "0.1.0"

#define MAX_EVENTS 64
#define MAX_QUERY_COUNT 32
#define PIPE_READ 0b1
#define PIPE_WRITE 0b10
#define MAX_MESSAGE_COUNT 10
#define EV_REMOVE_ALL (EV_REMOVE_READ | EV_REMOVE_WRITE | EV_REMOVE_EOF)
#define EVFD_BUFSIZE 16 * 1024

#ifndef countof
#define countof(x) (sizeof(x)/sizeof((x)[0]))
#endif

#define C_CONST(x) JS_PROP_INT32_DEF(#x, x, JS_PROP_CONFIGURABLE )

typedef JSValue (*PipeCallback)(JSContext* ctx, void* ptr, JSValueConst data);

/* forward */ typedef struct EvFD EvFD;
typedef void (*EvReadCallback)(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data);
typedef void (*EvWriteCallback)(EvFD* evfd, void* opaque);
typedef void (*EvCloseCallback)(int fd, void* opaque);
typedef void (*EvINotifyCallback)(struct inotify_event* event, void* user_data);
typedef void (*EvSyncCallback)(EvFD* evfd, void* user_data);
typedef void (*EvTimerCallback)(uint64_t count, void* user_data);

typedef struct{
    char *key;
    char *value;
} URL_query_data;

typedef struct{
    char *protocol;
    char *host;
    int port;
    char *path;
    URL_query_data *query;
    char* query_string;
    char *hash;
    char* username;
    char* password;
} URL_data;

typedef enum{
    HTTP_INIT,
    HTTP_FIRST_LINE,
    HTTP_HEADER,
    HTTP_BODY,
    HTTP_DONE,
    HTTP_ERROR
} HTTP_rw_state;
/* forward */ typedef struct HTTP_data HTTP_data;
struct HTTP_data {
    EvFD* fd;
    bool is_client;
    bool write_to_fd;
    HTTP_rw_state state;

    char *method;
    uint16_t status;
    float version;
    char* path;

    char*** headers;
    uint32_t header_count;
    uint32_t header_writed;

    bool chunked;
    uint32_t content_length;
    uint32_t content_read;

    void (*cb)(HTTP_data* data, uint8_t* buffer, uint32_t size, void* userdata);
    void* userdata;
};

typedef enum{
    EV_REMOVE_READ  = 0b001,
    EV_REMOVE_WRITE = 0b010,
    EV_REMOVE_EOF   = 0b100
} EV_DetachType;

typedef struct {
    char* message;
    int code;
} Worker_Error;

typedef struct {
    JSValue* message[MAX_MESSAGE_COUNT];
    struct LJS_Promise_Proxy* promise[MAX_MESSAGE_COUNT];
    uint8_t start;
    uint8_t end;
} Worker_Message_Queue;

struct Worker_Props{
    JSContext* parent_ctx;
    uint32_t worker_id;

    int efd_worker2main;
    int efd_main2worker;

    JSValue message_callback;
    Worker_Error* error;
    // write queue, in worker for main thread and worker thread
    Worker_Message_Queue main_q;
    Worker_Message_Queue worker_q;
};

typedef struct {
    JSContext* ctx;
    // in main thread, define workers
    JSContext** workers;
    int worker_count;

    struct Worker_Props* worker;
    bool module;

    char* script_path;
    char** argv;
    uint32_t argc;

    // module
    JSValue module_loader;
    JSValue module_format;
    JSContext* module_ctx;
} App;

typedef void (*HTTP_Callback)(HTTP_data* data, uint8_t* buffer, uint32_t size, void* userdata);
typedef void (*HTTP_ParseCallback)(HTTP_data *data, uint8_t *buffer, uint32_t len, void* ptr);


// Core events
void LJS_dispatch_ev(char* name, JSValue data);

// console
void LJS_print_value(JSContext *ctx, JSValueConst val, int depth, JSValue* visited[], FILE* target_fd);
void LJS_handle_promise_reject(
    JSContext *ctx, JSValue promise,
    JSValue reason,
    bool is_handled, void *opaque
);
void LJS_dump_error(JSContext *ctx, JSValueConst exception);

// exports
bool LJS_init_global_helper(JSContext *ctx);
bool LJS_init_console(JSContext *ctx);
bool LJS_init_pipe(JSContext *ctx);
bool LJS_init_HTTP(JSContext *ctx);
bool LJS_init_module(JSContext *ctx);
void LJS_init_runtime(JSRuntime* rt);
bool LJS_init_stdio(JSContext *ctx);
bool LJS_init_global_url(JSContext *ctx);
bool LJS_init_process(JSContext* ctx, char* _entry, uint32_t _argc, char** _argv);

// Core I/O Pipe
JSValue LJS_NewFDPipe(JSContext *ctx, int fd, uint32_t flag, uint32_t buf_size, JSValue onclose);
JSValue LJS_NewU8Pipe(JSContext *ctx, uint32_t flag, uint32_t buf_size, PipeCallback poll_cb, PipeCallback write_cb, PipeCallback close_cb, void* user_data);
JSValue LJS_NewPipe(JSContext *ctx, uint32_t flag, PipeCallback poll_cb, PipeCallback write_cb, PipeCallback close_cb, void* user_data);

// Core event loop
bool LJS_evcore_init();
bool LJS_evcore_run(bool (*evloop_abort_check)(void* user_data), void* user_data);
int LJS_evcore_attach(int fd, bool use_aio, EvReadCallback rcb, EvWriteCallback wcb, EvCloseCallback ccb, void* opaque);
bool LJS_evcore_detach(int fd, uint8_t type);
EvFD* LJS_evfd_new(int fd, bool readable, bool writeable, uint32_t bufsize, EvCloseCallback close_callback, void* close_opaque);
bool LJS_evfd_read(EvFD* evfd, uint32_t buf_size, uint8_t* buffer, EvReadCallback callback, void* user_data);
bool LJS_evfd_readsize(EvFD* evfd, uint32_t buf_size, uint8_t* buffer, EvReadCallback callback, void* user_data);
bool LJS_evfd_readline(EvFD* evfd, uint32_t buf_size, uint8_t* buffer, EvReadCallback callback, void* user_data);
bool LJS_evfd_write(EvFD* evfd, const uint8_t* data, uint32_t size, EvWriteCallback callback, void* user_data);
bool LJS_evfd_close(EvFD* evfd);
int LJS_evfd_getfd(EvFD* evfd, int* timer_fd);
EvFD* LJS_evcore_setTimeout(unsigned long milliseconds, EvTimerCallback callback, void* user_data);
EvFD* LJS_evcore_interval(unsigned long milliseconds, EvTimerCallback callback, void* user_data);
bool LJS_evcore_clearTimer(int timer_fd);
EvFD* LJS_evcore_inotify(EvINotifyCallback callback, void* user_data);
bool LJS_evcore_stop_inotify(EvFD* evfd);
int LJS_evcore_inotify_watch(EvFD* evfd, const char* path, uint32_t mask);
bool LJS_evcore_inotify_unwatch(EvFD* evfd, int wd);

// URL module
char* LJS_resolve_path(const char* path, const char* base);
bool LJS_parse_query(char *query, URL_query_data *query_list[], int max_query_count);
bool LJS_parse_url(char *url, URL_data *url_struct, URL_data *base);
void LJS_free_url(URL_data *url_struct);
char* LJS_format_url(URL_data *url_struct);
JSValue LJS_NewResponse(JSContext *ctx, HTTP_data *data, URL_data *url);
void LJS_parse_from_fd(EvFD* fd, HTTP_data *data, bool is_client, HTTP_ParseCallback callback, void *userdata);

// module
uint8_t *LJS_tryGetJSFile(uint32_t *pbuf_len, char **filename);

// threads
App* LJS_create_app(
    JSRuntime* rt,
    uint32_t argc, char** argv,
    bool worker, bool module, char* script_path,
    App* parent
);
void LJS_init_context(App* app, char** init_list);
App* LJS_NewWorker(App* parent);
bool LJS_init_thread(JSContext* ctx);

// --------------- HELPER FUNCTIONS ------------------------
void free_malloc(JSRuntime *rt, void *opaque, void *ptr);

// --------------- BUILT-IN FUNCTIONS ---------------------
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
    char* msg2 = malloc(msg_len);   // guessed
    if (!msg2) {
        JS_FreeValue(ctx, error_obj);
        return JS_EXCEPTION;
    }

    va_start(args, help);
    vsnprintf(msg2, msg_len, msg, args);
    va_end(args);

    JS_DefinePropertyValueStr(ctx, error_obj, "message", JS_NewString(ctx, msg2), JS_PROP_C_W_E);
    free(msg2);

    if (help) {
        JS_DefinePropertyValueStr(ctx, error_obj, "help", JS_NewString(ctx, help), JS_PROP_C_W_E);
    }
    return JS_Throw(ctx, error_obj);
}

static inline JSValue LJS_ThrowWithError(JSContext *ctx, const char *msg, const char *help){
    char* error_str = malloc(1024);
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
    free(error_str);
    return JS_EXCEPTION;
}

static inline void LJS_panic(const char *msg){
    printf("LightJS fatal error: %s\n", msg);
    exit(1);
}

struct LJS_Promise_Proxy{
    JSContext* ctx;
    JSValue resolve;
    JSValue reject;
    JSValue promise;
};

/**
 * 创建一个Promise Proxy，方便在C中操作
 * @param ctx 运行时上下文
 */
static inline struct LJS_Promise_Proxy* LJS_NewPromise(JSContext *ctx){
    struct LJS_Promise_Proxy* proxy = malloc(sizeof(struct LJS_Promise_Proxy));
    JSValue resolving_funcs[2];
    proxy -> ctx = ctx;
    proxy -> promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    proxy -> resolve = JS_DupValue(ctx, resolving_funcs[0]);
    proxy -> reject = JS_DupValue(ctx, resolving_funcs[1]);
    return proxy;
}

static inline void LJS_FreePromise(struct LJS_Promise_Proxy* proxy){
    JS_FreeValue(proxy -> ctx, proxy -> resolve);
    JS_FreeValue(proxy -> ctx, proxy -> reject);
    JS_FreeValue(proxy -> ctx, proxy -> promise);
    free(proxy);
}

static inline void LJS_Promise_Resolve(struct LJS_Promise_Proxy* proxy, JSValue value){
    JSValue args[1] = {value};
    if(!proxy) return;
    JS_Call(proxy -> ctx, proxy -> resolve, proxy -> promise, 1, args);
}

/**
 * 创建一个继承自指定父类的新类
 * 
 * @param ctx JS上下文
 * @param parent_class 父类的JS值
 * @param class_id 新类的ID
 * @param class_def 类定义
 * @return 新类的构造函数
 */
static inline JSValue JS_NewClass2(JSContext *ctx, JSValue parent_class, 
                    JSClassID class_id, const JSClassDef *class_def) {
    // 1. 注册新类
    if (JS_NewClass(JS_GetRuntime(ctx), class_id, class_def) < 0) {
        return JS_EXCEPTION;
    }
    
    // 2. 获取父类的原型
    JSValue parent_proto = JS_GetPropertyStr(ctx, parent_class, "prototype");
    if (JS_IsException(parent_proto)) {
        return JS_EXCEPTION;
    }
    
    // 3. 创建子类构造函数
    JSValue child_ctor = JS_NewCFunction2(ctx, NULL, class_def->class_name, 
                                        0, JS_CFUNC_constructor, class_id);
    if (JS_IsException(child_ctor)) {
        JS_FreeValue(ctx, parent_proto);
        return JS_EXCEPTION;
    }
    
    // 4. 创建子类原型对象
    JSValue child_proto = JS_NewObjectProtoClass(ctx, parent_proto, class_id);
    JS_FreeValue(ctx, parent_proto);
    if (JS_IsException(child_proto)) {
        JS_FreeValue(ctx, child_ctor);
        return JS_EXCEPTION;
    }
    
    // 5. 设置构造函数的prototype属性
    JS_SetPropertyStr(ctx, child_ctor, "prototype", child_proto);
    
    // 6. 设置原型对象的constructor属性
    JS_SetPropertyStr(ctx, child_proto, "constructor", child_ctor);
    
    JS_FreeValue(ctx, child_proto);
    return child_ctor;
}

static inline bool JS_CopyObject(JSContext *ctx, JSValueConst from, JSValue to, uint32_t max_items){
    JSValue val;

    JSPropertyEnum *props[max_items];
    int proplen = JS_GetOwnPropertyNames(ctx, props, &max_items, from, JS_GPN_ENUM_ONLY);
    if(proplen < 0) return false;
    for(int i = 0; i < proplen; i++){
        val = JS_GetProperty(ctx, from, props[i]->atom);
        if(!JS_IsException(val)){
            JS_SetProperty(ctx, to, props[i]->atom, val);
        }
    }
    return true;
}