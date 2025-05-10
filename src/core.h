#include "../engine/quickjs.h"
#include "../engine/list.h"
#include "../engine/cutils.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/inotify.h>
#include <arpa/inet.h>

// once include
#pragma once

// GNU/POSIX compatibility
#define _POSIX_C_SOURCE 1
#ifndef __GNUC__
#warning "This code may not fit well on non-GNU compilers"
#endif

// version
#define LJS_VERSION "0.1.0"
enum {
    __JS_ATOM_NULL = JS_ATOM_NULL,
#define DEF(name, str) JS_ATOM_ ## name,
#include "../engine/quickjs-atom.h"
#undef DEF
    JS_ATOM_END,
};

// mbedtls
#ifdef LJS_MBEDTLS
#include "../lib/mbedtls_config.h"
#include <mbedtls/ssl.h>
#endif

#define MAX_EVENTS 64
#define MAX_QUERY_COUNT 32
#define PIPE_READ 1
#define PIPE_WRITE (1 << 1)
#define PIPE_AIO (1 << 2)
#define PIPE_SOCKET (1 << 3)
#define MAX_MESSAGE_COUNT 10
#define EV_REMOVE_ALL (EV_REMOVE_READ | EV_REMOVE_WRITE | EV_REMOVE_EOF)
#define EVFD_BUFSIZE 16 * 1024
#define MAX_HEADER_COUNT 64

#ifndef countof
#define countof(x) (sizeof(x)/sizeof((x)[0]))
#endif

#define C_CONST(x) JS_PROP_INT32_DEF(#x, x, JS_PROP_CONFIGURABLE )

typedef JSValue (*PipeCallback)(JSContext* ctx, void* ptr, JSValueConst data);

/* forward */ typedef struct EvFD EvFD;
/* forward */ typedef enum EvPipeToNotifyType EvPipeToNotifyType;
typedef int (*EvReadCallback)(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data);
typedef void (*EvWriteCallback)(EvFD* evfd, void* opaque);
typedef void (*EvCloseCallback)(EvFD* fd, void* opaque);
typedef void (*EvINotifyCallback)(struct inotify_event* event, void* user_data);
typedef void (*EvSyncCallback)(EvFD* evfd, void* user_data);
typedef void (*EvTimerCallback)(uint64_t count, void* user_data);
typedef void (*EvSSLHandshakeCallback)(EvFD* evfd, void* user_data);
typedef bool (*EvPipeToFilter)(struct Buffer* buf, void* user_data);
typedef void (*EvPipeToNotify)(struct EvFD* from, struct EvFD* to, EvPipeToNotifyType type, void* user_data);
typedef void (*JSPromiseCallback)(JSContext* ctx, bool is_error, JSValue result, void* user_data);

typedef struct{
    char *key;
    char *value;
} URL_query_data;

typedef struct{
    char* source_str;   // free
    char *protocol;
    char *host;
    uint16_t port;
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
    bool is_client; // read data from client or server
    HTTP_rw_state state;

    bool __read_all;    // internal use only

    char *method;
    uint16_t status;
    float version;
    char* path;

    char** headers[MAX_HEADER_COUNT];
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

enum EvPipeToNotifyType{
    EV_PIPETO_NOTIFY_DONE,
    EV_PIPETO_NOTIFY_CLOSED
};

#define EVCB_RET_DONE 0
#define EVCB_RET_REWIND (1 << 1)      // rewind current buffer
#define EVCB_RET_CONTINUE (1 << 2)    // continue current task

typedef struct {
    char* message;
    int code;
} Worker_Error;

typedef struct Worker_Props Worker_Props;
typedef struct {
    JSContext* ctx;
    bool module;

    // in main thread, define workers
    struct list_head workers;

    // in worker thread, define app
    struct Worker_Props* worker;
    struct list_head link;
    
    // sandbox(Apps)
    struct list_head sandbox;

    char* script_path;
    char** argv;
    uint32_t argc;

    // module
    JSValue module_loader;
    JSValue module_format;
} App;

typedef enum {
    DNS_A = 1,
    DNS_NS = 2,
    DNS_CNAME = 5,
    DNS_SOA = 6,
    DNS_MX = 15,
    DNS_TXT = 16,
    DNS_AAAA = 28,
    DNS_SRV = 33
} DnsRecordType;

// 通用DNS记录结构
typedef struct {
    DnsRecordType type;
    uint32_t ttl;
    uint16_t data_len;
    union {
        struct in_addr a;
        struct in6_addr aaaa;
        struct {
            uint16_t priority;
            char exchange[256];
        } mx;
        char cname[256];
        char txt[256];
        char ns[256];
        struct {
            char mname[256];
            char rname[256];
            uint32_t serial;
            uint32_t refresh;
            uint32_t retry;
            uint32_t expire;
            uint32_t minimum;
        } soa;
        struct {
            uint16_t priority;
            uint16_t weight;
            uint16_t port;
            char target[256];
        } srv;
    } data;
} dns_record;

typedef void (*HTTP_Callback)(HTTP_data* data, uint8_t* buffer, uint32_t size, void* userdata);
typedef void (*HTTP_ParseCallback)(HTTP_data *data, uint8_t *buffer, uint32_t len, void* ptr);
typedef void (*DnsResponseCallback)(int total_records, dns_record** records, void* user_data);
typedef void (*DnsErrorCallback)(const char* error_msg, void* user_data);

// Core events
void LJS_dispatch_ev(JSContext *ctx, const char * name, JSValue data);
JSValue js_extends_evtarget(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv);

// console
void LJS_print_value(JSContext *ctx, JSValueConst val, int depth, JSValue* visited[], FILE* target_fd);
void js_handle_promise_reject(
    JSContext *ctx, JSValue promise,
    JSValue reason,
    bool is_handled, void *opaque
);
void LJS_dump_error(JSContext *ctx, JSValueConst exception);

// exports
bool LJS_init_global_helper(JSContext *ctx);
bool LJS_init_vm(JSContext *ctx);
bool LJS_init_console(JSContext *ctx);
bool LJS_init_pipe(JSContext *ctx);
bool LJS_init_http(JSContext *ctx);
bool LJS_init_module(JSContext *ctx);
void LJS_init_runtime(JSRuntime* rt);
bool LJS_init_stdio(JSContext *ctx);
bool LJS_init_process(JSContext* ctx, char* _entry, uint32_t _argc, char** _argv);
bool LJS_init_socket(JSContext* ctx);

// Core I/O Pipe
JSValue LJS_NewFDPipe(JSContext *ctx, int fd, uint32_t flag, uint32_t buf_size, EvFD** ref);
JSValue LJS_NewU8Pipe(JSContext *ctx, uint32_t flag, uint32_t buf_size, PipeCallback poll_cb, PipeCallback write_cb, PipeCallback close_cb, void* user_data);
JSValue LJS_NewPipe(JSContext *ctx, uint32_t flag, PipeCallback poll_cb, PipeCallback write_cb, PipeCallback close_cb, void* user_data);
EvFD* LJS_GetPipeFD(JSContext *ctx, JSValueConst obj);

// Core event loop
bool LJS_evcore_init();
bool LJS_evcore_run(bool (*evloop_abort_check)(void* user_data), void* user_data);
EvFD* LJS_evcore_attach(int fd, bool use_aio, EvReadCallback rcb, void* read_opaque, EvWriteCallback wcb, void* write_opaque, EvCloseCallback ccb, void* close_opaque);
bool LJS_evcore_detach(int fd, uint8_t type);
void LJS_evcore_set_memory(void* (*allocator)(size_t, void*), void* opaque);
EvFD* LJS_evfd_new(int fd, bool use_aio, bool readable, bool writeable, uint32_t bufsize, EvCloseCallback close_callback, void* close_opaque);
void LJS_evfd_setup_udp(EvFD* evfd);
bool LJS_evfd_read(EvFD* evfd, uint32_t buf_size, uint8_t* buffer, EvReadCallback callback, void* user_data);
bool LJS_evfd_readsize(EvFD* evfd, uint32_t buf_size, uint8_t* buffer, EvReadCallback callback, void* user_data);
bool LJS_evfd_readline(EvFD* evfd, uint32_t buf_size, uint8_t* buffer, EvReadCallback callback, void* user_data);
bool LJS_evfd_write(EvFD* evfd, const uint8_t* data, uint32_t size, EvWriteCallback callback, void* user_data);
bool LJS_evfd_write_dgram(EvFD* evfd, const uint8_t* data, uint32_t size, const struct sockaddr *addr, socklen_t addr_len, EvWriteCallback callback, void* user_data);
bool LJS_evfd_pipeTo(EvFD* from, EvFD* to, EvPipeToFilter filter, void* fopaque, EvPipeToNotify notify, void* nopaque);
bool LJS_evfd_close(EvFD* evfd);
bool LJS_evfd_override(EvFD* evfd, EvReadCallback rcb, void* read_opaque, EvWriteCallback wcb, void* write_opaque, EvCloseCallback ccb, void* close_opaque);
bool LJS_evfd_wait(EvFD* evfd, bool wait_read, EvSyncCallback cb, void* opaque);
bool LJS_evfd_close2(EvFD* evfd, EvSyncCallback cb, void* opaque);
bool LJS_evfd_clearbuf(EvFD* evfd);
bool LJS_evfd_onclose(EvFD* fd, EvCloseCallback callback, void* user_data);
int LJS_evfd_getfd(EvFD* evfd, int* timer_fd);
bool LJS_evfd_yield(EvFD* evfd, bool yield_read, bool yield_write);
bool LJS_evfd_consume(EvFD* evfd, bool consume_read, bool consume_write);
bool LJS_evfd_isAIO(EvFD* evfd);
#ifdef LJS_MBEDTLS
bool LJS_evfd_initssl(EvFD* evfd, mbedtls_ssl_config** config, bool is_client, int protocol, int preset, EvSSLHandshakeCallback handshake_cb, void* user_data);
void LJS_evfd_set_sni(char* name, char* server_name, mbedtls_x509_crt* cacert, mbedtls_pk_context* cakey);
bool LJS_evfd_remove_sni(const char* name);
bool LJS_evfd_initdtls(EvFD* evfd, mbedtls_ssl_config** _config);
#endif
EvFD* LJS_evcore_setTimeout(unsigned long milliseconds, EvTimerCallback callback, void* user_data);
EvFD* LJS_evcore_interval(unsigned long milliseconds, EvTimerCallback callback, void* user_data);
bool LJS_evcore_clearTimer(int timer_fd);
EvFD* LJS_evcore_inotify(EvINotifyCallback callback, void* user_data);
bool LJS_evcore_stop_inotify(EvFD* evfd);
int LJS_evcore_inotify_watch(EvFD* evfd, const char* path, uint32_t mask);
bool LJS_evcore_inotify_unwatch(EvFD* evfd, int wd);

int js_run_promise_jobs(); // internal use
bool LJS_enqueue_promise_job(JSContext* ctx, JSValue promise, JSPromiseCallback callback, void* opaque);
void* js_malloc_proxy(size_t size, void* opaque);

// compress
bool LJS_init_compress(JSContext *ctx);

// socket
bool LJS_dns_resolve(
    JSContext* ctx, const char* hostname, const char* dns_server, 
    DnsResponseCallback callback, DnsErrorCallback error_callback, void* user_data
);
EvFD* LJS_open_socket(const char* protocol, const char* hostname, int port, int bufsize);

// HTTP module
char* LJS_resolve_path(const char* path, const char* base);
bool LJS_parse_query(char *query, URL_query_data *query_list[], int max_query_count);
bool LJS_parse_url(const char *url, URL_data *url_struct, URL_data *base);
void LJS_free_url(URL_data *url_struct);
char* LJS_format_url(URL_data *url_struct);
JSValue LJS_NewResponse(JSContext *ctx, HTTP_data *data);
void LJS_parse_from_fd(EvFD* fd, HTTP_data *data, bool is_client, HTTP_ParseCallback callback, void *userdata);
JSValue LJS_NewWebSocket(JSContext *ctx, EvFD* fd, bool enable_mask);
JSValue LJS_NewWebSocket(JSContext *ctx, EvFD* fd, bool enable_mask);

// module
uint8_t *LJS_tryGetJSFile(uint32_t *pbuf_len, char **filename);

// threads
void LJS_destroy_app(App* app);
App* LJS_create_app(
    JSRuntime* rt,
    uint32_t argc, char** argv,
    bool worker, bool module, char* script_path,
    App* parent
);
void LJS_init_context(App* app, char** init_list);
App* LJS_NewWorker(App* parent);
bool LJS_init_thread(JSContext* ctx);

// ffi
bool LJS_init_ffi(JSContext *ctx);

// xml
bool LJS_init_xml(JSContext* ctx);

// --------------- HELPER FUNCTIONS ------------------------
void free_js_malloc(JSRuntime *rt, void *opaque, void *ptr);
void free_malloc(JSRuntime* rt, void* opaque, void* ptr);
void base64_decode(const char *input, size_t len, uint8_t *output, size_t *output_len);
void base64_decode(const char *input, size_t len, uint8_t *output, size_t *output_len);
void base64_encode(const uint8_t *input, size_t len, char *output);

// --------------- BUILT-IN FUNCTIONS ---------------------

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
    return JS_EXCEPTION;
}

static inline void LJS_panic(const char *msg){
    printf("LightJS fatal error: %s\n", msg);
    exit(1);
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
    if(!proxy -> ctx) return;
    JS_FreeValue(proxy -> ctx, proxy -> resolve);
    JS_FreeValue(proxy -> ctx, proxy -> reject);
    // WARN: 此处应该由用户决策，所有权是否转移到JS层？
    // JS_FreeValue(proxy -> ctx, proxy -> promise);
    js_free(proxy -> ctx, proxy);
    proxy -> ctx = NULL;
}

static inline void LJS_Promise_Resolve(struct promise* proxy, JSValue value){
    if(!proxy -> ctx) return;   // already done
    JSValue args[1] = {value};
    if(!proxy) return;
    JS_Call(proxy -> ctx, proxy -> resolve, proxy -> promise, 1, args);
    LJS_FreePromise(proxy);
}

static inline void LJS_Promise_Reject(struct promise* proxy, const char* msg){
    if(!proxy -> ctx) return;   // already done
    JSValue error = JS_NewError(proxy -> ctx);
    JS_SetPropertyStr(proxy -> ctx, error, "message", JS_NewString(proxy -> ctx, msg));
    JS_Call(proxy -> ctx, proxy -> reject, proxy -> promise, 1, (JSValueConst[]){error});
    LJS_FreePromise(proxy);
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

struct JSValueProxy {
    JSValue val;
    JSContext* ctx;
};

static inline struct JSValueProxy* LJS_NewJSValueProxy(JSContext *ctx, JSValue val){
    struct JSValueProxy* proxy = js_malloc(ctx, sizeof(struct JSValueProxy));
    if(!proxy) return NULL;
    proxy -> val = val;
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