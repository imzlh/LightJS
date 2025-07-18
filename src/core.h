#include "../engine/quickjs.h"
#include "../engine/list.h"
#include "../engine/cutils.h"
#include "utils.h"

#include <sys/inotify.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>

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
typedef void (*EvWriteCallback)(EvFD* evfd, bool success, void* opaque);
typedef void (*EvCloseCallback)(EvFD* fd, void* opaque);
typedef void (*EvINotifyCallback)(EvFD* fd, const char* path, uint32_t evtype, const char* move_to, void* user_data);
typedef void (*EvSyncCallback)(EvFD* evfd, bool success, void* user_data);
typedef void (*EvFinalizerCallback)(EvFD* evfd, struct Buffer* buffer, void* user_data);
typedef void (*EvTimerCallback)(uint64_t count, void* user_data);
typedef void (*EvSSLHandshakeCallback)(EvFD* evfd, void* user_data);
typedef bool (*EvPipeToFilter)(struct Buffer* buf, void* user_data);
typedef void (*EvPipeToNotify)(struct EvFD* from, struct EvFD* to, EvPipeToNotifyType type, void* user_data);
typedef void (*JSPromiseCallback)(JSContext* ctx, bool is_error, JSValue result, void* user_data);

typedef struct {
    char* key;
    char* value;
    struct list_head link;
} URL_query;

typedef struct{
    char *protocol;
    char *host;
    uint16_t port;
    char *path;
    struct list_head query; // URL_query
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

typedef struct {
    char* key;
    size_t keylen;
    char* value;
    size_t vallen;

    struct list_head link;
} LHttpHeader;

/* forward */ typedef struct LHTTPData LHTTPData;
struct LHTTPData {
    EvFD* fd;
    bool is_client; // read data from client or server
    HTTP_rw_state state;

    bool __read_all;    // internal use only

    char *method;
    uint16_t status;
    float version;
    char* path;

    struct list_head headers;

    bool chunked;
    ssize_t content_length;
    size_t content_resolved;
    bool deflate;

    void (*cb)(LHTTPData* data, uint8_t* buffer, uint32_t size, void* userdata);
    void* userdata;

    bool __header_owned; // internal use only
};

#define PUT_HEADER(hdstruct, _key, _value) { \
    LHttpHeader* h = js_malloc(ctx, sizeof(LHttpHeader)); \
    h -> key = _key; h -> keylen = strlen(_key); \
    h -> value = _value; h -> vallen = strlen(_value); \
    list_add_tail(&h -> link, &(hdstruct) -> headers); \
}

#define PUT_HEADER2(hdstruct, _key, _value) { \
    LHttpHeader* h = malloc2(sizeof(LHttpHeader)); \
    h -> key = _key; h -> keylen = strlen(_key); \
    h -> value = _value; h -> vallen = strlen(_value); \
    list_add_tail(&h -> link, &(hdstruct) -> headers); \
}

#define PUT_HEADER_DUP(hdstruct, _key, _value) \
    PUT_HEADER((hdstruct), js_strdup(ctx, _key), js_strdup(ctx, _value));

#define FIND_HEADERS(hdstruct, _key, varname, callback){ \
    struct list_head *__cur, *__tmp; \
    list_for_each_safe(__cur, __tmp, &(hdstruct) -> headers) { \
        LHttpHeader* varname = list_entry(__cur, LHttpHeader, link); \
        if(NULL == _key || memcmp(varname -> key, _key, varname -> keylen) == 0) callback \
    } \
}

#define DEL_HEADER(header) \
    list_del(&header -> link); \
    js_free(ctx, header -> key); \
    js_free(ctx, header -> value); \
    js_free(ctx, header);

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

    char* script_path;
    char** argv;
    uint32_t argc;

    // module
    JSValue module_loader;
    JSValue module_format;

    // thread
    pthread_t thread;
    atomic_bool busy;                // is JS execution busy

    // (for thread_top app)
    atomic_int_fast64_t interrupt;   // interrupt current task, mostly for worker thread/sandbox
                                     // if <0, interrupt immediately, otherwise, interrupt after given clocktick
    JSValue tick_func;               // if not interrupted, call this function in each tick
} App;

typedef struct SignalEvent {
    int sig;                    /* signal number */
    JSValue handler;            /* JS callback function */
    struct list_head link;      /* list linkage */
} SignalEvent;

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

typedef void (*HTTP_Callback)(LHTTPData* data, uint8_t* buffer, uint32_t size, void* userdata);
typedef void (*HTTP_ParseCallback)(LHTTPData *data, uint8_t *buffer, uint32_t len, void* ptr);
typedef void (*DnsResponseCallback)(int total_records, dns_record** records, void* user_data);
typedef void (*DnsErrorCallback)(const char* error_msg, void* user_data);

// Core events
bool js_dispatch_global_event(JSContext *ctx, const char * name, JSValue data);

// console
void js_dump(JSContext *ctx, JSValueConst val, EvFD* target_fd);
void js_handle_promise_reject(
    JSContext *ctx, JSValue promise,
    JSValue reason,
    bool is_handled, void *opaque
);

// exports
extern EvFD *pstdin, *pstdout, *pstderr;
bool LJS_init_global_helper(JSContext *ctx);
bool LJS_init_vm(JSContext *ctx);
bool LJS_init_console(JSContext *ctx);
bool LJS_init_pipe(JSContext *ctx);
bool LJS_init_http(JSContext *ctx);
bool LJS_init_module(JSContext *ctx);
void LJS_init_runtime(JSRuntime* rt);
bool LJS_init_fs(JSContext *ctx);
bool LJS_init_process(JSContext* ctx, uint32_t _argc, char** _argv);
bool LJS_init_socket(JSContext* ctx);
void LJS_init_timer(JSContext* ctx);

// Core I/O Pipe
JSValue LJS_NewFDPipe(JSContext *ctx, int fd, uint32_t flag, uint32_t buf_size, bool iopipe, EvFD** ref);
JSValue LJS_NewU8Pipe(JSContext *ctx, uint32_t flag, uint32_t buf_size, PipeCallback poll_cb, PipeCallback write_cb, PipeCallback close_cb, void* user_data);
JSValue LJS_NewPipe(JSContext *ctx, uint32_t flag, PipeCallback poll_cb, PipeCallback write_cb, PipeCallback close_cb, void* user_data);
EvFD* LJS_GetPipeFD(JSContext *ctx, JSValueConst obj);

// Core event loop
bool evcore_init();
bool evcore_run(bool (*evloop_abort_check)(void* user_data), void* user_data);
void evcore_destroy();
EvFD* evcore_attach(int fd, bool use_aio, EvReadCallback rcb, void* read_opaque, EvWriteCallback wcb, void* write_opaque, EvCloseCallback ccb, void* close_opaque);
EvFD* evfd_new(int fd, bool use_aio, bool readable, bool writeable, uint32_t bufsize, EvCloseCallback close_callback, void* close_opaque);
void evfd_setup_udp(EvFD* evfd);
bool evfd_read(EvFD* evfd, uint32_t buf_size, uint8_t* buffer, EvReadCallback callback, void* user_data);
bool evfd_readsize(EvFD* evfd, uint32_t buf_size, uint8_t* buffer, EvReadCallback callback, void* user_data);
bool evfd_readline(EvFD* evfd, uint32_t buf_size, uint8_t* buffer, EvReadCallback callback, void* user_data);
bool evfd_write(EvFD* evfd, const uint8_t* data, uint32_t size, EvWriteCallback callback, void* user_data);
bool evfd_write_dgram(EvFD* evfd, const uint8_t* data, uint32_t size, const struct sockaddr *addr, socklen_t addr_len, EvWriteCallback callback, void* user_data);
bool evfd_pipeTo(EvFD* from, EvFD* to, EvPipeToFilter filter, void* fopaque, EvPipeToNotify notify, void* nopaque);
bool evfd_close(EvFD* evfd);
bool evfd_close2(EvFD* evfd);
bool evfd_override(EvFD* evfd, EvReadCallback rcb, void* read_opaque, EvWriteCallback wcb, void* write_opaque, EvCloseCallback ccb, void* close_opaque);
bool evfd_wait(EvFD* evfd, bool wait_read, EvSyncCallback cb, void* opaque);
bool evfd_wait2(EvFD* evfd, EvSyncCallback cb, void* opaque);
bool evfd_shutdown(EvFD* evfd); // note: read all and then close
bool evfd_closed(EvFD* evfd);
bool evfd_clearbuf(EvFD* evfd);
bool evfd_onclose(EvFD* fd, EvCloseCallback callback, void* user_data);
bool evfd_finalizer(EvFD* evfd, EvFinalizerCallback callback, void* user_data);
int evfd_getfd(EvFD* evfd, int* timer_fd);
bool evfd_seek(EvFD* evfd, int seek_type, off_t pos);
bool evfd_yield(EvFD* evfd, bool yield_read, bool yield_write);
bool evfd_consume(EvFD* evfd, bool consume_read, bool consume_write);
bool evfd_isAIO(EvFD* evfd);
void* evfd_get_opaque(EvFD* evfd);
void evfd_set_opaque(EvFD* evfd, void* opaque);
bool evfd_syncexec(EvFD* pipe);
#ifdef LJS_MBEDTLS
bool evfd_initssl(EvFD* evfd, mbedtls_ssl_config** config, bool is_client, int preset, EvSSLHandshakeCallback handshake_cb, void* user_data);
void evfd_set_sni(char* name, char* server_name, mbedtls_x509_crt* cacert, mbedtls_pk_context* cakey);
bool evfd_remove_sni(const char* name);
bool evfd_initdtls(EvFD* evfd, mbedtls_ssl_config** _config);
#endif
EvFD* evcore_setTimeout(uint64_t milliseconds, EvTimerCallback callback, void* user_data);
EvFD* evcore_interval(uint64_t milliseconds, EvTimerCallback callback, void* cbopaque, EvCloseCallback close_cb, void* close_opaque);
bool evcore_clearTimer(int timer_fd);
bool evcore_clearTimer2(EvFD* evfd);
EvFD* evcore_inotify(EvINotifyCallback callback, void* user_data);
bool evcore_stop_inotify(EvFD* evfd);
bool evcore_inotify_watch(EvFD* evfd, const char* path, uint32_t mask, int* wd);
bool evcore_inotify_unwatch(EvFD* evfd, int wd);
int evcore_inotify_find(EvFD* evfd, const char* path);

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
bool LJS_parse_url(const char *url, URL_data *url_struct, URL_data *base);
void LJS_free_url(URL_data *url_struct);
char* LJS_format_url(URL_data *url_struct);
JSValue LJS_NewResponse(JSContext *ctx, LHTTPData *data, bool readonly);
void LJS_parse_from_fd(EvFD* fd, LHTTPData *data, bool is_client, HTTP_ParseCallback callback, void *userdata);
JSValue LJS_NewWebSocket(JSContext *ctx, EvFD* fd, bool enable_mask);
JSValue LJS_NewWebSocket(JSContext *ctx, EvFD* fd, bool enable_mask);

// module
uint8_t *LJS_tryGetJSFile(uint32_t *pbuf_len, char **filename);

// threads
void LJS_DestroyApp(App* app);
App* LJS_NewApp(
    JSRuntime* rt,
    uint32_t argc, char** argv,
    bool worker, bool module, char* script_path,
    App* parent
);
void LJS_init_context(App* app);
App* LJS_NewWorker(App* parent, char* script_path);
bool LJS_init_thread(JSContext* ctx);
char* js_resolve_module(JSContext* ctx, const char* module_name);
void js_set_import_meta(JSContext* ctx, JSValue func, const char* modname, bool main);

// ffi
bool LJS_init_ffi(JSContext *ctx);

// xml
bool LJS_init_xml(JSContext* ctx);

// crypto
bool LJS_init_crypto(JSContext *ctx);

// finalizer
void __js_destroy_process(JSContext* ctx);

// --------------- HELPER FUNCTIONS ------------------------
void free_js_malloc(JSRuntime *rt, void *opaque, void *ptr);
void free_malloc(JSRuntime* rt, void* opaque, void* ptr);
void base64_decode(const char *input, size_t len, uint8_t *output, size_t *output_len);
void base64_decode(const char *input, size_t len, uint8_t *output, size_t *output_len);
void base64_encode(const uint8_t *input, size_t len, char *output);

typedef struct promise Promise;

Promise* __js_promise(JSContext *ctx, const char* __debug__);
void __js_resolve(struct promise* proxy, JSValue value, const char* __debug__);
void __js_reject(struct promise* proxy, const char* msg, const char* __debug__);
void __js_reject2(struct promise* proxy, JSValue value, const char* __debug__);

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define js_promise(ctx) __js_promise(ctx, __FILE__ ":" TOSTRING(__LINE__))
#define js_resolve(proxy, value) __js_resolve(proxy, value, __FILE__ ":" TOSTRING((__LINE__)))
#define js_reject(proxy, msg) __js_reject(proxy, msg, __FILE__ ":" TOSTRING(__LINE__))
#define js_reject2(proxy, value) __js_reject2(proxy, value, __FILE__ ":" STRINGIFY(__LINE__))
JSValue js_get_promise(Promise* promise);
JSContext* js_get_promise_context(struct promise* proxy);

JSValue JS_CallSafe(JSContext *ctx, JSValueConst func_obj, JSValueConst this_val, int argc, JSValueConst *argv, bool* is_exception);
#define JS_CallOrHandle(ctx, func_obj, this_val, argc, argv) if(!JS_IsUninitialized(JS_CallSafe(ctx, func_obj, this_val, argc, argv, NULL))

// override malloc, free, realloc
void* malloc2(size_t size);
void free2(void* ptr);
void* realloc2(void* ptr, size_t size);

static inline void* strndup2(const char* str, size_t n){
    void* memory = malloc2(n + 1);
    memcpy(memory, str, n);
    ((char*)memory)[n] = '\0';
    return memory;
}

static inline void* strdup2(const char* str){
    return strndup2(str, strlen(str));
}

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

#ifndef MAX_OUTPUT_LEN
#define MAX_OUTPUT_LEN 1024
#endif

static __maybe_unused void __write_cb(EvFD* evfd, bool success, void* opaque){
    free2(opaque);
}

static inline int __fputs(const char* str, EvFD* fd){
    char* str2 = strdup2(str);
    if(!str2) return -1;
#ifdef LJS_DEBUG
    write(evfd_getfd(fd, NULL), str2, strlen(str2));
#else
    if(evfd_closed(fd)){
        write(evfd_getfd(fd, NULL), str2, strlen(str2));
    }else{
        evfd_write(fd, (uint8_t*)str2, strlen(str2), __write_cb, str2);
    }
#endif
    return 0;
}

static inline int __fputc(char chr, EvFD* fd){
    char* str = strndup2((char*)&chr, 1);
    __fputs(str, fd);
    return 0;
}

__attribute__((format(printf, 2, 3)))
static inline int __fprintf(EvFD* fd, const char* fmt, ...){
    char* buf = malloc2(MAX_OUTPUT_LEN);
    if(!buf) return -1;
    va_list args;
    va_start(args, fmt);
    int olen = snprintf(buf, MAX_OUTPUT_LEN, fmt, args);
    va_end(args);

    if(olen == -1){
        free(buf);
        return -1;
    }
    
    __fputs(buf, fd);
    return olen;
}

#ifdef __GNUC__
#pragma GCC diagnostic error "-Wformat-nonliteral"
#endif