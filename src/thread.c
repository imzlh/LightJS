/**
 * Control the behavior of each thread created by the engine.
 * Provide toolkits to better code multi-threading.
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

#include "core.h"
#include "polyfill.h"
#include "../engine/quickjs.h"

#include <pthread.h>
#include <signal.h>
#ifndef L_NO_THREADS_H
#include <threads.h>
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <semaphore.h>
#include <sys/stat.h>

#ifdef __CYGWIN__
#include "../deps/wepoll/wepoll.h"
#else
#include <sys/epoll.h>
#include <sys/eventfd.h>
#endif

#ifdef LJS_LIBFFI
#include <ffi.h>
#endif

#ifdef LJS_MBEDTLS
#include <mbedtls/version.h>
#include <mbedtls/base64.h>
#endif

#ifdef LJS_LIBEXPAT
#include <expat.h>
#endif

#ifdef LJS_ZLIB
#include <zlib.h>
#endif

#define BUFFER_SIZE 64 * 1024
#define HASH_TABLE_SIZE 26
#define EVENT_MAX_LISTENER 16

static thread_local JSRuntime* g_runtime = NULL;
static thread_local bool catch_error = false; 
static thread_local JSValue g_eventbus = JS_UNDEFINED;

// eventfd polyfill
#ifdef __CYGWIN__
#define evfd_t int64_t
#define EVPIPE_READABLE_FD(evfd) (evfd) >> 32
#define EVPIPE_WRITABLE_FD(evfd) (evfd) & UINT32_MAX

typedef uint64_t eventfd_t;

#define EFD_SEMAPHORE 1
#define EFD_CLOEXEC O_CLOEXEC
#define EFD_NONBLOCK O_NONBLOCK

static inline evfd_t eventfd(unsigned int, int flags){
    int fds[2];
    if(-1 == pipe2(fds, flags)) return -1;
    return fds[1];
}

int eventfd_read(evfd_t fd, eventfd_t * value){
    int* fds = (void*)&fd;
    return read(fds[0], value, sizeof(eventfd_t));
}

int eventfd_write(evfd_t fd, eventfd_t value){
    int* fds = (void*)&fd;
    return write(fds[1], &value, sizeof(eventfd_t)) == sizeof(eventfd_t);
}
#else
#define evfd_t int
#define EVPIPE_READABLE_FD(fd) fd
#define EVPIPE_WRITABLE_FD(fd) fd
#endif

// predef 
static inline JSModuleDef* module_getdef2(JSContext* ctx, JSValueConst this_val);

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
    free(filename);
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

#ifdef LJS_DEBUG
    printf("resolve module: %s, base=%s\n", module_name, module_base_name);
#endif

    if(JS_IsFunction(ctx, app -> module_format)){
        JSValue argv[2] = {
            JS_NewString(ctx, module_name),
            JS_NewString(ctx, module_base_name)
        };
        JSValue ret = JS_Call(ctx, app -> module_format, JS_UNDEFINED, 2, argv);
        for(int i = 0; i < 2; i ++) JS_FreeValue(ctx, argv[i]);
        if(JS_IsException(ret)){
            LJS_ThrowWithError(ctx, "failed to resolve module format", NULL);
            return NULL;
        }
        if(JS_IsString(ret)){
            const char* modpath = JS_ToCString(ctx, ret);
            char* modpath_dup = js_strdup(ctx, modpath);
            JS_FreeCString(ctx, modpath);
            JS_FreeValue(ctx, ret);
            return modpath_dup;
        }else{
            LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invaild return value of custom module format",
                "return value must be a string(module name or path) contains module format.");
            JS_FreeValue(ctx, ret);
            return NULL;
        }
    }else if(module_name[0] == '.'){
        char* module_name_path = LJS_resolve_path(module_name, module_base_name);
        if(!resolve_module_path(&module_name_path)){
#ifdef LJS_DEBUG
            printf("resolve module path: E: %s\n", module_name);
#endif
            LJS_Throw(ctx, EXCEPTION_IO, "failed to resolve module %s: %s", NULL, module_name, strerror(errno));
            free(module_name_path);
            return NULL;
        }

        char rp[1024];
        char* module_path = realpath(module_name_path, (char*)&rp);
        free(module_name_path);
        return js_strdup(ctx, module_path);
    }else{
        return js_strdup(ctx, module_name);
    }
}

// ? use libcurl instead ?
static char* simple_sync_http_request(JSContext* ctx, URL_data* url, uint32_t* pbuf_len){
    // limit: host、path length < 1000
    if(!url -> host || strlen(url -> host) > 1000 || (url -> path && strlen(url -> path) > 1000)){
        LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invaild or too long URL", NULL);
        return NULL;
    }

    // resolve host
    struct addrinfo *res;
    if(-1 == getaddrinfo(url -> host, NULL, NULL, &res)){
        LJS_Throw(ctx, EXCEPTION_IO, "getaddrinfo failed: %s", NULL, gai_strerror(errno));
        return NULL;
    }

    // find ipv4/ipv6 address
    struct addrinfo *v4addr = NULL, *v6addr = NULL;
    for(struct addrinfo *ai = res; ai; ai = ai -> ai_next){
        if(ai -> ai_family == AF_INET){
            v4addr = ai;
        }else if(ai -> ai_family == AF_INET6){
            v6addr = ai;
        }
    }

    int socket_fd = 0;
    if(v6addr){
        socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
        connect(socket_fd, (struct sockaddr*)v6addr -> ai_addr, v6addr -> ai_addrlen);
    }else if(v4addr){
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        connect(socket_fd, (struct sockaddr*)v4addr -> ai_addr, v4addr -> ai_addrlen);
    }else{
        LJS_Throw(ctx, EXCEPTION_IO, "no valid address found", NULL);
        freeaddrinfo(res);
        return NULL;
    }
    freeaddrinfo(res);

    // write body
    char buf[1024];
#define W(text, ...) { \
        int n = snprintf(buf, 1024, text, __VA_ARGS__); \
        if(-1 == write(socket_fd, buf, n)) goto error1; \
}
#define WD(text) { \
        int n = strlen(text); \
        if(-1 == write(socket_fd, text, n)) goto error1; \
}
    if(false){
error1:
        close(socket_fd);
        LJS_Throw(ctx, EXCEPTION_IO, "write failed: %s", NULL, strerror(errno));
        return NULL;
    }

    W("GET %s HTTP/1.1\r\n", url -> path);
    W("Host: %s\r\n", url -> host);
    WD("Connection: close\r\n");
    WD("\r\n");

    // read response
    FILE* f = fdopen(socket_fd, "r");
    int state = HTTP_FIRST_LINE;
    size_t content_length = 0;
    char* readed;
    const char* edesc = "unknown error";
    char* body = NULL;
    while ((readed = fgets(buf, 1024, f)) != NULL){
        switch (state){
            case HTTP_FIRST_LINE:{
                int hv2, st1, st2, st3;
                if(-1 == sscanf(readed, "HTTP/1.%d %d%d%d", &hv2, &st1, &st2, &st3)){
                    goto error2;
                }
                if(hv2 > 1){
                    edesc = "unsupported HTTP version";
                    goto error2;
                }
                if(st1 != 2 || st2 != 0 || st3 != 0){
                    edesc = "http not ok(200)";
                    goto error2;
                }

                state = HTTP_HEADER;
                break;
            }

            case HTTP_HEADER:{
                if(readed[0] == '\r' && readed[1] == '\n'){
                    state = HTTP_BODY;
                    goto read_body;
                }else{
                    char* key = readed;
                    char* value = strchr(key, ':');
                    if(!value){
                        edesc = "invaild header line";
                        goto error2;
                    }

                    *value = '\0';
                    if(strcasecmp(key, "Content-Length") == 0){
                        do{ value ++; } while(*value == ' ');
                        content_length = atoi(value);
                    }
#ifdef LJS_DEBUG
                    else{
                        printf("header: %s\n", key);
                    }
#endif
                    break;
                }
            }

            default:
error2:
                fclose(f);
                LJS_Throw(ctx, EXCEPTION_INPUT, "invaild response from server: %s", NULL, edesc);
                return NULL;
        }
    }

read_body:
    // read whole body
    if(content_length <= 0){
        edesc = "no content found in response";
        goto error2;
    }
    
    size_t readed_len = 0;
    body = js_malloc(ctx, content_length + 1);
    if(!body){
        fclose(f);
        JS_ThrowOutOfMemory(ctx);
        return NULL;
    }

    while (readed_len < content_length){
        ssize_t r = fread(body + readed_len, 1, content_length - readed_len, f);
        if(r <= 0){
            js_free(ctx, body);
            fclose(f);
            LJS_Throw(ctx, EXCEPTION_IO, "read failed: %s", NULL, errno ? strerror(errno) : "reached end of file");
            return NULL;
        }
        readed_len += r;
    }
    body[content_length] = '\0';
    *pbuf_len = content_length;
    fclose(f);
    return body;
}

static inline size_t urldecode(const char *src, size_t src_len, uint8_t *dst) {
    size_t i, j = 0;
    for (i = 0; i < src_len; i++) {
        if (src[i] == '%' && i + 2 < src_len && isxdigit((unsigned char)src[i+1]) && isxdigit((unsigned char)src[i+2])) {
            uint8_t hi = src[i+1];
            uint8_t lo = src[i+2];
            hi = hi <= '9' ? hi - '0' : (hi & 0x0F) + 9; // 处理16进制
            lo = lo <= '9' ? lo - '0' : (lo & 0x0F) + 9;
            dst[j++] = (hi << 4) | lo;
            i += 2;
        } else if (src[i] == '+') {
            dst[j++] = ' ';
        } else {
            dst[j++] = src[i];
        }
    }
    return j;
}

static int parse_data_url(const char *url, 
                   char **mime_type, 
                   uint8_t **data, 
                   size_t *data_len) {
    if (strncmp(url, "data:", 5) != 0) return -1;
    const char *comma = strchr(url, ',');
    if (!comma) return -1;

    const char *header_start = url + 5;
    size_t header_len = comma - header_start;
    char *header = malloc(header_len + 1);
    memcpy(header, header_start, header_len);
    header[header_len] = '\0';

    int is_base64 = 0;
    char *base64_ptr = strstr(header, ";base64");
    if (base64_ptr) {
        is_base64 = 1;
        *base64_ptr = '\0'; // 截断base64标记
    }
    *mime_type = header[0] ? strdup(header) : strdup("text/plain;charset=US-ASCII");
    free(header);

    const char *data_part = comma + 1;
    size_t data_part_len = strlen(data_part);

    if (is_base64) {
        size_t max_len = (data_part_len + 3) / 4 * 3;
        *data = malloc(max_len +1);
        *data_len = max_len; // 输入输出参数
        base64_decode(data_part, data_part_len, *data, data_len);
        (*data)[*data_len] = '\0';
    } else {
        *data = malloc(data_part_len +1);
        *data_len = urldecode(data_part, data_part_len, *data);
        (*data)[*data_len] = '\0';
    }

    return 0;
}

static JSModuleDef *js_module_loader(JSContext *ctx,
                              const char *_modname, void *opaque)
{
    JSModuleDef *m;
    char* buf = NULL;
    uint32_t buf_len;
    App* app = JS_GetContextOpaque(ctx);
    bool use_loader = JS_IsFunction(ctx, app -> module_loader);
    const char* module_name = NULL;
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
            const char* tmp = JS_ToCStringLen(ctx, &__len, ret);
            buf = strdup(tmp);
            buf_len = __len;
            JS_FreeValue(ctx, ret);
            JS_FreeCString(ctx, tmp);
            use_loader = false; // use default meta loader
            goto compile;
        }else if((m = module_getdef2(ctx, ret)) != NULL){
            goto set_meta;
        }else{
            LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invaild return value of custom module loader",
                "return value must be a string(module name or path) or a module object.");
            JS_FreeValue(ctx, ret);
            return NULL;
        }
    }

    // 默认加载器
    JSValue func_val;
    URL_data url = {0};
    if(!LJS_parse_url(_modname, &url, NULL)){
        LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid module URL: %s", NULL, _modname);
        return NULL;
    }
    free_url = true;

    if(!url.protocol || memcmp(url.protocol, "file", 5)){
        buf = (char*)read_file(url.path, &buf_len);
        if (!buf){
            LJS_Throw(ctx, EXCEPTION_NOTFOUND, "Read file failed: %s", NULL, strerror(errno));
            return NULL;
        }
    }else if(memcmp(url.protocol, "http", 5) == 0){
        buf = simple_sync_http_request(ctx, &url, &buf_len);
        if(!buf){
            return NULL;
        }
    // TODO: https stream?
    }else{
        LJS_Throw(ctx, EXCEPTION_TYPEERROR, "%s protocol is not supported", NULL, url.protocol);
        return NULL;
    }
    module_name = url.path;

compile:
    /* compile the module */
    func_val = JS_Eval(ctx, buf, buf_len, _modname,
        JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (JS_IsException(func_val))
        return NULL;

    // import meta
    m = JS_VALUE_GET_PTR(func_val);
set_meta:;
    JSValue meta_obj = JS_GetImportMeta(ctx, m);
    JS_DefinePropertyValueStr(ctx, meta_obj, "name",
        JS_NewString(ctx, module_name),
        JS_PROP_C_W_E);
    if (!use_loader) {
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

    // load source mapping?
#ifdef LJS_FEATURE_SOURCE_MAP
    if(use_loader){
        char* mname = NULL;
        if(module_name){
            mname = js_strdup(ctx, module_name);
        }else{
            JSValue meta = JS_MKPTR(JS_TAG_MODULE, m);
            JSValue name = JS_GetPropertyStr(ctx, meta, "name");
            const char* modname = JS_ToCString(ctx, name);
            JS_FreeValue(ctx, name);
            if(modname){
                module_name = js_strdup(ctx, modname);
                JS_FreeCString(ctx, modname);
            }
        }

        if(js_has_sourcemap(mname)) goto finalizer;

        // find sourcemap url
        // find last sourceMappingURL comment
        char* last_comment = NULL;
        char* p = buf;
        while((p = strstr(p, "//# sourceMappingURL=")) != NULL) last_comment = p;
        if(last_comment){
            last_comment += 21;

            // parse
            char* sourcemap = NULL;
            if(memcmp(last_comment, "data:", 5) == 0){
                // parse data url
                char* mime_type = NULL;
                size_t data_len = 0;
                if(parse_data_url(last_comment, &mime_type, (void*)&sourcemap, &data_len) != 0){
                    goto finalizer;
                }
            }else{
                URL_data url = {0}, base = {0};
                LJS_parse_url(mname, &base, NULL);
                if(!LJS_parse_url(last_comment, &url, &base)){
                    goto finalizer;
                }
                if(!url.protocol || memcmp(url.protocol, "file", 5) == 0){
                    // read from file
                    sourcemap = (char*)read_file(url.path, &buf_len);
                }else{
                    sourcemap = simple_sync_http_request(ctx, &url, &buf_len);
                }
            }
            js_load_sourcemap_cjson(ctx, mname, sourcemap);
        }

finalizer:
        js_free(ctx, mname);
    }
#endif

    if(buf) free(buf);
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
    return JS_ThrowReferenceError(ctx, "require() is not supported in LightJS");
}

bool LJS_init_module(JSContext *ctx){
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JSValue func_require = JS_NewCFunction(ctx, js_require, "require", 1);
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

struct Worker_Props{
    EvFD* efd_worker2main;
    evfd_t fd_worker2main;
    EvFD* efd_main2worker;
    evfd_t fd_main2worker;

    JSValue main_msgcb;  // for main thread
    JSValue destroy_cb;  // for main thread
    Worker_Error* error; // for main thread

    // write queue, in worker for main thread and worker thread
    struct list_head main_msg;      // main thread message(worker to main)
    struct list_head worker_msg;    // worker thread message(main to worker)
    pthread_mutex_t lock;

    App* parent;
    bool exiting;           // pthread_join is pending
    sem_t destroy_sem;      // in main thread, wait for worker thread to exit
};

static void worker_run_jobs(App* app){
    int jobs = 0;
    JSRuntime* rt = JS_GetRuntime(app -> ctx);

    do{
        jobs = js_run_promise_jobs();  // thread-local jobs

        int res = 1;
        JSContext* ectx;
        while(likely(res = JS_ExecutePendingJob(rt, &ectx))){
            jobs ++;
            if(res < 0){    // error
                JSValue exception = JS_GetException(ectx);
                if(unlikely(JS_IsInternalError(ectx, exception))){
                    app -> worker -> exiting = true;
                }
                JS_FreeValue(ectx, exception);
            }
        }
#ifdef LJS_DEBUG
        printf("run jobs: %d\n", jobs);
#endif
    }while(jobs);
}

// Note: in worker thread
__attribute__((noreturn))
static inline void worker_exit(App* app, int code, const char* message){
    Worker_Error* error = (Worker_Error*)malloc(sizeof(Worker_Error));
    error -> message = (char*)message;
    error -> code = code;

    JSRuntime* rt = JS_GetRuntime(app -> ctx);
    evcore_destroy();
    worker_run_jobs(app);
    JS_FreeRuntime(rt);
    app -> busy = false;

    // exit thread
    sem_post(&app -> worker -> destroy_sem);
    pthread_exit((void*)error);
}

// static inline JSValue __copy_arraybuffer(JSContext* from, JSContext* to, JSValue val){
//     size_t psize;
//     uint8_t* data = JS_GetArrayBuffer(from, psize, val);
//     if(!data) return JS_UNDEFINED;
//     JS_DetachArrayBuffer(from, val);

//     JSValue ret = JS_NewArrayBuffer(to, )
// }

// static inline JSValue worker_copy_value(JSContext* from, JSContext* to, JSValue val){
//     if(JS_IsArrayBuffer(from, val)){

//     }
// }

static inline void push_message(App* from, App* to, struct list_head* list, JSValue arg){
    // clone arg
    // XXX: WebAPI: Transferable object
    JSValue obj = JS_CopyValue(from -> ctx, to -> ctx, arg);
    if(JS_IsException(obj)) return;

    struct WorkerMessage* msg = malloc(sizeof(struct WorkerMessage));
    msg -> arg = obj;
    
    pthread_mutex_t* lock = to -> worker
        ? &to -> worker -> lock
        : &from -> worker -> lock;
    pthread_mutex_lock(lock);
    list_add_tail(&msg -> list, list);
    pthread_mutex_unlock(lock);

    // notify target thread
    eventfd_write(to -> worker ? to -> worker -> fd_main2worker : from -> worker -> fd_worker2main, 1);
}


App* LJS_NewApp(
    JSRuntime* rt,
    uint32_t argc, char** argv,
    bool worker, bool module, char* script_path,
    App* parent
){
    if(!script_path) return NULL;
    JSContext* ctx = JS_NewContext(rt);
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
    app -> busy = false;
    app -> thread = pthread_self();
    app -> interrupt = 0;
    app -> tick_func = JS_UNDEFINED;

    init_list_head(&app -> workers);

    if(parent && worker){
        // worker props
        struct Worker_Props* wel = app -> worker = malloc(sizeof(struct Worker_Props));
        wel -> main_msgcb = JS_UNDEFINED;
        wel -> destroy_cb = JS_UNDEFINED;
        wel -> error = NULL;
        wel -> exiting = false;
        sem_init(&wel -> destroy_sem, 0, 0);

        // Add to parent's worker list
        init_list_head(&app -> workers);
        list_add_tail(&app -> link, &parent -> workers);

        // Create eventfd for worker-main communication
        evfd_t fd1 = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC),
            fd2 = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if(fd1 < 0 || fd2 < 0){
            perror("eventfd");
            goto failed;
        }

        // Message List
        init_list_head(&wel -> main_msg);
        init_list_head(&wel -> worker_msg);
        pthread_mutex_init(&wel -> lock, NULL);
        
        app -> worker -> fd_worker2main = fd1;
        app -> worker -> fd_main2worker = fd2;
        app -> worker -> parent = parent;
    }

    JS_SetContextOpaque(ctx, app);
    if(!parent || worker){
        JS_SetRuntimeOpaque(rt, app);
        if(!g_runtime) g_runtime = rt;
    }
    return app;

failed:
    LJS_DestroyApp(app);
    return NULL;
}

static inline void msglist_clear(JSContext* ctx, struct list_head* list){
    struct list_head* pos, *tmp;
    list_for_each_safe(pos, tmp, list){
        struct WorkerMessage* msg = list_entry(pos, struct WorkerMessage, list);
        JS_FreeValue(ctx, msg -> arg);
    }
}

// Note: this call will block until all the sub-workers exits
void LJS_DestroyApp(App* app) {
    if (!app) return;

    if (app -> worker) {
        struct Worker_Props* wel = app -> worker;
        if(wel -> efd_main2worker)
            evfd_close(wel -> efd_main2worker);
        
        // remove lock
        pthread_mutex_destroy(&wel -> lock);

        // free msgcallback
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
        
        list_del(&app -> link);
        free(wel);
    }

    // sandbox can be auto destroyed, however workers not.
    // Note: LJS can create sub-workers for workers
    if(!list_empty(&app -> workers)){
        struct list_head* pos, *tmp;
        list_for_each_safe(pos, tmp, &app -> workers){
            App* child = list_entry(pos, App, link);
            JSRuntime* rt = JS_GetRuntime(child -> ctx);
            child -> interrupt = -1;
            child -> worker -> exiting = true;
            sem_wait(&child -> worker -> destroy_sem);
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
        // destroy app
        __js_destroy_process(app -> ctx);

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
    LJS_DestroyApp(app);

    free(app -> script_path);
    if (app -> argv) {
        for (uint32_t i = 0; i < app -> argc; i++) {
            free(app -> argv[i]);
        }
        free(app -> argv);
    }
}

JSValue message_delay_run(JSContext* ctx, int argc, JSValue* argv){
    if(JS_VALUE_GET_TAG(argv[0]) == JS_TAG_INT)
        js_dispatch_global_event(ctx, JS_VALUE_GET_PTR(argv[0]), argv[1], false);
    else
        JS_FreeValue(ctx, JS_Call(ctx, argv[0], JS_UNDEFINED, 1, (JSValueConst[]){ argv[1] }));
    JS_FreeValue(ctx, argv[0]);
    JS_FreeValue(ctx, argv[1]);
    return JS_UNDEFINED;
}

static inline void callev_delay(JSContext* ctx, const char* name, JSValue arg){
    JS_EnqueueJob(ctx, message_delay_run, 2, (JSValueConst[]){ JS_MKPTR(JS_TAG_INT, (void*)name), arg });
}

static inline void call_delay(JSContext* ctx, JSValue func, JSValue arg){
    JS_EnqueueJob(ctx, message_delay_run, 2, (JSValueConst[]){ func, arg });
}

// for worker thread
static int worker_message_callback(EvFD* __, bool _, uint8_t* buffer, uint32_t read_size, void* user_data){
    App* app = (App*)user_data;
    uint64_t value;
    // Alert: main2worker eventfs should be closed by worker thread
    if(unlikely(-1 == eventfd_read(app -> worker -> fd_main2worker, &value)))
        return EVCB_RET_DONE;
        
    // process queue
    // dispatch global event in next tick
    pthread_mutex_lock(&app -> worker -> lock);
    // if(list_empty(&app -> worker -> main_msg)) abort();
    struct list_head* pos, * tmp;
    list_for_each_safe(pos, tmp, &app -> worker -> main_msg) {
        struct WorkerMessage* msg = list_entry(pos, struct WorkerMessage, list);
        list_del(&msg -> list);

        // call
        callev_delay(app -> ctx, "message", msg -> arg);
        free(msg);
    }
    pthread_mutex_unlock(&app -> worker -> lock);
    
    return EVCB_RET_DONE;
}

// for worker thread
static void worker_close_callback(EvFD* fd, bool _, void* user_data){
    struct Worker_Props* wel = ((App*)user_data) -> worker;
    evfd_close(wel -> efd_worker2main);
    worker_exit((App*)user_data, 0, "worker closed");
}

// for main thread
static int main_message_callback(EvFD* __, bool _, uint8_t* buffer, uint32_t read_size, void* opaque){
    App* app = (App*)opaque;    // worker APP, not main!

    uint64_t value;
    if(!read_size && unlikely(eventfd_read(app -> worker -> fd_worker2main, &value) == -1))
        return EVCB_RET_DONE;
        
    // read queue
    JSContext __maybe_unused *pctx = app -> worker -> parent -> ctx,
        *ctx = app -> ctx;
    if(!JS_IsUndefined(app -> worker -> main_msgcb)){

        pthread_mutex_lock(&app -> worker -> lock);
        // if(list_empty(&app -> worker -> main_msg)) abort();
        struct list_head* pos, *tmp;
        list_for_each_safe(pos, tmp, &app -> worker -> worker_msg){
            struct WorkerMessage* msg = list_entry(pos, struct WorkerMessage, list);
            list_del(&msg -> list);

            // dispatch global event in next tick
            call_delay(pctx, JS_DupValue(app -> ctx, app -> worker -> main_msgcb), msg -> arg);
            free(msg);
        }
        pthread_mutex_unlock(&app -> worker -> lock);
    }

    return EVCB_RET_DONE;
}

// for main thread
static void main_close_callback(EvFD* fd, bool _, void* user_data){
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
            JS_FreeValue(ctx, obj);
        }

        free(app -> worker -> error -> message);
        free(app -> worker -> error);
        free(space);
    }

    // close fd
    if(app -> worker -> efd_main2worker)
        evfd_close(app -> worker -> efd_main2worker);
    worker_free_app(app);
}


static bool worker_check_abort(void* opaque){
    App* app = (App*)opaque;
    app -> busy = true;
    worker_run_jobs(app);
    app -> busy = false;
    if(app -> worker -> exiting) return true;
    return false;
}

static inline void worker_exit_with_exception(App* app, JSValue exception) {
    JSContext* ctx = app -> ctx;
    JSValue error = JS_GetException(ctx);
    js_dump(ctx, error, pstderr);

    const char* message = JS_ToCString(ctx, error);
    char* space = malloc(strlen(message) + 39);
    memcpy(space, "Worker thread exited with exception: ", 37);
    memcpy(space + 37, message, strlen(message) + 1);
    JS_FreeValue(app -> ctx, error);
    JS_FreeValue(app -> ctx, exception);
    worker_exit((App*) JS_GetContextOpaque(ctx), 1, space);
}

void worker_boot_pipeevent(JSContext* ctx, bool is_error, JSValue result, void* user_data){
    App* app = user_data;
    if(is_error) worker_exit_with_exception(app, result);

    // start pipe
    app -> worker -> efd_worker2main = evcore_attach(
        EVPIPE_READABLE_FD(app -> worker -> fd_worker2main), false,
        worker_message_callback, app,
        NULL, NULL,
        worker_close_callback, app
    );

    // try to poll data
    // worker_message_callback(
    //     app -> worker -> efd_worker2main,
    //     true, NULL, 0, app
    // );
}

static void worker_main_loop(App* app, JSValue func){
    JSContext* ctx = app -> ctx;
    
    // prevent signal(only handled in main thread)
    sigset_t sigmask;
    sigfillset(&sigmask);
    sigdelset(&sigmask, SIGUSR1);
    sigdelset(&sigmask, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, NULL, &sigmask);

    // create evfd after script loaded(after top await)
    app -> worker -> efd_main2worker = NULL;

#ifdef LJS_DEBUG
    printf("Worker thread started: %s\n", app -> script_path);
#endif

    // call main func
    JSValue ret = JS_EvalFunction(ctx, func);
    if(JS_IsException(ret))
        worker_exit_with_exception(app, JS_GetException(ctx));

    js_run_promise_jobs();  // run before enqueue
    LJS_enqueue_promise_job(ctx, ret, worker_boot_pipeevent, app);

    // start eventloop
    evcore_run(worker_check_abort, app);

    // exit
    worker_exit(app, 0, "worker thread exited");
}

static int js_interrupt_handler(JSRuntime *rt, void *opaque){
    App* app = JS_GetRuntimeOpaque(rt);
    if(app -> interrupt <= 0){
        return !!app -> interrupt;
    }

    if(!JS_IsUndefined(app -> tick_func)){
        JSValue ret = JS_Call(app -> ctx, app -> tick_func, JS_UNDEFINED, 0, NULL);
        if(JS_ToBool(app -> ctx, ret)){
            // return true to break code execution
            JS_FreeValue(app -> ctx, ret);
            return true;
        }
        return false;
    }

    // time
    clock_t current = clock();
    return current >= app -> interrupt;
}

#ifdef LJS_FEATURE_SOURCE_MAP
static void js_backtrace_filter(int* row, int* col, const char* fname){
    MappingResult mr = js_get_source_mapping(fname, *row, *col);
    if(!mr.found) return;
    *row = mr.original_line;
    *col = mr.original_column;
}
#endif

void LJS_init_runtime(JSRuntime* rt){
    // Promise logger
    JS_SetHostPromiseRejectionTracker(rt, js_handle_promise_reject, NULL);

    // ES module loader
    JS_SetModuleLoaderFunc(rt, js_module_format, js_module_loader, NULL);

    // atomic.wait()
    JS_SetCanBlock(rt, true);

    // tick function
    JS_SetInterruptHandler(rt, js_interrupt_handler, NULL);
    
#ifdef LJS_FEATURE_SOURCE_MAP
    JS_SetBackTraceFilter(rt, js_backtrace_filter);
#endif

#ifdef LJS_DEBUG
    JS_SetDumpFlags(rt, JS_DUMP_LEAKS | JS_DUMP_OBJECTS | JS_DUMP_SHAPES);
    JS_SetMaxStackSize(rt, 0);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
#endif
}

// static bool in(char** arr, const char* str){
//     for(int i = 0; arr[i]; i++){
//         if(strcmp(arr[i], str) == 0) return true;
//     }
//     return false;
// }

void LJS_init_context(App* app) {
    JSContext* ctx = app -> ctx;
    LJS_init_pipe(ctx);
    LJS_init_socket(ctx);
    LJS_init_process(ctx, app -> argc, app -> argv);
    LJS_init_thread(ctx);

    LJS_init_fs(ctx);
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
    g_runtime = JS_GetRuntime(app -> ctx);
    LJS_init_context(app);

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
    app -> busy = true;
    JSValue func = JS_Eval(app -> ctx, (char*)buf, buf_len, app -> script_path, flag);
    free(buf);

    if(JS_IsException(func)){
        JSValue exception = JS_GetException(app -> ctx);
        js_dump(app -> ctx, exception, pstderr);
        JS_FreeValue(app -> ctx, exception);
        worker_exit(app, 1, "eval script failed");
    }

    // import.meta
    if(app -> module){
        js_set_import_meta(app -> ctx, func, raw_name, true);
    }
    js_free(app -> ctx, raw_name);

    worker_main_loop(app, func);
    JS_FreeValue(app -> ctx, func);

    return NULL;
}

static char** arg_dup(int argc, char** argv){
    char** new_argv = malloc(sizeof(char*) * (argc + 1));
    for(int i = 0; i < argc; i++){
        new_argv[i] = strdup(argv[i]);
    }
    new_argv[argc] = NULL;
    return new_argv;
}

static JSValue launch_worker(JSContext* ctx, int argc, JSValue* argv){
    App* app = JS_VALUE_GET_PTR(argv[0]);
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if(0 != pthread_create(&thread, &attr, worker_entry, app)){
        LJS_DestroyApp(app);
    }
    return JS_UNDEFINED;
}

/**
 * Create a new worker thread.
 * Note: script_path will be freed by LJS_destroy_app.
 * @param parent 父进程的App
 */
App* LJS_NewWorker(App* parent, char* script_path){
    JSRuntime* rt = JS_NewRuntime();
    App* app = LJS_NewApp(
        rt, 
        parent -> argc, arg_dup(parent -> argc, parent -> argv),
        true, false, script_path, parent
    );
    LJS_init_runtime(rt);
    JS_CopyRuntimeArgs(JS_GetRuntime(parent -> ctx), rt);

// #ifdef LJS_DEBUG
//     JS_SetDumpFlags(rt, JS_DUMP_GC | JS_DUMP_LEAKS | JS_DUMP_PROMISE | JS_DUMP_OBJECTS);
// #endif

    // avoid thread-competeion
    JS_EnqueueJob(parent -> ctx, launch_worker, 1, (JSValueConst[]){ JS_MKPTR(JS_TAG_BOOL, app) });

    return app;
}

// class Worker
static thread_local JSClassID js_worker_class_id;
#define GET_APP(varname) App* varname = JS_GetOpaque(this_val, js_worker_class_id);\
    if(!varname) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Worker is destroyed", NULL);

static JSValue js_worker_close(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    App* app = JS_GetOpaque(this_val, js_worker_class_id);  // worker APP, not main!
    if(!app) return JS_UNDEFINED;

    // Note: close main-thread to worker pipe, but remain another to main-thread.
    if(app -> worker -> efd_worker2main)
        evfd_close(app -> worker -> efd_main2worker);
    app -> interrupt = -1;

    JS_SetOpaque(this_val, NULL);
    return JS_UNDEFINED;
}

static JSValue js_worker_send(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    GET_APP(app);

    if(argc == 0){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "postMessage requires at least one argument",
            "Worker.postMessage(message: any): void"
        );
    }

    // add to queue
    push_message((App*)JS_GetContextOpaque(ctx), app, &app -> worker -> worker_msg, argv[0]);
    return JS_UNDEFINED;
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

static JSValue js_worker_get_busy(JSContext* ctx, JSValueConst this_val){
    GET_APP(app);

    return JS_NewBool(ctx, app -> busy);
}

static JSValue js_worker_set_onmessage(JSContext* ctx, JSValueConst this_val, JSValueConst val){
    App* app = JS_GetOpaque2(ctx, this_val, js_worker_class_id);
    if(!app) return JS_EXCEPTION;
    if(!JS_IsUndefined(app -> worker -> main_msgcb))
        JS_FreeValue(ctx, app -> worker -> main_msgcb);
    app -> worker -> main_msgcb = JS_DupValue(ctx, val);

    // poll data?
    main_message_callback(app -> worker -> efd_worker2main, true, NULL, true, app);

    return JS_UNDEFINED;
}

static JSValue js_worker_get_onmessage(JSContext* ctx, JSValueConst this_val){
    App* app = JS_GetOpaque2(ctx, this_val, js_worker_class_id);
    if(!app) return JS_EXCEPTION;
    return JS_DupValue(ctx, app -> worker -> main_msgcb);
}

static JSValue js_worker_interrupt(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    GET_APP(app);

    double pre;
    if(argc == 0 || !JS_IsNumber(argv[0])){
        app -> interrupt = -1;
    }else{
        JS_ToFloat64(ctx, &pre, argv[0]);
        app -> interrupt = pre * CLOCKS_PER_SEC;
    }

    return JS_UNDEFINED;
}

static JSCFunctionListEntry js_worker_props[] = {
    JS_CGETSET_DEF("ondestroy", js_worker_get_ondestroy, js_worker_set_ondestroy),
    JS_CFUNC_DEF("terminate", 0, js_worker_close),
    JS_CFUNC_DEF("postMessage", 1, js_worker_send),
    JS_CGETSET_DEF("busy", js_worker_get_busy, NULL),
    JS_CFUNC_DEF("interrupt", 1, js_worker_interrupt),
    JS_CGETSET_DEF("onmessage", js_worker_get_onmessage, js_worker_set_onmessage),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Worker", JS_PROP_CONFIGURABLE),
};

static JSValue js_worker_ctor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    char* script_path;
    
    if(argc != 0){
        script_path = (char*)JS_ToCString(ctx, argv[0]);
    }else{
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Worker constructor takes 1 or 2 arguments",
            "Worker(script_path: string, opts = { ontick: undefined, module = true })"
        );
    }

    App* app = LJS_NewWorker((App*)JS_GetContextOpaque(ctx), strdup(script_path));

    app -> module = true;
    if(argc >= 2 && JS_IsObject(argv[1])){
        JSValue value;
        if(JS_IsFunction(ctx, value = JS_GetPropertyStr(ctx, argv[1], "ontick"))){
            app -> tick_func = JS_CopyValue(ctx, app -> ctx, value);
        }
        JS_FreeValue(ctx, value);
        if(JS_IsBool(JS_GetPropertyStr(ctx, argv[1], "module"))){
            app -> module = JS_ToBool(ctx, value);
        }
        JS_FreeValue(ctx, value);
    }

    // evloop
    app -> worker -> efd_worker2main =
        evcore_attach(
            EVPIPE_READABLE_FD(app -> worker -> fd_worker2main), false, 
            main_message_callback, app,
            NULL, NULL,
            main_close_callback, app
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

#define CHECK_WORKER_CTX(ctx) if(!is_worker_ctx(ctx)) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Worker is not available in this context", NULL);

static JSValue js_worker_static_postMessage(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    CHECK_WORKER_CTX(ctx);

    if(argc == 0){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Worker.postMessage takes 1 argument: message", "Worker.postMessage(message: any): void");
    }

    App* app = (App*)JS_GetContextOpaque(ctx);
    push_message(app, app -> worker -> parent, &app -> worker -> main_msg, argv[0]);
    return JS_UNDEFINED;
}

static JSValue js_worker_static_exit(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    CHECK_WORKER_CTX(ctx);
    App* app = (App*)JS_GetContextOpaque(ctx);

    int exit_code = 0;
    const char* message = "Worker.exit() called";
    if(argc != 0 && JS_IsNumber(argv[0])) JS_ToInt32(ctx, &exit_code, argv[0]);
    if(argc >= 2 && JS_IsString(argv[1])) message = JS_ToCString(ctx, argv[1]);

    JS_ThrowInternalError(ctx, " ");
    Worker_Error* error = (Worker_Error*)malloc(sizeof(Worker_Error));
    error -> message = (char*)message;
    error -> code = exit_code;
    app -> worker -> error = error;
    return JS_EXCEPTION;
}


static JSCFunctionListEntry js_worker_static_funcs[] = {
    JS_CFUNC_DEF("postMessage", 1, js_worker_static_postMessage),
    JS_CFUNC_DEF("exit", 0, js_worker_static_exit)
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
    JS_SetPropertyFunctionList(ctx, worker_ctor, js_worker_static_funcs, countof(js_worker_static_funcs));
    JS_DefinePropertyValueStr(ctx, worker_ctor, "isWorker", JS_NewBool(ctx, is_worker_ctx(ctx)), JS_PROP_CONFIGURABLE);

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

    if(timer -> once){
        JS_FreeValue(timer -> ctx, timer -> resolve);
        js_free(timer -> ctx, timer);
    }
}

static void timer_free_callback(EvFD* fd, bool _, void* ptr){
    struct Timer_T* timer = (struct Timer_T*)ptr;
    js_free(timer -> ctx, timer);
}

static JSValue js_timer_delay(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 1 || !JS_IsNumber(argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "delay takes 1 argument: delay_time", "delay(delay_time: number): Promise<void>");
    }

    JSValue promise_cb[2];
    JSValue promise = JS_NewPromiseCapability(ctx, promise_cb);
    struct Timer_T* timer = (struct Timer_T*)js_malloc(ctx, sizeof(struct Timer_T));
    timer -> ctx = ctx;
    timer -> resolve = promise_cb[0];
    timer -> once = true;

    uint32_t delay_time;
    if(-1 == JS_ToUint32(ctx, &delay_time, argv[0]) || delay_time == 0){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "delay takes a non-zero delay_time", NULL);
    }

    evcore_setTimeout(delay_time, timer_callback, timer);

    JS_FreeValue(ctx, promise_cb[1]);
    return promise;
}

static JSValue js_timer_timeout(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 2 || !JS_IsNumber(argv[1]) || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "setTimeout takes 2 argument", "setTimeout(callback: () => void, delay_time: number): number");
    }

    JSValue callback = JS_DupValue(ctx, argv[0]);
    uint32_t delay_time;
    if(-1 == JS_ToUint32(ctx, &delay_time, argv[1]) || delay_time == 0){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "setTimeout takes a non-zero delay_time", NULL);
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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "interval takes 2 argument", "interval(callback: () => void, interval_time: number): number");
    }

    JSValue callback = JS_DupValue(ctx, argv[0]);
    uint32_t interval_time;
    if(-1 == JS_ToUint32(ctx, &interval_time, argv[1]) || interval_time == 0){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "interval takes a non-zero interval_time", NULL);
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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "clearTimer takes 1 argument: timer", "clearTimer(timer: number): boolean");
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

// ------- event --------------
static thread_local JSValue event_notifier = JS_UNDEFINED;

struct JSEventTarget {
    JSContext* ctx;
    struct list_head table[HASH_TABLE_SIZE];
};

struct JSListener {
    JSValue listener;
    bool once;
};

struct JSEventType {
    JSAtom atom;
    struct JSListener listener[EVENT_MAX_LISTENER];
    int lcount;

    struct list_head head;
};

struct JSEvent {
    JSAtom event;
    bool prevented;
    bool cancelable;
    JSValue data;
};

// create hash
static inline uint8_t ev_hash(JSAtom atom){
    return atom % HASH_TABLE_SIZE;
}

static inline struct JSEventType* ev_find_eventtype(struct JSEventTarget* target, JSAtom atom){
    uint8_t hash = ev_hash(atom);
    struct list_head* head = &target -> table[hash];

    // find event
    struct list_head* pos;
    list_for_each(pos, head){
        struct JSEventType* type = list_entry(pos, struct JSEventType, head);
        if(type -> atom == atom){
            // found listener
            return type;
        }
    }

    return NULL;
}

static inline struct JSEventType* ev_create_eventtype(struct JSEventTarget* target, JSAtom atom){
    uint8_t hash = ev_hash(atom);
    struct list_head* head = &target -> table[hash];

    // create instance
    struct JSEventType* type = js_malloc(target -> ctx, sizeof(struct JSEventType));
    type -> atom = atom;
    type -> lcount = 0;
    list_add_tail(&type -> head, head);

    return type;
}

static inline struct JSListener* ev_add_listener(struct JSEventTarget* target, JSAtom atom, JSValue listener){
    struct JSEventType* first = ev_find_eventtype(target, atom);
    if(!first){
        // add listener to first
        struct JSEventType* type = ev_create_eventtype(target, atom);
        first = type;
    }
    struct JSListener* lt = &first -> listener[first -> lcount ++];
    *lt = (struct JSListener){
        .once = false,
        .listener = JS_DupValue(target -> ctx, listener)
    };
    return lt;
}

static inline bool ev_del_listener(struct JSEventTarget* target, JSAtom atom, JSValue listener){
    struct JSEventType* type = ev_find_eventtype(target, atom);
    if(type){
        int i;
        for(i = 0; i < type -> lcount; i++){
            if(JS_VALUE_GET_PTR(type -> listener[i].listener) == JS_VALUE_GET_PTR(listener)){
                // free listener
                JS_FreeValue(target -> ctx, type -> listener[i].listener);
                
                type -> lcount --;
                type -> listener[i] = type -> listener[type -> lcount];

                return true;
            }
        }
    }
    return false;
}

static inline bool ev_trigger_event(struct JSEventTarget* target, JSAtom atom, JSValue event){
    struct JSEventType* type = ev_find_eventtype(target, atom);

    if(type){
        for(int i = 0; i < type -> lcount; i++){
            JSValue listener = type -> listener[i].listener;
            JSValue ret = JS_Call(target -> ctx, listener, JS_UNDEFINED, 1, (JSValue[1]){ event });
            if(JS_IsException(ret)){
                JSValue error = JS_GetException(target -> ctx);
                __fprintf(pstderr, "Uncaught (in event) ");
                js_dump(target -> ctx, error, pstderr);
                JS_FreeValue(target -> ctx, error);
                return false;
            }
            JS_FreeValue(target -> ctx, ret);
            if(type -> listener[i].once){
                type -> lcount --;
                type -> listener[i] = type -> listener[type -> lcount];
            }
        }
#ifdef LJS_DEBUG
        const char* name = JS_AtomToCString(target -> ctx, atom);
        printf("event triggered: %s, listeners=%d\n", name, type -> lcount);
        JS_FreeCString(target -> ctx, name);
#endif
    }else{
#ifdef LJS_DEBUG
        const char* name = JS_AtomToCString(target -> ctx, atom);
        printf("warn: no event type: %s\n", name);
        JS_FreeCString(target -> ctx, name);
#endif
    }
    return true;
}

static inline struct JSEventTarget* ev_new_target(JSContext* ctx){
    struct JSEventTarget* target = js_malloc(ctx, sizeof(struct JSEventTarget));
    target -> ctx = ctx;
    for(int i = 0 ; i < HASH_TABLE_SIZE; i++){
        init_list_head(&target -> table[i]);
    }
    return target;
}

static inline void ev_free_event(JSRuntime* rt, struct JSEvent* event){
    JS_FreeAtomRT(rt, event -> event);
    JS_FreeValueRT(rt, event -> data);
    js_free_rt(rt, event);
}

static thread_local JSClassID event_class_id, eventtarget_class_id;

// class Event
static JSValue js_event_preventdefault(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    struct JSEvent* event = JS_GetOpaque2(ctx, this_val, event_class_id);
    if(!event) return JS_EXCEPTION;

    if(!event -> cancelable){
        return JS_ThrowTypeError(ctx, "Event is not cancelable");
    }

    event -> prevented = true;
    return JS_UNDEFINED;
}

static JSValue js_event_ctor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    if(argc == 0 || !JS_IsString(argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "at least 1 string argument required",
            "new Event(type: string, options?: { cancelable?: boolean, detail?: any })"
        );
    }

    JSValue class = JS_NewObjectClass(ctx, event_class_id);
    const char* name = JS_ToCString(ctx, argv[0]);
    JSAtom atom = JS_NewAtom(ctx, name);
    JS_FreeCString(ctx, name);
    struct JSEvent* event = js_malloc(ctx, sizeof(struct JSEvent));
    event -> prevented = false;
    event -> data = JS_UNDEFINED;
    event -> event = atom;
    event -> cancelable = true;
    JS_SetOpaque(class, event);
    JS_DefinePropertyValueStr(ctx, class, "type", JS_DupValue(ctx, argv[0]), JS_PROP_CONFIGURABLE);
    
    if(argc > 1 && JS_IsObject(argv[1])){
        JSValue valtmp;
        if(JS_IsBool(valtmp = JS_GetPropertyStr(ctx, argv[1], "cancelable"))){
            event -> cancelable = JS_ToBool(ctx, valtmp);
        }
        JS_FreeValue(ctx, valtmp);

        if(!JS_IsUndefined(valtmp = JS_GetPropertyStr(ctx, argv[1], "detail"))){
            event -> data = JS_DupValue(ctx, valtmp);
        }
        JS_FreeValue(ctx, valtmp);
    }

    return class;
}

static JSValue js_event_get_detail(JSContext* ctx, JSValueConst this_val){
    struct JSEvent* event = JS_GetOpaque2(ctx, this_val, event_class_id);
    if(!event) return JS_EXCEPTION;

    return JS_DupValue(ctx, event -> data);
}

static void js_event_finalizer(JSRuntime* rt, JSValue val){
    struct JSEvent* event = JS_GetOpaque(val, event_class_id);
    if(event){
        ev_free_event(rt, event);
    }
}

static JSClassDef event_def = {
    "Event",
    .finalizer = js_event_finalizer
};

static JSCFunctionListEntry js_event_props[] = {
    JS_CFUNC_DEF("preventDefault", 0, js_event_preventdefault),
    JS_CGETSET_DEF("detail", js_event_get_detail, NULL),
};

// class EventTarget
static JSValue js_et_addlistener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic){
    struct JSEventTarget* target = JS_GetOpaque2(ctx, this_val, eventtarget_class_id);
    if(!target) return JS_EXCEPTION;

    if(argc < 2 || !JS_IsString(argv[0]) || !JS_IsFunction(ctx, argv[1])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "%s() takes 2 argument"
            "_(type: string, listener: (ev: Event) => void): void",
            magic ? "once" : "on"
        );
    }

    const char* name = JS_ToCString(ctx, argv[0]);
    JSAtom atom = JS_NewAtom(ctx, name);
    JS_FreeCString(ctx, name);
    struct JSListener* type = ev_add_listener(target, atom, argv[1]);
    JS_FreeAtom(ctx, atom);

    if(magic) {
        type -> once = true;
    }

    return JS_UNDEFINED;
}

static JSValue js_et_removelistener(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    struct JSEventTarget* target = JS_GetOpaque2(ctx, this_val, eventtarget_class_id);
    if(!target) return JS_EXCEPTION;

    if(argc < 2 || !JS_IsString(argv[0]) || !JS_IsFunction(ctx, argv[1])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "off() takes 2 argument",
            "off(type: string, listener: Function): void"
        );
    }

    const char* name = JS_ToCString(ctx, argv[0]);
    JSAtom atom = JS_NewAtom(ctx, name);
    JS_FreeCString(ctx, name);
    bool ret = ev_del_listener(target, atom, argv[1]);
    JS_FreeAtom(ctx, atom);
    return JS_NewBool(ctx, ret);
}

static JSValue js_et_dispatchevent(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    struct JSEventTarget* target = JS_GetOpaque2(ctx, this_val, eventtarget_class_id);
    if(!target) return JS_EXCEPTION;

    if(argc == 0 || !JS_IsObject(argv[0]) || !JS_GetOpaque(argv[0], event_class_id)){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "fire() takes 1 Event typed argument",
            "fire(event: Event): boolean"
        );
    }

    struct JSEvent* event = JS_GetOpaque(argv[0], event_class_id);
    bool ret = ev_trigger_event(target, event -> event, argv[0]);
    return JS_NewBool(ctx, ret);
}

static JSValue js_et_ctor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    struct JSEventTarget* target = ev_new_target(ctx);
    JSValue obj = JS_NewObjectClass(ctx, eventtarget_class_id);
    JS_SetOpaque(obj, target);
    return obj;
}

static void js_et_finalizer(JSRuntime* rt, JSValue val){
    struct JSEventTarget* target = JS_GetOpaque(val, eventtarget_class_id);
    if(target){
        // free all listeners
        for(int i = 0; i < HASH_TABLE_SIZE; i++){
            struct list_head* head = &target -> table[i];
            struct list_head* pos;
            list_for_each(pos, head){
                struct JSEventType* type = list_entry(pos, struct JSEventType, head);
                for(int j = 0; j < type -> lcount; j++){
                    JS_FreeValue(target -> ctx, type -> listener[j].listener);
                }
                js_free(target -> ctx, type);
            }
        }
        js_free_rt(rt, target);
    }
}

static JSClassDef eventtarget_def = {
    "EventTarget",
    .finalizer = js_et_finalizer
};

static JSCFunctionListEntry js_et_funcs[] = {
    JS_CFUNC_MAGIC_DEF("on", 2, js_et_addlistener, 0),
    JS_CFUNC_MAGIC_DEF("once", 2, js_et_addlistener, 1),
    JS_CFUNC_DEF("off", 2, js_et_removelistener),
    JS_CFUNC_DEF("fire", 1, js_et_dispatchevent),
};

// return false if preventDefault() is called or handler return false
bool js_dispatch_global_event(JSContext *ctx, const char * name, JSValue data, bool cancelable){
    struct JSEventTarget* target = JS_GetOpaque(g_eventbus, eventtarget_class_id);
    if(!target) return false;

    JSValue class = JS_NewObjectClass(ctx, event_class_id);
    struct JSEvent* event = js_malloc(ctx, sizeof(struct JSEvent));
    event -> prevented = false;
    event -> data = JS_DupValue(ctx, data);
    event -> event = JS_NewAtom(ctx, name);
    event -> cancelable = cancelable;
    JS_SetOpaque(class, event);
    JS_DefinePropertyValueStr(ctx, class, "type", JS_NewString(ctx, name), JS_PROP_CONFIGURABLE);

    // dispatch
    ev_trigger_event(target, event -> event, class);
    bool ret = event -> prevented;
    JS_FreeValue(ctx, class);   // finalizer will free event

    return !ret;
}

// ------- base64 --------

#ifdef LJS_MBEDTLS
void base64_encode(const uint8_t *input, size_t len, char *output) {
    size_t olen = 0;
    mbedtls_base64_encode((void*)output, len * 4, &olen, (void*)input, len);
    output[olen] = '\0';
}

void base64_decode(const char *input, size_t len, uint8_t *output, size_t *output_len) {
    size_t olen = 0;
    mbedtls_base64_decode((void*)output, len * 4, &olen, (void*)input, len);
}
#else
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
#endif

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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "encodeStr() requires a string argument",
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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "decodeUint8Array() requires a TypedArray argument",
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

    // Base64 encode/decode
    JS_SetPropertyStr(ctx, global_obj, "atob", JS_NewCFunction(ctx, js_atob, "atob", 1));
    JS_SetPropertyStr(ctx, global_obj, "btoa", JS_NewCFunction(ctx, js_btoa, "btoa", 1));

    // encodeStr/decodeStr
    JS_SetPropertyStr(ctx, global_obj, "encodeStr", JS_NewCFunction(ctx, js_str_to_u8array, "encodeStr", 1));
    JS_SetPropertyStr(ctx, global_obj, "decodeStr", JS_NewCFunction(ctx, js_u8array_to_str, "decodeStr", 1));

    // Event
    JS_NewClassID(JS_GetRuntime(ctx), &event_class_id);
    JS_NewClass(JS_GetRuntime(ctx), event_class_id, &event_def);
    JSValue event_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, event_proto, js_event_props, countof(js_event_props));
    JSValue event_ctor = JS_NewCFunction2(ctx, js_event_ctor, "Event", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, event_ctor, event_proto);
    JS_SetPropertyStr(ctx, global_obj, "Event", event_ctor);
    JS_SetClassProto(ctx, event_class_id, event_proto);
    
    // EventTarget
    JS_NewClassID(JS_GetRuntime(ctx), &eventtarget_class_id);
    JS_NewClass(JS_GetRuntime(ctx), eventtarget_class_id, &eventtarget_def);
    JSValue et_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, et_proto, js_et_funcs, countof(js_et_funcs));
    JSValue et_ctor = JS_NewCFunction2(ctx, js_et_ctor, "EventTarget", 0, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, et_ctor, et_proto);
    JS_SetPropertyStr(ctx, global_obj, "EventTarget", et_ctor);
    JS_SetClassProto(ctx, eventtarget_class_id, et_proto);

    // global event
    JSValue eventbus = js_et_ctor(ctx, JS_UNDEFINED, 0, NULL);
    JS_SetPropertyStr(ctx, global_obj, "events", eventbus);
    g_eventbus = eventbus;

    JS_FreeValue(ctx, global_obj);
    return true;
}

// ---------- Module Wrapper ----------

static thread_local JSClassID js_module_class_id;
static JSValue js_module_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Module is not constructable in JS instance", NULL);
}

static void js_module_finalizer(JSRuntime *rt, JSValue val) {
    JSModuleDef *def = (JSModuleDef*)JS_GetOpaque(val, js_module_class_id);
    if(def) {
        JS_FreeValueRT(rt, JS_MKPTR(JS_TAG_MODULE, def));
    }
}

static JSValue js_module_get_ptr(JSContext *ctx, JSValueConst this_val){
    return 
#if __SIZEOF_POINTER__ == 8
    JS_NewInt64
#else
    JS_NewInt32
#endif
    (ctx, (uintptr_t)JS_GetOpaque(this_val, js_module_class_id));
}

static JSValue js_module_dump(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    JSModuleDef *def = (JSModuleDef*)JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!def) return JS_EXCEPTION;

    size_t len = 0;
    uint8_t *data = JS_WriteObject(ctx, &len, JS_MKPTR(JS_TAG_MODULE, def), JS_WRITE_OBJ_BYTECODE);
    if(!data) return JS_EXCEPTION;

    return JS_NewUint8Array(ctx, data, len, free_js_malloc, NULL, false);
}

static JSValue js_module_set_meta(JSContext* ctx, JSValueConst this_val, JSValueConst value){
    JSModuleDef *def = (JSModuleDef*)JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!def) return JS_EXCEPTION;

    JSValue meta = JS_MKPTR(JS_TAG_MODULE, def);
    JS_CopyObject(ctx, value, meta, UINT32_MAX);
    return JS_UNDEFINED;
}

static JSValue js_module_get_meta(JSContext* ctx, JSValueConst this_val){
    JSModuleDef *def = (JSModuleDef*)JS_GetOpaque2(ctx, this_val, js_module_class_id);
    if(!def) return JS_EXCEPTION;

    JSValue meta = JS_MKPTR(JS_TAG_MODULE, def);
    JSValue ret = JS_NewObject(ctx);
    JS_CopyObject(ctx, meta, ret, UINT32_MAX);
    return ret;
}

static inline JSModuleDef* module_getdef(JSValueConst this_val){
    return (JSModuleDef*)JS_GetOpaque(this_val, js_module_class_id);
}

static inline JSModuleDef* module_getdef2(JSContext* ctx, JSValueConst this_val){
    JSModuleDef* def = module_getdef(this_val);
    if(!def) return NULL;
    JS_DupValue(ctx, JS_MKPTR(JS_TAG_MODULE, def));
    return def;
}

static inline JSValue module_new(JSContext* ctx, JSModuleDef* def){
    JSValue obj = JS_NewObjectClass(ctx, js_module_class_id);
    JS_SetOpaque(obj, def);
    return obj;
}

static const JSClassDef js_module_class = {
    "Module",
    .finalizer = js_module_finalizer,
};

static const JSCFunctionListEntry js_module_proto_funcs[] = {
    JS_CGETSET_DEF("ptr", js_module_get_ptr, NULL),
    JS_CFUNC_DEF("dump", 0, js_module_dump),
    JS_CGETSET_DEF("meta", js_module_get_meta, js_module_set_meta),
};

//  ---------- VM features ----------
static JSValue js_vm_gc(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JS_RunGC(JS_GetRuntime(ctx));
    return JS_UNDEFINED;
}

static JSValue js_vm_dump(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc != 1){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "dump() requires at least one argument",
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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "load() requires a Uint8Array argument",
            "load(arr: Uint8Array): any"
        );
    }

    size_t len = 0;
    uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
    if(!data) return JS_EXCEPTION;

    JSValue obj = JS_ReadObject(ctx, data, len, JS_READ_OBJ_BYTECODE);
    switch (JS_VALUE_GET_TAG(obj)){
        case JS_TAG_UNINITIALIZED:
        case JS_TAG_CATCH_OFFSET:
            return JS_UNDEFINED;

        // case JS_TAG_FUNCTION_BYTECODE:
        case JS_TAG_MODULE:
            return module_new(ctx, (JSModuleDef*)JS_VALUE_GET_PTR(obj));
        
        default:
            return obj;
    }
}

static JSValue js_vm_compile(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc == 0 || !JS_IsString(argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "compile() requires a string argument",
            "compile(source: string, opts?: { strip?: boolean, filename?: string, internal?: boolean, module?: boolean }): Uint8Array"
        );
    }

    size_t len;
    int flag = JS_EVAL_FLAG_COMPILE_ONLY | JS_EVAL_TYPE_GLOBAL;
    int wflag = JS_WRITE_OBJ_BYTECODE;
    const char* filename = "<eval>";
    const char *source = JS_ToCStringLen(ctx, &len, argv[0]);
    if(!source) return JS_EXCEPTION;

    if(JS_IsObject(argv[1])){
        JSValue strip = JS_GetPropertyStr(ctx, argv[1], "strip");
        JSValue fname = JS_GetPropertyStr(ctx, argv[1], "filename");
        JSValue internal = JS_GetPropertyStr(ctx, argv[1], "internal");
        JSValue module = JS_GetPropertyStr(ctx, argv[1], "module");
        if(JS_IsBool(strip)) wflag |= JS_WRITE_OBJ_STRIP_DEBUG | JS_WRITE_OBJ_STRIP_SOURCE;
        if(JS_IsBool(internal)) wflag |= JS_WRITE_OBJ_SAB;
        if(JS_IsBool(module)) flag |= JS_EVAL_TYPE_MODULE;
        if(JS_IsString(fname)){
            filename = LJS_ToCString(ctx, fname, NULL);
            JS_FreeValue(ctx, fname);   // for ToCString
        }
        JS_FreeValue(ctx, strip);
        JS_FreeValue(ctx, fname);
        JS_FreeValue(ctx, internal);
    }

    JSValue compiled = JS_Eval(ctx, source, len, filename, flag);

    if(JS_IsException(compiled)) goto fail;

    size_t output_len;
    uint8_t* output = JS_WriteObject(ctx, &output_len, compiled, wflag);
    if(!output){ 
        JS_FreeValue(ctx, compiled); 
        goto fail; 
    }

    JS_FreeValue(ctx, compiled);
    JS_FreeCString(ctx, source);
    return JS_NewUint8Array(ctx, (uint8_t*)output, output_len, free_js_malloc, NULL, false);
fail:
    JS_FreeCString(ctx, source);
    return JS_EXCEPTION;
}

// static JSValue js_vm_pack(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
//     if(argc == 0 || !JS_IsObject(argv[0])){
//         return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "mkJSPack() requires an object argument",
//             "mkJSPack(obj: Record<string, Module>): Uint8Array"
//         );
//     }

//     // get object length
//     uint32_t len;
//     JSPropertyEnum* props;
//     if(-1 == JS_GetOwnPropertyNames(ctx, &props, &len, argv[0], JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY))
//         return JS_EXCEPTION;

//     struct PackResult* pack = js_malloc(ctx, sizeof(struct PackResult) * len);
//     if(!pack) return JS_EXCEPTION;

//     int pri = 0;
//     for(uint32_t i = 0; i < len; i++){
//         size_t pklen;
//         const char* prop_name = JS_AtomToCStringLen(ctx, &pklen, props[i].atom);
//         if(!prop_name){
//             JS_FreeCString(ctx, prop_name);
//             continue;
//         }

//         JSValue prop_val = JS_GetProperty(ctx, argv[0], props[i].atom);
//         __maybe_unused size_t __unused__;
//         void* modulePtr = module_getdef(prop_val);
//         JS_FreeValue(ctx, prop_val);
//         if(!modulePtr){
//             JS_FreeCString(ctx, prop_name);
//             continue;
//         }

//         pack[i].name = js_strdup(ctx, prop_name);
//         pack[i].value = JS_MKPTR(JS_TAG_MODULE, modulePtr);
//         pack[pri ++] = pack[i];
//         JS_FreeCString(ctx, prop_name);
//     }

//     JS_FreePropertyEnum(ctx, props, len);

//     // start
//     size_t olen = 0;
//     uint8_t* res = js_pack(ctx, pack, pri, &olen);

//     return JS_NewUint8Array(ctx, res, olen, free_js_malloc, NULL, false);
// }

// static JSValue js_vm_unpack(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
//     if(argc != 1 || JS_GetTypedArrayType(argv[0]) != JS_TYPED_ARRAY_UINT8){
//         return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "unpack() requires a Uint8Array argument",
//             "unpack(arr: Uint8Array): Record<string, vm.Module>"
//         );
//     }

//     size_t len = 0;
//     uint8_t *data = JS_GetUint8Array(ctx, &len, argv[0]);
//     if(!data) return JS_EXCEPTION;

//     size_t count;
//     struct PackResult* pack = js_unpack(ctx, data, len, &count);
//     if(!pack) return JS_EXCEPTION;

//     JSValue obj = JS_NewObject(ctx);
//     for(int i = 0; i < count; i++){
//         JSModuleDef* m = JS_VALUE_GET_PTR(pack[i].value);
//         JS_SetPropertyStr(ctx, obj, pack[i].name, module_new(ctx, m));
//         js_free(ctx, pack[i].name);
//         JS_FreeValue(ctx, pack[i].value);
//     }
//     js_free(ctx, pack);

//     return obj;
// }

#define EACHOPT(_name, check_func, then) \
    if(check_func(valtmp = JS_GetPropertyStr(ctx, argv[0], _name))) then \
    JS_FreeValue(ctx, valtmp);
#define EACHOPT2(_name, check_func, then) \
    if(check_func(ctx, valtmp = JS_GetPropertyStr(ctx, argv[0], _name))) then \
    JS_FreeValue(ctx, valtmp);

static JSValue js_vm_setvmopts(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc == 0 || !JS_IsObject(argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "setvmopts() requires an object argument",
            "setvmopts(opts: VMOpts extends Record<string, string | number>): void"
        );
    }

    JSValue valtmp;
    EACHOPT("memoryLimit", JS_IsBigInt, {
        uint64_t max_mem;
        if(JS_ToBigUint64(ctx, &max_mem, valtmp)){
            JS_SetMemoryLimit(JS_GetRuntime(ctx), max_mem);
        }
    });
    EACHOPT("codeExecutionTimeout", JS_IsNumber, {
        double timeout;
        if(JS_ToFloat64(ctx, &timeout, valtmp)){
            App* app = JS_GetContextOpaque(ctx);
            app -> interrupt = timeout * CLOCKS_PER_SEC;
        }
    });
    EACHOPT("stackLimit", JS_IsNumber, {
        uint32_t stack;
        if(JS_ToUint32(ctx, &stack, valtmp)){
            JS_SetMaxStackSize(JS_GetRuntime(ctx), stack);
        }
    });
    EACHOPT("disablePromiseReport", JS_IsBool, {
        bool disable = JS_ToBool(ctx, valtmp);
        catch_error = disable;
#ifdef LJS_DEBUG
        printf("Promise report %s by user\n", disable ? "disabled" : "enabled");
#endif
    });
    if(JS_GetContextOpaque(ctx) == JS_GetRuntimeOpaque(JS_GetRuntime(ctx))){
        EACHOPT2("eventNotifier", JS_IsFunction, {
            event_notifier = JS_DupValue(ctx, valtmp);
        });
    }
    EACHOPT2("tickCallback", JS_IsFunction, {
        App* app = JS_GetContextOpaque(ctx);
        JS_FreeValue(ctx, app -> tick_func);
        app -> tick_func = JS_DupValue(ctx, valtmp);
    })
    EACHOPT2("moduleResolver", JS_IsFunction, {
        App* app = JS_GetContextOpaque(ctx);
        JS_FreeValue(ctx, app -> module_format);
        app -> module_format = JS_DupValue(ctx, valtmp);
    })
    EACHOPT2("moduleLoader", JS_IsFunction, {
        App* app = JS_GetContextOpaque(ctx);
        JS_FreeValue(ctx, app -> module_loader);
        app -> module_loader = JS_DupValue(ctx, valtmp);
    })

    return JS_UNDEFINED;
}

#undef EACHOPT
#undef EACHOPT2

static JSValue js_vm_loadSourceMap(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc < 2 || !JS_IsString(argv[0]) || (!JS_IsString(argv[1]) && !JS_IsObject(argv[1]))){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "loadSourceMap() requires 2 string argument",
            "loadSourceMap(module_name: string, source_map: string | Object): boolean"
        );
    }

    const char* module_name = JS_ToCString(ctx, argv[0]);
    if(!module_name) return JS_EXCEPTION;

    JSValue ret;
    if(JS_IsString(argv[1])){
        const char* source_map = JS_ToCString(ctx, argv[1]);
        ret = JS_NewBool(ctx, js_load_sourcemap_cjson(ctx, module_name, source_map));
        JS_FreeCString(ctx, source_map);
    }else{
        ret = JS_NewBool(ctx, js_load_sourcemap(ctx, module_name, argv[1]));
    }
    JS_FreeCString(ctx, module_name);
    return ret;
}

const JSCFunctionListEntry js_vm_funcs[] = {
    JS_CFUNC_DEF("gc", 0, js_vm_gc),
    JS_CFUNC_DEF("dump", 1, js_vm_dump),
    JS_CFUNC_DEF("load", 1, js_vm_load),
    JS_CFUNC_DEF("compile", 1, js_vm_compile),
    // JS_CFUNC_DEF("pack", 1, js_vm_pack),
    // JS_CFUNC_DEF("unpack", 1, js_vm_unpack),
    JS_CFUNC_DEF("setVMOptions", 1, js_vm_setvmopts),
    JS_CFUNC_DEF("loadSourceMap", 2, js_vm_loadSourceMap),
    // JS_CFUNC_DEF("compileModule", 1, js_vm_compileModule)
};

// class Sandbox
// 使用线程内JSContext隔离执行JS代码
static thread_local JSClassID js_sandbox_class_id;

static JSValue js_sandbox_eval(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    App* app = (App*)JS_GetOpaque(this_val, js_sandbox_class_id);
    if(!app) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "this value invalid", NULL);

#ifdef QJS_DISABLE_PARSER
    return LJS_Throw(ctx, "Cannot evaluate code in ljsc that was compiled without parser support", NULL);
#else
    if(argc == 0){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "eval requires at least one argument",
            "Sandbox.eval(code: string, import_meta?: object): any | Promise<any>"
        );
    }

    const char* code = JS_ToCString(ctx, argv[0]);
    if(!code) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "code argument is not a string", NULL);
    JSValue func;
    JS_UpdateStackTop(JS_GetRuntime(ctx));
    
    if(argc == 2 && JS_IsObject(argv[1])){
        char* name = "<eval>";
        JSValue nameobj = JS_GetProperty(ctx, argv[1], JS_ATOM_name);
        if(JS_IsString(nameobj))
            name = (void*)JS_ToCString(ctx, nameobj);
        JS_FreeValue(ctx, nameobj);
        func = JS_Eval(app -> ctx, code, strlen(code), name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        if(!JS_IsException(func) && JS_IsModule(func)){
            // set import.meta
            JSValue meta = JS_GetImportMeta(app -> ctx, (JSModuleDef*)JS_VALUE_GET_PTR(func));
            JS_CopyObject(app -> ctx, argv[1], meta, 32);
        }
    }else{
        func = JS_Eval(app -> ctx, code, strlen(code), "<eval>", JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_ASYNC | JS_EVAL_FLAG_COMPILE_ONLY);
    }

    if(JS_IsException(func)){
        return JS_EXCEPTION;
    }
    app -> busy = true;
    JSValue ret = JS_EvalFunction(app -> ctx, func);
    if(JS_IsInternalError(ctx, ret))
        LJS_DestroyApp(app);
    app -> busy = false;
    return ret;
#endif
}

static JSValue js_sandbox_call(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    App* app = (App*)JS_GetOpaque2(ctx, this_val, js_sandbox_class_id);
    if(!app) return JS_EXCEPTION;

    if(argc == 0 || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "call requires at least one function argument",
            "Sandbox.call(func: Function, this_val?: any, ...args: any[]): any | Promise<any>"
        );
    }

    JSValue func = argv[0];
    JSValue this_arg = argc >= 2 ? argv[1] : JS_UNDEFINED;
    int arg_count = argc >= 3 ? argc - 2 : 0;
    JSValue* args = argc >= 3 ? argv + 2 : NULL;

    JS_UpdateStackTop(JS_GetRuntime(app -> ctx));
    app -> busy = true;
    JSValue ret = JS_Call(app -> ctx, func, this_arg, arg_count, args);
    if(JS_IsInternalError(ctx, ret))
        LJS_DestroyApp(app);
    app -> busy = false;
    return ret;
}

static JSValue js_sandbox_loadModule(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    App* app = (App*)JS_GetOpaque(this_val, js_sandbox_class_id);
    if(!app) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "this value invalid", NULL);

    if(argc < 2 || !JS_IsString(argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "loadModule() requires 2 argument",
            "loadModule(source: string, module_name: string): Module"
        );
    }

    size_t len;
    const char *source = JS_ToCStringLen(ctx, &len, argv[0]);
    const char *module_name = JS_ToCString(ctx, argv[1]);
    if(!source) return JS_EXCEPTION;

    JSValue compiled = JS_Eval(app -> ctx, source, len, module_name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if(JS_IsException(compiled)) goto fail;

    JS_FreeCString(ctx, source);
    JS_FreeCString(ctx, module_name);
    return module_new(ctx, (JSModuleDef*)JS_VALUE_GET_PTR(compiled));
fail:
    JS_FreeCString(ctx, source);
    JS_FreeCString(ctx, module_name);
    return JS_EXCEPTION;
}

static JSValue js_sandbox_get_context(JSContext* ctx, JSValueConst this_val){
    App* app = (App*)JS_GetOpaque(this_val, js_sandbox_class_id);
    if(!app) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "this value invalid", NULL);
    return JS_GetGlobalObject(app -> ctx);
}

static JSValue js_sandbox_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    JSValue obj = JS_NewObjectClass(ctx, js_sandbox_class_id);

    App* app = LJS_NewApp(JS_GetRuntime(ctx), 0, NULL, false, true, "<inmemory>", NULL);
    // char* init_apps[32];
    // uint8_t init_apps_len = 0;
    if(argc >= 1 && JS_IsObject(argv[0])){
        // JSValue init_apps_obj = JS_GetPropertyStr(ctx, argv[0], "init");
        // if(JS_IsArray(init_apps_obj)){
        //     int64_t len;
        //     if(JS_GetLength(ctx, init_apps_obj, &len)){
        //         for(uint32_t i = 0; i < len; i++){
        //             JSValue val = JS_GetPropertyUint32(ctx, init_apps_obj, i);
        //             if(JS_IsString(val)){
        //                 init_apps[init_apps_len++] = (char*)JS_ToCString(ctx, val);
        //             }
        //             JS_FreeValue(ctx, val);
        //         }
        //     }
        //     init_apps[init_apps_len] = '\0';
        // }
        // JS_FreeValue(ctx, init_apps_obj);

        // module loader
        JSValue loader = JS_GetPropertyStr(ctx, argv[0], "loader");
        if(JS_IsFunction(ctx, loader))
            app -> module_loader = loader;

        // module format
        JSValue format = JS_GetPropertyStr(ctx, argv[0], "format");
        if(JS_IsFunction(ctx, format))
            app -> module_format = format;
    }
    
    LJS_init_context(app);
    JS_SetOpaque(obj, app);
    return obj;
}

static void js_sandbox_finalizer(JSRuntime* rt, JSValue val){
    App* app = (App*)JS_GetOpaque(val, js_sandbox_class_id);
    if(app -> busy){
        // force exit sandbox
        // then the event would be processed by caller
        JS_ThrowInternalError(app -> ctx, " ");
    }else{
        LJS_DestroyApp(app);
    }
}

static JSCFunctionListEntry js_sandbox_funcs[] = {
    JS_CFUNC_DEF("eval", 1, js_sandbox_eval),
    JS_CFUNC_DEF("call", 1, js_sandbox_call),
    JS_CFUNC_DEF("loadModule", 2, js_sandbox_loadModule),
    JS_CGETSET_DEF("context", js_sandbox_get_context, NULL),
};

static JSClassDef js_sandbox_def = {
    "Sandbox",
    .finalizer = js_sandbox_finalizer,
};

static inline JSValue get_version_info(JSContext* ctx){
    JSValue obj = JS_NewObject(ctx);

    JS_SetPropertyStr(ctx, obj, "version", JS_NewString(ctx, LJS_VERSION));
    JS_SetPropertyStr(ctx, obj, "quickjs", JS_NewString(ctx, JS_GetVersion()));

#ifdef LJS_MBEDTLS
    JS_SetPropertyStr(ctx, obj, "mbedtls", JS_NewString(ctx, MBEDTLS_VERSION_STRING));
#endif

#ifdef LJS_ZLIB
    JS_SetPropertyStr(ctx, obj, "zlib", JS_NewString(ctx, ZLIB_VERSION));
#endif

#ifdef LJS_LIBEXPAT
    // JS_SetPropertyStr(ctx, obj, "expat", JS_NewString(ctx, XML_ExpatVersion()));
#endif

#ifdef LJS_LIBFFI
    JS_SetPropertyStr(ctx, obj, "ffi", JS_NULL);
#endif

    return obj;
}

static int vm_init(JSContext *ctx, JSModuleDef *m) {
    JS_SetModuleExportList(ctx, m, js_vm_funcs, countof(js_vm_funcs));

    JSValue sandbox = JS_GetClassProto(ctx, js_sandbox_class_id);
    JSValue sandbox_ctor = JS_NewCFunction2(ctx, js_sandbox_constructor, "Sandbox", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, sandbox_ctor, sandbox);
    JS_SetModuleExport(ctx, m, "Sandbox", sandbox_ctor);
    JS_FreeValue(ctx, sandbox);

    JSValue module = JS_GetClassProto(ctx, js_module_class_id);
    JSValue module_ctor = JS_NewCFunction2(ctx, js_module_constructor, "Module", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, module_ctor, module);
    JS_SetModuleExport(ctx, m, "Module", module_ctor);
    JS_FreeValue(ctx, module);

    JS_SetModuleExport(ctx, m, "version", get_version_info(ctx));

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

    JS_NewClassID(JS_GetRuntime(ctx), &js_module_class_id);
    if(-1 == JS_NewClass(JS_GetRuntime(ctx), js_module_class_id, &js_module_class)) return false;
    JSValue module_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, module_proto, js_module_proto_funcs, countof(js_module_proto_funcs));
    JS_SetClassProto(ctx, js_module_class_id, module_proto);
    JS_AddModuleExport(ctx, m, "Module");

    JS_AddModuleExport(ctx, m, "version");

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
            free2(data);
            count ++;
        }
    }
    return count;
}

// return true if promise has been resolved or rejected
// Note: promise will not js_dup, call dupvalue if needed after this call
bool LJS_enqueue_promise_job(JSContext* ctx, JSValue promise, JSPromiseCallback callback, void* opaque){
    int state = JS_PromiseState(ctx, promise);
    if(state != JS_PROMISE_PENDING){
        const bool error = state == -1 ? JS_IsException(promise) : state == JS_PROMISE_REJECTED;
        if(error) JS_PromiseHandleError(ctx, promise);  // make the promise auto-catched
        callback(ctx, error, JS_PromiseResult(ctx, promise), opaque);
        JS_FreeValue(ctx, promise);
        return true;
    }

    struct Promise_data* data = (struct Promise_data*)malloc2(sizeof(struct Promise_data));
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
//         __fprintf(stderr, "Uncaught (in promise) ");
//         js_dump(ctx, reason, stderr);
//     }
// }

void js_handle_promise_reject(
    JSContext *ctx, JSValue promise,
    JSValue reason,
    bool is_handled, void *opaque
){
    if (!is_handled && !JS_IsInternalError(ctx, reason)){
        // force next_tick
        // struct Promise_data* data = (struct Promise_data*)malloc2(sizeof(struct Promise_data));
        // data -> promise = JS_DupValue(ctx, promise);
        // data -> ctx = ctx;
        // data -> callback = handle_promise;
        // data -> opaque = LJS_NewJSValueProxy(ctx, promise);
        // list_add_tail(&data -> list, &promise_jobs);

        JSValue dobj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, dobj, "promise", JS_DupValue(ctx, promise));
        JS_SetPropertyStr(ctx, dobj, "reason", JS_DupValue(ctx, reason));
        if(!catch_error && js_dispatch_global_event(ctx, "unhandledrejection", dobj, true)){
            __fprintf(pstderr, "Uncaught (in promise) ");
            js_dump_promise(ctx, promise, pstderr);
            __fprintf(pstderr, "\n");
        }
        JS_FreeValue(ctx, dobj);
        // JS_FreeValue(ctx, reason);
    }
}

JSValue JS_CallSafe(JSContext *ctx, JSValueConst func_obj, JSValueConst this_val, int argc, JSValueConst *argv, bool* is_exception){
    catch_error = true;
    JSValue ret = JS_Call(ctx, func_obj, this_val, argc, argv);
    JSValue exception = JS_GetException(ctx);
    if(JS_IsException(ret)){
        JS_ClearUncatchableError(ctx, exception);
        if(is_exception) *is_exception = true;
    }else if(JS_IsPromise(ret) && JS_PROMISE_REJECTED == JS_PromiseState(ctx, ret)){
        ret = JS_PromiseHandleError(ctx, ret);
        if(is_exception) *is_exception = true;
    }else{
        if(is_exception) *is_exception = false;
    }
    catch_error = false;
    return JS_DupValue(ctx, ret);
}

void* js_malloc_proxy(size_t size, void* opaque){
    JSRuntime* rt = opaque;
    return js_malloc_rt(rt, size);
}

struct promise{
    JSContext* ctx;
    JSValue resolve;
    JSValue reject;
    JSValue promise;

#ifdef LJS_DEBUG
    const char* created;
    const char* resolved;

    struct list_head link;
#endif
};

#ifdef LJS_DEBUG
static struct list_head promise_debug_jobs;

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
    JS_FreeValue(proxy -> ctx, proxy -> promise);

#ifdef LJS_DEBUG
    printf("Promise %p freed, resolve: %s, created: %s\n", proxy, proxy -> resolved, proxy -> created);
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

JSValue js_get_promise(struct promise* proxy){
    return JS_DupValue(proxy -> ctx, proxy -> promise);
}

JSContext* js_get_promise_context(struct promise* proxy){
    return proxy -> ctx;
}

// memory
void* malloc2(size_t size){
    return js_malloc_rt(g_runtime, size);
}

void free2(void* ptr){
    js_free_rt(g_runtime, ptr);
}

void* realloc2(void* ptr, size_t size){
    return js_realloc_rt(g_runtime, ptr, size);
}

