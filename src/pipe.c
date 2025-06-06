#include "../engine/quickjs.h"
#include "core.h"
#include "utils.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <errno.h>
#include <threads.h>
#include <termios.h>

struct PipeRWTask{
    struct promise* promise;
    JSValue write_data; // for write()
    struct U8Pipe_T* pipe;
};

// 从FD创建的管道
struct FDPipe_T{
    EvFD* fd;
    uint8_t flag;
    JSContext* ctx;

    JSValue close_rs;
    JSValue close_rj;   // for socket only
    bool closed;
    bool is_socket; // 为socket优化

    uint8_t* data_before_eof;   // read buffer before EOF
    size_t eofbuf_size;
};
struct U8PipeTransfer {
    struct U8Pipe_T* pipe[2];
    JSValue filter;             // JS_UNDEFINED if not set
    struct promise* promise;
    bool active;
    bool aborted;
};
struct U8Pipe_T {
    bool fdpipe;
    union {
        struct FDPipe_T* fdpipe;
        struct Pipe_T* pipe;
    } pipe;
    struct U8PipeTransfer* transfer;
    int refcount; // JSRef, EvLoopRef
};

struct Pipe_T{
    JSValue close_rs;
    JSValue pull_func;
    JSValue write_func;
    JSValue close_func;

    bool read_lock;
    bool write_lock;

    JSContext* ctx;

    // for u8pipe
    struct Buffer* read_buf;

    bool closed;
    uint8_t flag;
};

// Pipe
static thread_local JSClassID Pipe_class_id;

// U8Pipe
static thread_local JSClassID U8Pipe_class_id;
static thread_local uint32_t PIPE_u8_buf_size = 16 * 1024;

// ---------------- Pipe -------------------
#define GET_PIPE_OPAQUE(var, pipe) struct Pipe_T* var = JS_GetOpaque(pipe, Pipe_class_id); if(!var) return JS_EXCEPTION;
#define CHECK_PIPE_CLOSED(pipe) if(pipe -> closed) return JS_ThrowTypeError(ctx, "Pipe is closed");
#define CHECK_PIPE_READABLE(pipe) if(!(pipe -> flag & PIPE_READ)) return JS_ThrowTypeError(ctx, "Pipe is not readable");
#define CHECK_PIPE_WRITEABLE(pipe) if(!(pipe -> flag & PIPE_WRITE)) return JS_ThrowTypeError(ctx, "Pipe is not writable");
#define EXCEPTION_THEN_CLOSE(val, ret) if(JS_IsException(val)){ pipe_handle_close(JS_GetRuntime(ctx), pipe); return ret; }
#define UNLOCK_AFTER(promise, ref) LJS_enqueue_promise_job(ctx, promise, pipe_unlock_job, ref);
#define DEF_ONCLOSE(pipe) { \
    JSValue promise[2]; \
    JSValue prom = JS_NewPromiseCapability(ctx, promise); \
    JS_SetPropertyStr(ctx, obj, "onclose", prom); \
    pipe -> close_rs = promise[0]; \
    JS_FreeValue(ctx, promise[1]); \
}
#define DEF_ONCLOSE2(pipe) { \
    JSValue promise[2]; \
    JSValue prom = JS_NewPromiseCapability(ctx, promise); \
    JS_SetPropertyStr(ctx, obj, "onclose", prom); \
    pipe -> close_rs = promise[0]; \
    pipe -> close_rj = promise[1]; \
}

static void pipe_unlock_job(JSContext* ctx, bool is_error, JSValue res, void* opaque){
    *(bool*)opaque = false;
}

static void pipe_handle_close(JSRuntime *rt, struct Pipe_T *pipe);
static JSValue pipe_handle_reject(JSContext* ctx, JSValue this_val, int argc, JSValueConst* argv, int magic, JSValueConst* data){
    struct Pipe_T* pipe = JS_VALUE_GET_PTR(data[0]);
    pipe_handle_close(JS_GetRuntime(ctx), pipe);
    return JS_UNDEFINED;
}

static inline void pipe_handle_promise(JSContext* ctx, JSValue promise, struct Pipe_T* pipe){
    if(JS_PromiseState(ctx, promise) == JS_PROMISE_REJECTED){
        pipe -> closed = true;
        return;
    }
    JS_PromiseCatch(
        ctx, JS_DupValue(ctx, promise), 
        JS_NewCFunctionData(ctx, pipe_handle_reject, 0, 0, 1, (JSValueConst[]){JS_MKPTR(JS_TAG_INT, pipe)})
    );
}

static void pipe_handle_close(JSRuntime *rt, struct Pipe_T *pipe) {
    if (pipe -> closed) return;

    JS_FreeValueRT(rt, pipe -> pull_func);
    JS_FreeValueRT(rt, pipe -> write_func);
    JS_FreeValueRT(rt, pipe -> close_func);

    JS_Call(pipe -> ctx, pipe -> close_func, JS_NULL, 0, NULL);
    if(JS_IsFunction(pipe -> ctx, pipe -> close_rs)){
        JS_Call(pipe -> ctx, pipe -> close_rs, JS_NULL, 0, NULL);
        JS_FreeValueRT(rt, pipe -> close_rs);
    }
    
    buffer_free(pipe -> read_buf);
    pipe -> closed = true;
}

static void pipe_cleanup(JSRuntime *rt, struct Pipe_T* pipe) {
    if(!pipe -> closed) pipe_handle_close(rt, pipe);
    js_free_rt(rt, pipe);
}

static void js_pipe_cleanup(JSRuntime *rt, JSValue val) {
    struct Pipe_T *pipe = JS_GetOpaque(val, Pipe_class_id);
    pipe_cleanup(rt, pipe);
}

static JSValue js_pipe_read(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_PIPE_OPAQUE(pipe, this_val);
    CHECK_PIPE_CLOSED(pipe);
    CHECK_PIPE_READABLE(pipe);

    JSValue data;
    // 调用pull()
    pipe -> read_lock = true;
    data = JS_Call(ctx, pipe -> pull_func, this_val, 0, NULL);
    EXCEPTION_THEN_CLOSE(data, JS_NULL);
    pipe_handle_promise(ctx, data, pipe);
    UNLOCK_AFTER(data, &pipe -> read_lock);

    // 返回数据
    return data;
}

static JSValue js_pipe_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_PIPE_OPAQUE(pipe, this_val);
    CHECK_PIPE_CLOSED(pipe);
    CHECK_PIPE_WRITEABLE(pipe);

    if(argc == 0)
        return LJS_Throw(ctx, "Pipe write need 1 argument", "Pipe.write(data: any): boolean");

    JSValue data = argv[0];

    // 传递给write()
    JSValue ret = JS_Call(ctx, pipe -> write_func, this_val, 1, (JSValueConst[]){data});
    pipe -> write_lock = true;
    EXCEPTION_THEN_CLOSE(ret, JS_FALSE);
    pipe_handle_promise(ctx, data, pipe);
    UNLOCK_AFTER(ret, &pipe -> write_lock);

    return ret;
}

static JSValue js_pipe_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_PIPE_OPAQUE(pipe, this_val);
    CHECK_PIPE_CLOSED(pipe);
    pipe_handle_close(JS_GetRuntime(ctx), pipe);
    return JS_UNDEFINED;
}

static JSClassDef Pipe_class = {
    "Pipe",
    .finalizer = js_pipe_cleanup
};
static const JSCFunctionListEntry Pipe_proto_funcs[] = {
    JS_CFUNC_DEF("read", 0, js_pipe_read),
    JS_CFUNC_DEF("write", 1, js_pipe_write),
    JS_CFUNC_DEF("close", 0, js_pipe_close),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Pipe", JS_PROP_CONFIGURABLE),
};

static JSValue js_pipe_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    // 解析参数
    if(argc != 2){
        return LJS_Throw(ctx, "Pipe constructor need 2 arguments", "new Pipe(ctrl: { read(), poll(), close(), start() }, flag: Pipe.READ | Pipe.WRITE)");
    }
    struct Pipe_T *pipe = js_malloc(ctx, sizeof(struct Pipe_T));
    JSValue close_func = JS_GetPropertyStr(ctx, argv[0], "close");
    JSValue pull_func = JS_GetPropertyStr(ctx, argv[0], "pull");
    JSValue write_func = JS_GetPropertyStr(ctx, argv[0], "write");
    JSValue start_func = JS_GetPropertyStr(ctx, argv[0], "start");
    JSValue pipe_type = argv[1];
    pipe -> ctx = ctx;
    pipe -> pull_func = JS_IsFunction(ctx, pull_func) ? JS_DupValue(ctx, pull_func) : JS_NULL;
    pipe -> write_func = JS_IsFunction(ctx, write_func) ? JS_DupValue(ctx, write_func) : JS_NULL;
    pipe -> close_func = JS_IsFunction(ctx, close_func) ? JS_DupValue(ctx, close_func) : JS_NULL;
    pipe -> flag = 0;

    uint32_t flag = 0;
    if(JS_ToUint32(ctx, &flag, pipe_type) < 0){
        return LJS_Throw(ctx, "Pipe flag must be a number", "new Pipe(ctrl, flag:Pipe.READ | Pipe.WRITE)");
    }

    // proto
    JSValue obj = JS_NewObjectClass(ctx, Pipe_class_id);

    // close promise
    DEF_ONCLOSE(pipe);

    // 调用start
    if(JS_IsFunction(ctx, start_func)){
        JS_Call(ctx, start_func, obj, 0, NULL);
    }

    return obj;
}

// -------------------- U8Pipe ------------------
#define GET_U8PIPE_OPAQUE(var, pipe) struct U8Pipe_T* var = ((struct U8Pipe_T*)JS_GetOpaque2(ctx, pipe, U8Pipe_class_id)); if(!var) return JS_EXCEPTION;
#define CHECK_U8PIPE_CLOSED(pipe) if(u8pipe_closed(ctx, pipe)) return JS_ThrowTypeError(ctx, "U8Pipe is closed");
#define CHECK_U8PIPE_CLOSED2(pipe, promise) if(u8pipe_closed(ctx, pipe)){ LJS_Promise_Reject(promise, "U8Pipe is closed"); return promise -> promise; }
#define CHECK_U8PIPE_READABLE(pipe) if(!u8pipe_is(ctx, pipe, PIPE_READ)) return JS_ThrowTypeError(ctx, "U8Pipe is not readable");
#define CHECK_U8PIPE_WRITEABLE(pipe) if(!u8pipe_is(ctx, pipe, PIPE_WRITE)) return JS_ThrowTypeError(ctx, "U8Pipe is not writable");
#define CHECK_U8PIPE_LOCKED(pipe, read) if(u8pipe_locked(ctx, pipe, read)) return JS_ThrowTypeError(ctx, "U8Pipe is locked");

#define U8PIPE_UNREF(pipe) pipe -> refcount --; u8pipe_handle_close(JS_GetRuntime(ctx), pipe, false);
#define U8PIPE_UNREF_RT(pipe) pipe -> refcount --; u8pipe_handle_close(rt, pipe, false);
#undef EXCEPTION_THEN_CLOSE
#define EXCEPTION_THEN_CLOSE(val, ret) if(JS_IsException(val)){ U8PIPE_UNREF(pipe); return ret; } \
    else if(JS_IsPromise(val)) JS_PromiseHandleError(ctx, val);
#define CALL_ONCLOSE(pipe) JS_Call(pipe -> ctx, pipe -> close_rs, JS_NULL, 0, NULL);

// struct JSValueProxy {
//     JSValue val;
//     // JSContext* ctx;
// };

// static struct JSValueProxy* js_value_proxy_new(JSContext* ctx, JSValue val){
//     struct JSValueProxy* proxy = js_malloc(ctx, sizeof(struct JSValueProxy));
//     proxy -> val = JS_DupValue(ctx, val);
//     // proxy -> ctx = ctx;
// }

static void u8pipe_handle_close(JSRuntime *rt, struct U8Pipe_T* pipe, bool closed){
    if(pipe -> refcount != 0) return;

    if(pipe -> transfer){
        LJS_FreePromise(pipe -> transfer -> promise);
        js_free_rt(rt, pipe -> transfer);
        U8PIPE_UNREF_RT(pipe -> transfer -> pipe[1]);
        U8PIPE_UNREF_RT(pipe);
    }

    if(pipe -> fdpipe){
        struct FDPipe_T* fdpipe = pipe -> pipe.fdpipe;
        if(fdpipe && !fdpipe -> closed){
            if(!closed) LJS_evfd_close(fdpipe  -> fd);
            fdpipe  -> closed = true;
            if(fdpipe -> is_socket){
                int error = 0;
                socklen_t errlen = sizeof(error);
                
                if (getsockopt(LJS_evfd_getfd(fdpipe -> fd, NULL), SOL_SOCKET, SO_ERROR, &error, &errlen) == -1)
                    error = errno;

                if(error == 0){
                    CALL_ONCLOSE(fdpipe);
                } else {
                    JSValue error_obj = JS_NewError(fdpipe -> ctx);
                    JS_SetPropertyStr(fdpipe -> ctx, error_obj, "message", JS_NewString(fdpipe -> ctx, strerror(error)));
                    JS_SetPropertyStr(fdpipe -> ctx, error_obj, "code", JS_NewInt32(fdpipe -> ctx, error));
                    JS_Call(fdpipe -> ctx, fdpipe -> close_rj, JS_NULL, 1, (JSValueConst[]){ error_obj });
                }
            }else{
                CALL_ONCLOSE(fdpipe);
            }

            if(JS_IsFunction(fdpipe -> ctx, fdpipe  -> close_rs)){
                JS_FreeValueRT(rt, fdpipe  -> close_rs);
                JS_FreeValueRT(rt, fdpipe  -> close_rj);
            }
        }
        js_free_rt(rt, fdpipe);
        // pipe -> pipe.fdpipe  -> fd was freed by evfd
    }else{
        pipe_handle_close(rt, pipe -> pipe.pipe);
    }

    js_free_rt(rt, pipe);
}

static void js_u8pipe_cleanup(JSRuntime *rt, JSValue val) {
    // U8Pipe will be 
    struct U8Pipe_T* pipe = ((struct U8Pipe_T*)JS_GetOpaque(val, U8Pipe_class_id));
    U8PIPE_UNREF_RT(pipe);
}

static inline bool u8pipe_is(JSContext *ctx, struct U8Pipe_T* pipe, uint8_t flag) {
    if(pipe -> fdpipe){
        return pipe -> pipe.fdpipe -> flag & flag;
    }else{
        return pipe -> pipe.pipe -> flag & flag;
    }
}

static inline bool u8pipe_locked(JSContext *ctx, struct U8Pipe_T* pipe, bool read){
    if(pipe -> transfer && read) return true;   // PipeTo will block read channel
    if(pipe -> fdpipe){
        return false;   // fdpipe evfd内置队列
    }else{
        return read
            ? pipe -> pipe.pipe -> read_lock
            : pipe -> pipe.pipe -> write_lock;
    }
}

static inline bool u8pipe_closed(JSContext *ctx, struct U8Pipe_T* pipe) {
    if(pipe -> fdpipe){
        return pipe -> pipe.pipe == NULL || pipe -> pipe.fdpipe -> closed;
    }else{
        return pipe -> pipe.pipe -> closed;
    }
}

void free_js_malloc(JSRuntime *rt, void *opaque, void *ptr){
    js_free_rt(rt, ptr);
}

void free_malloc(JSRuntime* rt, void* opaque, void* ptr){
    free(ptr);
}

static inline bool JS_IsTypedArray(JSContext *ctx, JSValueConst val){
    return JS_GetTypedArrayType(val) != -1;
}

struct PipeFillJob {
    struct promise* promise;
    uint32_t total;
    struct U8Pipe_T* pipe;
    bool once;
};

static void u8pipe_fill_job(JSContext* ctx, bool is_error, JSValue result, void* opaque){
    struct PipeFillJob* job = opaque;
    struct Pipe_T* pipe = job -> pipe -> pipe.pipe;

    if(is_error){
        LJS_Promise_Reject(job -> promise, "Pipe EOF reached");
        pipe_handle_close(JS_GetRuntime(ctx), pipe);
        goto done;
    }

    size_t size;
    uint8_t* data = JS_GetUint8Array(ctx, &size, result);
    if(!data){
        LJS_Promise_Reject(job -> promise, "Invaild data returned by pull()");
        goto done;
    }
    JS_FreeValue(ctx, result);

    uint32_t writed = buffer_push(pipe -> read_buf, data, size);

    if(buffer_is_full(pipe -> read_buf) || job -> once){
        uint32_t size2;
        uint8_t* res = buffer_sub_export(pipe -> read_buf, 
            pipe -> read_buf -> start, pipe -> read_buf -> end, &size2);
        buffer_seek(pipe -> read_buf, pipe -> read_buf -> start + size);
        JSValue ret = JS_NewUint8Array(ctx, res, size2, free_js_malloc, NULL, false);
        
        LJS_Promise_Resolve(job -> promise, ret);
        if(writed < size){
            // lost: re-push
            buffer_push(pipe -> read_buf, res + size, size - writed);
        }
done:
        U8PIPE_UNREF(job -> pipe);
        buffer_free(pipe -> read_buf);
        js_free(ctx, job);
    }else{
        // push
        JSValue data = JS_Call(ctx, pipe -> pull_func, JS_NULL, 0, NULL);
        if(JS_IsException(data)){
            pipe_handle_close(JS_GetRuntime(ctx), pipe);
            goto done;
        }
        LJS_enqueue_promise_job(ctx, data, u8pipe_fill_job, job);
    }
}

static inline bool u8pipe_fill(JSContext* ctx, struct U8Pipe_T* pipe, struct promise* promise, uint32_t total, bool once){
    struct PipeFillJob* job = js_malloc(ctx, sizeof(struct PipeFillJob));
    job -> promise = promise;
    job -> total = total;
    job -> pipe = pipe;
    job -> once = once;
    
    JSValue data = JS_Call(ctx, pipe -> pipe.pipe -> pull_func, JS_NULL, 0, NULL);
    if(JS_IsException(data)){
        pipe_handle_close(JS_GetRuntime(ctx), pipe -> pipe.pipe);
        js_free(ctx, job);
        U8PIPE_UNREF(pipe);
        return false;
    }
    LJS_enqueue_promise_job(ctx, data, u8pipe_fill_job, job);
    return true;
}

static int evread_callback(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data){
    struct PipeRWTask* task = user_data;
    struct U8Pipe_T* piperaw = task -> pipe;
    struct FDPipe_T* pipe = piperaw -> pipe.fdpipe;
    if(read_size == 0 && NULL == buffer){// note: read_size == 0 is not always means EOF
        LJS_Promise_Reject(task -> promise, "Pipe reached EOF");
    }else{
        JSValue data = JS_NewUint8Array(pipe -> ctx, buffer, read_size, free_js_malloc, NULL, false);
        LJS_Promise_Resolve(task -> promise, data);
    }
    JSContext* ctx = pipe -> ctx;
    U8PIPE_UNREF(piperaw);
    js_free(ctx, task);
    return EVCB_RET_DONE;
}

#define U8PIPE_FD_EOFCHECK(pipe, promise, blk) if(u8pipe_closed(ctx, pipe)){ \
    if(pipe -> pipe.fdpipe -> data_before_eof) blk \
    else{ \
        LJS_Promise_Reject(promise, "U8Pipe is closed"); \
        return promise -> promise; \
    } \
}

#define EXPORT_EOF(pipe, buf, size) JSValue buf = JS_NewUint8Array(ctx, pipe -> pipe.fdpipe -> data_before_eof, size, free_js_malloc, NULL, false);

#define NEW_TASK(_promise, _pipe) \
    struct PipeRWTask* task = js_malloc(ctx, sizeof(struct PipeRWTask)); \
    task -> promise = _promise; \
    task -> pipe = _pipe; \

static JSValue js_U8Pipe_read(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    CHECK_U8PIPE_READABLE(pipe);
    CHECK_U8PIPE_LOCKED(pipe, true);

    uint32_t expected_size = 0;
    struct promise* promise = LJS_NewPromise(ctx);
    JSValue promiseobj = promise -> promise;

    if(argc == 1){
        if(0 != JS_ToUint32(ctx, &expected_size, argv[0])){
            return LJS_Throw(ctx, "Expected size must be a number", "U8Pipe.read(expected_size?: number)");
        }
    }

    if(pipe -> fdpipe){
        U8PIPE_FD_EOFCHECK(pipe, promise, {
            EXPORT_EOF(pipe, buf, expected_size == 0 ? pipe -> pipe.fdpipe -> eofbuf_size : MIN(pipe -> pipe.fdpipe -> eofbuf_size, expected_size));
            if(expected_size == 0 || expected_size >= pipe -> pipe.fdpipe -> eofbuf_size){
                pipe -> pipe.fdpipe -> data_before_eof = NULL;
            }else{
                // rest data
                memmove(pipe -> pipe.fdpipe -> data_before_eof, pipe -> pipe.fdpipe -> data_before_eof + expected_size, pipe -> pipe.fdpipe -> eofbuf_size - expected_size);
            }
            LJS_Promise_Resolve(promise, buf);
            return promise -> promise;
        });

        NEW_TASK(promise, pipe);
        pipe -> refcount ++;

        if(expected_size == 0){
            uint8_t* buf = js_malloc(ctx, PIPE_u8_buf_size);
            LJS_evfd_read(pipe -> pipe.fdpipe -> fd, PIPE_u8_buf_size, buf, evread_callback, task);
        }else{
            uint8_t* buf = js_malloc(ctx, expected_size);
            LJS_evfd_readsize(pipe -> pipe.fdpipe -> fd, expected_size, buf, evread_callback, task);
        }
    }else{  // U8PIPE
        CHECK_U8PIPE_CLOSED2(pipe, promise);
        pipe -> refcount ++;
        if(!u8pipe_fill(ctx, pipe, promise, expected_size, expected_size == 0))
            return LJS_Throw(ctx, "Failed to fill buffer", NULL);
    }

    return promiseobj;
}

static void evwrite_callback(EvFD* evfd, bool success, void* opaque){
    struct PipeRWTask* task = opaque;
    if(success)
        LJS_Promise_Resolve(task -> promise, JS_UNDEFINED);
    else
        LJS_Promise_Reject(task -> promise, "Write failed");
    JSContext* ctx = task -> pipe -> pipe.fdpipe -> ctx;
    U8PIPE_UNREF(task -> pipe);
    js_free(ctx, task);
}

static JSValue js_U8Pipe_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    CHECK_U8PIPE_CLOSED(pipe);
    CHECK_U8PIPE_WRITEABLE(pipe);
    CHECK_U8PIPE_LOCKED(pipe, false);

    size_t expected_size = 0;
    uint8_t* buffer;

    if(argc == 0)
        return LJS_Throw(ctx, "U8Pipe write need 1 argument", "U8Pipe.write(data: Uint8Array): Promise<boolean>");

    buffer = JS_GetUint8Array(ctx, &expected_size, argv[0]);
    if(!buffer) return JS_EXCEPTION;

    if(expected_size == 0) return LJS_NewResolvedPromise(ctx, JS_UNDEFINED);

    pipe -> refcount ++;
    if (pipe -> fdpipe){
        struct promise* promise = LJS_NewPromise(ctx);
        // 发送数据
        NEW_TASK(promise, pipe);
        task -> write_data = JS_DupValue(ctx, argv[0]); 
        task -> promise = promise;
        LJS_evfd_write(pipe -> pipe.fdpipe -> fd, buffer, expected_size, evwrite_callback, task);
        return promise -> promise;
    }else{  // U8PIPE
        // 写入函数
        pipe -> pipe.pipe -> write_lock = true;
        JSValue ret = JS_Call(ctx, pipe -> pipe.pipe -> write_func, this_val, 1, (JSValueConst[]){argv[1]});
        EXCEPTION_THEN_CLOSE(ret, JS_EXCEPTION);
        pipe_handle_promise(ctx, ret, pipe -> pipe.pipe);
        U8PIPE_UNREF(pipe);
        return ret;
    }
}

static JSValue js_U8Pipe_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    CHECK_U8PIPE_CLOSED(pipe);

    if(pipe -> fdpipe && pipe -> pipe.fdpipe -> is_socket)
        shutdown(LJS_evfd_getfd(pipe -> pipe.fdpipe -> fd, NULL), SHUT_RDWR);
    else
        LJS_evfd_close(pipe -> pipe.fdpipe -> fd);

    return JS_UNDEFINED;
}

static void sync_promise_proxy(EvFD* fd, bool success, void* opaque){
    struct promise* promise = opaque;
    if(((uintptr_t)(promise -> user_data) ++) == 1){
        if(success)
            LJS_Promise_Resolve(promise, JS_UNDEFINED);
        else
            LJS_Promise_Reject(promise, "Pipe closed");
    }
}

static JSValue js_U8Pipe_sync(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    CHECK_U8PIPE_CLOSED(pipe);
    if(!pipe -> fdpipe) return LJS_Throw(ctx, "U8Pipe.sync() only support for fdpipe", NULL);

    struct promise* promise = LJS_NewPromise(ctx);
    promise -> user_data = 0;
    LJS_evfd_wait(pipe -> pipe.fdpipe -> fd, false, sync_promise_proxy, promise);
    LJS_evfd_wait(pipe -> pipe.fdpipe -> fd, true, sync_promise_proxy, promise);
    return promise -> promise;
}

static JSValue js_U8Pipe_readline(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    CHECK_U8PIPE_READABLE(pipe);
    CHECK_U8PIPE_LOCKED(pipe, true);

    // todo: supoort normal pipe
    if(!pipe -> fdpipe){
        return LJS_Throw(ctx, "U8Pipe.readline() only support for fdpipe", NULL);
    }

    uint32_t expected_size = 16 * 1024;
    if(argc == 1) JS_ToUint32(ctx, &expected_size, argv[0]);
    uint8_t* buffer = js_malloc(ctx, expected_size);

    struct promise* promise = LJS_NewPromise(ctx);
    if(!promise){
        return JS_ThrowOutOfMemory(ctx);
    }

    U8PIPE_FD_EOFCHECK(pipe, promise, {
        EXPORT_EOF(pipe, buf, pipe -> pipe.fdpipe -> eofbuf_size);
        LJS_Promise_Resolve(promise, buf);
        return promise -> promise;
    });

    NEW_TASK(promise, pipe);

    pipe -> refcount ++;
    LJS_evfd_readline(pipe -> pipe.fdpipe -> fd, expected_size, buffer, evread_callback, task);
    return promise -> promise;
}

static JSValue js_u8pipe_get_closed(JSContext *ctx, JSValueConst this_val) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    return JS_NewBool(ctx, u8pipe_closed(ctx, pipe));
}

static struct U8PipeTransfer* pipeto_transfer_new(JSContext* ctx, JSValue jsfrom, JSValue jsto, struct U8Pipe_T* from, struct U8Pipe_T* to){
    struct U8PipeTransfer* transfer = js_malloc(ctx, sizeof(struct U8PipeTransfer));
    transfer -> pipe[0] = from;
    transfer -> pipe[1] = to;
    transfer -> promise = LJS_NewPromise(ctx);
    transfer -> active = true;
    transfer -> aborted = false;
    return transfer;
}

#define FREE_TRANSFER(ctx, pipe, pipe2) pipeto_transfer_free(ctx, pipe -> transfer); pipe -> transfer = NULL;
static void pipeto_transfer_free(JSContext* ctx, struct U8PipeTransfer* transfer){
    U8PIPE_UNREF(transfer -> pipe[0]);
    U8PIPE_UNREF(transfer -> pipe[1]);
    js_free(ctx, transfer);
}

#define CALL_FILTER(dat, filter) JSValue __ret = JS_Call(ctx, filter, JS_NULL, 1, (JSValueConst[]){ dat }); \
    if(JS_IsException(__ret)) \
        goto done; \
    bool __ret_bool = JS_ToBool(ctx, __ret); \
    if(!__ret_bool) goto _false; \
    size_t size; \
    JS_GetUint8Array(ctx, &size, dat); \
    if(size == 0) goto _false;

static bool pipeto_transfer_filter(struct Buffer* buf, void* user_data){
    struct U8PipeTransfer* transfer = user_data;
    JSValue filter = transfer -> filter;
    JSContext* ctx = transfer -> promise -> ctx;

    buffer_flat(buf);
    JSValue arr = JS_NewUint8Array(ctx, buf -> buffer, buffer_used(buf), NULL, NULL, false);
    CALL_FILTER(arr, filter);
    buf -> end = size;  // size from filter
    return true;    // continue
    
_false:
    js_free(ctx, buf -> buffer);
    buffer_free(buf);
    return true;    // skip current buffer

done:
    js_free(ctx, buf -> buffer);
    buffer_free(buf);
    LJS_Promise_Resolve(transfer -> promise, JS_UNDEFINED);
    FREE_TRANSFER(ctx, transfer -> pipe[0], transfer -> pipe[1]);
    return false;   // stop
}

static void pipeto_transfer_callback(struct EvFD* from, struct EvFD* to, EvPipeToNotifyType type, void* user_data){
    struct U8PipeTransfer* transfer = user_data;
    JSContext* ctx = transfer -> promise -> ctx;
    LJS_Promise_Resolve(transfer -> promise, JS_UNDEFINED);
    FREE_TRANSFER(ctx, transfer -> pipe[0], transfer -> pipe[1]);
}

#define GET_ALL_OPAQUE(pipe, pipe2) struct U8Pipe_T* pipe_ ##pipe = JS_GetOpaque(pipe, U8Pipe_class_id); struct U8Pipe_T* pipe_ ##pipe2 = JS_GetOpaque(pipe2, U8Pipe_class_id);
static JSValue pipeto_init_fd2fd(JSContext* ctx, JSValue from, JSValue to, JSValue filter){
    GET_ALL_OPAQUE(from, to);
    EvFD *fd_in = pipe_from -> pipe.fdpipe -> fd,
               *fd_out = pipe_to -> pipe.fdpipe -> fd;

    struct U8PipeTransfer* t = 
        pipe_to -> transfer = 
        pipe_from -> transfer = 
            pipeto_transfer_new(ctx, from, to, pipe_from, pipe_to);
    if(!LJS_evfd_pipeTo(fd_in, fd_out, 
        JS_IsFunction(ctx, filter) ? pipeto_transfer_filter : NULL, t, 
        pipeto_transfer_callback, t
    )){ 
        pipeto_transfer_free(ctx, t);
        LJS_Promise_Reject(t -> promise, "Failed to pipe");
    }
    return t -> promise -> promise;
}

// predef
static void pipeto_promisecb2(JSContext* ctx, bool is_error, JSValue val, void* user_data);
static int pipeto_evloopcb(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data);

// write promise callback(continue poll)
static void pipeto_promisecb(JSContext* ctx, bool is_error, JSValue val, void* user_data){
    struct U8PipeTransfer* transfer = user_data;
    if(is_error){
        JSContext* ctx = transfer -> promise -> ctx;
        LJS_Promise_Resolve(transfer -> promise, JS_UNDEFINED);
        transfer -> pipe[1] -> pipe.pipe -> write_lock = false; // release lock
        FREE_TRANSFER(ctx, transfer -> pipe[0], transfer -> pipe[1]);
    }else if(transfer -> pipe[0] -> fdpipe){
        // read from pipe
        uint8_t* buf = js_malloc(ctx, PIPE_u8_buf_size);
        LJS_evfd_read(
            transfer -> pipe[0] -> pipe.fdpipe -> fd, PIPE_u8_buf_size, buf, 
            pipeto_evloopcb, transfer
        );
    }else{
        // continue pull
        JSValue pull = transfer -> pipe[0] -> pipe.pipe -> pull_func;
        JSValue ret = JS_Call(ctx, pull, JS_NULL, 0, NULL);
        LJS_enqueue_promise_job(ctx, ret, pipeto_promisecb2, transfer);
    }
}

static void pipeto_promisecb_evfdproxy(struct EvFD* evfd, bool success, void* user_data){
    struct U8PipeTransfer* transfer = user_data;
    pipeto_promisecb(transfer -> promise -> ctx, !success, JS_UNDEFINED, transfer);
}

// data promise callback
static void pipeto_promisecb2(JSContext* ctx, bool is_error, JSValue val, void* user_data){
    struct U8PipeTransfer* transfer = user_data;
    if(is_error){
        JSValue close1 = transfer -> pipe[1] -> pipe.pipe -> close_func,
            close2 = transfer -> pipe[0] -> pipe.pipe -> close_rs;
        JS_Call(ctx, close1, JS_NULL, 1, (JSValueConst[]){ val });
        JS_Call(ctx, close2, JS_NULL, 0, NULL);

done:
        JSContext* ctx = transfer -> promise -> ctx;
        LJS_Promise_Resolve(transfer -> promise, JS_UNDEFINED);
        FREE_TRANSFER(ctx, transfer -> pipe[0], transfer -> pipe[1]);
    }else if(transfer -> pipe[1] -> fdpipe){
        size_t psize;
        uint8_t* pbuf = JS_GetUint8Array(ctx, &psize, val);
        if(!pbuf) goto _false;
        LJS_evfd_write(transfer -> pipe[1] -> pipe.fdpipe -> fd, pbuf, psize, pipeto_promisecb_evfdproxy, transfer);
    }else{
        JSValue write = transfer -> pipe[1] -> pipe.pipe -> write_func;
        if(!JS_IsNull(write) || !JS_IsUndefined(write)){
            CALL_FILTER(val, transfer -> filter);
        }
        JSValue ret = JS_Call(ctx, write, JS_NULL, 1, (JSValueConst[]){ val });
        LJS_enqueue_promise_job(ctx, ret, pipeto_promisecb, transfer);
        return;

_false:
        JS_FreeValue(ctx, val);
    }
}

static int pipeto_evloopcb(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data){
    struct U8PipeTransfer* t = user_data;
    JSContext* ctx = t -> promise -> ctx;
    if(read_size > 0){
        JSValue data = JS_NewUint8Array(ctx, buffer, read_size, free_js_malloc, NULL, false);
        JSValue write = t -> pipe[1] -> pipe.pipe -> write_func;
        if(!JS_IsNull(t -> filter)){
            CALL_FILTER(data, t -> filter);
        }
        JSValue ret = JS_Call(ctx, write, JS_NULL, 1, (JSValueConst[]){ data });
        LJS_enqueue_promise_job(ctx, ret, pipeto_promisecb, t);

_false:
        js_free(ctx, buffer);
    }else{
done:
        JSContext* ctx = t -> promise -> ctx;
        LJS_Promise_Resolve(t -> promise, JS_UNDEFINED);
        FREE_TRANSFER(ctx, t -> pipe[0], t -> pipe[1]);
    }

    return EVCB_RET_DONE;   // always stop the current task
}

static JSValue pipeto_init_any2any(JSContext* ctx, JSValue from, JSValue to, JSValue filter){
    GET_ALL_OPAQUE(from, to);
    struct U8PipeTransfer* t = 
        pipe_from -> transfer = 
            pipeto_transfer_new(ctx, from, to, pipe_from, pipe_to);
    if(!t){
        LJS_Promise_Reject(t -> promise, "Failed to pipe");
        goto end;
    }
    t -> filter = JS_DupValue(ctx, filter);

    pipeto_promisecb(ctx, false, JS_UNDEFINED, t);  // start poll
end:
    return t -> promise -> promise;
}

static JSValue js_U8Pipe_pipeTo(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc == 0)
        return LJS_Throw(ctx, "Expected at least 1 arguments", "U8Pipe.pipeTo(to: U8Pipe, filter?: Function): Promise<boolean>");
    GET_U8PIPE_OPAQUE(from, this_val);
    CHECK_U8PIPE_READABLE(from);
    CHECK_U8PIPE_LOCKED(from, true);

    JSValue to = argv[0], filter = argc == 2 ? argv[1] : JS_NULL;
    struct U8Pipe_T* to_data = JS_GetOpaque(to, U8Pipe_class_id);
    if(!to_data){
        return LJS_Throw(ctx, "Expected a U8Pipe object", "U8Pipe.pipeTo(to: U8Pipe, filter?: Function): Promise<boolean>");
    }
    CHECK_U8PIPE_CLOSED(to_data);
    CHECK_U8PIPE_WRITEABLE(to_data);
    CHECK_U8PIPE_LOCKED(to_data, false);
    if(!to_data -> fdpipe){
        to_data -> pipe.pipe -> write_lock = true;
    }

    if(from -> fdpipe && from -> pipe.fdpipe -> closed && from -> pipe.fdpipe -> data_before_eof){
        // write to target
        js_U8Pipe_write(ctx, to, 1, (JSValueConst[]){
            JS_NewUint8Array(ctx, from -> pipe.fdpipe -> data_before_eof, from -> pipe.fdpipe -> eofbuf_size, free_js_malloc, NULL, false)
        });
        from -> pipe.fdpipe -> data_before_eof = NULL;

        JSValue prom[2];
        JSValue ret = JS_NewPromiseCapability(ctx, prom);
        JS_FreeValue(ctx, prom[1]);
        JS_Call(ctx, prom[0], JS_NULL, 1, (JSValueConst[]){ JS_NewBool(ctx, true) });
        JS_FreeValue(ctx, prom[0]);
        return ret;
    }

    // Note: use ref to control lifetime, -- to release
    CHECK_U8PIPE_CLOSED(from);
    from -> refcount ++;
    to_data -> refcount ++;

    JSValue ret;
    if(from -> fdpipe && to_data -> fdpipe){
        ret = pipeto_init_fd2fd(ctx, this_val, to, filter);
    }else{
        ret = pipeto_init_any2any(ctx, this_val, to, filter);
    }
    return ret;
}

static void evclose_callback(EvFD* fd, void* opaque){
    struct U8Pipe_T* pipe = (struct U8Pipe_T*)opaque;
    struct FDPipe_T* fdpipe = pipe -> pipe.fdpipe;
    JSContext* ctx = fdpipe -> ctx;
    U8PIPE_UNREF(pipe);

    if(!fdpipe -> closed && !fdpipe -> data_before_eof){
        fdpipe -> closed = true;
        u8pipe_handle_close(JS_GetRuntime(ctx), (struct U8Pipe_T*)opaque, true);
    }
}

static JSValue js_U8Pipe_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, U8Pipe_class_id);
    if(JS_IsException(obj)){
        return JS_ThrowOutOfMemory(ctx);
    }

    // 读取参数
    uint32_t type;
    if(argc == 0 || !JS_IsObject(argv[0])){
        return LJS_Throw(ctx, "illegal control object", "same as `new Pipe()`");
    }
    if(argc >= 2) JS_ToUint32(ctx, &type, argv[1]);
    else{   // auto detect type
        type = 0;
        if(JS_IsFunction(ctx, JS_GetPropertyStr(ctx, argv[0], "pull")))
            type |= PIPE_READ;
        if(JS_IsFunction(ctx, JS_GetPropertyStr(ctx, argv[0], "write")))
            type |= PIPE_WRITE;
    }

    // 从constructor注册的pipe都是U8_PIPE
    struct U8Pipe_T *pipe = js_malloc(ctx, sizeof(struct U8Pipe_T));
    pipe -> fdpipe = false;
    pipe -> transfer = NULL;
    pipe -> pipe.pipe = js_malloc(ctx, sizeof(struct Pipe_T));
    pipe -> pipe.pipe -> flag = type;
    pipe -> pipe.pipe -> pull_func = JS_DupValue(ctx, JS_GetPropertyStr(ctx, argv[0], "pull"));
    pipe -> pipe.pipe -> write_func = JS_DupValue(ctx, JS_GetPropertyStr(ctx, argv[0], "write"));
    pipe -> pipe.pipe -> close_func = JS_DupValue(ctx, JS_GetPropertyStr(ctx, argv[0], "close"));
    pipe -> pipe.pipe -> ctx = ctx;
    pipe -> pipe.pipe -> read_lock = false;
    pipe -> pipe.pipe -> write_lock = false;
    buffer_init(&pipe -> pipe.pipe -> read_buf, NULL, PIPE_u8_buf_size);
    pipe -> pipe.pipe -> closed = false;
    pipe -> refcount = 1;   // owned by QuickJS only
    JS_SetOpaque(obj, pipe);

    // 创建一个close Promise
    DEF_ONCLOSE(pipe -> pipe.pipe);

    // 完成
    return obj;
}

static inline int get_fd_from_pipe(JSContext* ctx, JSValueConst pipe){
    struct U8Pipe_T* pipe_data = JS_GetOpaque(pipe, U8Pipe_class_id);
    if(!pipe_data || !pipe_data -> fdpipe) return -1;
    EvFD* fd = pipe_data -> pipe.fdpipe -> fd;
    return LJS_evfd_getfd(fd, NULL);
}

static JSValue js_iopipe_setraw(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0)
        return LJS_Throw(ctx, "Expected a boolean value", "U8Pipe(tty).ttyRaw(set_to_raw: boolean): boolean");
    
    int fdnum = get_fd_from_pipe(ctx, this_val);
    if(fdnum == -1) return LJS_Throw(ctx, "Expected a U8Pipe object", NULL);
    bool res = isatty(fdnum);

    if(JS_ToBool(ctx, argv[0])){
        // set raw mode
        struct termios tty;

        memset(&tty, 0, sizeof(tty));
        tcgetattr(fdnum, &tty);

        tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
                            |INLCR|IGNCR|ICRNL|IXON);
        tty.c_oflag |= OPOST;
        tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
        tty.c_cflag &= ~(CSIZE|PARENB);
        tty.c_cflag |= CS8;
        tty.c_cc[VMIN] = 1;
        tty.c_cc[VTIME] = 0;

        tcsetattr(fdnum, TCSANOW, &tty);
    }

    return JS_NewBool(ctx, res);
}

#define GET_FD(this) int fdnum = get_fd_from_pipe(ctx, this_val); \
    if(fdnum == -1) return LJS_Throw(ctx, "Expected a U8Pipe object", NULL);

static JSValue js_iopipe_get_size(JSContext *ctx, JSValueConst this_val){
    GET_FD(this_val);

    struct winsize size;
    if(ioctl(fdnum, TIOCGWINSZ, &size) == -1){
        return LJS_Throw(ctx, "Failed to get terminal size", NULL);
    }

    return JS_NewArrayFrom(ctx, 2, (JSValueConst[]){JS_NewInt32(ctx, size.ws_row), JS_NewInt32(ctx, size.ws_col)});
}

static JSValue js_iopipe_set_size(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    GET_FD(this_val);

    uint32_t rows, cols;
    if (
        JS_ToUint32(ctx, &rows, JS_GetPropertyUint32(ctx, value, 0)) != 0 ||
        JS_ToUint32(ctx, &cols, JS_GetPropertyUint32(ctx, value, 1)) != 0
    ){
        return LJS_Throw(ctx, "expected array of two integers", NULL);
    }

    struct winsize size;
    size.ws_row = rows;
    size.ws_col = cols;
    if(ioctl(fdnum, TIOCSWINSZ, &size) == -1){
        return LJS_Throw(ctx, "Failed to set terminal size", NULL);
    }

    return JS_TRUE;
}

static JSValue js_iopipe_get_title(JSContext *ctx, JSValueConst this_val){
    GET_FD(this_val);

    char title[1024];
    if(ioctl(fdnum, TIOCGWINSZ, title) == -1){
        return LJS_Throw(ctx, "Failed to get terminal title", NULL);
    }

    return JS_NewString(ctx, title);
}

static JSValue js_iopipe_set_title(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    GET_FD(this_val);

    const char* title = JS_ToCString(ctx, value);
    if(!title) return JS_EXCEPTION;

    if(ioctl(fdnum, TIOCSWINSZ, title) == -1){
        JS_FreeCString(ctx, title);
        return LJS_Throw(ctx, "Failed to set terminal title", NULL);
    }

    JS_FreeCString(ctx, title);
    return JS_TRUE;
}

static JSValue js_iopipe_istty(JSContext *ctx, JSValueConst this_val){
    int fdnum = get_fd_from_pipe(ctx, this_val);
    if(fdnum == -1) return LJS_Throw(ctx, "Expected a U8Pipe object", NULL);

    return JS_NewBool(ctx, isatty(fdnum));
}

static JSValue js_iopipe_fflush(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct U8Pipe_T* pipe = JS_GetOpaque(this_val, U8Pipe_class_id);
    if(!pipe) return LJS_Throw(ctx, "Expected a U8Pipe object", NULL);
    EvFD* fd = pipe -> pipe.fdpipe -> fd;
    if(LJS_evfd_isAIO(fd)) return JS_UNDEFINED; // 不支持异步IO
    int fdnum = LJS_evfd_getfd(fd, NULL);

    if(isatty(fdnum)){
        if(tcflush(fdnum, TCIOFLUSH) == -1){
            return LJS_Throw(ctx, "Failed to flush terminal", NULL);
        }
    }else{
        if(fdatasync(fdnum) == -1){
            return LJS_Throw(ctx, "Failed to flush file", NULL);
        }
    }
    return JS_UNDEFINED;
}

static JSValue js_iopipe_fseek(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    GET_U8PIPE_OPAQUE(src, this_val);
    CHECK_U8PIPE_CLOSED(src);
    CHECK_U8PIPE_READABLE(src);

    if(argc!= 1 || !JS_IsNumber(argv[0])){
        return LJS_Throw(ctx, "Expected a number", "U8Pipe.fseek(offset: number, baseline?: string): void");
    }

    uint32_t offset;
    if(JS_ToUint32(ctx, &offset, argv[0]) == -1){
        return JS_EXCEPTION;
    }

    int seek = SEEK_SET;
    if(argc >= 2 && JS_IsString(argv[1])){
        const char* base = JS_ToCString(ctx, argv[1]);
        if(strcmp(base, "current") == 0){
            seek = SEEK_CUR;
        }else if(strcmp(base, "end") == 0){
            seek = SEEK_END;
        }else if(strcmp(base, "start") == 0){
            seek = SEEK_SET;
        }
        JS_FreeCString(ctx, base);
    }

    if(!src -> fdpipe) return LJS_Throw(ctx, "Expected a U8Pipe from fopen", NULL);
    int fdnum = LJS_evfd_getfd(src -> pipe.fdpipe -> fd, NULL);
    if(lseek(fdnum, offset, seek) == -1){
        return LJS_Throw(ctx, "Failed to seek: %s", NULL, strerror(errno));
    }

    LJS_evfd_clearbuf(src -> pipe.fdpipe -> fd);
    return JS_UNDEFINED;
}

static JSClassDef U8Pipe_class = {
    "U8Pipe",
    .finalizer = js_u8pipe_cleanup
};
static const JSCFunctionListEntry U8Pipe_proto_funcs[] = {
    JS_CFUNC_DEF("read", 0, js_U8Pipe_read),
    JS_CFUNC_DEF("write", 1, js_U8Pipe_write),
    JS_CFUNC_DEF("close", 0, js_U8Pipe_close),
    JS_CGETSET_DEF("closed", js_u8pipe_get_closed, NULL),
    JS_CFUNC_DEF("readline", 1, js_U8Pipe_readline),
    JS_CFUNC_DEF("pipeTo", 1, js_U8Pipe_pipeTo),
    JS_CFUNC_DEF("sync", 0, js_U8Pipe_sync),

    JS_CFUNC_DEF("ttyRaw", 1, js_iopipe_setraw),
    JS_CGETSET_DEF("ttySize", js_iopipe_get_size, js_iopipe_set_size),
    JS_CGETSET_DEF("isTTY", js_iopipe_istty, NULL),
    JS_CGETSET_DEF("ttyTitle", js_iopipe_get_title, js_iopipe_set_title),
    JS_CFUNC_DEF("fflush", 0, js_iopipe_fflush),
    JS_CFUNC_DEF("fseek", 1, js_iopipe_fseek),
    
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "U8Pipe", JS_PROP_CONFIGURABLE),
};

// 注册方法
bool LJS_init_pipe(JSContext *ctx) {
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JSRuntime* rt = JS_GetRuntime(ctx);

    // U8Pipe
    JS_NewClassID(rt, &U8Pipe_class_id);
    if(-1 == JS_NewClass(rt, U8Pipe_class_id, &U8Pipe_class)) return false;
    JSValue u8pipe_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, u8pipe_proto, U8Pipe_proto_funcs, countof(U8Pipe_proto_funcs));
    JS_SetClassProto(ctx, U8Pipe_class_id, u8pipe_proto);

    JSValue u8pipe_constructor = JS_NewCFunction2(ctx, js_U8Pipe_constructor, "U8Pipe", 2, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, u8pipe_constructor, u8pipe_proto);
    JS_SetPropertyStr(ctx, global_obj, "U8Pipe", u8pipe_constructor);

    // Pipe
    JS_NewClassID(rt, &Pipe_class_id);
    if(-1 == JS_NewClass(rt, Pipe_class_id, &Pipe_class)) return false;
    JSValue pipe_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, pipe_proto, Pipe_proto_funcs, countof(Pipe_proto_funcs));
    JS_SetClassProto(ctx, Pipe_class_id, pipe_proto);

    JSValue pipe_constructor = JS_NewCFunction2(ctx, js_pipe_constructor, "Pipe", 0, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, pipe_constructor, pipe_proto);
    JS_SetPropertyStr(ctx, global_obj, "Pipe", pipe_constructor);

    JS_FreeValue(ctx, global_obj);

    return true;
}

// C语言暴露接口
/**
 * 创建一个U8Pipe对象
 * @param ctx JS运行时上下文
 * @param type 管道类型
 * @param pipe 管道结构体
 */
static inline JSValue u8pipe_new(JSContext *ctx, bool fdpipe, struct U8Pipe_T *pipe){
    JSValue obj = JS_NewObjectClass(ctx, U8Pipe_class_id);
    pipe -> transfer = NULL;
    pipe -> fdpipe = fdpipe;
    JS_SetOpaque(obj, pipe);

    pipe -> refcount = 1;
    if(fdpipe){
        pipe -> pipe.fdpipe = js_malloc(ctx, sizeof(struct FDPipe_T));
        DEF_ONCLOSE2(pipe -> pipe.fdpipe);
        
        pipe -> pipe.fdpipe -> closed = false;
        // not locked check
        pipe -> pipe.fdpipe -> data_before_eof = NULL;
        pipe -> pipe.fdpipe -> is_socket = false;
    }else{
        pipe -> pipe.pipe = js_malloc(ctx, sizeof(struct Pipe_T));
        DEF_ONCLOSE(pipe -> pipe.pipe);
        pipe -> pipe.pipe -> closed = false;
    }

    return obj;
}

void u8pipe_finalizer_cb(EvFD* fd, struct Buffer* buf, void* opaque){
    struct U8Pipe_T* pipe = opaque;
    struct FDPipe_T* fdp = pipe -> pipe.fdpipe;
    if(!buffer_is_empty(buf)){
        uint8_t* buf2 = js_malloc(fdp -> ctx, buffer_used(buf));
        fdp -> eofbuf_size = buffer_copyto(buf, buf2, UINT32_MAX);
        fdp -> data_before_eof = buf2;
    }
}

/**
 * 创建一个FDPipe对象
 * @param ctx JS运行时上下文
 * @param fd 管道的文件描述符
 * @param flag 管道的标志位
 * @param buf_size 缓冲区大小
 */
JSValue LJS_NewFDPipe(JSContext *ctx, int fd, uint32_t flag, uint32_t buf_size, EvFD** ref){
    if(!ctx) abort();
    
    struct U8Pipe_T *pipe = js_malloc(ctx, sizeof(struct U8Pipe_T));

    if(!pipe){
        return JS_ThrowOutOfMemory(ctx);
    }

    EvFD* evfd = LJS_evfd_new(fd, flag & PIPE_AIO, flag & PIPE_READ, flag & PIPE_WRITE, buf_size, evclose_callback, pipe);
    
    if (!evfd){
        js_free(ctx, pipe);
        return LJS_Throw(ctx, "Failed to bind FD: %s", NULL, strerror(errno));
    }

    JSValue obj = u8pipe_new(ctx, true, pipe);

    if((flag & PIPE_READ) && !(flag & PIPE_AIO))
        LJS_evfd_finalizer(evfd, u8pipe_finalizer_cb, pipe);

#ifdef LJS_DEBUG
    if (flag & PIPE_SOCKET)
        printf("fdpipe socket: %d\n", fd);
#endif

    pipe -> pipe.fdpipe -> fd = evfd;
    pipe -> pipe.fdpipe -> flag = flag;
    pipe -> pipe.fdpipe -> ctx = ctx;
    pipe -> pipe.fdpipe -> closed = false;
    pipe -> pipe.fdpipe -> is_socket = flag & PIPE_SOCKET;
    pipe -> refcount = 2;   // owned by EventLoop and QuickJS

    if(ref) *ref = evfd;
    return obj;
}

static JSValue c_pipe_proxy(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic, JSValue* func_data){
    // struct U8Pipe_T* pipe = JS_VALUE_GET_PTR(func_data[0]);
    PipeCallback cb = JS_VALUE_GET_PTR(func_data[magic]);
    void* ptr = JS_VALUE_GET_PTR(func_data[4]);
    JSValue ret = argc == 1 ? argv[0] : JS_UNDEFINED;
    return cb == NULL ? JS_NULL : cb(ctx, ptr, ret);
}

/**
 * 创建一个C操作的暴露给JS的管道
 * @param ctx JS运行时上下文
 * @param flag 管道的标志位
 * @param buf_size 缓冲区大小
 * @param poll_cb 轮询回调
 * @param write_cb 写入回调
 * @param close_cb 关闭回调
 * @param user_data 用户数据，暴露在回调的`void* ptr`
 */
JSValue LJS_NewU8Pipe(JSContext *ctx, uint32_t flag, uint32_t buf_size, 
    PipeCallback poll_cb, PipeCallback write_cb, PipeCallback close_cb,
    void* user_data
){
    if(!ctx) abort();
    struct U8Pipe_T *pipe = js_malloc(ctx, sizeof(struct U8Pipe_T));
    JSValue obj = u8pipe_new(ctx, false, pipe);

    JSValue data[] = { 
        JS_MKPTR(JS_TAG_INT, pipe),
        JS_MKPTR(JS_TAG_INT, poll_cb),
        JS_MKPTR(JS_TAG_INT, write_cb),
        JS_MKPTR(JS_TAG_INT, close_cb),
        JS_MKPTR(JS_TAG_INT, user_data)
    };
    JSValue pull_func = JS_NewCFunctionData(ctx, c_pipe_proxy,  0, 1, 5, data),
        write_func = JS_NewCFunctionData(ctx, c_pipe_proxy, 1, 2, 5, data),
        close_func = JS_NewCFunctionData(ctx, c_pipe_proxy, 0, 3, 5, data);
    pipe -> pipe.pipe -> pull_func = JS_DupValue(ctx, pull_func);
    pipe -> pipe.pipe -> write_func = JS_DupValue(ctx, write_func);
    pipe -> pipe.pipe -> close_func = JS_DupValue(ctx, close_func);
    pipe -> pipe.pipe -> flag = flag;
    pipe -> pipe.pipe -> read_buf = NULL;
    pipe -> pipe.pipe -> closed = false;
    buffer_init(&pipe -> pipe.pipe -> read_buf, NULL, PIPE_u8_buf_size);
    return obj;
}

/**
 * 创建一个可以传递任何数据的Pipe
 * @param ctx JS运行时上下文
 * @param flag 管道的标志位
 * @param poll_cb 轮询回调
 * @param write_cb 写入回调
 * @param close_cb 关闭回调
 * @param user_data 用户数据，暴露在回调的`void* ptr`
 */
JSValue LJS_NewPipe(JSContext *ctx, uint32_t flag,
    PipeCallback poll_cb, PipeCallback write_cb, PipeCallback close_cb,
    void* user_data
){
    if(!ctx) abort();
    struct Pipe_T *pipe = js_malloc(ctx, sizeof(struct Pipe_T));
    JSValue obj = JS_NewObjectClass(ctx, Pipe_class_id);
    
    JSValue data[] = { 
        JS_MKPTR(JS_TAG_INT, pipe),
        JS_MKPTR(JS_TAG_INT, poll_cb),
        JS_MKPTR(JS_TAG_INT, write_cb),
        JS_MKPTR(JS_TAG_INT, close_cb),
        JS_MKPTR(JS_TAG_INT, user_data)
    };
    JSValue pull_func = JS_NewCFunctionData(ctx, c_pipe_proxy,  0, 1, 5, data),
        write_func = JS_NewCFunctionData(ctx, c_pipe_proxy, 1, 2, 5, data),
        close_func = JS_NewCFunctionData(ctx, c_pipe_proxy, 0, 3, 5, data);
    pipe -> pull_func = JS_DupValue(ctx, pull_func);
    pipe -> write_func = JS_DupValue(ctx, write_func);
    pipe -> close_func = JS_DupValue(ctx, close_func);
    pipe -> flag = flag;
    pipe -> read_buf = NULL;
    pipe -> closed = false;
    pipe -> read_lock = false;
    pipe -> write_lock = false;
    buffer_init(&pipe -> read_buf, NULL, PIPE_u8_buf_size);

    DEF_ONCLOSE(pipe);
    JS_SetOpaque(obj, pipe);

    return obj;
}

EvFD* LJS_GetPipeFD(JSContext *ctx, JSValueConst obj){
    struct U8Pipe_T* pipe = JS_GetOpaque(obj, U8Pipe_class_id);
    if(!pipe) return NULL;
    return pipe -> pipe.fdpipe ? pipe -> pipe.fdpipe -> fd : NULL;
}