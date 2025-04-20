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

#define PIPE_READ 0b1
#define PIPE_WRITE 0b10

// 从FD创建的管道
struct FDPipe_T{
    EvFD* fd;
    uint8_t flag;
    JSContext* ctx;

    struct promise* read;

    struct promise* write;
    // 从JS调用时传入的JSValue
    JSValue write_buf;

    JSValue close_rs;
    bool closed;
};
union FDPipeUnion_T{
    struct FDPipe_T* fdpipe;
    struct Pipe_T* pipe;
};
struct U8PipeTransfer {
    JSValue src;
    JSValue dest;
    struct promise* promise;
    bool active;
    bool aborted;
};
struct U8Pipe_T {
    bool fdpipe;
    union FDPipeUnion_T pipe;
    struct U8PipeTransfer* transfer;
};

struct Pipe_T{
    JSValue close_rs;
    JSValue pull_func;
    JSValue write_func;
    JSValue close_func;

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
#define CHECK_PIPE_CLOSED(pipe) if(pipe->closed) return JS_ThrowTypeError(ctx, "Pipe is closed");
#define CHECK_PIPE_READABLE(pipe) if(!(pipe->flag & PIPE_READ)) return JS_ThrowTypeError(ctx, "Pipe is not readable");
#define CHECK_PIPE_WRITEABLE(pipe) if(!(pipe->flag & PIPE_WRITE)) return JS_ThrowTypeError(ctx, "Pipe is not writable");
#define EXCEPTION_THEN_CLOSE(val, ret) if(JS_IsException(val)){ pipe_handle_close(JS_GetRuntime(ctx), pipe); return ret; }
#define DEF_ONCLOSE(pipe) { \
    JSValue promise[2]; \
    JSValue prom = JS_NewPromiseCapability(ctx, promise); \
    JS_SetPropertyStr(ctx, obj, "onclose", prom); \
    pipe -> close_rs = promise[0]; \
    JS_FreeValue(ctx, promise[1]); \
}

static void pipe_handle_close(JSRuntime *rt, struct Pipe_T *pipe) {
    if (pipe->closed) return;

    JS_FreeValueRT(rt, pipe->pull_func);
    JS_FreeValueRT(rt, pipe->write_func);
    JS_FreeValueRT(rt, pipe->close_func);

    JS_Call(pipe -> ctx, pipe->close_func, JS_NULL, 0, NULL);
    if(JS_IsFunction(pipe -> ctx, pipe->close_rs)){
        JS_Call(pipe -> ctx, pipe->close_rs, JS_NULL, 0, NULL);
        JS_FreeValueRT(rt, pipe->close_rs);
    }
    
    buffer_free(pipe->read_buf);
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
    data = JS_Call(ctx, pipe->pull_func, this_val, 0, NULL);
    EXCEPTION_THEN_CLOSE(data, JS_NULL);

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
    JSValue ret = JS_Call(ctx, pipe->write_func, this_val, 1, (JSValueConst[]){data});
    EXCEPTION_THEN_CLOSE(ret, JS_FALSE);

    return JS_TRUE;
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
    pipe -> closed = false;
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
#define GET_U8PIPE_OPAQUE(var, pipe) struct U8Pipe_T* var = ((struct U8Pipe_T*)JS_GetOpaque(pipe, U8Pipe_class_id)); if(!var) return JS_EXCEPTION;
#define CHECK_U8PIPE_CLOSED(pipe) if(u8pipe_closed(ctx, pipe)) return JS_ThrowTypeError(ctx, "U8Pipe is closed");
#define CHECK_U8PIPE_READABLE(pipe) if(!u8pipe_is(ctx, pipe, PIPE_READ)) return JS_ThrowTypeError(ctx, "U8Pipe is not readable");
#define CHECK_U8PIPE_WRITEABLE(pipe) if(!u8pipe_is(ctx, pipe, PIPE_WRITE)) return JS_ThrowTypeError(ctx, "U8Pipe is not writable");
#define CHECK_U8PIPE_LOCKED(pipe, read) if(u8pipe_locked(ctx, pipe, read)) return JS_ThrowTypeError(ctx, "U8Pipe is locked");

#undef EXCEPTION_THEN_CLOSE
#define EXCEPTION_THEN_CLOSE(val, ret) if(JS_IsException(val)){ u8pipe_handle_close(JS_GetRuntime(ctx), pipe); return ret; }

static void u8pipe_handle_close(JSRuntime *rt, struct U8Pipe_T* pipe){

    if(pipe -> transfer){
        JS_FreeValueRT(rt, pipe->transfer->src);
        JS_FreeValueRT(rt, pipe->transfer->dest);
        LJS_FreePromise(pipe->transfer->promise);
        js_free_rt(rt, pipe->transfer);
    }

    if(pipe -> fdpipe){
        if(!pipe -> pipe.fdpipe -> closed){
            LJS_evfd_close(pipe -> pipe.fdpipe  -> fd);
            if(pipe -> pipe.fdpipe -> read) LJS_FreePromise(pipe -> pipe.fdpipe  -> read);
            if(pipe -> pipe.fdpipe  -> write) LJS_FreePromise(pipe -> pipe.fdpipe  -> write);
            if(JS_IsFunction(pipe -> pipe.fdpipe -> ctx, pipe -> pipe.fdpipe  -> close_rs)) JS_FreeValueRT(rt, pipe -> pipe.fdpipe  -> close_rs);
            pipe -> pipe.fdpipe  -> closed = true;
        }
        js_free_rt(rt, pipe -> pipe.fdpipe );
        // pipe -> pipe.fdpipe  -> fd was freed by evfd
    }else{
        pipe_handle_close(rt, pipe -> pipe.pipe);
    }
    js_free_rt(rt, pipe);
}

static void js_u8pipe_cleanup(JSRuntime *rt, JSValue val) {
    // U8Pipe will be 
    // struct U8Pipe_T* pipe = ((struct U8Pipe_T*)JS_GetOpaque(val, U8Pipe_class_id));
    // 如果这里释放，Pipe会立即close，导致任务不正常
}

static inline bool u8pipe_is(JSContext *ctx, struct U8Pipe_T* pipe, uint8_t flag) {
    if(pipe->fdpipe){
        return pipe -> pipe.fdpipe -> flag & flag;
    }else{
        return pipe -> pipe.pipe -> flag & flag;
    }
}

static inline bool u8pipe_locked(JSContext *ctx, struct U8Pipe_T* pipe, bool read){
    if(pipe->fdpipe){
        return false;
    }else{
        return read
            ? pipe -> pipe.fdpipe -> read != NULL
            : pipe -> pipe.fdpipe -> write != NULL;
    }
}

static inline bool u8pipe_closed(JSContext *ctx, struct U8Pipe_T* pipe) {
    if(pipe->fdpipe){
        return pipe -> pipe.fdpipe -> closed;
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

static void u8pipe_fill_by_callback(JSContext *ctx, struct Pipe_T* pipe, struct promise* promise, uint32_t expected_size, bool once){
    uint8_t* buf = js_malloc(ctx, expected_size);

    JSValue data;
    while (buffer_used(pipe -> read_buf) < expected_size){
        // 调用函数
        data = JS_Call(ctx, pipe -> pull_func, JS_NULL, 0, NULL);
        if(JS_IsException(data)){
            pipe_handle_close(JS_GetRuntime(ctx), pipe);
            return;
        }
        if(!JS_IsTypedArray(ctx, data)){
            LJS_Promise_Reject(promise, "Invaild data returned by pull()");
            JS_FreeValue(ctx, data);
            return;
        }
        
        // 填充
        size_t readed = 0;
        uint8_t* buf2 = JS_GetUint8Array(ctx, &readed, data);
        buffer_push(pipe -> read_buf, buf2, readed);
        JS_FreeValue(ctx, data);
        if(once) break;
    }

    // 提取数据
    uint8_t* ret_buf = buffer_export(pipe -> read_buf, &expected_size);
    JSValue ret = JS_NewUint8Array(ctx, ret_buf, (size_t)expected_size, free_malloc, NULL, false);

    // 调用回调
    LJS_Promise_Resolve(promise, ret);
    JS_FreeValue(ctx, data);
    js_free(ctx, buf);
}

static void evread_callback(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data){
    struct FDPipe_T* pipe = user_data;
    if(read_size > 0){
        JSValue data = JS_NewUint8Array(pipe -> ctx, buffer, read_size, free_js_malloc, NULL, false);
        LJS_Promise_Resolve(pipe -> read, data);
    }else{
        LJS_Promise_Reject(pipe -> read, "Pipe reached EOF");
    }
    LJS_FreePromise(pipe -> read);
    pipe -> read = NULL;
}

static JSValue js_U8Pipe_read(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    CHECK_U8PIPE_CLOSED(pipe);
    CHECK_U8PIPE_READABLE(pipe);
    CHECK_U8PIPE_LOCKED(pipe, true);

    uint32_t expected_size = 0;
    struct promise* promise = LJS_NewPromise(ctx);

    if(argc == 1){
        if(0 != JS_ToUint32(ctx, &expected_size, argv[0])){
            return LJS_Throw(ctx, "Expected size must be a number", "U8Pipe.read(expected_size)");
        }
    }

    if(pipe -> fdpipe){
        pipe -> pipe.fdpipe -> read = promise;

        if(expected_size == 0){
            uint8_t* buf = js_malloc(ctx, PIPE_u8_buf_size);
            LJS_evfd_read(pipe -> pipe.fdpipe -> fd, PIPE_u8_buf_size, buf, evread_callback, pipe -> pipe.fdpipe);
        }else{
            uint8_t* buf = js_malloc(ctx, expected_size);
            LJS_evfd_readsize(pipe -> pipe.fdpipe -> fd, expected_size, buf, evread_callback, pipe -> pipe.fdpipe);
        }
    }else{  // U8PIPE
        u8pipe_fill_by_callback(ctx, pipe -> pipe.pipe, promise, expected_size, expected_size == 0);
    }

    return promise -> promise;
}

static void evwrite_callback(EvFD* evfd, void* opaque){
    struct FDPipe_T* pipe = opaque;
    LJS_Promise_Resolve(pipe -> write, JS_UNDEFINED);
}

static JSValue js_U8Pipe_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    CHECK_U8PIPE_CLOSED(pipe);
    CHECK_U8PIPE_WRITEABLE(pipe);
    CHECK_U8PIPE_LOCKED(pipe, false);

    size_t expected_size = 0;
    uint8_t* buffer;
    struct promise* promise = LJS_NewPromise(ctx);

    if(argc == 0)
        return LJS_Throw(ctx, "U8Pipe write need 1 argument", "U8Pipe.write(data: Uint8Array): Promise<boolean>");

    buffer = JS_GetUint8Array(ctx, &expected_size, argv[0]);
    if(!buffer) return JS_EXCEPTION;

    if (pipe->fdpipe){
        // 发送数据
        pipe->pipe.fdpipe->write_buf = JS_DupValue(ctx, argv[0]);
        pipe->pipe.fdpipe->write = promise;
        LJS_evfd_write(pipe->pipe.fdpipe->fd, buffer, expected_size, evwrite_callback, pipe->pipe.fdpipe);
    }else{  // U8PIPE
        // 写入函数
        JSValue ret = JS_Call(ctx, pipe -> pipe.pipe -> write_func, this_val, 1, (JSValueConst[]){argv[1]});
        EXCEPTION_THEN_CLOSE(ret, JS_FALSE)
        LJS_Promise_Resolve(promise, ret);  // <- ret转变所有权
    }

    return promise -> promise;
}

static JSValue js_U8Pipe_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    CHECK_U8PIPE_CLOSED(pipe);

    u8pipe_handle_close(JS_GetRuntime(ctx), pipe);

    return JS_UNDEFINED;
}

static JSValue js_U8Pipe_readline(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    CHECK_U8PIPE_CLOSED(pipe);
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
    pipe -> pipe.fdpipe -> read = promise;

    LJS_evfd_readline(pipe -> pipe.fdpipe -> fd, expected_size, buffer, evread_callback, pipe -> pipe.fdpipe);
    return promise -> promise;
}

static JSValue js_u8pipe_get_closed(JSContext *ctx, JSValueConst this_val) {
    GET_U8PIPE_OPAQUE(pipe, this_val);
    return JS_NewBool(ctx, u8pipe_closed(ctx, pipe));
}

// static bool pipeto_fastwrite(
//     JSContext* ctx, struct U8Pipe_T* dst, 
//     uint8_t* buffer, size_t size,
//     JSValue buffer_obj
// ){
//     if(dst -> fdpipe){
//         return LJS_evfd_write(dst -> pipe.fdpipe -> fd, buffer, size, NULL, dst -> pipe.fdpipe);
//     }else{
//         JSValue write_func = dst -> pipe.pipe -> write_func;
//         JSValue ret = JS_Call(ctx, write_func, JS_NULL, 1, (JSValueConst[]){
//             buffer
//                 ? JS_NewUint8Array(ctx, buffer, size, free_js_malloc, NULL, false)
//                 : buffer_obj
//         });
//         if(JS_IsException(ret)) return false;
//         JS_FreeValue(ctx, ret);
//         return true;
//     }
// }

// static JSValue pipeto_promise_callback(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, JSValueConst* func_data);

// static bool pipeto_pipe_next(JSContext* ctx, struct U8PipeTransfer* ctrl, struct U8Pipe_T* src, struct U8Pipe_T* dst, struct promise* prom){
//     if(src -> fdpipe) abort();
//     JSValue poll_func = dst -> pipe.pipe -> pull_func;
//     JSValue ret = JS_Call(ctx, poll_func, JS_NULL, 0, NULL);
//     if(JS_IsException(ret)) goto done;
//     if(JS_IsPromise(ret)){
//         JSValue callback = JS_NewCFunctionData(ctx, pipeto_promise_callback, 0, 0, 3,
//             (JSValueConst[]){ JS_MKPTR(JS_TAG_OBJECT, orin), JS_MKPTR(JS_TAG_OBJECT, src), JS_MKPTR(JS_TAG_OBJECT, dst) }
//         );
//     }

// done:
//     u8pipe_handle_close(JS_GetRuntime(ctx), src);
//     return false;
// }

// static JSValue pipeto_promise_callback(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, JSValueConst* func_data) {
//     struct promise* prom = JS_VALUE_GET_PTR(argv[0]);
//     struct U8Pipe_T* self_pipe = JS_VALUE_GET_PTR(argv[1]);
//     struct U8Pipe_T* dest_pipe = JS_VALUE_GET_PTR(argv[2]);
//     EXCEPTION_THEN_CLOSE(argv[0], JS_UNDEFINED)

//     // 读取数据
//     if(JS_GetTypedArrayType(argv[0]) == -1){
//         LJS_Promise_Reject(prom, "Invaild data returned by pull()");
//         return JS_UNDEFINED;
//     }

//     // 传给对端
//     if(!pipeto_fastwrite(ctx, dest_pipe, NULL, 0, argv[0])){
//         u8pipe_handle_close(JS_GetRuntime(ctx), self_pipe);
//         return JS_UNDEFINED;
//     }

//     // 继续读取
//     pipeto(ctx, self_pipe, dest_pipe, prom, magic);

//     return JS_UNDEFINED;
// }

// static bool pipeto(JSContext* ctx, struct U8PipeTransfer* ctrl) {
//     struct U8Pipe_T* src = JS_GetOpaque(ctrl->src, U8Pipe_class_id),
//         * dst = JS_GetOpaque(ctrl->dest, U8Pipe_class_id);
//     // 注册回调
//     if(src -> fdpipe){
//         src -> pipe.fdpipe -> closed = true;
//         EvFD* evfd = src -> pipe.fdpipe -> fd;
//         int __timer_fd;
//         int fd = LJS_evfd_getfd(evfd, &__timer_fd);
//         // 取消任务
//         LJS_evfd_destroy(evfd);
//         // 注册回调
//         LJS_evcore_attach(fd, __timer_fd != -1, evc);
//     }else{
//         return false; // not support yet
//     }

// }

// static JSValue pipeto_handle_abort(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, JSValueConst* func_data, int magic) {
//     struct U8Pipe_T* src = JS_VALUE_GET_PTR(argv[0]);
//     struct promise* prom = JS_VALUE_GET_PTR(argv[1]);

//     // 取消传输
//     src->transfer->active = false;
//     release_transfer_buffer(src->transfer->buffer, src->transfer->buffer_size);
//     JS_FreeValue(ctx, src->transfer->dest);
//     JS_FreeValue(ctx, src->transfer->abort_controller);
//     js_free(ctx, src->transfer);

//     // 取消Promise
//     LJS_Promise_Reject(prom, "Aborted");

//     return JS_UNDEFINED;
// }

// static JSValue js_U8Pipe_pipeTo(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
//     GET_U8PIPE_OPAQUE(src, this_val);
//     CHECK_U8PIPE_CLOSED(src);
//     CHECK_U8PIPE_READABLE(src);

//     if (argc < 1 || !JS_IsObject(argv[0])) {
//         return JS_ThrowTypeError(ctx, "Argument must be a WritableStream");
//     }

//     // 初始化传输控制块
//     struct U8PipeTransfer* t = &src->transfer;
//     if (t->active) {
//         return JS_ThrowTypeError(ctx, "Pipe is already being piped");
//     }

//     t->dest = JS_DupValue(ctx, argv[0]);
//     t->buffer = get_transfer_buffer(ctx, PIPE_u8_buf_size);
//     t->buffer_size = PIPE_u8_buf_size;
//     t->active = true;
//     t->back_pressure = false;

//     // 创建并返回Promise
//     struct promise* prom = LJS_NewPromise(ctx);
//     t->abort_controller = JS_NewCFunctionData(ctx, pipeto_handle_abort, 0, 0, 2,
//         (JSValueConst[]){ JS_MKPTR(JS_TAG_OBJECT, t), JS_MKPTR(JS_TAG_OBJECT, prom) }
//     );
//     JS_DefinePropertyValueStr(ctx, prom->promise, "abort", t->abort_controller, JS_PROP_CONFIGURABLE);

//     // 启动异步传输
//     return prom->promise;
// }

static void evclose_callback(int fd, void* opaque){
    struct FDPipe_T* pipe = ((struct U8Pipe_T*)opaque) -> pipe.fdpipe;
    pipe -> closed = true;
    u8pipe_handle_close(JS_GetRuntime(pipe -> ctx), (struct U8Pipe_T*)opaque);
}

static JSValue js_U8Pipe_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, U8Pipe_class_id);
    if(JS_IsException(obj)){
        return JS_ThrowOutOfMemory(ctx);
    }

    // 读取参数
    uint32_t type;
    if(argc != 2 || !JS_ToUint32(ctx, &type, argv[1])){
        return LJS_Throw(ctx, "Expected type and functions", "same as `new Pipe()`");
    }

    // 从constructor注册的pipe都是U8_PIPE
    struct U8Pipe_T *pipe = js_malloc(ctx, sizeof(struct U8Pipe_T));
    pipe -> fdpipe = false;
    pipe -> transfer = NULL;
    pipe -> pipe.pipe = js_malloc(ctx, sizeof(struct Pipe_T));
    pipe -> pipe.pipe -> flag = PIPE_READ | PIPE_WRITE;
    pipe -> pipe.pipe -> pull_func = JS_DupValue(ctx, JS_GetPropertyStr(ctx, argv[0], "pull"));
    pipe -> pipe.pipe -> write_func = JS_DupValue(ctx, JS_GetPropertyStr(ctx, argv[0], "write"));
    pipe -> pipe.pipe -> close_func = JS_DupValue(ctx, JS_GetPropertyStr(ctx, argv[0], "close"));
    pipe -> pipe.pipe -> ctx = ctx;
    buffer_init(&pipe -> pipe.pipe -> read_buf, NULL, PIPE_u8_buf_size);
    pipe -> pipe.pipe -> closed = false;
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

static JSValue js_iopipe_get_size(JSContext *ctx, JSValueConst this_val){
    int fdnum = get_fd_from_pipe(ctx, this_val);
    if(fdnum == -1) return LJS_Throw(ctx, "Expected a U8Pipe object", NULL);

    struct winsize size;
    if(ioctl(fdnum, TIOCGWINSZ, &size) == -1){
        return LJS_Throw(ctx, "Failed to get terminal size", NULL);
    }

    return JS_NewArrayFrom(ctx, 2, (JSValueConst[]){JS_NewInt32(ctx, size.ws_row), JS_NewInt32(ctx, size.ws_col)});
}

static JSValue js_iopipe_set_size(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    int fdnum = get_fd_from_pipe(ctx, this_val);
    if(fdnum == -1) return LJS_Throw(ctx, "Expected a U8Pipe object", NULL);

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

static JSValue js_iopipe_istty(JSContext *ctx, JSValueConst this_val){
    int fdnum = get_fd_from_pipe(ctx, this_val);
    if(fdnum == -1) return LJS_Throw(ctx, "Expected a U8Pipe object", NULL);

    return JS_NewBool(ctx, isatty(fdnum));
}

static JSValue js_iopipe_flush(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
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
    // JS_CFUNC_DEF("pipeTo", 1, js_U8Pipe_pipeTo),
    JS_CFUNC_DEF("ttyRaw", 1, js_iopipe_setraw),
    JS_CGETSET_DEF("ttySize", js_iopipe_get_size, js_iopipe_set_size),
    JS_CGETSET_DEF("isTTY", js_iopipe_istty, NULL),
    JS_CFUNC_DEF("flush", 0, js_iopipe_flush),
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
    JS_SetPropertyStr(ctx, global_obj, "U8Pipe", u8pipe_proto);
    JS_SetClassProto(ctx, U8Pipe_class_id, u8pipe_proto);

    JSValue u8pipe_constructor = JS_NewCFunction2(ctx, js_U8Pipe_constructor, "U8Pipe", 2, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, u8pipe_constructor, u8pipe_proto);
    JS_SetPropertyStr(ctx, global_obj, "U8Pipe", u8pipe_constructor);

    // Pipe
    JS_NewClassID(rt, &Pipe_class_id);
    if(-1 == JS_NewClass(rt, Pipe_class_id, &Pipe_class)) return false;
    JSValue pipe_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, pipe_proto, Pipe_proto_funcs, countof(Pipe_proto_funcs));
    JS_SetPropertyStr(ctx, global_obj, "Pipe", pipe_proto);
    JS_SetClassProto(ctx, Pipe_class_id, pipe_proto);

    JSValue pipe_constructor = JS_NewCFunction2(ctx, js_pipe_constructor, "Pipe", 0, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, pipe_constructor, pipe_proto);
    JS_SetPropertyStr(ctx, global_obj, "Pipe", pipe_constructor);

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

    if(fdpipe){
        pipe -> pipe.fdpipe = js_malloc(ctx, sizeof(struct FDPipe_T));
        DEF_ONCLOSE(pipe -> pipe.fdpipe);
        
        pipe -> pipe.fdpipe -> closed = false;
        // not locked check
        pipe -> pipe.fdpipe -> read = pipe -> pipe.fdpipe -> write = NULL;
    }else{
        pipe -> pipe.pipe = js_malloc(ctx, sizeof(struct Pipe_T));
        DEF_ONCLOSE(pipe -> pipe.pipe);
        pipe -> pipe.pipe -> closed = false;
    }

    return obj;
}

/**
 * 创建一个FDPipe对象
 * @param ctx JS运行时上下文
 * @param fd 管道的文件描述符
 * @param flag 管道的标志位
 * @param buf_size 缓冲区大小
 */
JSValue LJS_NewFDPipe(JSContext *ctx, int fd, uint32_t flag, uint32_t buf_size, JSValue onclose){
    if(!ctx) abort();
    struct U8Pipe_T *pipe = js_malloc(ctx, sizeof(struct U8Pipe_T));
    JSValue obj = u8pipe_new(ctx, true, pipe);
    EvFD* evfd = LJS_evfd_new(fd, flag & PIPE_AIO, flag & PIPE_READ, flag & PIPE_WRITE, buf_size, evclose_callback, pipe);

    if (!evfd){
        JS_FreeValue(ctx, obj);
        return LJS_Throw(ctx, "Failed to create eventfd: %s", NULL, strerror(errno));
    }

    pipe -> pipe.fdpipe -> fd = evfd;
    pipe -> pipe.fdpipe -> flag = flag;
    pipe -> pipe.fdpipe -> ctx = ctx;
    pipe -> pipe.fdpipe -> read = 
    pipe -> pipe.fdpipe -> write = NULL;
    pipe -> pipe.fdpipe -> closed = false;
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
        JS_MKPTR(JS_TAG_OBJECT, pipe),
        JS_MKPTR(JS_TAG_OBJECT, poll_cb),
        JS_MKPTR(JS_TAG_OBJECT, write_cb),
        JS_MKPTR(JS_TAG_OBJECT, close_cb),
        JS_MKPTR(JS_TAG_OBJECT, user_data)
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
        JS_MKPTR(JS_TAG_OBJECT, pipe),
        JS_MKPTR(JS_TAG_OBJECT, poll_cb),
        JS_MKPTR(JS_TAG_OBJECT, write_cb),
        JS_MKPTR(JS_TAG_OBJECT, close_cb),
        JS_MKPTR(JS_TAG_OBJECT, user_data)
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