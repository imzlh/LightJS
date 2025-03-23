#include "../engine/quickjs.h"
#include "core.h"
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

#define PIPE_READ 0b1
#define PIPE_WRITE 0b10
#define MIN(a, b) ((a) < (b)? (a) : (b))

// 从FD创建的管道
struct CycledBuffer_T{
    uint8_t* buf;
    uint32_t start;
    uint32_t end;
    uint32_t size;
    bool cycled;
};
struct FDPipe_T{
    EvFD* fd;
    uint8_t flag;
    JSContext* ctx;

    JSValue read_rs;
    JSValue read_rj;

    JSValue write_buf;
    JSValue write_rs;
    JSValue write_rj;

    JSValue close_rs;
    bool closed;
};
union FDPipeUnion_T{
    struct FDPipe_T* fdpipe;
    struct Pipe_T* pipe;
};
struct U8Pipe_T {
    bool fdpipe;
    union FDPipeUnion_T pipe;
};

struct Pipe_T{
    JSValue close_rs;
    JSValue pull_func;
    JSValue write_func;
    JSValue close_func;

    // for u8pipe
    struct CycledBuffer_T* read_buf;

    bool closed;
    uint8_t flag;
};

// Pipe
static JSClassID Pipe_class_id;

// U8Pipe
static JSClassID U8Pipe_class_id;
static thread_local uint32_t PIPE_u8_buf_size = 16 * 1024;

// ---------------- Pipe -------------------
static void c_pipe_destroy(JSContext *ctx, struct Pipe_T *pipe) {
    JS_Call(ctx, pipe->close_func, JS_NULL, 0, NULL);
    if(JS_IsFunction(ctx, pipe->close_rs))
        JS_Call(ctx, pipe->close_rs, JS_NULL, 0, NULL);
}

static void pipe_cleanup(JSRuntime *rt, struct Pipe_T* pipe) {
    if (!JS_IsNull(pipe->close_rs) && !JS_IsUndefined(pipe->close_rs))
        JS_FreeValueRT(rt, pipe->close_rs);
    JS_FreeValueRT(rt, pipe->pull_func);
    JS_FreeValueRT(rt, pipe->write_func);
    JS_FreeValueRT(rt, pipe->close_func);

    free(pipe);
}

static void c_pipe_cleanup(JSRuntime *rt, JSValue val) {
    struct Pipe_T *pipe = JS_GetOpaque(val, Pipe_class_id);
    if(!pipe) return;
    pipe_cleanup(rt, pipe);
}

static inline void c_pipe_close(JSContext *ctx, struct Pipe_T *pipe) {
    if (pipe->closed) return;
    pipe->closed = true;
    c_pipe_destroy(ctx, pipe);
}

static JSValue js_pipe_read(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct Pipe_T *pipe = JS_GetOpaque(this_val, Pipe_class_id);
    if (!pipe || pipe->closed){
        return JS_ThrowTypeError(ctx, "Pipe is closed");
    }
    if(!(pipe->flag & PIPE_READ)){
        return JS_ThrowTypeError(ctx, "Pipe is not readable");
    }

    JSValue data;
    // 调用pull()
    data = JS_Call(ctx, pipe->pull_func, this_val, 0, NULL);
    if (JS_IsException(data)){
        c_pipe_close(ctx, pipe);
        return JS_NULL;
    }
    // 返回数据
    return data;
}

static JSValue js_pipe_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct Pipe_T *pipe = JS_GetOpaque(this_val, Pipe_class_id);
    if (!pipe || pipe->closed){
        return JS_ThrowTypeError(ctx, "Pipe is closed");
    }
    if(!(pipe->flag & PIPE_WRITE)){
        return JS_ThrowTypeError(ctx, "Pipe is not writable");
    }

    JSValue data = argv[0];
    // 传递给write()
    JSValue ret = JS_Call(ctx, pipe->write_func, this_val, 1, &data);
    if(JS_IsException(ret)){
        c_pipe_close(ctx, pipe);
        return JS_FALSE;
    }
    return JS_TRUE;
}

static JSValue js_pipe_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct Pipe_T *pipe = JS_GetOpaque(this_val, Pipe_class_id);
    if (!pipe || pipe->closed){
        return JS_ThrowTypeError(ctx, "Pipe is closed");
    }
    pipe->closed = true;
    c_pipe_destroy(ctx, pipe);
    return JS_NULL;
}

static JSClassDef Pipe_class = {
    "FDPipe",
    .finalizer = c_pipe_cleanup
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
        return LJS_Throw(ctx, "Pipe constructor need 2 arguments", "new Pipe({ read(), poll(), close(), start() }, Pipe.READ | Pipe.WRITE)");
    }
    struct Pipe_T *pipe = malloc(sizeof(struct Pipe_T));
    JSValue close_func = JS_GetPropertyStr(ctx, argv[0], "close");
    JSValue pull_func = JS_GetPropertyStr(ctx, argv[0], "pull");
    JSValue write_func = JS_GetPropertyStr(ctx, argv[0], "write");
    JSValue start_func = JS_GetPropertyStr(ctx, argv[0], "start");
    pipe -> pull_func = JS_IsFunction(ctx, pull_func) ? pull_func : JS_NULL;
    pipe -> write_func = JS_IsFunction(ctx, write_func) ? write_func : JS_NULL;
    pipe -> close_func = JS_IsFunction(ctx, close_func) ? close_func : JS_NULL;
    pipe -> close_rs = JS_NULL;
    pipe -> closed = false;
    pipe -> flag = 0;

    // proto
    JSValue proto = JS_GetPropertyStr(ctx, new_target, "prototype");
    JSValue obj = JS_NewObjectProtoClass(ctx, proto, Pipe_class_id);

    // 调用start
    if(JS_IsFunction(ctx, start_func)){
        JS_Call(ctx, start_func, obj, 0, NULL);
    }

    JS_FreeValue(ctx, proto);
    return obj;
}

// -------------------- U8Pipe ------------------
static inline void fdpipe_cleanup(JSRuntime *rt, struct FDPipe_T* pipe){
    if(!JS_IsNull(pipe -> read_rs)) JS_FreeValueRT(rt, pipe -> read_rs);
    if(!JS_IsNull(pipe -> read_rj)) JS_FreeValueRT(rt, pipe -> read_rj);
    if(!JS_IsNull(pipe -> write_rs)) JS_FreeValueRT(rt, pipe -> write_rs);
    if(!JS_IsNull(pipe -> write_rj)) JS_FreeValueRT(rt, pipe -> write_rj);
    free(pipe);
}

static void c_u8pipe_cleanup(JSRuntime *rt, JSValue val) {
    struct U8Pipe_T *pipe = JS_GetOpaque(val, U8Pipe_class_id);
    if(!pipe) return;
    if(pipe->fdpipe){
        fdpipe_cleanup(rt, pipe->pipe.fdpipe);
    }else{
        c_pipe_cleanup(rt, val);
    }
    free(pipe);
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
        return read
            ? JS_IsFunction(ctx, pipe -> pipe.fdpipe -> read_rs)
            : JS_IsFunction(ctx, pipe -> pipe.fdpipe -> write_rs);
    }else {
        return false;
    }
}

static inline bool u8pipe_closed(JSContext *ctx, struct U8Pipe_T* pipe) {
    if(pipe->fdpipe){
        return pipe -> pipe.fdpipe -> closed;
    }else{
        return pipe -> pipe.pipe -> closed;
    }
}

void free_malloc(JSRuntime *rt, void *opaque, void *ptr){
    free(ptr);
}

static inline bool cbuf_get_available_size(struct CycledBuffer_T* cbuf){
    return cbuf -> cycled? cbuf -> end - cbuf -> start : cbuf -> end - cbuf -> start + cbuf -> size;
}

static inline bool cbuf_get_used_size(struct CycledBuffer_T* cbuf){
    return cbuf -> cycled? cbuf -> size - cbuf -> end + cbuf -> start : cbuf -> end - cbuf -> start;
}

static struct CycledBuffer_T* cbuf_create(uint32_t size){
    struct CycledBuffer_T* cbuf = malloc(sizeof(struct CycledBuffer_T));
    cbuf -> buf = malloc(size);
    cbuf -> start = 0;
    cbuf -> end = 0;
    cbuf -> size = size;
    cbuf -> cycled = false;
    return cbuf;
}

static inline void cbuf_destroy(struct CycledBuffer_T* cbuf){
    free(cbuf -> buf);
    free(cbuf);
}

static inline bool cbuf_write(struct CycledBuffer_T* cbuf, uint8_t* data, uint32_t size){
    uint32_t available = cbuf_get_available_size(cbuf);
    if(available < size){
        return false;
    }
    uint32_t used = cbuf_get_used_size(cbuf);
    if(used + size > cbuf -> size){
        // 缓冲区已满，需要循环
        uint32_t left = cbuf -> size - used;
        if(left) memcpy(cbuf -> buf + used, data, left);
        memcpy(cbuf -> buf, data + left, size - left);
        cbuf -> start = 0;
        cbuf -> end = size - left;
        cbuf -> cycled = true;
    }else{
        // 缓冲区未满，直接写入
        memcpy(cbuf -> buf + used, data, size);
        cbuf -> end += size;
    }
    return true;
}

static inline bool cbuf_read_fd(struct CycledBuffer_T* cbuf, int fd){
    // 单次能读取的量
    uint32_t available = cbuf -> cycled ? cbuf -> start - cbuf -> end : cbuf -> size - cbuf -> end,
        cycled_available = cbuf_get_available_size(cbuf) - available;
    if(available == 0){
        if(cycled_available == 0) return false;
        // 循环
        available = cycled_available;
        cbuf -> cycled = true;
        cbuf -> start = 0;
    }
    // 读取数据
    int ret = recv(fd, cbuf -> buf + cbuf -> end, available, 0);
    if(ret <= 0){
        return false;
    }
    cbuf -> end += ret;
    return true;
}

static inline JSValue cbuf_read(struct CycledBuffer_T* cbuf, JSContext *ctx, uint32_t size){
    uint32_t available = cbuf_get_available_size(cbuf);
    if(available < size){
        return JS_NULL;
    }

    uint8_t* buf = malloc(size);
    if(!buf){
        return JS_NULL;
    }

    if(cbuf -> cycled){
        if(cbuf -> size - cbuf -> start >= size){
            memcpy(buf, cbuf -> buf + cbuf -> start, size);
            cbuf -> start += size;
        }else{
            uint32_t space1 = cbuf -> size - cbuf -> start;
            memcpy(buf, cbuf -> buf + cbuf -> start, space1);
            memcpy(buf, cbuf -> buf, size - space1);
            cbuf -> start = size - space1;
            cbuf -> cycled = false;
        }
    }else{
        memcpy(buf, cbuf -> buf + cbuf -> start, size);
        cbuf -> start += size;
    }

    return JS_NewUint8Array(ctx, buf, size, free_malloc, NULL, true);
}

static inline bool is_uint8array(JSContext *ctx, JSValueConst val){
    return JS_IsInstanceOf(ctx, val, 
        JS_GetPropertyStr(ctx, JS_GetGlobalObject(ctx), "Uint8Array")
    );
}

static void u8pipe_fill_by_callback(JSContext *ctx, struct Pipe_T* pipe, JSValueConst promise_callback[2], uint32_t expected_size){
    uint8_t* buf = malloc(expected_size);

    JSValue data;
    while (cbuf_get_used_size(pipe -> read_buf) < expected_size){
        // 调用函数
        data = JS_Call(ctx, pipe -> pull_func, JS_NULL, 0, NULL);
        if(JS_IsException(data) || !is_uint8array(ctx, data)){
            JS_Call(ctx, promise_callback[1], JS_NULL, 0, NULL);
            return;
        }
        // 填充
        size_t readed = 0;
        uint8_t* buf2 = JS_GetUint8Array(ctx, &readed, data);
        cbuf_write(pipe -> read_buf, buf2, readed);
        JS_FreeValue(ctx, data);
    }

    // 提取数据
    JSValue ret = cbuf_read(pipe -> read_buf, ctx, expected_size);

    // 调用回调
    JSValue arr[1] = { ret };
    JS_Call(ctx, promise_callback[0], JS_NULL, 1, arr);
    JS_FreeValue(ctx, data);
    free(buf);
}

static void u8pipe_fill_once_by_callback(JSContext *ctx, struct Pipe_T* pipe, JSValueConst promise_callback[2]){
    JSValue data;
    // 调用函数
    data = JS_Call(ctx, pipe->pull_func, JS_NULL, 0, NULL);
    if (JS_IsException(data) || !is_uint8array(ctx, data)){
        JS_Call(ctx, promise_callback[1], JS_NULL, 0, NULL);
        return;
    }
    // 填充
    size_t readed = 0;
    uint8_t *buf = JS_GetUint8Array(ctx, &readed, data);
    cbuf_write(pipe -> read_buf, buf, readed);
    JS_FreeValue(ctx, data);
    JSValue ret = cbuf_read(pipe -> read_buf, ctx, cbuf_get_used_size(pipe -> read_buf));
    // 调用回调
    JSValue arr[1] = { ret };
    JS_Call(ctx, promise_callback[0], JS_NULL, 1, arr);
    JS_FreeValue(ctx, data);
}

static void evread_callback(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data){
    struct FDPipe_T* pipe = user_data;
    if(read_size > 0){
        JSValue data = JS_NewUint8Array(pipe -> ctx, buffer, read_size, free_malloc, NULL, true);
        JS_Call(pipe -> ctx, pipe -> read_rs, JS_NULL, 1, &data);
    }
}

static JSValue js_U8Pipe_read(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct U8Pipe_T *pipe = JS_GetOpaque(this_val, U8Pipe_class_id);
    if (!pipe){
        return JS_ThrowTypeError(ctx, "U8Pipe invaild");
    }
    if(u8pipe_closed(ctx, pipe)){
        return JS_ThrowTypeError(ctx, "U8Pipe is closed");
    }
    if(!u8pipe_is(ctx, pipe, PIPE_READ)){
        return JS_ThrowTypeError(ctx, "U8Pipe is not readable");
    }
    if(u8pipe_locked(ctx, pipe, true)){
        return JS_ThrowTypeError(ctx, "U8Pipe is locked");
    }

    uint32_t expected_size = 0;
    JSValue promise_callback[2];
    JSValue promise = JS_NewPromiseCapability(ctx, promise_callback);
    if(JS_IsException(promise)){
        return JS_NULL;
    }

    if(argc == 1){
        if(!JS_ToUint32(ctx, &expected_size, argv[0])){
            return LJS_Throw(ctx, "Expected size must be a number", "U8Pipe.read(expected_size)");
        }
    }

    if(pipe -> fdpipe){
        pipe -> pipe.fdpipe -> read_rs = JS_DupValue(ctx, promise_callback[0]);
        pipe -> pipe.fdpipe -> read_rj = JS_DupValue(ctx, promise_callback[1]);

        if(expected_size == 0){
            uint8_t* buf = malloc(PIPE_u8_buf_size);
            LJS_evfd_read(pipe -> pipe.fdpipe -> fd, PIPE_u8_buf_size, buf, evread_callback, pipe -> pipe.fdpipe);
        }else{
            uint8_t* buf = malloc(expected_size);
            LJS_evfd_readsize(pipe -> pipe.fdpipe -> fd, expected_size, buf, evread_callback, pipe -> pipe.fdpipe);
        }
    }else{  // U8PIPE
        expected_size == 0
            ? u8pipe_fill_by_callback(ctx, pipe -> pipe.pipe, promise_callback, expected_size)
            : u8pipe_fill_once_by_callback(ctx, pipe -> pipe.pipe, promise_callback);
    }

    return promise;
}

static void evwrite_callback(EvFD* evfd, void* opaque){
    struct FDPipe_T* pipe = opaque;
    JS_Call(pipe -> ctx, pipe -> write_rs, JS_NULL, 0, NULL);
}

static JSValue js_U8Pipe_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct U8Pipe_T *pipe = JS_GetOpaque(this_val, U8Pipe_class_id);
    if (!pipe){
        return JS_ThrowTypeError(ctx, "U8Pipe invaild");
    }
    if(u8pipe_closed(ctx, pipe)){
        return JS_ThrowTypeError(ctx, "U8Pipe is closed");
    }
    if(!u8pipe_is(ctx, pipe, PIPE_WRITE)){
        return JS_ThrowTypeError(ctx, "U8Pipe is not writable");
    }
    if(u8pipe_locked(ctx, pipe, true)){
        return JS_ThrowTypeError(ctx, "U8Pipe is locked");
    }

    size_t expected_size = 0;
    uint8_t* buffer;
    JSValue promise_callback[2];
    JSValue promise = JS_NewPromiseCapability(ctx, promise_callback);
    if(JS_IsException(promise)){
        return JS_NULL;
    }

    if(argc == 0){
        buffer = JS_GetUint8Array(ctx, &expected_size, argv[0]);
        if(!buffer){
            return LJS_Throw(ctx, "Expected data must be a Uint8Array", "U8Pipe.write(expected_data)");
        }
    }

    buffer = malloc(expected_size == 0 ? PIPE_u8_buf_size : expected_size);
    if (pipe->fdpipe){
        // 发送数据
        pipe->pipe.fdpipe->write_buf = JS_DupValue(ctx, argv[0]);
        pipe->pipe.fdpipe->write_rs = JS_DupValue(ctx, promise_callback[0]);
        pipe->pipe.fdpipe->write_rj = JS_DupValue(ctx, promise_callback[1]);
        LJS_evfd_write(pipe->pipe.fdpipe->fd, buffer, expected_size, evwrite_callback, pipe->pipe.fdpipe);
    }else{  // U8PIPE
        // 写入函数
        JSValue arr[1] = { JS_DupValue(ctx, argv[0]) },
            arr2[1] = { JS_Call( ctx, pipe -> pipe.pipe -> write_func, JS_NULL, 1, arr ) };
        if(JS_IsPromise(arr2[0])){
            return arr2[0];
        }
        JS_Call(ctx, promise_callback[0], JS_NULL, 1, arr2);
    }

    return promise;
}

static JSValue js_U8Pipe_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct U8Pipe_T *pipe = JS_GetOpaque(this_val, U8Pipe_class_id);
    if (!pipe){
        return JS_ThrowTypeError(ctx, "U8Pipe invaild");
    }
    if(u8pipe_closed(ctx, pipe)){
        return JS_ThrowTypeError(ctx, "U8Pipe is closed");
    }
    if(u8pipe_locked(ctx, pipe, true)){
        return JS_ThrowTypeError(ctx, "U8Pipe is locked");
    }

    if(pipe -> fdpipe){
        LJS_evfd_close(pipe -> pipe.fdpipe -> fd);
        pipe -> pipe.fdpipe -> closed = true;
    }

    u8pipe_closed(ctx, pipe);
    return JS_UNDEFINED;
}

static JSValue js_u8pipe_get_closed(JSContext *ctx, JSValueConst this_val) {
    struct U8Pipe_T *pipe = JS_GetOpaque(this_val, U8Pipe_class_id);
    if (!pipe){
        return JS_ThrowTypeError(ctx, "U8Pipe invaild");
    }
    return JS_NewBool(ctx, u8pipe_closed(ctx, pipe));
}
static void evclose_callback(int fd, void* opaque){
    struct FDPipe_T* pipe = opaque;
    JS_Call(pipe -> ctx, pipe -> close_rs, JS_NULL, 0, NULL);
    
    if(JS_IsFunction(pipe -> ctx, pipe -> read_rj)){
        JS_Call(pipe -> ctx, pipe -> read_rj, JS_NULL, 0, NULL);
    }
    if(JS_IsFunction(pipe -> ctx, pipe -> write_rj)){
        JS_Call(pipe -> ctx, pipe -> write_rj, JS_NULL, 0, NULL);
    }
}

static JSValue js_U8Pipe_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    JSValue proto = JS_GetPropertyStr(ctx, new_target, "prototype");
    JSValue obj = JS_NewObjectProtoClass(ctx, proto, U8Pipe_class_id);
    JS_FreeValue(ctx, proto);
    if(JS_IsException(obj)){
        return JS_NULL;
    }

    // 读取参数
    uint32_t type;
    if(argc != 2 || !JS_ToUint32(ctx, &type, argv[1])){
        return LJS_Throw(ctx, "Expected type and functions", "same as `new Pipe()`");
    }

    // 从constructor注册的pipe都是U8_PIPE
    struct U8Pipe_T *pipe = malloc(sizeof(struct U8Pipe_T));
    pipe -> fdpipe = false;
    pipe -> pipe.pipe = malloc(sizeof(struct Pipe_T));
    pipe -> pipe.pipe -> flag = PIPE_READ | PIPE_WRITE;
    pipe -> pipe.pipe -> pull_func = JS_DupValue(ctx, JS_GetPropertyStr(ctx, argv[0], "pull"));
    pipe -> pipe.pipe -> write_func = JS_DupValue(ctx, JS_GetPropertyStr(ctx, argv[0], "write"));
    pipe -> pipe.pipe -> close_func = JS_DupValue(ctx, JS_GetPropertyStr(ctx, argv[0], "close"));
    pipe -> pipe.pipe -> read_buf = cbuf_create(PIPE_u8_buf_size);
    pipe -> pipe.pipe -> closed = false;
    JS_SetOpaque(obj, pipe);

    // 创建一个close Promise
    JSValue promise_callback[2];
    JSValue close_prom = JS_NewPromiseCapability(ctx, promise_callback);
    if(JS_IsException(close_prom)){
        goto fail;
    }
    pipe -> pipe.pipe -> close_rs = JS_DupValue(ctx, promise_callback[0]);
    JS_FreeValue(ctx, promise_callback[1]);
    JS_SetPropertyStr(ctx, obj, "close", close_prom);

    // 完成
    return obj;

fail:
    JS_FreeValue(ctx, obj);
    return JS_NULL;
}

static JSClassDef U8Pipe_class = {
    "U8Pipe",
    .finalizer = c_u8pipe_cleanup
};
static const JSCFunctionListEntry U8Pipe_proto_funcs[] = {
    JS_CFUNC_DEF("read", 0, js_U8Pipe_read),
    JS_CFUNC_DEF("write", 1, js_U8Pipe_write),
    JS_CFUNC_DEF("close", 0, js_U8Pipe_close),
    JS_CGETSET_DEF("closed", js_u8pipe_get_closed, NULL),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "U8Pipe", JS_PROP_CONFIGURABLE),
};

// 注册方法
bool LJS_init_pipe(JSContext *ctx) {
    JSValue global_obj = JS_GetGlobalObject(ctx);
    JSRuntime* rt = JS_GetRuntime(ctx);

    // U8Pipe
    JS_NewClassID(rt, &U8Pipe_class_id);
    JS_NewClass(rt, U8Pipe_class_id, &U8Pipe_class);
    JSValue u8pipe_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, u8pipe_proto, U8Pipe_proto_funcs, countof(U8Pipe_proto_funcs));
    JS_SetPropertyStr(ctx, global_obj, "U8Pipe", u8pipe_proto);
    JS_SetClassProto(ctx, U8Pipe_class_id, u8pipe_proto);

    JSValue u8pipe_constructor = JS_NewCFunction2(ctx, js_U8Pipe_constructor, "U8Pipe", 2, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, u8pipe_constructor, u8pipe_proto);
    JS_SetPropertyStr(ctx, global_obj, "U8Pipe", u8pipe_constructor);

    // Pipe
    JS_NewClassID(rt, &Pipe_class_id);
    JS_NewClass(rt, Pipe_class_id, &Pipe_class);
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
    pipe -> fdpipe = fdpipe;
    JS_SetOpaque(obj, pipe);

    // 创建一个close Promise
    JSValue promise_callback[2];
    JSValue close_prom = JS_NewPromiseCapability(ctx, promise_callback);
    if(fdpipe){
        pipe -> pipe.fdpipe = malloc(sizeof(struct FDPipe_T));
        pipe -> pipe.fdpipe -> close_rs = JS_DupValue(ctx, promise_callback[0]);
    }else{
        pipe -> pipe.pipe = malloc(sizeof(struct Pipe_T));
        pipe -> pipe.pipe -> close_rs = JS_DupValue(ctx, promise_callback[0]);
    }
    JS_SetPropertyStr(ctx, obj, "closed", close_prom);

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
    struct U8Pipe_T *pipe = malloc(sizeof(struct U8Pipe_T));
    JSValue obj = u8pipe_new(ctx, true, pipe);
    EvFD* evfd = LJS_evfd_new(fd, flag & PIPE_READ, flag & PIPE_WRITE, buf_size, evclose_callback, pipe);

    if (!evfd){
        JS_FreeValue(ctx, obj);
        return LJS_Throw(ctx, "Failed to create eventfd: %s", NULL, strerror(errno));
    }

    pipe -> pipe.fdpipe -> fd = evfd;
    pipe -> pipe.fdpipe -> flag = flag;
    pipe -> pipe.fdpipe -> ctx = ctx;
    pipe -> pipe.fdpipe -> read_rs = JS_NULL;
    pipe -> pipe.fdpipe -> read_rj = JS_NULL;
    pipe -> pipe.fdpipe -> write_rs = JS_NULL;
    pipe -> pipe.fdpipe -> write_rj = JS_NULL;
    pipe -> pipe.fdpipe -> close_rs = onclose;
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
    struct U8Pipe_T *pipe = malloc(sizeof(struct U8Pipe_T));
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
    pipe -> pipe.pipe -> read_buf = cbuf_create(buf_size);
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
    struct Pipe_T *pipe = malloc(sizeof(struct Pipe_T));
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
    pipe -> read_buf = cbuf_create(PIPE_u8_buf_size);

    JS_SetOpaque(obj, pipe);

    return obj;
}