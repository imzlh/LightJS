/**
 * LightJS File System Module
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

#include "../engine/quickjs.h"
#include "core.h"
#include "polyfill.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#ifndef L_NO_THREADS_H
#include <threads.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __CYGWIN__
#include <windows.h>
#else
#include <sys/sendfile.h>
#endif

#ifndef DT_UNKNOWN
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14
#endif

// class SyncPipe
static thread_local JSClassID js_syncpipe_class_id;
struct SyncPipe {
    int fd;
    int size;  // -1 means unlimited size
};

static JSValue js_syncio_set_block(JSContext *ctx, JSValueConst this_val, JSValueConst val){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;

    int flags = fcntl(pipe -> fd, F_GETFL);
    if(flags < 0) return JS_EXCEPTION;

    if(JS_ToBool(ctx, val))
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    if(fcntl(pipe -> fd, F_SETFL, flags) < 0)
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to set blocking mode: %s", NULL, strerror(errno));

    return JS_UNDEFINED;
}

static JSValue js_syncio_get_block(JSContext *ctx, JSValueConst this_val){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;

    int flags = fcntl(pipe -> fd, F_GETFL);
    if(flags < 0) return JS_EXCEPTION;

    return JS_NewBool(ctx, flags & O_NONBLOCK);
}

static JSValue js_syncio_read(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;

    uint32_t len = 0;
    if(argc == 1) JS_ToUint32(ctx, &len, argv[0]);
    if(len == 0) len = BUFSIZ;

    uint8_t* buf = js_malloc(ctx, len);
    ssize_t recv = read(pipe -> fd, buf, len);

    if(recv == -1){
        js_free(ctx, buf);
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to read: %s", NULL, strerror(errno));
    }

    return JS_NewUint8Array(ctx, buf, recv, free_js_malloc, NULL, false);
}

static JSValue js_syncio_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;

    if(argc == 0 ){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "missing argument", "SyncPipe.write(data: TypedArray | string): void");
    }
    bool wait_until_sent = false;
    if(argc == 2) wait_until_sent = JS_ToBool(ctx, argv[1]);

    size_t size;
    uint8_t* buf = JS_IsString(argv[0])? (uint8_t*)JS_ToCStringLen(ctx, &size, argv[0]) : JS_GetUint8Array(ctx, &size, argv[0]);
    if(!buf) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid argument", "SyncPipe.write(data: TypedArray | string): void");

    uint32_t sent = write(pipe -> fd, buf, size);
    while(sent < size && wait_until_sent){
        sent += write(pipe -> fd, buf + sent, size - sent);
    }
    return JS_NewInt32(ctx, sent);
}

static JSValue js_syncio_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;

    close(pipe -> fd);
    return JS_UNDEFINED;
}

static JSValue js_syncio_prealloc(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    struct SyncPipe *pipe = JS_GetOpaque(new_target, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;

    if(argc <= 2 || !JS_IsNumber(argv[0]))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "SyncPipe.prealloc(size: int, flag: preallocFlag): boolean");

    uint32_t size = 0;
    int flag;
    JS_ToUint32(ctx, &size, argv[0]);
    JS_ToInt32(ctx, &flag, argv[1]);
    
    if(0 == fallocate(pipe -> fd, flag, 0, size)){
        return JS_TRUE;
    }else if(0 == ftruncate(pipe -> fd, size)){
        return JS_TRUE;
    }else{
        return JS_FALSE;
    }
}

static JSValue js_syncio_seek(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;

    int64_t offset;
    int whence;
    if(argc!= 2 || -1 == JS_ToInt64(ctx, &offset, argv[0]) || -1 == JS_ToInt32(ctx, &whence, argv[1]))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "SyncPipe.seek(offset: int, whence: int): void");

    if(lseek(pipe -> fd, offset, whence) < 0)
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to seek: %s", NULL, strerror(errno));

    return JS_UNDEFINED;
}

static JSValue js_syncio_tell(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;

    off_t pos = lseek(pipe -> fd, 0, SEEK_CUR);
    if(pos < 0)
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to tell: %s", NULL, strerror(errno));

    return JS_NewInt64(ctx, pos);
}

static JSValue js_syncio_get_eof(JSContext *ctx, JSValueConst this_val){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;
    if(pipe -> size == -1) return JS_FALSE;
    off_t pos = lseek(pipe -> fd, 0, SEEK_CUR);
    if(pos < 0)
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to get position: %s", NULL, strerror(errno));
    return JS_NewBool(ctx, pos >= pipe -> size);
}

static JSValue js_syncio_get_size(JSContext *ctx, JSValueConst this_val){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;
    return JS_NewInt64(ctx, pipe -> size);
}

static JSValue js_syncio_get_fd(JSContext *ctx, JSValueConst this_val){
    struct SyncPipe *pipe = JS_GetOpaque(this_val, js_syncpipe_class_id);
    if(!pipe) return JS_EXCEPTION;
    return JS_NewInt32(ctx, pipe -> fd);
}

static void js_syncio_finalizer(JSRuntime *rt, JSValue val){
    struct SyncPipe *pipe = JS_GetOpaque(val, js_syncpipe_class_id);
    if(pipe){
        close(pipe -> fd);
        js_free_rt(rt, pipe);
    }
}

static JSValue js_syncio_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv){
    int fd;
    if(argc == 0 || 0 != JS_ToInt32(ctx, &fd, argv[0]))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "new stdio.SyncPipe(fd: int): SyncPipe");

    if(fcntl(fd, F_GETFD) < 0)
        return JS_ThrowReferenceError(ctx, "invalid file descriptor");

    JSValue class = JS_NewObjectProtoClass(ctx, JS_GetClassProto(ctx, js_syncpipe_class_id), js_syncpipe_class_id);
    if(JS_IsException(class)) return JS_EXCEPTION;
    struct SyncPipe *pipe = js_malloc(ctx, sizeof(struct SyncPipe));
    if(!pipe) return JS_ThrowOutOfMemory(ctx);
    pipe -> fd = fd;

    pipe -> size = -1;
    if(fcntl(fd, F_GETFL) != -1){
        // is file
        struct stat st;
        if(fstat(fd, &st)){
            pipe -> size = st.st_size;
        }
    }

    JS_SetOpaque(class, pipe);
    return class;
}

static const JSClassDef js_syncpipe_class = {
    "SyncPipe",
    .finalizer = js_syncio_finalizer
};

static const JSCFunctionListEntry js_syncpipe_funcs[] = {
    JS_CFUNC_DEF("read", 1, js_syncio_read),
    JS_CFUNC_DEF("write", 1, js_syncio_write),
    JS_CFUNC_DEF("close", 0, js_syncio_close),
    JS_CFUNC_DEF("seek", 2, js_syncio_seek),
    JS_CFUNC_DEF("tell", 0, js_syncio_tell),
    JS_CFUNC_DEF("prealloc", 2, js_syncio_prealloc),
    JS_CGETSET_DEF("size", js_syncio_get_size, NULL),
    JS_CGETSET_DEF("block", js_syncio_get_block, js_syncio_set_block),
    JS_CGETSET_DEF("fd", js_syncio_get_fd, NULL),
    JS_CGETSET_DEF("eof", js_syncio_get_eof, NULL),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "SyncPipe", JS_PROP_CONFIGURABLE),
};

static const JSCFunctionListEntry js_syncpipe_flags[] = {
    C_CONST(SEEK_CUR),
    C_CONST(SEEK_END),
    C_CONST(SEEK_SET),

#ifndef __CYGWIN__
    JS_PROP_INT32_DEF("FL_KEEP_SIZE", FALLOC_FL_KEEP_SIZE, JS_PROP_CONFIGURABLE),
    JS_PROP_INT32_DEF("FL_PUNCH_HOLE", FALLOC_FL_PUNCH_HOLE, JS_PROP_CONFIGURABLE)
#endif
};

// class Inotify
static thread_local JSClassID js_inotify_class_id;

#define TELL_ERROR return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invaild INotify instance", "did you called Inotify.close() before?");

#ifndef __CYGWIN__
static JSValue js_inotify_watch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    EvFD* fd = JS_GetOpaque(this_val, js_inotify_class_id);
    if(!fd) TELL_ERROR;

    uint32_t flags;
    if(argc < 2 || !JS_IsString(argv[0]) || -1 == JS_ToUint32(ctx, &flags, argv[1]))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "Inotify.watch(path: string, flag: number): INWD");

    const char* path = JS_ToCString(ctx, argv[0]);
    int wd;
    if(!evcore_inotify_watch(fd, path, flags, &wd)){
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to add watch: %s", NULL, strerror(errno));
    }

    return JS_NewInt32(ctx, wd);
}

static JSValue js_inotify_unwatch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    EvFD* fd = JS_GetOpaque(this_val, js_inotify_class_id);
    if(!fd) TELL_ERROR;

    int wd;
    if(argc < 1 || -1 == JS_ToInt32(ctx, &wd, argv[0]))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "Inotify.unwatch(wd: INWD (aka number) ): void");

    if(!evcore_inotify_unwatch(fd, wd)){
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to remove watch: %s", NULL, strerror(errno));
    }

    return JS_UNDEFINED;
}

static JSValue js_inotify_find(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    EvFD* fd = JS_GetOpaque(this_val, js_inotify_class_id);
    if(!fd) TELL_ERROR;

    if(argc < 1 || !JS_IsString(argv[0]))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "Inotify.find(path: string): INWD | null");

    const char* path = JS_ToCString(ctx, argv[0]);
    int wd = evcore_inotify_find(fd, path);

    return wd == -1 ? JS_NULL : JS_NewInt32(ctx, wd);
}

static JSValue js_inotify_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    EvFD* fd = JS_GetOpaque(this_val, js_inotify_class_id);
    if(!fd) TELL_ERROR;

    struct JSValueProxy* proxy = evfd_get_opaque(fd);
    LJS_FreeJSValueProxy(proxy);

    evfd_close(fd);
    JS_SetOpaque(this_val, NULL);
    return JS_UNDEFINED;
}

#undef TELL_ERROR

void in_callback(EvFD* fd, const char* path, uint32_t evtype, const char* move_to, void* cb_ptr){
    struct JSValueProxy* proxy = (struct JSValueProxy*)cb_ptr;

    if(path == NULL && evtype == IN_CLOSE) return;

    JS_Call(proxy -> ctx, proxy -> val, JS_NULL, evtype == IN_MOVE ? 3 : 2, (JSValueConst[]){
        JS_NewUint32(proxy -> ctx, evtype),
        JS_NewString(proxy -> ctx, path),
        evtype == IN_MOVE ? JS_NewString(proxy -> ctx, move_to) : JS_UNDEFINED
    });
}

void in_resolve(EvFD* fd, bool _, void* cb_ptr){
    struct promise* prom = (struct promise*)cb_ptr;
    js_resolve(prom, JS_UNDEFINED);

    // free event callback
    LJS_FreeJSValueProxy(evfd_get_opaque(fd));
}

static JSValue js_inotify_ctor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsFunction(ctx, argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "missing argument", "new Inotify(callback: (type: number, path: string, move_to?: string) => void): Inotify");
    }

    struct JSValueProxy* proxy = LJS_NewJSValueProxy(ctx, argv[0]);
    EvFD* fd = evcore_inotify(in_callback, proxy);
    if(!fd) return LJS_Throw(ctx, EXCEPTION_IO, "failed to create inotify instance: %s", NULL, strerror(errno));
    evfd_set_opaque(fd, proxy);

    JSValue class = JS_NewObjectClass(ctx, js_inotify_class_id);
    JS_SetOpaque(class, fd);

    // close promise
    struct promise* prom = js_promise(ctx);
    JS_DefinePropertyValueStr(ctx, class, "closed", js_get_promise(prom), JS_PROP_C_W_E);

    evfd_onclose(fd, in_resolve, prom);

    return class;
}

static const JSCFunctionListEntry js_inotify_funcs[] = {
    JS_CFUNC_DEF("watch", 2, js_inotify_watch),
    JS_CFUNC_DEF("unwatch", 1, js_inotify_unwatch),
    JS_CFUNC_DEF("find", 1, js_inotify_find),
    JS_CFUNC_DEF("close", 0, js_inotify_close),
    JS_PROP_STRING_DEF("[Symbol.toStringTag]", "Inotify", JS_PROP_CONFIGURABLE),
};
#else
static JSValue js_inotify_ctor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv){
    return LJS_Throw(ctx, EXCEPTION_NOTSUPPORT, "not support inotify on windows", NULL);
}
static const JSCFunctionListEntry js_inotify_funcs[] = {};
#endif

static JSClassDef js_inotify_class = {
    "Inotify"
};

static const JSCFunctionListEntry js_inotify_flags[] = {
#ifndef __CYGWIN__
    // event mask
    C_CONST_RENAME(IN_ACCESS, ACCESS),
    C_CONST_RENAME(IN_MODIFY, MODIFY),
    C_CONST_RENAME(IN_ATTRIB, ATTRIB),
    C_CONST_RENAME(IN_CLOSE_WRITE, CLOSE_WRITE),
    C_CONST_RENAME(IN_CLOSE_NOWRITE, CLOSE_NOWRITE),
    C_CONST_RENAME(IN_OPEN, OPEN),
    C_CONST_RENAME(IN_CREATE, CREATE),
    C_CONST_RENAME(IN_DELETE, DELETE),
    C_CONST_RENAME(IN_DELETE_SELF, DELETE_SELF),
    C_CONST_RENAME(IN_MOVE_SELF, MOVE_SELF),
    C_CONST_RENAME(IN_UNMOUNT, UNMOUNT),
    // message flags
    C_CONST_RENAME(IN_Q_OVERFLOW, Q_OVERFLOW),
    C_CONST_RENAME(IN_IGNORED, IGNORED),
    C_CONST_RENAME(IN_ONLYDIR, ONLYDIR),
    C_CONST_RENAME(IN_DONT_FOLLOW, DONT_FOLLOW),
    C_CONST_RENAME(IN_MASK_ADD, MASK_ADD),
    C_CONST_RENAME(IN_ISDIR, ISDIR),
    // watch flags
    C_CONST_RENAME(IN_ONESHOT, ONESHOT),
    C_CONST_RENAME(IN_ALL_EVENTS, ALL_EVENTS),
#endif
};

// --------------- stdio ---------------

static JSValue js_stdio_read(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    const char *filename;
    size_t filename_len;
    uint8_t *buf;
    size_t buf_len;
    bool to_str = false;

    if(argc == 0 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.readSync(filename: string, str?: boolean): string | Uint8Array");

    if(argc == 2)
        to_str = JS_ToBool(ctx, argv[1]);

    filename = JS_ToCStringLen(ctx, &filename_len, argv[0]);
    if (!filename)
        return JS_EXCEPTION;

    int fd = open(filename, O_RDONLY);
    JS_FreeCString(ctx, filename);
    if (fd == -1) {
        LJS_Throw(ctx, EXCEPTION_NOTFOUND, "failed to open file: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }
    struct stat st;
    if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)) {
        close(fd);
        return LJS_Throw(ctx, EXCEPTION_INVAILDF, "not a regular file: %s", NULL, strerror(errno));
    }

    // 读取文件内容
    buf_len = st.st_size;
    buf = js_malloc(ctx, buf_len + 1);
    if (!buf) {
        close(fd);
        return JS_ThrowOutOfMemory(ctx);
    }
    if (read(fd, buf, buf_len) != buf_len) {
        js_free(ctx, buf);
        close(fd);
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to read file: %s", NULL, strerror(errno));
    }
    buf[buf_len] = '\0';
    close(fd);

    JSValue ret = to_str
        ? JS_NewStringLen(ctx, (char *)buf, buf_len)
        : JS_NewUint8Array(ctx, buf, buf_len, free_js_malloc, NULL, false);

    if(to_str) js_free(ctx, buf);
    return ret;
}

static JSValue js_stdio_stat(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    const char *filename;
    size_t filename_len;
    struct stat st;

    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.statSync(filename: string): object");

    filename = JS_ToCStringLen(ctx, &filename_len, argv[0]);
    if (!filename)
        return JS_EXCEPTION;

    if (stat(filename, &st) < 0) {
        LJS_Throw(ctx, EXCEPTION_IO, "failed to stat file: %s", NULL, strerror(errno));
        JS_FreeCString(ctx, filename);
        return JS_EXCEPTION;
    }
    JS_FreeCString(ctx, filename);

    JSValue obj = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, obj, "mtime", JS_NewBigInt64(ctx, st.st_mtime * 1000));
    JS_SetPropertyStr(ctx, obj, "atime", JS_NewBigInt64(ctx, st.st_atime * 1000));
    JS_SetPropertyStr(ctx, obj, "ctime", JS_NewBigInt64(ctx, st.st_ctime * 1000));
    JS_SetPropertyStr(ctx, obj, "ino", JS_NewInt64(ctx, st.st_ino));
    JS_SetPropertyStr(ctx, obj, "dev", JS_NewInt64(ctx, st.st_dev));
    JS_SetPropertyStr(ctx, obj, "mode", JS_NewInt32(ctx, st.st_mode));
    JS_SetPropertyStr(ctx, obj, "nlink", JS_NewInt64(ctx, st.st_nlink));
    JS_SetPropertyStr(ctx, obj, "uid", JS_NewInt64(ctx, st.st_uid));
    JS_SetPropertyStr(ctx, obj, "gid", JS_NewInt64(ctx, st.st_gid));

    if (S_ISDIR(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isDirectory", JS_NewBool(ctx, true));
    } else if(S_ISREG(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isFile", JS_NewBool(ctx, true));
        JS_SetPropertyStr(ctx, obj, "size", JS_NewInt64(ctx, st.st_size));
        
        JS_SetPropertyStr(ctx, obj, "blksize", JS_NewInt64(ctx, st.st_blksize));
        JS_SetPropertyStr(ctx, obj, "blocks", JS_NewInt64(ctx, st.st_blocks));
    } else if(S_ISCHR(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "rdev", JS_NewInt64(ctx, st.st_rdev));
        JS_SetPropertyStr(ctx, obj, "isCharacterDevice", JS_NewBool(ctx, true));
    } else if(S_ISBLK(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "rdev", JS_NewInt64(ctx, st.st_rdev));
        JS_SetPropertyStr(ctx, obj, "isBlockDevice", JS_NewBool(ctx, true));
    } else if(S_ISFIFO(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isFIFO", JS_NewBool(ctx, true));
    } else if(S_ISSOCK(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isSocket", JS_NewBool(ctx, true));
    } else if(S_ISLNK(st.st_mode)) {
        JS_SetPropertyStr(ctx, obj, "isSymbolicLink", JS_NewBool(ctx, true));
        char* link_target = js_malloc(ctx, PATH_MAX + 1);
        if (readlink(filename, link_target, PATH_MAX) >= 0) {
            JS_SetPropertyStr(ctx, obj, "target", JS_NewString(ctx, link_target));
        }
        js_free(ctx, link_target);
    }
    return obj;
}

static JSValue js_stdio_write(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    const char *filename;
    size_t filename_len;
    uint8_t *data;
    size_t data_len;

    if(argc != 2 || !JS_IsString(argv[0]) || (!JS_IsString(argv[1]) && JS_TYPED_ARRAY_UINT8 != JS_GetTypedArrayType(argv[1])))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.write(filename: string, data: string | Uint8Array): void");

    filename = JS_ToCStringLen(ctx, &filename_len, argv[0]);
    if (!filename)
        return JS_EXCEPTION;

    if(JS_IsString(argv[1])){
        data = (uint8_t*)JS_ToCStringLen(ctx, &data_len, argv[1]);
    }else{
        data = JS_GetUint8Array(ctx, &data_len, argv[1]);
    }
    if (!data)
        return JS_EXCEPTION;

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    JS_FreeCString(ctx, filename);
    if (fd < 0) {
        LJS_Throw(ctx, EXCEPTION_IO, "failed to open file: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }
    if (write(fd, data, data_len) != data_len) {
        if(JS_IsString(argv[1])) JS_FreeCString(ctx, (char*)data);
        close(fd);
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to write file: %s", NULL, strerror(errno));
    }
    if(JS_IsString(argv[1])) JS_FreeCString(ctx, (char*)data);
    close(fd);

    return JS_UNDEFINED;
}

static JSValue js_stdio_access(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc < 2 || !JS_IsString(argv[0]) || !JS_IsNumber(argv[1])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", 
            "stdio.access(path: string, test: number, safe?: boolean): string");
    }

    const char* path = JS_ToCString(ctx, argv[0]);
    int32_t mode;
    if(-1 == JS_ToInt32(ctx, &mode, argv[1])) return JS_EXCEPTION;
    bool safe = argc > 2 && JS_ToBool(ctx, argv[2]);

    int ret = access(path, mode);
    if(ret == -1){
        if(safe) return JS_FALSE;
        else return LJS_Throw(ctx, EXCEPTION_IO, "failed to access file: %s", NULL, strerror(errno));
    }else{
        if(safe) return JS_TRUE;
        else return JS_UNDEFINED;
    }
}

// mkdir
static JSValue js_stdio_mkdir(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    const char *path;
    size_t path_len;
    int mode = 0755;

    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.mkdir(path: string, mode: int): void");

    path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path)
        return JS_EXCEPTION;

    if (mkdir(path, mode) < 0) {
        LJS_Throw(ctx, EXCEPTION_IO,  "failed to create directory: %s", NULL, strerror(errno));
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }
    JS_FreeCString(ctx, path);

    return JS_UNDEFINED;
}

static bool get_all_files_or_dirs(
    JSContext *ctx, 
    const char* path, 
    char*** list, uint32_t* list_length, uint32_t* list_used,
    char*** dir_list, uint32_t* dir_list_length, uint32_t* dir_list_used, 
    bool stop_when_error
){
    DIR* dir = opendir(path);
    bool error = false;

    if (!dir) {
        return false;
    }

    struct dirent* ent;
    while ((ent = readdir(dir))!= NULL) {
        if (ent -> d_name[0] == '.' && (ent -> d_name[1] == '\0' || (ent -> d_name[1] == '.' && ent -> d_name[2] == '\0'))) {
            continue;
        }

        // is dir?
        if (ent -> d_type == DT_DIR) {
            char* new_path = js_malloc(ctx, strlen(path) + strlen(ent -> d_name) + 2);
            strcpy(new_path, path);
            strcat(new_path, "/");
            strcat(new_path, ent -> d_name);
            if (!get_all_files_or_dirs(
                ctx, new_path, 
                list, list_length, list_used,
                dir_list, dir_list_length, dir_list_used,
                stop_when_error
            )){ 
                if (stop_when_error){
                    js_free(ctx, new_path);
                    closedir(dir);
                    return false;
                }else{
                    error = true;
                }
            }
            js_free(ctx, new_path);
            // add to dir_list
            if (*dir_list_used >= *dir_list_length) {
                *dir_list_length += 16;
                *dir_list = realloc(*dir_list, *dir_list_length * sizeof(char*));
            }
            (*dir_list)[*dir_list_used] = strdup2(ent -> d_name);
            (*dir_list_used)++;
        }else{
            if (*list_used >= *list_length) {
                *list_length += 16;
                *list = realloc(*list, *list_length * sizeof(char*));
            }
            (*list)[*list_used] = strdup2(ent -> d_name);
            (*list_used)++;
        }
    }
    closedir(dir);
    return error;
}

static inline JSValue dirent_type_to_str(JSContext *ctx, unsigned char d_type){
    switch (d_type) {
        case DT_REG:
            return JS_NewString(ctx, "file");
        case DT_DIR:
            return JS_NewString(ctx, "dir");
        case DT_LNK:
            return JS_NewString(ctx, "link");
        case DT_BLK:
            return JS_NewString(ctx, "blkdrv");
        case DT_CHR:
            return JS_NewString(ctx, "chardev");
        case DT_FIFO:
            return JS_NewString(ctx, "fifo");
        case DT_SOCK:
            return JS_NewString(ctx, "socket");
        default:
            return JS_NewString(ctx, "unknown");
    }
}

// unlink
static JSValue js_stdio_unlink(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.unlink(path: string): void");
    
    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path){
        return JS_EXCEPTION;
    }

    // stat is a dir or file
    struct stat st;
    if (stat(path, &st) < 0) {
        LJS_Throw(ctx, EXCEPTION_IO, "failed to stat file: %s", NULL, strerror(errno));
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }
    if (S_ISDIR(st.st_mode)) {
        char** list = js_malloc(ctx, 16 * sizeof(char*));
        uint32_t list_length = 16;
        uint32_t list_used = 0;
        char** dir_list = js_malloc(ctx, 16 * sizeof(char*));
        uint32_t dir_list_length = 16;
        uint32_t dir_list_used = 0;
        if (!get_all_files_or_dirs(
            ctx, path, 
            &list, &list_length, &list_used, 
            &dir_list, &dir_list_length, &dir_list_used, 
            true
        )) {
            LJS_Throw(ctx, EXCEPTION_IO, "failed to get subfiles in this directory: %s", NULL, strerror(errno));
            js_free(ctx, list);
            js_free(ctx, dir_list);
            JS_FreeCString(ctx, path);
            return JS_EXCEPTION;
        }

        // delete all subfiles
        for (uint32_t i = 0; i < list_used; i++) {
            char* sub_path = js_malloc(ctx, strlen(path) + strlen(list[i]) + 2);
            strcpy(sub_path, path);
            strcat(sub_path, "/");
            strcat(sub_path, list[i]);
            if (unlink(sub_path) < 0) {
                LJS_Throw(ctx, EXCEPTION_IO, "failed to remove file %s: %s", NULL, sub_path, strerror(errno));
                js_free(ctx, sub_path);
                js_free(ctx, list);
                js_free(ctx, dir_list);
                JS_FreeCString(ctx, path);
                return JS_EXCEPTION;
            }
            js_free(ctx, sub_path);
        }
        js_free(ctx, list);

        // delete subdirs
        for (uint32_t i = 0; i < dir_list_used; i++) {
            char* sub_path = js_malloc(ctx, strlen(path) + strlen(dir_list[i]) + 2);
            strcpy(sub_path, path);
            strcat(sub_path, "/");
            strcat(sub_path, dir_list[i]);
            if (rmdir(sub_path) < 0) {
                LJS_Throw(ctx, EXCEPTION_IO, "failed to remove directory: %s", NULL, strerror(errno));
                js_free(ctx, sub_path);
                js_free(ctx, list);
                js_free(ctx, dir_list);
                JS_FreeCString(ctx, path);
                return JS_EXCEPTION;
            }
            js_free(ctx, sub_path);
        }
        js_free(ctx, dir_list);

        // delete dir
        if (rmdir(path) < 0) {
            LJS_Throw(ctx, EXCEPTION_IO, "failed to remove directory: %s", NULL, strerror(errno));
            js_free(ctx, list);
            js_free(ctx, dir_list);
            return JS_EXCEPTION;
        }

    } else {
        if (unlink(path) < 0) {
            LJS_Throw(ctx, EXCEPTION_IO, "failed to remove file: %s", NULL, strerror(errno));
            JS_FreeCString(ctx, path);
            return JS_EXCEPTION;
        }
    }

    JS_FreeCString(ctx, path);
    return JS_UNDEFINED;
}

// symlink
static JSValue js_stdio_symlink(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 2 || !JS_IsString(argv[0]) || !JS_IsString(argv[1])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.symlink(target: string, path: string): void");
    
    size_t target_len;
    const char *target = JS_ToCStringLen(ctx, &target_len, argv[0]);
    if (!target)
        return JS_EXCEPTION;

    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[1]);
    if (!path)
        return JS_EXCEPTION;

    JSValue ret = JS_UNDEFINED;
    if (symlink(target, path) < 0) {
        LJS_Throw(ctx, EXCEPTION_IO, "failed to create symlink: %s", NULL, strerror(errno));
        ret = JS_EXCEPTION;
    }

    JS_FreeCString(ctx, target);
    JS_FreeCString(ctx, path);
    return ret;
}

// chmod
static JSValue js_stdio_chmod(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 2 || !JS_IsString(argv[0]) || !JS_IsNumber(argv[1])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.chmod(path: string, mode: int): void");
    
    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path)
        return JS_EXCEPTION;

    uint32_t mode;
    if(-1 == JS_ToUint32(ctx, &mode, argv[1]) || mode > 07777)
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid mode", NULL);

    if (chmod(path, mode) < 0) {
        LJS_Throw(ctx, EXCEPTION_IO, "failed to change file mode: %s", NULL, strerror(errno));
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }

    JS_FreeCString(ctx, path);
    return JS_UNDEFINED;
}

// realpath
static JSValue js_stdio_realpath(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.realpath(path: string): string");
    
    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path)
        return JS_EXCEPTION;

    char* real_path = realpath(path, NULL);
    if (!real_path) {
        LJS_Throw(ctx, EXCEPTION_IO, "failed to get real path: %s", NULL, strerror(errno));
        JS_FreeCString(ctx, path);
        return JS_EXCEPTION;
    }

    JS_FreeCString(ctx, path);
    JSValue ret = JS_NewString(ctx, real_path);
    js_free(ctx, real_path);
    return ret;
}

// scandir
static JSValue js_stdio_scandir(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 1 || !JS_IsString(argv[0])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.scandir(path: string): array");
    
    size_t path_len;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    if (!path)
        return JS_EXCEPTION;

    DIR* dir = opendir(path);
    JS_FreeCString(ctx, path);
    if (!dir) {
        LJS_Throw(ctx, EXCEPTION_NOTFOUND, "failed to open directory: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    struct dirent* ent;
    JSValue arr = JS_NewArray(ctx);
    uint32_t i = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (ent -> d_name[0] == '.' && (ent -> d_name[1] == '\0' || (ent -> d_name[1] == '.' && ent -> d_name[2] == '\0'))) {
            continue;
        }

        JSValue obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, obj, "name", JS_NewString(ctx, ent -> d_name));
        JS_SetPropertyStr(ctx, obj, "type", dirent_type_to_str(ctx, ent -> d_type));
        JS_SetPropertyUint32(ctx, arr, i, obj);
        i++;
    }

    closedir(dir);
    return arr;
}

// rename
static JSValue js_stdio_rename(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 2 || !JS_IsString(argv[0]) || !JS_IsString(argv[1])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.rename(oldPath: string, newPath: string): void");
    
    size_t old_path_len;
    const char *old_path = JS_ToCStringLen(ctx, &old_path_len, argv[0]);
    if (!old_path)
        return JS_EXCEPTION;

    size_t new_path_len;
    const char *new_path = JS_ToCStringLen(ctx, &new_path_len, argv[1]);
    if (!new_path)
        return JS_EXCEPTION;

    if (rename(old_path, new_path) < 0) {
        LJS_Throw(ctx, EXCEPTION_IO, "failed to rename file: %s", NULL, strerror(errno));
        return JS_EXCEPTION;
    }

    return JS_UNDEFINED;
}

// copy: based on async splice
static JSValue js_stdio_copy(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc != 2 || !JS_IsString(argv[0]) || !JS_IsString(argv[1])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.copy(src: string, dst: string): void");
    
    size_t src_len;
    const char *src = JS_ToCStringLen(ctx, &src_len, argv[0]);
    size_t dst_len;
    const char *dst = JS_ToCStringLen(ctx, &dst_len, argv[1]);
    if (!src || !dst) return JS_EXCEPTION;

#ifdef __CYGWIN__
    if(!CopyFile(src, dst, false)){
        DWORD err = GetLastError();
        LJS_Throw(ctx, EXCEPTION_IO, "failed to copy file: %s", NULL, strerror(err));
    }
#else
    int src_fd = open(src, O_RDONLY);
    if(src_fd < 0) goto oserr;
    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if(dst_fd < 0){
        close(src_fd);
        goto oserr;
    }

    struct stat st;
    if(fstat(src_fd, &st) < 0) goto oserr;
    off_t size = st.st_size;

    int ret;
    off_t offset = 0;

    while (offset < size) {
        ret = sendfile(dst_fd, src_fd, &offset, EVFD_BUFSIZE);
        if (ret == -1) {
            close(src_fd);
            close(dst_fd);
            goto oserr;
        }
    }

#endif
    return JS_UNDEFINED;

#ifndef __CYGWIN__
oserr:
    return LJS_Throw(ctx, EXCEPTION_IO, "failed to copy file: %s", NULL, strerror(errno));
#endif
}

// open
static JSValue js_stdio_open(JSContext *ctx, JSValueConst self, int argc, JSValueConst *argv){
    if(argc < 2 || !JS_IsString(argv[0]) || !JS_IsString(argv[1])) 
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", "stdio.open(path: string, flags: string, mode?: number, sync?: boolean): Pipe|SyncPipe");
    
    size_t path_len;
    uint32_t mode = 0666;
    int flag = 0;
    const char *path = JS_ToCStringLen(ctx, &path_len, argv[0]);
    const char *flags = JS_ToCString(ctx, argv[1]);
    
    if((argc == 3 && 0 != JS_ToUint32(ctx, &mode, argv[2])) || !path || !flags){
        if(path) JS_FreeCString(ctx, path);
        if(flags) JS_FreeCString(ctx, flags);
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid arguments", NULL);
    }

    bool sync = false;
    if(argc == 4) sync = JS_ToBool(ctx, argv[3]);

    // parse flags
    // flag1: r, w, a, x
    if(flags[0] != '\0'){
        if(flags[0] == 'r') flag |= O_RDONLY;
        else if(flags[0] == 'w') flag |= O_WRONLY | O_CREAT | O_TRUNC;
        else if(flags[0] == 'a') flag |= O_WRONLY | O_CREAT | O_APPEND;
        else if(flags[0] == 'x') flag |= O_WRONLY | O_CREAT | O_EXCL;
        else {
            LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid flag", NULL);
            goto error;
        }
    }
    // flag2/3: x, s, +
    if(flags[1] != '\0'){
        if(flags[1] == 'x') flag |= O_EXCL;
        else if(flags[1] == 's') flag |= O_SYNC;
        else if(flags[1] == '+') flag |= O_RDWR;
        else {
            LJS_Throw(ctx, EXCEPTION_TYPEERROR, "invalid flag", NULL);
            goto error;
        }

        if(flags[2] != '\0' && flags[2] == '+'){
            flag |= O_RDWR;
        }
    }

    int fd = open(path, flag, mode);
    if (fd < 0) {
        LJS_Throw(ctx, EXCEPTION_NOTFOUND, "failed to open file: %s", NULL, strerror(errno));
        goto error;
    }

    JS_FreeCString(ctx, path);
    JS_FreeCString(ctx, flags);
    if(sync){
        struct stat st;

        // construct SyncPipe
        JSValue pipe = JS_NewObjectClass(ctx, js_syncpipe_class_id);
        struct SyncPipe* piped = js_malloc(ctx, sizeof(struct SyncPipe));
        JS_SetOpaque(pipe, piped);
        piped -> fd = fd;
        piped -> size = fstat(fd, &st) == 0 ? st.st_size : -1;
        return pipe;
    }else{
        // file pipe requires seek support(should be IOPipe)
        return LJS_NewFDPipe(ctx, fd, PIPE_READ | PIPE_WRITE | PIPE_AIO, true, NULL);
    }

    error:{
        JS_FreeCString(ctx, path);
        JS_FreeCString(ctx, flags);
        return JS_EXCEPTION;
    }
}

static const JSCFunctionListEntry js_stdio_funcs[] = {
    JS_CFUNC_DEF("write", 2, js_stdio_write),
    // JS_CFUNC_DEF("access", 2, js_stdio_access),
    JS_PROP_INT32_DEF("access", 0, JS_PROP_C_W_E),  // placeholder
    JS_CFUNC_DEF("mkdir", 1, js_stdio_mkdir),
    JS_CFUNC_DEF("unlink", 1, js_stdio_unlink),
    JS_CFUNC_DEF("symlink", 2, js_stdio_symlink),
    JS_CFUNC_DEF("chmod", 2, js_stdio_chmod),
    JS_CFUNC_DEF("realpath", 1, js_stdio_realpath),
    JS_CFUNC_DEF("scandir", 1, js_stdio_scandir),
    JS_CFUNC_DEF("open", 2, js_stdio_open),
    JS_CFUNC_DEF("stat", 1, js_stdio_stat),
    JS_CFUNC_DEF("read", 2, js_stdio_read),
    JS_CFUNC_DEF("rename", 2, js_stdio_rename),
    JS_CFUNC_DEF("copy", 2, js_stdio_copy)
};

static const JSCFunctionListEntry js_access_flag[] = {
    C_CONST_RENAME(F_OK, ACCESS),
    C_CONST_RENAME(R_OK, READ),
    C_CONST_RENAME(W_OK, WRITE),
    C_CONST_RENAME(X_OK, EXECUTE),
};

static int js_mod_stdio_init(JSContext *ctx, JSModuleDef *m) {
    JS_SetModuleExportList(ctx, m, js_stdio_funcs, countof(js_stdio_funcs));
    JSValue access_func = JS_NewCFunction(ctx, js_stdio_access, "access", 2);
    JS_SetModuleExport(ctx, m, "access", access_func);
    JS_SetPropertyFunctionList(ctx, access_func, js_access_flag, countof(js_access_flag));

    // class SyncPipe
    JS_NewClassID(JS_GetRuntime(ctx), &js_syncpipe_class_id);
    if(-1 == JS_NewClass(JS_GetRuntime(ctx), js_syncpipe_class_id, &js_syncpipe_class)) 
        return false;
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_syncpipe_funcs, countof(js_syncpipe_funcs));
    JS_SetClassProto(ctx, js_syncpipe_class_id, proto);
    JSValue constructor = JS_NewCFunction2(ctx, js_syncio_constructor, "SyncPipe", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, constructor, proto);
    JS_SetModuleExport(ctx, m, "SyncPipe", constructor);

    // proto
    JS_SetPropertyFunctionList(ctx, constructor, js_syncpipe_flags, countof(js_syncpipe_flags));

    // inotify
    JS_NewClassID(JS_GetRuntime(ctx), &js_inotify_class_id);
    if(-1 == JS_NewClass(JS_GetRuntime(ctx), js_inotify_class_id, &js_inotify_class)) 
        return false;
    JSValue inotify_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, inotify_proto, js_inotify_funcs, countof(js_inotify_funcs));
    JS_SetClassProto(ctx, js_inotify_class_id, inotify_proto);
    JSValue inotify_constructor = JS_NewCFunction2(ctx, js_inotify_ctor, "Inotify", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, inotify_constructor, inotify_proto);
    JS_SetPropertyFunctionList(ctx, inotify_constructor, js_inotify_flags, countof(js_inotify_flags));
    JS_SetModuleExport(ctx, m, "Inotify", inotify_constructor);

    return 0;
}

bool LJS_init_fs(JSContext *ctx){
    JSModuleDef *m = JS_NewCModule(ctx, "fs", js_mod_stdio_init);
    if (!m) return false;
    JS_AddModuleExportList(ctx, m, js_stdio_funcs, countof(js_stdio_funcs));
    JS_AddModuleExport(ctx, m, "SyncPipe");
    JS_AddModuleExport(ctx, m, "Inotify");

    return true;
}