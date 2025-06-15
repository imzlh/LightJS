#include "../engine/quickjs.h"
#include "../engine/cutils.h"
#include "../engine/list.h"
#include "core.h"
#include "polyfill.h"

#include <stdlib.h>
#include <string.h>

#ifdef LJS_ZLIB
#include <zlib.h>

#define LJS_ZLIB_CHUNK_SIZE 16384

struct js_zlib {
    z_stream zstream;
};

static JSValue js_zlib_zlibformat(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc <= 1 || -1 == JS_GetTypedArrayType(argv[0]) || !JS_IsBool(argv[1])){
        return LJS_Throw(ctx, "Invalid arguments for zlib", "zlib(data: Uint8Array, decompress: boolean, level?: number): Uint8Array");
    }

    size_t bufsize;
    uint8_t* buf = JS_GetUint8Array(ctx, &bufsize, argv[0]);
    if(!buf) return JS_EXCEPTION;

    uint32_t level = Z_DEFAULT_COMPRESSION;
    if(argc > 2){
        if(JS_ToUint32(ctx, &level, argv[2]) == -1 || level > 9){
            return LJS_Throw(ctx, "Invalid compression level", "deflate(data: Uint8Array, decompress: boolean, level?: number): Uint8Array");
        }
    }

    bool decompress = JS_ToBool(ctx, argv[1]);
    size_t outsize = compressBound(bufsize);
    uint8_t* outbuf = js_malloc(ctx, outsize);
    if(!outbuf) return JS_ThrowOutOfMemory(ctx);

main:
    int res;
    if(decompress){
        res = uncompress2(outbuf, &outsize, buf, &bufsize);
    }else{
        res = compress2(outbuf, &outsize, buf, bufsize, level);
    }

    switch(res){
        case Z_MEM_ERROR:
            return JS_ThrowOutOfMemory(ctx);

        case Z_BUF_ERROR:
            outsize *= 2;
            free(outbuf);
            outbuf = js_malloc(ctx, outsize);
            if(!outbuf) return JS_ThrowOutOfMemory(ctx);
            goto main;

        case Z_ERRNO:
            return LJS_Throw(ctx, "Failed to compress/decompress data: %s", NULL, strerror(errno));

        case Z_OK:
            break;

        default: abort();
    }
    
    JSValue ret = JS_NewUint8Array(ctx, outbuf, outsize, free_js_malloc, NULL, false);
    return ret;
}

static void* zlib_malloc_proxy(void* opaque, uint32_t items, uint32_t size){
    JSRuntime* rt = opaque;
    return js_malloc_rt(rt, items * size);
}

static void zlib_free_proxy(void* opaque, void* ptr){
    JSRuntime* rt = opaque;
    js_free_rt(rt, ptr);
}

#define INIT_ZSTREAM(zstream) z_stream zstream; \
    memset(&zstream, 0, sizeof(zstream)); \
    zstream.zalloc = zlib_malloc_proxy; \
    zstream.zfree = zlib_free_proxy; \
    zstream.opaque = JS_GetRuntime(ctx);

static JSValue js_zlib_inflate(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc <= 1 || -1 == JS_GetTypedArrayType(argv[0]) || !JS_IsBool(argv[1])){
        return LJS_Throw(ctx, "Invalid arguments for deflate", "deflate(data: Uint8Array, decompress: boolean, level?: number): Uint8Array");
    }

    size_t bufsize;
    uint8_t* buf = JS_GetUint8Array(ctx, &bufsize, argv[0]);
    if(!buf) return JS_EXCEPTION;

    uint32_t level = Z_DEFAULT_COMPRESSION;
    if(argc > 2){
        if(JS_ToUint32(ctx, &level, argv[2]) == -1 || level > 9){
            return LJS_Throw(ctx, "Invalid compression level", "deflate(data: Uint8Array, decompress: boolean, level?: number): Uint8Array");
        }
    }

    bool decompress = JS_ToBool(ctx, argv[1]);

    INIT_ZSTREAM(zstream);
    if(
        (decompress && -1 == inflateInit(&zstream)) ||
        (!decompress && -1 == deflateInit(&zstream, level))
    ){
        return LJS_Throw(ctx, "Failed to initialize zlib", NULL, Z_ERRNO);
    }

    zstream.next_in = buf;
    zstream.avail_in = bufsize;

    int osize = decompress ? bufsize : bufsize * 2;
    uint8_t* obuf = js_malloc(ctx, osize);
    zstream.avail_out = osize;
    zstream.next_out = obuf;
    if(!zstream.next_out){
        if(decompress) inflateEnd(&zstream);
        else deflateEnd(&zstream);
        return JS_ThrowOutOfMemory(ctx);
    }

main_loop:
    int res;
    if(decompress){
        res = inflate(&zstream, Z_NO_FLUSH);
    }else{
        res = deflate(&zstream, Z_FINISH);
    }
    
    switch (res){
        case Z_STREAM_END:
            if(decompress) inflateEnd(&zstream);
            else deflateEnd(&zstream);
            JSValue ret = JS_NewUint8Array(ctx, obuf, zstream.total_out, free_js_malloc, NULL, false);
            return ret;

        case Z_DATA_ERROR:
            LJS_Throw(ctx, "Invalid data format", NULL);
            goto error;

        case Z_MEM_ERROR:
            JS_ThrowOutOfMemory(ctx);
            goto error;

        case Z_OK:
            if(zstream.avail_out == 0){
                zstream.avail_out += osize;
                obuf = js_realloc(ctx, obuf, osize * 2);
                zstream.next_out = obuf + zstream.total_out;
                if(!zstream.next_out){
                    return JS_ThrowOutOfMemory(ctx);
                }
                goto main_loop;
            }

        default:
error:
            if(decompress) inflateEnd(&zstream);
            else deflateEnd(&zstream);
            js_free(ctx, obuf);
            return JS_EXCEPTION;
    }

    return JS_EXCEPTION;
}

struct js_zlib_stream {
    z_stream zstream;
    JSValue buffer;
    Promise* poll_promise;
    Promise* write_promise;
    bool compress;
    bool closed;
};

static JSValue stream_poll(JSContext* ctx, void* ptr, JSValueConst data){
    struct js_zlib_stream* stream = ptr;
    if(stream -> closed) abort();

    if(stream -> poll_promise) abort();  // pipe should not be polled again before previous poll is resolved
    stream -> poll_promise = js_promise(ctx);
    if(stream -> zstream.avail_in) goto loop;  // have some data to consume

    if(stream -> write_promise){    // get data
        js_resolve(stream -> poll_promise, JS_NULL); 
        size_t size;
        uint8_t* data = JS_GetUint8Array(ctx, &size, stream -> buffer);
        stream -> zstream.avail_in = size;
        stream -> zstream.next_in = data;
        stream -> write_promise = NULL;
    }

    // write to zlib
    char* error;
loop:
    uint8_t* outbuf = stream -> zstream.next_out;
    while(stream -> zstream.avail_in){
        int res = stream -> compress
            ? deflate(&stream -> zstream, Z_NO_FLUSH)
            : inflate(&stream -> zstream, Z_NO_FLUSH);

        switch (res) {
            case Z_STREAM_END:
                error = "Stream ended";
                goto error;

            case Z_DATA_ERROR:
                error = "Invalid data format";
                goto error;

            case Z_MEM_ERROR:
                error = "Out of memory";
                goto error;

            default:
                // full
                if (stream -> zstream.avail_out == 0 || stream -> zstream.avail_in == 0) {
                    JSValue chunk = JS_NewUint8Array(ctx, outbuf, stream -> zstream.next_out - outbuf, free_js_malloc, NULL, false);
                    js_resolve(stream -> poll_promise, chunk);

                    outbuf = js_malloc(ctx, LJS_ZLIB_CHUNK_SIZE);
                    if (!outbuf) {
                        JS_ThrowOutOfMemory(ctx);
                    }
                    stream -> zstream.next_out = outbuf;
                    stream -> zstream.avail_out = LJS_ZLIB_CHUNK_SIZE;
                }
            break;  // have some data to consume
        }
    }

    goto finally;

error:
    stream -> closed = true;
    stream -> poll_promise = NULL;
    js_reject(stream -> poll_promise, error);

    if(stream -> compress) inflateEnd(&stream -> zstream);
    else deflateEnd(&stream -> zstream);
    free(stream);

finally:
    return stream -> poll_promise -> promise;
}

static JSValue stream_write(JSContext* ctx, void* ptr, JSValueConst data){
    struct js_zlib_stream* stream = ptr;
    if(stream -> closed) abort();

    if(stream -> write_promise) abort();  // pipe should not be written again before previous write is resolved
    stream -> write_promise = js_promise(ctx);

    return stream -> write_promise -> promise;
}

static JSValue stream_close(JSContext* ctx, void* ptr, JSValueConst data){
    struct js_zlib_stream* stream = ptr;
    if(stream -> closed) return JS_NULL;

    stream -> closed = true;
    if(stream -> poll_promise) js_reject(stream -> poll_promise, "Stream closed");
    if(stream -> write_promise) js_reject(stream -> write_promise, "Stream closed");

    if(stream -> compress) inflateEnd(&stream -> zstream);
    else deflateEnd(&stream -> zstream);
    free(stream);

    return JS_NULL;
}

static JSValue js_zlib_deflate_stream(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0) goto invaild_args;
    bool decompress = JS_ToBool(ctx, argv[0]);

    struct js_zlib_stream* js_stream = js_malloc(ctx, sizeof(struct js_zlib_stream));
    if(!js_stream) return JS_ThrowOutOfMemory(ctx);

    js_stream -> zstream.zalloc = zlib_malloc_proxy;
    js_stream -> zstream.zfree = zlib_free_proxy;
    js_stream -> zstream.opaque = JS_GetRuntime(ctx);
    js_stream -> poll_promise = js_stream -> write_promise = NULL;
    js_stream -> compress = !decompress;
    js_stream -> closed = false;

    if(decompress) inflateInit(&js_stream -> zstream);
    else deflateInit(&js_stream -> zstream, Z_DEFAULT_COMPRESSION);

    JSValue stream = LJS_NewU8Pipe(ctx, PIPE_READ | PIPE_WRITE, LJS_ZLIB_CHUNK_SIZE, stream_poll, stream_write, stream_close, js_stream);
    return stream;

invaild_args:
    return LJS_Throw(ctx, "Invalid arguments", "inflateStream(decompress: boolean, level?: number): Uint8Array");
}
#endif

static const JSCFunctionListEntry js_compress_funcs[] = {
#ifdef LJS_ZLIB
    JS_CFUNC_DEF("zlib", 1, js_zlib_zlibformat),
    JS_CFUNC_DEF("deflate", 1, js_zlib_inflate),
    JS_CFUNC_DEF("deflateStream", 1, js_zlib_deflate_stream),
#endif
};

static int init_compress(JSContext *ctx, JSModuleDef *m){
    JS_SetModuleExportList(ctx, m, js_compress_funcs, countof(js_compress_funcs));
#ifdef LJS_ZLIB
    JS_SetModuleExport(ctx, m, "zlib_version", JS_NewString(ctx, ZLIB_VERSION));
#endif
    return 0;
}

bool LJS_init_compress(JSContext *ctx){
    JSModuleDef* m = JS_NewCModule(ctx, "compress", init_compress);
    if(!m) return false;
    JS_AddModuleExportList(ctx, m, js_compress_funcs, countof(js_compress_funcs));
#ifdef LJS_ZLIB
    JS_AddModuleExport(ctx, m, "zlib_version");
#endif
    return true;
}