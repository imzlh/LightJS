/**
 * LightJS Cyclic Buffer V2
 * Note that the new version is not compatible with the old version.
 * 
 * Buffer: [start, end)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/uio.h>

#include "../engine/cutils.h"

#pragma once

#define BUFFER_SIZE 1024

typedef struct {
    uint8_t* buffer;
    size_t size;
    size_t start;
    size_t end;
    bool cyclic;

    bool __is_dynamic;
} Buffer;

static inline bool buffer_init(Buffer* buffer, size_t size){
    buffer -> buffer = (uint8_t*)malloc(size);
    if(!buffer -> buffer) return false;
    buffer -> size = size;
    buffer -> start = 0;
    buffer -> end = 0;
    buffer -> cyclic = false;
    buffer -> __is_dynamic = true;
    return true;
}

static inline bool buffer_init2(Buffer* buffer, uint8_t* buffer_ptr, size_t size){
    buffer -> buffer = buffer_ptr;
    buffer -> size = size;
    buffer -> start = 0;
    buffer -> end = 0;
    buffer -> cyclic = false;
    buffer -> __is_dynamic = false;
    return true;
}

static inline Buffer* buffer_new(size_t size){
    Buffer* buffer = (Buffer*)malloc(sizeof(Buffer));
    if(!buffer) return NULL;
    if(!buffer_init(buffer, size)) return NULL;
    return buffer;
}

static inline void buffer_free(Buffer* buffer){
    if(buffer -> __is_dynamic){
        free(buffer -> buffer);
    }
    buffer -> buffer = NULL;
}

static inline size_t buffer_get_used(Buffer* buffer){
    return buffer -> cyclic
        ? buffer -> end - buffer -> start + buffer -> size
        : buffer -> end - buffer -> start;
}

static inline size_t buffer_get_free(Buffer* buffer){
    return buffer -> cyclic
        ? buffer -> start - buffer -> end
        : buffer -> start + buffer -> size - buffer -> end;
}

static inline bool buffer_is_empty(Buffer* buffer){
    return !buffer -> cyclic && buffer -> start == buffer -> end;
}

static inline bool buffer_is_full(Buffer* buffer){
    return buffer -> cyclic
        ? buffer -> start == 0 && buffer -> end == buffer -> size - 1
        : buffer -> end == buffer -> size;
}

static inline void buffer_seek_end(Buffer* buffer, size_t pos){
    if(pos > buffer -> size) pos = pos % buffer -> size;
    buffer -> cyclic = pos < buffer -> start;
    buffer -> end = pos;
}

static inline void buffer_seek_start(Buffer* buffer, size_t pos){
    if(pos > buffer -> size) pos = pos % buffer -> size;
    buffer -> cyclic = pos > buffer -> end;
    buffer -> start = pos;
}

static inline void buffer_seek_cur_start(Buffer* buffer, size_t pos){
    pos += buffer -> start;
    buffer_seek_start(buffer, pos);
}

static inline void buffer_seek_cur_end(Buffer* buffer, size_t pos){
    pos += buffer -> end;
    buffer_seek_end(buffer, pos);
}

static inline ssize_t buffer_io_write(Buffer* buffer, int fd, size_t max_write){
    size_t n = buffer_get_used(buffer);
    if(n == 0) return 0;
    if(n > max_write) n = max_write;

    if(buffer -> cyclic){
        struct iovec vec[2] = {
            {
                .iov_base = buffer -> buffer + buffer -> start,
                .iov_len = n
            },
            {
                .iov_base = buffer -> buffer,
                .iov_len = buffer -> size - buffer -> start
            }
        };
        ssize_t ret = writev(fd, vec, 2);
        if(ret < 0) return ret;
        buffer_seek_cur_start(buffer, ret);
        return ret;
    }else{
        ssize_t ret = write(fd, buffer -> buffer + buffer -> start, n);
        if(ret < 0) return ret;
        buffer_seek_cur_start(buffer, ret);
        return ret;
    }
}

static inline ssize_t buffer_io_read(Buffer* buffer, int fd, size_t max_read){
    size_t n = buffer_get_free(buffer);
    if(n == 0) return 0;
    if(n > max_read) n = max_read;

    if(buffer -> cyclic){
        struct iovec vec[2] = {
            {
                .iov_base = buffer -> buffer + buffer -> end,
                .iov_len = n
            },
            {
                .iov_base = buffer -> buffer,
                .iov_len = buffer -> size - buffer -> end
            }
        };
        ssize_t ret = readv(fd, vec, 2);
        if(ret < 0) return ret;
        buffer_seek_cur_end(buffer, ret);
        return ret;
    }else{
        ssize_t ret = read(fd, buffer -> buffer + buffer -> end, n);
        if(ret < 0) return ret;
        buffer_seek_cur_end(buffer, ret);
        return ret;
    }
}

static inline size_t buffer_append(Buffer* buffer, const uint8_t* data, size_t len){
    if(len == 0) return 0;
    if(buffer_is_full(buffer)) return 0;

    size_t free = buffer_get_free(buffer);
    if(len > free) len = free;

    if(buffer -> cyclic){
        memcpy(buffer -> buffer + buffer -> end, data, len);
        buffer -> end += len;
    }else{
        size_t n1 = buffer -> size - buffer -> end;
        memcpy(buffer -> buffer + buffer -> end, data, n1);
        if(len > n1){
            buffer -> cyclic = true;
            memcpy(buffer -> buffer, data + n1, len - n1);
            buffer -> end = len - n1;
        }else{
            buffer -> end += len;
        }
    }
    return len;
}

static inline size_t buffer_pop(Buffer* buffer, uint8_t* data, size_t len){
    if(len == 0) return 0;
    if(buffer_is_empty(buffer)) return 0;

    size_t used = buffer_get_used(buffer);
    if(len > used) len = used;

    if(buffer -> cyclic){
        size_t n1 = buffer -> size - buffer -> start;
        size_t n2 = buffer -> end;
        memcpy(data, buffer -> buffer + buffer -> start, n1);
        memcpy(data + n1, buffer -> buffer, n2);
        buffer_seek_cur_start(buffer, len);   // read len bytes
    }else{
        memcpy(data, buffer -> buffer + buffer -> start, len);
        buffer -> start += len;
    }
    return len;
}

static inline size_t buffer_copyto(Buffer* source, Buffer* dest, size_t len){
    if(len == 0) return 0;
}