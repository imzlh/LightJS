#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>

#pragma once

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// Note: Unsafe in the case that the buffer is modified in loop
#define BUFFER_UNSAFE_FOREACH_BYTE(_buffer, _index, _byte) \
    uint32_t __i = (_buffer) -> start, _index = 0; \
    uint8_t _byte = *(__i + (_buffer) -> buffer); \
    for(; (__i) != (_buffer) -> end; (_index) += 1, __i = (__i) + 1 == (_buffer) -> size ? 0 : (__i) + 1, _byte = *(__i + (_buffer) -> buffer)) 

/**
 * 环形缓冲区
 * [start, end)，指向缓冲区的有效数据
 */
struct Buffer {
    uint8_t* buffer;
    uint8_t* __aligned_ptr;
    uint32_t start;
    uint32_t end;
    uint32_t size;

    bool is_dynamic;
};

/**
 * 初始化环形缓冲区
 * @param buf 缓冲区指针
 * @param data 缓冲区数据
 * @param size 缓冲区大小
 */
static inline void buffer_init(struct Buffer** buf, uint8_t* data, uint32_t size) {
    struct Buffer* buffer = *buf = (struct Buffer*)malloc(sizeof(struct Buffer));
    if(!buffer) return;

    if(data)
        buffer -> buffer = data, buffer -> is_dynamic = false;
    else    // Note: 多分配1字节，用于循环缓冲区
        buffer -> buffer = (uint8_t*)malloc(size +1), buffer -> is_dynamic = true, size += 1;
    buffer -> start = 0;
    buffer -> end = 0;
    buffer -> size = size;
    buffer -> __aligned_ptr = NULL;
}

/**
 * 初始化环形缓冲区，不分配内存
 * @param buffer 缓冲区指针
 * @param data 缓冲区数据
 * @param size 缓冲区大小
 */
static inline void buffer_init2(struct Buffer* buffer, uint8_t* data, uint32_t size){
    if(data)
        buffer -> buffer = data, buffer -> is_dynamic = false;
    else
        buffer -> buffer = (uint8_t*)malloc(size), buffer -> is_dynamic = true;
    buffer -> start = 0;
    buffer -> end = 0;
    buffer -> size = size;
    buffer -> __aligned_ptr = NULL;
}

/**
 * 释放环形缓冲区
 * @param buffer 缓冲区指针
 */
static inline void buffer_free(struct Buffer* buffer) {
    if(buffer -> __aligned_ptr) free(buffer -> __aligned_ptr);
    if(buffer -> is_dynamic) free(buffer -> buffer);
}

/**
 * 计算缓冲区已用空间
 * @param buffer 缓冲区指针
 * @return 已用空间大小
 */
static inline uint32_t buffer_used(struct Buffer* buffer) {
    if (buffer -> size == 0) return 0;
    return (buffer -> end - buffer -> start + buffer -> size) % buffer -> size;
}

/**
 * 调整缓冲区指针位置
 * @param buffer 缓冲区指针
 * @param pos 指针位置
 * @return 是否调整成功
 */
static inline bool buffer_seek(struct Buffer* buffer, uint32_t pos) {
    if (buffer -> size == 0 && pos != 0) return false;
    
    // uint32_t used = buffer_used(buffer);
    buffer -> start = pos % buffer -> size;
    // buffer -> end = (buffer -> start + used) % buffer -> size;
    
    return true;
}

static inline bool buffer_seek_cur(struct Buffer* this, int32_t offset){
    uint32_t pos = offset + this -> start;
    return buffer_seek(this, pos);
}

/**
 * 计算缓冲区剩余可用空间
 * @param buffer 缓冲区指针
 * @return 剩余可用空间大小
 */
static inline uint32_t buffer_available(struct Buffer* buffer) {
    if (buffer -> size == 0) return 0;
    return (buffer -> size - 1) - buffer_used(buffer);
}

/**
 * 检查缓冲区是否为空
 * @param buffer 缓冲区指针
 * @return 是否为空
 */
static inline bool buffer_is_empty(struct Buffer* buffer) {
    return buffer -> start == buffer -> end;
}

/**
 * 检查缓冲区是否已满
 * @param buffer 缓冲区指针
 * @return 是否已满
 */
static inline bool buffer_is_full(struct Buffer* buffer) {
    if (buffer -> size == 0) return true;
    return (buffer -> end + 1) % buffer -> size == buffer -> start;
}

/**
 * 向缓冲区写入数据
 * @param buffer 缓冲区指针
 * @param data 写入数据指针
 * @param length 写入数据长度
 * @return 实际写入数据长度
 */
static inline uint32_t buffer_push(struct Buffer* buffer, 
                                 const uint8_t* data, 
                                 uint32_t length) {
    if (!data || length == 0 || buffer -> size == 0) return 0;

    uint32_t available = buffer_available(buffer);
    uint32_t can_write = MIN(length, available);
    uint32_t write_pos = buffer -> end % buffer -> size;

    // 分两段写入
    uint32_t first_chunk = MIN(buffer -> size - write_pos, can_write);
    memcpy(buffer -> buffer + write_pos, data, first_chunk);
    
    if (can_write > first_chunk) {
        memcpy(buffer -> buffer, data + first_chunk, can_write - first_chunk);
    }
    
    buffer -> end = (buffer -> end + can_write) % buffer -> size;
    return can_write;
}


/**
 * 从缓冲区读取数据
 * @param buffer 缓冲区指针
 * @param dest 读取数据指针
 * @param length 读取数据长度
 * @return 实际读取数据长度
 */
static inline uint32_t buffer_pop(struct Buffer* buffer,
                                uint8_t* dest,
                                uint32_t length) {
    if (!dest || length == 0) return 0;

    uint32_t used = buffer_used(buffer);
    uint32_t can_read = MIN(length, used);
    uint32_t read_pos = buffer -> start % buffer -> size;

    // 分两段读取
    uint32_t first_chunk = MIN(buffer -> size - read_pos, can_read);
    memcpy(dest, buffer -> buffer + read_pos, first_chunk);
    
    if (can_read > first_chunk) {
        memcpy(dest + first_chunk, buffer -> buffer, can_read - first_chunk);
    }
    
    buffer -> start = (buffer -> start + can_read) % buffer -> size;
    return can_read;
}

/**
 * 清空缓冲区数据
 * @param buffer 缓冲区指针
 */
static inline void buffer_clear(struct Buffer* buffer) {
    buffer -> start = 0;
    buffer -> end = 0;
}

/**
 * 从文件描述符读取数据到缓冲区
 * @param buffer 缓冲区指针
 * @param fd 文件描述符
 * @param max_size 最大读取数据长度
 * @return 实际读取数据长度
 */
static inline ssize_t buffer_read(struct Buffer* buffer, int fd, uint32_t max_size) {
    uint32_t avail = MIN(buffer_available(buffer), max_size);

    uint32_t write_pos = buffer -> end % buffer -> size;
    uint32_t first_chunk = MIN(buffer -> size - write_pos, avail);
    if(first_chunk == 0) return 0;
    
    // 分两段直接读取
    ssize_t n = read(fd, buffer -> buffer + write_pos, first_chunk);
    if (n <= 0) return n > 0 ? n : -1;

    ssize_t total = n;
    if ((uint32_t)n == first_chunk && avail > first_chunk) {
        ssize_t n2 = read(fd, buffer -> buffer, avail - first_chunk);
        if (n2 > 0) total += n2;
    }

    buffer -> end = (buffer -> end + total) % buffer -> size;
    return total;
}

/**
 * 调整缓冲区大小
 * @param buffer 缓冲区指针
 * @param new_size 新缓冲区大小
 * @return 是否调整成功
 */
static inline bool buffer_realloc(struct Buffer* buffer, uint32_t new_size, bool force) {
    if (!force && (
        !buffer -> is_dynamic || new_size <= buffer -> size
        || new_size < buffer_used(buffer)
    )) return false;

    uint8_t* new_buf = (uint8_t*)malloc(new_size);
    if (!new_buf) return false;

    // 保存旧指针
    uint8_t* old_buf = buffer -> buffer;

    // 安全复制数据
    uint32_t used = buffer_used(buffer);
    uint32_t safe_used = MIN(used, new_size - 1);
    uint32_t first_chunk = MIN(buffer -> size - buffer -> start, safe_used);
    
    memcpy(new_buf, old_buf + buffer -> start, first_chunk);
    if (safe_used > first_chunk) {
        memcpy(new_buf + first_chunk, old_buf, safe_used - first_chunk);
    }

    // 原子化更新缓冲区状态
    buffer -> buffer = new_buf;
    buffer -> start = 0;
    buffer -> end = safe_used;
    buffer -> size = new_size;

    // 最后释放旧内存
    free(old_buf);
    return true;
}

/**
 * 导出全部缓冲区数据，然后清空源Buffer
 * @param buffer 缓冲区指针
 * @param size 导出数据大小
 * @return 导出数据指针
 */
static inline uint8_t* buffer_export(struct Buffer* buffer, uint32_t* size) {
    uint32_t used = buffer_used(buffer);
    *size = used;
    if (used == 0) return NULL;

    const uint32_t start_pos = buffer -> start % buffer -> size; 
    const uint32_t first_chunk = MIN(buffer -> size - start_pos, used); // 增加保护
    
    uint8_t* copy = malloc(used);
    memcpy(copy, buffer -> buffer + start_pos, first_chunk);
    if (used > first_chunk) {
        memcpy(copy + first_chunk, buffer -> buffer, used - first_chunk);
    }

    buffer -> start = 0;
    buffer -> end = used; 
    return copy;
}

/**
 * 将缓冲区数据拷贝到指定位置，不修改原Buffer位置
 * 如果你希望取出数据，请使用buffer_pop或自带内存分配的buffer_export
 * @param buffer 缓冲区指针
 * @param dest 目标指针
 * @param dest_size 目标大小
 * @return 实际拷贝数据长度
 */
static inline uint32_t buffer_copyto(struct Buffer* buffer, 
                                   uint8_t* dest, 
                                   uint32_t dest_size) {
    if (!buffer || !dest || dest_size == 0) return 0;

    uint32_t used = buffer_used(buffer);
    if (used == 0) return 0;

    uint32_t can_copy = MIN(used, dest_size);
    uint32_t read_pos = buffer -> start % buffer -> size;

    // 分两段拷贝
    uint32_t first_chunk = MIN(buffer -> size - read_pos, can_copy);
    memcpy(dest, buffer -> buffer + read_pos, first_chunk);
    
    if (can_copy > first_chunk) {
        memcpy(dest + first_chunk, buffer -> buffer, can_copy - first_chunk);
    }

    return can_copy;
}

/**
 * 导出缓冲区子集数据副本
 * @param buffer 缓冲区指针
 * @param start 子集起始位置
 * @param end 子集结束位置
 * @param size 导出数据大小
 * @return 导出数据指针
 */
static inline uint8_t* buffer_sub_export(struct Buffer* buffer, 
                                       uint32_t start,
                                       uint32_t end,
                                       uint32_t* size) {
    if (!buffer || start >= end || !size) {
        if (size) *size = 0;
        return NULL;
    }

    // 计算实际数据长度
    uint32_t data_len = (buffer -> start + end) % buffer -> size >= (buffer -> start + start) % buffer -> size
                      ? ((buffer -> start + end) % buffer -> size - (buffer -> start + start) % buffer -> size)
                      : (buffer -> size - (buffer -> start + start) % buffer -> size + (buffer -> start + end) % buffer -> size);
    
    uint8_t* out = (uint8_t*)malloc(data_len);
    if (!out) {
        if(size) *size = 0;
        return NULL;
    }

    uint32_t read_start = (buffer -> start + start) % buffer -> size;
    uint32_t read_end = (buffer -> start + end) % buffer -> size;

    if (read_start <= read_end) {
        memcpy(out, buffer -> buffer + read_start, data_len);
    } else {
        uint32_t first_part = buffer -> size - read_start;
        memcpy(out, buffer -> buffer + read_start, first_part);
        memcpy(out + first_part, buffer -> buffer, read_end);
    }

    if(size) *size = data_len;
    return out;
}

/**
 * 将缓冲区数据写入文件描述符
 * @param buffer 缓冲区指针
 * @param fd 文件描述符
 * @param max_size 最大写入数据长度
 * @return 实际写入数据长度
 */
static inline ssize_t buffer_write(struct Buffer* buffer, int fd, uint32_t max_size) {
    uint32_t used = buffer_used(buffer);
    if (used == 0 || max_size == 0) return 0;

    uint32_t can_write = MIN(used, max_size);
    uint32_t read_pos = buffer -> start % buffer -> size;

    // 分两段写入
    uint32_t first_chunk = MIN(buffer -> size - read_pos, can_write);
    ssize_t total = write(fd, buffer -> buffer + read_pos, first_chunk);
    if (total < 0) return -1; else if(total == 0) goto end;

#ifdef LJS_DEBUG
    printf("buffer_write: %ld, %d, %d, %d\n", total, first_chunk, can_write, used);
#endif

    if (can_write > first_chunk) {
        ssize_t n2 = write(fd, buffer -> buffer, can_write - first_chunk);
        if (n2 > 0) total += n2;
    }

end:
    if(total == used) buffer -> start = buffer -> end = 0;
    else buffer -> start = (buffer -> start + total) % buffer -> size;
    return total;
}

/**
 * 调整缓冲区使得缓冲区中数据连续
 * @param buffer 缓冲区指针
 * @return 是否调整成功
 */
static inline bool buffer_flat(struct Buffer* buffer) {
    if (!buffer -> is_dynamic) return false;
    uint32_t used = buffer_used(buffer);
    if (used == 0 || buffer_is_empty(buffer)) {
        buffer -> start = 0;
        buffer -> end = 0;
        return true;
    }

    uint8_t* new_buf = (uint8_t*)malloc(buffer -> size);
    if (!new_buf) return false;

    // 计算实际需要拷贝的数据长度
    uint32_t first_chunk = buffer -> size - buffer -> start;
    first_chunk = (first_chunk > used) ? used : first_chunk;

    memcpy(new_buf, buffer -> buffer + buffer -> start, first_chunk);
    if (used > first_chunk) {
        memcpy(new_buf + first_chunk, buffer -> buffer, used - first_chunk);
    }

    free(buffer -> buffer);
    buffer -> buffer = new_buf;
    buffer -> start = 0;
    buffer -> end = used;
    return true;
}

/**
 * 只在需要展开时展开
 */
static inline bool buffer_flat2(struct Buffer* buffer){
    if( buffer -> end > buffer -> start) return buffer_flat(buffer);
    return true;
}

static inline bool buffer_offset(struct Buffer* buffer, uint32_t offset, bool force) {
    // 展开缓冲区确保数据连续
    buffer_flat(buffer);
    
    uint32_t used = buffer_used(buffer);
    
    // 检查偏移量有效性
    if (offset > used) return false;
    
    // 强制模式或需要扩容
    if (!force && (buffer -> size < used - offset)) {
        if (!buffer_realloc(buffer, used - offset, false)) {
            return false;
        }
    }

    // 移动数据并更新指针
    memmove(buffer -> buffer, buffer -> buffer + offset, used - offset);
    buffer -> start = 0;
    buffer -> end = used - offset;
    return true;
}

// static inline void* aligned_malloc(size_t size, int alignment, void** raw) {
//     const int pointerSize = sizeof(void*);
//     const int requestedSize = size + alignment - 1 + pointerSize;
//     *raw = malloc(requestedSize);
//     if(!*raw) abort();
//     uintt start = (uintptr_t)(*raw) + pointerSize;
//     void* aligned = (void*)((start + alignment - 1) & ~(alignment - 1));
//     *(void**)((uintptr_t)aligned - pointerSize) = *raw;
//     return aligned;
// }

/**
 * 调整缓冲区内存对齐
 * @param buffer 缓冲区指针
 * @return 是否调整成功
 */
static inline void buffer_aligned(struct Buffer* buffer, size_t blk_size) {
    if (!buffer || blk_size == 0) return;

    if (buffer -> size == 0 || (buffer -> size & (blk_size -1)) || (((uintptr_t)buffer -> buffer) & (blk_size - 1))) {
        size_t alloc_size = ((buffer -> size + blk_size - 1) & ~(blk_size - 1)) +1;
        void* raw_ptr = buffer -> buffer;
        // warn: 缓冲区需要预留1字节
        if(0 != posix_memalign((void**)&buffer -> buffer, blk_size, alloc_size))
            return;

#ifdef LJS_DEBUG
        if(((uintptr_t)buffer -> buffer) & (blk_size - 1))
            abort();
#endif

        size_t copy_size = MIN(buffer -> size, alloc_size);
        memcpy(buffer -> buffer, raw_ptr, copy_size);

        buffer -> is_dynamic = true;
        buffer -> size = alloc_size;
        if(!buffer -> is_dynamic) free(raw_ptr);
        else buffer -> __aligned_ptr = raw_ptr;

#ifdef LJS_DEBUG
        printf("buffer_aligned: %p, %d, %d, %d\n", buffer -> buffer, buffer -> size -1, buffer -> start, buffer -> end);
#endif
    }
}

static inline bool buffer_merge(struct Buffer* dest, struct Buffer* src) {
    if (!dest || !src || dest == src) return false;

    // 计算实际需要写入的数据量
    const uint32_t src_used = buffer_used(src);
    const uint32_t dest_used = buffer_used(dest);
    const uint32_t required = dest_used + src_used;

    // 动态扩容检查
    if (dest -> size < required) {
        if (!dest -> is_dynamic) return false;
        if (!buffer_realloc(dest, required, false)) return false; // 保持环形结构
    }

    // 分两段拷贝（处理环形跨越的情况）
    uint32_t contiguous_space = dest -> size - dest -> end;
    if (src_used <= contiguous_space) {
        // 单次拷贝即可
        memcpy(dest -> buffer + dest -> end, 
               src -> buffer + src -> start, 
               src_used);
    } else {
        // 第一次拷贝：填充尾部剩余空间
        memcpy(dest -> buffer + dest -> end,
               src -> buffer + src -> start,
               contiguous_space);
        
        // 第二次拷贝：从头部继续
        memcpy(dest -> buffer,
               src -> buffer + src -> start + contiguous_space,
               src_used - contiguous_space);
    }

    // 更新环形索引（自动处理回绕）
    dest -> end = (dest -> end + src_used) % dest -> size;
    
    // 清空源缓冲区（但不释放内存）
    src -> start = src -> end = 0;
    return true;
}

static inline uint32_t buffer_merge2(struct Buffer* dest, struct Buffer* src) {
    if (!dest || !src || dest == src) return 0;

    const uint32_t src_used = buffer_used(src);
    const uint32_t dest_free = buffer_available(dest);
    
    // 计算实际可写入量
    const uint32_t write_len = (src_used < dest_free) ? src_used : dest_free;
    if (write_len == 0) return 0;

    // 分两段拷贝（处理环形跨越）
    uint32_t contiguous_space = dest -> size - dest -> end;
    if (write_len <= contiguous_space) {
        memcpy(dest -> buffer + dest -> end, 
               src -> buffer + src -> start, 
               write_len);
    } else {
        // 第一次拷贝：填充尾部剩余空间
        memcpy(dest -> buffer + dest -> end,
               src -> buffer + src -> start,
               contiguous_space);
        
        // 第二次拷贝：从头部继续
        memcpy(dest -> buffer,
               src -> buffer + src -> start + contiguous_space,
               write_len - contiguous_space);
    }

    // 更新目标缓冲区索引
    dest -> end = (dest -> end + write_len) % dest -> size;
    
    // 更新源缓冲区已读取部分
    src -> start = (src -> start + write_len) % src -> size;
    
    return write_len;
}


static const char map[] = "0123456789ABCDEF";
static inline uint8_t u32tohex(uint32_t value, char* hex) {
    uint8_t len = 0;
    char buf[8];
    int8_t i = 7;
    do {
        buf[i--] = map[value & 0xf];    // big-endian
        len += 1;
    } while (value >>= 4);

    // copy
    while(i < 8) {
        *(hex ++) = buf[i++];
    }
    return len;
}