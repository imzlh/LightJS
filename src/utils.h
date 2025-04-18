#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// 环形缓冲区
struct Buffer {
    uint8_t* buffer;
    uint8_t* __aligned_ptr;
    uint32_t start;
    uint32_t end;
    uint32_t size;

    bool is_dynamic;
};

// 初始化环形缓冲区
static inline void buffer_init(struct Buffer** buf, uint8_t* data, uint32_t size) {
    struct Buffer* buffer = *buf = (struct Buffer*)malloc(sizeof(struct Buffer));

    if(data)
        buffer->buffer = data;
    else
        buffer->buffer = (uint8_t*)malloc(size), buffer->is_dynamic = true;
    buffer->start = 0;
    buffer->end = 0;
    buffer->size = size;
    buffer->__aligned_ptr = NULL;
}

// 释放环形缓冲区
static inline void buffer_free(struct Buffer* buffer) {
    if(buffer->is_dynamic){
        if(buffer->__aligned_ptr) free(buffer->__aligned_ptr);
        else free(buffer->buffer);
    }
    free(buffer);
}

// 缓冲区指针位置
static inline uint32_t buffer_tell(struct Buffer* buffer) {
    if(buffer -> size == 0) return 0;
    return buffer->end % buffer->size;
}

// 调整缓冲区指针位置 注意：pos需要自行判断是否越界
static inline bool buffer_seek(struct Buffer* buffer, uint32_t pos) {
    if(buffer -> size == 0 && pos != 0) return false;
    buffer -> start = (buffer->start + pos) % buffer->size;
    return true;
}

// 计算已用空间
static inline uint32_t buffer_used(struct Buffer* buffer) {
    if(buffer -> size == 0) return 0;
    return (buffer->end - buffer->start + buffer->size) % buffer->size;
}

// 计算剩余可用空间
static inline uint32_t buffer_available(struct Buffer* buffer) {
    if(buffer -> size == 0) return 0;
    return buffer->size - buffer_used(buffer) - 1; // 保留一个分隔位
}

// 检查缓冲区是否为空
static inline bool buffer_is_empty(struct Buffer* buffer) {
    return buffer->start == buffer->end || buffer->size == 0;
}

// 检查缓冲区是否已满
static inline bool buffer_is_full(struct Buffer* buffer) {
    if(buffer -> size == 0) return true;
    return (buffer->end + 1) % buffer->size == buffer->start;
}

// 向缓冲区写入数据
static inline uint32_t buffer_push(struct Buffer* buffer, 
                                 const uint8_t* data, 
                                 uint32_t length) {
    if (!data || length == 0) return 0;

    uint32_t available = buffer_available(buffer);
    uint32_t write_pos = buffer->end % buffer->size;
    uint32_t can_write = MIN(length, available);

    // 分两段写入
    uint32_t first_chunk = MIN(buffer->size - write_pos, can_write);
    memcpy(buffer->buffer + write_pos, data, first_chunk);
    
    if (can_write > first_chunk) {
        memcpy(buffer->buffer, data + first_chunk, can_write - first_chunk);
    }
    
    buffer->end += can_write;
    return can_write;
}

// 从缓冲区读取数据
static inline uint32_t buffer_pop(struct Buffer* buffer,
                                uint8_t* dest,
                                uint32_t length) {
    if (!dest || length == 0) return 0;

    uint32_t used = buffer_used(buffer);
    uint32_t can_read = MIN(length, used);
    uint32_t read_pos = buffer->start % buffer->size;

    // 分两段读取
    uint32_t first_chunk = MIN(buffer->size - read_pos, can_read);
    memcpy(dest, buffer->buffer + read_pos, first_chunk);
    
    if (can_read > first_chunk) {
        memcpy(dest + first_chunk, buffer->buffer, can_read - first_chunk);
    }
    
    buffer->start += can_read;
    return can_read;
}

// 清空缓冲区
static inline void buffer_clear(struct Buffer* buffer) {
    buffer->start = 0;
    buffer->end = 0;
}

// 从文件描述符读取数据到缓冲区
static inline ssize_t buffer_read(struct Buffer* buffer, int fd, uint32_t max_size) {
    uint32_t avail = MIN(buffer_available(buffer), max_size);
    if (avail == 0) return 0;

    uint32_t write_pos = buffer->end % buffer->size;
    uint32_t first_chunk = MIN(buffer->size - write_pos, avail);
    
    // 分两段直接读取
    ssize_t n = read(fd, buffer->buffer + write_pos, first_chunk);
    if (n <= 0) return n > 0 ? n : -1;

    ssize_t total = n;
    if ((uint32_t)n == first_chunk && (avail > first_chunk)) {
        ssize_t n2 = read(fd, buffer->buffer, avail - first_chunk);
        if (n2 > 0) total += n2;
    }

    buffer->end += total;
    return total;
}

// 重新分配缓冲区大小（保持现有数据）
static inline bool buffer_realloc(struct Buffer* buffer, uint32_t new_size) {
    if (!buffer->is_dynamic || new_size <= buffer->size) return false;

    uint8_t* new_buf = (uint8_t*)malloc(new_size);
    if (!new_buf) return false;

    // 复制现有数据到新缓冲区
    uint32_t used = buffer_used(buffer);
    uint32_t first_chunk = MIN(buffer->size - (buffer->start % buffer->size), used);
    memcpy(new_buf, buffer->buffer + (buffer->start % buffer->size), first_chunk);
    
    if (used > first_chunk) {
        memcpy(new_buf + first_chunk, buffer->buffer, used - first_chunk);
    }

    // 更新缓冲区信息
    free(buffer->buffer);
    buffer->buffer = new_buf;
    buffer->start = 0;
    buffer->end = used;
    buffer->size = new_size;
    return true;
}

// 导出缓冲区数据（需要自行释放非连续数据）
static inline uint8_t* buffer_export(struct Buffer* buffer, uint32_t* size) {
    uint32_t used = buffer_used(buffer);
    *size = used;
    if (used == 0) return NULL;

    const uint32_t start_pos = buffer->start % buffer->size;
    bool loop = start_pos + used <= buffer->size;
    
    uint8_t* copy = (uint8_t*)malloc(used);
    if (!copy) {
        *size = 0;
        return NULL;
    }
    
    const uint32_t first_chunk = buffer->size - start_pos;
    memcpy(copy, buffer->buffer + start_pos, first_chunk);
    if(loop) memcpy(copy + first_chunk, buffer->buffer, used - first_chunk);

    // 更新缓冲区信息
    buffer->start = 0;
    buffer->end = used;
    buffer->size = used;
    
    return copy;
}

/**
 * 将环形缓冲区数据拷贝到指定缓冲区
 * @param buffer 源环形缓冲区
 * @param dest 目标缓冲区
 * @param dest_size 目标缓冲区大小
 * @return 实际拷贝的字节数
 */
static inline uint32_t buffer_copyto(struct Buffer* buffer, 
                                   uint8_t* dest, 
                                   uint32_t dest_size) {
    if (!buffer || !dest || dest_size == 0) return 0;

    uint32_t used = buffer_used(buffer);
    if (used == 0) return 0;

    uint32_t can_copy = MIN(used, dest_size);
    uint32_t read_pos = buffer->start % buffer->size;

    // 分两段拷贝
    uint32_t first_chunk = MIN(buffer->size - read_pos, can_copy);
    memcpy(dest, buffer->buffer + read_pos, first_chunk);
    
    if (can_copy > first_chunk) {
        memcpy(dest + first_chunk, buffer->buffer, can_copy - first_chunk);
    }

    return can_copy;
}

// 导出指定范围的数据副本 [start, end)
static inline uint8_t* buffer_sub_export(struct Buffer* buffer, 
                                       uint32_t start,
                                       uint32_t end,
                                       uint32_t* size) {
                                        
    if (!buffer || start >= end || !size) {
        if (size) *size = 0;
        return NULL;
    }

    // 转换为物理位置
    uint32_t phys_start = start % buffer->size;
    uint32_t phys_end = end % buffer->size;
    
    // 计算实际数据长度
    uint32_t data_len = (phys_start <= phys_end) ? 
                      (phys_end - phys_start) : 
                      (buffer->size - phys_start + phys_end);
    
    uint8_t* out = (uint8_t*)malloc(data_len);
    if (!out) {
        if(size) *size = 0;
        return NULL;
    }

    if (phys_start <= phys_end) {
        memcpy(out, buffer->buffer + phys_start, data_len);
    } else {
        uint32_t first_part = buffer->size - phys_start;
        memcpy(out, buffer->buffer + phys_start, first_part);
        memcpy(out + first_part, buffer->buffer, phys_end);
    }

    if(size) *size = data_len;
    return out;
}

// 将缓冲区数据写入文件描述符
static inline ssize_t buffer_write(struct Buffer* buffer, int fd, uint32_t max_size) {
    uint32_t used = buffer_used(buffer);
    if (used == 0 || max_size == 0) return 0;

    uint32_t can_write = MIN(used, max_size);
    uint32_t read_pos = buffer->start % buffer->size;

    // 分两段写入
    uint32_t first_chunk = MIN(buffer->size - read_pos, can_write);
    ssize_t n = write(fd, buffer->buffer + read_pos, first_chunk);
    if (n <= 0) return n > 0 ? n : -1;

    ssize_t total = n;
    if ((uint32_t)n == first_chunk && (can_write > first_chunk)) {
        ssize_t n2 = write(fd, buffer->buffer, can_write - first_chunk);
        if (n2 > 0) total += n2;
    }

    buffer->start += total;
    return total;
}

// 扩展缓冲区为连续存储结构
static inline bool buffer_expand(struct Buffer* buffer) {
    if (!buffer->is_dynamic) return false;

    uint32_t used = buffer_used(buffer);
    if (used == 0 || (buffer->start == 0 && used == buffer->size)) {
        // 已经是连续状态或完全填满状态
        return true;
    }

    uint8_t* new_buf = (uint8_t*)malloc(buffer->size);
    if (!new_buf) return false;

    // 将数据整理到新缓冲区的起始位置
    uint32_t first_chunk = buffer->size - (buffer->start % buffer->size);
    first_chunk = MIN(first_chunk, used);
    
    memcpy(new_buf, buffer->buffer + (buffer->start % buffer->size), first_chunk);
    if (used > first_chunk) {
        memcpy(new_buf + first_chunk, buffer->buffer, used - first_chunk);
    }

    free(buffer->buffer);
    buffer->buffer = new_buf;
    buffer->start = 0;
    buffer->end = used;
    return true;
}

static inline void* aligned_malloc(size_t size, int alignment, void** raw) {
    const int pointerSize = sizeof(void*);
    const int requestedSize = size + alignment - 1 + pointerSize;
    *raw = malloc(requestedSize);
    if(!raw) abort();
    uintptr_t start = (uintptr_t)raw + pointerSize;
    void* aligned = (void*)((start + alignment - 1) & ~(alignment - 1));
    *(void**)((uintptr_t)aligned - pointerSize) = raw;
    return aligned;
}

// static inline bool buffer_aligned(struct Buffer* buffer, size_t blk_size) {
//     if (!buffer) return false;
    
//     size_t alloc = (buffer->size + blk_size - 1) & ~(blk_size - 1);
//     uint8_t* old = buffer->buffer;
    
//     uint8_t* raw_ptr;
//     uint8_t* new_buf = posix_memalign(alloc, blk_size, (void**)&raw_ptr);
//     if (!new_buf) return false;
    
//     // 确保不会拷贝超过新旧缓冲区中较小的那个大小
//     size_t copy_size = MIN(buffer->size, alloc);
//     if (old) {
//         memcpy(new_buf, old, copy_size);
//         free(old);
//     }
    
//     buffer->buffer = new_buf;
//     buffer->is_dynamic = true;
//     buffer->size = alloc;
//     buffer->__aligned_ptr = raw_ptr;
//     return true;
// }

static inline void buffer_aligned(struct Buffer* buffer, size_t blk_size) {
    if (!buffer) return;
    uint8_t* raw_ptr = buffer->buffer;
    buffer->size = (buffer->size + blk_size - 1) & ~(blk_size - 1);
    posix_memalign((void**)&buffer->buffer, blk_size, buffer->size);
    if(raw_ptr){ 
        memcpy(buffer->buffer, raw_ptr, buffer->size);
        if(buffer->is_dynamic) free(raw_ptr);
    }
    buffer->is_dynamic = true;
    
}

static inline bool buffer_merge(struct Buffer* buffer, struct Buffer* other) {
    if (!buffer || !other) return false;
    size_t ot_size = buffer_used(other);
    size_t self_size = buffer_used(buffer);
    if(buffer_available(buffer) < ot_size){
        if(buffer -> is_dynamic) 
            buffer -> buffer = realloc(buffer -> buffer, self_size + ot_size);
        else
            return false;
    }

    buffer_expand(buffer);
    buffer_expand(other);
    memcpy(buffer -> buffer + buffer -> end, other -> buffer, ot_size);
    buffer -> end += ot_size;
    buffer_free(other);
    return true;
}