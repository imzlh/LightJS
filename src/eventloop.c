#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <threads.h>
#include <stdio.h>
#include <assert.h>
#include <linux/aio_abi.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "../engine/cutils.h"
#include "../engine/list.h"
#include "utils.h"
#include "core.h"

#ifdef LJS_MBEDTLS
#include <mbedtls/mbedtls_config.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>

#ifndef MBEDTLS_X509_CRT_PARSE_C
#error "The build of MbedTLS does not support X509 certificates."
#endif

#endif

enum EvFDType {
    EVFD_NORM,
    EVFD_UDP,
    EVFD_AIO,
    EVFD_INOTIFY,
    EVFD_TIMER,
    EVFD_SSL,
    EVFD_DTLS   // udp tls
};

enum EvTaskType {
    EV_TASK_READ,
    EV_TASK_WRITE,
    EV_TASK_CLOSE,
    EV_TASK_READLINE,
    EV_TASK_READONCE,
    EV_TASK_SYNC,
    EV_TASK_READ_DGRAM,
    EV_TASK_WRITE_DGRAM,
    EV_TASK_PIPETO,
    EV_TASK_NOOP    // for sync use, eg, wait for all tasks done
};

struct UDPContext {
    struct sockaddr_storage peer_addr;
    socklen_t addr_len;
#ifdef LJS_MBEDTLS
    mbedtls_ssl_context *dtls_ctx;
#endif
};

struct PipeToTask {
    int8_t ready_state;    // 2: from、to stream ok

    EvFD* from;
    EvFD* to;

    EvPipeToFilter filter;
    void* filter_opaque;
    EvPipeToNotify notify;
    void* notify_opaque;
};

struct Task {
    void* opaque;
    enum EvTaskType type;
    struct Buffer* buffer;
    union cb {
        EvReadCallback read;
        EvWriteCallback write;
        EvCloseCallback close;
        EvINotifyCallback inotify;
        EvTimerCallback timer;
        EvSyncCallback sync;
        struct PipeToTask* pipeto;
    } cb;

    struct list_head list;
    uint32_t aio_write_remain;
};

#ifdef LJS_MBEDTLS
struct EvFD_SSL {
    mbedtls_ssl_context ctx;
    mbedtls_ssl_config config;
    struct Buffer* sendbuf;
    struct Buffer* recvbuf;
    bool ssl_handshaking;
    bool ssl_read_wants_write;
    bool ssl_write_wants_read;
    EvSSLHandshakeCallback handshake_cb;
    void* handshake_user_data;
};
#endif

struct EvFD{
    union {
        aio_context_t ctx;
        uint64_t __padding;
    } aio;

    int fd[2];  // 如果是aio，第二个则是原始fd
    enum EvFDType type;
    struct list_head list;          // for task list
    struct UDPContext* proto_ctx;   // udp
#ifdef LJS_MBEDTLS
    struct EvFD_SSL* ssl;           // for ssl
#endif
    bool task_based;  // 是否是基于任务的，如果是，则需要处理任务队列
    union{
        struct{
            struct list_head read_tasks;
            struct list_head write_tasks;
            struct list_head close_tasks;
            uint32_t offset;    // for AIO
        } task;
        struct {
            EvReadCallback read;
            void* read_opaque;
            EvWriteCallback write;
            void* write_opaque;
            EvCloseCallback close;
            void* close_opaque;
        } cb;
    } u;
    
    struct Buffer* read_buffer;
    bool strip_if_is_n; // readline可能已经截获\r，下一次读取开头的\n需要忽略

    bool destroy;   // 代表已经关闭
    bool active;

    int epoll_flags;
};

struct TimerList{
    struct EvFD* evfd;
};

static thread_local int epoll_fd = -1;
static thread_local struct list_head timer_list;
static thread_local ssize_t evloop_events = 0;
static int is_aio_supported = -1;

// malloc
#define malloc(size) alloc_func(size, alloc_opaque);
static inline void* _malloc(size_t size, void* opaque) {
    void* ptr;
    if(posix_memalign(&ptr, 8, size) != 0) {
#ifdef LJS_DEBUG
        perror("posix_memalign");
#endif
        return NULL;
    }
    return ptr;
}
static thread_local void* (*alloc_func)(size_t size, void* opaque) = _malloc;
static thread_local void* alloc_opaque = NULL;
void LJS_evcore_set_memory(void* (*allocator)(size_t, void*), void* opaque){
    alloc_func = allocator;
    alloc_opaque = opaque;
}

#define INIT_EVFD(evfd) { \
    evfd -> read_buffer = NULL; \
    evfd -> destroy = false; \
    evfd -> active = true; \
    evfd->strip_if_is_n = false; \
}

// linux_kernel aio syscall
static inline int io_setup(unsigned nr, aio_context_t *ctxp) { 
    return syscall(__NR_io_setup, nr, ctxp); 
} 

static inline int io_destroy(aio_context_t ctx) { 
	return syscall(__NR_io_destroy, ctx); 
} 

static inline int io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp) { 
	return syscall(__NR_io_submit, ctx, nr, iocbpp); 
}

static inline int io_getevents(aio_context_t ctx, long min_nr, long max_nr, struct io_event *events, struct timespec *timeout) { 
	return syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
} 

static inline int io_cancel(aio_context_t ctx, struct iocb *iocb, struct io_event *result) { 
	return syscall(__NR_io_cancel, ctx, iocb, result); 
} 

static inline int aio_supported() {
    aio_context_t test_ctx;
    if(-1 == io_setup(MAX_EVENTS, &test_ctx)) return false;
    io_destroy(test_ctx);
    return true;
}

static void handle_close(int fd, void* _evfd);

// 内部辅助函数

// 在handle_read/handle_write中添加队列状态检查
static void check_queue_status(EvFD* evfd, int fd) {
    uint32_t new_events = EPOLLHUP | EPOLLET;
    if (    // aio中，任何一个队列有任务都需要EPOLLIN
        (evfd -> type != EVFD_AIO && !list_empty(&evfd -> u.task.read_tasks)) ||
        (evfd -> type == EVFD_AIO && (!list_empty(&evfd -> u.task.read_tasks) || !list_empty(&evfd -> u.task.write_tasks)))
    ) 
        new_events |= EPOLLIN;
    if (evfd -> type == EVFD_NORM && !list_empty(&evfd -> u.task.write_tasks)) 
        new_events |= EPOLLOUT;
        
    
    if (evfd -> epoll_flags != new_events) {
        evfd -> epoll_flags = new_events;

#ifdef LJS_DEBUG
        printf("epoll_ctl: fd=%d, events=%d, r=%d, w=%d\n", fd, new_events, new_events & EPOLLIN, new_events & EPOLLOUT);
#endif
        
        // 修改epoll事件
        struct epoll_event ev;
        ev.events = evfd -> epoll_flags = new_events;
        ev.data.ptr = evfd;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, evfd->fd[0], &ev) == -1) {
            perror("epoll_ctl");
        }
    }
}

// buffer
#define CALL_AND_HANDLE(func, blk, ...) int _ret = func(__VA_ARGS__); \
    if (evfd -> destroy) return; \
    if (!(_ret & EVCB_RET_REWIND)) blk; \
    if (_ret & EVCB_RET_CONTINUE) goto main;

#define EVFD_YIELD(evfd, type) { \
     struct epoll_event ev = { \
        .events = evfd -> epoll_flags = (evfd -> epoll_flags ^ type), \
        .data.ptr = evfd \
    }; \
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, evfd->fd[0], &ev); \
    return; \
}

// evtype: -2 done, -1 close, 0 read, 1 write
// 检查是否可以执行pipeto任务，或者操作pipeto任务
static inline bool pipeto_ctl(EvFD* evfd, struct PipeToTask* task, int evtype){
    if(task -> ready_state == -1) return false; // error

    // closed
    if(evtype < 0){
        if(evtype == -1){// error
            task -> notify(evfd, task -> to, EV_PIPETO_NOTIFY_CLOSED, task -> notify_opaque);
        }else{  // task done
            task -> notify(evfd, task -> to, EV_PIPETO_NOTIFY_DONE, task -> notify_opaque);
        }

        task -> ready_state = -1;
        goto cleanup;
    }

    if(task -> ready_state < 2) task -> ready_state ++;
    if(task -> ready_state < 2) return false; // not ready
    return true;

cleanup:
    // 注销to
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &task -> to -> u.task.write_tasks) {
        struct Task* t = list_entry(cur, struct Task, list);
        if(t -> cb.pipeto == task) {
            evloop_events --;
            list_del(cur);
            free(t);
            break;
        }
    }

    // 注销from
    list_for_each_safe(cur, tmp, &task -> from -> u.task.write_tasks) {
        struct Task* t = list_entry(cur, struct Task, list);
        if(t -> cb.pipeto == task) {
            evloop_events --;
            list_del(cur);
            free(t);
            break;
        }
    }

    free(task);
    return false;
}

// 事件处理函数
static void handle_read(int fd, EvFD* evfd, struct io_event* ioev, struct inotify_event* inev) {
    // get data
    uint32_t n = 0;
    if (evfd->type == EVFD_NORM) {
        uint8_t* ptr_buffer = evfd->read_buffer->buffer + evfd->read_buffer->start;
        n = buffer_read(evfd->read_buffer, fd, UINT32_MAX);
#ifdef LJS_DEBUG
        if (n == -1){ 
            perror("evfd_read");
            return handle_close(fd, evfd);
        }    // error
#endif
        if (n <= 0) return;

        // strip_if_is_n
        if (evfd->strip_if_is_n && *ptr_buffer == '\n') {
            evfd->read_buffer->start = (evfd->read_buffer->start) % evfd->read_buffer->size;
            if (n-- == 1) return;
        }
        evfd->strip_if_is_n = false;
    } else if (evfd->type == EVFD_AIO/* && iocb */) {
        n = ioev->res;
        evfd->u.task.offset += n;
        buffer_push(evfd->read_buffer, (uint8_t*) ((struct iocb*) ioev->obj)->aio_buf, n);
    } else if (evfd->type == EVFD_SSL) {
        // evfd SSL下，只有mbedtls处理后才有数据
        n = buffer_used(evfd->read_buffer);
    } else if (evfd->type == EVFD_UDP || evfd->type == EVFD_DTLS) {
        struct UDPContext* ctx = evfd->proto_ctx;
        n = recvfrom(fd, evfd->read_buffer->buffer,
            buffer_available(evfd->read_buffer), 0,
            (struct sockaddr*) &ctx->peer_addr,
            &ctx->addr_len);
        if (n == -1) {
            perror("recvfrom");
            // handle_close(fd, evfd);
            return;
        }
        else if (n == 0) return;
    }

    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &evfd->u.task.read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        evloop_events --;
        list_del(cur); // avoid recursive call

        // linux inotify文件更改事件
        if(evfd -> type == EVFD_INOTIFY){
            // 传递给回调
            task -> cb.inotify(inev, task -> opaque);
            continue;
        // timerfd 定时器事件
        }else if(evfd -> type == EVFD_TIMER){
            // 尝试读取timerfd
            uint64_t val;
            if(sizeof(val) == read(fd, &val, sizeof(val))){
                task -> cb.timer(val, task -> opaque);
            }else{
                perror("timerfd read");
            }
#ifdef LJS_DEBUG
            printf("timerfd resolved %ld\n", val);
#endif
            continue;
        }else if(task -> type == EV_TASK_PIPETO){
            // pipeto存活且未完成
            struct PipeToTask* pt = task -> cb.pipeto;
            if(!pipeto_ctl(evfd, pt, 0) && pt -> ready_state > 0)
                EVFD_YIELD(evfd, EPOLLIN);
        }else if(task -> type == EV_TASK_NOOP){
            task -> cb.sync(evfd, task -> opaque);
            continue;
        }

main:   // while loop
        uint32_t bufsize = buffer_used(evfd -> read_buffer);
        switch(task -> type){
            case EV_TASK_READ: // readsize
                if (task -> buffer -> size <= bufsize) {
                    // 导出
                    buffer_copyto(evfd -> read_buffer, task -> buffer -> buffer, task -> buffer -> size);
                    CALL_AND_HANDLE(
                        task -> cb.read,
                        { buffer_clear(evfd -> read_buffer); }, 
                        evfd, task -> buffer -> buffer, task -> buffer -> size, task -> opaque
                    );
                    goto _continue;
                } else if(!n) {
                    perror("evfd_readsize");
                    // handle_close(fd, evfd);
                    goto _break;
                }
                goto __break;

            case EV_TASK_READLINE:
                if (n <= 0) {
                    if (n == 0) evfd->destroy = true;
                    // handle_close(fd, evfd);
                    goto _break;
                }
                
                // 扫描换行符
                buffer_flat(evfd->read_buffer);
                uint32_t start = evfd->read_buffer->start;
                uint32_t end = start + evfd->read_buffer->end;
                uint8_t* p = start + evfd->read_buffer->buffer;
                uint32_t i2 = 0, i = 0;

                for (; i <= end; i ++, p++) {
                    if(i > evfd -> read_buffer -> size) p -= evfd -> read_buffer -> size;

                    if (*p == '\n') {
                        // CRLF换行符
                        if(i != 0 && *(p-1) == '\r') p -= 1;
                        *p = '\0';
                        
                        // 复制到用户buffer
                        uint32_t readed = buffer_copyto(evfd -> read_buffer, task -> buffer -> buffer, task -> buffer -> size);

                        // 触发回调
                        CALL_AND_HANDLE(
                            task -> cb.read,
                            { buffer_seek(evfd -> read_buffer, i - start + 1); },
                            evfd, task -> buffer -> buffer, readed, task -> opaque
                        );
                        goto _continue;
                    } else if(*p == '\r' && !i2){
                        i2 = i; // 记录\r位置，备用
                    }
                }

                // 检查\r
                if(i2){
                    if(i2 == i) evfd -> strip_if_is_n = true;

                    // 导出并出发回调
                    uint32_t readed = buffer_copyto(evfd -> read_buffer, task -> buffer -> buffer, task -> buffer -> size);
                    task -> buffer -> buffer[readed-1] = '\0';    // end with \0
                    CALL_AND_HANDLE(
                        task -> cb.read,
                        { buffer_seek(evfd -> read_buffer, i2 +1); },
                        evfd, task -> buffer -> buffer, readed, task -> opaque
                    );
                    
                    goto _continue;
                }
                
                // 缓冲区满但未找到换行符
                if (bufsize >= task -> buffer -> size) {
                    buffer_copyto(evfd -> read_buffer, task -> buffer -> buffer, task -> buffer -> size);
                    CALL_AND_HANDLE(
                        task -> cb.read,
                        { buffer_clear(evfd -> read_buffer); },
                        evfd, task -> buffer -> buffer, task -> buffer -> size, task -> opaque
                    )
                    goto _continue;
                }

                // 没有换行符
                goto __break;
        
            case EV_TASK_READONCE: // readonce
                // int available;
                // ioctl(fd, FIONREAD, &available);
                // available = available > task->total_size ? task->total_size : available;

                buffer_copyto(evfd -> read_buffer, task -> buffer -> buffer, task -> buffer -> size);
                CALL_AND_HANDLE(
                    task -> cb.read,
                    { buffer_clear(evfd -> read_buffer); },
                    evfd, task -> buffer -> buffer, task -> buffer -> size, task -> opaque
                )
                goto _continue;

            // 真正写入的部分在另一个pipe handle_write中
            case EV_TASK_PIPETO:
                // filter
                EvPipeToFilter filter = task -> cb.pipeto -> filter;
                if(filter && !filter(evfd -> read_buffer, task -> cb.pipeto -> filter_opaque)){
                    // done
                    struct PipeToTask* pt = task -> cb.pipeto;
                    pipeto_ctl(evfd, pt, -2);
                    goto _continue;
                }

                if(buffer_is_full(evfd -> read_buffer))
                    EVFD_YIELD(evfd, EPOLLOUT);
                goto __break;

            _continue:
                if(evfd -> destroy) return;   // task already destroyed
                buffer_free(task -> buffer);
                free(task);
                continue;

            __break:
                if(evfd -> destroy) return;
                list_add(&task->list, &evfd->u.task.write_tasks);
                evloop_events ++;

            _break:
                if(evfd -> destroy) return;   // task already destroyed
                free(task -> buffer);
                free(task);
                break;

            default:    // never reach here
                abort();
        }
    }

    check_queue_status(evfd, fd);
}

static inline int blksize_get(int fd){
    int blksize;
    if(ioctl(fd, BLKSSZGET, &blksize) != 0) return 512;
    return blksize;
}

#ifdef LJS_DEBUG
// debug: AIO buffer对齐检查
static bool check_aio_alignment(EvFD* evfd, struct Buffer* buf, off_t offset) {
    int blksize = blksize_get(evfd->fd[1]);
    
    if ((uintptr_t)buf->buffer % blksize != 0 || offset % blksize != 0)
        return false;
    
    buf->size = (buf->size / blksize) * blksize;
    return true;
}
#endif

static inline int submit_aio_read(EvFD* evfd, struct Task* task){
    if(!is_aio_supported) return -1;

    // buffer对齐
    buffer_aligned(task -> buffer, blksize_get(evfd->fd[1]));

    // 提交io事务
    struct iocb iocb = {
        .aio_fildes = evfd->fd[1],
        .aio_lio_opcode = IOCB_CMD_PREAD,
        .aio_buf = (unsigned long long)task -> buffer -> buffer,
        .aio_nbytes = task -> buffer -> size -1,
        .aio_offset = evfd -> u.task.offset,
        .aio_data = (uint64_t)task,
        .aio_flags = IOCB_FLAG_RESFD,
        .aio_resfd = evfd->fd[0],
    };
    int ret = io_submit(evfd -> aio.ctx, 1, (struct iocb*[1]){&iocb});
#ifdef LJS_DEBUG
    printf("submit_aio_read: fd=%d, size=%d, ret=%d\n", evfd->fd[1], task->buffer->size -1, ret);
    if(ret == -1) perror("io_submit");
#endif
    return ret;
}

// 注意这里的buffer不能circular
static inline int submit_aio_write(EvFD* evfd, struct Task* task) {
    if(!is_aio_supported) return -1;

    // buffer对齐，适配aio
    buffer_aligned(task -> buffer, blksize_get(evfd->fd[1]));
    task -> aio_write_remain = task -> buffer -> size;
    
    // 检查最终对齐有效性
#ifdef LJS_DEBUG
    if (!check_aio_alignment(evfd, task->buffer, task->buffer->start)) {
        printf("buffer not aligned, start=%d, size=%d\n", task->buffer->start, task->buffer->size);
        return -1;
    }
#endif

    struct iocb iocb = {
        .aio_fildes = evfd->fd[1],
        .aio_lio_opcode = IOCB_CMD_PWRITE,
        .aio_buf = (unsigned long long)task -> buffer -> buffer,
        .aio_nbytes = task -> buffer -> size -1,
        .aio_offset = evfd -> u.task.offset,
        .aio_data = (uint64_t)task,
        .aio_flags = IOCB_FLAG_RESFD,
        .aio_resfd = evfd->fd[0],
    };
    int ret = io_submit(evfd -> aio.ctx, 1, (struct iocb*[1]){&iocb});

#ifdef LJS_DEBUG
    printf("submit_aio_write: fd=%d, remain=%d, ret=%d\n", evfd->fd[1], task->aio_write_remain, ret);
    if(ret == -1) perror("io_submit");
#endif
    return ret;
}

static inline void free_task(struct Task* task) {
    buffer_free(task -> buffer);
    free(task);
}

static void handle_write(int fd, EvFD* evfd, struct io_event* ioev) {
    struct list_head *cur, *tmp;
    // 只考虑aio、fd write
    list_for_each_safe(cur, tmp, &evfd->u.task.write_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);

        if(evfd -> type == EVFD_AIO){
            task -> aio_write_remain -= ioev -> res;
            evfd -> u.task.offset += ioev -> res;
            // 完成！
            if(task -> aio_write_remain == 0){
                task -> cb.write(evfd, task -> opaque);

                evloop_events --;
                list_del(&task->list);
                free_task(task);
                
                // 添加io事务：下一个io
                if(!list_empty(&evfd->u.task.write_tasks)){
                    struct Task* next_task = list_entry(evfd->u.task.write_tasks.next, struct Task, list);
                    submit_aio_write(evfd, next_task);
                }
            }
            return;
        }else if(task -> type == EV_TASK_PIPETO){
            struct PipeToTask* pt = task -> cb.pipeto;
            
            // pipeto存活且未完成
            if(!pipeto_ctl(evfd, pt, 1) && task -> cb.pipeto -> ready_state > 0)
                EVFD_YIELD(evfd, EPOLLIN);

            // 写入
            ssize_t n = buffer_write(pt -> from -> read_buffer, fd, UINT32_MAX);
            if(n == -1){ 
                perror("evfd_write");
                return handle_close(fd, evfd);
            }
            if(!buffer_is_empty(pt -> from -> read_buffer)){
                // 暂停对端
                EVFD_YIELD(pt -> from, EPOLLIN);
            }
            return;
        }else if(task -> type == EV_TASK_NOOP){
            task -> cb.sync(evfd, task -> opaque);
            continue;
        }

        ssize_t n = buffer_write(task -> buffer, fd, UINT32_MAX);
        if (n > 0) {

#ifdef LJS_DEBUG
            printf("evfd_write: fd=%d, n=%ld, remain=%d\n", fd, n, buffer_used(task -> buffer));
#endif

            if(buffer_is_empty(task -> buffer)){
                // 全部写入
                if(task -> cb.write) task -> cb.write(evfd, task -> opaque);
                evloop_events --;
                list_del(&task->list);
                free_task(task);
            }
        } else if(n == -1){
            perror("evfd_write");
            return handle_close(fd, evfd);
        } else {
            break;  // fd is busy
        }
    }

    check_queue_status(evfd, fd);
}

// for a case: read(call close) -> write(SIGPIPE)
static thread_local EvFD* evfd_destroy[MAX_EVENTS];
static thread_local uint8_t evfdarr_count = 0;
static void clear_tasks(EvFD* evfd, bool call_close) {
    struct list_head* cur, * tmp;
    bool has_data = evfd->read_buffer && !buffer_is_empty(evfd->read_buffer);
    // read queue
    list_for_each_safe(cur, tmp, &evfd->u.task.read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        if (task->type == EV_TASK_PIPETO) pipeto_ctl(evfd, task->cb.pipeto, -1);
        if (task->cb.read) {
            if (has_data) {
                // copy to user buffer
                uint32_t readed = buffer_copyto(evfd->read_buffer, task->buffer->buffer, task->buffer->size);
                if (readed < task->buffer->size) task->buffer->buffer[readed] = '\0';    // end with \0
                task->cb.read(evfd, task->buffer->buffer, readed, task->opaque);

                has_data = false;
            } else {
                task->cb.read(evfd, NULL, 0, task->opaque);
            }
        }
        if (task->buffer) buffer_free(task->buffer);
        free(task);
        evloop_events--;
    }

    // write queue
    list_for_each_safe(cur, tmp, &evfd->u.task.write_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        if(task -> type == EV_TASK_PIPETO) pipeto_ctl(evfd, task -> cb.pipeto, -1);
        if(task -> cb.write) task -> cb.write(evfd, task -> opaque);
        if(task -> buffer) buffer_free(task -> buffer);
        free(task);
        evloop_events --;
    }

    // close queue
    if(call_close)
        list_for_each_safe(cur, tmp, &evfd->u.task.close_tasks) {
            struct Task* task = list_entry(cur, struct Task, list);
            task -> cb.close(evfd, task -> opaque);
            free(task);
            evloop_events --;
        }
}

static void handle_close(int fd, void* _evfd) {
    EvFD* evfd = (EvFD*)_evfd;
    if(evfd -> task_based) clear_tasks(evfd, true);

    // 关闭fd
    if(!evfd -> destroy) switch (evfd -> type){
        case EVFD_NORM:
        case EVFD_TIMER:
        case EVFD_INOTIFY:
            close(fd);
        break;

        case EVFD_AIO:
            close(evfd -> fd[0]);
            close(evfd -> fd[1]);   // eventfd
            io_destroy(evfd -> aio.ctx);
        break;

        case EVFD_SSL:
#ifdef LJS_MBEDTLS
            if (evfd->ssl) {
                buffer_free(evfd->ssl->sendbuf);
                buffer_free(evfd->ssl->recvbuf);
                mbedtls_ssl_free(&evfd->ssl->ctx);
                mbedtls_ssl_config_free(&evfd->ssl->config);
                free(evfd->ssl);
            }
#endif
        break;

        default:
            abort();
        break;
    }
    if(evfd -> read_buffer) buffer_free(evfd -> read_buffer);
    // free(evfd);
    evfd_destroy[evfdarr_count++] = evfd;
    evfd -> active = false;
    evfd -> destroy = true;

    // remove in epoll
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

static void handle_sync(EvFD* evfd){
    struct list_head *cur, *tmp;
    // read queue
    list_for_each_safe(cur, tmp, &evfd->u.task.read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        task -> cb.sync(evfd, task -> opaque);
        if(task -> type == EV_TASK_SYNC) {
            evloop_events --;
            list_del(&task->list);
            free(task);
        }
    }
}

#ifdef LJS_MBEDTLS
static int handle_ssl_send(void* ctx, const unsigned char* buf, size_t len) {
    EvFD* evfd = (EvFD*)ctx;
    struct Buffer* sendbuf = evfd->ssl->sendbuf;
    
    if (buffer_available(sendbuf) < len) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    
    if (buffer_push(sendbuf, buf, len) != len) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    
    return (int)len;
}

static int handle_ssl_recv(void* ctx, unsigned char* buf, size_t len) {
    EvFD* evfd = (EvFD*)ctx;
    size_t copied = buffer_copyto(evfd->ssl->recvbuf, buf, len);
    handle_read(evfd->fd[0], evfd, NULL, NULL);
    return copied;
}

static inline void update_ssl_events(EvFD* evfd) {
    uint32_t events = EPOLLET | EPOLLERR | EPOLLHUP;
    
    if (evfd->ssl->ssl_handshaking) {
        if (evfd->ssl->ssl_read_wants_write) {
            events |= EPOLLOUT;
        } else {
            events |= EPOLLIN;
        }
    } else {
        if (!buffer_is_empty(evfd->ssl->sendbuf)) {
            events |= EPOLLOUT;
        }
        if (buffer_available(evfd->ssl->recvbuf) > 0) {
            events |= EPOLLIN;
        }
    }
    
    evfd -> epoll_flags = events;
    struct epoll_event ev = { .events = events, .data.ptr = evfd };
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, evfd->fd[0], &ev);
}

static void ssl_handle_handshake(EvFD* evfd) {
    int ret;
    while ((ret = mbedtls_ssl_handshake(&evfd->ssl->ctx)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            evfd->ssl->ssl_read_wants_write = false;
            update_ssl_events(evfd);
            return; // 退出循环等待事件
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            evfd->ssl->ssl_write_wants_read = false;
            update_ssl_events(evfd);
            return;
        } else {
            // 处理致命错误
            LJS_evfd_close(evfd);
            return;
        }
    }
    
    // 握手成功
    evfd->ssl->ssl_handshaking = false;
    evfd->ssl->handshake_cb(evfd, evfd->ssl->handshake_user_data);
    update_ssl_events(evfd);
}

struct SSL_data {
    char *name;
    char* server_name; // optional
    mbedtls_x509_crt *cacert;
    mbedtls_pk_context *cakey;
    struct list_head link;
};

static struct list_head* certs = NULL;

int ssl_sni_callback(void *ssl, const unsigned char *name, size_t len) {
    if(certs == NULL) return -1;

    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, certs) {
        struct SSL_data *data = list_entry(cur, struct SSL_data, link);
        if (len == strlen(data->name) && memcmp(name, data->name, len) == 0) {
            if(data -> server_name)
                mbedtls_ssl_set_hostname(&((EvFD*)ssl)->ssl->ctx, data->name);
            return mbedtls_ssl_set_hs_own_cert(&((EvFD*)ssl)->ssl->ctx, data->cacert, data->cakey);
        }
    }
    return -1;
}

static int udp_packet_send(void *ctx, const unsigned char *buf, size_t len) {
    EvFD *evfd = (EvFD*)ctx;
    struct UDPContext *uctx = evfd->proto_ctx;
    
    // 获取UDP套接字fd（假设存放在fd[0]）
    int sockfd = evfd->fd[0];
    
    ssize_t sent = sendto(sockfd, buf, len, MSG_DONTWAIT,
                        (struct sockaddr*)&uctx->peer_addr, 
                        uctx->addr_len);
    
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    }
    return (int)sent;
}

static int udp_packet_recv(void *ctx, unsigned char *buf, size_t len) {
    EvFD *evfd = (EvFD*)ctx;
    struct UDPContext *uctx = evfd->proto_ctx;
    
    // 接收时自动填充对端地址
    socklen_t addr_len = sizeof(struct sockaddr_storage);
    int sockfd = evfd->fd[0];
    
    ssize_t recvd = recvfrom(sockfd, buf, len, MSG_DONTWAIT,
                           (struct sockaddr*)&uctx->peer_addr,
                           &addr_len);
    
    if (recvd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    }
    
    uctx->addr_len = addr_len; // 保存最新对端地址
    return (int)recvd;
}
#endif

// 公共接口实现
bool LJS_evcore_init() {
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        return false;
    }

    // aio?
    if(is_aio_supported == -1) is_aio_supported = is_aio_supported;

    // timerfd
    init_list_head(&timer_list);

    return true;
}

#define CHECK_TO_BE_CLOSE(fd) for(uint8_t __i = 0 ; __i < evfdarr_count ; __i ++)\
    if(evfd_destroy[__i] == fd) goto _continue;

bool LJS_evcore_run(bool (*evloop_abort_check)(void* user_data), void* user_data) {
    struct epoll_event events[MAX_EVENTS];
    while (1) {
        if ((evloop_abort_check ? evloop_abort_check(user_data) : true) && evloop_events <= 0){
#ifdef LJS_DEBUG
            printf("evloop_abort_check: abort, events=%ld\n", evloop_events);
#endif
            return true; // no events
        }

#ifdef LJS_DEBUG
        printf("epoll_wait: enter, events=%ld\n", evloop_events);
#endif

        // clear up evfd
        if(evfdarr_count){
            uint8_t count = evfdarr_count;
            for(uint8_t _i = 0 ; _i < count ; _i ++){
                free(evfd_destroy[_i]);
            }
            evfdarr_count = 0;
        }

        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
        }
        
        for (int i = 0; i < nfds; ++i) {
            struct EvFD* evfd = events[i].data.ptr;

            if(evfd -> task_based){
                if (events[i].events & (EPOLLERR | EPOLLHUP)){
                    handle_close(LJS_evfd_getfd(evfd, NULL), evfd);
                    continue;
                }

                CHECK_TO_BE_CLOSE(evfd);
                
                if (events[i].events & EPOLLIN) switch(evfd->type){
                    case EVFD_NORM:
                    case EVFD_TIMER:
                    case EVFD_UDP:
                    case EVFD_DTLS:
                        handle_read(evfd->fd[0], evfd, NULL, NULL);
                    break;

                    case EVFD_AIO:
                        struct io_event events[MAX_EVENTS];
                        struct timespec timeout = {0, 0};
                        int ret = io_getevents(evfd->aio.ctx, 1, MAX_EVENTS, events, &timeout);
                        if (ret < 0) {
                            perror("io_getevents");
                            break;
                        }
                        for (int j = 0; j < ret; ++j) {
                            struct iocb* iocb = (struct iocb*)(uintptr_t)events[j].obj;
                            if(iocb -> aio_lio_opcode == IOCB_CMD_PREAD)
                                handle_read(evfd->fd[0], evfd, &events[j], NULL);
                            else if(iocb -> aio_lio_opcode == IOCB_CMD_PWRITE)
                                handle_write(evfd->fd[0], evfd, &events[j]);
                            else if(iocb -> aio_lio_opcode == IOCB_CMD_FSYNC)
                                handle_sync(evfd);
                            else    // ?
                                handle_close(evfd->fd[0], evfd);
                        }
                    break;

                    case EVFD_INOTIFY:
                        struct inotify_event inev;
                        while (read(evfd->fd[0], &inev, sizeof(inev)) == sizeof(inev)) {
                            handle_read(evfd->fd[0], evfd, NULL, &inev);
                        }
                    break;

                    case EVFD_SSL:
#ifdef LJS_MBEDTLS
                        struct EvFD_SSL *ssl_evfd = evfd->ssl;
                        
                        while (1) {
                            uint8_t tmp[4096];
                            int ret = mbedtls_ssl_read(&ssl_evfd->ctx, tmp, sizeof(tmp));
                            
                            if (ret > 0) {
                                buffer_push(ssl_evfd->recvbuf, tmp, ret);
                                handle_read(evfd->fd[0], evfd, NULL, NULL); // 触发用户回调
                            } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                                break; // 等待下次事件
                            } else {
                                break;
                            }
                        }
                        update_ssl_events(evfd);
#endif
                    break;
                }

                CHECK_TO_BE_CLOSE(evfd);
                
                if (events[i].events & EPOLLOUT){
                    if(evfd -> type == EVFD_NORM){
                        handle_write(evfd -> fd[0], evfd, NULL);
                    }
#ifdef LJS_MBEDTLS
                    else if(evfd -> type == EVFD_SSL){
                        ssize_t n = buffer_write(evfd->ssl->sendbuf, evfd->fd[0], UINT32_MAX);
                            
                        if (n == -1 && errno != EAGAIN) {
                            handle_close(evfd->fd[0], evfd);
                            break;
                        }

                        update_ssl_events(evfd);
                    }
#endif
                }
            }else{
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    evfd -> u.cb.close(evfd, evfd -> u.cb.close_opaque);
                    evloop_events --;
                }

                CHECK_TO_BE_CLOSE(evfd);

                if (events[i].events & EPOLLIN) 
                    evfd -> u.cb.read(evfd, NULL, 0, evfd -> u.cb.read_opaque);
                
                CHECK_TO_BE_CLOSE(evfd);
                
                if (events[i].events & EPOLLOUT) 
                    evfd -> u.cb.write(evfd, evfd -> u.cb.write_opaque);
            }
_continue:      continue;
        }
    }

    close(epoll_fd);
    return true;
}

/**
 * 将fd附加到eventloop。
 */
// 将fd附加到事件循环
struct EvFD* LJS_evcore_attach(
    int fd, bool use_aio, 
    EvReadCallback rcb, void* read_opaque, 
    EvWriteCallback wcb, void* write_opaque, 
    EvCloseCallback ccb, void* close_opaque
) {
    // fd是否有效？
    if (fd < 0 || (fcntl(fd, F_GETFL, 0) == -1 && errno == EBADF)) {
        perror("fcntl");
        return NULL;
    }

    // O_DIRECT
    if(use_aio) fcntl(fd, F_SETFL, O_DIRECT | fcntl(fd, F_GETFL, 0));

    EvFD* evfd = malloc(sizeof(EvFD));
    if (!evfd) return NULL;
    INIT_EVFD(evfd);

    // 设置文件类型
    if (use_aio) {
        if (io_setup(MAX_EVENTS, &evfd->aio.ctx) < 0) {
            free(evfd);
            close(fd);
            return NULL;
        }
        evfd->type = EVFD_AIO;
        evfd->fd[0] = fd;  // 原始fd
        evfd->fd[1] = -1;  // aio使用虚拟fd
        evfd->u.task.offset = 0;
    } else {
        evfd->type = EVFD_NORM;
        evfd->fd[0] = fd;
    }

    // 注册到epoll
    uint32_t evflag = EPOLLET | EPOLLERR | EPOLLHUP;
    if (rcb) evflag |= EPOLLIN;
    if (wcb) evflag |= EPOLLOUT;
    struct epoll_event ev = {
        .events = evflag,
        .data.ptr = evfd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        perror("epoll_ctl");
        free(evfd);
        return NULL;
    }
    evloop_events ++;

    // 设置默认回调
    evfd -> task_based = false;
    evfd -> u.cb.read = rcb;
    evfd -> u.cb.write = wcb;
    evfd -> u.cb.close = ccb;
    evfd -> u.cb.read_opaque = read_opaque;
    evfd -> u.cb.write_opaque = write_opaque;
    evfd -> u.cb.close_opaque = close_opaque;

    return evfd;
}

// 分离事件监听
bool LJS_evcore_detach(int fd, uint8_t type) {
    struct epoll_event ev;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &ev) == -1) {
        perror("epoll_ctl del");
        return false;
    }
    return true;
}

// 创建新的evfd对象
EvFD* LJS_evfd_new(int fd, bool use_aio, bool readable, bool writeable, uint32_t bufsize,
                   EvCloseCallback close_callback, void* close_opaque) {
    EvFD* evfd = malloc(sizeof(EvFD));
    if (!evfd) return NULL;

    // 初始化任务队列
    init_list_head(&evfd->u.task.read_tasks);
    init_list_head(&evfd->u.task.write_tasks);
    init_list_head(&evfd->u.task.close_tasks);
    INIT_EVFD(evfd);

    // 初始化缓冲区
    if (bufsize > 0) {
        buffer_init(&evfd->read_buffer, NULL, bufsize);
    }

    // 设置基础参数
    evfd->task_based = true;
    evfd->fd[0] = fd;
    evfd->fd[1] = -1;
    evfd->type = EVFD_NORM;
    evfd->epoll_flags = EPOLLET | EPOLLERR | EPOLLHUP;
    if(readable) evfd -> epoll_flags |= EPOLLIN;
    if(writeable) evfd -> epoll_flags |= EPOLLOUT;
    if(readable) buffer_init(&evfd->read_buffer, NULL, bufsize);

    // 注册关闭回调
    if (close_callback) {
        struct Task* task = malloc(sizeof(struct Task));
        task->cb.close = close_callback;
        task->opaque = close_opaque;
        list_add(&task->list, &evfd->u.task.close_tasks);
    }

    // 判断是否为文件IO, aio
    if (use_aio) {
        evfd -> type = EVFD_AIO;
        evfd -> fd[1] = fd;

        if(fcntl(fd, F_SETFL, O_DIRECT | fcntl(fd, F_GETFL, 0)) == -1){
            perror("fcntl");
            goto aio_err;
        }

        if(io_setup(MAX_EVENTS, &evfd->aio.ctx) != 0){
            perror("io_setup");
            goto aio_err;
        }

        fd = evfd -> fd[0] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (evfd -> fd[0] == -1) {
            perror("eventfd");
aio_err:
            free(evfd);
            return NULL;
        }
        evfd->u.task.offset = 0;
    } else {
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));        
    }

    // 添加到evloop
    struct epoll_event ev = {
        .events = evfd -> epoll_flags,
        .data.ptr = evfd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        perror("epoll_ctl");
        free(evfd);
        return NULL;
    }

#ifdef LJS_DEBUG
    printf("new evfd fd:%d, aio:%d, bufsize:%d\n", fd, use_aio, bufsize);
#endif

    return evfd;
}

void LJS_evfd_setup_udp(EvFD* evfd) {
    evfd->type = EVFD_UDP;
    evfd->proto_ctx = malloc(sizeof(struct UDPContext));
#ifdef LJS_MBEDTLS
    evfd->proto_ctx->dtls_ctx = NULL;
#endif
}

#ifdef LJS_MBEDTLS
bool LJS_evfd_initssl(
    EvFD* evfd, mbedtls_ssl_config** config,
    bool is_client, int protocol, int preset,
    EvSSLHandshakeCallback handshake_cb, void* user_data
) {
    evfd->type = EVFD_SSL;
    
    // 初始化mbedtls结构
    evfd -> ssl = malloc(sizeof(struct EvFD_SSL));
    mbedtls_ssl_init(&evfd->ssl->ctx);
    mbedtls_ssl_config_init(&evfd->ssl->config);
    mbedtls_ssl_config_defaults(&evfd->ssl->config, is_client ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER, protocol, preset);
    mbedtls_ssl_conf_authmode(&evfd->ssl->config, MBEDTLS_SSL_VERIFY_NONE);
    if(config) *config = &evfd->ssl->config;
    
    if (mbedtls_ssl_setup(&evfd->ssl->ctx, &evfd->ssl->config) != 0)
        goto error;
    
    mbedtls_ssl_conf_read_timeout(&evfd->ssl->config, 0);
    mbedtls_ssl_set_bio(&evfd->ssl->ctx, evfd, handle_ssl_send, handle_ssl_recv, NULL);
    
    // 初始化加密/解密缓冲区
    buffer_init(&evfd->ssl->sendbuf, NULL, 16384);
    buffer_init(&evfd->ssl->recvbuf, NULL, 16384);

    // callback
    evfd->ssl->handshake_cb = handshake_cb;
    evfd->ssl->handshake_user_data = user_data;
    
    // 开始握手
    evfd->ssl->ssl_handshaking = true;
    ssl_handle_handshake(evfd);
    return evfd;

error:
    LJS_evfd_close(evfd);
    return NULL;
}

bool LJS_evfd_initdtls(EvFD* evfd, mbedtls_ssl_config** _config) {
    if(!evfd -> proto_ctx) abort();
    struct UDPContext *ctx = evfd->proto_ctx;
    mbedtls_ssl_config* config = malloc(sizeof(mbedtls_ssl_config));
    if(_config) *_config = config;
    
    mbedtls_ssl_init(ctx->dtls_ctx);
    mbedtls_ssl_config_init(config);
    mbedtls_ssl_config_defaults(config, MBEDTLS_SSL_IS_SERVER,
                              MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                              MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&evfd->ssl->config, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_read_timeout(&evfd->ssl->config, 0);
    mbedtls_ssl_set_bio(ctx->dtls_ctx, evfd, 
                       udp_packet_send, udp_packet_recv, NULL);
    return true;
}

#ifdef LJS_DEBUG
void debug_callback(void *ctx, int level, const char *file, int line, const char *str) {
    printf("%s %s:%04d: %s\n", level == MBEDTLS_SSL_ALERT_LEVEL_FATAL ? "E:" : level == MBEDTLS_DEBUG_LEVEL_WARNING ? "W:" : "I:", file, line, str);
}
#endif

bool LJS_evfd_remove_sni(const char* name) {
    struct list_head* pos, *tmp;
    list_for_each_safe(pos, tmp, certs) {
        struct SSL_data* data = list_entry(pos, struct SSL_data, link);
        if(strcmp(data -> name, name) == 0) {
            list_del(pos);
            free(data -> name);
            if(data -> server_name) free(data -> server_name);
            mbedtls_x509_crt_free(data -> cacert);
            mbedtls_pk_free(data -> cakey);
            free(data);
            return true;
        }
    }
    return false;
}

void LJS_evfd_set_sni(char* name, char* server_name, mbedtls_x509_crt* cacert, mbedtls_pk_context* cakey) {
    struct SSL_data* data = malloc(sizeof(struct SSL_data));
    if(!certs) init_list_head(certs = &data -> link);
    else{ 
        LJS_evfd_remove_sni(name);  // 先移除旧的
        list_add(&data -> link, certs);
    }
    data -> name = name;
    data -> server_name = server_name;
    data -> cacert = cacert;
    data -> cakey = cakey;
}
#endif

// 提交读取固定大小的请求
bool LJS_evfd_readsize(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                      EvReadCallback callback, void* user_data) {
    struct Task* task = malloc(sizeof(struct Task));
    if (!task) return false;

    // 初始化buffer
    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size);

    task->type = EV_TASK_READ;
    task->cb.read = callback;
    task->opaque = user_data;
    task->buffer = buf;

    if(evfd -> type == EVFD_AIO) {
        // 提交AIO
        if (submit_aio_read(evfd, task)) {
            free(task);
            buffer_free(buf);
            return false;
        }
    }
    list_add(&task->list, &evfd->u.task.read_tasks);
    check_queue_status(evfd, evfd->fd[0]);
    evloop_events ++;

#ifdef LJS_DEBUG
    printf("new readsize task fd:%d, bufsize:%d\n", evfd->fd[0], buf_size);
#endif

    return true;
}

bool LJS_evfd_clearbuf(EvFD* evfd){
    if(evfd -> destroy) return false;
    buffer_clear(evfd->read_buffer);
    return true;
}

// 提交读取一行数据的请求
bool LJS_evfd_readline(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                      EvReadCallback callback, void* user_data) {
    struct Task* task = malloc(sizeof(struct Task));
    if (!task) return false;

    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size);

    task->type = EV_TASK_READLINE;
    task->buffer = buf;
    task->cb.read = callback;
    task->opaque = user_data;
    evfd->strip_if_is_n = false;
    
    if(evfd -> type == EVFD_AIO && submit_aio_read(evfd, task)){
        free(task);
        buffer_free(buf);
        return false;
    }
    list_add(&task->list, &evfd->u.task.read_tasks);
    check_queue_status(evfd, evfd->fd[0]);
    evloop_events ++;

#ifdef LJS_DEBUG
    printf("new readline task fd:%d, bufsize:%d\n", evfd->fd[0], buf_size);
#endif

    return true;
}

// 通用读取请求
bool LJS_evfd_read(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                   EvReadCallback callback, void* user_data) {
    if(buf_size == 0){
        callback(evfd, buffer, buf_size, user_data);
        return true;
    }
    
    struct Task* task = malloc(sizeof(struct Task));
    if (!task) return false;

    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size);

    task->type = EV_TASK_READONCE;
    task->buffer = buf;
    task->cb.read = callback;
    task->opaque = user_data;
    list_add(&task->list, &evfd->u.task.read_tasks);

#ifdef LJS_DEBUG
    if(evfd -> type == EVFD_AIO)
        printf("warn: aio is not supported for readonce\n");
#endif

    if(evfd -> type == EVFD_AIO) {
        buffer_aligned(buf, blksize_get(evfd->fd[1]));
        // 提交AIO
        if (submit_aio_read(evfd, task)) {
            free(task);
            buffer_free(buf);
            return false;
        }
    }
    list_add(&task->list, &evfd->u.task.read_tasks);
    check_queue_status(evfd, evfd->fd[0]);
    evloop_events ++;

#ifdef LJS_DEBUG
    printf("new readonce task fd:%d, bufsize:%d\n", evfd->fd[0], buf_size);
#endif

    return true;
}

// 提交写请求
bool LJS_evfd_write(EvFD* evfd, const uint8_t* data, uint32_t size,
                   EvWriteCallback callback, void* user_data) {
    if(size == 0){
        callback(evfd, user_data);
        return true;
    }

    struct Task* task = malloc(sizeof(struct Task));
    if (!task) return false;

    // 初始化写buffer
    struct Buffer* buf;
    buffer_init(&buf, (uint8_t*)data, size);
    buf->end = size-1; // 预填充数据

    task->type = EV_TASK_WRITE;
    task->buffer = buf;
    task->cb.write = callback;
    task->opaque = user_data;

    evloop_events ++;
    if (evfd->type == EVFD_AIO) {
        // 提交AIO
        if (!submit_aio_write(evfd, task)) 
            goto error;

        // add to list
        list_add(&task->list, &evfd->u.task.write_tasks);
    }else{
        list_add(&task->list, &evfd->u.task.write_tasks);
        handle_write(evfd->fd[0], evfd, NULL);
    }

#ifdef LJS_DEBUG
    printf("new write task fd:%d, bufsize:%d\n", evfd->fd[0], size);
#endif

    return true;

error:
    buffer_free(buf);
    free(task);
    return false;
}

// UDP写
bool LJS_evfd_write_dgram(EvFD* evfd, const uint8_t* data, uint32_t size,
                         const struct sockaddr *addr, socklen_t addr_len,
                         EvWriteCallback callback, void* user_data) {
    struct UDPContext *ctx = evfd->proto_ctx;
    memcpy(&ctx->peer_addr, addr, addr_len);
    ctx->addr_len = addr_len;
    
    // 复用原有write逻辑
    return LJS_evfd_write(evfd, data, size, callback, user_data);
}

// onclose
bool LJS_evfd_onclose(EvFD* fd, EvCloseCallback callback, void* user_data) {
    struct Task* task = malloc(sizeof(struct Task));
    if (!task) return false;

    task->type = EV_TASK_CLOSE;
    task->cb.close = callback;
    task->opaque = user_data;
    list_add(&task->list, &fd->u.task.close_tasks);

    return true;
}

// pipeto
bool LJS_evfd_pipeTo(EvFD* from, EvFD* to, EvPipeToFilter filter, void* fopaque, EvPipeToNotify notify, void* nopaque){
    struct Task* task = malloc(sizeof(struct Task));
    struct Task* task2 = malloc(sizeof(struct Task));
    if (!task || !task2) return false;

    struct PipeToTask* ptask = malloc(sizeof(struct PipeToTask));
    if (!ptask ) {
        free(task);
        return false;
    }

    task -> type = EV_TASK_PIPETO;
    task -> cb.pipeto = ptask;
    memcpy(task2, task, sizeof(struct Task));
    ptask -> ready_state = 0;
    ptask -> from = from;
    ptask -> to = to;
    ptask -> filter = filter;
    ptask -> filter_opaque = fopaque;
    ptask -> notify_opaque = nopaque;
    list_add(&task -> list, &from -> u.task.read_tasks);
    list_add(&task2 -> list, &to -> u.task.write_tasks);
    evloop_events ++;
    handle_read(from->fd[0], from, NULL, NULL);
    handle_write(to->fd[0], to, NULL);
    return true;
}

// 关闭evfd
bool LJS_evfd_close(EvFD* evfd) {
    if (!evfd || !evfd->active) return false;
    handle_close(evfd->fd[0], evfd);
    evfd->active = false;
    return true;
}

/**
 * Overwrite the default behavior of an EvFD object to callbacks provided by the user.
 * Mostly used after using `LJS_evfd_new()` and donot want to close the fd.
 */
bool LJS_evfd_override(EvFD* evfd, EvReadCallback rcb, void* read_opaque, EvWriteCallback wcb, void* write_opaque, EvCloseCallback ccb, void* close_opaque){
    if(evfd -> destroy || !evfd -> active) return false;
    assert(evfd -> task_based);
    clear_tasks(evfd, false);
    if(evfd -> read_buffer) buffer_free(evfd->read_buffer);
    evloop_events ++;   // force add task
    evfd -> read_buffer = NULL;
    evfd -> u.cb.read = rcb;
    evfd -> u.cb.write = wcb;
    evfd -> u.cb.close = ccb;
    evfd -> u.cb.read_opaque = read_opaque;
    evfd -> u.cb.write_opaque = write_opaque;
    evfd -> u.cb.close_opaque = close_opaque;
    return true;
}

/**
 * Wait for all tasks to complete.
 * After this, cb will be called with opaque as argument.
 */
bool LJS_evfd_wait(EvFD* evfd, bool wait_read, EvSyncCallback cb, void* opaque){
    if(evfd -> destroy || !evfd -> active) return false;
    struct Task* task = malloc(sizeof(struct Task));
    if (!task) return false;

    task->type = EV_TASK_NOOP;
    task->cb.sync = cb;
    task->opaque = opaque;
    if(wait_read){ 
        list_add(&task->list, &evfd->u.task.read_tasks);
        handle_read(evfd->fd[0], evfd, NULL, NULL);
    }else{
        list_add(&task->list, &evfd->u.task.write_tasks);
        handle_write(evfd->fd[0], evfd, NULL);
    }
    evloop_events ++;
    return true;
}

struct __sync_cb_arg {
    uint8_t count;
    EvSyncCallback cb;
    void* opaque;
};

// (internal use) close after all tasks are completed
static void __sync_cb(EvFD* evfd, void* opaque){
    struct __sync_cb_arg* arg = opaque;
    if(arg->count ++ == 1){ 
        LJS_evfd_close(evfd); 
        arg->cb(evfd, arg->opaque);
        free(arg);
    }
}

bool LJS_evfd_close2(EvFD* evfd, EvSyncCallback cb, void* opaque){
    struct __sync_cb_arg* arg = malloc(sizeof(struct __sync_cb_arg));
    if (!arg) return false;
    arg->count = 0;
    arg->cb = cb;
    arg->opaque = opaque;
    return LJS_evfd_wait(evfd, false, __sync_cb, arg) && LJS_evfd_wait(evfd, true, __sync_cb, arg);
}

static inline EvFD* timer_new(unsigned long milliseconds, EvTimerCallback callback, void* user_data, bool once) {
    // 创建定时器fd
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd == -1) {
        perror("timerfd_create");
        return NULL;
    }

    // 设置定时参数
    struct timespec itss = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (milliseconds % 1000) * 1000000
    };
    struct timespec itsn = { 0, 0 };
    struct itimerspec its = {
        .it_value = itss,
        .it_interval = once ? itsn : itss
    };
    
    if (timerfd_settime(fd, 0, &its, NULL) == -1) {
        perror("timerfd_settime");
        close(fd);
        return NULL;
    }

    // 创建定时器对象
    struct EvFD* evfd = malloc(sizeof(struct EvFD));
    if(evfd == NULL) LJS_panic("malloc failed");
    evfd -> task_based = true;

    // 初始化任务队列
    init_list_head(&evfd->u.task.read_tasks);
    init_list_head(&evfd->u.task.write_tasks);
    init_list_head(&evfd->u.task.close_tasks);
    INIT_EVFD(evfd);

    // 设置基础参数
    evfd->fd[0] = fd;
    evfd->type = EVFD_TIMER;
    evfd->task_based = true;

    // 添加到eventloop
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET,
        .data.ptr = evfd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        perror("epoll_ctl timerfd");
        close(fd);
        free(evfd);
        return NULL;
    }

    // 注册
    list_add(&evfd -> list, &timer_list);

#ifdef LJS_DEBUG
    printf("new timer fd:%d, s:%ld, ns:%ld, once:%d\n", fd, itss.tv_sec, itss.tv_nsec, once);
#endif
    
    return evfd;
}

static inline bool timer_task(struct EvFD* evfd, EvTimerCallback callback, void* user_data) {
    if(!evfd) return false;
    struct Task* task = malloc(sizeof(struct Task));
    if (!task) return false;

    task->cb.timer = callback;
    task->opaque = user_data;
    list_add(&task->list, &evfd->u.task.read_tasks);
    evloop_events ++;
    return true;
}

EvFD* LJS_evcore_interval(unsigned long milliseconds, EvTimerCallback callback, void* user_data) {
    struct EvFD* evfd = timer_new(milliseconds, callback, user_data, false);
    if(timer_task(evfd, callback, user_data)) return evfd;
    LJS_evfd_close(evfd);
    return NULL;
}

EvFD* LJS_evcore_setTimeout(unsigned long milliseconds, EvTimerCallback callback, void* user_data) {
    struct EvFD* evfd = timer_new(milliseconds, callback, user_data, true);
    if(timer_task(evfd, callback, user_data)) return evfd;
    LJS_evfd_close(evfd);
    return NULL;
}

bool LJS_evcore_clearTimer(int timer_fd) {
    // 在链表中查找定时器
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &timer_list) {
        struct EvFD* evfd = list_entry(pos, struct EvFD, list);
        if(evfd -> fd[0] == timer_fd){
            // 从epoll注销
            if(!epoll_ctl(epoll_fd, EPOLL_CTL_DEL, timer_fd, NULL)) return false;

#ifdef LJS_DEBUG
            printf("clear timer fd:%d\n", timer_fd);
#endif

            // 关闭文件描述符
            close(timer_fd);

            // 清理任务队列
            struct list_head *pos, *tmp;
            list_for_each_safe(pos, tmp, &evfd->u.task.read_tasks) {
                struct Task* task = list_entry(pos, struct Task, list);
                list_del(pos);
                evloop_events --;
                free(task);
            }

            // 释放缓冲区
            buffer_free(evfd->read_buffer);
            free(evfd);

            // 从链表中删除
            evloop_events --;
            list_del(pos);
            return true;
        }
    }

    return false;
}

// 初始化inotify监控实例
EvFD* LJS_evcore_inotify(EvINotifyCallback callback, void* user_data) {
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd == -1) {
        perror("inotify_init1");
        return NULL;
    }

    EvFD* evfd = calloc(1, sizeof(EvFD));
    if (!evfd) {
        close(inotify_fd);
        return NULL;
    }

    // 初始化任务队列
    evfd -> task_based = true;
    init_list_head(&evfd->u.task.read_tasks);

    // 设置inotify参数
    evfd->fd[0] = inotify_fd;
    evfd->type = EVFD_INOTIFY;
    evfd->active = true;

    // 添加默认读任务
    struct Task* task = malloc(sizeof(struct Task));
    task->type = EV_TASK_READ;
    task->cb.inotify = callback;
    task->opaque = user_data;
    list_add(&task->list, &evfd->u.task.read_tasks);

    // 注册到epoll
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET,
        .data.ptr = evfd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &ev) == -1) {
        perror("epoll_ctl");
        close(inotify_fd);
        free(evfd);
        return NULL;
    }
#ifdef LJS_DEBUG
    printf("inotify fd:%d\n", inotify_fd);
#endif

    evloop_events ++;
    return evfd;
}

// 停止inotify监控
bool LJS_evcore_stop_inotify(EvFD* evfd) {
    if (!evfd || evfd->type != EVFD_INOTIFY) return false;

    // 从epoll注销
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, evfd->fd[0], NULL);

    // 关闭文件描述符
    close(evfd->fd[0]);

    // 清理任务队列
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &evfd->u.task.read_tasks) {
        struct Task* task = list_entry(pos, struct Task, list);
        list_del(pos);
        evloop_events --;
        free(task);
    }

    // 释放缓冲区
    buffer_free(evfd->read_buffer);
    free(evfd);

    return true;
}

// 添加监控路径
int LJS_evcore_inotify_watch(EvFD* evfd, const char* path, uint32_t mask) {
    if (!evfd || evfd->type != EVFD_INOTIFY) return -1;

    int wd = inotify_add_watch(evfd->fd[0], path, mask);
    if (wd == -1) {
        perror("inotify_add_watch");
        return -1;
    }
    return wd;
}

// 移除监控路径
bool LJS_evcore_inotify_unwatch(EvFD* evfd, int wd) {
    if (!evfd || evfd->type != EVFD_INOTIFY) return -1;

    int ret = inotify_rm_watch(evfd->fd[0], wd);
    if (ret == -1) {
        perror("inotify_rm_watch");
        return false;
    }
    return true;
}

int LJS_evfd_getfd(EvFD* evfd, int* timer_fd) {
    if(evfd -> type == EVFD_AIO){
        if(timer_fd) *timer_fd = evfd -> fd[0];
        return evfd -> fd[1];
    }else if(evfd -> type == EVFD_NORM){
        if(timer_fd)*timer_fd = -1;
        return evfd -> fd[0];
    }else{
        return -1;  // not support
    }
}

bool LJS_evfd_isAIO(EvFD* evfd) {
    return evfd -> type == EVFD_AIO;
}