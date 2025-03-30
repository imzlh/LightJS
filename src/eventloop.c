#include <sys/epoll.h>
// #include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/timerfd.h>
#include <threads.h>
#include <stdio.h>
#include <linux/aio_abi.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

#include "core.h"

struct ReadTask {
    uint8_t* buffer;
    uint32_t total_size;
    uint32_t read_size;
    int task_type;
    EvReadCallback callback;
    void* user_data;
    struct ReadTask* next;
} ReadTask;

struct WriteTask {
    const uint8_t* data;
    uint32_t total_size;
    uint32_t written_size;
    struct WriteTask* next;
    EvWriteCallback callback;
    void* user_data;
};

struct FdContext {
    int fd;
    EvReadCallback rcb;
    EvWriteCallback wcb;
    EvCloseCallback ccb;
    void* opaque;
    uint32_t events;
    struct FdContext* next;

    // aio
    bool use_aio;
    struct AIOContext *aio_ctx; 
};

enum AIOTaskType {
    AIO_READ,
    AIO_WRITE,
    AIO_CLOSE,
    AIO_READLINE
};

struct AIOTask {
    EvReadCallback user_cb;
    void* user_data;
    enum AIOTaskType task_type;
    EvFD* evfd;
};

struct AIOContext {
    aio_context_t ctx_id;
    int event_fd;
    struct iocb **iocbs;
    struct io_event *events;
    struct FdContext *fd_ctx;
    
    uint8_t* line_buffer;
    uint32_t line_pos;
    uint32_t line_size;
};

typedef struct Timer {
    int fd;
    EvTimerCallback callback;
    void* user_data;
    bool is_interval;
    struct timespec interval;
    struct Timer* next;
} Timer;

static thread_local int epoll_fd = -1;
static thread_local struct FdContext* fd_ctx_list = NULL;
static thread_local Timer* timer_list = NULL;
static int is_aio_supported = -1;

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
    int ret = 0;
    int fd = open("/proc/sys/fs/aio-max-nr", O_RDONLY);
    if (fd >= 0) {
        char buf[100];
        int n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            int max_nr = atoi(buf);
            if (max_nr < 1024) {
                ret = -1;
            }
        }
        close(fd);
    }
    return ret;
}

// 内部辅助函数
static struct FdContext* find_fd_context(int fd) {
    for (struct FdContext* ctx = fd_ctx_list; ctx != NULL; ctx = ctx->next) {
        if (ctx->fd == fd) return ctx;
    }
    return NULL;
}

static void update_events(struct FdContext* ctx) {
    struct epoll_event ev;
    ev.events = ctx->events | EPOLLET;
    ev.data.ptr = ctx;

    int op = ctx->events ? EPOLL_CTL_MOD : EPOLL_CTL_DEL;
    if (epoll_ctl(epoll_fd, op, ctx->fd, &ev) == -1) {
        perror("epoll_ctl");
    }
}

// 在handle_read/handle_write中添加队列状态检查
static void check_queue_status(EvFD* evfd, int fd) {
    struct FdContext* ctx = find_fd_context(fd);
    if (!ctx) return;

    uint32_t new_events = 0;
    if (evfd->read_queue) new_events |= EPOLLIN;
    if (evfd->write_queue) new_events |= EPOLLOUT;
    
    if (ctx->events != new_events) {
        ctx->events = new_events;
        update_events(ctx);
    }
}


// 事件处理函数
static void handle_read(int fd, EvFD* evfd) {
    while (1) {
        struct ReadTask* task = evfd->read_queue;
        if (!task) break;

        if (task->task_type == 0) { // readsize
            ssize_t n = read(fd, task->buffer + task->read_size,
                           task->total_size - task->read_size);
            if (n > 0) {
                task->read_size += n;
                if (task->read_size >= task->total_size) {
                    evfd->read_queue = task->next;
                    task -> callback(evfd, task->buffer, task->read_size, task->user_data);
                    free(task);
                }
            } else if (n == 0 || errno == EAGAIN) {
                break;
            } else {
                perror("read");
                break;
            }
        } else if (task->task_type == 1) { // readline
            while (1) {
                // 确保line_buffer有足够空间
                if (!evfd->line_buffer || evfd->line_pos == 0) {
                    uint32_t new_size = evfd->line_size * 2;
                    uint8_t* new_buf = realloc(evfd->line_buffer, new_size);
                    if (!new_buf) {
                        LJS_panic("malloc failed");
                    }
                    evfd->line_buffer = new_buf;
                    evfd->line_size = new_size;
                }

                ssize_t n = read(fd, evfd->line_buffer + evfd->line_pos,
                            evfd->line_size - evfd->line_pos);
                if (n <= 0) {
                    if (n == 0) evfd->eof = true;
                    break;
                }
                
                evfd->line_pos += n;
                
                // 扫描换行符
                uint8_t* start = evfd->line_buffer;
                uint8_t* end = start + evfd->line_pos;
                for (uint8_t* p = start; p < end; ++p) {
                    if (*p == '\n') {
                        uint32_t line_len = p - start;
                        if (line_len > 0 && *(p-1) == '\r') line_len--;
                        
                        // 复制到用户buffer
                        uint32_t copy_len = line_len < task->total_size ? line_len : task->total_size;
                        memcpy(task->buffer, start, copy_len);
                        
                        // 触发回调
                        task->callback(evfd, task->buffer, copy_len, task->user_data);
                        
                        // 移动剩余数据
                        uint32_t remain = end - (p + 1);
                        memmove(start, p + 1, remain);
                        evfd->line_pos = remain;

                        // 指向下一个任务
                        task = task->next;
                        free(task);
                        break;
                    }
                }
                
                // 缓冲区满但未找到换行符
                if (evfd->line_pos == evfd->line_size) {
                    uint32_t copy_len = evfd->line_size < task->total_size ? evfd->line_size : task->total_size;
                    memcpy(task->buffer, start, copy_len);
                    task->callback(evfd, task->buffer, copy_len, task->user_data);
                    evfd->line_pos = 0;
                }
            }
        } else { // readonce
            // int available;
            // ioctl(fd, FIONREAD, &available);
            // available = available > task->total_size ? task->total_size : available;
            
            ssize_t n = read(fd, task->buffer, UINT32_MAX);
            if (n > 0) {
                task->read_size = n;
                evfd->read_queue = task->next;
                free(task);
            } else if (n == 0) {
                evfd->eof = true;
            }
            break;
        }
    }

    if(!evfd->read_queue) {
        check_queue_status(evfd, fd);
    }
}

static void handle_write(int fd, EvFD* evfd) {
    while (evfd->write_queue) {
        struct WriteTask* task = evfd->write_queue;
        ssize_t n = write(fd, task->data + task->written_size,
                        task->total_size - task->written_size);
        if (n > 0) {
            task->written_size += n;
            if (task->written_size >= task->total_size) {
                task -> callback(evfd, task -> user_data);
                evfd->write_queue = task->next;
                free(task);
            }
        } else if (errno == EAGAIN) {
            task -> callback(evfd, task -> user_data);
            break;
        } else {
            perror("write");
            break;
        }
    }

    if(!evfd->write_queue) {
        check_queue_status(evfd, fd);
    }
}

static void handle_close(int fd, void* _evfd) {
    EvFD* evfd = (EvFD*)_evfd;
    // read queue
    while (evfd->read_queue) {
        struct ReadTask* task = evfd->read_queue;
        task -> callback(evfd, task->buffer, 0, task->user_data);
        evfd->read_queue = task->next;
        free(task);
    }

    // write queue
    while (evfd->write_queue) {
        struct WriteTask* task = evfd->write_queue;
        evfd->write_queue = task->next;
        free(task);
    }

    // 从链表中移除fd
    struct FdContext** pp = &fd_ctx_list;
    while (*pp) {
        if ((*pp)->fd == fd) {
            struct FdContext* tmp = *pp;
            *pp = tmp->next;
            free(tmp);
            break;
        }
        pp = &(*pp)->next;
    }

    // 回调？
    if (evfd->close_callback) {
        evfd->close_callback(fd, evfd->close_opaque);
    }

    // 关闭fd
    if(!evfd -> eof)close(fd);
    if(evfd -> line_buffer) free(evfd->line_buffer);
    evfd -> line_buffer = NULL;
    free(evfd);
}

static void timer_callback(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* opaque) {
    Timer* timer = (Timer*)opaque;
    uint64_t exp;
    
    // 必须读取定时器事件
    if (read(evfd -> fd, &exp, sizeof(exp)) != sizeof(exp)) {
        perror("read timerfd");
        return;
    }
    
    // 执行用户回调
    if (timer->callback) {
        timer->callback(timer->user_data);
    }
}

static void timer_close_callback(int fd, void* opaque) {
    // 从链表中移除定时器
    Timer** pp = &timer_list;
    while (*pp) {
        if ((*pp)->fd == fd) {
            Timer* tmp = *pp;
            *pp = tmp->next;
            close(tmp->fd);
            free(tmp);
            break;
        }
        pp = &(*pp)->next;
    }
}

static void aio_event_handler(EvFD* evfd, uint8_t* buffer, uint32_t size, void* opaque) {
    struct AIOContext *aio = opaque;
    struct io_event events[16];
    int nr = io_getevents(aio->ctx_id, 1, 16, events, NULL);
    bool error = false;

    // closed
    if((nr == -1 && errno == EBADF) || nr == 0){
        LJS_evfd_close(evfd);
    }
    
    for (int i = 0; i < nr; ++i) {
        struct iocb* iocb = (void*)events[i].obj;
        struct AIOTask* task = (struct AIOTask*)iocb->aio_data;
        
        if (events[i].res > 0) {
            // 处理读取行的任务
            if (task->task_type == AIO_READLINE) { // readline任务
                // 将读取到的数据添加到line_buffer
                if (aio->line_pos + events[i].res > aio->line_size) {
                    // 扩展line_buffer
                    aio->line_size = (aio->line_pos + events[i].res) * 2;
                    aio->line_buffer = realloc(aio->line_buffer, aio->line_size);
                }
                
                // 复制数据到缓冲区
                memcpy(aio->line_buffer + aio->line_pos, (uint8_t*)iocb->aio_buf, iocb -> aio_nbytes);
                aio->line_pos += events[i].res;

                // 查找换行符
                for (uint8_t* p = aio->line_buffer; p < aio->line_buffer + aio->line_pos; ++p) {
                    if (*p == '\n') {
                        uint32_t line_len = p - aio->line_buffer;
                        task->user_cb(task->evfd, task->evfd->line_buffer, line_len, task->user_data);

                        // 移动剩余数据
                        uint32_t remain = aio->line_pos - (line_len + 1);
                        if (remain > 0) {
                            memmove(aio->line_buffer, p + 1, remain);
                        }
                        aio->line_pos = remain;
                        break;
                    }
                }
            } else if (task->task_type == AIO_READ) { // 普通读任务
                task->user_cb(task->evfd, (uint8_t*)iocb->aio_buf, events[i].res, task->user_data);
            } else if (task -> task_type == AIO_WRITE) { // 写任务
                task -> user_cb(task -> evfd, (uint8_t*)iocb -> aio_buf, iocb ->aio_nbytes, task -> user_data);
            }
        }else{
            error = true;
        }

        free(task);
        free(iocb);
    }

    if(error) LJS_evfd_close(evfd);
}


// 公共接口实现
bool LJS_evcore_init() {
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        return false;
    }

    // aio?
    if(is_aio_supported == -1) is_aio_supported = is_aio_supported;

    return true;
}

bool LJS_evcore_run(bool (*evloop_abort_check)(void* user_data), void* user_data) {
    struct epoll_event events[MAX_EVENTS];
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        // }else if (nfds == 0 && (evloop_abort_check ? evloop_abort_check(user_data) : false)){
        //     printf("evloop_abort_check return true, exit loop\n");
        //     return true; // no events
        // }
        
        for (int i = 0; i < nfds; ++i) {
            struct FdContext* ctx = (struct FdContext*)events[i].data.ptr;
            
            if(ctx -> opaque){
                EvFD* evfd = (EvFD*)ctx->opaque;
                if (events[i].events & EPOLLIN) {
                    handle_read(ctx->fd, evfd);
                }
                if (events[i].events & EPOLLOUT) {
                    handle_write(ctx->fd, evfd);
                }
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    if (ctx->ccb) ctx->ccb(ctx->fd, ctx->opaque);
                }
            }else{
                if (events[i].events & EPOLLIN) {
                    if(ctx -> rcb && (events[i].events & EPOLLIN)){
                        ctx -> rcb(NULL, NULL, 0, ctx->opaque);
                    }else if(ctx -> wcb && (events[i].events & EPOLLOUT)){
                        ctx -> wcb(NULL, ctx->opaque);
                    }else if(ctx -> ccb && (events[i].events & (EPOLLERR | EPOLLHUP))){
                        ctx -> ccb(ctx->fd, ctx->opaque);
                    }
                }
            }
        }
    }

    close(epoll_fd);
    return true;
}

/**
 * 将fd附加到eventloop。
 * 返回-1表示出错，0表示成功，>0表示使用AIO的evfd。
 */
int LJS_evcore_attach(int fd, EvReadCallback rcb, EvWriteCallback wcb,
                      EvCloseCallback ccb, void* opaque) {
    if(fcntl(fd, F_GETFD) == -1 && errno == EBADF){
        return false;
    }
    
    struct FdContext* ctx = malloc(sizeof(struct FdContext));
    ctx->fd = fd;
    ctx->rcb = rcb;
    ctx->wcb = wcb;
    ctx->ccb = ccb;
    ctx->opaque = opaque;
    ctx->events = EPOLLHUP | EPOLLET;
    ctx->next = fd_ctx_list;
    fd_ctx_list = ctx;

    if (rcb) ctx->events |= EPOLLIN;
    if (wcb) ctx->events |= EPOLLOUT;

    struct epoll_event ev;
    ev.events = ctx->events;
    ev.data.ptr = ctx;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1){
        // 使用aio,通过eventfd通知完成事件
        if (errno == EPERM) {
            if(!is_aio_supported){
                free(ctx);
                return -1;
            }
            ctx->use_aio = true;
            // 初始化AIO上下文
            struct AIOContext *aio = malloc(sizeof(struct AIOContext));
            memset(aio, 0, sizeof(struct AIOContext));
                
            // 创建eventfd用于通知完成事件
            aio->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
            if (aio->event_fd == -1) {
                perror("eventfd");
                free(aio);
                return -1;
            }

            // 初始化AIO上下文
            if (io_setup(128, &aio->ctx_id) < 0) {
                perror("io_setup");
                close(aio->event_fd);
                free(aio);
                return -1;
            }

            ctx -> aio_ctx = aio;
            ctx -> fd = aio->event_fd;  // 指向eventfd
            ctx -> rcb = aio_event_handler;

            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, aio -> event_fd, &ev);

            return aio -> event_fd;
        }else{
            return -1;
        }
    }
    return 0;
}

bool LJS_evcore_detach(int fd, uint8_t type) {
    struct FdContext* ctx = find_fd_context(fd);
    if (!ctx) return false;

    if (type & EV_REMOVE_READ) ctx->events &= ~EPOLLIN;
    if (type & EV_REMOVE_WRITE) ctx->events &= ~EPOLLOUT;

    update_events(ctx);
    return true;
}

EvFD* LJS_evfd_new(int fd, bool readable, bool writeable, uint32_t bufsize, 
                        EvCloseCallback close_callback, void* close_opaque) {
    EvFD* evfd = malloc(sizeof(EvFD));
    evfd -> fd = fd;
    evfd -> line_buffer = NULL;
    evfd -> close_callback = close_callback;
    evfd -> close_opaque = close_opaque;
    evfd -> read_queue = NULL;
    evfd -> write_queue = NULL;
    evfd -> eof = false;
    evfd -> active = true;

    // async
    if (readable || writeable) {
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    }

    int res = LJS_evcore_attach(fd, (EvReadCallback)(readable ? (void*)handle_read : (void*)NULL),
                     (EvWriteCallback)(writeable ? (void*)handle_write : (void*)NULL),
                     handle_close, evfd);
    if(res == 0){
        return evfd;
    }else if(res > 0){
        evfd -> fd = res;
        evfd -> aio = true;
        evfd -> raw_fd = fd;
        return evfd;
    }else{
        free(evfd);
        return NULL;
    }
}

static inline bool aio_read(EvFD* evfd, uint8_t* buf, size_t count, off_t offset,
                      EvReadCallback callback, enum AIOTaskType task_type, void* user_data) {
    struct FdContext *ctx = find_fd_context(evfd->fd);
    if (!ctx || !ctx->use_aio) return false;

    // 包装回调上下文
    struct AIOTask *task = malloc(sizeof(struct AIOTask));
    
    task->user_cb = callback;
    task->user_data = user_data;
    task->task_type = task_type;
    task->evfd = evfd;

    struct iocb *iocb = malloc(sizeof(struct iocb));
    iocb -> aio_lio_opcode = IOCB_CMD_PREAD;
    iocb -> aio_resfd = ctx -> aio_ctx -> event_fd;
    iocb -> aio_buf = (uint64_t)buf;
    iocb -> aio_nbytes = count;
    iocb -> aio_offset = offset;
    iocb -> aio_flags = IOCB_FLAG_RESFD;
    iocb -> aio_data = (uint64_t)task; // 存储任务上下文

    struct iocb *iocbs[1] = {iocb};
    return io_submit(ctx->aio_ctx->ctx_id, 1, iocbs) == 1;
}

static inline bool aio_write(EvFD* evfd, const uint8_t* buf, size_t count, off_t offset,
                       EvWriteCallback callback) {
    struct FdContext *ctx = find_fd_context(evfd->fd);
    if (!ctx || !ctx->use_aio) return false;

    struct iocb *iocb = malloc(sizeof(struct iocb));
    iocb -> aio_lio_opcode = IOCB_CMD_PWRITE;
    iocb -> aio_resfd = ctx -> aio_ctx -> event_fd;
    iocb -> aio_buf = (uint64_t)buf;
    iocb -> aio_nbytes = count;
    iocb -> aio_offset = offset;
    iocb -> aio_flags = IOCB_FLAG_RESFD;
    iocb -> aio_data = (uint64_t)callback;

    struct iocb *iocbs[1] = {iocb};
    int ret = io_submit(ctx->aio_ctx->ctx_id, 1, iocbs);
    if (ret != 1) {
        free(iocb);
        return false;
    }
    return true;
}

bool LJS_evfd_readsize(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                      EvReadCallback callback, void* user_data) {

    if(evfd -> aio){
        return aio_read(evfd, buffer, buf_size, 0, callback, 2, user_data);
    }

    uint32_t offset = 0;

    // 处理缓存的line数据
    if (evfd->line_buffer && evfd->line_pos > 0) {
        uint32_t copy_len = evfd->line_pos < buf_size ? evfd->line_pos : buf_size;
        memcpy(buffer, evfd->line_buffer, copy_len);
        
        // 移动剩余数据
        if (evfd->line_pos > copy_len) {
            memmove(evfd->line_buffer, evfd->line_buffer + copy_len, evfd->line_pos - copy_len);
        }
        evfd->line_pos -= copy_len;
        
        if(buf_size == copy_len){
            callback(evfd, buffer, copy_len, user_data);
            return true;
        }

        offset = copy_len;
    }

    struct ReadTask* task = malloc(sizeof(struct ReadTask));
    task->buffer = buffer;
    task->total_size = buf_size;
    task->read_size = offset;
    task->task_type = 0;
    task->callback = callback;    // 设置回调
    task->user_data = user_data;   // 设置用户数据
    task->next = evfd->read_queue;
    evfd->read_queue = task;

    struct FdContext* ctx = find_fd_context(evfd->fd);
    if (ctx && !(ctx->events & EPOLLIN)) {
        ctx->events |= EPOLLIN;
        update_events(ctx);
    }
    return true;
}


bool LJS_evfd_readline(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                      EvReadCallback callback, void* user_data) {
    if (evfd->aio) {
        return aio_read(evfd, buffer, /* 不要一次填充完 */ buf_size /2, 0, callback, 1, user_data);
    }

    struct ReadTask* task = malloc(sizeof(struct ReadTask));
    task->buffer = buffer;
    task->total_size = buf_size;
    task->read_size = 0;
    task->task_type = 1;
    task->callback = callback;    // 设置回调
    task->user_data = user_data;   // 设置用户数据
    task->next = evfd->read_queue;
    evfd->read_queue = task;

    if (evfd -> line_buffer){
        if(evfd -> line_pos >= buf_size){
            memcpy(evfd -> line_buffer, buffer, buf_size);
            evfd -> line_pos += buf_size;
            callback(evfd, evfd -> line_buffer, buf_size, user_data);
            return true;
        }else{
            memcpy(evfd -> line_buffer, buffer, evfd -> line_pos);
            free(evfd -> line_buffer);
            evfd -> line_buffer = malloc(buf_size - evfd -> line_pos);
            evfd -> line_size = buf_size - evfd -> line_pos;
            evfd -> line_pos = 0;
        }
    }

    struct FdContext* ctx = find_fd_context(evfd->fd);
    if (ctx && !(ctx->events & EPOLLIN)) {
        ctx->events |= EPOLLIN;
        update_events(ctx);
    }
    return true;
}

bool LJS_evfd_read(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                   EvReadCallback callback, void* user_data) {

    if(evfd -> aio){
        return aio_read(evfd, buffer, buf_size, 0, callback, 0, user_data);
    }

    // 检查buffer是否符合要求
    if(evfd -> line_buffer) {
        uint32_t read_len = evfd -> line_pos < buf_size ? evfd -> line_pos : buf_size;
        memcpy(buffer, evfd -> line_buffer, read_len);
        if(evfd -> line_pos > buf_size){    // 有剩余
            memmove(evfd -> line_buffer, evfd -> line_buffer + buf_size, evfd -> line_pos - buf_size);
            evfd -> line_pos -= buf_size;
        }else{
            // 释放
            free(evfd -> line_buffer);
            evfd -> line_buffer = NULL;
            evfd -> line_pos = 0;
        }

        callback(evfd, buffer, read_len, user_data);
        return true;
    }

    struct ReadTask* task = malloc(sizeof(struct ReadTask));
    task->buffer = buffer;
    task->total_size = buf_size;
    task->read_size = 0;
    task->task_type = 2;
    task->callback = callback;    // 设置回调
    task->user_data = user_data;   // 设置用户数据
    task->next = evfd->read_queue;
    evfd->read_queue = task;

    struct FdContext* ctx = find_fd_context(evfd->fd);
    if (ctx && !(ctx->events & EPOLLIN)) {
        ctx->events |= EPOLLIN;
        update_events(ctx);
    }
    return true;
}

bool LJS_evfd_write(EvFD* evfd, const uint8_t* data, uint32_t size, 
                   EvWriteCallback callback, void* user_data) {

    if(evfd -> aio){
        return aio_write(evfd, data, size, 0, callback);
    }

    // 创建写入任务
    struct WriteTask* task = malloc(sizeof(struct WriteTask));
    if (!task) return false;

    // 初始化任务信息
    task->data = data;
    task->total_size = size;
    task->written_size = 0;
    task->callback = callback;
    task->user_data = user_data;
    task->next = evfd->write_queue;
    evfd->write_queue = task;

    // 更新epoll监听事件
    struct FdContext* ctx = find_fd_context(evfd->fd);
    if (ctx && !(ctx->events & EPOLLOUT)) {
        ctx->events |= EPOLLOUT;
        update_events(ctx);
    }
    return true;
}

bool LJS_evfd_close(EvFD* evfd) {
    if(evfd -> aio){
        struct FdContext* ctx = find_fd_context(evfd->fd);
        if (ctx) {
            struct AIOContext *aio = ctx->aio_ctx;
            if (aio) {
                io_destroy(aio->ctx_id);
                // 关闭eventfd
                close(aio->event_fd);
                // 释放aio
                free(aio);
            }
        }
    }

    // 关闭fd
    evfd->active = false;
    LJS_evcore_detach(evfd->fd, EV_REMOVE_READ | EV_REMOVE_WRITE);
    handle_close(evfd->fd, evfd);
    return true;
}

int LJS_evcore_setTimeout(unsigned long milliseconds, EvTimerCallback callback, void* user_data) {
    // 创建定时器fd
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd == -1) {
        perror("timerfd_create");
        return -1;
    }

    // 设置定时参数
    struct itimerspec its = {
        .it_value = {
            .tv_sec = milliseconds / 1000,
            .tv_nsec = (milliseconds % 1000) * 1000000
        },
        .it_interval = {0}  // 单次触发
    };
    
    if (timerfd_settime(fd, 0, &its, NULL) == -1) {
        perror("timerfd_settime");
        close(fd);
        return -1;
    }

    // 创建定时器对象
    Timer* timer = malloc(sizeof(Timer));
    timer->fd = fd;
    timer->callback = callback;
    timer->user_data = user_data;
    timer->is_interval = false;
    timer->next = timer_list;
    timer_list = timer;

    // 注册到事件循环
    if (!LJS_evcore_attach(fd, timer_callback, (EvWriteCallback)NULL, timer_close_callback, timer)) {
        close(fd);
        free(timer);
        return -1;
    }
    
    return fd;
}

int LJS_evcore_interval(unsigned long milliseconds, EvTimerCallback callback, void* user_data) {
    // 创建定时器fd
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd == -1) {
        perror("timerfd_create");
        return -1;
    }

    // 设置定时参数
    struct itimerspec its = {
        .it_value = {
            .tv_sec = milliseconds / 1000,
            .tv_nsec = (milliseconds % 1000) * 1000000
        },
        .it_interval = {    // 间隔时间
            .tv_sec = milliseconds / 1000,
            .tv_nsec = (milliseconds % 1000) * 1000000
        }
    };
    
    if (timerfd_settime(fd, 0, &its, NULL) == -1) {
        perror("timerfd_settime");
        close(fd);
        return -1;
    }

    // 创建定时器对象
    Timer* timer = malloc(sizeof(Timer));
    timer->fd = fd;
    timer->callback = callback;
    timer->user_data = user_data;
    timer->is_interval = true;
    timer->next = timer_list;
    timer_list = timer;

    // 注册到事件循环
    if (!LJS_evcore_attach(fd, timer_callback, NULL, timer_close_callback, timer)) {
        close(fd);
        free(timer);
        return -1;
    }
    
    return fd;
}

bool LJS_evcore_clearTimer(int timer_fd) {
    // 在链表中查找定时器
    Timer** pp = &timer_list;
    while (*pp) {
        if ((*pp)->fd == timer_fd) {
            Timer* tmp = *pp;
            *pp = tmp->next;
            
            // 从epoll注销
            LJS_evcore_detach(tmp->fd, EV_REMOVE_READ | EV_REMOVE_WRITE);
            
            // 关闭文件描述符
            close(tmp->fd);
            free(tmp);
            return true;
        }
        pp = &(*pp)->next;
    }
    return false;
}
