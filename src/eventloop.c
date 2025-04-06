#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <threads.h>
#include <stdio.h>
#include <linux/aio_abi.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

#include "../engine/cutils.h"
#include "../engine/list.h"
#include "utils.h"
#include "core.h"

enum EvFDType {
    EVFD_NORM,
    EVFD_AIO,
    EVFD_INOTIFY,
    EVFD_TIMER,
};

enum EvTaskType {
    EV_TASK_READ,
    EV_TASK_WRITE,
    EV_TASK_CLOSE,
    EV_TASK_READLINE,
    EV_TASK_READONCE,
    EV_TASK_SYNC,
    EV_TASK_SYNCONCE
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
    } cb;

    struct list_head list;
    uint32_t aio_write_remain;
};

struct EvFD{
    int fd[2];  // 如果是aio，第二个则是原始fd
    enum EvFDType type;
    aio_context_t aio_ctx;  // for aio
    struct list_head list;  // for task list

    struct list_head read_tasks;
    struct list_head write_tasks;
    struct list_head close_tasks;
    
    struct Buffer* read_buffer;

    bool eof;   // 代表已经关闭
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
    if(!io_setup(0, &test_ctx)) return false;
    io_destroy(test_ctx);
    return true;
}

// 内部辅助函数
// 在handle_read/handle_write中添加队列状态检查
static void check_queue_status(EvFD* evfd, int fd) {
    uint32_t new_events = EPOLLHUP | EPOLLET;
    if (    // aio中，任何一个队列有任务都需要EPOLLIN
        (evfd -> type != EVFD_AIO && !list_empty(&evfd -> read_tasks)) ||
        (evfd -> type == EVFD_AIO && (!list_empty(&evfd -> read_tasks) || !list_empty(&evfd -> write_tasks)))
    ) 
        new_events |= EPOLLIN;
    if (evfd -> type == EVFD_NORM && !list_empty(&evfd -> write_tasks)) 
        new_events |= EPOLLOUT;
        
    
    if (evfd -> epoll_flags != new_events) {
        evfd -> epoll_flags = new_events;

#ifdef LJS_DEBUG
        printf("epoll_ctl: fd=%d, events=%d, r=%d, w=%d\n", fd, new_events, new_events & EPOLLIN, new_events & EPOLLOUT);
#endif
        
        // 修改epoll事件
        struct epoll_event ev;
        ev.events = new_events;
        ev.data.ptr = evfd;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, evfd->fd[0], &ev) == -1) {
            perror("epoll_ctl");
        }
    }
}

// buffer

// 事件处理函数
static void handle_read(int fd, EvFD* evfd, struct iocb* iocb, struct inotify_event* inev) {
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &evfd->read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);

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

        }

        uint32_t n = 0;
        if(evfd -> type == EVFD_NORM){
            n = buffer_read(evfd->read_buffer, fd, UINT32_MAX);
            if(n == -1) perror("evfd_read");    // error
            if(n <= 0) return;
        }else if(evfd -> type == EVFD_AIO/* && iocb */){
            n = iocb -> aio_nbytes;
            buffer_push(evfd->read_buffer, (uint8_t*)iocb->aio_buf, n);
        }

        switch(task -> type){
            case EV_TASK_READ: // readsize
                if (task -> buffer -> size == buffer_used(evfd -> read_buffer)) {
                    // 导出
                    buffer_copyto(evfd -> read_buffer, task -> buffer -> buffer, task -> buffer -> size);
                    buffer_clear(evfd -> read_buffer);
                    task -> cb.read(evfd, task -> buffer -> buffer, task -> buffer -> size, task -> opaque);
                    goto _continue;
                } else if(!n) {
                    perror("evfd_readsize");
                    goto _break;
                }
                goto _break;

            case EV_TASK_READLINE: while (1) {
                // 确保line_buffer有足够空间
                if (!evfd->read_buffer) buffer_init(&evfd->read_buffer, NULL, EVFD_BUFSIZE);
                
                if (n <= 0) {
                    if (n == 0) evfd->eof = true;
                    goto _break;
                }
                
                // 扫描换行符
                buffer_expand(evfd->read_buffer);
                uint32_t start = evfd->read_buffer->start;
                uint32_t end = start + evfd->read_buffer->end;
                uint8_t* p = start + evfd->read_buffer->buffer;

                for (uint32_t i = 0; i < end; i ++, p++) {
                    if(i > evfd -> read_buffer -> size) p -= evfd -> read_buffer -> size;

                    if (*p == '\n') {
                        // CRLF换行符
                        if(i != 0 && *(p-1) == '\r') p -= 1;
                        
                        // 复制到用户buffer
                        uint32_t readed;
                        uint8_t* buf = buffer_sub_export(evfd -> read_buffer, 
                            evfd -> read_buffer -> start, (i - start), &readed);

                        // 修改buffer状态
                        buffer_seek(evfd -> read_buffer, i - start + 1);
                        
                        // 触发回调
                        task->cb.read(evfd, buf, readed, task->opaque);
                        goto _continue;
                    }
                }
                
                // 缓冲区满但未找到换行符
                if (buffer_used(evfd -> read_buffer) >= task -> buffer -> size) {
                    buffer_copyto(evfd -> read_buffer, task -> buffer -> buffer, task -> buffer -> size);
                    task->cb.read(evfd, task -> buffer -> buffer, task -> buffer -> size, task -> opaque);
                    buffer_clear(evfd -> read_buffer);
                    goto _continue;
                }
            }
        
            case EV_TASK_READONCE: // readonce
                // int available;
                // ioctl(fd, FIONREAD, &available);
                // available = available > task->total_size ? task->total_size : available;

                buffer_copyto(evfd -> read_buffer, task -> buffer -> buffer, task -> buffer -> size);
                task->cb.read(evfd, task -> buffer -> buffer, task -> buffer -> size, task -> opaque);
                buffer_clear(evfd -> read_buffer);
                goto _continue;

            _continue:
                list_del(&task->list);
                evloop_events --;
                free(task);
                continue;

            _break:
                list_del(&task->list);
                evloop_events --;
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
    if(ioctl(fd, BLKSSZGET, &blksize) == -1) return 1024;
    return blksize;
}

static bool check_aio_alignment(EvFD* evfd, struct Buffer* buf, off_t offset) {
    int blksize = blksize_get(evfd->fd[1]);
    
    if ((uintptr_t)buf->buffer % blksize != 0 || offset % blksize != 0)
        return false;
    
    buf->size = (buf->size / blksize) * blksize;
    return true;
}

static bool check_and_read_direct(EvFD* evfd, struct Task* task) {
    int blksize = blksize_get(evfd->fd[1]);
    
    // 仅处理小于块大小的读取
    if (task->buffer->size >= blksize) 
        return false;

    ssize_t n = read(evfd->fd[1], task->buffer->buffer, task->buffer->size);
    if (n == task->buffer->size) {
        task->cb.read(evfd, task->buffer->buffer, n, task->opaque);
        return true;
    } else if (n > 0) {
        // 部分读取需要重新调整任务
        task->buffer->start += n;
        task->buffer->size -= n;
    }
    return false;
}

static void merge_read_tasks(EvFD* evfd) {
    struct list_head *cur, *next;
    struct Task *prev = NULL;
    int blksize = blksize_get(evfd->fd[1]);
    
    list_for_each_safe(cur, next, &evfd->read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        
        if (prev && (prev->buffer->start + prev->buffer->size == task->buffer->start)) {
            // 合并缓冲区（需要确保是线性buffer）
            if ((prev->buffer->size + task->buffer->size) % blksize == 0) {
                buffer_merge(prev->buffer, task->buffer);
                list_del(&task->list);
                free(task);
                evloop_events--;
            } else {
                prev = task;
            }
        } else {
            prev = task;
        }
    }
}

static void merge_write_tasks(EvFD* evfd) {
    struct list_head *cur, *next;
    struct Task *prev = NULL;
    
    list_for_each_safe(cur, next, &evfd->write_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        
        if (prev && (prev->buffer->end + prev->buffer->start == task->buffer->start)) {
            // 合并缓冲区
            buffer_merge(prev->buffer, task->buffer);
            list_del(&task->list);
            free(task);
            evloop_events--;
        } else {
            prev = task;
        }
    }
}

static inline int submit_aio_read(EvFD* evfd, struct Task* task){
    // buffer对齐
    buffer_aligned(task -> buffer, blksize_get(evfd->fd[1]));

    // 提交io事务
    struct iocb iocb = {
        .aio_fildes = evfd->fd[1],
        .aio_lio_opcode = IOCB_CMD_PREAD,
        .aio_buf = (unsigned long long)task -> buffer -> buffer,
        .aio_nbytes = task -> buffer -> size,
        .aio_offset = task -> buffer -> start,
        .aio_data = (uint64_t)task,
        .aio_flags = IOCB_FLAG_RESFD,
        .aio_resfd = evfd->fd[0],
    };
    int ret = io_submit(evfd -> aio_ctx, 1, (struct iocb*[1]){&iocb});
#ifdef LJS_DEBUG
    printf("submit_aio_read: fd=%d, size=%d, ret=%d\n", evfd->fd[1], task->buffer->size, ret);
    if(ret == -1) perror("io_submit");
#endif
    return ret;
}

// 注意这里的buffer不能circular
static inline int submit_aio_write(EvFD* evfd, struct Task* task) {
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
        .aio_nbytes = task -> buffer -> end,
        .aio_offset = task -> buffer -> start,
        .aio_data = (uint64_t)task,
        .aio_flags = IOCB_FLAG_RESFD,
        .aio_resfd = evfd->fd[0],
    };
    int ret = io_submit(evfd -> aio_ctx, 1, (struct iocb*[1]){&iocb});

#ifdef LJS_DEBUG
    printf("submit_aio_write: fd=%d, remain=%d, ret=%d\n", evfd->fd[1], task->aio_write_remain, ret);
#endif
    return ret;
}

static void handle_write(int fd, EvFD* evfd, struct iocb* iocb) {
    struct list_head *cur, *tmp;
    // 只考虑aio、fd write
    list_for_each_safe(cur, tmp, &evfd->write_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);

        if(evfd -> type == EVFD_AIO){
            task -> aio_write_remain -= iocb -> aio_nbytes;
            // 完成！
            if(task -> aio_write_remain == 0){
                task -> cb.write(evfd, task -> opaque);

                evloop_events --;
                list_del(&task->list);
                free(task);
                
                // 添加io事务：下一个io
                if(!list_empty(&evfd->write_tasks)){
                    struct Task* next_task = list_entry(evfd->write_tasks.next, struct Task, list);
                    submit_aio_write(evfd, next_task);
                }

                return;
            }
        }

        ssize_t n = buffer_write(task -> buffer, fd, UINT32_MAX);
        if (n > 0) {

#ifdef LJS_DEBUG
            printf("evfd_write: fd=%d, n=%ld, remain=%d\n", fd, n, buffer_used(task -> buffer));
#endif

            if(buffer_is_empty(task -> buffer)){
                // 全部写入
                task -> cb.write(evfd, task -> opaque);
                evloop_events --;
                list_del(&task->list);
                free(task);
            }
        } else if (errno == EAGAIN) {
            break;
        } else {
            perror("write");
            break;
        }
    }

    check_queue_status(evfd, fd);
}

static void handle_close(int fd, void* _evfd) {
    EvFD* evfd = (EvFD*)_evfd;
    struct list_head *cur, *tmp;
    // read queue
    list_for_each_safe(cur, tmp, &evfd->read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        free(task);
        evloop_events --;
    }

    // write queue
    list_for_each_safe(cur, tmp, &evfd->write_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        free(task);
        evloop_events --;
    }

    // close queue
    list_for_each_safe(cur, tmp, &evfd->close_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        task -> cb.close(fd, task -> opaque);
        free(task);
        evloop_events --;
    }

    // 关闭fd
    if(!evfd -> eof) switch (evfd -> type){
        case EVFD_NORM:
        case EVFD_TIMER:
            close(fd);
        break;

        case EVFD_AIO:
        case EVFD_INOTIFY:
            io_destroy(evfd -> aio_ctx);
        break;
    }
    if(evfd -> read_buffer) buffer_free(evfd -> read_buffer);
    free(evfd);
}

static void handle_sync(EvFD* evfd){
    struct list_head *cur, *tmp;
    // read queue
    list_for_each_safe(cur, tmp, &evfd->read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        task -> cb.sync(evfd, task -> opaque);
        if(task -> type == EV_TASK_SYNCONCE) {
            evloop_events --;
            list_del(&task->list);
            free(task);
        }
    }
}

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

bool LJS_evcore_run(bool (*evloop_abort_check)(void* user_data), void* user_data) {
    struct epoll_event events[MAX_EVENTS];
    while (1) {
        if ((evloop_abort_check ? evloop_abort_check(user_data) : true) && evloop_events <= 0){
#ifdef LJS_DEBUG
            printf("evloop_abort_check: abort\n");
#endif
            return true; // no events
        }

#ifdef LJS_DEBUG
        printf("epoll_wait: enter, events=%ld\n", evloop_events);
#endif

        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
        }
        
        for (int i = 0; i < nfds; ++i) {
            struct EvFD* evfd = events[i].data.ptr;
                
            if (events[i].events & EPOLLIN) switch(evfd->type){
                case EVFD_NORM:
                case EVFD_TIMER:
                    handle_read(evfd->fd[0], evfd, NULL, NULL);
                break;

                case EVFD_AIO:
                    struct io_event events[MAX_EVENTS];
                    struct timespec timeout = {0, 0};
                    int ret = io_getevents(evfd->aio_ctx, 1, MAX_EVENTS, events, &timeout);
                    if (ret < 0) {
                        perror("io_getevents");
                        break;
                    }
                    for (int j = 0; j < ret; ++j) {
                        struct iocb* iocb = (struct iocb*)events[j].obj;
                        if(iocb -> aio_flags & IOCB_CMD_PREAD)
                            handle_read(evfd->fd[0], evfd, iocb, NULL);
                        else if(iocb -> aio_flags & IOCB_CMD_PWRITE)
                            handle_write(evfd->fd[1], evfd, iocb);
                        else if(iocb -> aio_flags & IOCB_CMD_FSYNC)
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
            }

            if (events[i].events & EPOLLOUT)
                handle_write(evfd -> fd[0], evfd, NULL);
            if (events[i].events & (EPOLLERR | EPOLLHUP))
                handle_close(evfd->fd[0], evfd);
        }
    }

    close(epoll_fd);
    return true;
}

/**
 * 将fd附加到eventloop。
 * 返回-1表示出错，0表示成功，>0表示使用AIO的evfd。
 */
// 将fd附加到事件循环
int LJS_evcore_attach(int fd, bool use_aio, EvReadCallback rcb, EvWriteCallback wcb,
                      EvCloseCallback ccb, void* opaque) {
    // fd是否有效？
    if (fd < 0 || (fcntl(fd, F_GETFL, 0) == -1 && errno == EBADF)) {
        perror("fcntl");
        return -1;
    }

    // O_DIRECT
    if(use_aio) fcntl(fd, F_SETFL, O_DIRECT | fcntl(fd, F_GETFL, 0));

    EvFD* evfd = malloc(sizeof(EvFD));
    if (!evfd) return -1;

    // 初始化任务队列
    init_list_head(&evfd->read_tasks);
    init_list_head(&evfd->write_tasks);
    init_list_head(&evfd->close_tasks);

    // 设置文件类型
    if (use_aio) {
        if (io_setup(128, &evfd->aio_ctx) < 0) {
            free(evfd);
            close(fd);
            return -1;
        }
        evfd->type = EVFD_AIO;
        evfd->fd[0] = fd;  // 原始fd
        evfd->fd[1] = -1;  // aio使用虚拟fd
    } else {
        evfd->type = EVFD_NORM;
        evfd->fd[0] = fd;
    }

    // 注册到epoll
    uint32_t evflag = EPOLLET;
    if (rcb) evflag |= EPOLLIN; // TODO: evloop_events ++
    if (wcb) evflag |= EPOLLOUT;
    if (ccb) evflag |= EPOLLERR | EPOLLHUP;
    struct epoll_event ev = {
        .events = evflag,
        .data.ptr = evfd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        perror("epoll_ctl");
        free(evfd);
        return -1;
    }

    // 设置默认回调
    if (rcb) LJS_evfd_read(evfd, 4096, NULL, rcb, opaque);
    if (wcb) LJS_evfd_write(evfd, NULL, 0, wcb, opaque);
    if (ccb) {
        struct Task* task = malloc(sizeof(struct Task));
        task->cb.close = ccb;
        task->opaque = opaque;
        list_add(&task->list, &evfd->close_tasks);
    }

    return use_aio ? evfd->aio_ctx : 0;
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
    EvFD* evfd = malloc(sizeof(struct EvFD));
    if (!evfd) return NULL;

    // 初始化任务队列
    init_list_head(&evfd->read_tasks);
    init_list_head(&evfd->write_tasks);
    init_list_head(&evfd->close_tasks);

    // 初始化缓冲区
    if (bufsize > 0) {
        buffer_init(&evfd->read_buffer, NULL, bufsize);
    }

    // 设置基础参数
    evfd->fd[0] = fd;
    evfd->fd[1] = -1;
    evfd->type = EVFD_NORM;
    evfd->active = true;
    evfd->eof = false;
    evfd->epoll_flags = EPOLLET;

    // 注册关闭回调
    if (close_callback) {
        struct Task* task = malloc(sizeof(struct Task));
        task->cb.close = close_callback;
        task->opaque = close_opaque;
        list_add(&task->list, &evfd->close_tasks);
    }

    // 判断是否为文件IO, aio
    if (use_aio) {
        evfd -> type = EVFD_AIO;
        evfd -> fd[1] = fd;
        fd = evfd -> fd[0] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (evfd -> fd[0] == -1) {
            perror("eventfd");
            free(evfd);
            return NULL;
        }
    } else {
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));        
    }

    // 添加到evloop
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET,
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

// 提交读取固定大小的请求
bool LJS_evfd_readsize(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                      EvReadCallback callback, void* user_data) {
    struct Task* task = malloc(sizeof(struct Task));
    if (!task) return false;

    // 初始化buffer
    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size);

    task->type = EV_TASK_READ;
    task->buffer = buf;
    task->cb.read = callback;
    task->opaque = user_data;

    if(evfd -> type == EVFD_AIO) {
        // 尝试直接读取
        if (check_and_read_direct(evfd, task)) {
            free(task);
            buffer_free(buf);
            return true;
        }
        
        // 合并相邻任务
        merge_read_tasks(evfd);
        
        // 提交AIO
        if (submit_aio_read(evfd, task)) {
            free(task);
            buffer_free(buf);
            return false;
        }
    }
    list_add(&task->list, &evfd->read_tasks);
    check_queue_status(evfd, evfd->fd[0]);
    evloop_events ++;

#ifdef LJS_DEBUG
    printf("new readsize task fd:%d, bufsize:%d\n", evfd->fd[0], buf_size);
#endif

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
    
    if(evfd -> type == EVFD_AIO && submit_aio_read(evfd, task)){
        free(task);
        buffer_free(buf);
        return false;
    }
    list_add(&task->list, &evfd->read_tasks);
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
    list_add(&task->list, &evfd->read_tasks);

#ifdef LJS_DEBUG
    if(evfd -> type == EVFD_AIO)
        printf("warn: aio is not supported for readonce\n");
#endif

    if(evfd -> type == EVFD_AIO) {
        // 尝试直接读取
        if (check_and_read_direct(evfd, task)) {
            free(task);
            buffer_free(buf);
            return true;
        }
        
        // 合并相邻任务
        merge_read_tasks(evfd);
        
        // 提交AIO
        if (submit_aio_read(evfd, task)) {
            free(task);
            buffer_free(buf);
            return false;
        }
    }
    list_add(&task->list, &evfd->read_tasks);
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
    buf->end = size; // 预填充数据

    task->type = EV_TASK_WRITE;
    task->buffer = buf;
    task->cb.write = callback;
    task->opaque = user_data;
    list_add(&task->list, &evfd->write_tasks);

    evloop_events ++;
    if (evfd->type == EVFD_AIO) {
        // 小数据直接同步写入
        if (size < blksize_get(evfd->fd[1])) {
            ssize_t n = write(evfd->fd[1], data, size);
            if (n == size) {
                callback(evfd, user_data);
                free(task);
                return true;
            }
        }
        
        // 合并相邻任务
        merge_write_tasks(evfd);
        
        // 提交AIO
        if (!submit_aio_write(evfd, task)) {
            buffer_free(buf);
            list_del(&task->list);
            free(task);
            return false;
        }
    }else{
        handle_write(evfd->fd[0], evfd, NULL);
    }

#ifdef LJS_DEBUG
    printf("new write task fd:%d, bufsize:%d\n", evfd->fd[0], size);
#endif

    return true;
}

// 关闭evfd
bool LJS_evfd_close(EvFD* evfd) {
    if (!evfd || !evfd->active) return false;
    handle_close(evfd->fd[0], evfd);
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, evfd->fd[0], NULL);
    evfd->active = false;
    return true;
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
    struct timespec itsn = {0};
    struct itimerspec its = {
        .it_value = itss,
        .it_interval = once ? itsn : itss
    };
    
    if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL) == -1) {
        perror("timerfd_settime");
        close(fd);
        return NULL;
    }

    // 创建定时器对象
    struct EvFD* evfd = malloc(sizeof(struct EvFD));
    if(evfd == NULL) LJS_panic("malloc failed");

    // 初始化任务队列
    init_list_head(&evfd->read_tasks);
    init_list_head(&evfd->write_tasks);
    init_list_head(&evfd->close_tasks);

    // 设置基础参数
    evfd->fd[0] = fd;
    evfd->type = EVFD_TIMER;

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
    list_add(&task->list, &evfd->read_tasks);
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
            list_for_each_safe(pos, tmp, &evfd->read_tasks) {
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
    init_list_head(&evfd->read_tasks);

    // 创建缓冲区
    buffer_init(&evfd->read_buffer, NULL, 4096); 

    // 设置inotify参数
    evfd->fd[0] = inotify_fd;
    evfd->type = EVFD_INOTIFY;
    evfd->active = true;

    // 添加默认读任务
    struct Task* task = malloc(sizeof(struct Task));
    task->type = EV_TASK_READ;
    task->cb.inotify = callback;
    task->opaque = user_data;
    list_add(&task->list, &evfd->read_tasks);

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
    list_for_each_safe(pos, tmp, &evfd->read_tasks) {
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