#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <threads.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <linux/aio_abi.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// #undef LJS_DEBUG    // debug

#include "../engine/cutils.h"
#include "../engine/list.h"
#include "utils.h"
#include "core.h"

#ifdef LJS_MBEDTLS
#include <mbedtls/mbedtls_config.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

#ifndef MBEDTLS_X509_CRT_PARSE_C
#error "The build of MbedTLS does not support X509 certificates."
#endif

#endif

#ifndef free2
#define free2 free
#define malloc2 malloc
#define strdup2 strdup
#endif

#define EPOLLLT 0

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
    EvFD* from;
    EvFD* to;

    EvPipeToFilter filter;
    void* filter_opaque;
    EvPipeToNotify notify;
    void* notify_opaque;

    // alias to task -> buffer
    struct Buffer* exchange_buffer;

    uint8_t ready_state : 4;
    uint8_t closed : 4;
};
#define PIPETO_RCLOSED(p) p & 0b1
#define PIPETO_WCLOSED(p) p & 0b10

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

struct InotifyContext {
    // wd -> string index
    char* paths[MAX_EVENTS];
    char* move_tmp[2];
};

struct EvFD{
    union {
        aio_context_t ctx;
        uint64_t __padding;
    } aio;

    int fd[2];  // if type==EVFD_AIO, fd[1] is the real fd
    enum EvFDType type;

    struct UDPContext* proto_ctx;   // udp
    struct InotifyContext* inotify;

#ifdef LJS_MBEDTLS
    struct EvFD_SSL* ssl;           // for ssl
#endif
    bool task_based;
    union{
        struct{
            struct list_head read_tasks;
            struct list_head write_tasks;
            struct list_head close_tasks;
            EvFinalizerCallback finalizer;
            void* finalizer_opaque;
            
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
    
    struct Buffer* incoming_buffer;
    bool strip_if_is_n; // whether to strip the \n at the start of a line
                        // for readline task when previous buffer is end of \r
    bool destroy;       // whether to destroy the fd before next loop

    int epoll_flags;
    int modify_flag;    // target epoll_flags

    void* opaque;
    struct list_head link;
};

struct TimerFD {
    struct EvFD __pedding;  // offset

    uint64_t time;  // 0 marks unused
    bool once;
    bool executed;
};

static thread_local int epoll_fd = -1;
static thread_local struct list_head timer_list;
static thread_local ssize_t evloop_events = 0;
static atomic_int thread_id = 0;
static int is_aio_supported = -1;

// used when evfd_destroy is called
static thread_local struct list_head evfd_list;

#define INIT_EVFD2(evfd) \
    evfd -> incoming_buffer = NULL; \
    evfd -> destroy = false; \
    evfd -> strip_if_is_n = false; \
    evfd -> u.task.finalizer = NULL; \
    evfd -> modify_flag = 0; \

#define INIT_EVFD(evfd) { \
    INIT_EVFD2(evfd); \
    list_add_tail(&evfd -> link, &evfd_list); \
}

#ifdef LJS_DEBUG
void __trace_debug(int events, int direction) {
    // add trace here
    return;
}
#define TRACE_EVENTS(evfd, add) \
    printf("event_trace: func=%s, line=%d, fd=%d, add=%d, cevents=%ld(thread#%d) \n", __func__, __LINE__, evfd_getfd(evfd, NULL), add, evloop_events, thread_id); \
    __trace_debug(evloop_events, add); \
    evloop_events += add;
#else
#define TRACE_EVENTS(evfd, add) evloop_events += add;
#endif

#define TRACE_NSTDEVENTS(evfd, add) if((evfd) -> fd[0] > STDERR_FILENO){ TRACE_EVENTS(evfd, add); }

// linux_kernel aio syscall
static inline int io_setup(unsigned nr, aio_context_t *ctxp) { 
    return (int)syscall(__NR_io_setup, nr, ctxp); 
} 

static inline int io_destroy(aio_context_t ctx) { 
	return (int)syscall(__NR_io_destroy, ctx); 
} 

static inline int io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp) { 
	return (int)syscall(__NR_io_submit, ctx, nr, iocbpp); 
}

static inline int io_getevents(aio_context_t ctx, long min_nr, long max_nr, struct io_event *events, struct timespec *timeout) { 
	return (int)syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
} 

static inline int io_cancel(aio_context_t ctx, struct iocb *iocb, struct io_event *result) { 
	return (int)syscall(__NR_io_cancel, ctx, iocb, result); 
} 

__attribute__((constructor)) static void evloop_init() {
    struct sigaction act = {
        .sa_handler = SIG_IGN,
        .sa_flags = 0,
    };
    sigaction(SIGPIPE, &act, NULL);

    aio_context_t test_ctx;
    int ret = io_setup(MAX_EVENTS, &test_ctx);
    if(-1 == ret){
#ifdef LJS_DEBUG
        perror("io_setup");
#endif
        is_aio_supported = false;
    }else{
        io_destroy(test_ctx);
    }
    is_aio_supported = true;
}

static void handle_close(int fd, EvFD* evfd);

// 内部辅助函数
#define EPOLL_CTL_FREE -1
static thread_local struct EvFD* evfd_modify_tasks[1024];
static thread_local int evfd_modify_tasks_count = 0;
static inline void evfd_ctl(struct EvFD* evfd, int epoll_flags){
    assert(!evfd -> destroy);
    if(epoll_flags == evfd -> epoll_flags){
        if(evfd -> modify_flag){
            // delete from modify_tasks
            for(int i = 0; i < evfd_modify_tasks_count; i++){
                if(evfd_modify_tasks[i] == evfd){
                    evfd_modify_tasks[i] = evfd_modify_tasks[evfd_modify_tasks_count -1];
                    evfd_modify_tasks_count --;
                    break;
                }
            }
            evfd -> modify_flag = 0;
        }
        return;
    }

    // already modify?
    if(evfd -> modify_flag){
        evfd -> modify_flag = epoll_flags;
        return;
    }

    // assign epoll_flags
    evfd_modify_tasks[evfd_modify_tasks_count++] = evfd;
    evfd -> modify_flag = epoll_flags;

    if(epoll_flags == EPOLL_CTL_FREE){
        // remove from evfd_list
        list_del(&evfd -> link);
    }
}

static inline void evfd_mod(struct EvFD* evfd, bool add, int epoll_flags){
    int flag = evfd -> modify_flag ? evfd -> modify_flag : evfd -> epoll_flags;
    if(add) flag |= epoll_flags;
    else flag &= ~epoll_flags;
    evfd_ctl(evfd, flag);
}

static inline void evfd_mod_start(){
    for(int i = 0; i < evfd_modify_tasks_count; i++){
        struct EvFD* task = evfd_modify_tasks[i];
        if(task -> modify_flag == EPOLL_CTL_FREE){
#ifdef LJS_DEBUG
            printf("evfd_mod_start: free fd=%d\n", task -> fd[0]);
#endif
            task -> fd[0] = -1; // fall safe
            free2(task);
        }else{
            struct epoll_event ev = {
               .events = task -> modify_flag,
               .data.ptr = task
            };
            if(-1 == epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task -> fd[0], &ev)){
#ifdef LJS_DEBUG
                perror("epoll_ctl");
#endif
            }else{
#ifdef LJS_DEBUG
                printf("epoll_ctl: fd=%d, events=%d, r=%d, w=%d\n", task -> fd[0], task -> modify_flag, task -> modify_flag & EPOLLIN, task -> modify_flag & EPOLLOUT);
#endif
                task -> epoll_flags = task -> modify_flag;    
            }
            task -> modify_flag = 0;
        }
    }
    evfd_modify_tasks_count = 0;
}

static inline void free_task(struct Task* task);

// 在handle_read/handle_write中添加队列状态检查
static void check_queue_status(EvFD* evfd, int fd) {
    if(evfd -> destroy) return;

    uint32_t new_events = EPOLLLT;
    switch(evfd -> type){
        case EVFD_AIO:
        case EVFD_TIMER:
        case EVFD_INOTIFY:
            if(!list_empty(&evfd -> u.task.read_tasks) || !list_empty(&evfd -> u.task.write_tasks))
                new_events |= EPOLLIN;
        break;

#ifdef LJS_MBEDTLS
        case EVFD_SSL:
        case EVFD_DTLS:
            new_events |= EPOLLHUP | EPOLLERR;
            if(evfd -> ssl -> ssl_handshaking) new_events |= EPOLLIN | EPOLLOUT;
            else{ 
                if(evfd -> ssl -> ssl_read_wants_write) new_events |= EPOLLOUT;
                if(evfd -> ssl -> ssl_write_wants_read) new_events |= EPOLLIN;
            }
        break;
#endif
        default:
            new_events |= EPOLLHUP | EPOLLERR;
            if(!list_empty(&evfd -> u.task.read_tasks)) new_events |= EPOLLIN;
            if(!list_empty(&evfd -> u.task.write_tasks)) new_events |= EPOLLOUT;
        break;
    }
    
    // 修改epoll事件
    evfd_ctl(evfd, new_events);
}

// buffer
#define CALL_AND_HANDLE(func, blk, ...) int _ret = func(__VA_ARGS__); \
    if (unlikely(evfd -> destroy)) return; \
    if (!unlikely(_ret & EVCB_RET_REWIND)) blk; \
    if (_ret & EVCB_RET_CONTINUE){ \
        /* reuse the same task to read(task resume) */ \
        list_add(&task -> list, &evfd -> u.task.read_tasks); TRACE_EVENTS(evfd, +1); \
        goto main;\
    }

static inline bool pipeto_ready(struct PipeToTask* task){
    if(task -> ready_state == 2) return true;
    return task -> ready_state ++ == 1;
}

static inline void __pipeto_remove_task(struct PipeToTask* task, struct list_head* tlist){
    bool del_task = false; 
    struct list_head* cur, * tmp;
    list_for_each_safe(cur, tmp, tlist) {
        struct Task* t = list_entry(cur, struct Task, list);
        if (t -> type == EV_TASK_PIPETO && t -> cb.pipeto == task) {
            list_del(&t -> list);
            free_task(t);
            del_task = true;
            break;
        }
    }
    assert(del_task);
}

// also handle destroy and done event
// Note: will remove current task from fd
static inline bool pipeto_handle_close(EvFD* evfd, struct PipeToTask* task, bool error) {
    assert(!(PIPETO_RCLOSED(task -> closed) && evfd == task -> from));
    assert(!(PIPETO_WCLOSED(task -> closed) && evfd == task -> to));

    const bool is_from = (evfd == task -> from);
    const bool has_data = !buffer_is_empty(task -> exchange_buffer);

    if (task -> notify) {
        if (error) {
            task -> notify(evfd, task -> to, EV_PIPETO_NOTIFY_CLOSED, task -> notify_opaque);
        }else if (is_from && !has_data) {
            task -> notify(evfd, task -> to, EV_PIPETO_NOTIFY_DONE, task -> notify_opaque);
        }
        task -> notify = NULL;
    }

    task -> closed |= (is_from ? 0b1 : 0b10);

    // remove current pipeto task
    struct list_head* tlist = is_from ? &task -> from -> u.task.read_tasks : &task -> to -> u.task.write_tasks;
    __pipeto_remove_task(task, tlist);
    TRACE_NSTDEVENTS(evfd, -1);

    const bool both_closed = task -> closed == 0b11;
    const bool keep = is_from && has_data && !both_closed;

    if (keep) {
        check_queue_status(task -> to, evfd_getfd(task -> to, NULL));
    } else {
        if (!both_closed) {
            struct list_head* target_list = is_from 
                ? &task -> to -> u.task.write_tasks 
                : &task -> from -> u.task.read_tasks;
            EvFD* fd = is_from ? task -> from : task -> to;
            
            __pipeto_remove_task(task, target_list);
            TRACE_NSTDEVENTS(is_from ? task -> to : task -> from, -1);
            check_queue_status(fd, evfd_getfd(fd, NULL));
        }
        
        free2(task);
    }
    
    return false;
}

static inline void free_task(struct Task* task) {
    if(task -> buffer) buffer_free(task -> buffer);
    free2(task);
}

// 事件处理函数
static void handle_read(int fd, EvFD* evfd, struct io_event* ioev, struct inotify_event* inev) {
    if(list_empty(&evfd -> u.task.read_tasks)) goto end;
    // get data
    struct Task* next_task = list_entry(evfd -> u.task.read_tasks.next, struct Task, list);
    uint32_t n = 0;
    if (evfd -> type == EVFD_NORM) {
        uint8_t* ptr_buffer = evfd -> incoming_buffer -> buffer + evfd -> incoming_buffer -> end;
        n = buffer_read(evfd -> incoming_buffer, fd, UINT32_MAX);

        if (n == -1){ 
#ifdef LJS_DEBUG
            perror("evfd_read");
#endif
            return handle_close(fd, evfd);
        }    // error

        if (n <= 0) return;

        // strip_if_is_\n
        if (evfd -> strip_if_is_n && *ptr_buffer == '\n') {
            buffer_seek_cur(evfd -> incoming_buffer, 1);
            if (n-- == 1) return;
        }
        evfd -> strip_if_is_n = false;
    } else if (evfd -> type == EVFD_AIO/* && iocb */) {
        n = ioev -> res;
        evfd -> u.task.offset += n;
        buffer_push(evfd -> incoming_buffer, (uint8_t*) ((struct iocb*) ioev -> obj) -> aio_buf, n);
    } else if (evfd -> type == EVFD_SSL) {
        // evfd SSL下，只有mbedtls处理后才有数据
        n = buffer_used(evfd -> incoming_buffer);
    } else if (evfd -> type == EVFD_UDP || evfd -> type == EVFD_DTLS) {
        // TODO: buffer_recvfrom
        struct UDPContext* ctx = evfd -> proto_ctx;
        n = recvfrom(fd, evfd -> incoming_buffer -> buffer,
            evfd -> incoming_buffer -> size - evfd -> incoming_buffer -> end, 0,
            (struct sockaddr*) &ctx -> peer_addr,
            &ctx -> addr_len);
        if (n == -1) {
#ifdef LJS_DEBUG
            perror("recvfrom");
#endif
            handle_close(fd, evfd);
            return;
        }
        else if (n == 0) return;
        evfd -> incoming_buffer -> end += n;
    } else if(next_task -> type == EV_TASK_PIPETO){
        if(!pipeto_ready(next_task -> cb.pipeto)){
            // suspend read
            evfd_mod(evfd, false, EPOLLIN);
            return;
        }
        // closed?
        if(PIPETO_WCLOSED(next_task -> cb.pipeto -> closed)){
            // move data back
            struct Buffer* buf = next_task -> cb.pipeto -> exchange_buffer;
            n = buffer_merge2(evfd -> incoming_buffer, buf);
            // finalize task
            free_task(next_task);
        }else{
            // check whether buffer full
            EvFD* to = next_task -> cb.pipeto -> to;
            struct Buffer* buf = next_task -> cb.pipeto -> exchange_buffer;
            if(buffer_is_full(buf)){
                evfd_mod(evfd, false, EPOLLIN); // suspend read
                return;
            }else{
                evfd_mod(to, true, EPOLLOUT);   // wakeup write
                n = buffer_read(buf, fd, UINT32_MAX);
                if (n == -1) { 
#ifdef LJS_DEBUG
                    perror("evfd_read");
#endif
                    return handle_close(fd, evfd);
                }
            }
        }
    }

    struct list_head *cur, *tmp;
    list_for_each_prev_safe(cur, tmp, &evfd -> u.task.read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);

        // linux inotify文件更改事件
        if(evfd -> type == EVFD_INOTIFY){
            char real_path[PATH_MAX +1];

            // find path by wd
            const char* str = evfd -> inotify -> paths[inev -> wd];
            assert(str);
            size_t len = strlen(str);
            memcpy(real_path, str, len +1);

            if(inev -> len){
                memcpy(real_path + len, inev -> name, inev -> len);
                len += inev -> len -1;  // note: len include \0
            }

            if(inev -> cookie & IN_MOVED_FROM){
                evfd -> inotify -> move_tmp[0] = strdup2(real_path);
                goto inev_move;
            }else if(inev -> cookie & IN_MOVED_TO){
                evfd -> inotify -> move_tmp[1] = strdup2(real_path);
                goto inev_move;
            }

            // callback
            task -> cb.inotify(evfd, real_path, inev -> mask, NULL, task -> opaque);
            continue;

inev_move:
            if(!(
                evfd -> inotify -> move_tmp[0] &&
                evfd -> inotify -> move_tmp[1]
            )) continue;
            // handle move event
            task -> cb.inotify(evfd, evfd -> inotify -> move_tmp[0], IN_MOVE, NULL, task -> opaque);
            free2(evfd -> inotify -> move_tmp[0]);
            evfd -> inotify -> move_tmp[0] = NULL;
            free2(evfd -> inotify -> move_tmp[1]);
            evfd -> inotify -> move_tmp[1] = NULL;
            continue;
            
        }else if(evfd -> type == EVFD_TIMER){
            // read timerfd to get count
            uint64_t val;
            if(sizeof(val) == read(fd, &val, sizeof(val))){
                task -> cb.timer(val, task -> opaque);
                // will be reused, clear current task
                if(((struct TimerFD*)evfd) -> once){
                    list_del(&task -> list);
                    TRACE_EVENTS(evfd, -1);
                    free2(task);
                }
            }else{
#ifdef LJS_DEBUG
                perror("timerfd read");
#endif
            }
            continue;
        }

        TRACE_EVENTS(evfd, -1);
        list_del(cur); // avoid recursive call

        if(task -> type == EV_TASK_NOOP){
            task -> cb.sync(evfd, true, task -> opaque);
            continue;
        }

main:   // while loop
        uint32_t bufsize = buffer_used(evfd -> incoming_buffer);
        if(bufsize == 0) goto end;
        switch(task -> type){
            case EV_TASK_READ: // readsize
                // note: buffer contains 1 byte free space to maintain circular buffer
                if (task -> buffer -> size -1 <= bufsize) {
                    // export
                    buffer_copyto(evfd -> incoming_buffer, task -> buffer -> buffer, task -> buffer -> size);
                    CALL_AND_HANDLE(
                        task -> cb.read,
                        { buffer_seek(evfd -> incoming_buffer, evfd -> incoming_buffer -> end); }, 
                        evfd, task -> buffer -> buffer, task -> buffer -> size -1, task -> opaque
                    );
                    goto _continue;
                } else if(-1 == n) {
#ifdef LJS_DEBUG
                    perror("evfd_readsize");
#endif
                    TRACE_EVENTS(evfd, +1); handle_close(fd, evfd);
                    goto _break;
                }
                goto __break;

            case EV_TASK_READLINE:
                if (n <= 0) {
                    if (n == 0){
                        TRACE_EVENTS(evfd, +1); handle_close(fd, evfd);
                    }
                    goto _break;
                }
                
                // find \r\n or \n
                char forward_char = 0;
                uint32_t first_r_occurrence = UINT32_MAX;
                uint32_t first_r_bytes = 0;
                BUFFER_FOREACH_BYTE(evfd -> incoming_buffer, bytes, chr) {
                    uint32_t i = __i;   // note: __i is index of current byte in buffer    
                    if (chr == '\n') {
                        char* nchr = (void*)(evfd -> incoming_buffer -> buffer + i);
                        // CRLF check: replace to end-of-line with \0
                        if(i != 0 && forward_char == '\r') nchr -= 1;
                        *nchr = '\0';
                        
                        // Copy buffer to task buffer
                        uint32_t readed = buffer_copyto(evfd -> incoming_buffer, task -> buffer -> buffer, bytes);

                        // Trigger callback
                        CALL_AND_HANDLE(
                            task -> cb.read,
                            { buffer_seek(evfd -> incoming_buffer, i +1); },
                            evfd, task -> buffer -> buffer, readed, task -> opaque
                        );
                        goto _continue;
                    } else if(first_r_occurrence == UINT32_MAX && chr == '\r'){
                        // fallback if \n not found
                        first_r_occurrence =i;
                        first_r_bytes = bytes;
                    }

                    forward_char = chr;
                }

                // fallback: \r
                if(first_r_occurrence != UINT32_MAX){
                    evfd -> strip_if_is_n = true;
                    char* rchr = (void*)(evfd -> incoming_buffer -> buffer + first_r_occurrence);
                    *rchr = '\0';

                    uint32_t readed = buffer_copyto(evfd -> incoming_buffer, task -> buffer -> buffer, first_r_bytes);
                    CALL_AND_HANDLE(
                        task -> cb.read,
                        { buffer_seek(evfd -> incoming_buffer, first_r_occurrence +1); },
                        evfd, task -> buffer -> buffer, readed, task -> opaque
                    );
                    
                    goto _continue;
                }
                
                // Buffer full?
                // Note: buffer contains 1 byte free space to maintain circular buffer and \0 terminator
                if (bufsize >= (task -> buffer -> size -2)) {
                    *(task -> buffer -> buffer + task -> buffer -> size -2) = '\0';
                    buffer_copyto(evfd -> incoming_buffer, task -> buffer -> buffer, task -> buffer -> size -2);
                    CALL_AND_HANDLE(
                        task -> cb.read,
                        { buffer_seek_cur(evfd -> incoming_buffer, task -> buffer -> size -2); },
                        evfd, task -> buffer -> buffer, task -> buffer -> size -2, task -> opaque
                    )
                    goto _continue;
                }

                // Not found
                goto __break;
        
            case EV_TASK_READONCE: // readonce
                // int available;
                // ioctl(fd, FIONREAD, &available);
                // available = available > task -> total_size ? task -> total_size : available;

                buffer_copyto(evfd -> incoming_buffer, task -> buffer -> buffer, n);
                size_t n2 = n;  // backup
                n = 0;          // avoid reuse used data
                CALL_AND_HANDLE(
                    task -> cb.read,
                    { buffer_seek_cur(evfd -> incoming_buffer, n2); },
                    evfd, task -> buffer -> buffer, n2, task -> opaque
                )
                goto _continue;

            // Note: the main logic of pipeto is in handle_write
            case EV_TASK_PIPETO:
                // filter
                EvPipeToFilter filter = task -> cb.pipeto -> filter;
                struct Buffer* buf = task -> cb.pipeto -> exchange_buffer;
                if(filter && !filter(buf, task -> cb.pipeto -> filter_opaque)){
                    // skip current chunk
                    buffer_seek_cur(buf, n);
                }else{
                    // push to target buffer
                    assert(buffer_merge2(task -> cb.pipeto -> to -> incoming_buffer, buf) == n);
                }
            return;   // block task execution

            _continue:
                if(evfd -> destroy) return;   // task already destroyed
                free_task(task);
                continue;

            __break:
                if(evfd -> destroy) return;
                list_add(&task -> list, &evfd -> u.task.read_tasks);
                TRACE_EVENTS(evfd, +1);
                break;

            _break:
                if(evfd -> destroy) return;   // task already destroyed
                free_task(task);
                break;

            default:    // never reach here
                abort();
        }
    }

end:
    // finalize for timerfd
    if(evfd -> type == EVFD_TIMER){
        struct TimerFD* tfd = (void*) evfd;
        if (tfd -> once) {
            tfd -> time = 0;
            evfd_ctl(evfd, EPOLLLT);    // disable timerfd
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
    int blksize = blksize_get(evfd -> fd[1]);
    
    if ((uintptr_t)buf -> buffer % blksize != 0 || offset % blksize != 0)
        return false;
    
    buf -> size = (buf -> size / blksize) * blksize;
    return true;
}
#endif

static inline int submit_aio_read(EvFD* evfd, struct Task* task){
    if(!is_aio_supported) return -1;

    // buffer对齐
    buffer_aligned(task -> buffer, blksize_get(evfd -> fd[1]));

    // 提交io事务
    struct iocb iocb = {
        .aio_fildes = evfd -> fd[1],
        .aio_lio_opcode = IOCB_CMD_PREAD,
        .aio_buf = (unsigned long long)task -> buffer -> buffer,
        .aio_nbytes = task -> buffer -> size -1,
        .aio_offset = evfd -> u.task.offset,
        .aio_data = (uint64_t)task,
        .aio_flags = IOCB_FLAG_RESFD,
        .aio_resfd = evfd -> fd[0],
    };
    int ret = io_submit(evfd -> aio.ctx, 1, (struct iocb*[1]){&iocb});
#ifdef LJS_DEBUG
    printf("submit_aio_read: fd=%d, size=%d, ret=%d\n", evfd -> fd[1], task -> buffer -> size -1, ret);
    if(ret == -1) perror("io_submit");
#endif
    return ret;
}

// 注意这里的buffer不能circular
static inline int submit_aio_write(EvFD* evfd, struct Task* task) {
    if(!is_aio_supported) return -1;

    // buffer对齐，适配aio
    buffer_aligned(task -> buffer, blksize_get(evfd -> fd[1]));
    task -> aio_write_remain = task -> buffer -> size -1;
    
    // 检查最终对齐有效性
#ifdef LJS_DEBUG
    if (!check_aio_alignment(evfd, task -> buffer, task -> buffer -> start)) {
        printf("buffer not aligned, start=%d, size=%d\n", task -> buffer -> start, task -> buffer -> size);
        return -1;
    }
#endif

    struct iocb iocb = {
        .aio_fildes = evfd -> fd[1],
        .aio_lio_opcode = IOCB_CMD_PWRITE,
        .aio_buf = (unsigned long long)task -> buffer -> buffer,
        .aio_nbytes = task -> buffer -> size -1,
        .aio_offset = evfd -> u.task.offset,
        .aio_data = (uint64_t)task,
        .aio_flags = IOCB_FLAG_RESFD,
        .aio_resfd = evfd -> fd[0],
    };
    int ret = io_submit(evfd -> aio.ctx, 1, (struct iocb*[1]){&iocb});

#ifdef LJS_DEBUG
    printf("submit_aio_write: fd=%d, remain=%d, ret=%d\n", evfd -> fd[1], task -> aio_write_remain, ret);
    if(ret == -1) perror("io_submit");
#endif
    return ret;
}

static void handle_write(int fd, EvFD* evfd, struct io_event* ioev) {
    struct list_head *cur, *tmp;
    // 只考虑aio、fd write
// loop:
    list_for_each_prev_safe(cur, tmp, &evfd -> u.task.write_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);

        if(evfd -> type == EVFD_AIO){
            task -> aio_write_remain -= ioev -> res;
            evfd -> u.task.offset += ioev -> res;
            // 完成！
            if(task -> aio_write_remain == 0){
                TRACE_EVENTS(evfd, -1);
                list_del(&task -> list);

                task -> cb.write(evfd, true, task -> opaque);
                
                free_task(task);
                // 添加io事务：下一个io
                if(!list_empty(&evfd -> u.task.write_tasks)){
                    struct Task* next_task = list_entry(evfd -> u.task.write_tasks.next, struct Task, list);
                    submit_aio_write(evfd, next_task);
                }
            }
            return;
        }else if(task -> type == EV_TASK_PIPETO){
            struct PipeToTask* pt = task -> cb.pipeto;

            if(!pipeto_ready(pt)){
                // suspend write
                evfd_mod(evfd, false, EPOLLOUT);
                return;
            }

            // XXX: this action break the write logic
            // and not capable to handle AIO write
            ssize_t writed = buffer_write(pt -> exchange_buffer, fd, UINT32_MAX);

            if(writed == -1){
#ifdef LJS_DEBUG
                perror("evfd_write");
#endif
                return handle_close(fd, evfd);
            }

            if(buffer_is_empty(task -> buffer)){
                // suspense
                if(PIPETO_RCLOSED(pt -> closed)){
                    pipeto_handle_close(evfd, pt, false);
                    continue;   // next task
                }else{
                    evfd_mod(pt -> from, true, EPOLLIN);
                    return evfd_mod(evfd, false, EPOLLOUT);
                }
            }else{
                // wait for next write
                evfd_mod(evfd, true, EPOLLOUT);
                return;
            }
        }else if(task -> type == EV_TASK_NOOP){
            list_del(&task -> list);
            TRACE_EVENTS(evfd, -1);
            
            task -> cb.sync(evfd, true, task -> opaque);
            
            free2(task);
            continue;
        }

        ssize_t n = buffer_write(task -> buffer, fd, UINT32_MAX);
        if (n > 0) {
            if(buffer_is_empty(task -> buffer)){
                TRACE_EVENTS(evfd, -1);
                list_del(&task -> list);
                if(task -> cb.write) task -> cb.write(evfd, true, task -> opaque);
                free_task(task);
            }
        } else if(n == -1){
#ifdef LJS_DEBUG
            perror("evfd_write");
#endif
            return handle_close(fd, evfd);
        } else {
            break;  // fd is busy
        }
    }
    // if(!list_empty(&evfd -> u.task.write_tasks)) goto loop;

    check_queue_status(evfd, fd);
}

static thread_local bool __handle_closing = false;
static void clear_tasks(EvFD* evfd, bool call_close) {
    if(__handle_closing) return;
    __handle_closing = true;
    struct list_head* cur, * tmp;
    bool has_data = evfd -> incoming_buffer && !buffer_is_empty(evfd -> incoming_buffer);
    // read queue
    list_for_each_prev_safe(cur, tmp, &evfd -> u.task.read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        if (task -> type == EV_TASK_NOOP){
            task -> cb.sync(evfd, false, task -> opaque);
            goto _continue;
        }
        if (task -> type == EV_TASK_PIPETO){ 
            evfd -> u.task.read_tasks.next = cur;  // delete elements between cur and first
            cur -> prev = &evfd -> u.task.read_tasks;
            pipeto_handle_close(evfd, task -> cb.pipeto, true); // also freed task
            continue;
        }
        
        if (task -> cb.read) {
            if (has_data) {
                // copy to user buffer
                uint32_t readed = buffer_copyto(evfd -> incoming_buffer, task -> buffer -> buffer, task -> buffer -> size -1);

                // Note: readline requires \0 terminator
                if (task -> buffer -> end < task -> buffer -> size -1 && task -> type == EV_TASK_READLINE) 
                    task -> buffer -> buffer[task -> buffer -> end] = '\0';    // end with \0

                task -> cb.read(evfd, task -> buffer -> buffer, readed, task -> opaque);
                has_data = false;
            } else {
            //     task -> cb.sync(evfd, task -> opaque);
                task -> cb.read(evfd, NULL, 0, task -> opaque);
            }
        }
        if (task -> buffer){
            buffer_free(task -> buffer);
        }

_continue:
        free2(task);
        TRACE_EVENTS(evfd, -1);
    }
    if(evfd -> u.task.finalizer){
        evfd -> u.task.finalizer(evfd, evfd -> incoming_buffer, evfd -> u.task.finalizer_opaque);
        evfd -> u.task.finalizer = NULL;
    }

    // write queue
    list_for_each_prev_safe(cur, tmp, &evfd -> u.task.write_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        if(task -> type == EV_TASK_PIPETO){
            evfd -> u.task.write_tasks.next = cur;  // delete elements between cur and first
            cur -> prev = &evfd -> u.task.write_tasks;
            pipeto_handle_close(evfd, task -> cb.pipeto, true); // also freed task
            continue;
        }
        if (task -> type == EV_TASK_NOOP){
            task -> cb.sync(evfd, false, task -> opaque);
            goto _continue2;
        }
        if(task -> cb.write) {
            if(task -> type == EV_TASK_NOOP)
                task -> cb.sync(evfd, true, task -> opaque);
            else
                task -> cb.write(evfd, true, task -> opaque);
        }
        if(task -> buffer) buffer_free(task -> buffer);

_continue2:
        free2(task);
        TRACE_EVENTS(evfd, -1);
    }

    // close queue
    if(call_close)
        list_for_each_prev_safe(cur, tmp, &evfd -> u.task.close_tasks) {
            struct Task* task = list_entry(cur, struct Task, list);
            task -> cb.close(evfd, task -> opaque);
            free2(task);
            TRACE_NSTDEVENTS(evfd, -1);
        }
    __handle_closing = false;
}

static void handle_close(int fd, EvFD* evfd) {
    if(__handle_closing) return;
    __handle_closing = true;

#ifdef LJS_DEBUG
    printf("handle_close: fd=%d; ", fd);
#endif

    if(evfd -> destroy) return;

    // free in next loop
    evfd_ctl(evfd, EPOLL_CTL_FREE);
    evfd -> destroy = true;

    // remove in epoll
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    TRACE_NSTDEVENTS(evfd, -1);

    if(evfd -> task_based){
        __handle_closing = false;
        clear_tasks(evfd, true);
        __handle_closing = true;
    }else if(evfd -> u.cb.close){ 
        evfd -> u.cb.close(evfd, evfd -> u.cb.close_opaque);
    }

    // close fd
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
            if (evfd -> ssl) {
                buffer_free(evfd -> ssl -> sendbuf);
                buffer_free(evfd -> ssl -> recvbuf);
                mbedtls_ssl_free2(&evfd -> ssl -> ctx);
                mbedtls_ssl_config_free2(&evfd -> ssl -> config);
                free2(evfd -> ssl);
            }
#endif
        break;

        default:
            abort();
        break;
    }
    if(evfd -> incoming_buffer) buffer_free(evfd -> incoming_buffer);

    __handle_closing = false;
}

static void handle_sync(EvFD* evfd){
    struct list_head *cur, *tmp;
    // read queue
    list_for_each_prev_safe(cur, tmp, &evfd -> u.task.read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        task -> cb.sync(evfd, true, task -> opaque);
        if(task -> type == EV_TASK_SYNC) {
            TRACE_EVENTS(evfd, -1);
            list_del(&task -> list);
            free2(task);
        }
    }
}

#ifdef LJS_MBEDTLS
static int handle_ssl_send(void* ctx, const unsigned char* buf, size_t len) {
    EvFD* evfd = (EvFD*)ctx;
    struct Buffer* sendbuf = evfd -> ssl -> sendbuf;
    
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
    size_t copied = buffer_copyto(evfd -> ssl -> recvbuf, buf, len);
    handle_read(evfd -> fd[0], evfd, NULL, NULL);
    return copied;
}

static inline void update_ssl_events(EvFD* evfd) {
    uint32_t events = EPOLLLT | EPOLLERR | EPOLLHUP;
    
    if (evfd -> ssl -> ssl_handshaking) {
        if (evfd -> ssl -> ssl_read_wants_write) {
            events |= EPOLLOUT;
        } else {
            events |= EPOLLIN;
        }
    } else {
        if (!buffer_is_empty(evfd -> ssl -> sendbuf)) {
            events |= EPOLLOUT;
        }
        if (buffer_available(evfd -> ssl -> recvbuf) > 0) {
            events |= EPOLLIN;
        }
    }
    
    evfd_ctl(evfd, events);
}

static void ssl_handle_handshake(EvFD* evfd) {
    int ret;
    while ((ret = mbedtls_ssl_handshake(&evfd -> ssl -> ctx)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            evfd -> ssl -> ssl_read_wants_write = false;
            update_ssl_events(evfd);
            return; // 退出循环等待事件
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            evfd -> ssl -> ssl_write_wants_read = false;
            update_ssl_events(evfd);
            return;
        } else {
            // 处理致命错误
            evfd_close(evfd);
            return;
        }
    }
    
    // 握手成功
    evfd -> ssl -> ssl_handshaking = false;
    evfd -> ssl -> handshake_cb(evfd, evfd -> ssl -> handshake_user_data);
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
    list_for_each_prev_safe(cur, tmp, certs) {
        struct SSL_data *data = list_entry(cur, struct SSL_data, link);
        if (len == strlen(data -> name) && memcmp(name, data -> name, len) == 0) {
            if(data -> server_name)
                mbedtls_ssl_set_hostname(&((EvFD*)ssl) -> ssl -> ctx, data -> name);
            return mbedtls_ssl_set_hs_own_cert(&((EvFD*)ssl) -> ssl -> ctx, data -> cacert, data -> cakey);
        }
    }
    return -1;
}

static int udp_packet_send(void *ctx, const unsigned char *buf, size_t len) {
    EvFD *evfd = (EvFD*)ctx;
    struct UDPContext *uctx = evfd -> proto_ctx;
    
    // 获取UDP套接字fd（假设存放在fd[0]）
    int sockfd = evfd -> fd[0];
    
    ssize_t sent = sendto(sockfd, buf, len, MSG_DONTWAIT,
                        (struct sockaddr*)&uctx -> peer_addr, 
                        uctx -> addr_len);
    
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    }
    return (int)sent;
}

static int udp_packet_recv(void *ctx, unsigned char *buf, size_t len) {
    EvFD *evfd = (EvFD*)ctx;
    struct UDPContext *uctx = evfd -> proto_ctx;
    
    // 接收时自动填充对端地址
    socklen_t addr_len = sizeof(struct sockaddr_storage);
    int sockfd = evfd -> fd[0];
    
    ssize_t recvd = recvfrom(sockfd, buf, len, MSG_DONTWAIT,
                           (struct sockaddr*)&uctx -> peer_addr,
                           &addr_len);
    
    if (recvd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    }
    
    uctx -> addr_len = addr_len; // 保存最新对端地址
    return (int)recvd;
}
#endif

// Initialize the event loop.
// Eventloop is thread_local, so you should call this function in each thread.
bool evcore_init() {
    assert(epoll_fd == -1);
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        return false;
    }

    // init list
    init_list_head(&timer_list);
    init_list_head(&evfd_list);
    init_list_head(&timer_list);

    thread_id ++;
    return true;
}

#define CHECK_TO_BE_CLOSE(fd) if(fd -> destroy) goto _continue;

bool evcore_run(bool (*evloop_abort_check)(void* user_data), void* user_data) {
    struct epoll_event events[MAX_EVENTS];
    while (1) {
        bool abort_check_result = true;
        if(evloop_abort_check) abort_check_result = evloop_abort_check(user_data);

        if (unlikely(abort_check_result && evloop_events <= 0)){
#ifdef LJS_DEBUG
            printf("evloop_abort_check: abort, events=%ld(thread#%d)\n", evloop_events, thread_id);
#endif
            return true; // no events
        }

#ifdef LJS_DEBUG
        printf("epoll_wait: enter, events=%ld(thread#%d)\n", evloop_events, thread_id);
        bool first_epoll = true;
#endif

        if(epoll_fd == -1){
#ifdef LJS_DEBUG
            printf("epoll_wait: destroyed, force exit\n");
#endif
            return false;
        }

        // modify evfd
        evfd_mod_start();

        // wait
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno == EBADF) abort();    // avoid loop
            if (errno == EINTR) continue;
#ifdef LJS_DEBUG
            perror("epoll_wait");
#endif
        }
        
        for (int i = 0; i < nfds; ++i) {
            struct EvFD* evfd = events[i].data.ptr;

#ifdef LJS_DEBUG
            printf("epoll_wait: consumed, fd=%d, r=%d, w=%d, e=%d\n", evfd_getfd(evfd, NULL), events[i].events & EPOLLIN, events[i].events & EPOLLOUT, events[i].events & EPOLLERR);
#endif

            if(evfd -> task_based){
#ifdef LJS_DEBUG
                if(!first_epoll){
                    if(events[i].events & EPOLLIN) assert(!list_empty(&evfd -> u.task.write_tasks));
                    if(events[i].events & EPOLLOUT) assert(!list_empty(&evfd -> u.task.read_tasks));
                    if(events[i].events & EPOLLERR) assert(!list_empty(&evfd -> u.task.close_tasks));
                    first_epoll = false;
                }
#endif
        
                if (events[i].events & (EPOLLERR | EPOLLHUP)){
                    handle_close(evfd_getfd(evfd, NULL), evfd);
                    continue;
                }

                CHECK_TO_BE_CLOSE(evfd);
                
                if (events[i].events & EPOLLIN) switch(evfd -> type){
                    case EVFD_NORM:
                    case EVFD_TIMER:
                    case EVFD_UDP:
                    case EVFD_DTLS:
                        handle_read(evfd -> fd[0], evfd, NULL, NULL);
                    break;

                    case EVFD_AIO:
                        struct io_event events[MAX_EVENTS];
                        struct timespec timeout = {0, 0};
                        int ret = io_getevents(evfd -> aio.ctx, 1, MAX_EVENTS, events, &timeout);
                        if (ret < 0) {
#ifdef LJS_DEBUG
                            perror("io_getevents");
#endif
                            break;
                        }
                        for (int j = 0; j < ret; ++j) {
                            struct iocb* iocb = (struct iocb*)(uintptr_t)events[j].obj;
                            if(iocb -> aio_lio_opcode == IOCB_CMD_PREAD)
                                handle_read(evfd -> fd[0], evfd, &events[j], NULL);
                            else if(iocb -> aio_lio_opcode == IOCB_CMD_PWRITE)
                                handle_write(evfd -> fd[0], evfd, &events[j]);
                            else if(iocb -> aio_lio_opcode == IOCB_CMD_FSYNC)
                                handle_sync(evfd);
                            else    // ?
                                handle_close(evfd -> fd[0], evfd);
                        }
                    break;

                    case EVFD_INOTIFY:
                        struct inotify_event inev;
                        while (read(evfd -> fd[0], &inev, sizeof(inev)) == sizeof(inev)) {
                            handle_read(evfd -> fd[0], evfd, NULL, &inev);
                        }
                    break;

                    case EVFD_SSL:
#ifdef LJS_MBEDTLS
                        struct EvFD_SSL *ssl_evfd = evfd -> ssl;
                        
                        while (1) {
                            uint8_t tmp[4096];
                            int ret = mbedtls_ssl_read(&ssl_evfd -> ctx, tmp, sizeof(tmp));
                            
                            if (ret > 0) {
                                buffer_push(ssl_evfd -> recvbuf, tmp, ret);
                                handle_read(evfd -> fd[0], evfd, NULL, NULL); // 触发用户回调
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
                        ssize_t n = buffer_write(evfd -> ssl -> sendbuf, evfd -> fd[0], UINT32_MAX);
                            
                        if (n == -1 && errno != EAGAIN) {
                            handle_close(evfd -> fd[0], evfd);
                            break;
                        }

                        update_ssl_events(evfd);
                    }
#endif
                }
            }else{
                if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                    evfd -> u.cb.close(evfd, evfd -> u.cb.close_opaque);
                    TRACE_NSTDEVENTS(evfd, -1);
                }

                CHECK_TO_BE_CLOSE(evfd);

                if (events[i].events & EPOLLIN) 
                    evfd -> u.cb.read(evfd, NULL, 0, evfd -> u.cb.read_opaque);
                
                CHECK_TO_BE_CLOSE(evfd);
                
                if (events[i].events & EPOLLOUT) 
                    evfd -> u.cb.write(evfd, true, evfd -> u.cb.write_opaque);
            }
_continue:      continue;
        }
    }

    close(epoll_fd);
    return true;
}

void evcore_destroy() {
    if(epoll_fd == -1) return;

    // free all timerfd
    struct list_head *cur, *tmp;
    list_for_each_prev_safe(cur, tmp, &timer_list) {
        struct EvFD* timer = list_entry(cur, struct EvFD, link);
        evcore_clearTimer2(timer);
        close(timer -> fd[0]);
        list_del(&timer -> link);
        free2(timer);
    }

    // free all evfd
    list_for_each_safe(cur, tmp, &evfd_list) {
        struct EvFD* evfd = list_entry(cur, struct EvFD, link);
        evfd_close(evfd);
    }

    // free all SSL_data
#ifdef LJS_MBEDTLS
    struct list_head *cur2, *tmp2;
    list_for_each_prev_safe(cur2, tmp2, certs) {
        struct SSL_data *data = list_entry(cur2, struct SSL_data, link);
        list_del(&data -> link);
        free2(data);
    }
#endif

    close(epoll_fd);
    epoll_fd = -1;

#ifdef LJS_DEBUG
    printf("evcore_destroy: exit, (thread#%d)remains=%ld\n", thread_id, evloop_events);
    // assert(evloop_events == 0);
#endif
}

#ifdef LJS_DEBUG
#define tassert(cond) if(!unlikely(cond)){ \
    printf("assert(%s) failed at %s:%d\n", #cond, __FILE__, __LINE__); \
    __builtin_trap(); \
    return false; \
}
#else
#define tassert(cond) if(!(cond)) return false;
#endif


// Make async tasks synchronous(blocking)
bool evfd_syncexec(EvFD* pipe) {
    if(epoll_fd == -1) return false;
    tassert(pipe -> type != EVFD_INOTIFY && pipe -> type != EVFD_TIMER && !pipe -> destroy);

    int fd = evfd_getfd(pipe, NULL);
    int flags = ioctl(fd, F_GETFL, 0);
    if(-1 == flags || -1 == ioctl(fd, F_SETFL, flags &~ O_NONBLOCK))
        return false;
        
    // XXX: this logic is not safe, but it's a workaround for now.
    if(pipe -> type == EVFD_AIO){
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        close(pipe -> fd[0]); // close eventfd
        pipe -> fd[0] = fd;
        pipe -> type = EVFD_NORM;
    }
    handle_read(fd, pipe, NULL, NULL);
    if(!pipe -> destroy) handle_write(fd, pipe, NULL);
    
    ioctl(fd, F_SETFL, flags);
    return true;
}

/**
 * 将fd附加到eventloop。
 */
// 将fd附加到事件循环
struct EvFD* evcore_attach(
    int fd, bool use_aio, 
    EvReadCallback rcb, void* read_opaque, 
    EvWriteCallback wcb, void* write_opaque, 
    EvCloseCallback ccb, void* close_opaque
) {
    // fd是否有效？
    if (fd < 0 || (fcntl(fd, F_GETFL, 0) == -1 && errno == EBADF)) {
#ifdef LJS_DEBUG
        perror("fcntl");
#endif
        return NULL;
    }

    // O_DIRECT
    if(use_aio) fcntl(fd, F_SETFL, O_DIRECT | fcntl(fd, F_GETFL, 0));

    EvFD* evfd = malloc2(sizeof(EvFD));
    if (!evfd) return NULL;
    INIT_EVFD(evfd);

    // 设置文件类型
    if (use_aio) {
        if (io_setup(MAX_EVENTS, &evfd -> aio.ctx) < 0) {
#ifdef LJS_DEBUG
            perror("io_setup");
#endif
error:
            list_del(&evfd -> link);
            free2(evfd);
            return NULL;
        }
        evfd -> type = EVFD_AIO;
        evfd -> fd[0] = fd;  // 原始fd
        evfd -> fd[1] = -1;  // aio使用虚拟fd
        evfd -> u.task.offset = 0;
    } else {
        evfd -> type = EVFD_NORM;
        evfd -> fd[0] = fd;
    }

    // register to epoll
    uint32_t evflag = EPOLLLT | EPOLLERR;
    if (rcb) evflag |= EPOLLIN;
    if (wcb) evflag |= EPOLLOUT;
    struct epoll_event ev = {
        .events = evflag,
        .data.ptr = evfd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
#ifdef LJS_DEBUG
        perror("epoll_ctl");
#endif
        goto error;
    }
    TRACE_NSTDEVENTS(evfd, +1);

    // 设置默认回调
    evfd -> task_based = false;
    evfd -> u.cb.read = rcb;
    evfd -> u.cb.write = wcb;
    evfd -> u.cb.close = ccb;
    evfd -> u.cb.read_opaque = read_opaque;
    evfd -> u.cb.write_opaque = write_opaque;
    evfd -> u.cb.close_opaque = close_opaque;
    evfd -> modify_flag = 0;
    evfd -> epoll_flags = evflag;

    return evfd;
}

// 创建新的evfd对象
EvFD* evfd_new(int fd, bool use_aio, bool readable, bool writeable, uint32_t bufsize,
                   EvCloseCallback close_callback, void* close_opaque) {
    EvFD* evfd = malloc2(sizeof(EvFD));
    if (!evfd) return NULL;

    // initialize task list
    init_list_head(&evfd -> u.task.read_tasks);
    init_list_head(&evfd -> u.task.write_tasks);
    init_list_head(&evfd -> u.task.close_tasks);

    // initialize evfd
    INIT_EVFD(evfd);
    evfd -> task_based = true;
    evfd -> fd[0] = fd;
    evfd -> fd[1] = -1;
    evfd -> type = EVFD_NORM;
    evfd -> epoll_flags = EPOLLLT | EPOLLERR | EPOLLHUP;
    if(readable) evfd -> epoll_flags |= EPOLLIN;
    if(writeable) evfd -> epoll_flags |= EPOLLOUT;
    if(readable){ 
        assert(bufsize > 0);
        buffer_init(&evfd -> incoming_buffer, NULL, bufsize);
    }

    // close callback
    if (close_callback) {
        struct Task* task = malloc2(sizeof(struct Task));
        task -> cb.close = close_callback;
        task -> opaque = close_opaque;
        list_add(&task -> list, &evfd -> u.task.close_tasks);
        TRACE_NSTDEVENTS(evfd, +1);
    }

    // aio
    if (use_aio) {
        evfd -> type = EVFD_AIO;
        evfd -> fd[1] = fd;

        if(fcntl(fd, F_SETFL, O_DIRECT | fcntl(fd, F_GETFL, 0)) == -1){
#ifdef LJS_DEBUG
            perror("fcntl");
#endif
            goto error;
        }

        if(io_setup(MAX_EVENTS, &evfd -> aio.ctx) == -1){
#ifdef LJS_DEBUG
            perror("io_setup");
#endif
            goto error;
        }

        fd = evfd -> fd[0] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (evfd -> fd[0] == -1) {
#ifdef LJS_DEBUG
            perror("eventfd");
#endif
error:
            list_del(&evfd -> link);
            free2(evfd);
            return NULL;
        }
        evfd -> u.task.offset = 0;
    } else {
        fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));        
    }

    // push to eventloop
    struct epoll_event ev = {
        .events = evfd -> epoll_flags,
        .data.ptr = evfd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
#ifdef LJS_DEBUG
        perror("epoll_ctl");
#endif
        goto error;
    }

#ifdef LJS_DEBUG
    printf("new evfd fd:%d, aio:%d, bufsize:%d, r:%d, w:%d\n", fd, use_aio, bufsize, readable, writeable);
#endif
    TRACE_NSTDEVENTS(evfd, +1);

    return evfd;
}

void evfd_setup_udp(EvFD* evfd) {
    assert(!evfd -> destroy);
    evfd -> type = EVFD_UDP;
    evfd -> proto_ctx = malloc2(sizeof(struct UDPContext));
#ifdef LJS_MBEDTLS
    evfd -> proto_ctx -> dtls_ctx = NULL;
#endif
}

#ifdef LJS_MBEDTLS
bool evfd_initssl(
    EvFD* evfd, mbedtls_ssl_config** config,
    bool is_client, int preset,
    EvSSLHandshakeCallback handshake_cb, void* user_data
) {
    tassert(!evfd -> destroy);
    evfd -> type = EVFD_SSL;
    
    // 初始化mbedtls结构
    evfd -> ssl = malloc2(sizeof(struct EvFD_SSL));
    mbedtls_ssl_init(&evfd -> ssl -> ctx);
    mbedtls_ssl_config_init(&evfd -> ssl -> config);
    mbedtls_ssl_config_defaults(&evfd -> ssl -> config, is_client ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, preset);
    mbedtls_ssl_conf_authmode(&evfd -> ssl -> config, MBEDTLS_SSL_VERIFY_NONE);
    if(config) *config = &evfd -> ssl -> config;
    
    if (mbedtls_ssl_setup(&evfd -> ssl -> ctx, &evfd -> ssl -> config) != 0)
        goto error;
    
    mbedtls_ssl_conf_read_timeout(&evfd -> ssl -> config, 0);
    mbedtls_ssl_set_bio(&evfd -> ssl -> ctx, evfd, handle_ssl_send, handle_ssl_recv, NULL);
    
    // 初始化加密/解密缓冲区
    buffer_init(&evfd -> ssl -> sendbuf, NULL, 16384);
    buffer_init(&evfd -> ssl -> recvbuf, NULL, 16384);

    // callback
    evfd -> ssl -> handshake_cb = handshake_cb;
    evfd -> ssl -> handshake_user_data = user_data;
    
    // 开始握手
    evfd -> ssl -> ssl_handshaking = true;
    ssl_handle_handshake(evfd);
    return evfd;

error:
    evfd_close(evfd);
    return NULL;
}

bool evfd_initdtls(EvFD* evfd, mbedtls_ssl_config** _config) {
    tassert(!evfd -> destroy);
    if(!evfd -> proto_ctx) abort();
    struct UDPContext *ctx = evfd -> proto_ctx;
    mbedtls_ssl_config* config = malloc2(sizeof(mbedtls_ssl_config));
    if(_config) *_config = config;
    
    mbedtls_ssl_init(ctx -> dtls_ctx);
    mbedtls_ssl_config_init(config);
    mbedtls_ssl_config_defaults(config, MBEDTLS_SSL_IS_SERVER,
                              MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                              MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&evfd -> ssl -> config, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_read_timeout(&evfd -> ssl -> config, 0);
    mbedtls_ssl_set_bio(ctx -> dtls_ctx, evfd, 
                       udp_packet_send, udp_packet_recv, NULL);
    return true;
}

#if defined(LJS_MBEDTLS) && defined(MBEDTLS_DEBUG_C)
void debug_callback(void *ctx, int level, const char *file, int line, const char *str) {
    printf("%s %s:%04d: %s\n", level == MBEDTLS_SSL_ALERT_LEVEL_FATAL ? "E:" : level == MBEDTLS_SSL_ALERT_LEVEL_WARNING ? "W:" : "I:", file, line, str);
}
#endif

bool evfd_remove_sni(const char* name) {
    struct list_head* pos, *tmp;
    list_for_each_prev_safe(pos, tmp, certs) {
        struct SSL_data* data = list_entry(pos, struct SSL_data, link);
        if(strcmp(data -> name, name) == 0) {
            list_del(pos);
            free2(data -> name);
            if(data -> server_name) free2(data -> server_name);
            mbedtls_x509_crt_free2(data -> cacert);
            mbedtls_pk_free2(data -> cakey);
            free2(data);
            return true;
        }
    }
    return false;
}

void evfd_set_sni(char* name, char* server_name, mbedtls_x509_crt* cacert, mbedtls_pk_context* cakey) {
    struct SSL_data* data = malloc2(sizeof(struct SSL_data));
    if(!certs) init_list_head(certs = &data -> link);
    else{ 
        evfd_remove_sni(name);  // 先移除旧的
        list_add(&data -> link, certs);
    }
    data -> name = name;
    data -> server_name = server_name;
    data -> cacert = cacert;
    data -> cakey = cakey;
}
#endif

// read size from evfd
// similar to evfd_read, however, it will fail(buffer=NULL, size=0) or fill whole buffer
// evfd_read will read_once even if buffer is not filled
bool evfd_readsize(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                      EvReadCallback callback, void* user_data) {
    tassert(!evfd -> destroy && evfd -> task_based);

    if(
        evfd -> incoming_buffer && buffer_used(evfd -> incoming_buffer) >= buf_size && 
        list_empty(&evfd -> u.task.read_tasks)
    ){
        // directly return data from buffer
        uint32_t available = buffer_copyto(evfd -> incoming_buffer, buffer, buf_size);
        
        buffer_seek_cur(evfd -> incoming_buffer, available);
        callback(evfd, buffer, available, user_data);
        return true;
    }

    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;
    // initialize buffer
    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size +1);

    if(!evfd -> incoming_buffer) buffer_init(&evfd -> incoming_buffer, NULL, EVFD_BUFSIZE);

    task -> type = EV_TASK_READ;
    task -> cb.read = callback;
    task -> opaque = user_data;
    task -> buffer = buf;

    if(evfd -> type == EVFD_AIO) {
        // 提交AIO
        if (submit_aio_read(evfd, task)) {
            free2(task);
            buffer_free(buf);
            return false;
        }
    }

    list_add(&task -> list, &evfd -> u.task.read_tasks);
    check_queue_status(evfd, evfd -> fd[0]);
    TRACE_EVENTS(evfd, +1);

    return true;
}

bool evfd_clearbuf(EvFD* evfd){
    if(evfd -> destroy) return false;
    buffer_clear(evfd -> incoming_buffer);
    return true;
}

// read one line from evfd, "\r" "\r\n" "\n" are all welcomed
// fail or complete
bool evfd_readline(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                      EvReadCallback callback, void* user_data) {
    tassert(!evfd -> destroy);
    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size);
    if(!evfd -> incoming_buffer) buffer_init(&evfd -> incoming_buffer, NULL, EVFD_BUFSIZE);

    task -> type = EV_TASK_READLINE;
    task -> buffer = buf;
    task -> cb.read = callback;
    task -> opaque = user_data;
    evfd -> strip_if_is_n = false;
    
    if(evfd -> type == EVFD_AIO && submit_aio_read(evfd, task)){
        free2(task);
        buffer_free(buf);
        return false;
    }

    bool try_direct = list_empty(&evfd -> u.task.read_tasks);
    list_add(&task -> list, &evfd -> u.task.read_tasks);
    check_queue_status(evfd, evfd -> fd[0]);
    TRACE_EVENTS(evfd, +1);

    if(
        evfd -> incoming_buffer && !buffer_is_empty(evfd -> incoming_buffer) &&
        try_direct
    ){
        // try to find line directly from buffer
        handle_read(evfd_getfd(evfd, NULL), evfd, NULL, NULL);
    }

    return true;
}

// 通用读取请求
bool evfd_read(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
                   EvReadCallback callback, void* user_data) {
    tassert(!evfd -> destroy && buf_size > 0);

    if(evfd -> incoming_buffer && list_empty(&evfd -> u.task.read_tasks) && !buffer_is_empty(evfd -> incoming_buffer)){
        // directly return data from buffer
        uint32_t available = buffer_copyto(evfd -> incoming_buffer, buffer, buf_size);
        
        buffer_seek_cur(evfd -> incoming_buffer, available);
        callback(evfd, buffer, available, user_data);
        return true;
    }
    
    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size);

    if(!evfd -> incoming_buffer) buffer_init(&evfd -> incoming_buffer, NULL, EVFD_BUFSIZE);

    task -> type = EV_TASK_READONCE;
    task -> buffer = buf;
    task -> cb.read = callback;
    task -> opaque = user_data;

#ifdef LJS_DEBUG
    if(evfd -> type == EVFD_AIO)
        printf("warn: aio is not supported for readonce\n");
#endif

    if(evfd -> type == EVFD_AIO) {
        buffer_aligned(buf, blksize_get(evfd -> fd[1]));
        // 提交AIO
        if (submit_aio_read(evfd, task)) {
            free2(task);
            buffer_free(buf);
            return false;
        }
    }
    list_add(&task -> list, &evfd -> u.task.read_tasks);
    check_queue_status(evfd, evfd -> fd[0]);
    TRACE_EVENTS(evfd, +1);

    return true;
}

// 提交写请求
bool evfd_write(EvFD* evfd, const uint8_t* data, uint32_t size,
                   EvWriteCallback callback, void* user_data) {
    tassert(!evfd -> destroy);
    if(size == 0){
        callback(evfd, true, user_data);
        return true;
    }

    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    // 初始化写buffer
    struct Buffer* buf;
    buffer_init(&buf, (uint8_t*)data, size +1);
    buf -> end = size; // 预填充数据

    task -> type = EV_TASK_WRITE;
    task -> buffer = buf;
    task -> cb.write = callback;
    task -> opaque = user_data;

    if (evfd -> type == EVFD_AIO) {
        // 提交AIO
        if (!submit_aio_write(evfd, task)) 
            goto error;

        // add to list
        list_add(&task -> list, &evfd -> u.task.write_tasks);
    }else{
        list_add(&task -> list, &evfd -> u.task.write_tasks);
    }

    check_queue_status(evfd, evfd -> fd[0]);
    TRACE_EVENTS(evfd, +1);

    return true;

error:
    buffer_free(buf);
    free2(task);
    return false;
}

// UDP写
bool evfd_write_dgram(EvFD* evfd, const uint8_t* data, uint32_t size,
                         const struct sockaddr *addr, socklen_t addr_len,
                         EvWriteCallback callback, void* user_data) {
    tassert(!evfd -> destroy);
    struct UDPContext *ctx = evfd -> proto_ctx;
    memcpy(&ctx -> peer_addr, addr, addr_len);
    ctx -> addr_len = addr_len;
    
    return evfd_write(evfd, data, size, callback, user_data);
}

// onclose
// Note: passing callback as NULL will clear the callback.
bool evfd_onclose(EvFD* evfd, EvCloseCallback callback, void* user_data) {
    tassert(!evfd -> destroy);
    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    if(!callback){
        if(list_empty(&evfd -> u.task.close_tasks)) return false;
        // clear callback
        struct Task* t = list_entry(evfd -> u.task.close_tasks.next, struct Task, list);
        list_del(&t -> list);
        free2(t);
        TRACE_NSTDEVENTS(evfd, -1);
        return true;
    }

    task -> type = EV_TASK_CLOSE;
    task -> cb.close = callback;
    task -> opaque = user_data;
    list_add(&task -> list, &evfd -> u.task.close_tasks);
    TRACE_NSTDEVENTS(evfd, +1);

    return true;
}

// finalizer cb
// Note: finalizer is called after close, and buffer will be provided if readable.
bool evfd_finalizer(EvFD* evfd, EvFinalizerCallback callback, void* user_data) {
    tassert(!evfd -> destroy);
    evfd -> u.task.finalizer = callback;
    evfd -> u.task.finalizer_opaque = user_data;
    return true;
}

// only support normal fd, like socket, pipe, pty that supports epoll and stream-based
bool evfd_pipeTo(EvFD* from, EvFD* to, EvPipeToFilter filter, void* fopaque, EvPipeToNotify notify, void* nopaque){
    tassert(!from -> destroy && !to -> destroy);
    tassert(from -> type == EVFD_NORM && to -> type == EVFD_NORM);
    struct Task* task = malloc2(sizeof(struct Task));
    struct Task* task2 = malloc2(sizeof(struct Task));
    struct PipeToTask* ptask = malloc2(sizeof(struct PipeToTask));
    if (unlikely(!task || !task2 || !ptask)) return false;

    memset(ptask, 0, sizeof(struct PipeToTask));
    memset(task, 0, sizeof(struct Task));
    memset(task2, 0, sizeof(struct Task));
    buffer_init(&task2 -> buffer, NULL, EVFD_BUFSIZE);

    task -> type = task2 -> type = EV_TASK_PIPETO;
    task -> cb.pipeto = task2 -> cb.pipeto = ptask;
    ptask -> exchange_buffer = task2 -> buffer;
    ptask -> from = from;
    ptask -> to = to;
    ptask -> filter = filter;
    ptask -> notify = notify;
    ptask -> filter_opaque = fopaque;
    ptask -> notify_opaque = nopaque;
    list_add(&task -> list, &from -> u.task.read_tasks);
    list_add(&task2 -> list, &to -> u.task.write_tasks);

    TRACE_EVENTS(from, +1);
    TRACE_EVENTS(to, +1);
    check_queue_status(from, from -> fd[0]);
    check_queue_status(to, to -> fd[0]);
    return true;
}

static inline void close_stdpipe(EvFD* evfd){
#ifdef LJS_DEBUG
    printf("close_stdpipe: %d\n", evfd -> fd[0]);
#endif

    clear_tasks(evfd, true);
    if(evfd -> incoming_buffer) buffer_free(evfd -> incoming_buffer);
    evfd_ctl(evfd, EPOLL_CTL_FREE);
    evfd -> destroy = true;
}

// close evfd
bool evfd_close(EvFD* evfd) {
    tassert(evfd -> type != EVFD_TIMER && evfd -> type != EVFD_INOTIFY && evfd -> fd[0] >= 0);
    if(evfd -> destroy) return false;
    if(evfd -> fd[0] <= STDERR_FILENO) close_stdpipe(evfd);
    else handle_close(evfd -> fd[0], evfd);
    return true;
}

// Destroy evfd, not close fd
bool evfd_close2(EvFD* evfd) {
    if(evfd -> destroy) return false;
    if(evfd -> fd[0] <= STDERR_FILENO) close_stdpipe(evfd);
    if(evfd -> task_based) clear_tasks(evfd, false);
    if(evfd -> incoming_buffer) buffer_free(evfd -> incoming_buffer);
    evfd_ctl(evfd, EPOLL_CTL_FREE);
    evfd -> destroy = true;

    // remove in epoll
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, evfd -> fd[0], NULL);
    return true;
}

static void __shutdown_cb(EvFD* evfd, bool success, void* opaque){
    if(!success){
#ifdef LJS_DEBUG
        perror("shutdown");
#endif
    }
    evfd_close(evfd);
}

// better choice than evfd_close
// read/write all data from/to fd and close it
bool evfd_shutdown(EvFD* evfd){
    tassert(!evfd -> destroy);

    // force read Note: buffer is required
    if(!evfd -> incoming_buffer) buffer_init(&evfd -> incoming_buffer, NULL, EVFD_BUFSIZE);
    handle_read(evfd -> fd[0], evfd, NULL, NULL);

    // wait for all data to be written
    if(!evfd -> destroy && evfd -> task_based && (
        !list_empty(&evfd -> u.task.write_tasks) || !list_empty(&evfd -> u.task.read_tasks)
    )){
        evfd_wait2(evfd, __shutdown_cb, NULL);
    }else{
        evfd_close(evfd);
    }

    return true;
}

/**
 * Overwrite the default behavior of an EvFD object to callbacks provided by the user.
 * Mostly used after using `evfd_new()` and donot want to close the fd.
 */
bool evfd_override(EvFD* evfd, EvReadCallback rcb, void* read_opaque, EvWriteCallback wcb, void* write_opaque, EvCloseCallback ccb, void* close_opaque){
    tassert(!evfd -> destroy && evfd -> task_based);
    clear_tasks(evfd, false);
    if(evfd -> incoming_buffer) buffer_free(evfd -> incoming_buffer);
    TRACE_NSTDEVENTS(evfd, +1);   // force add task
    evfd -> incoming_buffer = NULL;
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
bool evfd_wait(EvFD* evfd, bool wait_read, EvSyncCallback cb, void* opaque){
    tassert(!evfd -> destroy);

    if( // already completed
        (wait_read && list_empty(&evfd -> u.task.read_tasks)) ||
        (wait_read && list_empty(&evfd -> u.task.write_tasks))
    ) cb(evfd, true, opaque);

    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    task -> type = EV_TASK_NOOP;
    task -> cb.sync = cb;
    task -> opaque = opaque;
    task -> buffer = NULL;
    if(wait_read){ 
        list_add(&task -> list, &evfd -> u.task.read_tasks);
    }else{
        list_add(&task -> list, &evfd -> u.task.write_tasks);
    }
    TRACE_EVENTS(evfd, +1);
    return true;
}

struct __sync_cb_arg {
    uint8_t count;
    EvSyncCallback cb;
    void* opaque;
};

// (internal use) close after all tasks are completed
static void __sync_cb(EvFD* evfd, bool success, void* opaque){
    struct __sync_cb_arg* arg = opaque;
    if(arg -> count ++ == 1){ 
        evfd_close(evfd); 
        arg -> cb(evfd, success, arg -> opaque);
        free2(arg);
    }
}

bool evfd_wait2(EvFD* evfd, EvSyncCallback cb, void* opaque){
    struct __sync_cb_arg* arg = malloc2(sizeof(struct __sync_cb_arg));
    if (!arg) return false;
    arg -> count = 0;
    arg -> cb = cb;
    arg -> opaque = opaque;
    return evfd_wait(evfd, false, __sync_cb, arg) && evfd_wait(evfd, true, __sync_cb, arg);
}

bool evfd_yield(EvFD* evfd, bool yield_read, bool yield_write){
    tassert(!evfd -> destroy);
    int events = evfd -> epoll_flags;
    if(yield_read) events &= ~EPOLLIN;
    if(yield_write) events &= ~EPOLLOUT;
    evfd_ctl(evfd, events);
    return true;
}

bool evfd_consume(EvFD* evfd, bool consume_read, bool consume_write){
    tassert(!evfd -> destroy);
    int events = evfd -> epoll_flags;
    if(consume_read) events |= EPOLLIN;
    if(consume_write) events |= EPOLLOUT;
    evfd_ctl(evfd, events);
    return true;
}

// Get whether the evfd is closed
bool evfd_closed(EvFD* evfd){
    return evfd -> destroy;
}

static inline EvFD* timer_new(uint64_t milliseconds, EvTimerCallback callback, void* user_data, bool once) {
    // find free timer fd
    struct TimerFD* tfd = NULL;
    int fd;
    bool reuse = false;
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &timer_list){
        struct TimerFD* _tfd = (void*)list_entry(pos, struct EvFD, link);
        if(_tfd -> time == 0){
            _tfd -> time = milliseconds;
            _tfd -> once = once;
            tfd = _tfd;
            reuse = true;
            fd = ((EvFD*)_tfd) -> fd[0];
            goto settime;
        }
    }

    // 创建定时器fd
    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd == -1) {
#ifdef LJS_DEBUG
        perror("timerfd_create");
#endif
        return NULL;
    }

    // 创建定时器对象
    tfd = malloc2(sizeof(struct TimerFD));
    struct EvFD* evfd = (void*)tfd;
    evfd -> task_based = true;
    tfd -> time = milliseconds;
    tfd -> once = once;
    tfd -> executed = false;

    // 初始化任务队列
    init_list_head(&evfd -> u.task.read_tasks);
    init_list_head(&evfd -> u.task.write_tasks);
    init_list_head(&evfd -> u.task.close_tasks);

    // 设置基础参数
    evfd -> fd[0] = fd;
    evfd -> type = EVFD_TIMER;
    INIT_EVFD2(evfd);

settime:
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
#ifdef LJS_DEBUG
        perror("timerfd_settime");
#endif
        close(fd);
        return NULL;
    }

    if(reuse){
        evfd = (void*)tfd;
        evfd_ctl(evfd, EPOLLIN | EPOLLLT);
    }else{
        struct epoll_event ev = {
            .events = evfd -> epoll_flags = EPOLLIN | EPOLLLT,
            .data.ptr = evfd
        };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
#ifdef LJS_DEBUG
            perror("epoll_ctl timerfd");
#endif
            close(fd);
            free2(evfd);
            return NULL;
        }
        // register to timer list
        list_add(&evfd -> link, &timer_list);

#ifdef LJS_DEBUG
    printf("new timer fd:%d, s:%ld, ns:%ld, once:%d\n", fd, itss.tv_sec, itss.tv_nsec, once);
#endif

    }
    
    return evfd;
}

static inline bool timer_task(struct EvFD* evfd, EvTimerCallback callback, void* user_data) {
    if(!evfd) return false;
    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    task -> type = EV_TASK_SYNC;
    task -> cb.timer = callback;
    task -> opaque = user_data;
    list_add(&task -> list, &evfd -> u.task.read_tasks);
    TRACE_EVENTS(evfd, +1);   // Note: eventfd starts with 1 task
    return true;
}

EvFD* evcore_interval(uint64_t milliseconds, EvTimerCallback callback, void* cbopaque, EvCloseCallback close_cb, void* close_opaque) {
    struct EvFD* evfd = timer_new(milliseconds, callback, cbopaque, false);
    if(timer_task(evfd, callback, cbopaque)){
        evfd_onclose(evfd, close_cb, close_opaque);
        return evfd;
    }
    close_cb(evfd, close_opaque);
    evfd_close(evfd);
    return NULL;
}

EvFD* evcore_setTimeout(uint64_t milliseconds, EvTimerCallback callback, void* user_data) {
    struct EvFD* evfd = timer_new(milliseconds, callback, user_data, true);
    if(timer_task(evfd, callback, user_data)) return evfd;
    evfd_close(evfd);
    return NULL;
}

bool evcore_clearTimer2(EvFD* evfd) {
    tassert(evfd -> type == EVFD_TIMER);
    // 从epoll注销
    evfd_ctl(evfd, EPOLLLT);

#ifdef LJS_DEBUG
    printf("yield timer fd:%d\n", evfd_getfd(evfd, NULL));
#endif

    struct TimerFD* tfd = (void*)evfd;

    // 清理任务队列
    struct list_head *pos, *tmp;
    list_for_each_prev_safe(pos, tmp, &evfd -> u.task.read_tasks) {
        struct Task* task = list_entry(pos, struct Task, list);

        // execute callback if once and not executed
        if(!tfd -> executed && tfd -> once)
            task -> cb.timer(0, task -> opaque);

        list_del(pos);
        TRACE_EVENTS(evfd, -1);
        free2(task);
    }

    // clear onclose tasks
    if(tfd -> once){
        assert(list_empty(&evfd -> u.task.close_tasks));
    }else{
        struct list_head *pos2, *tmp2;
        list_for_each_prev_safe(pos2, tmp2, &evfd -> u.task.close_tasks) {
            struct Task* task = list_entry(pos2, struct Task, list);
            task -> cb.close(evfd, task -> opaque);
            list_del(pos2);
            TRACE_EVENTS(evfd, -1);
            free2(task);
        }
    }

    // stop timerfd
    struct itimerspec its = { 0 };
    if (timerfd_settime(evfd -> fd[0], 0, &its, NULL) == -1) {
#ifdef LJS_DEBUG
        perror("timerfd_settime");
#endif
        return false;
    }

    tfd -> executed = true;
    return true;
}

bool evcore_clearTimer(int timer_fd) {
    // 在链表中查找定时器
    struct list_head *pos, *tmp;
    list_for_each_prev_safe(pos, tmp, &timer_list) {
        struct EvFD* evfd = list_entry(pos, struct EvFD, link);
        if(evfd -> fd[0] == timer_fd){
            return evcore_clearTimer2(evfd);
        }
    }

    return false;
}

// create an inotify file watcher
EvFD* evcore_inotify(EvINotifyCallback callback, void* user_data) {
    int inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (inotify_fd == -1) {
#ifdef LJS_DEBUG
        perror("inotify_init1");
#endif
        return NULL;
    }

    EvFD* evfd = calloc(1, sizeof(EvFD));
    if (!evfd) {
        close(inotify_fd);
        return NULL;
    }

    struct InotifyContext* inotify = malloc2(sizeof(struct InotifyContext));
    if (!inotify) {
        close(inotify_fd);
        free2(evfd);
        return NULL;
    }
    memset(inotify, 0, sizeof(struct InotifyContext));
    evfd -> inotify = inotify;

    // inotify is task-based
    evfd -> task_based = true;
    init_list_head(&evfd -> u.task.read_tasks);
    list_add_tail(&evfd -> link, &evfd_list);

    // init evfd
    evfd -> fd[0] = inotify_fd;
    evfd -> type = EVFD_INOTIFY;
    evfd -> u.task.finalizer = NULL;

    // register to evfd
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLLT,
        .data.ptr = evfd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &ev) == -1) {
#ifdef LJS_DEBUG
        perror("epoll_ctl");
#endif
        close(inotify_fd);
        free2(evfd);
        return NULL;
    }
#ifdef LJS_DEBUG
    printf("inotify fd:%d\n", inotify_fd);
#endif

    // default task
    struct Task* task = malloc2(sizeof(struct Task));
    task -> type = EV_TASK_READ;
    task -> cb.inotify = callback;
    task -> opaque = user_data;
    list_add(&task -> list, &evfd -> u.task.read_tasks);
    TRACE_EVENTS(evfd, +1);   // Note: inotify starts with 1 task

    return evfd;
}

// 停止inotify监控
bool evcore_stop_inotify(EvFD* evfd) {
    tassert(evfd -> type == EVFD_INOTIFY);

    // 从epoll注销
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, evfd -> fd[0], NULL);

    // 关闭文件描述符
    close(evfd -> fd[0]);

    // 清理任务队列
    struct list_head *pos, *tmp;
    list_for_each_prev_safe(pos, tmp, &evfd -> u.task.read_tasks) {
        struct Task* task = list_entry(pos, struct Task, list);
        list_del(pos);
        TRACE_EVENTS(evfd, -1);
        free2(task);
    }

    // free evfd
    for(int i = 0; i < MAX_EVENTS; i ++){
        if(evfd -> inotify -> paths[i])
            free2(evfd -> inotify -> paths[i]);
    }
    free2(evfd -> inotify);
    free2(evfd);

    return true;
}

// 添加监控路径
bool evcore_inotify_watch(EvFD* evfd, const char* path, uint32_t mask, int* wd) {
    tassert(evfd -> type == EVFD_INOTIFY);
    int _wd;
    if(!wd) wd = &_wd;

    *wd = inotify_add_watch(evfd -> fd[0], path, mask);
    if (*wd == -1) {
#ifdef LJS_DEBUG
        perror("inotify_add_watch");
#endif
        return false;
    }

    // save path
    evfd -> inotify -> paths[*wd] = strdup2(path);

    return true;
}

// 移除监控路径
bool evcore_inotify_unwatch(EvFD* evfd, int wd) {
    tassert(evfd -> type == EVFD_INOTIFY);

    int ret = inotify_rm_watch(evfd -> fd[0], wd);
    if (ret == -1) {
#ifdef LJS_DEBUG
        perror("inotify_rm_watch");
#endif
        return false;
    }

    free2(evfd -> inotify -> paths[wd]);
    evfd -> inotify -> paths[wd] = NULL;

    return true;
}

int evcore_inotify_find(EvFD* evfd, const char* path) {
    tassert(evfd -> type == EVFD_INOTIFY);
    for(int i = 0; i < MAX_EVENTS; i ++){
        if(evfd -> inotify -> paths[i] && strcmp(evfd -> inotify -> paths[i], path) == 0){
            return i;
        }
    }
    return -1;
}

int evfd_getfd(EvFD* evfd, int* timer_fd) {
    if(evfd -> type == EVFD_AIO){
        if(timer_fd) *timer_fd = evfd -> fd[0];
        return evfd -> fd[1];
    }else{
        if(timer_fd)*timer_fd = -1;
        return evfd -> fd[0];
    }
}

bool evfd_seek(EvFD* evfd, int seek_type, off_t pos){
    tassert(!evfd -> destroy && evfd -> type == EVFD_AIO && evfd -> task_based);

    switch (seek_type){
        case SEEK_CUR:
            evfd -> u.task.offset += pos;
        break;

        case SEEK_END:
            // Note: seek from end requires fstat which is not async
            errno = ENOTSUP;
            return false;
            // evfd -> u.task.offset = 

        case SEEK_SET:
            evfd -> u.task.offset = pos;
        break;

        default:
            abort();
    }

    return true;
}

bool evfd_isAIO(EvFD* evfd) {
    return evfd -> type == EVFD_AIO;
}

void* evfd_get_opaque(EvFD* evfd) {
    return evfd -> opaque;
}

void evfd_set_opaque(EvFD* evfd, void* opaque) {
    evfd -> opaque = opaque;
}