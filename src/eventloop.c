/*
 * LightJS EventLoop V1.1
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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <threads.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

// #define LJS_DEBUG    // debug
// #define LJS_EVLOOP_FULL_DEBUG

#include "../engine/cutils.h"
#include "../engine/list.h"
#include "utils.h"
#include "core.h"

#ifdef LJS_MBEDTLS
#include <mbedtls/mbedtls_config.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/ctr_drbg.h>

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

// unstable: thread-safe EvFD support
// #define LJS_EVLOOP_THREADSAFE

enum EvFDType {
    EVFD_NORM,
    EVFD_UDP,
    EVFD_AIO,
    EVFD_INOTIFY,
    EVFD_TIMER,
    EVFD_SSL,
    // diff: will attempt to read infinitely to avoid data lost when subprocess exiting
    EVFD_PTY,
    // DTLS removed since v1.1
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

struct TimerFDContext {
    uint64_t time;  // 0 marks unused
    bool once;
    bool executed;
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
};

#ifdef LJS_MBEDTLS
struct EvFD_SSL {
    mbedtls_ssl_config config;
    mbedtls_ssl_context ctx;
    struct Buffer* sendbuf;
    struct Buffer* recvbuf;

    // for ssl read/write wants
    bool want_read;

    // for handshake
    bool ssl_handshaking;       // SSL handshake in progress
    EvSSLHandshakeCallback handshake_cb;
    void* handshake_user_data;

    // ssl error reason? by default =0(no error);
    int mb_errno;
};
#endif

struct InotifyContext {
    // wd -> string index
    char* paths[MAX_EVENTS];
    char* move_tmp[2];
};

struct EvFD {
    union {
        aio_context_t ctx;
        uint64_t __padding;
    } aio;

    int fd[2];  // if type==EVFD_AIO, fd[1] is the real fd
    enum EvFDType type;

    // specific for each type
    union {
        struct UDPContext* udp;
        struct InotifyContext* inotify;
        struct TimerFDContext* timer;
#ifdef LJS_MBEDTLS
        struct EvFD_SSL* ssl;           // for ssl
#endif
    } proto;

    bool task_based;    // task-based or raw EvFD
    bool rdhup_feature; // whether to use RDHUP feature for socket-based EvFD
    bool rdhup;         // already hup?
    union {
        struct {
            struct list_head read_tasks;
            struct list_head write_tasks;
            struct list_head close_tasks;
            EvFinalizerCallback finalizer;
            void* finalizer_opaque;

            uint32_t offset;            // for AIO
            bool shutdown: 1;           // shutdown the fd in next event loop
                                        // this will allow all tasks to be executed before closing the fd
            int  tcp_connected: 2;      // for TCP-based EvFD
                                        // -1: not socket, 0/false: not connected, 1/true: connected
            bool thread_safe: 1;        // for thread-safe EvFD
                                        // if set to true, you can cast EvFD* to ThreadSafeEvFD*
            bool read_after_close: 1;   // act like system-fd that can be read after close
                                        // evfd will be freed after all data run out
            int rw_state: 2;            // if handle_read/handle_write is called, rw_state will be set to 1/2
                                        // it is useful to avoid calling handle_read/handle_write multiple times in one event loop
            bool reserved: 1;
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

    uint32_t epoll_flags;
    uint64_t modify_flag;    // target epoll_flags

    void* opaque;
    struct list_head link;
};

#ifdef LJS_EVLOOP_THREADSAFE
struct ThreadSafeEvFD {
    struct EvFD __padding;
    pthread_mutex_t rd_lock;    // read
    pthread_mutex_t wr_lock;    // write
    pthread_mutex_t fd_lock;    // close or other
};
#endif

static thread_local int epoll_fd = -1;
static thread_local struct list_head timer_list;
static thread_local ssize_t evloop_events = 0;
static atomic_int thread_id = 0;
static int is_aio_supported = -1;

// used when evfd_destroy is called
static thread_local struct list_head evfd_list;

#ifdef LJS_MBEDTLS
// override certs
static mbedtls_x509_crt tls_global_cert;
static pthread_rwlock_t tls_cert_mod_lock;

// for modified flag
#define LOCK_FLAG(flags, flag)      ((flags) | (uint64_t)(flag) << 32)
#define IS_LOCKED(flags, flag)      ((flags) & (uint64_t)(flag) << 32)
#define UNLOCK_FLAG(flags, flag)    ((flags) & ~((uint64_t)(flag) << 32))
#define ERASE_FLAG(flags, flag)     ((flags) & ~((uint64_t)(flag) << 32 | (flag)))

// use system random to generate random numbers
static int default_rng(void* userdata, unsigned char* output, size_t output_size) {
    if (-1 == getrandom(output, output_size, GRND_NONBLOCK)) {
        long rand = random();
        memcpy(output, &rand, output_size);
    }
    return 0;
}
#endif

#ifdef LJS_DEBUG
void __trace_debug(int events, int direction) {
    // add trace here
    return;
}
#define TRACE_EVENTS(evfd, add) \
    printf("event_trace: func=%s, line=%d, fd=%d, add=%d, cevents=%ld(thread#%d) \n", __func__, __LINE__, evfd_getfd(evfd, NULL), add, evloop_events + add, thread_id); \
    __trace_debug(evloop_events, add); \
    evloop_events += add;
#else
#define TRACE_EVENTS(evfd, add) evloop_events += add;
#endif

#define TRACE_NSTDEVENTS(evfd, add) if((evfd) -> fd[0] > STDERR_FILENO){ TRACE_EVENTS(evfd, add); }

// linux_kernel aio syscall
static inline int io_setup(unsigned nr, aio_context_t* ctxp) {
    return (int) syscall(__NR_io_setup, nr, ctxp);
}

static inline int io_destroy(aio_context_t ctx) {
    return (int) syscall(__NR_io_destroy, ctx);
}

static inline int io_submit(aio_context_t ctx, long nr, struct iocb** iocbpp) {
    return (int) syscall(__NR_io_submit, ctx, nr, iocbpp);
}

static inline int io_getevents(aio_context_t ctx, long min_nr, long max_nr, struct io_event* events, struct timespec* timeout) {
    return (int) syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
}

static inline int io_cancel(aio_context_t ctx, struct iocb* iocb, struct io_event* result) {
    return (int) syscall(__NR_io_cancel, ctx, iocb, result);
}

__attribute__((constructor)) static void evloop_init() {
    struct sigaction act = {
        .sa_handler = SIG_IGN,
        .sa_flags = 0,
    };
    sigaction(SIGPIPE, &act, NULL);

    aio_context_t test_ctx;
    int ret = io_setup(MAX_EVENTS, &test_ctx);
    if (-1 == ret) {
#ifdef LJS_DEBUG
        perror("io_setup");
#endif
        is_aio_supported = false;
    } else {
        io_destroy(test_ctx);
    }
    is_aio_supported = true;

#ifdef LJS_MBEDTLS
    // init 
    mbedtls_x509_crt_init(&tls_global_cert);

    // load system default ca certificates
    int mbret = mbedtls_x509_crt_parse_file(&tls_global_cert, "/etc/ssl/certs/ca-certificates.crt");
    if (mbret != 0) {
        char errbuf[100];
        mbedtls_strerror(mbret, errbuf, sizeof(errbuf));
        printf("Warn: Failed to load default certificates: %s\n", errbuf);
    }

    // mutex for cert modification
    pthread_rwlock_init(&tls_cert_mod_lock, NULL);

#if defined(LJS_DEBUG) && defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(
#ifdef LJS_EVLOOP_FULL_DEBUG
        4
#else
        1
#endif
    );
#endif
#endif
}

__attribute__((destructor)) static void evloop_cleanup(){
    mbedtls_x509_crt_free(&tls_global_cert);
    pthread_rwlock_destroy(&tls_cert_mod_lock);
}

#if defined(LJS_MBEDTLS) && defined(MBEDTLS_DEBUG_C)
void debug_callback(void* evfd, int level, const char* file, int line, const char* str) {
    printf("[ MbedTLS ] fd=%d %s %s:%04d: %s", ((EvFD*)evfd) -> fd[0], level == MBEDTLS_SSL_ALERT_LEVEL_FATAL ? "E:" : level == MBEDTLS_SSL_ALERT_LEVEL_WARNING ? "W:" : "I:", file, line, str);
}
#endif

static void handle_close(int fd, EvFD* evfd, bool rdhup);

// helper functions
#define EPOLL_CTL_FREE -1
static thread_local struct EvFD* evfd_modify_tasks[MAX_EVENTS];
static thread_local int evfd_modify_tasks_count = 0;
static inline void evfd_ctl(struct EvFD* evfd, uint32_t epoll_flags) {
    assert(!evfd -> destroy);
#ifdef LJS_EVLOOP_THREADSAFE
    evfd_perform(evfd, 0);
#endif
    if (epoll_flags == evfd -> epoll_flags) {
        if (evfd -> modify_flag) {
            // delete from modify_tasks
            for (int i = 0; i < evfd_modify_tasks_count; i++) {
                if (evfd_modify_tasks[i] == evfd) {
                    evfd_modify_tasks[i] = evfd_modify_tasks[evfd_modify_tasks_count - 1];
                    evfd_modify_tasks_count--;
                    break;
                }
            }
            evfd -> modify_flag = 0;
        }
        goto end;
    }

    // already modify?
    if (evfd -> modify_flag) {
        evfd -> modify_flag = epoll_flags;
        goto end;
    }

    // assign epoll_flags
    evfd_modify_tasks[evfd_modify_tasks_count++] = evfd;
    evfd -> modify_flag = epoll_flags;

    if (epoll_flags == EPOLL_CTL_FREE) {
        // remove from evfd_list
        list_del(&evfd -> link);
    }

end:
#ifdef LJS_DEBUG
    printf("evfd_ctl: fd=%d, r=%d, w=%d\n", evfd -> fd[0], epoll_flags & EPOLLIN, epoll_flags & EPOLLOUT);
#endif

#ifdef LJS_EVLOOP_THREADSAFE
    evfd_perform_end(evfd, 0);
#else
    return;
#endif
}

// cautious when using this function
// it may make the fd inaccessible but not closed
static inline void evfd_mod(struct EvFD* evfd, bool add, int epoll_flags) {
    int flag = evfd -> modify_flag ? evfd -> modify_flag : evfd -> epoll_flags;
    if (add)    flag &= LOCK_FLAG(flag, epoll_flags);
    else        flag &= ERASE_FLAG(flag, epoll_flags);
    evfd_ctl(evfd, flag);
}

static inline void evfd_mod_start(bool force) {
    int keepalive_count = 0;
    struct EvFD *keepalive_evfd[MAX_EVENTS];

    for (int i = 0; i < evfd_modify_tasks_count; i++) {
        struct EvFD* task = evfd_modify_tasks[i];
        if (task -> modify_flag == EPOLL_CTL_FREE) {
            if (force || (task -> incoming_buffer && buffer_is_empty(task -> incoming_buffer))){
#ifdef LJS_DEBUG
                printf("evfd_mod_start: free fd=%d\n", task -> fd[0]);
#endif
#ifdef LJS_MBEDTLS
                if(task -> type == EVFD_SSL){
                    // clean up ssl
                    free2(task -> proto.ssl);
                }
#endif
                if (task -> incoming_buffer) buffer_free(task -> incoming_buffer);
                task -> fd[0] = -1; // fall safe
                free2(task);
            }else{
#ifdef LJS_DEBUG
                printf("evfd_mod_start(skip): fd=%d, not empty, incoming_buffer=%d\n", task -> fd[0], 
                    task -> incoming_buffer ? buffer_used(task -> incoming_buffer) : 0
                );
#endif
                keepalive_evfd[keepalive_count++] = task;
            }
        } else {
            // process marked modify_flag
            uint32_t flag = (task -> modify_flag >> 32) | (task -> modify_flag & 0xffffffff);
            struct epoll_event ev = {
               .events = flag,
               .data.ptr = task
            };
            if (-1 == epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task -> fd[0], &ev)) {
#ifdef LJS_DEBUG
                perror("epoll_ctl");
#endif
            } else {
#ifdef LJS_DEBUG
                printf("epoll_ctl: fd=%d, events=%ld, r=%ld, w=%ld\n", task -> fd[0], task -> modify_flag, task -> modify_flag & EPOLLIN, task -> modify_flag & EPOLLOUT);
#endif
                task -> epoll_flags = task -> modify_flag;
            }
            task -> modify_flag = 0;
        }
    }

    evfd_modify_tasks_count = keepalive_count;
    memcpy(evfd_modify_tasks, keepalive_evfd, sizeof(struct EvFD*) * keepalive_count);
}

#ifdef LJS_EVLOOP_THREADSAFE
static inline bool evfd_perform(EvFD* fd, int action){
    if(!fd -> u.task.tcp_connected) return false;

    if(fd -> u.task.thread_safe){
        struct ThreadSafeEvFD* tfd = (struct ThreadSafeEvFD*)fd;
        switch (action){
            case PIPE_READ:
                pthread_mutex_lock(&tfd -> rd_lock);
                break;

            case PIPE_WRITE:
                pthread_mutex_lock(&tfd -> wr_lock);
                break;

            default:
                pthread_mutex_lock(&tfd -> fd_lock);
                break;
        }
    }
}

static inline void evfd_perform_end(EvFD* fd, int action){
    if(!fd -> u.task.tcp_connected) return;

    switch (action){
        case PIPE_READ:
            pthread_mutex_unlock(&((struct ThreadSafeEvFD*)fd) -> rd_lock);
            break;

        case PIPE_WRITE:
            pthread_mutex_unlock(&((struct ThreadSafeEvFD*)fd) -> wr_lock);
            break;

        default:
            pthread_mutex_unlock(&((struct ThreadSafeEvFD*)fd) -> fd_lock);
            break;
    }
    return true;
}
#endif

#define PERFORM(evfd, type, then) if(evfd_perform(evfd, type)){ then; evfd_perform_end(evfd, type); }

static inline void free_task(struct Task* task);

// required to check whether fd should EPOLLIN/EPOLLOUT
static void check_queue_status(EvFD* evfd) {
    if (evfd -> destroy) return;

    uint32_t new_events = evfd -> modify_flag | EPOLLLT;
    if(evfd -> u.task.tcp_connected == 0){
        new_events = EPOLLLT | EPOLLOUT | EPOLLHUP | EPOLLERR;
        goto modify;
    }

    switch (evfd -> type) {
        case EVFD_AIO:
        case EVFD_TIMER:
        case EVFD_INOTIFY:
            if (!list_empty(&evfd -> u.task.read_tasks) || !list_empty(&evfd -> u.task.write_tasks))
                new_events |= EPOLLIN;
        break;

#ifdef LJS_MBEDTLS
        case EVFD_SSL:
            new_events |= EPOLLHUP | EPOLLERR;
            // if(evfd -> proto.ssl -> proto.ssl_wants_write) new_events |= EPOLLOUT;
            // if(evfd -> proto.ssl -> want_read) new_events |= EPOLLIN;
            if (!buffer_is_empty(evfd -> proto.ssl -> sendbuf))
                new_events |= EPOLLOUT;
            if (evfd -> proto.ssl -> want_read)
                new_events |= EPOLLIN;
        break;
#endif
        case EVFD_PTY:
            new_events = EPOLLIN | EPOLLHUP | EPOLLERR;

        default:
            new_events |= EPOLLHUP | EPOLLERR;
            if (evfd -> rdhup_feature && !evfd -> rdhup)
                new_events |= EPOLLRDHUP;   // socket feature
            if (!list_empty(&evfd -> u.task.read_tasks) && !evfd -> rdhup)
                new_events |= EPOLLIN;
            if (!list_empty(&evfd -> u.task.write_tasks))
                new_events |= EPOLLOUT;
        break;
    }

modify:
    evfd_ctl(evfd, new_events);
}

// buffer
#define CALL_AND_HANDLE(func, rewind_blk, ...) int _ret = func(__VA_ARGS__); \
    if (unlikely(evfd -> destroy)) return; \
    if (unlikely(_ret & EVCB_RET_REWIND)) rewind_blk; \
    if (_ret & EVCB_RET_CONTINUE) goto main;

static inline bool pipeto_ready(struct PipeToTask* task) {
    if (task -> ready_state == 2) return true;
    return task -> ready_state++ == 1;
}

static inline void __pipeto_remove_task(struct PipeToTask* task, struct list_head* tlist) {
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
        } else if (is_from && !has_data) {
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
        check_queue_status(task -> to);
    } else {
        if (!both_closed) {
            struct list_head* target_list = is_from
                ? &task -> to -> u.task.write_tasks
                : &task -> from -> u.task.read_tasks;
            EvFD* fd = is_from ? task -> from : task -> to;

            __pipeto_remove_task(task, target_list);
            TRACE_NSTDEVENTS(is_from ? task -> to : task -> from, -1);
            check_queue_status(fd);
        }

        free2(task);
    }

    return false;
}

static inline void free_task(struct Task* task) {
    if (task -> buffer) buffer_free(task -> buffer);
    free2(task);
}

// Note: as handshake will return 0 if successful, zero_as_error should set to false
static inline int handle_mbedtls_ret(EvFD* evfd, bool zero_as_error, int ret) {
    if (ret > 0) {
        return ret;
    } else if (ret == 0 && zero_as_error) {
        mbedtls_ssl_close_notify(&evfd -> proto.ssl -> ctx);
        handle_close(evfd_getfd(evfd, NULL), evfd, false);
        return -1;
    } else switch (ret) {
        case 0:
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            // short of data
            // Note: handled in handle_ssl_recv/send
        return 0;

        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            handle_close(evfd_getfd(evfd, NULL), evfd, false);
        break;

        // note: we should handle early data before reading
#ifdef MBEDTLS_SSL_EARLY_DATA
        case MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA:
            struct Buffer* buf = evfd -> incoming_buffer;
            buffer_flat(buf);
            while (!buffer_is_full(buf)){
                ssize_t n = mbedtls_ssl_read_early_data(&evfd -> proto.ssl -> ctx, buf -> buffer + buf -> end, buffer_available(buf));
                if(n == MBEDTLS_ERR_SSL_CANNOT_READ_EARLY_DATA ) break;
                if(n < 0){
                    if(buffer_is_full(buf)){
                        buffer_realloc(buf, buf -> size * 1.5, true);
                    }else{
                        evfd -> proto.ssl -> mb_errno = n;
                        handle_close(evfd_getfd(evfd, NULL), evfd, false);
                        break;
                    }
                }else if(n){
                    buf -> end += n;
                }else{
                    break;  // no more early data
                }
            }
            return 0;
        break;
#endif

        default:
            evfd -> proto.ssl -> mb_errno = ret;
#ifdef LJS_DEBUG
            char errbuf[100];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            printf("MbedTLS error: %s\n", errbuf);
#endif
            handle_close(evfd_getfd(evfd, NULL), evfd, false);
        break;
    }

    return -1;
}

static void handle_handshake_done(EvFD* evfd){
    evfd -> proto.ssl -> ssl_handshaking = false;

    // callback
    if(evfd -> proto.ssl -> handshake_cb)
        evfd -> proto.ssl -> handshake_cb(evfd, true, evfd -> proto.ssl -> handshake_user_data);
}

static void handle_write(int fd, EvFD* evfd, struct io_event* ioev);
static inline ssize_t ssl_poll_data(EvFD* evfd) {
    if (evfd -> type != EVFD_SSL) return 0;
    if (evfd -> proto.ssl -> ssl_handshaking) return 0;
    buffer_flat(evfd -> incoming_buffer);
try_read:
    int ret = mbedtls_ssl_read(
        &evfd -> proto.ssl -> ctx, 
        evfd -> incoming_buffer -> buffer + evfd -> incoming_buffer -> end, 
        buffer_available(evfd -> incoming_buffer)
    );
    if(ret == 0 && buffer_is_full(evfd -> incoming_buffer)){
        buffer_realloc(evfd -> incoming_buffer, evfd -> incoming_buffer -> size * 1.5, true);
        goto try_read;
    }
    int readed = handle_mbedtls_ret(evfd, true, ret);
    if(readed > 0)
        evfd -> incoming_buffer -> end = (evfd -> incoming_buffer -> end + readed) % evfd -> incoming_buffer -> size;
    return readed;
}

// handle readable event/ssl recv event
static void handle_read(int fd, EvFD* evfd, struct io_event* ioev, struct inotify_event* inev) {
    if (evfd -> u.task.rw_state >> 1) return;  // already in read state
    if (list_empty(&evfd -> u.task.read_tasks)) goto end;
    evfd -> u.task.rw_state |= 0b10;  // set read state
    // get data
    struct Task* next_task = list_entry(evfd -> u.task.read_tasks.next, struct Task, list);
    uint32_t n = 0;
    if (evfd -> type == EVFD_NORM || evfd -> type == EVFD_PTY) {
        uint8_t* ptr_buffer = evfd -> incoming_buffer -> buffer + evfd -> incoming_buffer -> end;
        n = buffer_read(evfd -> incoming_buffer, fd, UINT32_MAX);

        // n == 0: use existing data, no-return
        if (n == -1) {
#ifdef LJS_DEBUG
            perror("evfd_read");
#endif
            goto _return;
        }    // error

        // strip_if_is_\n
        if (evfd -> strip_if_is_n && *ptr_buffer == '\n') {
            buffer_seek_cur(evfd -> incoming_buffer, 1);
            if (n-- == 1) goto _return;
        }
        evfd -> strip_if_is_n = false;
    } else if (evfd -> type == EVFD_AIO/* && iocb */) {
        n = ioev -> res;
        if(n == -1) goto _return;
        evfd -> u.task.offset += n;
        buffer_push(evfd -> incoming_buffer, (uint8_t*) ((struct iocb*) ioev -> obj) -> aio_buf, n);
    } else if (evfd -> type == EVFD_SSL) {
        if(evfd -> destroy) goto start;  // skip reading
        // evfd_ssl: read from mbedtls
        if(evfd -> proto.ssl -> ssl_handshaking){
            n = handle_mbedtls_ret(evfd, false, mbedtls_ssl_handshake(&evfd -> proto.ssl -> ctx));
            if (n == -1) goto _return;
            handle_handshake_done(evfd);

            // write to fd before read
            handle_write(evfd -> fd[0], evfd, NULL);
            if (evfd -> destroy) goto _return;
        }
        n = ssl_poll_data(evfd);
        if (n == -1) goto _return;
    } else if (evfd -> type == EVFD_UDP) {
        // TODO: buffer_recvfrom
        struct UDPContext* ctx = evfd -> proto.udp;
        n = recvfrom(fd, evfd -> incoming_buffer -> buffer,
            evfd -> incoming_buffer -> size - evfd -> incoming_buffer -> end, 0,
            (struct sockaddr*) &ctx -> peer_addr,
            &ctx -> addr_len);
        if (n == -1) {
#ifdef LJS_DEBUG
            perror("recvfrom");
#endif
            goto _return;
        } else if (n == 0) goto _return;
        evfd -> incoming_buffer -> end += n;
    } else if (next_task -> type == EV_TASK_PIPETO) {
        if (!pipeto_ready(next_task -> cb.pipeto)) {
            // suspend read
            evfd_mod(evfd, false, EPOLLIN);
            goto _return;
        }
        // closed?
        if (PIPETO_WCLOSED(next_task -> cb.pipeto -> closed)) {
            // move data back
            struct Buffer* buf = next_task -> cb.pipeto -> exchange_buffer;
            n = buffer_merge2(evfd -> incoming_buffer, buf);
            // finalize task
            free_task(next_task);
        } else {
            // check whether buffer full
            EvFD* to = next_task -> cb.pipeto -> to;
            struct Buffer* buf = next_task -> cb.pipeto -> exchange_buffer;
            if (buffer_is_full(buf)) {
                evfd_mod(evfd, false, EPOLLIN); // suspend read
                goto _return;
            } else {
                evfd_mod(to, true, EPOLLOUT);   // wakeup write
                n = buffer_read(buf, fd, UINT32_MAX);
                if (n == -1) {
#ifdef LJS_DEBUG
                    perror("evfd_read");
#endif
                    goto _return;
                }
            }
        }
    }

start:
    struct list_head* cur = NULL, * tmp;
    int prevexec = 0;
mainloop:
    list_for_each_prev_safe(cur, tmp, &evfd -> u.task.read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        // if(evfd -> destroy) return; // everything is destroyed

        // linux inotify
        // XXX: use struct to compute before for better performance?
        if (evfd -> type == EVFD_INOTIFY) {
            char real_path[PATH_MAX + 1];

            // find path by wd
            const char* str = evfd -> proto.inotify -> paths[inev -> wd];
            assert(str);
            size_t len = strlen(str);
            memcpy(real_path, str, len + 1);

            if (inev -> len) {
                memcpy(real_path + len, inev -> name, inev -> len);
                len += inev -> len - 1;  // note: len include \0
            }

            if (inev -> cookie & IN_MOVED_FROM) {
                evfd -> proto.inotify -> move_tmp[0] = strdup2(real_path);
                goto inev_move;
            } else if (inev -> cookie & IN_MOVED_TO) {
                evfd -> proto.inotify -> move_tmp[1] = strdup2(real_path);
                goto inev_move;
            }

            // callback
            task -> cb.inotify(evfd, real_path, inev -> mask, NULL, task -> opaque);
            prevexec ++;
            continue;

        inev_move:
            if (!(
                evfd -> proto.inotify -> move_tmp[0] &&
                evfd -> proto.inotify -> move_tmp[1]
                )) continue;
            // handle move event
            task -> cb.inotify(evfd, evfd -> proto.inotify -> move_tmp[0], IN_MOVE, NULL, task -> opaque);
            free2(evfd -> proto.inotify -> move_tmp[0]);
            evfd -> proto.inotify -> move_tmp[0] = NULL;
            free2(evfd -> proto.inotify -> move_tmp[1]);
            evfd -> proto.inotify -> move_tmp[1] = NULL;
            prevexec ++;
            continue;

        } else if (evfd -> type == EVFD_TIMER) {
            // read timerfd to get count
            uint64_t val;
            if (sizeof(val) == read(fd, &val, sizeof(val))) {
                task -> cb.timer(val, task -> opaque);
                prevexec ++;
                // will be reused, clear current task
                if (evfd -> proto.timer -> once) {
                    list_del(&task -> list);
                    TRACE_EVENTS(evfd, -1);
                    free2(task);
                }
            } else {
#ifdef LJS_DEBUG
                perror("timerfd read");
#endif
            }
            continue;
        }

        if(0 == n) break;   // no more data
        TRACE_EVENTS(evfd, -1);
        list_del(cur); // avoid recursive call

        if (task -> type == EV_TASK_NOOP) {
            task -> cb.sync(evfd, true, task -> opaque);
            prevexec ++;
            continue;
        }

main:   // while loop
        uint32_t bufsize = buffer_used(evfd -> incoming_buffer);
        if (bufsize == 0) {
            // no data
            list_add(&task -> list, &evfd -> u.task.read_tasks);
            TRACE_EVENTS(evfd, +1);
            goto end;
        }
        switch (task -> type) {
            case EV_TASK_READ: // readsize
                // note: buffer contains 1 byte free space to maintain circular buffer
                if (task -> buffer -> size - 1 <= bufsize) {
                    // export
                    uint32_t copied = buffer_pop(evfd -> incoming_buffer, task -> buffer -> buffer, task -> buffer -> size);
                    CALL_AND_HANDLE(
                        task -> cb.read,
                        { buffer_seek_cur(evfd -> incoming_buffer, -copied); },
                        evfd, true, task -> buffer -> buffer, task -> buffer -> size - 1, task -> opaque
                    );
                    prevexec ++;
                    goto _continue;
                }
            goto __break;

            case EV_TASK_READLINE:
                if (n <= 0) goto _break;

                // find \r\n or \n
                char forward_char = 0;
                uint32_t first_r_occurrence = UINT32_MAX;
                uint32_t first_r_bytes = 0;
                uint32_t copied = 0;
                BUFFER_UNSAFE_FOREACH_BYTE(evfd -> incoming_buffer, bytes, chr) {
                    uint32_t i = __i;   // note: __i is index of current byte position in buffer    
                    copied++;
                    if (chr == '\n') {
                        char* nchr = (void*) (evfd -> incoming_buffer -> buffer + i);
                        uint32_t bytes = copied -1;
                        // CRLF check: replace to end-of-line with \0
                        if (i != 0 && forward_char == '\r') nchr -= 1, bytes -= 1;
                        *nchr = '\0';

                        // Copy buffer to task buffer
                        buffer_pop(evfd -> incoming_buffer, task -> buffer -> buffer, copied);

                        // Trigger callback
                        CALL_AND_HANDLE(
                            task -> cb.read,
                            // Note: buffer would be changed by callback, absolute-position is dangerous
                            { buffer_seek_cur(evfd -> incoming_buffer, -copied); },
                            evfd, true, task -> buffer -> buffer, bytes, task -> opaque
                        );
                        prevexec ++;
                        goto _continue;
                    } else if (first_r_occurrence == UINT32_MAX && chr == '\r') {
                        // fallback if \n not found
                        first_r_occurrence = i;
                        first_r_bytes = bytes;
                    }

                    forward_char = chr;
                }

                // fallback: \r
                if (first_r_occurrence != UINT32_MAX) {
                    evfd -> strip_if_is_n = true;
                    char* rchr = (void*) (evfd -> incoming_buffer -> buffer + first_r_occurrence);
                    *rchr = '\0';

                    uint32_t readed = buffer_pop(evfd -> incoming_buffer, task -> buffer -> buffer, first_r_bytes);
                    CALL_AND_HANDLE(
                        task -> cb.read,
                        { buffer_seek_cur(evfd -> incoming_buffer, -readed); },
                        evfd, true, task -> buffer -> buffer, readed, task -> opaque
                    );
                    prevexec ++;

                    goto _continue;
                }

                // Buffer full?
                // Note: buffer contains 1 byte free space to maintain circular buffer and \0 terminator
                if (bufsize >= (task -> buffer -> size - 2)) {
                    *(task -> buffer -> buffer + task -> buffer -> size - 2) = '\0';
                    uint32_t copied = buffer_pop(evfd -> incoming_buffer, task -> buffer -> buffer, task -> buffer -> size - 2);
                    CALL_AND_HANDLE(
                        task -> cb.read,
                        { buffer_seek_cur(evfd -> incoming_buffer, -copied); },
                        evfd, true, task -> buffer -> buffer, task -> buffer -> size - 2, task -> opaque
                    );
                    prevexec ++;
                    goto _continue;
                }

            // Not found
            goto __break;

            case EV_TASK_READONCE: // readonce
                // int available;
                // ioctl(fd, FIONREAD, &available);
                // available = available > task -> total_size ? task -> total_size : available;

                buffer_pop(evfd -> incoming_buffer, task -> buffer -> buffer, n);
                size_t n2 = n;  // backup
                n = 0;          // avoid reuse used data
                CALL_AND_HANDLE(
                    task -> cb.read,
                    { buffer_seek_cur(evfd -> incoming_buffer, -n2); },
                    evfd, true, task -> buffer -> buffer, n2, task -> opaque
                )
                prevexec ++;
            goto _continue;

            // Note: the main logic of pipeto is in handle_write
            case EV_TASK_PIPETO:
                // filter
                EvPipeToFilter filter = task -> cb.pipeto -> filter;
                struct Buffer* buf = task -> cb.pipeto -> exchange_buffer;
                if (filter && !filter(buf, task -> cb.pipeto -> filter_opaque)) {
                    // skip current chunk
                    buffer_seek_cur(buf, n);
                } else {
                    // push to target buffer
                    assert(buffer_merge2(task -> cb.pipeto -> to -> incoming_buffer, buf) == n);
                }
            goto _return;   // block task execution

            _continue:
                if (evfd -> destroy) goto _return;   // task already destroyed
                free_task(task);
            continue;

            __break:
                if (evfd -> destroy) goto _return;
                list_add(&task -> list, &evfd -> u.task.read_tasks);
                TRACE_EVENTS(evfd, +1);
            break;

            _break:
                if (evfd -> destroy) goto _return;   // task already destroyed
                free_task(task);
            break;

            default:    // never reach here
                abort();
        }
    }

    // check if loop ended but still have task
    // mostly, when executing callback of last task
    // callback add new task, but list_for_each_prev_safe will not handle it
    if (prevexec && cur == &evfd -> u.task.read_tasks && !list_empty(&evfd -> u.task.read_tasks)) {
        prevexec = 0;   // avoid infinite loop
        goto mainloop;
    }
end:
    // finalize for timerfd
    if (evfd -> type == EVFD_TIMER) {
        if (evfd -> proto.timer -> once) {
            evfd -> proto.timer -> time = 0;
            evfd_ctl(evfd, EPOLLLT);    // disable timerfd
        }
    } else if (evfd -> type == EVFD_SSL && !evfd -> proto.ssl -> want_read) {
        evfd -> proto.ssl -> want_read = !list_empty(&evfd -> u.task.read_tasks);
    }
    check_queue_status(evfd);
_return:
    evfd -> u.task.rw_state &= 0b01;   // set read state
}

static inline int blksize_get(int fd) {
    int blksize;
    if (ioctl(fd, BLKSSZGET, &blksize) != 0) return 512;
    return blksize;
}

#ifdef LJS_DEBUG
// debug: AIO buffer对齐检查
static bool check_aio_alignment(EvFD* evfd, struct Buffer* buf, off_t offset) {
    int blksize = blksize_get(evfd -> fd[1]);

    if ((uintptr_t) buf -> buffer % blksize != 0 || offset % blksize != 0)
        return false;

    buf -> size = (buf -> size / blksize) * blksize;
    return true;
}
#endif

static inline int submit_aio_read(EvFD* evfd, struct Task* task) {
    if (!is_aio_supported) return -1;

    // buffer对齐
    buffer_aligned(task -> buffer, blksize_get(evfd -> fd[1]));

    // 提交io事务
    struct iocb iocb = {
        .aio_fildes = evfd -> fd[1],
        .aio_lio_opcode = IOCB_CMD_PREAD,
        .aio_buf = (unsigned long long)task -> buffer -> buffer,
        .aio_nbytes = task -> buffer -> size - 1,
        .aio_offset = evfd -> u.task.offset,
        .aio_data = (uint64_t) task,
        .aio_flags = IOCB_FLAG_RESFD,
        .aio_resfd = evfd -> fd[0],
    };
    int ret = io_submit(evfd -> aio.ctx, 1, (struct iocb* [1]) { &iocb });
#ifdef LJS_DEBUG
    printf("submit_aio_read: fd=%d, size=%d, ret=%d\n", evfd -> fd[1], task -> buffer -> size - 1, ret);
    if (ret == -1) perror("io_submit");
#endif
    return ret;
}

// 注意这里的buffer不能circular
static inline int submit_aio_write(EvFD* evfd, struct Task* task) {
    if (!is_aio_supported) return -1;

    // buffer对齐，适配aio
    buffer_aligned(task -> buffer, blksize_get(evfd -> fd[1]));

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
        .aio_nbytes = task -> buffer -> size - 1,
        .aio_offset = evfd -> u.task.offset,
        .aio_data = (uint64_t) task,
        .aio_flags = IOCB_FLAG_RESFD,
        .aio_resfd = evfd -> fd[0],
    };
    int ret = io_submit(evfd -> aio.ctx, 1, (struct iocb* [1]) { &iocb });

#ifdef LJS_DEBUG
    printf("submit_aio_write: fd=%d, remain=%d, ret=%d\n", evfd -> fd[1], buffer_used(task -> buffer), ret);
    if (ret == -1) perror("io_submit");
#endif
    return ret;
}

// handle write event for normal/ssl fd or aio fd
static void handle_write(int fd, EvFD* evfd, struct io_event* ioev) {
    if (evfd -> type == EVFD_AIO && !list_empty(&evfd -> u.task.write_tasks)) {
        if (ioev -> res < 0) {
            handle_close(fd, evfd, false);
            return;
        }
        // precheck
        // struct Task* task = list_entry(evfd -> u.task.write_tasks.next, struct Task, list);
        // buffer_seek_cur(task -> buffer, ioev -> res);
    }

    if(evfd -> u.task.rw_state & 0x1) return;  // read state
    evfd -> u.task.rw_state |= 0x1;
    if(evfd -> type == EVFD_SSL && evfd -> proto.ssl -> ssl_handshaking){
        int n = handle_mbedtls_ret(evfd, false, mbedtls_ssl_handshake(&evfd -> proto.ssl -> ctx));
        if(n == -1) goto _return;
        handle_handshake_done(evfd);

        // also active read task
        handle_read(fd, evfd, NULL, NULL);
        if(evfd -> destroy) goto _return;
    }

    struct list_head* cur, * tmp;
    // loop:
    list_for_each_prev_safe(cur, tmp, &evfd -> u.task.write_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);

        if (task -> type == EV_TASK_PIPETO) {
            struct PipeToTask* pt = task -> cb.pipeto;

            if (!pipeto_ready(pt)) {
                // suspend write
                evfd_mod(evfd, false, EPOLLOUT);
                goto _return;
            }

            // XXX: this action break the write logic
            // and not capable to handle AIO write
            ssize_t writed = buffer_write(pt -> exchange_buffer, fd, UINT32_MAX);

            if (writed == -1) {
#ifdef LJS_DEBUG
                perror("evfd_write");
#endif
                handle_close(fd, evfd, false);
                goto _return;
            }

            if (buffer_is_empty(task -> buffer)) {
                // suspense
                if (PIPETO_RCLOSED(pt -> closed)) {
                    pipeto_handle_close(evfd, pt, false);
                    continue;   // next task
                } else {
                    evfd_mod(pt -> from, true, EPOLLIN);
                    evfd_mod(evfd, false, EPOLLOUT);
                    goto _return;
                }
            } else {
                // wait for next write
                evfd_mod(evfd, true, EPOLLOUT);
                goto _return;
            }
        } else if (task -> type == EV_TASK_NOOP) {
            list_del(&task -> list);
            TRACE_EVENTS(evfd, -1);
            task -> cb.sync(evfd, true, task -> opaque);

            free2(task);
            continue;
        }

        ssize_t n;

        if (evfd -> type == EVFD_AIO) {
            n = ioev -> res;

            if (n == 0) {
                // submit io write
                if (submit_aio_write(evfd, task) == -1) goto _return;
            }

            buffer_seek_cur(task -> buffer, n);
            ioev -> res = 0;
        } else if (evfd -> type == EVFD_SSL) {
            // write to mbedtls
            ssize_t prev_write;
            n = 0;
            while (handle_mbedtls_ret(evfd, false,
                prev_write = mbedtls_ssl_write(
                    &evfd -> proto.ssl -> ctx,
                    task -> buffer -> buffer + n,
                    task -> buffer -> size - n - 1
                )
            ) > 0) {
                n += prev_write;
            }
            // seek
            if(n)   buffer_seek_cur(task -> buffer, n);
            else    evfd_mod(evfd, true, EPOLLOUT);
        } else {
            // write to fd directly
            n = buffer_write(task -> buffer, fd, UINT32_MAX);
        }

        if (n > 0) {
            if (buffer_is_empty(task -> buffer)) {
                TRACE_EVENTS(evfd, -1);
                list_del(&task -> list);
                if (task -> cb.write) task -> cb.write(evfd, true, task -> opaque);
                free_task(task);
            }
        } else if (n == -1) {
#ifdef LJS_DEBUG
            perror("evfd_write");
#endif
            handle_close(fd, evfd, false);
            goto _return;
        } else {
            break;  // fd is busy
        }
    }
    // if(!list_empty(&evfd -> u.task.write_tasks)) goto loop;

    check_queue_status(evfd);
_return:
    evfd -> u.task.rw_state &= 0b10;   // clear write state
}

static void clear_tasks(EvFD* evfd, bool rdhup, bool call_close) {
    struct list_head* cur, * tmp;
    bool has_data = evfd -> incoming_buffer && !buffer_is_empty(evfd -> incoming_buffer);
    // read queue
    if(!evfd -> rdhup){
        list_for_each_prev_safe(cur, tmp, &evfd -> u.task.read_tasks) {
            struct Task* task = list_entry(cur, struct Task, list);
            if (task -> type == EV_TASK_NOOP) {
                task -> cb.sync(evfd, false, task -> opaque);
                goto _continue;
            }
            if (task -> type == EV_TASK_PIPETO) {
                evfd -> u.task.read_tasks.next = cur;  // delete elements between cur and first
                cur -> prev = &evfd -> u.task.read_tasks;
                pipeto_handle_close(evfd, task -> cb.pipeto, true); // also freed task
                continue;
            }

            if (task -> cb.read) {
                if (has_data) {
                    // copy to user buffer
                    uint32_t readed = buffer_copyto(evfd -> incoming_buffer, task -> buffer -> buffer, task -> buffer -> size - 1);

                    // Note: readline requires \0 terminator
                    if (task -> buffer -> end < task -> buffer -> size - 1 && task -> type == EV_TASK_READLINE)
                        task -> buffer -> buffer[task -> buffer -> end] = '\0';    // end with \0

                    task -> cb.read(evfd, true, task -> buffer -> buffer, readed, task -> opaque);
                    has_data = false;
                } else {
                    //     task -> cb.sync(evfd, task -> opaque);
                    task -> cb.read(evfd, false, task -> buffer -> buffer, 0, task -> opaque);
                }
            }

_continue:
            free_task(task);
            TRACE_EVENTS(evfd, -1);
        }
    }
    if(rdhup) return;   // only close read tasks

    if (evfd -> u.task.finalizer) {
        evfd -> u.task.finalizer(evfd, evfd -> incoming_buffer, evfd -> u.task.finalizer_opaque);
        evfd -> u.task.finalizer = NULL;
    }

    // write queue
    list_for_each_prev_safe(cur, tmp, &evfd -> u.task.write_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        if (task -> type == EV_TASK_PIPETO) {
            evfd -> u.task.write_tasks.next = cur;  // delete elements between cur and first
            cur -> prev = &evfd -> u.task.write_tasks;
            pipeto_handle_close(evfd, task -> cb.pipeto, true); // also freed task
            continue;
        }
        if (task -> type == EV_TASK_NOOP) {
            task -> cb.sync(evfd, false, task -> opaque);
            goto _continue2;
        }
        if (task -> cb.write) {
            if (task -> type == EV_TASK_NOOP)
                task -> cb.sync(evfd, true, task -> opaque);
            else
                task -> cb.write(evfd, true, task -> opaque);
        }

_continue2:
        free_task(task);
        TRACE_EVENTS(evfd, -1);
    }

    // close queue
    if (call_close)
        list_for_each_prev_safe(cur, tmp, &evfd -> u.task.close_tasks) {
            struct Task* task = list_entry(cur, struct Task, list);
            task -> cb.close(evfd, false, task -> opaque);
            free2(task);
            TRACE_NSTDEVENTS(evfd, -1);
        }
}

static void handle_close(int fd, EvFD* evfd, bool is_rdhup) {

#ifdef LJS_DEBUG
    printf("handle_close: fd=%d; ", fd);
#endif

    if (evfd -> destroy || (is_rdhup && evfd -> rdhup)) return;
    evfd_ctl(evfd, EPOLL_CTL_FREE); // will free in next epoll loop
    if(!is_rdhup) evfd -> destroy = true;

    // Note: SSL should read again after close, to clear SSL buffer
    // due to destroy=true, no more action will be taken except read
    if (evfd -> type == EVFD_SSL) ssl_poll_data(evfd);
    if (evfd -> incoming_buffer) handle_read(fd, evfd, NULL, NULL);

    // remove in epoll
    if(!is_rdhup){
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        TRACE_NSTDEVENTS(evfd, -1);
    }

    if (evfd -> task_based)
        clear_tasks(evfd, is_rdhup, true);
    else if (evfd -> u.cb.close)
        evfd -> u.cb.close(evfd, is_rdhup, evfd -> u.cb.close_opaque);

    // close fd
    if (!evfd -> destroy && !is_rdhup) switch (evfd -> type) {
        case EVFD_NORM:
        case EVFD_PTY:
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
            if (evfd -> proto.ssl) {
                buffer_free(evfd -> proto.ssl -> sendbuf);
                buffer_free(evfd -> proto.ssl -> recvbuf);
                mbedtls_ssl_free(&evfd -> proto.ssl -> ctx);
                mbedtls_ssl_config_free(&evfd -> proto.ssl -> config);
                // Note: ssl object should live as long as evfd to get errno
                // it will be freed in next epoll loop
            }
#endif
        break;

        default:
            abort();
        break;
    }
    // Note: no free incoming buffer to use rest data of buffer

    if(is_rdhup){
        evfd -> rdhup = true;
        check_queue_status(evfd);
    }
}

static void handle_sync(EvFD* evfd) {
    struct list_head* cur, * tmp;
    // read queue
    list_for_each_prev_safe(cur, tmp, &evfd -> u.task.read_tasks) {
        struct Task* task = list_entry(cur, struct Task, list);
        task -> cb.sync(evfd, true, task -> opaque);
        if (task -> type == EV_TASK_SYNC) {
            TRACE_EVENTS(evfd, -1);
            list_del(&task -> list);
            free2(task);
        }
    }
}

#ifdef LJS_MBEDTLS
static int handle_ssl_send(void* ctx, const unsigned char* buf, size_t len) {
    EvFD* evfd = (EvFD*) ctx;
    struct Buffer* sendbuf = evfd -> proto.ssl -> sendbuf;

    if (evfd -> destroy) return 0;
    if (buffer_is_full(sendbuf)) return MBEDTLS_ERR_SSL_WANT_WRITE;

    // copy chunk to buffer
    return buffer_push(sendbuf, buf, len);
}

static int handle_ssl_recv(void* ctx, unsigned char* buf, size_t len) {
    EvFD* evfd = (EvFD*) ctx;
    if (evfd -> destroy || evfd -> rdhup) return 0;   // closed

    size_t copied = buffer_pop(evfd -> proto.ssl -> recvbuf, buf, len);
    if (copied == 0) {
        evfd -> proto.ssl -> want_read = true;
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return copied;
}

static void ssl_handle_handshake(EvFD* evfd) {
    int ret;
    while ((ret = mbedtls_ssl_handshake(&evfd -> proto.ssl -> ctx)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            check_queue_status(evfd);
            return;
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            evfd -> proto.ssl -> want_read = false;
            check_queue_status(evfd);
            return;
        } else {
            // fatal error
            evfd_close(evfd);
#ifdef LJS_DEBUG
            char mberror[1024];
            mbedtls_strerror(ret, mberror, sizeof(mberror));
            printf("ssl_handle_handshake: ret=%d, strerror=%s\n", ret, mberror);
#endif
            evfd -> proto.ssl -> mb_errno = ret;
            return;
        }
    }
    // handshake done
    evfd -> proto.ssl -> ssl_handshaking = false;
    evfd -> proto.ssl -> handshake_cb(evfd, true, evfd -> proto.ssl -> handshake_user_data);

    // try to execute pending tasks
    handle_read(evfd -> fd[0], evfd, NULL, NULL);
    handle_write(evfd -> fd[0], evfd, NULL);
}

struct SSL_data {
    char* name;
    char* server_name; // optional
    mbedtls_x509_crt* cacert;
    mbedtls_pk_context* cakey;
    struct list_head link;
};

static struct list_head cert_list;

int ssl_sni_callback(void* opaque, mbedtls_ssl_context* ssl, const unsigned char* name, size_t len) {
    struct list_head* cur, * tmp;
    list_for_each_prev_safe(cur, tmp, &cert_list) {
        struct SSL_data* data = list_entry(cur, struct SSL_data, link);
        if (len == strlen(data -> name) && memcmp(name, data -> name, len) == 0) {
            if (data -> server_name)
                mbedtls_ssl_set_hostname(&((EvFD*) ssl) -> proto.ssl -> ctx, data -> name);
            return mbedtls_ssl_set_hs_own_cert(&((EvFD*) ssl) -> proto.ssl -> ctx, data -> cacert, data -> cakey);
        }
    }
    return -1;
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
    init_list_head(&cert_list);

    thread_id++;
    return true;
}

#define CHECK_TO_BE_CLOSE(fd) if(fd -> destroy) goto _continue;

bool evcore_run(bool (*evloop_abort_check)(void* user_data), void* user_data) {
    struct epoll_event events[MAX_EVENTS];
    uint8_t evloop_abort_loop = 0;
    while (1) {
        bool abort_check_result = true;
        if (evloop_abort_check) abort_check_result = evloop_abort_check(user_data);

        // check whether to exit
        if (unlikely(abort_check_result && evloop_events <= 0)) {
#ifdef LJS_DEBUG
            printf("evloop_abort_check: abort, events=%ld(thread#%d)\n", evloop_events, thread_id);
#endif
            return true; // no events
        }
        
        // or epoll destroyed, force exit
        if (epoll_fd == -1) {
#ifdef LJS_DEBUG
            printf("epoll_wait: destroyed, force exit\n");
#endif
            return false;
        }

        // no events, skip epoll_wait
        // mod will be processed in `evcore_destroy`
        if (evloop_events <= 0){
            if(evloop_abort_loop ++ == 10) return true;
            continue;
        }

        // modify evfd
        evfd_mod_start(false);

        // wait start
#ifdef LJS_DEBUG
        printf("epoll_wait: enter, events=%ld(thread#%d)\n", evloop_events, thread_id);
        bool first_epoll = true;
#endif
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

            if (evfd -> task_based) {
#ifdef LJS_DEBUG
                if (!first_epoll) {
                    if (events[i].events & EPOLLIN) assert(!list_empty(&evfd -> u.task.write_tasks));
                    if (events[i].events & EPOLLOUT) assert(!list_empty(&evfd -> u.task.read_tasks));
                    first_epoll = false;
                }
#endif

                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    handle_close(evfd_getfd(evfd, NULL), evfd, events[i].events & EPOLLRDHUP);
                    continue;
                }

                CHECK_TO_BE_CLOSE(evfd);

//                 if (events[i].events & EPOLLOUT && 0 == evfd -> u.task.tcp_connected){
//                     // check if connected
//                     int err = 0;
//                     socklen_t len = sizeof(err);
//                     getsockopt(evfd -> fd[0], SOL_SOCKET, SO_ERROR, &err, &len);
//                     if(err != 0){
// #ifdef LJS_DEBUG
//                         perror("socket connection failed");
// #endif
//                         handle_close(evfd_getfd(evfd, NULL), evfd);
//                         goto _continue;
//                     }
//                     evfd -> u.task.tcp_connected = true;
//                     if(evfd -> type == EVFD_SSL){
//                         int _1 = 1;
//                         setsockopt(evfd -> fd[0], IPPROTO_TCP, TCP_QUICKACK, &_1, sizeof(_1));
//                         setsockopt(evfd -> fd[0], IPPROTO_TCP, TCP_NODELAY, &_1, sizeof(_1));
//                     }
//                 }
                if (events[i].events & EPOLLIN) switch (evfd -> type) {
                    case EVFD_PTY:
                    case EVFD_NORM:
                    case EVFD_TIMER:
                    case EVFD_UDP:
                        handle_read(evfd -> fd[0], evfd, NULL, NULL);
                    break;

                    case EVFD_AIO:
                        struct io_event events[MAX_EVENTS];
                        struct timespec timeout = { 0, 0 };
                        int ret = io_getevents(evfd -> aio.ctx, 1, MAX_EVENTS, events, &timeout);
                        if (ret < 0) {
#ifdef LJS_DEBUG
                            perror("io_getevents");
#endif
                            break;
                        }
                        for (int j = 0; j < ret; ++j) {
                            struct iocb* iocb = (struct iocb*) (uintptr_t) events[j].obj;
                            if (iocb -> aio_lio_opcode == IOCB_CMD_PREAD)
                                handle_read(evfd -> fd[0], evfd, &events[j], NULL);
                            else if (iocb -> aio_lio_opcode == IOCB_CMD_PWRITE)
                                handle_write(evfd -> fd[0], evfd, &events[j]);
                            else if (iocb -> aio_lio_opcode == IOCB_CMD_FSYNC)
                                handle_sync(evfd);
                            else    // ?
                                handle_close(evfd -> fd[0], false, evfd);
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
                        struct EvFD_SSL* ssl_evfd = evfd -> proto.ssl;
                        // feed to buffer
                        ssize_t n = buffer_read(ssl_evfd -> recvbuf, evfd -> fd[0], UINT32_MAX);
                        if (n < 0) {
                            handle_close(evfd -> fd[0], evfd, false);
                        } else {
                            ssl_evfd -> want_read = false;
                            // read from mbedtls
                            handle_read(evfd -> fd[0], evfd, NULL, NULL);
                            // try to write: write_wants_read?
                            CHECK_TO_BE_CLOSE(evfd);
                            handle_write(evfd -> fd[0], evfd, NULL);
                        }
#endif
                    break;
                }

                CHECK_TO_BE_CLOSE(evfd);

                if (events[i].events & EPOLLOUT) {
#ifdef LJS_MBEDTLS
                    if (evfd -> type == EVFD_SSL) {
                        // write buffer from mbedtls to fd
                        ssize_t n = buffer_write(evfd -> proto.ssl -> sendbuf, evfd -> fd[0], UINT32_MAX);

                        if (n == -1 && errno != EAGAIN) {
                            handle_close(evfd -> fd[0], evfd, false);
                            break;
                        }

                        // write to mbedtls to fill sendbuf
                        handle_write(evfd -> fd[0], evfd, NULL);
                        check_queue_status(evfd);
                    } else
#endif
                    {
                        handle_write(evfd -> fd[0], evfd, NULL);
                    }
                }
            } else {
                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    evfd -> rdhup = !!(events[i].events & EPOLLRDHUP);
                    evfd -> u.cb.close(evfd, evfd -> rdhup, evfd -> u.cb.close_opaque);
                    TRACE_NSTDEVENTS(evfd, -1);
                }

                CHECK_TO_BE_CLOSE(evfd);

                // Notify
                if (events[i].events & EPOLLIN)
                    evfd -> u.cb.read(evfd, true, NULL, 0, evfd -> u.cb.read_opaque);

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

static inline void expand_bufsize(EvFD* evfd, uint32_t minsize) {
    if (evfd -> incoming_buffer -> size < minsize) {
        buffer_realloc(evfd -> incoming_buffer, minsize + buffer_used(evfd -> incoming_buffer) + 2, false);
    }
}

void evcore_destroy() {
    if (epoll_fd == -1) return;

    // free all timerfd
    struct list_head* cur, * tmp;
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
    struct list_head* cur2, * tmp2;
    list_for_each_prev_safe(cur2, tmp2, &cert_list) {
        struct SSL_data* data = list_entry(cur2, struct SSL_data, link);
        list_del(&data -> link);
        free2(data);
    }
#endif

    close(epoll_fd);
    // evfd_mod_start(true);   // force cleanup evfds
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
    if (epoll_fd == -1) return false;
    tassert(pipe -> type != EVFD_INOTIFY && pipe -> type != EVFD_TIMER && !pipe -> destroy);

    int fd = evfd_getfd(pipe, NULL);
    int flags = ioctl(fd, F_GETFL, 0);
    if (-1 == flags || -1 == ioctl(fd, F_SETFL, flags & ~O_NONBLOCK))
        return false;

    // XXX: this logic is not safe, but it's a workaround for now.
    if (pipe -> type == EVFD_AIO) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        close(pipe -> fd[0]); // close eventfd
        pipe -> fd[0] = fd;
        pipe -> type = EVFD_NORM;
    }
    handle_read(fd, pipe, NULL, NULL);
    if (!pipe -> destroy) handle_write(fd, pipe, NULL);

    ioctl(fd, F_SETFL, flags);
    return true;
}

// XXX: use flags to replace use_aio and support more types
// attach evfd to epoll, and you would control the IO yourself
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
    if (use_aio) fcntl(fd, F_SETFL, O_DIRECT | fcntl(fd, F_GETFL, 0));

    EvFD* evfd = malloc2(sizeof(EvFD));
    if (!evfd) return NULL;
    memset(evfd, 0, sizeof(EvFD));
    list_add_tail(&evfd -> link, &evfd_list);    

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
        evfd -> fd[0] = fd;  // source fd
        evfd -> fd[1] = -1;  // aio requires fd[1] set to source fd, however, we failed
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
    evfd -> u.task.tcp_connected = -1;
    evfd -> epoll_flags = evflag;

    return evfd;
}

// create evfd
// Note: if you want to make it thread_safe, just set flag mask to `PIPE_THREADSAFE`
EvFD* evfd_new(int fd, int flag, uint32_t bufsize,
    EvCloseCallback close_callback, void* close_opaque) {
    EvFD* evfd = malloc2(
#ifdef LJS_EVLOOP_THREADSAFE
        flag & PIPE_THREADSAFE ? sizeof(struct ThreadSafeEvFD) : 
#endif
        sizeof(struct EvFD)
    );
    if (!evfd) return NULL;
    memset(evfd, 0, sizeof(EvFD));
    list_add_tail(&evfd -> link, &evfd_list);

    // initialize task list
    init_list_head(&evfd -> u.task.read_tasks);
    init_list_head(&evfd -> u.task.write_tasks);
    init_list_head(&evfd -> u.task.close_tasks);

#ifdef LJS_EVLOOP_THREADSAFE
    // initialize locks
    if(flag & PIPE_THREADSAFE){
        struct ThreadSafeEvFD* tsevfd = (struct ThreadSafeEvFD*) evfd;
        pthread_mutex_init(&tsevfd -> rd_lock, NULL);
        pthread_mutex_init(&tsevfd -> wr_lock, NULL);
        pthread_mutex_init(&tsevfd -> fd_lock, NULL);
    }
#endif

    // initialize evfd
    evfd -> u.task.tcp_connected = -1;
    evfd -> task_based = true;
    evfd -> fd[0] = fd;
    evfd -> fd[1] = -1;
    evfd -> type = flag & PIPE_PTY ? EVFD_PTY : EVFD_NORM;
    evfd -> epoll_flags = EPOLLLT | EPOLLERR | EPOLLHUP;
    if (flag & PIPE_READ) evfd -> epoll_flags |= EPOLLIN;
    if (flag & PIPE_WRITE || flag & PIPE_PTY) evfd -> epoll_flags |= EPOLLOUT;
    if (flag & PIPE_READ) {
        assert(bufsize > 0);
        buffer_init(&evfd -> incoming_buffer, NULL, bufsize);
    }

    // is socket?
    if (flag & PIPE_SOCKET) {
        evfd -> u.task.tcp_connected = 0;
    }else{
        evfd -> u.task.tcp_connected = -1; // not a socket
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
    if (flag & PIPE_AIO) {
        evfd -> type = EVFD_AIO;
        evfd -> fd[1] = fd;

        if (fcntl(fd, F_SETFL, O_DIRECT | fcntl(fd, F_GETFL, 0)) == -1) {
#ifdef LJS_DEBUG
            perror("fcntl");
#endif
            goto error;
        }

        if (io_setup(MAX_EVENTS, &evfd -> aio.ctx) == -1) {
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
    printf("new evfd fd:%d, aio:%d, bufsize:%d, r:%d, w:%d\n", fd, flag & PIPE_AIO, bufsize, flag & PIPE_READ, flag & PIPE_WRITE);
#endif
    TRACE_NSTDEVENTS(evfd, +1);

    return evfd;
}

void evfd_setup_udp(EvFD* evfd) {
    assert(!evfd -> destroy);
    evfd -> type = EVFD_UDP;
    if(evfd -> task_based) evfd -> u.task.tcp_connected = 1;    // udp doesnot need tcp handshake
    evfd -> proto.udp = malloc2(sizeof(struct UDPContext));
}

#ifdef LJS_MBEDTLS
/**
 * Initialize SSL/DTLS context for evfd.
 * the arguments except `evfd` and `is_client` are all optional.
 * 
 * Warning: evfd should be task-based and not destroyed before SSL/DTLS context is initialized.
 * \param evfd The evfd to initialize SSL/DTLS context for.
 * \param flag Flag like `SSL_*` in `core.h`
 * \param server_name (SNI required) set to hostname to enable SNI feature
 * \param handshake_cb The callback to call when the SSL/DTLS handshake is complete.
 * \param user_data The user data to pass to the handshake callback.
 */
bool evfd_initssl(
    EvFD* evfd, mbedtls_ssl_config** config,
    int flag, InitSSLOptions* options,
    EvSSLHandshakeCallback handshake_cb, void* user_data
) {
    tassert(!evfd -> destroy && evfd -> task_based);
    evfd -> type = EVFD_SSL;
    int ret = MBEDTLS_ERR_SSL_BAD_CONFIG;

    // init basic config
    evfd -> proto.ssl = malloc2(sizeof(struct EvFD_SSL));
    mbedtls_ssl_config* cfg = &evfd -> proto.ssl -> config;
    mbedtls_ssl_context* ctx = &evfd -> proto.ssl -> ctx;
    mbedtls_ssl_init(ctx);
    mbedtls_ssl_config_init(cfg);
    mbedtls_ssl_config_defaults(cfg, 
        flag & SSL_IS_SERVER,   // MBEDTLS_SSL_IS_CLIENT = 0
        MBEDTLS_SSL_TRANSPORT_STREAM, 
        flag & SSL_PRESET_SUITEB ? MBEDTLS_SSL_PRESET_SUITEB : 0
    );
    mbedtls_ssl_conf_authmode(cfg, flag & SSL_VERIFY ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
    // this may a bug in mbedtls
    // it will not as perform we expected, only TLSv1.2 will be used
    // mbedtls_ssl_conf_min_version(cfg, 3, 1);   // TLSv1.0
    mbedtls_ssl_conf_max_version(cfg, 3, flag & SSL_USE_TLS1_3 ? 4 : 3);// TLSv1.3/1.2
    mbedtls_ssl_conf_rng(cfg, default_rng, NULL);
    if (config) *config = cfg;

    // server specific config
    if (flag & SSL_IS_SERVER) {
#ifdef MBEDTLS_SSL_EARLY_DATA
        if(options && options -> early_data_len){
            mbedtls_ssl_conf_early_data(cfg, true);
            mbedtls_ssl_conf_max_early_data_size(cfg, options -> early_data_len);
        }
#endif
        if(flag & SSL_USE_SNI)
            mbedtls_ssl_conf_sni(cfg, ssl_sni_callback, evfd);
        else if(options && options -> server_cert && options -> server_key)
            mbedtls_ssl_conf_own_cert(cfg, options -> server_cert, options -> server_key);
        else
            goto error;
    }else{  // sni support
        if(options && options -> ca_cert)
            mbedtls_ssl_conf_own_cert(cfg, options -> ca_cert, NULL);
        else
            mbedtls_ssl_conf_own_cert(cfg, &tls_global_cert, NULL);
        if(options && options -> server_name)
            mbedtls_ssl_set_hostname(ctx, options -> server_name);
        if(options && options -> verify)
            mbedtls_ssl_set_verify(ctx, options -> verify, options -> verify_opaque);
    }

#if defined(LJS_MBEDTLS) && defined(MBEDTLS_DEBUG_C)
    // debug?
    mbedtls_ssl_conf_dbg(cfg, debug_callback, evfd);
#endif

    // mbedtls bio set
    mbedtls_ssl_conf_read_timeout(cfg, 0);
    mbedtls_ssl_set_bio(ctx, evfd, handle_ssl_send, handle_ssl_recv, NULL);

    // alpn
    if(options && options -> alpn_protocols){
        // mbedtls_ssl_conf_alpn_protocols(cfg, options -> alpn_protocols); 
    }

    // init ssl context
    if(options && options -> ciphersuites)
        mbedtls_ssl_conf_ciphersuites(cfg, options -> ciphersuites);
    mbedtls_ssl_set_user_data_p(ctx, evfd);
    ret = mbedtls_ssl_setup(ctx, cfg);
    if (0 != ret) goto error;

    // initial user-space SSL buffer
    buffer_init(&evfd -> proto.ssl -> sendbuf, NULL, EVFD_BUFSIZE);
    buffer_init(&evfd -> proto.ssl -> recvbuf, NULL, EVFD_BUFSIZE);

    // callback
    evfd -> proto.ssl -> handshake_cb = handshake_cb;
    evfd -> proto.ssl -> handshake_user_data = user_data;
    evfd -> proto.ssl -> mb_errno = 0;

    // start handshake
    evfd -> proto.ssl -> ssl_handshaking = true;
    ssl_handle_handshake(evfd);
    return true;

error:
#ifdef LJS_DEBUG
    char mberror[1024];
    mbedtls_strerror(ret, mberror, sizeof(mberror));
    printf("evfd_initssl: %s\n", mberror);
#endif
    evfd_close(evfd);
    return false;
}

bool evfd_remove_sni(const char* name) {
    struct list_head* pos, * tmp;
    list_for_each_prev_safe(pos, tmp, &cert_list) {
        struct SSL_data* data = list_entry(pos, struct SSL_data, link);
        if (strcmp(data -> name, name) == 0) {
            list_del(pos);
            free2(data -> name);
            if (data -> server_name) free2(data -> server_name);
            mbedtls_x509_crt_free(data -> cacert);
            mbedtls_pk_free(data -> cakey);
            free2(data);
            return true;
        }
    }
    return false;
}

void evfd_set_sni(char* name, char* server_name, mbedtls_x509_crt* cacert, mbedtls_pk_context* cakey) {
    struct SSL_data* data = malloc2(sizeof(struct SSL_data));
    evfd_remove_sni(name);  // remove old cert
    list_add(&data -> link, &cert_list);
    data -> name = name;
    data -> server_name = server_name;
    data -> cacert = cacert;
    data -> cakey = cakey;
}
#endif

#define HANDLE_CALLBACK(call_expr) {\
    int ret = call_expr; \
    if (ret & EVCB_RET_REWIND) \
        buffer_seek_cur(evfd -> incoming_buffer, -available); \
    if (ret & EVCB_RET_CONTINUE) \
        goto task; \
}

// read size from evfd
// similar to evfd_read, however, it will fail(buffer=NULL, size=0) or fill whole buffer
// evfd_read will read_once even if buffer is not filled
// we recommends allocate 1 byte bigger than buffer size is used
// 
// warn: the function may not be asyncronous, if there is data in buffer, it will return directly
//     cautious when using it with promise
bool evfd_readsize(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
    EvReadCallback callback, void* user_data) {
    if(-1 == ssl_poll_data(evfd) && buffer_is_empty(evfd -> incoming_buffer)){
no_data:
        callback(evfd, false, buffer, 0, user_data);
        return false;
    }

    tassert((!evfd -> destroy || !buffer_is_empty(evfd -> incoming_buffer)) && evfd -> task_based);

task:
    if (
        evfd -> incoming_buffer && buffer_used(evfd -> incoming_buffer) >= buf_size &&
        list_empty(&evfd -> u.task.read_tasks)
    ) {
        // directly return data from buffer
        uint32_t available = buffer_pop(evfd -> incoming_buffer, buffer, buf_size);
        if(available)
            HANDLE_CALLBACK(callback(evfd, true, buffer, available, user_data))
        else if(evfd -> destroy)
            callback(evfd, false, buffer, 0, user_data);
        else goto startup;
        return true;
    }
    if(evfd -> destroy) goto no_data;

startup:
    expand_bufsize(evfd, buf_size);
    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;
    // initialize buffer
    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size + 1);

    if (!evfd -> incoming_buffer) buffer_init(&evfd -> incoming_buffer, NULL, EVFD_BUFSIZE);

    task -> type = EV_TASK_READ;
    task -> cb.read = callback;
    task -> opaque = user_data;
    task -> buffer = buf;

    if (evfd -> type == EVFD_AIO) {
        // 提交AIO
        if (submit_aio_read(evfd, task)) {
            free2(task);
            buffer_free(buf);
            return false;
        }
    }
    bool try_direct = list_empty(&evfd -> u.task.read_tasks);
    list_add(&task -> list, &evfd -> u.task.read_tasks);
    check_queue_status(evfd);
    TRACE_EVENTS(evfd, +1);

#ifdef LJS_MBEDTLS
    if (try_direct && evfd -> type == EVFD_SSL) {
        // note: reading from mbedtls requires readbuf to be filled
        handle_read(evfd_getfd(evfd, NULL), evfd, NULL, NULL);
    }
#endif

    return true;
}

bool evfd_clearbuf(EvFD* evfd) {
    if (evfd -> destroy) return false;
    buffer_clear(evfd -> incoming_buffer);
    return true;
}

char const* strnpbrk(char const* s, char const* accept, size_t n) {
    assert((s || !n) && accept);

    char const* const end = s + n;
    for (char const* cur = s; cur < end; ++cur) {
        int const c = *cur;
        for (char const* a = accept; *a; ++a) {
            if (*a == c) {
                return cur;
            }
        }
    }

    return NULL;
}

// read one line from evfd, "\r" "\r\n" "\n" are all welcomed
// fail or complete
// warn: the function may not be asyncronous, if there is data in buffer, it will return directly
//     cautious when using it with promise
bool evfd_readline(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
    EvReadCallback callback, void* user_data) {
    if(-1 == ssl_poll_data(evfd) && buffer_is_empty(evfd -> incoming_buffer)){
no_data:
        callback(evfd, false, buffer, 0, user_data);
        return false;
    }

    tassert(buf_size > 0);

task:
    // destroied or no task: try direct read
    if ((evfd -> destroy || list_empty(&evfd -> u.task.read_tasks)) && evfd -> incoming_buffer) {
        buffer_flat2(evfd -> incoming_buffer);
        char* start = (char*)evfd -> incoming_buffer -> buffer + evfd -> incoming_buffer -> start;
        char const* end = strnpbrk(start, "\n\r", buffer_used(evfd -> incoming_buffer));
        if (end) {
            // CRLF
            uint32_t move = 1;
            if(end[0] == '\r' && end[1] == '\n') move = 2;

            uint32_t available = buffer_pop(evfd -> incoming_buffer, buffer, end - start);
            buffer_seek_cur(evfd -> incoming_buffer, move);
            if(available < buf_size) buffer[available] = '\0';
            HANDLE_CALLBACK(callback(evfd, true, buffer, available, user_data));
            return true;
        }
        // directly return data from buffer
        uint32_t available = buffer_pop(evfd -> incoming_buffer, buffer, buf_size);
        if(available)
            HANDLE_CALLBACK(callback(evfd, true, buffer, available, user_data))
        else if(evfd -> destroy)
            callback(evfd, false, buffer, 0, user_data);
        else goto startup;
        return true;
    }
    if(evfd -> destroy) goto no_data;   // if continue failed

startup:
    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size);
    if (!evfd -> incoming_buffer) buffer_init(&evfd -> incoming_buffer, NULL, EVFD_BUFSIZE);

    task -> type = EV_TASK_READLINE;
    task -> buffer = buf;
    task -> cb.read = callback;
    task -> opaque = user_data;
    evfd -> strip_if_is_n = false;

    if (evfd -> type == EVFD_AIO && submit_aio_read(evfd, task)) {
        free2(task);
        buffer_free(buf);
        return false;
    }

    bool try_direct = list_empty(&evfd -> u.task.read_tasks);
    list_add(&task -> list, &evfd -> u.task.read_tasks);
    check_queue_status(evfd);
    TRACE_EVENTS(evfd, +1);

#ifdef LJS_MBEDTLS
    if (try_direct && evfd -> type == EVFD_SSL && !evfd -> proto.ssl -> ssl_handshaking) {
        // note: reading from mbedtls requires readbuf to be filled
        handle_read(evfd_getfd(evfd, NULL), evfd, NULL, NULL);
    }
#endif

    return true;
}

// read data once from evfd
// warn: the function may not be asyncronous, if there is data in buffer, it will return directly
//     cautious when using it with promise
bool evfd_read(EvFD* evfd, uint32_t buf_size, uint8_t* buffer,
    EvReadCallback callback, void* user_data) {
    if(-1 == ssl_poll_data(evfd) && buffer_is_empty(evfd -> incoming_buffer)){
no_data:
        callback(evfd, false, buffer, 0, user_data);
        return false;
    }
    
    tassert(buf_size > 0);
task:
    if (
        evfd -> incoming_buffer && list_empty(&evfd -> u.task.read_tasks) && 
        !buffer_is_empty(evfd -> incoming_buffer)
    ) {
        // directly return data from buffer
        uint32_t available = buffer_pop(evfd -> incoming_buffer, buffer, buf_size);
        if(available)
            HANDLE_CALLBACK(callback(evfd, true, buffer, available, user_data))
        else if(evfd -> destroy)
            callback(evfd, false, buffer, 0, user_data);
        else goto startup;
        return true;
    }
    if(evfd -> destroy) goto no_data;

startup:
    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    struct Buffer* buf;
    buffer_init(&buf, buffer, buf_size);

    if (!evfd -> incoming_buffer) buffer_init(&evfd -> incoming_buffer, NULL, EVFD_BUFSIZE);

    task -> type = EV_TASK_READONCE;
    task -> buffer = buf;
    task -> cb.read = callback;
    task -> opaque = user_data;

#ifdef LJS_DEBUG
    if (evfd -> type == EVFD_AIO)
        printf("warn: aio is not supported for readonce\n");
#endif

    if (evfd -> type == EVFD_AIO) {
        buffer_aligned(buf, blksize_get(evfd -> fd[1]));
        // submit aio read
        if (submit_aio_read(evfd, task)) {
            free2(task);
            buffer_free(buf);
            return false;
        }
    }
    bool try_direct = list_empty(&evfd -> u.task.read_tasks);
    list_add(&task -> list, &evfd -> u.task.read_tasks);
    check_queue_status(evfd);
    TRACE_EVENTS(evfd, +1);

#ifdef LJS_MBEDTLS
    if (try_direct && evfd -> type == EVFD_SSL) {
        // note: reading from mbedtls requires readbuf to be filled
        handle_read(evfd_getfd(evfd, NULL), evfd, NULL, NULL);
    }
#endif

    return true;
}

// submit write task to evfd
// if size=0, it will call callback immediately with success=true
bool evfd_write(EvFD* evfd, const uint8_t* data, uint32_t size,
    EvWriteCallback callback, void* user_data) {
    tassert(!evfd -> destroy);
    if (size == 0) {
        callback(evfd, true, user_data);
        return true;
    }

    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;
    bool try_direct = list_empty(&evfd -> u.task.write_tasks);

    // write circular buffer
    struct Buffer* buf;
    buffer_init(&buf, (uint8_t*) data, size + 1);
    buf -> end = size; // fill data

    task -> type = EV_TASK_WRITE;
    task -> buffer = buf;
    task -> cb.write = callback;
    task -> opaque = user_data;

    if (evfd -> type == EVFD_AIO) {
        // submit AIO write
        if (!submit_aio_write(evfd, task))
            goto error;

        // add to list
        list_add(&task -> list, &evfd -> u.task.write_tasks);
    } else {
        list_add(&task -> list, &evfd -> u.task.write_tasks);
    }

    TRACE_EVENTS(evfd, +1);

    if (try_direct && evfd -> type == EVFD_SSL) {
        if(!evfd -> proto.ssl -> ssl_handshaking)
            // note: writing requires mbedtls processing data before EPOLLOUT
            handle_write(evfd -> fd[0], evfd, NULL);
    } else {
        check_queue_status(evfd);
    }

    return true;

error:
    buffer_free(buf);
    free2(task);
    return false;
}

// UDP write
bool evfd_write_dgram(EvFD* evfd, const uint8_t* data, uint32_t size,
    const struct sockaddr* addr, socklen_t addr_len,
    EvWriteCallback callback, void* user_data) {
    tassert(!evfd -> destroy);
    struct UDPContext* ctx = evfd -> proto.udp;
    memcpy(&ctx -> peer_addr, addr, addr_len);
    ctx -> addr_len = addr_len;

    return evfd_write(evfd, data, size, callback, user_data);
}

// onclose
// Note: passing callback as NULL will clear the callback.
bool evfd_onclose(EvFD* evfd, EvCloseCallback callback, void* user_data) {
    if(evfd -> destroy) callback(evfd, false, user_data);
    
    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    if (!callback) {
        if (list_empty(&evfd -> u.task.close_tasks)) return false;
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
// XXX: support more types of fd
bool evfd_pipeTo(EvFD* from, EvFD* to, EvPipeToFilter filter, void* fopaque, EvPipeToNotify notify, void* nopaque) {
    tassert(!from -> destroy && !to -> destroy);
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
    check_queue_status(from);
    evfd_mod(to, true, EPOLLOUT);
    return true;
}

static inline void close_stdpipe(EvFD* evfd) {
#ifdef LJS_DEBUG
    printf("close_stdpipe: %d\n", evfd -> fd[0]);
#endif

    clear_tasks(evfd, false, true);
    if (evfd -> incoming_buffer) buffer_free(evfd -> incoming_buffer);
    evfd_ctl(evfd, EPOLL_CTL_FREE);
    evfd -> destroy = true;
}

// close evfd
bool evfd_close(EvFD* evfd) {
    tassert(evfd -> type != EVFD_TIMER && evfd -> type != EVFD_INOTIFY);
    if (evfd -> destroy) return false;
    if (evfd -> fd[0] <= STDERR_FILENO) close_stdpipe(evfd);
    else handle_close(evfd -> fd[0], evfd, false);
    return true;
}

// Destroy evfd, not close fd
bool evfd_close2(EvFD* evfd) {
    if (evfd -> destroy) return false;
    if (evfd -> fd[0] <= STDERR_FILENO) close_stdpipe(evfd);
    if (evfd -> task_based) clear_tasks(evfd, false, false);
    if (evfd -> incoming_buffer) buffer_free(evfd -> incoming_buffer);
    evfd_ctl(evfd, EPOLL_CTL_FREE);
    evfd -> destroy = true;

    // remove in epoll
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, evfd -> fd[0], NULL);
    return true;
}

static void __shutdown_cb(EvFD* evfd, bool success, void* opaque) {
    if (!success) {
#ifdef LJS_DEBUG
        perror("shutdown");
#endif
    }
    evfd_close(evfd);
}

// better choice than evfd_close
// read/write all data from/to fd and close it
bool evfd_shutdown(EvFD* evfd) {
    if(evfd -> destroy) return true;

    // force read Note: buffer is required
    if (!evfd -> incoming_buffer) buffer_init(&evfd -> incoming_buffer, NULL, EVFD_BUFSIZE);
    handle_read(evfd -> fd[0], evfd, NULL, NULL);

    // wait for all data to be written
    if (!evfd -> destroy && evfd -> task_based && (
        !list_empty(&evfd -> u.task.write_tasks) || !list_empty(&evfd -> u.task.read_tasks)
        )) {
        evfd_wait2(evfd, __shutdown_cb, NULL);
    } else {
        evfd_close(evfd);
    }

    return true;
}

/**
 * Overwrite the default behavior of an EvFD object to callbacks provided by the user.
 * Mostly used after using `evfd_new()` and donot want to close the fd.
 */
bool evfd_override(EvFD* evfd, EvReadCallback rcb, void* read_opaque, EvWriteCallback wcb, void* write_opaque, EvCloseCallback ccb, void* close_opaque) {
    tassert(!evfd -> destroy && evfd -> task_based);
    clear_tasks(evfd, false, false);
    if (evfd -> incoming_buffer) buffer_free(evfd -> incoming_buffer);
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
bool evfd_wait(EvFD* evfd, bool wait_read, EvSyncCallback cb, void* opaque) {
    tassert(!evfd -> destroy);

    if ( // already completed
        (wait_read && list_empty(&evfd -> u.task.read_tasks) && !(evfd -> u.task.rw_state & 0b10)) ||
        (!wait_read && list_empty(&evfd -> u.task.write_tasks) && !(evfd -> u.task.rw_state & 0b01))
    ) cb(evfd, true, opaque);

    struct Task* task = malloc2(sizeof(struct Task));
    if (!task) return false;

    task -> type = EV_TASK_NOOP;
    task -> cb.sync = cb;
    task -> opaque = opaque;
    task -> buffer = NULL;
    if (wait_read) {
        list_add(&task -> list, &evfd -> u.task.read_tasks);
    } else {
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
static void __sync_cb(EvFD* evfd, bool success, void* opaque) {
    struct __sync_cb_arg* arg = opaque;
    if (arg -> count++ == 1) {
        evfd_close(evfd);
        arg -> cb(evfd, success, arg -> opaque);
        free2(arg);
    }
}

bool evfd_wait2(EvFD* evfd, EvSyncCallback cb, void* opaque) {
    struct __sync_cb_arg* arg = malloc2(sizeof(struct __sync_cb_arg));
    if (!arg) return false;
    arg -> count = 0;
    arg -> cb = cb;
    arg -> opaque = opaque;
    return evfd_wait(evfd, false, __sync_cb, arg) && evfd_wait(evfd, true, __sync_cb, arg);
}

bool evfd_yield(EvFD* evfd, bool yield_read, bool yield_write) {
    tassert(!evfd -> destroy);
    if (yield_read)     evfd_mod(evfd, false, EPOLLIN);
    if (yield_write)    evfd_mod(evfd, true, EPOLLOUT);
    return true;
}

bool evfd_consume(EvFD* evfd, bool consume_read, bool consume_write) {
    tassert(!evfd -> destroy);
    int events = evfd -> epoll_flags;
    if (consume_read) events |= EPOLLIN;
    if (consume_write) events |= EPOLLOUT;
    evfd_ctl(evfd, events);
    return true;
}

// Get whether the evfd is closed
bool evfd_closed(EvFD* evfd) {
    return evfd -> destroy;
}

static inline EvFD* timer_new(uint64_t milliseconds, EvTimerCallback callback, void* user_data, bool once) {
    // find free timer fd
    struct EvFD* evfd = NULL;
    int fd;
    bool reuse = false;
    struct list_head* pos, * tmp;
    list_for_each_safe(pos, tmp, &timer_list) {
        evfd = list_entry(pos, struct EvFD, link);
        if (evfd -> proto.timer -> time == 0) {
            evfd -> proto.timer -> time = milliseconds;
            evfd -> proto.timer -> once = once;
            reuse = true;
            fd = evfd -> fd[0];
            goto settime;
        }
    }

    // create new timer fd if no free fd
    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd == -1) {
#ifdef LJS_DEBUG
        perror("timerfd_create");
#endif
        return NULL;
    }

    // alloc EvFD object
    evfd = malloc2(sizeof(struct EvFD));
    memset(evfd, 0, sizeof(EvFD));
    evfd -> task_based = true;
    evfd -> proto.timer = malloc2(sizeof(struct TimerFDContext));
    evfd -> proto.timer -> time = milliseconds;
    evfd -> proto.timer -> once = once;
    evfd -> proto.timer -> executed = false;
    evfd -> u.task.tcp_connected = -1;

    // init task queue
    init_list_head(&evfd -> u.task.read_tasks);
    init_list_head(&evfd -> u.task.write_tasks);
    init_list_head(&evfd -> u.task.close_tasks);

    // set basic params
    evfd -> fd[0] = fd;
    evfd -> type = EVFD_TIMER;

settime:
    // set timer params
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

    if (reuse) {
        evfd_ctl(evfd, EPOLLIN | EPOLLLT);
    } else {
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
    if (!evfd) return false;
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
    if (timer_task(evfd, callback, cbopaque)) {
        evfd_onclose(evfd, close_cb, close_opaque);
        return evfd;
    }
    close_cb(evfd, false, close_opaque);
    evfd_close(evfd);
    return NULL;
}

EvFD* evcore_setTimeout(uint64_t milliseconds, EvTimerCallback callback, void* user_data) {
    struct EvFD* evfd = timer_new(milliseconds, callback, user_data, true);
    if (timer_task(evfd, callback, user_data)) return evfd;
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

    // clear task queue
    struct list_head* pos, * tmp;
    list_for_each_prev_safe(pos, tmp, &evfd -> u.task.read_tasks) {
        struct Task* task = list_entry(pos, struct Task, list);

        // execute callback if once and not executed
        if (!evfd -> proto.timer -> executed && evfd -> proto.timer -> once)
            task -> cb.timer(0, task -> opaque);

        list_del(pos);
        TRACE_EVENTS(evfd, -1);
        free2(task);
    }

    // clear onclose tasks
    if (evfd -> proto.timer -> once) {
        assert(list_empty(&evfd -> u.task.close_tasks));
    } else {
        struct list_head* pos2, * tmp2;
        list_for_each_prev_safe(pos2, tmp2, &evfd -> u.task.close_tasks) {
            struct Task* task = list_entry(pos2, struct Task, list);
            task -> cb.close(evfd, false, task -> opaque);
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

    evfd -> proto.timer -> executed = true;
    return true;
}

bool evcore_clearTimer(int timer_fd) {
    // 在链表中查找定时器
    struct list_head* pos, * tmp;
    list_for_each_prev_safe(pos, tmp, &timer_list) {
        struct EvFD* evfd = list_entry(pos, struct EvFD, link);
        if (evfd -> fd[0] == timer_fd) {
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
    evfd -> proto.inotify = inotify;

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
    struct list_head* pos, * tmp;
    list_for_each_prev_safe(pos, tmp, &evfd -> u.task.read_tasks) {
        struct Task* task = list_entry(pos, struct Task, list);
        list_del(pos);
        TRACE_EVENTS(evfd, -1);
        free2(task);
    }

    // free evfd
    for (int i = 0; i < MAX_EVENTS; i++) {
        if (evfd -> proto.inotify -> paths[i])
            free2(evfd -> proto.inotify -> paths[i]);
    }
    free2(evfd -> proto.inotify);
    free2(evfd);

    return true;
}

// 添加监控路径
bool evcore_inotify_watch(EvFD* evfd, const char* path, uint32_t mask, int* wd) {
    tassert(evfd -> type == EVFD_INOTIFY);
    int _wd;
    if (!wd) wd = &_wd;

    *wd = inotify_add_watch(evfd -> fd[0], path, mask);
    if (*wd == -1) {
#ifdef LJS_DEBUG
        perror("inotify_add_watch");
#endif
        return false;
    }

    // save path
    evfd -> proto.inotify -> paths[*wd] = strdup2(path);

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

    free2(evfd -> proto.inotify -> paths[wd]);
    evfd -> proto.inotify -> paths[wd] = NULL;

    return true;
}

int evcore_inotify_find(EvFD* evfd, const char* path) {
    tassert(evfd -> type == EVFD_INOTIFY);
    for (int i = 0; i < MAX_EVENTS; i++) {
        if (evfd -> proto.inotify -> paths[i] && strcmp(evfd -> proto.inotify -> paths[i], path) == 0) {
            return i;
        }
    }
    return -1;
}

int evfd_getfd(EvFD* evfd, int* timer_fd) {
    if (evfd -> type == EVFD_AIO) {
        if (timer_fd) *timer_fd = evfd -> fd[0];
        return evfd -> fd[1];
    } else {
        if (timer_fd)*timer_fd = -1;
        return evfd -> fd[0];
    }
}

int evfd_ssl_errno(EvFD* evfd) {
    if(evfd -> type != EVFD_SSL)
        return 0;
    return evfd -> proto.ssl -> mb_errno;
}

bool evfd_seek(EvFD* evfd, int seek_type, off_t pos) {
    tassert(!evfd -> destroy && evfd -> type == EVFD_AIO && evfd -> task_based);

    switch (seek_type) {
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

// Read-After-Close feature for task-based evfd
// The feature only acts before the first eventloop after evfd closed.
// Warning: cautious use of this feature can cause memory leaks and other issues.
//     EventLoop will not close the file descriptor until all data run out.
void evfd_enable_rac(EvFD* evfd, bool enable){
    if(evfd -> task_based)
        evfd -> u.task.read_after_close = enable;
}