#include "../engine/quickjs.h"
#include "../engine/cutils.h"
#include "../engine/list.h"
#include "./core.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <threads.h>
#include <paths.h>
#include <limits.h>
#include <signal.h>
#include <libgen.h>
#include <pty.h>
#include <errno.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>

#define MAX_SIGNAL_SIZE 1024

extern char **environ;
static JSValue* argv;
static size_t argc;

// --- class ReactiveEnviron --- thread_safe
struct ReactiveEnviron {
    char** env_names;
    char** env_values;
    size_t env_count;
};
static thread_local JSClassID js_reactive_environ_class_id;
static struct ReactiveEnviron* env = NULL;
static pthread_rwlock_t env_lock;

static int js_re_get_prop_exists(JSContext *ctx, JSPropertyDescriptor *desc, JSValue obj, JSAtom prop){
    pthread_rwlock_rdlock(&env_lock);
    const char* name = JS_AtomToCString(ctx, prop);
    for(size_t i = 0; i < env -> env_count; i++){
        if(strcmp(name, env -> env_names[i]) == 0){
            desc -> flags = JS_PROP_ENUMERABLE | JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE;
            desc -> value = JS_NewString(ctx, env -> env_values[i]);
            pthread_rwlock_unlock(&env_lock);
            return true;
        }
    }
    pthread_rwlock_unlock(&env_lock);
    return false;
}

static int js_re_get_prop_names(JSContext *ctx, JSPropertyEnum **ptab, uint32_t *plen, JSValue obj){
    pthread_rwlock_rdlock(&env_lock);
    *ptab = js_malloc(ctx, env -> env_count * sizeof(JSPropertyEnum));
    *plen = env -> env_count;
    for(size_t i = 0; i < env -> env_count; i++){
        (*ptab)[i].atom = JS_NewAtom(ctx, env -> env_names[i]);
        (*ptab)[i].is_enumerable = true;
    }
    pthread_rwlock_unlock(&env_lock);
    return 0;
}

static int js_re_del_prop(JSContext *ctx, JSValue obj, JSAtom prop){
    pthread_rwlock_wrlock(&env_lock);
    const char* name = JS_AtomToCString(ctx, prop);
    for(size_t i = 0; i < env -> env_count; i++){
        if(strcmp(name, env -> env_names[i]) == 0){
            js_free(ctx, env -> env_names[i]);
            js_free(ctx, env -> env_values[i]);
            env -> env_count--;

            // move from end to fill the gap
            for(size_t j = i; j < env -> env_count; j++){
                env -> env_names[j] = env -> env_names[j+1];
                env -> env_values[j] = env -> env_values[j+1];
            }

            unsetenv(name);
            pthread_rwlock_unlock(&env_lock);
            return true;
        }
    }

    pthread_rwlock_unlock(&env_lock);
    return false;
}

static int js_re_set_own_prop(JSContext *ctx, JSValue this_obj, JSAtom prop, JSValue val, JSValue getter, JSValue setter, int flags){
    return false;   // not support
}

// static JSValue js_re_get_prop(JSContext *ctx, JSValue obj, JSAtom atom, JSValue receiver){
//     struct ReactiveEnviron* re = JS_GetOpaque(obj, js_reactive_environ_class_id);
//     if(!re) return JS_UNDEFINED;
//     const char* name = JS_AtomToCString(ctx, atom);
//     for(size_t i = 0; i < re -> env_count; i++){
//         if(strcmp(name, re -> env_names[i]) == 0){
//             return JS_NewString(ctx, re -> env_values[i]);
//         }
//     }
//     return JS_UNDEFINED;
// }

static int js_re_set_prop(JSContext *ctx, JSValue obj, JSAtom atom, JSValue value, JSValue receiver, int flags){
    pthread_rwlock_wrlock(&env_lock);
    const char* name = JS_AtomToCString(ctx, atom);
    for(size_t i = 0; i < env -> env_count; i++){
        if(strcmp(name, env -> env_names[i]) == 0){
            js_free(ctx, env -> env_values[i]);
            env -> env_values[i] = js_strdup(ctx, JS_ToCString(ctx, value));

            setenv(name, env -> env_values[i], true);
            pthread_rwlock_unlock(&env_lock);
            return true;
        }
    }

    // create
    const char* value_str = JS_ToCString(ctx, value);
    char* name_str = strdup(name);
    char* value_str_copy = strdup(value_str);
    env -> env_names = realloc(env -> env_names, (env -> env_count + 1) * sizeof(char*));
    env -> env_values = realloc(env -> env_values, (env -> env_count + 1) * sizeof(char*));
    env -> env_names[env -> env_count] = name_str;
    env -> env_values[env -> env_count] = value_str_copy;
    env -> env_count++;
    setenv(name, value_str, true);
    pthread_rwlock_unlock(&env_lock);
    return true;
}

__attribute((constructor)) void init_env_class(void) {
    pthread_rwlock_init(&env_lock, NULL);
    pthread_rwlock_wrlock(&env_lock);
    env = malloc(sizeof(struct ReactiveEnviron));
    char** envp = environ;

    // measure env count
    size_t env_count = 0;
    while (envp[env_count]) env_count++;
    env->env_count = env_count;

    // allocate memory
    env->env_names = malloc(env_count * sizeof(char*));
    env->env_values = malloc(env_count * sizeof(char*));

    // parse env
    for (uint32_t i = 0; i < env_count; i++) {
        char* eq_pos = strchr(envp[i], '=');
        if (eq_pos == NULL) continue;
        uint32_t name_len = eq_pos - envp[i];

        env->env_names[i] = malloc( name_len + 1);
        env->env_values[i] = strdup(eq_pos + 1);
        memcpy(env->env_names[i], envp[i], name_len);
        env->env_names[i][name_len] = '\0';
    }
    pthread_rwlock_unlock(&env_lock);
}

__attribute((destructor)) void free_env_class(void) {
    free(env -> env_names);
    free(env -> env_values);
    free(env);
    pthread_rwlock_destroy(&env_lock);
}

static JSClassExoticMethods js_re_exotic_methods = {
    .get_own_property = js_re_get_prop_exists,
    .get_own_property_names = js_re_get_prop_names,
    .define_own_property = js_re_set_own_prop,
    .delete_property = js_re_del_prop,
    .set_property = js_re_set_prop
};

static JSClassDef js_re_class_def = {
    "ReactiveEnviron",
    .exotic = &js_re_exotic_methods
};

JSValue js_exit(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    uint32_t exit_code = 0;
    if (argc == 1) {
        if(-1 == JS_ToUint32(ctx, &exit_code, argv[0]) || exit_code > 255){
            return JS_ThrowTypeError(ctx, "invalid exit code");
        }
    }

    // 调用事件
    LJS_dispatch_ev(ctx, "exit", JS_NewInt32(ctx, exit_code));

#ifdef LJS_DEBUG
    printf("jsvm: exit with code %d\n", exit_code);
#endif

    exit(exit_code);
    return JS_UNDEFINED;
}

typedef struct {
    JSValue handler;
    JSContext* ctx;
    int sig;
    struct list_head list;
} signal_data;
static struct list_head signal_list;
static pthread_rwlock_t signal_lock;

static void js_signal_handler(int sig){
    pthread_rwlock_rdlock(&signal_lock);
    struct list_head *el, *el1;
    list_for_each_safe(el, el1, &signal_list){
        signal_data* data = list_entry(el, signal_data, list);
        if(data -> sig == sig){
            JSValue handler = data -> handler;
            JSValue ret = JS_Call(data -> ctx, handler, JS_UNDEFINED, 0, NULL);
            if(JS_IsException(ret)){
                fprintf(stderr, "Uncaught exception: %s\n", JS_ToCString(data -> ctx, ret));
            }
            JS_FreeValue(data -> ctx, ret);
            break;
        }
    }
    pthread_rwlock_unlock(&signal_lock);
}

static JSValue js_set_signal(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if (argc!= 2) {
        return LJS_Throw(ctx, "Invalid arguments", "Process.signal(signal: number, handler: () => any)");
    }
    uint32_t sig;
    if(-1 == JS_ToUint32(ctx, &sig, argv[0])) return JS_EXCEPTION;
    if( signal(sig, js_signal_handler) ){
        return JS_ThrowTypeError(ctx, "Set signal handler failed");
    }

    // 加入signal表
    signal_data* data = js_malloc(ctx, sizeof(signal_data));
    data -> handler = JS_DupValue(ctx, argv[1]);
    data -> ctx = ctx;
    data -> sig = sig;
    pthread_rwlock_wrlock(&signal_lock);
    list_add_tail(&data -> list, &signal_list);
    pthread_rwlock_unlock(&signal_lock);

    return JS_UNDEFINED;
}

static JSValue js_del_signal(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if (argc!= 1) {
        return LJS_Throw(ctx, "Invalid arguments", "Process.removeSignal(callback: Function, signal?: number): boolean");
    }
    uint32_t sig = -1;
    if(argc == 2) JS_ToUint32(ctx, &sig, argv[1]);
    JSValue handler = argv[0];

    // 遍历signal表
    pthread_rwlock_wrlock(&signal_lock);
    struct list_head* el, *el1;
    list_for_each_safe(el, el1, &signal_list){
        signal_data* data = list_entry(el, signal_data, list);
        if(data -> sig == sig || sig == -1){
            if(
                // 完全相同函数
                JS_VALUE_GET_PTR(data -> handler) == JS_VALUE_GET_PTR(handler) &&
                (sig == -1 ? true : data -> sig == sig)
            ){
                list_del(&data -> list);
                js_free(ctx, data);
                return JS_TRUE;
            }
        }
    }
    pthread_rwlock_unlock(&signal_lock);
    return JS_FALSE;
}

static JSValue js_get_ppid(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    return JS_NewInt32(ctx, getppid());
}

static JSValue js_cwd(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc == 0){
        char cwd[PATH_MAX];
        if(getcwd(cwd, PATH_MAX) == NULL)
            return JS_ThrowTypeError(ctx, "Failed to get current working directory");
        return JS_NewString(ctx, cwd);
    }else{
        const char* path = JS_ToCString(ctx, argv[0]);
        if(chdir(path)!= 0)
            return LJS_Throw(ctx, "Failed to change cwd to %s: %s", NULL, path, strerror(errno));
        JS_FreeCString(ctx, path);
        return JS_UNDEFINED;
    }
}

static JSValue js_sleep(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 1) return LJS_Throw(ctx, "Invalid arguments", "Process.sleep(ms: number): void");
    int32_t ms;
    if(-1 == JS_ToInt32(ctx, &ms, argv[0])) return JS_EXCEPTION;
    usleep(ms * 1000);
    return JS_UNDEFINED;
}

static JSValue js_get_self(JSContext* ctx){
    App* app = JS_GetContextOpaque(ctx);
    char* entry = app -> script_path;

    // note: basename() and dirname() may modify the input string, so we need to make a copy
    char* dir = js_strdup(ctx, entry),
        * file = js_strdup(ctx, entry);

    JSValue ret = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, ret, "pid", JS_NewInt32(ctx, getpid()));
    JS_SetPropertyStr(ctx, ret, "argv", JS_NewArrayFrom(ctx, argc, argv));
    JS_SetPropertyStr(ctx, ret, "entry", JS_NewString(ctx, entry));
    JS_SetPropertyStr(ctx, ret, "dirname", JS_NewString(ctx, dirname(dir)));
    JS_SetPropertyStr(ctx, ret, "filename", JS_NewString(ctx, basename(file)));
    JS_SetPropertyStr(ctx, ret, "env", JS_NewObjectClass(ctx, js_reactive_environ_class_id));

    js_free(ctx, dir);
    js_free(ctx, file);

#ifdef LJS_DEBUG
    printf("jsvm: create process %d, entry: %s\n", getpid(), entry);
#endif

    JS_SetPropertyStr(ctx, ret, "signal", JS_NewCFunction(ctx, js_set_signal, "setSignal", 2));
    JS_SetPropertyStr(ctx, ret, "removeSignal", JS_NewCFunction(ctx, js_del_signal, "removeSignal", 1));

    JS_DefinePropertyGetSet(ctx, ret, JS_NewAtom(ctx, "cwd"), JS_NewCFunction(ctx, js_cwd, "getCwd", 0), JS_NewCFunction(ctx, js_cwd, "setCwd", 1), 0);
    JS_DefinePropertyGetSet(ctx, ret, JS_NewAtom(ctx, "ppid"), JS_NewCFunction(ctx, js_get_ppid, "getPpid", 0), JS_UNDEFINED, 0);

    return ret;
}

// class Process
static thread_local JSClassID js_process_class_id;
struct process_class {
    int pid;
    int16_t exit_code;
    JSValue onclose;
    JSContext* ctx;

    EvFD* evfd;
    struct list_head link;
};
#define GET_PROC_OPAQUE struct process_class *obj = JS_GetOpaque(this_val, js_process_class_id); \
    if(obj == NULL) return JS_EXCEPTION;

static JSValue js_process_kill(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    GET_PROC_OPAQUE
    if(obj -> exit_code >= 0){
        return JS_ThrowTypeError(ctx, "Process is already exited");
    }
    int32_t sig = SIGTERM;
    if(argc > 0){
        if(-1 == JS_ToInt32(ctx, &sig, argv[0])){
            return LJS_Throw(ctx, "Invalid signal", "Process.kill(signal: number)");
        }
    }
    if(kill(obj -> pid, sig) == -1){
        return JS_FALSE;
    }
    return JS_TRUE;
}

static JSValue js_process_get_return_code(JSContext *ctx, JSValueConst this_val){
    GET_PROC_OPAQUE
    return JS_NewUint32(ctx, obj -> exit_code);
}

static JSValue js_process_isrunning(JSContext *ctx, JSValueConst this_val){
    GET_PROC_OPAQUE
    return obj -> exit_code == -1 ? JS_TRUE : JS_FALSE;
}

static JSValue js_process_get_pid(JSContext* ctx, JSValueConst this_val){
    GET_PROC_OPAQUE
    return JS_NewInt32(ctx, obj -> pid);
}

static void js_process_finalizer(JSRuntime* rt, JSValue this_val){
    struct process_class *obj = JS_GetOpaque(this_val, js_process_class_id);
    if(obj -> exit_code < 0){
        // send close signal
        kill(obj -> pid, SIGTERM);
    }
    js_free_rt(rt, obj);
}

struct list_head process_list;
pthread_rwlock_t process_lock;

static JSValue js_process_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    struct process_class *obj = js_malloc(ctx, sizeof(struct process_class));
    JSValue class_obj = JS_NewObjectClass(ctx, js_process_class_id);
    if (JS_IsException(class_obj))
        goto fail;

    // 转换args
    if(argc < 1){
        LJS_Throw(ctx, "Expect at least one argument", "new Process(command: string, options?: {env?: Record<string, string>, inheritPipe?: boolean, cwd?: string})");
        goto fail;
    }

    // 参数2: env, inheritPipe, cwd
    JSValue opts = argc > 1 ? argv[1] : JS_NULL;
    bool inherit = JS_ToBool(ctx, JS_GetPropertyStr(ctx, opts, "inheritPipe"));
    if(inherit && !LJS_IsMainContext(ctx)){
        LJS_Throw(ctx, "inherit-pipe Process can only be created in main thread", 
            "To avoid race condition, Process can only be created in main thread"
        );
        goto fail;
    }

    JSValue args = argv[0];
    int64_t len;
    if(!JS_IsArray(args) || -1 == JS_GetLength(ctx, args, &len) || len < 1){
        LJS_Throw(ctx, "Invalid arguments: Expected an array of at least one string(executable path)", NULL);
        goto fail;
    }
    char** _argv = malloc((len +1) * sizeof(char*));
    for(int i = 0; i < len; i++){
        JSValue val = JS_GetPropertyUint32(ctx, args, i);
        if(JS_IsException(val)){
            goto fail;
        }
        const char* str = JS_ToCString(ctx, val);
        _argv[i] = strdup(str);
        JS_FreeCString(ctx, str);
        JS_FreeValue(ctx, val);
    }
    _argv[len] = NULL;

    // onclose
    JSValue promise_cb[2];
    JSValue promise = JS_NewPromiseCapability(ctx, promise_cb);
    JS_SetPropertyStr(ctx, class_obj, "onclose", promise);

    // 创建pty
    int master_fd, slave_fd;
    if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL) == -1) {
        LJS_Throw(ctx, "Failed to create pty: %s", NULL, strerror(errno));
        goto fail;
    }

    // 加入链表
    obj -> exit_code = -1;
    obj -> ctx = ctx;
    obj -> onclose = promise_cb[1];
    JS_FreeValue(ctx, promise_cb[0]);
    pthread_rwlock_wrlock(&process_lock);
    list_add_tail(&obj -> link, &process_list);
    pthread_rwlock_unlock(&process_lock);

    // 创建进程
    pid_t pid = fork();
    if (pid == -1) {
        LJS_Throw(ctx, "Failed to create process: %s", NULL, strerror(errno));
        list_del(&obj -> link);
        close(master_fd);
        goto fail;
    } else if (pid == 0) {
        // 子进程
        close(master_fd);
        
#ifdef LJS_DEBUG
        printf("Child process: %d with pty\n", getpid());
#endif

#define ioassert(cond) if(-1 == (cond)){ perror(#cond); exit(1); }
        ioassert(setsid());
        ioassert(ioctl(slave_fd, TIOCSCTTY, NULL));
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        fcntl(STDIN_FILENO, F_DUPFD, slave_fd); 
        fcntl(STDOUT_FILENO, F_DUPFD, slave_fd);
        fcntl(STDERR_FILENO, F_DUPFD, slave_fd);
        setbuf(stdin, NULL);
        setbuf(stdout, NULL);
        setbuf(stderr, NULL);
        close(slave_fd);
#undef ioassert
        
        // 初始化环境变量
        if(argc > 1){
            JSValue envs = JS_GetPropertyStr(ctx, opts, "env");
            if(JS_IsObject(envs)){
                JSPropertyEnum* props;
                uint32_t len;
                if(JS_GetOwnPropertyNames(ctx, &props, &len, envs, JS_GPN_STRING_MASK)){
                    for(int i = 0; i < len; i++){
                        JSAtom atom = props[i].atom;
                        const char* name = JS_AtomToCString(ctx, atom);
                        JSValue val = JS_GetProperty(ctx, envs, atom);
                        if(JS_IsString(val)){
                            const char* value = JS_ToCString(ctx, val);
                            setenv(name, value, 1);
                        }
                        JS_FreeCString(ctx, name);
                        JS_FreeValue(ctx, val);
                    }
                }
                JS_FreePropertyEnum(ctx, props, len);
            }
            JS_FreeValue(ctx, envs);
        }

        // cwd
        if(JS_IsString(JS_GetPropertyStr(ctx, opts, "cwd"))){
            const char* cwd = JS_ToCString(ctx, JS_GetPropertyStr(ctx, opts, "cwd"));
            chdir(cwd);
            JS_FreeCString(ctx, cwd);
        }

        execvp(_argv[0], _argv);

        // free
        for(int i = 0; i < len; i++){
            free(_argv[i]);
        }
        free(_argv);
        exit(127);
    }else{
        obj -> pid = pid;
    }

    close(slave_fd);    // not required
    EvFD* evfd;
    if(inherit){
        // Note: This will block stdin but not stdout
        EvFD* from = LJS_evfd_new(master_fd, false, true, true, EVFD_BUFSIZE, NULL, NULL);
        LJS_evfd_pipeTo(from, pstdin, NULL, NULL, NULL, NULL);
        LJS_evfd_pipeTo(pstdout, from, NULL, NULL, NULL, NULL);
        LJS_evfd_pipeTo(pstderr, from, NULL, NULL, NULL, NULL);
    }else{
        JSValue pipe = LJS_NewFDPipe(ctx, master_fd, PIPE_READ | PIPE_WRITE, PIPE_BUF, &evfd);
        obj -> evfd = evfd;
        JS_SetPropertyStr(ctx, class_obj, "pipe", pipe);
    }
    JS_SetOpaque(class_obj, obj);
    return class_obj;

fail:
    js_free(ctx, obj);
    JS_FreeValue(ctx, class_obj);
    JS_Call(ctx, promise_cb[1], JS_UNDEFINED, 0, NULL);
    JS_FreeValue(ctx, promise_cb[1]);
    JS_FreeValue(ctx, promise_cb[0]);
    return JS_EXCEPTION;
}

// capture signal
void sigchild_handle(int sig){
    pthread_rwlock_rdlock(&process_lock);
    struct list_head* el, *el1;
    list_for_each_safe(el, el1, &process_list){
        struct process_class* obj = list_entry(el, struct process_class, link);
        // waitpid?
        int exitcode;
        if(waitpid(obj -> pid, &exitcode, WNOHANG) == 0){
            if(WIFEXITED(exitcode)) {
#ifdef LJS_DEBUG
                printf("Process %d exited with code %d\n", obj -> pid, WEXITSTATUS(exitcode));
#endif
                // close
                LJS_evfd_shutdown(obj -> evfd);
                JS_Call(obj -> ctx, obj -> onclose, JS_UNDEFINED, 0, NULL);
                obj -> exit_code = WEXITSTATUS(exitcode);
                JS_FreeValue(obj -> ctx, obj -> onclose);
                list_del(&obj -> link);
            }
        }
    }
    pthread_rwlock_unlock(&process_lock);
}

__attribute__((destructor)) void subproc_destructor(void){
    pthread_rwlock_rdlock(&process_lock);
    struct list_head* el, *el1;
    list_for_each_safe(el, el1, &process_list){
#ifdef LJS_DEBUG
        printf("Process %d is not exited, kill it with SIGINT\n", list_entry(el, struct process_class, link) -> pid);
#endif
        struct process_class* obj = list_entry(el, struct process_class, link);
        // kill force
        kill(obj -> pid, SIGINT);
    }
}

__attribute__((constructor)) void subproc_constructor(void){
    init_list_head(&signal_list);
    init_list_head(&process_list);
    pthread_rwlock_init(&process_lock, NULL);
    signal(SIGCHLD, sigchild_handle);
}

static const JSCFunctionListEntry js_process_proto_funcs[] = {
    JS_CFUNC_DEF("kill", 1, js_process_kill),
    JS_CGETSET_DEF("code", js_process_get_return_code, NULL),
    JS_CGETSET_DEF("alive", js_process_isrunning, NULL),
    JS_CGETSET_DEF("pid", js_process_get_pid, NULL)
};

static const JSCFunctionListEntry js_process_signals[] = {
    C_CONST(SIGTERM),
    C_CONST(SIGINT),
    C_CONST(SIGKILL),
    C_CONST(SIGQUIT),
    C_CONST(SIGHUP),
    C_CONST(SIGUSR1),
    C_CONST(SIGUSR2),
    C_CONST(SIGPIPE),
    C_CONST(SIGALRM),
    C_CONST(SIGCHLD),
    C_CONST(SIGCONT),
    C_CONST(SIGSTOP),
    C_CONST(SIGTSTP),
    C_CONST(SIGTTIN),
    C_CONST(SIGTTOU),
    C_CONST(SIGURG),
    C_CONST(SIGXCPU),
    C_CONST(SIGXFSZ),
    C_CONST(SIGVTALRM),
    C_CONST(SIGPROF),
    C_CONST(SIGWINCH),
    C_CONST(SIGIO),
    C_CONST(SIGPWR),
    C_CONST(SIGSYS),
};

static const JSClassDef js_process_class = {
    "Process",
    .finalizer = js_process_finalizer
};

static JSValue js_get_sysinfo(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    struct sysinfo info;
    if(sysinfo(&info) == -1){
        return LJS_Throw(ctx, "Failed to get system information: %s", NULL, strerror(errno));
    }
    JSValue obj = JS_NewObject(ctx);
    JSValue memory_obj = JS_NewObject(ctx);
    JSValue cpu_obj = JS_NewObject(ctx);
    JSValue load_arr = JS_NewArrayFrom(ctx, 3, (JSValueConst[]){
        JS_NewFloat64(ctx, info.loads[0]), 
        JS_NewFloat64(ctx, info.loads[1]), 
        JS_NewFloat64(ctx, info.loads[2])
    });
    JS_SetPropertyStr(ctx, memory_obj, "total", JS_NewInt64(ctx, info.totalram));
    JS_SetPropertyStr(ctx, memory_obj, "free", JS_NewInt64(ctx, info.freeram));
    JS_SetPropertyStr(ctx, memory_obj, "shared", JS_NewInt64(ctx, info.sharedram));
    JS_SetPropertyStr(ctx, memory_obj, "buffers", JS_NewInt64(ctx, info.bufferram));
    JS_SetPropertyStr(ctx, memory_obj, "cached", JS_NewInt64(ctx, info.totalswap - info.freeswap));
    JS_SetPropertyStr(ctx, memory_obj, "used", JS_NewInt64(ctx, info.totalram - info.freeram));
    JS_SetPropertyStr(ctx, memory_obj, "swap", JS_NewInt64(ctx, info.totalswap));

    JS_SetPropertyStr(ctx, cpu_obj, "count", JS_NewInt32(ctx, sysconf(_SC_NPROCESSORS_ONLN)));
    JS_SetPropertyStr(ctx, cpu_obj, "speed", JS_NewInt32(ctx, sysconf(_SC_CLK_TCK)));
    struct timespec cpu_time;
    if(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_time)){
        JS_SetPropertyStr(ctx, cpu_obj, "time", JS_NewInt64(ctx, cpu_time.tv_sec * 1000 + cpu_time.tv_nsec / 1000000 % 1000));
    }

    struct utsname uts;
    if(uname(&uts) == 0){
        JSValue sys_obj = JS_NewObject(ctx);
        JS_SetPropertyStr(ctx, sys_obj, "system", JS_NewString(ctx, uts.sysname));
        JS_SetPropertyStr(ctx, sys_obj, "node", JS_NewString(ctx, uts.nodename));
        JS_SetPropertyStr(ctx, sys_obj, "release", JS_NewString(ctx, uts.release));
        JS_SetPropertyStr(ctx, sys_obj, "version", JS_NewString(ctx, uts.version));
        JS_SetPropertyStr(ctx, sys_obj, "arch", JS_NewString(ctx, uts.machine));
        JS_SetPropertyStr(ctx, sys_obj, "domain", JS_NewString(ctx, uts.domainname));
        JS_SetPropertyStr(ctx, obj, "sys", sys_obj);
    }

    JS_SetPropertyStr(ctx, obj, "memory", memory_obj);
    JS_SetPropertyStr(ctx, obj, "uptime", JS_NewInt64(ctx, info.uptime));
    JS_SetPropertyStr(ctx, obj, "loadavg", load_arr);
    JS_SetPropertyStr(ctx, obj, "cpu", cpu_obj);
    JS_SetPropertyStr(ctx, obj, "process", JS_NewInt32(ctx, info.procs));
    return obj;
}

EvFD *pstdin, *pstdout, *pstderr;
static int js_process_init(JSContext* ctx, JSModuleDef* m){
    JS_SetModuleExport(ctx, m, "self", js_get_self(ctx));
    JS_SetModuleExport(ctx, m, "exit", JS_NewCFunction(ctx, js_exit, "exit", 1));

    // class Process
    JSValue process = JS_NewCFunction2(ctx, js_process_constructor, "Process", 1, JS_CFUNC_constructor, 0);
    JSValue proc_proto = JS_GetPrototype(ctx, process);
    JS_SetPropertyFunctionList(ctx, proc_proto, js_process_proto_funcs, countof(js_process_proto_funcs));
    JS_SetClassProto(ctx, js_process_class_id, proc_proto);
    JS_SetConstructor(ctx, process, JS_GetClassProto(ctx, js_process_class_id));

    JS_SetModuleExport(ctx, m, "Process", process);

    // signal
    JSValue signals = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, signals, js_process_signals, countof(js_process_signals));
    JS_SetModuleExport(ctx, m, "signals", signals);

    // set STDIN
    // struct termios tty;
    // tcgetattr(STDIN_FILENO, &tty);
    // tty.c_iflag &= ~(ICRNL | INLCR | ECHO | ICANON);    // 禁止 CR -> LF 转换
    // tty.c_oflag &= ~(OPOST | ONLCR);                    // 禁止输出时添加 CR
    // tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    // stdin, stdout, stderr
    if(LJS_IsMainContext(ctx)){
        JSValue stdin_p = LJS_NewFDPipe(ctx, STDIN_FILENO, PIPE_READ, PIPE_BUF, &pstdin),
            stdout_p = LJS_NewFDPipe(ctx, STDOUT_FILENO, PIPE_WRITE, PIPE_BUF, &pstdout),
            stderr_p = LJS_NewFDPipe(ctx, STDERR_FILENO, PIPE_WRITE, PIPE_BUF, &pstderr);
        JS_SetModuleExport(ctx, m, "stdin", stdin_p);
        JS_SetModuleExport(ctx, m, "stdout", stdout_p);
        JS_SetModuleExport(ctx, m, "stderr", stderr_p);
    }

    // sleep
    JS_SetModuleExport(ctx, m, "sleep", JS_NewCFunction(ctx, js_sleep, "sleep", 1));

    // vm
    JS_SetModuleExport(ctx, m, "sysinfo", JS_NewCFunction(ctx, js_get_sysinfo, "sysinfo", 0));

    return 0;
}

bool LJS_init_process(JSContext* ctx, uint32_t _argc, char** _argv
){
    argc = _argc;

    // parse argv
    argv = _argc == 0 ? NULL : js_malloc(ctx, sizeof(JSValue) * _argc);
    if(_argc != 0)
        for(int i = 0; i < _argc; i++){
            argv[i] = JS_NewString(ctx, _argv[i]);
        }

    // init module
    JSRuntime* rt = JS_GetRuntime(ctx);
    JSModuleDef* m = JS_NewCModule(ctx, "process", js_process_init);
    if(!m) return false;
    JS_AddModuleExport(ctx, m, "self");

    // class process
    JS_NewClassID(rt, &js_process_class_id);
    JS_NewClass(rt, js_process_class_id, &js_process_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_process_proto_funcs, countof(js_process_proto_funcs));
    JS_SetClassProto(ctx, js_process_class_id, proto);

    // class ReactiveEnviron
    JS_NewClassID(rt, &js_reactive_environ_class_id);
    JS_NewClass(rt, js_reactive_environ_class_id, &js_re_class_def);

    JS_AddModuleExport(ctx, m, "Process");
    JS_AddModuleExport(ctx, m, "exit");

    // signal
    JS_AddModuleExport(ctx, m, "signals");

    // stdin/out/err
    JS_AddModuleExport(ctx, m, "stdin");
    JS_AddModuleExport(ctx, m, "stdout");
    JS_AddModuleExport(ctx, m, "stderr");

    // vm
    JS_AddModuleExport(ctx, m, "sysinfo");

    // sleep
    JS_AddModuleExport(ctx, m, "sleep");

    return true;
}