#include "../engine/quickjs.h"
#include "../engine/cutils.h"
#include "../engine/list.h"
#include "polyfill.h"
#include "core.h"

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
extern char* __progpath;    // XXX: define a function to set this?
static JSValue* js_argv;
static size_t js_argc;

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
            free(env -> env_names[i]);
            free(env -> env_values[i]);
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
            free(env -> env_values[i]);
            env -> env_values[i] = strdup(JS_ToCString(ctx, value));

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

__attribute__((constructor)) void init_env_class(void) {
    pthread_rwlock_init(&env_lock, NULL);
    pthread_rwlock_wrlock(&env_lock);
    env = malloc(sizeof(struct ReactiveEnviron));
    char** envp = environ;

    // measure env count
    size_t env_count = 0;
    while (envp[env_count]) env_count++;
    env -> env_count = env_count;

    // allocate memory
    env -> env_names = malloc(env_count * sizeof(char*));
    env -> env_values = malloc(env_count * sizeof(char*));

    // parse env
    for (uint32_t i = 0; i < env_count; i++) {
        char* eq_pos = strchr(envp[i], '=');
        if (eq_pos == NULL) continue;
        uint32_t name_len = eq_pos - envp[i];

        env -> env_names[i] = malloc( name_len + 1);
        env -> env_values[i] = strdup(eq_pos + 1);
        memcpy(env -> env_names[i], envp[i], name_len);
        env -> env_names[i][name_len] = '\0';
    }
    pthread_rwlock_unlock(&env_lock);
}

__attribute__((destructor)) void free_env_class(void) {
    for(size_t i = 0; i < env -> env_count; i++){
        free(env -> env_names[i]);
        free(env -> env_values[i]);
    }
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

static JSValue js_process_exit(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    uint32_t exit_code = 0; 
    if (argc == 1) {
        if(-1 == JS_ToUint32(ctx, &exit_code, argv[0]) || exit_code > 255){
            return JS_ThrowTypeError(ctx, "invalid exit code");
        }
    }

#ifdef LJS_DEBUG
    printf("jsvm: exit with code %d\n", exit_code);
#endif

    JS_ThrowInternalError(ctx, " ");
    JSValue ie = JS_GetException(ctx);
    JS_SetProperty(ctx, ie, JS_ATOM__ret_, JS_NewInt32(ctx, exit_code));
    JS_SetUncatchableError(ctx, ie);
    return JS_Throw(ctx, ie);
}

struct signal_data{
    JSValue handler;
    JSContext* ctx;
    int sig;
    struct list_head list;
};


static struct list_head signal_list;
static pthread_rwlock_t signal_lock;
extern bool exiting;

static void js_signal_handler(int sig){
    pthread_rwlock_rdlock(&signal_lock);
    struct list_head *el, *el1;
    list_for_each_safe(el, el1, &signal_list){
        struct signal_data* data = list_entry(el, struct signal_data, list);
        if(data -> sig == sig){
            App* app = (App*)JS_GetContextOpaque(data -> ctx);
            if(app -> thread == pthread_self()){
                // exec in current thread
                JSValue ret = JS_Call(data -> ctx, data -> handler, JS_UNDEFINED, 0, NULL);
                if(JS_IsException(ret)){
                    JSValue err = JS_GetException(data -> ctx);
                    if(JS_IsInternalError(data -> ctx, err))
                        exiting = true;
                    else
                        js_dump(data -> ctx, err, pstderr);
                    JS_FreeValue(data -> ctx, err);
                }else{
                    JS_FreeValue(data -> ctx, ret);
                }
            }else{
                pthread_kill(app -> thread, sig);
                break;
            }
        }
    }
    pthread_rwlock_unlock(&signal_lock);
}

static struct sigaction default_sa = {
    .sa_flags = SA_RESTART,
    .sa_handler = js_signal_handler
};

static JSValue js_set_signal(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if (argc < 2 || !JS_IsFunction(ctx, argv[1]) || !JS_IsNumber(argv[0])) {
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid arguments", "Process.signal(signal: number, handler: () => any)");
    }
    uint32_t sig;
    if(-1 == JS_ToUint32(ctx, &sig, argv[0])) return JS_EXCEPTION;

    // push to signal list
    struct signal_data* data = js_malloc(ctx, sizeof(struct signal_data));
    data -> handler = JS_DupValue(ctx, argv[1]);
    data -> ctx = ctx;
    data -> sig = sig;

    if(-1 == sigaction(sig, &default_sa, NULL)) {
        free(data);
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Set signal handler failed: %s", NULL, strerror(errno));
    }

    pthread_rwlock_wrlock(&signal_lock);
    list_add_tail(&data -> list, &signal_list);
    pthread_rwlock_unlock(&signal_lock);

    return JS_UNDEFINED;
}

static JSValue js_del_signal(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if (argc!= 1) {
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid arguments", "Process.removeSignal(callback: Function, signal?: number): boolean");
    }
    uint32_t sig = -1;
    if(argc == 2) JS_ToUint32(ctx, &sig, argv[1]);
    JSValue handler = argv[0];

    // 遍历signal表
    pthread_rwlock_wrlock(&signal_lock);
    struct list_head* el, *el1;
    list_for_each_safe(el, el1, &signal_list){
        struct signal_data* data = list_entry(el, struct signal_data, list);
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
            return LJS_Throw(ctx, EXCEPTION_IO, "Failed to change cwd to %s: %s", NULL, path, strerror(errno));
        JS_FreeCString(ctx, path);
        return JS_UNDEFINED;
    }
}

static JSValue js_sleep(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc!= 1) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid arguments", "Process.sleep(ms: number): void");
    int32_t ms;
    if(-1 == JS_ToInt32(ctx, &ms, argv[0])) return JS_EXCEPTION;
    usleep(ms * 1000);
    return JS_UNDEFINED;
}

static JSValue js_get_self(JSContext* ctx){
    App* app = JS_GetContextOpaque(ctx);
    char* entry = app -> script_path;
    JSValue ret = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, ret, "pid", JS_NewInt32(ctx, getpid()));
    JS_SetPropertyStr(ctx, ret, "args", JS_NewArrayFrom(ctx, js_argc, js_argv));
    JS_SetPropertyStr(ctx, ret, "entry", JS_NewString(ctx, entry));
    JS_SetPropertyStr(ctx, ret, "binary", JS_NewString(ctx, __progpath));
    JS_SetPropertyStr(ctx, ret, "env", JS_NewObjectClass(ctx, js_reactive_environ_class_id));
    
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
            return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid signal", "Process.kill(signal: number)");
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
    JSValue jsobj;   // cache to free after getprop
    if (JS_IsException(class_obj))
        goto fail;

    // 转换args
    if(argc < 1){
        LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Expect at least one argument", "new Process(command: string, options?: {env?: Record<string, string>, inheritPipe?: boolean, cwd?: string})");
        goto fail;
    }

    // 参数2: env, inheritPipe, cwd
    JSValue opts = argc > 1 ? argv[1] : JS_NULL;
    bool inherit = JS_ToBool(ctx, jsobj = JS_GetPropertyStr(ctx, opts, "inheritPipe"));
    JS_FreeValue(ctx, jsobj);
    if(inherit && !LJS_IsMainContext(ctx)){
        LJS_Throw(ctx, EXCEPTION_TYPEERROR, "inherit-pipe Process can only be created in main thread", 
            "To avoid race condition for STDIN/STDOUT/STDERR, inherit-pipe Process cannot be created in worker thread"
        );
        goto fail;
    }

    JSValue args = argv[0];
    int64_t len;
    if(!JS_IsArray(args) || -1 == JS_GetLength(ctx, args, &len) || len < 1){
        LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid arguments: Expected an array of at least one string(executable path)", NULL);
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
        LJS_Throw(ctx, EXCEPTION_IO, "Failed to create pty: %s", NULL, strerror(errno));
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
        LJS_Throw(ctx, EXCEPTION_IO, "Failed to create process: %s", NULL, strerror(errno));
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
        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);
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
        if(JS_IsString(jsobj = JS_GetPropertyStr(ctx, opts, "cwd"))){
            const char* cwd = JS_ToCString(ctx, jsobj);
            chdir(cwd);
            JS_FreeCString(ctx, cwd);
        }
        JS_FreeValue(ctx, jsobj);

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
    
    // exit immediately
    if(obj -> exit_code >= 0){
        close(master_fd);
        goto fail;
    }

    if(inherit){
        // Note: This will block stdin but not stdout
        evfd = evfd_new(master_fd, PIPE_WRITE | PIPE_READ | PIPE_PTY, EVFD_BUFSIZE, NULL, NULL);
        evfd_pipeTo(pstdin, evfd, NULL, NULL, NULL, NULL);
        evfd_pipeTo(evfd, pstdout, NULL, NULL, NULL, NULL);
    }else{
        JSValue pipe = LJS_NewFDPipe(ctx, master_fd, PIPE_READ | PIPE_WRITE | PIPE_PTY, true, &evfd);
        JS_SetPropertyStr(ctx, class_obj, "pipe", pipe);
    }
    obj -> evfd = evfd;
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

static JSValue js_process_static_kill(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    int pid, signal = SIGILL;
    if(argc == 0) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid arguments", "Process.kill(pid: number, signal?: number): void");
    if(argc >= 2) JS_ToInt32(ctx, &signal, argv[1]);
    if(-1 == JS_ToInt32(ctx, &pid, argv[0])) return JS_EXCEPTION;
    if(kill(pid, signal) == -1){
        return LJS_Throw(ctx, EXCEPTION_IO, "Failed to kill process: %s", NULL, strerror(errno));
    }
    return JS_UNDEFINED;
}

// capture signal
static void sigchild_handler(int sig){
    pthread_rwlock_rdlock(&process_lock);
    struct list_head* el, *el1;
    list_for_each_safe(el, el1, &process_list){
        struct process_class* obj = list_entry(el, struct process_class, link);
        // waitpid?
        int exitcode;
        if(waitpid(obj -> pid, &exitcode, WNOHANG) != -1 && WIFEXITED(exitcode)) {
#ifdef LJS_DEBUG
            printf("Process %d exited with code %d\n", obj -> pid, WEXITSTATUS(exitcode));
#endif
            // close
            if(obj -> evfd){
                evfd_shutdown(obj -> evfd);
            }
            JS_Call(obj -> ctx, obj -> onclose, JS_UNDEFINED, 0, NULL);
            obj -> exit_code = WEXITSTATUS(exitcode);
            JS_FreeValue(obj -> ctx, obj -> onclose);
            list_del(&obj -> link);
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

__attribute__((constructor)) static void init_signal_system(void) {
    init_list_head(&signal_list);
    init_list_head(&process_list);
    pthread_rwlock_init(&process_lock, NULL);
    pthread_rwlock_init(&signal_lock, NULL);

    // handle SIGCHLD
    struct sigaction sa_child = {
        .sa_flags = SA_RESTART,
        .sa_handler = sigchild_handler
    };
    sigaction(SIGCHLD, &sa_child, NULL);
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
        return JS_NULL;
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

EvFD *pstdin, *pstdout, *pstderr = NULL;
static JSValue stdin_p, stdout_p, stderr_p;
static int js_process_init(JSContext* ctx, JSModuleDef* m){
    JS_SetModuleExport(ctx, m, "self", js_get_self(ctx));
    JS_SetModuleExport(ctx, m, "exit", JS_NewCFunction(ctx, js_process_exit, "exit", 1));

    // class Process
    JSValue process = JS_NewCFunction2(ctx, js_process_constructor, "Process", 1, JS_CFUNC_constructor, 0);
    JSValue procproto = JS_GetClassProto(ctx, js_process_class_id);
    JS_SetConstructor(ctx, process, procproto);
    JS_DefinePropertyValueStr(ctx, process, "kill",
        JS_NewCFunction(ctx, js_process_static_kill, "Process.kill", 1),
        JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE
    );
    JS_FreeValue(ctx, procproto);

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
        if(pstdin) JS_SetModuleExport(ctx, m, "stdin", stdin_p);
        if(pstdout) JS_SetModuleExport(ctx, m, "stdout", stdout_p);
        if(pstderr) JS_SetModuleExport(ctx, m, "stderr", stderr_p);
        stdin_p = stdout_p = stderr_p = JS_UNDEFINED;
    }

    // sleep
    JS_SetModuleExport(ctx, m, "sleep", JS_NewCFunction(ctx, js_sleep, "sleep", 1));

    // vm
    JS_SetModuleExport(ctx, m, "sysinfo", JS_NewCFunction(ctx, js_get_sysinfo, "sysinfo", 0));

    return 0;
}

bool LJS_init_process(JSContext* ctx, uint32_t _argc, char** _argv
){
    js_argc = _argc;

    // parse argv
    js_argv = _argc == 0 ? NULL : js_malloc(ctx, sizeof(JSValue) * _argc);
    if(_argc != 0)
        for(int i = 0; i < _argc; i++){
            js_argv[i] = JS_NewString(ctx, _argv[i]);
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

    // init stdpipe
    if(LJS_IsMainContext(ctx)){
        stdin_p = LJS_NewFDPipe(ctx, STDIN_FILENO, PIPE_READ, isatty(STDIN_FILENO), &pstdin);
        stdout_p = LJS_NewFDPipe(ctx, STDOUT_FILENO, PIPE_WRITE, isatty(STDOUT_FILENO), &pstdout);
        stderr_p = LJS_NewFDPipe(ctx, STDERR_FILENO, PIPE_WRITE, isatty(STDERR_FILENO), &pstderr);
        if(!pstderr) pstderr = pstdout;
    }

    // vm
    JS_AddModuleExport(ctx, m, "sysinfo");

    // sleep
    JS_AddModuleExport(ctx, m, "sleep");

    return true;
}

void __js_destroy_process(JSContext* ctx){
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &signal_list){
        struct signal_data* obj = list_entry(cur, struct signal_data, list);
        if(obj -> ctx == ctx){
            JS_FreeValue(ctx, obj -> handler);
            list_del(&obj -> list);
            js_free(ctx, obj);
        }
    }

    if(!JS_IsUndefined(stdin_p)) JS_FreeValue(ctx, stdin_p);
    if(!JS_IsUndefined(stdout_p)) JS_FreeValue(ctx, stdout_p);
    if(!JS_IsUndefined(stderr_p)) JS_FreeValue(ctx, stderr_p);
}