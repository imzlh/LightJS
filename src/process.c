#include "../engine/quickjs.h"
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
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <libgen.h>
#include <pty.h>

#define MAX_SIGNAL_SIZE 1024

extern char **environ;
static JSValue* argv;
static size_t argc;
static thread_local char* entry;

// --- class ReactiveEnviron ---
static JSClassID js_reactive_environ_class_id;
struct ReactiveEnviron {
    char** env_names;
    char** env_values;
    JSAtom* env_names_atom;
    size_t env_count;
};

static int js_re_get_prop_exists(JSContext *ctx, JSPropertyDescriptor *desc, JSValue obj, JSAtom prop){
    struct ReactiveEnviron* re = JS_GetOpaque(obj, js_reactive_environ_class_id);
    if(!re) return -1;
    const char* name = JS_AtomToCString(ctx, prop);
    for(size_t i = 0; i < re->env_count; i++){
        if(strcmp(name, re->env_names[i]) == 0){
            desc->flags = JS_PROP_ENUMERABLE | JS_PROP_CONFIGURABLE | JS_PROP_WRITABLE;
            desc->value = JS_NewString(ctx, re->env_values[i]);
            return true;
        }
    }
    return false;
}

static int js_re_get_prop_names(JSContext *ctx, JSPropertyEnum **ptab, uint32_t *plen, JSValue obj){
    struct ReactiveEnviron* re = JS_GetOpaque(obj, js_reactive_environ_class_id);
    if(!re) return -1;
    *ptab = malloc(re->env_count * sizeof(JSPropertyEnum));
    *plen = re->env_count;
    for(size_t i = 0; i < re->env_count; i++){
        (*ptab)[i].atom = re->env_names_atom[i];
        (*ptab)[i].is_enumerable = true;
    }
    return 0;
}

static int js_re_del_prop(JSContext *ctx, JSValue obj, JSAtom prop){
    struct ReactiveEnviron* re = JS_GetOpaque(obj, js_reactive_environ_class_id);
    if(!re) return -1;
    const char* name = JS_AtomToCString(ctx, prop);
    for(size_t i = 0; i < re->env_count; i++){
        if(strcmp(name, re->env_names[i]) == 0){
            free(re->env_names[i]);
            free(re->env_values[i]);
            re->env_count--;

            // move from end to fill the gap
            for(size_t j = i; j < re->env_count; j++){
                re->env_names_atom[j] = re->env_names_atom[j+1];
                re->env_names[j] = re->env_names[j+1];
                re->env_values[j] = re->env_values[j+1];
            }

            unsetenv(name);
            return true;
        }
    }

    return false;
}

static int js_re_set_own_prop(JSContext *ctx, JSValue this_obj, JSAtom prop, JSValue val, JSValue getter, JSValue setter, int flags){
    return false;   // not support
}

// static JSValue js_re_get_prop(JSContext *ctx, JSValue obj, JSAtom atom, JSValue receiver){
//     struct ReactiveEnviron* re = JS_GetOpaque(obj, js_reactive_environ_class_id);
//     if(!re) return JS_UNDEFINED;
//     const char* name = JS_AtomToCString(ctx, atom);
//     for(size_t i = 0; i < re->env_count; i++){
//         if(strcmp(name, re->env_names[i]) == 0){
//             return JS_NewString(ctx, re->env_values[i]);
//         }
//     }
//     return JS_UNDEFINED;
// }

static int js_re_set_prop(JSContext *ctx, JSValue obj, JSAtom atom, JSValue value, JSValue receiver, int flags){
    struct ReactiveEnviron* re = JS_GetOpaque(obj, js_reactive_environ_class_id);
    if(!re) return -1;
    const char* name = JS_AtomToCString(ctx, atom);
    for(size_t i = 0; i < re->env_count; i++){
        if(strcmp(name, re->env_names[i]) == 0){
            free(re->env_values[i]);
            re->env_values[i] = strdup(JS_ToCString(ctx, value));

            setenv(name, re->env_values[i], true);
            return true;
        }
    }

    // create
    const char* value_str = JS_ToCString(ctx, value);
    char* name_str = strdup(name);
    char* value_str_copy = strdup(value_str);
    re->env_names = realloc(re->env_names, (re->env_count + 1) * sizeof(char*));
    re->env_values = realloc(re->env_values, (re->env_count + 1) * sizeof(char*));
    re->env_names_atom = realloc(re->env_names_atom, (re->env_count + 1) * sizeof(JSAtom));
    re->env_names[re->env_count] = name_str;
    re->env_values[re->env_count] = value_str_copy;
    re->env_names_atom[re->env_count] = atom;
    re->env_count++;
    setenv(name, value_str, true);
    return true;
}

static JSValue js_create_reactive_environ(JSContext* ctx){
    struct ReactiveEnviron* re = malloc(sizeof(struct ReactiveEnviron));
    char** envp = environ;

    // measure env count
    size_t env_count = 0;
    while(envp[env_count]) env_count++;

    // allocate memory
    re->env_names = malloc(env_count * sizeof(char*));
    re->env_values = malloc(env_count * sizeof(char*));
    re->env_names_atom = malloc(env_count * sizeof(JSAtom));

    // parse env
    for(uint32_t i = 0; i < env_count; i++){
        char* eq_pos = strchr(envp[i], /* = */ 0x3D);
        if(eq_pos == NULL) continue;
        *eq_pos = '\0';

        re->env_names[i] = strdup(envp[i]);
        re->env_values[i] = strdup(eq_pos + 1);
        re->env_names_atom[i] = JS_NewAtom(ctx, re->env_names[i]);
    }
    
    // create JS object
    JSValue obj = JS_NewObjectClass(ctx, js_reactive_environ_class_id);
    JS_SetOpaque(obj, re);
    return obj;
}

static void js_re_finalizer(JSRuntime *rt, JSValue val){
    struct ReactiveEnviron* re = JS_GetOpaque(val, js_reactive_environ_class_id);
    if(!re) return;
    for(size_t i = 0; i < re->env_count; i++){
        free(re->env_names[i]);
        free(re->env_values[i]);
    }
    free(re->env_names);
    free(re->env_values);
    free(re->env_names_atom);
    free(re);
}

static JSClassDef js_re_class_def = {
    "ReactiveEnviron",
   .finalizer = js_re_finalizer
};

JSValue js_exit(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    uint32_t exit_code = 0;
    if (argc == 1) {
        if(! JS_ToUint32(ctx, &exit_code, argv[0]) || exit_code > 255){
            return JS_ThrowTypeError(ctx, "invalid exit code");
        }
    }

    // 调用事件
    LJS_dispatch_ev("exit", JS_NewInt32(ctx, exit_code));

    exit(exit_code);
    return JS_UNDEFINED;
}

struct signal_data {
    JSValue handler;
    JSContext* ctx;
    int sig;
};
struct signal_data* js_signal_table[MAX_SIGNAL_SIZE];
size_t js_signal_table_size = 0;

static void js_signal_handler(int sig){
    for(int i = 0; i < js_signal_table_size; i++){
        if(js_signal_table[i] && js_signal_table[i]->sig == sig){
            JSValue handler = js_signal_table[i]->handler;
            JSValue ret = JS_Call(js_signal_table[i]->ctx, handler, JS_UNDEFINED, 0, NULL);
            if(JS_IsException(ret)){
                fprintf(stderr, "Uncaught exception: %s\n", JS_ToCString(js_signal_table[i]->ctx, ret));
            }
            JS_FreeValue(js_signal_table[i]->ctx, ret);
            break;
        }
    }
}

static JSValue js_set_signal(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if (argc!= 2) {
        return JS_EXCEPTION;
    }
    const uint32_t sig = JS_ToInt32(ctx, NULL, argv[0]);
    if( signal(sig, js_signal_handler) ){
        return JS_ThrowTypeError(ctx, "Set signal handler failed");
    }

    // 加入signal表
    if(js_signal_table_size >= MAX_SIGNAL_SIZE){
        return JS_ThrowTypeError(ctx, "Too many signal handlers");
    }
    struct signal_data* data = malloc(sizeof(struct signal_data));
    data->handler = JS_DupValue(ctx, argv[1]);
    data->ctx = ctx;
    data->sig = sig;
    js_signal_table[js_signal_table_size++] = data;

    return JS_UNDEFINED;
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
            return JS_ThrowTypeError(ctx, "Failed to change current working directory");
        JS_FreeCString(ctx, path);
        return JS_UNDEFINED;
    }
}

static JSValue js_get_self(JSContext* ctx){
    JSValue ret = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, ret, "pid", JS_NewInt32(ctx, getpid()));
    JS_SetPropertyStr(ctx, ret, "argv", JS_NewArrayFrom(ctx, argc, argv));
    JS_SetPropertyStr(ctx, ret, "entry", JS_NewString(ctx, entry));
    JS_SetPropertyStr(ctx, ret, "dirname", JS_NewString(ctx, dirname(entry)));
    JS_SetPropertyStr(ctx, ret, "filename", JS_NewString(ctx, basename(entry)));
    JS_SetPropertyStr(ctx, ret, "env", js_create_reactive_environ(ctx));

    JS_SetPropertyStr(ctx, ret, "signal", JS_NewCFunction(ctx, js_set_signal, "setSignal", 2));

    JS_DefinePropertyGetSet(ctx, ret, JS_NewAtom(ctx, "cwd"), JS_NewCFunction(ctx, js_cwd, "getCwd", 0), JS_NewCFunction(ctx, js_cwd, "setCwd", 1), 0);
    JS_DefinePropertyGetSet(ctx, ret, JS_NewAtom(ctx, "ppid"), JS_NewCFunction(ctx, js_get_ppid, "getPpid", 0), JS_UNDEFINED, 0);

    return ret;
}

// class Process
JSClassID js_process_class_id;
struct process_class {
    int pid;
    int16_t exit_code;
    int pty_fd;
};

static JSValue js_process_kill(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct process_class *obj = JS_GetOpaque2(ctx, this_val, js_process_class_id);
    if(obj == NULL){
        return JS_ThrowTypeError(ctx, "Process object required");
    }
    if(obj -> exit_code >= 0){
        return JS_ThrowTypeError(ctx, "Process is already exited");
    }
    int32_t sig = SIGTERM;
    if(argc > 0){
        if(!JS_ToInt32(ctx, &sig, argv[0])){
            return LJS_Throw(ctx, "Invalid signal", "Process.kill(signal: number)");
        }
    }
    if(kill(obj->pid, sig) == -1){
        return JS_FALSE;
    }
    return JS_TRUE;
}

static JSValue js_process_get_return_code(JSContext *ctx, JSValueConst this_val){
    struct process_class *obj = JS_GetOpaque2(ctx, this_val, js_process_class_id);
    if(obj == NULL) return JS_EXCEPTION;
    return JS_NewUint32(ctx, obj->exit_code);
}

static JSValue js_process_isrunning(JSContext *ctx, JSValueConst this_val){
    struct process_class *obj = JS_GetOpaque2(ctx, this_val, js_process_class_id);
    if(obj == NULL) return JS_EXCEPTION;

    return obj -> exit_code == -1 ? JS_TRUE : JS_FALSE;
}

static JSValue js_process_set_termsize(JSContext *ctx, JSValueConst this_val, JSValueConst set_value){
    struct process_class *obj = JS_GetOpaque2(ctx, this_val, js_process_class_id);
    if(obj == NULL) return JS_EXCEPTION;
    if(obj -> exit_code < 0) return JS_ThrowTypeError(ctx, "Process is not running");

    uint32_t rows, cols;
    if (
        JS_ToUint32(ctx, &rows, JS_GetPropertyUint32(ctx, set_value, 0)) != 0
     || JS_ToUint32(ctx, &cols, JS_GetPropertyUint32(ctx, set_value, 1)) != 0
    ){
        return JS_ThrowTypeError(ctx, "expected array of two integers");
    }

    struct winsize size;
    size.ws_row = rows;
    size.ws_col = cols;
    if(ioctl(obj->pty_fd, TIOCSWINSZ, &size) == -1){
        return JS_FALSE;
    }
    return JS_TRUE;
}

static JSValue js_process_get_termsize(JSContext *ctx, JSValueConst this_val){
    struct process_class *obj = JS_GetOpaque2(ctx, this_val, js_process_class_id);
    if(obj == NULL) return JS_EXCEPTION;
    if(obj -> exit_code < 0) return JS_ThrowTypeError(ctx, "Process is not running");

    struct winsize size;
    if(ioctl(obj->pty_fd, TIOCGWINSZ, &size) == -1){
        return JS_FALSE;
    }
    return JS_NewArrayFrom(ctx, 2, (JSValueConst[]){JS_NewInt32(ctx, size.ws_row), JS_NewInt32(ctx, size.ws_col)});
}

static JSValue js_process_get_title(JSContext *ctx, JSValueConst this_val){
    struct process_class *obj = JS_GetOpaque2(ctx, this_val, js_process_class_id);
    if(obj == NULL) return JS_EXCEPTION;
    if(obj -> exit_code < 0) return JS_ThrowTypeError(ctx, "Process is not running");

    char title[1024];
    if(ioctl(obj->pty_fd, TIOCGWINSZ, title) == -1){
        return JS_FALSE;
    }
    return JS_NewString(ctx, title);
}

static void js_process_finalizer(JSRuntime* rt, JSValue val){
    struct process_class *obj = JS_GetOpaque(val, js_process_class_id);
    if(obj == NULL) return;
    if(obj -> exit_code < 0){
        close(obj->pty_fd);
    }
    free(obj);
}

static JSValue pipe_close_cb(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic, JSValue *func_data){
    struct process_class *obj = JS_VALUE_GET_PTR(func_data[0]);
    if(obj == NULL) return JS_UNDEFINED;
    
    // waitpid获取退出状态
    int status;
    pid_t pid = waitpid(obj->pid, &status, 0);
    if(pid == -1){
        perror("waitpid");
        obj -> exit_code = 255;
        return JS_UNDEFINED;
    }
    if(WIFEXITED(status)){
        obj->exit_code = WEXITSTATUS(status);
    }else if(WIFSIGNALED(status)){
        obj->exit_code = -WTERMSIG(status);
    }else{
        obj->exit_code = -1;
    }

    return JS_UNDEFINED;
}

static inline JSValue create_pipe(JSContext* ctx, struct process_class* obj){
    JSValue cbarr[1] = { JS_MKPTR(JS_TAG_OBJECT, obj) };
    JSValue callback = JS_NewCFunctionData(ctx, pipe_close_cb, 0, 0, 1, cbarr);
    JSValue pipe = LJS_NewFDPipe(ctx, obj->pty_fd, PIPE_READ | PIPE_WRITE, PIPE_BUF, callback);

    return pipe;
}

static JSValue js_process_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    JSValue proto, class_obj;
    struct process_class *obj = malloc(sizeof(struct process_class));
    
    if (JS_IsUndefined(new_target)) {
        proto = JS_GetClassProto(ctx, js_process_class_id);
    } else {
        proto = JS_GetPropertyStr(ctx, new_target, "prototype");
        if (JS_IsException(proto))
            goto fail;
    }

    class_obj = JS_NewObjectProtoClass(ctx, proto, js_process_class_id);
    if (JS_IsException(class_obj))
        goto fail;

    // 转换args
    if(argc < 1){
        goto fail;
    }
    JSValue args = argv[0];
    int64_t len;
    if(!JS_IsArray(args) || !JS_GetLength(ctx, args, &len) || len < 1){
        goto fail;
    }
    char** _argv = malloc(len * sizeof(char*));
    for(int i = 0; i < len; i++){
        JSValue val = JS_GetPropertyUint32(ctx, args, i);
        if(JS_IsException(val)){
            goto fail;
        }
        const char* str = JS_ToCString(ctx, val);
        _argv[i] = malloc(strlen(str) + 1);
        strcpy(_argv[i], str);
        JS_FreeCString(ctx, str);
        JS_FreeValue(ctx, val);
    }

    // 参数2: env, inheritPipe, cwd
    JSValue opts;
    if(argc > 1){
        opts = argv[1];
    }

    // 创建pty
    int master_fd, slave_fd;
    if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL) == -1) {
        goto fail;
    }

    // 创建进程
    pid_t pid = fork();
    if (pid == -1) {
        JS_ThrowInternalError(ctx, "Failed to create process");
        goto fail;
    } else if (pid == 0) {
        // 子进程
        close(master_fd);
        if(!JS_IsEqual(ctx, JS_GetPropertyStr(ctx, opts, "inheritPipe"), JS_TRUE)){
            // 将子进程的终端设置为从设备
            setsid();
            ioctl(slave_fd, TIOCSCTTY, NULL);
            dup2(slave_fd, 0);
            dup2(slave_fd, 1);
            dup2(slave_fd, 2);
        }
        
        close(slave_fd);

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
    } else {
        // 父进程
        close(slave_fd);
        obj->pid = pid;
        obj->exit_code = -1;
        obj->pty_fd= master_fd;

    }

    JS_SetPropertyStr(ctx, class_obj, "pipe", create_pipe(ctx, obj));
    JS_SetOpaque(new_target, obj);
    JS_FreeValue(ctx, proto);
    return class_obj;

fail:
    js_free(ctx, obj);
    JS_FreeValue(ctx, proto);
    JS_FreeValue(ctx, class_obj);
    return JS_EXCEPTION;
}

static const JSCFunctionListEntry js_process_proto_funcs[] = {
    JS_CFUNC_DEF("kill", 1, js_process_kill),
    JS_CGETSET_DEF("code", js_process_get_return_code, NULL),
    JS_CGETSET_DEF("alive", js_process_isrunning, NULL),
    JS_CGETSET_DEF("size", js_process_get_termsize, js_process_set_termsize),
    JS_CGETSET_DEF("title", js_process_get_title, NULL),
};

static const JSClassDef js_process_class = {
    "Process",
    .finalizer = js_process_finalizer
};

static int js_process_init(JSContext* ctx, JSModuleDef* m){
    JS_SetModuleExport(ctx, m, "self", js_get_self(ctx));
    JS_SetModuleExport(ctx, m, "exit", JS_NewCFunction(ctx, js_exit, "exit", 1));

    // class Process
    JSValue process = JS_NewCFunction2(ctx, js_process_constructor, "Process", 1, JS_CFUNC_constructor, 0);
    JSValue proc_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proc_proto, js_process_proto_funcs, countof(js_process_proto_funcs));
    JS_SetClassProto(ctx, js_process_class_id, proc_proto);
    JS_SetConstructor(ctx, process, process);

    JS_SetModuleExport(ctx, m, "Process", process);

    return 0;
}

bool LJS_init_process(JSContext* ctx,
    char* _entry, uint32_t _argc, char** _argv
){
    const char* base = ((App*)JS_GetContextOpaque(ctx)) -> script_path;
    entry = LJS_resolve_path(_entry, base);
    argc = _argc;

    // parse argv
    argv = malloc(sizeof(JSValue) * _argc);
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

    // preconfigure ReactiveEnviron
    js_re_class_def.exotic = malloc(sizeof(JSClassExoticMethods));
    js_re_class_def.exotic->get_own_property = js_re_get_prop_exists;
    js_re_class_def.exotic->get_own_property_names = js_re_get_prop_names;
    js_re_class_def.exotic->define_own_property = js_re_set_own_prop;
    js_re_class_def.exotic->delete_property = js_re_del_prop;
    js_re_class_def.exotic->set_property = js_re_set_prop;
    js_re_class_def.exotic->get_property = NULL;
    js_re_class_def.exotic->has_property = NULL;

    // class ReactiveEnviron
    JS_NewClassID(rt, &js_reactive_environ_class_id);
    JS_NewClass(rt, js_reactive_environ_class_id, &js_re_class_def);

    JS_AddModuleExport(ctx, m, "Process");
    JS_AddModuleExport(ctx, m, "exit");

    return true;
}