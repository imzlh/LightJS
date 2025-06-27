/**
 * LightJS - A lightweight JavaScript engine
 */

#include "src/core.h"
#include "engine/quickjs.h"
#include "src/polyfill.h"

#include "src/repl.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <threads.h>

static JSRuntime *runtime;
static App* app;
bool exiting = false;
static int exit_code = 0;

static inline void run_jobs(){
    int jobs = 0;

    do{
        jobs = js_run_promise_jobs();  // thread-local jobs

        int res = 1;
        JSRuntime* rt = JS_GetRuntime(app -> ctx);
        JSContext* ectx;
        while(res){
            res = JS_ExecutePendingJob(rt, &ectx);
            if(res < 0){    // error
                JSValue exception = JS_GetException(ectx);
                if(unlikely(JS_IsInternalError(app -> ctx, exception))){
                    exiting = true;
                }else{
                    js_dump(ectx, exception, stderr);
                }
                JS_FreeValue(ectx, exception);
            } else if(res > 0) {
                jobs++;
            }
        }
#ifdef LJS_DEBUG
        printf("run jobs: %d\n", jobs);
#endif
    }while(jobs);
}

static bool check_promise_resolved(void* opaque){
    bool ret = false;

    // check if global promise is resolved
    JSValue* prom = (JSValue*)opaque;
    JSPromiseStateEnum state = JS_PromiseState(app -> ctx, *prom);
    if(state == JS_PROMISE_FULFILLED){
        run_jobs();
        if(!JS_IsJobPending(JS_GetRuntime(app -> ctx)))
            goto ret_true;
    }else if(state == JS_PROMISE_REJECTED){
        JSValue result = JS_PromiseResult(app -> ctx, *prom);
        if(unlikely(JS_IsInternalError(app -> ctx, result))){
            JSValue ecode = JS_GetProperty(app -> ctx, result, JS_ATOM__ret_);
            JS_ToInt32(app -> ctx, &exit_code, ecode);
            JS_FreeValue(app -> ctx, ecode);
            exiting = true;
        }else{
            js_dump(app -> ctx, result, stderr);
            JS_FreeValue(app -> ctx, result);
        }
        goto ret_true;
    }else{  // TIMING
        run_jobs();
        goto finalize;
    }

ret_true:
    ret = true;
finalize:
    if(exiting) evcore_destroy();
    return ret;
}

static size_t parse_limit(const char *arg) {
    char *p;
    unsigned long unit = 1024; /* default to traditional KB */
    double d = strtod(arg, &p);

    if (p == arg) {
        fprintf(stderr, "Invalid limit: %s\n", arg);
        return -1;
    }

    if (*p) {
        switch (*p++) {
        case 'b': case 'B': unit = 1UL <<  0; break;
        case 'k': case 'K': unit = 1UL << 10; break; /* IEC kibibytes */
        case 'm': case 'M': unit = 1UL << 20; break; /* IEC mebibytes */
        case 'g': case 'G': unit = 1UL << 30; break; /* IEC gigibytes */
        default:
            fprintf(stderr, "Invalid limit: %s, unrecognized suffix, only k,m,g are allowed\n", arg);
            return -1;
        }
        if (*p) {
            fprintf(stderr, "Invalid limit: %s, only one suffix allowed\n", arg);
            return -1;
        }
    }

    return (size_t)(d * unit);
}

// signal listener
static void exit_signal_handler(int sig) {
#ifdef LJS_DEBUG
    printf("Received signal %d, exiting...\n", sig);
#endif

    // kill all threads
    exiting = true;
}

__attribute__((constructor)) void init_signal_handler() {
    struct sigaction sa = {
        .sa_handler = exit_signal_handler,
        .sa_flags = SA_RESETHAND
    };
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
}

extern void __js_dump_not_resolved_promises();

int main(int argc, char **argv) {

    int optind = 1;
    bool eval_code = false;
    bool repl = false;
    bool check = false;

    runtime = JS_NewRuntime();

    while (optind < argc && *argv[optind] == '-') {
        char *arg = argv[optind] + 1;
        const char *longopt = "";
        char *opt_arg = NULL;
        if (!*arg)
            break;
        optind++;
        if (*arg == '-') {
            longopt = arg + 1;
            opt_arg = strchr(longopt, '=');
            if (opt_arg)
                *opt_arg++ = '\0';
            arg += strlen(arg);
            /* -- stops argument scanning */
            if (!*longopt)
                break;
        }
        for (; *arg || *longopt; longopt = "") {
            char opt = *arg;
            if (opt) {
                arg++;
                if (!opt_arg && *arg)
                    opt_arg = arg;
            }
            
            if (strcmp(longopt, "help") == 0 || opt == 'h') {
                printf(
                    "LightJS %s - A lightweight JavaScript engine\n"
                    "Copyright (c) 2025-present iz (https://github.com/imzlh/LightJS)\n"
                    "Usage: \n"
                    "    lightjs [options] [script] [args to script]\n"
                    "Options:\n"
                    "    -h, --help         Print this help message\n"
                    "    -v, --version      Print the version number\n"
                    "    -e, --eval         Evaluate the follow argument as JavaScript code\n"
                    "    -c, --check        Check syntax only (no execution)\n"
                    "    -r, --repl         Start a read-eval-print loop\n"
                    "        --stack-size   Set the stack size in bytes\n"
                    "        --memory-limit Set the memory limit in bytes\n"
                    "\n",
                    LJS_VERSION
                );
                return 0;
            }else if(strcmp(longopt, "version") == 0 || opt == 'v'){
                printf("LightJS %s with QuickJS-ng %s\n", LJS_VERSION, JS_GetVersion());
                printf("Built on %s, by "
#ifdef __GNUC__
                    "gcc " TOSTRING(__GNUC__) "." TOSTRING(__GNUC_MINOR__) "." TOSTRING(__GNUC_PATCHLEVEL__) 
#elif defined(__clang__)
                    "clang " TOSTRING(__clang_major__) "." TOSTRING(__clang_minor__) "." TOSTRING(__clang_patchlevel__) 
#else
                    "unknown compiler"
#endif

#ifdef __WIN32__
                    " (Windows)"
#else
                    " (POSIX)"
#endif

#ifdef __x86_64__
                    " (x86_64)"
#elif defined(__i386__)
                    " (i386)"
#elif defined(__aarch64__)
                    " (aarch64)"
#elif defined(__arm__)
                    " (arm)"
#else
                    " (unknown)"
#endif

                    "\n" , __DATE__);
                return 0;
            }else if(strcmp(longopt, "eval") == 0 || opt == 'e'){
                eval_code = true;
            }else if(strcmp(longopt, "check") == 0 || opt == 'c'){
                check = true;
            }else if(strcmp(longopt, "repl") == 0 || opt == 'r'){
                repl = true;
            }else if(strcmp(longopt, "stack-size") == 0){
                if(opt_arg){
                    JS_SetMaxStackSize(runtime, atoi(opt_arg));
                }else{
                    printf("Error: Missing argument for --stack-size\n");
                    return 1;
                }
            }else if(strcmp(longopt, "memory-limit") == 0){
                if(opt_arg){
                    JS_SetMemoryLimit(runtime, parse_limit(opt_arg));
                }else{
                    printf("Error: Missing argument for --memory-limit\n");
                    return 1;
                }
            }else{
                printf("Error: Unknown option: %s(%s)\n", opt ? &opt : "-", longopt ? longopt : "[unknown]");
                return 1;
            }
        }
    }

    if(eval_code && optind == argc){
        printf("Error: Missing argument for -e/--eval\n");
        return 1;
    }

    // rt init
    LJS_init_runtime(runtime);
#ifdef LJS_DEBUG
    JS_SetDumpFlags(runtime, JS_DUMP_LEAKS | JS_DUMP_PROMISE | JS_DUMP_OBJECTS | JS_DUMP_SHAPES);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
#endif

    // app init
    char* script_path;
    const char* raw_name;
    if(eval_code){
        raw_name = script_path = "<eval>";
    }else if(optind < argc){
        script_path = js_resolve_module(NULL, raw_name = argv[optind]);
        if(!script_path){
            printf("Failed to resolve module: %s\n", argv[optind]);
            return 1;
        }
    }else {
        script_path = strdup(raw_name = get_current_dir_name());
        repl = true;
    }
    
    app = LJS_create_app(runtime, 
        argc == optind ? 0 : argc - optind -1, argc == optind ? NULL : argv + optind +1, 
        false, true, script_path, NULL
    );
    if(!app){
        printf("Failed to create app.\nMake sure you have enough memory.\n");
        return 1;
    }
    LJS_init_context(app);
    evcore_init();  // epoll init

    if(argc - optind == 0 || repl){
        printf("LightJS %s with QuickJS-NG %s\n", LJS_VERSION, JS_GetVersion());
        printf("Type \".help\" for usage. for more information, please access github wiki.\n");

        JSValue buf = JS_ReadObject(app -> ctx, code_repl, sizeof(code_repl), JS_READ_OBJ_BYTECODE);
        JSValue val = JS_EvalFunction(app -> ctx, buf);
        if(JS_IsException(val)) js_dump(app -> ctx, JS_GetException(app -> ctx), stderr);

        goto run_evloop;
    }

    uint32_t buf_len;
    uint8_t* buf;
    if(eval_code){
        // measure eval code size
        buf_len = 0;
        for(int i = optind; i < argc; i++){
            if(argv[i]) buf_len += strlen(argv[i]) +1;
        }
        buf = malloc(buf_len +1);
        if(!buf){
            printf("Failed to allocate memory for eval code.\n");
            return 1;
        }
        uint32_t wsize = 0;
        for(int i = optind; i < argc; i++){
            size_t len = strlen(argv[i]);
            memcpy(buf + wsize, argv[i], len);
            buf[wsize + len] = ' ';
            wsize += len + 1;
        }
        buf[wsize - 1] = '\n';
        buf[wsize] = '\0';
    }else{
        buf = LJS_tryGetJSFile(&buf_len, &app -> script_path);
        if(!buf){
            printf("Failed to load script file: %s\n", app -> script_path);
            return 1;
        }
    }

    if(check){
        JSValue ret_val = JS_Eval(app -> ctx, (char*)buf, buf_len, app -> script_path, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        free(buf);
        if(JS_IsException(ret_val)){
            js_dump(app -> ctx, JS_GetException(app -> ctx), stderr);
            printf("The script has syntax errors.\n");
            return 1;
        }else{
            printf("The script has no syntax errors.\n");
            return 0;
        }
    }

    // parse
    JSValue code = JS_Eval(app -> ctx, (char*)buf, buf_len, app -> script_path, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    JSValue ret_val = JS_UNDEFINED;
    free(buf);
    if(JS_IsException(code)){
print_error:
        JSValue exception = JS_GetException(app -> ctx);
        js_dump(app -> ctx, exception, stderr);
        JS_FreeValue(app -> ctx, exception);
        exit_code = 1;
        goto finalize;
    }
    js_set_import_meta(app -> ctx, code, raw_name, true);

    // eval
    ret_val = JS_EvalFunction(app -> ctx, code);
    if(JS_IsException(ret_val)){
        goto print_error;
    }

    // start!
run_evloop:
    evcore_run(check_promise_resolved, &ret_val);
    // LJS_destroy_app(app); // destroy app will cause SEGFAULT as <argv> is not able to free.

    // dispatch exit event
finalize:
    js_dispatch_global_event(app -> ctx, "exit", JS_UNDEFINED);
    evcore_destroy();
    run_jobs();
    JS_FreeValue(app -> ctx, ret_val);
    JS_RunGC(runtime);
    __js_dump_not_resolved_promises();
    
    LJS_destroy_app(app);
    JS_FreeRuntime(runtime);
    if(!eval_code) free(script_path);
    if(exit_code < 0) exit_code = 0;
    return exit_code;
}