/**
 * LightJS - A lightweight JavaScript engine
 */

#include "src/core.h"
#include "engine/quickjs.h"

#include <string.h>

static JSRuntime *runtime;
static App* app;

static bool check_promise_resolved(void* opaque){
    // check if promise is resolved
    int pending = JS_ExecutePendingJob(JS_GetRuntime(app -> ctx), &app -> ctx);
    if(pending == -1){
        LJS_dump_error(app -> ctx, JS_GetException(app -> ctx));
        return true;
    }else if(pending == 0){
        return true;
    }

    // check if global promise is resolved
    JSValue* prom = (JSValue*)opaque;
    JSPromiseStateEnum state = JS_PromiseState(app -> ctx, *prom);
    if(state == JS_PROMISE_FULFILLED){
        return true;
    }else if(state == JS_PROMISE_REJECTED){
        LJS_dump_error(app -> ctx, JS_PromiseResult(app -> ctx, *prom));
        return true;
    }

    return false;
}

int main(int argc, char **argv) {

    int optind = 1;
    bool eval_code = false;
    bool repl = false;
    bool check = false;
    bool compile = false;

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
                    "    -b, --compile      Compile scripts in given directory to \"<dirname>.jspack\"\n"
                    "    -r, --repl         Start a read-eval-print loop\n"
                    "        --stack-size   Set the stack size in bytes\n"
                    "        --memory-limit Set the memory limit in bytes\n"
                    "\n",
                    LJS_VERSION
                );
                exit(0);
            }else if(strcmp(longopt, "version") == 0 || opt == 'v'){
                printf("LightJS %s with QuickJS-ng %s\n", LJS_VERSION, JS_GetVersion());
                exit(0);
            }else if(strcmp(longopt, "eval") == 0 || opt == 'e'){
                eval_code = true;
            }else if(strcmp(longopt, "check") == 0 || opt == 'c'){
                check = true;
            }else if(strcmp(longopt, "compile") == 0 || opt == 'b'){
                compile = true;
            }else if(strcmp(longopt, "repl") == 0 || opt == 'r'){
                repl = true;
            }else if(strcmp(longopt, "stack-size") == 0){
                if(opt_arg){
                    opt_arg = argv[optind++];   // next argument
                    JS_SetMaxStackSize(runtime, atoi(opt_arg));
                }else{
                    printf("Error: Missing argument for --stack-size\n");
                    exit(1);
                }
            }else if(strcmp(longopt, "memory-limit") == 0){
                if(opt_arg){
                    opt_arg = argv[optind++];   // next argument
                    JS_SetMemoryLimit(runtime, atoi(opt_arg));
                }else{
                    printf("Error: Missing argument for --memory-limit\n");
                    exit(1);
                }
            }else{
                printf("Error: Unknown option: %s(%s)\n", opt ? &opt : "-", longopt ? longopt : "[unknown]");
                exit(1);
            }
        }
    }

    if(argc - optind == 0 || repl){
        if(check || compile){
            printf("Could not use --check or --compile when running in REPL mode.\n");
            printf("If you want to check syntax or compile, please provide script name\n");
            exit(1);
        }
        // todo: repl mode
        printf("LightJS %s with QuickJS-NG %s\n", LJS_VERSION, JS_GetVersion());
        printf("Type \".help\" for usage. for more information, please access github wiki.\n");
        exit(0);
    }

    char* script_path = argv[optind];

    // rt init
    LJS_init_runtime(runtime);

    // app init
    app = LJS_create_app(runtime, argc - optind -1, argv + optind +1, false, true, strdup(script_path), NULL);
    LJS_init_context(app, NULL);
    LJS_evcore_init();  // epoll init

    uint32_t buf_len;
    uint8_t* buf;
    if(eval_code){
        buf = (uint8_t*)script_path;
        buf_len = strlen(script_path);
        app -> script_path = "<eval>";
    }else{
        buf = LJS_tryGetJSFile(&buf_len, &app -> script_path);
        if(!buf){
            printf("Failed to load script file: %s\n", app -> script_path);
            return 1;
        }
    }

    if(check){
        JSValue ret_val = JS_Eval(app -> ctx, (char*)buf, buf_len, app -> script_path, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
        if(JS_IsException(ret_val)){
            LJS_dump_error(app -> ctx, JS_GetException(app -> ctx));
            printf("The script has syntax errors.\n");
            exit(1);
        }else{
            printf("The script has no syntax errors.\n");
            exit(0);
        }
    }
    
    if(compile){
        // -- to impl
        printf("Sorry, --compile option is not implemented yet.\n");
        exit(0);
    }

    // eval
    JSValue ret_val = JS_Eval(app -> ctx, (char*)buf, buf_len, app -> script_path, JS_EVAL_TYPE_MODULE);
    if(JS_IsException(ret_val)){
        LJS_dump_error(app -> ctx, JS_GetException(app -> ctx));
        return 1;
    }
    JS_FreeValue(app -> ctx, ret_val);

    // start!
    if(check_promise_resolved(&ret_val)) return 0;
    JS_DupValue(app -> ctx, ret_val);
    LJS_evcore_run(check_promise_resolved, &ret_val);
    // LJS_evcore_run(NULL, NULL);
    return 0;
}