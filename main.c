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
            // ---
        }
    }

    if(argc - optind == 0){
        // todo: repl mode
        return 0;
    }

    char* script_path = argv[optind];
    runtime = JS_NewRuntime();

    // rt init
    LJS_init_runtime(runtime);

    // app init
    app = LJS_create_app(runtime, argc - optind -1, argv + optind +1, false, true, strdup(script_path), NULL);
    LJS_init_context(app, NULL);
    LJS_evcore_init();  // epoll init

    uint32_t buf_len;
    uint8_t* buf = LJS_tryGetJSFile(&buf_len, &app -> script_path);
    if(!buf){
        printf("Failed to load script file: %s\n", app -> script_path);
        return 1;
    }
    JSValue func = JS_Eval(app -> ctx, (char*)buf, buf_len, app -> script_path, JS_EVAL_TYPE_MODULE);
    if(JS_IsException(func)){
        LJS_dump_error(app -> ctx, JS_GetException(app -> ctx));
        return 1;
    }
    JS_FreeValue(app -> ctx, func);

    // start!
    if(check_promise_resolved(&func)) return 0;
    LJS_evcore_run(check_promise_resolved, &func);
    // LJS_evcore_run(NULL, NULL);
    return 0;
}