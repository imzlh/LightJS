#include "core.h"
#include "../engine/quickjs.h"
#include "../engine/cutils.h"
#include "../engine/quickjs-atom.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <threads.h>
#include <assert.h>

#define MAX_DEPTH 8
#define MAX_OUTPUT_LEN 1024
#define MAX_OBJECT_PROP_LEN 20

// ANSI 颜色代码
#define ANSI_RESET   "\x1b[0m"
#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_BLUE    "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_WHITE   "\x1b[37m"
#define ANSI_BOLD    "\x1b[1m"
#define ANSI_UNDERLINE "\x1b[4m"
#define ANSI_ITALIC "\x1b[3m"

/**
 * 将字符串重复 n 次
 */
static inline char* str_repeat(char* c, int n) {
    char *s = malloc(n + 1);
    
    for (int i = 0; i < n; i++) {
        s[i] = *c;
    }

    s[n] = '\0';
    return s;
}

static JSValue getClassName(JSContext *ctx, JSValue prototype) {
    JSValue constructor, name;

    // 从原型中获取构造函数
    constructor = JS_GetPropertyStr(ctx, prototype, "constructor");
    JS_FreeValue(ctx, constructor);
    if (JS_IsException(constructor))
        return JS_UNDEFINED;

    // 从构造函数中获取name属性
    name = JS_GetPropertyStr(ctx, constructor, "name");
    if (JS_IsException(name))
        return JS_UNDEFINED;

    return name;
}

#define PRINT_INDENT(depth) char* indent = str_repeat(" ", depth *4); \
    fprintf(target_fd, "\n%s", indent); \
    free(indent);

/**
 * 打印 JSValue 值
 */
void LJS_print_value(JSContext *ctx, JSValueConst val, int depth, JSValue* visited[], FILE* target_fd) {
    JS_DupValue(ctx, val); // 复制值，防止被修改
    
    // 防止递归过深
    int free_visited = 0;
    if (NULL == visited) {
        visited = js_malloc(ctx, MAX_OUTPUT_LEN * sizeof(JSValue));
        if(!visited) return;
        free_visited = 1;
    }

    // uninitialed?
    if (JS_VALUE_GET_TAG(val) == JS_TAG_UNINITIALIZED){
        fprintf(target_fd, ANSI_RED "[val: NULL]" ANSI_RESET);
        return;
    }

    // global.Object 缓存
    static thread_local JSValue cached_object;
    if (JS_IsUndefined(cached_object)) {
        JSValue global_obj = JS_GetGlobalObject(ctx);
        cached_object = JS_GetProperty(ctx, global_obj, JS_ATOM_Object);
        JS_FreeValue(ctx, global_obj);
    }

    if (JS_IsUndefined(val)) {
        fprintf(target_fd, ANSI_BLUE "undefined" ANSI_RESET);
    } else if (JS_IsNull(val)) {
        fprintf(target_fd, ANSI_BLUE "null" ANSI_RESET);
    } else if (JS_IsBool(val)) {
        fprintf(target_fd, ANSI_BOLD "%s" ANSI_RESET, JS_ToBool(ctx, val) ? "true" : "false");
    } else if (JS_IsNumber(val)) {
        double num;
        if(0 != JS_ToFloat64(ctx, &num, val))
            fprintf(target_fd, ANSI_CYAN "NaN" ANSI_RESET);
        else
            fprintf(target_fd, ANSI_CYAN "%g" ANSI_RESET, num);
    } else if (JS_IsBigInt(ctx, val)) {
        const char *str = JS_ToCString(ctx, val);
        fprintf(target_fd, ANSI_CYAN "%s" ANSI_RESET ANSI_GREEN "n" ANSI_RESET, str);
        JS_FreeCString(ctx, str);
    } else if (JS_IsString(val)) {
        const char *str = JS_ToCString(ctx, val);
        if(depth == 0)
            fprintf(target_fd, ANSI_GREEN "%s" ANSI_RESET, str);
        else
            fprintf(target_fd, ANSI_GREEN "\"%s\"" ANSI_RESET, str);
        JS_FreeCString(ctx, str);
    } else if (JS_IsFunction(ctx, val)) {
        // constructor?
        JSValue name = JS_GetPropertyStr(ctx, val, "name");
        const char *name_str = JS_ToCString(ctx, name);
        if (JS_IsConstructor(ctx, val)){
            fprintf(target_fd, ANSI_RED ANSI_ITALIC "f" ANSI_RESET ANSI_MAGENTA " class(" ANSI_RESET "%s" ANSI_MAGENTA ")" ANSI_RESET, name_str);
        } else {
            fprintf(target_fd, ANSI_RED ANSI_ITALIC "f" ANSI_RESET ANSI_MAGENTA " (" ANSI_RESET "%s" ANSI_MAGENTA ")" ANSI_RESET, name_str);
        }
        JS_FreeCString(ctx, name_str);
        JS_FreeValue(ctx, name);
    } else if (JS_IsArray(val)) {
        if(depth >= MAX_DEPTH){
            fprintf(target_fd, ANSI_RED "Array()" ANSI_RESET);
            goto end;
        }

        // 检查是否已经访问过
        for (int i = 0; i < depth; i++) {
            if (JS_IsSameValue(ctx, val, *visited[i])) {
                fprintf(target_fd, ANSI_RED "[circular]" ANSI_RESET);
                goto end;
            }
        }

        // 将当前数组标记为已访问
        visited[depth] = &val;

        int length;
        JSValue length_val = JS_GetPropertyStr(ctx, val, "length");
        JS_ToInt32(ctx, &length, length_val);
        JS_FreeValue(ctx, length_val);
        
        if (length > MAX_OBJECT_PROP_LEN) {
            fprintf(target_fd, "Array(%d) ", length);
            goto end;
        }
        
        fprintf(target_fd, ANSI_GREEN "[" ANSI_RESET);
        char* indent = str_repeat(" ", (depth + 1) * 4);
        for (uint32_t i = 0; i < length; i++) {
            if (i > 0) {
                if(length > 8) fprintf(target_fd, ",\n%s", indent);
                else fprintf(target_fd, ", ");
            }else if(length > 8){
                fprintf(target_fd, "\n%s", indent);
            }
            JSValue element = JS_GetPropertyUint32(ctx, val, i);
            LJS_print_value(ctx, element, depth + 1, visited, target_fd);
            JS_FreeValue(ctx, element);
        }
        if(length > 8) printf("\n%s", str_repeat(" ", depth * 4));
        fprintf(target_fd, ANSI_GREEN "]" ANSI_RESET);
        free(indent);

    end:
        visited[depth] = NULL;
    } else if (JS_IsObject(val)) {
        // Error检查
        if(JS_IsError(ctx, val) && depth == 0){
            char* indent = str_repeat(" ", (depth) * 4 + 2);

            JSValue name = JS_GetPropertyStr(ctx, val, "name");
            JSValue message = JS_GetPropertyStr(ctx, val, "message");
            JSValue help = JS_GetPropertyStr(ctx, val, "help");
            JSValue stack = JS_GetPropertyStr(ctx, val, "stack");
            const char *name_str = JS_ToCString(ctx, name);
            const char *message_str = JS_ToCString(ctx, message);
            const char *js_stack_str = JS_ToCString(ctx, stack);
            char* stack_str = strdup(js_stack_str);
            char* stack_str_raw = stack_str;

            if(JS_IsString(help)){
                const char *help_str = JS_ToCString(ctx, help);
                fprintf(target_fd, 
                    ANSI_RED "%s" ANSI_RESET ": %s\n" \
                    ANSI_GREEN " help: " ANSI_RESET "%s\n",
                name_str, message_str, help_str);
                JS_FreeCString(ctx, help_str);
            }else{
                fprintf(target_fd, ANSI_RED "%s" ANSI_RESET ": %s\n" , name_str, message_str);
            }

            // print stack
            char* wrap_pos = strchr(stack_str, '\n');
            while(wrap_pos!= NULL){
                *wrap_pos = '\0';
                fprintf(target_fd, "%s%s\n", indent, stack_str);
                stack_str = wrap_pos + 1;
                wrap_pos = strchr(stack_str, '\n');
            }
            fprintf(target_fd, "%s%s\n", indent, stack_str);

            free(indent);
            JS_FreeCString(ctx, name_str);
            JS_FreeCString(ctx, message_str);
            JS_FreeCString(ctx, js_stack_str);
            free(stack_str_raw);
            JS_FreeValue(ctx, name);
            JS_FreeValue(ctx, message);
            JS_FreeValue(ctx, stack);
            JS_FreeValue(ctx, help);
            goto end;
        }

        // Promise检查
        if(JS_IsPromise(val)){
            JSPromiseStateEnum state = JS_PromiseState(ctx, val);
            char* state_str = "unknown";
            switch(state){
                case JS_PROMISE_PENDING:
                    state_str = "pending";
                    break;
                case JS_PROMISE_FULFILLED:
                    state_str = "fulfilled";
                    break;
                case JS_PROMISE_REJECTED:
                    state_str = "rejected";
                    break;
            }
            fprintf(target_fd, ANSI_MAGENTA "Promise(" ANSI_RESET ANSI_YELLOW "<%s>" ANSI_RESET ANSI_MAGENTA ")" ANSI_RESET, state_str);
            goto end;
        }

        // 检查是否为Object()，防止死循环
        if(depth >= MAX_DEPTH || JS_IsSameValue(ctx, val, cached_object)){
            fprintf(target_fd, ANSI_MAGENTA "Object()" ANSI_RESET);
            goto end;
        }

        // 检查是否已经访问过
        for (int i = 0; i < depth; i++) {
            if (JS_IsSameValue(ctx, val, *visited[i])) {
                fprintf(target_fd, ANSI_RED "[circular]" ANSI_RESET);
                goto end;
            }
        }

        // 将当前对象标记为已访问
        visited[depth] = &val;

        // prototype是class?
        JSValue proto = JS_GetPrototype(ctx, val);
        if(JS_IsObject(proto) && JS_IsRegisteredClass(JS_GetRuntime(ctx), JS_GetClassID(proto))){
            // 获取getter setter
            JSPropertyEnum* classprops;
            uint32_t len;
            if (-1 == JS_GetOwnPropertyNames(ctx, &classprops, &len, val, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY))
                goto obj_norm;

            char* indent = str_repeat(" ", (depth + 1) * 4);
            int vaild = 0;
            for (int i = 0; i < len; i++) {
                JSPropertyDescriptor desc;
                if (-1 != JS_GetOwnProperty(ctx, &desc, val, classprops[i].atom)) {
                    if (desc.flags & JS_PROP_GETSET) {
                        bool setter = JS_IsFunction(ctx, desc.getter);
                        bool getter = JS_IsFunction(ctx, desc.setter);
                        const char *key_str = JS_AtomToCString(ctx, classprops[i].atom);
                        if((setter || getter) && depth){    // indent
                            fprintf(target_fd, "\n%s", indent);
                        }
                        vaild ++;
                        if(getter){
                            const char *key_str = JS_AtomToCString(ctx, classprops[i].atom);
                            fprintf(target_fd, ANSI_BLUE "get " ANSI_YELLOW "%s" ANSI_RESET "()", key_str);

                            // try get
                            JSValue get_val = JS_Call(ctx, desc.getter, val, 0, NULL);
                            if(!JS_IsException(get_val)){
                                fprintf(target_fd, ":");
                                LJS_print_value(ctx, get_val, depth + 1, visited, target_fd);
                                JS_FreeValue(ctx, get_val);
                            }
                            JS_FreeCString(ctx, key_str);
                        }else if(setter){
                            printf(ANSI_BLUE "set " ANSI_YELLOW "%s" ANSI_RESET "()", key_str);
                        }
                    }
                }
            }

            free(indent);
            JS_FreePropertyEnum(ctx, classprops, len);
            if(vaild == 0) goto obj_norm;
        }

        // 检查是否为Class
        JSClassID class_id = JS_GetClassID(val);
        if(JS_IsRegisteredClass(JS_GetRuntime(ctx), class_id)){
            JSValue class_name = getClassName(ctx, val);
            const char *class_name_str = JS_ToCString(ctx, class_name);
            if(!class_name_str) fprintf(target_fd, ANSI_MAGENTA "Object(Unknown)" ANSI_RESET);
            else{
                if(strcmp(class_name_str, "Object") != 0)
                    fprintf(target_fd, ANSI_MAGENTA "%s" ANSI_RESET, class_name_str);
                JS_FreeCString(ctx, class_name_str);
            }
        }

        // 读取对象键名
obj_norm:
        JSPropertyEnum *props;
        uint32_t len;
        if (JS_GetOwnPropertyNames(ctx, &props, &len, val, JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY)) {
            fprintf(target_fd, ANSI_MAGENTA "Object()" ANSI_RESET);
            goto end1;
        }
        
        fprintf(target_fd, ANSI_GREEN " { " ANSI_RESET);
        char* indent = str_repeat(" ", (depth +1) * 4);

        for (int i = 0; i < len; i++) {
            if(len > 4) {
                fprintf(target_fd, "\n%s", indent);
            }

            JSValue key = JS_AtomToValue(ctx, props[i].atom);
            const char *key_str = JS_ToCString(ctx, key);
            fprintf(target_fd, ANSI_YELLOW "%s" ANSI_RESET ": ", key_str);
            JS_FreeCString(ctx, key_str);

            JSValue prop_val = JS_GetProperty(ctx, val, props[i].atom);
            if (JS_IsException(prop_val)) {
                fprintf(target_fd, ANSI_RED "[failed]" ANSI_RESET);
                continue;
            }
            LJS_print_value(ctx, prop_val, depth + 1, visited, target_fd);
            JS_FreeValue(ctx, prop_val);
            JS_FreeValue(ctx, key);
            
            if (i != len - 1) fprintf(target_fd, ", ");
            if ( i == MAX_OBJECT_PROP_LEN ){
                fprintf(target_fd, "\n%s...", indent);
                break;
            }
        }

        if(len > 4) {
            fprintf(target_fd, "\n%s", indent);
        } else {
            fprintf(target_fd, " ");
        }

        fprintf(target_fd, ANSI_GREEN "}" ANSI_RESET);
        JS_FreePropertyEnum(ctx, props, len);
        free(indent);

end1:
        visited[depth] = NULL;
    } else if (JS_IsSymbol(val)) {
        const char *str = JS_ToCString(ctx, val);
        fprintf(target_fd, ANSI_MAGENTA "Symbol(" ANSI_RESET "%s" ANSI_MAGENTA ")" ANSI_RESET, str);
        JS_FreeCString(ctx, str);
    } else {
        fprintf(target_fd, ANSI_RED "[value: %d]" ANSI_RESET, JS_VALUE_GET_TAG(val));
    }

    if (free_visited) {
        js_free(ctx, visited);
    }
    JS_FreeValue(ctx, val);
}

// console.log 实现
static JSValue js_console_log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    for (int i = 0; i < argc; i++) {
        LJS_print_value(ctx, argv[i], 0, NULL, stdout);
        printf(" ");
    }
    printf("\n");
    return JS_UNDEFINED;
}

// console.error 实现
static JSValue js_console_error(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    fprintf(stderr, ANSI_RED " error " ANSI_RESET);
    for (int i = 0; i < argc; i++) {
        LJS_print_value(ctx, argv[i], 0, NULL, stderr);
        fprintf(stderr, " ");
    }
    fprintf(stderr, "\n");
    return JS_UNDEFINED;
}

// console.info 实现
static JSValue js_console_info(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    printf(ANSI_BLUE " info " ANSI_RESET);
    js_console_log(ctx, this_val, argc, argv);
    return JS_UNDEFINED;
}

// console.debug 实现
static JSValue js_console_debug(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(getenv("DEBUG") == NULL){
        return JS_UNDEFINED;
    }
    
    printf(ANSI_WHITE " debug " ANSI_RESET);
    js_console_log(ctx, this_val, argc, argv);
    return JS_UNDEFINED;
}

// console.assert 实现
static JSValue js_console_assert(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (!JS_ToBool(ctx, argv[0])) {
        const char *msg = JS_ToCString(ctx, argv[1]);
        
        printf(ANSI_RED " assert " ANSI_RESET);
        for (int i = 0; i < argc; i++) {
            LJS_print_value(ctx, argv[i], 0, NULL, stdout);
            printf(" ");
        }
        printf("\n");

        JS_FreeCString(ctx, msg);
    }
    return JS_UNDEFINED;
}

// console.warn 实现
static JSValue js_console_warn(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    printf(ANSI_YELLOW " warn " ANSI_RESET);
    js_console_log(ctx, this_val, argc, argv);
    return JS_UNDEFINED;
}

// console.clear 实现
static JSValue js_console_clear(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    printf("\033[2J\033[1;1H");
    return JS_UNDEFINED;
}

thread_local static int count = 0;

// console.count 实现
static JSValue js_console_count(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    count++;
    printf(ANSI_YELLOW " count " ANSI_RESET " %d\n", count);
    return JS_UNDEFINED;
}

// console.countReset 实现
static JSValue js_console_countReset(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    count = 0;
    printf(ANSI_YELLOW " count " ANSI_RESET " %d\n", count);
    return JS_UNDEFINED;
}

// 全局计时器存储对象
thread_local static JSValue timers = JS_UNDEFINED;

// 获取当前时间（毫秒）
static double get_current_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000 + (double)tv.tv_usec / 1000;
}

// console.time 实现
static JSValue js_console_time(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "label must be a string");
    }

    // 初始化全局计时器对象
    if (JS_IsUndefined(timers)) {
        timers = JS_NewObject(ctx);
    }

    const char *label = JS_ToCString(ctx, argv[0]);
    double start_time = get_current_time();

    // 存储计时器
    JS_SetPropertyStr(ctx, timers, label, JS_NewFloat64(ctx, start_time));

    JS_FreeCString(ctx, label);
    return JS_UNDEFINED;
}

// console.timeEnd 实现
static JSValue js_console_timeEnd(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "label must be a string");
    }

    if (JS_IsUndefined(timers)) {
        return JS_ThrowTypeError(ctx, "no timers found");
    }

    const char *label = JS_ToCString(ctx, argv[0]);
    JSValue start_time_val = JS_GetPropertyStr(ctx, timers, label);

    if (JS_IsUndefined(start_time_val)) {
        JS_FreeCString(ctx, label);
        return JS_ThrowTypeError(ctx, "timer '%s' does not exist", label);
    }

    double start_time;
    JS_ToFloat64(ctx, &start_time, start_time_val);
    double end_time = get_current_time();
    double duration = end_time - start_time;

    // 输出时间差
    printf(ANSI_CYAN "%s: " ANSI_RESET "%.2fms\n", label, duration);

    // 删除计时器
    JSAtom atom_label = JS_NewAtom(ctx, label);
    JS_DeleteProperty(ctx, timers, atom_label, 0);

    JS_FreeCString(ctx, label);
    JS_FreeValue(ctx, start_time_val);
    return JS_UNDEFINED;
}

// console.timeLog 实现
static JSValue js_console_timeLog(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc < 1 || !JS_IsString(argv[0])) {
        return JS_ThrowTypeError(ctx, "label must be a string");
    }

    if (JS_IsUndefined(timers)) {
        return JS_ThrowTypeError(ctx, "no timers found");
    }

    const char *label = JS_ToCString(ctx, argv[0]);
    JSValue start_time_val = JS_GetPropertyStr(ctx, timers, label);

    if (JS_IsUndefined(start_time_val)) {
        JS_FreeCString(ctx, label);
        return JS_ThrowTypeError(ctx, "timer '%s' does not exist", label);
    }

    double start_time;
    JS_ToFloat64(ctx, &start_time, start_time_val);
    double current_time = get_current_time();
    double duration = current_time - start_time;

    // 输出时间差
    printf(ANSI_CYAN "%s: " ANSI_RESET "%.2fms", label, duration);

    // 输出额外的参数
    for (int i = 1; i < argc; i++) {
        printf(" ");
        LJS_print_value(ctx, argv[i], 0, NULL, stdout);
    }
    printf("\n");

    JS_FreeCString(ctx, label);
    JS_FreeValue(ctx, start_time_val);
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry console_funcs[] = {
    JS_CFUNC_DEF("log", 1, js_console_log),
    JS_CFUNC_DEF("error", 1, js_console_error),
    JS_CFUNC_DEF("info", 1, js_console_info),
    JS_CFUNC_DEF("debug", 1, js_console_debug),
    JS_CFUNC_DEF("assert", 2, js_console_assert),
    JS_CFUNC_DEF("warn", 1, js_console_warn),
    JS_CFUNC_DEF("clear", 0, js_console_clear),
    JS_CFUNC_DEF("count", 0, js_console_count),
    JS_CFUNC_DEF("countReset", 0, js_console_countReset),
    JS_CFUNC_DEF("time", 1, js_console_time),
    JS_CFUNC_DEF("timeEnd", 1, js_console_timeEnd),
    JS_CFUNC_DEF("timeLog", 1, js_console_timeLog),
};

// 初始化 console 模块
bool LJS_init_console(JSContext *ctx) {
    JSValue console = JS_NewObject(ctx);
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyFunctionList(ctx, console, console_funcs, countof(console_funcs));
    JS_DefinePropertyValueStr(ctx, global, "console", console, JS_PROP_C_W_E);
    return true;
}

// ------------ for C --------------
#define GET_STRING(ctx, val) JS_IsUndefined(val)? (const char*)0 : JS_ToCString(ctx, val)
void LJS_dump_error(JSContext *ctx, JSValueConst exception) {
    if(JS_IsError(ctx, exception)){
        JSValue stack = JS_GetPropertyStr(ctx, exception, "stack");
        JSValue name = JS_GetPropertyStr(ctx, exception, "name");
        JSValue message = JS_GetPropertyStr(ctx, exception, "message");
        JSValue help = JS_GetPropertyStr(ctx, exception, "help");
        const char *error_name = JS_ToCString(ctx, name);
        const char *error_message = JS_ToCString(ctx, message);
        const char *error_stack = GET_STRING(ctx, stack);
        const char *error_help = GET_STRING(ctx, help);
        if(error_name == NULL) error_name = "Error";
        if(error_message == NULL) error_message = "";
        fprintf(stderr, ANSI_RED "%s" ANSI_RESET ": %s\n", error_name, error_message);
        if(error_help) fprintf(stderr, ANSI_GREEN "help" ANSI_RESET ": %s\n", error_help);
        if(error_stack) fprintf(stderr, "%s\n", error_stack);
        JS_FreeCString(ctx, error_name);
        JS_FreeCString(ctx, error_message);
        if(error_stack) JS_FreeCString(ctx, error_stack);
        if(error_help) JS_FreeCString(ctx, error_help);
    } else {
        LJS_print_value(ctx, exception, 0, NULL, stderr);
        fprintf(stderr, "\n");
    }
}