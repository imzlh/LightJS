#include "core.h"
#include "polyfill.h"
#include "../engine/quickjs.h"
#include "../engine/cutils.h"
#include "../engine/quickjs-atom.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <threads.h>
#include <assert.h>

#define MAX_DEPTH 64
#define MAX_OUTPUT_LEN 1024
#define MAX_OBJECT_PROP_LEN 20
#define MAX_OBJEXT_INLINE_PROP_LEN 5

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

static const char* getClassName(JSContext *ctx, JSValue prototype) {
    JSValue constructor, name;

    constructor = JS_GetProperty(ctx, prototype, JS_ATOM_constructor);
    if (JS_IsException(constructor))
        return NULL;
    name = JS_GetProperty(ctx, constructor, JS_ATOM_name);
    if (JS_IsException(name))
        return NULL;

    JS_FreeValue(ctx, constructor);
    JS_FreeValue(ctx, name);
    return JS_ToCString(ctx, name);
}

#define PRINT_INDENT(depth) fputs(getBlank(depth), target_fd)

#define BLANK_64 "                                                                "
static const char* blank = BLANK_64 BLANK_64 BLANK_64 BLANK_64; // max depth 64
static size_t blank_len = 64;

static inline const char* getBlank(int depth) {
    assert(depth <= blank_len);
    size_t offset = (blank_len - depth) * 4;
    return blank + offset;
}

static thread_local JSValue global_object[2];

// forward declaration
void print_jsvalue(JSContext *ctx, JSValueConst val, int depth, JSValue visited[], FILE* target_fd) ;

static inline bool check_circular(JSContext *ctx, JSValue val, JSValue visited[], int depth) {
    if(depth == 64) return true; // max depth
    for(int i = 0; i < depth; i++){
        if(JS_IsSameValue(ctx, val, visited[i])) return true;
    }
    return false;
}

// measure whether to wrap display into multiple lines
// useful for Array and Object with many properties
static bool measure_wrap_display(JSContext *ctx, JSValue val, JSValue visited[MAX_OBJEXT_INLINE_PROP_LEN], int depth) {
#define MEASURE_SUBELEMENT(el) JSValue value = el; \
    if(measure_wrap_display(ctx, value, visited, depth + 1)){ \
        JS_FreeValue(ctx, value); \
        return true; \
    }\
    JS_FreeValue(ctx, value);

    // Too deep?
    if(depth == MAX_OBJEXT_INLINE_PROP_LEN) return true;

    // check circular reference
    if(check_circular(ctx, val, visited, depth)) return false;

    // add to visited
    visited[depth] = val;

    int64_t plen;
    if(JS_IsProxy(val) || JS_IsError(ctx, val)) return false;
    if(JS_GetEnumerableLength(ctx, val, &plen) != -1){
        if(plen > MAX_OBJEXT_INLINE_PROP_LEN) return false;
        for(int64_t i = 0; i < plen; i++){
            MEASURE_SUBELEMENT(JS_GetPropertyUint32(ctx, val, i));
        }
    }else if(JS_IsObject(val)){
        // some special objects
        if(JS_IsWeakMap(val) || JS_IsWeakSet(val)) return false;
        // weakref?
        if(JS_IsWeakRef(val)){
            MEASURE_SUBELEMENT(JS_GetWeakRefValue(ctx, val));
            return false;
        }

        // NULL and many special objects
        if(JS_IsNull(val) || JS_IsSymbol(val) || JS_IsRegExp(val) || JS_IsFunction(ctx, val) || JS_IsDate(val))
            return false;
        if(JS_IsPromise(val)){
            MEASURE_SUBELEMENT(JS_PromiseResult(ctx, val));
            return false;
        }

        // display prototype?
        JSValue prototype = JS_GetProperty(ctx, val, JS_ATOM_prototype);
        if(!JS_IsException(prototype) ) return true;

        JSPropertyEnum *props;
        uint32_t prop_count;
        if(-1 == JS_GetOwnPropertyNames(ctx, &props, &prop_count, val, JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK | JS_GPN_PRIVATE_MASK)) return false;
        if(prop_count > MAX_OBJEXT_INLINE_PROP_LEN){
            JS_FreePropertyEnum(ctx, props, prop_count);
            return true;
        }
        for(uint32_t i = 0; i < prop_count; i++){
            JSAtom atom = props[i].atom;
            JSValue prop = JS_GetProperty(ctx, val, atom);
            if(measure_wrap_display(ctx, prop, visited, depth + 1)){
                JS_FreeValue(ctx, prop);
                JS_FreePropertyEnum(ctx, props, prop_count);
                return true;
            }
            JS_FreeValue(ctx, prop);
        }
        JS_FreePropertyEnum(ctx, props, prop_count);
    }
    return false;
}

static inline bool measure_wrap_disp2(JSContext *ctx, JSValue val){
    JSValue visited[MAX_OBJEXT_INLINE_PROP_LEN];
    return measure_wrap_display(ctx, val, visited, 0);
}

static void print_jserror(JSContext* ctx, JSValue val, int depth, FILE* target_fd) {
    const char* indent = getBlank(depth) + 2;

    JSValue name = JS_GetProperty(ctx, val, JS_ATOM_name);
    JSValue message = JS_GetProperty(ctx, val, JS_ATOM_message);
    JSValue help = JS_GetPropertyStr(ctx, val, "help");
    JSValue stack = JS_GetProperty(ctx, val, JS_ATOM_stack);
    const char* name_str = JS_ToCString(ctx, name);
    const char* message_str = LJS_ToCString(ctx, message, NULL);
    const char* js_stack_str = LJS_ToCString(ctx, stack, NULL);

    if (JS_IsString(help)) {
        const char* help_str = JS_ToCString(ctx, help);
        fprintf(target_fd,
            ANSI_RED "%s" ANSI_RESET ": %s\n" \
            ANSI_GREEN " help: " ANSI_RESET "%s\n",
            name_str, message_str, help_str);
        JS_FreeCString(ctx, help_str);
    } else {
        fprintf(target_fd, ANSI_RED "%s" ANSI_RESET ": %s\n", name_str, message_str);
    }

    // print stack
    if (js_stack_str) {
        char* stack_str_raw = js_stack_str ? strdup(js_stack_str) : NULL;
        char* stack_str = stack_str_raw;
        char* wrap_pos = strchr(stack_str, '\n');
        while (wrap_pos != NULL) {
            *wrap_pos = '\0';
            fprintf(target_fd, "%s%s\n", indent, stack_str);
            stack_str = wrap_pos + 1;
            wrap_pos = strchr(stack_str, '\n');
        }
        fprintf(target_fd, "%s%s\n", indent, stack_str);
        free(stack_str_raw);
        JS_FreeCString(ctx, js_stack_str);
    }

    JS_FreeCString(ctx, name_str);
    JS_FreeCString(ctx, message_str);
    JS_FreeValue(ctx, name);
    JS_FreeValue(ctx, message);
    JS_FreeValue(ctx, stack);
    JS_FreeValue(ctx, help);
}

static void print_jspromise(JSContext* ctx, JSValue val, int depth, JSValue visited[], FILE* target_fd) {
    JSPromiseStateEnum state = JS_PromiseState(ctx, val);
    char* state_str = "unknown";
    switch (state) {
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
    fprintf(target_fd, ANSI_MAGENTA "Promise" ANSI_YELLOW "<%s>" ANSI_RESET, state_str);

    if (state != JS_PROMISE_PENDING) {
        JSValue res = JS_PromiseResult(ctx, val);
        print_jsvalue(ctx, res, depth + 1, visited, target_fd);
        JS_FreeValue(ctx, res);
    }
}

static void print_jsbuffer(JSContext* ctx, JSValue val, int depth, FILE* target_fd) {
    size_t psize;
    uint8_t* buf;
    if (JS_IsArrayBuffer(val)) {
        buf = JS_GetArrayBuffer(ctx, &psize, val);
        printf(ANSI_MAGENTA "ArrayBuffer(" ANSI_BLUE "%ld" ANSI_MAGENTA ") {" ANSI_RESET, psize);

        goto print_buffer;
    }

    if (JS_IsTypedArray(ctx, val)) {
        buf = JS_GetUint8Array(ctx, &psize, val);

        printf(ANSI_MAGENTA "TypedArray(" ANSI_BLUE "%ld" ANSI_MAGENTA ")" ANSI_RESET " {", psize);

    print_buffer:
        if (buf == NULL) {
            fputs(ANSI_RED "NULL" ANSI_RESET, target_fd);
            return;
        }
        const char* indent = getBlank(depth + 1);
        size_t iend = MIN(psize, 128);
        for (size_t i = 0; i < iend; i += 16) {
            printf("\n%s", indent);
            for (int j = 0; j < MIN(psize - i, 16); j++) {
                printf(ANSI_BLUE "%02x" ANSI_RESET, buf[i + j]);
                if(i + j != iend -1) fputs(", ", target_fd);
            }
        }

        printf("\n%s}", indent + 4);

        return;
    }
}

/**
 * 打印 JSValue 值
 */
void print_jsvalue(JSContext *ctx, JSValueConst val, int depth, JSValue visited[], FILE* target_fd) {
    if(depth == 64){        // max depth
        fputs(ANSI_RED "..." ANSI_RESET, target_fd);
        return;
    }

    // uninitialed?
    if (JS_VALUE_GET_TAG(val) == JS_TAG_UNINITIALIZED){
        fputs(ANSI_RED "[val: NULL]" ANSI_RESET, target_fd);
        return;
    }

    // weakref?
    if(JS_IsWeakRef(val)){
        JSValue value = JS_GetWeakRefValue(ctx, val);
        if(JS_IsUndefined(value)){
            fputs(ANSI_RED "WeakRef<destroyed>" ANSI_RESET, target_fd);
            return;
        }else{
            fputs(ANSI_MAGENTA "WeakRef" ANSI_RESET " -> ", target_fd);
            val = value;
            goto main;
        }
    }
    // weakset and weakmap is not enumerable
    if(JS_IsWeakSet(val) || JS_IsWeakMap(val)){
        fputs(JS_IsWeakMap(val) ? "WeakMap {}" : "WeakSet []", target_fd);
        return;
    }
    JS_DupValue(ctx, val); // 复制值，防止被修改

main:
    visited[depth] = val;   // record visited value

    if (JS_IsUndefined(val)) {
        fputs(ANSI_BLUE "undefined" ANSI_RESET, target_fd);
    } else if (JS_IsNull(val)) {
        fputs(ANSI_BLUE "null" ANSI_RESET, target_fd);
    } else if (JS_IsBool(val)) {
        fprintf(target_fd, ANSI_BOLD "%s" ANSI_RESET, JS_ToBool(ctx, val) ? "true" : "false");
    } else if (JS_IsNumber(val)) {
        double num;
        if(-1 == JS_ToFloat64(ctx, &num, val))
        fputs(ANSI_CYAN "NaN" ANSI_RESET, target_fd);
        else
            fprintf(target_fd, ANSI_CYAN "%g" ANSI_RESET, num);
    } else if (JS_IsBigInt(val)) {
        const char *str = JS_ToCString(ctx, val);
        if(str){
            fprintf(target_fd, ANSI_CYAN "%s" ANSI_RESET ANSI_GREEN "n" ANSI_RESET, str);
            JS_FreeCString(ctx, str);
        }else{
            fputs(ANSI_RED "BigInt" ANSI_RESET, target_fd);
        }
    } else if (JS_IsString(val)) {
        const char *str = JS_ToCString(ctx, val);
        if(str){
            if(depth == 0)
                fprintf(target_fd, "%s", str);
            else
                fprintf(target_fd, ANSI_GREEN "\"%s\"" ANSI_RESET, str);
            JS_FreeCString(ctx, str);
        }else{
            fputs(ANSI_RED "String" ANSI_RESET, target_fd);
        }
    } else if (JS_IsFunction(ctx, val)) {
        // constructor?
        JSValue name = JS_GetProperty(ctx, val, JS_ATOM_name);
        const char *name_str = LJS_ToCString(ctx, name, NULL);
        if(name_str){
            if (JS_IsConstructor(ctx, val)){
                fprintf(target_fd, ANSI_RED ANSI_ITALIC "f" ANSI_RESET ANSI_MAGENTA " class(" ANSI_RESET "%s" ANSI_MAGENTA ")" ANSI_RESET, name_str);
            } else {
                fprintf(target_fd, ANSI_RED ANSI_ITALIC "f" ANSI_RESET ANSI_MAGENTA " (" ANSI_RESET "%s" ANSI_MAGENTA ")" ANSI_RESET, name_str);
            }
            JS_FreeCString(ctx, name_str);
        }else{
            fputs(ANSI_RED "Function" ANSI_RESET, target_fd);
        }
        JS_FreeValue(ctx, name);
    } else if (JS_IsSymbol(val)) {
        JSAtom atom = JS_ValueToAtom(ctx, val);
        const char* str = JS_AtomToCString(ctx, atom);
        if(str){
            fprintf(target_fd, ANSI_MAGENTA "Symbol(" ANSI_RESET "%s" ANSI_MAGENTA ")" ANSI_RESET, str);
            JS_FreeCString(ctx, str);
        }else{
            fputs(ANSI_RED "Symbol" ANSI_RESET, target_fd);
        }
        JS_FreeAtom(ctx, atom);
    } else if (JS_IsArray(val) || JS_IsSet(val)) {
        int64_t length;
        if(-1 == JS_GetEnumerableLength(ctx, val, &length)){
                fputs(ANSI_RED "[]" ANSI_RESET, target_fd);
            goto end;
        }

        if(depth >= MAX_DEPTH || length > MAX_OBJECT_PROP_LEN){
            fprintf(target_fd, ANSI_RED "ArrayLike(%ld)" ANSI_RESET, length); // 保留格式化输出
            goto end;
        }

        // Circular check
        if(check_circular(ctx, val, visited, depth)) {
            fputs(ANSI_RED "[circular]" ANSI_RESET, target_fd);
            goto end;
        }
        
        fputs(ANSI_GREEN "[ " ANSI_RESET, target_fd);
        const char* indent = getBlank(depth + 1);
        bool wrap_display = measure_wrap_disp2(ctx, val);
        for (uint32_t i = 0; i < length; i++) {
            if(wrap_display)
                fprintf(target_fd, "\n%s", indent);
            if(i != 0) fprintf(target_fd, ", ");
            JSValue element = JS_GetPropertyUint32(ctx, val, i);
            print_jsvalue(ctx, element, depth + 1, visited, target_fd);
            JS_FreeValue(ctx, element);
        }
        if(length > 8) printf("\n%s", getBlank(depth +1));
        fputs(ANSI_GREEN " ]" ANSI_RESET, target_fd);

    end:
        visited[depth] = JS_NULL;
    } else if (JS_IsObject(val)) {
        // Error
        if(JS_IsError(ctx, val) && depth == 0){
            print_jserror(ctx, val, depth, target_fd);
            goto end;
        }

        // Promise
        if(JS_IsPromise(val)){
            print_jspromise(ctx, val, depth, visited, target_fd);
            goto end;
        }

        // TypedArray or ArrayBuffer
        if(JS_IsArrayBuffer(val) || JS_IsTypedArray(ctx, val)){
            print_jsbuffer(ctx, val, depth, target_fd);
            goto end;
        }

        // cached_object
        if(check_circular(ctx, val, visited, depth)){
            fprintf(target_fd, ANSI_RED "[circular]" ANSI_RESET);
            goto end;
        }

        // print class name
        JSClassID class_id = JS_GetClassID(val);
        if(JS_IsRegisteredClass(JS_GetRuntime(ctx), class_id)){
            const char* class_name = getClassName(ctx, val);
            if(NULL == class_name){
                fprintf(target_fd, ANSI_MAGENTA "Object(Unknown)" ANSI_RESET);
            }else{
                fprintf(target_fd, ANSI_MAGENTA "%s" ANSI_RESET, class_name);
                JS_FreeCString(ctx, class_name);
            }
        }

        // toString?
        JSValue tostr = JS_GetProperty(ctx, val, JS_ATOM_toString);
        if(JS_IsFunction(ctx, tostr)){
            JSValue proto_str = JS_Call(ctx, tostr, val, 0, NULL);
            if(JS_IsException(proto_str)){
                JS_ResetUncatchableError(ctx);
            }else{
                const char* proto_str_str = JS_ToCString(ctx, proto_str);
                if(proto_str_str){
                    if(memcmp("[object ", proto_str_str, 8) == 0){
                        JS_FreeCString(ctx, proto_str_str);
                        JS_FreeValue(ctx, proto_str);
                        JS_FreeValue(ctx, tostr);
                        goto obj_restart;
                    }
                    if(strlen(proto_str_str) > 100 || strchr(proto_str_str, '\n')){
                        fprintf(target_fd, "<<< \n%s\n<<<", proto_str_str);
                    }else{
                        fprintf(target_fd, "(" ANSI_GREEN " %s " ANSI_RESET ")", proto_str_str);
                    }
                    JS_FreeCString(ctx, proto_str_str);
                }else{
                    JS_FreeValue(ctx, proto_str);
                    JS_FreeValue(ctx, tostr);
                    goto obj_restart;
                }
            }
            JS_FreeValue(ctx, proto_str);
            JS_FreeValue(ctx, tostr);
            goto end1;
        }

obj_restart:
        bool wrap_display = measure_wrap_disp2(ctx, val);
        // 读取对象键名
        JSPropertyEnum *props;
        uint32_t len;
        if (-1 == JS_GetOwnPropertyNames(ctx, &props, &len, val, JS_GPN_STRING_MASK | JS_GPN_SYMBOL_MASK | JS_GPN_PRIVATE_MASK)) {
            fputs(ANSI_MAGENTA "Object()" ANSI_RESET, target_fd);
            goto end1;
        }
        
        fputs(ANSI_GREEN " { " ANSI_RESET, target_fd);
        const char* indent = getBlank(depth + 1);

        for (int i = 0; i < len; i++) {
            JSPropertyDescriptor desc;
            if (-1 == JS_GetOwnProperty(ctx, &desc, val, props[i].atom)) {
                continue;
            }
            
            if(wrap_display) {
                fprintf(target_fd, "\n%s", indent);
            }

            JSValue atom_val = JS_AtomToValue(ctx, props[i].atom);
            const char *key_str = JS_AtomToCString(ctx, props[i].atom);
            if(props[i].is_enumerable || !JS_IsSymbol(atom_val))
                fprintf(target_fd, ANSI_YELLOW "%s" ANSI_RESET ": ", key_str);
            else
                fprintf(target_fd, ANSI_RED "Symbol(" ANSI_RESET "%s" ANSI_RED ")" ANSI_RESET ": ", key_str);
            JS_FreeCString(ctx, key_str);
            JS_FreeValue(ctx, atom_val);

            if(desc.flags & JS_PROP_GETSET){
                if(!JS_IsUndefined(desc.setter)){
                    fprintf(target_fd, ANSI_GREEN "set " ANSI_RESET);
                    JS_FreeValue(ctx, desc.setter);
                }
                if(!JS_IsUndefined(desc.getter)){
                    fprintf(target_fd, ANSI_GREEN "get" ANSI_RESET);
                    JSValue getres = JS_Call(ctx, desc.getter, val, 0, NULL);

                    if(JS_IsException(getres)){
                        JS_ResetUncatchableError(ctx);
                    }else{
                        fprintf(target_fd, "() => ");
                        print_jsvalue(ctx, getres, depth + 1, visited, target_fd);
                        JS_FreeValue(ctx, getres);
                    }
                    JS_FreeValue(ctx, desc.getter);
                }
            }else{
                print_jsvalue(ctx, desc.value, depth + 1, visited, target_fd);
                JS_FreeValue(ctx, desc.value);
            }
            
            if ( i != len - 1 ) fprintf(target_fd, ", ");
            if ( i == MAX_OBJECT_PROP_LEN ){
                fprintf(target_fd, "\n%s...", indent);
                break;
            }
        }

        JSValue proto = JS_GetPrototype(ctx, val);
        // Not globalThis.Object and globalThis.Map
        if(!JS_IsUndefined(proto) && !JS_IsNull(proto) && !JS_IsException(proto)){
            for(int i = 0; i < countof(global_object); i++){
                if(JS_IsSameValue(ctx, proto, global_object[i])){
                    goto skip_proto;
                }
            }

            fprintf(target_fd, ",\n%s" ANSI_MAGENTA ANSI_BOLD "__proto__" ANSI_RESET ": ", indent);
            print_jsvalue(ctx, proto, depth + 1, visited, target_fd);
        }
        JS_FreeValue(ctx, proto);

skip_proto:
        if(wrap_display) {
            fprintf(target_fd, "\n%s", indent + 4);
        } else {
            fputs(" ", target_fd);
        }

        fputs(ANSI_GREEN "}" ANSI_RESET, target_fd);
        JS_FreePropertyEnum(ctx, props, len);

end1:
        visited[depth] = JS_NULL;
    } else {
        fprintf(target_fd, ANSI_RED "[value: %d]" ANSI_RESET, JS_VALUE_GET_TAG(val));
    }

    JS_FreeValue(ctx, val);
}

static inline void printval_internal(JSContext *ctx, int argc, JSValueConst *argv, FILE *target_fd) {
    static JSValue visited[64];
    bool wrap = false;
    for(int i = 0; i < argc; i++){
        if(measure_wrap_disp2(ctx, argv[i])){
            wrap = true;
            break;
        }
    }
    for(int i = 0; i < argc; i++){
        JSValue val = argv[i];    
        print_jsvalue(ctx, val, 0, visited, target_fd);
        if(JS_IsObject(val)) fputc(' ', target_fd);
        if(wrap) fputc('\n', target_fd);
        else fputc(' ', target_fd);
    }
    fputc('\n', target_fd);
}

void js_dump(JSContext *ctx, JSValueConst val, FILE* target_fd){
    static JSValue visited[64];
    print_jsvalue(ctx, val, 0, visited, target_fd);
}

// console.log 实现
static JSValue js_console_log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    printval_internal(ctx, argc, argv, stdout);
    return JS_UNDEFINED;
}

// console.error 实现
static JSValue js_console_error(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    fputs(ANSI_RED " error " ANSI_RESET, stderr);
    printval_internal(ctx, argc, argv, stderr);
    return JS_UNDEFINED;
}

// console.info 实现
static JSValue js_console_info(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    fputs(ANSI_BLUE " info " ANSI_RESET, stdout);
    printval_internal(ctx, argc, argv, stdout);
    return JS_UNDEFINED;
}

// console.debug 实现
static JSValue js_console_debug(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(getenv("DEBUG") == NULL){
        return JS_UNDEFINED;
    }
    
    printf(ANSI_WHITE " debug " ANSI_RESET);
    printval_internal(ctx, argc, argv, stdout);
    return JS_UNDEFINED;
}

// console.assert 实现
static JSValue js_console_assert(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc < 2){
        return LJS_Throw(ctx, "Assertion failed: at least 2 arguments required, but only %d present", 
                "console.assert(condition: any, ...)"
            , argc);
    }

    if (!JS_ToBool(ctx, argv[0])) {
        printf(ANSI_RED " assert " ANSI_RESET);
        printval_internal(ctx, argc - 1, argv + 1, stdout);
    }
    return JS_UNDEFINED;
}

// console.warn 实现
static JSValue js_console_warn(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    printf(ANSI_YELLOW " warn " ANSI_RESET);
    printval_internal(ctx, argc, argv, stdout);
    return JS_UNDEFINED;
}

// console.clear 实现
static JSValue js_console_clear(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    printf("\033[2J\033[1;1H");
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
};

// 初始化 console 模块
bool LJS_init_console(JSContext *ctx) {
    JSValue console = JS_NewObject(ctx);
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyFunctionList(ctx, console, console_funcs, countof(console_funcs));
    JS_DefinePropertyValueStr(ctx, global, "console", console, JS_PROP_C_W_E);
    JS_FreeValue(ctx, global);

    // cache global object that should hide its prototype chain
    JSValue go = JS_GetGlobalObject(ctx);
    global_object[0] = JS_GetProperty(ctx, go, JS_ATOM_Object);
    global_object[1] = JS_GetProperty(ctx, go, JS_ATOM_Map);
    JS_FreeValue(ctx, go);
    // Note: will never freed until ctx released
    for (int i = 0; i < countof(global_object); i++) {
        JS_FreeValue(ctx, global_object[i]);
    }
    return true;
}