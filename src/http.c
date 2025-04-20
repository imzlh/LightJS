#include "../engine/quickjs.h"
#include "../engine/cutils.h"
#include "../engine/list.h"
#include "core.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <threads.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define MAX_QUERY_COUNT 32
#define MAX_HEADER_COUNT 64
#define BUFFER_SIZE 1024

static char* normalize_path(const char* path) {
    char* copy = strdup(path);
    if (!copy) return NULL;

    char** parts = malloc(sizeof(char*) * PATH_MAX);
    if (!parts) {
        free(copy);
        return NULL;
    }
    
    int part_count = 0;
    char* saveptr;
    char* token = strtok_r(copy, "/", &saveptr);

    while (token) {
        if (strcmp(token, ".") == 0) {
            /* 忽略当前目录 */
        } else if (strcmp(token, "..") == 0) {
            /* 回退上级目录 */
            if (part_count > 0) part_count--;
        } else {
            parts[part_count++] = strdup(token);
        }
        token = strtok_r(NULL, "/", &saveptr);
    }

    /* 计算最终路径长度 */
    size_t total_len = 1; // 终止符
    int is_absolute = (path[0] == '/');
    if (is_absolute) total_len++;
    
    for (int i = 0; i < part_count; i++) {
        total_len += strlen(parts[i]) + 1;
    }
    
    if (part_count > 0) total_len--;

    /* 构建最终路径 */
    char* result = malloc(total_len);
    result[0] = '\0';
    
    if (is_absolute) strcat(result, "/");
    
    for (int i = 0; i < part_count; i++) {
        if (i > 0) strcat(result, "/");
        strcat(result, parts[i]);
        free(parts[i]);
    }
    
    free(parts);
    free(copy);
    return result;
}

/**
 * 解析路径，别忘了手动free
 * @param base 基础路径
 * @param path 待解析路径
 * @return 解析后的路径
 */
char* LJS_resolve_path(const char* path, const char* _base) {
    if (!path || !*path) return strdup(_base);
    
    /* 处理绝对路径 */
    if (path[0] == '/') return normalize_path(path);
    bool free_base = false;
    char* base = (char*)_base;
    if(!base) {
        base = getcwd(NULL, 0);
        free_base = true;
    }

    /* 拼接路径 */
    size_t base_len = strlen(base);
    size_t path_len = strlen(path);
    char* combined = malloc(base_len + path_len + 2);
    
    int needs_slash = !(base_len && base[base_len-1] == '/') && 
                     !(path_len && path[0] == '/');
    
    sprintf(combined, "%s%s%s", 
            base, 
            needs_slash ? "/" : "", 
            path);

    /* 标准化路径 */
    char* resolved = normalize_path(combined);
    free(combined);
    if(free_base) free(base);
    return resolved;
}

/**
 * 解析Query字符串
 * 严重警告：请确保query深拷贝，释放会导致空指针错误
 */
bool LJS_parse_query(char *query, URL_query_data *query_list[], int max_query_count){
    if(query == NULL || strlen(query) == 0){
        return false;
    }
    URL_query_data *query_obj = malloc(sizeof(URL_query_data));
    if(query_obj == NULL){
        return false;
    }
    for(uint32_t i = 0; i < max_query_count; i++){
        char *eq_pos = strchr(query, '='),
            *next_query = strchr(query, '&');
        if( // 只有key
            eq_pos == NULL || 
            (eq_pos != NULL && next_query != NULL && next_query < eq_pos) // 出现&前有=
        ){
            query_obj -> key = query;
        }else{  // 有value和key
            eq_pos[0] = '\0';
            query_obj -> key = query;
            query_obj -> value = eq_pos + 1;
        }
        query_list[i] = query_obj;

        // 处理下一个query
        if(next_query != NULL && next_query[1] != '\0'){
            query = next_query + 1;
        }else{
            break;
        }
    }
    return true;
}

static URL_data *default_url;

/**
 * 解析URL
 * 严重警告：请确保url深拷贝，释放会导致空指针错误
 */
bool LJS_parse_url(char *url, URL_data *url_struct, URL_data *base){
    if (strlen(url) <= 1){
        return false;
    }

    // 创建模板
    if(base == NULL){
        if(default_url == NULL){
            default_url = malloc(sizeof(URL_data));
            if(default_url == NULL){
                return false;
            }
        }
        base = default_url;
    }
    
    // 检查起始字符
    if(url[0] == '/'){
        if(url[1] == '/'){
            url_struct -> protocol = base -> protocol;
        }else{
            url_struct -> protocol = base -> protocol;
            url_struct -> host = base -> host;
            url_struct -> port = base -> port;
        }
    }else if(url[0] == '?'){
        url_struct -> protocol = base -> protocol;
        url_struct -> host = base -> host;
        url_struct -> port = base -> port;
        url_struct -> path = base -> path;
    }else if(url[0] == '#'){
        url_struct -> protocol = base -> protocol;
        url_struct -> host = base -> host;
        url_struct -> port = base -> port;
        url_struct -> path = base -> path;
        url_struct -> query = base -> query;

        url += 1;
        url_struct -> hash = url;
        return true;
    }

    if(!url_struct -> protocol){
        char* pos = strstr(url, "://");
        if(pos){
            pos[0] = '\0';
            url_struct -> protocol = url;
            url = pos + 3;
        }else{
            return false;
        }
    }

    if(!url_struct -> host){
        char *pos0 = strchr(url, '@'),
            *pos1 = strchr(url, ':'),
            *pos2 = strchr(url, '/');
        if(pos1 == NULL && pos2 == NULL){
            url_struct -> host = url;
            return true;
        }
        if(pos0 != NULL){
            if(
                (pos1 != NULL && pos0 > pos1) ||
                (pos2 != NULL && pos0 > pos2)
            ){
                return false;
            }
            *pos0 = '\0';
            
            // 继续找密码
            char *pw_pos = strchr(url, ':');
            if(pw_pos != NULL){
                *pw_pos = '\0';
                url_struct -> password = pw_pos + 1;
            }
            url_struct -> username = url;
            url = pos0 + 1;
        }

        // 没有端口
        if(pos1 == NULL){
            // 常见端口
            if(strcmp(url_struct -> protocol, "http") == 0){
                url_struct -> port = 80;
            } else if(strcmp(url_struct -> protocol, "https") == 0){
                url_struct -> port = 443;
            } else if(strcmp(url_struct -> protocol, "ftp") == 0){
                url_struct -> port = 21;
            } else if(strcmp(url_struct -> protocol, "ws") == 0){
                url_struct -> port = 80;
            } else if(strcmp(url_struct -> protocol, "wss") == 0){
                url_struct -> port = 443;
            } else {
                url_struct -> port = 0;
            }
            pos2[0] = '\0';
            url_struct -> host = url;
            url = pos2 + 1;
        }else{
            // 有端口
            *pos1 = '\0';
            url_struct -> port = atoi(pos1 + 1);
            pos2[0] = '\0';
            url_struct -> host = url;
            url = pos2 + 1;
        }
    }

    if(!url_struct -> path){
        // 找"?"和"#"
        char *pos1 = strchr(url, '?'),
            *pos2 = strchr(pos1 == NULL ? url : pos1, '#');
        if(pos2 != NULL){
            *pos2 = '\0';
            url_struct -> hash = pos2 + 1;
        }
        if(pos1 != NULL){
            // 解析query
            pos1[0] = '\0';
            pos1 += 1;

            URL_query_data* query_list = malloc(MAX_QUERY_COUNT * sizeof(URL_query_data));
            if(!LJS_parse_query(pos1, &query_list, MAX_QUERY_COUNT)){
                return false;
            }
            url_struct -> query = query_list;
        } 
        if (pos2 != NULL){
            *pos2 = '\0';
            url_struct -> hash = pos2 + 1;
        }
        url_struct -> path = LJS_resolve_path(url, NULL);
    }
    return true;
}

void LJS_free_url(URL_data *url_struct){
    if( url_struct -> query ){
        free(url_struct -> query);
        free(url_struct -> query_string);
    }
    free(url_struct -> path);
}

char* LJS_format_url(URL_data *url_struct){
    // Scheme://login:password@address:port/path/to/resource?query_string#fragment
    char* data = malloc(2048);
    if(!data) LJS_panic("Out of memory");
    data[0] = '\0';
    strcat(data, url_struct -> protocol);
    strcat(data, "://");
    if(url_struct -> username != NULL){
        strcat(data, url_struct -> username);
        if(url_struct -> password != NULL){
            strcat(data, ":");
            strcat(data, url_struct -> password);
        }
        strcat(data, "@");
    }
    strcat(data, url_struct -> host);
    if(url_struct -> port != 0){
        char port_str[10];
        sprintf(port_str, ":%d", url_struct -> port);
        strcat(data, port_str);
    }
    strcat(data, url_struct -> path);
    if(url_struct -> query != NULL){
        strcat(data, "?");
        for(uint32_t i = 0; i < MAX_QUERY_COUNT; i++){
            if(url_struct -> query[i].key == NULL){
                break;
            }
            if(i != 0){
                strcat(data, "&");
            }
            strcat(data, url_struct -> query[i].key);
            if(url_struct -> query[i].value != NULL){
                strcat(data, "=");
                strcat(data, url_struct -> query[i].value);
            }
        }
    }
    if(url_struct -> hash != NULL){
        strcat(data, "#");
        strcat(data, url_struct -> hash);
    }
    return data;
}

void LJS_free_http_data(HTTP_data *data){
    if(data -> headers){
        for(uint32_t i = 0; i < data -> header_count; i++){
            free(data -> headers[i][0]);
            free(data -> headers[i][1]);
        }
        free(data -> headers);
    }
    free(data);
}

// Header class
static thread_local JSClassID headers_class_id;

static JSValue headers_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    return LJS_Throw(ctx, "Headers is not constructable in JS context", NULL);
}

static JSValue js_headers_append(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque(this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;
    
    const char *key = JS_ToCString(ctx, argv[0]);
    const char *value = JS_ToCString(ctx, argv[1]);
    if(!key || !value)
        return LJS_Throw(ctx, "Invalid arguments", "Headers.append(key: string, value: string): void");

    // 新增
    char **header = js_malloc(ctx, 2 * sizeof(char*));
    strcpy(header[0], key);
    strcpy(header[1], value);
    data -> headers[data -> header_count] = header;
    data -> header_count++;

    return JS_UNDEFINED;
}

static JSValue js_headers_get(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque(this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;
    
    const char *key = JS_ToCString(ctx, argv[0]);
    if(!key)
        return LJS_Throw(ctx, "Invalid arguments", "Headers.get(key: string): string");

    for (uint32_t i = 0; i < data -> header_count; i++){
        if(strcmp(data -> headers[i][0], key) == 0){
            return JS_NewString(ctx, data -> headers[i][1]);
        }
    }
        
    return JS_UNDEFINED;
}

static JSValue js_headers_getall(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque(this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;
    
    JSValue arr = JS_NewArray(ctx);
    uint32_t index = 0;

    const char* find_key = JS_ToCString(ctx, argv[0]);
    if(!find_key)
        return LJS_Throw(ctx, "Invalid arguments", "Headers.getall(key: string): string[]");

    for (uint32_t i = 0; i < data -> header_count; i++){
        if(strcmp(data -> headers[i][0], find_key) == 0){
            JS_SetPropertyUint32(ctx, arr, index, JS_NewString(ctx, data -> headers[i][1]));
            index++;
        }
    }

    return arr;
}

static JSValue js_headers_set(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque(this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;
    
    const char *key = JS_ToCString(ctx, argv[0]);
    const char *value = JS_ToCString(ctx, argv[1]);
    if(!key || !value)
        return LJS_Throw(ctx, "Invalid arguments", "Headers.set(key: string, value: string): void");

    // 找到key
    uint32_t index = 0;
    bool found = false;
    for (uint32_t i = 0; i < data -> header_count; i++){
        if(strcmp(data -> headers[i][0], key) == 0){
            found = true;
            index = i;
            break;
        }
    }

    if(found){
        free(data -> headers[index][1]);
        data -> headers[index][1] = malloc(strlen(value) + 1);
        strcpy(data -> headers[index][1], value);
    }else{
        // 新增
        char **header = malloc(2 * sizeof(char*));
        strcpy(header[0], key);
        strcpy(header[1], value);
        data -> headers[data -> header_count] = header;
        data -> header_count++;
    }

    return JS_UNDEFINED;
}

static JSValue js_headers_delete(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque(this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;
    
    const char *key = JS_ToCString(ctx, argv[0]);
    if(!key)
        return LJS_Throw(ctx, "Invalid arguments", "Headers.delete(key: string): void");

    // 找到key
    uint32_t index = 0;
    bool found = false;
    for (uint32_t i = 0; i < data -> header_count; i++){
        if(strcmp(data -> headers[i][0], key) == 0){
            found = true;
            index = i;
            break;
        }
    }

    if(found){
        free(data -> headers[index][0]);
        free(data -> headers[index][1]);
        data -> header_count--;
        for(uint32_t i = index; i < data -> header_count; i++){
            data -> headers[i] = data -> headers[i + 1];
        }
    }

    return JS_UNDEFINED;
}

static const JSCFunctionListEntry headers_proto_funcs[] = {
    JS_CFUNC_DEF("append", 2, js_headers_append),
    JS_CFUNC_DEF("get", 1, js_headers_get),
    JS_CFUNC_DEF("getall", 1, js_headers_getall),
    JS_CFUNC_DEF("set", 2, js_headers_set),
    JS_CFUNC_DEF("delete", 1, js_headers_delete),
};

static const JSClassDef headers_class = {
    "Headers",
};

JSValue LJS_create_headers(JSContext *ctx, HTTP_data *data){
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, headers_proto_funcs, countof(headers_proto_funcs));

    JSValue headers = JS_NewObjectClass(ctx, headers_class_id);
    JS_SetOpaque(headers, data);
    JS_SetConstructor(ctx, headers, proto);

    return headers;
}

// HTTP
static inline void init_http_data(HTTP_data *data){
    if(data) return;
    data = malloc(sizeof(HTTP_data));
    data -> method = "GET";
    data -> status = 200;
    data -> version = 1.1;
    data -> headers = malloc(MAX_HEADER_COUNT * sizeof(char*));
    data -> header_count = 0;
    data -> chunked = false;
    data -> content_length = 0;
    data -> state = HTTP_INIT;
}

static inline void str_trim(char* str){
    while (*str != '\0' && isspace(*str)){
        str++;
    }
}

static inline float parse_http_version(char* str){
    if(str == NULL || strlen(str) < 3){
        return 0.0;
    }
    char* version = strchr(str, '/');
    if(version == NULL){
        return 0.0;
    }
    version[0] = '\0';
    version += 1;
    float ver = atof(version);
    if(ver < 1.0 || ver > 1.1){
        return 0.0;
    }
    return ver;
}

static inline uint32_t hex2int(char* c){
    uint32_t hex = 0;
    for(uint32_t i = 0; i < strlen(c); i++){
        if(c[i] >= '0' && c[i] <= '9'){
            hex <<= 4;
            hex |= c[i] - '0';
        }else if(c[i] >= 'a' && c[i] <= 'f'){
            hex <<= 4;
            hex |= c[i] - 'a' + 10;
        }else if(c[i] >= 'A' && c[i] <= 'F'){
            hex <<= 4;
            hex |= c[i] - 'A' + 10;
        }else{
            return hex;
        }
    }
    return hex;
}

static inline char* find_header(HTTP_data *data, const char* name){
    for(int i = 0; i < data -> header_count; i++){
        if(strcmp(data -> headers[i][0], name) == 0){
            return data -> headers[i][1];
        }
    }
    return NULL;
}

static inline char* strtoupper(char* str){
    char* p = str;
    while (*p != '\0'){
        *p = toupper(*p);
        p++;
    }
    return str;
}

static inline char* strtolower(char* str){
    char* p = str;
    while (*p != '\0'){
        *p = tolower(*p);
        p++;
    }
    return str;
}

static void parse_evloop_callback(EvFD* evfd, uint8_t* _line_data, uint32_t len, void* userdata){
    HTTP_data *data = userdata;
    char* line_data = (char*)_line_data;
    line_data[len] = '\0';
    // 是第一行
    if (data->state == HTTP_INIT){
        // 找空格解析参数
        char *param1 = line_data;
        str_trim (param1);
        char *param2 = strchr (line_data, ' ');
        if (param2 == NULL){
            goto error;
        }
        *param2 = '\0';
        param2 += 1;
        str_trim (param2);
        char *param3 = strchr (param2, ' ');
        if (param3 == NULL){
            goto error;
        }
        *param3 = '\0';
        param3 += 1;
        str_trim (param3);

        // GET / HTTP/1.1
        if (data->is_client){
            data->method = strdup(strtoupper (param1));
            data->path = strdup(param2);
            data->version = parse_http_version (param3);
            if (data->version < 1.0){
                goto error;
            }
            // HTTP/1.1 200 OK
        }else{
            data->version = parse_http_version (param1);
            data->status = atoi (param2);
        }
    }else if (data->state == HTTP_HEADER){
        str_trim (line_data);
        if (line_data[0] == '\0'){
            if (strcmp (find_header (data, "Transfer-Encoding"), "chunked") == 0){
                data->chunked = true;
                data->state = HTTP_BODY;
            }
            if (data->content_length){
                data->state = HTTP_BODY;
            }
            return;
        }

        char *colon = strchr (line_data, ':');
        if (colon == NULL){
            goto error;
        }
        *colon = '\0';
        colon += 1;
        str_trim (colon);
        
        if (strcmp (strtolower(line_data), "content-length") == 0){
            data->content_length = atoi (colon);
        }else{
            char **header = malloc(sizeof(char*) * 2);
            header[0] = strdup(strtolower(line_data));
            header[1] = strdup(colon);
            data->headers[data->header_count++] = header;
        }
    }

    uint8_t *buffer = malloc (BUFFER_SIZE);
    LJS_evfd_readline (data -> fd, BUFFER_SIZE, buffer, parse_evloop_callback, data);
    free(buffer);
    return;

    error:{
        data->state = HTTP_ERROR;
        close (LJS_evfd_getfd(evfd, NULL));
        return;
    }
}

// 提前定义
static void parse_evloop_body_callback(EvFD* evfd, uint8_t* line_data, uint32_t len, void* user_data);
static void parse_evloop_chunk_callback(EvFD* evfd, uint8_t* chunk_data, uint32_t len, void* user_data);

static void parse_evloop_chunk_callback(EvFD* evfd, uint8_t* chunk_data, uint32_t len, void* user_data){
    HTTP_data *data = user_data;
    if (data->state == HTTP_BODY && data->chunked){
        data -> cb(data, chunk_data, len, data -> userdata);
        data -> content_read += len;
        uint8_t *buffer = malloc(BUFFER_SIZE);
        LJS_evfd_readline(data -> fd, BUFFER_SIZE, buffer, parse_evloop_body_callback, data);
    }
}

static void parse_evloop_body_callback(EvFD* evfd, uint8_t* buffer, uint32_t len, void* user_data){
    HTTP_data *data = user_data;
    if (data->state != HTTP_BODY)
        return;
    char* line_data = (char*)buffer;
    if (data->chunked){
        // 处理chunked编码
        str_trim(line_data);
        uint32_t chunk_size = hex2int(line_data);
        if (chunk_size == 0){
            data->state = HTTP_DONE;
            data->cb(data, NULL, 0, data->userdata);
            return;
        }
        free(line_data);

        // 读取chunk
        uint8_t *buffer = malloc(chunk_size);
        LJS_evfd_readline(data -> fd, chunk_size, buffer, parse_evloop_chunk_callback, data);
    }else{
        // 读取fd
        data->content_read += len;
        data->cb(data, buffer, len, data->userdata);
        if (data->content_read >= data->content_length){
            data->state = HTTP_DONE;
            data->cb(data, NULL, 0, data->userdata);
        }
    }
}

static void write_evloop_callback(EvFD* evfd, void *userdata){
    HTTP_data *data = userdata;
    if (data->state != HTTP_HEADER)
        return;
    if (data->header_writed == data->header_count){
        data->state = HTTP_BODY;
        return;
    }

    char **header = data->headers[data->header_writed++];
    char *line = malloc(1024);
    sprintf(line, "%s: %s\r\n", header[0], header[1]);
    LJS_evfd_write(data -> fd, (uint8_t*)line, strlen(line), write_evloop_callback, data);
    free(line);
}


void LJS_write_header_to_fd(int fd, HTTP_data *data){
    // 第一行
    char *first_line = malloc(1024);
    if(data -> is_client){
        sprintf(first_line, "%s %s HTTP/%.1f\r\n", data -> method, data -> path, data -> version);
    }else{
        sprintf(first_line, "HTTP/%.1f %d OK\r\n", data -> version, data -> status);
    }
    LJS_evfd_write(data -> fd, (uint8_t*)first_line, strlen(first_line), write_evloop_callback, data);
    free(first_line);
}

static void http_promise_callback(HTTP_data *data, uint8_t *buffer, uint32_t len, void *userdata){
    struct promise *promise = userdata;
    if(NULL == buffer){
        if(data -> state == HTTP_ERROR)
            JS_Call(promise -> ctx, promise -> reject, JS_NewError(promise -> ctx), 0, NULL);
        else
            JS_Call(promise -> ctx, promise -> resolve, JS_NULL, 0, NULL);
    }else{
        JS_Call(promise -> ctx, promise -> resolve, 
            JS_NewUint8Array(promise -> ctx, buffer, len, free_js_malloc, NULL, false),    
        0, NULL);
    }

    // free promise
    LJS_FreePromise(promise);
}

void LJS_read_body(HTTP_data *data, HTTP_ParseCallback callback, void *userdata){
    if(data -> state != HTTP_BODY){
        return;
    }
    data -> cb = callback;
    data -> userdata = userdata;

    uint8_t *buffer = malloc(BUFFER_SIZE);
    if(data -> chunked) LJS_evfd_readline(data -> fd, BUFFER_SIZE, buffer, parse_evloop_chunk_callback, data);
    else LJS_evfd_read(data -> fd, BUFFER_SIZE, buffer, parse_evloop_chunk_callback, data);
}

void LJS_parse_from_fd(EvFD* fd, HTTP_data *data, bool is_client, 
    HTTP_ParseCallback callback, void *userdata
){
    init_http_data(data);
    data -> fd = fd;
    data -> is_client = is_client;
    data -> cb = callback;

    // 第一行
    uint8_t *buffer = malloc(BUFFER_SIZE);
    LJS_evfd_readline(data -> fd, BUFFER_SIZE, buffer, parse_evloop_callback, data);
}

// Request结构体
struct HTTP_Response{
    HTTP_data *data;

    bool locked;
};
static thread_local JSClassID response_class_id;

static JSValue js_response_get_status(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque(this_val, response_class_id);
    return JS_NewInt32(ctx, response -> data -> status);
}

static JSValue js_response_get_headers(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque(this_val, response_class_id);
    JSValue headers = JS_NewObject(ctx);
    for(int i = 0; i < response -> data -> header_count; i++){
        JS_SetPropertyStr(ctx, headers, response -> data -> headers[i][0], JS_NewString(ctx, response -> data -> headers[i][1]));
    }
    return headers;
}

static JSValue response_poll(JSContext* ctx, void* ptr, JSValue __){
    struct promise *promise = LJS_NewPromise(ctx);
    struct HTTP_Response *response = ptr;
    LJS_read_body(response -> data, http_promise_callback, promise);
    return promise -> promise;
}

static JSValue js_response_get_body(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque(this_val, response_class_id);
    if(response -> locked) return LJS_Throw(ctx, "Body is locked", NULL);

    response -> locked = true;
    JSValue pipe = LJS_NewU8Pipe(ctx, PIPE_READ, BUFFER_SIZE, response_poll, NULL, NULL, response);
    return pipe;
}

static JSValue js_response_get_locked(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque(this_val, response_class_id);
    return JS_NewBool(ctx, response -> locked);
}

static void js_response_finalizer(JSRuntime *rt, JSValue val) {
    struct HTTP_Response *response = JS_GetOpaque(val, response_class_id);
    if(response){
        if(response -> data){
            LJS_free_http_data(response -> data);
        }
        free(response);
    }
}

static JSValue js_response_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    JSValue proto = JS_GetPropertyStr(ctx, new_target, "prototype");
    JSValue obj = JS_NewObjectProtoClass(ctx, proto, response_class_id);
    JS_FreeValue(ctx, proto);
    struct HTTP_Response *response = malloc(sizeof(struct HTTP_Response));
    response -> data = NULL;
    response -> locked = false;
    JS_SetOpaque(obj, response);
    return obj;
}

JSValue LJS_NewResponse(JSContext *ctx, HTTP_data *data){
    JSValue obj = JS_NewObjectClass(ctx, response_class_id);
    struct HTTP_Response *response = malloc(sizeof(struct HTTP_Response));
    response -> data = data;
    response -> locked = false;
    JS_SetOpaque(obj, response);
    return obj;
}

static JSClassDef response_class = {
    "Response",
    .finalizer = js_response_finalizer
};
static JSCFunctionListEntry response_proto_funcs[] = {
    JS_CGETSET_DEF("status", js_response_get_status, NULL),
    JS_CGETSET_DEF("headers", js_response_get_headers, NULL),
    JS_CGETSET_DEF("body", js_response_get_body, NULL),
    JS_CGETSET_DEF("locked", js_response_get_locked, NULL),
};

// fetch API
struct keepalive_connection{
    int fd;
    bool free;
    struct list_head list;
};

static struct list_head keepalive_list = { 0, 0 };

static JSValue js_fetch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc == 0)
        return LJS_Throw(ctx, "Fetch requires at least 1 argument", "fetch(url: string, options?: FetchInit): Promise<Response>");
    
    // parse URL
    const char *urlstr = JS_ToCString(ctx, argv[0]);
    if(!urlstr) return JS_EXCEPTION;
    char* url_str = strdup(urlstr);
    JS_FreeCString(ctx, urlstr);
    URL_data url;
    if(!LJS_parse_url(url_str, &url, NULL) || url.protocol == NULL || url.host == NULL){
        JS_FreeCString(ctx, url_str);
        return LJS_Throw(ctx, "Invalid URL", NULL);
    }
    
    if(strstr(url.protocol, "http") == NULL && strstr(url.protocol, "ws") == NULL){
        LJS_free_url(&url);
        return LJS_Throw(ctx, "Unsupported protocol %s", NULL, url.protocol);
    }

    // 获取连接
    EvFD* fd = NULL;
    if(keepalive_list.prev == NULL){
        init_list_head(&keepalive_list);
    }
    struct list_head *cur, *tmp;
    struct keepalive_connection *conn;
    list_for_each_safe(cur, tmp, &keepalive_list){
        conn = list_entry(cur, struct keepalive_connection, list);
        if(!conn -> free) continue;
        conn -> free = false;
    }
    if(!conn){
        // open new connection
        // bool ssl = url.protocol[strlen(url.protocol) - 1] == 's';
        // todo...
    }
    if(!conn) return LJS_Throw(ctx, "Failed to open connection", NULL);

    // 解析参数
    JSValue obj = argc >= 2 ? JS_DupValue(ctx, argv[1]) : JS_NewObject(ctx);

    // GET / HTTP/1.1
    char* method = (char*) JS_ToCString(ctx, JS_GetPropertyStr(ctx, obj, "method"));
    if (!method) method = "GET";
    size_t guess_len = strlen(method) + 1 + strlen(url.path) + 1 + 8 + 2 + 1;
    char* buf = malloc(guess_len);
    snprintf(buf, guess_len, "%s %s HTTP/1.1\r\n", method, url.path);
    LJS_evfd_write(fd, (uint8_t*) buf, strlen(buf), NULL, NULL);

    // keep-alive
    bool keep_alive = JS_ToBool(ctx, JS_GetPropertyStr(ctx, obj, "keepAlive"));
    if (keep_alive) {
        LJS_evfd_write(fd, (uint8_t*) "Connection: keep-alive\r\n", 24, NULL, NULL);
    }
    else {
        LJS_evfd_write(fd, (uint8_t*) "Connection: close\r\n", 19, NULL, NULL);
    }

    // referer
    const char* referer = JS_ToCString(ctx, JS_GetPropertyStr(ctx, obj, "referer"));
    if (referer) {
        size_t guess_len = strlen(referer) + 16;
        char* buf = malloc(guess_len);
        snprintf(buf, guess_len, "Referer: %s\r\n", referer);
        LJS_evfd_write(fd, (uint8_t*) buf, strlen(buf), NULL, NULL);
    }

    // host
    if(JS_IsUndefined(JS_GetPropertyStr(ctx, obj, "host"))){
        char* host = malloc(strlen(url.host) + 16);
        snprintf(host, strlen(url.host) + 16, "Host: %s\r\n", url.host);
        LJS_evfd_write(fd, (uint8_t*) host, strlen(host), NULL, NULL);
    }

    // headers
    const char* headers = JS_ToCString(ctx, JS_GetPropertyStr(ctx, obj, "headers"));
    if (headers) {
        JSPropertyEnum* props;
        uint32_t prop_count;
        if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, obj, JS_GPN_STRING_MASK) == 0) {
            for (int i = 0; i < prop_count; i++) {
                const char* key = JS_AtomToCString(ctx, props[i].atom);
                const char* value = JS_ToCString(ctx, JS_GetProperty(ctx, obj, props[i].atom));
                if (key && value) {
                    if (
                        strcasecmp(key, "method") == 0 || 
                        strcasecmp(key, "keepalive") == 0 || 
                        strcasecmp(key, "referer") == 0
                    ) {
                        continue;
                    }
                    size_t guess_len = strlen(key) + 2 + strlen(value) + 2;
                    char* buf = malloc(guess_len);
                    snprintf(buf, guess_len, "%s: %s\r\n", key, value);
                    LJS_evfd_write(fd, (uint8_t*) buf, strlen(buf), NULL, NULL);
                }
                JS_FreeCString(ctx, key);
                JS_FreeCString(ctx, value);
            }
        }
    }

    // body
    JSValue body = JS_GetPropertyStr(ctx, obj, "body");
    // typedarray
    if (JS_GetTypedArrayType(body) != -1) {
        size_t data_len;
        uint8_t* data = JS_GetArrayBuffer(ctx, &data_len, body);
        if (data) {
            size_t len = 22 + sizeof(size_t);
            char* buf = malloc(len);
            snprintf(buf, len, "Content-Length: %lu\r\n\r\n", data_len);
            LJS_evfd_write(fd, (uint8_t*) buf, len, NULL, NULL);
            free(buf);
        }

        // 写入数据
        LJS_evfd_write(fd, data, data_len, NULL, NULL);
    }else{
        // 暂时不支持
        LJS_evfd_write(fd, (uint8_t*) "Content-Length: 0\r\n\r\n", 26, NULL, NULL);
    }

    // 解析响应
    HTTP_data *data = malloc(sizeof(HTTP_data));
    LJS_parse_from_fd(fd, data, true, NULL, NULL);

    // 创建Response对象
    JSValue response_obj = LJS_NewResponse(ctx, data);
    LJS_free_url(&url);
    return response_obj;
}

// --------------------- JAVASCRIPT URL API -----------------------------

struct JS_URL_struct{
    URL_data* self;
    JSValue template;
    URL_data* base;
    JSValue dup_value[10];
    uint8_t dup_count;
};

static thread_local JSClassID js_class_url_id;

static JSValue js_url_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv){
    URL_data *url_struct = malloc(sizeof(URL_data));
    struct JS_URL_struct *js_url_struct = malloc(sizeof(struct JS_URL_struct));
    if(url_struct == NULL || js_url_struct == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }

    js_url_struct -> dup_count = 0;

    if(argc == 1){
        const char *url = JS_ToCString(ctx, argv[0]);
        if(url == NULL){
            free(url_struct);
            return LJS_Throw(ctx, "Invalid URL", NULL);
        }
        // 深拷贝
        char* url_copied = malloc(strlen(url) + 1);
        memcpy(url_copied, url, strlen(url) + 1);
        LJS_parse_url(url_copied, url_struct, NULL);
    }else if(argc == 2){
        const char *url = JS_ToCString(ctx, argv[0]);
        if(JS_IsObject(argv[1])){
            URL_data *base_url = JS_GetOpaque(argv[1], js_class_url_id);
            if(base_url == NULL){
                free(url_struct);
                return LJS_Throw(ctx, "Invalid base URL", NULL);
            }
            // 创建引用
            js_url_struct -> template = JS_DupValue(ctx, argv[1]);
        }else{
            URL_data *base_url = malloc(sizeof(URL_data));
            if(base_url == NULL){
                free(url_struct);
                return JS_ThrowOutOfMemory(ctx);
            }
            const char *base_url_str = JS_ToCString(ctx, argv[1]);
            if(base_url_str == NULL){
                free(url_struct);
                return LJS_Throw(ctx, "Invalid base URL", NULL);
            }
            // 拷贝
            char* base_url_copied = strdup(base_url_str);
            char* url_copied = strdup(url);
            LJS_parse_url(base_url_copied, base_url, NULL);
            js_url_struct -> base = base_url;
            // 解析
            LJS_parse_url(url_copied, url_struct, base_url);
        }
    }else if(argc != 0){
        JS_ThrowTypeError(ctx, "URL constructor takes 0 or 1 argument");
        free(url_struct);
        return JS_EXCEPTION;
    }
    js_url_struct -> self = url_struct;
    return JS_NewObjectClass(ctx, js_class_url_id);
}

static JSValue js_url_toString(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    char *url_str = malloc(1024);
    if(url_str == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }

    char* data = LJS_format_url(url_struct);
    JSValue url_val = JS_NewString(ctx, data);
    free(data);
    return url_val;
}

static JSValue js_url_getProtocol(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> protocol == NULL){
        return JS_UNDEFINED;
    }
    return JS_NewString(ctx, url_struct -> protocol);
}

static JSValue js_url_getHost(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> host == NULL){ 
        return JS_UNDEFINED;
    }
    return JS_NewString(ctx, url_struct -> host);
}

static JSValue js_url_getPort(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> port == 0){    
        return JS_UNDEFINED;
    }
    return JS_NewInt32(ctx, url_struct -> port);
}

static JSValue js_url_getPath(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> path == NULL){
        return JS_UNDEFINED;
    }
    return JS_NewString(ctx, url_struct -> path);
}

static JSValue js_url_getQueryStr(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> query == NULL){
        return JS_UNDEFINED;
    }
    char *query_str = malloc(1024);
    if(query_str == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }
    for(uint32_t i = 0; i < MAX_QUERY_COUNT; i++){
        if(url_struct -> query[i].key == NULL){
            break;
        }
        if(i != 0){
            strcat(query_str, "&");
        }
        strcat(query_str, url_struct -> query[i].key);
        if(url_struct -> query[i].value != NULL){
            strcat(query_str, "=");
            strcat(query_str, url_struct -> query[i].value);
        }
    }
    JSValue query_val = JS_NewString(ctx, query_str);
    free(query_str);
    return query_val;
}

static JSValue js_url_getQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> query == NULL){
        return JS_UNDEFINED;
    }
    JSValue query_obj = JS_NewObject(ctx);
    for(uint32_t i = 0; i < MAX_QUERY_COUNT; i++){
        if(url_struct -> query[i].key == NULL){
            break;
        }
        JSValue value_val = JS_NewString(ctx, url_struct -> query[i].value);
        JS_SetPropertyStr(ctx, query_obj, url_struct -> query[i].key, value_val);
    }
    return query_obj;
}

static JSValue js_url_getHash(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> hash == NULL){
        return JS_UNDEFINED;
    }
    return JS_NewString(ctx, url_struct -> hash);
}

static JSValue js_url_getUsername(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> username == NULL){
        return JS_UNDEFINED;
    }
    return JS_NewString(ctx, url_struct -> username);
}

static JSValue js_url_getPassword(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> password == NULL){
        return JS_UNDEFINED;
    }
    return JS_NewString(ctx, url_struct -> password);
}

static JSValue js_url_setUsername(JSContext *ctx, JSValueConst this_val, JSValueConst value){ 
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *username = JS_ToCString(ctx, value);
    if(username == NULL){
        return LJS_Throw(ctx, "Invalid username", NULL);
    }
    js_url_struct -> dup_value[js_url_struct -> dup_count ++] = JS_DupValue(ctx, value);
    url_struct -> username = (char*)username;
    return JS_UNDEFINED;
}

static JSValue js_url_setPassword(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *password = JS_ToCString(ctx, value);
    if(password == NULL){
        return LJS_Throw(ctx, "Invalid password", NULL);
    }
    js_url_struct -> dup_value[js_url_struct -> dup_count ++] = JS_DupValue(ctx, value);
    url_struct -> password = (char*)password;
    return JS_UNDEFINED;
}

static JSValue js_url_setProtocol(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *protocol = JS_ToCString(ctx, value);
    if(protocol == NULL){
        return LJS_Throw(ctx, "Invalid protocol", NULL);
    }
    js_url_struct -> dup_value[js_url_struct -> dup_count ++] = JS_DupValue(ctx, value);
    url_struct -> protocol = (char*)protocol;
    return JS_UNDEFINED;
}

JSValue js_url_setHost(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *host = JS_ToCString(ctx, value);
    if(host == NULL){
        return LJS_Throw(ctx, "Invalid host", NULL);
    }
    js_url_struct -> dup_value[js_url_struct -> dup_count ++] = JS_DupValue(ctx, value);
    url_struct -> host = (char*)host;
    return JS_UNDEFINED;
}

JSValue js_url_setPort(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    int32_t port;
    if(-1 == JS_ToInt32(ctx, &port, value))
        return LJS_Throw(ctx, "Invalid port", NULL);
    if(port < 0 || port > 65535){
        return JS_ThrowRangeError(ctx, "port out of range");
    }
    url_struct -> port = port;
    return JS_UNDEFINED;
}

JSValue js_url_setPath(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *path = JS_ToCString(ctx, value);
    if(path == NULL){
        return LJS_Throw(ctx, "Invalid path", NULL);
    }
    url_struct -> path = strdup(path);
    return JS_UNDEFINED;
}

JSValue js_url_setQueryStr(JSContext *ctx, JSValueConst this_val, JSValue value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *query = JS_ToCString(ctx, value);
    if(query == NULL){
        return LJS_Throw(ctx, "Invalid query string", NULL);
    }
    URL_query_data* query_list = malloc(sizeof(URL_query_data) * MAX_QUERY_COUNT);
    char* query_str = strdup(query);
    if(!LJS_parse_query(query_str, &query_list, MAX_QUERY_COUNT)){
        return LJS_Throw(ctx, "Failed to parse query string", NULL);
    }
    url_struct -> query_string = query_str;
    url_struct -> query = query_list;
    return JS_UNDEFINED;
}

JSValue js_url_delQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    
    if(NULL == js_url_struct -> self -> query){
        return JS_UNDEFINED;
    }

    uint32_t del_id = -1;
    char* key;
    if(argc == 1){
        key = (char*)JS_ToCString(ctx, argv[0]);
        if(key == NULL){
            return LJS_Throw(ctx, "Invalid query key", NULL);
        }
    }else if(argc == 2){
        key = (char*)JS_ToCString(ctx, argv[0]);
        if(-1 == JS_ToUint32(ctx, &del_id, argv[1]) || key == NULL){
            return LJS_Throw(ctx, "Invalid arguments", NULL);
        }
    }else{
        return JS_ThrowTypeError(ctx, "delQuery takes 1 or 2 arguments");
    }

    uint32_t key_occurrence = 0;
    bool found = false;
    for(uint32_t i = 0; i < MAX_QUERY_COUNT; i++){
        if(js_url_struct -> self -> query[i].key == NULL){
            break;
        }
        if(strcmp(js_url_struct -> self -> query[i].key, key) == 0){
            if(del_id == -1 || del_id == key_occurrence){
                js_url_struct -> self -> query[i].key = NULL;
                js_url_struct -> self -> query[i].value = NULL;
                found = true;
            }
            key_occurrence++;
        }
    }

    if(!found){
        return JS_ThrowTypeError(ctx, "query key not found");
    }
    return JS_UNDEFINED;
}

JSValue js_url_addQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *key = JS_ToCString(ctx, argv[0]);
    if(key == NULL){
        return LJS_Throw(ctx, "Invalid query key", NULL);
    }
    const char *value = NULL;
    if(argc == 2){
        value = JS_ToCString(ctx, argv[1]);
        if(value == NULL){
            return LJS_Throw(ctx, "Invalid query value", NULL);
        }
    }

    if(url_struct -> query == NULL){
        URL_query_data *query_list = malloc(sizeof(URL_query_data) * MAX_QUERY_COUNT);
        if(query_list == NULL){
            return JS_ThrowOutOfMemory(ctx);
        }
        memset(query_list, 0, sizeof(URL_query_data) * MAX_QUERY_COUNT);
        url_struct -> query = query_list;
    }

    for(uint32_t i = 0; i < MAX_QUERY_COUNT; i++){
        if(url_struct -> query[i].key == NULL){
            if(value == NULL){
                url_struct -> query[i].key = malloc(strlen(key) + 1);
                if(url_struct -> query[i].key == NULL){
                    return JS_ThrowOutOfMemory(ctx);
                }
                memcpy(url_struct -> query[i].key, key, strlen(key) + 1);
            }else{
                url_struct -> query[i].key = malloc(strlen(key) + 1);
                if(url_struct -> query[i].key == NULL){
                    return JS_ThrowOutOfMemory(ctx);
                }
                url_struct -> query[i].value = malloc(strlen(value) + 1);
                if(url_struct -> query[i].value == NULL){
                    return JS_ThrowOutOfMemory(ctx);
                }
                memcpy(url_struct -> query[i].key, key, strlen(key) + 1);
                memcpy(url_struct -> query[i].value, value, strlen(value) + 1);
            }
            break;
        }
    }
    return JS_UNDEFINED;
}

JSValue js_url_setHash(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *hash = JS_ToCString(ctx, value);
    if(hash == NULL){
        return LJS_Throw(ctx, "Invalid hash", NULL);
    }
    char* hash_copied = malloc(strlen(hash) + 1);
    memcpy(hash_copied, hash, strlen(hash) + 1);
    url_struct -> hash = hash_copied;
    return JS_UNDEFINED;
}

static void js_url_finalizer(JSRuntime *rt, JSValue val) {
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(val, js_class_url_id);
    if(js_url_struct == NULL){
        return;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> protocol != NULL){
        free(url_struct -> protocol);
    }
    if(url_struct -> host != NULL){
        free(url_struct -> host);
    }
    if(url_struct -> path != NULL){
        free(url_struct -> path);
    }
    if(url_struct -> username != NULL){
        free(url_struct -> username);
    }
    if(url_struct -> password != NULL){
        free(url_struct -> password);
    }
    if(url_struct -> hash != NULL){
        free(url_struct -> hash);
    }
    if(url_struct -> query != NULL){
        for(uint32_t i = 0; i < MAX_QUERY_COUNT; i++){
            if(url_struct -> query[i].key != NULL){
                free(url_struct -> query[i].key);
            }
            if(url_struct -> query[i].value != NULL){
                free(url_struct -> query[i].value);
            }
        }
        free(url_struct -> query);
    }
    for(uint32_t i = 0; i < js_url_struct -> dup_count; i++){
        JS_FreeValueRT(rt, js_url_struct -> dup_value[i]);
    }
    free(js_url_struct);
};

static JSValue js_url_proto_canParse(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsString(argv[0]))
        return LJS_Throw(ctx, "Invalid arguments", "URL.canParse(url: string, baseURL?: string): boolean\n for more, please see https://developer.mozilla.org/zh-CN/docs/Web/API/URL/canParse_static");

    // url
    const char *url = JS_ToCString(ctx, argv[0]);
    if(!url) return JS_EXCEPTION;
    char* url_str = strdup(url);
    JS_FreeCString(ctx, url);

    // base url
    URL_data url_base_struct;
    char* base_url_str = NULL;
    if(argc == 2){
        const char* base_url = JS_ToCString(ctx, argv[1]);
        if(base_url){
            base_url_str = strdup(base_url);
            JS_FreeCString(ctx, base_url);
            if(!LJS_parse_url(base_url_str, &url_base_struct, NULL)){
                free(base_url_str);
                return JS_FALSE;
            }
        }
    }
    
    // parse
    URL_data url_struct;
    bool result = LJS_parse_url(url_str, &url_struct, &url_base_struct);

    // free
    LJS_free_url(&url_struct);
    LJS_free_url(&url_base_struct);
    free(url_str);
    if(base_url_str) free(base_url_str);
    
    return JS_NewBool(ctx, result);
}

static const JSCFunctionListEntry js_url_funcs[] = {
    JS_CFUNC_DEF("toString", 0, js_url_toString),
    JS_CGETSET_DEF("protocol", js_url_getProtocol, js_url_setProtocol),
    JS_CGETSET_DEF("host", js_url_getHost, js_url_setHost),
    JS_CGETSET_DEF("port", js_url_getPort, js_url_setPort),
    JS_CGETSET_DEF("path", js_url_getPath, js_url_setPath),
    JS_CGETSET_DEF("query", js_url_getQueryStr, js_url_setQueryStr),
    JS_CFUNC_DEF("getQuery", 0, js_url_getQuery),
    JS_CFUNC_DEF("delQuery", 1, js_url_delQuery),
    JS_CFUNC_DEF("addQuery", 1, js_url_addQuery),
    JS_CGETSET_DEF("hash", js_url_getHash, js_url_setHash),
    JS_CGETSET_DEF("username", js_url_getUsername, js_url_setUsername),
    JS_CGETSET_DEF("password", js_url_getPassword, js_url_setPassword),
};

static const JSCFunctionListEntry url_proto_funcs[] = {
    JS_CFUNC_DEF("canParse", 1, js_url_proto_canParse)
};

static const JSClassDef js_url_class = {
    "URL",
    .finalizer = js_url_finalizer,
};

int init_http(JSContext *ctx, JSModuleDef *m){
    JSValue headers_ctor = JS_NewCFunction2(ctx, headers_constructor, "Headers", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, headers_ctor, JS_GetClassProto(ctx, headers_class_id));

    JS_SetModuleExport(ctx, m, "Headers", headers_ctor);

    return true;
}

bool LJS_init_http(JSContext *ctx){
    JSModuleDef *m = JS_NewCModule(ctx, "http", init_http);
    JSRuntime *rt = JS_GetRuntime(ctx);
    
    JS_NewClassID(rt, &response_class_id);
    JS_NewClass(rt, response_class_id, &response_class);
    JS_SetClassProto(ctx, response_class_id, JS_NewObject(ctx));
    JS_SetPropertyFunctionList(ctx, JS_GetClassProto(ctx, response_class_id), response_proto_funcs, countof(response_proto_funcs));

    JSValue response_constructor = JS_NewCFunction2(ctx, js_response_constructor, "Response", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, response_constructor, JS_GetClassProto(ctx, response_class_id));

    // URL
    JS_NewClassID(rt, &js_class_url_id);
    JS_NewClass(rt, js_class_url_id, &js_url_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_url_funcs, countof(js_url_funcs));
    JS_SetClassProto(ctx, js_class_url_id, proto);

    JSValue url_ctor = JS_NewCFunction2(ctx, js_url_constructor, "URL", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, url_ctor, proto);
    JSValue url_ctro_proto = JS_NewObjectProto(ctx, JS_GetPrototype(ctx, url_ctor));
    JS_SetPropertyFunctionList(ctx, url_ctro_proto, url_proto_funcs, countof(url_proto_funcs));
    JS_SetPrototype(ctx, url_ctor, url_ctro_proto);

    JS_SetPropertyStr(ctx, JS_GetGlobalObject(ctx), "URL", url_ctor);

    // fetch
    JSValue fetch_func = JS_NewCFunction2(ctx, js_fetch, "fetch", 1, JS_CFUNC_generic, 0);
    JS_SetPropertyStr(ctx, JS_GetGlobalObject(ctx), "fetch", fetch_func);

    // Headers
    JS_NewClassID(rt, &headers_class_id);
    JS_NewClass(rt, headers_class_id, &headers_class);

    JSValue headers_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, headers_proto, headers_proto_funcs, countof(headers_proto_funcs));

    JS_AddModuleExport(ctx, m, "Headers");

    return true;
}