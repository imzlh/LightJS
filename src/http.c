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
#include <assert.h>
#include <sys/random.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define MAX_QUERY_COUNT 32
#define BUFFER_SIZE 1024

#define SPLIT_HEADER(line) \
    char *name = line; \
    char *value = strchr(line, ':'); \
    if(value){ \
        *(value ++) = '\0'; \
        while(*value == ' ') value ++; \
        str_trim(value); \
    }\
    str_trim(name);
#define TRIM_START(var2, line, _len) \
    char* var2 = line; \
    uint32_t __i = 0; \
    while((*var2 != '\0' || __i < _len) && (*var2 == ' ' || *var2 == '\t' || *var2 == '\r' || *var2 == '\n')) \
        var2++, __i++; \
    if(__i == _len) var2 = NULL;

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
    char* base = strdup(_base);
    if(!base) {
        base = getcwd(NULL, 0);
    }

    /* 拼接路径 */
    size_t base_len = strlen(base);
    size_t path_len = strlen(path);
    char* combined = malloc(base_len + path_len + 2);

    // Remove filename from base path
    if(base[base_len-1] != '/'){
        char* slash = strrchr(base, '/');
        if(slash){
            *(slash +1) = '\0';
        }
    }
    
    int needs_slash = !(base_len && base[base_len-1] == '/') && 
                     !(path_len && path[0] == '/');
    
    sprintf(combined, "%s%s%s", 
            base, 
            needs_slash ? "/" : "", 
            path);

    /* 标准化路径 */
    char* resolved = normalize_path(combined);
    free(combined);
    free(base);
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
 * 务必使用memset(url_struct, 0, sizeof(URL_data))初始化url_struct
 */
bool LJS_parse_url(const char *_url, URL_data *url_struct, URL_data *base) {
    bool result = false;
    char *url = NULL;
    URL_query_data *query_list = NULL;
    char *source_str = NULL;
    char *base_path_backup = NULL; // 用于暂存base路径

    if (strlen(_url) == 0) {
        goto cleanup;
    }

    if (!(source_str = strdup(_url))) {
        goto cleanup;
    }
    url_struct -> source_str = source_str;
    url = source_str;

    if (!base) {
        if (!default_url) {
            if (!(default_url = calloc(1, sizeof(URL_data)))) {
                goto cleanup;
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

    if (!url_struct -> host) {
        char *host_end = strpbrk(url, ":/?#");
        char *user_pass_end = strrchr(url, '@'); // 使用最后一个@

        if (user_pass_end && (!host_end || user_pass_end < host_end)) {
            *user_pass_end = '\0';
            char *colon = strchr(url, ':');
            if (colon) {
                *colon = '\0';
                url_struct -> username = url;
                url_struct -> password = colon + 1;
            } else {
                url_struct -> username = url;
            }
            url = user_pass_end + 1;
            host_end = strpbrk(url, ":/?#"); // 重新计算host_end
        }

        if (host_end && *host_end == ':') {
            *host_end = '\0';
            char *port_str = host_end + 1;
            char *port_end = strpbrk(port_str, "/?#");
            if (port_end) *port_end = '\0';

            char *end;
            long port = strtol(port_str, &end, 10);
            if (*end != '\0' || port < 0 || port > 65535) {
                goto cleanup;
            }
            url_struct -> port = (int)port;
            // url = (port_end ? port_end : (port_str - strlen(port_str))) +1;
        } else {
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
        }

        url_struct -> host = url;
        if (host_end) {
            *host_end = '\0';
            url = host_end;
        }
    }

    if (!url_struct -> path) {
        char *path_start = url;
        char *query_start = strchr(path_start, '?');
        char *hash_start = strchr(query_start ? query_start : path_start, '#');

        if (hash_start) {
            *hash_start = '\0';
            url_struct -> hash = hash_start + 1;
        }

        if (query_start) {
            *query_start = '\0';
            char *query_str = query_start + 1;

            query_list = malloc(MAX_QUERY_COUNT * sizeof(URL_query_data));
            if (!query_list || !LJS_parse_query(query_str, &query_list, MAX_QUERY_COUNT)) {
                goto cleanup;
            }
            url_struct -> query = query_list;
            query_list = NULL; // 防止重复释放
        }

        char *input_path = (*path_start == '/') ? path_start : "/";
        if (strcmp(input_path, "/") != 0) {
            base_path_backup = strdup(base -> path ? base -> path : "/");
            url_struct -> path = LJS_resolve_path(input_path, base_path_backup);
            if (!url_struct -> path) {
                goto cleanup;
            }
        } else {
            url_struct -> path = strdup(input_path);
        }
    }

    result = true;

cleanup:
    if (!result) {
        free(url_struct -> source_str);
        free(url_struct -> path);
        free(query_list);
        url_struct -> source_str = NULL;
        url_struct -> path = NULL;
        url_struct -> query = NULL;
    }
    free(base_path_backup);
    return result;
}


void LJS_free_url(URL_data *url_struct){
    if( url_struct -> query ){
        free(url_struct -> query);
        free(url_struct -> query_string);
    }
    free(url_struct -> path);
    free(url_struct -> source_str);
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

// Note: data itself is not freed here, please free it by yourself
void LJS_free_http_data(HTTP_data *data){
    for(uint32_t i = 0; i < data -> header_count; i++){
        free(data -> headers[i][0]);
        free(data -> headers[i][1]);
    }
    // free(data);
}

#define CHECK_ARGS(n, msg, ...){ \
    if(argc < n) return LJS_Throw(ctx, "Too few arguments, expect %d, got %d", msg, n, argc); \
    int32_t types[] = {  __VA_ARGS__ }; \
    for(int i = 0; i < n; i++)\
        if(JS_VALUE_GET_TAG(argv[i]) != types[i]) \
            return LJS_Throw(ctx, "Invalid argument type at index %d", msg, i); \
}

// Header class
static thread_local JSClassID headers_class_id;

static JSValue headers_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    return LJS_Throw(ctx, "Headers is not constructable in JS context", NULL);
}

static JSValue js_headers_append(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;

    CHECK_ARGS(2, "Headers.append(key: string, value: string): void", JS_TAG_STRING, JS_TAG_STRING);
    
    const char *key = JS_ToCString(ctx, argv[0]);
    const char *value = JS_ToCString(ctx, argv[1]);

    // 新增
    char **header = js_malloc(ctx, 2 * sizeof(char*));
    strcpy(header[0], key);
    strcpy(header[1], value);
    data -> headers[data -> header_count ++] = header;

    return JS_UNDEFINED;
}

static JSValue js_headers_get(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;
    
    CHECK_ARGS(1, "Headers.get(key: string): string", JS_TAG_STRING);

    const char *key = JS_ToCString(ctx, argv[0]);

    for (uint32_t i = 0; i < data -> header_count; i++){
        if(strcmp(data -> headers[i][0], key) == 0){
            return JS_NewString(ctx, data -> headers[i][1]);
        }
    }
        
    return JS_UNDEFINED;
}

static JSValue js_headers_getall(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;
    
    JSValue arr = JS_NewArray(ctx);
    uint32_t index = 0;

    CHECK_ARGS(1, "Headers.getall(key: string): Array<string>", JS_TAG_STRING);

    const char* find_key = JS_ToCString(ctx, argv[0]);

    for (uint32_t i = 0; i < data -> header_count; i++){
        if(strcmp(data -> headers[i][0], find_key) == 0){
            JS_SetPropertyUint32(ctx, arr, index, JS_NewString(ctx, data -> headers[i][1]));
            index++;
        }
    }

    return arr;
}

static JSValue js_headers_set(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;

    CHECK_ARGS(2, "Headers.set(key: string, value: string): void", JS_TAG_STRING, JS_TAG_STRING);
    
    const char *key = JS_ToCString(ctx, argv[0]);
    const char *value = JS_ToCString(ctx, argv[1]);

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
        data -> headers[data -> header_count ++] = header;
    }

    return JS_UNDEFINED;
}

static JSValue js_headers_delete(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    HTTP_data *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;

    CHECK_ARGS(1, "Headers.delete(key: string): void", JS_TAG_STRING);
    
    const char *key = JS_ToCString(ctx, argv[0]);

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
    JSValue headers = JS_NewObjectClass(ctx, headers_class_id);
    JS_SetOpaque(headers, data);

    return headers;
}

// HTTP
static inline void init_http_data(HTTP_data *data){
    data -> method = "GET";
    data -> status = 200;
    data -> version = 1.1;
    data -> header_count = 0;
    data -> header_writed = 0;
    data -> chunked = false;
    data -> content_length = 0;
    data -> state = HTTP_INIT;
    data -> __read_all = false;
    data -> content_read = 0;
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

static inline void strtoupper(char* str){
    while (*str != '\0'){
        if('a' <= *str && *str <= 'z')
            *str = toupper(*str);
        str ++;
    }
}

static inline char* strtolower(char* str){
    char* p = str;
    while (*p != '\0'){
        *p = tolower(*p);
        p++;
    }
    return str;
}

#define COPY_BUF(var, buf, len) uint8_t* var = malloc(len); memcpy(var, buf, len);

// predef
static int parse_evloop_body_callback(EvFD* evfd, uint8_t* buffer, uint32_t len, void* user_data);

// http chunk
static int parse_evloop_chunk_callback(EvFD* evfd, uint8_t* chunk_data, uint32_t len, void* user_data){
    HTTP_data *data = user_data;
    if (data -> state == HTTP_BODY && data -> chunked){
        data -> cb(data, chunk_data, len, data -> userdata);
        data -> content_read += len;
    }

    free(chunk_data);
    
    if(data -> __read_all){
        uint8_t* buf = malloc(BUFFER_SIZE);
        LJS_evfd_readline(evfd, BUFFER_SIZE, buf, parse_evloop_body_callback, data);
    }
    return EVCB_RET_DONE;
}

// body: read once
static int parse_evloop_body_callback(EvFD* evfd, uint8_t* buffer, uint32_t len, void* user_data){
    HTTP_data *data = user_data;
    if (data -> state != HTTP_BODY) return EVCB_RET_DONE ;
    char* line_data = (char*)buffer;
    if (data -> chunked) {
        // 处理chunked编码
        str_trim(line_data);
        uint32_t chunk_size = hex2int(line_data);
        if (chunk_size == 0) goto done;

        // chunk read
        uint8_t* buf = malloc(chunk_size);
        LJS_evfd_readsize(evfd, chunk_size, buf, parse_evloop_chunk_callback, data);

        free(line_data);
        return EVCB_RET_DONE;
    }else {
        // 读取fd
        COPY_BUF(databuf, buffer, len);
        data -> content_read += len;
        data -> cb(data, databuf, len, data -> userdata);
        if (data -> content_read >= data -> content_length)
            goto done;

        if(data -> __read_all){
            goto end;   // continue read
        }

        return EVCB_RET_DONE;
    }

    return EVCB_RET_DONE;

end:
    return EVCB_RET_CONTINUE;   // 继续读取

done:
    data -> state = HTTP_DONE;
    data -> cb(data, NULL, 0, data -> userdata);
    free(buffer);
    return EVCB_RET_DONE;
}

// main
static int parse_evloop_callback(EvFD* evfd, uint8_t* _line_data, uint32_t len, void* userdata){
    HTTP_data *data = userdata;
    char* line_data = (char*)_line_data;
    if(!line_data) goto error2; // close
    // 是第一行
    if (data -> state == HTTP_INIT){
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
        if (data -> is_client){
            strtoupper(param1);
            data -> method = strdup(param1);
            data -> path = strdup(param2);
            data -> version = parse_http_version (param3);
            if (data -> version < 1.0){
                goto error;
            }
        // HTTP/1.1 200 OK
        }else{
            data -> version = parse_http_version (param1);
            data -> status = atoi (param2);
        }
        data -> state = HTTP_HEADER;
    }else if (data -> state == HTTP_HEADER){
        str_trim (line_data);
        if (line_data[0] == '\0'){
            // POST PUT有body
            if(data -> content_length == 0 && !strcmp(data -> method, "POST") && !strcmp(data -> method, "PUT"))
                data -> state = HTTP_DONE;
            else
                data -> state = HTTP_BODY;
            data -> cb(data, NULL, 0, data -> userdata);
            free(line_data);
            return EVCB_RET_DONE;
        }

        SPLIT_HEADER(line_data);    // name&value

        if(!strlen(name) || !strlen(value)) return EVCB_RET_CONTINUE;
        
        if (strncasecmp(line_data, "content-length", 15) == 0){
            data -> content_length = atoi (value);
        }else if(
            strncasecmp (line_data, "transfer-encoding", 18) == 0 && 
            strcmp(value, "chunked") == 0
        ){
            data -> chunked = true;
        }else{
            char **header = malloc(sizeof(char*) * 2);
            header[0] = strdup(strtolower(name));
            header[1] = strdup(value);
            data -> headers[data -> header_count++] = header;
        }
    }


    return EVCB_RET_CONTINUE;

error:
    LJS_evfd_close(evfd);
error2:
    data -> state = HTTP_ERROR;
    free(_line_data);
    return EVCB_RET_DONE;
}

static void write_evloop_callback(EvFD* evfd, void *userdata){
    HTTP_data *data = userdata;
    if (data -> state != HTTP_HEADER)
        return;
    if (data -> header_writed == data -> header_count){
        data -> state = HTTP_BODY;
        return;
    }
    
    char **header = data -> headers[data -> header_writed++];
    char *line = malloc(1024);
    sprintf(line, "%s: %s\r\n", header[0], header[1]);
    LJS_evfd_write(data -> fd, (uint8_t*)line, strlen(line), write_evloop_callback, data);
    free(line);
}

static inline void write_firstline(int fd, HTTP_data *data){
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

static inline void read_body(HTTP_data *data, HTTP_ParseCallback callback, void *userdata, bool readall){
    if(data -> state != HTTP_BODY){
        return;
    }
    data -> cb = callback;
    data -> userdata = userdata;
    data -> __read_all = readall;

    uint8_t *buffer = malloc(BUFFER_SIZE);
    if(data -> chunked) LJS_evfd_readline(data -> fd, BUFFER_SIZE, buffer, parse_evloop_body_callback, data);
    else LJS_evfd_read(data -> fd, BUFFER_SIZE, buffer, parse_evloop_body_callback, data);
}

void LJS_parse_from_fd(EvFD* fd, HTTP_data *data, bool is_client, 
    HTTP_ParseCallback callback, void *userdata
){
    init_http_data(data);
    data -> fd = fd;
    data -> is_client = is_client;
    data -> cb = callback;
    data -> userdata = userdata;

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
    struct HTTP_Response *response = JS_GetOpaque2(ctx, this_val, response_class_id);
    return JS_NewInt32(ctx, response -> data -> status);
}

static JSValue js_response_get_ok(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque2(ctx, this_val, response_class_id);
    return JS_NewBool(ctx, response -> data -> status - 200 < 100);
}

static void callback_tou8(HTTP_data *data, uint8_t *buffer, uint32_t len, void *userdata){
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

static JSValue response_poll(JSContext* ctx, void* ptr, JSValue __){
    struct promise *promise = LJS_NewPromise(ctx);
    struct HTTP_Response *response = ptr;
    read_body(response -> data, callback_tou8, promise, false);
    return promise -> promise;
}

struct buf_link {
    uint8_t* buf;
    uint32_t len;
    
    struct list_head list;
};

struct readall_promise{
    struct promise *promise;
    struct list_head u8arrs;
    struct HTTP_Response *response;

    bool tostr;
    bool tojson;

    void* addition_data;
};

static inline struct readall_promise* init_tou8_merge_task(struct promise *promise, struct HTTP_Response *response){
    struct readall_promise *task = malloc(sizeof(struct readall_promise));
    task -> promise = promise;
    task -> response = response;
    task -> tostr = false;
    task -> tojson = false;
    task -> addition_data = NULL;
    init_list_head(&task -> u8arrs);
    return task;
}

static void callback_tou8_merge(HTTP_data *data, uint8_t *buffer, uint32_t len, void *userdata){
    struct readall_promise *task = userdata;

    if(data -> state == HTTP_DONE){
        // merge u8arrs
        struct list_head *tmp, *cur;
        int length = task -> response -> data -> content_read;
        JSContext* ctx = task -> promise -> ctx;
        uint8_t* merged_buf = js_malloc(ctx, length +1);
        int copy_len = 0;

        list_for_each_safe(cur, tmp, &task -> u8arrs){
            struct buf_link *bufobj = list_entry(cur, struct buf_link, list);
            memcpy(merged_buf + copy_len, bufobj -> buf, bufobj -> len);
            copy_len += bufobj -> len;
            free(bufobj -> buf);
            free(bufobj);
        }

        merged_buf[copy_len] = '\0';

        JSValue res;
        if(task -> tostr){
            res = JS_NewStringLen(ctx, (char*)merged_buf, length);
        }else if(task -> tojson){
            res = JS_ParseJSON(ctx, (char*)merged_buf, length, "<httpstream>.json");
        }else{
            res = JS_NewUint8Array(ctx, merged_buf, length, free_js_malloc, NULL, false);
        }
        LJS_Promise_Resolve(task -> promise, res);
        free(merged_buf);
        // after this, buffer=NULL will be passed to this again
    }else if(data -> state == HTTP_BODY){
        struct buf_link *bufobj = malloc(sizeof(struct buf_link));
        bufobj -> buf = buffer;
        bufobj -> len = len;
        list_add_tail(&bufobj -> list, &task -> u8arrs);
    }else if(NULL == buffer){
        struct list_head *tmp, *cur;
        list_for_each_safe(cur, tmp, &task -> u8arrs){
            struct buf_link *bufobj = list_entry(cur, struct buf_link, list);
            free(bufobj -> buf);
            free(bufobj);
        }

        struct promise *promise = task -> promise;
        // if(data -> state == HTTP_ERROR)
        LJS_Promise_Reject(promise, "Failed to receive data");
        // else
        //     LJS_Promise_Resolve(promise, )
        free(task); // done!
    }
}

struct formdata_t {
    char *name;
    char* type;
    char* filename;

    uint32_t length;
    uint8_t* data;

    struct list_head list;
};

enum FormDataState {
    FD_BOUNDARY,
    FD_NEWLINE,
    FD_HEADER,
    FD_DATA,
    FD_DONE
};

struct formdata_addition_data {
    enum FormDataState state;
    char* boundary;
    uint32_t readed;

    struct list_head formdata;  // 反序添加(add to tail)
};

static inline struct formdata_addition_data* init_formdata_parse_task(struct promise *promise, struct HTTP_Response *response){
    struct formdata_addition_data *task = malloc(sizeof(struct formdata_addition_data));
    task -> state = FD_BOUNDARY;
    task -> readed = 0;
    init_list_head(&task -> formdata);
    return task;
}

#define SET_IF_NOT_NULL(obj, prop, val) if(val){ \
    JS_SetPropertyStr(ctx, obj, prop, JS_NewString(ctx, val)); \
    free(val); \
}
#define FREE_IF_NOT_NULL(obj) if(obj) js_free(ctx, obj);

static int callback_formdata_parse(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* userdata){
    struct readall_promise *task = userdata;
    struct formdata_addition_data *fd_task = task -> addition_data;
    JSContext *ctx = task -> promise -> ctx;
    fd_task -> readed += read_size;

    // 空行
    if (fd_task -> state == FD_NEWLINE) {
        fd_task -> state = FD_HEADER;
        return EVCB_RET_CONTINUE;
    }

    // ------WebKitFormBoundaryABC123
    if (fd_task -> state == FD_BOUNDARY) {
        char* line = (char*) buffer;
        if (line[0] != '-' || line[1] != '-' || strcmp(line + 2, fd_task -> boundary) != 0) {
            // error
            LJS_Promise_Reject(task -> promise, "Invalid boundary");
            goto end;
        }
        fd_task -> state = FD_HEADER;
        return EVCB_RET_CONTINUE;
    }

    struct formdata_t* formdata = list_entry(fd_task -> formdata.next, struct formdata_t, list);

    // Content-Disposition: form-data; name="file"; filename="test.txt"
    if (fd_task -> state == FD_HEADER) {
        char* _line = (char*) buffer;
        TRIM_START(line, _line, read_size);

        if (line == NULL) {
            // end of header
            if (formdata -> length == 0) fd_task -> state = FD_NEWLINE;
            else fd_task -> state = FD_DATA;

            uint8_t* buf = js_malloc(ctx, formdata -> length);
            LJS_evfd_readsize(evfd, formdata -> length, buf, parse_evloop_body_callback, formdata);

            js_free(ctx, _line);
            return EVCB_RET_DONE;   // 切换模式
        }

        SPLIT_HEADER(line);
        if (!value) {
            // error
            LJS_Promise_Reject(task -> promise, "Invalid header");
            goto end_cleanup;
        }

        if (strcmp(name, "Content-Disposition") == 0) {
            char* filename = NULL;
            char* type = NULL;
            char* tmp = strchr(value, ';');
            if (tmp) {
                *tmp = '\0';
                tmp += 1;
                str_trim(tmp);
                char* tmp2 = strstr(tmp, "filename=");
                if (tmp2) {
                    tmp2 += 9;
                    str_trim(tmp2);
                    filename = strdup(tmp2);
                }
                tmp2 = strstr(tmp, "type=");
                if (tmp2) {
                    tmp2 += 5;
                    str_trim(tmp2);
                    type = strdup(tmp2);
                }
            } else {
                filename = strdup(value);
            }
            formdata -> filename = filename;
            formdata -> type = type;
        } else if (strcmp(name, "Content-Type") == 0) {
            formdata -> type = strdup(value);
        } else if (strcmp(name, "Content-Length") == 0) {
            int len = atoi(value);
            if (len < 0) {
                // error
                LJS_Promise_Reject(task -> promise, "Invalid content-length");
                goto end_cleanup;
            }
            formdata -> length = len;
        } else {
            // ignore
        }
        fd_task -> state = FD_DATA;
        return EVCB_RET_CONTINUE;
    }

    if (fd_task -> state == FD_DATA) {
        if (formdata -> length < read_size) {
            // error
            LJS_Promise_Reject(task -> promise, "Failed to receive data: short readed");
            goto end_cleanup;
        }

        // already recv all data
        formdata -> data = buffer;

        // end
        if(fd_task -> readed == formdata -> length) goto end_callback;

        // newline: the buffer will be reused for header
        fd_task -> state = FD_NEWLINE;
        uint8_t* buf = js_malloc(ctx, BUFFER_SIZE);
        LJS_evfd_readline(evfd, BUFFER_SIZE, buf, parse_evloop_body_callback, formdata);

        return EVCB_RET_DONE;
    }

struct list_head *tmp, *cur;
end_callback:
    JSValue array = JS_NewArray(ctx);
    uint32_t i = 0;
    
    list_for_each_safe(cur, tmp, &fd_task -> formdata){
        struct formdata_t *formdata = list_entry(cur, struct formdata_t, list);
        JSValue obj = JS_NewObject(ctx);
        SET_IF_NOT_NULL(obj, "name", formdata -> name);
        SET_IF_NOT_NULL(obj, "type", formdata -> type);
        SET_IF_NOT_NULL(obj, "filename", formdata -> filename);
        JS_SetPropertyStr(ctx, obj, "data", JS_NewUint8Array(ctx, formdata -> data, formdata -> length, free_js_malloc, NULL, false));
        JS_SetPropertyUint32(ctx, array, i++, obj);
        js_free(ctx, formdata);
    }

    JS_SetLength(ctx, array, i);
    JS_Call(ctx, task -> promise -> resolve, JS_UNDEFINED, 1, (JSValue[]){ array });
    goto end;

end_cleanup:
    list_for_each_safe(cur, tmp, &fd_task -> formdata){
        struct formdata_t *formdata = list_entry(cur, struct formdata_t, list);
        FREE_IF_NOT_NULL(formdata -> name);
        FREE_IF_NOT_NULL(formdata -> type);
        FREE_IF_NOT_NULL(formdata -> filename);
        FREE_IF_NOT_NULL(formdata -> data);
        FREE_IF_NOT_NULL(formdata);
    }

end:
    FREE_IF_NOT_NULL(buffer);
    // free promise
    free(fd_task);
    LJS_FreePromise(task -> promise);
    return EVCB_RET_DONE;
}

#define RESPONSE_GET_OPAQUE(var, this_val) \
    struct HTTP_Response *var = JS_GetOpaque2(ctx, this_val, response_class_id); \
    if(!var) return JS_EXCEPTION; \
    if(var -> locked) return LJS_Throw(ctx, "Body is locked", NULL);

static JSValue js_response_get_body(JSContext *ctx, JSValueConst this_val) {
    RESPONSE_GET_OPAQUE(response, this_val);

    response -> locked = true;
    JSValue pipe = LJS_NewU8Pipe(ctx, PIPE_READ, BUFFER_SIZE, response_poll, NULL, NULL, response);
    return pipe;
}

static JSValue js_response_get_locked(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque2(ctx, this_val, response_class_id);
    if(!response) return JS_EXCEPTION;
    return JS_NewBool(ctx, response -> locked);
}

#define INIT_TOU8_TASK \
    RESPONSE_GET_OPAQUE(response, this_val); \
    if(response -> data -> state != HTTP_BODY) return JS_ThrowTypeError(ctx, "Body is not available"); \
    struct promise *promise = LJS_NewPromise(ctx); \
    struct readall_promise* data = init_tou8_merge_task(promise, response); \
    read_body(response -> data, callback_tou8_merge, data, true);

static JSValue js_response_buffer(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    INIT_TOU8_TASK
    return promise -> promise;
}

static JSValue js_response_text(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    INIT_TOU8_TASK
    data -> tostr = true;
    return promise -> promise;
}

static JSValue js_response_json(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    INIT_TOU8_TASK
    data -> tojson = true;
    return promise -> promise;
}

static JSValue js_response_formData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    RESPONSE_GET_OPAQUE(response, this_val);

    // get form info
    char* boundary;
    for(uint32_t i = 0 ; i < response -> data -> header_count; i++){
        char* key = response -> data -> headers[i][0];
        char* value = response -> data -> headers[i][1];
        if(strncasecmp(key, "Content-Type", 12) == 0){
            char* bound = strstr(value, "boundary=");
            if(bound){
                bound += 9;
                str_trim(bound);
                boundary = bound;
                goto main;
            }else{
                goto not_found;   
            }
        }
    }

not_found:
    return LJS_Throw(ctx, "Invalid or missing content-type. Please ensure boundary is set", NULL);

main:
    struct promise *promise = LJS_NewPromise(ctx);
    struct formdata_addition_data* task = init_formdata_parse_task(promise, response);
    task -> boundary = boundary;
    uint8_t* buf = js_malloc(ctx, BUFFER_SIZE);
    LJS_evfd_readline(response -> data -> fd, BUFFER_SIZE, buf, callback_formdata_parse, task);
    return promise -> promise;
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
    JSValue obj = JS_NewObjectClass(ctx, response_class_id);
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

    JSValue headers = JS_NewObject(ctx);
    uint32_t count = response -> data -> header_count;
    for(uint32_t i = 0; i < count; i++){
        JS_SetPropertyStr(ctx, headers, response -> data -> headers[i][0], JS_NewString(ctx, response -> data -> headers[i][1]));
    }
    JS_DefinePropertyValueStr(ctx, obj, "headers", headers, 
        JS_PROP_CONFIGURABLE | JS_PROP_ENUMERABLE   // const
    );

    return obj;
}

static JSClassDef response_class = {
    "Response",
    .finalizer = js_response_finalizer
};
static JSCFunctionListEntry response_proto_funcs[] = {
    JS_CGETSET_DEF("status", js_response_get_status, NULL),
    JS_CGETSET_DEF("body", js_response_get_body, NULL),
    JS_CGETSET_DEF("locked", js_response_get_locked, NULL),
    JS_CGETSET_DEF("ok", js_response_get_ok, NULL),
    
    JS_CFUNC_DEF("bytes", 0, js_response_buffer),
    JS_CFUNC_DEF("text", 0, js_response_text),
    JS_CFUNC_DEF("json", 0, js_response_json),
    JS_CFUNC_DEF("formData", 0, js_response_formData)
};

// fetch API
struct keepalive_connection{
    int fd;
    bool free;
    struct list_head list;
};

static struct list_head keepalive_list = { 0, 0 };
static pthread_mutex_t keepalive_mutex;

// alert: buffer = NULL
void fetch_resolve(HTTP_data *data, uint8_t *buffer, uint32_t len, void* ptr){
    struct promise *promise = ptr;
    JSContext *ctx = promise -> ctx;
    JSValue obj = LJS_NewResponse(ctx, data);
    LJS_Promise_Resolve(promise, obj);
}

void ws_resolve(HTTP_data *data, uint8_t *buffer, uint32_t len, void* ptr){
    struct promise *promise = ptr;
    JSContext *ctx = promise -> ctx;
    JSValue obj = LJS_NewWebSocket(ctx, data -> fd, data -> is_client);
    LJS_Promise_Resolve(promise, obj);
}

bool body_chunked_filter(struct Buffer* buf, void* user_data){
    char chunk_header[14];
    uint32_t chunk_len = buffer_used(buf);
    uint8_t len = u32tohex(chunk_len, chunk_header);
    if(!len) return false;

    buffer_offset(buf, len +2, true);
    chunk_header[len ++] = '\r';
    chunk_header[len ++] = '\n';
    memcpy(buf -> buffer, chunk_header, len);
    return true;
}

static void fetch_close_cb(EvFD* evfd, void* user_data){
    struct promise *promise = user_data;
    LJS_Promise_Reject(promise, "Connection closed or failed");
}

static void write_then_free(EvFD* evfd, void* opaque){
    free(opaque);
}

static inline char* ws_random_key(){
    static uint8_t key[24];
    if(-1 == getrandom(key, 24, GRND_NONBLOCK))
        for (uint8_t i = 0; i < 24; i++) key[i] = (rand() >> 5) & 0xff;

    char* result = malloc(40);
    base64_encode(key, 24, result);
    return result;
}

#define FORMAT_WRITE(template, guessed_size, ...) { \
    char* buf = js_calloc(ctx, guessed_size, 1); \
    /* int len = */ snprintf(buf, guessed_size, template "\r\n", __VA_ARGS__); \
    LJS_evfd_write(fd, (uint8_t*) buf, /* len > guessed_size -1 ? guessed_size -1 : len */ strlen(buf), write_then_free, buf); \
}

#define WS_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static JSValue js_fetch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc == 0)
        return LJS_Throw(ctx, "Fetch requires at least 1 argument", "fetch(url: string, options?: FetchInit): Promise<Response>");
    
    // parse URL
    const char *urlstr = JS_ToCString(ctx, argv[0]);
    if(!urlstr) return JS_EXCEPTION;
    URL_data url = {};
    if(!LJS_parse_url(urlstr, &url, NULL) || url.protocol == NULL || url.host == NULL){
        JS_FreeCString(ctx, urlstr);
        return LJS_Throw(ctx, "Invalid URL", NULL);
    }
    JS_FreeCString(ctx, urlstr);
    
    if(strstr(url.protocol, "http") == NULL && strstr(url.protocol, "ws") == NULL){
        LJS_free_url(&url);
        return LJS_Throw(ctx, "Unsupported protocol %s", NULL, url.protocol);
    }

    JSValue obj = argc >= 2 ? JS_DupValue(ctx, argv[1]) : JS_NewObject(ctx);
    bool websocket = strstr(url.protocol, "ws") != NULL;

    // 获取连接
    EvFD* fd = NULL;
    if(JS_ToBool(ctx, JS_GetPropertyStr(ctx, obj, "keepalive"))){
        if(keepalive_list.prev == NULL){
            init_list_head(&keepalive_list);
            pthread_mutex_init(&keepalive_mutex, NULL);
        }
        pthread_mutex_lock(&keepalive_mutex);
        struct list_head *cur, *tmp;
        struct keepalive_connection *conn;
        list_for_each_safe(cur, tmp, &keepalive_list){
            conn = list_entry(cur, struct keepalive_connection, list);
            if(conn -> free){
                conn -> free = false;
                break;
            }
        }
        pthread_mutex_unlock(&keepalive_mutex);
    }
    if(!fd){
        // open new connection
        // ws -> tcp, wss -> ssl
        bool ssl = strlen(url.protocol) >= 3 && url.protocol[strlen(url.protocol) - 1] == 's';
        if(ssl){
#ifdef LJS_MBEDTLS
            // todo
#else
            return LJS_Throw(ctx, "SSL is not supported", NULL);
#endif
        }else{
            if(strstr(url.protocol, "+unix") != NULL){
                fd = LJS_open_socket("unix", url.host, -1, BUFFER_SIZE);
            }else{
                fd = LJS_open_socket("tcp", url.host, url.port, BUFFER_SIZE);
            }
        }
    }
    if(!fd) return LJS_Throw(ctx, "Failed to open connection", NULL);

    // close监听
    struct promise *promise = LJS_NewPromise(ctx);
    LJS_evfd_onclose(fd, fetch_close_cb, promise);

    // 解析参数
    // GET / HTTP/1.1
    char* method = (char*) LJS_ToCString(ctx, JS_GetPropertyStr(ctx, obj, "method"), NULL);
    if (!method) method = "GET";
    FORMAT_WRITE("%s %s HTTP/1.1", strlen(method) + strlen(url.path) + 16, method, url.path);

    // keep-alive
    bool keep_alive = JS_ToBool(ctx, JS_GetPropertyStr(ctx, obj, "keepalive"));
    if (keep_alive) {
        LJS_evfd_write(fd, (uint8_t*) "Connection: keep-alive\r\n", 25, NULL, NULL);
    }
    else {
        LJS_evfd_write(fd, (uint8_t*) "Connection: close\r\n", 20, NULL, NULL);
    }

    // referer
    const char* referer = LJS_ToCString(ctx, JS_GetPropertyStr(ctx, obj, "referer"), NULL);
    if (referer)
        FORMAT_WRITE("Referer: %s", strlen(referer) + 16, referer);

    // host
    if(JS_IsUndefined(JS_GetPropertyStr(ctx, obj, "host")))
        FORMAT_WRITE("Host: %s:%u", strlen(url.host) + 16, url.host, url.port);
    
    // websocket?
    if(websocket){
        // connection upgrade
        LJS_evfd_write(fd, (uint8_t*) "Connection: Upgrade\r\n", 22, NULL, NULL);
        LJS_evfd_write(fd, (uint8_t*) "Upgrade: websocket\r\n", 21, NULL, NULL);
        LJS_evfd_write(fd, (uint8_t*) "Sec-WebSocket-Version: 13\r\n", 31, NULL, NULL);
        char* key = ws_random_key();
        FORMAT_WRITE("Sec-WebSocket-Key: %s", 64, key);
        free(key);
    }

    // headers
    JSValue headers = JS_GetPropertyStr(ctx, obj, "headers");
    if (JS_IsObject(headers)) {
        JSPropertyEnum* props;
        uint32_t prop_count;
        if (JS_GetOwnPropertyNames(ctx, &props, &prop_count, headers, JS_GPN_STRING_MASK) == 0) {
            for (int i = 0; i < prop_count; i++) {
                if(!props[i].is_enumerable) continue;
                const char* key = JS_AtomToCString(ctx, props[i].atom);
                const char* value = JS_ToCString(ctx, JS_GetProperty(ctx, headers, props[i].atom));
                if (key && value) {
                    if (
                        strcasecmp(key, "method") == 0 || 
                        strcasecmp(key, "keepalive") == 0 || 
                        strcasecmp(key, "referer") == 0
                    ) {
                        continue;
                    }
                    size_t guess_len = strlen(key) + 2 + strlen(value) + 2;
                    char* buf = js_malloc(ctx, guess_len);
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
    if (JS_GetTypedArrayType(body) != -1 || JS_IsString(body)) {
        size_t data_len;
        uint8_t* data = JS_IsString(body) 
            ? (uint8_t*) JS_ToCStringLen(ctx, &data_len, body) 
            : JS_GetArrayBuffer(ctx, &data_len, body);
        if (data) {
            size_t len = 22 + sizeof(size_t);
            char* buf = js_malloc(ctx, len);
            snprintf(buf, len, "Content-Length: %lu\r\n\r\n", data_len);
            LJS_evfd_write(fd, (uint8_t*) buf, len, NULL, NULL);
            free(buf);
        }

        // 写入数据
        LJS_evfd_write(fd, data, data_len, NULL, NULL);
    }else{
        // pipeTo chunked
        EvFD* body_fd = LJS_GetPipeFD(ctx, body);
        if(!body_fd) {
            // content 0
            LJS_evfd_write(fd, (uint8_t*) "Content-Length: 0\r\n\r\n", 26, NULL, NULL);
        }else{
            LJS_evfd_pipeTo(fd, body_fd, body_chunked_filter, NULL, NULL, NULL);
        }
    }

    // 解析响应
    HTTP_data *data = js_malloc(ctx, sizeof(HTTP_data));
    LJS_parse_from_fd(fd, data, false, websocket ? ws_resolve : fetch_resolve, promise);
    LJS_free_url(&url);
    return promise -> promise;
}

// --------------------- JAVASCRIPT WebSocket API -------------------
static thread_local JSClassID ws_class_id;

struct WebSocketFrame {
    bool fin;
    bool mask;
    uint8_t opcode;
    uint64_t payload_len;
    uint8_t mask_key[4];
};

struct JSWebSocket_T{
    bool in_payload;
    bool enable_mask;

    EvFD* fd;

    JSContext *ctx;
    JSValue onmessage;
    JSValue onclose;

    struct Buffer rbuffer;
    struct WebSocketFrame frame;

    struct Buffer wbuffer;
    struct promise* send_promise;

    bool closed;
    uint8_t free_count;    // 引用计数
};

static int event_ws_readable(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data){
    struct JSWebSocket_T* ws = user_data;
    int fd = LJS_evfd_getfd(evfd, NULL);
    if(buffer_read(&ws -> rbuffer, fd, UINT32_MAX) <= 0) return 0;

    uint32_t bufsize = buffer_used(&ws -> rbuffer);

    if(!ws -> in_payload){
        if(bufsize < 4) return 0;
        bool completed = false;
        uint32_t payload_end_offset = 0;
        uint8_t payload_len[8];
        BUFFER_FOREACH_BYTE(&ws -> rbuffer, index, byte){
            if(index == 0){
                ws -> frame.fin = byte >> 7;
                ws -> frame.opcode = byte & 0xf;
            }else if(index == 1){
                ws -> frame.mask = byte >> 7;
                ws -> frame.payload_len = byte & 0x7f;
                if(ws -> frame.payload_len == 126){
                    payload_end_offset = 2 +2;
                }else if(ws -> frame.payload_len == 127){
                    payload_end_offset = 8 +2;
                }else{
                    payload_end_offset = 2;
                }
            }else if(index >= 2 && index < payload_end_offset){
#if __ORDER_BIG_ENDIAN__ == __BYTE_ORDER__
                payload_len[index - 2] = byte;
#else
                payload_len[7 - (index - 2)] = byte;
#endif
            }else if(ws -> frame.mask && index >= payload_end_offset && index < payload_end_offset + 4){
                ws -> frame.mask_key[index - payload_end_offset] = byte;
            }else{
                completed = true;
                break;
            }
        }

        if(completed){
            buffer_seek(&ws -> rbuffer, __i);
            if(ws -> frame.payload_len == 126){
                ws -> frame.payload_len = *(uint16_t*) payload_len;
            }else if(ws -> frame.payload_len == 127){
                ws -> frame.payload_len = *(uint64_t*) payload_len;
            }
            
            ws -> in_payload = true;
            goto check_payload;
        }
    }else{
check_payload:
        if(buffer_used(&ws -> rbuffer) >= ws -> frame.payload_len){
            uint8_t* buf = js_malloc(ws -> ctx, ws -> frame.payload_len);
            buffer_copyto(&ws -> rbuffer, buf, ws -> frame.payload_len);
            buffer_seek(&ws -> rbuffer, ws -> frame.payload_len + ws -> rbuffer.start);
            if(ws -> frame.mask){
                for(uint32_t i = 0; i < ws -> frame.payload_len; i++){
                    buf[i] ^= ws -> frame.mask_key[i % 4];
                }
            }
            JSValue array = JS_NewUint8Array(ws -> ctx, buf, ws -> frame.payload_len, free_js_malloc, NULL, false);

            assert(JS_IsFunction(ws -> ctx, ws -> onmessage));
            JS_Call(ws -> ctx, ws -> onmessage, JS_UNDEFINED, 2, (JSValueConst[]){ 
                array, JS_NewBool(ws -> ctx, ws -> frame.fin)
            });
            ws -> in_payload = false;
        }
    }

    return 0;
}

static void js_ws_free(JSRuntime *rt, struct JSWebSocket_T* ws){
    if(ws -> free_count < 2) return;
    if(!ws -> closed){
        LJS_evfd_close(ws -> fd);
        return; // will re-call this function
    }

    buffer_free(&ws -> rbuffer);
    buffer_free(&ws -> wbuffer);
    JS_FreeValue(ws -> ctx, ws -> onmessage);
    JS_FreeValue(ws -> ctx, ws -> onclose);
    
    js_free(ws -> ctx, ws);
}

static void event_ws_close(EvFD* evfd, void* user_data){
    struct JSWebSocket_T* ws = user_data;
    ws -> closed = true;
    ws -> free_count ++;
    if(JS_IsFunction(ws -> ctx, ws -> onclose)){
        JS_Call(ws -> ctx, ws -> onclose, JS_UNDEFINED, 0, NULL);
    }
    if(ws -> send_promise)
        LJS_Promise_Reject(ws -> send_promise, "WebSocket is already closed");

    js_ws_free(JS_GetRuntime(ws -> ctx), ws);
}

static void js_ws_finalizer(JSRuntime *rt, JSValue val){
    struct JSWebSocket_T* ws = JS_GetOpaque( val, ws_class_id);
    js_ws_free(rt, ws);
}

static void build_ws_frame(struct Buffer* buffer, bool fin, uint8_t opcode, uint8_t* data, uint32_t len, bool mask){
    uint8_t header[10] = { 0 };
    header[0] = fin << 7 | opcode;
    if(len < 126){
        header[1] = mask << 7 | len;
    }else if(len < 65536){
        header[1] = mask << 7 | 126;
        header[2] = len >> 8;
        header[3] = len & 0xff;
    }else{
        header[1] = mask << 7 | 127;
        // in LJS, max chunk size is 32-bit
        header[6] = (len >> 24) & 0xff;
        header[7] = (len >> 16) & 0xff;
        header[8] = (len >> 8) & 0xff;
        header[9] = len & 0xff;
    }
    buffer_push(buffer, header, 2 + (len < 126 ? 0 : (len < 65536 ? 2 : 8)));
    if(mask){
        uint8_t mask_key[4];
        int random = rand();
        memcpy(mask_key, &random, 4);
        buffer_push(buffer, mask_key, 4);
        for(uint32_t i = 0; i < len; i++){
            buffer_push(buffer, &data[i], 1);
            data[i] ^= mask_key[i % 4];
        }
    }else{
        buffer_push(buffer, data, len);
    }
    buffer_free(buffer);
}

static void event_ws_writable(EvFD* evfd, void* opaque){
    struct JSWebSocket_T* ws = opaque;
    if(!ws -> send_promise) return;
    buffer_write(&ws -> wbuffer, LJS_evfd_getfd(evfd, NULL), UINT32_MAX);
    if(buffer_used(&ws -> wbuffer) == 0){
        LJS_evfd_yield(evfd, false, true);
        LJS_Promise_Resolve(ws -> send_promise, JS_UNDEFINED);
        ws -> send_promise = NULL;
    }
}

static JSValue js_ws_send(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JSWebSocket_T* ws = JS_GetOpaque2(ctx, this_val, ws_class_id);
    if(!ws) return JS_EXCEPTION;

    if(ws -> closed){
        return LJS_Throw(ctx, "WebSocket is already closed", NULL);
    }
    if(argc != 1){
        return LJS_Throw(ctx, "WebSocket.send() requires 1 argument", "WebSocket.send(data: Uint8Array | string): Promise<void>");
    }

    uint8_t* data;
    size_t len;
    uint8_t opcode;
    if(JS_IsString(argv[0])){
        data = (void*)JS_ToCStringLen(ctx, &len, argv[0]);
        opcode = 1;
    }else if((data = JS_GetUint8Array(ctx, &len, argv[0])) != NULL){
        opcode = 2;
    }else{
        return LJS_Throw(ctx, "WebSocket.send() requires a string or Uint8Array argument", "WebSocket.send(data: Uint8Array | string): Promise<void>");
    }

    struct promise* promise = LJS_NewPromise(ctx);
    ws -> send_promise = promise;
    buffer_init2(&ws -> wbuffer, NULL, len + 16);
    build_ws_frame(&ws -> wbuffer, true, opcode, data, len, ws -> enable_mask);
    if(JS_IsString(argv[0])) JS_FreeCString(ctx, (void*)data);
    LJS_evfd_consume(ws -> fd, false, true);
    return promise -> promise;
}

static JSValue js_ws_set_onmessage(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    struct JSWebSocket_T* ws = JS_GetOpaque2(ctx, this_val, ws_class_id);
    if(!ws) return JS_EXCEPTION;
    JS_FreeValue(ctx, ws -> onmessage);
    ws -> onmessage = JS_DupValue(ctx, value);

    if(JS_IsUndefined(value)) LJS_evfd_yield(ws -> fd, true, false); // consume readable event
    else LJS_evfd_consume(ws -> fd, true, false); // consume readable event

    return JS_UNDEFINED;
}

static JSValue js_ws_get_onmessage(JSContext *ctx, JSValueConst this_val){
    struct JSWebSocket_T* ws = JS_GetOpaque2(ctx, this_val, ws_class_id);
    if(!ws) return JS_EXCEPTION;
    return JS_DupValue(ctx, ws -> onmessage);
}

static JSValue js_ws_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JSWebSocket_T* ws = JS_GetOpaque2(ctx, this_val, ws_class_id);
    if(!ws) return JS_EXCEPTION;
    if(ws -> closed){
        return LJS_Throw(ctx, "WebSocket is already closed", NULL);
    }
    ws -> closed = true;
    LJS_evfd_close(ws -> fd);
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry js_ws_proto_funcs[] = {
    JS_CFUNC_DEF("send", 1, js_ws_send),
    JS_CFUNC_DEF("close", 0, js_ws_close),
    JS_CGETSET_DEF("onmessage", js_ws_get_onmessage, js_ws_set_onmessage),
};

static const JSClassDef js_ws_class_def = {
    "WebSocket",
    .finalizer = js_ws_finalizer
};

static JSValue js_ws_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv){
    return LJS_Throw(ctx, "WebSocket constructor is not implemented, use fetch(ws://) instead", NULL);
}

JSValue LJS_NewWebSocket(JSContext *ctx, EvFD* fd, bool enable_mask){
    struct JSWebSocket_T* ws = js_malloc(ctx, sizeof(struct JSWebSocket_T));
    if(ws == NULL) return JS_EXCEPTION;
    memset(ws, 0, sizeof(struct JSWebSocket_T));
    ws -> fd = fd;
    ws -> enable_mask = enable_mask;
    ws -> ctx = ctx;
    ws -> onmessage = JS_UNDEFINED;
    // buffer_init(&ws -> rbuffer, NULL, 0);
    // buffer_init(&ws -> wbuffer, NULL, 0);

    JSValue pcb[2];
    JSValue promise = JS_NewPromiseCapability(ctx, pcb);
    JS_SetPropertyStr(ctx, promise, "onclose", promise);
    JS_FreeValue(ctx, pcb[1]);
    ws -> onclose = pcb[0];

    LJS_evfd_override(fd, 
        event_ws_readable, ws,
        event_ws_writable, ws,
        event_ws_close, ws
    );
    return JS_NewObjectClass(ctx, ws_class_id);
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
    URL_data *url_struct = js_malloc(ctx, sizeof(URL_data));
    struct JS_URL_struct *js_url_struct = js_malloc(ctx, sizeof(struct JS_URL_struct));
    if(url_struct == NULL || js_url_struct == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }
    memset(url_struct, 0, sizeof(URL_data));

    js_url_struct -> dup_count = 0;

    if(argc == 1){
        const char *url = JS_ToCString(ctx, argv[0]);
        if(url == NULL){
            free(url_struct);
            return LJS_Throw(ctx, "Invalid URL", NULL);
        }
        // 深拷贝
        LJS_parse_url(url, url_struct, NULL);
    }else if(argc == 2){
        const char *url = JS_ToCString(ctx, argv[0]);
        if(JS_IsObject(argv[1])){
            URL_data *base_url = JS_GetOpaque2(ctx, argv[1], js_class_url_id);
            if(base_url == NULL){
                free(url_struct);
                return LJS_Throw(ctx, "Invalid base URL", NULL);
            }
            // 创建引用
            js_url_struct -> template = JS_DupValue(ctx, argv[1]);
        }else{
            URL_data *base_url = js_malloc(ctx, sizeof(URL_data));
            if(base_url == NULL){
                free(url_struct);
                return JS_ThrowOutOfMemory(ctx);
            }
            memset(base_url, 0, sizeof(URL_data));
            const char *base_url_str = JS_ToCString(ctx, argv[1]);
            if(base_url_str == NULL){
                free(url_struct);
                return LJS_Throw(ctx, "Invalid base URL", NULL);
            }
            // 拷贝
            LJS_parse_url(base_url_str, base_url, NULL);
            js_url_struct -> base = base_url;
            // 解析
            LJS_parse_url(url, url_struct, base_url);
        }
    }else if(argc != 0){
        JS_ThrowTypeError(ctx, "URL constructor takes 0 or 1 argument");
        free(url_struct);
        return JS_EXCEPTION;
    }
    js_url_struct -> self = url_struct;
    return JS_NewObjectClass(ctx, js_class_url_id);
}

#define GETTER_STRING(func_name, field) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    URL_data *url_struct = js_url_struct -> self; \
    return (url_struct -> field) ? JS_NewString(ctx, url_struct -> field) : JS_UNDEFINED; \
}

#define GETTER_INT(func_name, field, invalid_value) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    URL_data *url_struct = js_url_struct -> self; \
    return (url_struct -> field == invalid_value) ? JS_UNDEFINED : JS_NewInt32(ctx, url_struct -> field); \
}

#define SETTER_STRING_DUP(func_name, field, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    const char *str = JS_ToCString(ctx, value); \
    if (!str) return LJS_Throw(ctx, err_msg, NULL); \
    js_url_struct -> dup_value[js_url_struct -> dup_count++] = JS_DupValue(ctx, value); \
    js_url_struct -> self -> field = (char*)str; \
    return JS_UNDEFINED; \
}

#define SETTER_STRING_COPY(func_name, field, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    const char *str = JS_ToCString(ctx, value); \
    if (!str) return LJS_Throw(ctx, err_msg, NULL); \
    free(js_url_struct -> self -> field); \
    js_url_struct -> self -> field = strdup(str); \
    JS_FreeCString(ctx, str); \
    return JS_UNDEFINED; \
}

#define SETTER_INT_RANGE(func_name, field, min, max, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    int32_t val; \
    if (JS_ToInt32(ctx, &val, value) < 0) return LJS_Throw(ctx, err_msg, NULL); \
    if (val < min || val > max) return JS_ThrowRangeError(ctx, #field " out of range"); \
    js_url_struct -> self -> field = val; \
    return JS_UNDEFINED; \
}

/* 生成getter方法 */
GETTER_STRING(js_url_getProtocol, protocol)
GETTER_STRING(js_url_getHost, host)
GETTER_STRING(js_url_getPath, path)
GETTER_STRING(js_url_getHash, hash)
GETTER_STRING(js_url_getUsername, username)
GETTER_STRING(js_url_getPassword, password)
GETTER_INT(js_url_getPort, port, 0)

/* 生成setter方法 */
SETTER_STRING_DUP(js_url_setProtocol, protocol, "Invalid protocol")
SETTER_STRING_DUP(js_url_setHost, host, "Invalid host")
SETTER_STRING_DUP(js_url_setUsername, username, "Invalid username")
SETTER_STRING_DUP(js_url_setPassword, password, "Invalid password")
SETTER_STRING_COPY(js_url_setPath, path, "Invalid path")
SETTER_STRING_COPY(js_url_setHash, hash, "Invalid hash")
SETTER_INT_RANGE(js_url_setPort, port, 0, 65535, "Invalid port")

JSValue js_url_addQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
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
        URL_query_data *query_list = js_malloc(ctx, sizeof(URL_query_data) * MAX_QUERY_COUNT);
        if(query_list == NULL){
            return JS_ThrowOutOfMemory(ctx);
        }
        memset(query_list, 0, sizeof(URL_query_data) * MAX_QUERY_COUNT);
        url_struct -> query = query_list;
    }

    for(uint32_t i = 0; i < MAX_QUERY_COUNT; i++){
        if(url_struct -> query[i].key == NULL){
            if(value == NULL){
                url_struct -> query[i].key = js_malloc(ctx, strlen(key) + 1);
                if(url_struct -> query[i].key == NULL){
                    return JS_ThrowOutOfMemory(ctx);
                }
                memcpy(url_struct -> query[i].key, key, strlen(key) + 1);
            }else{
                url_struct -> query[i].key = js_malloc(ctx, strlen(key) + 1);
                if(url_struct -> query[i].key == NULL){
                    return JS_ThrowOutOfMemory(ctx);
                }
                url_struct -> query[i].value = js_malloc(ctx, strlen(value) + 1);
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

JSValue js_url_delQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
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


static JSValue js_url_toString(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    char *url_str = js_malloc(ctx, 1024);
    if(url_str == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }

    char* data = LJS_format_url(url_struct);
    JSValue url_val = JS_NewString(ctx, data);
    free(data);
    return url_val;
}


static JSValue js_url_getQueryStr(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    if(url_struct -> query == NULL){
        return JS_UNDEFINED;
    }
    char *query_str = js_malloc(ctx, 1024);
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
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
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


JSValue js_url_setQueryStr(JSContext *ctx, JSValueConst this_val, JSValue value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *query = JS_ToCString(ctx, value);
    if(query == NULL){
        return LJS_Throw(ctx, "Invalid query string", NULL);
    }
    URL_query_data* query_list = js_malloc(ctx, sizeof(URL_query_data) * MAX_QUERY_COUNT);
    char* query_str = strdup(query);
    if(!LJS_parse_query(query_str, &query_list, MAX_QUERY_COUNT)){
        return LJS_Throw(ctx, "Failed to parse query string", NULL);
    }
    url_struct -> query_string = query_str;
    url_struct -> query = query_list;
    return JS_UNDEFINED;
}

static void js_url_finalizer(JSRuntime *rt, JSValue val) {
    struct JS_URL_struct *js_url_struct = JS_GetOpaque( val, js_class_url_id);
    if (!js_url_struct) return;
    
    URL_data *url = js_url_struct -> self;

#define FREE_FIELD(field) do { if(url -> field) free(url -> field); } while(0)
    FREE_FIELD(protocol);
    FREE_FIELD(host);
    FREE_FIELD(path);
    FREE_FIELD(username);
    FREE_FIELD(password);
    FREE_FIELD(hash);
#undef FREE_FIELD
    
    if (url -> query) {
        for (uint32_t i = 0; i < MAX_QUERY_COUNT; i++) {
            free(url -> query[i].key);
            free(url -> query[i].value);
        }
        free(url -> query);
    }
    
    for (uint32_t i = 0; i < js_url_struct -> dup_count; i++) {
        JS_FreeValueRT(rt, js_url_struct -> dup_value[i]);
    }
    js_free_rt(rt, js_url_struct);
}

static JSValue js_url_proto_canParse(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsString(argv[0]))
        return LJS_Throw(ctx, "Invalid arguments", "URL.canParse(url: string, baseURL?: string): boolean\n for more, please see https://developer.mozilla.org/zh-CN/docs/Web/API/URL/canParse_static");

    // url
    const char *url = JS_ToCString(ctx, argv[0]);
    if(!url) return JS_EXCEPTION;

    // base url
    URL_data url_base_struct;
    char* base_url_str = NULL;
    if(argc == 2){
        const char* base_url = JS_ToCString(ctx, argv[1]);
        if(base_url){
            if(!LJS_parse_url(base_url, &url_base_struct, NULL)){
                js_free(ctx, base_url_str);
                return JS_FALSE;
            }
            JS_FreeCString(ctx, base_url);
        }
    }
    
    // parse
    URL_data url_struct;
    bool result = LJS_parse_url(url, &url_struct, &url_base_struct);
    JS_FreeCString(ctx, url);

    // free
    LJS_free_url(&url_struct);
    LJS_free_url(&url_base_struct);
    if(base_url_str) js_free(ctx, base_url_str);
    
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

// --------------- CookieJar -----------------------
struct CookiePair {
    char *name;
    char *value;
    char* modify;   // optional!
};

struct CookieJar {
    struct CookiePair *pairs;
    int count;
    int capacity;
    uint8_t ref_count;

    struct CookiePair **modified;
    int mod_count;
    int mod_capacity;
};

void init_cookie_jar(struct CookieJar *jar, int initial_capacity) {
    jar -> pairs = (struct CookiePair *)malloc(initial_capacity * sizeof(struct CookiePair));
    jar -> count = 0;
    jar -> capacity = initial_capacity;
    jar -> ref_count = 1;
    jar -> modified = NULL;
    jar -> mod_count = 0;
    jar -> mod_capacity = 0;
}

static void mark_modified(struct CookieJar *jar, struct CookiePair *pair) {
    for (int i = 0; i < jar -> mod_count; i++) {
        if (jar -> modified[i] == pair) return;
    }

    if (jar -> mod_count >= jar -> mod_capacity) {
        jar -> mod_capacity += 8;
        jar -> modified = realloc(jar -> modified, 
            jar -> mod_capacity * sizeof(struct CookiePair*));
    }

    jar -> modified[jar -> mod_count++] = pair;
}

void free_cookie_jar(struct CookieJar *jar) {
    assert(jar -> ref_count == 0);    // self-ref
    for (int i = 0; i < jar -> count; i++) {
        free(jar -> pairs[i].name);
        free(jar -> pairs[i].value);
    }
    free(jar -> pairs);
    jar -> count = 0;
    jar -> capacity = 0;
    jar -> mod_count = 0;
    jar -> mod_capacity = 0;
    free(jar -> modified);
}

void set_cookie_pair(struct CookieJar *jar, const char *name, const char *value) {
    for (int i = 0; i < jar -> count; i++) {
        if (strcmp(jar -> pairs[i].name, name) == 0) {
            free(jar -> pairs[i].value);
            jar -> pairs[i].value = strdup(value);
            
            if (value[0] == '\0') {
                free(jar -> pairs[i].name);
                if (i < jar -> count - 1) {
                    jar -> pairs[i] = jar -> pairs[jar -> count - 1];
                }
                jar -> count--;
            }

            mark_modified(jar, &jar -> pairs[i]);
            return;
        }
    }

    // New CookiePair
    if (jar -> count >= jar -> capacity) {
        jar -> capacity = jar -> capacity ? jar -> capacity * 2 : 4;
        jar -> pairs = (struct CookiePair *)realloc(
            jar -> pairs, 
            jar -> capacity * sizeof(struct CookiePair)
        );
    }
    
    jar -> pairs[jar -> count].name = strdup(name);
    jar -> pairs[jar -> count].value = strdup(value);
    jar -> count++;
    mark_modified(jar, &jar -> pairs[jar -> count]);
}

struct CookiePair** get_modified_cookies(struct CookieJar *jar, int *count) {
    *count = jar -> mod_count;
    return jar -> modified;
}

// 解析Cookie字符串
void parse_set_cookie(struct CookieJar *jar, const char *set_cookie_str) {
    const char *p = set_cookie_str;
    const char *name_start = NULL;
    const char *value_start = NULL;
    
    // 跳过前导空格
    while (*p && isspace(*p)) p++;
    
    // 解析name
    name_start = p;
    while (*p && *p != '=' && !isspace(*p)) p++;
    if (*p != '=') return;
    
    size_t name_len = p - name_start;
    char *name = strndup(name_start, name_len);
    
    p++; // 跳过'='
    
    // 解析value
    while (*p && isspace(*p)) p++;
    value_start = p;
    while (*p && *p != ';') p++;
    size_t value_len = p - value_start;
    char *value = strndup(value_start, value_len);
    
    // 覆盖已存在的同名cookie
    for (int i = 0; i < jar -> count; i++) {
        if (strcmp(jar -> pairs[i].name, name) == 0) {
            free(jar -> pairs[i].value);
            jar -> pairs[i].value = strdup(value);
            free(name);
            free(value);
            return;
        }
    }
    
    // 新增cookie
    set_cookie_pair(jar, name, value);
    free(name);
    free(value);
}

// 增强原始解析函数
void parse_cookie_string(struct CookieJar *jar, const char *cookie_str) {
    const char *p = cookie_str;
    
    while (*p) {
        // 跳过空格和分号
        while (*p && (isspace(*p) || *p == ';')) p++;
        if (!*p) break;
        
        // 解析name
        const char *name_start = p;
        while (*p && *p != '=' && !isspace(*p)) p++;
        if (*p != '=') continue;
        
        size_t name_len = p - name_start;
        char *name = strndup(name_start, name_len);
        
        p++; // 跳过'='
        
        // 解析value
        while (*p && isspace(*p)) p++;
        const char *value_start = p;
        while (*p && *p != ';') p++;
        size_t value_len = p - value_start;
        char *value = strndup(value_start, value_len);
        
        // 追加cookie（不覆盖）
        set_cookie_pair(jar, name, value);
        
        free(name);
        free(value);
    }
}

// 查找特定cookie的值
const char *get_cookie_value(struct CookieJar *jar, const char *name) {
    for (int i = 0; i < jar -> count; i++) {
        if (strcmp(jar -> pairs[i].name, name) == 0) {
            return jar -> pairs[i].value;
        }
    }
    return NULL;
}

static thread_local JSClassID cookie_jar_class_id;

static JSValue js_cookies_set(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    CHECK_ARGS(2, "cookies.set(name: string, value: string): void", JS_TAG_STRING, JS_TAG_STRING);
    struct CookieJar* jar = JS_GetOpaque2(ctx, this_val, cookie_jar_class_id);
    if(!jar) return JS_EXCEPTION;
    const char* name = JS_ToCString(ctx, argv[0]);
    const char* value = JS_ToCString(ctx, argv[1]);
    if(!name ||!value) return JS_EXCEPTION;

    set_cookie_pair(jar, name, value);

    JS_FreeCString(ctx, name);
    JS_FreeCString(ctx, value);
    return JS_UNDEFINED;
}

static JSValue js_cookies_get(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    CHECK_ARGS(1, "cookies.get(name: string): string | null", JS_TAG_STRING);
    struct CookieJar* jar = JS_GetOpaque2(ctx, this_val, cookie_jar_class_id);
    if(!jar) return JS_EXCEPTION;
    const char* name = JS_ToCString(ctx, argv[0]);
    if(!name) return JS_EXCEPTION;

    const char* value = get_cookie_value(jar, name);
    JSValue result = JS_NewString(ctx, value? value : "");

    JS_FreeCString(ctx, name);
    return result;
}

static JSValue js_cookies_getAll(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct CookieJar* jar = JS_GetOpaque2(ctx, this_val, cookie_jar_class_id);
    if(!jar) return JS_EXCEPTION;

    JSValue result = JS_NewObject(ctx);
    for (int i = 0; i < jar -> count; i++) {
        JSValue name_val = JS_NewString(ctx, jar -> pairs[i].name);
        JSValue value_val = JS_NewString(ctx, jar -> pairs[i].value);
        JSValue arr = JS_NewArrayFrom(ctx, 2, (JSValueConst[]){name_val, value_val});
        JS_SetPropertyUint32(ctx, result, i, arr);
    }
    return result;
}

static JSValue js_cookies_del(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    CHECK_ARGS(1, "cookies.del(name: string): void", JS_TAG_STRING);
    struct CookieJar* jar = JS_GetOpaque2(ctx, this_val, cookie_jar_class_id);
    if(!jar) return JS_EXCEPTION;
    const char* name = JS_ToCString(ctx, argv[0]);
    if(!name) return JS_EXCEPTION;

    for (int i = 0; i < jar -> count; i++) {
        if (strcmp(jar -> pairs[i].name, name) == 0) {
            free(jar -> pairs[i].name);
            free(jar -> pairs[i].value);
            jar -> pairs[i] = jar -> pairs[jar -> count - 1];
            jar -> count--;
            break;
        }
    }

    JS_FreeCString(ctx, name);
    return JS_UNDEFINED;
}

static JSValue js_cookies_toString(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct CookieJar* jar = JS_GetOpaque2(ctx, this_val, cookie_jar_class_id);
    if(!jar) return JS_EXCEPTION;

    char* cookie_str = js_malloc(ctx, 1);
    cookie_str[0] = '\0';
    for (int i = 0; i < jar -> count; i++) {
        char* pair_str = js_malloc(ctx, strlen(jar -> pairs[i].name) + strlen(jar -> pairs[i].value) + 3);
        sprintf(pair_str, "%s=%s", jar -> pairs[i].name, jar -> pairs[i].value);
        cookie_str = js_realloc(ctx, cookie_str, strlen(cookie_str) + strlen(pair_str) + 1);
        strcat(cookie_str, pair_str);
        free(pair_str);
    }
    JSValue result = JS_NewString(ctx, cookie_str);
    free(cookie_str);
    return result;
}

static JSValue js_cookies_fromSetCookies(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    CHECK_ARGS(1, "cookies.fromCookies(setHeaderField: Arrar<string>): void", JS_TAG_OBJECT);
    struct CookieJar* jar = JS_GetOpaque2(ctx, this_val, cookie_jar_class_id);
    int64_t length;
    if(!jar || JS_GetLength(ctx, argv[0], &length) == -1) return JS_EXCEPTION;

    for(int64_t i = 0; i < length; i++){
        const char* str = LJS_ToCString(ctx, JS_GetPropertyUint32(ctx, argv[0], i), NULL);
        if(!str) continue;   // ignore invalid value

        parse_set_cookie(jar, str);
    }

    return JS_UNDEFINED;
}


static JSValue js_cookies_fromCookies(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    CHECK_ARGS(1, "cookies.fromCookies(setHeaderFields: Array<string>): void", JS_TAG_OBJECT);
    struct CookieJar* jar = JS_GetOpaque2(ctx, this_val, cookie_jar_class_id);
    int64_t length;
    
    if(!jar || JS_GetLength(ctx, argv[0], &length) == -1) 
        return JS_EXCEPTION;

    for(int64_t i = 0; i < length; i++){
        JSValue header_val = JS_GetPropertyUint32(ctx, argv[0], i);
        const char* str = JS_ToCString(ctx, header_val);
        if(!str) continue;   // ignore invalid value
        parse_cookie_string(jar, str);
        JS_FreeCString(ctx, str);
    }
    return JS_UNDEFINED;
}

static JSValue js_cookies_constructor(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    CHECK_ARGS(1, "new Cookies(cookie: Array<[string, string]> | Record<string, string>): CookieJar", JS_TAG_OBJECT);

    struct CookieJar* jar = js_malloc(ctx, sizeof(struct CookieJar));
    if(JS_IsArray(argv[0])){
        int64_t length;
        if(!JS_GetLength(ctx, argv[0], &length)) return JS_EXCEPTION;
        init_cookie_jar(jar, length);
    }else{
        JSPropertyEnum* properties;
        uint32_t count;
        if(JS_GetOwnPropertyNames(ctx, &properties, &count, argv[0], JS_GPN_STRING_MASK) == -1) return JS_EXCEPTION;
        init_cookie_jar(jar, count);
        for(uint32_t i = 0; i < count; i++){
            if(!properties[i].is_enumerable) continue;
            const char* name = JS_AtomToCString(ctx, properties[i].atom);
            const char* value = JS_ToCString(ctx, JS_GetProperty(ctx, argv[0], properties[i].atom ));
            set_cookie_pair(jar, name, value);
            JS_FreeCString(ctx, name);
            JS_FreeCString(ctx, value);
        }
        JS_FreePropertyEnum(ctx, properties, count);
    }

    JSValue obj = JS_NewObjectClass(ctx, cookie_jar_class_id);
    JS_SetOpaque(obj, jar);
    return obj;
}

static inline void js_cookies_cleanup(JSRuntime *rt, struct CookieJar* jar){
    free_cookie_jar(jar);
    js_free_rt(rt, jar);
}

static void js_cookies_finalizer(JSRuntime *rt, JSValue val){
    struct CookieJar* cookies = JS_GetOpaque(val, cookie_jar_class_id);

    cookies -> ref_count --;
    if(cookies -> ref_count == 0) js_cookies_cleanup(rt, cookies);
}

static const JSCFunctionListEntry cookie_jar_funcs[] = {
    JS_CFUNC_DEF("set", 2, js_cookies_set),
    JS_CFUNC_DEF("get", 1, js_cookies_get),
    JS_CFUNC_DEF("getAll", 0, js_cookies_getAll),
    JS_CFUNC_DEF("del", 1, js_cookies_del),
    JS_CFUNC_DEF("toString", 0, js_cookies_toString),
    JS_CFUNC_DEF("fromCookies", 1, js_cookies_fromCookies),
    JS_CFUNC_DEF("fromSetCookies", 1, js_cookies_fromSetCookies),
};

static const JSClassDef cookie_jar_class = {
    "CookieJar",
    .finalizer = js_cookies_finalizer,
};

// ---------------- HTTP server --------------------
static thread_local JSClassID handler_class_id;

// Handler.from() return a Promise
struct JSClientAsyncResult {
    struct promise* promise;
    struct JSClientHandler* handler;
    JSValue reusing_obj;    // if reuse(), return myself
};

struct JSClientHandler {
    EvFD* fd;
    JSContext* ctx;
    HTTP_data request;
    HTTP_data response;
    bool header_sent;
    bool destroy;       // ws? closed?
    void* sending_data; // processing

    struct CookieJar cookiejar; // note: ref_count is used to manage lifetime of handler

    struct promise* promise;

    struct list_head chunks;
};

struct JSChunkData {
    size_t len;
    uint8_t* data;

    struct list_head link;
};

struct JSEventStreamData {
    size_t len;
    const char** data;  // splited by \r\n
    const char* id;
    char** headers[MAX_HEADER_COUNT];
    uint32_t header_count;
    uint32_t header_writed;

    struct list_head link;
};

#define FIND_HEADER(httpdata, name) \
    for(uint32_t i = 0; i < httpdata.header_count; i++) \
        if(strcmp(httpdata.headers[i][0], name) == 0) \

#define GET_OPAQUE(this_val) struct JSClientHandler* handler = JS_GetOpaque2(ctx, this_val, handler_class_id);  \
    if(!handler) return JS_EXCEPTION;
    
#define DEF_END_PROMISE(obj, handler) handler -> promise = LJS_NewPromise(ctx); \
    JS_SetPropertyStr(ctx, obj, "done", handler -> promise -> promise);
#define DEF_RESPONSE(obj, handler) { \
    JSValue response_obj = JS_NewObjectClass(ctx, response_class_id); \
    JS_SetOpaque(response_obj, &handler -> request); \
    JS_SetPropertyStr(ctx, obj, "request", response_obj); \
}

static void handler_close_cb(EvFD* fd, void* data){
    struct JSClientHandler* handler = data;
    if(handler -> destroy) return;
    handler -> destroy = true;
    if(handler -> promise){
        LJS_Promise_Reject(handler -> promise, "Connection closed");
        free(handler);
    }
}

static void handler_parse_cb(HTTP_data *data, uint8_t *buffer, uint32_t len, void* ptr){
    struct JSClientAsyncResult* async_result = ptr;
    struct JSClientHandler* handler = async_result -> handler;
    JSContext* ctx = handler -> ctx;
    bool error = data -> state == HTTP_ERROR;
    
    if(error){
        LJS_Promise_Reject(async_result -> promise, "Failed to parse request: Invaild request");
        free(async_result);
        free(handler);
    }else if(!JS_IsUndefined(async_result -> reusing_obj)){
        LJS_evfd_onclose(handler -> fd, handler_close_cb, handler);
        LJS_Promise_Resolve(async_result -> promise, async_result -> reusing_obj);
        free(async_result);
    }else{
        JSValue obj = JS_NewObjectClass(ctx, handler_class_id);
        JS_SetOpaque(obj, handler);
        DEF_END_PROMISE(obj, handler);
        DEF_RESPONSE(obj, handler);

        // parse Cookie header
        if(handler -> cookiejar.capacity > 0){ 
            handler -> cookiejar.ref_count --;
            free_cookie_jar(&handler -> cookiejar);
        }
        bool has_cookie = false;
        FIND_HEADER(handler -> request, "cookie"){
            if(handler -> cookiejar.count == 0){
                init_cookie_jar(&handler -> cookiejar, 16);
                handler -> cookiejar.ref_count ++;  // note: avoid free_cookie_jar(), this will trigger SIGSEGV
            }
            parse_cookie_string(&handler -> cookiejar, handler -> request.headers[i][1]);
            has_cookie = true;
        }

        if(has_cookie){
            JSAtom atom = JS_NewAtom(ctx, "cookies");
            if(JS_HasProperty(ctx, obj, atom)) JS_FreeValue(ctx, JS_GetProperty(ctx, obj, atom));
            JSValue cookie_jar = JS_NewObjectClass(ctx, cookie_jar_class_id);
            JS_SetOpaque(cookie_jar, &handler -> cookiejar);
            JS_SetProperty(ctx, obj, atom, cookie_jar);
            JS_FreeAtom(ctx, atom);
        }

        LJS_Promise_Resolve(async_result -> promise, obj);
        free(async_result);
    }
}

static inline void init_handler(EvFD* fd, JSContext* ctx, struct JSClientHandler* handler){
    handler -> fd = fd;
    handler -> ctx = ctx;
    init_list_head(&handler -> chunks);
    handler -> header_sent = false;
    handler -> sending_data = NULL;
    handler -> promise = NULL;  // note: use DEF_END_PROMISE() to set it
    handler -> destroy = false;
    init_http_data(&handler -> response);
    LJS_parse_from_fd(fd, &handler -> request, true, handler_parse_cb, handler);
}

static inline struct JSClientAsyncResult* init_async_result(struct JSClientHandler* handler){
    struct JSClientAsyncResult* async_result = js_malloc(handler -> ctx, sizeof(struct JSClientAsyncResult));
    if(!async_result) return NULL;
    async_result -> promise = LJS_NewPromise(handler -> ctx);
    async_result -> handler = handler;
    async_result -> reusing_obj = JS_UNDEFINED; // if reuse(), please set it after this
    return async_result;
}

static JSValue js_handler_status(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    CHECK_ARGS(1, "status(code: number): void", JS_TAG_INT);
    GET_OPAQUE(this_val);

    int32_t code;
    if(JS_ToInt32(ctx, &code, argv[0]) == -1 || code < 100 || code > 599)
        return JS_ThrowTypeError(ctx, "Invalid status code");

    handler -> response.status = code;
    return this_val;
}

static JSValue js_handler_header(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    // CHECK_ARGS(1, "hander(name: string, value: string | null): void", JS_TAG_STRING, JS_TAG_STRING);
    GET_OPAQUE(this_val);

    if(
        argc == 0 ||
        (argc == 1 && !JS_IsString(argv[0])) ||
        (argc == 2 && (!JS_IsString(argv[0]) || (!JS_IsNull(argv[1]) && !JS_IsString(argv[1])) || !JS_IsArray(argv[1])))
    ) return LJS_Throw(ctx, "Invalid arguments", "handler.header(name: string, value?: string | null | string[]): void");

    const char* name = JS_ToCString(ctx, argv[0]);
    const char* value = argc == 1 ? NULL : LJS_ToCString(ctx, argv[1], NULL);
    if(!name) return JS_EXCEPTION;

    FIND_HEADER(handler -> response, name){
        if(value){
            handler -> response.headers[i][1] = js_strdup(ctx, value);
        }else{
            // free header
            char** current_el = handler -> response.headers[i];
            free(current_el[0]);
            free(current_el[1]);
            free(current_el);

            // move last header to current position
            char** endel = handler -> response.headers[handler -> response.header_count - 1];
            handler -> response.headers[i] = endel;
        }
        goto free;
    }

    // not found, add new header
    char** header = js_malloc(ctx, 2 * sizeof(char*));
    handler -> response.headers[handler -> response.header_count ++] = header;
    header[0] = js_strdup(ctx, name);
    header[1] = js_strdup(ctx, value);

    if(strcasecmp(name, "transfer-encoding") == 0 && strcasecmp(value, "chunked") == 0){
        handler -> response.chunked = true;
    }

free:
    JS_FreeCString(ctx, name);
    JS_FreeCString(ctx, value);
    return this_val;
}

static inline void chunk_append(JSContext* ctx, struct list_head* list, uint8_t* data, size_t len){
    struct JSChunkData* chunk = js_malloc(ctx, sizeof(struct JSChunkData) + len);
    if(!chunk) return;
    chunk -> len = len;
    memcpy(chunk -> data, data, len);
    list_add_tail(&chunk -> link, list);
}

static inline void write_chunk(JSContext* ctx, EvFD* fd, uint8_t* data, size_t len){
    FORMAT_WRITE("%zx\r\n", 16, len);
    LJS_evfd_write(fd, data, len, write_then_free, data);
}

static JSValue js_handler_send(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
#define TYPE_DECLARE "handler.send(data: string | ArrayBuffer | Uint8Array): void"
    
    if(argc == 0) return LJS_Throw(ctx, "Too few arguments, expect 1, got 0", TYPE_DECLARE);
    GET_OPAQUE(this_val);

    uint8_t* data;
    size_t len;
    if(JS_IsString(argv[0])){
        data = (void*)JS_ToCStringLen(ctx, &len, argv[0]);
    }else if(JS_IsArrayBuffer(argv[0])){
        data = JS_GetArrayBuffer(ctx, &len, argv[0]);
    }else if(JS_GetTypedArrayType(argv[0]) == JS_TYPED_ARRAY_UINT8){
        data = JS_GetUint8Array(ctx, &len, argv[0]);
    }else{
        return LJS_Throw(ctx, "Invalid argument type, expect string or array buffer", TYPE_DECLARE);
    }

    if(handler -> response.chunked){
        // header not writed yet
        if(handler -> header_sent && list_empty(&handler -> chunks)){
            chunk_append(ctx, &handler -> chunks, data, len);
        }else{
            uint8_t* chunked = js_malloc(ctx, len + 16);
            if(!chunked){
                JS_ThrowOutOfMemory(ctx);
                goto error;
            }

            int written = snprintf((char*)chunked, len + 16, "%zx\r\n", len);
            if(written < 0) goto error;

            memcpy(chunked + written, data, len);
            chunked[written + len] = '\r';
            chunked[written + len + 1] = '\n';
            LJS_evfd_write(handler -> fd, chunked, len + written + 2, write_then_free, chunked);
        }
    }else{
        if(handler -> header_sent && list_empty(&handler -> chunks)){
            // cache
            chunk_append(ctx, &handler -> chunks, data, len);
        }else if(handler -> response.content_length >= handler -> response.content_read + len){
            // continue feed data
            len = handler -> response.content_length - handler -> response.content_read;
            uint8_t* data2 = js_malloc(ctx, len);
            memcpy(data2, data, len);   // avoid free after this function return
            LJS_evfd_write(handler -> fd, data2, len, write_then_free, data);
        }else{
            LJS_Throw(ctx, "body already sent, cannot send more data.",
                "If you want to send more data, please use chunked transfer-encoding or set larger content-length"
            );
            goto error;
        }
    }

    return this_val;

#undef TYPE_DECLARE
error:
    if(JS_IsString(argv[0])) JS_FreeCString(ctx, (const char*)data);
    return JS_EXCEPTION;
}

// TODO: eventstream
static void handler_wbody_sync(EvFD* fd, void* data){
    struct JSClientHandler* handler = data;
    if(handler -> sending_data) free(handler -> sending_data);

    if(list_empty(&handler -> chunks)){
        LJS_Promise_Resolve(handler -> promise, JS_UNDEFINED);
        handler -> promise = NULL;
        return;
    }
    struct list_head* cur = handler -> chunks.prev;
    struct JSChunkData* chunk = list_entry(cur, struct JSChunkData, link);
    if (handler -> response.chunked) {
        // write chunk
        JSContext* ctx = handler -> ctx;
        FORMAT_WRITE("%zx\r\n", 16, chunk -> len);
        LJS_evfd_write(fd, chunk -> data, chunk -> len, handler_wbody_sync, handler);
    } else {
        // continue write
        LJS_evfd_write(fd, chunk -> data, chunk -> len, handler_wbody_sync, handler);
    }
    list_del(cur);
    js_free(handler -> ctx, chunk);
    handler -> sending_data = chunk -> data;    // free after current write
}

static inline void handler_write_all_header(JSContext* ctx, struct JSClientHandler* handler){
    EvFD* fd = handler -> fd;
    while(handler -> response.header_writed < handler -> response.header_count){
        FORMAT_WRITE("%s: %s\r\n", 1024, 
            handler -> response.headers[handler -> response.header_writed][0], 
            handler -> response.headers[handler -> response.header_writed][1]
        );
        handler -> response.header_writed ++;
    }

    // set-cookies
    if(handler -> cookiejar.mod_count > 0){
        struct CookiePair** modified = handler -> cookiejar.modified;
        for(int i = 0; i < handler -> cookiejar.mod_count; i ++) {
            char* cookie = modified[i] -> name;
            char* value = modified[i] -> value;
            char* modify = modified[i] -> modify;
            size_t len = strlen(cookie) + strlen(value) + strlen(modify) + 20;
            char* buf = js_malloc(ctx, len);
            snprintf(buf, len, "Set-Cookie: %s=%s; %s\r\n", cookie, value, modify);
            js_free(ctx, modified[i] -> name);
            js_free(ctx, modified[i] -> value);
            js_free(ctx, modified[i] -> modify);
        }
        handler -> cookiejar.mod_count = 0;
    }

    handler -> header_sent = true;
}

static JSValue js_handler_done(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    GET_OPAQUE(this_val);

    if(handler -> header_sent){
        return JS_ThrowTypeError(ctx, "Headers already sent");
    }
    
    // write header
    handler_write_all_header(ctx, handler);

    // wait sync
    EvFD* fd = handler -> fd;
    if(!list_empty(&handler -> chunks)) LJS_evfd_wait(fd, false, handler_wbody_sync, handler);
    return this_val;
}

void handler_close2_cb(JSContext* ctx, bool is_error, JSValueConst promise, void* data){
    struct JSClientHandler* handler = data;
    LJS_evfd_close(handler -> fd);
    handler -> destroy = true;
}

static JSValue js_handler_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    GET_OPAQUE(this_val);
    if(handler -> header_sent && list_empty(&handler -> chunks)){
        LJS_enqueue_promise_job(ctx, handler -> promise -> promise, handler_close2_cb, handler);
    }else{
        LJS_evfd_close(handler -> fd);
    }
    return JS_UNDEFINED;
}

static JSValue js_handler_reuse(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    GET_OPAQUE(this_val);

    if(handler -> response.state != HTTP_DONE){
        return JS_ThrowTypeError(ctx, "Response not read yet, please call response.*() to read body before reuse()");
    }
    if(!handler -> header_sent){
        return JS_ThrowTypeError(ctx, "Headers not sent yet, please call done() first");
    }
    
    if(!list_empty(&handler -> chunks)){
        return JS_ThrowTypeError(ctx, "Chunks not sent yet, please await for handler.end promise");
    }

    struct JSClientAsyncResult* async_result = init_async_result(handler);
    if(!async_result) return JS_ThrowOutOfMemory(ctx);

    async_result -> reusing_obj = this_val;
    LJS_parse_from_fd(handler -> fd, &handler -> request, true, handler_parse_cb, async_result);
    return async_result -> promise -> promise;
}

#ifndef LJS_MBEDTLS
#define SHA1_BLOCK_SIZE 20  // SHA-1 outputs a 20 byte digest

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA1_CTX;

static inline uint32_t rol(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32 - bits));
}

static inline uint32_t bswap_32(uint32_t x) {
    return ((x & 0xFF000000) >> 24) |
           ((x & 0x00FF0000) >> 8) |
           ((x & 0x0000FF00) << 8) |
           ((x & 0x000000FF) << 24);
}

static void sha1_init(SHA1_CTX *ctx) {
    ctx -> state[0] = 0x67452301;
    ctx -> state[1] = 0xEFCDAB89;
    ctx -> state[2] = 0x98BADCFE;
    ctx -> state[3] = 0x10325476;
    ctx -> state[4] = 0xC3D2E1F0;
    ctx -> count[0] = ctx -> count[1] = 0;
}

static void sha1_transform(SHA1_CTX *ctx, const uint8_t* buffer) {
    uint32_t a, b, c, d, e, temp;
    uint32_t w[80];
    
    // 将字节转换为32位字
    for (int i = 0; i < 16; i++) {
        w[i] = (buffer[i*4] << 24) | (buffer[i*4+1] << 16) | 
               (buffer[i*4+2] << 8) | (buffer[i*4+3]);
    }
    
    // 扩展16个字为80个字
    for (int i = 16; i < 80; i++) {
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    
    a = ctx -> state[0];
    b = ctx -> state[1];
    c = ctx -> state[2];
    d = ctx -> state[3];
    e = ctx -> state[4];
    
    // 主循环
    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            temp = rol(a, 5) + ((b & c) | ((~b) & d)) + e + w[i] + 0x5A827999;
        } else if (i < 40) {
            temp = rol(a, 5) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1;
        } else if (i < 60) {
            temp = rol(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDC;
        } else {
            temp = rol(a, 5) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6;
        }
        
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }
    
    // 更新状态
    ctx -> state[0] += a;
    ctx -> state[1] += b;
    ctx -> state[2] += c;
    ctx -> state[3] += d;
    ctx -> state[4] += e;
}

static void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t len) {
    uint32_t i, j;
    
    j = (ctx -> count[0] >> 3) & 63;
    if ((ctx -> count[0] += len << 3) < (len << 3)) ctx -> count[1]++;
    ctx -> count[1] += (len >> 29);
    
    if (j + len > 63) {
        memcpy(&ctx -> buffer[j], data, (i = 64 - j));
        sha1_transform(ctx, ctx -> buffer);
        for (; i + 63 < len; i += 64) {
            sha1_transform(ctx, data + i);
        }
        j = 0;
    } else {
        i = 0;
    }
    
    memcpy(&ctx -> buffer[j], &data[i], len - i);
}

static void sha1_final(SHA1_CTX *ctx, uint8_t digest[SHA1_BLOCK_SIZE]) {
    uint32_t i;
    uint8_t finalcount[8];
    
    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((ctx -> count[(i >= 4 ? 0 : 1)] >> 
                                 ((3 - (i & 3)) * 8)) & 255);
    }
    
    sha1_update(ctx, (uint8_t *)"\200", 1);
    while ((ctx -> count[0] & 504) != 448) {
        sha1_update(ctx, (uint8_t *)"\0", 1);
    }
    
    sha1_update(ctx, finalcount, 8);
    for (i = 0; i < SHA1_BLOCK_SIZE; i++) {
        digest[i] = (uint8_t)((ctx -> state[i>>2] >> ((3 - (i & 3)) * 8)) & 255);
    }
    
    memset(ctx, 0, sizeof(*ctx));
}

static void sha1(const uint8_t *data, size_t len, uint8_t digest[SHA1_BLOCK_SIZE]) {
    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}
#endif

static inline char* ws_calc_accept(const char* key){
    char sec[128];
    sprintf(sec, "%s" WS_KEY, key);

    // sha1
    uint8_t sha1val[20];
#ifdef LJS_MBEDTLS
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts(&ctx);
    mbedtls_sha1_update(&ctx, (const uint8_t*)sec, strlen(sec));
    mbedtls_sha1_finish(&ctx, sha1val);
    mbedtls_sha1_free(&ctx);
#else
    sha1((const uint8_t*)sec, strlen(sec), sha1val);
#endif

    // base64
    char* b64 = malloc(24);
    if(!b64) return NULL;
    base64_encode(sha1val, 20, b64);

    return b64;
}

#define ADD_HEADER(request, name, value) { \
    char** header = js_malloc(ctx, sizeof(char*) * 2); \
    if(!header) return JS_ThrowOutOfMemory(ctx); \
    header[0] = js_malloc(ctx, strlen(name) + 1); \
    strcpy(header[0], name); \
    header[1] = js_malloc(ctx, strlen(value) + 1); \
    strcpy(header[1], value); \
    request.headers[request.header_count] = header; \
    request.header_count++; \
}

static JSValue js_handler_ws(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    GET_OPAQUE(this_val);
    FIND_HEADER(handler -> request, "sec-websocket-key"){
        char* key = handler -> request.headers[i][1];
        char* accept = ws_calc_accept(key);
        if(!accept) return JS_ThrowOutOfMemory(ctx);

        handler -> response.status = 101;
        // add to headers
        ADD_HEADER(handler -> response, "Upgrade", "websocket");
        ADD_HEADER(handler -> response, "Connection", "Upgrade");
        ADD_HEADER(handler -> response, "Sec-WebSocket-Accept", accept);

        // free
        free(accept);
        goto main;
    }
    return JS_ThrowTypeError(ctx, "Not a WebSocket request");

main:
    // start body
    handler -> response.chunked = false;
    handler -> destroy = true;
    handler_write_all_header(ctx, handler);
    return LJS_NewWebSocket(ctx, handler -> fd, false);
}

static JSValue js_handler_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    return LJS_Throw(ctx, "Handler is not constructable", 
        "Handler is not constructable, please use Handler.from(pipe: U8Pipe) instead"
    );
}

static JSValue js_handler_static_from(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc == 0){
param_err:
        return LJS_Throw(ctx, "Handler.from() requires at least one argument",
            "Handler.from(pipe: U8Pipe): Promise<Handler>"
        );
    }

    EvFD* fd = LJS_GetPipeFD(ctx, argv[0]);
    if(!fd) goto param_err;

    struct JSClientHandler* handler = js_malloc(ctx, sizeof(struct JSClientHandler));
    if(!handler) return JS_ThrowOutOfMemory(ctx);
    init_handler(fd, ctx, handler);
    LJS_parse_from_fd(fd, &handler -> request, false, handler_parse_cb, handler);
    handler -> promise = LJS_NewPromise(ctx);
    return handler -> promise -> promise;
}

void handler_close2_cb2(JSContext* ctx, bool is_resolve, JSValueConst promise, void* data){
    free(data);
}

static void handler_finalizer(JSRuntime *rt, JSValue val){
    struct JSClientHandler* handler = JS_GetOpaque(val, handler_class_id);
    if(!handler || handler -> destroy) goto end;
    if(handler -> promise)
        LJS_Promise_Reject(handler -> promise, "Client handler lost");

    js_handler_done(handler -> ctx, val, 0, NULL);
    js_handler_close(handler -> ctx, val, 0, NULL);

    // cookiejar
    if(handler -> cookiejar.capacity > 0){
        handler -> cookiejar.ref_count --;
        free_cookie_jar(&handler -> cookiejar);
    }

    // add finalizer
    LJS_enqueue_promise_job(handler -> ctx, handler -> promise -> promise, handler_close2_cb2, handler);
    return;

end:
    free(handler);
}

static JSCFunctionListEntry handler_proto_funcs[] = {
    JS_CFUNC_DEF("send", 1, js_handler_send),
    JS_CFUNC_DEF("done", 0, js_handler_done),
    JS_CFUNC_DEF("close", 0, js_handler_close),
    JS_CFUNC_DEF("reuse", 0, js_handler_reuse),
    JS_CFUNC_DEF("ws", 0, js_handler_ws),
    JS_CFUNC_DEF("status", 1, js_handler_status),
    JS_CFUNC_DEF("header", 2, js_handler_header)
};

static JSClassDef handler_class = {
    "Handler",
    .finalizer = handler_finalizer
};

int init_http(JSContext *ctx, JSModuleDef *m){
    JSValue headers_ctor = JS_NewCFunction2(ctx, headers_constructor, "Headers", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, headers_ctor, JS_GetClassProto(ctx, headers_class_id));
    JS_SetModuleExport(ctx, m, "Headers", headers_ctor);

    JSValue response_constructor = JS_NewCFunction2(ctx, js_response_constructor, "Response", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, response_constructor, JS_GetClassProto(ctx, response_class_id));
    JS_SetModuleExport(ctx, m, "Response", response_constructor);

    JSValue websocket_ctor = JS_NewCFunction2(ctx, js_ws_constructor, "WebSocket", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, websocket_ctor, JS_GetClassProto(ctx, ws_class_id));
    JS_SetModuleExport(ctx, m, "WebSocket", websocket_ctor);

    JSValue handler_ctor = JS_NewCFunction2(ctx, js_handler_constructor, "Handler", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, handler_ctor, JS_GetClassProto(ctx, handler_class_id));
    JS_SetModuleExport(ctx, m, "Handler", handler_ctor);

    // Handler.prototype.from
    JSValue handler_ctor_proto = JS_NewObjectProto(ctx, JS_GetPrototype(ctx, handler_ctor));
    JSValue handler_from = JS_NewCFunction(ctx, js_handler_static_from, "from", 1);
    JS_SetPropertyStr(ctx, handler_ctor_proto, "from", handler_from);
    JS_SetPrototype(ctx, handler_ctor, handler_ctor_proto);

    // Cookies
    JSValue cookie_ctor = JS_NewCFunction2(ctx, js_cookies_constructor, "Cookies", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, cookie_ctor, JS_GetClassProto(ctx, cookie_jar_class_id));
    JS_SetModuleExport(ctx, m, "Cookie", cookie_ctor);

    return true;
}

bool LJS_init_http(JSContext *ctx){
    JSModuleDef *m = JS_NewCModule(ctx, "http", init_http);
    JSRuntime *rt = JS_GetRuntime(ctx);
    
    JS_NewClassID(rt, &response_class_id);
    JS_NewClass(rt, response_class_id, &response_class);
    JS_SetClassProto(ctx, response_class_id, JS_NewObject(ctx));
    JS_SetPropertyFunctionList(ctx, JS_GetClassProto(ctx, response_class_id), response_proto_funcs, countof(response_proto_funcs));

    JS_AddModuleExport(ctx, m, "Response");

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

    // WebSocket
    JS_NewClassID(rt, &ws_class_id);
    JS_NewClass(rt, ws_class_id, &js_ws_class_def);
    
    proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_ws_proto_funcs, countof(js_ws_proto_funcs));
    JS_SetClassProto(ctx, ws_class_id, proto);

    JS_AddModuleExport(ctx, m, "WebSocket");

    // Handler
    JS_NewClassID(rt, &handler_class_id);
    JS_NewClass(rt, handler_class_id, &handler_class);

    proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, handler_proto_funcs, countof(handler_proto_funcs));
    JS_SetClassProto(ctx, handler_class_id, proto);
    
    JS_AddModuleExport(ctx, m, "Handler");

    // Cookies
    JS_NewClassID(rt, &cookie_jar_class_id);
    JS_NewClass(rt, cookie_jar_class_id, &cookie_jar_class);

    proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, cookie_jar_funcs, countof(cookie_jar_funcs));
    JS_SetClassProto(ctx, cookie_jar_class_id, proto);

    JS_AddModuleExport(ctx, m, "Cookie");

    return true;
}