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
 * 务必使用memset(url_struct, 0, sizeof(URL_data))初始化url_struct
 */
bool LJS_parse_url(const char *_url, URL_data *url_struct, URL_data *base){
    if (strlen(_url) <= 1){
        return false;
    }
    char* url = url_struct -> source_str = strdup(_url);
    if(!url){
        return false;
    }

    // 创建模板
    if(base == NULL){
        if(default_url == NULL){
            default_url = malloc(sizeof(URL_data));
            if(default_url == NULL){
                return false;
            }
            memset(default_url, 0, sizeof(URL_data));
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
        // copy path
        int urlen = strlen(url) + 1;
        char* path = malloc(urlen);
        *path = '/';
        memcpy(path + 1, url, urlen);
        url_struct -> path = LJS_resolve_path(path, base -> path);
        free(path);
    }
    return true;
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
    data -> __read_all = false;
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
    if (data->state == HTTP_BODY && data->chunked){
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
    if (data->state != HTTP_BODY) abort();
    char* line_data = (char*)buffer;
    if (data->chunked) {
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
        data->content_read += len;
        data->cb(data, databuf, len, data->userdata);
        if (data->content_read >= data->content_length)
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
    data->state = HTTP_DONE;
    data->cb(data, NULL, 0, data->userdata);
    free(buffer);
    return EVCB_RET_DONE;
}

// main
static int parse_evloop_callback(EvFD* evfd, uint8_t* _line_data, uint32_t len, void* userdata){
    HTTP_data *data = userdata;
    char* line_data = (char*)_line_data;
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
            strtoupper(param1);
            data->method = strdup(param1);
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
            }
            data->state = HTTP_BODY;
            free(line_data);
            return EVCB_RET_DONE;
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


    return EVCB_RET_CONTINUE;

    error:{
        data->state = HTTP_ERROR;
        LJS_evfd_close(evfd);
        free(_line_data);
        return EVCB_RET_DONE;
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

static JSValue js_response_get_ok(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque(this_val, response_class_id);
    return JS_NewBool(ctx, response -> data -> status - 200 < 100);
}

static JSValue js_response_get_headers(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque(this_val, response_class_id);
    JSValue headers = JS_NewObject(ctx);
    for(int i = 0; i < response -> data -> header_count; i++){
        JS_SetPropertyStr(ctx, headers, response -> data -> headers[i][0], JS_NewString(ctx, response -> data -> headers[i][1]));
    }
    return headers;
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
        JS_Call(ctx, task -> promise -> resolve, JS_UNDEFINED, 1, (JSValue[]){ res });
        free(merged_buf);
        goto end;
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
        if(data -> state == HTTP_ERROR)
            JS_Call(promise -> ctx, promise -> reject, JS_NewError(promise -> ctx), 0, NULL);
        else
            JS_Call(promise -> ctx, promise -> resolve, JS_NULL, 0, NULL);
        goto end;
    }

end:
    // free promise
    LJS_FreePromise(task -> promise);
    free(task);
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
#define SPLIT_HEADER(line) \
    char *name = line; \
    char *value = strchr(line, ':'); \
    if(value){ \
        *value = '\0'; \
        value += 1; \
        str_trim(value); \
    }\
    str_trim(name);
#define TRIM_START(var2, line, _len) \
    char* var2 = line; \
    uint32_t __i = 0; \
    while((*var2 != '\0' || __i < _len) && (*var2 == ' ' || *var2 == '\t' || *var2 == '\r' || *var2 == '\n')) \
        var2++, __i++; \
    if(__i == _len) var2 = NULL;

static int callback_formdata_parse(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* userdata){
    struct readall_promise *task = userdata;
    struct formdata_addition_data *fd_task = task -> addition_data;
    JSContext *ctx = task -> promise -> ctx;
    fd_task -> readed += read_size;

    // 空行
    if (fd_task->state == FD_NEWLINE) {
        fd_task->state = FD_HEADER;
        return EVCB_RET_CONTINUE;
    }

    // ------WebKitFormBoundaryABC123
    if (fd_task->state == FD_BOUNDARY) {
        char* line = (char*) buffer;
        if (line[0] != '-' || line[1] != '-' || strcmp(line + 2, fd_task->boundary) != 0) {
            // error
            LJS_Promise_Reject(task->promise, "Invalid boundary");
            goto end;
        }
        fd_task->state = FD_HEADER;
        return EVCB_RET_CONTINUE;
    }

    struct formdata_t* formdata = list_entry(fd_task->formdata.next, struct formdata_t, list);

    // Content-Disposition: form-data; name="file"; filename="test.txt"
    if (fd_task->state == FD_HEADER) {
        char* _line = (char*) buffer;
        TRIM_START(line, _line, read_size);

        if (line == NULL) {
            // end of header
            if (formdata->length == 0) fd_task->state = FD_NEWLINE;
            else fd_task->state = FD_DATA;

            uint8_t* buf = js_malloc(ctx, formdata->length);
            LJS_evfd_readsize(evfd, formdata->length, buf, parse_evloop_body_callback, formdata);

            js_free(ctx, _line);
            return EVCB_RET_DONE;   // 切换模式
        }

        SPLIT_HEADER(line);
        if (!value) {
            // error
            LJS_Promise_Reject(task->promise, "Invalid header");
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
            formdata->filename = filename;
            formdata->type = type;
        } else if (strcmp(name, "Content-Type") == 0) {
            formdata->type = strdup(value);
        } else if (strcmp(name, "Content-Length") == 0) {
            int len = atoi(value);
            if (len < 0) {
                // error
                LJS_Promise_Reject(task->promise, "Invalid content-length");
                goto end_cleanup;
            }
            formdata->length = len;
        } else {
            // ignore
        }
        fd_task->state = FD_DATA;
        return EVCB_RET_CONTINUE;
    }

    if (fd_task->state == FD_DATA) {
        if (formdata->length < read_size) {
            // error
            LJS_Promise_Reject(task->promise, "Failed to receive data: short readed");
            goto end_cleanup;
        }

        // already recv all data
        formdata->data = buffer;

        // end
        if(fd_task -> readed == formdata -> length) goto end_callback;

        // newline: the buffer will be reused for header
        fd_task->state = FD_NEWLINE;
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
    struct HTTP_Response *var = JS_GetOpaque(this_val, response_class_id); \
    if(!var) return JS_EXCEPTION; \
    if(var -> locked) return LJS_Throw(ctx, "Body is locked", NULL);

static JSValue js_response_get_body(JSContext *ctx, JSValueConst this_val) {
    RESPONSE_GET_OPAQUE(response, this_val);

    response -> locked = true;
    JSValue pipe = LJS_NewU8Pipe(ctx, PIPE_READ, BUFFER_SIZE, response_poll, NULL, NULL, response);
    return pipe;
}

static JSValue js_response_get_locked(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque(this_val, response_class_id);
    if(!response) return JS_EXCEPTION;
    return JS_NewBool(ctx, response -> locked);
}

#define INIT_TOU8_TASK \
    RESPONSE_GET_OPAQUE(response, this_val); \
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
    JSValue obj = JS_NewObjectClass(ctx, response_class_id);
    struct HTTP_Response *response = malloc(sizeof(struct HTTP_Response));
    response -> data = data;
    response -> locked = false;
    JS_SetOpaque(obj, response);
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
        bool ssl = url.protocol[strlen(url.protocol) - 1] == 's';
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

    // 解析参数
    // GET / HTTP/1.1
    char* method = (char*) JS_ToCString(ctx, JS_GetPropertyStr(ctx, obj, "method"));
    if (!method) method = "GET";
    size_t guess_len = strlen(method) + 1 + strlen(url.path) + 1 + 8 + 2 + 1;
    char* buf = malloc(guess_len);
    snprintf(buf, guess_len, "%s %s HTTP/1.1\r\n", method, url.path);
    LJS_evfd_write(fd, (uint8_t*) buf, strlen(buf), NULL, NULL);
    free(buf);

    // keep-alive
    bool keep_alive = JS_ToBool(ctx, JS_GetPropertyStr(ctx, obj, "keepalive"));
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
        free(buf);
    }

    // host
    if(JS_IsUndefined(JS_GetPropertyStr(ctx, obj, "host"))){
        char* host = malloc(strlen(url.host) + 16);
        snprintf(host, strlen(url.host) + 16, "Host: %s\r\n", url.host);
        LJS_evfd_write(fd, (uint8_t*) host, strlen(host), NULL, NULL);
    }
    
    // websocket?
    if(websocket){
        // todo
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
    if (JS_GetTypedArrayType(body) != -1 || JS_IsString(body)) {
        size_t data_len;
        uint8_t* data = JS_IsString(body) 
            ? (uint8_t*) JS_ToCStringLen(ctx, &data_len, body) 
            : JS_GetArrayBuffer(ctx, &data_len, body);
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
    HTTP_data *data = malloc(sizeof(HTTP_data));
    struct promise *promise = LJS_NewPromise(ctx);
    LJS_parse_from_fd(fd, data, false, fetch_resolve, promise);
    LJS_free_url(&url);
    return promise -> promise;
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
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    URL_data *url_struct = js_url_struct->self; \
    return (url_struct->field) ? JS_NewString(ctx, url_struct->field) : JS_UNDEFINED; \
}

#define GETTER_INT(func_name, field, invalid_value) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    URL_data *url_struct = js_url_struct->self; \
    return (url_struct->field == invalid_value) ? JS_UNDEFINED : JS_NewInt32(ctx, url_struct->field); \
}

#define SETTER_STRING_DUP(func_name, field, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    const char *str = JS_ToCString(ctx, value); \
    if (!str) return LJS_Throw(ctx, err_msg, NULL); \
    js_url_struct->dup_value[js_url_struct->dup_count++] = JS_DupValue(ctx, value); \
    js_url_struct->self->field = (char*)str; \
    return JS_UNDEFINED; \
}

#define SETTER_STRING_COPY(func_name, field, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    const char *str = JS_ToCString(ctx, value); \
    if (!str) return LJS_Throw(ctx, err_msg, NULL); \
    free(js_url_struct->self->field); \
    js_url_struct->self->field = strdup(str); \
    JS_FreeCString(ctx, str); \
    return JS_UNDEFINED; \
}

#define SETTER_INT_RANGE(func_name, field, min, max, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    int32_t val; \
    if (JS_ToInt32(ctx, &val, value) < 0) return LJS_Throw(ctx, err_msg, NULL); \
    if (val < min || val > max) return JS_ThrowRangeError(ctx, #field " out of range"); \
    js_url_struct->self->field = val; \
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

static void js_url_finalizer(JSRuntime *rt, JSValue val) {
    struct JS_URL_struct *js_url_struct = JS_GetOpaque(val, js_class_url_id);
    if (!js_url_struct) return;
    
    URL_data *url = js_url_struct->self;

#define FREE_FIELD(field) do { if(url->field) free(url->field); } while(0)
    FREE_FIELD(protocol);
    FREE_FIELD(host);
    FREE_FIELD(path);
    FREE_FIELD(username);
    FREE_FIELD(password);
    FREE_FIELD(hash);
#undef FREE_FIELD
    
    if (url->query) {
        for (uint32_t i = 0; i < MAX_QUERY_COUNT; i++) {
            free(url->query[i].key);
            free(url->query[i].value);
        }
        free(url->query);
    }
    
    for (uint32_t i = 0; i < js_url_struct->dup_count; i++) {
        JS_FreeValueRT(rt, js_url_struct->dup_value[i]);
    }
    free(js_url_struct);
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
                free(base_url_str);
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