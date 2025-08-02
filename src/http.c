/*
 * LightJS HTTP Module(server & client)
 *
 * Copyright (c) 2025 iz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "../engine/quickjs.h"
#include "../engine/cutils.h"
#include "../engine/list.h"
#include "polyfill.h"
#include "core.h"
#include "httpmeta.h"

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
#include <stdbool.h>
#include <sys/random.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#ifdef LJS_MBEDTLS
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#endif

#define BUFFER_SIZE 1024
#define MAX_HEADER_SIZE 4096
#define MAX_URL_SIZE 2048

// global keepalive connections
static struct list_head keepalive_list;
static pthread_mutex_t keepalive_mutex;

struct keepalive_connection{
    EvFD* fd;
    char host[64];
    struct list_head list;
};

// trim the start of a string
#define STRTRIM(str) \
    while(*str != '\0' && isspace(*str)) str ++;

// split a string by blanks
#define SPLIT_HEADER(line) \
    char *name = line; \
    char *value = strchr(line, ':'); \
    if(value){ \
        *(value ++) = '\0'; \
        while(*value == ' ') value ++; \
        STRTRIM(value); \
    }\
    STRTRIM(name);

#define DEL_HEADER2(header) \
    list_del(&header -> link); \
    free2(header -> key); \
    free2(header -> value); \
    free2(header);

// trim the start of a length-specified string
#define TRIM_START(var2, line, _len) \
    char* var2 = line; \
    uint32_t __i = 0; \
    while((*var2 != '\0' || __i < _len) && (*var2 == ' ' || *var2 == '\t' || *var2 == '\r' || *var2 == '\n')) \
        var2++, __i++; \
    if(__i == _len) var2 = NULL;

// resolve linux-style path
static char* normalize_path(const char* path) {
    char* copy = strdup2(path);
    if (!copy) return NULL;

    char** parts = malloc2(sizeof(char*) * PATH_MAX);
    if (!parts) {
        free2(copy);
        return NULL;
    }
    
    int part_count = 0;
    char* saveptr;
    char* token = strtok_r(copy, "/", &saveptr);

    while (token) {
        if (strcmp(token, ".") == 0) {
            // ignore
        } else if (strcmp(token, "..") == 0) {
            // pop last part
            if (part_count > 0) part_count--;
        } else {
            parts[part_count++] = strdup2(token);
        }
        token = strtok_r(NULL, "/", &saveptr);
    }

    // concat strings
    size_t total_len = 1;
    int is_absolute = (path[0] == '/');
    if (is_absolute) total_len++;
    
    for (int i = 0; i < part_count; i++) {
        total_len += strlen(parts[i]) + 1;
    }
    
    if (part_count > 0) total_len--;

    char* result = malloc2(total_len);
    result[0] = '\0';
    
    if (is_absolute) strcat(result, "/");
    
    for (int i = 0; i < part_count; i++) {
        if (i > 0) strcat(result, "/");
        strcat(result, parts[i]);
        free2(parts[i]);
    }

    // dir: add trailing slash
    if(path[strlen(path) -1] == '/') strcat(result, "/");
    
    free2(parts);
    free2(copy);
    return result;
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
        if('A' <= *p && *p <= 'Z')
            *p = tolower(*p);
        p++;
    }
    return str;
}


static inline int hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    else if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    else if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    else return -1;
}

// decode url-encoded string
// note: modifies the input string
static char* url_decode(char* str) {
    if (!str) return NULL;
    
    char *src = str;
    char *dst = str;
    
    while (*src) {
        if (*src == '%') {
            if (src[1] && src[2]) {
                const int high = hex_char_to_value(src[1]);
                const int low = hex_char_to_value(src[2]);
                if (high != -1 && low != -1) {
                    *dst++ = (high << 4) | low;
                    src += 3;
                    continue;
                }
            }
            *dst++ = *src++;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
    return str;
}

static const char HEX_CHARS[] = "0123456789ABCDEF";
bool encode_map[256];
__attribute__((constructor)) void init_url_map(void) {
    for (int i = 0; i < 256; i++) {
        encode_map[i] = !(
            (i >= '0' && i <= '9') ||
            (i >= 'A' && i <= 'Z') ||
            (i >= 'a' && i <= 'z') ||
            i == '-' || i == '_' || i == '.' || i == '~'
        );
    }
}

// decode url-encoded string
static bool url_encode(const char* src, char* dest, size_t dest_len) {
    // calculate encoded length
    if(dest_len < 3 * strlen(src) + 1){
        size_t encoded_len = 0;
        const unsigned char* p = (const unsigned char*)src;
        while (*p) {
            encoded_len += encode_map[*p] ? 3 : 1;
            p++;
        }
        if(dest_len < encoded_len + 1){
            return false;   // memory not enough
        }
    }

    // malloc and encode
    char* q = dest;
    unsigned char* p;
    for (p = (unsigned char*)src; *p; p++) {
        if (encode_map[*p]) {
            *q++ = '%';
            *q++ = HEX_CHARS[(*p >> 4) & 0xF];
            *q++ = HEX_CHARS[*p & 0xF];
        } else {
            *q++ = *p;
        }
    }
    *q = '\0';

    return dest;
}

// resolve absolute path from base path and relative path
// if base is not provided, use current working directory
// return NULL on error
char* LJS_resolve_path(const char* path, const char* _base) {
    if (!path || !*path) return strdup2(_base);
    
    // absolute path
    if (path[0] == '/') return normalize_path(path);
    char* base = strdup2(_base ? _base : "");
    if(!base) {
        base = getcwd(NULL, 0);
    }

    // relative path
    size_t base_len = strlen(base);
    size_t path_len = strlen(path);
    char* combined = malloc2(base_len + path_len + 2);

    // Remove filename from base path
    if(base_len && base[base_len-1] != '/'){
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

    // normalize concatenated path
    char* resolved = normalize_path(combined);
    free2(combined);
    free2(base);
    return resolved;
}

// parse query string, \0 terminated
static inline bool url_parse_query(char *query, struct list_head *query_list){
    if(query == NULL) return false;
    if(*query == '\0') return true;
    while(true){
        URL_query* query_obj = malloc2(sizeof(URL_query));
        if(query_obj == NULL){
            return false;
        }

        char *eq_pos = strchr(query, '=');

        char* next_query = strchr(eq_pos ? eq_pos : query, '&');
        if( // no value
            eq_pos == NULL || 
            (eq_pos != NULL && next_query != NULL && next_query < eq_pos) // "=" ahead of "&"
        ){
            query_obj -> key = url_decode(strdup2(query));
        }else{  // both value and key
            eq_pos[0] = '\0';
            query_obj -> key = url_decode(strdup2(query));
            if(next_query){
                *next_query = '\0';
            }
            query_obj -> value = url_decode(strdup2(eq_pos + 1));
        }
        list_add_tail(&query_obj -> link, query_list);

        // next query
        if(next_query != NULL && next_query[1] != '\0'){
            query = next_query + 1;
        }else{
            break;
        }
    }
    return true;
}

static URL_data *default_url;

// copy query from base to dest
static void url_query_dup(URL_data* source, URL_data* dest){
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &source -> query) {
        URL_query* query = list_entry(cur, URL_query, link);
        URL_query* new_query = malloc2(sizeof(URL_query));
        if(new_query == NULL){
            return;
        }
        new_query -> key = strdup2(query -> key);
        new_query -> value = strdup2(query -> value);
        list_add_tail(&new_query -> link, &dest -> query);
    }
}

// parse url string
// return true on success, false on error
// note: `url_struct` will be modified, make sure it is cleared before parse
bool LJS_parse_url(const char *_url, URL_data *url_struct, URL_data *base) {
    char* __url = NULL;
    if (strlen(_url) == 0) {
        goto error;
    }
    init_list_head(&url_struct -> query);
    char* url = __url = strdup2(_url);

    // fallback to default url if base is NULL
    if (!base) {
        if (!default_url) {
            if (!(default_url = calloc(1, sizeof(URL_data)))) {
                goto error;
            }
        }
        base = default_url;
    }

    // starter
#define dup(c) c ? strdup2(c) : NULL
    if(url[0] == '/'){  // path
        if(url[1] == '/'){
            url_struct -> protocol = dup(base -> protocol);
            goto skip_protocol;
        }else{
            url_struct -> protocol = dup(base -> protocol);
            url_struct -> host = dup(base -> host);
            url_struct -> port = base -> port;
            goto skip_host;
        }
    }else if(url[0] == '?'){    // query
        url_struct -> protocol = dup(base -> protocol);
        url_struct -> host = dup(base -> host);
        url_struct -> port = base -> port;
        url_struct -> path = dup(base -> path);
        // find hash?
        char *hash_start = strchr(url, '#');
        if(hash_start){
            *hash_start = '\0';
            url_struct -> hash = url_decode(strdup2(hash_start + 1));
        }

        // parse query
        char *query_str = url + 1;
        if (!url_parse_query(query_str, &url_struct -> query)) {
            goto error;
        }
        return true;    // finished
    }else if(url[0] == '#'){    // hash
        url_struct -> protocol = dup(base -> protocol);
        url_struct -> host = dup(base -> host);
        url_struct -> port = base -> port;
        url_struct -> path = dup(base -> path);
        url_query_dup(base, url_struct);

        url += 1;
        url_struct -> hash = url_decode(strdup2(url));
        return true;    // finished
#undef dup
    }

    
    if(!url_struct -> protocol){
        char* pos = strstr(url, ":");
        if(pos){
            pos[0] = '\0';
            url_struct -> protocol = strtolower(strdup2(url));
            url = pos + 1;
        }else{  // recognize as absolute path
            goto skip_host;
        }
    }

skip_protocol:
    if (!url_struct -> host) {
        if(*url != '/' || *(url + 1) != '/') goto skip_host;
        url += 2;

        char *user_pass_end = strchr(url, '@'); // User&Pass field

        // have user&pass field
        // e.g: http://user:pass@example.com:81/path
        // note: http://user@example.com/path can also be valid
        if (user_pass_end) {
            char* host_end = strpbrk(user_pass_end, ":/?#");
            if(host_end && user_pass_end > host_end){
                // invaild u&p field, skip
                goto skip_up;
            }

            char *last_at = user_pass_end;
            char *current = user_pass_end + 1;

            while ((current = strchr(current, '@')) != NULL) {
                if (!host_end || current < host_end) {
                    last_at = current;
                    current++; 
                } else {
                    break;
                }
            }

            if (last_at) {
                *last_at = '\0';
                char *colon = strchr(url, ':');
                if (colon) {
                    *colon = '\0';
                    url_struct -> username = url_decode(strdup2(url));
                    url_struct -> password = url_decode(strdup2(colon + 1));
                } else {
                    url_struct -> username = url_decode(strdup2(url));
                }
                url = last_at + 1; 
            }
        }
skip_up:
        char* host = url;
        char* host_end;
        if(*host == '['){   // ipv6
            char* ipv6_end = strchr(host, ']');
            if(ipv6_end){
                url_struct -> host = strndup2(host, ipv6_end - host);
                host_end = ipv6_end + 1;

                // check if ipv6 vaild
                for(char* p = host + 1; p < ipv6_end; p++) {
                    if(!strpbrk(p, ":.0123456789")){
                        goto error;
                    }
                }
            }else{
                goto error;
            }
        }

        host_end = strpbrk(url, ":/?#");
        if (host_end && *host_end == ':') { // port field
            *host_end = '\0';
            char *port_str = host_end + 1;
            char *port_end = strpbrk(port_str, "/?#");
            char port_end_chr = port_end ? *port_end : '/';
            if (port_end) *port_end = '\0';

            if(strlen(port_str) > 5){
                goto error; // port too long, 65535 max
            }

            char *end;
            long port = strtol(port_str, &end, 10);
            if (*end != '\0' || port < 0 || port > 65535) {
                goto error;
            }
            url_struct -> port = (uint16_t)port;
            if(port_end){
                *port_end = port_end_chr;
                url = port_end;
            }else{
                url_struct -> host = strdup2(host);
                goto final; // no path field
            }
        } else if(url_struct -> protocol) {                        // use default port
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

        url_struct -> host = strndup2(host, host_end ? host_end - host : strlen(host));
        if(host_end) url = host_end;
        else goto final;    // no path field
    }

skip_host:
    if (!url_struct -> path) {
        char *path_start = url;
        char *hp_start = strpbrk(url, "?#");

        if (hp_start){
            if (*hp_start == '#') {
                url_struct -> hash = url_decode(strdup2(hp_start + 1));
            } else {
                char* hash_start = strchr(hp_start, '#');
                if(hash_start){
                    *hash_start = '\0';
                    url_struct -> hash = url_decode(strdup2(hash_start + 1));
                }
                char *query_str = hp_start + 1;
                if (!url_parse_query(query_str, &url_struct -> query)) {
                    goto error;
                }
            }
            *hp_start = '\0';
        }

        if (*path_start != '/') {
            // Note: LJS_resolve_path will motify input path
            char* bpath = strdup2(base -> path ? base -> path : "");
            url_struct -> path = LJS_resolve_path(url_decode(path_start), bpath);
            free2(bpath);
            if (!url_struct -> path) {
                goto error;
            }
        } else {
            url_struct -> path = url_decode(strdup2(path_start));
        }
    }
final:
    free2(__url);
    return true;

error:
    if(__url) free2(__url);
    LJS_free_url(url_struct);
    return false;
}

// free URL struct
// note: this function will not free data itself, please free it by yourself
void LJS_free_url(URL_data *url_struct){
#define free2(ptr) if(ptr) free2(ptr)
    if(url_struct -> query.next != NULL && !list_empty(&url_struct -> query)){
        struct list_head *cur, *tmp;
        list_for_each_safe(cur, tmp, &url_struct -> query) {
            URL_query* query = list_entry(cur, URL_query, link);
            free2(query -> key);
            free2(query -> value);
            free2(query);
        }
    }
    free2(url_struct -> protocol);
    free2(url_struct -> host);
    free2(url_struct -> path);
    free2(url_struct -> username);
    free2(url_struct -> password);
    free2(url_struct -> hash);
#undef free2
}

// format `url_struct` to standard URL string
char* LJS_format_url(URL_data *url_struct){
    // Scheme://login:password@address:port/path/to/resource?query_string#fragment
    char* data = malloc2(2048);
    size_t datapos = 0;

    char enctmp[MAX_URL_SIZE]; // for URL encode, same as max length in Chrome
#define PUT(str) memcpy(data + datapos, str , strlen(str)); datapos += strlen(str);
#define EPUT(str) url_encode(str, enctmp, sizeof(enctmp)); PUT(enctmp);
    if(url_struct -> host){
        if(url_struct -> protocol != NULL){
            PUT(url_struct -> protocol);
            PUT("://");
        }else{
            PUT("//");
        }

        if(url_struct -> username != NULL){
            EPUT(url_struct -> username);
            if(url_struct -> password != NULL){
                PUT(":");
                EPUT(url_struct -> password);
            }
            PUT("@");
        }
        PUT(url_struct -> host);
        if(url_struct -> port != 0){
            char port_str[10];
            sprintf(port_str, ":%d", url_struct -> port);
            PUT(port_str);
        }
        
    }
    
    if(url_struct -> path){
        PUT(url_struct -> path);
    }else{
        PUT("/");
    }

    if(!list_empty(&url_struct -> query)){
        PUT("?");
        struct list_head *cur, *tmp;
        list_for_each_safe(cur, tmp, &url_struct -> query) {
            URL_query* query = list_entry(cur, URL_query, link);
            EPUT(query -> key);
            if(query -> value != NULL){
                PUT("=");
                EPUT(query -> value);
            }
            PUT("&");
        }
        datapos--;  // remove last '&'
    }
    if(url_struct -> hash != NULL){
        PUT("#");
        EPUT(url_struct -> hash);
    }
    data[datapos] = '\0';
#undef PUT
    return data;
}

// Note: data itself is not freed here, please free it by yourself
void LJS_free_http_data(LHTTPData *data){
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &data -> headers){
        LHttpHeader* header = list_entry(cur, LHttpHeader, link);
        DEL_HEADER2(header);
    }

#define free2(ptr) if(ptr) free2(ptr)
    free2(data -> method);
    free2(data -> path);
    free2(data -> __target_host);
#undef free2
    // free2(data);
}

// check JS args by JSTag
#define CHECK_ARGS(n, msg, ...){ \
    if(argc < n) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Too few arguments, expect %d, got %d", msg, n, argc); \
    int32_t types[] = {  __VA_ARGS__ }; \
    for(int i = 0; i < n; i++)\
        if(JS_VALUE_GET_TAG(argv[i]) != types[i]) \
            return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid argument type at index %d", msg, i); \
}

// Header class
static thread_local JSClassID headers_class_id;

static inline void init_http_data(LHTTPData *data, bool is_client); // forward declaration
static JSValue js_headers_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    // CHECK_ARGS(1, "Headers(): Headers", JS_TAG_OBJECT);
    // TODO: import Headers from Object or Array
    LHTTPData* data = malloc2(sizeof(LHTTPData));
    init_http_data(data, true);
    data -> __header_owned = true;
    data -> __target_host = NULL;
    
    JSValue headers = JS_NewObjectClass(ctx, headers_class_id);
    JS_SetOpaque(headers, data);

    return headers;
}

static JSValue js_headers_append(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    LHTTPData *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;

    CHECK_ARGS(2, "Headers.append(key: string, value: string): void", JS_TAG_STRING, JS_TAG_STRING);
    
    const char *key = JS_ToCString(ctx, argv[0]);
    const char *value = JS_ToCString(ctx, argv[1]);

    // 新增
    PUT_HEADER_DUP(data, key, value);

    return JS_UNDEFINED;
}

static JSValue js_headers_get(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    LHTTPData *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;
    
    CHECK_ARGS(1, "Headers.get(key: string): string", JS_TAG_STRING);

    const char *key = JS_ToCString(ctx, argv[0]);

    FIND_HEADERS(data, key, value, {
        return JS_NewStringLen(ctx, value -> value, value -> vallen);
    });
        
    return JS_UNDEFINED;
}

static JSValue js_headers_getall(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    LHTTPData *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;

    const char* find_key = LJS_ToCString(ctx, argv[0], NULL);
    if(!find_key){
        // process all headers
        JSValue headers = JS_NewObject(ctx);
        struct list_head *cur, *tmp;
        list_for_each_safe(cur, tmp, &data -> headers){
            LHttpHeader* header = list_entry(cur, LHttpHeader, link);
            JSValue obj = JS_GetPropertyStr(ctx, headers, header -> key);
            if(JS_IsUndefined(obj)){
                obj = JS_NewArray(ctx);
                JS_SetPropertyStr(ctx, headers, header -> key, obj);
            }
            int64_t len;
            JS_GetLength(ctx, obj, &len);
            JS_SetPropertyUint32(ctx, obj, len ++, JS_NewStringLen(ctx, header -> value, header -> vallen));
            JS_SetLength(ctx, obj, len);
        }
        return headers;
    }
    
    // find values
    JSValue arr = JS_NewArray(ctx);
    uint32_t index = 0;

    FIND_HEADERS(data, find_key, value, {
        JS_SetPropertyUint32(ctx, arr, index, JS_NewStringLen(ctx, value -> value, value -> vallen));
        index++;
    });
    JS_SetLength(ctx, arr, index);

    return arr;
}

static JSValue js_headers_set(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    LHTTPData *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;

    CHECK_ARGS(2, "Headers.set(key: string, value: string): void", JS_TAG_STRING, JS_TAG_STRING);
    
    const char *key = JS_ToCString(ctx, argv[0]);
    const char *value = JS_ToCString(ctx, argv[1]);

    LHttpHeader* header = NULL;
    FIND_HEADERS(data, key, value, {
        header = value;
        break;
    })

    if(header){
        free2(header -> value);
        header -> value = strdup2(value);
    }else{
        PUT_HEADER_DUP(data, key, value);
    }

    return JS_UNDEFINED;
}

static JSValue js_headers_delete(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    LHTTPData *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;

    CHECK_ARGS(1, "Headers.delete(key: string): void", JS_TAG_STRING);
    
    const char *key = JS_ToCString(ctx, argv[0]);

    FIND_HEADERS(data, key, value, {
        DEL_HEADER(value);
        JS_FreeCString(ctx, key);
        return JS_TRUE;
    });

    JS_FreeCString(ctx, key);
    return JS_FALSE;
}

static JSValue js_headers_has(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    LHTTPData *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;

    CHECK_ARGS(1, "Headers.has(key: string): boolean", JS_TAG_STRING);
    
    const char *key = JS_ToCString(ctx, argv[0]);
    FIND_HEADERS(data, key, value, {
        return JS_TRUE;
    });
    return JS_FALSE;
}

static JSValue js_headers_toString(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    LHTTPData *data = JS_GetOpaque2(ctx, this_val, headers_class_id);
    if (!data) return JS_EXCEPTION;

    char buf[1024];
    size_t pos = 1;
    buf[0] = '\n';
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &data -> headers){
        LHttpHeader* header = list_entry(cur, LHttpHeader, link);
        pos += sprintf(buf + pos, " * %s: %s\n", header -> key, header -> value);
    }
    if(data -> content_length > 0){
        pos += sprintf(buf + pos, " * content-length: %ld\n", data -> content_length);
    }

    return JS_NewStringLen(ctx, buf, pos);
}

void headers_finalizer(JSRuntime *rt, JSValue val) {
    LHTTPData *data = JS_GetOpaque(val, headers_class_id);

    // constructed by js_headers_constructor
    if (data && data -> __header_owned) {
        struct list_head *cur, *tmp;
        list_for_each_safe(cur, tmp, &data -> headers){
            LHttpHeader* header = list_entry(cur, LHttpHeader, link);
            free2(header -> key);
            free2(header -> value);
            free2(header);
        }
        free2(data);
    }
}

static const JSCFunctionListEntry headers_proto_funcs[] = {
    JS_CFUNC_DEF("append", 2, js_headers_append),
    JS_CFUNC_DEF("get", 1, js_headers_get),
    JS_CFUNC_DEF("getAll", 1, js_headers_getall),
    JS_CFUNC_DEF("set", 2, js_headers_set),
    JS_CFUNC_DEF("delete", 1, js_headers_delete),
    JS_CFUNC_DEF("has", 1, js_headers_has),
    JS_CFUNC_DEF2("toString", 0, js_headers_toString, JS_PROP_CONFIGURABLE),
};

static const JSClassDef headers_class = {
    "Headers",
    .finalizer = headers_finalizer
};

JSValue LJS_NewHeaders(JSContext *ctx, LHTTPData *data){
    data -> __header_owned = false;
    JSValue headers = JS_NewObjectClass(ctx, headers_class_id);
    JS_SetOpaque(headers, data);

    return headers;
}

// HTTP
// init http data
// Note: method should be set after this call
static inline void init_http_data(LHTTPData *data, bool is_client){
    data -> method = NULL;
    data -> status = 200;
    data -> version = 1.1;
    data -> chunked = false;
    data -> content_length = 0;
    data -> state = HTTP_INIT;
    data -> __read_all = false;
    data -> content_resolved = 0;
    data -> path = NULL;
    data -> is_client = is_client;

    init_list_head(&data -> headers);
}

static inline float parse_http_version(char* str){
    if(strlen(str) < 8 || memcmp(str, "HTTP/", 5) != 0) {
        return 0.0;
    }
    str += 5;
    float ver = atof(str);
    return ver;
}

static inline uint32_t hex2int(char* c, size_t len){
    uint32_t hex = 0;
    for(uint32_t i = 0; i < len; i++){
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

#define COPY_BUF(var, buf, len) uint8_t* var = malloc2(len); memcpy(var, buf, len);

// predef
static int parse_evloop_body_callback(EvFD* evfd, bool ok, uint8_t* buffer, uint32_t len, void* user_data);

// http chunk
// read -> chunked(after length)
static int parse_evloop_chunk_callback(EvFD* evfd, bool ok, uint8_t* chunk_data, uint32_t len, void* user_data){
    LHTTPData *data = user_data;
    
    // closed
    if(!ok) data -> state = HTTP_ERROR;

    if (data -> state == HTTP_BODY && data -> chunked){
        data -> cb(data, chunk_data, len, data -> userdata);
        data -> content_resolved += len;
    }else{
        free2(chunk_data);
    }
    
    if(data -> __read_all){
        uint8_t* buf = malloc2(BUFFER_SIZE);
        evfd_readline(evfd, BUFFER_SIZE, buf, parse_evloop_body_callback, data);
    }
    return EVCB_RET_DONE;
}

// body: read once
// read -> body(before chunk-content)
static int parse_evloop_body_callback(EvFD* evfd, bool ok, uint8_t* buffer, uint32_t len, void* user_data){
    LHTTPData *data = user_data;
    char* line_data = (char*)buffer;

    if(!ok) goto error;
    if(!len) return EVCB_RET_CONTINUE;

    if (data -> chunked) {
        // chunked length
        STRTRIM(line_data);
        uint32_t chunk_size = hex2int(line_data, len);
        if (chunk_size == 0) goto done;

        // chunk read
        uint8_t* buf = malloc2(chunk_size +1);
        evfd_readsize(evfd, chunk_size, buf, parse_evloop_chunk_callback, data);

        free2(line_data);
        return EVCB_RET_DONE;
    }else {
        COPY_BUF(databuf, buffer, len);
        data -> content_resolved += len;
        data -> cb(data, databuf, len, data -> userdata);
        if (data -> content_resolved >= data -> content_length)
            goto done;

        if(data -> __read_all){
            goto end;   // continue read
        }

        return EVCB_RET_DONE;
    }

    return EVCB_RET_DONE;

end:
    return EVCB_RET_CONTINUE;   // continue

done:
    data -> state = HTTP_DONE;
    data -> cb(data, NULL, 0, data -> userdata);
    free2(buffer);
    return EVCB_RET_DONE;

error:
    data -> state = HTTP_ERROR;
    data -> cb(data, NULL, 0, data -> userdata);
    free2(buffer);
    return EVCB_RET_DONE;
}

// main
// read -> header(before body)
static int parse_evloop_callback(EvFD* evfd, bool _, uint8_t* _line_data, uint32_t len, void* userdata){
    LHTTPData *data = userdata;
    char* line_data = (char*)_line_data;
    if(!line_data && len == 0 && data -> state < HTTP_BODY) goto error2; // close
    // 是第一行
    if (data -> state == HTTP_INIT){
        // 找空格解析参数
        char *param1 = line_data;
        STRTRIM (param1);
        char *param2 = strchr (line_data, ' ');
        if (param2 == NULL){
            goto error;
        }
        *param2 = '\0';
        param2 += 1;
        STRTRIM (param2);
        char *param3 = strchr (param2, ' ');
        if (param3 == NULL){
            goto error;
        }
        *param3 = '\0';
        param3 += 1;
        STRTRIM (param3);

        // GET / HTTP/1.1
        if (data -> is_client){
            strtoupper(param1);
            data -> method = strdup2(param1);
            data -> path = strdup2(param2);
            data -> version = parse_http_version (param3);
            if (data -> version < 1.0){
                goto error;
            }
        // HTTP/1.1 200 OK
        }else{
            data -> version = parse_http_version (param1);
            data -> status = atoi (param2);
            if (data -> version < 1.0 || data -> status < 100){
                goto error;
            }
        }
        data -> state = HTTP_HEADER;
    }else if (data -> state == HTTP_HEADER){
        STRTRIM (line_data);
        if (line_data[0] == '\0'){
            // POST PUT definitely have body content
            // also: chunked?
            if(data -> content_length == 0 && !data -> chunked)
                data -> state = HTTP_DONE;
            else
                data -> state = HTTP_BODY;
            data -> cb(data, NULL, 0, data -> userdata);
            free2(line_data);
            data -> cb = NULL;

            // Connection: close ???
            // if(data -> is_client){
            //     FIND_HEADERS(data, "Connection", value, {
            //         if(strcmp(value -> value, "close") == 0){
            //             evfd_close(data -> fd);
            //         }
            //     });
            // }

            return EVCB_RET_DONE;
        }

        SPLIT_HEADER(line_data);    // name&value
        strtolower(line_data);

        // very very long header
        // concat to previous header
        if(!value){
            if(list_empty(&data -> headers)){
                goto error;
            }else{
                LHttpHeader* p = list_entry(data -> headers.prev, LHttpHeader, link);
                p -> value = realloc2(p -> value, p -> vallen + len + 2);
                memcpy(p -> value + p -> vallen, line_data, len);
                p -> vallen += len + 2;
            }
        }
        
        if(!strlen(name) || !strlen(value)) return EVCB_RET_CONTINUE;
        
        if (strcmp(line_data, "content-length") == 0){
            data -> content_length = atoi (value);
        }else if(
            strcmp (line_data, "transfer-encoding") == 0 && 
            strcmp(value, "chunked") == 0
        ){
            data -> chunked = true;
        }else{
            PUT_HEADER2(data, strdup2(name), strdup2(value));
        }
    }


    return EVCB_RET_CONTINUE;

// error_is_http:
//     evfd_write(evfd, (uint8_t*)"HTTP/1.1 400 Bad Request\r\n\r\n", 28, NULL, NULL);
// error:
//     evfd_shutdown(evfd);
error:
    evfd_close(evfd);
error2:
    data -> state = HTTP_ERROR;
    free2(_line_data);
    data -> cb(data, NULL, 0, data -> userdata);
    return EVCB_RET_DONE;
}

// write -> header(each line)
// after write_firstline, write_evloop_callback will be called
static void write_evloop_callback(EvFD* evfd, bool success, void *userdata){
    LHTTPData *data = userdata;
    if (data -> state != HTTP_HEADER)
        return;
    if (list_empty(&data -> headers)){
        data -> state = HTTP_BODY;
        return;
    }

    // maybe closed
    if(!success) return;
    
    struct list_head* el = data -> headers.next;
    list_del(el);

    LHttpHeader* header = list_entry(el, LHttpHeader, link);
    char *line = malloc2(1024);
    sprintf(line, "%s: %s\r\n", header -> key, header -> value);
    evfd_write(data -> fd, (uint8_t*)line, strlen(line), write_evloop_callback, data);
    free2(line);
}

// write first line of response/request
// after write_firstline, write_evloop_callback will be called
static inline void write_firstline(int fd, LHTTPData *data){
    char *first_line = malloc2(1024);
    if(data -> is_client){
        sprintf(first_line, "%s %s HTTP/%.1f\r\n", data -> method, data -> path, data -> version);
    }else{
        sprintf(first_line, "HTTP/%.1f %d OK\r\n", data -> version, data -> status);
    }
    evfd_write(data -> fd, (uint8_t*)first_line, strlen(first_line), write_evloop_callback, data);
    free2(first_line);
}

// read and parse body from socket fd.
static inline void read_body(LHTTPData *data, HTTP_ParseCallback callback, void *userdata, bool readall){
    assert(data -> state == HTTP_BODY);
    data -> cb = callback;
    data -> userdata = userdata;
    data -> __read_all = readall;

    if(data -> content_length == 0 && !data -> chunked){
        data -> state = HTTP_DONE;
        data -> cb(data, NULL, 0, data -> userdata);
        return;
    }

    uint8_t *buffer = malloc2(BUFFER_SIZE);
    if(data -> chunked) evfd_readline(data -> fd, BUFFER_SIZE, buffer, parse_evloop_body_callback, data);
    else evfd_read(data -> fd, BUFFER_SIZE, buffer, parse_evloop_body_callback, data);
}

// Parse the header part of the HTTP request/response.
// Note: is_client: the incoming request is from client
void LJS_parse_from_fd(EvFD* fd, LHTTPData *data, bool is_client, 
    HTTP_ParseCallback callback, void *userdata
){
    init_http_data(data, is_client);
    data -> fd = fd;
    data -> cb = callback;
    data -> userdata = userdata;

    // write the first line
    uint8_t *buffer = malloc2(MAX_HEADER_SIZE);
    evfd_readline(data -> fd, MAX_HEADER_SIZE, buffer, parse_evloop_callback, data);
}

// JS response object
struct HTTP_Response{
    LHTTPData *data;
    JSValue header; // to avoid the effort of header_finalizer

    bool locked;
    bool owned;     // if false, will not free data
    bool keepalive;
};
static thread_local JSClassID response_class_id;

static JSValue js_response_get_status(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque2(ctx, this_val, response_class_id);
    if(!response) return JS_EXCEPTION;
    return JS_NewInt32(ctx, response -> data -> status);
}

static JSValue js_response_get_ok(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque2(ctx, this_val, response_class_id);
    if(!response) return JS_EXCEPTION;
    return JS_NewBool(ctx, response -> data -> status - 200 < 100);
}

static JSValue js_response_get_headers(JSContext *ctx, JSValueConst this_val) {
    struct HTTP_Response *response = JS_GetOpaque2(ctx, this_val, response_class_id);
    if(!response) return JS_EXCEPTION;
    return JS_DupValue(ctx, response -> header);
}

// after read the whole body, return the content as a string to JS
// as `read_body` callback
static void callback_tou8(LHTTPData *data, uint8_t *buffer, uint32_t len, void *userdata){
    Promise *promise = userdata;
    if(NULL == buffer){
        if(data -> state == HTTP_ERROR)
            js_reject(promise, "Failed to receive data");
        else
            js_resolve(promise, JS_UNDEFINED);
    }else{
        js_resolve(promise,
            JS_NewUint8Array(js_get_promise_context(promise), buffer, len, free_js_malloc, NULL, false)
        );
    }
}

// for U8Pipe
static JSValue response_poll(JSContext* ctx, void* ptr, JSValue __){
    Promise *promise = js_promise(ctx);
    JSValue ret = js_get_promise(promise);
    struct HTTP_Response *response = ptr;
    read_body(response -> data, callback_tou8, promise, false);
    return ret;
}

struct buf_link {
    uint8_t* buf;
    uint32_t len;
    
    struct list_head list;
};

struct readall_promise{
    Promise *promise;
    struct list_head u8arrs;
    struct HTTP_Response *response;

    bool tostr;
    bool tojson;
    bool urlform;

    void* addition_data;
};

// init task
static inline struct readall_promise* init_tou8_merge_task(Promise *promise, struct HTTP_Response *response){
    struct readall_promise *task = malloc2(sizeof(struct readall_promise));
    task -> promise = promise;
    task -> response = response;
    task -> tostr = false;
    task -> tojson = false;
    task -> urlform = false;
    task -> addition_data = NULL;
    init_list_head(&task -> u8arrs);
    return task;
}

// (from `read_body` callback) push chunks to task -> u8arrs and merge
static void response_merge_cb(LHTTPData *data, uint8_t *buffer, uint32_t len, void *userdata){
    struct readall_promise *task = userdata;

    // data received
    if(data -> state == HTTP_DONE){
        // merge u8arrs
        struct list_head *tmp, *cur;
        int length = task -> response -> data -> content_length
            ? task -> response -> data -> content_length
            : task -> response -> data -> content_resolved;
        JSContext* ctx = js_get_promise_context(task -> promise);
        uint8_t* merged_buf = js_malloc(ctx, length +1);
        size_t copy_len = 0;

        list_for_each_safe(cur, tmp, &task -> u8arrs){
            struct buf_link *bufobj = list_entry(cur, struct buf_link, list);
            size_t copy_len2 = MIN(bufobj -> len, length - copy_len);
            memcpy(merged_buf + copy_len, bufobj -> buf, copy_len2);
            copy_len += copy_len2;
            free2(bufobj -> buf);
            free2(bufobj);
        }

        merged_buf[copy_len] = '\0';

        JSValue res;
        if(task -> tostr){
            res = JS_NewStringLen(ctx, (char*)merged_buf, length);
        }else if(task -> tojson){
            res = JS_ParseJSON(ctx, (char*)merged_buf, length, "<httpstream>.json");
        }else if(task -> urlform){
            struct list_head query;
            init_list_head(&query);
            if(!url_parse_query((char*)merged_buf, &query)){
                js_reject(task -> promise, "Invalid url query");
                free2(merged_buf);
            }

            struct list_head *cur, *tmp;
            res = JS_NewObject(ctx);
            list_for_each_safe(cur, tmp, &query){
                URL_query* param = list_entry(cur, URL_query, link);
                JSValue val = JS_NewString(ctx, param -> value);
                JS_SetPropertyStr(ctx, res, param -> key, val);
                free2(param -> key);
                free2(param -> value);
            }
        }else{
            res = JS_NewUint8Array(ctx, merged_buf, length -1, free_js_malloc, NULL, false);
        }
        js_resolve(task -> promise, res);
        JS_FreeValue(ctx, res);
        free2(merged_buf);

        // then close the response if not keepalive
        if(task -> response -> keepalive){
            // fetch: keepalive
            if(!data -> is_client){
                pthread_mutex_lock(&keepalive_mutex);
                struct keepalive_connection* ka = malloc2(sizeof(struct keepalive_connection));
                ka -> fd = data -> fd;
                strcpy(ka -> host, data -> __target_host);
                list_add_tail(&ka -> list, &keepalive_list);
                pthread_mutex_unlock(&keepalive_mutex);
            }
        }else{
            evfd_close(task -> response -> data -> fd);
            task -> response -> data -> fd = false;
        }

        // after this, buffer=NULL will be passed to this again

    // done
    }else if(data -> state == HTTP_BODY){
        // push to u8arrs
        struct buf_link *bufobj = malloc2(sizeof(struct buf_link));
        bufobj -> buf = buffer;
        bufobj -> len = len;
        list_add_tail(&bufobj -> list, &task -> u8arrs);
    // error
    }else{
        // finalize: close callback
        struct list_head *tmp, *cur;
        list_for_each_safe(cur, tmp, &task -> u8arrs){
            struct buf_link *bufobj = list_entry(cur, struct buf_link, list);
            free2(bufobj -> buf);
            free2(bufobj);
        }

        Promise *promise = task -> promise;
        // if(data -> state == HTTP_ERROR)
        js_reject3(promise, "Failed to receive data: %ld bytes missed due to EOF", data -> content_length - data -> content_resolved);
        // else
        //     LJS_Promise_Resolve(promise, )
        free2(task); // done!
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

    struct list_head formdata;  // add to tail
};

// parse form data from response body
static inline struct formdata_addition_data* init_formdata_parse_task(Promise *promise, struct HTTP_Response *response){
    struct formdata_addition_data *task = malloc2(sizeof(struct formdata_addition_data));
    task -> state = FD_BOUNDARY;
    task -> readed = 0;
    init_list_head(&task -> formdata);
    return task;
}

#define SET_IF_NOT_NULL(obj, prop, val) if(val){ \
    JS_SetPropertyStr(ctx, obj, prop, JS_NewString(ctx, val)); \
    free2(val); \
}
#define FREE_IF_NOT_NULL(obj) if(obj) js_free(ctx, obj);

static int callback_formdata_parse(EvFD* evfd, bool ok, uint8_t* buffer, uint32_t read_size, void* userdata){
    struct readall_promise *task = userdata;
    struct formdata_addition_data *fd_task = task -> addition_data;
    JSContext *ctx = js_get_promise_context(task -> promise);
    
    if(!ok) goto end_callback;  // data reached EOF
    fd_task -> readed += read_size;

    // blank line: end of header
    if (fd_task -> state == FD_NEWLINE) {
        fd_task -> state = FD_HEADER;
        return EVCB_RET_CONTINUE;
    }

    // ------WebKitFormBoundaryABC123
    if (fd_task -> state == FD_BOUNDARY) {
        char* line = (char*) buffer;
        if (line[0] != '-' || line[1] != '-' || strcmp(line + 2, fd_task -> boundary) != 0) {
            // error
            js_reject(task -> promise, "Invalid boundary");
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
            evfd_readsize(evfd, formdata -> length, buf, parse_evloop_body_callback, formdata);

            js_free(ctx, _line);
            return EVCB_RET_DONE;   // switch to content
        }

        SPLIT_HEADER(line);
        if (!value) {
            // error
            js_reject(task -> promise, "Invalid header");
            goto end_cleanup;
        }

        if (strcmp(name, "Content-Disposition") == 0) {
            char* filename = NULL;
            char* type = NULL;
            char* tmp = strchr(value, ';');
            if (tmp) {
                *tmp = '\0';
                tmp += 1;
                STRTRIM(tmp);
                char* tmp2 = strstr(tmp, "filename=");
                if (tmp2) {
                    tmp2 += 9;
                    STRTRIM(tmp2);
                    filename = strdup2(tmp2);
                }
                tmp2 = strstr(tmp, "type=");
                if (tmp2) {
                    tmp2 += 5;
                    STRTRIM(tmp2);
                    type = strdup2(tmp2);
                }
            } else {
                filename = strdup2(value);
            }
            formdata -> filename = filename;
            formdata -> type = type;
        } else if (strcmp(name, "Content-Type") == 0) {
            formdata -> type = strdup2(value);
        } else if (strcmp(name, "Content-Length") == 0) {
            int len = atoi(value);
            if (len < 0) {
                // error
                js_reject(task -> promise, "Invalid content-length");
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
            js_reject(task -> promise, "Failed to receive data: short readed");
            goto end_cleanup;
        }

        // already recv all data
        formdata -> data = buffer;

        // end
        if(fd_task -> readed == formdata -> length) goto end_callback;

        // newline: the buffer will be reused for header
        fd_task -> state = FD_NEWLINE;
        uint8_t* buf = js_malloc(ctx, BUFFER_SIZE);
        evfd_readline(evfd, BUFFER_SIZE, buf, parse_evloop_body_callback, formdata);

        return EVCB_RET_DONE;
    }

    struct list_head *tmp, *cur;
end_callback:
    JSValue array = JS_NewArray(ctx);
    uint32_t i = 0;
    
    // build formdata array
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
    js_resolve(task -> promise, array);
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
    free2(fd_task);
    return EVCB_RET_DONE;
}

#define RESPONSE_GET_OPAQUE(var, this_val) \
    struct HTTP_Response *var = JS_GetOpaque2(ctx, this_val, response_class_id); \
    if(!var) return JS_EXCEPTION; \
    if(var -> locked) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Body is locked", NULL);

static JSValue js_response_body(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    RESPONSE_GET_OPAQUE(response, this_val);

    response -> locked = true;
    JSValue pipe = LJS_NewU8Pipe(ctx, PIPE_READ, response_poll, NULL, NULL, response);
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
    Promise *promise = js_promise(ctx); \
    JSValue retval = js_get_promise(promise); \
    struct readall_promise* data = init_tou8_merge_task(promise, response);

static JSValue js_response_buffer(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    INIT_TOU8_TASK
    read_body(response -> data, response_merge_cb, data, true);
    return retval;
}

static JSValue js_response_text(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    INIT_TOU8_TASK
    data -> tostr = true;
    read_body(response -> data, response_merge_cb, data, true);
    return retval;
}

static JSValue js_response_json(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    INIT_TOU8_TASK
    data -> tojson = true;
    read_body(response -> data, response_merge_cb, data, true);
    return retval;
}

static JSValue js_response_formData(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    RESPONSE_GET_OPAQUE(response, this_val);

    // get form info
    char* boundary;
    FIND_HEADERS(response -> data, "content-type", value, {
        if(memcmp(value -> value, "multipart/form-data", 19) == 0){
            char* bound = strstr(value -> value, "boundary=");
            if(bound){
                bound += 9;
                STRTRIM(bound);
                boundary = bound;
                goto main;
            }else{
                goto not_found;   
            }
        }else if(memcmp(value -> value, "application/x-www-form-urlencoded", 33) == 0){
            goto urlform;
        }else{
            return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Unsupported content-type %s", NULL, value -> value);
        }
    });

not_found:
    return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid or missing content-type. Please ensure boundary is set", NULL);

main:
    Promise *promise = js_promise(ctx);
    struct formdata_addition_data* task = init_formdata_parse_task(promise, response);
    task -> boundary = boundary;
    uint8_t* buf = js_malloc(ctx, BUFFER_SIZE);
    JSValue ret = js_get_promise(promise);
    evfd_readline(response -> data -> fd, BUFFER_SIZE, buf, callback_formdata_parse, task);
    return ret;

urlform:{
    INIT_TOU8_TASK;
    data -> urlform = true;
    read_body(response -> data, response_merge_cb, data, true);
    return retval;
}
}

#define RESPONSE_GET_OPAQUE2(var, this_val) \
    struct HTTP_Response *var = JS_GetOpaque2(ctx, this_val, response_class_id); \
    if(!var) return JS_EXCEPTION;

static JSValue js_response_get_method(JSContext *ctx, JSValueConst this_val) {
    RESPONSE_GET_OPAQUE2(response, this_val);
    return response -> data -> method
         ? JS_NewString(ctx, response -> data -> method)
         : JS_UNDEFINED;
}

static JSValue js_response_get_path(JSContext *ctx, JSValueConst this_val) {
    RESPONSE_GET_OPAQUE2(response, this_val);
    return response -> data -> path
        ? JS_NewString(ctx, response -> data -> path)
         : JS_UNDEFINED;
}

static JSValue js_response_get_http_version(JSContext *ctx, JSValueConst this_val) {
    RESPONSE_GET_OPAQUE2(response, this_val);
    return JS_NewFloat64(ctx, response -> data -> version);
}

static void js_response_finalizer(JSRuntime *rt, JSValue val) {
    struct HTTP_Response *response = JS_GetOpaque(val, response_class_id);
    if(response){
        if(response -> data && response -> owned)
            headers_finalizer(rt, response -> header);
        JS_SetOpaque(response -> header, NULL); // fail safe
        JS_FreeValueRT(rt, response -> header);
        
        if(response -> data && response -> owned){
            LJS_free_http_data(response -> data);
            js_free_rt(rt, response -> data);
        }
        
        js_free_rt(rt, response);
    }
}

static JSValue js_response_constructor(JSContext *ctx, JSValueConst new_target, int argc, JSValueConst *argv) {
    JSValue obj = JS_NewObjectClass(ctx, response_class_id);
    struct HTTP_Response *response = js_malloc(ctx, sizeof(struct HTTP_Response));
    response -> data = NULL;
    response -> locked = false;
    response -> owned = true;
    response -> keepalive = false;
    response -> header = JS_UNDEFINED;
    JS_SetOpaque(obj, response);
    return obj;
}

static JSValue response_close_job(JSContext *ctx, int argc, JSValueConst *argv){
    EvFD* evfd = JS_VALUE_GET_PTR(argv[0]);
    evfd_close(evfd);
    return JS_UNDEFINED;
}

// create Response object
// Note: header object will be defined internally
// Note: if keepalive=false, the connection will be closed after readed whole response
JSValue LJS_NewResponse(JSContext *ctx, LHTTPData *data, bool readonly, bool keepalive){
    JSValue obj = JS_NewObjectClass(ctx, response_class_id);
    struct HTTP_Response *response = js_malloc(ctx, sizeof(struct HTTP_Response));
    response -> data = data;
    response -> locked = readonly;
    response -> owned = false;
    response -> keepalive = keepalive;
    response -> header = LJS_NewHeaders(ctx, data);
    JS_SetOpaque(obj, response);
    
    if(
        !response -> keepalive && !data -> is_client &&
        !data -> chunked && data -> content_length == 0
    ){
        // close connection due to no body
        JS_EnqueueJob(ctx, response_close_job, 1, (JSValueConst[]){ JS_MKPTR(JS_TAG_INT, data -> fd) });
    }

    return obj;
}

static JSClassDef response_class = {
    "Response",
    .finalizer = js_response_finalizer
};
static JSCFunctionListEntry response_proto_funcs[] = {
    JS_CGETSET_DEF("status", js_response_get_status, NULL),
    JS_CGETSET_DEF("locked", js_response_get_locked, NULL),
    JS_CGETSET_DEF("ok", js_response_get_ok, NULL),
    JS_CGETSET_DEF("headers", js_response_get_headers, NULL),
    
    JS_CFUNC_DEF("bytes", 0, js_response_buffer),
    JS_CFUNC_DEF("text", 0, js_response_text),
    JS_CFUNC_DEF("json", 0, js_response_json),
    JS_CFUNC_DEF("formData", 0, js_response_formData),
    JS_CFUNC_DEF("body", 0, js_response_body),

    // not standard
    JS_CGETSET_DEF("method", js_response_get_method, NULL),
    JS_CGETSET_DEF("path", js_response_get_path, NULL),
    JS_CGETSET_DEF("httpVersion", js_response_get_http_version, NULL),
};

// fetch API
__attribute__((constructor)) static void init_keepalive_list(){
    init_list_head(&keepalive_list);
    pthread_mutex_init(&keepalive_mutex, NULL);
}

struct FetchResult {
    Promise* promise;
    struct keepalive_connection* keepalive;
};

// alert: buffer = NULL
// fetch: return Response object
void fetch_resolve(LHTTPData *data, uint8_t *buffer, uint32_t len, void* ptr){
    struct FetchResult *fr = ptr;
    Promise* promise = fr -> promise;
    JSContext *ctx = js_get_promise_context(promise);

    // closed connection
    if(data -> state == HTTP_ERROR){
        // will be rejected in fetch_close_cb
        return;
    }

    // create Response object and grand ownership to it
    JSValue obj = LJS_NewResponse(ctx, data, false, fr -> keepalive);
    ((struct HTTP_Response*)JS_GetOpaque(obj, response_class_id)) -> owned = true;
    js_resolve(promise, obj);
    JS_FreeValue(ctx, obj);
    // del onclose callback
    evfd_onclose(data -> fd, NULL, NULL);

    js_free(ctx, fr);
}

// fetch: return WebSocket object
void ws_resolve(LHTTPData *data, uint8_t *buffer, uint32_t len, void* ptr){
    Promise *promise = ptr;
    JSContext *ctx = js_get_promise_context(promise);
    JSValue obj = LJS_NewWebSocket(ctx, data -> fd, data -> is_client);
    js_resolve(promise, obj);
    // del onclose callback
    evfd_onclose(data -> fd, NULL, NULL);
}

// pipeTo: add chunk length to buffer
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

// reject on fd close
static void fetch_close_cb(EvFD* evfd, bool is_rdhup, void* user_data){
    Promise *promise = user_data;
    if(is_rdhup) return;
    if(evfd_ssl_errno(evfd) != 0){
        char ebuf[512] = {0};
        mbedtls_strerror(evfd_ssl_errno(evfd), ebuf, sizeof(ebuf));
        js_reject3(promise, "TLS connection error: %s", ebuf);
    }else{
        js_reject(promise, "Connection closed or failed");
    }
}

// free after write
// Note: do not use `js_malloc`
static void write_then_free(EvFD* evfd, bool success, void* opaque){
    free2(opaque);
}

// create random key for websocket request
static inline char* ws_random_key(){
    static uint8_t key[24];
    if(-1 == getrandom(key, 24, GRND_NONBLOCK))
        for (uint8_t i = 0; i < 24; i++) key[i] = (rand() >> 5) & 0xff;

    char* result = malloc2(40);
    base64_encode(key, 24, result);
    return result;
}

// format and write to fd
#define FORMAT_WRITE(template, guessed_size, ...) { \
    char* buf = malloc2(guessed_size +2); \
    int len = snprintf(buf, guessed_size, template "\r\n", __VA_ARGS__); \
    assert(len > 0); \
    evfd_write(fd, (uint8_t*) buf, len, write_then_free, buf); \
}

#define WS_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static inline void path_basic_fill(URL_data* data){
    if(!data -> path) data -> path = strdup2("/");
}

static JSValue js_fetch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(unlikely(argc == 0))
        LJS_ThrowInAsync(ctx, EXCEPTION_TYPEERROR, "Fetch requires at least 1 argument", "fetch(url: string, options?: FetchInit): Promise<Response>");
    
    // parse URL
    const char *urlstr = JS_ToCString(ctx, argv[0]);
    if(!urlstr) return JS_EXCEPTION;
    URL_data url = {};
    if(unlikely(!LJS_parse_url(urlstr, &url, NULL) || url.protocol == NULL || url.host == NULL)){
        JS_FreeCString(ctx, urlstr);
        LJS_ThrowInAsync(ctx, EXCEPTION_TYPEERROR, "Invalid URL", NULL);
    }
    path_basic_fill(&url);
    JS_FreeCString(ctx, urlstr);
    
    if(unlikely(strstr(url.protocol, "http") == NULL && strstr(url.protocol, "ws") == NULL)){
        LJS_free_url(&url);
        LJS_ThrowInAsync(ctx, EXCEPTION_TYPEERROR, "Unsupported protocol %s", NULL, url.protocol);
    }

    JSValue obj = argc >= 2 ? JS_DupValue(ctx, argv[1]) : JS_NewObject(ctx);
    bool websocket = strstr(url.protocol, "ws") != NULL;
    bool tls = url.protocol && url.protocol[strlen(url.protocol) - 1] == 's';

    // find available connection
    EvFD* fd = NULL;
    JSValue jsobj;
    jsobj = JS_GetPropertyStr(ctx, obj, "keepalive");
    bool keep_alive = JS_IsBool(jsobj) ? JS_ToBool(ctx, jsobj) : false;
    JS_FreeValue(ctx, jsobj);
    if(unlikely(!keep_alive && websocket)){
        JS_FreeValue(ctx, obj);
        LJS_ThrowInAsync(ctx, EXCEPTION_TYPEERROR, "WebSocket connection requires keepalive option", NULL);
    }
    if(keep_alive){
        pthread_mutex_lock(&keepalive_mutex);
        struct list_head *cur, *tmp;
        struct keepalive_connection *conn;
        list_for_each_safe(cur, tmp, &keepalive_list){
            conn = list_entry(cur, struct keepalive_connection, list);
            if(strcmp(conn -> host, url.host) == 0){
                list_del(cur);
                fd = conn -> fd;
                free2(conn); // TODO: reuse it
                break;
            }
        }
        pthread_mutex_unlock(&keepalive_mutex);
    }
    if(!fd || evfd_closed(fd)){
        // open new connection
        // ws -> tcp, wss -> ssl
        fd = LJS_open_socket(url.protocol, url.host, url.port, BUFFER_SIZE, &(InitSSLOptions){
            .server_name = url.host,
            .alpn_protocols = (const char*[]){ "http/1.1", NULL }
        });
        if(!fd || evfd_closed(fd)){
            JS_FreeValue(ctx, obj);
            if(errno == ENOTSUP)
                LJS_ThrowInAsync(ctx, EXCEPTION_INTERNAL, "Unsupported protocol %s", 
                    "if you are using TLS-based protocol, make sure you have enabled MbedTLS in build time"
                    , url.protocol)
            else if(errno == EADDRNOTAVAIL)
                LJS_ThrowInAsync(ctx, EXCEPTION_IO, "Failed to resolve host %s", NULL, url.host)
            else
                LJS_ThrowInAsync(ctx, EXCEPTION_IO, "Failed to open connection", NULL);
        }
    }

    // bind close event
    Promise *promise = js_promise(ctx);
    evfd_onclose(fd, fetch_close_cb, promise);

    // parse options and write headers
    // GET / HTTP/1.1
    char* method = (char*) LJS_ToCString(ctx, jsobj = JS_GetPropertyStr(ctx, obj, "method"), NULL);
    JS_FreeValue(ctx, jsobj);
    if (method) JS_FreeValue(ctx, jsobj);   // FreeCString
    if (!method) method = "GET";
    FORMAT_WRITE("%s %s HTTP/1.1", strlen(method) + strlen(url.path) + 16, method, url.path);

    // keep-alive
    if (keep_alive) {
        evfd_write(fd, (uint8_t*) "Connection: keep-alive\r\n", 24, NULL, NULL);
    } else {
        evfd_write(fd, (uint8_t*) "Connection: close\r\n", 19, NULL, NULL);
    }

    // referer
    const char* referer = LJS_ToCString(ctx, jsobj = JS_GetPropertyStr(ctx, obj, "referer"), NULL);
    JS_FreeValue(ctx, jsobj);
    if (referer)
        FORMAT_WRITE("Referer: %s", strlen(referer) + 16, referer);

    // host
    if(JS_IsUndefined(jsobj = JS_GetPropertyStr(ctx, obj, "host"))){
        if(tls ? url.port == 443 : url.port == 80)
            FORMAT_WRITE("Host: %s", strlen(url.host) + 16, url.host)
        else
            FORMAT_WRITE("Host: %s:%d", strlen(url.host) + 16 + 5, url.host, url.port)
    }
    JS_FreeValue(ctx, jsobj);
    
    // websocket?
    if(websocket){
        // connection upgrade
        evfd_write(fd, (uint8_t*) "Connection: Upgrade\r\n", 21, NULL, NULL);
        evfd_write(fd, (uint8_t*) "Upgrade: websocket\r\n", 20, NULL, NULL);
        evfd_write(fd, (uint8_t*) "Sec-WebSocket-Version: 13\r\n", 27, NULL, NULL);
        char* key = ws_random_key();
        FORMAT_WRITE("Sec-WebSocket-Key: %s", 64, key);
        free2(key);
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
                const char* value = JS_ToCString(ctx, jsobj = JS_GetProperty(ctx, headers, props[i].atom));
                JS_FreeValue(ctx, jsobj);
                if (key && value) {
                    if (
                        strcasecmp(key, "method") == 0 || 
                        strcasecmp(key, "keepalive") == 0 || 
                        strcasecmp(key, "referer") == 0
                    ) {
                        continue;
                    }
                    FORMAT_WRITE("%s: %s", strlen(key) + strlen(value) + 16, key, value);
                }
                JS_FreeCString(ctx, key);
                JS_FreeCString(ctx, value);
            }
        }
    }
    JS_FreeValue(ctx, headers);

    // body
    JSValue body = JS_GetPropertyStr(ctx, obj, "body");
    if(strcmp(method, "GET") && strcmp(method, "HEAD") && strcmp(method, "OPTIONS")){
        // typedarray
        if (JS_GetTypedArrayType(body) != -1 || JS_IsString(body)) {
            size_t data_len;
            uint8_t* data = JS_IsString(body) 
                ? (uint8_t*) JS_ToCStringLen(ctx, &data_len, body) 
                : JS_GetArrayBuffer(ctx, &data_len, body);
            if(data_len){
                if (data) {
                    size_t len = 21 + sizeof(size_t);
                    char* buf = malloc2(len);
                    snprintf(buf, len, "Content-Length: %lu\r\n\r\n", data_len);
                    evfd_write(fd, (uint8_t*) buf, len, write_then_free, buf);
                    free2(buf);
                }

                // body content
                // Note: u8 will likely to be changed in JS, clone it 
                uint8_t* data2 = malloc2(data_len);
                memcpy(data2, data, data_len);
                evfd_write(fd, data2, data_len, write_then_free, data2);
            }else{
                evfd_write(fd, (uint8_t*) "Content-Length: 0\r\n\r\n", 21, NULL, NULL);
            }
            if(JS_IsString(body)) JS_FreeCString(ctx, (char*) data);
        }else if(JS_IsObject(body)){
            // pipeTo chunked
            EvFD* body_fd = LJS_GetPipeFD(ctx, body);
            if(!body_fd) {
                // content 0
                evfd_write(fd, (uint8_t*) "Content-Length: 0\r\n\r\n", 21, NULL, NULL);
            }else{
                evfd_pipeTo(fd, body_fd, body_chunked_filter, NULL, NULL, NULL);
                evfd_write(fd, (uint8_t*) "\r\n", 2, NULL, NULL);
            }
        }else{
            evfd_write(fd, (uint8_t*) "Content-Length: 0\r\n\r\n", 21, NULL, NULL);
        }
    }else{
        evfd_write(fd, (uint8_t*) "\r\n", 2, NULL, NULL);
    }
    JS_FreeValue(ctx, body);

    struct FetchResult* fr;
    if(!websocket){
        fr = js_malloc(ctx, sizeof(struct FetchResult));
        fr -> promise = promise;
        fr -> keepalive = NULL;
    }

    // keepalive?
    if (keep_alive && !websocket) {
        struct keepalive_connection* conn = malloc2(sizeof(struct keepalive_connection));
        conn -> fd = fd;
        strncpy(conn -> host, url.host, 64);
        fr -> keepalive = conn;
    }

    // parse response
    LHTTPData *data = js_malloc(ctx, sizeof(LHTTPData));
    JSValue ret = js_get_promise(promise);
    data -> __target_host = js_strdup(ctx, url.host);
    LJS_parse_from_fd(fd, data, false, websocket ? ws_resolve : fetch_resolve, websocket ? (void*)promise : (void*)fr);
    LJS_free_url(&url);
    JS_FreeValue(ctx, obj);
    return ret;
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
    Promise* send_promise;

    bool closed;
    uint8_t free_count;    // refcount, used by eventloop and JS
};

// parse received data
static int event_ws_readable(EvFD* evfd, bool _, uint8_t* buffer, uint32_t read_size, void* user_data){
    struct JSWebSocket_T* ws = user_data;
    int fd = evfd_getfd(evfd, NULL);
    if(buffer_read(&ws -> rbuffer, fd, UINT32_MAX) <= 0) return 0;

    uint32_t bufsize = buffer_used(&ws -> rbuffer);

    if(!ws -> in_payload){
        // payload data
        if(bufsize < 4) return 0;
        bool completed = false;
        uint32_t payload_end_offset = 0;
        uint8_t payload_len[8];
        BUFFER_UNSAFE_FOREACH_BYTE(&ws -> rbuffer, index, byte){
            // TODO: cache the result in previous call?
            if(index == 0){
                // meta
                ws -> frame.fin = byte >> 7;
                ws -> frame.opcode = byte & 0xf;
            }else if(index == 1){
                // payload length
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
                // long payload length
#if __ORDER_BIG_ENDIAN__ == __BYTE_ORDER__
                payload_len[index - 2] = byte;
#else
                payload_len[7 - (index - 2)] = byte;
#endif
            }else if(ws -> frame.mask && index >= payload_end_offset && index < payload_end_offset + 4){
                // mask key(for security)
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

            // unmask
            if(ws -> frame.mask){
                for(uint32_t i = 0; i < ws -> frame.payload_len; i++){
                    buf[i] ^= ws -> frame.mask_key[i % 4];
                }
            }
            JSValue array = JS_NewUint8Array(ws -> ctx, buf, ws -> frame.payload_len, free_js_malloc, NULL, false);

            // call JS callback
            assert(JS_IsFunction(ws -> ctx, ws -> onmessage));
            JS_Call(ws -> ctx, ws -> onmessage, JS_UNDEFINED, 2, (JSValueConst[]){ 
                array, JS_NewBool(ws -> ctx, ws -> frame.fin)
            });
            ws -> in_payload = false;
        }
    }

    return 0;
}

// after freed both in JS and C, call this function to free the memory
static void js_ws_free(JSRuntime *rt, struct JSWebSocket_T* ws){
    if(ws -> free_count < 2) return;
    if(!ws -> closed){
        evfd_close(ws -> fd);
        return; // will re-call this function
    }

    buffer_free(&ws -> rbuffer);
    buffer_free(&ws -> wbuffer);
    JS_FreeValue(ws -> ctx, ws -> onmessage);
    JS_FreeValue(ws -> ctx, ws -> onclose);
    
    js_free(ws -> ctx, ws);
}

// callback from eventloop
static void event_ws_close(EvFD* evfd, bool _, void* user_data){
    struct JSWebSocket_T* ws = user_data;
    ws -> closed = true;
    ws -> free_count ++;
    if(JS_IsFunction(ws -> ctx, ws -> onclose)){
        JS_Call(ws -> ctx, ws -> onclose, JS_UNDEFINED, 0, NULL);
    }
    if(ws -> send_promise)
        js_reject(ws -> send_promise, "WebSocket is already closed");

    js_ws_free(JS_GetRuntime(ws -> ctx), ws);
}

// callback from JS
static void js_ws_finalizer(JSRuntime *rt, JSValue val){
    struct JSWebSocket_T* ws = JS_GetOpaque( val, ws_class_id);
    js_ws_free(rt, ws);
}

// build WebSocket frame
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

// write frame to websocket
static void event_ws_writable(EvFD* evfd, bool __unused__, void* opaque){
    struct JSWebSocket_T* ws = opaque;
    if(!ws -> send_promise) return;
    buffer_write(&ws -> wbuffer, evfd_getfd(evfd, NULL), UINT32_MAX);
    if(buffer_used(&ws -> wbuffer) == 0){
        evfd_yield(evfd, false, true);
        js_resolve(ws -> send_promise, JS_UNDEFINED);
        ws -> send_promise = NULL;
    }
}

static JSValue js_ws_send(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JSWebSocket_T* ws = JS_GetOpaque2(ctx, this_val, ws_class_id);
    if(!ws) return JS_EXCEPTION;

    if(ws -> closed){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "WebSocket is already closed", NULL);
    }
    if(argc != 1){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "WebSocket.send() requires 1 argument", "WebSocket.send(data: Uint8Array | string): Promise<void>");
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
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "WebSocket.send() requires a string or Uint8Array argument", "WebSocket.send(data: Uint8Array | string): Promise<void>");
    }

    Promise* promise = js_promise(ctx);
    ws -> send_promise = promise;
    buffer_init2(&ws -> wbuffer, NULL, len + 16);
    build_ws_frame(&ws -> wbuffer, true, opcode, data, len, ws -> enable_mask);
    if(JS_IsString(argv[0])) JS_FreeCString(ctx, (void*)data);
    evfd_consume(ws -> fd, false, true);
    return js_get_promise(promise);
}

static JSValue js_ws_set_onmessage(JSContext *ctx, JSValueConst this_val, JSValueConst value){
    struct JSWebSocket_T* ws = JS_GetOpaque2(ctx, this_val, ws_class_id);
    if(!ws) return JS_EXCEPTION;
    JS_FreeValue(ctx, ws -> onmessage);
    ws -> onmessage = JS_DupValue(ctx, value);

    if(JS_IsUndefined(value)) evfd_yield(ws -> fd, true, false); // consume readable event
    else evfd_consume(ws -> fd, true, false); // consume readable event

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
        return JS_ThrowTypeError(ctx, "WebSocket is already closed");
    }
    ws -> closed = true;
    evfd_close(ws -> fd);
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
    return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "WebSocket constructor is not implemented, use fetch(ws://) instead", 
        "fetch() returns a Promise<WebSocket> object that is ready to use, easier than WebAPI."
    );
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

    JSValue obj = JS_NewObjectClass(ctx, ws_class_id);

    JSValue pcb[2];
    JSValue promise = JS_NewPromiseCapability(ctx, pcb);
    JS_SetPropertyStr(ctx, obj, "onclose", promise);
    JS_FreeValue(ctx, pcb[1]);
    ws -> onclose = pcb[0];

    evfd_override(fd, 
        event_ws_readable, ws,
        event_ws_writable, ws,
        event_ws_close, ws
    );
    return obj;
}

// --------------------- JAVASCRIPT URL API -----------------------------

struct JS_URL_struct{
    URL_data* self;
    JSValue template;
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
    js_url_struct -> template = JS_UNDEFINED;

    if(argc == 1){
        // single URL
        const char *url = JS_ToCString(ctx, argv[0]);
        if(url == NULL || !LJS_parse_url(url, url_struct, NULL)){
            JS_FreeCString(ctx, url);
            JS_ThrowTypeError(ctx, "Invalid URL");
            goto error;
        }
        JS_FreeCString(ctx, url);
    }else if(argc == 2){
        // parse by base URL(arg#2)
        const char *url = JS_ToCString(ctx, argv[0]);
        if(!likely(url)) return JS_ThrowTypeError(ctx, "Invalid URL");
        URL_data base_url = { 0 };
        URL_data* burl = &base_url;
        if(JS_IsObject(argv[1])){
            URL_data *burl = JS_GetOpaque2(ctx, argv[1], js_class_url_id);
            if(burl == NULL){
                JS_ThrowTypeError(ctx, "Invalid base URL");
                goto error;
            }
            // base URL object
            js_url_struct -> template = JS_DupValue(ctx, argv[1]);
        }else{
            // parse base URL string
            const char *base_url_str = JS_ToCString(ctx, argv[1]);
            if(base_url_str == NULL || !LJS_parse_url(base_url_str, &base_url, NULL)){
                JS_ThrowTypeError(ctx, "Invalid URL");
                goto error;
            }
            JS_FreeCString(ctx, base_url_str);
        }
        if(!likely(LJS_parse_url(url, url_struct, burl))){
            JS_FreeCString(ctx, url);
            JS_ThrowTypeError(ctx, "Invalid base URL");
            goto error;
        }
        JS_FreeCString(ctx, url);
    }else if(unlikely(argc != 0)){
        JS_ThrowTypeError(ctx, "URL constructor takes 0 or 1 argument");
        goto error;
    }
    js_url_struct -> self = url_struct;

    JSValue obj =  JS_NewObjectClass(ctx, js_class_url_id);
    JS_SetOpaque(obj, js_url_struct);
    return obj;

error:
    js_free(ctx, js_url_struct);
    return JS_EXCEPTION;
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
    if (!str) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, err_msg, NULL); \
    js_url_struct -> self -> field = strdup2(str); \
    return JS_UNDEFINED; \
}

#define SETTER_STRING_COPY(func_name, field, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    const char *str = JS_ToCString(ctx, value); \
    if (!str) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, err_msg, NULL); \
    free2(js_url_struct -> self -> field); \
    js_url_struct -> self -> field = strdup2(str); \
    JS_FreeCString(ctx, str); \
    return JS_UNDEFINED; \
}

#define SETTER_INT_RANGE(func_name, field, min, max, err_msg) \
static JSValue func_name(JSContext *ctx, JSValueConst this_val, JSValueConst value) { \
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id); \
    if (!js_url_struct) return JS_EXCEPTION; \
    int32_t val; \
    if (JS_ToInt32(ctx, &val, value) < 0) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, err_msg, NULL); \
    if (val < min || val > max) return JS_ThrowRangeError(ctx, #field " out of range"); \
    js_url_struct -> self -> field = val; \
    return JS_UNDEFINED; \
}

// getter methods
GETTER_STRING(js_url_getProtocol, protocol)
GETTER_STRING(js_url_getHost, host)
GETTER_STRING(js_url_getPath, path)
GETTER_STRING(js_url_getHash, hash)
GETTER_STRING(js_url_getUsername, username)
GETTER_STRING(js_url_getPassword, password)
GETTER_INT(js_url_getPort, port, 0)

// setter methods
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
        return JS_ThrowTypeError(ctx, "Invalid query key");
    }
    const char *value = NULL;
    if(argc == 2){
        value = JS_ToCString(ctx, argv[1]);
        if(value == NULL){
            return JS_ThrowTypeError(ctx, "Invalid query value");
        }
    }

    URL_query* query = js_malloc(ctx, sizeof(URL_query));
    if(query == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }
    query -> key = js_strdup(ctx, key);
    query -> value = value? js_strdup(ctx, value) : NULL;
    list_add_tail(&url_struct -> query, &query -> link);
    return JS_UNDEFINED;
}

JSValue js_url_delQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }

    uint32_t del_id = -1;
    char* key;
    if(argc == 1){
        key = (char*)JS_ToCString(ctx, argv[0]);
        if(key == NULL){
            return JS_ThrowTypeError(ctx, "Invalid query key");
        }
    }else if(argc == 2){
        key = (char*)JS_ToCString(ctx, argv[0]);
        if(-1 == JS_ToUint32(ctx, &del_id, argv[1]) || key == NULL){
            return JS_ThrowTypeError(ctx, "Invalid arguments");
        }
    }else{
        return JS_ThrowTypeError(ctx, "delQuery takes 1 or 2 arguments");
    }

    uint32_t key_occurrence = 0;
    bool found = false;
    struct list_head* pos;
    list_for_each(pos, &js_url_struct -> self -> query){
        URL_query* query = list_entry(pos, URL_query, link);
        if(strcmp(query -> key, key) == 0){
            if(del_id == -1 || del_id == key_occurrence){
                found = true;
                js_free(ctx, query -> key);
                if(query -> value != NULL){
                    js_free(ctx, query -> value);
                }
                js_free(ctx, query);
                list_del(pos);
                break;
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
    free2(data);
    return url_val;
}


static JSValue js_url_getQueryStr(JSContext *ctx, JSValueConst this_val){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    char *query_str = js_malloc(ctx, 1024);
    
    size_t qoffset = 0;
    if(query_str == NULL){
        return JS_ThrowOutOfMemory(ctx);
    }

#define PUT(str) memcpy(query_str + qoffset, str, strlen(str)); qoffset += strlen(str);
#define PUTC(c) query_str[qoffset++] = c;
    
    struct list_head* pos;
    list_for_each(pos, &url_struct -> query){
        URL_query* query = list_entry(pos, URL_query, link);
        PUT(query -> key);
        if(query -> value){
            PUTC('='); PUT(query -> value);
        }
        PUTC('&');
    }
    if(qoffset > 0){
        qoffset -= 1;    
    }
    query_str[qoffset] = '\0';
    JSValue query_val = JS_NewStringLen(ctx, query_str, qoffset);
    free2(query_str);
    return query_val;
}

static JSValue js_url_getQuery(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    
    const char* search = argc >= 1 ? LJS_ToCString(ctx, argv[0], NULL) : NULL;
    JSValue query_obj = search ? JS_NewArray(ctx) : JS_NewObject(ctx);
    size_t arrlen = 0;

    struct list_head* pos;
    list_for_each(pos, &url_struct -> query){
        URL_query* query = list_entry(pos, URL_query, link);

        if(search){
            if(strcmp(query -> key, search) == 0){
                JSValue value_val = JS_NewString(ctx, query -> value);
                JS_SetPropertyUint32(ctx, query_obj, arrlen ++, value_val);
            }
            continue;
        }

        JSValue value_arr;
        int64_t len = 0;
        if(JS_IsUndefined(value_arr = JS_GetPropertyStr(ctx, query_obj, query -> key))){
            value_arr = JS_NewArray(ctx);   // ref=1
            JS_SetPropertyStr(ctx, query_obj, query -> key, JS_DupValue(ctx, value_arr));   //ref+1-1
        }else{
            JS_GetLength(ctx, value_arr, &len);
        }
        if(likely(query -> value)){
            JSValue value_val = JS_NewString(ctx, query -> value);
            JS_SetPropertyUint32(ctx, value_arr, len ++, value_val);
        }
        JS_FreeValue(ctx, value_arr);   // ref=0
        JS_SetLength(ctx, value_arr, len);
    }

    if(search) JS_SetLength(ctx, query_obj, arrlen);
    return query_obj;
}


JSValue js_url_setQueryStr(JSContext *ctx, JSValueConst this_val, JSValue value){
    struct JS_URL_struct *js_url_struct = JS_GetOpaque2(ctx, this_val, js_class_url_id);
    if(js_url_struct == NULL){
        return JS_EXCEPTION;
    }
    URL_data *url_struct = js_url_struct -> self;
    const char *query = JS_ToCString(ctx, value);

    // clear previous query
    struct list_head *pos, *tmp;
    list_for_each_safe(pos, tmp, &url_struct -> query){
        URL_query* query = list_entry(pos, URL_query, link);
        js_free(ctx, query -> key);
        if(query -> value != NULL){
            js_free(ctx, query -> value);
        }
        js_free(ctx, query);
    }
    init_list_head(&url_struct -> query);   // clear

    // parse
    char* query2 = js_strdup(ctx, query);
    JS_FreeCString(ctx, query);
    if(!url_parse_query(query2, &url_struct -> query)){
        js_free(ctx, query2);
        return JS_ThrowTypeError(ctx, "Invalid query string");
    }
    js_free(ctx, query2);
    return JS_UNDEFINED;
}

static void js_url_finalizer(JSRuntime *rt, JSValue val) {
    struct JS_URL_struct *js_url_struct = JS_GetOpaque( val, js_class_url_id);
    if (!js_url_struct) return;
    
    URL_data *url = js_url_struct -> self;
    LJS_free_url(url);

    // free template object refcount
    if(!JS_IsUndefined(js_url_struct -> template)){
        JS_FreeValueRT(rt, js_url_struct -> template);
    }
    
    js_free_rt(rt, js_url_struct);
}

static JSValue js_url_proto_canParse(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsString(argv[0]))
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid arguments", "URL.canParse(url: string, baseURL?: string): boolean\n for more, please see https://developer.mozilla.org/zh-CN/docs/Web/API/URL/canParse_static");

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

    struct CookiePair **modified;
    int mod_count;
    int mod_capacity;
};

// allocate and initialize a new CookieJar
// owned: CookieJar will take ownership of pairs and modified
//  freed after class destruction
void init_cookie_jar(struct CookieJar *jar, int initial_capacity) {
    jar -> pairs = (struct CookiePair *)malloc2(initial_capacity * sizeof(struct CookiePair));
    jar -> count = 0;
    jar -> capacity = initial_capacity;
    jar -> modified = NULL;
    jar -> mod_count = 0;
    jar -> mod_capacity = 0;
}

// modify a cookie pair and mark it as modified
// and then useful in server to update the cookie in response header
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

// free a cookie jar and its pairs
// Note: `jar` will not be freed and should free by caller
void free_cookie_jar(struct CookieJar *jar) {
    for (int i = 0; i < jar -> count; i++) {
        free2(jar -> pairs[i].name);
        free2(jar -> pairs[i].value);
    }
    if(jar -> count) free2(jar -> pairs);
    // fail safe
    jar -> count = 0;
    jar -> capacity = 0;
    jar -> mod_count = 0;
    jar -> mod_capacity = 0;
    free2(jar -> modified);
}

// set a cookie pair to the cookie jar
// Note: `is_modified` is used only in server to update the cookie in response header
void set_cookie_pair(struct CookieJar *jar, const char *name, const char *value, bool is_modified) {
    for (int i = 0; i < jar -> count; i++) {
        if (strcmp(jar -> pairs[i].name, name) == 0) {
            free2(jar -> pairs[i].value);
            
            if (value[0] == '\0') {
                free2(jar -> pairs[i].name);
                // Move the last pair to the current position
                // and decrease the count to delete the pair
                if (i < jar -> count - 1) {
                    jar -> pairs[i] = jar -> pairs[jar -> count - 1];
                }
                jar -> count--;
            }else{
                jar -> pairs[i].value = strdup2(value);
            }

            if(is_modified) mark_modified(jar, &jar -> pairs[i]);
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
    
    jar -> pairs[jar -> count].name = strdup2(name);
    jar -> pairs[jar -> count].value = strdup2(value);
    jar -> count++;

    if(is_modified) mark_modified(jar, &jar -> pairs[jar -> count]);
}

struct CookiePair** get_modified_cookies(struct CookieJar *jar, int *count) {
    *count = jar -> mod_count;
    return jar -> modified;
}

// parse Set-Cookie header and set the cookie to the cookie jar
void parse_set_cookie(struct CookieJar *jar, const char *set_cookie_str) {
    const char *p = set_cookie_str;
    const char *name_start = NULL;
    const char *value_start = NULL;
    
    STRTRIM(p);
    
    // parse name
    name_start = p;
    while (*p && *p != '=' && !isspace(*p)) p++;
    if (*p != '=') return;
    
    size_t name_len = p - name_start;
    char *name = strndup2(name_start, name_len);
    
    p++; // skip '='
    
    // parse value
    while (*p && isspace(*p)) p++;
    value_start = p;
    while (*p && *p != ';') p++;
    size_t value_len = p - value_start;
    char *value = strndup2(value_start, value_len);
    
    // overwrite existing cookie with the same name
    for (int i = 0; i < jar -> count; i++) {
        if (strcmp(jar -> pairs[i].name, name) == 0) {
            free2(jar -> pairs[i].value);
            jar -> pairs[i].value = strdup2(value);
            free2(name);
            free2(value);
            return;
        }
    }
    
    // add new cookie
    set_cookie_pair(jar, name, value, false);
    free2(name);
    free2(value);
}

// parse "Cookie" header and set the cookies to the cookie jar
// it is useful in client to set the cookies to the request header
// Note: "Set-Cookie" header should be parsed by `parse_set_cookie`
void parse_cookie_string(struct CookieJar *jar, const char *cookie_str) {
    const char *p = cookie_str;
    
    while (*p) {
        // skip spaces and semicolons
        while (*p && (isspace(*p) || *p == ';')) p++;
        if (!*p) break;
        
        // parse name
        const char *name_start = p;
        while (*p && *p != '=' && !isspace(*p)) p++;
        if (*p != '=') continue;
        
        size_t name_len = p - name_start;
        char *name = strndup2(name_start, name_len);
        
        p++; // skip '='
        
        // parse value
        while (*p && isspace(*p)) p++;
        const char *value_start = p;
        while (*p && *p != ';') p++;
        size_t value_len = p - value_start;
        char *value = strndup2(value_start, value_len);
        
        // append cookie (not overwrite)
        set_cookie_pair(jar, name, value, false);
        
        free2(name);
        free2(value);
    }
}

// find a cookie value by name
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

    set_cookie_pair(jar, name, value, true);

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
    JS_FreeCString(ctx, name);

    if(!value) return JS_NULL;
    return JS_NewString(ctx, value);
}

static JSValue js_cookies_getAll(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    struct CookieJar* jar = JS_GetOpaque2(ctx, this_val, cookie_jar_class_id);
    if(!jar) return JS_EXCEPTION;

    JSValue result = JS_NewObject(ctx);
    for (int i = 0; i < jar -> count; i++) {
        JSValue value_val = JS_NewString(ctx, jar -> pairs[i].value);
        JS_SetPropertyStr(ctx, result, jar -> pairs[i].name, value_val);
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
            free2(jar -> pairs[i].name);
            free2(jar -> pairs[i].value);
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

    if(jar -> count == 0) return JS_NewString(ctx, "");

    char cookie_str[1024];
    cookie_str[0] = '\0';
    for (int i = 0; i < jar -> count; i++) {
        char pair_str[strlen(jar -> pairs[i].name) + strlen(jar -> pairs[i].value) + 3];
        sprintf(pair_str, "%s=%s; ", jar -> pairs[i].name, jar -> pairs[i].value);
        strcat(cookie_str, pair_str);
    }
    cookie_str[strlen(cookie_str) - 2] = '\0'; // remove last "; "
    JSValue result = JS_NewString(ctx, cookie_str);
    return result;
}

static JSValue js_cookies_fromSetCookies(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    CHECK_ARGS(1, "cookies.fromCookies(setHeaderField: Arrar<string>): void", JS_TAG_OBJECT);
    struct CookieJar* jar = JS_GetOpaque2(ctx, this_val, cookie_jar_class_id);
    int64_t length;
    if(!jar || JS_GetLength(ctx, argv[0], &length) == -1) return JS_EXCEPTION;

    JSValue jsobj;
    for(int64_t i = 0; i < length; i++){
        const char* str = LJS_ToCString(ctx, jsobj = JS_GetPropertyUint32(ctx, argv[0], i), NULL);
        JS_FreeValue(ctx, jsobj);
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
        JS_FreeValue(ctx, header_val);
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
        JSValue jsobj;
        if(JS_GetOwnPropertyNames(ctx, &properties, &count, argv[0], JS_GPN_STRING_MASK) == -1) return JS_EXCEPTION;
        init_cookie_jar(jar, count);
        for(uint32_t i = 0; i < count; i++){
            if(!properties[i].is_enumerable) continue;
            const char* name = JS_AtomToCString(ctx, properties[i].atom);
            const char* value = JS_ToCString(ctx, jsobj = JS_GetProperty(ctx, argv[0], properties[i].atom ));
            JS_FreeValue(ctx, jsobj);
            set_cookie_pair(jar, name, value, false);
            JS_FreeCString(ctx, name);
            JS_FreeCString(ctx, value);
        }
        JS_FreePropertyEnum(ctx, properties, count);
    }

    JSValue obj = JS_NewObjectClass(ctx, cookie_jar_class_id);
    JS_SetOpaque(obj, jar);
    return obj;
}

static void js_cookies_finalizer(JSRuntime *rt, JSValue val){
    struct CookieJar* jar = JS_GetOpaque(val, cookie_jar_class_id);

    if(jar){
        free_cookie_jar(jar);
        js_free_rt(rt, jar);
    }
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
    Promise* promise;
    struct JSClientHandler* handler;
    JSValue reusing_obj;    // if reuse(), return myself
};

struct JSClientHandler {
    JSContext* ctx;
    LHTTPData request;
    LHTTPData response;
    bool destroy;       // ws? closed?
    void* sending_data; // processing

    struct CookieJar cookiejar; // note: ref_count is used to manage lifetime of handler
    JSValue cookiejarObj;   // to keep the object alive

    Promise* promise;

    struct list_head chunks;

    int ref_count;
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

    struct list_head headers;

    struct list_head link;
};

#define GET_OPAQUE(this_val) struct JSClientHandler* handler = JS_GetOpaque2(ctx, this_val, handler_class_id);  \
    if(!handler) return JS_EXCEPTION;
    
// define "end" field in class
#define DEF_END_PROMISE(obj, handler) handler -> promise = js_promise(ctx); \
    JS_SetPropertyStr(ctx, obj, "end", js_get_promise(handler -> promise));

// define headers and request in class
#define DEF_RESPONSE(obj, handler) { \
    JSValue response_obj = LJS_NewResponse(ctx, &handler -> request, false, true); \
    JS_SetPropertyStr(ctx, obj, "request", response_obj); \
    JSValue headers_obj = LJS_NewHeaders(ctx, &handler -> response); \
    JS_SetPropertyStr(ctx, obj, "headers", headers_obj); \
}

#define FREE_HANDLER_COOKIEJAR(handler) \
    JS_SetOpaque(handler -> cookiejarObj, NULL); \
    free_cookie_jar(&handler -> cookiejar);

// Free handler by ref_count
static void handler_free(JSRuntime* rt, struct JSClientHandler* handler) {
    if(handler -> ref_count -- == 1){
        if(handler -> sending_data)
            free2(handler -> sending_data);

        struct list_head* cur, *tmp;
        list_for_each_safe(cur, tmp, &handler -> chunks){
            struct JSChunkData* chunk = list_entry(cur, struct JSChunkData, link);
            free2(chunk -> data);
            js_free_rt(rt, chunk);
        }

        LJS_free_http_data(&handler -> request);
        LJS_free_http_data(&handler -> response);
        FREE_HANDLER_COOKIEJAR(handler);
        js_free_rt(rt, handler);
    }
}

// handle close event
static void handler_close_cb(EvFD* fd, bool rdhup, void* data){
    struct JSClientHandler* handler = data;
    if(handler -> destroy || rdhup) return;
    handler -> destroy = true;
    if(handler -> promise){
        js_reject(handler -> promise, "Connection closed");
    }

    handler_free(JS_GetRuntime(handler -> ctx), handler);
}

// (from `parse_from_fd`) callback for parsing http request
static void handler_parse_cb(LHTTPData *data, uint8_t *buffer, uint32_t len, void* ptr){
    struct JSClientAsyncResult* async_result = ptr;
    struct JSClientHandler* handler = async_result -> handler;
    JSContext* ctx = handler -> ctx;
    bool error = data -> state == HTTP_ERROR;
    
    if(error){
        js_reject(async_result -> promise, "Failed to parse request: Invaild request");
        free2(async_result);
        return;
    }else if(!JS_IsUndefined(async_result -> reusing_obj)){
        // reusing object: resolve it directly
        DEF_END_PROMISE(async_result -> reusing_obj, handler);
        js_resolve(async_result -> promise, async_result -> reusing_obj);
#ifdef LJS_DEBUG
        printf("http request(reused): %s %s\n", handler -> request.method, handler -> request.path);
#endif
    }else{
        // init handler
        evfd_onclose(handler -> response.fd, handler_close_cb, handler);
        JSValue obj = JS_NewObjectClass(ctx, handler_class_id);
        JS_SetOpaque(obj, handler);
        DEF_END_PROMISE(obj, handler);
        DEF_RESPONSE(obj, handler);

        // Cookies(Note: can be reused)
        JSValue cookie_jar = JS_NewObjectClass(ctx, cookie_jar_class_id);
        JS_SetOpaque(cookie_jar, &handler -> cookiejar);
        JS_SetPropertyStr(ctx, obj, "cookies", cookie_jar);
        handler -> cookiejarObj = cookie_jar;

        // Note: js_resolve will not take ownership of obj
        js_resolve(async_result -> promise, obj);
        JS_FreeValue(ctx, obj);

#ifdef LJS_DEBUG
        printf("http request: %s %s\n", handler -> request.method, handler -> request.path);
#endif
    }
    
    // reset http state
    handler -> response.content_length = -1;

    // parse Cookie header
    if (handler -> cookiejar.capacity > 0) {
        free_cookie_jar(&handler -> cookiejar);
    }
    FIND_HEADERS(&handler -> request, "cookie", value, {
        if (handler -> cookiejar.count == 0) {
            init_cookie_jar(&handler -> cookiejar, 16);
        }
        parse_cookie_string(&handler -> cookiejar, value -> value);
    })

    free2(async_result);
}

// TODO: eventstream
// write body to client
static void handler_wbody_cb(EvFD* fd, bool success, void* data){
    struct JSClientHandler* handler = data;
    if(handler -> sending_data){
        free2(handler -> sending_data);
        handler -> sending_data = NULL; // fall safe
    }
    if(!success) return;

    if(list_empty(&handler -> chunks)){
        // all chunks sent
        // Note: if chunked, the last chunk will be sent by done()
        if(!handler -> response.chunked){
            handler -> response.state = HTTP_DONE;
            // after Response.*(), request will be in HTTP_DONE state
            // if(handler -> request.state >= HTTP_DONE){
            js_resolve(handler -> promise, JS_UNDEFINED);
            handler -> promise = NULL;
            // }
        }
        return;
    }
    struct list_head* cur = handler -> chunks.prev;
    struct JSChunkData* chunk = list_entry(cur, struct JSChunkData, link);
    if (handler -> response.chunked) {
        // write chunk
        FORMAT_WRITE("%zx", 16, chunk -> len);
        evfd_write(fd, chunk -> data, chunk -> len, handler_wbody_cb, handler);
    } else {
        // continue write raw body
        evfd_write(fd, chunk -> data, chunk -> len, handler_wbody_cb, handler);
    }
    list_del(cur);
    handler -> sending_data = chunk -> data;    // free after current write
    js_free(handler -> ctx, chunk);
}

// Note: different from `js_handler_done()`, this function will close the fd after complete.
static void handler_wbody_cb2(EvFD* fd, bool success, void* data){
    handler_wbody_cb(fd, success, data);
    struct JSClientHandler* handler = data;
    if(handler -> promise == NULL && success){ // done, close fd and finalize
        evfd_close(fd);
        JSContext* ctx = handler -> ctx;

        handler_free(JS_GetRuntime(ctx), handler);
    }
}

// write headers to client
static inline void handler_write_all_header(JSContext* ctx, struct JSClientHandler* handler){
    EvFD* fd = handler -> response.fd;

    // status
    const char* status_str = http_get_reason_by_code(handler -> response.status);
    FORMAT_WRITE("HTTP/%.1f %d %s", 128, handler -> response.version, handler -> response.status, status_str);

    // all headers
    struct list_head *cur, *tmp;
    list_for_each_safe(cur, tmp, &handler -> response.headers){
        LHttpHeader* header = list_entry(cur, LHttpHeader, link);
        FORMAT_WRITE("%s: %s", 1024, header -> key, header -> value);
        DEL_HEADER(header);
    }

    // content-length
    if(handler -> response.chunked){
        evfd_write(fd, (void*)"Transfer-Encoding: chunked\r\n", 28, NULL, NULL);
    }else if(handler -> response.content_length >= 0){
        FORMAT_WRITE("Content-Length: %zd", 128, handler -> response.content_length);
    }else{
        evfd_write(fd, (void*)"Connection: close\r\n", 19, NULL, NULL);
    }

    // date?
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char date[32];
    strftime(date, 32, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    FORMAT_WRITE("Date: %s", 128, date);

#ifdef LJS_DEBUG
    evfd_write(fd, (void*)"Server: LightJS/" LJS_VERSION "\r\n", 18 + strlen(LJS_VERSION), NULL, NULL);
#endif

    // set-cookies
    if(handler -> cookiejar.mod_count > 0){
        struct CookiePair** modified = handler -> cookiejar.modified;
        for(int i = 0; i < handler -> cookiejar.mod_count; i ++) {
            char* cookie = modified[i] -> name;
            char* value = modified[i] -> value;
            char* modify = modified[i] -> modify ? modified[i] -> modify : "";
            size_t len = strlen(cookie) + strlen(value) + strlen(modify) + 32;
            char* set_cookie = malloc2(len);
            int real_size = snprintf(set_cookie, len, "%s=%s; %s", cookie, value, modify);
            if(real_size > 0) evfd_write(fd, (uint8_t*)set_cookie, real_size, write_then_free, set_cookie);
            free2(cookie);
            free2(value);
            if(modified[i] -> modify) free2(modified[i] -> modify);
            free2(modified[i]);
        }
        handler -> cookiejar.mod_count = 0;
    }

    // done
    evfd_write(fd, (void*)"\r\n", 2, NULL, NULL);

    if(handler -> response.content_length == 0){
        handler -> response.state = HTTP_DONE;

        // r, w all resolved
        // if(handler -> request.state >= HTTP_DONE){
            // not required to write body
            js_resolve(handler -> promise, JS_UNDEFINED);
            handler -> promise = NULL;
        // }
    }else{
        handler -> response.state = HTTP_BODY;
    }
}

// write final chunk to client and resolve the promise
static void handler_final_chunk_cb(EvFD* fd, bool success, void* data){
    struct JSClientHandler* handler = data;
    handler -> response.state = HTTP_DONE;
    // if(handler -> request.state >= HTTP_DONE){
        js_resolve(handler -> promise, JS_UNDEFINED);
        handler -> promise = NULL;
    // }
}

// init JSClientHandler struct
static inline void init_handler(EvFD* fd, JSContext* ctx, struct JSClientHandler* handler){
    handler -> ctx = ctx;
    init_list_head(&handler -> chunks);
    handler -> sending_data = NULL;
    handler -> promise = NULL;  // note: use DEF_END_PROMISE() to set it
    handler -> destroy = false;
    handler -> ref_count = 2;   // eventloop and JS owned 2 ref
    init_http_data(&handler -> response, false); // from server
    init_http_data(&handler -> request, true);   // from client
    handler -> response.fd = fd;
}

// init JSClientAsyncResult struct
static inline struct JSClientAsyncResult* init_async_result(struct JSClientHandler* handler){
    struct JSClientAsyncResult* async_result = js_malloc(handler -> ctx, sizeof(struct JSClientAsyncResult));
    if(! likely(async_result)) return NULL;
    async_result -> promise = js_promise(handler -> ctx);
    async_result -> handler = handler;
    async_result -> reusing_obj = JS_UNDEFINED; // if reuse(), please set it after this
    return async_result;
}

#define LC_BEFORE_HEADER(type) if(unlikely(handler -> response.state >= HTTP_BODY)) \
    return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Header already sent, cannot " type, \
        "you can `reuse()` the connection if the connection alive and vaild.");

#define CHECK_HANDLER if(unlikely(handler -> destroy)) return JS_ThrowTypeError(ctx, "Connection closed or taken over by WebSocket");

static JSValue js_handler_status(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    CHECK_ARGS(1, "status(code: number): void", JS_TAG_INT);
    GET_OPAQUE(this_val);
    CHECK_HANDLER;

    LC_BEFORE_HEADER("set status code");    

    int32_t code;
    if(JS_ToInt32(ctx, &code, argv[0]) == -1 || code < 100 || code > 599)
        return JS_ThrowTypeError(ctx, "Invalid status code");

    handler -> response.status = code;
    return JS_DupValue(ctx, this_val);
}

static JSValue js_handler_header(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsString(argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Too few arguments, expect at least 1, got 0", "handler.header(name: string, value?: string): void \n Note: alias to handler.headers.set/delete");
    }

    GET_OPAQUE(this_val);
    LC_BEFORE_HEADER("set header");
    CHECK_HANDLER;

    const char* name = JS_ToCString(ctx, argv[0]);
    if(!name) return JS_EXCEPTION;
    const char* value = argc >= 2 ? JS_ToCString(ctx, argv[1]) : NULL;

    if(strcasecmp(name, "content-length") == 0){
        if(value){
            int64_t len = strtoll(value, NULL, 10);
            if(len < 0) handler -> response.content_length = -1;
            else handler -> response.content_length = len;
        }else{
            char size[32];
            i64toa(size, handler -> response.content_length);
            return JS_NewString(ctx, size);
        }
        goto skip;
    }else if(strcasecmp(name, "transfer-encoding") == 0){
        // Note: can specify more than one encoding
        if(value && strstr(value, "chunked")){
            handler -> response.chunked = true;
            goto skip;
#ifdef LJS_ZLIB
        }else if(value && strstr(value, "deflate") == 0){
            handler -> response.deflate = true;
            goto skip;
#endif
        }else if(value && strcmp(value, "identity") == 0){
            handler -> response.deflate = false;
            handler -> response.chunked = false;
            goto skip;
        }else{
            return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid transfer-encoding", 
#ifdef LJS_ZLIB
                "LightJS only support chunked and deflate transfer-encoding."
#else
                "LightJS only support chunked transfer-encoding as zlib is not enabled."
#endif
            );
        }
    }

    JSValue header = JS_GetPropertyStr(ctx, this_val, "headers");
    JSValue ret;
    if(argc == 1 || (argc >= 2 && (JS_IsUndefined(argv[1]) || JS_IsNull(argv[1])))){
        ret = js_headers_delete(ctx, header, argc, argv);
    }else{
        ret = js_headers_set(ctx, header, argc, argv);
    }
    JS_FreeValue(ctx, ret);
    JS_FreeValue(ctx, header);

skip:
    return JS_DupValue(ctx, this_val);
}

// cache a chunk to the list 
static inline void chunk_append(JSContext* ctx, struct list_head* list, uint8_t* data, size_t len){
    struct JSChunkData* chunk = js_malloc(ctx, sizeof(struct JSChunkData) + len);
    if(!chunk) return;

    assert(len != 0);   // should not be empty chunk

    chunk -> len = len;
    chunk -> data = malloc2(len);
    memcpy(chunk -> data, data, len);
    list_add_tail(&chunk -> link, list);
}

static inline void write_chunk(JSContext* ctx, EvFD* fd, uint8_t* data, size_t len){
    FORMAT_WRITE("%x", 16, len);
    evfd_write(fd, data, len, write_then_free, data);
}

static JSValue js_handler_chunked(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    GET_OPAQUE(this_val);
    CHECK_HANDLER;
    LC_BEFORE_HEADER("use chunked encoding");
    handler -> response.chunked = true;
    return JS_DupValue(ctx, this_val);
}

static JSValue js_handler_send(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
#define TYPE_DECLARE "handler.send(data: string | ArrayBuffer | Uint8Array): void"
    
    if(argc == 0) return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Too few arguments, expect 1, got 0", TYPE_DECLARE);
    GET_OPAQUE(this_val);
    CHECK_HANDLER;

    if(handler -> response.state >= HTTP_DONE){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Response already finished, cannot send more data.", "you can `reuse()` the connection if the connection alive and vaild.");
    }

    uint8_t* data;
    size_t len;
    if(JS_IsString(argv[0])){
        data = (void*)JS_ToCStringLen(ctx, &len, argv[0]);
    }else if(JS_IsArrayBuffer(argv[0]) || JS_IsTypedArray(ctx, argv[0])){
        data = JS_GetArrayBuffer(ctx, &len, argv[0]);
    }else{
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid argument type, expect string or array buffer", TYPE_DECLARE);
    }

    if(len == 0) goto end;

    if(handler -> response.chunked){
        // header not writed yet
        if(handler -> response.state < HTTP_BODY && list_empty(&handler -> chunks)){
            chunk_append(ctx, &handler -> chunks, data, len);
        }else{
            uint8_t* chunked = malloc2(len + 16);
            if(!chunked){
                JS_ThrowOutOfMemory(ctx);
                goto error;
            }

            int written = snprintf((char*)chunked, len + 16, "%zx\r\n", len);
            if(written < 0) goto error;

            memcpy(chunked + written, data, len);
            chunked[written + len] = '\r';
            chunked[written + len + 1] = '\n';
            evfd_write(handler -> response.fd, chunked, len + written + 2, write_then_free, chunked);
        }
    }else{
        ssize_t clen = handler -> response.content_length;
        if(handler -> response.state < HTTP_BODY){
            // cache
            chunk_append(ctx, &handler -> chunks, data, len);
            if(clen == -1) handler -> response.content_length = len;
            else handler -> response.content_length += len;
        }else if(clen == -1){
            // continue feed data
            uint8_t* data2 = malloc2(len);
            memcpy(data2, data, len);   // avoid free after this function return
            evfd_write(handler -> response.fd, data2, len, write_then_free, data2);
        }else if(handler -> response.content_length >= handler -> response.content_resolved + len){
            len = handler -> response.content_length - handler -> response.content_resolved;
            uint8_t* data2 = malloc2(len);
            memcpy(data2, data, len);   // avoid free after this function return
            evfd_write(handler -> response.fd, data2, len, write_then_free, data2);
            handler -> response.content_resolved += len;
        }else{
            LJS_Throw(ctx, EXCEPTION_TYPEERROR, "body already sent completely, cannot send more data.",
                "If you want to send more data, please use chunked transfer-encoding or set larger content-length"
            );
            goto error;
        }
    }

end:
    if(JS_IsString(argv[0])) JS_FreeCString(ctx, (const char*)data);
    return JS_DupValue(ctx, this_val);

#undef TYPE_DECLARE
#undef LEN_ADD

error:
    if(JS_IsString(argv[0])) JS_FreeCString(ctx, (const char*)data);
    return JS_EXCEPTION;
}

static JSValue js_handler_done(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    GET_OPAQUE(this_val);
    CHECK_HANDLER;

    bool force_no_body = false;
    if(argc != 0){
        force_no_body = JS_ToBool(ctx, argv[0]);
    }

    switch(handler -> response.state){
        case HTTP_INIT:
            // write header & chunked body
            if(list_empty(&handler -> chunks) && force_no_body){
                handler -> response.content_length = 0;
            }
            handler_write_all_header(ctx, handler);
            if(handler -> response.chunked || handler -> response.content_length > 0)
                evfd_wait(handler -> response.fd, false, handler_wbody_cb, handler);
        break;

        case HTTP_BODY:
            if(handler -> response.chunked){
                // write last chunk
                EvFD* fd = handler -> response.fd;
                evfd_write(fd, (void*)"0\r\n\r\n", 5, handler_final_chunk_cb, handler);
                return JS_DupValue(ctx, this_val);
            }else if(handler -> response.content_length == -1){
                // close connection
                js_resolve(handler -> promise, JS_UNDEFINED);
                handler -> promise = NULL;
                evfd_shutdown(handler -> response.fd);
                handler -> destroy = true;
                handler -> response.state = HTTP_DONE;
            }else if(handler -> response.content_length <= handler -> response.content_resolved){
                // body satisfy content-length
                handler -> response.state = HTTP_DONE;
            }else{
                return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "No enought data to send(%ld < %ld)", "header has already been sent before, please use `send()` to feed more data", 
                    handler -> response.content_resolved, handler -> response.content_length);
            }
        break;

        case HTTP_DONE:
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Response already finished, cannot send more data.", "you can `reuse()` the connection if the connection alive and vaild.");

        default:
        abort();    // should not happen
    }

    return JS_DupValue(ctx, this_val);
}

// (for promise callback) close the connection
static void handler_close2_cb(JSContext* ctx, bool is_error, JSValueConst promise, void* data){
    struct JSClientHandler* handler = data;
    evfd_close(handler -> response.fd);
    handler -> destroy = true;
}

static JSValue js_handler_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    GET_OPAQUE(this_val); 
    CHECK_HANDLER;
    if(handler -> response.state < HTTP_DONE && !list_empty(&handler -> chunks)){
        LJS_enqueue_promise_job(ctx, js_get_promise(handler -> promise), handler_close2_cb, handler);
    }else{
        evfd_close(handler -> response.fd);
    }
    return JS_UNDEFINED;
}

// static JSValue js_handler_get_state(JSContext *ctx, JSValueConst this_val){
//     char* state_str;
//     GET_OPAQUE(this_val);
//     switch(handler -> response.state){
//         case HTTP_INIT: 
//         case HTTP_FIRST_LINE: state_str = "WAITING"; break;
//         case HTTP_HEADER: state_str = "WAITING_HEADER"; break;
//         case HTTP_BODY: state_str = "WAITING_BODY"; break;
//         case HTTP_DONE: state_str = "DONE"; break;
//         case HTTP_ERROR: state_str = "ERROR"; break;
//     }
//     return JS_NewString(ctx, state_str);
// }

static JSValue js_handler_reuse(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    GET_OPAQUE(this_val);
    CHECK_HANDLER;

    if(handler -> request.state < HTTP_DONE && handler -> request.content_length > 0){
        return JS_ThrowTypeError(ctx, "Response not read yet, please call response.*() to read body before reuse()");
    }

    // TODO: use evfd_wait to wait for the connection to be ready
    if(!list_empty(&handler -> chunks)){
        return JS_ThrowTypeError(ctx, "HTTP response is not completely sent yet, please call done() and await for `handler.end` first");
    }

    struct JSClientAsyncResult* async_result = init_async_result(handler);
    if(!async_result) return JS_ThrowOutOfMemory(ctx);

    async_result -> reusing_obj = this_val;
    JSValue ret = js_get_promise(async_result -> promise);
    LJS_parse_from_fd(handler -> response.fd, &handler -> request, true, handler_parse_cb, async_result);
    handler -> response.state = HTTP_INIT;
    return ret;
}

#ifndef LJS_MBEDTLS         // polyfill for mbedtls SHA
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
    
    // to 32-bit words
    for (int i = 0; i < 16; i++) {
        w[i] = (buffer[i*4] << 24) | (buffer[i*4+1] << 16) | 
               (buffer[i*4+2] << 8) | (buffer[i*4+3]);
    }
    
    // extend 16 words to 80 words
    for (int i = 16; i < 80; i++) {
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    
    a = ctx -> state[0];
    b = ctx -> state[1];
    c = ctx -> state[2];
    d = ctx -> state[3];
    e = ctx -> state[4];
   
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
    
    // update state
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

// sha1 encode
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
    char* b64 = malloc2(24);
    if(!b64) return NULL;
    base64_encode(sha1val, 20, b64);

    return b64;
}

static JSValue js_handler_ws(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    GET_OPAQUE(this_val);
    LC_BEFORE_HEADER("accept websocket handshake");
    CHECK_HANDLER;
    FIND_HEADERS(&handler -> request, "sec-websocket-key", value, {
        char* accept = ws_calc_accept(value -> value);
        if(!accept) return JS_ThrowOutOfMemory(ctx);

        handler -> response.status = 101;
        // add to headers
        PUT_HEADER_DUP(&handler -> response, "Upgrade", "websocket");
        PUT_HEADER_DUP(&handler -> response, "Connection", "Upgrade");
        PUT_HEADER(&handler -> response, strdup2("Sec-WebSocket-Accept"), accept);

        // free
        DEL_HEADER(value);
        goto main;
    });

    return JS_ThrowTypeError(ctx, "Not a WebSocket request");

main:
    // start body
    handler -> response.chunked = false;
    handler -> destroy = true;
    handler_write_all_header(ctx, handler);
    return LJS_NewWebSocket(ctx, handler -> response.fd, false);
}

static JSValue js_handler_constructor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv){
    return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Handler is not constructable", 
        "Handler is not constructable, please use Handler.from(pipe: U8Pipe) instead"
    );
}

static JSValue js_handler_static_status(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc == 0 || !JS_IsNumber(argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Handler.status() requires one number argument",
            "Handler.status(code: number): string"
        );
    }

    uint32_t reason = 200;
    JS_ToUint32(ctx, &reason, argv[0]);
    if(reason < 100 || reason > 599){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Invalid status code %d",
            "RFC 7231 defines status codes in the range 100-599, please use a valid code",
            reason
        );
    }

    return JS_NewString(ctx, http_get_reason_by_code(reason));
}

static JSValue js_handler_static_mimetype(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc == 0 || !JS_IsString(argv[0])){
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Handler.mimetype() requires one string argument",
            "Handler.mimetype(fileextention: string): string"
        );
    }

    const char* ext = JS_ToCString(ctx, argv[0]);
    if(!ext) return JS_EXCEPTION;

    const char* mimetype = get_mime_by_ext(ext);
    JS_FreeCString(ctx, ext);
    return JS_NewString(ctx, mimetype);
}

static JSValue js_handler_static_from(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv){
    if(argc == 0){
param_err:
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "Handler.from() requires at least one argument",
            "Handler.from(pipe: U8Pipe): Promise<Handler>"
        );
    }

    EvFD* fd = LJS_GetPipeFD(ctx, argv[0]);
    if(!fd) goto param_err;

    struct JSClientHandler* handler = js_malloc(ctx, sizeof(struct JSClientHandler));
    if(!handler) return JS_ThrowOutOfMemory(ctx);
    init_handler(fd, ctx, handler);

    // cookiejar
    handler -> cookiejar.capacity = 0;
    handler -> cookiejar.count = 0;
    handler -> cookiejar.mod_count = 0;
    handler -> cookiejar.modified = NULL;

    // AsyncResult
    struct JSClientAsyncResult* async_result = init_async_result(handler);
    JSValue ret = js_get_promise(async_result -> promise);
    LJS_parse_from_fd(fd, &handler -> request, true, handler_parse_cb, async_result);
    
    return ret;
}

static void handler_finalizer(JSRuntime *rt, JSValue val){
    struct JSClientHandler* handler = JS_GetOpaque(val, handler_class_id);
    if(handler -> destroy) goto end;
    
    if(handler -> response.state < HTTP_DONE){
        // write header and body, then close the connection
        if(handler -> response.state < HTTP_HEADER)
            handler_write_all_header(handler -> ctx, handler);
        evfd_wait(handler -> response.fd, false, handler_wbody_cb2, handler);
        return; // Note: the handler will be freed in the callback
    }

    // cookiejar
    if(handler -> cookiejar.capacity > 0){
        FREE_HANDLER_COOKIEJAR(handler);
    }

end:
    handler_free(rt, handler);
}

static JSCFunctionListEntry handler_proto_funcs[] = {
    JS_CFUNC_DEF("send", 1, js_handler_send),
    JS_CFUNC_DEF("done", 0, js_handler_done),
    JS_CFUNC_DEF("close", 0, js_handler_close),
    JS_CFUNC_DEF("reuse", 0, js_handler_reuse),
    JS_CFUNC_DEF("ws", 0, js_handler_ws),
    JS_CFUNC_DEF("status", 1, js_handler_status),
    JS_CFUNC_DEF("chunked", 0, js_handler_chunked),
    JS_CFUNC_DEF("header", 2, js_handler_header),
    // JS_CGETSET_DEF("state", js_handler_get_state, NULL)
};

static JSCFunctionListEntry handler_static_funcs[] = {
    JS_CFUNC_DEF("from", 1, js_handler_static_from),
    JS_CFUNC_DEF("status", 1, js_handler_static_status),
    JS_CFUNC_DEF("mimetype", 1, js_handler_static_mimetype)
};

static JSClassDef handler_class = {
    "Handler",
    .finalizer = handler_finalizer
};

int init_http(JSContext *ctx, JSModuleDef *m){
    JSValue headers_ctor = JS_NewCFunction2(ctx, js_headers_constructor, "Headers", 1, JS_CFUNC_constructor, 0);
    JS_SetCtorProto(ctx, headers_ctor, headers_class_id);
    JS_SetModuleExport(ctx, m, "Headers", headers_ctor);

    JSValue response_constructor = JS_NewCFunction2(ctx, js_response_constructor, "Response", 1, JS_CFUNC_constructor, 0);
    JS_SetCtorProto(ctx, response_constructor, response_class_id);
    JS_SetModuleExport(ctx, m, "Response", response_constructor);

    JSValue websocket_ctor = JS_NewCFunction2(ctx, js_ws_constructor, "WebSocket", 1, JS_CFUNC_constructor, 0);
    JS_SetCtorProto(ctx, websocket_ctor, ws_class_id);
    JS_SetModuleExport(ctx, m, "WebSocket", websocket_ctor);

    JSValue handler_ctor = JS_NewCFunction2(ctx, js_handler_constructor, "Handler", 1, JS_CFUNC_constructor, 0);
    JS_SetCtorProto(ctx, handler_ctor, handler_class_id);
    JS_SetModuleExport(ctx, m, "Handler", handler_ctor);

    // Handler.prototype.from
    JS_SetPropertyFunctionList(ctx, handler_ctor, handler_static_funcs, countof(handler_static_funcs));

    // Cookies
    JSValue cookie_ctor = JS_NewCFunction2(ctx, js_cookies_constructor, "Cookies", 1, JS_CFUNC_constructor, 0);
    JS_SetCtorProto(ctx, cookie_ctor, cookie_jar_class_id);
    JS_SetModuleExport(ctx, m, "Cookies", cookie_ctor);

    return true;
}

bool LJS_init_http(JSContext *ctx){
    JSModuleDef *m = JS_NewCModule(ctx, "http", init_http);
    JSRuntime *rt = JS_GetRuntime(ctx);
    JSValue global = JS_GetGlobalObject(ctx);   // Note: should free after
    
    // Response(m)
    JSValue response_proto = JS_NewObject(ctx);
    JS_NewClassID(rt, &response_class_id);
    JS_NewClass(rt, response_class_id, &response_class);
    JS_SetClassProto(ctx, response_class_id, response_proto);
    JS_SetPropertyFunctionList(ctx, response_proto, response_proto_funcs, countof(response_proto_funcs));

    JS_AddModuleExport(ctx, m, "Response");

    // URL
    JS_NewClassID(rt, &js_class_url_id);
    JS_NewClass(rt, js_class_url_id, &js_url_class);
    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, js_url_funcs, countof(js_url_funcs));
    JS_SetClassProto(ctx, js_class_url_id, proto);

    JSValue url_ctor = JS_NewCFunction2(ctx, js_url_constructor, "URL", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, url_ctor, proto);
    JS_SetPropertyFunctionList(ctx, url_ctor, url_proto_funcs, countof(url_proto_funcs));

    JS_SetPropertyStr(ctx, global, "URL", url_ctor);

    // fetch
    JSValue fetch_func = JS_NewCFunction2(ctx, js_fetch, "fetch", 1, JS_CFUNC_generic, 0);
    JS_SetPropertyStr(ctx, global, "fetch", fetch_func);

    // Headers
    JS_NewClassID(rt, &headers_class_id);
    JS_NewClass(rt, headers_class_id, &headers_class);

    JSValue headers_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, headers_proto, headers_proto_funcs, countof(headers_proto_funcs));
    JS_SetClassProto(ctx, headers_class_id, headers_proto);

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

    JS_AddModuleExport(ctx, m, "Cookies");

    JS_FreeValue(ctx, global);

    return true;
}