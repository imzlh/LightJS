#include "../engine/quickjs.h"
#include "core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <threads.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <sys/epoll.h>

#ifdef LJS_MBEDTLS
#include "../lib/mbedtls_config.h"
#include <mbedtls/ssl.h>
#endif

#define BUFFER_SIZE 64 * 1024

struct JS_Server_Data{
    JSValue on_connection;
    int fd;
    JSContext* ctx;
    uint32_t bufsize;
    bool ssl;

    struct promise* promise;
};

JSValue js_server_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic, JSValueConst* func_data){
    EvFD* fd = (void*)JS_VALUE_GET_PTR(func_data[0]);
    if(fd) LJS_evfd_close(fd);
    return JS_UNDEFINED;
}

void socket_handle_connect(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data) {
    struct JS_Server_Data* data = (struct JS_Server_Data*)user_data;

    // accept
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_fd = accept(LJS_evfd_getfd(evfd, NULL), (struct sockaddr*)&client_addr, &client_addr_len);

    // 转换为Object
    JSValue addr_info = JS_NewObject(data -> ctx);
    if (client_addr.ss_family == AF_INET) {
        // IPv4 地址
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, (struct sockaddr_in*)&client_addr, ip, INET_ADDRSTRLEN);
        JS_SetPropertyStr(data -> ctx, addr_info, "type", JS_NewString(data -> ctx, "tcp4"));
        JS_SetPropertyStr(data -> ctx, addr_info, "addr", JS_NewString(data -> ctx, ip));
        JS_SetPropertyStr(data -> ctx, addr_info, "port", JS_NewInt32(data -> ctx, ntohs(
            ((struct sockaddr_in*)&client_addr) -> sin_port
        )));
    } else if (client_addr.ss_family == AF_INET6) {
        // IPv6 地址
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, (struct sockaddr_in6*)&client_addr, ip, INET6_ADDRSTRLEN);
        JS_SetPropertyStr(data -> ctx, addr_info, "type", JS_NewString(data -> ctx, "tcp6"));
        JS_SetPropertyStr(data -> ctx, addr_info, "addr", JS_NewString(data -> ctx, ip));
        JS_SetPropertyStr(data -> ctx, addr_info, "port", JS_NewInt32(data -> ctx, ntohs(
            ((struct sockaddr_in6*)&client_addr) -> sin6_port
        )));
    } else if (client_addr.ss_family == AF_UNIX) {
        // Unix domain socket
        JS_SetPropertyStr(data -> ctx, addr_info, "path", JS_NewString(data -> ctx, 
            ((struct sockaddr_un*)&client_addr) -> sun_path
        ));
        JS_SetPropertyStr(data -> ctx, addr_info, "type", JS_NewString(data -> ctx, "unix"));
    } else {
        JS_SetPropertyStr(data -> ctx, addr_info, "type", JS_NewString(data -> ctx, "unknown"));
    }

    // 转换为Pipe
    JSValue pipe = LJS_NewFDPipe(data -> ctx, client_fd, PIPE_READ | PIPE_WRITE, data -> bufsize, JS_NULL);

    // 调用on_connection回调
    JSValue on_connection = data->on_connection;
    JSValue args[2] = { pipe, addr_info };
    JS_Call(data -> ctx, on_connection, JS_UNDEFINED, 2, args);
}

static void socket_handle_close(int fd, void* user_data) {
    struct JS_Server_Data* data = (struct JS_Server_Data*)user_data;
    JSValue close_handler = data->promise -> resolve;
    if(JS_IsFunction(data -> ctx, close_handler)) {
        JSValue args[1] = { JS_UNDEFINED };
        JS_Call(data -> ctx, close_handler, JS_UNDEFINED, 1, args);
    }

    // clear
    LJS_FreePromise(data -> promise);
    free(data);
}

static int open_socket(const char* protocol, const char* host, uint16_t port, const char* unix_path) {
    int sockfd = -1;
    if(strstr(protocol, "tcp")) {
        struct sockaddr_in addr_in;
        memset(&addr_in, 0, sizeof(addr_in));
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = htons(port);
        addr_in.sin_addr.s_addr = inet_addr(host);
        if(addr_in.sin_addr.s_addr == INADDR_NONE) return -2;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }else if(strstr(protocol, "tcp6")) {
        struct sockaddr_in6 addr_in6;
        memset(&addr_in6, 0, sizeof(addr_in6));
        addr_in6.sin6_family = AF_INET6;
        addr_in6.sin6_port = htons(port);
        if(inet_pton(AF_INET6, host, &addr_in6.sin6_addr) != 1) return -2;
        sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    }else if(strstr(protocol, "unix")){
        struct sockaddr_un addr_un;
        memset(&addr_un, 0, sizeof(addr_un));
        addr_un.sun_family = AF_UNIX;
        strncpy(addr_un.sun_path, unix_path, sizeof(addr_un.sun_path)-1);
        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    }
    if(sockfd < 0) return -1;
    return sockfd;
}

// Async DNS

#define DNS_PORT 53
#define DNS_TIMEOUT 5000

typedef struct {
    uint16_t transaction_id;
    DnsResponseCallback user_callback;
    DnsErrorCallback error_callback;
    void* user_data;
} DnsQueryContext;

// DNS头部结构
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};



// 生成随机事务ID
static uint16_t generate_transaction_id() {
    static thread_local uint16_t seed = 0;
    return seed++ % UINT16_MAX;
}

// 构造DNS查询包
static int build_dns_query(char* buf, const char* domain, uint16_t transaction_id) {
    struct dns_header* header = (struct dns_header*)buf;
    header->id = htons(transaction_id);
    header->flags = htons(0x0100); // 标准查询
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    char* ptr = buf + sizeof(struct dns_header);
    const char* domain_part = domain;
    
    // 构造问题部分
    while(*domain_part) {
        char* dot = strchr(domain_part, '.');
        int len = dot ? dot - domain_part : strlen(domain_part);
        
        *ptr++ = len;
        memcpy(ptr, domain_part, len);
        ptr += len;
        
        domain_part = dot ? dot + 1 : domain_part + len;
    }
    *ptr++ = 0; // 结束符
    
    // 查询类型A记录，class IN
    *(uint16_t*)ptr = htons(1); // Type A
    ptr += 2;
    *(uint16_t*)ptr = htons(1); // Class IN
    ptr += 2;
    
    return ptr - buf;
}

// 解析域名（处理压缩指针）
static int parse_dns_name(const uint8_t* packet, const uint8_t* origin, 
                         char* output, size_t out_len) {
    const uint8_t* pos = origin;
    int len = 0;
    
    while(*pos) {
        if((*pos & 0xC0) == 0xC0) { // 处理指针
            uint16_t offset = ntohs(*(uint16_t*)pos) & 0x3FFF;
            pos = packet + offset;
            continue;
        }
        
        size_t seg_len = *pos++;
        if(len + seg_len + 1 > out_len) return -1;
        
        memcpy(output + len, pos, seg_len);
        len += seg_len;
        output[len++] = '.';
        pos += seg_len;
    }
    
    if(len == 0) return -1;
    output[len-1] = '\0'; // 替换最后的点
    return 0;
}

static void parse_dns_response(
    dns_record** records, int* record_i, 
    int total_records, uint8_t* ptr, uint8_t* packet
) {
    // 遍历所有资源记录部分
    for(int i = 0; i < total_records; i++) {
        dns_record *record = malloc(sizeof(*record));

        // 解析公共头
        record->type = ntohs(*(uint16_t*)ptr);
        ptr += 2; // Type
        ptr += 2; // Class
        record->ttl = ntohl(*(uint32_t*)ptr);
        ptr += 4;
        uint16_t rdlength = ntohs(*(uint16_t*)ptr);
        ptr += 2;

        // 根据类型解析数据
        switch(record->type) {
            case DNS_A:
                memcpy(&record->data.a, ptr, 4);
                ptr += 4;
                break;
                
            case DNS_AAAA:
                memcpy(&record->data.aaaa, ptr, 16);
                ptr += 16;
                break;
                
            case DNS_CNAME:
            case DNS_NS:
                parse_dns_name(packet, ptr, 
                    (record->type == DNS_CNAME) ? 
                    record->data.cname : record->data.ns, 
                    sizeof(record->data.cname));
                ptr += rdlength;
                break;
                
            case DNS_MX: {
                record->data.mx.priority = ntohs(*(uint16_t*)ptr);
                ptr += 2;
                parse_dns_name(packet, ptr, record->data.mx.exchange, 
                    sizeof(record->data.mx.exchange));
                ptr += (rdlength - 2);
                break;
            }
                
            case DNS_SRV: {
                record->data.srv.priority = ntohs(*(uint16_t*)ptr);
                ptr += 2;
                record->data.srv.weight = ntohs(*(uint16_t*)ptr);
                ptr += 2;
                record->data.srv.port = ntohs(*(uint16_t*)ptr);
                ptr += 2;
                parse_dns_name(packet, ptr, record->data.srv.target, 
                    sizeof(record->data.srv.target));
                ptr += (rdlength - 6);
                break;
            }
                
            case DNS_TXT: {
                size_t txt_len = *ptr++;
                txt_len = txt_len > sizeof(record->data.txt)-1 ? 
                    sizeof(record->data.txt)-1 : txt_len;
                memcpy(record->data.txt, ptr, txt_len);
                record->data.txt[txt_len] = '\0';
                ptr += txt_len;
                break;
            }
                
            case DNS_SOA: {
                // const uint8_t* start = ptr;
                parse_dns_name(packet, ptr, record->data.soa.mname, 
                    sizeof(record->data.soa.mname));
                ptr += (record->data.soa.mname[0] ? 
                    strlen(record->data.soa.mname)+2 : 1);
                
                parse_dns_name(packet, ptr, record->data.soa.rname, 
                    sizeof(record->data.soa.rname));
                ptr += (record->data.soa.rname[0] ? 
                    strlen(record->data.soa.rname)+2 : 1);
                
                record->data.soa.serial = ntohl(*(uint32_t*)ptr);
                ptr +=4;
                record->data.soa.refresh = ntohl(*(uint32_t*)ptr);
                ptr +=4;
                record->data.soa.retry = ntohl(*(uint32_t*)ptr);
                ptr +=4;
                record->data.soa.expire = ntohl(*(uint32_t*)ptr);
                ptr +=4;
                record->data.soa.minimum = ntohl(*(uint32_t*)ptr);
                ptr +=4;
                break;
            }
                
            default:
                // 处理未知类型
                memcpy(&record->data, ptr, rdlength);
                ptr += rdlength;
                break;
        }

        // 加入
        records[(*record_i) ++] = record;
    }
}

void dns_free_record(dns_record** record, int count) {
    for(int i = 0; i < count; i++) {
        free(record[i]);
    }
    free(record);
}

void dns_response_handler(EvFD* evfd, uint8_t* buffer, uint32_t read_size, void* user_data) {
    DnsQueryContext* ctx = (DnsQueryContext*)user_data;
    struct dns_header* header = (struct dns_header*)buffer;

    // 基础校验
    if (!buffer || read_size < sizeof(struct dns_header) || ntohs(header->id) != ctx->transaction_id) {
        ctx -> error_callback("Invalid DNS response", ctx -> user_data);
        goto cleanup;
    }

    // 检查DNS响应状态
    uint16_t rcode = ntohs(header->flags) & 0x000F;
    if (rcode != 0) {
        const char* error_msg = "Unknown DNS error";
        switch(rcode) {
            case 1: error_msg = "Format error"; break;
            case 2: error_msg = "Server failure"; break;
            case 3: error_msg = "Name error"; break;
            case 4: error_msg = "Not implemented"; break;
            case 5: error_msg = "Refused"; break;
        }
        ctx -> error_callback(error_msg, ctx -> user_data);
        goto cleanup;
    }

    // 计算各段记录数
    uint16_t ancount = ntohs(header->ancount);
    uint16_t nscount = ntohs(header->nscount);
    uint16_t arcount = ntohs(header->arcount);
    uint16_t total_records = ancount + nscount + arcount;

    uint8_t* ptr = buffer + sizeof(struct dns_header);
    while (*ptr != 0 && ptr < buffer + read_size) ptr += *ptr + 1;
    ptr += 5;

    // 解析所有资源记录
    dns_record **records = malloc(total_records * sizeof(dns_record*));
    int record_i = 0;
    parse_dns_response(records, &record_i, total_records, ptr, buffer);

    // 调用回调
    ctx -> user_callback(total_records, records, ctx -> user_data);
    return;

cleanup:
    // 清理资源
    LJS_evfd_close(evfd);
    free(ctx);
}

// 异步DNS解析入口函数
static inline bool async_dns_resolve(const char* dns_server, const char* domain, 
                      DnsResponseCallback callback, DnsErrorCallback error_callback, void* user_data) {
    // 创建UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, 0);
    if(sockfd < 0) return false;

    // 创建evfd
    EvFD* evfd = LJS_evfd_new(sockfd, false, true, false, 512, NULL, NULL);
    LJS_evfd_setup_udp(evfd);
    
    // 准备DNS服务器地址
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT)
    };
    inet_pton(AF_INET, dns_server, &server_addr.sin_addr);

    // 生成查询包
    char query[256];
    uint16_t transaction_id = generate_transaction_id();
    int query_len = build_dns_query(query, domain, transaction_id);

    // 创建查询上下文
    DnsQueryContext* ctx = malloc(sizeof(DnsQueryContext));
    ctx->transaction_id = transaction_id;
    ctx->user_callback = callback;
    ctx->error_callback = error_callback;
    ctx->user_data = user_data;

    // 注册读取回调
    LJS_evfd_read(evfd, 512, NULL, dns_response_handler, ctx);

    // 发送DNS查询
    if(!LJS_evfd_write_dgram(evfd, (uint8_t*)query, query_len,
                            (struct sockaddr*)&server_addr, sizeof(server_addr),
                            NULL, NULL)) {
        close(sockfd);
        free(ctx);
        return false;
    }

    return true;
}


/*
 * bind: 
 */
static JSValue js_bind(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc < 1 || !JS_IsString(argv[0]) || !JS_IsFunction(ctx, argv[1])) {
        return LJS_Throw(ctx, "bind: missing or invalid arguments",
            "bind(addr: string, handler: (client: ClientHandler) => void, settings?: Object) => /* close function */ () => void"
        );
    }

    JSValue handler = argv[1];
    const char *addr = JS_ToCString(ctx, argv[0]);
    if(addr == NULL) {
        return JS_EXCEPTION;
    }
    const char *bindto = NULL;
    URL_data bind_addr;
    
    if (argc <= 1) return JS_EXCEPTION;
    const char* addr_str = JS_ToCString(ctx, argv[0]);
    if(addr_str == NULL) {
        return JS_EXCEPTION;
    }
    char* addr_copied = strdup(addr_str);
    if(LJS_parse_url(addr_copied, &bind_addr, NULL) == false) {
        free(addr_copied);
        return JS_ThrowTypeError(ctx, "bind: invalid address");
    }
    free(addr_copied);

    // 绑定地址
    int sockfd = open_socket(bind_addr.protocol, bind_addr.host, bind_addr.port, bind_addr.path);
    uint32_t bufsize = BUFFER_SIZE;
    if(sockfd < 0) {
        return JS_ThrowTypeError(ctx, "bind: failed to create socket: %s", strerror(errno));
    }

    if(argc == 3) {
        if(!JS_IsObject(argv[2])) {
            return JS_ThrowTypeError(ctx, "bind: tcpsettings must be an object");
        }

        JSValue val;
        if(JS_IsNumber(val = JS_GetPropertyStr(ctx, argv[2], "bufferSize"))){
            int bufferSize;
            if(JS_ToInt32(ctx, &bufferSize, val)){
                setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
                setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
            }
            bufsize = bufferSize;
        }
        if(JS_IsNumber(val = JS_GetPropertyStr(ctx, argv[2], "timeout"))){
            int timeout;
            if(JS_ToInt32(ctx, &timeout, val)){
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            }
        }
        // TCP设置
        if (strcmp(bind_addr.protocol, "unix") != 0){
            if(JS_IsBool(val = JS_GetPropertyStr(ctx, argv[2], "reuseaddr"))){
                bool reuseaddr = JS_ToBool(ctx, val);
                setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(val));
            }
            if(JS_IsBool(val = JS_GetPropertyStr(ctx, argv[2], "nodelay"))){
                int nodelay = JS_ToBool(ctx, val);
                setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
            }
            if(JS_IsBool(val = JS_GetPropertyStr(ctx, argv[2], "keepalive"))){
                int keepalive = JS_ToBool(ctx, val);
                setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&keepalive, sizeof(keepalive));
            }
            if(JS_IsBool(val = JS_GetPropertyStr(ctx, argv[2], "bindto"))){
                bindto = JS_ToCString(ctx, val);
                if(bindto == NULL) {
                    return JS_EXCEPTION;
                }
                setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, bindto, strlen(bindto));
            }
        }
    }
 
    // 添加到evloop
    struct promise* promise = LJS_NewPromise(ctx);
    struct JS_Server_Data* data = malloc(sizeof(struct JS_Server_Data));
    data->promise = promise;
    data->on_connection = handler;
    data->fd = sockfd;
    data->ctx = ctx;
    data->bufsize = bufsize;
    LJS_evcore_attach(sockfd, false, socket_handle_connect, (EvWriteCallback)NULL, socket_handle_close, data);

    return promise -> promise;
}

void ssl_handshake_callback(EvFD* evfd, void* user_data) {
    struct promise* promise = (struct promise*)user_data;
    LJS_Promise_Resolve(promise, JS_UNDEFINED);
}

static JSValue js_ssl_handshake(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
#ifdef LJS_MBEDTLS
    if(argc == 0 || !JS_IsObject(argv[0])) {
        return LJS_Throw(ctx, "handshake_ssl: missing or invalid arguments",
            "handshake_ssl(socket: Pipe, options?: Object) => Promise<void>"
        );
    }

    bool is_client = true;
    int preset = MBEDTLS_SSL_PRESET_DEFAULT;
    int* ciphers = NULL;
    int cipher_count = 0;
    EvFD* fd = LJS_GetPipeFD(ctx, argv[0]);
    if(fd == NULL) {
        return JS_ThrowTypeError(ctx, "handshake_ssl: invalid socket");
    }

    if(argc >= 2){
        JSValue obj = argv[1];
        JSValue val;
        if(JS_IsBool(val = JS_GetPropertyStr(ctx, obj, "server"))){
            is_client = !JS_ToBool(ctx, val);
        }
        if(JS_IsArray(val = JS_GetPropertyStr(ctx, obj, "ciphers"))) {
            int64_t count;
            if(JS_GetLength(ctx, val, &count) > 0){
                ciphers = malloc((count +1) * sizeof(int));
                for(int i = 0; i < count; i++){
                    JSValue item = JS_GetPropertyUint32(ctx, val, i);
                    int cipher;
                    if(JS_ToInt32(ctx, &cipher, item)){
                        ciphers[cipher_count++] = cipher;
                    }
                }
                ciphers[cipher_count] = 0;
            }
        }
        if(JS_IsBool(val = JS_GetPropertyStr(ctx, obj, "suiteb"))){
            bool suiteb = JS_ToBool(ctx, val);
            if(suiteb){
                preset = MBEDTLS_SSL_PRESET_SUITEB;
            }
        }
    }

    struct promise* promise = LJS_NewPromise(ctx);
    mbedtls_ssl_config* config = NULL;
    LJS_evfd_initssl(fd, &config, is_client, MBEDTLS_SSL_TRANSPORT_STREAM, preset, ssl_handshake_callback, promise);

    // chipers
    if(ciphers){
        mbedtls_ssl_conf_ciphersuites(config, ciphers);
        free(ciphers);
    }

    return promise -> promise;
#else
    return LJS_Throw(ctx, "handshake_ssl: mbedtls not enabled in build",
        "remove `-DLJS_MBEDTLS=off` from cmake build flags to enable"
    );
#endif
}

void js_handle_dns_resolve(int total_records, dns_record** records, void* user_data) {
    struct promise* promise = (struct promise*)user_data;
    JSContext* ctx = promise -> ctx;
    JSValue arr = JS_NewArray(ctx);
    for(int i = 0; i < total_records; i++){
        dns_record* record = records[i];
        JSValue obj = JS_NewObject(ctx);
        switch(record->type){
            case DNS_A:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "A"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, inet_ntoa(record->data.a)));
                break;
            case DNS_AAAA:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "AAAA"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, inet_ntop(AF_INET6, &record->data.aaaa, NULL, 0)));
                break;
            case DNS_CNAME:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "CNAME"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, record->data.cname));
                break;
            case DNS_MX:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "MX"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewInt32(ctx, record->data.mx.priority));
                JS_SetPropertyStr(ctx, obj, "mx", JS_NewString(ctx, record->data.mx.exchange));
                break;
            case DNS_NS:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "NS"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, record->data.ns));
                break;
            case DNS_TXT:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "TXT"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, record->data.txt));
                break;
            case DNS_SOA:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "SOA"));
                JS_SetPropertyStr(ctx, obj, "mname", JS_NewString(ctx, record->data.soa.mname));
                JS_SetPropertyStr(ctx, obj, "rname", JS_NewString(ctx, record->data.soa.rname));
                JS_SetPropertyStr(ctx, obj, "serial", JS_NewInt32(ctx, record->data.soa.serial));
                JS_SetPropertyStr(ctx, obj, "refresh", JS_NewInt32(ctx, record->data.soa.refresh));
                JS_SetPropertyStr(ctx, obj, "retry", JS_NewInt32(ctx, record->data.soa.retry));
                JS_SetPropertyStr(ctx, obj, "expire", JS_NewInt32(ctx, record->data.soa.expire));
                JS_SetPropertyStr(ctx, obj, "minimum", JS_NewInt32(ctx, record->data.soa.minimum));
                break;
            default:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "unknown"));
                break;
        }
        JS_SetPropertyUint32(ctx, arr, i, obj);
        free(record);
    }
    LJS_Promise_Resolve(promise, arr);
    free(records);
}

static void js_handle_dns_error(const char* error_msg, void* user_data) {
    struct promise* promise = (struct promise*)user_data;
    LJS_Promise_Reject(promise, error_msg);
}

static JSValue js_resolve_dns(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0){
        return LJS_Throw(ctx, "resolve_dns: missing or invalid arguments",
            "resolve_dns(hostname: string, dns_server?: string) => Promise<Array<RecordItem>>"
        );
    }

    JSValue hostname = argv[0];
    const char* domain = JS_ToCString(ctx, hostname);
    if(domain == NULL) return JS_EXCEPTION;

    const char* dns_server = "8.8.8.8";
    if(argc >= 2){
        JSValue dns_server_val = argv[1];
        const char* dns_server_str = JS_ToCString(ctx, dns_server_val);
        if(dns_server_str) dns_server = dns_server_str;
    }

    struct promise* promise = LJS_NewPromise(ctx);
    async_dns_resolve(dns_server, domain, js_handle_dns_resolve, js_handle_dns_error, promise);
    return promise -> promise;
}

static JSValue js_cert_add(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsObject(argv[0])) {
        return LJS_Throw(ctx, "cert_add: missing or invalid arguments",
            "regCert(name: string, cert: string, key: string) => void"
        );
    }

#ifdef LJS_MBEDTLS
    JSValue name_val = argv[0];
    JSValue cert_val = argv[1];
    JSValue key_val = argv[2];
    const char* name_str = JS_ToCString(ctx, name_val);
    const char* cert_str = JS_ToCString(ctx, cert_val);
    const char* key_str = JS_ToCString(ctx, key_val);
    if(cert_str == NULL || key_str == NULL || name_str == NULL) return JS_EXCEPTION;
    
    // mbedtls parse
    int ret;
    mbedtls_x509_crt* crt = NULL;
    mbedtls_pk_context* pk = NULL;
    mbedtls_x509_crt_init(crt);
    mbedtls_pk_init(pk);
    ret = mbedtls_x509_crt_parse(crt, (const unsigned char*)cert_str, strlen(cert_str) + 1);
    JS_FreeCString(ctx, cert_str);
    if(ret != 0){
        mbedtls_x509_crt_free(crt);
        mbedtls_pk_free(pk);
        return LJS_Throw(ctx, "cert_add: failed to parse certificate", NULL);
    }
    ret = mbedtls_pk_parse_key(pk, (const unsigned char*)key_str, strlen(key_str) + 1, NULL, 0);
    JS_FreeCString(ctx, key_str);
    if(ret != 0){
        mbedtls_x509_crt_free(crt);
        mbedtls_pk_free(pk);
        return LJS_Throw(ctx, "cert_add: failed to parse private key", NULL);
    }

    // add to global
    LJS_evfd_set_sni(strdup(name_str), NULL, crt, pk);
    JS_FreeCString(ctx, name_str);
    
    return JS_UNDEFINED;
#else
    return LJS_Throw(ctx, "mbedtls not enabled in build",
        "remove `-DLJS_MBEDTLS=off` from cmake build flags to enable"
    );
#endif
}

static JSValue js_cert_remove(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsString(argv[0])) {
        return LJS_Throw(ctx, "cert_remove: missing or invalid arguments",
            "unregCert(name: string) => void"
        );
    }

#ifdef LJS_MBEDTLS
    const char* name_str = JS_ToCString(ctx, argv[0]);
    if(name_str == NULL) return JS_EXCEPTION;

    bool ret = LJS_evfd_remove_sni(name_str);
    JS_FreeCString(ctx, name_str);
    return JS_NewBool(ctx, ret);
#else
    return LJS_Throw(ctx, "mbedtls not enabled in build",
        "remove `-DLJS_MBEDTLS=off` from cmake build flags to enable"
    );
#endif
}

static const JSCFunctionListEntry LJS_socket_funcs[] = {
    JS_CFUNC_DEF("bind", 1, js_bind),
    JS_CFUNC_DEF("upgradeTLS", 1, js_ssl_handshake),
    JS_CFUNC_DEF("resolveDNS", 1, js_resolve_dns),
    JS_CFUNC_DEF("regCert", 3, js_cert_add),
    JS_CFUNC_DEF("unregCert", 1, js_cert_remove),
};

static int js_init_socket(JSContext* ctx, JSModuleDef* m) {
    JS_SetModuleExportList(ctx, m, LJS_socket_funcs, countof(LJS_socket_funcs));
    return 0;
}

bool LJS_init_module_socket(JSContext* ctx) {
    JSModuleDef* m = JS_NewCModule(ctx, "socket", js_init_socket);
    if(!m) return false;
    JS_AddModuleExportList(ctx, m, LJS_socket_funcs, countof(LJS_socket_funcs));
    return true;
}

// C API
bool LJS_dns_resolve(
    JSContext* ctx, const char* hostname, const char* dns_server, 
    DnsResponseCallback callback, DnsErrorCallback error_callback, void* user_data
) {
    return async_dns_resolve(dns_server, hostname, callback, error_callback, user_data);
}