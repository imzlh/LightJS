/**
 * LightJS Socket Module
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
#include "core.h"
#include "polyfill.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#ifndef L_NO_THREADS_H
#include <threads.h>
#endif
#include <signal.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/random.h>

#ifdef __CYGWIN__
#include "../deps/wepoll/wepoll.h"
#else
#include <sys/epoll.h>
#endif

#ifdef LJS_MBEDTLS
#include "../lib/mbedtls_config.h"
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#endif

#define BUFFER_SIZE 16 * 1024

struct JS_Server_Data{
    JSValue on_connection;  // to handle a new connection
    JSValue on_close;
    int fd;
    JSContext* ctx;
    uint32_t bufsize;
    bool ssl;
};

JSValue js_server_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv, int magic, JSValueConst* func_data){
    EvFD* fd = (void*)JS_VALUE_GET_PTR(func_data[0]);
    if(fd) evfd_close(fd);
    return JS_UNDEFINED;
}

int server_handle_accept(EvFD* evfd, bool success, uint8_t* buffer, uint32_t read_size, void* user_data) {
    struct JS_Server_Data* data = (struct JS_Server_Data*)user_data;
    if(!success) return EVCB_RET_DONE;    // finalized in handle_close

    // accept
    struct sockaddr_storage client_addr = { 0 };
    socklen_t client_addr_len = sizeof(client_addr);
    int client_fd = accept(evfd_getfd(evfd, NULL), (struct sockaddr*)&client_addr, &client_addr_len);

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
        JS_SetPropertyStr(data -> ctx, addr_info, "url", JS_NewString(data -> ctx, 
            ((struct sockaddr_un*)&client_addr) -> sun_path
        ));
        JS_SetPropertyStr(data -> ctx, addr_info, "type", JS_NewString(data -> ctx, "unix"));
    } else {
        JS_SetPropertyStr(data -> ctx, addr_info, "type", JS_NewString(data -> ctx, "unknown"));
    }

    // 转换为Pipe
    JSValue pipe = LJS_NewFDPipe(data -> ctx, client_fd, PIPE_READ | PIPE_WRITE | PIPE_SOCKET, false, NULL);

    // 调用on_connection回调
    JSValue on_connection = data -> on_connection;
    JSValue args[2] = { pipe, addr_info };
    JS_Call(data -> ctx, on_connection, JS_UNDEFINED, 2, args);
    JS_FreeValue(data -> ctx, addr_info);
    JS_FreeValue(data -> ctx, pipe);

    return EVCB_RET_DONE;
}

static void server_handle_close(EvFD* fd, bool _, void* user_data) {
    struct JS_Server_Data* data = (struct JS_Server_Data*)user_data;
    JS_FreeValue(data -> ctx, data -> on_connection);
    if(!JS_IsUndefined(data -> on_close)){
        JS_Call(data -> ctx, data -> on_close, JS_UNDEFINED, 0, NULL);
        JS_FreeValue(data -> ctx, data -> on_close);
    }
    free2(data);
}

#define NONBLOCK(fd) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
static inline int socket_create(const char* protocol){
    if(memcmp(protocol, "tcp6", 4) == 0) return socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(memcmp(protocol, "tcp", 3) == 0) return socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(memcmp(protocol, "udp6", 4) == 0) return socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(memcmp(protocol, "udp", 3) == 0) return socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if(memcmp(protocol, "unix", 4) == 0) return socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    errno = EADDRNOTAVAIL;
    return -1;
}

static int socket_connect(int sockfd, const char* protocol, const char* host, uint16_t port, const char* unix_path) {
    NONBLOCK(sockfd);
    
    if(memcmp(protocol, "tcp6", 4) == 0) {
        struct sockaddr_in6 addr_in6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port)
        };
        if(inet_pton(AF_INET6, host, &addr_in6.sin6_addr) != 1) return -2;

        return connect(sockfd, (struct sockaddr*)&addr_in6, sizeof(addr_in6));
    }else if(memcmp(protocol, "tcp", 3) == 0) {
        struct sockaddr_in addr_in = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = inet_addr(host),
            .sin_port = htons(port)
        };
        if(inet_pton(AF_INET, host, &addr_in.sin_addr) != 1) return -2;

        return connect(sockfd, (struct sockaddr*)&addr_in, sizeof(addr_in));
    }else if(memcmp(protocol, "unix", 4) == 0){
        struct sockaddr_un addr_un = {
            .sun_family = AF_UNIX
        };
        strncpy(addr_un.sun_path, unix_path, sizeof(addr_un.sun_path)-1);

        return connect(sockfd, (struct sockaddr*)&addr_un, sizeof(addr_un));
    }else if(memcmp(protocol, "udp6", 4) == 0){
        struct sockaddr_in6 addr_in6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port)
        };
        if(inet_pton(AF_INET6, host, &addr_in6.sin6_addr) != 1) return -2;

        return connect(sockfd, (struct sockaddr*)&addr_in6, sizeof(addr_in6));
    }else if(memcmp(protocol, "udp", 3) == 0){
        struct sockaddr_in addr_in = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = inet_addr(host),
            .sin_port = htons(port)
        };
        if(inet_pton(AF_INET, host, &addr_in.sin_addr) != 1) return -2;

        return connect(sockfd, (struct sockaddr*)&addr_in, sizeof(addr_in));
    }
    
    return false;
}

static int socket_listen(int sockfd, const char* protocol, const char* host, uint16_t port, const char* unix_path) {
    int bindres = -1;
    if(strstr(protocol, "tcp")) {
        struct sockaddr_in addr_in = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = inet_addr(host),
            .sin_port = htons(port)
        };
        if(inet_pton(AF_INET, host, &addr_in.sin_addr) != 1) return -2;

        bindres = bind(sockfd, (struct sockaddr*)&addr_in, sizeof(addr_in));
    }else if(strstr(protocol, "tcp6")) {
        struct sockaddr_in6 addr_in6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(port)
        };
        if(inet_pton(AF_INET6, host, &addr_in6.sin6_addr) != 1) return -2;

        bindres = bind(sockfd, (struct sockaddr*)&addr_in6, sizeof(addr_in6));
    }else if(strstr(protocol, "unix")){
        struct sockaddr_un addr_un = {
            .sun_family = AF_UNIX
        };
        strncpy(addr_un.sun_path, unix_path, sizeof(addr_un.sun_path)-1);

        // pre-bind, check if path exists
        if(access(unix_path, F_OK) == 0) {
            unlink(unix_path);
        }

        bindres = bind(sockfd, (struct sockaddr*)&addr_un, sizeof(addr_un));
    }
    return listen(sockfd, 128) == 0;
}

// Async DNS
#define DNS_PORT 53
#define DNS_TIMEOUT 5000
#define DNS_MAX_NAME_LENGTH 253
#define DNS_MAX_LABEL_LENGTH 63

typedef struct {
    uint16_t transaction_id;
    DnsResponseCallback user_callback;
    DnsErrorCallback error_callback;
    void* user_data;
    uint32_t timeout_ms;
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

// Generate random eventid
static uint16_t generate_transaction_id() {
    static _Thread_local uint16_t seed = 0;
    if (seed == 0) {
        seed = (uint16_t)time(NULL) ^ (uint16_t)getpid();
    }
    return ++seed;
}

// build DNS query packet
static int build_dns_query(uint8_t* buf, size_t buf_size, const char* domain, uint16_t transaction_id) {
    if (!buf || !domain || buf_size < sizeof(struct dns_header) + strlen(domain) + 6) {
        return -1;
    }

    // 构造DNS头部
    struct dns_header* header = (struct dns_header*)buf;
    header -> id = htons(transaction_id);
    header -> flags = htons(0x0100);  // 标准递归查询
    header -> qdcount = htons(1);     // 1个问题
    header -> ancount = 0;
    header -> nscount = 0;
    header -> arcount = 0;

    uint8_t* ptr = buf + sizeof(struct dns_header);
    const char* label_start = domain;
    
    // 编码域名 (将 "example.com" 转换为 "\7example\3com\0")
    while (*label_start) {
        const char* dot = strchr(label_start, '.');
        size_t label_len = dot ? (size_t)(dot - label_start) : strlen(label_start);
        
        // 检查标签长度限制
        if (label_len > DNS_MAX_LABEL_LENGTH) {
            return -1;
        }
        
        *ptr++ = (uint8_t)label_len;
        memcpy(ptr, label_start, label_len);
        ptr += label_len;
        
        label_start = dot ? dot + 1 : label_start + label_len;
    }
    *ptr++ = 0; // 域名结束符
    
    // 查询类型 (A记录)
    *(uint16_t*)ptr = htons(DNS_A);
    ptr += 2;
    
    // 查询类别 (IN)
    *(uint16_t*)ptr = htons(1);
    ptr += 2;
    
    return (int)(ptr - buf);
}

// 解析域名（处理压缩指针）
static int parse_dns_name(const uint8_t* packet, size_t packet_size, 
                         const uint8_t* start_pos, char* output, size_t output_size) {
    if (!packet || !start_pos || !output || output_size == 0) {
        return -1;
    }
    
    const uint8_t* pos = start_pos;
    const uint8_t* packet_end = packet + packet_size;
    size_t output_pos = 0;
    int jumps = 0;
    const int MAX_JUMPS = 16; // 防止无限循环
    
    while (pos < packet_end && *pos != 0 && jumps < MAX_JUMPS) {
        if ((*pos & 0xC0) == 0xC0) {
            // 处理压缩指针
            if (pos + 1 >= packet_end) return -1;
            
            uint16_t offset = ((pos[0] & 0x3F) << 8) | pos[1];
            if (offset >= packet_size) return -1;
            
            pos = packet + offset;
            jumps++;
            continue;
        }
        
        // 读取标签长度
        uint8_t label_len = *pos++;
        if (label_len > DNS_MAX_LABEL_LENGTH || pos + label_len > packet_end) {
            return -1;
        }
        
        // 检查输出缓冲区空间
        if (output_pos + label_len + 1 >= output_size) {
            return -1;
        }
        
        // 复制标签
        if (output_pos > 0) {
            output[output_pos++] = '.';
        }
        memcpy(output + output_pos, pos, label_len);
        output_pos += label_len;
        pos += label_len;
    }
    
    output[output_pos] = '\0';
    return jumps < MAX_JUMPS && pos < packet_end ? 0 : -1;
}

static int skip_dns_name(const uint8_t* packet, size_t packet_size, const uint8_t* pos) {
    if (!packet || !pos || pos >= packet + packet_size) {
        return -1;
    }
    
    const uint8_t* start = pos;
    const uint8_t* packet_end = packet + packet_size;
    
    while (pos < packet_end && *pos != 0) {
        if ((*pos & 0xC0) == 0xC0) {
            // 压缩指针，固定2字节
            return (int)(pos - start + 2);
        }
        
        uint8_t label_len = *pos;
        if (label_len > DNS_MAX_LABEL_LENGTH) {
            return -1;
        }
        
        pos += label_len + 1;
    }
    
    return pos < packet_end ? (int)(pos - start + 1) : -1;
}

static int parse_dns_records(const uint8_t* packet, size_t packet_size,
                            const uint8_t* records_start, int record_count,
                            dns_record*** out_records) {
    if (!packet || !records_start || record_count <= 0 || !out_records) {
        return -1;
    }
    
    dns_record** records = calloc(record_count, sizeof(dns_record*));
    if (!records) return -1;
    
    const uint8_t* ptr = records_start;
    const uint8_t* packet_end = packet + packet_size;
    int parsed_count = 0;
    
    for (int i = 0; i < record_count && ptr < packet_end; i++) {
        // 跳过记录名称
        int name_skip = skip_dns_name(packet, packet_size, ptr);
        if (name_skip < 0 || ptr + name_skip + 10 > packet_end) {
            break;
        }
        ptr += name_skip;
        
        // 分配记录结构
        dns_record* record = calloc(1, sizeof(dns_record));
        if (!record) break;
        
        // 读取记录头部
        record -> type = ntohs(*(uint16_t*)ptr); ptr += 2;  // Type
        ptr += 2;  // Class (跳过)
        record -> ttl = ntohl(*(uint32_t*)ptr); ptr += 4;   // TTL
        uint16_t rdlength = ntohs(*(uint16_t*)ptr); ptr += 2;  // Data Length
        
        // 检查数据长度
        if (ptr + rdlength > packet_end) {
            free(record);
            break;
        }
        
        // 根据类型解析数据
        switch (record -> type) {
            case DNS_A:
                if (rdlength == 4) {
                    memcpy(&record -> data.a, ptr, 4);
                }
                break;
                
            case DNS_AAAA:
                if (rdlength == 16) {
                    memcpy(&record -> data.aaaa, ptr, 16);
                }
                break;
                
            case DNS_CNAME:
            case DNS_NS:
                if (parse_dns_name(packet, packet_size, ptr, 
                    (record -> type == DNS_CNAME) ? record -> data.cname : record -> data.ns, 
                    sizeof(record -> data.cname)) == 0) {
                    // 解析成功
                }
                break;
                
            case DNS_MX:
                if (rdlength >= 3) {
                    record -> data.mx.priority = ntohs(*(uint16_t*)ptr);
                    parse_dns_name(packet, packet_size, ptr + 2, 
                        record -> data.mx.exchange, sizeof(record -> data.mx.exchange));
                }
                break;
                
            case DNS_TXT:
                if (rdlength > 0) {
                    uint8_t txt_len = *ptr;
                    size_t copy_len = (txt_len < sizeof(record -> data.txt) - 1) ? 
                        txt_len : sizeof(record -> data.txt) - 1;
                    if (copy_len > 0 && ptr + 1 + copy_len <= packet_end) {
                        memcpy(record -> data.txt, ptr + 1, copy_len);
                        record -> data.txt[copy_len] = '\0';
                    }
                }
                break;
                
            case DNS_SOA:
                if (rdlength >= 20) {
                    const uint8_t* soa_ptr = ptr;
                    
                    // 解析主名称服务器
                    int mname_len = skip_dns_name(packet, packet_size, soa_ptr);
                    if (mname_len > 0) {
                        parse_dns_name(packet, packet_size, soa_ptr, 
                            record -> data.soa.mname, sizeof(record -> data.soa.mname));
                        soa_ptr += mname_len;
                    }
                    
                    // 解析负责人邮箱
                    int rname_len = skip_dns_name(packet, packet_size, soa_ptr);
                    if (rname_len > 0) {
                        parse_dns_name(packet, packet_size, soa_ptr, 
                            record -> data.soa.rname, sizeof(record -> data.soa.rname));
                        soa_ptr += rname_len;
                    }
                    
                    // 解析序列号等字段
                    if (soa_ptr + 20 <= ptr + rdlength) {
                        record -> data.soa.serial = ntohl(*(uint32_t*)soa_ptr); soa_ptr += 4;
                        record -> data.soa.refresh = ntohl(*(uint32_t*)soa_ptr); soa_ptr += 4;
                        record -> data.soa.retry = ntohl(*(uint32_t*)soa_ptr); soa_ptr += 4;
                        record -> data.soa.expire = ntohl(*(uint32_t*)soa_ptr); soa_ptr += 4;
                        record -> data.soa.minimum = ntohl(*(uint32_t*)soa_ptr);
                    }
                }
                break;
                
            case DNS_SRV:
                if (rdlength >= 6) {
                    record -> data.srv.priority = ntohs(*(uint16_t*)ptr);
                    record -> data.srv.weight = ntohs(*(uint16_t*)(ptr + 2));
                    record -> data.srv.port = ntohs(*(uint16_t*)(ptr + 4));
                    parse_dns_name(packet, packet_size, ptr + 6, 
                        record -> data.srv.target, sizeof(record -> data.srv.target));
                }
                break;
                
            default:
                // 未知类型，跳过
                break;
        }
        
        ptr += rdlength;
        records[parsed_count++] = record;
    }
    
    *out_records = records;
    return parsed_count;
}

void dns_free_record(dns_record** records, int count) {
    if (!records) return;
    
    for (int i = 0; i < count; i++) {
        free(records[i]);
    }
    free(records);
}

int dns_response_handler(EvFD* evfd, bool ok, uint8_t* buffer, uint32_t read_size, void* user_data) {
    DnsQueryContext* ctx = (DnsQueryContext*)user_data;

    if(!ok){
        ctx -> error_callback("failed to read DNS response", ctx -> user_data);
        goto cleanup;
    }
    
    // 基础校验
    if (!buffer || read_size < sizeof(struct dns_header)) {
        ctx -> error_callback("Invalid DNS response: too short", ctx -> user_data);
        goto cleanup;
    }
    
    struct dns_header* header = (struct dns_header*)buffer;
    
    // 检查事务ID
    if (ntohs(header -> id) != ctx -> transaction_id) {
        ctx -> error_callback("Invalid DNS response: transaction ID mismatch", ctx -> user_data);
        goto cleanup;
    }
    
    // 检查响应状态码
    uint16_t flags = ntohs(header -> flags);
    uint16_t rcode = flags & 0x000F;
    
    if (rcode != 0) {
        const char* error_msg = "Unknown DNS error";
        switch (rcode) {
            case 1: error_msg = "Format error"; break;
            case 2: error_msg = "Server failure"; break;
            case 3: error_msg = "Name error (domain not found)"; break;
            case 4: error_msg = "Not implemented"; break;
            case 5: error_msg = "Refused"; break;
            default: break;
        }
        ctx -> error_callback(error_msg, ctx -> user_data);
        goto cleanup;
    }
    
    // 解析各部分记录数
    uint16_t qdcount = ntohs(header -> qdcount);
    uint16_t ancount = ntohs(header -> ancount);
    uint16_t nscount = ntohs(header -> nscount);
    uint16_t arcount = ntohs(header -> arcount);
    
    // 跳过问题部分
    const uint8_t* ptr = buffer + sizeof(struct dns_header);
    const uint8_t* buffer_end = buffer + read_size;
    
    for (int i = 0; i < qdcount && ptr < buffer_end; i++) {
        int name_skip = skip_dns_name(buffer, read_size, ptr);
        if (name_skip < 0 || ptr + name_skip + 4 > buffer_end) {
            ctx -> error_callback("Malformed DNS response: invalid question section", ctx -> user_data);
            goto cleanup;
        }
        ptr += name_skip + 4; // 跳过QTYPE(2) + QCLASS(2)
    }
    
    // 解析答案记录
    int total_records = ancount + nscount + arcount;
    if (total_records == 0) {
        // 没有记录，返回空数组
        dns_record** empty_records = malloc(sizeof(dns_record*));
        ctx -> user_callback(0, empty_records, ctx -> user_data);
        goto cleanup;
    }
    
    dns_record** records = NULL;
    int parsed_count = parse_dns_records(buffer, read_size, ptr, total_records, &records);
    
    if (parsed_count < 0) {
        ctx -> error_callback("Failed to parse DNS records", ctx -> user_data);
        goto cleanup;
    }
    
    // 调用用户回调
    ctx -> user_callback(parsed_count, records, ctx -> user_data);

cleanup:
    evfd_close(evfd);
    free(ctx);
    return EVCB_RET_DONE;
}

static inline bool async_dns_resolve(const char* dns_server, const char* domain, 
                      DnsResponseCallback callback, DnsErrorCallback error_callback, 
                      void* user_data) {
    if (!dns_server || !domain || !callback || !error_callback) {
        return false;
    }
    
    // 验证域名长度
    if (strlen(domain) > DNS_MAX_NAME_LENGTH) {
        error_callback("Domain name too long", user_data);
        return false;
    }
    
    // 创建UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sockfd < 0) {
        error_callback("Failed to create socket", user_data);
        return false;
    }
    
    // 创建事件文件描述符
    EvFD* evfd = evfd_new(sockfd, PIPE_READ | PIPE_WRITE, 1024, NULL, NULL);
    if (!evfd) {
        close(sockfd);
        error_callback("Failed to create event fd", user_data);
        return false;
    }
    
    evfd_setup_udp(evfd);
    
    // 准备DNS服务器地址
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    
    if (inet_pton(AF_INET, dns_server, &server_addr.sin_addr) != 1) {
        evfd_close(evfd);
        error_callback("Invalid DNS server address", user_data);
        return false;
    }
    
    // 生成查询包
    uint8_t query_buffer[512];
    uint16_t transaction_id = generate_transaction_id();
    int query_len = build_dns_query(query_buffer, sizeof(query_buffer), domain, transaction_id);
    
    if (query_len <= 0) {
        evfd_close(evfd);
        error_callback("Failed to build DNS query", user_data);
        return false;
    }
    
    // 创建查询上下文
    DnsQueryContext* ctx = malloc(sizeof(DnsQueryContext));
    if (!ctx) {
        evfd_close(evfd);
        error_callback("Memory allocation failed", user_data);
        return false;
    }
    
    ctx -> transaction_id = transaction_id;
    ctx -> user_callback = callback;
    ctx -> error_callback = error_callback;
    ctx -> user_data = user_data;
    ctx -> timeout_ms = DNS_TIMEOUT;
    
    // 注册读取回调
    if (!evfd_read(evfd, 1024, NULL, dns_response_handler, ctx)) {
        evfd_close(evfd);
        free(ctx);
        error_callback("Failed to register read callback", user_data);
        return false;
    }
    
    // 发送DNS查询
    if (!evfd_write_dgram(evfd, query_buffer, query_len,
                            (struct sockaddr*)&server_addr, sizeof(server_addr),
                            NULL, NULL)) {
        evfd_close(evfd);
        free(ctx);
        error_callback("Failed to send DNS query", user_data);
        return false;
    }
    
    return true;
}

/*
 * bind: 
 */
static JSValue js_bind(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if(argc < 1 || !JS_IsString(argv[0]) || !JS_IsFunction(ctx, argv[1])) {
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "bind: missing or invalid arguments",
            "bind(addr: string, handler: (client: ClientHandler) => void, settings?: Object) => /* close function */ () => void"
        );
    }

    JSValue handler = argv[1];
    const char *addr = JS_ToCString(ctx, argv[0]);
    if(addr == NULL) {
        return JS_EXCEPTION;
    }
    URL_data bind_addr = {};
    if(LJS_parse_url(addr, &bind_addr, NULL) == false) {
        JS_ThrowTypeError(ctx, "bind: invalid address");
        goto fail1;
    }

    // bind address
    if(bind_addr.protocol == NULL){
        JS_ThrowTypeError(ctx, "bind: missing protocol");
        goto fail2;
    }
    int sockfd = socket_create(bind_addr.protocol);
    uint32_t bufsize = BUFFER_SIZE;

    if(sockfd == -1){
        LJS_Throw(ctx, EXCEPTION_IO, "bind: failed to create socket: %s", NULL, strerror(errno));
        goto fail2;
    }

    JSValue onclose = JS_UNDEFINED;
    if(argc == 3) {
        if(!JS_IsObject(argv[2])) {
            LJS_Throw(ctx, EXCEPTION_TYPEERROR, "bind: tcpsettings must be an object", NULL);
            goto fail2;
        }

        JSValue jsobj;
        if(JS_IsNumber(jsobj = JS_GetPropertyStr(ctx, argv[2], "bufferSize"))){
            int bufferSize;
            if(JS_ToInt32(ctx, &bufferSize, jsobj) != -1){
                setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
                setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
            }
            bufsize = bufferSize;
        }
        JS_FreeValue(ctx, jsobj);
        if(JS_IsNumber(jsobj = JS_GetPropertyStr(ctx, argv[2], "timeout"))){
            int timeout;
            if(JS_ToInt32(ctx, &timeout, jsobj) != -1){
                setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            }
        }
        JS_FreeValue(ctx, jsobj);
        if(JS_IsFunction(ctx, jsobj = JS_GetPropertyStr(ctx, argv[2], "onclose"))){
            onclose = jsobj;
        }else{
            JS_FreeValue(ctx, jsobj);
        }
        // TCP设置
        if (strcmp(bind_addr.protocol, "unix") != 0){
            if(JS_IsBool(jsobj = JS_GetPropertyStr(ctx, argv[2], "reuseaddr"))){
                bool reuseaddr = JS_ToBool(ctx, jsobj);
                setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
            }
            JS_FreeValue(ctx, jsobj);
            if(JS_IsBool(jsobj = JS_GetPropertyStr(ctx, argv[2], "nodelay"))){
                bool nodelay = JS_ToBool(ctx, jsobj);
                setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
            }
            JS_FreeValue(ctx, jsobj);
            if(JS_IsBool(jsobj = JS_GetPropertyStr(ctx, argv[2], "keepalive"))){
                bool keepalive = JS_ToBool(ctx, jsobj);
                setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&keepalive, sizeof(keepalive));
            }
            JS_FreeValue(ctx, jsobj);
#ifndef __CYGWIN__
            if(JS_IsString(jsobj = JS_GetPropertyStr(ctx, argv[2], "bindto"))){
                const char* bindto = JS_ToCString(ctx, jsobj);
                if(bindto != NULL) {
                    setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, bindto, strlen(bindto));
                    JS_FreeCString(ctx, bindto);
                }
            }
            JS_FreeValue(ctx, jsobj);
#endif
        }
    }

    // start
    int ret_bind = socket_listen(sockfd, bind_addr.protocol, bind_addr.host, bind_addr.port, bind_addr.path);
    if(ret_bind != true){
        if(ret_bind == -2)
            LJS_Throw(ctx, EXCEPTION_TYPEERROR, "bind: invalid address or unsupported protocol", NULL);
        else
            LJS_Throw(ctx, EXCEPTION_IO, "bind: failed to bind address: %s", NULL, strerror(errno));
        goto fail3;
    }
 
    // 添加到evloop
    struct JS_Server_Data* data = malloc2(sizeof(struct JS_Server_Data));
    data -> on_connection = JS_DupValue(ctx, handler);
    data -> fd = sockfd;
    data -> ctx = ctx;
    data -> bufsize = bufsize;
    data -> on_close = onclose;
    EvFD* evfd = evcore_attach(sockfd, false, 
        server_handle_accept, data,    // read callback
        NULL, NULL,                     // write callback
        server_handle_close, data       // close callback
    );

    if(evfd == NULL){
        LJS_Throw(ctx, EXCEPTION_IO, "bind: failed to add to event loop: %s", NULL, strerror(errno));
        goto fail3;
    }

    JSValue func = JS_NewCFunctionData(ctx, js_server_close, 0, 0, 1, (JSValueConst[]){ JS_MKPTR(JS_TAG_INT, evfd) });
    JS_FreeCString(ctx, addr);
    return func;

fail3:
    close(sockfd);
fail2:
    LJS_free_url(&bind_addr);
fail1:
    JS_FreeCString(ctx, addr);
    return JS_EXCEPTION;
}

static JSValue js_connect(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsString(argv[0]) ) {
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "connect: missing or invalid arguments",
            "connect(addr: string, flag?: Object) => U8Pipe"
        );
    }
    const char *addr_str = JS_ToCString(ctx, argv[0]);
    if(addr_str == NULL)  return JS_EXCEPTION;
    URL_data addr = {};
    if(!LJS_parse_url((char*)addr_str, &addr, NULL)) {
        JS_FreeCString(ctx, addr_str);
        return JS_ThrowTypeError(ctx, "connect: invalid address");
    }
    JS_FreeCString(ctx, addr_str);

#ifdef LJS_MBEDTLS
    // TLS -> TCPs
    bool is_tls = false;
    if(memcmp(addr.protocol, "tls", 3) == 0){
        bool v6 = addr.protocol[strlen(addr.protocol)-1] == '6';
        js_free(ctx, addr.protocol);
        addr.protocol = js_strdup(ctx, v6 ? "tcp6s" : "tcps");
        is_tls = true;  
    }
#endif
    bool is_udp = memcmp(addr.protocol, "udp", 3) == 0;

    int sockfd = socket_create(addr.protocol);
    if(sockfd <= 0){
        LJS_free_url(&addr);
        if(errno == EADDRNOTAVAIL)
            return LJS_Throw(ctx, EXCEPTION_IO, "invalid protocol: %s", NULL, addr.protocol);
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to create socket: %s", NULL, strerror(errno));
    }
    int con = socket_connect(sockfd, addr.protocol, addr.host, addr.port, addr.path);
    if(con <= 0 && errno != EINPROGRESS){
        close(sockfd);
        LJS_free_url(&addr);
        return LJS_Throw(ctx, EXCEPTION_IO, "failed to connect: %s", NULL, con == -1 ? strerror(errno) : "address format error");
    }
    LJS_free_url(&addr);
    if(sockfd == -1) return LJS_Throw(ctx, EXCEPTION_IO, "failed to connect: %s", NULL, strerror(errno));

    // TCP设置
    JSValue obj = argc >= 2 ? JS_DupValue(ctx, argv[1]) : JS_NewObject(ctx);
    JSValue jsobj;
    uint32_t timeout = 0;
    if(JS_ToUint32(ctx, &timeout, jsobj = JS_GetPropertyStr(ctx, obj, "timeout")) != -1){
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }
    JS_FreeValue(ctx, jsobj);
    JS_FreeValue(ctx, obj);

    EvFD* evfd;
    JSValue pipe = LJS_NewFDPipe(ctx, sockfd, PIPE_READ | PIPE_WRITE | PIPE_SOCKET, false, &evfd);

    if(is_udp){
        evfd_setup_udp(evfd);
    }
#ifdef LJS_MBEDTLS
    else if(is_tls){
        InitSSLOptions options = {0};

        // tls options
        if(argc >= 2){
            if(JS_IsString(jsobj = JS_GetPropertyStr(ctx, argv[1], "hostname"))){
                options.server_name = JS_ToCString(ctx, jsobj);
                JS_FreeCString(ctx, options.server_name);
            }
            JS_FreeValue(ctx, jsobj);

            if(JS_IsArray(jsobj = JS_GetPropertyStr(ctx, argv[1], "alpn"))){
                int64_t count;
                if(JS_GetLength(ctx, jsobj, &count) > 0){
                    options.alpn_protocols = malloc2((count +1) * sizeof(char*));
                    for(int i = 0; i < count; i++){
                        JSValue item = JS_GetPropertyUint32(ctx, jsobj, i);
                        const char* protocol = JS_ToCString(ctx, item);
                        if(protocol != NULL){
                            ((char**)options.alpn_protocols)[i] = (void*)protocol;
                        }
                        JS_FreeCString(ctx, protocol);
                        JS_FreeValue(ctx, item);
                    }
                    ((char**)options.alpn_protocols)[count] = NULL;
                }
            }
        }
        JS_FreeValue(ctx, jsobj);

        evfd_initssl(evfd, NULL, true, &options, NULL, NULL);
    }
#endif

    return pipe;
}

#ifdef LJS_MBEDTLS
struct HandshakeContext {
    struct promise* promise;

    JSValue values[2];
    JSContext* ctx;
};

void ssl_handshake_callback(EvFD* evfd, bool success, const mbedtls_x509_crt* peer_cert, void* user_data) {
    struct HandshakeContext* ctx = user_data;
    struct promise* promise = ctx -> promise;
    if(success){
        // XXX: crt will be freed when evfd is closed
        //      may cause SEGFAULT if used later
        JSValue cert = LJS_NewCertificate(ctx -> ctx, peer_cert);
        js_resolve(promise, cert);
        JS_FreeValue(ctx -> ctx, cert);
    }else if(evfd_ssl_errno(evfd)){
        char buf[128];
        mbedtls_strerror(evfd_ssl_errno(evfd), buf, sizeof(buf));
        js_reject3(promise, "handshake failed: %s", buf);
    }else{
        js_reject(promise, "SSL handshake failed");
    }

    // unref objects
    JS_FreeValue(ctx -> ctx, ctx -> values[0]);
    JS_FreeValue(ctx -> ctx, ctx -> values[1]);
    js_free(ctx -> ctx, ctx);
}

static JSValue js_ssl_handshake(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsObject(argv[0])) {
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "handshake_ssl: missing or invalid arguments",
            "handshake_ssl(socket: Pipe, options?: Object) => Promise<void>"
        );
    }

    int flag = SSL_VERIFY;
    int cipher_count = 0;
    InitSSLOptions options = {0};
    EvFD* fd = LJS_GetFDFromPipe(ctx, argv[0], false);
    if(fd == NULL) {
        return JS_ThrowTypeError(ctx, "handshake_ssl: invalid socket");
    }

    JSValue stored[2] = {JS_UNDEFINED, JS_UNDEFINED};
    if(argc >= 2){
        JSValue obj = argv[1];
        JSValue val;
        if(JS_IsEqual(ctx, val = JS_GetPropertyStr(ctx, obj, "server"), JS_TRUE)){
            flag |= SSL_IS_SERVER;
        }
        JS_FreeValue(ctx, val);
        if(JS_IsEqual(ctx, val = JS_GetPropertyStr(ctx, obj, "sni"), JS_TRUE)){
            flag |= SSL_USE_SNI;
        }
        JS_FreeValue(ctx, val);
        if(JS_IsEqual(ctx, val = JS_GetPropertyStr(ctx, obj, "verify"), JS_FALSE)){
            flag &= ~SSL_VERIFY;
        }
        JS_FreeValue(ctx, val);
        if(JS_IsArray(val = JS_GetPropertyStr(ctx, obj, "ciphers"))) {
            int64_t count;
            if(JS_GetLength(ctx, val, &count) > 0){
                options.ciphersuites = malloc2((count +1) * sizeof(int));
                for(int i = 0; i < count; i++){
                    JSValue item = JS_GetPropertyUint32(ctx, val, i);
                    int cipher;
                    if(JS_ToInt32(ctx, &cipher, item)){
                        ((int*)options.ciphersuites)[cipher_count++] = cipher;
                    }
                    JS_FreeValue(ctx, item);
                }
                ((int*)options.ciphersuites)[cipher_count] = 0;
            }
        }
        JS_FreeValue(ctx, val);
        if(JS_IsBool(val = JS_GetPropertyStr(ctx, obj, "suiteb"))){
            bool suiteb = JS_ToBool(ctx, val);
            if(suiteb){
                flag |= SSL_PRESET_SUITEB;
            }
        }
        JS_FreeValue(ctx, val);
        if (JS_IsArray(val = JS_GetPropertyStr(ctx, argv[1], "alpn"))) {
            int64_t count;
            if (JS_GetLength(ctx, val, &count) > 0) {
                options.alpn_protocols = malloc2((count + 1) * sizeof(char*));
                for (int i = 0; i < count; i++) {
                    JSValue item = JS_GetPropertyUint32(ctx, val, i);
                    const char* protocol = JS_ToCString(ctx, item);
                    if (protocol != NULL) {
                        ((char**) options.alpn_protocols)[i] = (void*) protocol;
                    }
                    // live as long as the function
                    JS_FreeCString(ctx, protocol);
                    JS_FreeValue(ctx, item);
                }
                ((char**) options.alpn_protocols)[count] = NULL;
            }
        }
        JS_FreeValue(ctx, val);
        if(JS_IsString(val = JS_GetPropertyStr(ctx, obj, "hostname"))){
            options.server_name = JS_ToCString(ctx, val);
            JS_FreeCString(ctx, options.server_name);
        }
        JS_FreeValue(ctx, val);
        if(JS_IsObject(val = JS_GetPropertyStr(ctx, obj, "cert"))){
            mbedtls_x509_crt* crt = (void*)LJS_GetCertificate(ctx, val);
            if(!crt){
                JS_FreeValue(ctx, val);
                return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "handshake_ssl: invalid certificate", 
                    "Require a valid crypto.Certificate class object"
                );
            }

            if(flag & SSL_IS_SERVER)
                options.server_cert = crt;
            else
                options.ca_cert = crt;
            stored[0] = JS_DupValue(ctx, val);
        }
        JS_FreeValue(ctx, val);
        if(JS_IsObject(val = JS_GetPropertyStr(ctx, obj, "key"))){
            size_t psize;
            mbedtls_pk_context* pk = (void*)JS_GetArrayBuffer(ctx, &psize, val);
            if(!pk || psize != sizeof(mbedtls_pk_context)){
                JS_FreeValue(ctx, val);
                if(options.ca_cert) JS_FreeValue(ctx, stored[0]);
                return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "handshake_ssl: invalid private key", 
                    "Require a valid ArrayBuffer allocated by crypto.Certificate.parseKey() "
                );
            }
        
            options.server_key = pk;
            stored[1] = JS_DupValue(ctx, val);
        }
        JS_FreeValue(ctx, val);
    }

    if((flag & SSL_IS_SERVER) && (JS_IsUndefined(stored[0]) || JS_IsUndefined(stored[1]))){
        JS_FreeValue(ctx, stored[0]);
        JS_FreeValue(ctx, stored[1]);
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "handshake_ssl: missing certificate or private key", NULL);
    }

    struct HandshakeContext* ctx_data = malloc2(sizeof(struct HandshakeContext));
    Promise* promise = js_promise(ctx);
    JSValue retprom = js_get_promise(promise);
    ctx_data -> promise = promise;
    ctx_data -> ctx = ctx;
    memcpy(ctx_data -> values, stored, sizeof(stored));

    evfd_initssl(fd, NULL, flag, &options, ssl_handshake_callback, ctx_data);
    free((void*)options.ciphersuites);

    return retprom;
#else
static JSValue js_ssl_handshake(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "handshake_ssl: mbedtls not enabled in build",
        "remove `-DLJS_MBEDTLS=off` from cmake build flags to enable"
    );
#endif
}

void js_handle_dns_resolve(int total_records, dns_record** records, void* user_data) {
    struct promise* promise = (struct promise*)user_data;
    JSContext* ctx = js_get_promise_context(promise);
    JSValue arr = JS_NewArray(ctx);
    
    for (int i = 0; i < total_records; i++) {
        dns_record* record = records[i];
        JSValue obj = JS_NewObject(ctx);
        
        // 添加TTL字段
        JS_SetPropertyStr(ctx, obj, "ttl", JS_NewInt32(ctx, record -> ttl));
        
        switch (record -> type) {
            case DNS_A: {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &record -> data.a, ip_str, INET_ADDRSTRLEN);
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "A"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, ip_str));
                break;
            }
            case DNS_AAAA: {
                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &record -> data.aaaa, ip_str, INET6_ADDRSTRLEN);
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "AAAA"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, ip_str));
                break;
            }
            case DNS_CNAME:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "CNAME"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, record -> data.cname));
                break;
            case DNS_MX:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "MX"));
                JS_SetPropertyStr(ctx, obj, "priority", JS_NewInt32(ctx, record -> data.mx.priority));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, record -> data.mx.exchange));
                break;
            case DNS_NS:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "NS"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, record -> data.ns));
                break;
            case DNS_TXT:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "TXT"));
                JS_SetPropertyStr(ctx, obj, "data", JS_NewString(ctx, record -> data.txt));
                break;
            case DNS_SOA:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "SOA"));
                JS_SetPropertyStr(ctx, obj, "mname", JS_NewString(ctx, record -> data.soa.mname));
                JS_SetPropertyStr(ctx, obj, "rname", JS_NewString(ctx, record -> data.soa.rname));
                JS_SetPropertyStr(ctx, obj, "serial", JS_NewInt64(ctx, record -> data.soa.serial));
                JS_SetPropertyStr(ctx, obj, "refresh", JS_NewInt32(ctx, record -> data.soa.refresh));
                JS_SetPropertyStr(ctx, obj, "retry", JS_NewInt32(ctx, record -> data.soa.retry));
                JS_SetPropertyStr(ctx, obj, "expire", JS_NewInt32(ctx, record -> data.soa.expire));
                JS_SetPropertyStr(ctx, obj, "minimum", JS_NewInt32(ctx, record -> data.soa.minimum));
                break;
            case DNS_SRV:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "SRV"));
                JS_SetPropertyStr(ctx, obj, "priority", JS_NewInt32(ctx, record -> data.srv.priority));
                JS_SetPropertyStr(ctx, obj, "weight", JS_NewInt32(ctx, record -> data.srv.weight));
                JS_SetPropertyStr(ctx, obj, "port", JS_NewInt32(ctx, record -> data.srv.port));
                JS_SetPropertyStr(ctx, obj, "target", JS_NewString(ctx, record -> data.srv.target));
                break;
            default:
                JS_SetPropertyStr(ctx, obj, "type", JS_NewString(ctx, "UNKNOWN"));
                break;
        }
        
        JS_SetPropertyUint32(ctx, arr, i, obj);
    }
    
    js_resolve(promise, arr);
    JS_FreeValue(ctx, arr);
    dns_free_record(records, total_records);
}

static void js_handle_dns_error(const char* error_msg, void* user_data) {
    struct promise* promise = (struct promise*)user_data;
    js_reject(promise, error_msg);
}

static JSValue js_resolve_dns(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    if (argc == 0 || !JS_IsString(argv[0])) {
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "resolve_dns: missing or invalid arguments",
            "resolve_dns(hostname: string, dns_server?: string) => Promise<Array<RecordItem>>"
        );
    }

    const char* domain = JS_ToCString(ctx, argv[0]);
    if (!domain) return JS_EXCEPTION;

    const char* dns_server = "8.8.8.8";
    if (argc >= 2 && JS_IsString(argv[1])) {
        const char* dns_server_str = JS_ToCString(ctx, argv[1]);
        if (dns_server_str) {
            dns_server = dns_server_str;
        }
    }

    struct promise* promise = js_promise(ctx);
    
    if (!async_dns_resolve(dns_server, domain, js_handle_dns_resolve, js_handle_dns_error, promise)) {
        JS_FreeCString(ctx, domain);
        if (argc >= 2) JS_FreeCString(ctx, dns_server);
        return LJS_Throw(ctx, EXCEPTION_IO, "resolve_dns: failed to start DNS resolution", NULL);
    }

    JS_FreeCString(ctx, domain);
    if (argc >= 2) JS_FreeCString(ctx, dns_server);
    
    return js_get_promise(promise);
}

#ifdef LJS_MBEDTLS
static int default_rng(void *userdata, unsigned char *output, size_t output_size) {
    if(-1 == getrandom(output, output_size, GRND_NONBLOCK)){
        long rand = random();
        memcpy(output, &rand, output_size);
    }
    return 0;
}
#endif

static JSValue js_cert_add(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
#ifdef LJS_MBEDTLS
    if(argc == 0 || !JS_IsString(argv[0]) || (!JS_IsString(argv[1]) && !JS_IsTypedArray(ctx, argv[1])) || !JS_IsString(argv[2])) {
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "cert_add: missing or invalid arguments",
            "regCert(name: string, cert: string | Uint8Array, key: string, options?: { keypwd?: string }) => void"
        );
    }

    JSValue name_val = argv[0];
    JSValue cert_val = argv[1];
    JSValue key_val = argv[2];
    bool cbinary = JS_IsTypedArray(ctx, cert_val);
    size_t cert_len;
    const char* name_str = JS_ToCString(ctx, name_val);
    uint8_t* cert_str = cbinary
        ? (void*)JS_GetUint8Array(ctx, &cert_len, cert_val)
        : (void*)JS_ToCStringLen(ctx, &cert_len, cert_val);
    const char* key_str = JS_ToCString(ctx, key_val);
    if(cert_str == NULL || key_str == NULL || name_str == NULL) return JS_EXCEPTION;

    const char* keypwd = NULL;
    size_t keypwd_len = 0;
    if(argc >= 4){
        JSValue options_val = argv[3];
        JSValue keypwd_val = JS_GetPropertyStr(ctx, options_val, "keypwd");
        if(JS_IsString(keypwd_val)){
            keypwd = JS_ToCStringLen(ctx, &keypwd_len, keypwd_val);
        }
        JS_FreeValue(ctx, keypwd_val);
    }
    
    // mbedtls parse
    int ret;
    mbedtls_x509_crt* crt = js_malloc(ctx, sizeof(mbedtls_x509_crt));
    mbedtls_pk_context* pk = js_malloc(ctx, sizeof(mbedtls_pk_context));
    mbedtls_x509_crt_init(crt);
    mbedtls_pk_init(pk);
    ret = cbinary
        ? mbedtls_x509_crt_parse_der(crt, (const unsigned char*)cert_str, cert_len)
        : mbedtls_x509_crt_parse(crt, (const unsigned char*)cert_str, cert_len +1);
    if(!cbinary) JS_FreeCString(ctx, (void*)cert_str);
    if(ret != 0){
        mbedtls_x509_crt_free(crt);
        mbedtls_pk_free(pk);
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "cert_add: failed to parse certificate", NULL);
    }
    // XXX: return a promise?
    ret = mbedtls_pk_parse_key(pk, (const unsigned char*)key_str, strlen(key_str) + 1, (void*)keypwd, keypwd_len, default_rng, NULL);
    JS_FreeCString(ctx, key_str);
    JS_FreeCString(ctx, name_str);
    if(ret != 0){
        mbedtls_x509_crt_free(crt);
        mbedtls_pk_free(pk);
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "cert_add: failed to parse private key", NULL);
    }

    // add to evloop
    evcore_set_sni(name_str, name_str, crt, pk);

    return JS_UNDEFINED;
#else
    return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "mbedtls not enabled in build",
        "remove `-DLJS_MBEDTLS=off` from cmake build flags to enable"
    );
#endif
}

static JSValue js_cert_remove(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv){
    if(argc == 0 || !JS_IsString(argv[0])) {
        return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "cert_remove: missing or invalid arguments",
            "unregCert(name: string) => void"
        );
    }

#ifdef LJS_MBEDTLS
    const char* name_str = JS_ToCString(ctx, argv[0]);
    if(name_str == NULL) return JS_EXCEPTION;

    bool ret = evcore_remove_sni(name_str);
    JS_FreeCString(ctx, name_str);
    return JS_NewBool(ctx, ret);
#else
    return LJS_Throw(ctx, EXCEPTION_TYPEERROR, "mbedtls not enabled in build",
        "remove `-DLJS_MBEDTLS=off` from cmake build flags to enable"
    );
#endif
}

static const JSCFunctionListEntry js_socket_funcs[] = {
    JS_CFUNC_DEF("bind", 1, js_bind),
    JS_CFUNC_DEF("connect", 1, js_connect),
    JS_CFUNC_DEF("upgradeTLS", 1, js_ssl_handshake),
    JS_CFUNC_DEF("resolveDNS", 1, js_resolve_dns),
    JS_CFUNC_DEF("regCert", 3, js_cert_add),
    JS_CFUNC_DEF("unregCert", 1, js_cert_remove),
};

static int js_init_socket(JSContext* ctx, JSModuleDef* m) {
    JS_SetModuleExportList(ctx, m, js_socket_funcs, countof(js_socket_funcs));

    // ignore SIGPIPE
    // signal(SIGPIPE, SIG_IGN);

    return 0;
}

bool LJS_init_socket(JSContext* ctx) {
    JSModuleDef* m = JS_NewCModule(ctx, "socket", js_init_socket);
    if(!m) return false;
    JS_AddModuleExportList(ctx, m, js_socket_funcs, countof(js_socket_funcs));
    return true;
}

// C API
bool LJS_dns_resolve(
    JSContext* ctx, const char* hostname, const char* dns_server, 
    DnsResponseCallback callback, DnsErrorCallback error_callback, void* user_data
) {
    if (!dns_server) dns_server = "8.8.8.8";
    return async_dns_resolve(dns_server, hostname, callback, error_callback, user_data);
}

EvFD* LJS_open_socket(const char* protocol, const char* hostname, int port, int bufsize, InitSSLOptions* ssl_options) {
    bool ssl = protocol[strlen(protocol) - 1] == 's';
    const char* host4 = NULL, *host6 = NULL;
    // unix domain socket is not required to resolve DNS
    if(memcmp(protocol, "unix", 4)){
        // resolve DNS sync
        // XXX: use async DNS resolve
        struct addrinfo hints = {0}, *res, *res0;
        hints.ai_family = AF_INET; // IPv4
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
            errno = EADDRNOTAVAIL;
            return NULL;
        }

        res0 = res;
        do{
            switch(res0 -> ai_family){
                case AF_INET:
                    if(!host4)
                        host4 = inet_ntoa(((struct sockaddr_in*)res0 -> ai_addr) -> sin_addr);
                break;
                case AF_INET6:
                    if(!host6)
                        host6 = inet_ntop(AF_INET6, &((struct sockaddr_in6*)res0 -> ai_addr) -> sin6_addr, NULL, 0);
                break;
                default:
                    freeaddrinfo(res);
                    return NULL;
            }
        }while((res0 = res0 -> ai_next) != NULL);
        freeaddrinfo(res);

        hostname = host6 ? host6 : host4;
        protocol = host6 ? "tcp6" : "tcp";
    }

#ifdef __CYGWIN__
    else {
        errno = ENOTSUP;
        return NULL;
    }
#endif

    bool try_ipv4 = true;
retry:;
    int fd = socket_create(protocol);
    if(fd < 0) return NULL;
    socket_connect(fd, protocol, hostname, port, hostname);
    EvFD* evfd = evfd_new(fd, PIPE_READ | PIPE_WRITE, bufsize, NULL, NULL);
    if(evfd == NULL || evfd_closed(evfd)){
        // also try ipv6 address if ipv4 fails for non-unix socket
        if(try_ipv4 && host4 && memcmp(protocol, "unix", 4)){
            try_ipv4 = false;
            hostname = host4;
            protocol = "tcp";
            goto retry;
        }
        return NULL;
    }
    if(ssl){
#ifdef LJS_MBEDTLS
        mbedtls_ssl_config* config = NULL;
        evfd_initssl(evfd, &config, SSL_USE_TLS1_3, ssl_options, NULL, NULL);
#else
        errno = ENOTSUP;
        evfd_close(evfd);
        return NULL;
#endif
    }
    return evfd;
}