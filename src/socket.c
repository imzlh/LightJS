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
#include <netinet/tcp.h>
#include <sys/un.h>
#include <sys/epoll.h>

#define BUFFER_SIZE 64 * 1024

struct JS_Server_Data{
    JSValue on_connection;
    int fd;
    JSContext* ctx;
    uint32_t bufsize;

    struct LJS_Promise_Proxy* promise;
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
    int sockfd = -1;
    uint32_t bufsize = BUFFER_SIZE;

    if(strcmp(bind_addr.protocol, "tcp")!= 0) {
        struct sockaddr_in addr_in;
        memset(&addr_in, 0, sizeof(addr_in));
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = htons(bind_addr.port);
        addr_in.sin_addr.s_addr = inet_addr(bind_addr.host);
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }else if(strcmp(bind_addr.protocol, "tcp6") == 0) {
        struct sockaddr_in6 addr_in6;
        memset(&addr_in6, 0, sizeof(addr_in6));
        addr_in6.sin6_family = AF_INET6;
        addr_in6.sin6_port = htons(bind_addr.port);
        if(inet_pton(AF_INET6, bind_addr.host, &addr_in6.sin6_addr) != 1) {
            return JS_ThrowTypeError(ctx, "bind: invalid address");
        }
        sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    }else if(strcmp(bind_addr.protocol, "unix") == 0){
        struct sockaddr_un addr_un;
        memset(&addr_un, 0, sizeof(addr_un));
        addr_un.sun_family = AF_UNIX;
        strncpy(addr_un.sun_path, bind_addr.path, sizeof(addr_un.sun_path)-1);
        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    }

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
    struct LJS_Promise_Proxy* promise = LJS_NewPromise(ctx);
    struct JS_Server_Data* data = malloc(sizeof(struct JS_Server_Data));
    data->promise = promise;
    data->on_connection = handler;
    data->fd = sockfd;
    data->ctx = ctx;
    data->bufsize = bufsize;
    LJS_evcore_attach(sockfd, false, socket_handle_connect, (EvWriteCallback)NULL, socket_handle_close, data);

    return promise -> promise;
}

static const JSCFunctionListEntry LJS_socket_funcs[] = {
    JS_CFUNC_DEF("bind", 1, js_bind),
};

static int js_init_socket(JSContext* ctx, JSModuleDef* m) {
    return 1;
}

bool LJS_init_module_socket(JSContext* ctx) {
    JSModuleDef* m = JS_NewCModule(ctx, "socket", js_init_socket);
    if(!m) return false;
    JS_SetModuleExportList(ctx, m, LJS_socket_funcs, countof(LJS_socket_funcs));
    return true;
}