#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE] = {0};
    
    // 创建socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // 设置socket选项
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // 绑定socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // 监听
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d...\n", PORT);
    
    // 接受连接
    if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    
    printf("Client connected: %s\n", inet_ntoa(client_addr.sin_addr));
    
    // 接收和回显数据
    printf("Data received: \n");
    while (1) {
        int valread = read(client_fd, buffer, BUFFER_SIZE);
        if (valread <= 0) {
            // 客户端断开连接
            printf("Client disconnected\n");
            break;
        }
        
        printf("%s", buffer);
        
        // 回显数据
        // send(client_fd, buffer, valread, 0);
        memset(buffer, 0, BUFFER_SIZE);
    }
    printf("Server closed\n");
    
    // 关闭连接
    close(client_fd);
    close(server_fd);
    
    return 0;
}