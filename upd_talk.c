#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024
#define PROXY_SERVER "127.0.0.1"
#define PROXY_PORT 1080
#define UDP_SERVER "www.baidu.com"
#define UDP_PORT 80

int main() {
    int sockfd, n;
    struct sockaddr_in servaddr, proxyaddr;
    char sendline[] = "hello udp";
    char buffer[BUFFER_SIZE];

    // 创建 UDP 套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置代理服务器地址
    memset(&proxyaddr, 0, sizeof(proxyaddr));
    proxyaddr.sin_family = AF_INET;
    proxyaddr.sin_port = htons(PROXY_PORT);
    proxyaddr.sin_addr.s_addr = inet_addr(PROXY_SERVER);

    // 设置 UDP 服务器地址
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(UDP_PORT);
    servaddr.sin_addr.s_addr = inet_addr(UDP_SERVER);

    // 通过代理发送 UDP 数据包
    if (sendto(sockfd, sendline, strlen(sendline), 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("sendto failed");
        exit(EXIT_FAILURE);
    }

    // 接收 UDP 服务器的回复
    n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (n > 0) {
        buffer[n] = '\0';
        printf("Received from UDP server: %s\n", buffer);
    } else {
        perror("recvfrom failed");
        exit(EXIT_FAILURE);
    }

    close(sockfd);
    return 0;
}