#include"socks5.h"
#define MYPORT "0"
#define UDP_DESTIP "10.0.1.2"

int udp_addr(void)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    // hints.ai_flags = AI_ALL; // use my IP

    if ((rv = getaddrinfo(NULL, MYPORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "listener: failed to bind socket\n");
        return -1;
    }

    freeaddrinfo(servinfo);
    return sockfd;
}

int handle_udp(int atyp, int client_socket, char *dest_addr, uint16_t dest_port)
{
    
    int udp_socket = udp_addr();
    if(udp_socket == -1)return -1;
    
    uint8_t response_buffer[BUFFER_SIZE];
    memset(response_buffer, 0, sizeof(response_buffer));
    response_buffer[0] = SOCKS5_VERSION;
    response_buffer[1] = ReplySuccess;  // Success
    response_buffer[2] = ReservedField;  // Reserved
    response_buffer[3] = atyp;
    
    memset(dest_addr, 0, sizeof dest_addr);
    dest_port = get_local(udp_socket, dest_addr,atyp);
    dest_addr = UDP_DESTIP;
    printf("Local address: %s\n", dest_addr);
    printf("Local port: %d\n", dest_port);

    if (atyp== TypeIPv4) {
        inet_pton(AF_INET, dest_addr, response_buffer + 4);
        *(uint16_t *)(response_buffer + 4 + IPv4Length) = htons(dest_port);
    } else if (atyp == TypeDomain) {
        response_buffer[4] = strlen(dest_addr);
        strncpy((char *)(response_buffer + 5), dest_addr, strlen(dest_addr));
        *(uint16_t *)(response_buffer + 5 + strlen(dest_addr)) = htons(dest_port);
    } else if(atyp == TypeIPv6) {
        inet_pton(AF_INET6, dest_addr, response_buffer + 4);
        *(uint16_t *)(response_buffer + 4 + IPv6Length) = htons(dest_port);
    }

    send(client_socket, response_buffer, sizeof(response_buffer), 0);
    printf("deal with udp\n");

    // deal with UDP data
    struct sockaddr_in udp_client_addr;
    socklen_t udp_client_len = sizeof(udp_client_addr);
    char buffer[BUFFER_SIZE];
    memset(buffer, 0 , sizeof buffer);
    int received;
    while(received = recvfrom(udp_socket, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&udp_client_addr, &udp_client_len) > 0)
    {
        if(buffer[0] != ReservedField && buffer[1] != ReservedField && buffer[2] != Fragment)
        {
            perror("wrong");
        }
        // printf("re %d buf %d\n", received,buffer[3]);
        // memset(buffer, 0 , sizeof buffer);
        char dst_addr[256];
        memset(dst_addr, 0 , sizeof dst_addr);
        char dst_addr1[256];
        memset(dst_addr1, 0 , sizeof dst_addr1);
        uint16_t *dst_port;
        int data_len  = 0;
        if(buffer[3] == TypeIPv4)
        {
            memcpy(dst_addr, buffer+4,IPv4Length);
            dst_port = (uint16_t *)&(buffer[4 + IPv4Length]) ; 
            *dst_port = ntohs(*dst_port);
            inet_ntop(AF_INET,dst_addr,dst_addr1,sizeof dst_addr1);
            data_len = 4+IPv4Length+2;
        }
        else if(buffer[3] == TypeIPv6)
        {
            memcpy(dst_addr, buffer+4,IPv6Length);
            dst_port = (uint16_t *)&(buffer[4 + IPv6Length]) ; 
            *dst_port = ntohs(*dst_port);
            inet_ntop(AF_INET6,dst_addr,dst_addr1,sizeof dst_addr1);
            data_len = 4+IPv6Length+2;
        }
        // else if(buffer[3] == TypeDomain)
        // {

        // }
        
        // printf("buf ad %s %d\n",dst_addr1, *dst_port);
        char dat[BUFFER_SIZE];
        memset(dat, 0 ,sizeof dat);
        memcpy(dat,buffer+data_len, (sizeof buffer) - data_len);
        
        // printf("dat %s %ld\n",dat, sizeof(dat));
        char ret1[BUFFER_SIZE];
        memset(ret1, 0, sizeof ret1);
        int len = 0;
        udp_dest(*dst_port,dst_addr1, dat,ret1,&len);
        // printf("suc ret %d\n", len);

        uint8_t response_buf[BUFFER_SIZE];
        memset(response_buf, 0, sizeof(response_buf));
        response_buf[3] = atyp;
        if(atyp == TypeIPv4)
        {
            inet_pton(AF_INET, dst_addr1, response_buf + 4);
            *(uint16_t *)(response_buf + 4 + IPv4Length) = htons(*dst_port);
            memcpy(response_buf+10,ret1, len);
            // send receive UDP data to client
            if(sendto(udp_socket, response_buf, len+10, 0, (struct sockaddr *)&udp_client_addr, udp_client_len) == -1) 
            {
                perror("back: sendto");
                exit(1);
            }
        }
        else if(atyp == TypeIPv6)
        {
            inet_pton(AF_INET6, dst_addr1, response_buf + 4);
            *(uint16_t *)(response_buf + 4 + IPv6Length) = htons(*dst_port);
            memcpy(response_buf+22,ret1, len);
            // send receive UDP data to client
            if(sendto(udp_socket, response_buf, len+22, 0, (struct sockaddr *)&udp_client_addr, udp_client_len) == -1) 
            {
                perror("back: sendto");
                exit(1);
            }
        }

    }

    // 关闭套接字
    close(udp_socket);
    close(client_socket);
}

int udp_dest(uint16_t dst_port, char * dst_addr, char * dat, char *ret, int *len) {
    
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int numbytes;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // set to AF_INET to use IPv4
    hints.ai_socktype = SOCK_DGRAM;

    char dst[48];
    sprintf(dst, "%hu", dst_port);

    if ((rv = getaddrinfo(dst_addr, dst, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("talker: socket");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "talker: failed to create socket\n");
        return 2;
    }

    if ((numbytes = sendto(sockfd, dat, strlen(dat), 0,
             p->ai_addr, p->ai_addrlen)) == -1) {
        perror("talker: sendto");
        exit(1);
    }

    freeaddrinfo(servinfo);

    printf("talker: sent %d bytes to %s\n", numbytes , dst_addr);

    // 接收 UDP 服务器的回复
    struct sockaddr_in udp_client_addr;
    socklen_t udp_client_len = sizeof(udp_client_addr);
    // char buf[2048];
    // memset(buf, 0 , sizeof buf);
    int received = recvfrom(sockfd, ret, BUFFER_SIZE, 0,
                        NULL, NULL);

    printf("listener: packet is %d bytes long\n", received);
    ret[received] = '\0';
    // printf("listener: packet contains \"%s\"\n", ret);
    *len = received;
    close(sockfd);

    return 0;
}
