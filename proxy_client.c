#include"socks5.h"

int proxy_client(const char* destAddr, const char* destPort) {
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(destAddr, destPort, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // 遍历地址信息链表，尝试连接
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("connect");
            continue;
        }

        break; // 成功连接，跳出循环
    }

    if (p == NULL) {
        fprintf(stderr, "Failed to connect\n");
        return -1;
    }

    char ipstr[INET6_ADDRSTRLEN];
    void *addr;
    char *ipver;

    // 将目标地址转换为字符串格式
    if (p->ai_family == AF_INET) { // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr = &(ipv4->sin_addr);
        ipver = "IPv4";
    } else { // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
        addr = &(ipv6->sin6_addr);
        ipver = "IPv6";
    }

    // 将地址转换为字符串格式
    inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
    printf("Connected to %s: %s\n", ipver, ipstr);

    freeaddrinfo(servinfo);
    return sockfd;
}


void handle_ProxyClient(int client_socket)
{
   // accept client request and authenticates
   char buf[BUFFER_SIZE];
   char VER, NMETHODS;
   recv(client_socket,&VER,1,0);
   recv(client_socket,&NMETHODS,1,0);
   char *METHODS =  (char *)malloc(NMETHODS);
   recv(client_socket,METHODS,NMETHODS,0);
  //  printf("method %d Nm %d\n", METHODS[0], NMETHODS);
   if (VER != SOCKS5_VERSION){
        perror("protocol version not support");
        return;
   }
   

// chose autho method: NO AUTHENTICATION REQUIRED 0x00
   int fg = 0;
   for (int i = 0; i < NMETHODS; i++)
   {
      char tmp = METHODS[i];
      if(tmp == Method_NoAuth){
        fg = 1;
        break;
      }
   }
   char methods = Method_NoAuth;
   if(!fg){
    methods = Method_NoAcceptable;
    send(client_socket,&VER,1,0);
    send(client_socket,&methods,1,0);
    perror("method not supported");
    return;
   }

    unsigned char method_selection[] = { SOCKS5_VERSION, Method_NoAuth};
    send(client_socket, method_selection, sizeof method_selection,0);
    printf("fg %d ver %d m %d\n",fg, VER, methods);

  // accept client connect request
    memset(buf,0, sizeof buf);
    unsigned char connect_request[4];
    // memset(connect_request,0, sizeof connect_request);
    if(recv(client_socket, connect_request, sizeof(connect_request),MSG_WAITALL) == -1){
      perror("recv error");
    }
    char ver = connect_request[0];
    char cmd = connect_request[1];
    char rsv = connect_request[2];
    char atyp = connect_request[3];
    printf("ver %d cmd %d rsv %d atyp %d\n", ver,cmd, rsv, atyp);

    // curl --proxy socks5://localhost:8080 www.baidu.com -v

    char dst_addr[256];
    // domain
    int add_len;
    
    if(atyp == TypeIPv4)
    {
      recv(client_socket, buf,IPv4Length,0);
      inet_ntop(AF_INET,buf,dst_addr,sizeof dst_addr); 
      
      // sprintf(dst_addr,"%d.%d.%d.%d" ,buf[0],buf[1],buf[2],buf[3]);
    }
    else if(atyp == TypeIPv6)
    {
      recv(client_socket, buf,IPv6Length,0);
      inet_ntop(AF_INET6,buf,dst_addr,sizeof dst_addr); 
      
    }
    else if(atyp == TypeDomain){
      recv(client_socket, buf, 1, 0);
      add_len  = buf[0];
      recv(client_socket, dst_addr, add_len, 0);
      dst_addr[add_len] = '\0';
    }
    // else {
    //     // Send an address type not supported message
    //     unsigned char address_type_not_supported[] = { SOCKS5_VERSION, ReplyAddressTypeNotSupported, ReservedField, atyp, 0, 0 };
    //     write(client_socket, address_type_not_supported, sizeof(address_type_not_supported));
    //     close(client_socket);
    //     return;
    // }
    
    uint16_t dst_port;
    recv(client_socket, &dst_port, 2, 0);
    dst_port = ntohs(dst_port);
    
    printf("dst %s atyp %d port %d\n",dst_addr, atyp, dst_port);

    if(ver != SOCKS5_VERSION){
      printf("ver %d\n",ver);
      perror("protocol version not supported");
      return;
    }

    if(cmd != CmdBind && cmd != CmdConnect && cmd != CmdUDP){
      printf("cmd %d\n",cmd);
      perror("request command not supported");
      unsigned char address_type_not_supported[] = { SOCKS5_VERSION, ReplyCommandNotSupported};
      send(client_socket, address_type_not_supported, sizeof(address_type_not_supported),0);
      return;
    }

    if (rsv != ReservedField) {
      printf("rsv %d\n",rsv);
      perror("invaild reserved field");
      return;
    }

    if (atyp != TypeIPv4 && atyp != TypeIPv6 && atyp != TypeDomain){
      printf("atyp %d\n",atyp);
      perror("address type not supported");
      // Send an address type not supported message
      unsigned char address_type_not_supported[] = { SOCKS5_VERSION, ReplyAddressTypeNotSupported};
      send(client_socket, address_type_not_supported, sizeof(address_type_not_supported),0);
      // close(client_socket);
      return;
    }

   const char *proxy_add = "10.0.2.2";
   const char *proxy_port = "8080";
   uint16_t proxy_port0 = 8080;
   int proxy_socket = proxy_client(proxy_add,proxy_port);

   // send handshake request
    unsigned char handshake_request[] = {SOCKS5_VERSION, 1, Method_NoAuth};
    if (send(proxy_socket, handshake_request, sizeof(handshake_request), 0) != sizeof(handshake_request)) {
        perror("Failed to send handshake request");
        close(proxy_socket);
        return;
    }

    // accept handshake request
    unsigned char handshake_response[2];
    if (recv(proxy_socket, handshake_response, sizeof(handshake_response), 0) != sizeof(handshake_response)) {
        perror("Failed to receive handshake response");
        close(proxy_socket);
        return;
    }

    if (handshake_response[0] != SOCKS5_VERSION || handshake_response[1] != Method_NoAuth) {
        printf("Handshake failed: Unsupported authentication method\n");
        close(proxy_socket);
        return;
    }

    // 向代理服务器发送协商请求
    uint8_t request[4] = {SOCKS5_VERSION, CmdConnect, ReservedField, atyp};
    if (send(proxy_socket, request, sizeof(request), 0) == -1) {
        perror("send");
        return;
    }

    // 根据地址类型发送目标地址
    if (atyp == TypeDomain) { // hostname
        uint8_t addr_len = strlen(dst_addr);
        if (send(proxy_socket, &addr_len, sizeof(addr_len), 0) == -1) {
            perror("send");
            return;
        }
        if (send(proxy_socket, dst_addr, addr_len, 0) == -1) {
            perror("send");
            return;
        }
    } else if (atyp == TypeIPv4) { // ipv4
        struct in_addr ip;
        if (inet_pton(AF_INET, dst_addr, &ip) <= 0) {
            perror("inet_pton");
            return;
        }
        if (send(proxy_socket, &ip, sizeof(ip), 0) == -1) {
            perror("send");
            return;
        }
    } else { // ipv6
        struct in6_addr ip;
        if (inet_pton(AF_INET6, dst_addr, &ip) <= 0) {
            perror("inet_pton");
            return;
        }
        if (send(proxy_socket, &ip, sizeof(ip), 0) == -1) {
            perror("send");
            return;
        }
    }

    // 发送目标端口号
    uint16_t port_network_order = htons(dst_port);
    if (send(proxy_socket, &port_network_order, sizeof(port_network_order), 0) == -1) {
        perror("send");
        return;
    }

    // 读取代理服务器的响应
    uint8_t reply[3];
    if (recv(proxy_socket, reply, sizeof(reply), 0) == -1) {
        perror("recv");
        return;
    }
    if (reply[0] != SOCKS5_VERSION || reply[1] != ReplySuccess) {
        fprintf(stderr, "reply code: %d\n", reply[1]);
        return;
    }

    // 读取绑定的地址
    uint8_t addr_type;
    char bnd_addr[256];
    uint16_t bnd_port;
    if (recv(proxy_socket, &addr_type, sizeof(addr_type), 0) == -1) {
        perror("recv");
        return;
    }

    if (addr_type == TypeIPv4) { // ipv4
        struct in_addr ip;
        if (recv(proxy_socket, &ip, sizeof(ip), 0) == -1) {
            perror("recv");
            return;
        }
        if (inet_ntop(AF_INET, &ip, bnd_addr, INET_ADDRSTRLEN) == NULL) {
            perror("inet_ntop");
            return;
        }
    } else if (addr_type == TypeIPv6) { // ipv6
        struct in6_addr ip;
        if (recv(proxy_socket, &ip, sizeof(ip), 0) == -1) {
            perror("recv");
            return;
        }
        if (inet_ntop(AF_INET6, &ip, bnd_addr, INET6_ADDRSTRLEN) == NULL) {
            perror("inet_ntop");
            return;
        }
    } else if (addr_type == TypeDomain) { // hostname
        uint8_t addr_len;
        if (recv(proxy_socket, &addr_len, sizeof(addr_len), 0) == -1) {
            perror("recv");
            return;
        }
        if (recv(proxy_socket, bnd_addr, addr_len, 0) == -1) {
            perror("recv");
            return;
        }
        bnd_addr[addr_len] = '\0';
    } else {
        fprintf(stderr, "invalid atyp\n");
        return;
    }

    // 读取绑定的端口号
    if (recv(proxy_socket, &bnd_port, sizeof(bnd_port), 0) == -1) {
        perror("recv");
        return;
    }
    bnd_port = ntohs(bnd_port);

    printf("bnd IP: %s \n", bnd_addr);
    printf("bnd Port: %hu atyp %d\n", bnd_port, atyp);

    unsigned char success_reply[] = { SOCKS5_VERSION,ReplySuccess,ReservedField,atyp};
    write(client_socket,success_reply,sizeof success_reply);
    if(atyp ==TypeIPv4)send(client_socket,bnd_addr,IPv4Length,0);
    else if(atyp == TypeIPv6)send(client_socket,bnd_addr,IPv6Length,0);
    // write(client_socket,local_ip,sizeof local_ip);
    write(client_socket,&bnd_port,sizeof (bnd_port));
    // send(client_socket,local_ip,IPv4Length,0);

    // forward data
    Socks5Forward(client_socket, proxy_socket);

}

int accept_client()
{
  int sockfd, new_fd; // 在 sock_fd 进行 listen，new_fd 是新的连接
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr; // 连接者的地址资料
  socklen_t sin_size;
  struct sigaction sa;
  int yes=1;
  char s[INET6_ADDRSTRLEN];
  int rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; // 使用我的 IP

  if ((rv = getaddrinfo(NULL, PROXY_PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  // 以循环找出全部的结果，并绑定（bind）到第一个能用的结果
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
      p->ai_protocol)) == -1) {
      perror("server: socket");
      continue;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
        sizeof(int)) == -1) {
      perror("setsockopt");
      exit(1);
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("server: bind");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "server: failed to bind\n");
    return 2;
  }

  freeaddrinfo(servinfo); // 全部都用这个 structure

  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  sa.sa_handler = sigchld_handler; // 收拾全部死掉的 processes
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }

  printf("server: waiting for connections...\n");

  while(1) { // 主要的 accept() 循环
  
  sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);

    if (new_fd == -1) {
      perror("accept");
      continue;
    }

    inet_ntop(their_addr.ss_family,
    get_in_addr((struct sockaddr *)&their_addr),
      s, sizeof s);
    printf("server: got connection from %s\n", s);
 
    if (!fork()) { // 这个是 child process
      close(sockfd); // child 不需要 listener

      // if (send(new_fd, "Hello, world!", 13, 0) == -1)
      //   perror("send");
      handle_ProxyClient(new_fd);

      // close(new_fd);

      exit(0);
    }
    close(new_fd); // parent 不需要这个
  }

  return 0;
}

int main()
{
  accept_client();
  
}