#include"socks5.h"

void handle_client(int client_socket)
{
   // accept client request and authenticates
   char buf[BUFFER_SIZE];
   char VER, NMETHODS;
   recv(client_socket,&VER,1,MSG_WAITALL);
   recv(client_socket,&NMETHODS,1,MSG_WAITALL);
   char *METHODS =  (char *)malloc(NMETHODS);
   recv(client_socket,METHODS,NMETHODS,MSG_WAITALL);
  //  printf("method %d Nm %d\n", METHODS[0], NMETHODS);
   if (VER != SOCKS5_VERSION)
   {
      perror("protocol version not support");
      return;
   }
   
// chose autho method: NO AUTHENTICATION REQUIRED 0x00
   int fg = 0;
   for (int i = 0; i < NMETHODS; i++) 
   {
      char tmp = METHODS[i];
      if(tmp == Method_NoAuth)
      {
        fg = 1;
        break;
      }
   }
   char methods = Method_NoAuth;
   if(!fg) 
   {
    methods = Method_NoAcceptable;
    send(client_socket,&VER,1,0);
    send(client_socket,&methods,1,0);
    perror("method not supported");
    return;
   }

    unsigned char method_selection[] = { SOCKS5_VERSION, Method_NoAuth};
    send(client_socket, method_selection, sizeof method_selection,0);
    // printf("fg %d ver %d m %d\n",fg, VER, methods);

  // accept client connect request
    memset(buf,0, sizeof buf);
    unsigned char connect_request[4];
    // memset(connect_request,0, sizeof connect_request);
    if(recv(client_socket, connect_request, sizeof(connect_request),MSG_WAITALL) == -1)
    {
      perror("recv error");
    }
    char ver = connect_request[0];
    char cmd = connect_request[1];
    char rsv = connect_request[2];
    char atyp = connect_request[3];
    // printf("ver %d cmd %d rsv %d atyp %d\n", ver,cmd, rsv, atyp);

    // curl --proxy socks5://localhost:8080 www.baidu.com -v

    char dst_addr[256];
    // domain
    int add_len;
    
    if(atyp == TypeIPv4)
    {
      recv(client_socket, buf,IPv4Length,0);
      inet_ntop(AF_INET,buf,dst_addr,sizeof dst_addr); 
    }
    else if(atyp == TypeIPv6)
    {
      recv(client_socket, buf,IPv6Length,0);
      inet_ntop(AF_INET6,buf,dst_addr,sizeof dst_addr); 
    }
    else if(atyp == TypeDomain)
    {
      recv(client_socket, buf, 1, 0);
      add_len  = buf[0];
      recv(client_socket, dst_addr, add_len, 0);
      dst_addr[add_len] = '\0';
    }
    
    
    uint16_t dst_port;
    recv(client_socket, &dst_port, 2, 0);
    dst_port = ntohs(dst_port);
    
    // printf("atyp %d port %d\n", atyp, dst_port);

    if(ver != SOCKS5_VERSION)
    {
      printf("ver %d\n",ver);
      perror("protocol version not supported");
      return;
    }

    if(cmd != CmdBind && cmd != CmdConnect && cmd != CmdUDP)
    {
      printf("cmd %d\n",cmd);
      perror("request command not supported");
      unsigned char address_type_not_supported[] = { SOCKS5_VERSION, ReplyCommandNotSupported};
      send(client_socket, address_type_not_supported, sizeof(address_type_not_supported),0);
      return;
    }

    if (rsv != ReservedField) 
    {
      printf("rsv %d\n",rsv);
      perror("invaild reserved field");
      return;
    }

    if (atyp != TypeIPv4 && atyp != TypeIPv6 && atyp != TypeDomain)
    {
      printf("atyp %d\n",atyp);
      perror("address type not supported");
      // Send an address type not supported message
      unsigned char address_type_not_supported[] = { SOCKS5_VERSION, ReplyAddressTypeNotSupported};
      send(client_socket, address_type_not_supported, sizeof(address_type_not_supported),0);
      return;
    }

    
    char dst[48];
    sprintf(dst, "%hu", dst_port);
    // printf("dst_addr %s dst_port %s\n", dst_addr,dst);

    // Handle udp connect
    if(cmd == CmdUDP)
    {
      if(handle_udp(atyp, client_socket, dst_addr, dst_port) == -1)
      {
        perror("udp fail");
      }
      return;
    }

    // Forward the client's request to the destination server
    int domain_type[1];
    int server_socket = client(dst_addr,dst, domain_type);
    // printf("server %d\n", server_socket);
    if(server_socket == ECONNREFUSED)
    {
      unsigned char address_type_not_supported[] = { SOCKS5_VERSION, ReplyConnectionRefused};
      send(client_socket, address_type_not_supported, sizeof(address_type_not_supported),0);
      // close(client_socket);
      return;
    }
    else if(server_socket == 1)
    {
      unsigned char address_type_not_supported[] = { SOCKS5_VERSION, ReplyHostunreachable};
      send(client_socket, address_type_not_supported, sizeof(address_type_not_supported),0);
      // close(client_socket);
      return;
    }
    else if(server_socket == ENETUNREACH)
    {
      unsigned char address_type_not_supported[] = { SOCKS5_VERSION, ReplyNetworkUnreachable};
      send(client_socket, address_type_not_supported, sizeof(address_type_not_supported),0);
      // close(client_socket);
      return;
    }

    // Send a success reply
    char local_ip[INET6_ADDRSTRLEN];
    memset(local_ip, 0, sizeof local_ip);
    if(atyp == TypeDomain)atyp = domain_type[0];
    uint16_t local_port = get_local(server_socket, local_ip,atyp);
    // printf("Local IP: %s \n", local_ip);
    // printf("Local Port: %hu atyp %d\n", local_port, atyp);

    unsigned char success_reply[] = { SOCKS5_VERSION,ReplySuccess,ReservedField,atyp};
    send(client_socket,success_reply,sizeof success_reply,0);
    if(atyp ==TypeIPv4)send(client_socket,local_ip,IPv4Length,0);
    else if(atyp == TypeIPv6)send(client_socket,local_ip,IPv6Length,0);
    send(client_socket,&local_port,sizeof (local_port),0);

    // forward data
    Socks5Forward(client_socket, server_socket);


}

int accept_client()
{
  int sockfd, new_fd; // Monitor on sock_fd, new_fd is a new connection
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr; // Connector's address information
  socklen_t sin_size;
  struct sigaction sa;
  int yes=1;
  char s[INET6_ADDRSTRLEN];
  int rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; // use my ip

  if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) 
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  // Loop through all results and bind to the first available result
  for(p = servinfo; p != NULL; p = p->ai_next) 
  {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
    {
      perror("server: socket");
      continue;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) 
    {
      perror("setsockopt");
      exit(1);
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) 
    {
      close(sockfd);
      perror("server: bind");
      continue;
    }

    break;
  }

  if (p == NULL) 
  {
    fprintf(stderr, "server: failed to bind\n");
    return 2;
  }


  freeaddrinfo(servinfo); // All use this structure

  if (listen(sockfd, BACKLOG) == -1) 
  {
    perror("listen");
    exit(1);
  }

  sa.sa_handler = sigchld_handler; // Clean up all dead processes
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  if (sigaction(SIGCHLD, &sa, NULL) == -1) 
  {
    perror("sigaction");
    exit(1);
  }
  

  printf("server: waiting for connections...\n");

  while(1) // The main accept() loop
  {   
    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);

    if (new_fd == -1) {
      perror("accept");
      continue;
    }

    inet_ntop(their_addr.ss_family,
    get_in_addr((struct sockaddr *)&their_addr),
      s, sizeof s);
    int clientPort = ntohs(((struct sockaddr_in *)&their_addr)->sin_port);
    printf("server: got connection from %s %d fd %d\n", s, clientPort, new_fd);
 
    if (!fork()) // This is child process
    { 
      close(sockfd); // child does not require a listener

      handle_client(new_fd);
      close(new_fd);

      exit(0);
    }
    close(new_fd); // parent does not need this
  }

  return 0;
}

int main(void)
{
  // Start socks5 proxy sever
  accept_client();
}