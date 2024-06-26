#include "socks5.h"

void forward(int srcSocket, int destSocket) {
    char buffer[BUFFER_SIZE];
    ssize_t bytesRead;

    while ((bytesRead = read(srcSocket, buffer, sizeof(buffer))) > 0) {
        write(destSocket, buffer, bytesRead);
    }
}

void Socks5Forward(int clientSocket, int targetSocket) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process: forward from client to target
        forward(clientSocket, targetSocket);
        exit(EXIT_SUCCESS);
    } else {
        // Parent process: forward from target to client
        forward(targetSocket, clientSocket);
    }

    close(clientSocket);
    close(targetSocket);
}

uint16_t get_local(int sockfd, char *ip, int type) {
    
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    if (getsockname(sockfd, (struct sockaddr *)&addr, &addrlen) == -1) {
        perror("getsockname");
        return -1;
    }

    if(type == TypeIPv4)
    {
      if (inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&addr), ip, INET_ADDRSTRLEN) == NULL) 
      {
        perror("inet_ntop");
        return -1;
      }
    }
    else if(type == TypeIPv6)
    {
      if (inet_ntop(AF_INET6, get_in_addr((struct sockaddr *)&addr), ip, INET6_ADDRSTRLEN) == NULL) 
      {
        perror("inet_ntop");
        return -1;
      }
    }
    // printf("ip %s\n",ip);
    unsigned short port = ntohs(addr.sin_port);
    return port;
}

void sigchld_handler(int s)
{
  while(waitpid(-1, NULL, WNOHANG) > 0);
}

// Get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) 
  {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int client(char *dst_add, char *dst_port, int *type)
{
    int sockfd, numbytes;  
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

   

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(dst_add, dst_port, &hints, &servinfo)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) 
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
        {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) 
        {
            close(sockfd);    
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) 
    {
        fprintf(stderr, "client: failed to connect\n");
        return errno;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    if(p->ai_family == AF_INET)
    {
        *type = TypeIPv4;
    }
    else if(p->ai_family == AF_INET6)
    {
        *type = TypeIPv6;
    }
    printf("client: connecting to %s type %d\n", s, *type);
    

    freeaddrinfo(servinfo); // all done with this structure
    return sockfd;
}