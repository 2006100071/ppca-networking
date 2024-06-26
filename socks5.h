#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include<stdbool.h>

#define PORT "8080" // 提供给用戶连接的 port
#define PROXY_PORT "1080" // 提供给用戶连接的 proxy_port
#define BACKLOG 100 // 有多少个特定的连接队列（pending connections queue）
#define BUFFER_SIZE 4096
#define SOCKS5_VERSION 0X05
#define Method_NoAuth 0X00
#define Method_NoAcceptable 0Xff
#define CmdConnect  0x01
#define	CmdBind 0x02
#define	CmdUDP 0x03
#define ReservedField  0x00
#define Fragment 0x00
#define TypeIPv4 0x01
#define	TypeDomain 0x03
#define	TypeIPv6 0x04
#define IPv4Length 4
#define	IPv6Length 16
#define MAXDATASIZE 100 // max number of bytes we can get at once 
#define MAX_KEYWORDS 100
#define MAX_CIDRS 100

enum{
    ReplySuccess,
	ReplySeverFailure,
	ReplyConnectionNotAllowed,
	ReplyNetworkUnreachable,
    ReplyHostunreachable,
	ReplyConnectionRefused,
	ReplyTTLExpired,
	ReplyCommandNotSupported,
	ReplyAddressTypeNotSupported,
};

struct Rules {
    bool addrON;
    bool progON;
    bool httpON;
    char* keywords[MAX_KEYWORDS];
    char* http[MAX_KEYWORDS];
    char* program[MAX_KEYWORDS];
    struct in6_addr cidrs6[MAX_CIDRS];
    struct in_addr cidrs4[MAX_CIDRS];
};



void *get_in_addr(struct sockaddr *sa);
int client(char *dst_add, char *dst_port, int *type);
void sigchld_handler(int s);
void forward(int srcSocket, int destSocket);
void Socks5Forward(int clientSocket, int targetSocket);
void parseRules(struct Rules* rules, const char* fileName);
bool matchCIDR(const struct Rules* rules, const char* ipAddress);
bool matchKeyword(const struct Rules* rules, const char* text);
uint16_t get_local(int sockfd, char *ip, int type);
bool matchHttp(const struct Rules* rules, int client_socket, char* buf);
void parseHttpRules(struct Rules* rules, const char* fileName);
void parseProgramRules(struct Rules* rules, const char* fileName);
bool matchCmd(int port,struct Rules* rules);
int handle_udp(int atyp, int client_socket, char *dest_addr, uint16_t dest_port);
int udp_dest(uint16_t dst_port, char * dst_addr, char * dat, char *ret, int *len);