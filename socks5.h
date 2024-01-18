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
#define PORT "8080" // 提供给用戶连接的 port
#define BACKLOG 100 // 有多少个特定的连接队列（pending connections queue）
#define BUFFER_SIZE 4096
#define SOCKS5_VERSION 0X05
#define Method_NoAuth 0X00
#define Method_NoAcceptable 0Xff
#define CmdConnect  0x01
#define	CmdBind 0x02
#define	CmdUDP 0x03
#define ReservedField  0x00
#define TypeIPv4 0x01
#define	TypeDomain 0x03
#define	TypeIPv6 0x04
#define IPv4Length 4
#define	IPv6Length 16
#define MAXDATASIZE 100 // max number of bytes we can get at once 

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

void *get_in_addr(struct sockaddr *sa);
int client(char *dst_add, char *dst_port, int *type);