#ifndef FTPSERVER_COMMON_H
#define FTPSERVER_COMMON_H

#include <limits.h>
#include <stdint.h>
#include <netinet/in.h>
#include <glob.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <wait.h>
#include <syslog.h>
#include "libUseful-2.3/libUseful.h"

#define LIST_SHORT 0
#define LIST_LONG 1
#define LIST_MLSD 2
#define LIST_STAT 3

#define MODE_FTP_SERVER 1
#define MODE_FTP_PROXY 2
#define MODE_INETD 4
#define FLAG_CHHOME 16
#define FLAG_CHROOT 32
#define FLAG_CHSHARE 64
#define FLAG_DEMON 128
#define FLAG_ALOCK 4096
#define FLAG_MLOCK 8192
#define FLAG_SYSLOG 16384
#define FLAG_LOGPASSWORDS 32768
#define FLAG_NOPASV 65536
#define FLAG_LOG_VERBOSE 131072

#define SESSION_FTP_SERVER 1
#define SESSION_FTP_PROXY 2
#define SESSION_AUTHENTICATED 4
#define SESSION_PAM 8
#define SESSION_ASCII_TRANSFERS 16
#define SESSION_COMPRESSED_TRANSFERS 32
#define SESSION_TAR_STRUCTURE 64

#define FILE_RECV 1
#define FILE_SEND 2

#define DC_OUTGOING 1
#define DC_INCOMING 2
#define DC_PROXY 4
#define DC_RETR 8
#define DC_STOR 16

#define ERR_OKAY 0
#define ERR_FILE 1
#define ERR_SIZE 2

#define CAPS_LEVEL_STARTUP  1
#define CAPS_LEVEL_NETBOUND 2
#define CAPS_LEVEL_SESSION  3


typedef struct
{
int Flags;
int ListenSock;
char *SourceAddress, *DestAddress;
int SourcePort, DestPort;
char *FileName;
double BytesSent;
STREAM *Sock, *Input, *Output;
THash *Hash;
}TDataConnection;

typedef struct
{
int Flags;
char *User;
char *Passwd;
char *RealUser;
char *HomeDir;
int RealUserUID;
int GroupID;
char *ClientHost;
char *ClientIP;
char *DestIP;
char *LocalIP;
char *UserSettings;
char *Challenge;
char *MLSFactsList;
STREAM *ClientSock;
STREAM *ProxySock;
STREAM *IPCCon;
char *DataConnectionIP;
TDataConnection *DataConnection, *ProxyDataConnection;
ListNode *Connections;
ListNode *Vars;
time_t LastActivity;
} TSession;

typedef struct
{
int Pid;
STREAM *S;
char *User;
time_t LogonTime;
} TSessionProcess;


typedef enum {CMD_NOOP,CMD_DENIED,CMD_USER, CMD_PASS,CMD_PORT,CMD_XCWD,CMD_CWD,CMD_XCUP,CMD_CDUP,CMD_TYPE,CMD_RETR,CMD_APPE,CMD_STOR,CMD_REST,CMD_LIST,CMD_NLST,CMD_MLST,CMD_MLSD,CMD_MDTM,CMD_XDEL,CMD_DELE,CMD_SYST,CMD_SITE,CMD_STAT,CMD_STRU,CMD_QUIT,CMD_XPWD,CMD_PWD,CMD_XMKD,CMD_MKD,CMD_XRMD,CMD_RMD, CMD_RMDA, CMD_RNFR,CMD_RNTO, CMD_OPTS, CMD_SIZE, CMD_DSIZ, CMD_PASV, CMD_EPSV, CMD_FEAT, CMD_MODE, CMD_ALLO, CMD_AVBL, CMD_REIN, CMD_CLNT, CMD_MD5, CMD_XMD5, CMD_XCRC, CMD_XSHA, CMD_XSHA1, CMD_XSHA256, CMD_XSHA512, CMD_HASH} TFtpCommands;


typedef enum {HASH_CRC, HASH_MD5, HASH_SHA1, HASH_SHA256, HASH_SHA512, HASH_WHIRL, HASH_WHIRL2, HASH_JH224, HASH_JH256, HASH_JH384, HASH_JH512, HASH_FTPCRC, HASH_FTPMD5} EHashNames;
extern const char *HashNames[];

extern char *CmdLine, *ProgName, *Version;

int DecodePORTStr(char *PortStr, char **Address, int *Port);
void ParseConfigItem(char *ConfigLine);
char *GetDefaultUser();
int FtpCopyBytes(TSession *Session,TDataConnection *DC);
char *GetCurrDirFullPath(char *RetStr);
void DropCapabilities(int Level);
int HashNameToID(const char *Name);


#endif
