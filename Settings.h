#ifndef METAFTPD_SETTINGS_H
#define METAFTPD_SETTINGS_H

#include "common.h"


typedef struct
{
int Flags;
int Port;
char *ConfigFile;
char *Chroot;
char *ConnectBanner;
char *ServerLogPath;
char *LogPath;
char *AuthFile;
char *DefaultUser;
gid_t DefaultGroupID;
int DataConnectionLowPort;
int DataConnectionHighPort;
char *AllowUsers;
char *DenyUsers;
char *BindAddress;
char *AuthMethods;
char *UserPrompt;
char *PermittedCommands;
char *UploadHook;
char *DownloadHook;
char *RenameHook;
char *DeleteHook;
char *LoginHook;
char *LogoutHook;
char *ConnectUpHook;
char *ConnectDownHook;
char *UpdatePasswordType;
ListNode *VirtualHosts;
int DefaultIdle;
int MaxIdle;
double MaxFileSize;
} TSettings;

extern TSettings Settings;

void ParseCommandLine(int argc, char *argv[]);
int ReadConfigFile(char *ConfigPath);


#endif

