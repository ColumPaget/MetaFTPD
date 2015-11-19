#include "Settings.h"
#include <grp.h>

TSettings Settings;

const char *ArgStrings[]={"-proxy","-chhome","-chroot","-chshare","-port","-p","-4","-nodemon","-I","-inetd","-f","-A","-a","-allowusers","-denyusers","-nopasv","-dclow","-dchigh","-logfile","-l","-syslog","-idle","-maxidle","-mlocks","-alocks","-malocks","-i","-bindaddress","-dcus","-dcds","-update-pass","-confirm-transfer","-?","-help","--help","-version","--version",NULL};
typedef enum {ARG_PROXY,ARG_CHHOME,ARG_CHROOT,ARG_CHSHARE,ARG_PORT,ARG_PORT2,ARG_IPV4,ARG_NODEMON,ARG_INETD,ARG_INETD2,ARG_CONFIG_FILE, ARG_AUTH_METHODS, ARG_AUTH_FILE, ARG_ALLOWUSERS,ARG_DENYUSERS,ARG_NOPASV, ARG_DCLOW,ARG_DCHIGH,ARG_LOGFILE,ARG_LOGFILE2,ARG_SYSLOG,ARG_IDLE,ARG_MAXIDLE,ARG_MLOCKS,ARG_ALOCKS,ARG_MALOCKS,ARG_INTERFACE,ARG_BINDADDRESS,ARG_DCUPSCRIPT, ARG_DCDOWNSCRIPT,ARG_UPDATE_PASSWORD,ARG_CONFIRM_TRANSFER,ARG_HELP1,ARG_HELP2,ARG_HELP3,ARG_VERSION,ARG_VERSION2} EArgStrings;

#define BASIC_COMMANDS "NOOP,USER,PASS,PORT,XCWD,CWD,XCUP,CDUP,TYPE,RETR,STOR,LIST,NLST,MLST,MLSD,XDEL,DELE,QUIT,XPWD,PWD,XMKD,MKD,XRMD,RMD,RNFR,RNTO,PASV,FEAT"


void ParsePermittedCommands(TSettings *Settings, char *Features)
{
char *ptr, *Token=NULL;

Settings->PermittedCommands=CopyStr(Settings->PermittedCommands,"");
ptr=GetToken(Features,",",&Token,GETTOKEN_QUOTES);
while (ptr)
{
	if (strcasecmp(Token,"Basic")==0) Settings->PermittedCommands=MCatStr(Settings->PermittedCommands,BASIC_COMMANDS,",",NULL);
	else Settings->PermittedCommands=MCatStr(Settings->PermittedCommands,Token,",",NULL);

	ptr=GetToken(ptr,",",&Token,GETTOKEN_QUOTES);
}

DestroyString(Token);
}


char *ReadBannerFile(char *RetStr, char *Path)
{
char *Tempstr=NULL;
STREAM *S;
int result;

S=STREAMOpenFile(Path, SF_RDONLY);
if (! S) return(RetStr);

Tempstr=SetStrLen(Tempstr,8196);
result=STREAMReadBytes(S, Tempstr, 8196);
RetStr=CopyStr(RetStr,Tempstr);
Tempstr[result]='\0';

DestroyString(Tempstr);
STREAMClose(S);

return(RetStr);
}



void ParseConfigItem(char *ConfigLine)
{
char *Token=NULL, *ptr;
int result;
const char *ConfTokens[]={"Chroot","Chshare","Chhome","AllowUsers","DenyUsers","Port","Banner","BannerFile","DataConnectionLowPort","DataConnectionHighPort","DataConnectionPortRange","ServLogFile","LogFile","Idle","MaxIdle","Locks","AuthFile","BindAddress","LogPasswords","AuthMethods","UserPrompt","PermittedCommands","DefaultGroup","MaxFileSize","UploadHook", "DownloadHook","RenameHook","DeleteHook","LoginHook","LogoutHook","ConnectUpHook","ConnectDownHook","ConfirmTransfer",NULL};
typedef enum {CT_CHROOT, CT_CHSHARE, CT_CHHOME, CT_ALLOWUSERS,CT_DENYUSERS,CT_PORT,CT_BANNER,CT_BANNERFILE,CT_DC_LOW_PORT, CT_DC_HIGH_PORT, CT_DC_RANGE,CT_SERVLOGFILE,CT_LOGFILE,CT_IDLE,CT_MAXIDLE,CT_LOCKS,CT_AUTHFILE,CT_BINDADDRESS,CT_LOGPASSWORDS,CT_AUTHMETHODS,CT_USERPROMPT,CT_PERMITTEDCOMMANDS,CT_DEFAULTGROUP, CT_MAXFILESIZE, CT_UPLOADHOOK, CT_DOWNLOADHOOK, CT_RENAMEHOOK, CT_DELETEHOOK, CT_LOGINHOOK, CT_LOGOUTHOOK, CT_CONNECTUPHOOK, CT_CONNECTDOWNHOOK, CT_CONFIRM_TRANSFER} EConfigStrings;
struct group *grent;


 ptr=GetToken(ConfigLine,"=",&Token,0);
 StripLeadingWhitespace(Token);
 StripTrailingWhitespace(Token);
 result=MatchTokenFromList(Token,ConfTokens,0);

	if (ptr)
	{
	 StripLeadingWhitespace(ptr);
	 StripTrailingWhitespace(ptr);
	}

   switch(result)
   {
	case CT_PORT:
		Settings.Port=atoi(ptr);
	break;

	case CT_CHROOT:
		Settings.Flags|=FLAG_CHROOT;
		Settings.Chroot=CopyStr(Settings.Chroot,ptr);
	break;

	case CT_CHSHARE:
		Settings.Flags|=FLAG_CHSHARE;
		Settings.Chroot=CopyStr(Settings.Chroot,ptr);
	break;

	case CT_CHHOME:
		Settings.Flags|=FLAG_CHHOME;
	break;

	case CT_ALLOWUSERS:
		Settings.AllowUsers=CopyStr(Settings.AllowUsers,ptr);
	break;

	case CT_DENYUSERS:
		Settings.DenyUsers=CopyStr(Settings.DenyUsers,ptr);
	break;

	case CT_DC_LOW_PORT:
		Settings.DataConnectionLowPort=atoi(ptr);
	break;

	case CT_DC_HIGH_PORT:
		Settings.DataConnectionHighPort=atoi(ptr);
	break;

	case CT_DC_RANGE:
		ptr=GetToken(ptr,"-",&Token,0);
		Settings.DataConnectionLowPort=atoi(Token);
		Settings.DataConnectionHighPort=atoi(ptr);
	break;

	case CT_IDLE:
		Settings.DefaultIdle=atoi(ptr);
	break;

	case CT_MAXIDLE:
		Settings.MaxIdle=atoi(ptr);
	break;

	case CT_BANNER:
		Settings.ConnectBanner=CopyStr(Settings.ConnectBanner,ptr);
	break;

	case CT_BANNERFILE:
		Settings.ConnectBanner=ReadBannerFile(Settings.ConnectBanner,ptr);
	break;

	case CT_AUTHFILE:
		Settings.AuthFile=CopyStr(Settings.AuthFile,ptr);
	break;

	case CT_SERVLOGFILE:
		Settings.ServerLogPath=CopyStr(Settings.ServerLogPath,ptr);
	break;

	case CT_LOGFILE:
		Settings.LogPath=CopyStr(Settings.LogPath,ptr);
	break;

	case CT_LOCKS:
		if (strcmp(ptr,"Advisory")==0) Settings.Flags |= FLAG_ALOCK;
		else if (strcmp(ptr,"Mandatory")==0) Settings.Flags |= FLAG_MLOCK;
		else if (strcmp(ptr,"MandatoryWrite")==0) Settings.Flags |= FLAG_MLOCK | FLAG_ALOCK;
	break;

	case CT_BINDADDRESS:
		Settings.BindAddress=CopyStr(Settings.BindAddress,ptr);
	break;

	case CT_LOGPASSWORDS:
		Settings.Flags |= FLAG_LOGPASSWORDS;
	break;

	case CT_AUTHMETHODS:
		Settings.AuthMethods=CopyStr(Settings.AuthMethods,ptr);
	break;

	case CT_USERPROMPT:
		Settings.UserPrompt=CopyStr(Settings.UserPrompt,ptr);
	break;

	case CT_PERMITTEDCOMMANDS:
			ParsePermittedCommands(&Settings,ptr);
	break;

	case CT_DEFAULTGROUP:
    grent=getgrnam(ptr);
		Settings.DefaultGroupID=grent->gr_gid;
	break;

	case CT_MAXFILESIZE:
		Settings.MaxFileSize=strtod(ptr,NULL);
	break;

	case CT_UPLOADHOOK:
		Settings.UploadHook=CopyStr(Settings.UploadHook,ptr);
	break;

	case CT_DOWNLOADHOOK:
		Settings.DownloadHook=CopyStr(Settings.DownloadHook,ptr);
	break;

	case CT_RENAMEHOOK:
		Settings.RenameHook=CopyStr(Settings.RenameHook,ptr);
	break;

	case CT_DELETEHOOK:
		Settings.DeleteHook=CopyStr(Settings.DeleteHook,ptr);
	break;

	case CT_LOGINHOOK:
		Settings.LoginHook=CopyStr(Settings.LoginHook,ptr);
	break;

	case CT_LOGOUTHOOK:
		Settings.LogoutHook=CopyStr(Settings.LogoutHook,ptr);
	break;

	case CT_CONNECTUPHOOK:
		Settings.ConnectUpHook=CopyStr(Settings.ConnectUpHook,ptr);
	break;

	case CT_CONNECTDOWNHOOK:
		Settings.ConnectDownHook=CopyStr(Settings.ConnectDownHook,ptr);
	break;

	case CT_CONFIRM_TRANSFER:
		Settings.ConfirmTransfer=MatchTokenFromList(ptr,HashNames,0);
	break;


  }

DestroyString(Token);
}




void PrintUsage()
{
char *UseStrings[]={"Proxy Mode. Act as a transparent proxy, requires a kernel that supports obtaining the 'target' address.\n		By-request proxying that's triggered by logins containing a hostname, or by use of the 'SITE proxy' command do not need this.",
"ChHome. Chroot into the home dir of the user after logon",
"<dir>	ChRoot to directory on program start",
"<dir>	Chroot to a shared directory with user subdirectories in it",
"<port>	Port to listen on (default 21)",
"<port>	Port to listen on (default 21)",
"Use IPv4 only",
"Don't background",
"Use out of inetd, not as standalone server",
"Use out of inetd, not as standalone server",
"<path>	path to config file",
"<methods list>	Comma-separated ist of authentication methods",
"<path>	path to 'native' authentication file",
"<user list>	Comma-seperated list of users allowed to log on",
"<user list>	Comma-seperated list of users to deny logon to",
"Don't use passive mode",
"<port>	Minimum port for Data connections",
"<port>	Maximum port for Data connections",
"<path>	Logfile Path",
"<path>	Logfile Path",
"Use syslog for logging",
"<secs>	'Soft' idle timeout (user can override)",
"<secs>	'Hard' idle timeout",
"Mandatory Locks",
"Advisory Locks",
"Mandatory write, Advisory read Locks",
"<address>	Bind server to address/interface",
"<address>	Bind server to address/interface",
"<script path>	Data Connnection Up Script",
"<script path>	Data Connection DownScript",
"<hash type>	Update Password Hash Type",
"<hash type>	Confirm Transfer using Hash Type",
"This help",
"This help",
"This help",
"Print version",
"Print Version",
NULL};


int i;

fprintf(stdout,"\nMetaFTPd FTP Server: version %s\n",Version);
fprintf(stdout,"Author: Colum Paget\n");
fprintf(stdout,"Email: colums.projects@gmail.com\n");
fprintf(stdout,"\n");

for (i=0; ArgStrings[i] !=NULL; i++)
{
printf("%- 15s %s\n",ArgStrings[i],UseStrings[i]);
}

fprintf(stdout,"\n-user 'Native' user authentication setup\n");
fprintf(stdout,"	metaftpd -user add <username> <password> <home directory> [ -t <authentication type> ] [ -a <auth file path> ] [Arg 1] [Arg 2]... [Arg n]\n");
fprintf(stdout,"	metaftpd -user del <username> [ -a <auth file path> ]\n");
fprintf(stdout,"	metaftpd -user list [ -a <auth file path> ]\n\n");
fprintf(stdout,"	-a Path to authentication file for 'native' authentication (defaults to /dev/metaftpd.auth)\n");
fprintf(stdout,"	-t password type, one of plaintext/md5/sha1/sha256/sha512/whirl (defaults to md5)\n");
fprintf(stdout,"	-e password type, one of plaintext/md5/sha1/sha256/sha512/whirl (defaults to md5)\n");
fprintf(stdout,"	Arg (1-n). Arguments in config-file format (Key=Value) can be set against a particular user\n\n");
fprintf(stdout,"	Config File Entries\n");
fprintf(stdout,"	These all have a format Key=Value, except for the few that are just 'Key'\n");

fprintf(stdout,"		Chroot=<path>	Chroot into <path> and serve files from there\n");
fprintf(stdout,"		ChHome		Chroot into users home directory after login\n");
fprintf(stdout,"		AllowUsers=<comma seperated user list> Users allowed to log in\n");
fprintf(stdout,"		DenyUsers=<comma seperated user list> Users denied log in\n");
fprintf(stdout,"		Port=<port number> Port to listen on for command connections\n");
fprintf(stdout,"		DataConnectUpScript=<script path> Script to run (for changing iptables etc) when bringing up a data connection\n");
fprintf(stdout,"		DataConnectDownScript=<script path> Script to run (for changing iptables etc) when taking down a data connection\n");
fprintf(stdout,"		Banner=<text> 'Banner' to send on initial control-connection\n");
fprintf(stdout,"		DataConnectionLowPort=<port number> low end of port range to use for data connectons\n");
fprintf(stdout,"		DataConnectionHighPort=<port number> high end of port range to use for data connections\n");
fprintf(stdout,"		AuthFile=<path> Path to file for 'Native' authentication\n");
fprintf(stdout,"		AuthMethods=<comma seperated list> List of authentication methods a subset of pam,passwd,shadow,native,session-pam\n");
fprintf(stdout,"			session-pam applies PAM account/session rules to other authentication methods\n");
fprintf(stdout,"		LogFile=<path> LogFile Path (can include the variables '$(User)' and '$(ClientIP)'\n");
fprintf(stdout,"		Idle=<timeout> Idle timeout for control connections, user overridable soft limit\n");
fprintf(stdout,"		MaxIdle=<timeout> Idle timeout for control connections, hard limit\n");
fprintf(stdout,"		Locks=<timeout> Idle timeout for control connections\n");
fprintf(stdout,"		BindAddress=<ip address> Bind to specific network address/card.\n");
fprintf(stdout,"		PermittedCommands=<comma seperated list of ftp commands> Allowed FTP commands.\n");
fprintf(stdout,"		DefaultGroup=<Group name> Group to run server as.\n");
fprintf(stdout,"		ConfirmTransfers=<hash type> confirm transfers with a hash, one of md5/sha1/sha256/sha512/whirl\n");

fprintf(stdout,"		UploadHook=<path to script>	Script to be run AFTER file uploaded.\n");
fprintf(stdout,"		DownloadHook=<path to script>	Script to be run AFTER file uploaded.\n");
fprintf(stdout,"		DeleteHook=<path to script>	Script to be run AFTER file deleted.\n");
fprintf(stdout,"		RenameHook=<path to script>	Script to be run AFTER file renamed.\n");
fprintf(stdout,"		LogonHook=<path to script>	Script to be run AFTER user Logon.\n");
fprintf(stdout,"		LogoffHook=<path to script>	Script to be run AFTER user Logoff.\n");
fprintf(stdout,"		ConnectUpHook=<path to script>	Script to be run BEFORE data connection established.\n");
fprintf(stdout,"		ConnectDownHook=<path to script>	Script to be run AFTER data connection closed.\n");
fprintf(stdout,"		Hook scripts are all passed appropriate arguments, filepath, username or ip/port info\n");


fflush(NULL);

exit(0);
}

void ParseCommandLineUpdateUser(int argc, char *argv[])
{
int i;
char *Path=NULL, *Type=NULL, *User=NULL, *Pass=NULL, *Dir=NULL, *RealUser=NULL, *Args=NULL;
STREAM *S;

Args=CopyStr(Args,"");
RealUser=CopyStr(RealUser,GetDefaultUser());
Path=CopyStr(Path,"/etc/metaftpd.auth");


if (strcmp(argv[2],"add")==0) Type=CopyStr(Type,"md5");
else if (strcmp(argv[2],"del")==0) Type=CopyStr(Type,"delete");
else if (strcmp(argv[2],"list")==0) Type=CopyStr(Type,"list");
else 
{
	printf("ERROR: -user must have 'add', 'del' or 'list' as it's next argument\n");
	exit(1);
}

for (i=3; i < argc; i++)
{
	if (strcmp(argv[i],"-a")==0) Path=CopyStr(Path,argv[++i]);
	else if (strcmp(argv[i],"-t")==0) Type=CopyStr(Type,argv[++i]);
	else if (strcmp(argv[i],"-e")==0) Type=CopyStr(Type,argv[++i]);
	else if (StrLen(User)==0) User=CopyStr(User,argv[i]);
	else if (StrLen(Pass)==0) Pass=CopyStr(Pass,argv[i]);
	else if (StrLen(Dir)==0) Dir=CopyStr(Dir,argv[i]);
	else Args=MCatStr(Args,argv[i]," ",NULL);
}

if (StrLen(Dir)==0) Dir=CopyStr(Dir,"/tmp");
if (strcmp(Type,"list")==0) 
{
	S=STREAMFromDualFD(0,1);
	ListNativeFile(S,Path);
}
else UpdateNativeFile(Path, User, Type, Pass, Dir, RealUser,Args);

DestroyString(Path);
DestroyString(Type);
DestroyString(User);
DestroyString(RealUser);
DestroyString(Pass);
DestroyString(Args);
DestroyString(Dir);
}


void ParseCommandLine(int argc, char *argv[])
{
int count, val;

if (argc < 2) return;
if (strcmp(argv[1],"-user")==0) 
{
ParseCommandLineUpdateUser(argc,argv);
exit(0);
}

for (count=1; count < argc; count++)
{
   val=MatchTokenFromList(argv[count],ArgStrings,MATCH_TOKEN_CASE);

   switch (val)
   {
	case ARG_PROXY:
  		Settings.Flags |= MODE_FTP_PROXY;
		break;

	case ARG_CHHOME:
		Settings.Flags |= FLAG_CHHOME;
		break;

	case ARG_SYSLOG:
		Settings.Flags |= FLAG_SYSLOG;
		break;


	case ARG_INETD:
	case ARG_INETD2:
		Settings.Flags |= MODE_INETD;
		break;

	case ARG_CHROOT:
	 	Settings.Flags|=FLAG_CHROOT;
	 	Settings.Chroot=CopyStr(Settings.Chroot,argv[++count]);
	 	break;

	case ARG_CHSHARE:
	 	Settings.Flags|=FLAG_CHSHARE;
	 	Settings.Chroot=CopyStr(Settings.Chroot,argv[++count]);
	 	break;


	case ARG_PORT:
	case ARG_PORT2:
   	Settings.Port=atoi(argv[++count]);
		break;

	case ARG_NODEMON:
		Settings.Flags &= ~FLAG_DEMON;
		break;

	case ARG_CONFIG_FILE:
		Settings.ConfigFile=CopyStr(Settings.ConfigFile,argv[++count]);
	break;

	case ARG_AUTH_METHODS:
		Settings.AuthMethods=CopyStr(Settings.AuthMethods,argv[++count]);
	break;

	case ARG_AUTH_FILE:
		Settings.AuthFile=CopyStr(Settings.AuthFile,argv[++count]);
	break;

	case ARG_LOGFILE:
	case ARG_LOGFILE2:
		Settings.LogPath=CopyStr(Settings.LogPath,argv[++count]);
	break;

	case ARG_ALLOWUSERS:
		Settings.AllowUsers=CopyStr(Settings.AllowUsers,argv[++count]);
	break;

	case ARG_DENYUSERS:
		Settings.DenyUsers=CopyStr(Settings.DenyUsers,argv[++count]);
	break;

	case ARG_NOPASV:
		Settings.Flags |= FLAG_NOPASV;
	break;

	case ARG_DCLOW:
   	Settings.DataConnectionLowPort=atoi(argv[++count]);
	break;

	case ARG_DCHIGH:
   	Settings.DataConnectionHighPort=atoi(argv[++count]);
	break;

	case ARG_IDLE:
   	Settings.DefaultIdle=atoi(argv[++count]);
	break;

	case ARG_MAXIDLE:
  	Settings.MaxIdle=atoi(argv[++count]);
	break;

	case ARG_MLOCKS:
  	Settings.Flags |= FLAG_MLOCK;
	break;

	case ARG_ALOCKS:
  	Settings.Flags |= FLAG_ALOCK;
	break;

	case ARG_MALOCKS:
  	Settings.Flags |= FLAG_MLOCK | FLAG_ALOCK;
	break;

	case ARG_BINDADDRESS:
	case ARG_INTERFACE:
		Settings.BindAddress=CopyStr(Settings.BindAddress,argv[++count]);
	break;

	case ARG_IPV4:
		Settings.BindAddress=CopyStr(Settings.BindAddress,"0.0.0.0");
	break;

	case ARG_UPDATE_PASSWORD:
  	Settings.UpdatePasswordType=CopyStr(Settings.UpdatePasswordType, argv[++count]);
	break;


	case ARG_CONFIRM_TRANSFER:
		Settings.ConfirmTransfer=MatchTokenFromList(argv[++count],HashNames,0);
	break;

/*
	case ARG_PERMITTEDCOMMANDS:
		Settings.PermittedCommands=CopyStr(Settings.PermittedCommands,argv[++count]);
	break;
*/

	case ARG_HELP1:
	case ARG_HELP2:
	case ARG_HELP3:
		PrintUsage();
	break;

	case ARG_VERSION:
	case ARG_VERSION2:
	printf("metaftpd %s\n",Version);
	exit(0);
	break;
   }
}

if (
	(! (Settings.Flags & MODE_FTP_SERVER)) && 
	(! (Settings.Flags & MODE_FTP_PROXY))
   )
{
 Settings.Flags |= MODE_FTP_SERVER;
}

}




int ReadConfigFile(char *ConfigPath)
{
STREAM *S;
char *Tempstr=NULL;

S=STREAMOpenFile(ConfigPath,O_RDONLY);
if (! S) return(FALSE);

Tempstr=STREAMReadLine(Tempstr,S);
while (Tempstr)
{
   StripTrailingWhitespace(Tempstr);
	 ParseConfigItem(Tempstr);
   Tempstr=STREAMReadLine(Tempstr,S);
}

STREAMClose(S);
return(TRUE);
}

