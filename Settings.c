#include "Settings.h"

char *ArgStrings[]={"-proxy","-chhome","-chroot","-chshare","-port","-p","-4","-nodemon","-I","-inetd","-f","-a","-allowusers","-denyusers","-nopasv","-dclow","-dchigh","-logfile","-l","-syslog","-idle","-maxidle","-mlocks","-alocks","-malocks","-i","-bindaddress","-dcus","-dcds","-?","-help","--help","-version","--version",NULL};
typedef enum {ARG_PROXY,ARG_CHHOME,ARG_CHROOT,ARG_CHSHARE,ARG_PORT,ARG_PORT2,ARG_IPV4,ARG_NODEMON,ARG_INETD,ARG_INETD2,ARG_CONFIG_FILE, ARG_AUTH_FILE, ARG_ALLOWUSERS,ARG_DENYUSERS,ARG_NOPASV, ARG_DCLOW,ARG_DCHIGH,ARG_LOGFILE,ARG_LOGFILE2,ARG_SYSLOG,ARG_IDLE,ARG_MAXIDLE,ARG_MLOCKS,ARG_ALOCKS,ARG_MALOCKS,ARG_INTERFACE,ARG_BINDADDRESS,ARG_DCUPSCRIPT, ARG_DCDOWNSCRIPT,ARG_HELP1,ARG_HELP2,ARG_HELP3,ARG_VERSION,ARG_VERSION2};





void PrintUsage()
{
char *UseStrings[]={"Proxy Mode. Act as a transparent proxy, requires a kernel that supports obtaining the 'target' address. By-request proxying that's triggered by logins containing a hostname, or by use of the 'SITE proxy' command do not need this.","ChHome. Chroot into the home dir of the user after logon","ChRoot. ChRoot to directory on program start","Chroot to a shared directory with user subdirectories in it","Port to listen on (default 21)","Port to listen on (default 21)","Use IPv4 only","Don't background","Use out of inetd, not as standalone server","Use out of inetd, not as standalone server","path to config file","path to 'native' authentication file","List of users allowed to log on","List of users to deny logon to","Don't use passive mode","Minimum port for Data connections","Maximum port for Data connections","Logfile Path","Logfile Path","Use syslog for logging","'Soft' idle timeout (user can override)","'Hard' idle timeout","Mandatory Locks","Advisory Locks","Mandartory write, Advisory read Locks","Bind server to address/interface","Bind server to address/interface","Data Connnection Up Script","Data Connection DownScript","This help","This help","This help","Print version","Print Version",NULL};
int i;

fprintf(stdout,"\nMetaFTPd FTP Server: version %s\n",Version);
fprintf(stdout,"Author: Colum Paget\n");
fprintf(stdout,"Email: colums.projects@gmail.com\n");
fprintf(stdout,"Blog: http://idratherhack.blogspot.com \n");
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
fprintf(stdout,"	-t password type, one of plaintext/md5/sha1/sha256/sha512 (defaults to md5)\n");
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
fprintf(stdout,"		AuthMethods=<comma seperated list> List of authentication methods a subset of pam,passwd,shadow,native\n");
fprintf(stdout,"		LogFile=<path> LogFile Path (can include the variables '$(User)' and '$(ClientIP)'\n");
fprintf(stdout,"		Idle=<timeout> Idle timeout for control connections, user overridable soft limit\n");
fprintf(stdout,"		MaxIdle=<timeout> Idle timeout for control connections, hard limit\n");
fprintf(stdout,"		Locks=<timeout> Idle timeout for control connections\n");
fprintf(stdout,"		BindAddress=<ip address> Bind to specific network address/card.\n");
fprintf(stdout,"		PermittedCommands=<comma seperated list of ftp commands> Allowed FTP commands.\n");
fprintf(stdout,"		DefaultGroup=<Group name> Group to run server as.\n");

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
else printf("ERROR: -user must have 'add', 'del' or 'list' as it's next argument\n");

for (i=3; i < argc; i++)
{
	if (strcmp(argv[i],"-a")==0) Path=CopyStr(Path,argv[++i]);
	else if (strcmp(argv[i],"-t")==0) Type=CopyStr(Type,argv[++i]);
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

