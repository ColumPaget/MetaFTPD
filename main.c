#include "common.h"
#include "Authenticate.h"
#include <sys/param.h>


TSettings Settings;
unsigned int RetrieveStartPos;
time_t Now;

//Used to Pass Values to a session
typedef struct
{
int client_infd;
int client_outfd;
} TSessionArg;


//CmdLine is a pointer, not a libUseful String
char *CmdLine, *ProgName=NULL, *Version="1.0.1";
ListNode *Sessions;



char *ArgStrings[]={"-proxy","-chhome","-chroot","-chshare","-port","-p","-nodemon","-i","-inetd","-f","-a","-allowusers","-denyusers","-nopasv","-dclow","-dchigh","-logfile","-l","-syslog","-idle","-maxidle","-mlocks","-alocks","-malocks","-bindaddress","-dcus","-dcds","-?","-help","--help","-version","--version",NULL};
typedef enum {ARG_PROXY,ARG_CHHOME,ARG_CHROOT,ARG_CHSHARE,ARG_PORT,ARG_PORT2,ARG_NODEMON,ARG_INETD,ARG_INETD2,ARG_CONFIG_FILE, ARG_AUTH_FILE, ARG_ALLOWUSERS,ARG_DENYUSERS,ARG_NOPASV, ARG_DCLOW,ARG_DCHIGH,ARG_LOGFILE,ARG_LOGFILE2,ARG_SYSLOG,ARG_IDLE,ARG_MAXIDLE,ARG_MLOCKS,ARG_ALOCKS,ARG_MALOCKS,ARG_BINDADDRESS,ARG_DCUPSCRIPT, ARG_DCDOWNSCRIPT,ARG_HELP1,ARG_HELP2,ARG_HELP3,ARG_VERSION,ARG_VERSION2};


void SetTimezoneEnv()
{
if (StrLen(tzname[1]))
{
	 setenv("TZ",tzname[1],TRUE);
}
else
{
	 setenv("TZ",tzname[0],TRUE);
}
}




void PrintUsage()
{
char *UseStrings[]={"Proxy Mode. Act as a transparent proxy, requires a kernel that supports obtaining the 'target' address. By-request proxying that's triggered by logins containing a hostname, or by use of the 'SITE proxy' command do not need this.","ChHome. Chroot into the home dir of the user after logon","ChRoot. ChRoot to directory on program start","Chroot to a shared directory with user subdirectories in it","Port to listen on (default 21)","Port to listen on (default 21)","Don't background","Use out of inetd, not as standalone server","Use out of inetd, not as standalone server","path to config file","path to 'native' authentication file","List of users allowed to log on","List of users to deny logon to","Don't use passive mode","Minimum port for Data connections","Maximum port for Data connections","Logfile Path","Logfile Path","Use syslog for logging","'Soft' idle timeout (user can override)","'Hard' idle timeout","Mandatory Locks","Advisory Locks","Mandartory write, Advisory read Locks","Bind server to address","Data Connnection Up Script","Data Connection DownScript","This help","This help","This help","Print version","Print Version",NULL};
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
   val=MatchTokenFromList(argv[count],ArgStrings,0);
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
			Settings.BindAddress=CopyStr(Settings.BindAddress,argv[++count]);
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


TDataConnection *DataConnectionCreate()
{
TDataConnection *Con;

Con=(TDataConnection *) calloc(1,sizeof(TDataConnection));
Con->ListenSock=-1;

return(Con);
}

int SessionReadFTPCommand(TSession *Session)
{
char *Tempstr=NULL, *Command=NULL, *Arg=NULL, *ptr;
int result=FALSE;

	Tempstr=STREAMReadLine(Tempstr,Session->ClientSock);
	if (Tempstr)
	{
		result=TRUE;
		time(&Now);

		StripTrailingWhitespace(Tempstr);

		if (StrLen(Tempstr))
		{
			ptr=GetToken(Tempstr," ",&Command,0);
			Arg=CopyStr(Arg,ptr);
			StripTrailingWhitespace(Arg);
			StripLeadingWhitespace(Arg);

			if (Session->Flags & SESSION_FTP_PROXY) DoProxyCommand(Session, Command, Arg);
			else DoCommand(Session, Command, Arg);

			time(&Session->LastActivity);
		}
	}
	DestroyString(Tempstr);
	DestroyString(Command);
	DestroyString(Arg);

return(result);
}

void SessionCheckIdleTimeout(TSession *Session)
{
int val;

//check idle timeout

time(&Now);
val=Now-Session->LastActivity;
if (
		(Settings.DefaultIdle > 0) ||
		(Settings.MaxIdle > 0)
		)
		{
			if ((Settings.DefaultIdle > 0) && (val > Settings.DefaultIdle)) 
			{
				LogToFile(Settings.ServerLogPath,"Closing session on default idle timeout");
				_exit(1);
			}
			if ((Settings.MaxIdle > 0) && (val > Settings.MaxIdle))
			{
				LogToFile(Settings.ServerLogPath,"Closing session on max idle timeout");
				 _exit(1); 
			}
		}
}	



void EndTransfer(TSession *Session, TDataConnection *DC, char *Status, char *Error)
{
char *Tempstr=NULL, *HookArgs=NULL;

		//CloseDataConnection will free 'DC->FileName', but we should really
		//run any hook script and send message after connection is closed.
		//So format message now, but send after 'CloseDataConnection'

		Tempstr=GetCurrDirFullPath(Tempstr);
		if (DC->Flags & DC_STOR) HookArgs=MCopyStr(HookArgs,"Upload"," '",Tempstr,DC->FileName,"'",NULL);
    else HookArgs=MCopyStr(HookArgs,"Download"," '",Tempstr,DC->FileName,"'",NULL);

		Tempstr=MCopyStr(Tempstr,Status," '",DC->FileName,"' ",Error,NULL);
		CloseDataConnection(Session, DC);
		SendLoggedLine(Tempstr,Session->ClientSock);
		LogToFile(Settings.LogPath,"EndTransfer: %s",HookArgs);
    Tempstr=IPCRequest(Tempstr, Session, "RunHook", HookArgs);

DestroyString(Tempstr);
DestroyString(HookArgs);
}


void SessionProcessingLoop(TSession *Session)
{
fd_set selectset;
int highfd, result;
ListNode *Curr, *Next;
TDataConnection *DC;
char *Tempstr=NULL, *Buffer=NULL;
struct timeval tv;


while (1)
{
FD_ZERO(&selectset);
FD_SET(Session->ClientSock->in_fd, &selectset);
highfd=Session->ClientSock->in_fd;


Curr=ListGetNext(Session->FileTransfers);
while (Curr)
{
DC=(TDataConnection *) Curr->Item;
FD_SET(DC->Input->in_fd, &selectset);
highfd=DC->Input->in_fd;

Curr=ListGetNext(Curr);
}


//must do this every time, as values are changed by select
tv.tv_sec=10;
tv.tv_usec=0;
result=select(highfd+1,&selectset,NULL,NULL,&tv);
if (result > 0)
{
	if (FD_ISSET(Session->ClientSock->in_fd,&selectset)) 
	{
		if (! SessionReadFTPCommand(Session)) break;
	}


	Buffer=SetStrLen(Buffer,BUFSIZ);
	Curr=ListGetNext(Session->FileTransfers);
	while (Curr)
	{
		Next=ListGetNext(Curr);
		DC=(TDataConnection *) Curr->Item;

		while (STREAMCheckForBytes(DC->Input))
		{
			result=STREAMReadBytes(DC->Input,Buffer,BUFSIZ);
			if (result > 0) 
			{
				result=FtpWriteBytes(Session,DC,Buffer,result);
				if (result==ERR_SIZE)
				{
				EndTransfer(Session, DC, "552 ERR", "Max file size exceeded.");
				ListDeleteNode(Curr);
				break; //must break, can't go round the loop again!
				}
			}
			else //Successful transfer
			{
				Tempstr=FormatStr(Tempstr,"%s bytes Transferred",GetHumanReadableDataQty(DC->BytesSent,0));
				EndTransfer(Session, DC, "226 OK", Tempstr);
				ListDeleteNode(Curr);
				break; //must break, can't go round the loop again!
			}
		}
		Curr=Next;
	}
}


SessionCheckIdleTimeout(Session);
}

DestroyString(Tempstr);
DestroyString(Buffer);
}


void HandleSession(TSessionArg *SA)
{
TSession *Session;
char *Tempstr=NULL, *ptr;
int val;

SetTimezoneEnv();
sprintf(CmdLine,"%s %s",ProgName,"New Session");

Session=(TSession *) calloc(1,sizeof(TSession));
Session->RealUserUID=-1;
Session->GroupID=-1;
time(&Session->LastActivity);
Session->Vars=ListCreate();
Session->FileTransfers=ListCreate();
SetVar(Session->Vars,"User","unknown");
SetVar(Session->Vars,"RealUser","root");


//MODE_FTP_X and SESSION_FTP_X are setup to have the same values, so this is
//not as alarming as it looks
Session->Flags=Settings.Flags & (MODE_FTP_SERVER | MODE_FTP_PROXY);
GetSockDetails(SA->client_infd,&Session->LocalIP,&val,&Session->ClientIP,&val);
SetVar(Session->Vars,"ClientIP",Session->ClientIP);


val=LOGFILE_LOGPID | LOGFILE_LOGUSER;
if (Settings.Flags & FLAG_SYSLOG) 
{
	val |=LOGFILE_SYSLOG;
	openlog("ftpd",LOG_PID,LOG_DAEMON);
}
LogFileSetValues(Settings.ServerLogPath, val, 100000000, 0);
LogToFile(Settings.ServerLogPath,"New Connection from %s",Session->ClientIP);


Session->DataConnection=DataConnectionCreate();


Session->ClientSock=STREAMFromDualFD(SA->client_infd, SA->client_outfd);
STREAMSetFlushType(Session->ClientSock,FLUSH_LINE,0);

if (! (Settings.Flags & MODE_INETD)) 
{
	Session->IPCCon=STREAMFromDualFD(0,1);
	STREAMSetFlushType(Session->IPCCon,FLUSH_LINE,0);
}

GetIntendedDestination(SA->client_infd, Session);

if (StrLen(Session->DestIP))
{
	if (strcmp(Session->DestIP,Session->LocalIP)==0) Session->DestIP=CopyStr(Session->DestIP,"");
	LogToFile(Settings.ServerLogPath,"Connection from %s to %s\n",Session->ClientIP,Session->DestIP);

	if (Session->Flags & SESSION_FTP_PROXY)
	{
   		if (! ProxyControlConnect(Session, Session->DestIP,21)) exit(0);
	}
}
else 
{
	if (StrLen(Settings.ConnectBanner)) Tempstr=FormatStr(Tempstr,"220 OK %s\r\n",Settings.ConnectBanner);
	else Tempstr=CopyStr(Tempstr,"220 OK\r\n");
	STREAMWriteLine(Tempstr,Session->ClientSock);
	STREAMFlush(Session->ClientSock);
}

STREAMSetTimeout(Session->ClientSock,10);

SessionProcessingLoop(Session);
DestroyString(Tempstr);
}





void InitialiseSettings(TSettings *Settings)
{
//Initialise timezone information, this is so that
//we don't get erratic times in log files from forked
//chrooted processes
time(&Now);
localtime(&Now);
srand(Now+getpid());
SetTimezoneEnv();

memset(Settings,0,sizeof(TSettings));
Settings->Flags |= FLAG_DEMON;
Settings->Port=21;
Settings->ServerLogPath=CopyStr(Settings->ServerLogPath,"/var/log/metaftpd/system.log");
Settings->LogPath=CopyStr(Settings->LogPath,"/var/log/metaftpd/system.log");
Settings->ConfigFile=CopyStr(Settings->ConfigFile,"/etc/metaftpd.conf");
Settings->AuthFile=CopyStr(Settings->AuthFile,"/etc/metaftpd.auth");
Settings->BindAddress=CopyStr(Settings->BindAddress,"");
Settings->AuthMethods=CopyStr(Settings->AuthMethods,"native,pam,shadow,passwd");
Settings->DefaultUser=CopyStr(Settings->DefaultUser,GetDefaultUser());
Settings->PermittedCommands=CopyStr(Settings->PermittedCommands,"ALL");
}

void DestroySessionCon(TSessionProcess *Con)
{
DestroyString(Con->User);
STREAMClose(Con->S);
free(Con);
}

void FtpAcceptClient(int ListenSock)
{
int val, fd;
TSessionArg SA;
TSessionProcess *Session;

  fd=TCPServerSockAccept(ListenSock,&val);
  SA.client_infd=fd;
  SA.client_outfd=fd;
  Session=(TSessionProcess *) calloc(1,sizeof(TSessionProcess));
  Session->S=STREAMCreate();
  ListAddItem(Sessions,Session);
  Session->Pid=PipeSpawnFunction(&Session->S->out_fd, &Session->S->in_fd,NULL, HandleSession, &SA);
  close(fd);
}


void CheckConnections(int ListenSock)
{
int pid, highfd;
ListNode *Curr, *Next;
TSessionProcess *Con;
fd_set selectset;

pid=waitpid(-1,NULL,WNOHANG);

FD_ZERO(&selectset);
FD_SET(ListenSock,&selectset);
highfd=ListenSock;

Curr=ListGetNext(Sessions);
while (Curr)
{
  Con=(TSessionProcess *)Curr->Item;
  Next=ListGetNext(Curr);

  if ((pid > 0) && (Con->Pid==pid))
  {
      DestroySessionCon(Con);
      ListDeleteNode(Curr);
  }
  else
  {
    FD_SET(Con->S->in_fd,&selectset);
    if (Con->S->in_fd > highfd) highfd=Con->S->in_fd;
  }
  Curr=Next;
}

if (select(highfd+1,&selectset,NULL,NULL,NULL) > 0)
{
if (FD_ISSET(ListenSock,&selectset)) FtpAcceptClient(ListenSock);

Curr=ListGetNext(Sessions);
while (Curr)
{
  Con=(TSessionProcess *)Curr->Item;
  Next=ListGetNext(Curr);

    if (FD_ISSET(Con->S->in_fd,&selectset))
    {
      if (! IPCHandleRequest(Con)) 
			{
	      DestroySessionCon(Con);
	      ListDeleteNode(Curr);
			}
    }
  Curr=Next;
}
}


}


void InetdSession(int argc, char *argv[])
{
TSessionArg SA;

  argv[1]=NULL;
  sprintf(CmdLine,"%s %s",ProgName,"New Session");
  SA.client_infd=0;
  SA.client_outfd=1;
	LogToFile(Settings.ServerLogPath,"INETD style session. Some features will not work if chroot/chhome mode is used, as there is no server process to handle requests for processes jailed in chroot.");

	if (Settings.Flags & FLAG_CHROOT)
	{
	chdir(Settings.Chroot);
	chroot(".");
	}

  HandleSession(&SA);
}


void DefaultSignalHandler(int Signal)
{
signal(Signal,DefaultSignalHandler);
}


main(int argc, char *argv[])
{
int fd, ListenSock, val;
char *Tempstr=NULL;

ProgName=CopyStr(ProgName,argv[0]);
CmdLine=argv[0];
Sessions=ListCreate();

signal(SIGPIPE,DefaultSignalHandler);

//Close anything other than stdin, stdout, stderr
for (fd=3; fd < 1000; fd++) close(fd);

memset(&Settings,0,sizeof(TSettings));
InitialiseSettings(&Settings);
ParseCommandLine(argc, argv); //must do this twice

ReadConfigFile(Settings.ConfigFile);

ParseCommandLine(argc, argv); //must do this twice

MakeDirPath(Settings.ServerLogPath,0760); 
LogToFile(Settings.ServerLogPath,"MetaFtpd starting up!");



if (Settings.Flags & MODE_INETD) InetdSession(argc, argv);
else
{
	if (Settings.Flags & FLAG_DEMON) demonize();
	ListenSock=InitServerSock(Settings.BindAddress,Settings.Port);
	if (ListenSock==-1) 
	{
			printf("Failed to bind port!\n");
			LogToFile(Settings.ServerLogPath,"Failed to bind port!");
		exit(0);
	}

	Tempstr=FormatStr(Tempstr,"metaftpd-port%d",Settings.Port);
	WritePidFile(Tempstr);

	if (Settings.Flags & FLAG_CHROOT)
	{
	chdir(Settings.Chroot);
	chroot(".");
	}

	while (1)
	{
	CheckConnections(ListenSock);
	}
}

DestroyString(Tempstr);
}
