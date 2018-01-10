#include "common.h"
#include "Authenticate.h"
#include "Settings.h"
#include "IPC.h"
#include "connections.h"
#include <sys/param.h>


unsigned int RetrieveStartPos;
time_t Now;

//Used to Pass Values to a session
typedef struct
{
int client_infd;
int client_outfd;
} TSessionArg;


//CmdLine is a pointer, not a libUseful String
char *CmdLine, *ProgName=NULL;
ListNode *Sessions;

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
		SendLoggedLine(Session,Tempstr);
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
STREAM *S;
char *Tempstr=NULL, *Line=NULL;
struct timeval tv;

while (1)
{
tv.tv_sec=10;
tv.tv_usec=0;

S=STREAMSelect(Session->Connections, &tv);

if (S)
{
	if (S==Session->ClientSock)
	{
		if (! SessionReadFTPCommand(Session)) break;
	}
	else
	{
	Curr=ListGetNext(Session->Connections);
	while (Curr)
	{
		Next=ListGetNext(Curr);
		DC=(TDataConnection *) STREAMGetItem((STREAM *) Curr->Item, "DataCon");

//|| STREAMCheckForBytes(DC->Input))
		if (DC && (S==DC->Input) )
		{
			result=FtpCopyBytes(Session,DC);
			switch (result)
			{
				case ERR_SIZE:
				EndTransfer(Session, DC, "552 ERR", "Max file size exceeded.");
				ListDeleteNode(Curr);
				break;

				case 0:
				Line=FormatStr(Line,"%s bytes Transferred",GetHumanReadableDataQty(DC->BytesSent,0));
				if (DC->Hash)
				{
					DC->Hash->Finish(DC->Hash, ENCODE_HEX, &Tempstr);
					Line=MCatStr(Line," ",DC->Hash->Type,"=",Tempstr,NULL);
				}
				EndTransfer(Session, DC, "226 OK", Line);
				ListDeleteNode(Curr);
				break;
			}
		}
		Curr=Next;
	}
	}
}
//if No 'S' returned, then we timed out, so check idle
else SessionCheckIdleTimeout(Session);
}

DestroyString(Tempstr);
DestroyString(Line);
}



char *BuildConnectBanner(char *RetStr, TSession *Session)
{
char *Token=NULL, *HashPassTypes=NULL, *ptr;

	RetStr=CopyStr(RetStr, "");
	ptr=GetToken(Settings.AuthMethods, ",",&Token,0);
	while (ptr)
	{
	if (strncmp(Token,"hp-",3)==0) HashPassTypes=MCatStr(HashPassTypes,Token,",",NULL);
	ptr=GetToken(ptr, ",",&Token,0);
	}

	if (StrLen(HashPassTypes) || StrLen(Settings.ConnectBanner))
	{
		if (StrLen(Settings.ConnectBanner)) 
		{
			ptr=GetToken(Settings.ConnectBanner,"\n",&Token,0);
			while (ptr)
			{
			RetStr=MCatStr(RetStr,"220-",Token,"\r\n",NULL);
			ptr=GetToken(ptr,"\n",&Token,0);
			}
		}
		if (StrLen(HashPassTypes)) 
		{
			GenerateRandomBytes(&Session->Challenge, 20, ENCODE_BASE64);
			RetStr=MCatStr(RetStr,"220-PasswdTypes: ",HashPassTypes," ",Session->Challenge, "\r\n", NULL);
		}
	}

	RetStr=CatStr(RetStr,"220 OK\r\n");

	DestroyString(Token);
	DestroyString(HashPassTypes);

	return(RetStr);
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
Session->Connections=ListCreate();
SetVar(Session->Vars,"User","unknown");
SetVar(Session->Vars,"RealUser","root");
Session->MLSFactsList=CopyStr(Session->MLSFactsList, "type;size;modify");

//MODE_FTP_X and SESSION_FTP_X are setup to have the same values, so this is
//not as alarming as it looks
Session->Flags=Settings.Flags & (MODE_FTP_SERVER | MODE_FTP_PROXY);
GetSockDetails(SA->client_infd,&Session->LocalIP,&val,&Session->ClientIP,&val);
SetVar(Session->Vars,"ClientIP",Session->ClientIP);

val=LOGFILE_LOGPID | LOGFILE_LOGUSER | LOGFILE_TIMESTAMP | LOGFILE_MILLISECS;
if (Settings.Flags & FLAG_SYSLOG) 
{
	val |=LOGFILE_SYSLOG;
	openlog("ftpd",LOG_PID,LOG_DAEMON);
}
LogFileFindSetValues(Settings.ServerLogPath, val, 100000000, 0, 0);
LogToFile(Settings.ServerLogPath,"New Connection from %s",Session->ClientIP);

Session->DataConnection=DataConnectionCreate();


Session->ClientSock=STREAMFromDualFD(SA->client_infd, SA->client_outfd);
ListAddItem(Session->Connections,Session->ClientSock);
STREAMSetFlushType(Session->ClientSock,FLUSH_LINE,0,0);

if (! (Settings.Flags & MODE_INETD)) 
{
	Session->IPCCon=STREAMFromDualFD(0,1);
	STREAMSetFlushType(Session->IPCCon,FLUSH_LINE,0,0);
}

GetIntendedDestination(SA->client_infd, Session);

if (StrLen(Session->DestIP) && (strcmp(Session->DestIP,Session->LocalIP)==0)) Session->DestIP=CopyStr(Session->DestIP,"");

//Check DestIP again, as may have been changed
if (StrLen(Session->DestIP))
{
	LogToFile(Settings.ServerLogPath,"Connection from %s to %s\n",Session->ClientIP,Session->DestIP);

	if (Session->Flags & SESSION_FTP_PROXY)
	{
   		if (! ProxyControlConnect(Session, Session->DestIP,21)) exit(0);
	}
}
else 
{
	Tempstr=BuildConnectBanner(Tempstr, Session);
	
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
int fd;
TSessionArg SA;
TSessionProcess *Session;

  fd=TCPServerSockAccept(ListenSock,NULL);
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

DropCapabilities(CAPS_LEVEL_STARTUP);
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



if (Settings.Flags & MODE_INETD) 
{
	InetdSession(argc, argv);
}
else
{
	if (Settings.Flags & FLAG_DEMON) demonize();
	ListenSock=InitServerSock(SOCK_STREAM,Settings.BindAddress,Settings.Port);
	if (ListenSock==-1) 
	{
			printf("Failed to bind port!\n");
			LogToFile(Settings.ServerLogPath,"Failed to bind port!");
		exit(0);
	}

	DropCapabilities(CAPS_LEVEL_NETBOUND);
	if (StrLen(Settings.BindAddress) && (strcmp(Settings.BindAddress,"0.0.0.0") !=0) ) Tempstr=FormatStr(Tempstr,"metaftpd-%s-port%d",Settings.BindAddress, Settings.Port);
	else Tempstr=FormatStr(Tempstr,"metaftpd-port%d",Settings.Port);
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
