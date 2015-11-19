#include "proxy.h"
#include "ftp-commands.h"
#include "connections.h"
#include "Settings.h"
#include "IPC.h"


int AsciiSendFileData(STREAM *InStream,STREAM * OutStream, int Direction)
{
char *Tempstr=NULL;
int result;
struct stat FStat;
double FileSize=0;
int RetVal=FALSE;


Tempstr=STREAMReadLine(Tempstr,InStream);
while (Tempstr)
{
		StripCRLF(Tempstr);
		Tempstr=CatStr(Tempstr,"\r\n");
		result=StrLen(Tempstr);

	STREAMWriteLine(Tempstr,OutStream);
	Tempstr=STREAMReadLine(Tempstr,InStream);
	RetVal=TRUE;
}

STREAMFlush(OutStream);
DestroyString(Tempstr);

return(RetVal);
}


int BinarySendFileData(STREAM *InStream,STREAM *OutStream, int Direction)
{
char *Buffer=NULL;
int result, BuffSize=BUFSIZ;
struct stat FStat;
double FileSize=0;
int RetVal=FALSE;


Buffer=SetStrLen(Buffer,BuffSize);
result=STREAMReadBytes(InStream, Buffer,BuffSize );
while (result > EOF)
{
	 RetVal=TRUE;
	 if (result==0) sleep(0);
	 else STREAMWriteBytes(OutStream, Buffer, result);

  result=STREAMReadBytes(InStream, Buffer, BuffSize);
}


DestroyString(Buffer);
return(RetVal);
}


int SendFileData(int Ascii, STREAM *InStream, STREAM *OutStream, int Direction)
{
int result;

if (Ascii) result=AsciiSendFileData(InStream,OutStream,Direction);
else result=BinarySendFileData(InStream,OutStream,Direction);
return(result);
}

void SendToProxy(TSession *Session, char *Command, char *Arg)
{
char *Tempstr=NULL;

Tempstr=CopyStr(Tempstr,Command);
if (StrLen(Arg) > 0)
{
  Tempstr=CatStr(Tempstr," ");
  Tempstr=CatStr(Tempstr,Arg);
}
Tempstr=CatStr(Tempstr,"\r\n");
STREAMWriteLine(Tempstr,Session->ProxySock);
STREAMFlush(Session->ProxySock);

do
{
   Tempstr=STREAMReadLine(Tempstr,Session->ProxySock);
	StripTrailingWhitespace(Tempstr);
   SendLoggedLine(Session,Tempstr);
} while ( (Tempstr[3]=='-') || (isspace(Tempstr[0])) );

STREAMFlush(Session->ProxySock);
STREAMFlush(Session->ClientSock);
DestroyString(Tempstr);
}



TDataConnection *ProxyOpenDataConnection(TSession *Session, int Flags)
{
int result=FALSE, val;
char *Type="ToServer", *ptr, *Tempstr=NULL;
char *Message=NULL;
TDataConnection *DataCon;


DataCon=Session->ProxyDataConnection;
LogToFile(Settings.LogPath, "PRoxy OPD %s",DataCon->SourceAddress);

//May already be open
if (DataCon->Sock !=NULL) return(DataCon);

if (DataCon->Flags & DC_OUTGOING)
{
	GetSockDetails(Session->ProxySock->in_fd,&DataCon->SourceAddress,&val,&Tempstr,&val);
	result=MakeOutgoingDataConnection(Session->ProxySock, DataCon, Type);
	if (! CopyToSock(Session->ClientSock, Session->ProxySock)) return(NULL);
LogToFile(Settings.LogPath, "PRoxy MOD %s %d",DataCon->DestAddress,DataCon->DestPort);
}
else 
{
	GetSockDetails(Session->ProxySock->in_fd,&DataCon->DestAddress,&val,&Tempstr,&val);
	Type="FromServer";

LogToFile(Settings.LogPath, "PRoxy MID %s %d",DataCon->DestAddress,DataCon->SourcePort);
	result=MakeIncomingDataConnection(Session->ClientSock, DataCon, Type);
}


/*
if (Session->Flags & SESSION_COMPRESSED_TRANSFERS) 
{
	Tempstr=CopyStr(Tempstr,"");
	ptr=GetVar(Session->Vars,"Opt:Mode Z:LEVEL");
	if (StrLen(ptr)) Tempstr=MCopyStr(Tempstr,"level=",ptr,NULL);
		LogToFile(Settings.LogPath, "Compression Level %s",ptr);
	STREAMAddStandardDataProcessor(DataCon->Sock,"compression","zlib",Tempstr);
}
*/

DestroyString(Tempstr);
return(DataCon);
}


/* Proxy functions */


void ProxyHandlePASV(TSession *Session)
{
Session->ProxyDataConnection=DataConnectionCreate();
if (NegotiateDataConnection(Session->ProxySock, "", Session->ProxyDataConnection))
{
	LogToFile(Settings.LogPath, "NEG DC %s",Session->ProxyDataConnection->SourceAddress);
	HandlePASV(Session);
	Session->ProxyDataConnection->Flags |= DC_PROXY;
}
}



void ProxyHandlePORT(TSession *Session, char *PortStr)
{
char *Tempstr=NULL, *Address=NULL, *ptr;
int Port=0;

  DecodePORTStr(PortStr,&Address,&Port);
  AddDataConnection(Session, DC_OUTGOING, Address, Port);
  Session->ProxyDataConnection=DataConnectionCreate();

if (NegotiateDataConnection(Session->ProxySock, Session->LocalIP, Session->ProxyDataConnection))
{
  Session->ProxyDataConnection->Flags |= DC_PROXY;
  SendLoggedLine(Session,"200 OK");
}
else 
{
	SendLoggedLine(Session,"451 ERROR Can't open data connection");
}

DestroyString(Tempstr);
DestroyString(Address);
}

void ProxyHandleUSER(TSession *Session, char *Args)
{
char *User=NULL, *Host=NULL, *ptr;
int Port=21;

if (strchr(Args,'@'))
{
ptr=GetToken(Args,"@",&User,0);
Host=CopyStr(Host,ptr);

//This looks odd, but this function can be called from 'non proxy mode' to set
//us into proxy
if (ProxyControlConnect(Session, Host, Port)) Session->Flags |= SESSION_FTP_PROXY;
}
else User=CopyStr(User,Args);

SendToProxy(Session, "USER", User);

DestroyString(User);
DestroyString(Host);
}






int ProxyHandleFileTransfer(TSession *Session, char *Command, char *Path, int Direction)
{
STREAM *InFile;
int fd, KeepReading;
char *Tempstr=NULL;

Tempstr=MCopyStr(Tempstr,Command," ",Path,"\r\n",NULL);
STREAMWriteLine(Tempstr,Session->ProxySock); 
STREAMFlush(Session->ProxySock);
LogToFile(Settings.LogPath,"PROXY SEND: %s ",Tempstr);
if (! CopyToSock(Session->ProxySock, Session->ClientSock)) return(FALSE);


if (ProxyOpenDataConnection(Session,0)) 
{

	if (OpenDataConnection(Session,0))
	{
		if (Direction==FILE_SEND) SendFileData(Session->Flags & SESSION_ASCII_TRANSFERS,Session->DataConnection->Sock, Session->ProxyDataConnection->Sock,0);
		else
		{
			 SendFileData(Session->Flags & SESSION_ASCII_TRANSFERS,Session->ProxyDataConnection->Sock, Session->DataConnection->Sock,0);
		}
		CloseDataConnection(Session, Session->DataConnection);
  }

  CloseDataConnection(Session, Session->ProxyDataConnection);
  Tempstr=STREAMReadLine(Tempstr,Session->ProxySock);
  STREAMWriteLine(Tempstr,Session->ClientSock);
	STREAMFlush(Session->ClientSock);

  Session->DataConnection=NULL;
  Session->ProxyDataConnection=NULL;
}

/*
//One day will use this instead
LogToFile(Settings.LogPath, "MADE DATA CON");
DataCon->Input=DataCon->Sock;
LogToFile(Settings.LogPath, "ADD LOCAL CON");
DataCon->Output=Session->DataConnection->Sock;
LogToFile(Settings.LogPath, "SET FNAME");
DataCon->FileName=CopyStr(DataCon->FileName,"Proxy");
DataCon->Flags |= DC_RETR;
Session->DataConnection=NULL;
Session->ProxyDataConnection=NULL;
ListAddItem(Session->FileTransfers,DataCon);
*/



DestroyString(Tempstr);

return(TRUE);
}



int ProxyHandleRETR(TSession *Session, char *Path)
{
  return(ProxyHandleFileTransfer(Session,"RETR",Path,FILE_RECV));
}

int ProxyHandleSTOR(TSession *Session, char *Path)
{
  return(ProxyHandleFileTransfer(Session,"STOR",Path,FILE_SEND));
}

int ProxyHandleLIST(TSession *Session, char *Path, int ListType)
{
  if (ListType==LIST_SHORT) return(ProxyHandleFileTransfer(Session,"NLST",Path,FILE_RECV));
  return(ProxyHandleFileTransfer(Session,"LIST",Path,FILE_RECV));
}




void DoProxyCommand(TSession *Session, char *Command, char *Arg)
{
int cmd;

LogToFile(Settings.LogPath,"PROXY RCV: %s '%s'",Command,Arg);
cmd=MatchFtpCommand(Command);

switch (cmd)
{
case CMD_PORT: ProxyHandlePORT(Session, Arg); break;
case CMD_PASV: ProxyHandlePASV(Session); break;
case CMD_RETR: ProxyHandleRETR(Session,Arg); break;
case CMD_STOR: ProxyHandleSTOR(Session,Arg); break;
case CMD_LIST: ProxyHandleLIST(Session, Arg, LIST_LONG); break;
case CMD_NLST: ProxyHandleLIST(Session, Arg, LIST_SHORT); break;
case CMD_USER: ProxyHandleUSER(Session,Arg); break;

case CMD_NOOP:
case CMD_PASS: 
case CMD_SYST:
case CMD_TYPE:
case CMD_CDUP:
case CMD_XCUP:
case CMD_CWD:
case CMD_XCWD:
case CMD_PWD:
case CMD_XPWD:
case CMD_MKD:
case CMD_XRMD:
case CMD_XMKD:
case CMD_RMD:
case CMD_RMDA:
case CMD_SIZE:
case CMD_MDTM:
case CMD_DELE:
case CMD_QUIT: 
case CMD_OPTS: 
case CMD_FEAT: 
case CMD_AVBL: 
case CMD_REIN: 
 SendToProxy(Session, Command, Arg);
break;

default:
      SendLoggedLine(Session,"500 ERROR: Command not recognized");
break;
}

}


int ProxyControlConnect(TSession *Session, char *Host, int Port)
{
char *Tempstr=NULL;
int fd, result=FALSE;

if (StrLen(Host)==0) 
{
	SendLoggedLine(Session,"421 ERROR: Proxy cannot connect. No destination host.");
}
else 
{
Tempstr=IPCRequest(Tempstr, Session, "GetIP", Host);

   if (strcmp(Tempstr,"DENIED")==0)
   {
      Tempstr=FormatStr(Tempstr,"421 ERROR: Proxy connection denied for host %s:%d",Host,Port);
      SendLoggedLine(Session,Tempstr);

   }
   else
  {
      fd=ConnectToHost(Tempstr,Port,FALSE);
      if (fd==-1)
      {
      	Tempstr=FormatStr(Tempstr,"421 ERROR: Proxy cannot connect to host %s:%d",Host,Port);
        SendLoggedLine(Session,Tempstr);
      }
			else
			{
     	 Session->ProxySock=STREAMFromFD(fd);
     	 result=TRUE;
     	 do
     	 {
     	  Tempstr=STREAMReadLine(Tempstr,Session->ProxySock);
     	  STREAMWriteLine(Tempstr,Session->ClientSock);
     	 } while ( (Tempstr[3]=='-') || (isspace(Tempstr[0])) );
			STREAMFlush(Session->ClientSock);
			}
  }
}

DestroyString(Tempstr);
return(result);
}


