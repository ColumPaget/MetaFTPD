#include "connections.h"
#include "Settings.h"
#include "IPC.h"

#ifdef HAVE_IPTABLES
#include <linux/netfilter_ipv4.h>
#endif




TDataConnection *DataConnectionCreate()
{
TDataConnection *Con;

Con=(TDataConnection *) calloc(1,sizeof(TDataConnection));
Con->ListenSock=-1;

return(Con);
}


/* This is a bit of kernel magic to decide where the client was trying */
/* to connect to before it got transparently proxied */
int GetIntendedDestination(int sock, TSession *Session)
{
int length;
struct sockaddr_in sa;

length=sizeof(struct sockaddr_in);


#ifdef HAVE_IPTABLES
	LogToFile(Settings.LogPath,"Getting intended ip...");
	if (getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, (char *) &sa, &length) < 0) return(FALSE); 

Session->DestIP=CopyStr(Session->DestIP,(char *) inet_ntoa(sa.sin_addr));
	
return(TRUE);
#endif

return(FALSE);
}



/*This is something else I'm working on, which is a kind of 'sudo' thing */
STREAM *OpenInvokeSock()
{
int sock,i,result;
struct sockaddr_un sa;
int salen;
STREAM *InvokeSock;

sock=socket(AF_UNIX, SOCK_STREAM, FALSE);

sa.sun_family=AF_UNIX;
strcpy(sa.sun_path,"/tmp/.InvocationSock");
salen=sizeof(sa);
if (connect(sock,(struct sockaddr *) &sa,salen)==0)
{
  InvokeSock=STREAMFromFD(sock);
  STREAMSetFlushType(InvokeSock,FLUSH_LINE,0, 0);
}
}


void RunConnectionInvoke(char *Command, char *SourceAddress, int SourcePort, char *DestAddress, int DestPort)
{
char *Tempstr=NULL;
STREAM *InvokeSock;

InvokeSock=OpenInvokeSock();
if (! InvokeSock) return;

Tempstr=FormatStr(Tempstr,",%s %s %d %s %d\n",Command, SourceAddress,SourcePort,DestAddress,DestPort);
LogToFile(Settings.LogPath,"invoke: %s",Tempstr);
STREAMWriteLine(Tempstr,InvokeSock);

STREAMClose(InvokeSock);
DestroyString(Tempstr);
}



int BindDataConnectionPort(int ControlSock, char *BindAddress, int Port, char **ResultAddress, int *ResultPort)
{
int fd=-1, salen, result;
struct sockaddr_in sa, cs_sa;
char *Tempstr=NULL;
int Tempval;

fd=InitServerSock(SOCK_STREAM, BindAddress, Port);
if (result == -1)
{
close(fd);
return(-1);
}

GetSockDetails(fd,ResultAddress,ResultPort,&Tempstr,&Tempval);
LogToFile(Settings.LogPath, "Bind for PASV DataConnection: %s:%d %s:%d",BindAddress, Port, *ResultAddress,*ResultPort);

DestroyString(Tempstr);

return(fd);
}


int BindDataConnectionPortFromRange(int ControlSock, char *BindAddress, int LowPort, int HighPort, char **ResultAddress, int *ResultPort)
{
int fd=-1, i, val, Port;

	val=HighPort-LowPort;

	//try three times to get one at random
	for (i=0; i < 3; i++)
	{
		Port=(rand() % val) + LowPort;
		fd=BindDataConnectionPort(ControlSock, BindAddress, Port, ResultAddress,ResultPort);
		if (fd > -1) return(fd);
	}

	//else search through all
	for (Port=LowPort; Port <= HighPort; Port++)
	{
		fd=BindDataConnectionPort(ControlSock, BindAddress, Port, ResultAddress,ResultPort);
		if (fd > -1) return(fd);
	}

return(-1);
}



int MakeOutgoingDataConnection(TSession *Session, STREAM *ControlSock, TDataConnection *DataCon, char *Type)
{
char *ptr;
int fd, salen, result;
char *Tempstr=NULL, *HookArgs=NULL;

LogToFile(Settings.LogPath, "Running data connection setup script for %s:%d -> %s:%d",DataCon->SourceAddress,DataCon->SourcePort,DataCon->DestAddress,DataCon->DestPort);
HookArgs=FormatStr(HookArgs,"ConnectUp %s %d %s %d %s",  DataCon->SourceAddress,0,DataCon->DestAddress,DataCon->DestPort,Type);
Tempstr=IPCRequest(Tempstr, Session, "RunHook", HookArgs);

DataCon->Sock=STREAMCreate();

DestroyString(HookArgs);
DestroyString(Tempstr);

if (STREAMConnectToHost(DataCon->Sock,DataCon->DestAddress,DataCon->DestPort,0)) return(TRUE);
STREAMClose(DataCon->Sock);
DataCon->Sock=NULL;

return(FALSE);
}



int MakeIncomingDataConnection(TSession *Session, STREAM *ControlSock, TDataConnection *DataCon, char *Type)
{
int fd, remoteip;
int salen;
struct sockaddr_in sa;
char *Tempstr=NULL, *HookArgs=NULL;


salen=sizeof(struct sockaddr_in);
getsockname(DataCon->ListenSock, (struct sockaddr *) &sa, &salen);
DataCon->SourcePort=ntohs(sa.sin_port);

LogToFile(Settings.LogPath, "Incoming: %s:%d -> %s:%d %s",DataCon->SourceAddress,DataCon->SourcePort,DataCon->DestAddress,DataCon->DestPort,Type);
HookArgs=FormatStr(HookArgs,"ConnectUp %s %d %s %d %s",  DataCon->SourceAddress,0,DataCon->DestAddress,DataCon->DestPort,Type);
Tempstr=IPCRequest(Tempstr, Session, "RunHook", HookArgs);

fd=TCPServerSockAccept(DataCon->ListenSock,NULL);

DestroyString(HookArgs);
DestroyString(Tempstr);

if (fd < 0) return(FALSE);
DataCon->Sock=STREAMFromFD(fd);

return(TRUE);
}


//This sends PASV to another ftp server when we're in proxy mode
int SendPASV(STREAM *ControlSock, TDataConnection *DataCon)
{
char *Tempstr=NULL, *Address=NULL, *sptr, *eptr;
int Port=0, result=FALSE;

STREAMWriteLine("PASV\r\n",ControlSock);
STREAMFlush(ControlSock);

Tempstr=STREAMReadLine(Tempstr,ControlSock);
LogToFile(Settings.LogPath, "PROXY: %s",Tempstr);
if (strncmp(Tempstr,"227",3)==0)
{
   sptr=strrchr(Tempstr,'(');
   if (sptr)
   {
      sptr++;
      eptr=strrchr(sptr,')');
      if (eptr) *eptr=0;
      DecodePORTStr(sptr,&Address,&Port);
      DataCon->DestAddress=CopyStr(DataCon->DestAddress,Address);
      DataCon->DestPort=Port;
      Tempstr=FormatStr(Tempstr,"Data Connect To: %s %d\n",Address,Port);
	  DataCon->Flags=DC_OUTGOING | DC_PROXY;
	  result=TRUE;
  }
}
DestroyString(Tempstr);
DestroyString(Address);

return(result);
}


//This sends PORT to another ftp server when we're in proxy mode
int SendPORT(STREAM *ControlSock, char *BindAddress, TDataConnection *DataCon)
{
char *Tempstr=NULL;
int result=FALSE;

if (FTP_BindDataConnection(ControlSock, BindAddress, DataCon, "PORT $(DestAddressCSV),$(DestPortHi),$(DestPortLow)"))
{
  Tempstr=STREAMReadLine(Tempstr,ControlSock);
  LogToFile(Settings.LogPath, "PROXY: %s",Tempstr);
  if (strncmp(Tempstr,"200",3)==0)
  {
//    DataCon->SourcePort=20;
		result=TRUE;
	  DataCon->Flags=DC_INCOMING | DC_PROXY;
  }
  else
  {
      close(DataCon->ListenSock); 
  }
}

DestroyString(Tempstr);

return(result);
}


int CopyToSock(STREAM *Input, STREAM *Output)
{
char *Tempstr=NULL;
int result=FALSE;

    Tempstr=STREAMReadLine(Tempstr,Input);
	if (strncmp(Tempstr,"150",3)==0) result=TRUE;
	if (strncmp(Tempstr,"2",1)==0) result=TRUE;
    while (Tempstr)
    {
  		LogToFile(Settings.LogPath, "PROXY: %s",Tempstr);
        if (Output) STREAMWriteLine(Tempstr,Output);
        if (Tempstr[3] != '-') break;
        Tempstr=STREAMReadLine(Tempstr,Input);
    }
STREAMFlush(Output);

DestroyString(Tempstr);
return(result);
}


TDataConnection *OpenDataConnection(TSession *Session, int Flags)
{
int result=FALSE;
char *Type="FromClient", *ptr, *Tempstr=NULL;
char *Message=NULL;
TDataConnection *DataCon;

DataCon=Session->DataConnection;

//May already be open
if (DataCon->Sock !=NULL)
{
 return(DataCon);
}


if (DataCon->Flags & DC_OUTGOING)
{
	DataCon->SourceAddress=CopyStr(DataCon->SourceAddress,Session->LocalIP);
	Type="ToClient";

	result=MakeOutgoingDataConnection(Session, Session->ClientSock, DataCon, Type);
	if (StrLen(Message)) SendLoggedLine(Message,Session->ClientSock);
}
else 
{
	DataCon->DestAddress=CopyStr(DataCon->DestAddress,Session->LocalIP);
	Type="FromClient";

	if (StrLen(Message)) SendLoggedLine(Message,Session->ClientSock);
	result=MakeIncomingDataConnection(Session, Session->ClientSock, DataCon, Type);
}

if (Session->Flags & SESSION_COMPRESSED_TRANSFERS) 
{
	Tempstr=CopyStr(Tempstr,"");
	ptr=GetVar(Session->Vars,"Opt:Mode Z:LEVEL");
	if (StrLen(ptr)) Tempstr=MCopyStr(Tempstr,"level=",ptr,NULL);
		LogToFile(Settings.LogPath, "Compression Level %s",ptr);
	STREAMAddStandardDataProcessor(DataCon->Sock,"compression","zlib",Tempstr);
}

DestroyString(Tempstr);
return(DataCon);
}


int NegotiateDataConnection(STREAM *ControlSock, char *BindAddress, TDataConnection *DC)
{
int result=FALSE;

if (! (Settings.Flags & FLAG_NOPASV)) result=SendPASV(ControlSock, DC);
if (! result)
{
   result=SendPORT(ControlSock, BindAddress, DC);
}
return(result);
}



int CloseDataConnection(TSession *Session, TDataConnection *DataCon)
{
struct linger linger;
char *Type="FromClient";
char *Tempstr=NULL, *HookArgs=NULL;

if (! DataCon) return(FALSE);

linger.l_onoff = 1;
linger.l_linger = 999;
//setsockopt(DataCon->Sock->in_fd, SOL_SOCKET, SO_LINGER, (char*)&linger, sizeof(linger));

//Only Close Sock if Input or output do not point to it
if ((DataCon->Sock != DataCon->Input) && (DataCon->Sock !=DataCon->Output)) STREAMClose(DataCon->Sock);

if (DataCon->Input) STREAMClose(DataCon->Input);
if (DataCon->Output) STREAMClose(DataCon->Output);

if (DataCon->ListenSock > -1) close(DataCon->ListenSock);

if (DataCon->Flags & DC_OUTGOING)
{
	if (DataCon->Flags & DC_PROXY) Type="ToServer";
	else Type="ToClient";
}
else
{
	if (DataCon->Flags & DC_PROXY) Type="FromServer";
	else Type="FromClient";
}


LogToFile(Settings.LogPath, "Running data connection close script for %s:%d -> %s:%d",DataCon->SourceAddress,DataCon->SourcePort,DataCon->DestAddress,DataCon->DestPort);
HookArgs=FormatStr(HookArgs,"ConnectDown %s %d %s %d %s", DataCon->SourceAddress,DataCon->SourcePort,DataCon->DestAddress,DataCon->DestPort,Type);
Tempstr=IPCRequest(Tempstr, Session, "RunHook", HookArgs);


DestroyString(Tempstr);
DestroyString(HookArgs);
DestroyString(DataCon->SourceAddress);
DestroyString(DataCon->DestAddress);
DestroyString(DataCon->FileName);
free(DataCon);

return(TRUE);
}



TDataConnection *AddDataConnection(TSession *Session, int Type, char *Address, int Port)
{
char *Tempstr=NULL;
TDataConnection *DC;

DC=(TDataConnection *) calloc(1,sizeof(TDataConnection));
DC->ListenSock=-1; //Must do this, as '0' is stdin, so if we leave ti stdin will be closed!
DC->DestAddress=CopyStr(DC->DestAddress,Address);
DC->DestPort=Port;
DC->Flags=Type;
Session->DataConnection=DC;

DestroyString(Tempstr);

return(DC);
}


//Sets things up for an INCOMING connection
int FTP_BindDataConnection(STREAM *PeerSock, char *BindAddress, TDataConnection *DC, char *MsgStr)
{
int val;
struct sockaddr_in sa;
char *Buffer=NULL, *Tempstr=NULL, *ptr;
ListNode *Vars;

	if (Settings.DataConnectionLowPort==0) DC->ListenSock=BindDataConnectionPort(PeerSock->in_fd, BindAddress, 0,&DC->DestAddress,&DC->DestPort); //pick one at random
	else DC->ListenSock=BindDataConnectionPortFromRange(PeerSock->in_fd,BindAddress, Settings.DataConnectionLowPort,Settings.DataConnectionHighPort,&DC->DestAddress,&DC->DestPort);
	
	if (DC->ListenSock==-1) 
	{
		LogToFile(Settings.LogPath,"ERROR: Can't bind Port for data connection!");
		return(FALSE);
	}

	 Vars=ListCreate();

   /* now we have to send a message to the remote server to tell it to connect*/
   /* back to us on the specified port */
	 Tempstr=FormatStr(Tempstr,"%d",DC->DestPort);
	 SetVar(Vars,"DestPort",Tempstr);
			
   val=(DC->DestPort & 0xFF00) >>8;
	 Tempstr=FormatStr(Tempstr,"%d",val);
	 SetVar(Vars,"DestPortHi",Tempstr);
	
   val=DC->DestPort & 0x00FF;
	 Tempstr=FormatStr(Tempstr,"%d",val);
	 SetVar(Vars,"DestPortLow",Tempstr);
	
	 val=sizeof(struct sockaddr_in);
   getpeername(PeerSock->in_fd,(struct sockaddr *) &sa, &val);
   DC->SourceAddress=CopyStr(DC->SourceAddress,(char *) inet_ntoa(sa.sin_addr));
   DC->SourcePort=ntohs(sa.sin_port);

	/* in FTP we have commas in IP addresses rather than dots (!??!!) */
	Tempstr=CopyStr(Tempstr,DC->DestAddress);
	LogToFile(Settings.LogPath,"DESTA: %s",DC->DestAddress);
	strrep(Tempstr,'.',',');
	SetVar(Vars,"DestAddressCSV",Tempstr);

	Buffer=SubstituteVarsInString(Buffer,MsgStr,Vars,0);

	SendLoggedLine(Buffer,PeerSock);
	DC->Flags=DC_INCOMING;

	ListDestroy(Vars,DestroyString);

	DestroyString(Tempstr);
	DestroyString(Buffer);

return(TRUE);
}

