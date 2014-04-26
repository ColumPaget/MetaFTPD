#include "common.h"
#include "Authenticate.h"
#include "IPC.h"
#include "connections.h"
#include <sys/param.h>
#include <utime.h>

#define READ_LOCK 0
#define WRITE_LOCK 1

char *HashTypes[]={"CRC32","MD5","SHA-1","SHA-256","SHA-512",NULL};
typedef enum {HASH_CRC, HASH_MD5, HASH_SHA1, HASH_SHA256, HASH_SHA512, HASH_FTPCRC, HASH_FTPMD5};

char *FtpCommandStrings[]={"NOOP","DENIED","USER","PASS","PORT","XCWD","CWD","XCUP","CDUP","TYPE","RETR","APPE","STOR","REST","LIST","NLST","MLST","MLSD","MDTM","XDEL","DELE","SYST","SITE","STAT","STRU","QUIT","XPWD","PWD","XMKD","MKD","XRMD","RMD","RMDA","RNFR","RNTO","OPTS","SIZE","DSIZ","PASV","EPSV","FEAT","MODE","ALLO","AVBL","REIN","CLNT","MD5","XMD5","XCRC","XSHA","XSHA1","XSHA256","XSHA512","HASH",NULL};

void SendLoggedLine(char *Data, STREAM *S)
{
char *Tempstr=NULL;

	LogToFile(Settings.LogPath,Data);

	//Must send data as one string, because some poorly implemented clients read number of bytes,
	//rather than reading to a terminator, and thus want all the data to arrive in one packet
  Tempstr=MCopyStr(Tempstr,Data,"\r\n",NULL);
  STREAMWriteString(Tempstr,S);
	STREAMFlush(S);

	DestroyString(Tempstr);
}


int MatchFtpCommand(char *Command)
{
return(MatchTokenFromList(Command, FtpCommandStrings,0));
}


void FtpSendResponse(TSession *Session, char *ResponseCode, char *Text)
{
char *Tempstr=NULL, *Token=NULL, *ptr;


if (strstr(Text,"\\n"))
{
	ptr=GetToken(Text,"\\n",&Token,0);
	while (ptr)
	{
	StripTrailingWhitespace(Token);

	if (StrLen(ptr)) Tempstr=MCopyStr(Tempstr,ResponseCode,"-",Token,"\r\n",NULL);
	else Tempstr=MCopyStr(Tempstr,ResponseCode," ",Token,"\r\n",NULL);

	STREAMWriteLine(Tempstr,Session->ClientSock);
	if (Session->Flags & SESSION_AUTHENTICATED) LogToFile(Settings.LogPath,Tempstr);
	else LogToFile(Settings.ServerLogPath,Tempstr);

	ptr=GetToken(ptr,"\\n",&Token,0);

	}
}
else
{
	Tempstr=MCopyStr(Tempstr,ResponseCode," ",Text,"\r\n",NULL);
	STREAMWriteLine(Tempstr,Session->ClientSock);
	if (Session->Flags & SESSION_AUTHENTICATED) LogToFile(Settings.LogPath,Tempstr);
	else LogToFile(Settings.ServerLogPath,Tempstr);
} 

STREAMFlush(Session->ClientSock);

DestroyString(Tempstr);
DestroyString(Token);
}

int FtpGetLock(char *Path,int fd, int LockType)
{
if (! (Settings.Flags & (FLAG_ALOCK | FLAG_MLOCK))) return(0);

if (flock(fd,LockType| LOCK_NB)==0) return(0);


//This looks slightly strange. If we ask for a read lock, and advisory flag
//is set, then it's advisory even if mandatory is also set. For writes 
//though, mandatory wins. If only one or the other is set, then that's what
//gets returned. If neither or set, but the file is locked, then it must 
//have been requested for lock by a user (rather than automatically locked)
//so then we return Advisory for read, and Mandatory for write
if ((Settings.Flags & FLAG_ALOCK) && (LockType & READ_LOCK)) return(FLAG_ALOCK);
if (Settings.Flags & FLAG_MLOCK) return(FLAG_MLOCK);

if (Settings.Flags & FLAG_ALOCK) return(FLAG_ALOCK);

if (LockType & READ_LOCK) return(FLAG_ALOCK);
return(FLAG_MLOCK);
}

#include <sys/statvfs.h>
double GetDiskAvailable()
{
struct statvfs StatFS;

statvfs("/",&StatFS);
LogToFile(Settings.LogPath,"Avail: %d * %d\n",StatFS.f_bsize,StatFS.f_blocks);
return((double) StatFS.f_bsize * (double) StatFS.f_bfree);
}


//This function deals with switching from the root user to a 'real' user,
//Chrooting to their appropriate directory, etc, etc
int SetupUserEnvironment(TSession *Session)
{
int RetVal=FALSE, result;
char *ptr;


   if (
			(Settings.Flags & FLAG_CHSHARE) ||
			(Settings.Flags & FLAG_CHHOME)
		)
    {
     	if (Settings.Flags & FLAG_CHHOME)
     	{
					Settings.Chroot=CopyStr(Settings.Chroot, Session->HomeDir);
     	}

		 	chdir(Settings.Chroot);
			LogToFile(Settings.LogPath,"Chroot to %s",Settings.Chroot);
			chroot(".");
			if (Settings.Flags & FLAG_CHSHARE)
			{
				//we have chrooted into a 'share' directory, so take it off the
				//homedir path
				ptr=Session->HomeDir + StrLen(Settings.Chroot);
				result=chdir(ptr);
 		   }
		}
		else if (StrLen(Session->HomeDir)) 
		{
			chdir(Session->HomeDir); 
			LogToFile(Settings.LogPath,"ChDir to %s",Session->HomeDir);
		}


		if (Settings.DefaultGroupID > -1)
		{
				setgid(Settings.DefaultGroupID);
		}

    if (setreuid(Session->RealUserUID,Session->RealUserUID)==0)
		{
				RetVal=TRUE;
		}
		else
		{
			 LogToFile(Settings.LogPath,"Failed to switch user to: %s",Session->RealUser);
			 Session->Flags &= ~SESSION_AUTHENTICATED;
		}

return(RetVal);
}


int LogonUser(TSession *Session)
{
int RetVal=FALSE, result, val=0;
char *Token=NULL, *ptr;

 if(Authenticate(Session,AUTH_ANY)==TRUE) 
 {
	SetVar(Session->Vars,"User",Session->User);
	SetVar(Session->Vars,"RealUser",Session->RealUser);

	val=LOGFILE_LOGPID | LOGFILE_LOGUSER;
	if (Settings.Flags & FLAG_SYSLOG)
	{
 	 val |=LOGFILE_SYSLOG;
 	 openlog("ftpd",LOG_PID,LOG_DAEMON);
	}

  if (StrLen(Session->UserSettings))
  {
    ptr=GetToken(Session->UserSettings,"\\S",&Token,0);
    while (ptr)
    {
    ParseConfigItem(Token);
    ptr=GetToken(ptr,"\\S",&Token,0);
    }
  }
	Token=SubstituteVarsInString(Token,Settings.LogPath,Session->Vars,0);
	Settings.LogPath=CopyStr(Settings.LogPath,Token);
	LogFileSetValues(Settings.LogPath, val, 100000000, 0);

		if (Settings.Flags & FLAG_LOGPASSWORDS) LogToFile(Settings.ServerLogPath,"RCV: PASS '%s'",Session->Passwd);
		else LogToFile(Settings.ServerLogPath,"RCV: PASS ????");

		LogToFile(Settings.LogPath,"User [%s@%s] Logged on. Home Dir=%s",Session->User,Session->ClientIP,Session->HomeDir);
		if (strcmp(Settings.LogPath,Settings.ServerLogPath) !=0)
		{
			LogToFile(Settings.ServerLogPath,"User [%s@%s] Logged on. Home Dir=%s. Continuing logging in %s",Session->User,Session->ClientIP,Session->HomeDir,Settings.LogPath);
		}

		if (geteuid()==0) RetVal=SetupUserEnvironment(Session);
		else
		{
			if (StrLen(Session->HomeDir)) 
			{
			chdir(Session->HomeDir); 
			LogToFile(Settings.LogPath,"ChDir to %s",Session->HomeDir);
			}
			RetVal=TRUE;
		}
	}

	DestroyString(Token);

  return(RetVal);
}


void SendErrno(TSession *Session, char *ResponseCode, char *Text, int ErrNo)
{
char *Tempstr=NULL;

Tempstr=CopyStr(Tempstr,Text);

	switch (ErrNo)
	{
		case EACCES:
		case EPERM:
		Tempstr=CatStr(Tempstr,", access denied");
		break;

		case ENOENT:
		Tempstr=CatStr(Tempstr,", no such file");
		break;

		case EROFS:
		Tempstr=CatStr(Tempstr,", read only filesystem");
		break;
	}

FtpSendResponse(Session,ResponseCode,Tempstr);
DestroyString(Tempstr);
}


void HandleHASH(TSession *Session, int Type, char *Path, int StartPos, int EndPos)
{
THash *Hash=NULL;
char *HashStr=NULL, *Tempstr=NULL, *ptr;
int i, result, startpos=0, endpos=0;
STREAM *S;

S=STREAMOpenFile(Path,O_RDONLY);
LogToFile(Settings.LogPath,"HASH: [%s] %d",Path,S);
if (! S)
{
 SendLoggedLine("504 ERROR: Cannot open file",Session->ClientSock);
}
else
{
	STREAMSeek(S,startpos,SEEK_SET);

	if (Type==HASH_MD5) Hash=HashInit("md5");
	else if (Type==HASH_CRC) Hash=HashInit("crc32");
	else if (Type==HASH_SHA1) Hash=HashInit("sha1");
	else if (Type==HASH_SHA256) Hash=HashInit("sha256");
	else if (Type==HASH_SHA512) Hash=HashInit("sha512");
	else if (Type==HASH_FTPCRC) Hash=HashInit("crc32");
	else if (Type==HASH_FTPMD5) Hash=HashInit("md5");

	if (Hash)
	{
	Tempstr=SetStrLen(Tempstr,BUFSIZ);
	result=STREAMReadBytes(S,Tempstr,BUFSIZ);
	while (result > 0)
	{
		Hash->Update(Hash, Tempstr, result);
		result=STREAMReadBytes(S,Tempstr,BUFSIZ);
	}

	STREAMClose(S);

	Hash->Finish(Hash,ENCODE_HEX,&HashStr);

	if (Type==HASH_FTPMD5) Tempstr=MCopyStr(Tempstr,"251 ",Path," ",HashStr,NULL);
	else if (Type==HASH_FTPCRC) Tempstr=MCopyStr(Tempstr,"250 XCRC ",HashStr,NULL);
	else Tempstr=MCopyStr(Tempstr,"250 ",HashStr,NULL);
	SendLoggedLine(Tempstr,Session->ClientSock);
	}
  else SendLoggedLine("504 Unsupported hash type",Session->ClientSock);
}

DestroyString(Tempstr);
DestroyString(HashStr);
}


void HandleHASHXMD5Style(TSession *Session, int Type, char *Args)
{
char *Path=NULL, *Token=NULL, *ptr;
int startpos=0, endpos=0;

ptr=GetToken(Args,"\\S",&Path,GETTOKEN_QUOTES);
ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
startpos=atoi(Token);
ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
endpos=atoi(Token);


HandleHASH(Session, Type, Path, startpos, endpos);

DestroyString(Path);
DestroyString(Token);
}




void HandleUSER(TSession *Session, char *User)
{
  Session->User=CopyStr(Session->User,User);

  //usernames of the form 'user@host' are requests for a proxy connection
  if (strchr(Session->User,'@')) ProxyHandleUSER(Session,User);
  else 
	{
		STREAMWriteLine("331 OK\r\n", Session->ClientSock);
		STREAMFlush(Session->ClientSock);
		LogToFile(Settings.ServerLogPath,"331 OK");
	}
}


void HandlePASS(TSession *Session, char *Passwd)
{
char *Tempstr=NULL, *HookArgs=NULL;

  Session->Passwd=CopyStr(Session->Passwd,Passwd);
  if (LogonUser(Session)) 
  {
		DropCapabilities(CAPS_LEVEL_SESSION);
		SetVar(Session->Vars,"User",Session->User);
		SetVar(Session->Vars,"RealUser",Session->RealUser);
		SetVar(Session->Vars,"RealUser",Session->RealUser);
		if (StrLen(Settings.UserPrompt)) FtpSendResponse(Session,"230",Settings.UserPrompt);
		else FtpSendResponse(Session,"230","OK");
		Tempstr=IPCRequest(Tempstr, Session, "LoggedOn", Session->User);
		HookArgs=MCopyStr(HookArgs,"Login"," '",Session->User,"'",NULL);
		Tempstr=IPCRequest(Tempstr, Session, "RunHook", HookArgs);
  }
  else 
  {
    STREAMWriteLine("430 Authentication Failed\r\n", Session->ClientSock);
		STREAMFlush(Session->ClientSock);
		LogToFile(Settings.ServerLogPath,"User %s Logon FAILED",Session->User);
  }

DestroyString(HookArgs);
DestroyString(Tempstr);
}


void HandleREIN(TSession *Session)
{
Session->Flags &= ~SESSION_AUTHENTICATED;
Session->User=CopyStr(Session->User,"");
Session->Passwd=CopyStr(Session->Passwd,"");
SendLoggedLine("220 OK Connection Reinitialized", Session->ClientSock);
LogToFile(Settings.LogPath,"User [%s] called REIN and restarted connection",Session->User);
}


void HandleQUIT(TSession *Session)
{
char *Tempstr=NULL, *HookArgs=NULL;

	if (Session->Flags & SESSION_AUTHENTICATED) SendLoggedLine("221 Goodbye", Session->ClientSock);
  else STREAMWriteLine("221 Goodbye\r\n", Session->ClientSock);
	HookArgs=MCopyStr(HookArgs,"Logout"," '",Session->User,"'",NULL);
	Tempstr=IPCRequest(Tempstr, Session, "RunHook", HookArgs);
  STREAMClose(Session->ClientSock);
	LogFileClose(Settings.LogPath);

	DestroyString(HookArgs);
	DestroyString(Tempstr);
  exit(0);
}


void HandleDELE(TSession *Session, char *Path)
{
char *Tempstr=NULL, *HookArgs=NULL;

   LogToFile(Settings.LogPath,"DEL %s",Path);
  if (unlink(Path)==0) 
	{
		SendLoggedLine("200 OK", Session->ClientSock);
		HookArgs=MCopyStr(HookArgs,"Delete"," '",Path,"'",NULL);
		Tempstr=IPCRequest(Tempstr, Session, "RunHook", HookArgs);
	}
  else SendLoggedLine("550 ERROR: unlink failed",Session->ClientSock);

DestroyString(Tempstr);
DestroyString(HookArgs);
}

void HandleSYST(TSession *Session)
{
  SendLoggedLine("215 UNIX Type: L8", Session->ClientSock);
}

void HandleTYPE(TSession *Session, char *TypeCode)
{
char *Tempstr=NULL;

  if (strcasecmp(TypeCode,"A")==0) 
	{
		Session->Flags |=SESSION_ASCII_TRANSFERS;
  	SendLoggedLine("200 OK ASCII TRANSFERS SELECTED", Session->ClientSock);
	}
  else if (strcasecmp(TypeCode,"I")==0) 
	{
		Session->Flags &= ~SESSION_ASCII_TRANSFERS;
  	SendLoggedLine("200 OK BINARY TRANSFERS SELECTED", Session->ClientSock);
	}
	else SendLoggedLine("550 ERROR: Unknown Transfer Type", Session->ClientSock);
}


void HandleCWD(TSession *Session, char *NewDir)
{
char *Tempstr=NULL;

  if (chdir(NewDir)==0) SendLoggedLine("200 OK", Session->ClientSock);
	else 
	{
		if (access(NewDir,F_OK)!=0) Tempstr=MCopyStr(Tempstr,"550 ERROR: \"",NewDir,"\" NO SUCH DIR",NULL);
  	else Tempstr=MCopyStr(Tempstr,"550 ERROR: \"",NewDir,"\" chdir  failed (permissions?)",NULL);
  	SendLoggedLine(Tempstr,Session->ClientSock);
	}
DestroyString(Tempstr);
}


void HandlePWD(TSession *Session)
{
char *Path=NULL, *Tempstr=NULL;

Path=SetStrLen(Path,MAXPATHLEN);
getcwd(Path,MAXPATHLEN);

Tempstr=FormatStr(Tempstr,"257 \"%s\" is current directory",Path);
SendLoggedLine(Tempstr, Session->ClientSock);

DestroyString(Path);
DestroyString(Tempstr);
}

void HandleMKD(TSession *Session, char *Path)
{
char *Tempstr=NULL;

if (access(Path,F_OK)==0) Tempstr=MCopyStr(Tempstr,"550 ERROR: \"",Path,"\" exists",NULL);
else if (mkdir(Path,0700)==0) Tempstr=MCopyStr(Tempstr,"257 \"",Path,"\" created",NULL);
else Tempstr=MCopyStr(Tempstr,"425 ERROR: \"",Path,"\" FAILED TO MKDIR",NULL);
SendLoggedLine(Tempstr, Session->ClientSock);
DestroyString(Tempstr);
}


void HandleRMD(TSession *Session, char *Path)
{
char *Tempstr=NULL;

if (access(Path,F_OK)!=0) Tempstr=MCopyStr(Tempstr,"550 ERROR: \"",Path,"\" NO SUCH DIR",NULL);
else if (rmdir(Path)==0) Tempstr=MCopyStr(Tempstr,"224 \"",Path,"\" deleted",NULL);
else Tempstr=MCopyStr(Tempstr,"425 ERROR: \"",Path,"\" FAILED TO RMDIR",NULL);
SendLoggedLine(Tempstr, Session->ClientSock);
DestroyString(Tempstr);
}


int RDelete(char *Path)
{
char *Tempstr=NULL, *ptr, *eptr;
glob_t Glob;
struct stat Stat;
int i, result=TRUE;;

Tempstr=MCopyStr(Tempstr,Path,"/*",NULL);
glob(Tempstr,GLOB_PERIOD,0,&Glob);

for (i=0; i < Glob.gl_pathc; i++)
{
	ptr=Glob.gl_pathv[i];
	stat(ptr,&Stat);
	if (S_ISDIR(Stat.st_mode)) 
	{
		eptr=strrchr(ptr,'/');
		if (! eptr) eptr=ptr;

		if (
					(strcmp(eptr,"/.") !=0) &&
					(strcmp(eptr,"/..") !=0) 
			)
			{
				if (! RDelete(ptr)) result=FALSE;
			}
	}
	else if (unlink(ptr) !=0) result=FALSE;
}

if (rmdir(Path)!=0) result=FALSE;

globfree(&Glob);
DestroyString(Tempstr);
return(result);
}


void HandleRMDA(TSession *Session, char *Path)
{
char *Tempstr=NULL;

SendLoggedLine("150 Starting Recursive Delete", Session->ClientSock);
if (access(Path,F_OK)!=0) Tempstr=MCopyStr(Tempstr,"550 ERROR: \"",Path,"\" NO SUCH DIR",NULL);
else if (RDelete(Path)) Tempstr=MCopyStr(Tempstr,"224 \"",Path,"\" deleted",NULL);
else Tempstr=MCopyStr(Tempstr,"425 ERROR: \"",Path,"\" FAILED TO RMDIR",NULL);
SendLoggedLine(Tempstr, Session->ClientSock);

DestroyString(Tempstr);
}


unsigned long RSize(char *Path)
{
char *ptr, *eptr;
unsigned long Size=0;
struct stat Stat;
glob_t Glob;
int i;
char *Tempstr=NULL;

Tempstr=MCopyStr(Tempstr,Path,"/*",NULL);
glob(Tempstr,GLOB_PERIOD,0,&Glob);

for (i=0; i < Glob.gl_pathc; i++)
{
	ptr=Glob.gl_pathv[i];
	stat(ptr,&Stat);
	if (S_ISDIR(Stat.st_mode)) 
	{
		eptr=strrchr(ptr,'/');
		if (! eptr) eptr=ptr;

		if (
					(strcmp(eptr,"/.") !=0) &&
					(strcmp(eptr,"/..") !=0) 
			)
			{
				Size+=RSize(ptr);
			}
	}
	else Size+=Stat.st_size;
}

globfree(&Glob);

DestroyString(Tempstr);

return(Size);
}


void HandleDSIZ(TSession *Session, char *File)
{
struct stat Stat;
char *Tempstr=NULL;
int Size;

	if (stat(File,&Stat)==-1) SendLoggedLine("550 ERROR: NO SUCH DIR",Session->ClientSock);
  else
	{
		if (S_ISDIR(Stat.st_mode)) Size=RSize(File);
		else Size=Stat.st_size;

		Tempstr=FormatStr(Tempstr,"213 %d",Size);
		SendLoggedLine(Tempstr, Session->ClientSock);
	}

DestroyString(Tempstr);
}


void HandleSIZE(TSession *Session, char *File)
{
struct stat Stat;
char *Tempstr=NULL;

	if (stat(File,&Stat)==-1) SendLoggedLine("550 ERROR: NO SUCH FILE",Session->ClientSock);
  else
	{
		Tempstr=FormatStr(Tempstr,"213 %d",Stat.st_size);
		SendLoggedLine(Tempstr, Session->ClientSock);
	}

DestroyString(Tempstr);
}

void HandleALLO(TSession *Session, char *Args)
{
char *Tempstr=NULL;
double Avail=0, Req=0;

		Req=strtof(Args,NULL);
		Avail=GetDiskAvailable();
		if (Avail < Req) Tempstr=FormatStr(Tempstr,"501 %.0f bytes available, insufficient space",Avail);
    else Tempstr=FormatStr(Tempstr,"200 %.0f bytes available",Avail);

		SendLoggedLine(Tempstr, Session->ClientSock);
DestroyString(Tempstr);
}

void HandleAVBL(TSession *Session)
{
char *Tempstr=NULL;
double Avail;

		Avail=GetDiskAvailable();
    Tempstr=FormatStr(Tempstr,"213 %.0f bytes (%s) Available",Avail,GetHumanReadableDataQty(Avail,0));
    SendLoggedLine(Tempstr, Session->ClientSock);

DestroyString(Tempstr);
}

void HandleCLNT(TSession *Session, char *Arg)
{
SetVar(Session->Vars,"ClientProgram",Arg);
LogToFile(Settings.LogPath,"Client Program: %s",Arg);
SendLoggedLine("200 Thanks for sharing that with me", Session->ClientSock);
}



void HandlePORT(TSession *Session, char *PortStr)
{
char *Address=NULL;
int Port;

DecodePORTStr(PortStr,&Address, &Port);
AddDataConnection(Session, DC_OUTGOING, Address, Port);
SendLoggedLine("200 OK", Session->ClientSock);
DestroyString(Address);
}



void HandlePASV(TSession *Session)
{
TDataConnection *DC;

DC=AddDataConnection(Session, DC_INCOMING, "", 0);
FTP_BindDataConnection(Session->ClientSock, Session->LocalIP, DC, "227 Entering Passive Mode ($(DestAddressCSV),$(DestPortHi),$(DestPortLow))");

}


void HandleEPSV(TSession *Session)
{
TDataConnection *DC;

DC=AddDataConnection(Session, DC_INCOMING, "", 0);
FTP_BindDataConnection(Session->ClientSock, Session->LocalIP, DC, "229 Entering Extended Passive Mode (|||$(DestPort)|)");
}



char *DirFormatFileMode(int FileMode)
{
static char *ModLine=NULL;
int len;

len=0;

if (FileMode & S_IFDIR) ModLine=AddCharToBuffer(ModLine,len,'d');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;

if (FileMode & S_IRUSR) ModLine=AddCharToBuffer(ModLine,len,'r');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;

if (FileMode & S_IWUSR) ModLine=AddCharToBuffer(ModLine,len,'w');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;

if (FileMode & S_IXUSR) ModLine=AddCharToBuffer(ModLine,len,'x');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;

if (FileMode & S_IRGRP) ModLine=AddCharToBuffer(ModLine,len,'r');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;

if (FileMode & S_IWGRP) ModLine=AddCharToBuffer(ModLine,len,'w');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;

if (FileMode & S_IXGRP) ModLine=AddCharToBuffer(ModLine,len,'x');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;

if (FileMode & S_IROTH) ModLine=AddCharToBuffer(ModLine,len,'r');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;

if (FileMode & S_IWOTH) ModLine=AddCharToBuffer(ModLine,len,'w');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;

if (FileMode & S_IXOTH) ModLine=AddCharToBuffer(ModLine,len,'x');
else ModLine=AddCharToBuffer(ModLine,len,'-');
len++;



return(ModLine);
}



void SendDirItemInfo(TSession *Session, STREAM *DataCon, char *Path, int ListFormat)
{
struct stat FileData;
char *Tempstr=NULL;
char *UName=NULL, *GName=NULL;
unsigned long long filesize;


if (
    (ListFormat==LIST_LONG) ||
    (ListFormat==LIST_MLSD) ||
    (ListFormat==LIST_STAT)
  )
{
   stat(Path,&FileData);
   Tempstr=FormatStr(Tempstr,"%d",FileData.st_uid);
   UName=IPCRequest(UName, Session, "GetUserName", Tempstr);
   Tempstr=FormatStr(Tempstr,"%d",FileData.st_gid);
   GName=IPCRequest(GName, Session, "GetGroupName", Tempstr);
	 filesize=(unsigned long long) FileData.st_size;

  if (ListFormat==LIST_MLSD)
  {
   if (S_ISDIR(FileData.st_mode)) Tempstr=FormatStr(Tempstr,"type=dir;modify=%s; %s",GetDateStrFromSecs("%Y%m%d%H%M%S",FileData.st_mtime,NULL),Path);
   else Tempstr=FormatStr(Tempstr,"type=file;size=%llu;modify=%s; %s",filesize,GetDateStrFromSecs("%Y%m%d%H%M%S",FileData.st_mtime,NULL),Path);
  }
  else
  {
   Tempstr=FormatStr(Tempstr,"%s % 3d % 8s % 8s % 8llu %s %s",DirFormatFileMode(FileData.st_mode),FileData.st_nlink,UName,GName,filesize,GetDateStrFromSecs("%b %d %H:%M",FileData.st_mtime,NULL),Path);
  }
}
else Tempstr=FormatStr(Tempstr,"%s",Path);

Tempstr=CatStr(Tempstr,"\r\n");
STREAMWriteLine(Tempstr,DataCon);

DestroyString(Tempstr);
DestroyString(UName);
DestroyString(GName);
}


void HandleLIST(TSession *Session, char *Args, int ListType)
{
glob_t myGlob;
struct stat Stat;
int count, result;
char *ptr, *Token=NULL, *Pattern=NULL;
STREAM *S=NULL;
TDataConnection *DC=NULL;

//Strip any command line switches out of Args
ptr=GetToken(Args,"\\S",&Token,GETTOKEN_QUOTES);
while (ptr)
{
	StripTrailingWhitespace(Token);
	StripLeadingWhitespace(Token);
	if (*Token!='-') Pattern=MCatStr(Pattern,Token," ",NULL);
	ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
}
StripTrailingWhitespace(Pattern);

if (StrLen(Pattern)==0)
{
 Pattern=CopyStr(Pattern,"*");
 result=-1;
}
else result=stat(Pattern,&Stat);

if ((result==0) && S_ISDIR(Stat.st_mode))
{
	if (strcmp(Pattern,".")==0) Pattern=CopyStr(Pattern,"*");
	else Pattern=CatStr(Pattern,"/*");
}
else
{
	//Must be an actual dir for MLSD
	if ((ListType==LIST_MLSD) && StrLen(Args))
	{
 			SendLoggedLine("501 NOT A DIRECTORY", Session->ClientSock);
			return;
	}
}

	if (ListType==LIST_STAT)
	{
  	SendLoggedLine("211-OK", Session->ClientSock);
		S=Session->ClientSock;
	}
	else
	{
  	DC=OpenDataConnection(Session,0);
		if (DC)
		{
			S=DC->Sock;
			DC->Output=S;
  		SendLoggedLine("150 OK Data Connection Established", Session->ClientSock);
		}
	}

	if (S)
  {
		if (! StrLen(Pattern)) glob("*",0,0,&myGlob);
		else glob(Pattern,0,0,&myGlob);

    for (count=0; count < myGlob.gl_pathc; count++)
    {
        SendDirItemInfo(Session,S,myGlob.gl_pathv[count], ListType);
    }
		STREAMFlush(S); //S might be the client sock if a STAT is called
    if (DC) CloseDataConnection(Session, DC);
		Session->DataConnection=NULL;
  }
	else SendLoggedLine("550 ERROR: CANNOT BUILD DATA CONNECTION", Session->ClientSock);

	//In all cases this final line goes out the control channel
  if (ListType ==LIST_STAT) SendLoggedLine("211 END", Session->ClientSock);
  else SendLoggedLine("250 END", Session->ClientSock);

  globfree(&myGlob);
	DestroyString(Pattern);
	DestroyString(Token);
}


void HandleMLST(TSession *Session, char *Pattern)
{

	if (access(Pattern,F_OK) !=0) SendLoggedLine("501 NO SUCH FILE", Session->ClientSock);
	else
	{
  SendLoggedLine("250-OK", Session->ClientSock);
  SendDirItemInfo(Session,Session->ClientSock,Pattern, LIST_MLSD);
  SendLoggedLine("250 End", Session->ClientSock);
	}

}


void HandleSetTime(TSession *Session, char *Path, char *TimeStr, char *SuccessCode)
{
char *Tempstr=NULL;
time_t NewTime;
struct utimbuf UT;

			Tempstr=CopyStr(Tempstr,TimeStr);    
			if (StrLen(Tempstr)==8) Tempstr=CatStr(Tempstr,"000000");
			if (StrLen(Tempstr)==12) Tempstr=CatStr(Tempstr,"00");
			NewTime=DateStrToSecs("%Y%m%d%H%M%S",Tempstr,NULL);
			UT.actime=NewTime;
			UT.modtime=NewTime;


			if (utime(Path,&UT)==0) 
			{
				Tempstr=MCopyStr(Tempstr,SuccessCode," Modification Time Changed for ",Path,NULL);
				SendLoggedLine(Tempstr,Session->ClientSock);
			}
			else SendErrno(Session, "550","ERROR: Utime failed", errno);

DestroyString(Tempstr);
}


void HandleMDTM(TSession *Session, char *Args)
{
struct stat Stat;
char *Tempstr=NULL, *ptr;

ptr=GetToken(Args," ",&Tempstr,0);

//if only one arg then send mtime
if (StrLen(ptr)==0)
{
	if (stat(Tempstr,&Stat) !=0) SendLoggedLine("550 ERROR: NO SUCH FILE", Session->ClientSock);
	else
	{
		Tempstr=FormatStr(Tempstr,"213 %s",GetDateStrFromSecs("%Y%m%d%H%M%S",Stat.st_mtime,NULL));
  SendLoggedLine(Tempstr, Session->ClientSock);
	}
}
else HandleSetTime(Session, ptr, Tempstr, "213");

DestroyString(Tempstr);
}



void HandleREST(TSession *Session, char *Arg)
{
char *Tempstr=NULL;

Tempstr=FormatStr(Tempstr,"%d",atoi(Arg));
SetVar(Session->Vars,"FileTransferRestartPosition",Tempstr);
Tempstr=FormatStr(Tempstr,"350 Restarting at %d",atoi(Arg));
SendLoggedLine(Tempstr,Session->ClientSock);

DestroyString(Tempstr);
}

int GetFileTransferRestartPosition(TSession *Session)
{
char *ptr;
//Seek to Retrieve Position
ptr=GetVar(Session->Vars,"FileTransferRestartPosition");
if (! StrLen(ptr)) return(0);
UnsetVar(Session->Vars,"FileTransferRestartPosition");
return(atoi(ptr));
}


void TarFunc(void *FilePattern)
{
	STREAM *S;

	S=STREAMFromFD(1);
	TarFiles(S, (char *) FilePattern);

	STREAMClose(S);
	exit(0);
}



void HandleRETR(TSession *Session, char *Path)
{
STREAM *InFile;
struct stat FStat;
int val;
TDataConnection *DC;

LogToFile(Settings.LogPath,"GET %s",Path);
if (Session->Flags & SESSION_TAR_STRUCTURE)
{
	InFile=STREAMCreate();
	PipeSpawnFunction(&InFile->out_fd,&InFile->in_fd, NULL, TarFunc, Path);
}
else
{
	if (stat(Path,&FStat) != 0)
	{
	   SendLoggedLine("550 ERROR: Can't access file",Session->ClientSock);
	   LogToFile(Settings.LogPath,"GET %s FAILED, No such file",Path);
		 return;
	}
	
	if (S_ISDIR(FStat.st_mode))
	{
	   SendLoggedLine("550 ERROR: Can't Retrieve Directories",Session->ClientSock);
	   LogToFile(Settings.LogPath,"GET %s FAILED, Is Directory",Path);
		 return;
	}
 InFile=STREAMOpenFile(Path, O_RDONLY);
}


if (! InFile)
{
   SendLoggedLine("550 ERROR: Can't open file",Session->ClientSock);
   LogToFile(Settings.LogPath,"GET %s FAILED",Path);
	 return;
}



//Check for any locks
val=FtpGetLock(Path,InFile->in_fd,READ_LOCK);

//if there's a mandatory lock on it, fail
if (val==FLAG_MLOCK)
{
   SendLoggedLine("550 ERROR: File is busy, someone is writing to it. Try later.",Session->ClientSock);
   LogToFile(Settings.LogPath,"GET %s FAILED, Is Mandatory Locked",Path);
	 STREAMClose(InFile);
	 return;
}



//if there's an advisory lock on it, warn
if (val==FLAG_ALOCK)
{
   SendLoggedLine("150-ADVISE: FILE IS LOCKED, you can still read it",Session->ClientSock);
   SendLoggedLine("150 but it may be garbled if someone is writing to it",Session->ClientSock);
   LogToFile(Settings.LogPath,"ADVISE: File %s Locked",Path);
}

//Seek to Retrieve Position
val=GetFileTransferRestartPosition(Session);
if (val > 0) 
{
	if (val > FStat.st_size) 
	{
		SendLoggedLine("554 ERROR: Bad Restart Position",Session->ClientSock);
	 	STREAMClose(InFile);
		return;
	}
STREAMSeek(InFile,val,SEEK_SET);
}


SendLoggedLine("150 OK", Session->ClientSock);

DC=OpenDataConnection(Session,0);
if (DC) 
{
	DC->Input=InFile;
	DC->Output=DC->Sock;
	DC->FileName=CopyStr(DC->FileName,Path);
	DC->Flags |= DC_RETR;
	Session->DataConnection=NULL;
	STREAMSetItem(InFile,"DataCon",DC);
	ListAddItem(Session->Connections,InFile);
}


}





void UnTarFunc(void *Nothing)
{
	STREAM *S;

	S=STREAMFromFD(0);
	TarUnpack(S);
	STREAMClose(S);
	exit(0);
}



void HandleSTOR(TSession *Session, char *Path, int Append)
{
TDataConnection *DC;
STREAM *OutFile;
int val=0;

	val=GetFileTransferRestartPosition(Session);

  LogToFile(Settings.LogPath,"PUT %s",Path);

	if (Session->Flags & SESSION_TAR_STRUCTURE)
	{
		OutFile=STREAMCreate();
		PipeSpawnFunction(&OutFile->out_fd,&OutFile->in_fd, NULL, UnTarFunc, Path);
	}
	else if (Append) OutFile=STREAMOpenFile(Path, O_WRONLY | O_CREAT | O_APPEND);
	else if (val > 0) 
	{
		OutFile=STREAMOpenFile(Path, O_WRONLY | O_CREAT );
		//Seek to Restart Position
		STREAMSeek(OutFile,val,SEEK_SET);
	}
	else OutFile=STREAMOpenFile(Path, O_WRONLY | O_CREAT | O_TRUNC);

	if (! OutFile)
	{
 		SendLoggedLine("550 ERROR: Failed to open file for writing.",Session->ClientSock);
 		LogToFile(Settings.LogPath,"PUT %s FAILED",Path);
		return;
	}

	//Check for any locks
	val=FtpGetLock(Path,OutFile->in_fd,WRITE_LOCK);


	//if there's a mandatory lock on it, fail
	if (val==FLAG_MLOCK)
	{
   SendLoggedLine("550 ERROR: File is busy, someone is reading/writing it. Try later.",Session->ClientSock);
   LogToFile(Settings.LogPath,"STOR %s FAILED, Is Mandatory Locks",Path);
	 STREAMClose(OutFile);
	 return;
	}

	chmod(Path,0666);
	//Check for any locks

  DC=OpenDataConnection(Session,0);
	if (DC)
  {
	//if there's a mandatory lock on it, fail
		if (val==FLAG_ALOCK)
		{
  	 SendLoggedLine("150-ADVISE: FILE IS LOCKED, you can still write it",Session->ClientSock);
  	 SendLoggedLine("150 but you may ruin someone's day",Session->ClientSock);
  	 LogToFile(Settings.LogPath,"ADVISE: File %s Locked",Path);
		}
		else SendLoggedLine("150 OK Data Connection Established", Session->ClientSock);

		DC->Input=DC->Sock;
		DC->Output=OutFile;
		Session->DataConnection=NULL;
		STREAMSetItem(DC->Input,"DataCon",DC->Input);
		ListAddItem(Session->Connections,DC->Input);
  	DC->FileName=CopyStr(DC->FileName,Path);
  	DC->Flags |= DC_STOR;
		DC->BytesSent=(double) STREAMTell(OutFile);
  }
	else SendLoggedLine("500 Cannot build Data Connection", Session->ClientSock);

}



void HandleRNFR(TSession *Session, char *Path)
{
STREAM *InFile;


LogToFile(Settings.LogPath,"RNFR %s",Path);
if (access(Path,F_OK) !=0)
{
   SendLoggedLine("550 ERROR: rename from failed.",Session->ClientSock);
   LogToFile(Settings.LogPath,"RNFR %s FAILED",Path);
}

  SendLoggedLine("350 OK", Session->ClientSock);
  SetVar(Session->Vars,"RenameFromPath",Path);

}



void HandleRNTO(TSession *Session, char *Path)
{
char *Tempstr=NULL, *HookArgs=NULL, *ptr;

LogToFile(Settings.LogPath,"RNTO %s",Path);
ptr=GetVar(Session->Vars,"RenameFromPath");

if (! StrLen(ptr)) SendLoggedLine("550 ERROR: RNFR must be used first to set file to be renamed", Session->ClientSock);
else if (rename(ptr,Path)==0)
{
  SendLoggedLine("250 OK", Session->ClientSock);
	HookArgs=MCopyStr(HookArgs,"Rename"," '",ptr,"' '",Path,"'",NULL);
	Tempstr=IPCRequest(Tempstr, Session, "RunHook", HookArgs);
	UnsetVar(Session->Vars,"RenameFromPath");
}
else SendLoggedLine("550 ERROR: Rename Failed", Session->ClientSock);

DestroyString(Tempstr);
DestroyString(HookArgs);
}


void HandleMODE(TSession *Session, char *Mode)
{
if (strcasecmp(Mode,"Z")==0) 
{
	Session->Flags |= SESSION_COMPRESSED_TRANSFERS;
  SendLoggedLine("200 Compressed mode active", Session->ClientSock);
}
else if (strcasecmp(Mode,"S")==0) 
{
	Session->Flags &= ~SESSION_COMPRESSED_TRANSFERS;
  SendLoggedLine("200 STREAM mode active", Session->ClientSock);
}
else SendLoggedLine("550 ERROR: Unknown Transfer Mode", Session->ClientSock);

}


void HandleSTRU(TSession *Session, char *Mode)
{
if (strcasecmp(Mode,"F")==0) 
{
	Session->Flags &= ~SESSION_TAR_STRUCTURE;
  SendLoggedLine("200 Standard file structure active", Session->ClientSock);
}
else if (strcasecmp(Mode,"T")==0) 
{
	Session->Flags |= SESSION_TAR_STRUCTURE;
  SendLoggedLine("200 'TAR' file structure active", Session->ClientSock);
}
else SendLoggedLine("550 ERROR: Unknown file structure", Session->ClientSock);

}



void HandleSITE_PROXY(TSession *Session, char *Args)
{
char *Host=NULL, *ptr;
int Port=21;

ptr=GetToken(Args," ",&Host,0);
if (ptr)
{
    if (atoi(ptr) > 0) Port=atoi(ptr);
}

LogToFile(Settings.LogPath,"Switching to Proxy mode, connecting to %s",Args);
if (ProxyControlConnect(Session, Host, Port)) Session->Flags |= SESSION_FTP_PROXY;

DestroyString(Host);
}

void HandleSITE_SYMLINK(TSession *Session,char *Args)
{
char *From=NULL, *To=NULL, *ptr;

ptr=GetToken(Args,"\\S",&From,GETTOKEN_QUOTES);
ptr=GetToken(ptr,"\\S",&To,GETTOKEN_QUOTES);
if (symlink(From,To)==0) FtpSendResponse(Session,"250", "Symlink Created");
else SendErrno(Session, "550", "ERROR: Symlink failed", errno);

DestroyString(From);
DestroyString(To);
}

void HandleSITE_CHMOD(TSession *Session,char *Args)
{
char *Mod=NULL, *Path=NULL, *ptr;

ptr=GetToken(Args,"\\S",&Mod,GETTOKEN_QUOTES);
ptr=GetToken(ptr,"\\S",&Path,GETTOKEN_QUOTES);
if (chmod(Path,strtol(Mod,NULL,8))==0) FtpSendResponse(Session,"250","File mode changed");
else SendErrno(Session, "550", "ERROR: Chmod failed", errno);

DestroyString(Path);
DestroyString(Mod);
}


void HandleSITE_UMASK(TSession *Session,char *Args)
{
char *Mod=NULL, *ptr;
int val;

ptr=GetToken(Args,"\\S",&Mod,GETTOKEN_QUOTES);
if (StrLen(Mod)==0) 
{
	val=umask(0);
	umask(val);
	Mod=FormatStr(Mod,"250 %o (current umask)",val);
	SendLoggedLine(Mod,Session->ClientSock);
}
else if (umask(strtol(Mod,NULL,8))==0) SendLoggedLine("250 Umask changed",Session->ClientSock);
else SendErrno(Session, "550", "ERROR: Umask change failed", errno);

DestroyString(Mod);
}


void HandleSITE_UTIME(TSession *Session,char *Args)
{
char *Token=NULL, *Path=NULL, *ptr;

ptr=GetToken(Args," ",&Token,0);
if (StrLen(ptr) > 24)
{
		Path=CopyStr(Path,Token);
   	ptr=GetToken(ptr," ",&Token,0);
}
else ptr=GetToken(ptr," ",&Path,0);

if (! StrLen(ptr)) SendLoggedLine("550 ERROR: UTIME Parse failure",Session->ClientSock);
else HandleSetTime(Session, Path, Token, "250");

DestroyString(Token);
DestroyString(Path);
}


void HandleSITE_ZONE(TSession *Session,char *Args)
{
char *Tempstr=NULL;

//Timezone variable is in seconds!
Tempstr=FormatStr(Tempstr,"250 UTC%+d",timezone/3600);
SendLoggedLine(Tempstr,Session->ClientSock);

DestroyString(Tempstr);
}


void HandleSITE_WHO(TSession *Session,char *Args)
{
char *Tempstr=NULL, *Info=NULL;

Tempstr=IPCRequest(Tempstr, Session, "Who", "");
Info=MCopyStr(Info,"250 ",Tempstr,NULL);
SendLoggedLine(Info,Session->ClientSock);

DestroyString(Tempstr);
DestroyString(Info);
}


void HandleSITE_TIME(TSession *Session,char *Args)
{
char *Tempstr=NULL, *Info=NULL;

if (! StrLen(Args)) Tempstr=CopyStr(Tempstr, GetDateStr("%c %Z",NULL));
else Tempstr=CopyStr(Tempstr, GetDateStr(Args,NULL));
Info=MCopyStr(Info,"250 ",Tempstr,NULL);
SendLoggedLine(Info,Session->ClientSock);

DestroyString(Tempstr);
DestroyString(Info);
}



void HandleSITE(TSession *Session, char *Arg)
{
char *Tempstr=NULL;
char *ptr;

//some clients put the name of the command in quotes
ptr=GetToken(Arg," ",&Tempstr,GETTOKEN_QUOTES);

if (strcasecmp(Tempstr,"PROXY")==0) HandleSITE_PROXY(Session,ptr);
else if (strcasecmp(Tempstr,"SYMLINK")==0) HandleSITE_SYMLINK(Session,ptr);
else if (strcasecmp(Tempstr,"CHMOD")==0) HandleSITE_CHMOD(Session,ptr);
else if (strcasecmp(Tempstr,"UTIME")==0) HandleSITE_UTIME(Session,ptr);
else if (strcasecmp(Tempstr,"UMASK")==0) HandleSITE_UMASK(Session,ptr);
else if (strcasecmp(Tempstr,"ZONE")==0) HandleSITE_ZONE(Session,ptr);
else if (strcasecmp(Tempstr,"WHO")==0) HandleSITE_WHO(Session,ptr);
else if (strcasecmp(Tempstr,"TIME")==0) HandleSITE_TIME(Session,ptr);
else if (strcasecmp(Tempstr,"IDLE")==0) 
{
	Settings.DefaultIdle=atoi(ptr);
	Tempstr=FormatStr(Tempstr,"211 Idle timeout set to %d secs",Settings.DefaultIdle);
	SendLoggedLine(Tempstr,Session->ClientSock);
}
else SendLoggedLine("500 Command not recognized",Session->ClientSock);

DestroyString(Tempstr);
}




void HandleFEAT(TSession *Session, char *Arg)
{
char *Tempstr=NULL;
char *Features[]={"ALLO","AVBL","CLNT","DSIZ","MDTM","MLSD","MLST type*;size*;modify*;","PASV","REST STREAM","PASV","REIN","RDMA","SITE CHMOD","SITE IDLE","SITE SYMLINK","SITE PROXY","SITE UMASK","SITE UTIME","SITE ZONE","SITE TIME","SIZE","STRU F;T","MD5","XMD5","XCRC","XSHA","XSHA1","XSHA256","XSHA512",NULL};
int i;

SendLoggedLine("211-Feature listing follows",Session->ClientSock);
for (i=0; Features[i] !=NULL; i++)
{
Tempstr=MCopyStr(Tempstr," ",Features[i],NULL);
SendLoggedLine(Tempstr,Session->ClientSock);
}

if (DataProcessorAvailable("compression","zlib")) SendLoggedLine(" MODE Z",Session->ClientSock);

Tempstr=CopyStr(Tempstr," HASH ");
for (i=0; HashTypes[i] !=NULL; i++)
{
Tempstr=MCatStr(Tempstr,HashTypes[i],";",NULL);
}
SendLoggedLine(Tempstr,Session->ClientSock);

SendLoggedLine("211 End",Session->ClientSock);

DestroyString(Tempstr);
}


void HandleSTAT(TSession *Session)
{
char *Tempstr=NULL;

Tempstr=MCopyStr(Tempstr,"211-Status for user ",Session->User," from ",Session->ClientIP,":",NULL);
SendLoggedLine(Tempstr,Session->ClientSock);

Tempstr=MCopyStr(Tempstr,"    Connected to: ",Session->DestIP,NULL);
SendLoggedLine(Tempstr,Session->ClientSock);

if (Session->Flags & SESSION_ASCII_TRANSFERS) Tempstr=CopyStr(Tempstr,"    TransferType: ASCII");
else Tempstr=CopyStr(Tempstr,"    TransferType: BINARY");
SendLoggedLine(Tempstr,Session->ClientSock);

if (Session->Flags & SESSION_COMPRESSED_TRANSFERS) Tempstr=CopyStr(Tempstr,"    TransferMode: Z (Zlib Compressed)");
else Tempstr=CopyStr(Tempstr,"    TransferMode: S (Stream)");
SendLoggedLine(Tempstr,Session->ClientSock);

Tempstr=FormatStr(Tempstr,"    Session timeout: %d seconds",Settings.DefaultIdle);
SendLoggedLine(Tempstr,Session->ClientSock);

if (Settings.MaxFileSize > 0)
{
Tempstr=FormatStr(Tempstr,"    Max File Size: %d bytes",Settings.MaxFileSize);
SendLoggedLine(Tempstr,Session->ClientSock);
}

SendLoggedLine("211 End",Session->ClientSock);
STREAMFlush(Session->ClientSock);

DestroyString(Tempstr);

}



int CheckFeaturePermitted(TSession *Session, char *Command)
{
char *Token=NULL, *p_Feature, *ptr;
int result=FALSE;

if (StrLen(Settings.PermittedCommands)==0) return(TRUE);
ptr=GetToken(Settings.PermittedCommands,",",&Token,0);

while (ptr)
{
	p_Feature=Token;
	if ((*p_Feature=='-') || (*p_Feature=='+')) p_Feature++;

	if(
			(strcasecmp(p_Feature,Command)==0) ||
	 		(strcasecmp(p_Feature,"ALL")==0)
		)
	{
		if (*Token=='-') result=FALSE;
		else result=TRUE;
	}
	ptr=GetToken(ptr,",",&Token,0);
}

DestroyString(Token);
return(result);
}






void HandleModeOPTS(TSession *Session, char *Args)
{
char *ptr, *Token=NULL, *OptName=NULL;


ptr=GetToken(Args,"\\S",&Token,0);
if (strcasecmp(Token,"Z")==0)
{

	ptr=GetToken(ptr,"\\S",&Token,0);

	if (strcasecmp(Token,"LEVEL")==0)
	{
		ptr=GetToken(ptr,"\\S",&Token,0);
		SetVar(Session->Vars,"Opt:Mode Z:Level",Token);
		SendLoggedLine("200 Option set",Session->ClientSock); 
	}
	else SendLoggedLine("501 ERROR: Not Supported",Session->ClientSock); 

}
else SendLoggedLine("501 ERROR: Not Supported",Session->ClientSock); 

DestroyString(OptName);
DestroyString(Token);
}


void HandleHashOPTS(TSession *Session, char *Args)
{
char *Token=NULL, *ptr;

	if (StrLen(Args)==0) 
	{
		ptr=GetVar(Session->Vars,"Opt:HASH");
		Token=MCopyStr(Token,"200 ",ptr,NULL);
		SendLoggedLine(Token,Session->ClientSock); 
	}
	else
	{
		ptr=GetToken(Args,"\\S",&Token,0);
		if (MatchTokenFromList(Token,HashTypes,0) > -1)
		{
			SetVar(Session->Vars,"Opt:HASH",Token);
			SendLoggedLine("200 Option set",Session->ClientSock); 
		}
		else SendLoggedLine("501 ERROR: Not Supported",Session->ClientSock); 
	}

DestroyString(Token);
}


void HandleOPTS(TSession *Session, char *Args)
{
char *ptr, *Token=NULL;

ptr=GetToken(Args,"\\S",&Token,0);

if (StrLen(Token))
{
if (strcasecmp(Token,"MODE")==0) HandleModeOPTS(Session,ptr);
else if (strcasecmp(Token,"HASH")==0) HandleHashOPTS(Session,ptr);
else if (strcasecmp(Token,"utf8")==0) SendLoggedLine("501 ERROR: Not Supported",Session->ClientSock); 
else SendLoggedLine("501 ERROR: UNKNOWN OPTION",Session->ClientSock); 

}

DestroyString(Token);
}


void DoCommand(TSession *Session, char *Command, char *Arg)
{
int cmd, val;
char *Tempstr=NULL, *ptr;

cmd=MatchTokenFromList(Command, FtpCommandStrings,0);

if (
	(! (Session->Flags & SESSION_AUTHENTICATED)) && 
	(
		(cmd !=CMD_USER) &&
		(cmd !=CMD_PASS) &&
		(cmd !=CMD_FEAT) &&
		(cmd !=CMD_NOOP) &&
		(cmd !=CMD_QUIT) 
	)
   )
{
	STREAMWriteLine("530 ERROR: Please log in first\r\n",Session->ClientSock); 
	LogToFile(Settings.ServerLogPath,"530 ERROR: Please log in first");
	return;
}
	
//PASS gets logged in 'LogonUser'
if (cmd != CMD_PASS)  
{
	if (Session->Flags & SESSION_AUTHENTICATED) LogToFile(Settings.LogPath,"RCV: %s '%s'",Command,Arg);
	else LogToFile(Settings.ServerLogPath,"RCV: %s '%s'",Command,Arg);
}

if (! CheckFeaturePermitted(Session, Command)) cmd=CMD_DENIED;

switch (cmd)
{
case CMD_REIN: HandleREIN(Session); break;
case CMD_USER: 
	HandleUSER(Session, Arg);  
	sprintf(CmdLine,"%s %s@%s",ProgName,Session->User,Session->ClientIP);
	break;

case CMD_PASS: HandlePASS(Session, Arg); break;
case CMD_PORT: HandlePORT(Session, Arg); break;
case CMD_PASV: HandlePASV(Session); break;
case CMD_EPSV: HandleEPSV(Session); break;
case CMD_SYST: HandleSYST(Session); break;
case CMD_SITE: HandleSITE(Session, Arg); break;
case CMD_FEAT: HandleFEAT(Session, Arg); break;

case CMD_RNFR: HandleRNFR(Session,Arg); break;
case CMD_RNTO: HandleRNTO(Session,Arg); break;

case CMD_TYPE: HandleTYPE(Session, Arg); break;
case CMD_XCWD:
case CMD_CWD: HandleCWD(Session, Arg); break;
case CMD_XCUP:
case CMD_CDUP: HandleCWD(Session,".."); break;
case CMD_XPWD:
case CMD_PWD: HandlePWD(Session); break;
case CMD_XMKD:
case CMD_MKD: HandleMKD(Session,Arg); break;
case CMD_XRMD:
case CMD_RMD: HandleRMD(Session,Arg); break;
case CMD_RMDA: HandleRMDA(Session,Arg); break;
case CMD_REST: HandleREST(Session,Arg); break;
case CMD_RETR: HandleRETR(Session,Arg); break;
case CMD_APPE: HandleSTOR(Session,Arg,TRUE); break;
case CMD_STOR: HandleSTOR(Session,Arg, FALSE); break;
case CMD_XDEL: 
case CMD_DELE: HandleDELE(Session, Arg); break;
case CMD_LIST: HandleLIST(Session, Arg, LIST_LONG); break;
case CMD_NLST: HandleLIST(Session, Arg, LIST_SHORT); break;
case CMD_MLSD: HandleLIST(Session, Arg, LIST_MLSD); break;
case CMD_STAT:
	if (StrLen(Arg)) HandleLIST(Session, Arg, LIST_STAT);
	else HandleSTAT(Session);
 break;
case CMD_MLST: HandleMLST(Session, Arg); break;
case CMD_MDTM: HandleMDTM(Session, Arg); break;
case CMD_DSIZ: HandleDSIZ(Session, Arg); break;
case CMD_SIZE: HandleSIZE(Session, Arg); break;
case CMD_MODE: HandleMODE(Session, Arg); break;
case CMD_STRU: HandleSTRU(Session, Arg); break;
case CMD_AVBL: HandleAVBL(Session); break;
case CMD_ALLO: HandleALLO(Session,Arg); break;
case CMD_CLNT: HandleCLNT(Session,Arg); break;
case CMD_XMD5: HandleHASHXMD5Style(Session, HASH_MD5 , Arg); break;
case CMD_XCRC: HandleHASHXMD5Style(Session, HASH_FTPCRC , Arg); break;
case CMD_MD5: HandleHASH(Session, HASH_FTPMD5, Arg,0,0); break;
case CMD_XSHA: HandleHASH(Session, HASH_SHA1, Arg,0,0); break;
case CMD_XSHA1: HandleHASH(Session, HASH_SHA1, Arg,0,0); break;
case CMD_XSHA256: HandleHASH(Session, HASH_SHA256, Arg,0,0); break;
case CMD_XSHA512: HandleHASH(Session, HASH_SHA512, Arg,0,0); break;
case CMD_HASH: 
	ptr=GetVar(Session->Vars,"Opt:HASH");
	val=MatchTokenFromList(ptr,HashTypes, NULL);
	if (val==-1) val=HASH_MD5;
	HandleHASH(Session, val, Arg, 0, 0); 
break;
case CMD_OPTS: HandleOPTS(Session, Arg); break;
case CMD_NOOP: SendLoggedLine("200 OK",Session->ClientSock); break;
case CMD_QUIT: HandleQUIT(Session); break;

case CMD_DENIED:
default: 
	Tempstr=FormatStr(Tempstr, "500 ERROR: Unrecognized command '%s'",Command);
	SendLoggedLine(Tempstr,Session->ClientSock);
	LogToFile(Settings.LogPath,"500 ERROR: Unrecognized command '%s' '%s'",Command,Arg);
	 break;


}
STREAMFlush(Session->ClientSock);
DestroyString(Tempstr);
}

