#include "IPC.h"
#include "Settings.h"

ListNode *IPCCache=NULL;


char *GetUserName(int UID)
{
struct passwd *pwent;

    pwent=getpwuid(UID);
		if (! pwent) return("");
		else return(pwent->pw_name);
}

char *GetGroupName(int GID)
{
struct group *grent;

    grent=getgrgid(GID);
		if (! grent) return("");
		else return(grent->gr_name);
}


extern ListNode *Sessions;

void SendWho(STREAM *S)
{
TSessionProcess *Proc;
ListNode *Curr;
char *Tempstr=NULL;

Curr=ListGetNext(Sessions);
while (Curr)
{
	Proc=(TSessionProcess *) Curr->Item;
	Tempstr=MCatStr(Tempstr," ",Proc->User,NULL);
	Curr=ListGetNext(Curr);
}
SendLoggedLine(Tempstr,S);

DestroyString(Tempstr);
}


void RunHook(char *Args)
{
char *Tempstr=NULL, *Type=NULL;
char *ScriptPath=NULL, *ScriptUser=NULL, *ScriptDir=NULL;
char *p_HookConfig=NULL, *ptr, *sptr;
pid_t pid=-1;


if (! Args) return;

ptr=GetToken(Args," ",&Type,GETTOKEN_QUOTES);

if (strcmp(Type,"Upload")==0) p_HookConfig=Settings.UploadHook;
else if (strcmp(Type,"Download")==0) p_HookConfig=Settings.DownloadHook;
else if (strcmp(Type,"Rename")==0) p_HookConfig=Settings.RenameHook;
else if (strcmp(Type,"Delete")==0) p_HookConfig=Settings.DeleteHook;
else if (strcmp(Type,"Login")==0) p_HookConfig=Settings.LoginHook;
else if (strcmp(Type,"Logout")==0) p_HookConfig=Settings.LogoutHook;
else if (strcmp(Type,"ConnectUp")==0) p_HookConfig=Settings.ConnectUpHook;
else if (strcmp(Type,"ConnectDown")==0) p_HookConfig=Settings.ConnectDownHook;

if (p_HookConfig) 
{
	sptr=GetToken(p_HookConfig,",",&ScriptPath,GETTOKEN_QUOTES);
	sptr=GetToken(sptr,",",&ScriptUser,GETTOKEN_QUOTES);
	sptr=GetToken(sptr,",",&ScriptDir,GETTOKEN_QUOTES);

	Tempstr=MCopyStr(Tempstr,ScriptPath, " ", ptr, NULL);
	//RunStr=MakeShellSafeString(RunStr, Tempstr, 0);
	pid=Spawn(Tempstr, ScriptUser, "", ScriptDir);

	if (pid > -1)  
	{
		LogToFile(Settings.ServerLogPath,"Running Hook Script: %s",Tempstr);
		if ((p_HookConfig==Settings.ConnectUpHook) || (p_HookConfig==Settings.ConnectDownHook)) waitpid(pid,NULL,0);
	}
	else LogToFile(Settings.ServerLogPath,"ERROR: Hook Script: %s Failed to run",Tempstr);
}

DestroyString(Tempstr);
DestroyString(Type);
}



char *IPCProcessRequest(char *RetStr, TSessionProcess *Proc, char *InfoType, char *Arg)
{
char *Tempstr=NULL;

Tempstr=CopyStr(RetStr,"");

if (strcmp(InfoType,"GetIP")==0) Tempstr=MCopyStr(Tempstr,LookupHostIP(Arg),"\n",NULL);
else if (strcmp(InfoType,"GetUserName")==0) Tempstr=MCopyStr(Tempstr,GetUserName(atoi(Arg)),"\n",NULL);
else if (strcmp(InfoType,"GetGroupName")==0) Tempstr=MCopyStr(Tempstr,GetGroupName(atoi(Arg)),"\n",NULL);
else if (strcmp(InfoType,"RunHook")==0) 
{
	RunHook(Arg);
	Tempstr=CopyStr(Tempstr,"OKAY\n");
}
else if (strcmp(InfoType,"LoggedOn")==0)
{
	//This doesn't lookup data, it just registers that they're logged on
	if (Proc)
	{
	Proc->User=CopyStr(Proc->User,Arg);
	time(&Proc->LogonTime);
	}
	Tempstr=CopyStr(Tempstr,"OKAY\n");
}
//else if (strcmp(Token,"Who")==0) SendWho(Proc->S);
else Tempstr=CopyStr(Tempstr,"ERROR: Unknown Request\n");

return(Tempstr);
}




int IPCHandleRequest(TSessionProcess *Proc)
{
char *Tempstr=NULL, *Response=NULL, *Token=NULL, *ptr;

Tempstr=STREAMReadLine(Tempstr,Proc->S);
if (Tempstr==NULL) return(FALSE);
StripTrailingWhitespace(Tempstr);

ptr=GetToken(Tempstr,":",&Token,0);
while (isspace(*ptr)) ptr++;

Response=IPCProcessRequest(Response,Proc, Token, ptr);
STREAMWriteLine(Response,Proc->S);
STREAMFlush(Proc->S);

DestroyString(Tempstr);
DestroyString(Response);
DestroyString(Token);

return(TRUE);
}



char *IPCRequest(char *Buffer, TSession *Session, char *InfoType, char *Arg)
{
char *Tempstr=NULL, *RetStr=NULL, *ptr=NULL;

if (! Session->IPCCon) 
{
	RetStr=IPCProcessRequest(Buffer,NULL, InfoType, Arg);
	StripTrailingWhitespace(RetStr);
	return(RetStr);
}


if (! IPCCache) IPCCache=ListCreate();

Tempstr=MCopyStr(Tempstr,InfoType, ": ",Arg,"\n",NULL);


//ptr must == NULL here, because we use it to decide if we
//got a carched value
ptr=NULL;

if (strncmp(InfoType,"Get",3) ==0) ptr=GetVar(IPCCache,Tempstr);

if (ptr) RetStr=CopyStr(Buffer,ptr);
else
{
	STREAMWriteLine(Tempstr,Session->IPCCon);
	RetStr=STREAMReadLine(Buffer,Session->IPCCon);
	StripTrailingWhitespace(RetStr);
	if (strncmp(InfoType,"Get",3) ==0) SetVar(IPCCache,Tempstr,RetStr);
}

DestroyString(Tempstr);

return(RetStr);
}


