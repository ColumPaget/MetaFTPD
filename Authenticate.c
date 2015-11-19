#include "Authenticate.h"
#include "Settings.h"
#include <pwd.h>


#define ENC_MD5_HEX 0
#define ENC_MD5_BASE64 1

#include <stdio.h> /* For NULL */

#ifdef HAVE_LIBCRYPT
#include <crypt.h>
#endif


#ifdef HAVE_LIBPAM
#include <security/pam_appl.h>
static pam_handle_t *pamh=NULL;
#endif

#define USER_UNKNOWN -1

char *AuthenticationsTried=NULL;

int CheckUserExists(char *UserName)
{
TSession *Session;
int result=FALSE;

if (! UserName) return(FALSE);

Session=(TSession *) calloc(1,sizeof(TSession));
Session->User=CopyStr(Session->User,UserName);
Session->Passwd=CopyStr(Session->Passwd,"");

if (AuthPasswdFile(Session) != USER_UNKNOWN) result=TRUE;
if (AuthShadowFile(Session) != USER_UNKNOWN) result=TRUE;
if (AuthNativeFile(Session) != USER_UNKNOWN) result=TRUE;

DestroyString(Session->User);
DestroyString(Session->Passwd);

free(Session);

return(result);
}



int CheckServerAllowDenyLists(char *UserName)
{
char *ptr, *Token=NULL;

if (StrLen(Settings.DenyUsers))
{
ptr=GetToken(Settings.DenyUsers,"\\S",&Token,GETTOKEN_QUOTES);

while (ptr)
{
	if (strcmp(Token,UserName)==0)
	{
		LogToFile(Settings.ServerLogPath,"UserName '%s' in 'DenyUsers' list. Login Denied",UserName);
		DestroyString(Token);
		return(FALSE);
	}
	ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
}

}

if (! StrLen(Settings.AllowUsers))
{
DestroyString(Token);
return(TRUE);
}

ptr=GetToken(Settings.AllowUsers,"\\S",&Token,GETTOKEN_QUOTES);
while (ptr)
{
	if (strcmp(Token,UserName)==0)
	{
		LogToFile(Settings.ServerLogPath,"UserName '%s' Found in 'AllowUsers' list.",UserName);
		DestroyString(Token);
		return(TRUE);
	}
	ptr=GetToken(ptr,"\\S",&Token,GETTOKEN_QUOTES);
}

return(FALSE);
}




int AuthPasswdFile(TSession *Session)
{
struct passwd *pass_struct;
char *ptr;

AuthenticationsTried=CatStr(AuthenticationsTried,"passwd ");
pass_struct=getpwnam(Session->User);
if (pass_struct==NULL) return(USER_UNKNOWN);

#ifdef HAVE_LIBCRYPT

if (pass_struct->pw_passwd && Session->Passwd)
{
	ptr=crypt(Session->Passwd,pass_struct->pw_passwd);
	if (ptr && (strcmp(pass_struct->pw_passwd, ptr)==0))
	{
		Session->RealUser=CopyStr(Session->RealUser,Session->User);
		Session->HomeDir=CopyStr(Session->HomeDir,pass_struct->pw_passwd);
		return(TRUE);
	}
}

#endif

return(FALSE);
}


int AuthShadowFile(TSession *Session)
{
char *sptr, *eptr, *Salt=NULL, *Digest=NULL;
int result=FALSE;

#ifdef HAVE_SHADOW_H
#include <shadow.h>
struct spwd *pass_struct=NULL;

AuthenticationsTried=CatStr(AuthenticationsTried,"shadow ");
pass_struct=getspnam(Session->User);

if (pass_struct==NULL) return(USER_UNKNOWN);

sptr=pass_struct->sp_pwdp;

#ifdef HAVE_LIBCRYPT

// this is an md5 password
if (
	(StrLen(sptr) > 4) && 
	(strncmp(sptr,"$1$",3)==0)
   )
{
	eptr=strchr(sptr+3,'$');
  Salt=CopyStrLen(Salt,sptr,eptr-sptr);

  Digest=CopyStr(Digest, crypt(Session->Passwd,Salt));
  if (strcmp(Digest,sptr)==0) 
	{
		result=TRUE;
	}
}
else
{
   // assume old des crypt password
   if (Session->Passwd)
   {
   sptr=crypt(Session->Passwd,pass_struct->sp_pwdp);
   if (sptr && (strcmp(pass_struct->sp_pwdp, sptr)==0))
   {
      result=TRUE;
   }
	}
}


#endif

if (result) Session->RealUser=CopyStr(Session->RealUser,Session->User);

#endif
DestroyString(Salt);
DestroyString(Digest);

return(result);
}


#ifdef HAVE_LIBPAM

/* PAM works in a bit of a strange way, insisting on having a callback */
/* function that it uses to prompt for the password. We have arranged  */
/* to have the password passed in as the 'appdata' arguement, so this  */
/* function just passes it back!                                       */

int PAMConvFunc(int NoOfMessages, const struct pam_message **messages, 
         struct pam_response **responses, void *appdata)
{
int count;
const struct pam_message *mess;
struct pam_response *resp;

*responses=(struct pam_response *) calloc(NoOfMessages,sizeof(struct pam_response));

mess=*messages;
resp=*responses;

for (count=0; count < NoOfMessages; count++)
{
if ((mess->msg_style==PAM_PROMPT_ECHO_OFF) ||
    (mess->msg_style==PAM_PROMPT_ECHO_ON))
    {
      resp->resp=CopyStr(NULL,(char *) appdata); 
      resp->resp_retcode=0;
    }
mess++;
resp++;
}

return(PAM_SUCCESS);
}


int PAMStart(TSession *Session, const char *User)
{
static struct pam_conv  PAMConvStruct = {PAMConvFunc, NULL };
const char *PAMConfigs[]={"metaftpd","ftp","other",NULL};
int result=PAM_PERM_DENIED, i;

PAMConvStruct.appdata_ptr=(void *)Session->Passwd;

	for (i=0; (PAMConfigs[i] != NULL) && (result != PAM_SUCCESS); i++)
	{
		result=pam_start(PAMConfigs[i],User,&PAMConvStruct,&pamh);
	}	

	if (result==PAM_SUCCESS)
	{
	pam_set_item(pamh,PAM_RUSER,Session->User);
	if (StrLen(Session->ClientHost) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientHost);
	else if (StrLen(Session->ClientIP) > 0) pam_set_item(pamh,PAM_RHOST,Session->ClientIP);
	else pam_set_item(pamh,PAM_RHOST,"");
	return(TRUE);
	}

	return(FALSE);
}



int AuthPAM(TSession *Session)
{
int result;

AuthenticationsTried=CatStr(AuthenticationsTried,"pam ");


if(! PAMStart(Session, Session->User))
	{
		LogToFile(Settings.ServerLogPath,"PAM: No such user %s",Session->User);
  	return(USER_UNKNOWN);
	}

/* set the credentials for the remote user and remote host */

result=pam_authenticate(pamh,0);


if (result==PAM_SUCCESS)
{
	Session->Flags |= SESSION_PAM;
	Session->RealUser=CopyStr(Session->RealUser,Session->User);
	return(TRUE);
}
else return(FALSE);
}



int AuthPAMCheckSession(TSession *Session)
{
if (! pamh)
{
	if (! PAMStart(Session, Session->RealUser)) return(FALSE);
}
fprintf(stderr,"APCS!\n");

if (pam_acct_mgmt(pamh, 0)==PAM_SUCCESS) 
{
	pam_open_session(pamh, 0);
	return(TRUE);
}
return(FALSE);
}



void AuthPAMClose()
{
	if (pamh)
	{
	pam_close_session(pamh, 0);
	pam_end(pamh,PAM_SUCCESS);
	}
}
#endif



char *GetDefaultUser()
{
char *Possibilities[]={"nobody","daemon","guest",NULL};
TSession *Session;
int i;

Session=(TSession *) calloc(1,sizeof(TSession));

for (i=0; Possibilities[i] !=NULL; i++)
{
	Session->User=CopyStr(Session->User,Possibilities[i]);
	Session->Passwd=CopyStr(Session->Passwd,"");
	if (AuthPasswdFile(Session) != USER_UNKNOWN) break;
} 
    
return(Possibilities[i]);  
}


int CheckNativeFileChallengePassword(char *Challenge, char *Password, char *ProvidedPass)
{
char *Token=NULL, *Digest=NULL, *Tempstr=NULL, *ptr;
int RetVal=FALSE;

	if (strcmp(Password,ProvidedPass)==0) return(TRUE);

	if (! StrLen(Challenge)) return(FALSE);

	ptr=GetToken(Settings.AuthMethods,",",&Token,0);
	while (ptr)
	{
		if (strncmp(Token,"hp-",3)==0)
		{
		Tempstr=MCopyStr(Tempstr,Challenge,Password,NULL);
		HashBytes(&Digest,Token+3,Tempstr,StrLen(Tempstr),ENCODE_HEX);
		if (StrLen(Digest) && (strcasecmp(ProvidedPass, Digest)==0)) RetVal=TRUE;
		}
	ptr=GetToken(ptr,",",&Token,0);
	}

	DestroyString(Tempstr);
	DestroyString(Digest);
	DestroyString(Token);
	return(RetVal);
}


int CheckNativeFileHashedPassword(const char *PasswordType, const char *Name, const char *Salt, const char *Password, const char *ProvidedPass)
{
char *HashTypes[]={"md5","sha1","sha256","sha512","whirlpool","jh-224","jh-256","jh-384","jh-512",NULL};
char *Digest=NULL, *Tempstr=NULL;
int RetVal=FALSE;
int i;

for (i=0; (! RetVal) && (HashTypes[i] !=NULL); i++)
{
if (strcmp(PasswordType,HashTypes[i])==0) 
{
	Tempstr=MCopyStr(Tempstr,Name,Salt,ProvidedPass,NULL);
	HashBytes(&Digest,HashTypes[i],Tempstr,StrLen(Tempstr),ENCODE_HEX);
	if (strcasecmp(Password,Digest)==0) RetVal=TRUE;
LogToFile(Settings.ServerLogPath,"PASS: [%s] [%s] [%s]",Password,Digest,ProvidedPass);
}
}

DestroyString(Tempstr);
DestroyString(Digest);
return(RetVal);
}



int CheckNativeFilePassword(const char *PasswordType, const char *Name, const char *Salt, const char *Password, const char *ProvidedPass, TSession *Session)
{
if (strcmp(PasswordType,"null")==0) return(TRUE);

if (strcmp(PasswordType,"plain")==0)
{
	if (strcmp(Password,ProvidedPass)==0) return(TRUE);
	return(FALSE);
}

if (Session && strcmp(PasswordType,"challenge")==0) return(CheckNativeFileChallengePassword(Session->Challenge, Password, ProvidedPass));
return(CheckNativeFileHashedPassword(PasswordType, Name, Salt, Password, ProvidedPass));
}


int AuthNativeFile(TSession *Session)
{
STREAM *S;
char *Tempstr=NULL,*ptr;
char *Name=NULL, *Pass=NULL, *Salt=NULL, *RealUser=NULL, *HomeDir=NULL, *PasswordType=NULL;
int RetVal=USER_UNKNOWN;
struct passwd *pass_struct;


AuthenticationsTried=CatStr(AuthenticationsTried,"native ");

if (! StrLen(Settings.AuthFile)) return(FALSE);
S=STREAMOpenFile(Settings.AuthFile,O_RDONLY);
if (! S) 
{
if (Settings.Flags & FLAG_LOG_VERBOSE) LogToFile(Settings.ServerLogPath,"Cannot open %s",Settings.AuthFile);
return(USER_UNKNOWN);
}

Tempstr=STREAMReadLine(Tempstr,S);
while (Tempstr)
{
  StripTrailingWhitespace(Tempstr);
	ptr=GetToken(Tempstr,":",&Name,0);
	ptr=GetToken(ptr,":",&PasswordType,0);
	ptr=GetToken(ptr,":",&Salt,0);
	ptr=GetToken(ptr,":",&Pass,0);
	ptr=GetToken(ptr,":",&RealUser,0);
	ptr=GetToken(ptr,":",&HomeDir,0);
	
  if (strcasecmp(Name,Session->User)==0)
  {
		RetVal=FALSE;
		if (CheckNativeFilePassword(PasswordType,Name,Salt,Pass,Session->Passwd,Session))
    {
			RetVal=TRUE;
			Session->RealUser=CopyStr(Session->RealUser,RealUser);	
			if (StrLen(HomeDir)) Session->HomeDir=CopyStr(Session->HomeDir,HomeDir);	
			Session->UserSettings=CopyStr(Session->UserSettings,ptr);
			LogToFile(Settings.ServerLogPath,"AUTH OK %s [%s] [%s]",Name,Session->HomeDir,Session->RealUser);
			if (StrLen(Settings.UpdatePasswordType) && (strcasecmp(Settings.UpdatePasswordType, PasswordType) !=0) && (strcasecmp(PasswordType, "challenge") !=0))
			{
			UpdateNativeFile(S->Path, Name, Settings.UpdatePasswordType, Session->Passwd, HomeDir, RealUser, ptr);
			}
    }
		break;
  }

  Tempstr=STREAMReadLine(Tempstr,S);
}
STREAMClose(S);

DestroyString(Tempstr);
DestroyString(Name);
DestroyString(Pass);
DestroyString(Salt);
DestroyString(RealUser);
DestroyString(HomeDir);
DestroyString(PasswordType);

return(RetVal);
}


void ListNativeFile(STREAM *Out, char *Path)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *SendStr=NULL, *ptr;

S=STREAMOpenFile(Settings.AuthFile,O_RDONLY);
if (S)
{
  Tempstr=STREAMReadLine(Tempstr,S);
  while (Tempstr)
  {
    StripTrailingWhitespace(Tempstr);
    ptr=GetToken(Tempstr,":",&Token,0);
    SendStr=MCopyStr(SendStr,Token," ",NULL);

    ptr=GetToken(ptr,":",&Token,0); //passtype
    ptr=GetToken(ptr,":",&Token,0); //password
    ptr=GetToken(ptr,":",&Token,0); //realuser
    SendStr=MCatStr(SendStr,"realuser=",Token," ",NULL);
    ptr=GetToken(ptr,":",&Token,0); //homedir
    SendStr=MCatStr(SendStr,"homedir=",Token," ",NULL);
    SendStr=MCatStr(SendStr,ptr,"\n",NULL);

    STREAMWriteLine(SendStr,Out);
    Tempstr=STREAMReadLine(Tempstr,S);
  }
  STREAMClose(S);
}

STREAMFlush(Out);

DestroyString(Tempstr);
DestroyString(SendStr);
DestroyString(Token);
}




int UpdateNativeFile(const char *Path, const char *Name, const char *iPassType, const char *Pass, const char *iHomeDir, const char *iRealUser, const char *iArgs)
{
STREAM *S;
ListNode *Entries;
char *Tempstr=NULL, *Token=NULL, *ptr;
char *PassType=NULL, *HomeDir=NULL, *RealUser=NULL, *Args=NULL, *Salt=NULL;
ListNode *Curr;
int RetVal=ERR_FILE;

Entries=ListCreate();
S=STREAMOpenFile(Path,O_RDONLY);

if (S)
{
	Tempstr=STREAMReadLine(Tempstr,S);
	while (Tempstr)
	{
		ptr=GetToken(Tempstr,":",&Token,0);

		if (strcmp(Token,Name) !=0) ListAddItem(Entries,CopyStr(NULL,Tempstr));	
		else 
		{
			StripTrailingWhitespace(Tempstr);
			ptr=GetToken(ptr,":",&PassType,0);
			ptr=GetToken(ptr,":",&Salt,0);
			ptr=GetToken(ptr,":",&Token,0);
			ptr=GetToken(ptr,":",&RealUser,0);
			ptr=GetToken(ptr,":",&HomeDir,0);
			ptr=GetToken(ptr,":",&Args,0);
		}
	
		Tempstr=STREAMReadLine(Tempstr,S);
	}
	STREAMClose(S);
}

if (iPassType) PassType=CopyStr(PassType,iPassType);
if (iHomeDir) HomeDir=CopyStr(HomeDir,iHomeDir);
if (iRealUser) RealUser=CopyStr(RealUser,iRealUser);
if (iArgs) Args=CopyStr(Args,iArgs);


S=STREAMOpenFile(Path,O_WRONLY| O_CREAT | O_TRUNC);
if (S)
{
	//First copy all other entries
	Curr=ListGetNext(Entries);
	while (Curr)
	{
		STREAMWriteLine((char *) Curr->Item,S);
		Curr=ListGetNext(Curr);
	}
	STREAMFlush(S);


	if (strcmp(PassType,"delete")==0)
	{
		//Don't bother to write new entry, effectively deleting user
	}
	else //WriteNew Entry
	{
		//Do this or else HashBytes appends
		Token=CopyStr(Token,"");
		if (strcmp(PassType,"plain") == 0) Token=CopyStr(Token,Pass);
		else if (strcmp(PassType,"challenge") == 0) Token=CopyStr(Token,Pass);
		else 
		{
		  //Generate a new salt
			GenerateRandomBytes(&Salt,20,ENCODE_HEX);
			Tempstr=MCopyStr(Tempstr,Name,Salt,Pass,NULL);
			HashBytes(&Token, PassType, Tempstr, StrLen(Tempstr), ENCODE_HEX);
		}
		Tempstr=MCopyStr(Tempstr,Name,":",PassType,":",Salt,":",Token,":",RealUser,":",HomeDir,":",Args,"\n",NULL);
	
		STREAMWriteLine(Tempstr,S);
	}

	STREAMClose(S);
	RetVal=ERR_OKAY;
}

DestroyString(Args);
DestroyString(Salt);
DestroyString(HomeDir);
DestroyString(RealUser);
DestroyString(PassType);
DestroyString(Tempstr);
DestroyString(Token);
ListDestroy(Entries,DestroyString);

return(RetVal);
}


	
int Authenticate(TSession *Session, int AuthType)
{
int result=0;
char *Token=NULL, *ptr;
struct passwd *pwent;



AuthenticationsTried=CopyStr(AuthenticationsTried,"");
if (! CheckUserExists(Session->User))
{
	LogToFile(Settings.ServerLogPath,"Authentication failed for UserName '%s'. User Unknown. Tried methods: %s ",Session->User,AuthenticationsTried);
 return(FALSE);
}

AuthenticationsTried=CopyStr(AuthenticationsTried,"");


if (! CheckServerAllowDenyLists(Session->User)) return(FALSE);

//check for this as it changes behavior of other auth types
ptr=GetToken(Settings.AuthMethods,",",&Token,0);
while (ptr) 
{
	if (strcasecmp(Token,"session-pam")==0) Session->Flags |= SESSION_PAM;
	ptr=GetToken(ptr,",",&Token,0);
}


ptr=GetToken(Settings.AuthMethods,",",&Token,0);
while (ptr)
{

fprintf(stderr,"%s\n",Token);

	if (strcasecmp(Token,"native")==0) result=AuthNativeFile(Session);
	else if (strcasecmp(Token,"shadow")==0) result=AuthShadowFile(Session);
	else if (strcasecmp(Token,"passwd")==0) result=AuthPasswdFile(Session);
	#ifdef HAVE_LIBPAM
	else if (strcasecmp(Token,"pam")==0) result=AuthPAM(Session);
	#endif

	if (result==TRUE) 
	{
		LogToFile(Settings.ServerLogPath,"User '%s'. Authenticated via %s ",Session->User,Token);
		break;
	}
	ptr=GetToken(ptr,",",&Token,0);
}

if (result==USER_UNKNOWN) LogToFile(Settings.ServerLogPath,"Authentication failed for UserName '%s'. User Unknown. Tried methods: %s ",Session->User,AuthenticationsTried);
else if (result==FALSE) LogToFile(Settings.ServerLogPath,"Authentication failed for UserName '%s'. Bad Password/Credentials. Tried methods: %s ",Session->User,AuthenticationsTried);

//We no longer care if it was 'user unknown' or 'password wrong'
if (result !=TRUE) result=FALSE;



//Don't let them authenticate if HomeDir and user mapping not set

if (result)
{
	if (! StrLen(Session->RealUser)) 
	{
		LogToFile(Settings.ServerLogPath,"No 'RealUser' set for '%s'. Login Denied",Session->User);
		result=FALSE;
	}
	else
	{
		pwent=getpwnam(Session->RealUser);
		if (pwent) 
		{
			Session->RealUserUID=pwent->pw_uid;
			if (! StrLen(Session->HomeDir)) Session->HomeDir=CopyStr(Session->HomeDir,pwent->pw_dir);
		}

		if (! StrLen(Session->HomeDir)) 
		{
			LogToFile(Settings.ServerLogPath,"No 'HomeDir' set for '%s'. Login Denied",Session->User);
			result=FALSE;
		}
	}
}

fprintf(stderr,"PS2! %d\n",Session->Flags & SESSION_PAM);

//check again, because may have changed in above block
if (result && (Session->Flags & SESSION_PAM))
{
#ifdef HAVE_LIBPAM
	if (! AuthPAMCheckSession(Session))
	{
		LogToFile(Settings.ServerLogPath,"PAM Account invalid for '%s'. Login Denied",Session->User);
		result=FALSE;
	}
#endif
}


if (result)
{
	Session->Flags |= SESSION_AUTHENTICATED;
}

DestroyString(Token);
return(result);
}




