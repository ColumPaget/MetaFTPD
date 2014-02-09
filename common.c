#include "common.h"
#include <sys/param.h>

#define BASIC_COMMANDS "NOOP,USER,PASS,PORT,XCWD,CWD,XCUP,CDUP,TYPE,RETR,STOR,LIST,NLST,MLST,MLSD,XDEL,DELE,QUIT,XPWD,PWD,XMKD,MKD,XRMD,RMD,RNFR,RNTO,PASV,FEAT"


int DecodePORTStr(char *PortStr, char **Address, int *Port)
{
char *Tempstr=NULL, *ptr;
int count;

for (count=0; count < StrLen(PortStr); count++) if (! isdigit(PortStr[count])) PortStr[count]=',';
ptr=PortStr;
for (count=0; count < 4; count++)
{
 ptr=GetToken(ptr,",",&Tempstr,0);
 StripTrailingWhitespace(Tempstr);
 *Address=CatStr(*Address,Tempstr);
 if (count < 3) *Address=CatStr(*Address,".");
}


 ptr=GetToken(ptr,",",&Tempstr,0);
 StripTrailingWhitespace(Tempstr);
 count=atoi(Tempstr);
 *Port=count;
 *Port=*Port << 8;
 
 ptr=GetToken(ptr,",",&Tempstr,0);
 StripTrailingWhitespace(Tempstr);
 count=atoi(Tempstr);
 *Port=*Port | count;

DestroyString(Tempstr);
return(TRUE);
}


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




#include <grp.h>

void ParseConfigItem(char *ConfigLine)
{
char *Token=NULL, *ptr;
int result;
char *ConfTokens[]={"Chroot","Chshare","Chhome","AllowUsers","DenyUsers","Port","Banner","DataConnectionLowPort","DataConnectionHighPort","DataConnectionPortRange","ServLogFile","LogFile","Idle","MaxIdle","Locks","AuthFile","BindAddress","LogPasswords","AuthMethods","UserPrompt","PermittedCommands","DefaultGroup","MaxFileSize","UploadHook", "DownloadHook","RenameHook","DeleteHook","LoginHook","LogoutHook","ConnectUpHook","ConnectDownHook",NULL};
typedef enum {CT_CHROOT, CT_CHSHARE, CT_CHHOME, CT_ALLOWUSERS,CT_DENYUSERS,CT_PORT,CT_BANNER,CT_DC_LOW_PORT, CT_DC_HIGH_PORT, CT_DC_RANGE,CT_SERVLOGFILE,CT_LOGFILE,CT_IDLE,CT_MAXIDLE,CT_LOCKS,CT_AUTHFILE,CT_BINDADDRESS,CT_LOGPASSWORDS,CT_AUTHMETHODS,CT_USERPROMPT,CT_PERMITTEDCOMMANDS,CT_DEFAULTGROUP, CT_MAXFILESIZE, CT_UPLOADHOOK, CT_DOWNLOADHOOK, CT_RENAMEHOOK, CT_DELETEHOOK, CT_LOGINHOOK, CT_LOGOUTHOOK, CT_CONNECTUPHOOK, CT_CONNECTDOWNHOOK};
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


  }

DestroyString(Token);
}



int CheckTransferPermission(int Direction, double *FileSize, int BytesRead)
{
int RetVal=TRUE;

*FileSize+=(double) BytesRead;

return(RetVal);
}

char *StripCR(char *RetStr,char *Data, int Len)
{
int i;
char *dptr, *sptr;

RetStr=SetStrLen(RetStr,Len*2);
dptr=RetStr;
for (sptr=Data; sptr < Data+Len; sptr++)
{
  if (*sptr!='\r')
	{
  	*dptr=*sptr;
    dptr++;
	}
}
*dptr='\0';

return(RetStr);
}


char *ExpandLF(char *RetStr,char *Data, int Len)
{
int i;
char *dptr, *sptr;

RetStr=SetStrLen(RetStr,Len*2);
dptr=RetStr;
for (sptr=Data; sptr < Data+Len; sptr++)
{
  if (*sptr=='\n')
  {
    *dptr='\r';
    dptr++;
  }

  *dptr=*sptr;
  dptr++;
}
*dptr='\0';

return(RetStr);
}


int FtpWriteBytes(TSession *Session,TDataConnection *DC, char *Buffer, int Len)
{
char *Tempstr=NULL;
int result;

	//Check this before writing, otherwise they'll be able to use 'REST' to add a little more
	//to the file over and over
	if ((DC->Flags & DC_STOR) && Settings.MaxFileSize > 0)
	{
    if (DC->BytesSent > Settings.MaxFileSize)
    {
      return(ERR_SIZE);
    }
  }

  if (Session->Flags & SESSION_ASCII_TRANSFERS)
  {
		if (DC->Flags & DC_STOR) Tempstr=StripCR(Tempstr,Buffer,Len);
    else Tempstr=ExpandLF(Tempstr,Buffer,Len);
		result=STREAMWriteBytes(DC->Output,Tempstr,StrLen(Tempstr));
  }
  else result=STREAMWriteBytes(DC->Output,Buffer,Len);

	DC->BytesSent+= (double) result;

DestroyString(Tempstr);

return(ERR_OKAY);
}


char *GetCurrDirFullPath(char *RetStr)
{
char *Path=NULL, *Dir=NULL, *ptr;

  Dir=SetStrLen(Dir,MAXPATHLEN);
  getcwd(Dir,MAXPATHLEN);

	Path=MCopyStr(RetStr,Settings.Chroot,Dir,NULL);
	Path=SlashTerminateDirectoryPath(Path);

	DestroyString(Dir);
	return(Path);
}
