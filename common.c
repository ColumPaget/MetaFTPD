#include "common.h"
#include <sys/param.h>
#include "Settings.h"

char *Version="1.2.1";
const char *HashNames[]={"CRC32","MD5","SHA-1","SHA-256","SHA-512","WHIRL","WHIRLPOOL","JH-224","JH-256","JH-384","JH-512",NULL};


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


int FtpCopyBytes(TSession *Session,TDataConnection *DC)
{
char *Buffer=NULL, *Tempstr=NULL;
int result, Len=BUFSIZ;

	/*
	if (Settings.MaxFileSize)
	{
		Len=Settings.MaxFileSize - DC->BytesSent;
  	if (Len < 1) return(ERR_SIZE);
	}
	*/

	if (Len > BUFSIZ) Len=BUFSIZ;
	Buffer=SetStrLen(Buffer, Len);
	
  if (Session->Flags & SESSION_ASCII_TRANSFERS)
  {
		result=STREAMReadBytes(DC->Input,Buffer,BUFSIZ);
		if (result > 0)
		{
		if (DC->Flags & DC_STOR) Tempstr=StripCR(Tempstr,Buffer,Len);
    else Tempstr=ExpandLF(Tempstr,Buffer,Len);
		result=STREAMWriteBytes(DC->Output,Tempstr,StrLen(Tempstr));
		}
  }
  else if (DC->Hash)
	{
		result=STREAMReadBytes(DC->Input,Buffer,BUFSIZ);
		if (result > 0)
		{
		DC->Hash->Update(DC->Hash, Buffer, result);
		result=STREAMWriteBytes(DC->Output,Buffer,result);
		}
	}
	else
	{
		result=STREAMSendFile(DC->Input, DC->Output, Len, SENDFILE_KERNEL);
	}

	//result can be negative for 'STREAMClosed'
	if (result < 0) result=0;
	DC->BytesSent+= (double) result;

DestroyString(Buffer);
DestroyString(Tempstr);

return(result);
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



void DropCapabilities(int Level)
{
#ifdef USE_LINUX_CAPABILITIES

//use portable 'libcap' interface if it's available
#ifdef HAVE_LIBCAP
#include <sys/capability.h>

#define CAPSET_SIZE 10
int CapSet[CAPSET_SIZE];
int NumCapsSet=0, i;
cap_t cap;


//if we are a session then drop everything. Switch user should have happened,
//but if it failed we drop everything. Yes, a root attacker can probably 
//reclaim caps, but it at least makes them do some work

if (Level < CAPS_LEVEL_SESSION) 
{
	CapSet[NumCapsSet]= CAP_CHOWN;
	NumCapsSet++;

	CapSet[NumCapsSet]= CAP_SETUID;
	NumCapsSet++;

	CapSet[NumCapsSet]= CAP_SETGID;
	NumCapsSet++;

	CapSet[NumCapsSet] = CAP_SYS_CHROOT;
	NumCapsSet++;

	CapSet[NumCapsSet] = CAP_FOWNER;
	NumCapsSet++;

	CapSet[NumCapsSet] = CAP_DAC_OVERRIDE;
	NumCapsSet++;
}

if (Level==CAPS_LEVEL_STARTUP) 
{
	CapSet[NumCapsSet] = CAP_NET_BIND_SERVICE;
	NumCapsSet++;
}

cap=cap_init();
if (cap_set_flag(cap, CAP_EFFECTIVE, NumCapsSet, CapSet, CAP_SET) == -1)  ;
if (cap_set_flag(cap, CAP_PERMITTED, NumCapsSet, CapSet, CAP_SET) == -1)  ;
if (cap_set_flag(cap, CAP_INHERITABLE, NumCapsSet, CapSet, CAP_SET) == -1)  ;

cap_set_proc(cap);

#else 

//if libcap is not available try linux-only interface

#include <linux/capability.h>

struct __user_cap_header_struct cap_hdr;
cap_user_data_t cap_values;
unsigned long CapVersions[]={ _LINUX_CAPABILITY_VERSION_3, _LINUX_CAPABILITY_VERSION_2, _LINUX_CAPABILITY_VERSION_1, 0};
int val=0, i, result;

//the CAP_ values are not bitmask flags, but instead indexes, so we have
//to use shift to get the appropriate flag value
if (Level < CAPS_LEVEL_SESSION)
{
 val |=(1 << CAP_CHOWN);
 val |=(1 << CAP_SETUID);
 val |=(1 << CAP_SETGID);
 val |= (1 << CAP_SYS_CHROOT);
}

//only allow bind between startup and the next level call of
//this function
if (Level==CAPS_LEVEL_STARTUP) val |= (1 << CAP_NET_BIND_SERVICE);


for (i=0; CapVersions[i] > 0; i++)
{
	cap_hdr.version=CapVersions[i];
	cap_hdr.pid=0;

	//Horrible cludgy interface. V1 uses 32bit, V2 uses 64 bit, and somehow spreads this over
	//two __user_cap_data_struct items
	if (CapVersions[i]==_LINUX_CAPABILITY_VERSION_1) cap_values=calloc(1,sizeof(struct __user_cap_data_struct));
	else cap_values=calloc(2,sizeof(struct __user_cap_data_struct));

	cap_values->effective=val;
	cap_values->permitted=val;
	cap_values->inheritable=val;
	result=capset(&cap_hdr, cap_values);
	free(cap_values);
	if (result == 0) break;
}

#endif
#endif
}
