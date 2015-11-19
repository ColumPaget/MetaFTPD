
#ifndef FTPSERVER_COMMANDS_H
#define FTPSERVER_COMMANDS_H

#include "common.h"

void SendLoggedLine(TSession *Session,char *Data);
int MatchFtpCommand(char *Command);
void FTPDoCommand(TSession *Session, char *Command, char *Arg);

#endif
