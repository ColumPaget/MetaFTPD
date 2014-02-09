
#ifndef FTPSERVER_COMMANDS_H
#define FTPSERVER_COMMANDS_H

#include "common.h"


int MatchFtpCommand(char *Command);
void FTPDoCommand(TSession *Session, char *Command, char *Arg);

#endif
