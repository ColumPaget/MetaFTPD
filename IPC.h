
#ifndef METAFTPD_IPC_H
#define METAFTPD_IPC_H

#include "common.h"

int IPCHandleRequest(TSessionProcess *Proc);
char *IPCRequest(char *Buffer, TSession *Session, char *InfoType, char *Arg);

#endif

