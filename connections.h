#ifndef FTPSERVER_CONNECTIONS_H
#define FTPSERVER_CONNECTIONS_H

#include "common.h"



TDataConnection *DataConnectionCreate();
int GetIntendedDestination(int sock, TSession *Session);
TDataConnection *OpenDataConnection(TSession *Session, int Flags);
int NegotiateDataConnection(STREAM *ControlSock, char *BindAddress, TDataConnection *DC);
int CloseDataConnection(TSession *Session, TDataConnection *DataCon);
int FTP_BindDataConnection(STREAM *PeerSock, char *BindAddress, TDataConnection *DC, char *MsgStr);
TDataConnection *AddDataConnection(TSession *Session, int Type, char *Address, int Port);

#endif
