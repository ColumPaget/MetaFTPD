CC = gcc
VERSION = 1.0.0
CFLAGS = -g -O2
LIBS = -lcrypt -lpam -lz -lcap 
INSTALL=/bin/install -c
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sysconfdir=${prefix}/etc
FLAGS=$(CFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_LIBCAP=1 -DUSE_LINUX_CAPABILITIES=1 -DHAVE_LIBZ=1 -DHAVE_LIBPAM=1 -DHAVE_LIBCRYPT=1 -DHAVE_SHADOW_H=1 

OBJ=Authenticate.o Settings.o ftp-commands.o proxy.o common.o connections.o IPC.o libUseful-2.3/libUseful-2.3.a

all: $(OBJ) main.c
	gcc -g $(FLAGS) $(LIBS) -o metaftpd main.c $(OBJ)

libUseful-2.3/libUseful-2.3.a:
	@cd libUseful-2.3; $(MAKE)


Authenticate.o: Authenticate.c Authenticate.h 
	gcc -g $(FLAGS) -c Authenticate.c

ftp-commands.o: ftp-commands.c ftp-commands.h 
	gcc -g $(FLAGS) -c ftp-commands.c

proxy.o: proxy.c proxy.h 
	gcc $(FLAGS) -c proxy.c

connections.o: connections.c connections.h 
	gcc -g $(FLAGS) -c connections.c

IPC.o: IPC.c IPC.h 
	gcc -g $(FLAGS) -c IPC.c

common.o: common.c common.h 
	gcc $(FLAGS) -c common.c

Settings.o: Settings.c Settings.h 
	gcc $(FLAGS) -c Settings.c


clean:
	rm -f *.o metaftpd */*.o */*.so */*.a

install:
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL) metaftpd $(DESTDIR)$(bindir)
	$(INSTALL) metaftpd.conf $(DESTDIR)$(sysconfdir)
