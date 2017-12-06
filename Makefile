CC=gcc -Wall -rdynamic
CFLAGS+= -g -fpack-struct=4 -lpthread -DTLV_CACHE_MULTI=31

xdr:xdr.o
	${CC} ${CFLAGS} -o xdr xdr.o
ufs:ufs.o
	${CC} ${CFLAGS} -o ufs ufs.o
%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@
clean:
	rm -f *.o xdr ufs

