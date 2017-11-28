CC=gcc -Wall -rdynamic
#OBJS=xdr.o
#TARGET=xdr
CFLAGS+= -g -fpack-struct=4 -lpthread

$(TARGET):$(OBJS)
	${CC} ${CFLAGS} -o xdr xdr.o
#	${CC} ${CFLAGS} -o ufs ufs.o
%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@
clean:
	rm -f *.o xdr ufs