CC=gcc -Wall -rdynamic
OBJS=main.o
TARGET=tlv2xdr
CFLAGS+=

$(TARGET):$(OBJS)
	${CC} ${CFLAGS} -o $(TARGET) $(OBJS)
%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@
