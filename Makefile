CC=gcc -Wall -rdynamic
OBJS=main.o
TARGET=xdr
CFLAGS+= -g -fpack-struct=4

$(TARGET):$(OBJS)
	${CC} ${CFLAGS} -o $(TARGET) $(OBJS)
%.o:%.c
	${CC} -c ${CFLAGS} $< -o $@
clean:
	rm -f *.o $(TARGET)