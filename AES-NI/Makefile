CC = gcc
CFLAGS = -maes -msse4 -O3 -Wall -Wextra
LIBS =

all: saes_test encrypt decrypt

encrypt: encrypt.o saes.o
	$(CC) $(CFLAGS) -o encrypt encrypt.o saes.o $(LIBS)


decrypt: decrypt.o saes.o
	$(CC) $(CFLAGS) -o decrypt decrypt.o saes.o $(LIBS)


saes_test: saes_test.o saes.o
	$(CC) $(CFLAGS) -o saes_test saes_test.o saes.o $(LIBS)

encrypt.o: encrypt.c
	$(CC) $(CFLAGS) -c encrypt.c

decrypt.o: decrypt.c
	$(CC) $(CFLAGS) -c decrypt.c

saes.o: saes.c
	$(CC) $(CFLAGS) -c saes.c

saes_test.o: saes_test.c
	$(CC) $(CFLAGS) -c saes_test.c

clean:
	rm -f saes_test encrypt decrypt *.o

.PHONY: all clean

