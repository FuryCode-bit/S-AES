CC=gcc
CFLAGS=-maes -msse4 -O3 -Wall -Wextra
LIBS=

all: saes

saes: saes.o
	$(CC) $(CFLAGS) -o saes saes.o $(LIBS)

saes.o: saes.c
	$(CC) $(CFLAGS) -c saes.c

clean:
	rm -f saes *.o

.PHONY: all clean
