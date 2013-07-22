CC=clang

DEBUG=-g
CFLAGS=$(DEBUG) -std=c99 -Wall -Wextra -pedantic -Werror
LDFLAGS=

all: ipfw-table

clean: 
	rm -f ipfw-table ipfw-table.o

ipfw-table: ipfw-table.o
	$(CC) $(LDFLAGS) -o ipfw-table ipfw-table.o

ipfw-table.o: ipfw-table.c
	$(CC) $(CFLAGS) -c ipfw-table.c
