CC = g++
CFLAGS = -Wall
LIBNAME = capstone

all: sdb

sdb: sdb.cpp
	$(CC) $^ $(CFLAGS) -l $(LIBNAME) -o $@ 

clean:
	rm -f sdb