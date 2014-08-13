CC=g++
CFLAGS=-Wall -Werror -std=c++11 -O3
LIBS=-ltins -lpthread

all:	test

test: test.o
	$(CC) $(CFLAGS) $(LIBS) test.o -o test 

test.o: test.cpp 
	$(CC) $(CFLAGS) -c test.cpp

run: test
	sudo ./test

clean:
	rm -rf test test.o 

