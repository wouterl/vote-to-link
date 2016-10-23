CC=gcc
CFLAGS=-std=c11 -g -O2 -Wall -Werror -march=native
LIB=-lrelic_s -lsodium -lgmp -lssl -lcrypto

%.o: %.c
	$(CC) $(CFLAGS) -c $<

all: test-tdh test-bbsplus test-vtr test-shuffle test-anonvtr bench

test-bbsplus: bbsplus.o test-bbsplus.o utils.o dirs
	$(CC) $(CFLAGS) -o bin/test-bbsplus test-bbsplus.o bbsplus.o utils.o $(LIB)

test-tdh: tdh.o utils.o test-tdh.o dirs
	$(CC) $(CFLAGS) -o bin/test-tdh tdh.o test-tdh.o utils.o $(LIB)

test-vtr: vtr.o tdh.o utils.o bbsplus.o test-vtr.o dirs
	$(CC) $(CFLAGS) -o bin/test-vtr vtr.o bbsplus.o tdh.o test-vtr.o utils.o $(LIB)

test-shuffle: utils.o shuffle.o test-shuffle.o dirs
	$(CC) $(CFLAGS) -o bin/test-shuffle shuffle.o test-shuffle.o utils.o $(LIB)

test-anonvtr: utils.o shuffle.o vtr.o test-anonvtr.o bbsplus.o dirs anonvtr.o
	$(CC) $(CFLAGS) -o bin/test-anonvtr shuffle.o test-anonvtr.o vtr.o bbsplus.o utils.o anonvtr.o tdh.o $(LIB)

bench: utils.o shuffle.o vtr.o bench.o bbsplus.o dirs anonvtr.o
	$(CC) $(CFLAGS) -o bin/bench shuffle.o bench.o vtr.o bbsplus.o utils.o anonvtr.o tdh.o $(LIB)

clean:
	rm *.o

dirs:
	mkdir -p bin/
