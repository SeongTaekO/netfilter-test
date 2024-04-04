LDLIBS += -lnetfilter_queue

all: nfqnl_test

nfqnl_test: nfqnl_test.o

nfqnl_test.o: nfqnl_test.c

clean:
	rm -f nfqnl_test.o
	rm -f nfqnl_test
