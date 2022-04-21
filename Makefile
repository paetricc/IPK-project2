CC=gcc
CFLAGS=-std=c11 -pedantic -Wall -Wextra -g
NAME=packetsniffer
run:
	$(CC) $(CFLAGS) *.c -o $(NAME)

clean:
	-rm -f *.o $(NAME)
