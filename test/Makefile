CC= gcc
CFLAGS= -Wall -I../src

prog:
	$(CC) $(CFLAGS) -o test test.c ../src/siphash.so

clean:
	@-$(RM) *.o
	@-$(RM) test

.PHONY: prog clean
