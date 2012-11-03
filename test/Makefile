CC= gcc
CFLAGS= -Wall -I../src
DLEXT= so

prog:
	$(CC) $(CFLAGS) -o test test.c ../src/siphash.$(DLEXT)

clean:
	@-$(RM) *.o
	@-$(RM) test

.PHONY: prog clean
