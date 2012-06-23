# Simple Makefile for siphash

CC= gcc
CFLAGS= -I. -fPIC -Wall
DEPS= siphash.h
OBJ= siphash.o

RM= rm -f

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

siphash: $(OBJ)
	$(CC) -shared -Wl,-soname,$@.so -o $@.so $^

clean:
	@-$(RM) *.o
	@-$(RM) *.so

.PHONY: siphash clean
