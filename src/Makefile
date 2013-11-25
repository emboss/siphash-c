# Simple Makefile for siphash

CC= gcc
CFLAGS= -fPIC -Wall
CPPFLAGS= -I.
DEPS= siphash.h
OBJ= siphash.o
DLEXT = so

RM= rm -f

all: static shared

shared: libsiphash.$(DLEXT)

static: $(OBJ) siphash.a

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

libsiphash.$(DLEXT): $(OBJ)
	$(CC) -shared -o $@ $^
siphash.a:
	ar -r libsiphash.a *.o

clean:
	@-$(RM) *.o
	@-$(RM) *.$(DLEXT)
	@-$(RM) *.a

.PHONY: siphash clean
