ifeq ($(UNAME), Darwin)
SHAREDFLAGS = -dynamiclib
SHAREDEXT = dylib
else
SHAREDFLAGS = -shared
SHAREDEXT = so
endif

ifeq ("$(LIBDIR)", "")
LIBDIR=/usr/local/lib
endif

ifeq ("$(INCDIR)", "")
INCDIR=/usr/local/include
endif

all:
	make -C src all
clean:
	make -C src clean
install:
	 @echo "Installing libraries in $(LIBDIR)"; \
	 cp -v src/libsiphash.a $(LIBDIR)/;\
	 cp -v src/libsiphash.$(SHAREDEXT) $(LIBDIR)/;\
	 echo "Installing headers in $(INCDIR)"; \
	 cp -v src/*.h $(INCDIR)/;
