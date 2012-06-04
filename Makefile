# Reference implementation of Moeller 2004, "A Public-Key Encryption
# Scheme with Pseudo-Random Ciphertexts" (key encapsulation only).
# Written and placed in the public domain by Zack Weinberg, 2012.

PROGRAMS = katgen kat-c kat-o

CFLAGS   = -g -O2 -std=c89 -Werror -Wall -Wextra -pedantic -Wstrict-prototypes -Wmissing-prototypes -Wwrite-strings -Wformat=2
CXXFLAGS = -g -O2 -std=c++98 -Werror -Wall -Wextra -Wformat=2
CPPFLAGS = -D_FORTIFY_SOURCE=2

all: $(PROGRAMS)

katgen: katgen.o mref-c.o curves.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcryptopp

kat-c: kat-c.o mref-c.o curves.o katdata.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcryptopp

kat-o: kat-o.o mref-o.o curves.o katdata.o
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

curves.o:  curves.c  curves.h
katdata.o: katdata.c katdata.h

kat-c.o:  kat-c.cc  mref-c.h katdata.h
katgen.o: katgen.cc mref-c.h
mref-c.o: mref-c.cc mref-c.h curves.h
mref-o.o: mref-o.c  mref-o.h curves.h

# We regenerate katdata.c every time, but then we check to make sure it
# came out the way we expected it.
katdata.cT: katgen
	./katgen katdata.cT

katdata.c: katdata.cT katdata-ref.c
	cmp -s katdata.cT katdata-ref.c || \
	    { diff -u katdata-ref.c katdata.cT; exit 1; }
	cp katdata.cT katdata.c

check: all
	./kat-c
	./kat-o

clean:
	-rm -f $(PROGRAMS)
	-rm -f *.o
	-rm -f katdata.cT katdata.c

.PHONY: all clean check
