# Reference implementation of Moeller 2004, "A Public-Key Encryption
# Scheme with Pseudo-Random Ciphertexts" (key encapsulation only).
# Written and placed in the public domain by Zack Weinberg, 2012.

PROGRAMS = katgen kat-c

CFLAGS   = -g -O2 -W -Wall
CXXFLAGS = -g -O2 -W -Wall

all: $(PROGRAMS)

katgen: katgen.o mref-c.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcryptopp

kat-c: kat-c.o mref-c.o katdata.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -lcryptopp

kat-c.o: kat-c.cc mref-c.h katdata.h
katdata.o: katdata.c katdata.h
katgen.o: katgen.cc mref-c.h
mref-c.o: mref-c.cc mref-c.h

# We regenerate katdata.c every time, but then we check to make sure it
# came out the way we expected it.
katdata.c: katgen
	./katgen > katdata.cT
	cmp -s katdata.cT katdata-ref.c || \
	    { diff -u katdata.cT katdata-ref.c; exit 1; }
	mv -f katdata.cT katdata.c

check: all
	./kat-c

clean:
	-rm -f $(PROGRAMS)
	-rm -f *.o
	-rm -f katdata.cT katdata.c

.PHONY: all clean check
