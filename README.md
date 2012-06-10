This is a reference implementation of the key encapsulation mechanism
from [Bodo Möller][0]'s paper "[A Public-Key Encryption Scheme with Pseudo-
Random Ciphertexts][1]" ([ESORICS 2004][2]).  To the best
of my knowledge this cryptosystem has never been implemented before.
I have implemented *only* the key encapsulation mechanism, not the
full hybrid cryptosystem.  There are other slight deviations from the
paper; see comments in the header files.

There are actually two reference implementations, based on different
libraries.  The `-c` files use [Crypto++][3] and the `-o` files use
[OpenSSL][4].  `make check` tests them against each other.

[CC0][]: To the extent possible under law, I, Zachary Weinberg, do
hereby waive all copyright and related or neighboring rights to
this reference implementation.

[0]: http://www.bmoeller.de/
[1]: http://www.bmoeller.de/pdf/pke-pseudo-esorics2004.pdf
[2]: http://esorics04.eurecom.fr/program.html
[3]: http://www.cryptopp.com/
[4]: http://www.openssl.org/
[CC0]: http://creativecommons.org/publicdomain/zero/1.0/
