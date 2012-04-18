/* Reference implementation of Moeller 2004, "A Public-Key Encryption
   Scheme with Pseudo-Random Ciphertexts" (key encapsulation only).
   Written and placed in the public domain by Zack Weinberg, 2012. */

#include "curves.h"

/* 21-byte hexadecimal bignum */
#define N21(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u)                  \
  ((const uint8_t[]){0x##a,0x##b,0x##c,0x##d,0x##e,0x##f,0x##g,         \
                     0x##h,0x##i,0x##j,0x##k,0x##l,0x##m,0x##n,         \
                     0x##o,0x##p,0x##q,0x##r,0x##s,0x##t,0x##u}), 21

/* 21+1-byte compressed hexadecimal curve point */
#define P21(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u)                  \
  ((const uint8_t[]){0x02,                                              \
                     0x##a,0x##b,0x##c,0x##d,0x##e,0x##f,0x##g,         \
                     0x##h,0x##i,0x##j,0x##k,0x##l,0x##m,0x##n,         \
                     0x##o,0x##p,0x##q,0x##r,0x##s,0x##t,0x##u}), 22

const struct mk_curve_params mk_curves[] = {
/* MK_CURVE_163_0:
   p0 = 2923003274661805836407371179614143033958162426611, n0 = p0*4
   p1 = 5846006549323611672814736302501978089331135490587, n1 = p1*2  */
{
  N21(08,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,c9), /* m  */
  N21(05,84,6d,0f,da,25,53,61,60,67,11,bf,7a,99,b0,72,2e,2e,c8,f7,6b), /* b  */

  N21(02,00,00,00,00,00,00,00,00,00,01,40,a3,f2,a0,c6,ce,d9,ce,ea,f3), /* p0 */
  N21(03,ff,ff,ff,ff,ff,ff,ff,ff,ff,fd,7e,b8,1a,be,72,62,4c,62,2a,1b), /* p1 */

  N21(08,00,00,00,00,00,00,00,00,00,05,02,8f,ca,83,1b,3b,67,3b,ab,cc), /* n0 */
  N21(07,ff,ff,ff,ff,ff,ff,ff,ff,ff,fa,fd,70,35,7c,e4,c4,98,c4,54,36), /* n1 */

  P21(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,01), /* g0 */
  P21(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,02)  /* g1 */
},

};
