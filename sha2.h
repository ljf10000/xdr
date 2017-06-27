#ifndef __SHA2_H_f482c6dfe05341e7b2ddf4db926acb7d__
#define __SHA2_H_f482c6dfe05341e7b2ddf4db926acb7d__
/******************************************************************************/
#define SHA256_DIGEST_SIZE ( 256 / 8)   // 32
#define SHA256_BLOCK_SIZE  ( 512 / 8)   // 64

typedef struct {
    unsigned int tot_len;
    unsigned int len;
    byte block[2 * SHA256_BLOCK_SIZE];
    uint32 h[8];
} sha256_ctx;

#define sha2_SHFR(x, n)     (x >> n)
#define sha2_ROTR(x, n)     ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define sha2_ROTL(x, n)     ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define sha2_CH(x, y, z)    ((x & y) ^ (~x & z))
#define sha2_MAJ(x, y, z)   ((x & y) ^ (x & z) ^ (y & z))

#define sha256_F1(x) (sha2_ROTR(x,  2) ^ sha2_ROTR(x, 13) ^ sha2_ROTR(x, 22))
#define sha256_F2(x) (sha2_ROTR(x,  6) ^ sha2_ROTR(x, 11) ^ sha2_ROTR(x, 25))
#define sha256_F3(x) (sha2_ROTR(x,  7) ^ sha2_ROTR(x, 18) ^ sha2_SHFR(x,  3))
#define sha256_F4(x) (sha2_ROTR(x, 17) ^ sha2_ROTR(x, 19) ^ sha2_SHFR(x, 10))

#define sha2_UNPACK32(x, str)  do {         \
    *((str) + 3) = (uint8) ((x)      );     \
    *((str) + 2) = (uint8) ((x) >>  8);     \
    *((str) + 1) = (uint8) ((x) >> 16);     \
    *((str) + 0) = (uint8) ((x) >> 24);     \
}while(0)

#define sha2_PACK32(str, x)      do {           \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}while(0)

#define sha2_UNPACK64(x, str)    do {          \
    *((str) + 7) = (uint8) ((x)      );       \
    *((str) + 6) = (uint8) ((x) >>  8);       \
    *((str) + 5) = (uint8) ((x) >> 16);       \
    *((str) + 4) = (uint8) ((x) >> 24);       \
    *((str) + 3) = (uint8) ((x) >> 32);       \
    *((str) + 2) = (uint8) ((x) >> 40);       \
    *((str) + 1) = (uint8) ((x) >> 48);       \
    *((str) + 0) = (uint8) ((x) >> 56);       \
}while(0)

#define sha2_PACK64(str, x)   do {              \
    *(x) =   ((uint64) *((str) + 7)      )    \
           | ((uint64) *((str) + 6) <<  8)    \
           | ((uint64) *((str) + 5) << 16)    \
           | ((uint64) *((str) + 4) << 24)    \
           | ((uint64) *((str) + 3) << 32)    \
           | ((uint64) *((str) + 2) << 40)    \
           | ((uint64) *((str) + 1) << 48)    \
           | ((uint64) *((str) + 0) << 56);   \
}while(0)

/* Macros used for loops unrolling */

#define sha256_SCR(i)            do {       \
    w[i] =  sha256_F4(w[i -  2]) + w[i -  7]  \
          + sha256_F3(w[i - 15]) + w[i - 16]; \
}while(0)

#define sha256_EXP(a, b, c, d, e, f, g, h, j)      do{      \
    t1 = wv[h] + sha256_F2(wv[e]) + sha2_CH(wv[e], wv[f], wv[g]) \
         + sha256_k[j] + w[j];                              \
    t2 = sha256_F1(wv[a]) + sha2_MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}while(0)

static inline void 
sha256_transf(sha256_ctx *ctx, const byte *message, unsigned int block_nb)
{
    static uint32 sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
             
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const byte *sub_block;
    int i;

    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);

        sha2_PACK32(&sub_block[ 0], &w[ 0]); sha2_PACK32(&sub_block[ 4], &w[ 1]);
        sha2_PACK32(&sub_block[ 8], &w[ 2]); sha2_PACK32(&sub_block[12], &w[ 3]);
        sha2_PACK32(&sub_block[16], &w[ 4]); sha2_PACK32(&sub_block[20], &w[ 5]);
        sha2_PACK32(&sub_block[24], &w[ 6]); sha2_PACK32(&sub_block[28], &w[ 7]);
        sha2_PACK32(&sub_block[32], &w[ 8]); sha2_PACK32(&sub_block[36], &w[ 9]);
        sha2_PACK32(&sub_block[40], &w[10]); sha2_PACK32(&sub_block[44], &w[11]);
        sha2_PACK32(&sub_block[48], &w[12]); sha2_PACK32(&sub_block[52], &w[13]);
        sha2_PACK32(&sub_block[56], &w[14]); sha2_PACK32(&sub_block[60], &w[15]);

        sha256_SCR(16); sha256_SCR(17); sha256_SCR(18); sha256_SCR(19);
        sha256_SCR(20); sha256_SCR(21); sha256_SCR(22); sha256_SCR(23);
        sha256_SCR(24); sha256_SCR(25); sha256_SCR(26); sha256_SCR(27);
        sha256_SCR(28); sha256_SCR(29); sha256_SCR(30); sha256_SCR(31);
        sha256_SCR(32); sha256_SCR(33); sha256_SCR(34); sha256_SCR(35);
        sha256_SCR(36); sha256_SCR(37); sha256_SCR(38); sha256_SCR(39);
        sha256_SCR(40); sha256_SCR(41); sha256_SCR(42); sha256_SCR(43);
        sha256_SCR(44); sha256_SCR(45); sha256_SCR(46); sha256_SCR(47);
        sha256_SCR(48); sha256_SCR(49); sha256_SCR(50); sha256_SCR(51);
        sha256_SCR(52); sha256_SCR(53); sha256_SCR(54); sha256_SCR(55);
        sha256_SCR(56); sha256_SCR(57); sha256_SCR(58); sha256_SCR(59);
        sha256_SCR(60); sha256_SCR(61); sha256_SCR(62); sha256_SCR(63);

        wv[0] = ctx->h[0]; wv[1] = ctx->h[1];
        wv[2] = ctx->h[2]; wv[3] = ctx->h[3];
        wv[4] = ctx->h[4]; wv[5] = ctx->h[5];
        wv[6] = ctx->h[6]; wv[7] = ctx->h[7];

        sha256_EXP(0,1,2,3,4,5,6,7, 0); sha256_EXP(7,0,1,2,3,4,5,6, 1);
        sha256_EXP(6,7,0,1,2,3,4,5, 2); sha256_EXP(5,6,7,0,1,2,3,4, 3);
        sha256_EXP(4,5,6,7,0,1,2,3, 4); sha256_EXP(3,4,5,6,7,0,1,2, 5);
        sha256_EXP(2,3,4,5,6,7,0,1, 6); sha256_EXP(1,2,3,4,5,6,7,0, 7);
        sha256_EXP(0,1,2,3,4,5,6,7, 8); sha256_EXP(7,0,1,2,3,4,5,6, 9);
        sha256_EXP(6,7,0,1,2,3,4,5,10); sha256_EXP(5,6,7,0,1,2,3,4,11);
        sha256_EXP(4,5,6,7,0,1,2,3,12); sha256_EXP(3,4,5,6,7,0,1,2,13);
        sha256_EXP(2,3,4,5,6,7,0,1,14); sha256_EXP(1,2,3,4,5,6,7,0,15);
        sha256_EXP(0,1,2,3,4,5,6,7,16); sha256_EXP(7,0,1,2,3,4,5,6,17);
        sha256_EXP(6,7,0,1,2,3,4,5,18); sha256_EXP(5,6,7,0,1,2,3,4,19);
        sha256_EXP(4,5,6,7,0,1,2,3,20); sha256_EXP(3,4,5,6,7,0,1,2,21);
        sha256_EXP(2,3,4,5,6,7,0,1,22); sha256_EXP(1,2,3,4,5,6,7,0,23);
        sha256_EXP(0,1,2,3,4,5,6,7,24); sha256_EXP(7,0,1,2,3,4,5,6,25);
        sha256_EXP(6,7,0,1,2,3,4,5,26); sha256_EXP(5,6,7,0,1,2,3,4,27);
        sha256_EXP(4,5,6,7,0,1,2,3,28); sha256_EXP(3,4,5,6,7,0,1,2,29);
        sha256_EXP(2,3,4,5,6,7,0,1,30); sha256_EXP(1,2,3,4,5,6,7,0,31);
        sha256_EXP(0,1,2,3,4,5,6,7,32); sha256_EXP(7,0,1,2,3,4,5,6,33);
        sha256_EXP(6,7,0,1,2,3,4,5,34); sha256_EXP(5,6,7,0,1,2,3,4,35);
        sha256_EXP(4,5,6,7,0,1,2,3,36); sha256_EXP(3,4,5,6,7,0,1,2,37);
        sha256_EXP(2,3,4,5,6,7,0,1,38); sha256_EXP(1,2,3,4,5,6,7,0,39);
        sha256_EXP(0,1,2,3,4,5,6,7,40); sha256_EXP(7,0,1,2,3,4,5,6,41);
        sha256_EXP(6,7,0,1,2,3,4,5,42); sha256_EXP(5,6,7,0,1,2,3,4,43);
        sha256_EXP(4,5,6,7,0,1,2,3,44); sha256_EXP(3,4,5,6,7,0,1,2,45);
        sha256_EXP(2,3,4,5,6,7,0,1,46); sha256_EXP(1,2,3,4,5,6,7,0,47);
        sha256_EXP(0,1,2,3,4,5,6,7,48); sha256_EXP(7,0,1,2,3,4,5,6,49);
        sha256_EXP(6,7,0,1,2,3,4,5,50); sha256_EXP(5,6,7,0,1,2,3,4,51);
        sha256_EXP(4,5,6,7,0,1,2,3,52); sha256_EXP(3,4,5,6,7,0,1,2,53);
        sha256_EXP(2,3,4,5,6,7,0,1,54); sha256_EXP(1,2,3,4,5,6,7,0,55);
        sha256_EXP(0,1,2,3,4,5,6,7,56); sha256_EXP(7,0,1,2,3,4,5,6,57);
        sha256_EXP(6,7,0,1,2,3,4,5,58); sha256_EXP(5,6,7,0,1,2,3,4,59);
        sha256_EXP(4,5,6,7,0,1,2,3,60); sha256_EXP(3,4,5,6,7,0,1,2,61);
        sha256_EXP(2,3,4,5,6,7,0,1,62); sha256_EXP(1,2,3,4,5,6,7,0,63);

        ctx->h[0] += wv[0]; ctx->h[1] += wv[1];
        ctx->h[2] += wv[2]; ctx->h[3] += wv[3];
        ctx->h[4] += wv[4]; ctx->h[5] += wv[5];
        ctx->h[6] += wv[6]; ctx->h[7] += wv[7];
    }
}

static inline void 
sha256_init(sha256_ctx *ctx)
{
    static uint32 sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
             
    ctx->h[0] = sha256_h0[0]; ctx->h[1] = sha256_h0[1];
    ctx->h[2] = sha256_h0[2]; ctx->h[3] = sha256_h0[3];
    ctx->h[4] = sha256_h0[4]; ctx->h[5] = sha256_h0[5];
    ctx->h[6] = sha256_h0[6]; ctx->h[7] = sha256_h0[7];

    ctx->len = 0;
    ctx->tot_len = 0;
}

static inline void
sha256_update(sha256_ctx *ctx, const byte *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const byte *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
           rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

static inline void
sha256_final(sha256_ctx *ctx, byte digest[SHA256_DIGEST_SIZE])
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    sha2_UNPACK32(len_b, ctx->block + pm_len - 4);

    sha256_transf(ctx, ctx->block, block_nb);

   sha2_UNPACK32(ctx->h[0], &digest[ 0]);
   sha2_UNPACK32(ctx->h[1], &digest[ 4]);
   sha2_UNPACK32(ctx->h[2], &digest[ 8]);
   sha2_UNPACK32(ctx->h[3], &digest[12]);
   sha2_UNPACK32(ctx->h[4], &digest[16]);
   sha2_UNPACK32(ctx->h[5], &digest[20]);
   sha2_UNPACK32(ctx->h[6], &digest[24]);
   sha2_UNPACK32(ctx->h[7], &digest[28]);
}

static inline void 
sha256(const byte *message, unsigned int len, byte digest[SHA256_DIGEST_SIZE])
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}
/******************************************************************************/
#endif /* __SHA2_H_f482c6dfe05341e7b2ddf4db926acb7d__ */
