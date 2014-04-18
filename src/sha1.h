#include<stdio.h>
#include<stdlib.h>
#include<string.h>


unsigned int H0 = 0x67452301;
unsigned int H1 = 0xEFCDAB89;
unsigned int H2 = 0x98BADCFE;
unsigned int H3 = 0x10325476;
unsigned int H4 = 0xC3D2E1F0;

unsigned int rotate_left(unsigned int val, int by)
{
	unsigned int rotated = (val<<by) | (val>>(32-by));
	return rotated;
}

void swap_chars(char *c1, char *c2)
{
        char temp = *c1;
        *c1 = *c2;
        *c2 = temp;
}

void small_to_big_endian(char *a, int len)
{
        int i;
        char *temp;

        temp = a;
        // simply reverse the bytes
        for(i=0;i<len/2;i++)
        {
                swap_chars(&temp[i], &temp[len-i-1]);
        }
}

char *pad_msg(char *msg, long long msg_len, int *pad_len)
{
	*pad_len = (msg_len % 64) < 56 ? ((msg_len / 64 + 1) * 64) : ((msg_len / 64 +2) * 64);
	char *buf = calloc(*pad_len, 1);
	memcpy(buf, msg, msg_len);
	buf[msg_len] = 0x80;

	small_to_big_endian((char *)&msg_len, 8);
	memcpy((buf +(*pad_len) - 8),  &msg_len, 8);
	
	return buf;
}

unsigned int f(int t, unsigned int B, unsigned int C, unsigned int D)
{
    // f(t;B,C,D) = (B AND C) OR ((NOT B) AND D)         ( 0 <= t <= 19)
    if(t>=0 && t<=19)
    {
        return ((B & C) | (~B) & D);
    }
    // f(t;B,C,D) = B XOR C XOR D                        (20 <= t <= 39)
    if(t>= 20 && t<=39)
    {
        return(B ^ C ^ D);
    }
    // f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D)  (40 <= t <= 59)
    if(t>=40 && t<= 59)
    {
        return( (B&C) | (B&D) | (C&D) );
    }
    // f(t;B,C,D) = B XOR C XOR D                        (60 <= t <= 79)
    if(t>=60 && t<=79)
    {
        return ( B^C^D );
    }
}
  
unsigned int get_k(int t)
{
    // K(t) = 5A827999         ( 0 <= t <= 19)
    if(t>=0 && t<=19)
    {
        return 0x5A827999;
    }
    // K(t) = 6ED9EBA1         (20 <= t <= 39)
    if(t>=20 && t<=39)
    {
        return 0x6ED9EBA1;
    }
    // K(t) = 8F1BBCDC         (40 <= t <= 59)
    if(t >= 40 && t<=59)
    {
        return 0x8F1BBCDC;
    }
    // K(t) = CA62C1D6         (60 <= t <= 79)
    if(t>=60 && t<=79)
    {
        return 0xCA62C1D6;
    }
}

void process_block(char *M)
{
	int t;
	unsigned int temp;
	unsigned int A, B, C, D, E;
	unsigned int *W = malloc(80*4); // 80 words
	memcpy(W, M, 64); // 64 bytes == 16 words == 512 bits
	
	for(t=16; t<80; t++)
	{
		W[t] = (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
		W[t] = rotate_left(W[t], 1);
	}

	A = H0; B = H1; C = H2; D = H3, E = H4;

	for(t = 0; t<80; t++)
	{
		temp = rotate_left(A, 5) + f(t, B, C, D) + E +W[t] + get_k(t);
		E = D; D = C; C = rotate_left(B, 30); B = A; A = temp;
	}

	H0 = H0 + A; H1 = H1 + B; H2 = H2 + C; H3 = H3 + D; H4 = H4 + E;
	free(W);
}

// uses the method described here: https://tools.ietf.org/html/rfc3174#section-6.1 
char *sha1_compute(char *msg, int msg_len)
{
	// pad msg
	int pad_len, i;
	char *padded;
	char *sha1 = malloc(20);
	char *temp;

	padded = pad_msg(msg, msg_len, &pad_len);
	// process in 512 byte chunks
	temp = padded;
	for(i=0; i<pad_len; i+=64)
	{
		process_block(temp);
		temp += 64;
	}
	
	// now copy H0 to H4 into the sha1 buffer
	temp = sha1;
	memcpy(temp, &H0, 4);
	memcpy(temp + 4, &H1, 4);
	memcpy(temp + 8, &H2, 4);
	memcpy(temp + 12, &H3, 4);
	memcpy(temp + 16, &H4, 4);
	
	free(padded);
	return sha1;
}
