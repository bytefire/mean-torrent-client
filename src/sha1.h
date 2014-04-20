#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>


uint32_t H0 = 0x67452301;
uint32_t H1 = 0xEFCDAB89;
uint32_t H2 = 0x98BADCFE;
uint32_t H3 = 0x10325476;
uint32_t H4 = 0xC3D2E1F0;

/*
unsigned int H0 = 0x01234567; // 0x67452301;
unsigned int H1 = 0x89ABCDEF; // 0xEFCDAB89;
unsigned int H2 = 0xFEDCBA89; // 0x98BADCFE;
unsigned int H3 = 0x76543210; // 0x10325476;
unsigned int H4 = 0xF0E1D2C3; // 0xC3D2E1F0;
*/

uint32_t rotate_left(uint32_t val, int by)
{
	uint32_t rotated = (val<<by) | (val>>(32-by));
	return rotated;
}

void swap_chars(uint8_t *c1, uint8_t *c2)
{
        uint8_t temp = *c1;
        *c1 = *c2;
        *c2 = temp;
}

void small_to_big_endian(uint8_t *a, int len)
{
        int i;
        uint8_t *temp;

        temp = a;
        // simply reverse the bytes
        for(i=0;i<len/2;i++)
        {
                swap_chars(&temp[i], &temp[len-i-1]);
        }
}

uint8_t *pad_msg(uint8_t *msg, long long msg_len, int *pad_len)
{
	*pad_len = (msg_len % 64) < 56 ? ((msg_len / 64 + 1) * 64) : ((msg_len / 64 +2) * 64);
	uint8_t *buf = calloc(*pad_len, 1);
	memcpy(buf, msg, msg_len);
	buf[msg_len] = 0x80;
	
	msg_len *= 8;
	small_to_big_endian((uint8_t *)&msg_len, 8);
	memcpy((buf +(*pad_len) - 8),  &msg_len, 8);
	
	return buf;
}

uint32_t f(int t, uint32_t B, uint32_t C, uint32_t D)
{
    // f(t;B,C,D) = (B AND C) OR ((NOT B) AND D)         ( 0 <= t <= 19)
    if(t>=0 && t<=19)
    {
        return ((B & C) | ((~B) & D));
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

    return 0;
}
  
uint32_t get_k(int t)
{
    // K(t) = 5A827999         ( 0 <= t <= 19)
    if(t>=0 && t<=19)
    {
        return 0x5A827999; 
		// 0x9979825A;
    }
    // K(t) = 6ED9EBA1         (20 <= t <= 39)
    if(t>=20 && t<=39)
    {
        return 0x6ED9EBA1; 
		// 0xA1EBD96E;
    }
    // K(t) = 8F1BBCDC         (40 <= t <= 59)
    if(t >= 40 && t<=59)
    {
        return  0x8F1BBCDC; 
		//  0xDCBC1B8F;
    }
    // K(t) = CA62C1D6         (60 <= t <= 79)
    if(t>=60 && t<=79)
    {
        return 0xCA62C1D6; 
		// 0xD6C162CA;
    }
    
    return 0;
}

void process_block(uint8_t *M)
{
	int t;
	uint32_t temp;
	uint32_t A, B, C, D, E;
	uint32_t W[80]; // 80 words
	// memcpy(W, M, 64); // 64 bytes == 16 words == 512 bits
	for(t = 0; t < 16; t++)
    	{
        	W[t] = M[t * 4] << 24;
	        W[t] |= M[t * 4 + 1] << 16;
        	W[t] |= M[t * 4 + 2] << 8;
       		W[t] |= M[t * 4 + 3];
   	}	

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
}

// uses the method described here: https://tools.ietf.org/html/rfc3174#section-6.1 
uint8_t *sha1_compute(uint8_t *msg, int msg_len)
{
	// pad msg
	int pad_len, i;
	uint8_t *padded;
	uint8_t *sha1 = malloc(20);
	uint8_t *temp;

	padded = pad_msg(msg, msg_len, &pad_len);
	// process in 512 byte chunks
	temp = padded;
	for(i=0; i<pad_len; i+=64)
	{
		process_block(temp);
		temp += 64;
	}

	small_to_big_endian((unsigned char *)&H0, 4);
	small_to_big_endian((unsigned char *)&H1, 4);
	small_to_big_endian((unsigned char *)&H2, 4);
	small_to_big_endian((unsigned char *)&H3, 4);
	small_to_big_endian((unsigned char *)&H4, 4);
	
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
