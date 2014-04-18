#include<stdio.h>
#include<stdlib.h>
#include<string.h>

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

char *sha1_compute(char *msg, int msg_len)
{
	// pad msg
	int pad_len;
	char *padded;
	char sha1[20];

	padded = pad_msg(msg, msg_len, &pad_len);
	// process in 512 byte chunks


	// endian-ness

	return sha1;
}
