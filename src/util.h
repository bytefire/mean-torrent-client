#ifndef UTIL_H
#define UTIL_H

#pragma once

#include<stdlib.h>
#include<stdio.h>
#include<stdint.h>
#include<string.h>

int util_read_whole_file(char *filename, uint8_t **contents, int *file_len)
{
        FILE *fp;
	int len;

        if((fp =fopen(filename, "r")) == 0)
        {
                fprintf(stderr, "Failed to open file %s.\n", filename);
                return -1;
        }

        fseek(fp, 0L, SEEK_END);
        len = ftell(fp);
	*file_len = len;
        fseek(fp, 0L, SEEK_SET);
        (*contents) = malloc(len);
        len = fread((*contents), 1, len, fp);
        fclose(fp);

        return 0;
}

int util_hex_to_ba(char *hex, uint8_t **ba)
{
    int len;
    char *temp, buf[3];
    uint8_t *curr;
    int i;
      
    if(*ba == NULL)
    {
        return -1;
    }
      
    len = strlen(hex);
    if(len % 2 != 0)
    {
        return -1;
    }
      
    temp = hex;
    curr = *ba;
    buf[2] = '\0';
    for(i=0; i<len; i+=2)
    {
        strncpy(buf, temp, 2);
        *curr = (uint8_t)strtol(buf, NULL, 16);
        curr++;
        temp += 2;
    }
      
    return 0;
} 

void util_append_to_file(char *filename, char *str, int len)
{
        FILE *fp;
        fp = fopen(filename, "a");
        if(!fp)
        {
                fprintf(stderr, "Failed to open file.\n");
                return;
        }
        int i;
        for(i = 0; i<len; i++)
        {
                fputc(str[i], fp);
        }
        fclose(fp);
}

FILE *util_create_file_of_size(const char *file_name, long bytes)
{
	FILE *fp = fopen(file_name, "w+");
	 if(!fp)
        {
                fprintf(stderr, "[ERROR] util_create_file_of_size(): Failed to create file.\n");
                return fp;
        }

	fseek(fp, bytes - 1, SEEK_SET);
	fputc('\n', fp);
	return fp;
}
#endif // UTIL_H
