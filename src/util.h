#ifndef UTIL_H
#define UTIL_H

#pragma once

#include<stdlib.h>
#include<stdio.h>
#include<stdint.h>

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

#endif // UTIL_H
