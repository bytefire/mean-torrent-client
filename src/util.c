#include<stdlib.h>
#include<stdio.h>
#include<stdint.h>
#include<string.h>

#include "util.h"

#define BUF_LEN 512

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
	
	uint8_t *buf = (*contents);
	int bytes_read = 0;
	while(len > 0)
	{
		bytes_read = fread(buf, 1, len, fp);
		buf += bytes_read;
		len = len - bytes_read;
	}
        fclose(fp);

        return 0;
}

int util_hex_to_ba(char *hex, uint8_t *ba)
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
    curr = ba;
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


	int bytes_written = 0;
	while(len > 0)
	{
		bytes_written = fwrite(str, 1, len, fp);
		len -= bytes_written;
		str += bytes_written;
	}

        fclose(fp);
}

int util_create_file_of_size(const char *file_name, long bytes)
{
	FILE *fp = fopen(file_name, "w+");
	 if(!fp)
        {
                fprintf(stderr, "[ERROR] util_create_file_of_size(): Failed to create file.\n");
                return -1;
        }

	fseek(fp, bytes - 1, SEEK_SET);
	fputc('\0', fp);
	fclose(fp);
	return 0;
}

int util_read_file_chunk(char *filename, int start_idx, int chunk_len,  uint8_t *contents)
{
        FILE *fp;
        int len = chunk_len;

        if((fp =fopen(filename, "r")) == 0)
        {
                fprintf(stderr, "Failed to open file %s.\n", filename);
                return -1;
        }

        fseek(fp, start_idx, SEEK_SET);

        while((len = fread(contents, 1, chunk_len, fp)) < chunk_len)
	{
		chunk_len = chunk_len - len;
		contents += len;
	}

        fclose(fp);

        return 0;
}

// concatenates the two null terminated strings and returns a newly malloc'd combined string.
char *util_concatenate(char *str1, char *str2)
{
	int len = strlen(str1) + strlen(str2);
	char *combined = (char *)malloc(len);

	strcpy(combined, str1);
	strcat(combined, str2);

	return combined;
}

int util_copy_file(char *src_path, char *dest_path)
{
	FILE *src = NULL;
	FILE *dest = NULL;
	int rv = 0;
	uint8_t buf[BUF_LEN];
	int bytes_read, bytes_written;

	// open source file (src)  using fopen(src_path, "r")
	if((src =fopen(src_path, "r")) == 0)
        {
                fprintf(stderr, "[ERROR] util_copy_file(): Failed to open source file %s.\n", src_path);
                perror(NULL);
		rv = -1;
		goto cleanup;
        }
	// open destination file (dest) using fopen(dest_path, "w")
	if((dest =fopen(dest_path, "w")) == 0)
        {
                fprintf(stderr, "[ERROR] util_copy_file(): Failed to open destination file %s.\n", dest_path);
                perror(NULL);
		rv = -1;
                goto cleanup;
        }
	// create a buffer (buf) of length 512 bytes
	// while fread(buf, 1, 512, src) returns a positive number,
	// 	fwrite(buf, 1, len_read, dest) <--- this will need to go in a loop to ensure all bytes are written
	while((bytes_read = fread(buf, 1, BUF_LEN, src)) > 0)
	{
		bytes_written = 0;
		while((bytes_written += fwrite(buf + bytes_written, 1, bytes_read - bytes_written, dest)) < bytes_read);
	}
cleanup:
	// close src
	if(src)
	{
		fclose(src);
	}
	// close dest
	if(dest)
	{
		fclose(dest);
	}

	return rv;
}

char *util_extract_filename(char *path)
{
        if(path == NULL || strlen(path) == 0)
        {
                printf("[ERROR] extract_filename(): 'path' is either null or empty.\n");
                return NULL;
        }
        char *last_dot = strrchr(path, '.');
        if(last_dot == NULL)
        {
                printf("[ERROR] extract_filename(): 'path' doesn't contain a dot.\n");
                return NULL;
        }

        char *first_char = strrchr(path, '/');
        if(first_char == NULL)
        {
                first_char = path;
        }
        else
        {
                first_char = first_char + 1;
        }

        if(first_char >= last_dot)
        {
                printf("[ERROR] extract_filename(): Last dot occurs before the first character of file name.\n");
                return NULL;
        }

        int len = last_dot - first_char + 1;
        char *filename = (char *)malloc(len);
        memcpy(filename, first_char, len-1);
        filename[len-1] = '\0';

        return filename;
}

int util_write_new_file(char *filename, uint8_t *contents, int len)
{
	FILE *fp;
        fp = fopen(filename, "w");
        if(!fp)
        {
                fprintf(stderr, "[ERROR] util_write_new_file(): Failed to open or create file %s.\n", filename);
                return -1;
        }

	int bytes_written = 0;
        while(len > 0)
        {
                bytes_written = fwrite(contents, 1, len, fp);
                len -= bytes_written;
                contents += bytes_written;
        }

        fclose(fp);
	
	return 0;
}
