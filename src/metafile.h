#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "bencode.h"

struct metafile_info
{
	char *announce_url;
	char *file_name; // filename with path
	long int length;
	long int piece_length;
	long int num_of_pieces;
	char (*pieces)[20];
};

void split_sha1s(char *sha1_str, struct metafile_info *mi);

int read_metafile(char *filename, struct metafile_info *mi)
{
	FILE *fp;
	int len, rv;
	char *contents, *temp;
	const char *str;
	bencode_t b1, b2, b3, b4, b5, b6; // bn where n represents level of nestedness

	rv = 0;
	fp = fopen(filename, "r");
	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	contents = malloc(len);
	len = fread(contents, 1, len, fp);
	fclose(fp);

	bencode_init(&b1, contents, len);
	// TODO: check if this is not a dictionary

	// announce
	bencode_dict_get_next(&b1, &b2, &str, &len);
	if(strncmp(str, "announce", 8) != 0)
	{
		rv = -1;
		goto cleanup;
	}
	bencode_string_value(&b2, &str, &len);
	(*mi).announce_url  = calloc(len+1, 1); // so that string is null terminated
	strncpy((*mi).announce_url, str, len);
	
	while(1)
	{
		bencode_dict_get_next(&b1, &b2, &str, &len);
		if(strncmp(str, "info", 4) == 0)
		{
			break;
		}				
	}

	bencode_dict_get_next(&b2, &b3, &str, &len); // this should be key files
	if(strncmp(str, "files", 5) != 0)
	{
		fprintf(stderr, "Expected the key 'files' but didn't find it.\n");
		rv = -1;
		goto cleanup;
	}

	// TODO: this assumes there is only one file. we should parse this list (in b3) in a while loop.
	// every dictionary in the list represents a file.
	bencode_list_get_next(&b3, &b4);
	bencode_dict_get_next(&b4, &b5, &str, &len);
	if(strncmp(str, "length", 6) != 0)
	{
		fprintf(stderr, "Expected key 'length' but didn't find it.\n");
		rv = -1;
		goto cleanup;
	}
	bencode_int_value(&b5, &(*mi).length);
	bencode_dict_get_next(&b4, &b5, &str, &len);
        if(strncmp(str, "md5sum", 5) == 0)
        {
        	bencode_dict_get_next(&b4, &b5, &str, &len);        
        }
	if(strncmp(str, "path", 4) != 0)
	{
		fprintf(stderr, "Expected key 'path' but didn't find it.\n");
		rv = -1;
		goto cleanup;
	}
	// TODO: this assumes there will ever be just one file name element in the list.
	// run a while loop to go through all the elements one by one. every element is a directory name
	// and the last element is file name.
	bencode_list_get_next(&b5, &b6);
	bencode_string_value(&b6, &str, &len);
	(*mi).file_name = calloc(len + 1, 1);
	strncpy((*mi).file_name, str, len);
	/********** Done with 'files' which is a list of dictionaries. ******************/

	bencode_dict_get_next(&b2, &b3, &str, &len); // this should be key 'name'
        if(strncmp(str, "name", 4) != 0)
        {
                fprintf(stderr, "Expected the key 'name' but didn't find it.\n");
                rv = -1;
                goto cleanup;
        }
	// TODO: assign top level directory name to the the bencode info struct.

	bencode_dict_get_next(&b2, &b3, &str, &len); // this should be key 'piece length'
        if(strncmp(str, "piece length", 12) != 0)
        {
                fprintf(stderr, "Expected the key 'piece length' but didn't find it.\n");
                rv = -1;
                goto cleanup;
        }
	bencode_int_value(&b3, &(*mi).piece_length);

	bencode_dict_get_next(&b2, &b3, &str, &len); // this should be key 'pieces'
        if(strncmp(str, "pieces", 6) != 0)
        {
                fprintf(stderr, "Expected the key 'pieces' but didn't find it.\n");
                rv = -1;
                goto cleanup;
        }
	bencode_string_value(&b3, &str, &len);
	printf("Length: %d. Num pieces: %d\n", len, len/20);
	temp = calloc(len + 1, 1);
	strncpy(temp, str, len);
	split_sha1s(temp, mi);
	free(temp);

cleanup:
	free(contents);
	return rv;
}

void split_sha1s(char *sha1_str, struct metafile_info *mi)
{
	char (*temp)[20];
	char *input;
	int len, i, count;

	len = strlen(sha1_str);
	count = len / 20;
	(*mi).num_of_pieces = count;
	
	// this is same as len. but this way it makes the intent clear.
	(*mi).pieces = calloc(sizeof(char[21]), count);
	temp = (*mi).pieces;
	input = sha1_str;
	for(i=0; i<len; i+=20)
	{
		strncpy(*temp, input, 20);
		temp += 1;
		input += 20;
	}
}

void metafile_print(struct metafile_info *mi)
{
	int i;
	char (*temp)[20];

	printf("Announce URL: %s\n", (*mi).announce_url);
	printf("File name: %s\n", (*mi).file_name);
	printf("Length: %ld\n", (*mi).length);
	printf("Piece length: %ld\n", (*mi).piece_length);
	printf("Number of pieces: %ld\n", (*mi).num_of_pieces);
	printf("Pieces:\n");
	
	temp = (*mi).pieces;

	for(i=0; i<(*mi).num_of_pieces; i++)
	{
		printf("  %d) %s\n", i, *temp);
		temp += 1;
	}
}

void free_metafile(struct metafile_info *mi)
{
	free((*mi).announce_url);
	free((*mi).file_name);
	free((*mi).pieces);
}
