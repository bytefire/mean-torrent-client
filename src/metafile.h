#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

#include "bencode.h"

struct metafile_info
{
	char *announce_url;
	char *file_name; // filename with path
	char md5[32];
	char *top_most_directory; // the 'name' field in info dictionary
	long int length;
	long int piece_length;
	long int num_of_pieces;
	char (*pieces)[20];
	int info_len;
	uint8_t *info_val;
};

void split_sha1s(char *sha1_str, int len, struct metafile_info *mi);

int parse_multiple_files(bencode_t *files_list, struct metafile_info *mi);

int read_metafile(char *filename, struct metafile_info *mi)
{
	FILE *fp;
	int len, rv;
	char *contents, *temp;
	const char *str;
	bencode_t b1, b2, b3; // bn where n represents level of nestedness

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

	mi->info_len = b1.str - b2.start;
	mi->info_val = malloc(mi->info_len);
	memcpy(mi->info_val, b2.start, mi->info_len);

	bencode_dict_get_next(&b2, &b3, &str, &len); // this should be key files for multi-file torrent
	if(strncmp(str, "length", 6) == 0)
	{
		bencode_int_value(&b3, &(*mi).length);
        	bencode_dict_get_next(&b2, &b3, &str, &len);
        	if(strncmp(str, "md5sum", 5) == 0)
       		{
			// TODO: populate md5
			bencode_dict_get_next(&b2, &b3, &str, &len);
	        }
		// else b3 must now point to value of the key 'name' in info dictionary.
	}
	else
	{
		if(strncmp(str, "files", 5) != 0)
	        {
        	        fprintf(stderr, "Expected the key 'length' or 'files' but didn't find either.\n");
                	rv = -1;
                	goto cleanup;
	        }

		// here b3 contains value for the key 'files'
		if(parse_multiple_files(&b3, mi) == -1)
		{
			rv = -1;
			goto cleanup;
		}

		bencode_dict_get_next(&b2, &b3, &str, &len); // this should be key 'name'
	}

	/********** Done with 'files' which is a list of dictionaries (or single file) and b3 has value of 'name' key. ******************/
        
	if(strncmp(str, "name", 4) != 0)
        {
                fprintf(stderr, "Expected the key 'name' but didn't find it.\n");
                rv = -1;
                goto cleanup;
        }

	bencode_string_value(&b3, &str, &len);
        mi->top_most_directory = calloc(len + 1, 1);
        strncpy(mi->top_most_directory, str, len);

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
	memcpy(temp, str, len);
	split_sha1s(temp, len, mi);
	free(temp);

cleanup:
	free(contents);
	return rv;
}

// len param is needed because if we do strlen then we can hit a null character in middle of sha1_str which is a
// binray string
void split_sha1s(char *sha1_str, int len, struct metafile_info *mi)
{
	char (*temp)[20];
	char *input;
	int i, count;

	//len = strlen(sha1_str);
	count = len / 20;
	(*mi).num_of_pieces = count;
	
	// this is same as len. but this way it makes the intent clear.
	(*mi).pieces = calloc(sizeof(char[21]), count);
	temp = (*mi).pieces;
	input = sha1_str;
	for(i=0; i<len; i+=20)
	{
		memcpy(*temp, input, 20);
		temp += 1;
		input += 20;
	}
}

int parse_multiple_files(bencode_t *files_list, struct metafile_info *mi)
{
	//        b4, b5, b6
	bencode_t ba, bb, bc;
	const char *str;
	int len;
	
	// TODO: this assumes there is only one file. we should parse this list (in b3) in a while loop.
        // every dictionary in the list represents a file.
        bencode_list_get_next(files_list, &ba);
        bencode_dict_get_next(&ba, &bb, &str, &len);
        if(strncmp(str, "length", 6) != 0)
        {
                fprintf(stderr, "Expected key 'length' but didn't find it.\n");
                return -1;
        }
        bencode_int_value(&bb, &(*mi).length);
        bencode_dict_get_next(&ba, &bb, &str, &len);
        if(strncmp(str, "md5sum", 5) == 0)
        {
		// TODO: parse md5 here
                bencode_dict_get_next(&ba, &bb, &str, &len);
        }
        if(strncmp(str, "path", 4) != 0)
        {
                fprintf(stderr, "Expected key 'path' but didn't find it.\n");
                return -1;
        }
        // TODO: this assumes there will ever be just one file name element in the list.
        // run a while loop to go through all the elements one by one. every element is a directory name
        // and the last element is file name.
        bencode_list_get_next(&bb, &bc);
        bencode_string_value(&bc, &str, &len);
        (*mi).file_name = calloc(len + 1, 1);
        strncpy((*mi).file_name, str, len);

	return 0;
}

void metafile_print(struct metafile_info *mi)
{
	//int i;
	//char (*temp)[20];

	printf("Announce URL: %s\n", mi->announce_url);
	printf("Top-most directory: %s\n", mi->top_most_directory);
	printf("File name: %s\n", mi->file_name);
	printf("Length: %ld\n", mi->length);
	printf("Piece length: %ld\n", mi->piece_length);
	printf("Number of pieces: %ld\n", mi->num_of_pieces);
	printf("Pieces:\n");
	
	/*
	temp = (*mi).pieces;

	for(i=0; i<(*mi).num_of_pieces; i++)
	{
		printf("  %d) %s\n", i, *temp);
		temp += 1;
	}
	*/
}

void metafile_free(struct metafile_info *mi)
{
	free((*mi).announce_url);
	free((*mi).file_name);
	free(mi->top_most_directory);
	free((*mi).pieces);
	free(mi->info_val);
}
