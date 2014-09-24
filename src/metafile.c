#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

#include "metafile.h"

#include "bencode.h"
#include "bf_logger.h"

int read_metafile(char *filename, struct metafile_info *mi)
{
	FILE *fp;
	int len, rv;
	char *contents = NULL;
	const char *str;
	bencode_t b1, b2, b3; // bn where n represents level of nestedness

	rv = 0;
	
	util_read_whole_file(filename, &contents, &len);

	bencode_init(&b1, contents, len);

	if(!bencode_is_dict(&b1))
	{
		bf_log("[ERROR] read_metafile(): The metafile %s seems to be malformed.Aborting.\n", filename);
		rv = -1;
		goto cleanup;
	}

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

		// since single file won't have file_name set so zero it out:
		mi->file_name = '\0';
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
	mi->num_of_pieces = len/20;
	printf("Length: %d. Num pieces: %d\n", len, mi->num_of_pieces);
	mi->pieces = (uint8_t *)malloc(len);
	memcpy((char *)(mi->pieces), str, len);

cleanup:
	if(contents)
	{
		free(contents);
	}

	return rv;
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
}

void metafile_free(struct metafile_info *mi)
{
	if(mi->announce_url)
	{
		free(mi->announce_url);
		mi->announce_url = NULL;
	}

	if(mi->file_name)
	{
		free(mi->file_name);
		mi->file_name = NULL;
	}

	if(mi->top_most_directory)
	{
		free(mi->top_most_directory);
		mi->top_most_directory = NULL;
	}

	if(mi->pieces)
	{
		free(mi->pieces);
		mi->pieces = NULL;
	}

	if(mi->info_val)
	{
		free(mi->info_val);
		mi->info_val = NULL;
	}
}
