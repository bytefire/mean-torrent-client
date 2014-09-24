#ifndef METAFILE_H
#define METAFILE_H

#pragma once

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
	char *pieces;
	int info_len;
	uint8_t *info_val;
};

int parse_multiple_files(bencode_t *files_list, struct metafile_info *mi);

int read_metafile(char *filename, struct metafile_info *mi);

void metafile_print(struct metafile_info *mi);

void metafile_free(struct metafile_info *mi);
#endif // METAFILE_H
