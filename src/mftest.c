#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "metafile.h"
#include "sha1.h"

// #define FILE_NAME "loff.torrent"
#define FILE_NAME "dbc.torrent"

int main(int argc, char *argv[])
{
	uint8_t *hash;
	struct metafile_info mi;

	if(read_metafile(FILE_NAME, &mi) != 0)
	{
		fprintf(stderr, "Error reading metainfo file.\n");
		return -1;
	}
	printf("Metafile Info:\n");
	metafile_print(&mi);

	hash = sha1_compute(mi.info_val, mi.info_len);

	metafile_free(&mi);

	return 0;
}
