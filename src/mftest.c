#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "metafile.h"
#include "sha1.h"

#define FILE_NAME "loff.torrent"
// #define FILE_NAME "dbc.torrent"

int main(int argc, char *argv[])
{
	uint8_t *hash;
	struct metafile_info mi;
	int i;

	if(read_metafile(FILE_NAME, &mi) != 0)
	{
		fprintf(stderr, "Error reading metainfo file.\n");
		return -1;
	}
	printf("Metafile Info:\n");
	metafile_print(&mi);

	printf("\nSHA1 of info dictionary: ");
	hash = sha1_compute(mi.info_val, mi.info_len);
	for(i=0; i<20; i++)
	{
		printf("%02x", hash[i]);
	}	
	printf("\n");
	
	metafile_free(&mi);
	free(hash);

	return 0;
}
