#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "metafile.h"

#define FILE_NAME "dbc.torrent"

int main(int argc, char *argv[])
{
	struct metafile_info mi;

	if(read_metafile(FILE_NAME, &mi) != 0)
	{
		fprintf(stderr, "Error reading metainfo file.\n");
		return -1;
	}
	printf("Metafile Info:\n");
	metafile_print(&mi);

	free_metafile(&mi);

	return 0;
}
