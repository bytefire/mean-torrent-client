#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<curl/curl.h>
#include<curl/easy.h>

#include "metafile.h"
#include "sha1.h"
#include "peers.h"
#include "pwp.h"
#include "util.h"

#define PEER_ID_HEX "dd0e76bcc7f711e3af893c77e686ca85b8f12e24";
/*********************************************************************/

#define LOG_FILE "/home/bytefire/programming/code/bit-torrent-client/src/bin/logs/client.log"
#define USAGE_MESSAGE "Usage: client <path-to-torrent-file> {fresh|new}\n"

#define MODE_DEFAULT 0
#define MODE_FRESH 1
#define MODE_NEW 2

struct buffer_struct
{
	char *buffer;
	size_t size;
};

static size_t write_memory_callback(void *ptr, size_t size, size_t nmemb, void *data);
char *get_first_request(char *announce_url, char *info_hash_hex, char *peer_id_hex, long int file_size);
int parse_torrent_file(char *torrent_filename, struct metafile_info *mi, char *hash);
char *make_tracker_http_request(char *request, int *len);
int generate_announce_file(struct metafile_info *mi, char *hash, char *filename_to_generate);
int generate_metadata_file(char *announce_filename, struct metafile_info *mi, char *filename_to_generate);
int create_resume_file(const char *filename, int num_of_pieces);

int main(int argc, char *argv[])
{	
	char *torrent_filename = NULL;
	char *filename = NULL;
	char *announce_filename = NULL;
	char *metadata_filename = NULL;
	char *resume_filename = NULL;
	char *saved_filename = NULL;
	char hash[41];
	struct metafile_info mi;
	struct stat s;
	int rv = 0;
	int torrent_already_present = 1;

	bf_logger_init(LOG_FILE);

	if(argc < 2 || argc > 3) 
	{
		printf(USAGE_MESSAGE);
		return -1;
	}

	char *path_to_torrent = argv[1];
	// initialise mode
	int mode = MODE_DEFAULT;
	if(argc == 3)
	{
		if(strcmp(argv[2], "fresh") == 0)
		{
			mode = MODE_FRESH;
		}
		else if(strcmp(argv[2], "new") == 0)
		{
			mode = MODE_NEW;
		}
		else
		{
			printf(USAGE_MESSAGE);
			return -1;
		}
	}	

	filename = util_extract_filename(path_to_torrent);
	// check if folder with the same name as filename exists. if not then create one.
	if(stat(filename, &s) == -1)
	{
		// create the folder
		if(mkdir(filename, 0700) != 0)
		{
			bf_log("[ERROR] client.main(): There was an error creating directory %s.\n", filename);
			perror(NULL);
			goto cleanup;
		}
	}

	// move into that directory
	if(chdir(filename) == -1)
	{
		bf_log("[ERROR] client.main(): Problem changing to directory %s.\n", filename);
		perror(NULL);
		goto cleanup;
	}
	
	torrent_filename = util_concatenate(filename, ".torrent");
	// check if the folder contains torrent file (i.e. filename+".torrent")
	if(stat(torrent_filename, &s) == -1)
	{
		torrent_already_present = 0;
		// copy the torrent file into this folder
		// src: path_to_torrent; dest: torrent_filename
		char *relative_path = util_concatenate("../", path_to_torrent);	
		if(util_copy_file(relative_path, torrent_filename) < 0)
		{
			bf_log("[ERROR] client.main(): Failed to copy the torrent file into the data folder.\n");
			free(relative_path);
			goto cleanup;
		}
		free(relative_path);
	}

	announce_filename = util_concatenate(filename, ".announce");
	metadata_filename = util_concatenate(filename, ".metadata");
	resume_filename = util_concatenate(filename, ".resume");
	saved_filename = util_concatenate(filename, ".saved");

	// if torrent isn't already present we assume that it is a DIFFERENT torrent.
	if((mode == MODE_NEW) || (!torrent_already_present))
	{
		// if mode is MODE_NEW then delete announce file, metadata file, resume file and savedfile file
		if(stat(announce_filename, &s) == 0)
        	{
			remove(announce_filename);
		}

		if(stat(metadata_filename, &s) == 0)
                {
                        remove(metadata_filename);
                }

		if(stat(resume_filename, &s) == 0)
                {
                        remove(resume_filename);
                }

		if(stat(saved_filename, &s) == 0)
                {
                        remove(saved_filename);
                }
	}


	if(parse_torrent_file(torrent_filename, &mi, hash) != 0)
        {
               	rv = -1;
       	        goto cleanup;
        }

	// if either metadata file doesn't exist of mode is fresh then generate new announce AND metadata files
        if((stat(metadata_filename, &s) == -1) || (mode == MODE_FRESH))
        {
		// create a new announce file
		generate_announce_file(&mi, hash, announce_filename);
		// create a new metadata file
		generate_metadata_file(announce_filename, &mi, metadata_filename);	
	}

	// if saved file doesn't already exist then create a new one along with new resume file.
	// NOTE that whenever we create a new saved file we must also create a new resume file.
	if(stat(saved_filename, &s) == -1)
	{
	        if(util_create_file_of_size(saved_filename, mi.length) != 0)
        	{
                	bf_log("[ERROR] client.main(): Failed to create saved file. Aborting.\n");
	                rv = -1;
        	        goto cleanup;
        	}
		// create a resume file which is just a bit string containing one (unset) bit for every piece.
 		if(create_resume_file(resume_filename, mi.num_of_pieces) != 0)
		{
			bf_log("[ERROR] client.main(): Failed to create resume file. Aborting.\n");
			rv = -1;
			goto cleanup;
		}
	}

	// if saved file doesn't exist then report error and abort
	if(stat(saved_filename, &s) == -1)
	{
		bf_log("[ERROR] client.main(): Saved file should exist by now but it doesn't. Aborting.\n");
		rv = -1;
		goto cleanup;
	}

	// free mi instance as it won't be needed any further. note that this free method will be called again 
	// under cleanup label but that doesn't matter as metafile_free() is idempotent.
	metafile_free(&mi);

	// call pwp_start
	if(pwp_start(metadata_filename, saved_filename, resume_filename) != 0)
        {
                bf_log("[ERROR] client.main(): There was a problem communicating with remote peer.\n");
        }
        else
        {
                bf_log("[LOG] client.main(): Performed pwp comm. successfully.\n");
        }

cleanup:
	if(filename)
	{
		free(filename);
	}
	if(torrent_filename)
	{
		free(torrent_filename);
	}
	if(announce_filename)
	{
		free(announce_filename);
	}
	if(metadata_filename)
	{
		free(metadata_filename);
	}
	if(resume_filename)
	{
		free(resume_filename);
	}
	if(saved_filename)
	{
		free(saved_filename);
	}
	metafile_free(&mi);

	bf_logger_end();

	return rv;
}

int generate_announce_file(struct metafile_info *mi, char *hash, char *filename_to_generate)
{
	int rv = 0;
	int len;
	char *request_url = NULL;
	char *tracker_response = NULL;
	char *peer_id_hex = PEER_ID_HEX;

        request_url = get_first_request(mi->announce_url, hash, peer_id_hex, mi->length);
        tracker_response = (char *)make_tracker_http_request(request_url, &len);
        util_write_new_file(filename_to_generate, (uint8_t *)tracker_response, len);

cleanup:
	if(request_url)
	{
		free(request_url);
	}	
	if(tracker_response)
	{
		free(tracker_response);
	}

	return rv;
}

int generate_metadata_file(char *announce_filename, struct metafile_info *mi, char *filename_to_generate)
{
	int rv = 0;
	uint8_t *announce_data = NULL;
	int len;
	uint8_t info_hash[20];
	uint8_t our_peer_id[20];
	char *peer_id_hex = PEER_ID_HEX;

	if(util_read_whole_file(announce_filename, &announce_data, &len) != 0)
        {
		bf_log("[ERROR] generate_metadata_file(): Failed to read announce file.\n");
		rv = -1;
		goto cleanup;
        }
	
        sha1_compute(mi->info_val, mi->info_len, info_hash);
        if(util_hex_to_ba(peer_id_hex, our_peer_id) != 0)
	{
		bf_log("[ERROR] generate_metadata_file(): Failed during call to util_hex_to_ba().\n");
		rv = -1;
		goto cleanup;
	}
        peers_create_metadata(announce_data, len, info_hash, mi->pieces,  our_peer_id, mi->length, mi->num_of_pieces, mi->piece_length, filename_to_generate);
cleanup:
	if(announce_data)
	{
		free(announce_data);
	}

	return rv;
}

int create_resume_file(const char *filename, int num_of_pieces)
{
	int rv = 0;
	int size_in_bytes = num_of_pieces / 8;
	size_in_bytes += (num_of_pieces % 8) ? 1 : 0;
	uint8_t *data = (uint8_t *)calloc(size_in_bytes, 1);
	
	if(util_write_new_file(filename, data, size_in_bytes) != 0)
	{
		rv = -1;
	}

	free(data);

	return rv;
}

char *make_tracker_http_request(char *request, int *len)
{
	curl_global_init(CURL_GLOBAL_ALL);
        CURL *my_handle;
        CURLcode result;
	struct buffer_struct output;

	output.buffer = NULL;
        output.size = 0;
        my_handle = curl_easy_init();
        curl_easy_setopt(my_handle, CURLOPT_WRITEFUNCTION, write_memory_callback);
        curl_easy_setopt(my_handle, CURLOPT_WRITEDATA, (void *)&output);
        curl_easy_setopt(my_handle, CURLOPT_URL, request);
        result = curl_easy_perform(my_handle);
        curl_easy_cleanup(my_handle);	
	
	*len = output.size;
	// is this a memory leak? output.buffer is realloc'ed in write_memory_callback function but not sure if curl handles this already.
	return output.buffer;
}

int parse_torrent_file(char *torrent_filename, struct metafile_info *mi, char *hash)
{
	uint8_t sha1[20];
	int i;

	if(read_metafile(torrent_filename, mi) != 0)
        {
                bf_log("[ERROR] parse_torrent_file(): Error reading torrent file when calling read_metafile().\n");
                return -1;
        }
        printf("Metafile Info:\n");
        metafile_print(mi);

        printf("\nSHA1 of info dictionary: ");
        sha1_compute(mi->info_val, mi->info_len, sha1);
	
	for(i=0; i<20; i++)
        {
                snprintf(hash+(2*i), 3, "%02x", sha1[i]);
        }
	hash[40] = '\0';

	printf("%s\n", hash);
	
	return 0;
}

char *get_first_request(char *announce_url, char *info_hash_hex, char *peer_id_hex, long int file_size)
{
/*
	char *request = "http://tracker.documentfoundation.org:6969/announce?info_hash=\%2f\%7e\%c3\%b7\%42\%ec\%28\%28\%64\%92\%aa\%ad\%58\%f7\%58\%a9\%7c\%8d\%dd\%55&peer_id=\%dd\%0e\%76\%bc\%c7\%f7\%11\%e3\%af\%89\%3c\%77\%e6\%86\%ca\%85\%b8\%f1\%2e\%20&port=6881&uploaded=0&downloaded=0&left=206739284&compact=1&event=started";
*/
	char *request;
	char *request_format = "%s?info_hash=%s&peer_id=%s&port=6881&uploaded=0&downloaded=0&left=%d&compact=1&event=started";
	char url_encoded_info_hash[61];
	char url_encoded_peer_id[61];
	int i, j;
	for(i=0, j=0; i<40; i+=2)
	{
		url_encoded_info_hash[j] = '%';
		url_encoded_info_hash[j+1] = info_hash_hex[i];
		url_encoded_info_hash[j+2] = info_hash_hex[i+1];

		url_encoded_peer_id[j] = '%';
                url_encoded_peer_id[j+1] = peer_id_hex[i];
                url_encoded_peer_id[j+2] = peer_id_hex[i+1];

		j += 3;
	}

	url_encoded_info_hash[60] = '\0';
	url_encoded_peer_id[60] = '\0';

	request = calloc(512, 1);

	sprintf(request, request_format, announce_url, url_encoded_info_hash, url_encoded_peer_id, file_size);
	
	return request;
}


static size_t write_memory_callback(void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t real_size = size * nmemb;
	struct buffer_struct *mem = (struct buffer_struct *)data;

	mem->buffer = realloc(mem->buffer, mem->size + real_size + 1);
	if(mem->buffer)
	{
		memcpy(&(mem->buffer[mem->size]), ptr, real_size);
		mem->size += real_size;
		mem->buffer[mem->size] = '\0';
	}
	return real_size;
}
