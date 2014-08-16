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

#define LOG_FILE "logs/client.log"
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
char *make_tracker_http_request(char *request);
int generate_announce_file(struct metafile_info *mi, char *hash, char *filename_to_generate);
int generate_metadata_file(char *announce_filename, struct metafile_info *mi, char *filename_to_generate);

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
	// TODO: implement following method.
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

	if(mode == MODE_NEW)
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

	// if either announce file doesn't exist of mode is fresh then generate new announce AND metadata files
	if((stat(announce_filename, &s) == -1) || (mode == MODE_FRESH))
	{
		if(parse_torrent_file(torrent_filename, &mi, hash) != 0)
	        {
                	rv = -1;
        	        goto cleanup;
	        }
		// create a new announce file
		generate_announce_file(&mi, hash, announce_filename);
		// create a new metadata file
		generate_metadata_file(announce_filename, &mi, metadata_filename);
	}

/*
	if(!//TODO: resume file doesn't exist)
	{
		// TODO: create a resume file
	}

	if(!//TODO: savedfile doesn't exists)
	{
		// TODO: create savedfile
	}

*/	// call pwp_start
	 if(pwp_start(metadata_filename) != 0)
        {
                bf_log("[ERROR] client.main(): There was a problem communicating with remote peer.\n");
        }
        else
        {
                bf_log("{LOG] client.main(): Performed pwp comm. successfully.\n");
        }

/*---------------------------------------------------------------------------------------------------*/
/*
	int rv;
	char *request_url;
	char *peer_id_hex = PEER_ID_HEX;	
	char *hash = malloc(41);
        struct metafile_info mi;
	uint8_t *info_hash;
	uint8_t *handshake;
	uint8_t *our_peer_id;
	int hs_len, len;	
	
	char *tracker_response;

	rv=0;

	if(parse_metainfo_file(&mi, &hash) != 0)
	{
		rv = -1;
		goto cleanup;
	}	

	request_url = get_first_request(mi.announce_url, hash, peer_id_hex, mi.length);
	tracker_response = (char *)make_tracker_http_request(request_url);
	write_to_file(tracker_response);
	
	if(util_read_whole_file(ANNOUNCE_FILE, (uint8_t **)(&tracker_response), &len) != 0)
	{
			goto cleanup;
	}
	
	info_hash = sha1_compute(mi.info_val, mi.info_len);
	
	our_peer_id = malloc(20);
	util_hex_to_ba(peer_id_hex, &our_peer_id);
	peers_create_metadata(tracker_response, len, info_hash, mi.pieces,  our_peer_id, mi.num_of_pieces, mi.piece_length);

	// for testing only:
	// handshake = compose_handshake(info_hash, our_peer_id, &hs_len);
	
	printf("LibCurl rules.\n");
*/

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

/************************************************************************************************/
/*
	metafile_free(&mi);
        free(hash);
	free(request_url);
	free(tracker_response);
	free(info_hash);
	if(our_peer_id)
	{
		free(our_peer_id);
	}
*/
	bf_logger_end();

	return rv;
}

int generate_announce_file(struct metafile_info *mi, char *hash, char *filename_to_generate)
{
	int rv = 0;
	//char hash[41];
        //struct metafile_info mi;
	char *request_url = NULL;
	char *tracker_response = NULL;
	char *peer_id_hex = PEER_ID_HEX;

/*
	if(parse_torrent_file(torrent_filename, &mi, hash) != 0)
        {
                rv = -1;
                goto cleanup;
        }
*/

        request_url = get_first_request(mi->announce_url, hash, peer_id_hex, mi->length);
        tracker_response = (char *)make_tracker_http_request(request_url);
        util_write_new_file(filename_to_generate, tracker_response);

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
	uint8_t *info_hash = NULL;
	uint8_t our_peer_id[20];
	char *peer_id_hex = PEER_ID_HEX;

	if(util_read_whole_file(announce_filename, &announce_data, &len) != 0)
        {
		bf_log("[ERROR] generate_metadata_file(): Failed to read announce file.\n");
		rv = -1;
		goto cleanup;
        }
	// TODO: sha1_compute() should take in a 20-byte array rather than malloc a new one every time!
	//	that way the caller can decide whether it wants to allocate the 20 bytes on stack or heap.
        info_hash = sha1_compute(mi->info_val, mi->info_len);
        if(util_hex_to_ba(peer_id_hex, our_peer_id) != 0)
	{
		bf_log("[ERROR] generate_metadata_file(): Failed during call to util_hex_to_ba().\n");
		rv = -1;
		goto cleanup;
	}
        peers_create_metadata(announce_data, len, info_hash, mi->pieces,  our_peer_id, mi->num_of_pieces, mi->piece_length, filename_to_generate);
cleanup:
	if(announce_data)
	{
		free(announce_data);
	}
	if(info_hash)
	{
		free(info_hash);
	}

	return rv;
}

char *make_tracker_http_request(char *request)
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
	
	return output.buffer;
}

int parse_torrent_file(char *torrent_filename, struct metafile_info *mi, char *hash)
{
	uint8_t *sha1;
	int i;

	if(read_metafile(torrent_filename, mi) != 0)
        {
                bf_log("[ERROR] parse_torrent_file(): Error reading torrent file when calling read_metafile().\n");
                return -1;
        }
        printf("Metafile Info:\n");
        metafile_print(mi);

        printf("\nSHA1 of info dictionary: ");
        sha1 = sha1_compute(mi->info_val, mi->info_len);
	
	for(i=0; i<20; i++)
        {
                snprintf(hash+(2*i), 3, "%02x", sha1[i]);
        }
	hash[40] = '\0';

	printf("%s\n", hash);
	
	free(sha1);
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
	// TODO: should use snprintf and also check if whole url has been copied. if not then realloc and snprintf again.
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
