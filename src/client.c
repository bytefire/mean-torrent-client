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

#define FILE_NAME "/home/bytefire/dev/code/bit-torrent-client/files/loff.torrent"
//#define FILE_NAME "~/dev/code/bit-torrent-client/files/dbc.torrent"
#define ANNOUNCE_FILE "/home/bytefire/dev/code/bit-torrent-client/files/loff.announce"
#define PEER_ID_HEX "dd0e76bcc7f711e3af893c77e686ca85b8f12e21";


struct buffer_struct
{
	char *buffer;
	size_t size;
};

static size_t write_memory_callback(void *ptr, size_t size, size_t nmemb, void *data);

char *get_first_request(char *announce_url, char *info_hash_hex, char *peer_id_hex, long int file_size);

int parse_metainfo_file(struct metafile_info *mi, char **hash);

char *make_tracker_http_request(char *request);

void write_to_file(char *str);

int main()
{
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
	peers_create_metadata(tracker_response, info_hash, our_peer_id, mi.num_of_pieces, mi.piece_length);

	// for testing only:
	// handshake = compose_handshake(info_hash, our_peer_id, &hs_len);
	
	printf("LibCurl rules.\n");

cleanup:
	metafile_free(&mi);
        free(hash);
	free(request_url);
	free(tracker_response);
	free(info_hash);
	if(our_peer_id)
	{
		free(our_peer_id);
	}
	return rv;
}

// TODO: this method is a candidate for util.h
void write_to_file(char *str)
{
	FILE *fp;
        fp = fopen(ANNOUNCE_FILE, "w");
        if(!fp)
        {
                fprintf(stderr, "Failed to open file to write tracker's announce response.\n");
                return;
        }
        fprintf(fp, str);
        fclose(fp);
}

void print_peers(char *announce)
{
	
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

int parse_metainfo_file(struct metafile_info *mi, char **hash)
{
	uint8_t *sha1;
	int i;

	if(read_metafile(FILE_NAME, mi) != 0)
        {
                fprintf(stderr, "Error reading metainfo file.\n");
                return -1;
        }
        printf("Metafile Info:\n");
        metafile_print(mi);

        printf("\nSHA1 of info dictionary: ");
        sha1 = sha1_compute(mi->info_val, mi->info_len);
	
	for(i=0; i<20; i++)
        {
                snprintf((*hash)+(2*i), 3, "%02x", sha1[i]);
        }
	(*hash)[40] = '\0';

	printf("%s\n", (*hash));
	
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
