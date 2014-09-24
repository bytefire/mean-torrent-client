#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

#include "peers.h"

#include "bencode.h"
#include "bf_logger.h"

int peers_extract_from_file(char *filename, struct peer **head)
{
	FILE *fp;
	int len;
	char *contents;
	int rv = 0;
	
	util_read_whole_file(filename, &contents, &len);
	rv = peers_extract(contents, len, head);
	free(contents);

	return rv;
}
int peers_extract(char *contents, int len, struct peer **head)
{
	int rv, i;
	const char *temp, *str;
	bencode_t b1, b2;// bn where n represents level of nestedness
        struct peer *curr, *next;
        uint8_t *swap;

	rv = 0;
	bencode_init(&b1, contents, len);

	// keep going until we hit the key 'peers'
	while(1)
	{
		if(!bencode_dict_get_next(&b1, &b2, &str, &len))
		{
			bf_log("[ERROR] peers_extract(): The bencoded dictionary doesn't contain the key 'peers'. Aborting.\n");
			rv = -1;
			goto cleanup;
		}
		if(strncmp(str, "peers", 5) == 0)
		{
			break;
		}
	}
	bencode_string_value(&b2, &str, &len);
	if(len == 0)
	{
		fprintf(stderr, "No peers found.\n");
		rv = -1;
		goto cleanup;
	}
	curr = malloc(sizeof(struct peer));
	*head = curr;
	next = curr;
	
	temp = str;
	for(i=0; i<len; i+=6)
	{
		curr = next;
		memcpy(curr->ip, temp, 4);
		temp += 4;
		swap = (uint8_t *) &(curr->port);
		memcpy(swap, temp + 1, 1);
		memcpy(swap + 1, temp, 1);
		temp += 2;
		next = malloc(sizeof(struct peer));
		curr->next = next;
	}

	free(next);
	curr->next = NULL;

cleanup:
	return rv;
}        

void peers_free(struct peer *head)
{
	struct peer *temp = head;
	struct peer *next;

	while(temp)
	{
		next = temp->next;
		free(temp);
		temp = next;
	}
	
	head = NULL;
}

/*
Format of metadata file:
------------------------

Whole file is one bencoded dictionary with following keys.

1. info_hash: 20 byte info hash
2. our_peer_id: 20 byte our peer id
3. total_length (integer): total size of the file to be downloaded
4. num_of_pieces (integer): total number of pieces
5. piece_length (integer): length of each piece in bytes
6. piece_hashes: sha1 hashes of all the pieces.
7. peers (list of dictionaries): each element is a dictionary with following keys.
	a. ip
	b. port
*/
void peers_create_metadata(char *announce, int len, uint8_t *info_hash, uint8_t *piece_hashes, uint8_t *our_peer_id, long int total_length, long int num_of_pieces, long int piece_length, const char *metadata_filename)
{
	struct peer *head, *curr;
	FILE *fp;
	char buf[30];
	int piece_hashes_len = num_of_pieces * 20; // where 20 is length of sha1 hash

	fp = fopen(metadata_filename, "w");
	
	fprintf(fp, "d");

	fprintf(fp, "9:info_hash20:");
	fwrite(info_hash, 1, 20, fp);

        fprintf(fp, "11:our_peer_id20:");
        fwrite(our_peer_id, 1, 20, fp);

	fprintf(fp, "12:total_lengthi%lde", total_length);

	fprintf(fp, "13:num_of_piecesi%lde", num_of_pieces);
        
	fprintf(fp, "12:piece_lengthi%lde", piece_length);

	// piece sha1 hashes
	fprintf(fp, "12:piece_hashes%d:", piece_hashes_len);
        fwrite(piece_hashes, 1, piece_hashes_len, fp);	

	if(peers_extract(announce, len, &head) != 0)
	{
		fprintf(stderr, "Got problem while extracting peers from announce file.\n");
		goto cleanup;
	}
	fprintf(fp, "5:peersl"); /* start of list of peers */
	curr = head;
	while(curr != NULL)
	{
		fprintf(fp, "d"); /* start of dictionary for every peer */

		fprintf(fp, "2:ip");
		sprintf(buf, "%d.%d.%d.%d", curr->ip[0], curr->ip[1], curr->ip[2], curr->ip[3]);		
		len = strlen(buf);
		fprintf(fp, "%d:%s", len, buf);
		fprintf(fp, "4:porti%de", curr->port);
		fprintf(fp, "e"); /*end of dictionary for every peer */

		curr = curr->next;
	}
	fprintf(fp, "e"); /* end of list of peers */

	// end of root dictionary:
	fprintf(fp, "e");

cleanup:
	fclose(fp);
}
