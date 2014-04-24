#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

#include "bencode.h"

#define METADATA_FILE "../files/loff.metadata"

struct peer
{
	uint8_t ip[4];
	uint16_t port;
	
	struct peer *next;
};

int peers_extract(char *contents, struct peer **head);

int peers_extract_from_file(char *filename, struct peer **head)
{
	FILE *fp;
	int len;
	char *contents;
	int rv;
	
	rv = 0;	
	// TODO: this file reading functionality should go in <proj-name>utils.h
	fp = fopen(filename, "r");
	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	contents = malloc(len);
	len = fread(contents, 1, len, fp);
	fclose(fp);
	rv = peers_extract(contents, head);
	free(contents);

	return rv;
}
int peers_extract(char *contents, struct peer **head)
{
	int len, rv, i;
	const char *temp, *str;
	bencode_t b1, b2;// bn where n represents level of nestedness
        struct peer *curr, *next;
        uint8_t *swap;

	rv = 0;
	bencode_init(&b1, contents, len);

	// keep going until we hit the key 'peers'
	while(1) // TODO: what if there is no key named 'peers'?
	{
		bencode_dict_get_next(&b1, &b2, &str, &len);
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


void peers_create_metadata(char *announce, uint8_t *info_hash, uint8_t *our_peer_id)
{
	struct peer *head, *curr;
	FILE *fp;
	int len;
	char buf[30];

	fp = fopen(METADATA_FILE, "w");
	
	fprintf(fp, "d");
	fprintf(fp, "9:info_hash20:");
	fwrite(info_hash, 1, 20, fp);

        fprintf(fp, "11:our_peer_id20:");
        fwrite(our_peer_id, 1, 20, fp);

	// TODO: extract peers linked list and print it as a list of dictionary
	if(peers_extract(announce, &head) != 0)
	{
		fprintf(stderr, "Got problem while extracting peers from announce file.\n");
		goto cleanup;
	}
	fprintf(fp, "5:peersl"); /* start of list of peers */
	curr = head;
	while(curr != NULL)
	{
		fprintf(fp, "d");
		fprintf(fp, "2:ip");
		sprintf(buf, "%d.%d.%d.%d", curr->ip[0], curr->ip[1], curr->ip[2], curr->ip[3]);		
		len = strlen(buf);
		fprintf(fp, "%d:%s", len, buf);
		fprintf(fp, "4:porti%de", curr->port);
		fprintf(fp, "e");

		curr = curr->next;
	}
	fprintf(fp, "e"); /* end of list of peers */
	// end of root dictionary:
	fprintf(fp, "e");

cleanup:
	fclose(fp);
}
