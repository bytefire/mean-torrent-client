#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

#include "bencode.h"

struct peer
{
	uint8_t ip[4];
	uint16_t port;
	
	struct peer *next;
};

int peers_extract(char *filename, struct peer **head)
{
	FILE *fp;
	int len, rv, i;
	char *contents;
	const char *str, *temp;
	bencode_t b1, b2;// bn where n represents level of nestedness
	struct peer *curr, *next;
	uint8_t *swap;

	rv = 0;
	fp = fopen(filename, "r");
	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	contents = malloc(len);
	len = fread(contents, 1, len, fp);
	fclose(fp);

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
